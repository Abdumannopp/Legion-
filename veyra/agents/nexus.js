// NEXUS — the orchestrator. It listens for events (an email arrived, a load reached Sourcing,
// a truck was booked, a document was uploaded, a truck went quiet) and makes the other agents
// do their part, then leaves the result as a TASK for a person.
//
// The rule that keeps this safe: NEXUS only prepares. It never sends a message, books a truck,
// changes a status or creates a load. Every outward action waits for a person to press the button
// on the task ("approve"). What it may do on its own is cheap, reversible work: reading text,
// ranking carriers, drafting messages, comparing a document with a load.
//
// Every reaction is idempotent (tasks carry a dedupe key), runs after the web request has
// finished, and failures are logged, never thrown at the person who triggered the event.
const db = require('../database');
const aiGateway = require('../ai/gateway');
const flowAgent = require('./flow');
const scoutAgent = require('./scout');
const relayAgent = require('./relay');
const vaultAgent = require('./vault');

const defaults = {
  flow: { weightUnit: 'kg', currency: 'USD', equipment: [], maxRate: 10000000, maxWeight: 1000000 },
  language: 'en',
  staleHours: 12,
  aiDailyLimit: 300,
  formatMoney: (value) => String(value)
};
let settings = { ...defaults };

function configure(next) {
  settings = { ...settings, ...next, flow: { ...settings.flow, ...(next.flow || {}) } };
}

const enabled = () => process.env.NEXUS_ENABLED !== 'false';
const pending = new Set();

// Schedules the reaction to an event and returns at once.
function emit(event, context) {
  if (!enabled()) return;
  const promise = handle(event, context)
    .catch((error) => console.error(`[NEXUS] ${event} failed:`, error.message))
    .finally(() => pending.delete(promise));
  pending.add(promise);
}

// Resolves when every scheduled reaction has finished (used by tests and graceful shutdown).
async function idle() {
  while (pending.size) await Promise.allSettled([...pending]);
}

const logger = (tenantId, shipmentId = null) => (task) => db.recordAgentTask(tenantId, { ...task, shipmentId, actorId: null })
  .catch((error) => console.error('[NEXUS] agent log failed:', error.message));

// Automatic AI work stops at a daily cap per company, so a flood of emails cannot run up a bill.
async function aiAvailable(tenantId) {
  if (!aiGateway.isEnabled()) return { ok: false, reason: 'AI is off.' };
  if ((await db.countAgentTasksToday(tenantId)) >= settings.aiDailyLimit) {
    return { ok: false, reason: 'The daily AI limit for this company was reached.' };
  }
  return { ok: true };
}

async function handle(event, context) {
  switch (event) {
    case 'inbox.received': return onInboxReceived(context);
    case 'shipment.status': return onShipmentStatus(context);
    case 'shipment.dispatched': return onShipmentDispatched(context);
    case 'document.uploaded': return onDocumentUploaded(context);
    default: return undefined;
  }
}

/* ---------- an order email arrived ---------- */
async function onInboxReceived({ tenantId, inboxId }) {
  const item = await db.getInboxItem(tenantId, inboxId);
  if (!item) return;
  let parsed = item.parsed;
  let note = null;
  if (item.status === 'new') {
    const ai = await aiAvailable(tenantId);
    if (!ai.ok) {
      note = ai.reason;
    } else {
      try {
        parsed = await flowAgent.parseOrder(`Subject: ${item.subject || ''}\n\n${item.body}`, settings.flow, logger(tenantId));
        await db.updateInboxItem(tenantId, inboxId, { status: 'parsed', parsed });
      } catch (error) {
        note = 'FLOW could not read this email automatically.';
        await db.updateInboxItem(tenantId, inboxId, { status: 'failed', error: error.message });
      }
    }
  }
  const draft = parsed?.draft;
  const title = draft?.origin && draft?.destination
    ? `New order: ${draft.customer || item.from || 'customer'} · ${draft.origin} → ${draft.destination}`
    : `New email from ${item.from || 'unknown sender'}`;
  await db.createTask(tenantId, {
    kind: 'review_intake',
    title,
    inboxId,
    dedupeKey: `inbox:${inboxId}`,
    payload: { from: item.from, subject: item.subject, preview: item.body.slice(0, 300), parsed, note }
  });
}

/* ---------- a load changed status ---------- */
async function onShipmentStatus({ tenantId, shipmentId, status }) {
  if (status !== 'Exception') await db.resolveTasksByKey(tenantId, `exception:${shipmentId}:`);

  if (status === 'Delivered' || status === 'Cancelled') {
    await db.resolveTasksForShipment(tenantId, shipmentId);
  }

  const shipment = await db.getShipment(tenantId, shipmentId);
  if (!shipment) return;
  const label = `SHP-${shipmentId}`;

  if (status === 'Sourcing') {
    const data = await db.getScoutData(tenantId, shipmentId);
    const recommendations = scoutAgent.rankCarriers(data).slice(0, 3);
    await db.createTask(tenantId, {
      kind: 'book_carrier',
      title: recommendations.length ? `Book a carrier for ${label} · ${shipment.origin} → ${shipment.destination}` : `No carrier available for ${label}`,
      shipmentId,
      dedupeKey: `book:${shipmentId}`,
      payload: { recommendations, laneAverageRate: data.laneAverageRate, laneLoads: data.laneLoads }
    });
  }

  if (status === 'Exception') {
    const count = await db.countShipmentExceptions(tenantId, shipmentId);
    await db.createTask(tenantId, {
      kind: 'attention',
      title: `${label} is in Exception · ${shipment.customer}`,
      shipmentId,
      dedupeKey: `exception:${shipmentId}:${count}`,
      payload: { text: 'Find out what happened, tell the customer if the delivery will be late, then move the load on.', carrierPhone: shipment.carrierPhone || null, driverPhone: shipment.driver_phone || null }
    });
  }

  if (status === 'Delivered') {
    await draftMessageTask(tenantId, shipment, 'customer', 'delivered', `msg:${shipmentId}:customer:delivered`);
  }
}

/* ---------- a truck was booked ---------- */
async function onShipmentDispatched({ tenantId, shipmentId }) {
  await db.resolveTasksByKey(tenantId, `book:${shipmentId}`);
  const shipment = await db.getShipment(tenantId, shipmentId);
  if (!shipment) return;
  for (const [recipient, purpose] of [['carrier', 'booking_confirmation'], ['customer', 'booking_confirmation'], ['driver', 'pickup_details']]) {
    await draftMessageTask(tenantId, shipment, recipient, purpose, `msg:${shipmentId}:${recipient}:booking`);
  }
}

// A drafted message waits for approval. It is only created when the load has a number to send it to.
async function draftMessageTask(tenantId, shipment, recipient, purpose, dedupeKey, extraTitle = '') {
  const tenant = await db.getTenant(tenantId);
  const draft = relayAgent.draftMessage({
    shipment, recipient, purpose, language: settings.language, company: tenant?.name || '', formatMoney: settings.formatMoney
  });
  if (!draft?.to) return false;
  const what = { booking_confirmation: 'booking', pickup_details: 'pickup details', location_request: 'ask for location', status_update: 'status update', delivered: 'delivered' }[draft.purpose] || draft.purpose;
  const result = await db.createTask(tenantId, {
    kind: 'message',
    title: `Message the ${recipient} about SHP-${shipment.id}: ${what}${extraTitle}`,
    shipmentId: shipment.id,
    dedupeKey,
    payload: { recipient, purpose: draft.purpose, language: draft.language, body: draft.body, to: draft.to }
  });
  return result.created;
}

/* ---------- a document was uploaded ---------- */
async function onDocumentUploaded({ tenantId, shipmentId, documentId }) {
  const document = await db.getDocument(tenantId, shipmentId, documentId);
  if (!document) return;
  if (!vaultAgent.READABLE_TYPES.includes(document.type)) {
    await db.updateDocumentExtraction(tenantId, documentId, { status: 'skipped', error: 'Only CMR and proof of delivery files are read automatically.' });
    return;
  }
  const ai = await aiAvailable(tenantId);
  if (!ai.ok) {
    await db.updateDocumentExtraction(tenantId, documentId, { status: 'skipped', error: ai.reason });
    return;
  }
  const file = await db.getDocumentFile(tenantId, shipmentId, documentId);
  const shipment = await db.getShipment(tenantId, shipmentId);
  if (!file || !shipment) return;
  try {
    const fields = await vaultAgent.extractFields({ content: file.content, mime: file.mime, filename: file.filename }, settings.flow, logger(tenantId, shipmentId));
    const comparison = vaultAgent.compareWithShipment(fields, shipment);
    await db.updateDocumentExtraction(tenantId, documentId, { status: 'done', extracted: fields, comparison });
    if (comparison.mismatches > 0) {
      await db.createTask(tenantId, {
        kind: 'check_document',
        title: `${file.filename}: ${comparison.mismatches} difference${comparison.mismatches === 1 ? '' : 's'} from SHP-${shipmentId}`,
        shipmentId,
        dedupeKey: `doc:${documentId}`,
        payload: { documentId, filename: file.filename, mismatches: comparison.checks.filter((check) => check.status === 'mismatch') }
      });
    }
  } catch (error) {
    await db.updateDocumentExtraction(tenantId, documentId, { status: 'failed', error: error.message });
  }
}

/* ---------- trucks that went quiet (periodic) ---------- */
// Looks at every company's booked trucks. One task per truck per "silence": a new task appears only
// after the truck has reported again and then gone quiet again.
async function sweep() {
  const stale = await db.listStaleLoadsAllTenants(settings.staleHours);
  let created = 0;
  for (const row of stale) {
    const shipment = await db.getShipment(row.tenantId, row.id);
    if (!shipment) continue;
    const key = `stale:${row.id}:${row.lastTrackedAt || 'none'}`;
    const made = await draftMessageTask(row.tenantId, shipment, 'driver', 'location_request', key, ` (no update for ${settings.staleHours}h+)`);
    if (made) {
      created += 1;
      continue;
    }
    // No driver number on the load: a plain reminder to call.
    const result = await db.createTask(row.tenantId, {
      kind: 'attention',
      title: `SHP-${row.id}: no location update for ${settings.staleHours}h+ — call the driver`,
      shipmentId: row.id,
      dedupeKey: key,
      payload: { text: 'No driver phone number is on this load. Call the carrier, then log the location.', carrierPhone: shipment.carrierPhone || null }
    });
    if (result.created) created += 1;
  }
  return created;
}

let sweepTimer = null;

function startSweeper(intervalMinutes = 10) {
  if (!enabled() || sweepTimer) return;
  const run = () => sweep().catch((error) => console.error('[NEXUS] sweep failed:', error.message));
  sweepTimer = setInterval(run, intervalMinutes * 60 * 1000);
  sweepTimer.unref();
  setTimeout(run, 15000).unref();
}

function stopSweeper() {
  if (sweepTimer) clearInterval(sweepTimer);
  sweepTimer = null;
}

module.exports = { configure, emit, idle, sweep, startSweeper, stopSweeper };
