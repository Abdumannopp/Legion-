const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const testDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-transactions-'));
process.env.DATABASE_PATH = path.join(testDirectory, 'shipments.db');
process.env.NODE_ENV = 'development';

const {
  db,
  initialize,
  createShipment,
  dispatchShipment,
  listCarriers,
  listShipmentEvents,
  listShipments
} = require('../database');

function execute(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) return reject(error);
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) return reject(error);
      resolve(row || null);
    });
  });
}

async function createSourcingShipment(customer) {
  const shipment = await createShipment({
    customer,
    origin: 'Dallas, TX',
    destination: 'Austin, TX',
    pickup: '2026-10-05',
    delivery: '2026-10-06',
    status: 'Sourcing',
    weight: '4,000 lb',
    equipment: 'Dry Van'
  });
  return Number(shipment.id.replace('SHP-', ''));
}

before(async () => {
  await initialize();
});

after(async () => {
  await new Promise((resolve, reject) => {
    db.close((error) => error ? reject(error) : resolve());
  });
  fs.rmSync(testDirectory, { recursive: true, force: true });
});

test('concurrent dispatches cannot assign one carrier to two shipments', async () => {
  const firstShipmentId = await createSourcingShipment('Concurrent Load A');
  const secondShipmentId = await createSourcingShipment('Concurrent Load B');
  const carrierId = 1;

  const attempts = await Promise.allSettled([
    dispatchShipment(firstShipmentId, carrierId, 1200, 1),
    dispatchShipment(secondShipmentId, carrierId, 1300, 1)
  ]);

  assert.equal(attempts.filter((attempt) => attempt.status === 'fulfilled').length, 1);
  const rejectedAttempt = attempts.find((attempt) => attempt.status === 'rejected');
  assert.equal(rejectedAttempt.reason.statusCode, 409);

  const [first, second] = await Promise.all([
    get('SELECT status, carrier_id AS carrierId FROM shipments WHERE id = ?', [firstShipmentId]),
    get('SELECT status, carrier_id AS carrierId FROM shipments WHERE id = ?', [secondShipmentId])
  ]);
  const assigned = [first, second].filter((shipment) => shipment.status === 'Dispatched');
  const unassigned = [first, second].filter((shipment) => shipment.status === 'Sourcing');
  assert.equal(assigned.length, 1);
  assert.equal(unassigned.length, 1);
  assert.equal(assigned[0].carrierId, carrierId);
  assert.equal(unassigned[0].carrierId, null);

  const carrier = (await listCarriers()).find((item) => item.id === carrierId);
  assert.equal(carrier.status, 'Busy');
  const dispatchedEvents = (await listShipmentEvents(assigned[0] === first ? firstShipmentId : secondShipmentId))
    .filter((event) => event.status === 'Dispatched');
  assert.equal(dispatchedEvents.length, 1);
});

test('failed audit insert rolls back shipment and carrier updates', async () => {
  const shipmentId = await createSourcingShipment('Rollback Load');
  const carrierId = 2;
  await execute(`
    CREATE TRIGGER fail_dispatch_audit
    BEFORE INSERT ON shipment_events
    WHEN NEW.to_status = 'Dispatched'
    BEGIN
      SELECT RAISE(ABORT, 'forced audit insert failure');
    END
  `);

  await assert.rejects(
    dispatchShipment(shipmentId, carrierId, 975, 1),
    /forced audit insert failure/
  );

  const [shipment, carrier] = await Promise.all([
    get('SELECT status, carrier_id AS carrierId FROM shipments WHERE id = ?', [shipmentId]),
    get('SELECT status FROM carriers WHERE id = ?', [carrierId])
  ]);
  assert.equal(shipment.status, 'Sourcing');
  assert.equal(shipment.carrierId, null);
  assert.equal(carrier.status, 'Available');
  assert.equal((await listShipmentEvents(shipmentId)).filter((event) => event.status === 'Dispatched').length, 0);

  await execute('DROP TRIGGER fail_dispatch_audit');
});
