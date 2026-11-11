// SENTINEL — watches every open load for trouble before the customer calls:
// no truck yet and pickup is near, pickup day passed, delivery day passed, the driver's own ETA
// is after the promised day, a booked truck without a driver number, a silent truck,
// a message that did not arrive. Rules only, no language model.
// It reports risks; it changes nothing on a load.
const { parseDay, parseDbTime } = require('./route');

const DAY = 24 * 60 * 60 * 1000;
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
// Risks that get their own task in Inbox & tasks. Silent trucks, exceptions and failed messages
// already get a task from NEXUS, so they are listed here but not duplicated.
const TASK_RISKS = ['no_carrier', 'late_pickup', 'late_delivery', 'eta_after_delivery', 'missing_driver'];

function assessLoad(load, { now = Date.now(), staleHours = 12 } = {}) {
  const today = Math.floor(now / DAY) * DAY;
  const pickup = parseDay(load.pickup);
  const delivery = parseDay(load.delivery);
  const label = `SHP-${load.id}`;
  const risks = [];
  const add = (type, severity, title, advice, detail = null) => risks.push({ type, severity, title, advice, detail });
  const booked = ['Dispatched', 'In Transit', 'Exception'].includes(load.status);

  if (['New', 'Sourcing', 'Pending Approval'].includes(load.status) && pickup !== null && pickup - today <= DAY) {
    const overdue = pickup < today;
    add('no_carrier', pickup <= today ? 'high' : 'medium',
      `${label}: no truck booked and pickup is ${overdue ? 'already past' : pickup === today ? 'today' : 'tomorrow'}`,
      'Book a carrier now or tell the customer the pickup will move.');
  }
  if (load.status === 'Dispatched' && pickup !== null && pickup < today) {
    add('late_pickup', 'high', `${label}: pickup day (${load.pickup}) passed and the truck has not left`,
      'Call the driver or carrier. If the truck is loaded, set the load to In Transit.');
  }
  if (booked && delivery !== null && delivery < today) {
    add('late_delivery', 'high', `${label}: delivery day (${load.delivery}) passed and the load is not delivered`,
      'Find out where the truck is and tell the customer a new time. If it arrived, set the load to Delivered.');
  }
  const etaDay = parseDay(String(load.eta || '').slice(0, 10));
  if (booked && etaDay !== null && delivery !== null && etaDay > delivery && delivery >= today) {
    add('eta_after_delivery', 'medium', `${label}: expected arrival ${String(load.eta).replace('T', ' ')} is after the promised ${load.delivery}`,
      'Warn the customer now, before the delivery day.', String(load.eta));
  }
  if (['Dispatched', 'In Transit'].includes(load.status) && (!load.driverPhone || !load.truckPlate)) {
    const what = [!load.driverPhone && 'driver phone', !load.truckPlate && 'truck plate'].filter(Boolean).join(' and ');
    add('missing_driver', pickup !== null && pickup - today <= DAY ? 'medium' : 'low', `${label}: no ${what} on the load`,
      'Ask the carrier. Without the phone you cannot reach the driver; without the plate GPS cannot find the truck.');
  }
  const lastSeen = parseDbTime(load.lastSignOfLife);
  if (['Dispatched', 'In Transit'].includes(load.status) && lastSeen !== null && now - lastSeen > staleHours * 60 * 60 * 1000) {
    add('silent', 'medium', `${label}: no location update for ${Math.floor((now - lastSeen) / (60 * 60 * 1000))} h`, 'Ask the driver where the truck is.');
  }
  if (load.status === 'Exception') {
    add('exception', 'high', `${label} is in Exception`, 'Solve the problem, then move the load on.');
  }
  if (Number(load.failedMessages) > 0) {
    add('message_failed', 'medium', `${label}: a message was not delivered`, 'Check the phone number on the load and call instead.');
  }
  return risks.map((risk) => ({
    ...risk,
    shipmentId: label,
    customer: load.customer,
    lane: `${load.origin} → ${load.destination}`,
    carrierPhone: load.carrierPhone || null,
    driverPhone: load.driverPhone || null
  }));
}

function assess(loads, options) {
  return loads
    .flatMap((load) => assessLoad(load, options))
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

module.exports = { assess, assessLoad, TASK_RISKS };
