// ROUTE — plans the trip from the company's own history. No language model and no map service:
// it knows how long this lane took on past loads, so it can say whether the promised dates are
// realistic, when the truck will probably arrive, and which trucks finish near the pickup
// (a return load is cheaper than an empty truck).
// It only advises. Nothing is changed on the load.
const MIN_SAMPLES = 3;
const HOUR = 60 * 60 * 1000;
// Driving time from the map x this = a realistic trip with rests (an assumption, shown as such).
const REST_FACTOR = 1.35;

// SQLite stores UTC as "YYYY-MM-DD HH:MM:SS".
function parseDbTime(value) {
  if (!value) return null;
  const time = Date.parse(`${String(value).replace(' ', 'T')}Z`);
  return Number.isNaN(time) ? null : time;
}

function parseDay(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ''))) return null;
  const time = Date.parse(`${value}T00:00:00Z`);
  return Number.isNaN(time) ? null : time;
}

// "Tashkent, UZ" -> "UZ": the last part of a place name, when it is a two-letter country code.
function countryOf(place) {
  const last = String(place || '').split(',').pop().trim();
  return /^[A-Za-z]{2}$/.test(last) && String(place).includes(',') ? last.toUpperCase() : null;
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

const round1 = (value) => Math.round(value * 10) / 10;

function humanDuration(hours) {
  if (hours < 36) return `${Math.max(1, Math.round(hours))} h`;
  return `${round1(hours / 24)} days`;
}

// data: from db.getRouteData. Returns a plan a person can read.
function planRoute(data) {
  const { shipment } = data;
  const durations = data.history
    .map((row) => {
      const start = parseDbTime(row.startedAt);
      const end = parseDbTime(row.deliveredAt);
      return start !== null && end !== null && end > start ? (end - start) / HOUR : null;
    })
    .filter((hours) => hours !== null && hours < 24 * 60);
  const enough = durations.length >= MIN_SAMPLES;
  const typical = enough ? median(durations) : null;
  const lane = {
    loads: durations.length,
    typicalHours: typical === null ? null : round1(typical),
    fastestHours: enough ? round1(Math.min(...durations)) : null,
    slowestHours: enough ? round1(Math.max(...durations)) : null
  };

  const pickupDay = parseDay(shipment.pickup);
  const deliveryDay = parseDay(shipment.delivery);
  // Pickup at the start of the pickup day, delivery by the end of the delivery day.
  const allowedHours = pickupDay !== null && deliveryDay !== null ? (deliveryDay - pickupDay) / HOUR + 24 : null;
  const deadline = deliveryDay === null ? null : deliveryDay + 24 * HOUR;

  // With a map, the road gives a first estimate when the company has no history on the lane yet:
  // driving time plus a rest allowance (drivers must rest; borders and loading take time too).
  const map = data.map || null;
  // A border crossing the company entered (hours of waiting). Past loads already include it, a map estimate does not.
  const border = data.border ? { pair: data.border.pair, hours: data.border.hours } : null;
  const borderHours = typical === null && border ? border.hours : 0;
  // Live traffic delay counts only for a truck that is on the road now: a delay today says little about next week.
  const traffic = data.traffic || null;
  const trafficHours = typical === null && traffic && ['Dispatched', 'In Transit'].includes(shipment.status) ? traffic.delayMinutes / 60 : 0;
  const mapHours = map ? round1(map.durationHours * REST_FACTOR + borderHours + trafficHours) : null;
  const expected = typical !== null ? typical : mapHours;
  const expectedBasis = typical !== null ? 'this lane usually takes' : 'by road it takes about';

  let schedule = { verdict: 'unknown', text: `Not enough history on this lane yet (${durations.length} of ${MIN_SAMPLES} delivered loads needed).` };
  if (expected !== null && allowedHours !== null) {
    schedule = allowedHours < expected
      ? { verdict: 'tight', text: `The dates allow ${humanDuration(allowedHours)}, but ${expectedBasis} ${humanDuration(expected)}. Agree a later delivery date or expect a delay.` }
      : { verdict: 'ok', text: `The dates allow ${humanDuration(allowedHours)}; ${expectedBasis} ${humanDuration(expected)}.` };
  }

  // Estimated arrival: from the moment the truck left, otherwise from the planned pickup day.
  let arrival = null;
  if (expected !== null && !['Delivered', 'Cancelled'].includes(shipment.status)) {
    const started = parseDbTime(data.startedAt);
    const from = started !== null ? started : (pickupDay !== null ? pickupDay + 8 * HOUR : null);
    if (from !== null) {
      const at = from + expected * HOUR;
      arrival = {
        at: new Date(at).toISOString(),
        basis: `${started !== null ? 'from the time the truck left' : 'from the planned pickup day'}${typical === null ? ', estimated from the map' : ''}`,
        late: deadline !== null && at > deadline
      };
    }
  }

  // Trucks that unload where this load starts.
  const seen = new Set();
  const returnTrucks = data.nearby
    .filter((row) => row.carrierId !== shipment.carrier_id)
    .map((row) => {
      const delivered = row.status === 'Delivered';
      const day = delivered ? null : parseDay(String(row.eta || '').slice(0, 10)) ?? parseDay(row.delivery);
      // Useful if the truck is free from three days before pickup up to the pickup day.
      const fits = delivered || pickupDay === null || day === null || (day <= pickupDay && day >= pickupDay - 3 * 24 * HOUR);
      return fits ? {
        carrierId: row.carrierId,
        name: row.carrierName,
        phone: row.carrierPhone || null,
        load: `SHP-${row.id}`,
        note: delivered
          ? `Unloaded in ${shipment.origin} on SHP-${row.id}; may still be there.`
          : `Arrives in ${shipment.origin} with SHP-${row.id}${row.delivery ? ` (delivery ${row.delivery})` : ''}.`
      } : null;
    })
    .filter((item) => item && !seen.has(item.carrierId) && seen.add(item.carrierId))
    .slice(0, 3);

  return {
    lane,
    map: map ? { distanceKm: map.distanceKm, drivingHours: map.durationHours, withRestsHours: mapHours } : null,
    border: border ? { ...border, counted: borderHours > 0 } : null,
    traffic: traffic ? { delayMinutes: traffic.delayMinutes, travelHours: traffic.travelHours, counted: trafficHours > 0 } : null,
    schedule,
    arrival,
    returnTrucks
  };
}

module.exports = { countryOf, planRoute, MIN_SAMPLES, parseDay, parseDbTime, median };
