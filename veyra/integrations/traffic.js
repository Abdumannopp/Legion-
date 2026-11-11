// Live traffic on the road between two places, from TomTom (needs TRAFFIC_PROVIDER=tomtom and TOMTOM_API_KEY).
// OFF by default. Only the coordinates of the two places of a load are sent, never customer or price data.
// Answers are cached for 30 minutes per lane (traffic changes slowly and the free quota is limited).
// The key travels in the request address (that is how TomTom works), so errors are cleaned before they are logged or shown.
const geo = require('./geo');

const enabled = () => String(process.env.TRAFFIC_PROVIDER || '').toLowerCase() === 'tomtom' && Boolean(process.env.TOMTOM_API_KEY) && geo.enabled();
const baseUrl = () => String(process.env.TOMTOM_URL || 'https://api.tomtom.com').replace(/\/+$/, '');
const TTL_MS = 30 * 60 * 1000;
const cache = new Map();

let transport = (url, init) => fetch(url, init);
function setTransport(fn) {
  transport = fn || ((url, init) => fetch(url, init));
}
const clearCache = () => cache.clear();

const scrub = (text) => String(text).split(process.env.TOMTOM_API_KEY || '\u0000').join('***');

// { delayMinutes, travelHours } for driving a truck now, or null when switched off / a place is unknown.
async function current(origin, destination, { now = Date.now() } = {}) {
  if (!enabled()) return null;
  const key = `${String(origin).trim().toLowerCase()}|${String(destination).trim().toLowerCase()}`;
  const hit = cache.get(key);
  if (hit && now - hit.at < TTL_MS) return hit.value;
  const from = await geo.geocode(origin);
  const to = from ? await geo.geocode(destination) : null;
  if (!from || !to) return null;
  const url = `${baseUrl()}/routing/1/calculateRoute/${from.lat},${from.lng}:${to.lat},${to.lng}/json?traffic=true&travelMode=truck&key=${encodeURIComponent(process.env.TOMTOM_API_KEY)}`;
  let summary;
  try {
    const response = await transport(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(12000) });
    if (!response.ok) throw new Error(`Traffic service returned ${response.status}`);
    summary = (await response.json())?.routes?.[0]?.summary;
  } catch (error) {
    throw new Error(scrub(error.message));
  }
  if (!summary || !Number.isFinite(summary.travelTimeInSeconds)) return null;
  const value = {
    travelHours: Math.round((summary.travelTimeInSeconds / 3600) * 10) / 10,
    delayMinutes: Math.max(0, Math.round((Number(summary.trafficDelayInSeconds) || 0) / 60))
  };
  cache.set(key, { at: now, value });
  return value;
}

module.exports = { enabled, current, setTransport, clearCache };
