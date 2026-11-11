// Map facts from OpenStreetMap services: where a place is (Nominatim) and the road between two places (OSRM).
// OFF by default: place names of your loads would be sent to a third party. Switch it on with GEO_PROVIDER=osm.
// The public servers are for light use only (about one request a second); every answer is cached in the
// database, so a lane is looked up once. For heavy use point NOMINATIM_URL and OSRM_URL at your own servers.
// Nothing about customers, prices or people is sent: only the two place names of a load.
const db = require('../database');

const enabled = () => String(process.env.GEO_PROVIDER || '').toLowerCase() === 'osm';
const nominatimUrl = () => String(process.env.NOMINATIM_URL || 'https://nominatim.openstreetmap.org').replace(/\/+$/, '');
const osrmUrl = () => String(process.env.OSRM_URL || 'https://router.project-osrm.org').replace(/\/+$/, '');
// A truck farther than this from the road between origin and destination is "off route".
const offRouteKm = () => Math.max(5, Number(process.env.OFF_ROUTE_KM) || 60);

let transport = (url, init) => fetch(url, init);
function setTransport(fn) {
  transport = fn || ((url, init) => fetch(url, init));
}

const key = (text) => String(text || '').trim().toLowerCase().replace(/\s+/g, ' ');
const EARTH_KM = 6371;
const rad = (degrees) => (degrees * Math.PI) / 180;

function haversineKm(a, b) {
  const dLat = rad(b.lat - a.lat);
  const dLng = rad(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * EARTH_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

// Shortest distance (km) from a point to a line of [lat, lng] points. Flat-earth approximation around the
// point: fine for "is the truck 60 km away from the road", not for surveying.
function distanceToLineKm(point, line) {
  if (!line.length) return null;
  const kx = Math.cos(rad(point.lat)) * 111.32;
  const toXY = ([lat, lng]) => [(lng - point.lng) * kx, (lat - point.lat) * 110.57];
  let best = Infinity;
  for (let i = 0; i < line.length; i += 1) {
    const [x1, y1] = toXY(line[i]);
    if (i === line.length - 1) {
      best = Math.min(best, Math.hypot(x1, y1));
      break;
    }
    const [x2, y2] = toXY(line[i + 1]);
    const dx = x2 - x1;
    const dy = y2 - y1;
    const length = dx * dx + dy * dy;
    const t = length === 0 ? 0 : Math.max(0, Math.min(1, -(x1 * dx + y1 * dy) / length));
    best = Math.min(best, Math.hypot(x1 + t * dx, y1 + t * dy));
  }
  return best;
}

// Keeps at most `max` points, evenly spread (always including the first and last).
function thin(points, max = 300) {
  if (points.length <= max) return points;
  const step = (points.length - 1) / (max - 1);
  return Array.from({ length: max }, (_, i) => points[Math.round(i * step)]);
}

async function fetchJson(url) {
  const response = await transport(url, { headers: { 'User-Agent': 'VEYRA-logistics', Accept: 'application/json' }, signal: AbortSignal.timeout(12000) });
  if (!response.ok) throw new Error(`Map service returned ${response.status}`);
  return response.json();
}

// { lat, lng } or null when the place is unknown. Cached, including "unknown".
async function geocode(place) {
  const name = key(place);
  if (!name) return null;
  const cached = await db.getGeoPlace(name);
  if (cached !== undefined) return cached.lat === null ? null : cached;
  const data = await fetchJson(`${nominatimUrl()}/search?format=json&limit=1&q=${encodeURIComponent(place)}`);
  const hit = Array.isArray(data) ? data[0] : null;
  const lat = Number(hit?.lat);
  const lng = Number(hit?.lon);
  const found = Number.isFinite(lat) && Number.isFinite(lng);
  await db.setGeoPlace(name, found ? lat : null, found ? lng : null);
  return found ? { lat, lng } : null;
}

const routeKey = (origin, destination) => `${key(origin)}|${key(destination)}`;

// Cached road route, or null (never asks the network).
async function cachedRoute(origin, destination) {
  return db.getGeoRoute(routeKey(origin, destination));
}

// { distanceKm, durationHours, points: [[lat, lng], ...] } or null when a place cannot be found.
// Asks the map services only when the lane is not cached yet.
async function route(origin, destination) {
  if (!enabled()) return null;
  const known = await cachedRoute(origin, destination);
  if (known) return known;
  const from = await geocode(origin);
  const to = from ? await geocode(destination) : null;
  if (!from || !to) return null;
  const data = await fetchJson(`${osrmUrl()}/route/v1/driving/${from.lng},${from.lat};${to.lng},${to.lat}?overview=simplified&geometries=geojson`);
  const best = data?.routes?.[0];
  const coordinates = best?.geometry?.coordinates;
  if (!best || !Array.isArray(coordinates) || coordinates.length < 2) return null;
  const result = {
    distanceKm: Math.round(best.distance / 100) / 10,
    durationHours: Math.round((best.duration / 3600) * 10) / 10,
    points: thin(coordinates.map(([lng, lat]) => [Math.round(lat * 1e5) / 1e5, Math.round(lng * 1e5) / 1e5]))
  };
  await db.setGeoRoute(routeKey(origin, destination), result);
  return result;
}

const GPS_FRESH_MS = 6 * 60 * 60 * 1000;

// Adds offRouteKm to loads that are on the road and have a fresh GPS point. `fetchMissing` allows asking the
// map services for lanes that are not cached yet (background job); the web request only reads the cache.
async function annotateOffRoute(loads, { fetchMissing = false, now = Date.now() } = {}) {
  if (!enabled()) return loads;
  for (const load of loads) {
    if (load.status !== 'In Transit' || load.lastLat === null || load.lastLat === undefined) continue;
    const seen = Date.parse(`${String(load.lastGpsAt).replace(' ', 'T')}Z`);
    if (Number.isNaN(seen) || now - seen > GPS_FRESH_MS) continue;
    try {
      const road = fetchMissing ? await route(load.origin, load.destination) : await cachedRoute(load.origin, load.destination);
      if (road) load.offRouteKm = Math.round(distanceToLineKm({ lat: load.lastLat, lng: load.lastLng }, road.points));
    } catch (error) {
      console.error('[geo] route lookup failed:', error.message);
    }
  }
  return loads;
}

module.exports = { enabled, offRouteKm, setTransport, geocode, route, cachedRoute, annotateOffRoute, haversineKm, distanceToLineKm, thin };
