# VEYRA Logistics Platform

A production-style logistics dashboard and backend built with Express and SQLite.

## Features

- Dark premium logistics landing page
- Authentication with JWT
- SQLite persistence for users and shipments
- Admin operations console with role-based access
- Shipment intake with required customer, route, date, weight, and equipment details
- Carrier assignment, quoted rate, and dispatch management
- Validated shipment lifecycle with an auditable activity history

## Shipment operations flow

1. Create a shipment from the dashboard using the New Shipment form.
2. Move the shipment from New to Sourcing, then optionally to Pending Approval.
3. Select an available carrier and enter the agreed rate to dispatch the load.
4. Update the load through In Transit to Delivered, or log an Exception.
5. Use History on a shipment to review its recorded activity.

Allowed progression is enforced by the API. Carriers assigned to dispatched loads are marked Busy and released when the shipment is Delivered or Cancelled.

### Operations API

- `POST /api/shipments` creates a validated shipment.
- `PATCH /api/admin/shipments/:id/status` advances an allowed lifecycle state.
- `POST /api/admin/shipments/:id/dispatch` assigns an available carrier and rate.
- `GET /api/shipments/:id/events` returns shipment activity history.

- `GET /api/carriers` lists carriers with load statistics (loads, active, delivered, exceptions, booked revenue, current load).
- `POST /api/carriers` adds a carrier (`name`, `mode`: Truckload, LTL, Expedited, Reefer, Flatbed, Intermodal).
- `PATCH /api/carriers/:id/status` sets a carrier `Available` or `Inactive` (refused while the carrier has an active load).
- `GET /api/analytics?days=7|30|90` returns KPIs, daily volume, status pipeline, equipment mix, top lanes, top customers and carrier performance.

## App pages

The dashboard uses hash routes, so links can be bookmarked and shared:

- `#/dashboard` — overview, AI assistant and operations console.
- `#/shipments` — all loads with status tabs, search, equipment filter, sorting, status changes, dispatch and CSV export. `#/shipments?status=Pending%20Approval` is the Approvals queue.
- `#/carriers` — carrier network with availability, load history, add carrier and activate/deactivate.
- `#/analytics` — 7/30/90-day analytics.

Pages and actions follow the signed-in role; the API remains the security boundary.

All operations endpoints require a valid JWT; admin shipment controls require an admin or operations role.

## Role permissions

- `admin`: full access to dashboard, analytics, users, shipments, status changes, dispatch, and carriers.
- `operations`: dashboard/analytics access, team and shipment reads, shipment creation, status changes, carrier dispatch, and carrier reads and management.
- `operator`: shipment/dashboard reads, shipment creation, and carrier reads. Analytics, team access, dispatch, and status changes are denied by the API.

Permissions are returned at login and enforced server-side; hiding a UI panel is not the security boundary.

## Quick start

0. Frontend files live in `public/`; only that folder is served statically.
1. Install dependencies:
   npm install
2. Copy environment variables:
   copy .env.example .env
3. Configure production values in .env:
   - PORT=3000
   - JWT_SECRET=your-real-secret
   - NODE_ENV=production
   - DATABASE_PATH=./data/veyra.db (use persistent storage for cloud hosting)
4. Start the app locally:
   npm start
5. Start the app in production mode (default for `npm start`):
   npm run prod

`npm start` and `npm run prod` run in production mode and require `JWT_SECRET` plus the `INITIAL_ADMIN_*` variables. Use `npm run dev` for local development; only that mode seeds the demo users.

## Production deployment checklist

- Use a strong JWT secret in production
- Run behind HTTPS / a reverse proxy
- Set NODE_ENV=production
- Mount persistent storage for SQLite; use PostgreSQL before adding app replicas
- Add monitoring, logs, and backups
- Keep admin credentials out of source control

Render, Railway, and VPS deployment files and setup steps are in [DEPLOYMENT.md](DEPLOYMENT.md).

## Demo users

- Created only with `npm run dev` (NODE_ENV=development); never in production.
- admin@veyra.ai / admin123
- ops@veyra.ai / ops123
- demo@veyra.ai / demo123

## Production notes

- Change JWT_SECRET before deployment.
- Set NODE_ENV=production using npm run prod.
- Add HTTPS and proper hosting configuration for production use.
- For cloud deployments, keep secrets in environment variables, not in code.

## Registration

Open registration creates `operator` accounts. Set `REGISTRATION_INVITE_CODE` to require an invite code.

## Security & production notes

- **XSS**: the frontend builds DOM with `textContent`/`createElement` only (no `innerHTML`, `eval`, inline scripts or inline handlers); a test scans the sources for these sinks. CSP is `script-src 'self'`.
- **Auth**: JWT lives only in an HttpOnly, SameSite=Lax cookie (`Secure` in production); sessions are revocable server-side; login is rate-limited per account and per IP; production never seeds demo users.
- **Dispatch**: assignment and status changes run in a single SQLite transaction, so two operators cannot book the same carrier or load.
- **Validation**: strict IDs, ISO dates, positive bounded numbers, 50 kb JSON limit; malformed input returns 400, never a 500.
- **Errors**: a global handler returns generic messages; details are logged server-side only.
- **Database**: foreign keys enforced, indexes on hot queries, `npm run db:check` runs `PRAGMA integrity_check` and `foreign_key_check`.
- **Production start**: `NODE_ENV=production`, `JWT_SECRET` and (first start only) `INITIAL_ADMIN_NAME/EMAIL/PASSWORD` (12+ chars) are required; the server refuses to start without them.
- **Tests**: `npm test` (27 tests: auth, rate limits, transactions, validation, security headers, carriers, analytics, XSS).
- **Dependencies**: `npm audit` reports 0 vulnerabilities at the time of release.
