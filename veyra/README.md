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

This is one truck (FTL) load from order to delivery:

1. Create a shipment with the New Shipment form (weight in the configured unit, optional customer price).
2. Move the shipment from New to Sourcing, then optionally to Pending Approval.
3. Dispatch: pick an available carrier, enter the carrier rate, the customer price (margin is shown live), truck plate and driver.
4. While the truck is on the road, log location updates ("where is the truck now?", ETA, note) from the load's details. Trucks with no update for 12 hours appear in notifications.
5. Move the load through In Transit to Delivered, or log an Exception. A dispatched load can still be cancelled before pickup.
6. Use History on a shipment to review its recorded activity.

Allowed progression is enforced by the API. Carriers assigned to dispatched loads are marked Busy and released when the shipment is Delivered or Cancelled.

### Operations API

- `POST /api/shipments` creates a validated shipment.
- `PATCH /api/admin/shipments/:id/status` advances an allowed lifecycle state.
- `POST /api/admin/shipments/:id/dispatch` assigns an available carrier and rate.
- `GET /api/shipments/:id/events` returns shipment activity history.
- `GET /api/shipments/:id/tracking` lists location updates; `POST` adds one (`location`, optional `eta` as `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM`, optional `note`) while the load is Dispatched, In Transit or Exception.
- Dispatch also accepts optional `customerRate`, `driverName`, `driverPhone`, `truckPlate`; shipments return `customerRate`, `margin`, driver/truck fields, `lastLocation` and `eta`.
- `GET /api/config` (public) returns `weightUnit`, `currency`, `equipment` and the sign-up mode.
- `POST /api/admin/users` (admin) adds a team member; `PATCH /api/admin/users/:id` changes `role` and/or `active`. Changes sign the user out immediately.
- `GET /api/shipments/search?page=&limit=&status=&q=&equipment=&sort=` returns one page (`items`, `total`, `pages`, `statusCounts`); `GET /api/alerts` returns the notification counts. Both are computed in SQL, so they stay correct at any volume.

### AI agents and integrations

| Agent | What it does | Needs |
|---|---|---|
| **FLOW** | `POST /api/agents/flow/parse` `{text}` turns a customer's email / WhatsApp message into a shipment draft (weight converted to the configured unit, missing fields listed, questions to ask). Nothing is saved: a person reviews the form and presses Create. | `OPENROUTER_API_KEY` |
| **SCOUT** | `GET /api/agents/scout/:id` ranks available carriers by trailer fit, deliveries on the same lane and past problems, and suggests a rate from lane history. Rules, not a language model: free, instant, explainable. | nothing |
| **RELAY** | `POST /api/shipments/:id/messages/draft` drafts a message to the driver, carrier or customer (uz / ru / en templates from the load's real data); `POST /api/shipments/:id/messages` sends it by SMS or WhatsApp. The number always comes from the load record. | Twilio settings to send; drafts and "Copy text" work without |
| **NEXUS** | Reacts to events and leaves **tasks** for a person under *Inbox & tasks*: review an order that arrived by email, book a carrier (SCOUT's top picks), approve drafted messages (booking, pickup details, delivered, "where are you?" for quiet trucks), check a document that differs from the load. It only prepares: nothing is sent, booked or changed until a person presses the button. | nothing (AI only for reading emails) |
| **VAULT** | `POST /api/shipments/:id/documents?type=cmr\|pod\|other&filename=` (raw PDF/JPEG/PNG/WebP body) stores a document; for CMR and proof of delivery an AI model reads it and plain rules compare weight (10% allowance), truck plate, loading and delivery place, customer and date with the load. Differences become a task; the load is never edited. Also `GET .../documents`, `GET .../documents/:docId/file` (always an attachment), `POST .../documents/:docId/extract`, `DELETE`. The file type is checked from the first bytes, size is capped, files are kept per company. | `OPENROUTER_API_KEY` and a model that can read images / PDFs |
| **Email inbox** | `POST /api/integrations/inbox/<company token>` receives incoming email (Postmark JSON, Mailgun and SendGrid Inbound Parse forms incl. multipart with files, generic JSON). Attached PDF/JPEG/PNG/WebP files are kept (type checked from the first bytes, signature logos dropped, files from blocked senders never stored): an email that names a load (`SHP-12` or its reference) puts them on that load and VAULT reads them; otherwise they wait with the email (`GET /api/inbox/:id/attachments/:fileId/file`, `POST /api/inbox/:id/attach {shipmentId}`) and move to the load created from it. Senders can be restricted to an allow-list; duplicates (same Message-ID) are stored once; FLOW reads the email and a task appears. Nothing becomes a load until a person presses *Create load*. Daily cap per company. | an email service that can POST to a URL |
| **ROUTE** | `GET /api/agents/route/:id`: typical transit time on the lane (median of the company's delivered loads), whether the promised dates are realistic, probable arrival, and trucks that unload near the pickup (return loads). Rules only; needs 3 delivered loads on the lane. No map service. | nothing |
| **PULSE** | `GET /api/agents/pulse/:id?rate=&customerRate=`: usual carrier and customer prices on the lane, a suggested customer price, and warnings (price 30%+ off the usual, thin margin, loss). Shown live in the dispatch window; booking at a warned price leaves a task. | nothing |
| **SENTINEL** | `GET /api/agents/sentinel`: open loads at risk (no truck and pickup near, pickup or delivery day passed, ETA after the promised day, missing driver phone / plate, silent truck, undelivered message). Runs every 10 minutes; one task per risk, closed automatically when the risk is gone. | nothing |
| **Delivery reports** | Twilio posts to `/api/integrations/twilio/status/<per-message secret>`; the request must carry a valid `X-Twilio-Signature` for that company's account. Messages show sent / delivered / read / not delivered; a failed message leaves a task. | `PUBLIC_URL` (automatic on Render and Railway) |
| **TRACE (GPS)** | `POST /api/integrations/gps` receives positions from a GPS provider (`Authorization: Bearer <company GPS token>`, body `{"positions":[{"truckPlate","lat","lng","speed","address"}]}`), matches them to the active load by truck plate and stores at most one point per `GPS_MIN_INTERVAL_MINUTES`. Admins create the token under Integrations. | a GPS provider that can POST JSON |

The AI gateway (`ai/gateway.js`) is the only code that talks to a model: OpenRouter, no hard-coded model (`OPENROUTER_MODEL` empty = account default), no `HTTP-Referer` header, 20 s timeout, one retry, per-person hourly limit, and every call logged in `agent_tasks` (agent, model, tokens, time, result) — visible under Analytics → AI agents. Customer text is passed as untrusted data and the model's JSON is validated with the same rules as typed input. No new dependencies (built-in `fetch`).

Tasks: `GET /api/tasks`, `POST /api/tasks/:id/dismiss`, `POST /api/tasks/:id/approve` (sends the drafted message once, optionally edited). Inbox: `GET /api/inbox`, `POST /api/inbox/:id/parse|dismiss`. Settings (admin): `PUT/DELETE /api/settings/messaging` (the company's own Twilio account, checked with Twilio, stored AES-256-GCM encrypted, never returned), `POST /api/settings/inbox/token`, `PUT /api/settings/inbox` (allowed senders).

**Whose Twilio account sends?** A company that connected its own account always uses it. Otherwise only the first company may use the server-wide Twilio settings from the environment; other companies cannot send until they connect their own (or the owner sets `MESSAGING_SHARED_ALL_TENANTS=true`).

### Multiple companies (multi-tenant)

Every user, shipment and carrier belongs to one company (`tenant_id`); every query is scoped to the signed-in user's company and a missing company fails closed. Records of another company behave as if they do not exist (404). The platform owner (the first production admin) adds customer companies with their first administrator under **Companies** (`GET/POST /api/platform/tenants`); each company admin then adds their own team. Data from before this change belongs to company 1.

- `GET /api/carriers` lists carriers with load statistics (loads, active, delivered, exceptions, booked revenue, current load).
- `POST /api/carriers` adds a carrier (`name`, `mode`: Truckload, LTL, Expedited, Reefer, Flatbed, Intermodal; optional `phone`, `contactName`).
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

- `admin`: full access, including adding users, changing roles and disabling accounts.
- `operations`: dashboard/analytics access, team and shipment reads, shipment creation, status changes, carrier dispatch, location updates, and carrier reads and management.
- `operator` (dispatcher): shipment/dashboard reads, shipment creation, location updates and carrier reads. Analytics, team access, dispatch, and status changes are denied by the API.

Permissions are enforced server-side, and the role is read from the database on every request, so an admin's change applies immediately; hiding a UI panel is not the security boundary.

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

## Registration and team

In production sign-up is closed: the administrator adds people under Team Access → Add user. Set `REGISTRATION_INVITE_CODE` to let people sign up with a code, or `ALLOW_OPEN_REGISTRATION=true` for demos. Self-registered accounts are `operator`. In development (`npm run dev`) sign-up stays open.

## Region settings

`WEIGHT_UNIT` (`kg` default, or `lb`), `CURRENCY` (ISO code, default `USD`) and `MAX_RATE` (largest allowed price) configure one deployment for its market. Equipment types include Tent / Curtainsider, common outside North America.

## Security & production notes

- **XSS**: the frontend builds DOM with `textContent`/`createElement` only (no `innerHTML`, `eval`, inline scripts or inline handlers); a test scans the sources for these sinks. CSP is `script-src 'self'`.
- **Auth**: JWT lives only in an HttpOnly, SameSite=Lax cookie (`Secure` in production); sessions are revocable server-side and are revoked when an admin changes or disables the account; login is rate-limited per IP, per account per IP, and per account across all IPs; one bcrypt cost for all hashes (no timing difference between accounts); production never seeds demo users and development listens on 127.0.0.1 only.
- **Dispatch**: assignment and status changes run in a single SQLite transaction, so two operators cannot book the same carrier or load.
- **Validation**: strict IDs, ISO dates, positive bounded numbers, 50 kb JSON limit; malformed input returns 400, never a 500.
- **Errors**: a global handler returns generic messages; details are logged server-side only.
- **Database**: foreign keys enforced, indexes on hot queries, `npm run db:check` runs `PRAGMA integrity_check` and `foreign_key_check`.
- **Production start**: `NODE_ENV=production`, `JWT_SECRET` and (first start only) `INITIAL_ADMIN_NAME/EMAIL/PASSWORD` (12+ chars) are required; the server refuses to start without them.
- **Tests**: `npm test` (90 tests: auth, rate limits, transactions, validation, security headers, carriers, analytics, XSS, truck workflow, team management, production mode, company isolation, FLOW / SCOUT / RELAY with fake providers, GPS, paging, NEXUS tasks and approvals, email inbox, document upload and reading, per-company Twilio and secret encryption).
- **Dependencies**: `npm audit` reports 0 vulnerabilities at the time of release.
