/**
 * One-shot, optional database hardening step, run by hand (or from a deploy
 * script) before the API starts. It alone holds the superuser password; the
 * API gets only the app role's.
 *
 * `npm run setup` already creates a non-superuser role for you, so this is
 * not required to run Legion. Run it when you want the API's database
 * connection locked down further than that default role — no ownership of
 * the whole database, no ability to create more roles or databases, and
 * every privilege re-checked (and stripped if drifted) each time this runs:
 *
 *   DATABASE_ADMIN_URL=postgresql://legion:…@localhost:5432/legion \
 *   APP_DB_USER=legion_app APP_DB_PASSWORD=… node dist/db/provision-cli.js
 *
 * Then point the API's own DATABASE_URL at that role instead.
 *
 * Deliberately does not import config.ts: it must not need (or see) the
 * API's secrets.
 */
import pg from "pg";
import { DEFAULT_APP_ROLE, provisionAppRole } from "./provision.js";

const adminUrl = process.env.DATABASE_ADMIN_URL;
const appPassword = process.env.APP_DB_PASSWORD ?? "";
const appUser = process.env.APP_DB_USER || DEFAULT_APP_ROLE;

if (!adminUrl) {
  console.error("provision-cli: DATABASE_ADMIN_URL is not set.");
  process.exit(2);
}

const client = new pg.Client({ connectionString: adminUrl, connectionTimeoutMillis: 10_000 });
try {
  await client.connect();
  const r = await provisionAppRole(client, { appUser, appPassword });
  console.info(`provision-cli: role ${r.role} ${r.created ? "created" : "verified"}` +
    (r.transferred.length ? `; ownership moved for ${r.transferred.length} object(s) from an earlier install` : "") +
    (r.revokedMemberships.length ? `; removed role memberships: ${r.revokedMemberships.join(", ")}` : ""));
  await client.end();
  process.exit(0);
} catch (err) {
  console.error(`provision-cli failed: ${err instanceof Error ? err.message : String(err)}`);
  await client.end().catch(() => {});
  process.exit(1);
}
