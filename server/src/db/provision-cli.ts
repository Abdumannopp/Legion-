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
 * F-02, owner/runtime split (DB_ROLE_SPLIT=on; the Docker installs set it):
 * the schema is owned by legion_owner (cannot log in), this step applies the
 * migrations as that owner, and the API's role gets data privileges only — it
 * cannot ALTER, DROP, TRUNCATE or disable a trigger, and erases audit rows
 * only through the bounded functions of migration 0008. The API then checks
 * the schema at boot instead of migrating it, so run this step after every
 * upgrade (docker compose does: db-provision runs before the backend).
 *
 * Deliberately does not import config.ts: it must not need (or see) the
 * API's secrets.
 */
import pg from "pg";
import { DEFAULT_APP_ROLE, DEFAULT_OWNER_ROLE, grantRuntimePrivileges, provisionAppRole } from "./provision.js";
import { runMigrations } from "./migrator.js";

const adminUrl = process.env.DATABASE_ADMIN_URL;
const appPassword = process.env.APP_DB_PASSWORD ?? "";
const appUser = process.env.APP_DB_USER || DEFAULT_APP_ROLE;
const ownerRole = process.env.DB_OWNER_ROLE || DEFAULT_OWNER_ROLE;
const splitFlag = (process.env.DB_ROLE_SPLIT ?? "off").toLowerCase();
if (!["on", "off"].includes(splitFlag)) {
  console.error("provision-cli: DB_ROLE_SPLIT must be on or off.");
  process.exit(2);
}
const split = splitFlag === "on";

if (!adminUrl) {
  console.error("provision-cli: DATABASE_ADMIN_URL is not set.");
  process.exit(2);
}

const client = new pg.Client({ connectionString: adminUrl, connectionTimeoutMillis: 10_000 });
try {
  await client.connect();
  const r = await provisionAppRole(client, { appUser, appPassword, split, ownerRole });
  console.info(`provision-cli: role ${r.role} ${r.created ? "created" : "verified"}` +
    (r.transferred.length ? `; ownership of ${r.transferred.length} object(s) moved to ${r.owner}` : "") +
    (r.revokedMemberships.length ? `; removed role memberships: ${r.revokedMemberships.join(", ")}` : ""));
  if (split) {
    // Migrate as the owner, so everything the migrations create belongs to it, not to the superuser.
    const ownerPool = new pg.Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 10_000, options: `-c role=${ownerRole}` });
    try {
      await runMigrations(ownerPool);
    } finally {
      await ownerPool.end();
    }
    await grantRuntimePrivileges(client, { appUser, ownerRole });
    console.info(`provision-cli: schema migrated as ${ownerRole}; ${appUser} has data privileges only`);
  }
  await client.end();
  process.exit(0);
} catch (err) {
  console.error(`provision-cli failed: ${err instanceof Error ? err.message : String(err)}`);
  await client.end().catch(() => {});
  process.exit(1);
}
