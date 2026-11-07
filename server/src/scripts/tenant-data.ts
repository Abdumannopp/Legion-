/**
 * Operator tool for a workspace's data lifecycle (see DATA-RETENTION.md).
 *
 *   npm run tenant:data -w server -- plan     --tenant <uuid>
 *   npm run tenant:data -w server -- delete   --tenant <uuid> --confirm "<exact workspace name>" [--reason "…"]
 *   npm run tenant:data -w server -- hold     --tenant <uuid>
 *   npm run tenant:data -w server -- release  --tenant <uuid>
 *   npm run tenant:data -w server -- expired  --days 30
 *   npm run tenant:data -w server -- replay   --ledger /path/ledger.jsonl [--apply]
 *
 * `plan` and `replay` (without --apply) change nothing. `delete` is irreversible.
 */
import "dotenv/config";
import { closePool, migrate, query } from "../db/pool.js";
import * as store from "../store.js";
import { deleteTenant, expiredWorkspaces, planDeletion, replayLedger } from "../tenant-deletion.js";

const [command, ...rest] = process.argv.slice(2);
const flag = (name: string): string | undefined => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : undefined; };
const usage = () => { console.error("usage: tenant-data <plan|delete|hold|release|expired|replay> [--tenant uuid] [--confirm name] [--days n] [--ledger file] [--apply]"); process.exit(2); };

async function main() {
  if (!command) return usage();
  await migrate();
  const tenantId = flag("tenant");
  switch (command) {
    case "plan": {
      if (!tenantId) return usage();
      const p = await planDeletion(tenantId);
      console.log(JSON.stringify(p, null, 2));
      if (p.blockers.length) process.exitCode = 1;
      break;
    }
    case "delete": {
      if (!tenantId || flag("confirm") === undefined) return usage();
      const r = await deleteTenant(tenantId, { by: "operator", confirmName: flag("confirm"), reason: flag("reason") });
      console.log(`Erased workspace ${r.tenantId}.`);
      console.log(JSON.stringify(r.counts));
      break;
    }
    case "hold":
    case "release": {
      if (!tenantId || !(await store.tenantExists(tenantId))) { console.error("Unknown tenant"); process.exit(1); }
      await query("UPDATE tenants SET legal_hold = $2 WHERE id = $1", [tenantId, command === "hold"]);
      await store.audit({ tenant_id: tenantId, user_id: null, user_email: "cli", action: command === "hold" ? "legal.hold_set" : "legal.hold_released", resource_type: "tenant", resource_id: tenantId, detail: null, ip_address: null });
      console.log(command === "hold" ? "Legal hold set: retention jobs skip this workspace and it cannot be erased." : "Legal hold released.");
      break;
    }
    case "expired": {
      const rows = await expiredWorkspaces(Number(flag("days") ?? 30));
      console.table(rows);
      break;
    }
    case "replay": {
      const file = flag("ledger");
      if (!file) return usage();
      const found = await replayLedger(file, { dryRun: !rest.includes("--apply") });
      console.log(found.length ? `${rest.includes("--apply") ? "Erased" : "Would erase"} ${found.length} workspace(s) that a restore brought back:\n${found.join("\n")}` : "Nothing to replay: every workspace in the ledger is already gone.");
      break;
    }
    default: return usage();
  }
}

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; }).finally(() => closePool());
