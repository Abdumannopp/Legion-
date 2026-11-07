/**
 * Operator tool: set a workspace's plan by hand — for a contract (Enterprise is
 * sold by agreement, so there is no checkout for it) or a goodwill upgrade.
 * An override wins over the subscription; clearing it returns to whatever the
 * subscription (or the trial) says.
 *
 *   npm run plan -w server -- show  --tenant <uuid>
 *   npm run plan -w server -- set   --tenant <uuid> --plan starter|professional|business|enterprise
 *   npm run plan -w server -- clear --tenant <uuid>
 */
import "dotenv/config";
import { closePool, migrate, query } from "../db/pool.js";
import { resolvePlan } from "../plan-limits.js";
import { isPlanId, PLAN_IDS } from "../plans.js";
import * as store from "../store.js";

const [command, ...rest] = process.argv.slice(2);
const flag = (name: string): string | undefined => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : undefined; };
const usage = () => { console.error(`usage: plan <show|set|clear> --tenant <uuid> [--plan ${PLAN_IDS.join("|")}]`); process.exit(2); };

async function main() {
  const tenantId = flag("tenant");
  if (!command || !tenantId) return usage();
  await migrate();
  if (!(await store.tenantExists(tenantId))) { console.error("Unknown tenant"); process.exit(1); }
  switch (command) {
    case "show": {
      const p = await resolvePlan(tenantId);
      console.log(`${p.plan} (${p.source})${p.addons.length ? ` + ${p.addons.join(", ")}` : ""}`);
      break;
    }
    case "set": {
      const plan = flag("plan");
      if (!isPlanId(plan)) return usage();
      await query("UPDATE tenants SET plan_override = $2 WHERE id = $1", [tenantId, plan]);
      await store.audit({ tenant_id: tenantId, user_id: null, user_email: "cli", action: "billing.plan_override_set", resource_type: "tenant", resource_id: tenantId, detail: plan, ip_address: null });
      console.log(`Plan set to ${plan}.`);
      break;
    }
    case "clear":
      await query("UPDATE tenants SET plan_override = NULL WHERE id = $1", [tenantId]);
      await store.audit({ tenant_id: tenantId, user_id: null, user_email: "cli", action: "billing.plan_override_cleared", resource_type: "tenant", resource_id: tenantId, detail: null, ip_address: null });
      console.log("Plan override cleared.");
      break;
    default: return usage();
  }
}

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exitCode = 1; }).finally(() => closePool());
