/**
 * Operator tool for sensor webhook credentials — for the person with shell
 * access to the server (self-hosted installs, break-glass on hosted ones).
 * Administrators can do the same through the API (GET/POST/DELETE
 * /security-events/credentials).
 *
 *   npm run webhook:credential -w server -- list         --tenant <uuid>
 *   npm run webhook:credential -w server -- create       --tenant <uuid> [--label "wazuh-manager-1"]
 *   npm run webhook:credential -w server -- rotate       --tenant <uuid> --key whk_… [--overlap-hours 24]
 *   npm run webhook:credential -w server -- revoke       --tenant <uuid> --key whk_…
 *   npm run webhook:credential -w server -- revoke-all   --tenant <uuid>
 *
 * `create` and `rotate` print the new secret exactly once, on stdout, and
 * nowhere else: not to the audit log, not to the server log.
 */
import "dotenv/config";
import { closePool, migrate } from "../db/pool.js";
import * as store from "../store.js";
import * as creds from "../webhook-credentials.js";
import { isKeyId } from "../webhook-auth.js";

const [command, ...rest] = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};

const usage = () => {
  console.error("usage: webhook-credential <list|create|rotate|revoke|revoke-all> --tenant <uuid> [--key whk_…] [--label text] [--overlap-hours n]");
  process.exit(2);
};

async function audit(tenantId: string, action: string, resourceId: string | null, detail: string | null = null) {
  await store.audit({ tenant_id: tenantId, user_id: null, user_email: "cli", action, resource_type: "webhook_credential", resource_id: resourceId, detail, ip_address: null });
}

async function main() {
  const tenantId = flag("tenant");
  if (!command || !tenantId) return usage();
  if (!(await store.tenantExists(tenantId))) { console.error("Unknown tenant"); process.exit(1); }
  await migrate();
  const keyId = flag("key");
  if (["rotate", "revoke"].includes(command) && !isKeyId(keyId)) return usage();

  switch (command) {
    case "list":
      console.table((await creds.listCredentials(tenantId)).map((c) => ({ id: c.id, label: c.label, status: c.status, expires_at: c.expires_at, last_used_at: c.last_used_at })));
      break;
    case "create": {
      const issued = await creds.createCredential(tenantId, { label: flag("label") });
      await audit(tenantId, "webhook.credential_created", issued.id);
      console.log(`Created ${issued.id}. Put this in ossec.conf as <api_key> — it is shown only now:\n\n${issued.api_key}\n`);
      break;
    }
    case "rotate": {
      const hours = flag("overlap-hours");
      const { issued, previous } = await creds.rotateCredential(tenantId, keyId!, { overlapHours: hours === undefined ? undefined : Number(hours) });
      await audit(tenantId, "webhook.credential_rotated", keyId!, `replaced by ${issued.id}`);
      console.log(`Created ${issued.id}. The old credential ${previous.id} keeps working until ${previous.expires_at}.\nNew <api_key> — shown only now:\n\n${issued.api_key}\n`);
      break;
    }
    case "revoke":
      await creds.revokeCredential(tenantId, keyId!);
      await audit(tenantId, "webhook.credential_revoked", keyId!);
      console.log(`Revoked ${keyId}. It stopped working immediately.`);
      break;
    case "revoke-all": {
      const n = await creds.revokeAllCredentials(tenantId);
      await audit(tenantId, "webhook.credential_revoked", null, `all (${n})`);
      console.log(`Revoked ${n} credential(s). Every sensor for this organisation is now refused.`);
      break;
    }
    default:
      return usage();
  }
}

main()
  .catch((error) => { console.error(error instanceof Error ? error.message : "failed"); process.exitCode = 1; })
  .finally(() => closePool());
