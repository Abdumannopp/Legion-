/**
 * Operator tool for secrets at rest (see secrets-migration.ts).
 *
 *   npm run secrets -w server -- status      which keys are in use (ids and counts only)
 *   npm run secrets -w server -- reencrypt   move everything to the active key now
 *
 * Key rotation:
 *   1. generate a key:   openssl rand -hex 32
 *   2. put it FIRST in LEGION_ENCRYPTION_KEYS, keeping the old entry after it
 *      (e.g. "k2:<new>,k1:<old>"), and restart — boot re-encrypts everything;
 *   3. run `status`: when no row uses k1 any more, remove k1 and restart.
 * Removing a key that is still in use makes those secrets unreadable; MFA then
 * refuses sign-in (it is never switched off) until the key is put back.
 */
import "dotenv/config";
import { closePool, migrate } from "../db/pool.js";
import { describeReport, migrateSecretsAtRest, secretsStatus } from "../secrets-migration.js";

async function main() {
  const command = process.argv[2];
  await migrate();
  if (command === "status") {
    console.log(JSON.stringify(await secretsStatus(), null, 2));
  } else if (command === "reencrypt") {
    const report = await migrateSecretsAtRest();
    console.log(describeReport(report));
    if (report.mfa.unreadable || report.webhook.unreadable) process.exitCode = 2;
  } else {
    console.error("usage: secrets <status|reencrypt>");
    process.exitCode = 2;
  }
}

main()
  .catch((error) => { console.error(error instanceof Error ? error.message : "failed"); process.exitCode = 1; })
  .finally(() => closePool());
