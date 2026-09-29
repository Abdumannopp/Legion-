/**
 * First-run setup token for self-hosted installs.
 *
 * Problem this solves: on a brand-new install nobody has an account, so "who
 * may create the first administrator" cannot be answered by a login. Before
 * this existed, the answer was "whoever reaches the setup step first" — and on
 * a server reachable from the internet that can be a stranger scanning ports.
 *
 * The answer now is "whoever can read this server's console". At startup, while
 * no workspace exists, the server prints a random one-time token. Creating the
 * first administrator requires it. Reading it requires access to the machine
 * Legion was installed on, which is exactly the person who installed it.
 *
 * Only the SHA-256 of the token is stored, so a leaked database or backup does
 * not reveal it. The token is also written to a file (owner-only permissions)
 * so a restart or a closed terminal does not lose it.
 */
import { createHash, randomBytes } from "node:crypto";
import { chmod, readFile, unlink, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type pg from "pg";
import { queryOne, transaction } from "./db/pool.js";

/** Advisory-lock key serialising everything about first-run setup, across
 *  every Legion process sharing this database. Arbitrary but fixed. */
export const SETUP_LOCK_KEY = 7_347_101;

export const SETUP_TOKEN_FILE = resolve(
  process.cwd(),
  process.env.SETUP_TOKEN_FILE || ".legion-setup-token"
);

const hash = (token: string) => createHash("sha256").update(token, "utf8").digest("hex");

/** Issues a fresh token, replacing any previous one. Returns the plaintext —
 *  the only time it exists outside the operator's screen and file. */
export async function issueSetupToken(): Promise<string> {
  const token = `lst_${randomBytes(32).toString("base64url")}`;
  await queryOne(
    `INSERT INTO setup_token (id, token_hash, created_at) VALUES (1, $1, now())
     ON CONFLICT (id) DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = now()`,
    [hash(token)]
  );
  return token;
}

/**
 * Inside the caller's transaction: consume the token if — and only if — it
 * matches. The DELETE is the check, so two requests presenting the same token
 * cannot both succeed: the second finds nothing to delete.
 */
export async function consumeSetupToken(client: pg.PoolClient, token: unknown): Promise<boolean> {
  if (typeof token !== "string" || token.length < 10 || token.length > 200) return false;
  const result = await client.query(
    "DELETE FROM setup_token WHERE token_hash = $1 RETURNING 1",
    [hash(token)]
  );
  return (result.rowCount ?? 0) === 1;
}

export type SetupTokenState =
  | { kind: "not-needed" }
  | { kind: "issued"; token: string; reused: boolean }
  | { kind: "issued-elsewhere"; since: Date };

/**
 * Called once at startup. Decides whether a token is needed and makes sure
 * one exists, under the setup lock so several instances booting together do
 * not each overwrite the others' token.
 */
export async function ensureSetupToken(): Promise<SetupTokenState> {
  return transaction(async (client) => {
    await client.query("SELECT pg_advisory_xact_lock($1)", [SETUP_LOCK_KEY]);

    const setUp = await client.query("SELECT 1 FROM tenants LIMIT 1");
    if (setUp.rowCount) {
      // Already set up: nothing may remain that could create another admin.
      await client.query("DELETE FROM setup_token");
      await unlink(SETUP_TOKEN_FILE).catch(() => {});
      return { kind: "not-needed" };
    }

    const existing = await client.query<{ token_hash: string; created_at: Date }>(
      "SELECT token_hash, created_at FROM setup_token WHERE id = 1"
    );
    const row = existing.rows[0];

    // Restart on the same machine: the token on disk is still the valid one,
    // so show it again instead of invalidating what the operator already has.
    const onDisk = await readFile(SETUP_TOKEN_FILE, "utf8").then((s) => s.trim()).catch(() => "");
    if (row && onDisk && hash(onDisk) === row.token_hash) {
      return { kind: "issued", token: onDisk, reused: true };
    }

    // Another instance issued one moments ago; don't clobber it.
    if (row && Date.now() - new Date(row.created_at).getTime() < 10 * 60_000) {
      return { kind: "issued-elsewhere", since: new Date(row.created_at) };
    }

    const token = `lst_${randomBytes(32).toString("base64url")}`;
    await client.query(
      `INSERT INTO setup_token (id, token_hash, created_at) VALUES (1, $1, now())
       ON CONFLICT (id) DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = now()`,
      [hash(token)]
    );
    await writeFile(SETUP_TOKEN_FILE, `${token}\n`, { mode: 0o600 });
    await chmod(SETUP_TOKEN_FILE, 0o600).catch(() => {}); // Windows ignores POSIX modes
    return { kind: "issued", token, reused: false };
  });
}

/** After the first administrator exists the file is useless and should go. */
export async function removeSetupTokenFile(): Promise<void> {
  await unlink(SETUP_TOKEN_FILE).catch(() => {});
}

/** The console banner. Deliberately loud: this is the one thing the operator
 *  must notice on first start. */
export function setupBanner(state: SetupTokenState, dashboardUrl: string): string {
  if (state.kind === "not-needed") return "";
  if (state.kind === "issued-elsewhere") {
    return [
      "",
      "  Legion is not set up yet. Another Legion process issued the setup token",
      `  at ${state.since.toISOString()} — use the token printed in that process's log.`,
      "",
    ].join("\n");
  }
  const line = "=".repeat(72);
  return [
    "",
    line,
    "  FIRST-RUN SETUP",
    "",
    "  Nobody can use this Legion yet. To create the first administrator, open",
    `    ${dashboardUrl}/setup`,
    "  and enter this one-time setup token:",
    "",
    `    ${state.token}`,
    "",
    `  It is also saved in ${SETUP_TOKEN_FILE} (readable only by you).`,
    "  It stops working the moment the first administrator is created.",
    "  Anyone who has it can take over this installation — do not share it.",
    line,
    "",
  ].join("\n");
}
