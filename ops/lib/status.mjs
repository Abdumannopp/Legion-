#!/usr/bin/env node
// Backup status file: a small JSON document that answers "is Legion's backup
// healthy?" without anyone reading logs. Written by ops/backup.sh and
// ops/verify-backup.sh, read by ops/check-backup.sh and GET /health/backup.
//
//   node status.mjs FILE set key=value [key=value …]   merge fields (atomic write)
//   node status.mjs FILE check                          print problems; exit 1 if any
//   node status.mjs FILE get key                        print one field
//
// Values are strings; `n:123` is a number, `null` is null. The file holds
// timestamps, sizes, file NAMES and failure reasons — never keys, URLs or data.
import { readFileSync, writeFileSync, renameSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";

export function evaluate(status, now = Date.now(), opts = {}) {
  const maxAgeH = opts.maxAgeHours ?? 30;
  const restoreMaxDays = opts.restoreMaxDays ?? 8;
  const requireOffsite = opts.requireOffsite ?? false;
  const problems = [];
  const t = (v) => (v ? Date.parse(v) : NaN);
  if (!status) return { ok: false, state: "unknown", problems: ["no backup status recorded — the backup has never run"] };
  const ok = t(status.last_success_at), bad = t(status.last_failure_at);
  if (Number.isNaN(ok)) problems.push("no successful backup has ever been recorded");
  else if (now - ok > maxAgeH * 3_600_000) problems.push(`last successful backup is ${Math.floor((now - ok) / 3_600_000)}h old (limit ${maxAgeH}h)`);
  if (!Number.isNaN(bad) && (Number.isNaN(ok) || bad > ok)) problems.push(`the most recent backup run failed: ${status.last_failure_reason || "unknown reason"}`);
  if (status.encrypted === "false") problems.push("the last backup was NOT encrypted");
  const rt = t(status.restore_tested_at);
  if (status.restore_test_result === "failed") problems.push("the last restore test FAILED");
  else if (Number.isNaN(rt)) problems.push("no successful restore test has been recorded");
  else if (now - rt > restoreMaxDays * 86_400_000) problems.push(`last successful restore test is ${Math.floor((now - rt) / 86_400_000)} days old (limit ${restoreMaxDays})`);
  if (status.offsite_result === "failed") problems.push("the last off-server copy failed");
  else if (requireOffsite && !status.offsite_uploaded_at) problems.push("no off-server copy has been recorded");
  const state = problems.length === 0 ? "ok" : Number.isNaN(ok) ? "unknown" : (!Number.isNaN(bad) && bad > ok) ? "failing" : "stale";
  return { ok: problems.length === 0, state, problems };
}

function load(file) { try { return JSON.parse(readFileSync(file, "utf8")); } catch { return null; } }

function main() {
  const [file, cmd, ...rest] = process.argv.slice(2);
  if (!file || !cmd) { console.error("usage: status.mjs FILE set|check|get …"); process.exit(2); }
  if (cmd === "set") {
    const cur = load(file) ?? {};
    for (const kv of rest) {
      const i = kv.indexOf("="); if (i < 1) continue;
      const k = kv.slice(0, i); const v = kv.slice(i + 1);
      cur[k] = v === "null" ? null : v.startsWith("n:") ? Number(v.slice(2)) : v;
    }
    const tmp = join(dirname(file), `.status.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(cur, null, 2) + "\n", { mode: 0o644 });
    chmodSync(tmp, 0o644);
    renameSync(tmp, file);
  } else if (cmd === "get") {
    const v = load(file)?.[rest[0]]; if (v != null) console.log(v);
  } else if (cmd === "check") {
    const r = evaluate(load(file), Date.now(), {
      maxAgeHours: Number(process.env.BACKUP_MAX_AGE_HOURS || 30),
      restoreMaxDays: Number(process.env.RESTORE_TEST_MAX_AGE_DAYS || 8),
      requireOffsite: process.env.BACKUP_REQUIRE_OFFSITE === "true",
    });
    for (const p of r.problems) console.log(p);
    process.exit(r.ok ? 0 : 1);
  } else { console.error("unknown command"); process.exit(2); }
}
if (import.meta.url === `file://${process.argv[1]}`) main();
