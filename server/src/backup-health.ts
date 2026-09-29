/**
 * Backup health for monitoring. ops/backup.sh and ops/verify-backup.sh record
 * what happened in a small JSON status file; this reads it and answers "is the
 * backup healthy?" — including the case no script can report about itself: the
 * backup that stopped running (a stale last_success_at).
 *
 * The rules are the same ones ops/lib/status.mjs applies for ops/check-backup.sh
 * (tests/backup-health.test.ts feeds both the same cases so they cannot drift).
 * The file holds timestamps, sizes, file names and failure reasons — no keys,
 * URLs or data — and the endpoint that serves it is token-protected.
 */
import { readFile } from "node:fs/promises";

export interface BackupStatus {
  last_success_at?: string | null;
  last_failure_at?: string | null;
  last_failure_reason?: string | null;
  last_failure_stage?: string | null;
  last_backup_file?: string | null;
  last_backup_bytes?: number | null;
  encrypted?: string | null;
  restore_tested_at?: string | null;
  restore_test_result?: string | null;
  offsite_uploaded_at?: string | null;
  offsite_result?: string | null;
}

export interface BackupHealthOptions { maxAgeHours: number; restoreMaxDays: number; requireOffsite: boolean }
export interface BackupHealth { ok: boolean; state: "ok" | "stale" | "failing" | "unknown"; problems: string[] }

export function evaluateBackupStatus(status: BackupStatus | null, now: number, opts: BackupHealthOptions): BackupHealth {
  if (!status) return { ok: false, state: "unknown", problems: ["no backup status recorded — the backup has never run"] };
  const problems: string[] = [];
  const t = (v?: string | null) => (v ? Date.parse(v) : NaN);
  const ok = t(status.last_success_at), bad = t(status.last_failure_at);
  if (Number.isNaN(ok)) problems.push("no successful backup has ever been recorded");
  else if (now - ok > opts.maxAgeHours * 3_600_000) problems.push(`last successful backup is ${Math.floor((now - ok) / 3_600_000)}h old (limit ${opts.maxAgeHours}h)`);
  if (!Number.isNaN(bad) && (Number.isNaN(ok) || bad > ok)) problems.push(`the most recent backup run failed: ${status.last_failure_reason || "unknown reason"}`);
  if (status.encrypted === "false") problems.push("the last backup was NOT encrypted");
  const rt = t(status.restore_tested_at);
  if (status.restore_test_result === "failed") problems.push("the last restore test FAILED");
  else if (Number.isNaN(rt)) problems.push("no successful restore test has been recorded");
  else if (now - rt > opts.restoreMaxDays * 86_400_000) problems.push(`last successful restore test is ${Math.floor((now - rt) / 86_400_000)} days old (limit ${opts.restoreMaxDays})`);
  if (status.offsite_result === "failed") problems.push("the last off-server copy failed");
  else if (opts.requireOffsite && !status.offsite_uploaded_at) problems.push("no off-server copy has been recorded");
  const state = problems.length === 0 ? "ok" : Number.isNaN(ok) ? "unknown" : (!Number.isNaN(bad) && bad > ok) ? "failing" : "stale";
  return { ok: problems.length === 0, state, problems };
}

export async function readBackupStatus(file: string): Promise<BackupStatus | null> {
  try { return JSON.parse(await readFile(file, "utf8")) as BackupStatus; } catch { return null; }
}

/** What the monitoring endpoint returns: verdict, ages and the last file — nothing sensitive. */
export async function backupHealthReport(file: string, opts: BackupHealthOptions, now = Date.now()) {
  const status = await readBackupStatus(file);
  const health = evaluateBackupStatus(status, now, opts);
  const age = (v?: string | null) => (v && !Number.isNaN(Date.parse(v)) ? Math.max(0, Math.floor((now - Date.parse(v)) / 1000)) : null);
  return {
    status: health.state,
    healthy: health.ok,
    problems: health.problems,
    last_backup_age_seconds: age(status?.last_success_at),
    last_restore_test_age_seconds: age(status?.restore_tested_at),
    last_offsite_age_seconds: age(status?.offsite_uploaded_at),
    last_backup_bytes: status?.last_backup_bytes ?? null,
    encrypted: status ? status.encrypted !== "false" : null,
  };
}
