# Data retention, export and deletion

What Legion keeps, for how long, and the tools that enforce it. Hosted installations only;
a self-hosted installation keeps its data for as long as its owner likes.

| Data | Kept | How it is enforced |
|---|---|---|
| Resolved alerts | By plan: Starter 30 days … Enterprise 365 | `pruneAlertsByPlan` (open alerts are never deleted) |
| Payment checks | 24 months (`RETENTION_PAYMENT_MONTHS`) | `prunePaymentChecks` |
| Audit log: e-mail, IP, e-mail-like text in `detail` | 24 months (`RETENTION_AUDIT_MONTHS`), then removed. The entry itself stays | `pseudonymiseAudit` |
| Agent logs (identity audit, firewall decisions, content scans, tool calls) | 24 months (`RETENTION_AGENT_LOG_MONTHS`); the oldest rows of each chain are deleted | `pruneAgentLogs` |
| Backups | Up to 12 months | Local: `prune-backups.sh` (14 daily, 8 weekly, 12 monthly). **Off-server: the storage's lifecycle rule, which you must set to 12 months.** Deletions are re-applied after a restore (below) |

All jobs skip a workspace on a **legal hold** (`tenants.legal_hold`).

### How the agent logs are pruned

These logs are hash-chained, so a row cannot be edited to remove personal data; the oldest rows are deleted instead.
Only a contiguous prefix of a chain goes, and the newest row always stays. The hash of the last deleted row is
kept in `chain_prune_anchors`, and `verifyChain` starts from it, so the remaining history is still proven unaltered.
Not pruned: kill-switch events, agent behaviour events, agent-to-agent interactions and trust-graph snapshots
(no message content or addresses; they stay as the record of what was stopped and why).

## Export

Admins download everything their workspace holds: Settings → Data export
(`GET /workspace/export`, 3 per hour, audited as `workspace.exported`). Format: `legion-workspace-export/1`.
Export stays available while a workspace is locked.

## Deleting a workspace

Irreversible, so deliberate. From `server/`:

```bash
npm run tenant:data -- plan   <tenant-id>                       # dry run: blockers and row counts
npm run tenant:data -- delete <tenant-id> --confirm "<exact name>"
npm run tenant:data -- hold   <tenant-id>                       # legal hold on
npm run tenant:data -- release <tenant-id>                      # legal hold off
npm run tenant:data -- expired --days 90                        # locked workspaces past the period
```

Refused while: a legal hold is set; a paid subscription is active/trialing/past due; someone whose
account lives in this workspace also belongs to another one.

Deletion runs in one transaction, then leaves:
- a **tombstone** (`tenant_deletions`): id, time, who, reason, row counts. No personal data;
- a **ledger line** in `DELETION_LEDGER_FILE`, written after commit and kept outside the database.

The append-only audit logs are only erasable inside this transaction, through the transaction-local
switch `legion.audit_erasure`; nothing else can remove them.

### After restoring a backup

```bash
npm run tenant:data -- replay --ledger "$DELETION_LEDGER_FILE"            # list
npm run tenant:data -- replay --ledger "$DELETION_LEDGER_FILE" --apply    # erase again
```

### Automatic deletion (OFF by default)

`TENANT_AUTO_DELETE_DAYS=N` turns on the job for workspaces locked for more than N days. It never deletes without warning:

1. **Warning.** The first time a workspace qualifies, its active administrators (and the notification address) are
   e-mailed: the date it will be erased, what goes, how to stop it (subscribe again), and how to download a copy
   (Settings → Data export, which works while locked). Nothing is deleted yet.
2. **Wait.** The date is `TENANT_DELETE_NOTICE_DAYS` later (default 30, never fewer than 7).
3. **Erasure.** After that date, if the workspace is still locked, it is erased like a manual deletion; the tombstone
   records that it was warned and when.
4. **Cancelled** (and the notice cleared) if the workspace is subscribed again or put on a legal hold meanwhile.

If mail is not configured, sending fails, or there is no administrator to tell, **the workspace is not deleted** and
stays unwarned. `npm run tenant:data -- expired --days N` shows each workspace's notice and scheduled date.
Only one instance runs the job at a time, so one warning is sent. There is no second reminder.

## Honest limits

- Pruning the agent logs removes history, including what an investigation might need: keep a workspace on legal hold when that matters.
- A person with write access to the database can edit `chain_prune_anchors` together with the log, as they can already switch the erasure flag on. The chain protects against edits by the application, not against a database administrator.
- A backup older than 12 months is gone; younger ones can hold deleted data until they expire, hence the replay step.
- Legal retention duties (tax, disputes) are for a lawyer to decide: see LEGAL-DECISIONS.md.
