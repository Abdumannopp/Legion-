# Data retention, export and deletion

What Legion keeps, for how long, and the tools that enforce it. Hosted installations only;
a self-hosted installation keeps its data for as long as its owner likes.

| Data | Kept | How it is enforced |
|---|---|---|
| Resolved alerts | By plan: Starter 30 days … Enterprise 365 | `pruneAlertsByPlan` (open alerts are never deleted) |
| Payment checks | 24 months (`RETENTION_PAYMENT_MONTHS`) | `prunePaymentChecks` |
| Audit log: e-mail, IP, e-mail-like text in `detail` | 24 months (`RETENTION_AUDIT_MONTHS`), then removed. The entry itself stays | `pseudonymiseAudit` |
| Backups | Up to 12 months | Backup rotation; deletions are re-applied after a restore (below) |

All jobs skip a workspace on a **legal hold** (`tenants.legal_hold`).

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

`TENANT_AUTO_DELETE_DAYS=N` erases workspaces locked for more than N days. It is **off** because Legion
does not yet send a warning before deleting. Turn it on only with a notice process in place.

## Honest limits

- Agent-layer logs (identity, firewall decisions) are not pseudonymised on a schedule; they go when the workspace is erased.
- A backup older than 12 months is gone; younger ones can hold deleted data until they expire, hence the replay step.
- Legal retention duties (tax, disputes) are for a lawyer to decide: see LEGAL-DECISIONS.md.
