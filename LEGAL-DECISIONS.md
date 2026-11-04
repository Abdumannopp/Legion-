# Legal answers: what was adopted

Source: "Legion Global Legal Answers", a counsel-review **draft**. It is **not** approved by a lawyer.
Every item below must be confirmed by one before it is relied on. See LEGAL-QUESTIONS.md for the questions.

## Built

| Recommendation | Where |
|---|---|
| Backups kept up to 12 months; deletions re-applied after restore | privacy text, DATA-RETENTION.md, RECOVERY.md |
| Cloudflare listed as a sub-processor | privacy text |
| Payment checks deleted after 24 months | `retention.ts` |
| Audit-log personal data removed after 24 months | `retention.ts` |
| Warning e-mail to the administrators before an automatic deletion; erasure only after the notice period (automatic deletion is still OFF by default) | `tenant-deletion.ts` `autoDeleteExpired` |
| Agent logs pruned after 24 months (oldest rows; chain stays verifiable) | `retention.ts` `pruneAgentLogs` |
| Legal hold | `tenants.legal_hold`, `tenant:data hold` |
| Customer data export | Settings → Data export |
| Workspace erasure with proof, restore replay | `tenant-deletion.ts` |
| Written acknowledgement before automatic blocking (versioned, recorded) | Defense page, `PATCH /security/auto-response` |
| security.txt | `/.well-known/security.txt` (needs `NEXT_PUBLIC_SUPPORT_EMAIL`) |

## Not built (needs a lawyer, a contract, or a product decision)

- DPA and SCC drafting; public sub-processor page
- Strict AI-provider default; consent screen for payment holds
- Row-level security, point-in-time recovery, external pentest
