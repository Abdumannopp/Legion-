# Legion — Enterprise productization: scope proposal (Task 14)

**Status: PROPOSAL, awaiting your review and approval. Nothing in §8 has been implemented.**
No production billing, customer setting or deployment was changed. Legion holds **no SOC 2 or ISO 27001 certification**; §6 describes readiness, not certification.

This document answers: what Legion already has for each of the 17 requirements (§1, from the code, not from earlier documents), how the missing parts should be built (§2–§5), what it takes to be credible to enterprise buyers (§6–§7), and the ordered backlog to approve (§8). The decisions I need from you are in §9.

---

## 1. Where Legion stands today (verified in the code, 2026-11-05)

Legend: **Built** (code + tests) · **Partial** (works but missing something an enterprise buyer will ask for) · **Seam** (interface/contract only) · **Missing**

| # | Requirement | Status | What exists (file) | What is missing |
|---|---|---|---|---|
| 1 | Multi-tenant customer management | **Partial** | Workspaces, memberships, invitations, home workspace, per-workspace sessions (`workspaces.ts`); tenant-query guard; isolation sweeps | No **organization** above workspaces (one customer, several workspaces); no **MSSP/partner** model; no platform operator console (customer list, plan, health) |
| 2 | Enterprise SSO (OIDC, SAML) | **Seam** | `enterprise.ts`: `IdentityProvider`, `ExternalIdentity`, `SsoPolicy` (verified domains, invite-only vs JIT, group→role, enforce SSO); sign-in path `startSession()` | Everything executable: OIDC client, SAML SP, domain verification, admin UI, tests |
| 3 | SCIM provisioning | **Seam** | `ScimProvisioner` contract → membership functions | SCIM 2.0 `/Users`, `/Groups` endpoints, per-workspace SCIM token, tests against the RFC 7644 shapes |
| 4 | Role-based access, granular permissions | **Partial** | 24-permission catalogue; routes ask for a permission (`permissions.ts`, `requirePermission`); `GET /workspace/roles`; route-auth sweep test | Only 3 fixed roles (viewer/analyst/admin). No custom roles, no scoped grants (e.g. "only these integrations"), no separation of duties for critical permissions |
| 5 | Customer-specific autonomy configuration | **Partial** | Per-workspace versioned policy document with default/per-agent/per-action autonomy, rules, simulate, rollback (`policy/`); approval engine (R4 = 2 approvers + MFA); per-workspace pause | No **ceilings**: nothing ties the maximum autonomy to the plan or to a platform limit beyond the hard-coded "live refused"; no dashboard screens (R-5) |
| 6 | SaaS and self-hosted options | **Partial** | `DEPLOYMENT_MODE` saas/self-hosted; self-hosted = no limits; `install.sh`, `docker-compose.pilot.yml` (hardened, CI-tested), `SAAS.md`, `INSTALL.md` | No Helm chart / Kubernetes option; no air-gapped install bundle; no signed images or SBOM; no update channel/version policy |
| 7 | Subscription and billing | **Built** (SaaS) | Plans, add-ons, entitlements (`plans.ts`), Paddle checkout/portal/webhook (`paddle.ts`), currency, billing page | Enterprise contracts (invoice, PO, custom entitlements per customer), self-hosted **licence keys**, MSSP wholesale billing |
| 8 | Usage and resource quotas | **Partial** | Endpoint/admin limits reported (`plan-limits.ts`); hourly SOC action budget; rate limits; payload caps | No metering table; no quotas on ingest volume, API calls, AI credits, storage; no usage page for customers |
| 9 | Customer audit exports | **Partial** | `GET /audit/export` (NDJSON/CSV, streamed, injection-safe, itself audited); `/audit/principal-events`; `GET /soc/audit`, `/soc/audit/verify` | SOC audit chain **export with a verification bundle** (customer can check integrity offline); continuous SIEM streaming (outbound webhook seam) |
| 10 | Data retention and deletion | **Partial** | Retention jobs (payments, audit pseudonymisation, agent-log pruning with anchors), legal hold, workspace export, tenant deletion with tombstone/ledger and replay after restore, opt-in auto-delete with notices (`retention.ts`, `tenant-deletion.ts`, `DATA-RETENTION.md`) | Retention is **platform-wide**, not per customer; SOC history tables have **no retention** (Task 13 K-2); no customer-initiated deletion request flow in the UI |
| 11 | Data residency architecture | **Partial** | `tenants.region`, `LEGION_REGION`, a deployment refuses other regions' workspaces with 421 (`GLOBAL-SAAS-ARCHITECTURE.md` §6) | Global directory/routing (sign-in for an account in another region); per-region sub-processor list; documented residency of backups, logs, AI provider calls |
| 12 | Enterprise reporting | **Partial** | Reports page; `response_sla_review`, `triage_priority`, `threat_coverage` skills | Scheduled reports (PDF/CSV by email), MTTA/MTTR — **impossible today: Legion does not record when an alert is resolved**; multi-workspace rollups for MSSPs |
| 13 | API and integration documentation | **Partial** | `packages/agent-identity/README.md`, `SOC-CORE.md`, `WAZUH.md`, `AGENTS.md`; integration catalogue endpoint | No OpenAPI spec; no guarantee docs match routes; no versioning/deprecation policy; no SDK |
| 14 | Customer onboarding | **Partial** | First-run setup token, signup, invitations, connect page, onboarding UX doc | No guided checklist with progress (connect sensor → first alert → invite team → set policy); no SSO/SCIM set-up wizard |
| 15 | Backup and DR documentation | **Built** (operator) | `BACKUP.md`, `RECOVERY.md`, `PILOT.md` §7, CI restore test | A **customer-facing** DR statement (RPO/RTO per plan, what the customer must keep for self-hosted) |
| 16 | Support and incident management | **Partial** | Support page; incident response in `PRODUCTION-READINESS-ASSESSMENT.md` §7; `security.txt` | No ticket intake tied to the workspace; no customer incident notification workflow; no severity/response-time matrix per plan |
| 17 | SLA and service health reporting | **Missing** (customer-facing) | Internal `/health`, `/metrics`, Prometheus alerts (Task 13) | Public status page, per-region uptime measured by an **external** probe, SLA definitions and credit calculation, monthly SLA report per customer |

**Product requirements check (today):**

| Requirement | Today |
|---|---|
| Each customer controls agent autonomy | Yes via the policy API; no UI; no plan ceiling |
| Customer data isolated | Yes, application-enforced and heavily tested; no Postgres RLS (Task 13 K-4) |
| Customers manage integrations and credentials | Yes (`/integrations`, secrets sealed with `LEGION_ENCRYPTION_KEYS`, write-only); no rotation reminder, no per-integration permission |
| Customers inspect agent decisions and audit | Yes via API (`/policy/decisions`, `/soc/audit`, `/audit`); limited UI |
| No cross-customer access | Yes for customers. **Must stay true for MSSPs and for our own support staff** — §3 designs both without a bypass |
| Autonomous actions bounded by policy | Yes, and stronger: live actions are refused at API, engine and DB |

---

## 2. Enterprise architecture (target)

```
                          ┌──────────────────────── Global (no customer data) ───────────────────────┐
                          │ Directory: account email → home region · Org/partner registry ·         │
                          │ Licence service (self-hosted) · Status page · Docs portal               │
                          └───────────────▲──────────────────────────────▲───────────────────────────┘
                                          │ routing only                 │ health only
     ┌────────── Region A (one stack) ────┴───────────┐     ┌──── Region B (same stack) ───┐
     │ Edge (TLS, WAF, rate limits)                     │     │            …                 │
     │ API ─ Identity: password+MFA · OIDC · SAML · SCIM│     └──────────────────────────────┘
     │     ─ AuthZ: role → permission set → scope       │
     │     ─ Tenancy: Organization ▸ Workspace          │
     │       (partner access = delegated membership)    │
     │ SOC core: Policy (ceilings) ▸ Approval ▸ Action  │
     │ Workers: runtime · integrations pull · retention │
     │         · metering · reports · audit streaming   │
     │ Postgres (per region, RLS as second layer)       │
     │ Redis · Object storage (exports, reports)        │
     └──────────────────────────────────────────────────┘
```

Principles that do not change:
1. **The workspace is the isolation boundary.** Every new table carries `tenant_id`; the tenant-query guard and the isolation sweep extend to it in the same change.
2. **No god mode.** Neither an MSSP nor Legion staff gets a code path that skips membership checks. Access to a workspace is always a membership (possibly delegated and time-bound), visible to and revocable by the customer, and audited.
3. **Effective autonomy = min(platform ceiling, plan ceiling, customer policy).** The platform ceiling stays "no live actions" until a separate approval (Task 13 stage 5).
4. **One way in for identity.** Password, OIDC, SAML all end at `startSession()`; SCIM only calls the membership functions.
5. **Second layer for isolation:** add Postgres row-level security keyed by a per-transaction `app.tenant_id`, in addition to the application guard (closes Task 13 K-4).

### 2.1 Tenancy model

| Entity | Owns | New? |
|---|---|---|
| **Organization** | Billing account, verified domains, SSO connections, SCIM token, default retention, one or more workspaces | New |
| **Workspace** (= tenant) | All security data, policy, integrations, audit | Exists |
| **Membership** | Person × workspace × role (+ optional expiry, + optional scope) | Exists; add expiry, scope, `source` (invite/JIT/SCIM/delegation) |
| **Partner** (MSSP) | Its own organization + a list of *customer organizations that granted it access* | New |
| **Delegation** | Customer org → partner: which workspaces, which role ceiling, until when | New |

An MSSP console shows several customers by calling the API **once per delegated workspace with that delegation's membership**, never by a cross-tenant query. A customer revoking the delegation ends access on the next request.

**Legion staff support access** uses the same mechanism: a time-boxed (max 72 h), customer-approved "support delegation", read-only by default, every request audited in the customer's own audit log.

### 2.2 Authorization model

- **System roles** (immutable): Viewer, Analyst, Responder (new: may triage and propose actions, not manage users), Admin, Owner (new: billing, SSO, delete workspace — at least one per org).
- **Custom roles**: a named permission set per organization, built only from the catalogue. Rule: you can only grant permissions you hold (no escalation); `members:manage` cannot grant Owner.
- **Scopes** (phase 2): a membership may be limited to a set of integrations/asset groups.
- **Separation of duties**: permissions marked *critical* (`policy:manage`, `approvals:decide` for R4, `actions:control`, `audit:export`, `billing:manage`, SSO settings) can require MFA step-up per call and, optionally, two people.

### 2.3 Autonomy configuration

| Layer | Who sets it | Values |
|---|---|---|
| Platform ceiling | Legion (code + deployment) | `SHADOW_ONLY` today; `LIVE_ALLOWED_FOR(action list)` only after Task 13 stage 5 approval |
| Plan ceiling | Entitlement | Starter: OBSERVE/ASSIST · Professional: + APPROVE · Business/Enterprise: + per-action AUTO *within the platform ceiling* |
| Customer policy | Customer admin, versioned, simulated before save, rollback | default / per agent / per action / rules |
| Emergency | Customer admin or Legion on-call | Pause (exists), policy freeze (exists) |

The policy screen shows the effective value per action **and which layer limited it**.

---

## 3. SaaS and self-hosted deployment strategy

| Option | For | Isolation | Operated by | Updates | Status |
|---|---|---|---|---|---|
| **SaaS multi-tenant** (shared stack per region) | SMB, mid-market | Workspace (app guard + RLS) | Legion | Continuous, staged rollout | Exists in single region |
| **SaaS dedicated** (one stack per customer, our cloud) | Enterprise, regulated | Separate DB and process | Legion | Same images, customer-specific window | Same compose/Helm, new automation |
| **Self-hosted** (customer's infra) | Air-gapped, government, MSSP own DC | Customer's | Customer | Signed releases, licence key, LTS channel | Compose exists; add Helm, offline bundle, licence |
| **MSSP-hosted** | MSSPs serving SMBs | Workspace per end-customer | MSSP | MSSP pulls our releases | Uses self-hosted + partner model |

**Common release artefacts:** OCI images signed (cosign) with SBOM and vulnerability scan (closes Task 13 K-3); Helm chart with the same hardening as `docker-compose.pilot.yml`; offline bundle (images + chart + checksums); version policy: monthly minor, 12-month LTS for self-hosted, security fixes back-ported to the last two minors.

**Licence (self-hosted):** a signed (Ed25519) offline licence file: customer, expiry, entitlements. Expiry **never** disables detection or data access — it shows a banner and stops updates/support. Self-hosted keeps "no limits" by default as today unless the contract says otherwise.

---

## 4. Customer administration model

| Persona | Can | Cannot |
|---|---|---|
| **Org Owner** | Billing, SSO/SCIM, domains, create/delete workspaces, retention, delegations, appoint owners | Bypass approvals; see other orgs |
| **Workspace Admin** | Members, roles, integrations and credentials, policy/autonomy within ceilings, audit export | Billing, SSO, delete org |
| **Responder / Analyst / Viewer** | As the matrix | Change policy or members |
| **Partner (MSSP) operator** | What the delegation's role ceiling allows, in delegated workspaces only | Exceed the ceiling; see undelegated workspaces; keep access after revocation |
| **Legion support** | Read-only during an approved support delegation | Anything without the customer's approval; write by default |
| **Legion platform operator** | Customer list, plan, region, health, usage (metadata only) | Read customer security data (that needs a support delegation) |

Every administrative change writes to the workspace (or org) audit log with actor, source (UI/API/SCIM/SSO-JIT/delegation) and before/after.

---

## 5. Commercial feature roadmap (packaging)

| Capability | Starter | Professional | Business | Enterprise | MSSP |
|---|---|---|---|---|---|
| Workspaces per org | 1 | 1 | 3 | By agreement | Per end-customer |
| SSO (OIDC) | – | ✓ | ✓ | ✓ | ✓ |
| SAML | – | – | ✓ | ✓ | ✓ |
| SCIM | – | – | ✓ | ✓ | ✓ |
| Custom roles / scopes | – | – | Custom roles | + scopes, SoD | + partner ceilings |
| Autonomy ceiling | OBSERVE/ASSIST | + APPROVE | + per-action AUTO* | + AUTO* | As delegated |
| Audit export / SIEM stream | Export | Export | + stream | + chain bundle | + stream |
| Retention control | Fixed | Fixed | Choose within range | Custom + legal hold | Per end-customer |
| Residency | Default region | Choose region | Choose region | + dedicated stack | Per end-customer |
| Reports | On-screen | + scheduled | + SLA report | + custom | + rollup |
| Support / SLA | Email | Priority email | Priority | SLA + named contact | Partner SLA |

\* AUTO stays shadow/simulation until the platform ceiling is raised by a separate approval. Prices: unchanged; packaging changes need your decision (§9) and **will not be applied to live billing** without explicit authorization.

---

## 6. Security and compliance readiness (not certification)

**Not certified.** No SOC 2 report, no ISO 27001 certificate, no independent penetration test exists. Marketing, docs and the sales deck must not imply otherwise.

| Framework area | What we can show today | Gap to audit-readiness |
|---|---|---|
| Access control (SOC 2 CC6, ISO A.5.15–A.5.18, A.8.2–A.8.5) | MFA, permission catalogue, route-auth sweep, least-privilege DB role, audit of admin changes | SSO/SCIM, quarterly access reviews (needs a report), joiner/mover/leaver evidence |
| Change management (CC8, A.8.32) | CI release gate with mandatory security jobs, self-tested gate | Formal change tickets, approvals recorded per release, branch protection evidence |
| Operations / monitoring (CC7, A.8.15–A.8.16) | Alerts with unit tests, keyed audit chain | Alert delivery evidence, log retention policy, SIEM for our own platform |
| Incident response (CC7.3–7.5, A.5.24–A.5.28) | Procedure in Task 13 §7 | Exercised game-day, customer notification workflow, post-mortems |
| Availability / DR (A1, A.5.29–A.5.30) | Backups with restore test, documented RPO/RTO | HA, timed DR on production-size data, published SLA |
| Vendor management (CC9, A.5.19–A.5.22) | Sub-processor list in legal texts | Vendor reviews, DPAs on file |
| Privacy (GDPR) | Export, deletion with ledger, retention, residency enforcement | DPIA, records of processing, per-region sub-processors |

Path: (1) close the Task 13 blockers; (2) policies and evidence collection (a compliance-automation tool is cheaper than building); (3) independent pen-test; (4) SOC 2 Type I, then Type II after ≥ 3–6 months of operating evidence; ISO 27001 if the market asks for it.

---

## 7. Documentation plan

| Document | Audience | Source of truth | Kept honest by |
|---|---|---|---|
| **API reference (OpenAPI 3.1)** | Developers | Generated from the zod schemas already used by routes | CI test: every route in the app is in the spec and vice versa (reuses the route sweep) |
| Integration guides (Wazuh, generic webhook, pull adapters, outbound SIEM) | Customer engineers | Existing `WAZUH.md` etc. | Examples executed in CI where possible |
| Admin guide (org, SSO, SCIM, roles, delegations, autonomy, retention) | Customer admins | New | Screenshots from the journey tests |
| Security whitepaper | Buyers, security reviewers | Architecture + `TENANT-ISOLATION.md` | Reviewed per release; no certification claims |
| Trust/compliance page | Buyers | §6 | Legal review |
| DR & backup statement | Customers | `BACKUP.md`, `RECOVERY.md` | Numbers only from timed drills |
| Self-hosted install & upgrade (Compose, Helm, offline) | Operators | `INSTALL.md`, pilot compose | CI installs each path |
| Support & SLA policy | Customers | New | Matches contract templates |
| MSSP partner guide | Partners | New | — |
| Changelog & deprecation policy | Everyone | New | Release tooling |

---

## 8. Implementation backlog (for approval)

Sizes: S ≤ 2 days, M ≤ 1 week, L ≤ 3 weeks (one engineer). Every item ships with tests, the tenant-guard/sweep extended to new tables, docs, and no change to live billing or customer data without your authorization.

### Phase A — Foundations (unblocks everything else)
| ID | Item | Size | Req |
|---|---|---|---|
| A1 | Organization entity above workspaces; owner role; migration of existing workspaces (one org each) | M | 1 |
| A2 | Custom roles + Responder/Owner system roles; no-escalation rule; SoD flags with MFA step-up | M | 4 |
| A3 | Autonomy ceilings (platform + plan) and "effective autonomy" API | S | 5 |
| A4 | Postgres RLS as second isolation layer (behind a flag, then default) | L | 1, isolation |
| A5 | SOC history retention + per-workspace retention within plan bounds (closes Task 13 K-2) | M | 10 |
| A6 | Usage metering table + quotas for ingest, API calls, AI credits, storage; usage page | M | 8 |

### Phase B — Enterprise identity
| B1 | OIDC SSO (authorization code + PKCE, nonce/state, JWKS rotation) with domain verification (DNS TXT), JIT/invite-only, group→role, enforce-SSO | L | 2 |
| B2 | SCIM 2.0 Users/Groups, per-org hashed token, deprovision = deactivate membership | M | 3 |
| B3 | SAML 2.0 SP (signed assertions required, XML-signature-wrapping tests, clock skew, replay cache) | L | 2 |

### Phase C — Customer self-service and visibility
| C1 | Dashboard screens: policy & autonomy (with "limited by" layer), approvals, actions (closes R-5) | L | 5, inspect |
| C2 | Audit: SOC chain export with offline verification bundle; outbound SIEM streaming via outbox | M | 9 |
| C3 | Record alert `resolved_at`/`acknowledged_at`; MTTA/MTTR; scheduled reports (CSV/PDF by email) | M | 12 |
| C4 | Onboarding checklist with progress; SSO/SCIM set-up wizard | M | 14 |
| C5 | Customer deletion-request flow (owner + MFA + cooling-off, uses existing deletion tool) | S | 10 |
| C6 | Credential hygiene: rotation dates, "last used", per-integration permission | S | integrations |

### Phase D — Commercial and partners
| D1 | Partner (MSSP) model: delegations, partner console via per-workspace memberships, revocation | L | 1 |
| D2 | Support delegation (time-boxed, customer-approved, read-only, audited) | M | 16 |
| D3 | Enterprise contracts: custom entitlements per org, invoice billing flag (Paddle unchanged for self-serve) | M | 7 |
| D4 | Self-hosted licence file (Ed25519, offline, never disables detection) | M | 6, 7 |

### Phase E — Operations, residency and trust
| E1 | Release artefacts: signed images, SBOM, image scan in CI, Helm chart, offline bundle | L | 6 |
| E2 | Global directory + region routing for sign-in; per-region sub-processor list | L | 11 |
| E3 | Public status page fed by an external probe; SLA definitions; monthly per-customer SLA report | M | 17 |
| E4 | Support intake tied to workspace + severity matrix per plan; customer incident notifications | M | 16 |
| E5 | OpenAPI spec + CI drift test; versioning/deprecation policy | M | 13 |
| E6 | Documentation set (§7), customer DR statement | M | 13, 15 |
| E7 | Compliance evidence programme (policies, access reviews, pen-test booking) — mostly non-code | — | §6 |

**Suggested order:** A1–A3, A5 → B1 → C1 → A6, B2 → C2, C3 → A4 → B3 → D1, D2 → E1, E5 → rest. Rough total: 5–7 engineer-months for A–D; E2 and compliance run in parallel.

**What I propose to implement first, if you approve:** A1, A2, A3 and A5 (foundations with the most product value and no external dependencies), each with tests, isolation sweep coverage and docs, in separate commits, then stop for review.

---

## 9. Decisions I need from you

1. **Scope of the first increment:** approve A1–A3 + A5 as proposed, or reorder (e.g. SSO first if a deal depends on it)?
2. **Target segments for the first release:** SMB + mid-market SaaS first, or MSSP first? (Changes whether D1 moves up.)
3. **SAML in the first enterprise release, or OIDC only?** SAML is the higher-risk component (XML signatures); I recommend OIDC first.
4. **New dependencies:** OK to add a maintained OIDC library (`openid-client`) and, later, a SAML library (`@node-saml/node-saml`), instead of hand-written crypto?
5. **Packaging (§5):** approve the matrix as a direction? It will **not** be applied to live Paddle products or existing customers without a separate explicit authorization.
6. **Support tooling:** integrate an external helpdesk (recommended) or build ticketing into Legion?
7. **Postgres RLS (A4):** accept the effort now, or after the first enterprise customer?
