# Plans and prices

The price list below is what Legion shows on the website and enforces in the
product. It lives in one place, `server/src/plans.ts` (the website has an exact
copy, `frontend/lib/plans.ts`, and a test fails if they differ).

Source: "Legion — recommended prices and plans". These are a **commercial
recommendation**, not a guaranteed market price: validate them against your real
hosting and AI costs on pilot customers before you launch.

Currency: USD. Annual = 10 months' price (two months free, 16.7% off).

## SaaS plans

| Plan | Monthly | Yearly | For |
|---|---|---|---|
| Starter | $49 | $490 | Small business |
| Professional | $149 | $1,490 | Growing company (the recommended plan) |
| Business | $399 | $3,990 | Large IT / SOC team |
| Enterprise | from $999 | by agreement | Large organisation |

| | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|
| Endpoints | up to 25 | up to 100 | up to 500 | 1,000+ |
| Administrators | 2 | 5 | 20 | by agreement |
| Alert history | 30 days | 90 days | 180 days | 365+ days |
| AI analysis | basic | extended | extended | custom |
| The five Legion agents | — | yes | yes | yes |
| AI Agent Security | — (add-on) | yes | yes | yes |
| Payment fraud check | add-on | yes | yes | yes |
| Blocking attacker addresses | — | with your approval | by policy | custom policy |
| API and integrations | — | basic | extended | custom |
| Support | email | fast email | priority | SLA |

## Add-ons (monthly)

| Add-on | Price | What it does |
|---|---|---|
| AI Agent Security | +$49 | Identities, permissions and the policy firewall for the customer's own AI agents |
| Payment Fraud Protection | +$79 | The payment check |
| Advanced Threat Intelligence | +$99 | Listed and sold; nothing in the product is gated by it yet |
| Extra 100 endpoints | +$25 | Raises the endpoint limit by 100 (each one counts) |
| Extra 5,000 AI credits | +$39 | Listed and sold; AI usage is not metered per plan yet |

Add-ons are billed monthly and ride on a monthly plan.

## Self-hosted (yearly licence)

| Plan | Endpoints | Yearly licence |
|---|---|---|
| Starter | up to 25 | $490 |
| Professional | up to 100 | $1,490 |
| Business | up to 500 | $3,990 |
| Enterprise | 1,000+ | from $7,500 |

The customer runs the server and Wazuh. The licence covers updates and the
plan's support. **The software does not check a licence key**: a self-hosted
installation has no plan limits, and the licence is a contract, not a lock.

## Setup services

Basic Setup $300–500 · Professional Setup $750–1,500 · Enterprise Integration from $2,000.

## What each limit does in the product

| Limit | What happens |
|---|---|
| **Administrators** | Inviting or promoting an administrator beyond the plan's number is refused (403 `plan_limit`). Invited-but-not-joined admins count. Analysts and viewers are not limited. |
| **Alert history** | Resolved alerts older than the plan keeps them are deleted (hosted only). Open and investigating alerts are never deleted. |
| **Endpoints** | **Reported, never enforced.** Usage is shown in Billing with a warning when over the limit. Legion keeps recording every event: dropping telemetry over a billing limit would leave a hole in a customer's security history that can never be filled. Machines seen in the last 30 days count. |
| **Copilot assistant** | Part of extended AI analysis: refused on Starter. |
| **The five Legion agents** (skills) | Refused on Starter. |
| **AI Agent Security** (agent identities, firewall, tokens) | Refused on Starter unless the add-on is bought. Stopping an agent (kill switch, suspend, revoke) is always allowed. |
| **Payment check** | The signed check is refused (403) on Starter without the add-on; the payment software then does not pay automatically. Holds already made can still be released or rejected. |
| **Blocking addresses** | None on Starter. Professional: a person blocks (automatic blocking cannot be turned on). Business and up: automatic blocking by policy. The Wazuh manager gets an empty list on a plan without blocking. Turning blocking off never needs a plan. |

Detection is **not** a plan feature: campaigns, coverage and alerts work on every plan.

A workspace in its **free trial** has the whole Professional plan. A subscription
from before plans existed (one price) is treated as Professional.

## Connecting prices to Paddle

See [SAAS.md](SAAS.md), step 4. In short, create one Paddle price per plan and
period and per add-on, and list them in `server/.env`:

```env
PADDLE_PLAN_PRICES=starter.month=pri_…,starter.year=pri_…,professional.month=pri_…,professional.year=pri_…,business.month=pri_…,business.year=pri_…
PADDLE_ADDON_PRICES=agent_security=pri_…,payment_fraud=pri_…
```

The browser asks for a plan, a period and add-ons; the server chooses the Paddle
prices. A subscription whose price is not in these lists grants no access.

## Enterprise

Enterprise is sold by agreement, so it has no checkout. Set it by hand once the
contract is signed:

```bash
npm run plan -w server -- set   --tenant <workspace-uuid> --plan enterprise
npm run plan -w server -- show  --tenant <workspace-uuid>
npm run plan -w server -- clear --tenant <workspace-uuid>
```

An override wins over the subscription and is written to the audit log.

## Before you publish these prices

- Measure server, AI API and support cost per plan on pilot customers.
- Decide a fair-use rule for heavy AI use and say it openly on the pricing page.
- The payment check cannot verify beneficiaries with the bank on its own: the
  payment system needs a person's confirmation and a fail-closed rule.
- Have a lawyer review the Enterprise SLA, data retention, privacy, licence and refund terms.

## Not implemented yet (honest list)

- **AI credits** and **Advanced Threat Intelligence** are sold as add-ons but nothing in the product is metered or gated by them yet: the price list gives no quantities per plan.
- **Changing plan** on a running subscription goes through support (the Paddle portal does not switch plans by itself).
- **Launch offer, partner (reseller/MSP) discounts and Managed SOC** from the recommendation are commercial terms, not product features.
- **Self-hosted licence keys**: not enforced by the software, by design.
- **API/integration levels** are shown on the price list; the API is available wherever AI Agent Security is.
