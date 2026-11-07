# Protection modes — Legion acts on its own only when an administrator allowed it

Legion watches around the clock, detects, explains, and — **only if an
administrator switched it on** — carries out a small set of pre-approved
actions by itself, tells the administrators, and records everything.
Dangerous actions always wait for a person.

**Default: manual. Nothing is switched on in any environment by this release.**

## The six parts

| Part | What happens | Where |
|---|---|---|
| 24/7 monitoring | Sensors (Wazuh etc.) send events; the runtime worker processes them continuously | [WAZUH.md](WAZUH.md), runtime worker |
| Automatic detection | Detection rules turn events into alerts | Sentinel / Hunter |
| AI analysis | Cause and risk explained in plain words; the AI only explains, it does not act | Oracle |
| Automatic protection | Only the actions the administrator ticked, only in `hybrid`/`automatic` mode | this document |
| Human confirmation | Anything dangerous, or proposed by an AI model, waits for a person (R4 also needs MFA) | approvals engine |
| Audit and report | Every automatic action is in the chained audit trail, mailed to administrators, and in the 7-day report | Defense → Protection |

## The three modes (per workspace)

| Mode | Behaviour |
|---|---|
| `manual` (default) | Legion detects and recommends. Nothing is done without a person. |
| `hybrid` | Legion does by itself **only the actions the administrator ticked**. Everything else asks. |
| `automatic` | Legion does by itself every action that has a real executor and is not critical. |

## What is real, and what is not

Only two actions have a real executor (`LIVE_ACTION_IDS`; a database `CHECK` enforces the same list):

- `ip.block` — add a **public** address to the blocklist.
- `notify.admins` — e-mail the workspace administrators.

Everything else (disable an account, isolate a host, kill a process, money, …)
stays **simulation only** and always needs a person. These cannot be allowed
(the API answers 422).

## Safety rules (cannot be changed by settings)

1. Off by default; turning it on needs the **administrator**, the **plan** (`autoBlocking`, Business+), a **recent sign-in (10 minutes)**, and **acceptance of a written notice**. A newer notice version sends the workspace back to manual until accepted again.
2. R4 (critical) actions and anything proposed by an **AI model** always need approval.
3. Private/internal addresses and the workspace **allowlist** are never blocked; this is checked again at the moment of acting.
4. Facts are re-checked when the action runs (plan, mode, emergency stop, address).
5. **Hourly cap** (`SOC_LIVE_ACTIONS_PER_HOUR`, default 20): beyond it, actions wait for approval.
6. A live action whose outcome is unknown after a crash is marked failed and **never retried**.
7. **Emergency stop** (Defense page, or `POST /actions/controls`) halts everything at once; held actions resume only when lifted.
8. Switching back to manual is immediate and never needs the recent sign-in.
9. Alerts from test/demo sources (`legion-test`, `mock`, `demo`, `legion-monitor`, `legion-agent-security`) never trigger automatic action.
10. Every automatic action: chained audit event, administrator e-mail, counted in `GET /soc/protection/report`.

## API

- `GET /soc/protection` — current mode and effective mode.
- `PUT /soc/protection` — `{mode, auto_actions, acknowledge}`.
- `GET /soc/protection/report?days=7` — what Legion did on its own, and who changed the settings.
- Metrics: `legion_soc_actions_live`, `legion_soc_workspaces_protection_active`. The page alert `LegionLiveActionDetected` fires only when a live action exists while **no** workspace has opted in.

## Honest limits

- Tested in CI and end to end on the built API (`ops/tests/e2e-protection.mjs`: manual does nothing, hybrid blocks within seconds, private/allowlisted left alone, emergency stop, report, audit chain). It has **not** been through a multi-day soak, a pilot with real traffic, or an independent penetration test.
- A source address in a log can be forged; blocking is reversible (unblock on the Defense page) but a wrong block is possible. Many-address attacks are not stopped by blocking.
- "24/7" depends on your deployment staying up; there is no high-availability setup yet.
- Pilot workspaces stay in manual mode; `legion_soc_actions_live` must be 0 unless a workspace has deliberately opted in.
