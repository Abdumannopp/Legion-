# CI and the release security gate

Workflow: `.github/workflows/ci.yml`. It runs on every push, every pull
request and every tag.

## Jobs

| Job | What it checks |
|---|---|
| `deploy-scripts` | CI gate self-test, shellcheck, backup/verify/restore tests against real Postgres |
| `dependencies` | `npm audit` — fails on high/critical advisories |
| `agent-identity` | Agent module: audit, typecheck, all unit tests, build; then end to end: provision-cli hardens a database role, the built API runs self-hosted as that role, Wazuh alerts through the real integration script, an AI agent reading them and running skills (`ops/tests/e2e-wazuh.mjs`) |
| `app` | Server + dashboard: typecheck, all tests, build |
| **`security-assessment`** | Security regression tests, the 56-scenario attack assessment, and validation of its result file |
| **`release-gate`** | Passes only if **all five jobs above succeeded** |
| `release` | Tags `v*` only, after `release-gate`: packages the tested commit plus its security evidence |

Normal tests and security tests are separate on purpose: `app` and
`agent-identity` answer "does it work?", `security-assessment` answers "is it
still defended?" — and shows up as its own check.

## What blocks a release

`release-gate` fails — and `release` does not run — if any of these happens:

1. **A security regression test fails** (`npm run test:security` in `server/`
   or `packages/agent-identity/`): first-admin setup, webhook signatures,
   tenant isolation, AI prompt handling, notification retries, sessions, MFA,
   the untrusted-content hold, suspension, prompt-injection detection,
   kill switch, firewall, database least privilege (agent SQL role and
   row-level tenant isolation), security skills (authorization, tenant
   isolation, untrusted content, audit) and the AI red-team skill.
2. **An attack scenario is NOT DEFENDED at Critical or High severity.**
   PARTIAL results and Medium/Low findings are reported in the evidence but do
   not block.
3. **A required scenario is missing** from the run. The required list is
   pinned in `packages/agent-identity/assessment/required-scenarios.json`;
   deleting a scenario file does not shrink it. A new scenario must be added
   there too, or validation fails.
4. **The result file is malformed or incomplete** — bad JSON, invalid verdict,
   a row from another run, or no completion row (the run crashed).
5. **Provenance is missing or wrong** — any field absent, the run came from
   uncommitted changes (`--require-clean`), or the recorded commit is not the
   commit CI checked out (`--expect-commit`).
6. **Any other required job fails, is skipped or is cancelled.**

No step uses `continue-on-error`. `deploy-scripts` runs
`.github/scripts/check-ci-gate.mjs`, which fails the build if anyone adds
`continue-on-error`, removes a job from what `release-gate` waits for, makes
`release` stop depending on the gate, or drops the provenance flags from
validation. `ops/tests/test-ci-gate.sh` proves each of those is caught.

## Evidence

Every `security-assessment` run — pass or fail — uploads
`security-assessment-<commit>`: the assessment run file (with provenance) and
the logs of all three security steps, kept 90 days. A release attaches the
same evidence next to the source package.

## One setting only you can make

CI can fail a check but cannot stop a merge by itself. In GitHub →
Settings → Branches → branch protection for `main`, mark **Release gate** as a
required status check.

## Running the gate locally

```bash
# needs PostgreSQL; TEST_DATABASE_URL pointing at a throwaway database
npm ci && npm run test:security -w server
cd packages/agent-identity && npm ci
npm run test:security
npm run assess
node assessment/provenance.mjs validate assessment/results/latest.jsonl --require-clean --expect-commit "$(git rev-parse HEAD)"
```
