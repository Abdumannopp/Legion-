# Wazuh → Legion integration

When the Wazuh manager detects a security event, it sends it to Legion.
Legion turns it into an alert and streams it live to the dashboard over WebSocket.

```
Wazuh agent → Wazuh manager → custom-legion → POST /security-events/webhook → Legion → dashboard
```

---

## 1. Create a webhook credential in Legion

Every organisation has **its own random credential**: `KEY_ID:SECRET`
(`whk_…:whs_…`). There is no shared secret. A Legion administrator creates the
credential, and **the secret is shown only once**. The server encryption key
(`WEBHOOK_ENCRYPTION_KEY`, created by `npm run setup`) encrypts the secrets in
the database.

From the server console (you need the tenant ID — step 2):

```bash
npm run webhook:credential -w server -- create --tenant TENANT_ID --label "wazuh-manager-1"
```

or, as an administrator, through the API: `POST /security-events/credentials`.

**Important:** without a credential, nothing is accepted on the organisation's
behalf (401). Legion does not need a restart.

---

## 2. Get the tenant ID

```bash
# DATABASE_URL — the value in server/.env
psql "$DATABASE_URL" -c "SELECT id, name FROM tenants;"
```

Or "Organisation ID" on the Settings page. The tenant ID is needed only to
create the credential; Wazuh does **not** send it — the organisation is
identified from the credential itself.

---

## 3. Copy the scripts to the Wazuh manager

Both files are needed — Wazuh calls the name without an extension, which runs the `.py`.

```bash
cp integrations/custom-legion     /var/ossec/integrations/
cp integrations/custom-legion.py  /var/ossec/integrations/

chmod 750 /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py
chown root:wazuh /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py
```

If the permissions are wrong, Wazuh does not run the script at all.

---

## 4. Add it to `ossec.conf`

In `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<integration>
  <name>custom-legion</name>
  <hook_url>http://LEGION_ADDRESS:8000/security-events/webhook</hook_url>
  <api_key>whk_XXXXXXXXXXXXXXXXXXXXXX:whs_YYYYYYYY…</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

| Field | Notes |
|---|---|
| `hook_url` | Legion API address — **`https://`** in production. If installed following [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md): `https://YOUR_DOMAIN/api/security-events/webhook`. If Wazuh runs on the same server as Legion: `http://127.0.0.1:8000/security-events/webhook` |
| `api_key` | The `KEY_ID:SECRET` from step 1, separated by a colon |
| `level` | Alerts at this level and above are sent. `7` is a sensible start |
| `alert_format` | **Must be `json`** |

Restart Wazuh:

```bash
systemctl restart wazuh-manager
```

---

## 5. Check it works

**Logs:**

```bash
tail -f /var/ossec/logs/integrations.log
```

A successful line looks like:

```
legion: OK rule=5720 status=202 {"status":"ingested","alert_id":"SEC-123559EACCF4DC48"}
```

**Manual test** (without waiting for Wazuh):

```bash
python3 /var/ossec/integrations/custom-legion.py \
  /tmp/test-alert.json \
  "whk_XXXX…:whs_YYYY…" \
  "http://localhost:8000/security-events/webhook"
```

---

## Wazuh level → Legion severity

| Wazuh level | Legion severity |
|---|---|
| 12+ | critical |
| 9–11 | high |
| 5–8 | medium |
| 0–4 | low |

---

## Possible responses

| Response | Meaning | Fix |
|---|---|---|
| `202 ingested` | Alert accepted | — |
| `202 skipped, duplicate` | This exact event already exists | Normal |
| `202 skipped` | `rule.description` is empty | Check that `alert_format` is `json` |
| `401 Invalid webhook credentials` | The credential is wrong, **revoked** or expired (deliberately the same answer for all three) | Check `api_key`; create a new credential if needed |
| `401 … too far from this server's clock` | The Wazuh server's clock is wrong | Enable NTP on the Wazuh server |
| `401 This request was already received` | The same request was sent again (replay) | The script uses a new nonce on every attempt; do not re-send by hand |
| `401 … script is out of date` | Old `custom-legion.py` or the old `TENANT_ID:SECRET` format | Install the new script and use the credential from step 1 |
| `401 Malformed webhook authentication headers` | Broken header format | Use the official script |

---

## Security notes

In production, put Legion behind **HTTPS** — there is an example in
`deploy/nginx.conf`. By default the Legion API listens only on `127.0.0.1`
(`LEGION_BIND_ADDRESS`), so Wazuh on another server can reach it only through
the HTTPS proxy — this is deliberate.

Authentication: every message is **signed**; the secret never travels over the
network. Headers: `x-legion-key-id` (public ID — identifies the organisation),
`x-legion-timestamp`, `x-legion-nonce` (a new random value per request) and
`x-legion-signature` = `"v2=" + HMAC-SHA256(secret, "v2." + timestamp + "." + nonce
+ "." + raw_body)`. Rejected: a modified body, a signature from another message
or credential, a timestamp older or newer than `WEBHOOK_MAX_SKEW_SECONDS`
(5 minutes), **a nonce seen before (replay)**, a revoked or expired credential.
`x-tenant-id` is ignored (if present, it must match the credential's owner).

## Rotating and revoking a credential

```bash
# new credential; the old one keeps working for 24 hours (overlap)
npm run webhook:credential -w server -- rotate --tenant TENANT_ID --key whk_… --overlap-hours 24
# switch off immediately
npm run webhook:credential -w server -- revoke --tenant TENANT_ID --key whk_…
# incident: every credential of the organisation
npm run webhook:credential -w server -- revoke-all --tenant TENANT_ID
```

Order: rotate → update `<api_key>` in `ossec.conf` →
`systemctl restart wazuh-manager` → the old credential expires on its own (or revoke it).
API: `GET/POST /security-events/credentials`, `POST …/:id/rotate`, `DELETE …/:id`.

## Known limitations

1. **The key-encryption key (KEK) is still in `.env`**, not in a secret
   manager or KMS (see ADR-003 in [ADR.md](ADR.md)). If `.env` and a database
   backup leak together, the credentials can be decrypted.
2. **The sensor keeps the secret in plain text** (`ossec.conf`, protected by
   file permissions). If the Wazuh server is compromised, only **that
   organisation's** credential is exposed — revoke it.
3. Over `http://` the body is visible on the network (a signature does not hide
   it). HTTPS is required in production.
4. Failed (badly signed) attempts are throttled per client address before the
   body is read; correctly signed telemetry is never throttled. Add limits at
   nginx/WAF level too.

---

## Legion unreachable: nothing is lost (spool)

When Legion cannot be reached (restart, outage, network) or answers 5xx/429,
`custom-legion.py` retries a few times and then **keeps the event on disk**
in `/var/ossec/tmp/legion-spool/<key id>/` (owner-only permissions; the secret
is never written). The next alert re-sends the backlog first, oldest first,
signed afresh. Legion de-duplicates by event id, so a re-send is never a
second alert, and the original Wazuh `timestamp` is kept as the alert's
`occurred_at`.

For quiet periods, run the drain every minute on the manager:
`deploy/wazuh-legion-drain.service` + `.timer` (instructions inside).

- Each credential has its own spool: one organisation's backlog is never sent
  with another organisation's credential.
- An event Legion **refuses** (401/403 — e.g. a revoked credential — or 400)
  is kept in `<key id>/dead/`, not retried. After rotating a credential,
  re-send what the old one could not deliver:
  `custom-legion.py --drain <new KEY_ID:SECRET> <hook_url> --from <old key id>`
- The spool holds at most `LEGION_SPOOL_MAX_FILES` events (50 000); beyond
  that the oldest are dropped and the integration log says so.

### A broken event does not block the queue

If one event itself makes the server fail (HTTP 500), it does not hold up
everything behind it:

- the sensor skips it and sends the next ones;
- after `LEGION_POISON_AFTER` failures (default 10) the event is moved to
  `dead/` (not deleted — you can inspect it);
- three 500s in a row are treated as a server problem: the sensor stops and
  tries again later;
- on connection errors, 401 and 403 the sensor stops immediately (events are kept).

The failure counts are kept in `failures.state` in the spool folder.

---

## Automatic response: blocking the attacker through Wazuh

Automated and AI-assisted attacks make dozens of attempts in seconds. Legion
groups related alerts into **attack campaigns** (Dashboard → **Defense**) and,
if you choose, blocks the attacker's address through your Wazuh manager in
**about a minute**.

### What Legion treats as a campaign

| Rule | Condition | Auto-blocked |
|---|---|---|
| Fast multi-stage attack (`rapid_chain`) | ≥ 3 different MITRE techniques from one address in 15 minutes | yes |
| Sweep across many servers (`wide_sweep`) | ≥ 5 servers from one address in 10 minutes | yes |
| Sudden burst (`velocity`) | ≥ 30 alerts from one address in 5 minutes | yes |
| Password attack (`credential_attack`) | ≥ 10 failed sign-ins or ≥ 5 different accounts tried from one address in 10 minutes | yes |
| Account broken into (`account_compromise`) | the same address signed in within 30 minutes after ≥ 3 failures | yes (the attacker's address) |
| Many addresses, one server (`swarm`) | ≥ 10 addresses against one server in 10 minutes | **no** (too many addresses; this is DDoS — see EDGE-SECURITY.md) |
| Attempt to manipulate AI (`ai_manipulation`) | instructions to an AI inside a log ("ignore previous instructions", hidden characters, model tokens…) | **no** (it is text, not an address) |
| Ransomware (`ransomware`) | signs of ransomware, or ≥ 50 file changes on one host in a short time | no (isolate the host) |
| Mailbox takeover (`mailbox_takeover`) | new forwarding or inbox rules, unusual mailbox access | no |
| Phishing executed (`phishing_execution`) | an attachment or link opened and then a program run | no |
| Supply chain (`supply_chain`) | a new package or update followed within 60 minutes by suspicious activity | no |
| Slow intrusion (`slow_intrusion`) | ≥ 3 attack stages from one source spread over days (up to 7) | no |

Each new campaign is **one** alert (the "Hunter" agent), not one per attempt.
See [THREATS.md](THREATS.md) for what Legion can and cannot do against each
attack type.

### Safety limits (cannot be switched off)

- **Off** by default — Legion only detects and reports. An administrator turns
  it on in the Defense page (recorded in the audit log).
- **Public** IP addresses only: private (10.x, 192.168.x, 172.16–31.x), CGNAT,
  loopback and documentation addresses are never blocked automatically.
- An **allowlist** (your own office, partners, your scanners) — never blocked
  automatically.
- At most **50** automatic blocks per hour, at most **1000** active at once.
- Every block expires (5 minutes – 7 days, default 1 hour), is written to the
  audit log, and can be undone with one click on the Defense page.

### One-time setup on the Wazuh manager

```bash
# 1. Script (the same one as in section 3) and the rule
cp integrations/wazuh/legion_rules.xml /var/ossec/etc/rules/legion_rules.xml
chown root:wazuh /var/ossec/etc/rules/legion_rules.xml

# 2. Sensor credential in a file (the same KEY_ID:SECRET as in ossec.conf)
echo 'whk_...:whs_...' > /var/ossec/etc/legion.key
chown root:wazuh /var/ossec/etc/legion.key && chmod 640 /var/ossec/etc/legion.key

# 3. The file Wazuh reads — create it BEFORE restarting
touch /var/ossec/logs/legion-blocklist.log
chown wazuh:wazuh /var/ossec/logs/legion-blocklist.log
```

4. Add the three blocks from `integrations/wazuh/ossec-legion-response.xml`
   (`wodle`, `localfile`, `active-response`) to `ossec.conf`, replacing
   `LEGION_URL` with your own `hook_url`.
5. Run `/var/ossec/bin/wazuh-analysisd -t` (check there are no errors), then
   `systemctl restart wazuh-manager`.

Check: `/var/ossec/logs/integrations.log` shows a line
`BLOCKLIST n active, m sent to active response` every minute.

### How it works

1. Every minute Wazuh runs `custom-legion.py --sync-blocklist`; it fetches the
   list from Legion with a **signed** request (only this organisation's list).
2. For a new address it writes one JSON line to `legion-blocklist.log`.
3. Wazuh rule 100950 sees the line and runs the `firewall-drop` active response
   **on every agent**.
4. Wazuh removes the block itself after `<timeout>` (600 s). While Legion still
   wants the block, the script re-announces the address every 5 minutes, so the
   block does not lapse.
5. If you unblock in Legion, the script stops announcing it and Wazuh removes
   it within **10 minutes** at most.

Legion's own blocking events (group `legion_response`) never come back to
Legion as new alerts — this is checked on both sides.

### Honest limits

- **No system stops every attack.** This adds speed: the attacker is stopped
  before a person has read the alert.
- Blocking IPs does not stop an attack from many addresses (botnet, DDoS) —
  that needs an edge service such as Cloudflare (EDGE-SECURITY.md).
- An attacker can forge the address in a log (for example, a log line with
  someone else's IP). That is why: public addresses only, an allowlist, an
  hourly limit and expiring blocks. Put your own important addresses on the
  allowlist.
- Wazuh agents do the blocking (`firewall-drop` → iptables). Where there is no
  agent or no iptables, the block does nothing. Our automated test
  (`ops/tests/e2e-wazuh-response.mjs`, real Wazuh 4.9.2) confirmed that Wazuh
  runs `firewall-drop`; the kernel rule itself was not verified, because the
  Docker image has no iptables.
- A new `legion-blocklist.log`: Wazuh reads a file it discovers late from the
  end. If you skip the `touch` step above, the script creates the file itself
  and waits 2 minutes — the first block is delayed by that much.
