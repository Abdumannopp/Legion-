#!/usr/bin/env python3
"""
Wazuh -> Legion integration.

Wazuh invokes this as:
    custom-legion <alert_file> <api_key> <hook_url>

where <api_key> and <hook_url> come from the <integration> block in
ossec.conf. <api_key> carries "KEY_ID:SECRET" -- the webhook credential a
Legion administrator created for your organisation:

    <api_key>whk_AbCd...:whs_XyZ...</api_key>

Every message is signed; the secret itself is never sent:
    x-legion-key-id:     the credential's public id (Legion learns the
                         organisation from this, not from anything you type)
    x-legion-timestamp:  current Unix time in seconds
    x-legion-nonce:      a fresh random value for every request
    x-legion-signature:  "v2=" + hex(HMAC-SHA256(SECRET,
                             "v2.<timestamp>.<nonce>." + <body bytes>))

Legion rejects a message whose body was changed, whose signature belongs to
another message or credential, whose timestamp is outside its window
(5 minutes by default), or whose nonce it has already seen (a replay). Keep the
Wazuh manager's clock in sync (NTP).

Rotation: create a new credential in Legion, put the new KEY_ID:SECRET in
ossec.conf and restart wazuh-manager. The old credential keeps working for the
overlap period Legion chose, so nothing is dropped in between.

Delivery is retried: a connection failure, timeout, 408, 429 or 5xx is tried
again (up to MAX_ATTEMPTS, with exponential backoff), each attempt signed
afresh with a new nonce -- so a retry is never mistaken for a replay. This is
safe because Legion de-duplicates events by id -- a retry of an event that was
in fact stored comes back as "duplicate". A 4xx other than 408/429 means the
request itself is wrong and is not retried. Legion only answers 2xx after the
alert is committed to its database.

Nothing is dropped when Legion is unreachable: an event that exhausts its
retries is written to
LEGION_SPOOL_DIR/<key id>/ and re-sent -- oldest first, with the same
credential only -- by the next invocation, or by
`custom-legion.py --drain <api_key> <hook_url>` from a timer (see WAZUH.md).
An event Legion refuses (401/403 or another 4xx) is kept in <key id>/dead/.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 10
MAX_ATTEMPTS = int(os.environ.get("LEGION_MAX_ATTEMPTS", "4"))
BACKOFF_BASE_SECONDS = float(os.environ.get("LEGION_BACKOFF_SECONDS", "1"))
RETRYABLE_STATUS = {408, 429}
# Named, so a CDN's bot protection in front of Legion does not take this for an
# abusive client (Python's default "Python-urllib/3.x" is a common block-list entry).
USER_AGENT = "Legion-Wazuh-Integration/2 (+custom-legion.py)"
# Legion refuses bodies over WEBHOOK_MAX_BODY_BYTES (1 MB by default) with 413,
# which is not retryable -- so an oversized event used to be dropped. Legion
# keeps only the first 4000 characters of full_log anyway, so an event larger
# than this has its full_log trimmed (never its id, rule or agent) before signing.
MAX_PAYLOAD_BYTES = int(os.environ.get("LEGION_MAX_PAYLOAD_BYTES", str(900 * 1024)))
TRIMMED_LOG_CHARS = 64 * 1024
LOG_FILE = os.environ.get("LEGION_INTEGRATION_LOG", "/var/ossec/logs/integrations.log")

# --sync-blocklist: Legion's automatic response, enforced by Wazuh itself.
# Each address to block becomes one JSON line in BLOCKLIST_LOG; Wazuh reads that
# file (<localfile>), rule 100950 (integrations/wazuh/legion_rules.xml) matches
# it and its active response runs firewall-drop on every agent, undone after the
# <timeout> configured there. While Legion still lists an address, it is
# re-announced every BLOCK_REFRESH_SECONDS so the block does not lapse; once
# Legion stops listing it (expired, or an administrator unblocked it), Wazuh's
# timeout lifts it. Keep BLOCK_REFRESH_SECONDS below that timeout.
BLOCKLIST_LOG = os.environ.get("LEGION_BLOCKLIST_LOG", "/var/ossec/logs/legion-blocklist.log")
BLOCKLIST_STATE = os.environ.get("LEGION_BLOCKLIST_STATE", "/var/ossec/tmp/legion-blocklist-state.json")
BLOCK_REFRESH_SECONDS = int(os.environ.get("LEGION_BLOCK_REFRESH_SECONDS", "300"))
LOG_GRACE_SECONDS = int(os.environ.get("LEGION_BLOCKLIST_LOG_GRACE_SECONDS", "120"))
LOG_CREATED_KEY = "_log_created"
# Our own block events must not travel back to Legion as new alerts.
OWN_RESPONSE_GROUP = "legion_response"


def log(message):
    line = f"legion: {message}\n"
    try:
        with open(LOG_FILE, "a") as handle:
            handle.write(line)
    except OSError:
        sys.stderr.write(line)


KEY_ID_RE = re.compile(r"^whk_[A-Za-z0-9_-]{22}$")


def sign(secret, timestamp, nonce, body):
    mac = hmac.new(secret.encode("utf-8"), f"v2.{timestamp}.{nonce}.".encode("utf-8"), hashlib.sha256)
    mac.update(body)
    return "v2=" + mac.hexdigest()


def parse_api_key(api_key):
    key_id, _, secret = api_key.partition(":")
    key_id, secret = key_id.strip(), secret.strip()
    if not KEY_ID_RE.match(key_id) or not secret:
        # Never echo api_key: it contains the secret.
        log("ERROR api_key must be formatted as KEY_ID:SECRET (whk_...:whs_...). "
            "The old TENANT_ID:SECRET format is no longer accepted -- ask a Legion "
            "administrator to create a webhook credential")
        return None
    return key_id, secret


def read_api_key(value):
    """A credential given directly, or as @/path/to/file (keeps it out of
    ossec.conf and the process list)."""
    if value.startswith("@"):
        try:
            with open(value[1:], "r") as handle:
                return handle.read().strip()
        except OSError as exc:
            log(f"ERROR could not read the credential file: {exc.strerror}")
            return ""
    return value


def blocklist_url(hook_url):
    if not hook_url.rstrip("/").endswith("/webhook"):
        return None
    return hook_url.rstrip("/")[: -len("/webhook")] + "/blocklist"


def payment_check_url(hook_url):
    if not hook_url.rstrip("/").endswith("/webhook"):
        return None
    return hook_url.rstrip("/")[: -len("/webhook")] + "/payment-check"


# Exit codes for --payment-check, so payment software can branch without parsing.
PAYMENT_ALLOW, PAYMENT_ERROR, PAYMENT_HOLD = 0, 1, 3


def payment_check(hook_url, key_id, secret, payment, out=sys.stdout):
    """Asks Legion whether a payment may go ahead. Prints Legion's answer as
    JSON. Returns 0 (allow), 3 (hold: do not pay yet) or 1 (could not ask).
    Anything but 0 means: do not pay automatically."""
    url = payment_check_url(hook_url)
    if not url:
        log("ERROR --payment-check needs the webhook URL (ending in /security-events/webhook)")
        return PAYMENT_ERROR
    if not isinstance(payment, dict):
        log("ERROR payment-check: the payment must be a JSON object")
        return PAYMENT_ERROR
    body = json.dumps(dict(payment, action="payment-check")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "x-legion-key-id": key_id,
        "x-legion-timestamp": timestamp,
        "x-legion-nonce": nonce,
        "x-legion-signature": sign(secret, timestamp, nonce, body),
    })
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            answer = json.loads(response.read(64 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        log(f"ERROR payment-check: Legion answered {exc.code}; do not pay automatically")
        return PAYMENT_ERROR
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        log(f"ERROR payment-check: could not reach Legion ({type(exc).__name__}); do not pay automatically")
        return PAYMENT_ERROR
    decision = answer.get("decision") if isinstance(answer, dict) else None
    if decision not in ("allow", "hold"):
        log("ERROR payment-check: unexpected answer from Legion; do not pay automatically")
        return PAYMENT_ERROR
    out.write(json.dumps(answer) + "\n")
    log(f"PAYMENT {answer.get('id', '?')} {decision}")
    return PAYMENT_ALLOW if decision == "allow" else PAYMENT_HOLD


def clean_text(value, limit=200):
    text = "".join(ch for ch in str(value or "") if ch.isprintable())
    return text[:limit]


def sync_blocklist(hook_url, key_id, secret):
    """Fetches the workspace's blocklist and hands new (or due) addresses to
    Wazuh's active response. Returns 0 on success."""
    url = blocklist_url(hook_url)
    if not url:
        log("ERROR --sync-blocklist needs the webhook URL (ending in /security-events/webhook)")
        return 1
    body = json.dumps({"action": "sync-blocklist"}).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "x-legion-key-id": key_id,
        "x-legion-timestamp": timestamp,
        "x-legion-nonce": nonce,
        "x-legion-signature": sign(secret, timestamp, nonce, body),
    })
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            data = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        log(f"ERROR blocklist: Legion answered {exc.code}; existing blocks stay until their Wazuh timeout")
        return 1
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        log(f"ERROR blocklist: could not reach Legion ({type(exc).__name__}); existing blocks stay until their Wazuh timeout")
        return 1

    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        log("ERROR blocklist: unexpected answer from Legion")
        return 1
    try:
        with open(BLOCKLIST_STATE, "r") as handle:
            state = json.load(handle)
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}

    # Wazuh's logcollector looks for a missing file about once a minute and
    # starts reading it at its END, so a line written into a file Wazuh has not
    # found yet is lost. When the file is new, create it and wait LOG_GRACE_SECONDS
    # before writing into it (the setup step `touch`es it, so this rarely waits).
    now = time.time()
    created = state.pop(LOG_CREATED_KEY, None)
    if not os.path.exists(BLOCKLIST_LOG):
        try:
            with open(BLOCKLIST_LOG, "a"):
                pass
        except OSError as exc:
            log(f"ERROR blocklist: could not create {BLOCKLIST_LOG}: {exc.strerror}")
            return 1
        created = now
    waiting = isinstance(created, (int, float)) and now - created < LOG_GRACE_SECONDS

    active = {}
    lines = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(str(entry.get("ip", "")).strip()))
        except ValueError:
            continue
        last = float(state.get(ip, 0)) if isinstance(state.get(ip, 0), (int, float)) else 0.0
        active[ip] = last
        if not waiting and now - last >= BLOCK_REFRESH_SECONDS:
            lines.append(json.dumps({
                "legion": {
                    "action": "block",
                    "reason": clean_text(entry.get("reason")),
                    "campaign": clean_text(entry.get("campaign_id") or "", 40),
                },
                "srcip": ip,
            }, separators=(",", ":")))
            active[ip] = now

    if lines:
        try:
            with open(BLOCKLIST_LOG, "a") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError as exc:
            log(f"ERROR blocklist: could not write {BLOCKLIST_LOG}: {exc.strerror}")
            return 1
    # Only addresses Legion still lists are remembered; one it drops is no longer
    # re-announced, so Wazuh lifts it at its timeout.
    if waiting:
        active[LOG_CREATED_KEY] = created
    tmp = f"{BLOCKLIST_STATE}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as handle:
            json.dump(active, handle)
        os.replace(tmp, BLOCKLIST_STATE)
    except OSError as exc:
        log(f"ERROR blocklist: could not save state: {exc.strerror}")
    log(f"BLOCKLIST {len(active) - (1 if waiting else 0)} active, {len(lines)} sent to active response"
        + (" (waiting for Wazuh to find the new log file)" if waiting else ""))
    return 0


def main(argv):
    # Payment check, for payment software (ERP, bank connector) before it pays:
    #   custom-legion.py --payment-check <api_key or @file> <hook_url> <payment.json or ->
    # payment.json: {"beneficiary": {"account": "...", "name": "..."}, "amount": 12500,
    #                "currency": "EUR", "requestedBy": "dana@acme.example"}
    # Exit 0: allow. Exit 3: hold (a person must confirm by phone). Exit 1: error — do not pay.
    if len(argv) == 5 and argv[1] == "--payment-check":
        creds = parse_api_key(read_api_key(argv[2]))
        if not creds:
            return PAYMENT_ERROR
        try:
            if argv[4] == "-":
                payment = json.load(sys.stdin)
            else:
                with open(argv[4], "r", encoding="utf-8") as handle:
                    payment = json.load(handle)
        except (OSError, ValueError):
            log("ERROR payment-check: could not read the payment JSON")
            return PAYMENT_ERROR
        return payment_check(argv[3], creds[0], creds[1], payment)
    # Blocklist mode, for Wazuh's command wodle (every minute):
    #   custom-legion.py --sync-blocklist <api_key or @file> <hook_url>
    if len(argv) == 4 and argv[1] == "--sync-blocklist":
        creds = parse_api_key(read_api_key(argv[2]))
        if not creds:
            return 1
        return sync_blocklist(argv[3], creds[0], creds[1])
    # Drain mode, for a timer:  custom-legion.py --drain <api_key> <hook_url>
    # After a credential rotation, an operator may re-send what the OLD
    # credential could not deliver:  ... --drain <new api_key> <hook_url> --from <old key id>
    # From a timer, keep the secret out of the process list:
    #   LEGION_API_KEY=... LEGION_HOOK_URL=... custom-legion.py --drain
    if len(argv) == 2 and argv[1] == "--drain":
        api_key, hook_url = os.environ.get("LEGION_API_KEY", ""), os.environ.get("LEGION_HOOK_URL", "")
        if not api_key or not hook_url:
            log("ERROR --drain without arguments needs LEGION_API_KEY and LEGION_HOOK_URL in the environment")
            return 1
        argv = [argv[0], "--drain", api_key, hook_url]
    if len(argv) in (4, 6) and argv[1] == "--drain":
        creds = parse_api_key(argv[2])
        if not creds:
            return 1
        source = creds[0]
        if len(argv) == 6:
            if argv[4] != "--from" or not KEY_ID_RE.match(argv[5]):
                log("ERROR usage: --drain <api_key> <hook_url> [--from <old key id>]")
                return 1
            source = argv[5]
        state = drain(argv[3], creds[0], creds[1], limit=None, source_key_id=source)
        return 0 if state == "clear" else 1

    if len(argv) < 4:
        log("ERROR wrong argument count; expected <alert_file> <api_key> <hook_url>")
        return 1

    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    creds = parse_api_key(api_key)
    if not creds:
        return 1
    key_id, secret = creds

    try:
        with open(alert_file, "r") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log(f"ERROR could not read alert file {alert_file}: {exc}")
        return 1

    # Legion reads req.body.event, so wrap the Wazuh alert as-is. Its field
    # names (rule.description, rule.level, rule.mitre.id, full_log,
    # data.srcip, agent.name, id, timestamp) already match what the webhook expects.
    groups = alert.get("rule", {}).get("groups") or []
    if isinstance(groups, list) and OWN_RESPONSE_GROUP in groups:
        return 0  # Legion's own block, as Wazuh recorded it: nothing to report
    payload = build_payload(alert)
    rule_id = str(alert.get("rule", {}).get("id", "?"))

    # Anything left over from an outage goes first (a bounded batch per run),
    # so the backlog empties as soon as Legion is reachable again.
    drain(hook_url, key_id, secret, limit=DRAIN_BATCH)

    status = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        outcome, status = post_once(hook_url, key_id, secret, payload, rule_id, attempt)
        if outcome == "ok":
            return 0
        if outcome in ("fatal", "hold") or attempt == MAX_ATTEMPTS:
            break
        time.sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))

    # Not delivered, and never silently dropped:
    #  - Legion down, overloaded or failing (no answer, 408, 429, 5xx): kept in
    #    this credential's spool and re-sent automatically.
    #  - Refused (401/403: revoked, wrong or rotated credential; or any other
    #    4xx): kept in this credential's dead/ folder. It is NOT re-sent under
    #    another credential automatically -- on a manager serving several
    #    organisations that would deliver one organisation's events to another.
    #    After a rotation an operator re-sends it explicitly with --from.
    if is_retryable(status):
        if spool(payload, rule_id, key_id):
            log(f"SPOOLED rule={rule_id} after {attempt} attempt(s); it will be re-sent when Legion accepts it")
            return 1
    else:
        spool(payload, rule_id, key_id, dead=True)
    log(f"ERROR rule={rule_id} not delivered after {attempt} attempt(s)")
    return 1


# --- the spool: events Legion could not take yet ----------------------------------------
#
# Files hold the unsigned body only (never the secret), mode 0600 in a 0700
# directory, named <nanoseconds>-<body hash>.json so the oldest drains first
# and an identical event spooled twice is one file. A drain claims a file by
# renaming it before sending, so several integration processes running at once
# never send the same file together (and if they did, Legion's per-event
# de-duplication would absorb it). A claim left by a crashed process is
# returned to the queue after STALE_CLAIM_SECONDS.

SPOOL_DIR = os.environ.get("LEGION_SPOOL_DIR", "/var/ossec/tmp/legion-spool")
SPOOL_MAX_FILES = int(os.environ.get("LEGION_SPOOL_MAX_FILES", "50000"))
DRAIN_BATCH = int(os.environ.get("LEGION_DRAIN_BATCH", "200"))
STALE_CLAIM_SECONDS = 600


def blocked_by_cdn(exc):
    """A CDN in front of Legion (Cloudflare) refused the request before Legion
    saw it -- bot protection or a challenge page. That is not Legion's verdict
    on the event or the credential, so the event is kept (spooled) rather than
    set aside as refused, and goes out once the CDN lets it through. Legion's
    own refusals are JSON, even when they pass through Cloudflare."""
    headers = exc.headers or {}
    if headers.get("cf-mitigated"):
        return True
    server = (headers.get("server") or "").lower()
    content_type = (headers.get("content-type") or "").lower()
    return exc.code in (403, 503) and server == "cloudflare" and "json" not in content_type


def is_retryable(status):
    """No HTTP answer, 408, 429 or 5xx: Legion may accept it later."""
    return status is None or status >= 500 or status in RETRYABLE_STATUS


def spool_dir(key_id):
    """One spool per credential: events are only ever re-sent with the
    credential -- and so to the organisation -- they were meant for."""
    return os.path.join(SPOOL_DIR, key_id)


def _spool_files(key_id):
    try:
        return sorted(n for n in os.listdir(spool_dir(key_id)) if n.endswith(".json"))
    except FileNotFoundError:
        return []


def spool(payload, rule_id, key_id, dead=False):
    """Keeps an undelivered event on disk. Returns False only if it could not be written."""
    base = spool_dir(key_id)
    directory = os.path.join(base, "dead") if dead else base
    try:
        os.makedirs(SPOOL_DIR, mode=0o700, exist_ok=True)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(base, 0o700)
        if not dead:
            waiting = _spool_files(key_id)
            if len(waiting) >= SPOOL_MAX_FILES:
                # Full: the oldest go, loudly. Recent events are the actionable ones.
                excess = waiting[: len(waiting) - SPOOL_MAX_FILES + 1]
                for name in excess:
                    try:
                        os.remove(os.path.join(base, name))
                    except FileNotFoundError:
                        pass
                log(f"ERROR spool full ({SPOOL_MAX_FILES} events): dropped the {len(excess)} oldest")
        name = f"{time.time_ns():020d}-{hashlib.sha256(payload).hexdigest()[:16]}.json"
        tmp = os.path.join(directory, f".{name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(tmp, os.path.join(directory, name))
        if dead:
            log(f"ERROR rule={rule_id} refused by Legion; kept in {directory}. If the credential was "
                f"rotated, re-send with: --drain <new api_key> <hook_url> --from {key_id}")
        return True
    except OSError as exc:
        log(f"ERROR rule={rule_id} could not be spooled ({type(exc).__name__}); it is lost")
        return False


def _release_stale_claims(directory):
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return
    now = time.time()
    for name in names:
        if ".json.claim-" not in name:
            continue
        path = os.path.join(directory, name)
        try:
            if now - os.path.getmtime(path) > STALE_CLAIM_SECONDS:
                os.rename(path, os.path.join(directory, name.split(".claim-")[0]))
        except OSError:
            pass


def drain(hook_url, key_id, secret, limit, source_key_id=None):
    """Re-sends this credential's spooled events (or, with source_key_id, a
    rotated-away credential's -- an explicit operator action), oldest first,
    one attempt each. Stops at the first failure that means "Legion still
    cannot take it". Returns "clear" when nothing is left, "more" when the
    batch ended with events waiting, and "blocked" when Legion is still refusing."""
    source = source_key_id or key_id
    directory = spool_dir(source)
    if source_key_id and source_key_id != key_id:
        # The operator named an old credential: its refused events count too.
        dead = os.path.join(directory, "dead")
        for name in (os.listdir(dead) if os.path.isdir(dead) else []):
            if name.endswith(".json"):
                os.rename(os.path.join(dead, name), os.path.join(directory, name))
    _release_stale_claims(directory)
    sent = 0
    for name in _spool_files(source)[: limit or None]:
        path = os.path.join(directory, name)
        claimed = f"{path}.claim-{os.getpid()}"
        try:
            os.rename(path, claimed)
        except OSError:
            continue  # another process has it
        try:
            with open(claimed, "rb") as handle:
                payload = handle.read()
        except OSError:
            continue
        outcome, status = post_once(hook_url, key_id, secret, payload, "spooled", 1)
        if outcome == "ok":
            os.remove(claimed)
            sent += 1
            continue
        if is_retryable(status) or status in (401, 403):
            # Still down -- or this credential is refused: keep it, stop here.
            os.rename(claimed, path)
            if sent:
                log(f"DRAIN re-sent {sent} spooled event(s) before Legion stopped accepting")
            return "blocked"
        os.makedirs(os.path.join(directory, "dead"), mode=0o700, exist_ok=True)
        os.rename(claimed, os.path.join(directory, "dead", name))
        log(f"ERROR a spooled event was refused (HTTP {status}); moved to dead/ for review")
    if sent:
        log(f"DRAIN re-sent {sent} spooled event(s)")
    return "clear" if not _spool_files(source) else "more"


def build_payload(alert):
    """The signed body. Oversized events keep everything Legion stores; only
    the tail of full_log, which Legion would discard, is cut."""
    payload = json.dumps({"provider": "wazuh", "event": alert}).encode("utf-8")
    if len(payload) <= MAX_PAYLOAD_BYTES or not isinstance(alert.get("full_log"), str):
        return payload
    trimmed = dict(alert)
    trimmed["full_log"] = alert["full_log"][:TRIMMED_LOG_CHARS] + " [truncated by custom-legion]"
    return json.dumps({"provider": "wazuh", "event": trimmed}).encode("utf-8")


def post_once(hook_url, key_id, secret, payload, rule_id, attempt):
    """One signed POST. Returns (outcome, http_status) with outcome "ok",
    "retry" or "fatal" and status None when no HTTP answer came back. Never
    logs the secret, the signature or the alert body."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)  # new for every attempt
    request = urllib.request.Request(
        hook_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "x-legion-key-id": key_id,
            "x-legion-timestamp": timestamp,
            "x-legion-nonce": nonce,
            # Signs these exact bytes: the server verifies before parsing.
            "x-legion-signature": sign(secret, timestamp, nonce, payload),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", "replace")[:300]
            log(f"OK rule={rule_id} status={response.status} attempt={attempt} {body}")
            return "ok", response.status
    except urllib.error.HTTPError as exc:
        if blocked_by_cdn(exc):
            log(f"ERROR rule={rule_id} status={exc.code} attempt={attempt} blocked by Cloudflare before it reached Legion "
                "(bot protection / challenge). Add a WAF skip rule for /api/security-events/webhook -- "
                "DEPLOY-ONLINE.md section 12.5. The event is kept and re-sent automatically.")
            return "hold", None
        detail = exc.read().decode("utf-8", "replace")[:300]
        log(f"ERROR rule={rule_id} status={exc.code} attempt={attempt} {detail}")
        return ("retry" if exc.code >= 500 or exc.code in RETRYABLE_STATUS else "fatal"), exc.code
    except urllib.error.URLError as exc:
        log(f"ERROR rule={rule_id} attempt={attempt} could not reach Legion: {exc.reason}")
        return "retry", None
    except TimeoutError:
        log(f"ERROR rule={rule_id} attempt={attempt} timed out")
        return "retry", None
    except Exception as exc:  # never let an integration crash the Wazuh manager
        log(f"ERROR rule={rule_id} attempt={attempt} unexpected failure: {type(exc).__name__}")
        return "fatal", None


if __name__ == "__main__":
    sys.exit(main(sys.argv))
