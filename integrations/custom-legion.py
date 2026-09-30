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
# Legion refuses bodies over WEBHOOK_MAX_BODY_BYTES (1 MB by default) with 413,
# which is not retryable -- so an oversized event used to be dropped. Legion
# keeps only the first 4000 characters of full_log anyway, so an event larger
# than this has its full_log trimmed (never its id, rule or agent) before signing.
MAX_PAYLOAD_BYTES = int(os.environ.get("LEGION_MAX_PAYLOAD_BYTES", str(900 * 1024)))
TRIMMED_LOG_CHARS = 64 * 1024
LOG_FILE = os.environ.get("LEGION_INTEGRATION_LOG", "/var/ossec/logs/integrations.log")


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


def main(argv):
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
        if outcome == "fatal" or attempt == MAX_ATTEMPTS:
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
