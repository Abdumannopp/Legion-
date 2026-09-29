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


def main(argv):
    if len(argv) < 4:
        log("ERROR wrong argument count; expected <alert_file> <api_key> <hook_url>")
        return 1

    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]

    key_id, _, secret = api_key.partition(":")
    key_id, secret = key_id.strip(), secret.strip()
    if not KEY_ID_RE.match(key_id) or not secret:
        # Never echo api_key: it contains the secret.
        log("ERROR api_key must be formatted as KEY_ID:SECRET (whk_...:whs_...). "
            "The old TENANT_ID:SECRET format is no longer accepted -- ask a Legion "
            "administrator to create a webhook credential")
        return 1

    try:
        with open(alert_file, "r") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log(f"ERROR could not read alert file {alert_file}: {exc}")
        return 1

    # Legion reads req.body.event, so wrap the Wazuh alert as-is. Its field
    # names (rule.description, rule.level, rule.mitre.id, full_log,
    # data.srcip, agent.name, id) already match what the webhook expects.
    payload = json.dumps({"provider": "wazuh", "event": alert}).encode("utf-8")
    rule_id = str(alert.get("rule", {}).get("id", "?"))

    for attempt in range(1, MAX_ATTEMPTS + 1):
        outcome = post_once(hook_url, key_id, secret, payload, rule_id, attempt)
        if outcome == "ok":
            return 0
        if outcome == "fatal" or attempt == MAX_ATTEMPTS:
            break
        time.sleep(BACKOFF_BASE_SECONDS * 2 ** (attempt - 1))
    log(f"ERROR rule={rule_id} not delivered after {attempt} attempt(s)")
    return 1


def post_once(hook_url, key_id, secret, payload, rule_id, attempt):
    """One signed POST. Returns "ok", "retry" or "fatal". Never logs the secret,
    the signature or the alert body."""
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
            return "ok"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        log(f"ERROR rule={rule_id} status={exc.code} attempt={attempt} {detail}")
        return "retry" if exc.code >= 500 or exc.code in RETRYABLE_STATUS else "fatal"
    except urllib.error.URLError as exc:
        log(f"ERROR rule={rule_id} attempt={attempt} could not reach Legion: {exc.reason}")
        return "retry"
    except TimeoutError:
        log(f"ERROR rule={rule_id} attempt={attempt} timed out")
        return "retry"
    except Exception as exc:  # never let an integration crash the Wazuh manager
        log(f"ERROR rule={rule_id} attempt={attempt} unexpected failure: {type(exc).__name__}")
        return "fatal"


if __name__ == "__main__":
    sys.exit(main(sys.argv))
