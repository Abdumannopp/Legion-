"""Tests for the Wazuh -> Legion integration's delivery retries.

    python3 -m unittest integrations/test_custom_legion.py
"""
import hashlib
import hmac
import importlib.util
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEY_ID = "whk_AbCdEfGhIjKlMnOpQrStUv"
SECRET = "whs_wazuh-shared-secret-do-not-log-0123456789"
API_KEY = f"{KEY_ID}:{SECRET}"
SENSITIVE = "sshd: password for root is hunter2-do-not-log"


def load_module(log_file, spool_dir=None, **env):
    os.environ["LEGION_INTEGRATION_LOG"] = log_file
    os.environ["LEGION_BACKOFF_SECONDS"] = "0"
    os.environ["LEGION_SPOOL_DIR"] = spool_dir or os.path.join(os.path.dirname(log_file), "spool")
    for k, v in env.items():
        os.environ[k] = str(v)
    spec = importlib.util.spec_from_file_location("custom_legion", HERE / "custom-legion.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Server:
    """Answers with the given status codes in order, then 202; records requests."""

    def __init__(self, statuses, default=202):
        self.statuses = list(statuses)
        self.default = default
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
                status = outer.statuses.pop(0) if outer.statuses else outer.default
                # A status may be (code, headers, body): e.g. a CDN's challenge page.
                code, headers, reply = status if isinstance(status, tuple) else (status, {}, b'{"status":"ok"}')
                self.send_response(code)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/security-events/webhook"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "integrations.log")
        self.mod = load_module(self.log)
        self.alert_file = os.path.join(self.dir.name, "alert.json")
        with open(self.alert_file, "w") as f:
            json.dump({"id": "1700000000.1", "full_log": SENSITIVE, "rule": {"id": "5712", "level": 10, "description": "brute force"}}, f)

    def tearDown(self):
        self.dir.cleanup()

    def run_with(self, statuses):
        server = Server(statuses)
        try:
            code = self.mod.main(["custom-legion", self.alert_file, API_KEY, server.url])
        finally:
            server.close()
        return code, server.requests

    def logged(self):
        with open(self.log) as f:
            return f.read()

    def test_retries_server_errors_until_accepted(self):
        code, reqs = self.run_with([503, 500])
        self.assertEqual(code, 0)
        self.assertEqual(len(reqs), 3)
        # Same event every time; each attempt signed on its own.
        self.assertEqual(len({r["body"] for r in reqs}), 1)
        for r in reqs:
            self.assertTrue(r["headers"]["x-legion-signature"].startswith("v2="))

    def test_every_attempt_has_a_fresh_nonce_so_a_retry_is_never_a_replay(self):
        _, reqs = self.run_with([503, 503])
        self.assertEqual(len(reqs), 3)
        nonces = [r["headers"]["x-legion-nonce"] for r in reqs]
        self.assertEqual(len(set(nonces)), 3)
        self.assertEqual(len({r["headers"]["x-legion-signature"] for r in reqs}), 3)

    def test_request_matches_the_documented_scheme(self):
        _, reqs = self.run_with([])
        h = reqs[0]["headers"]
        # The credential id identifies the organisation; none is named directly.
        self.assertEqual(h["x-legion-key-id"], KEY_ID)
        self.assertNotIn("x-tenant-id", h)
        self.assertNotIn("x-security-event-secret", h)
        # Independent re-computation: HMAC-SHA256(secret, "v2.<ts>.<nonce>." + raw body)
        mac = hmac.new(SECRET.encode(), f"v2.{h['x-legion-timestamp']}.{h['x-legion-nonce']}.".encode(), hashlib.sha256)
        mac.update(reqs[0]["body"])
        self.assertEqual(h["x-legion-signature"], "v2=" + mac.hexdigest())
        self.assertGreaterEqual(len(h["x-legion-nonce"]), 16)
        self.assertLessEqual(abs(int(h["x-legion-timestamp"]) - __import__("time").time()), 5)

    def test_rejects_the_old_tenant_id_format_without_echoing_the_secret(self):
        server = Server([])
        try:
            old_style = "11111111-2222-3333-4444-555555555555:old-global-secret-do-not-log"
            code = self.mod.main(["custom-legion", self.alert_file, old_style, server.url])
        finally:
            server.close()
        self.assertEqual((code, len(server.requests)), (1, 0))  # nothing was sent
        self.assertIn("KEY_ID:SECRET", self.logged())
        self.assertNotIn("old-global-secret-do-not-log", self.logged())

    def test_gives_up_after_max_attempts(self):
        code, reqs = self.run_with([503] * 10)
        self.assertEqual(code, 1)
        self.assertEqual(len(reqs), self.mod.MAX_ATTEMPTS)
        # Not lost: after the last attempt the event is kept for a later re-send.
        self.assertIn("SPOOLED rule=5712 after 4 attempt(s)", self.logged())

    def test_retries_rate_limit(self):
        code, reqs = self.run_with([429])
        self.assertEqual((code, len(reqs)), (0, 2))

    def test_does_not_retry_a_rejected_request(self):
        code, reqs = self.run_with([401])
        self.assertEqual((code, len(reqs)), (1, 1))

    def test_sends_a_named_user_agent_not_pythons_default(self):
        _, requests = self.run_with([])
        self.assertTrue(requests[0]["headers"]["user-agent"].startswith("Legion-Wazuh-Integration/"))

    def test_a_cloudflare_challenge_is_kept_for_later_not_set_aside_as_refused(self):
        challenge = (403, {"Server": "cloudflare", "cf-mitigated": "challenge", "Content-Type": "text/html"}, b"<html>Just a moment...</html>")
        code, requests = self.run_with([challenge])
        self.assertEqual(code, 1)
        self.assertEqual(len(requests), 1)  # no pointless retries against the CDN
        spool = os.path.join(self.mod.SPOOL_DIR, KEY_ID)
        self.assertEqual(len([n for n in os.listdir(spool) if n.endswith(".json")]), 1)
        self.assertFalse(os.path.isdir(os.path.join(spool, "dead")))
        self.assertIn("blocked by Cloudflare", self.logged())
        self.assertIn("DEPLOY-ONLINE.md", self.logged())

    def test_legions_own_refusal_through_cloudflare_is_still_a_refusal(self):
        refused = (403, {"Server": "cloudflare", "Content-Type": "application/json"}, b'{"detail":"Invalid webhook signature"}')
        code, requests = self.run_with([refused])
        self.assertEqual(code, 1)
        self.assertEqual(len(requests), 1)
        self.assertTrue(os.path.isdir(os.path.join(self.mod.SPOOL_DIR, KEY_ID, "dead")))
        self.assertNotIn("blocked by Cloudflare", self.logged())

    def test_retries_when_legion_is_unreachable(self):
        server = Server([])
        url = server.url
        server.close()  # nothing listening any more
        code = self.mod.main(["custom-legion", self.alert_file, API_KEY, url])
        self.assertEqual(code, 1)
        self.assertEqual(self.logged().count("could not reach Legion"), self.mod.MAX_ATTEMPTS)

    def test_never_logs_secret_signature_or_alert_body(self):
        _, reqs = self.run_with([503])
        log = self.logged()
        self.assertNotIn(SECRET, log)
        self.assertNotIn(reqs[0]["headers"]["x-legion-signature"], log)
        self.assertNotIn(reqs[0]["headers"]["x-legion-nonce"], log)
        self.assertNotIn("hunter2", log)

    def test_an_oversized_event_is_trimmed_not_dropped(self):
        with open(self.alert_file, "w") as f:
            json.dump({"id": "1700000000.2", "full_log": "X" * (2 * 1024 * 1024),
                       "rule": {"id": "5712", "level": 10, "description": "huge"}}, f)
        code, reqs = self.run_with([])
        self.assertEqual(code, 0)
        body = reqs[0]["body"]
        self.assertLessEqual(len(body), self.mod.MAX_PAYLOAD_BYTES)
        event = json.loads(body)["event"]
        # Identity and classification are untouched; only the log tail is cut.
        self.assertEqual(event["id"], "1700000000.2")
        self.assertEqual(event["rule"]["description"], "huge")
        self.assertTrue(event["full_log"].endswith("[truncated by custom-legion]"))

    def test_a_normal_event_is_sent_byte_for_byte_unchanged(self):
        _, reqs = self.run_with([])
        with open(self.alert_file) as f:
            original = json.load(f)
        self.assertEqual(json.loads(reqs[0]["body"])["event"], original)


def write_alert(path, alert_id, description="brute force"):
    with open(path, "w") as f:
        json.dump({"id": alert_id, "timestamp": "2026-09-30T01:02:03.456+0000", "full_log": SENSITIVE,
                   "rule": {"id": "5712", "level": 10, "description": description}}, f)


class SpoolTests(unittest.TestCase):
    """Legion unreachable must never mean the event is gone."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "integrations.log")
        self.spool_dir = os.path.join(self.dir.name, "spool")
        self.mod = load_module(self.log, self.spool_dir)
        self.alert = os.path.join(self.dir.name, "alert.json")

    def tearDown(self):
        self.dir.cleanup()

    def spooled(self, key_id=KEY_ID):
        d = os.path.join(self.spool_dir, key_id)
        return sorted(n for n in os.listdir(d) if n.endswith(".json")) if os.path.isdir(d) else []

    def dead(self, key_id=KEY_ID):
        d = os.path.join(self.spool_dir, key_id, "dead")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def send(self, server_or_url, alert_id):
        write_alert(self.alert, alert_id)
        url = server_or_url if isinstance(server_or_url, str) else server_or_url.url
        return self.mod.main(["custom-legion", self.alert, API_KEY, url])

    def down_url(self):
        s = Server([]); url = s.url; s.close()
        return url

    def test_legion_down_the_event_is_spooled_not_lost(self):
        self.assertEqual(self.send(self.down_url(), "e-1"), 1)
        files = self.spooled()
        self.assertEqual(len(files), 1)
        with open(os.path.join(self.spool_dir, KEY_ID, files[0]), "rb") as f:
            body = json.loads(f.read())
        self.assertEqual(body["event"]["id"], "e-1")
        self.assertIn("SPOOLED", open(self.log).read())

    def test_the_spool_holds_no_secret_and_is_private(self):
        self.send(self.down_url(), "e-1")
        name = self.spooled()[0]
        path = os.path.join(self.spool_dir, KEY_ID, name)
        self.assertNotIn(SECRET.encode(), open(path, "rb").read())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.spool_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(self.spool_dir, KEY_ID)).st_mode & 0o777, 0o700)

    def test_when_legion_returns_the_backlog_goes_first_oldest_first_then_the_new_event(self):
        down = self.down_url()
        for i in range(3):
            self.send(down, f"e-{i}")
        self.assertEqual(len(self.spooled()), 3)
        server = Server([])
        try:
            self.assertEqual(self.send(server, "e-new"), 0)
        finally:
            server.close()
        ids = [json.loads(r["body"])["event"]["id"] for r in server.requests]
        self.assertEqual(ids, ["e-0", "e-1", "e-2", "e-new"])
        self.assertEqual(self.spooled(), [])
        # Each re-send was signed afresh (a new nonce), so it is not a replay.
        self.assertEqual(len({r["headers"]["x-legion-nonce"] for r in server.requests}), 4)

    def test_drain_mode_empties_the_spool_without_a_new_alert(self):
        down = self.down_url()
        for i in range(5):
            self.send(down, f"e-{i}")
        server = Server([])
        try:
            self.assertEqual(self.mod.main(["custom-legion", "--drain", API_KEY, server.url]), 0)
        finally:
            server.close()
        self.assertEqual(len(server.requests), 5)
        self.assertEqual(self.spooled(), [])

    def test_drain_mode_reads_the_credential_from_the_environment(self):
        self.send(self.down_url(), "e-env")
        server = Server([])
        os.environ["LEGION_API_KEY"], os.environ["LEGION_HOOK_URL"] = API_KEY, server.url
        try:
            self.assertEqual(self.mod.main(["custom-legion", "--drain"]), 0)
        finally:
            server.close()
            del os.environ["LEGION_API_KEY"], os.environ["LEGION_HOOK_URL"]
        self.assertEqual(len(server.requests), 1)

    def test_drain_stops_at_the_first_failure_and_keeps_the_rest(self):
        down = self.down_url()
        for i in range(4):
            self.send(down, f"e-{i}")
        server = Server([202, 503], default=503)  # takes one, then goes down again
        try:
            self.assertEqual(self.mod.main(["custom-legion", "--drain", API_KEY, server.url]), 1)
        finally:
            server.close()
        self.assertEqual(len(server.requests), 2)
        self.assertEqual(len(self.spooled()), 3)

    def test_one_event_that_always_gets_500_does_not_hold_back_the_ones_behind_it(self):
        down = self.down_url()
        for i in range(4):
            self.send(down, f"e-{i}")                       # e-0 is the oldest: it drains first
        server = Server([500], default=202)                 # 500 for the oldest, then Legion accepts the rest
        try:
            self.assertEqual(self.mod.main(["custom-legion", "--drain", API_KEY, server.url]), 1)
        finally:
            server.close()
        self.assertEqual(len(server.requests), 4)           # it went on to the other three
        left = self.spooled()
        self.assertEqual(len(left), 1)                      # only the oldest remains, still queued
        with open(os.path.join(self.spool_dir, KEY_ID, left[0]), "rb") as f:
            self.assertEqual(json.loads(f.read())["event"]["id"], "e-0")
        # The count is kept beside the spool, and is never mistaken for an event.
        self.assertTrue(os.path.exists(os.path.join(self.spool_dir, KEY_ID, "failures.state")))
        self.assertEqual(self.dead(), [])

    def test_after_ten_500s_while_others_are_accepted_it_is_set_aside_not_lost(self):
        down = self.down_url()
        self.send(down, "poison")
        for run in range(10):
            self.send(down, f"ok-{run}")
            server = Server([500], default=202)
            try:
                self.mod.main(["custom-legion", "--drain", API_KEY, server.url])
            finally:
                server.close()
        self.assertEqual(self.spooled(), [])                # nothing is waiting any more
        self.assertEqual(len(self.dead()), 1)               # the poison one is kept for review
        self.assertIn("moved to dead/ for review", open(self.log).read())
        self.assertFalse(os.path.exists(os.path.join(self.spool_dir, KEY_ID, "failures.state")))
        with open(os.path.join(self.spool_dir, KEY_ID, "dead", self.dead()[0]), "rb") as f:
            self.assertEqual(json.loads(f.read())["event"]["id"], "poison")

    def test_three_different_events_in_a_row_getting_500_looks_like_an_outage_and_stops(self):
        down = self.down_url()
        for i in range(6):
            self.send(down, f"e-{i}")
        server = Server([], default=500)
        try:
            self.assertEqual(self.mod.main(["custom-legion", "--drain", API_KEY, server.url]), 1)
        finally:
            server.close()
        self.assertEqual(len(server.requests), 3)           # did not hammer the rest
        self.assertEqual(len(self.spooled()), 6)            # and nothing was set aside

    def test_503_is_still_an_outage_and_stops_at_once(self):
        down = self.down_url()
        for i in range(4):
            self.send(down, f"e-{i}")
        server = Server([], default=503)
        try:
            self.mod.main(["custom-legion", "--drain", API_KEY, server.url])
        finally:
            server.close()
        self.assertEqual(len(server.requests), 1)
        self.assertEqual(len(self.spooled()), 4)

    def test_a_refused_credential_keeps_the_event_and_an_operator_can_resend_it_after_rotation(self):
        server = Server([], default=401)
        try:
            self.send(server, "e-1")
        finally:
            server.close()
        # Kept (not lost), but NOT queued for automatic re-sending.
        self.assertEqual(self.spooled(), [])
        self.assertEqual(len(self.dead()), 1)
        self.assertIn(f"--from {KEY_ID}", open(self.log).read())
        # The operator rotated the credential and re-sends the old one's events explicitly.
        new_key = "whk_NewNewNewNewNewNewNewN:whs_rotated-secret-0123456789"
        ok = Server([])
        try:
            self.assertEqual(self.mod.main(["custom-legion", "--drain", new_key, ok.url, "--from", KEY_ID]), 0)
        finally:
            ok.close()
        self.assertEqual([json.loads(r["body"])["event"]["id"] for r in ok.requests], ["e-1"])
        self.assertEqual(ok.requests[0]["headers"]["x-legion-key-id"], "whk_NewNewNewNewNewNewNewN")
        self.assertEqual(self.dead(), [])

    def test_one_credentials_backlog_is_never_sent_with_another_credential(self):
        # A manager serving two organisations: A's outage backlog must not
        # reach B when B's integration runs.
        self.send(self.down_url(), "a-secret-event")
        other = "whk_BBBBBBBBBBBBBBBBBBBBBB:whs_organisation-b-secret-0123"
        write_alert(self.alert, "b-event")
        server = Server([])
        try:
            self.assertEqual(self.mod.main(["custom-legion", self.alert, other, server.url]), 0)
        finally:
            server.close()
        self.assertEqual([json.loads(r["body"])["event"]["id"] for r in server.requests], ["b-event"])
        self.assertEqual(len(self.spooled()), 1)  # A's event still waits for A's credential

    def test_a_request_legion_can_never_accept_is_set_aside_not_retried_forever(self):
        server = Server([], default=400)
        try:
            self.send(server, "e-1")
        finally:
            server.close()
        self.assertEqual(self.spooled(), [])
        self.assertEqual(len(self.dead()), 1)

    def test_two_drains_at_once_never_send_the_same_file_twice(self):
        down = self.down_url()
        for i in range(30):
            self.send(down, f"e-{i}")
        server = Server([])
        try:
            threads = [threading.Thread(target=self.mod.drain, args=(server.url, KEY_ID, SECRET, None)) for _ in range(4)]
            for t in threads: t.start()
            for t in threads: t.join()
        finally:
            server.close()
        ids = [json.loads(r["body"])["event"]["id"] for r in server.requests]
        self.assertEqual(len(ids), 30)
        self.assertEqual(len(set(ids)), 30)

    def test_a_claim_left_by_a_crashed_process_is_returned_to_the_queue(self):
        self.send(self.down_url(), "e-1")
        name = self.spooled()[0]
        claimed = os.path.join(self.spool_dir, KEY_ID, name) + ".claim-99999"
        os.rename(os.path.join(self.spool_dir, KEY_ID, name), claimed)
        old = __import__("time").time() - self.mod.STALE_CLAIM_SECONDS - 5
        os.utime(claimed, (old, old))
        server = Server([])
        try:
            self.mod.main(["custom-legion", "--drain", API_KEY, server.url])
        finally:
            server.close()
        self.assertEqual(len(server.requests), 1)

    def test_a_full_spool_drops_the_oldest_loudly(self):
        self.mod = load_module(self.log, self.spool_dir, LEGION_SPOOL_MAX_FILES=3)
        down = self.down_url()
        for i in range(5):
            self.send(down, f"e-{i}")
        kept = [json.loads(open(os.path.join(self.spool_dir, KEY_ID, n), "rb").read())["event"]["id"] for n in self.spooled()]
        self.assertEqual(kept, ["e-2", "e-3", "e-4"])
        self.assertIn("spool full", open(self.log).read())
        load_module(self.log, self.spool_dir, LEGION_SPOOL_MAX_FILES=50000)



class BlocklistTests(unittest.TestCase):
    """--sync-blocklist: Legion's list becomes Wazuh active-response lines."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "integrations.log")
        self.out = os.path.join(self.dir.name, "legion-blocklist.log")
        self.state = os.path.join(self.dir.name, "state.json")
        self.mod = load_module(self.log, LEGION_BLOCKLIST_LOG=self.out, LEGION_BLOCKLIST_STATE=self.state,
                               LEGION_BLOCK_REFRESH_SECONDS=300)
        open(self.out, "a").close()  # the setup step creates it; see the fresh-file test

    def tearDown(self):
        self.dir.cleanup()

    def sync(self, entries, status=200, api_key=API_KEY):
        reply = json.dumps({"entries": entries}).encode()
        server = Server([(status, {"Content-Type": "application/json"}, reply)])
        try:
            url = server.url  # .../security-events/webhook; the script derives /blocklist
            code = self.mod.main(["custom-legion", "--sync-blocklist", api_key, url])
        finally:
            server.close()
        return code, server.requests

    def lines(self):
        if not os.path.exists(self.out):
            return []
        with open(self.out) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_asks_signed_for_its_list_and_writes_one_line_per_address(self):
        code, requests = self.sync([
            {"ip": "45.155.205.12", "reason": "Automatic: campaign CMP-1 (rapid chain)", "campaign_id": "CMP-1"},
            {"ip": "2a00:1450:4001:80b::200e", "reason": "manual", "campaign_id": None},
        ])
        self.assertEqual(code, 0)
        self.assertEqual(len(requests), 1)
        self.assertEqual(json.loads(requests[0]["body"]), {"action": "sync-blocklist"})
        headers = requests[0]["headers"]
        self.assertEqual(headers["x-legion-key-id"], KEY_ID)
        self.assertTrue(headers["x-legion-signature"].startswith("v2="))
        lines = self.lines()
        self.assertEqual([l["srcip"] for l in lines], ["45.155.205.12", "2a00:1450:4001:80b::200e"])
        self.assertEqual(lines[0]["legion"], {"action": "block", "reason": "Automatic: campaign CMP-1 (rapid chain)", "campaign": "CMP-1"})
        self.assertNotIn(SECRET, open(self.log).read())

    def test_a_brand_new_log_file_is_created_and_left_alone_until_wazuh_has_found_it(self):
        # Wazuh looks for a missing file about once a minute and reads it from its
        # end: a line written into a file it has not found yet would be lost.
        os.remove(self.out)
        entry = [{"ip": "45.155.205.12", "reason": "r"}]
        self.assertEqual(self.sync(entry)[0], 0)
        self.assertTrue(os.path.exists(self.out))
        self.assertEqual(self.lines(), [])
        self.sync(entry)                       # a minute later: still within the grace period
        self.assertEqual(self.lines(), [])
        with open(self.state) as f:
            state = json.load(f)
        self.assertEqual(set(state), {"45.155.205.12", "_log_created"})
        state["_log_created"] -= 121
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.sync(entry)
        self.assertEqual([l["srcip"] for l in self.lines()], ["45.155.205.12"])
        with open(self.state) as f:
            self.assertEqual(set(json.load(f)), {"45.155.205.12"})   # the marker is gone

    def test_an_address_is_announced_again_only_when_due(self):
        entry = [{"ip": "45.155.205.12", "reason": "r"}]
        self.sync(entry)
        self.sync(entry)
        self.assertEqual(len(self.lines()), 1)  # not due yet
        with open(self.state) as f:
            state = json.load(f)
        state["45.155.205.12"] -= 301
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.sync(entry)
        self.assertEqual(len(self.lines()), 2)  # refreshed before Wazuh's timeout lifts it

    def test_an_address_legion_stops_listing_is_forgotten(self):
        self.sync([{"ip": "45.155.205.12", "reason": "r"}])
        self.sync([])
        with open(self.state) as f:
            self.assertEqual(json.load(f), {})

    def test_anything_that_is_not_an_address_is_ignored(self):
        self.sync([{"ip": "45.155.205.12; rm -rf /", "reason": "x"}, {"ip": "", "reason": "x"}, "junk",
                   {"ip": "8.8.8.8", "reason": "line\nbreak\u0000and control"}])
        lines = self.lines()
        self.assertEqual([l["srcip"] for l in lines], ["8.8.8.8"])
        self.assertEqual(lines[0]["legion"]["reason"], "linebreakand control")

    def test_legion_unreachable_or_refusing_writes_nothing(self):
        code, _ = self.sync([{"ip": "8.8.8.8"}], status=401)
        self.assertEqual(code, 1)
        self.assertEqual(self.lines(), [])
        self.assertIn("existing blocks stay until their Wazuh timeout", open(self.log).read())

    def test_the_credential_can_come_from_a_file(self):
        key_file = os.path.join(self.dir.name, "legion.key")
        with open(key_file, "w") as f:
            f.write(API_KEY + "\n")
        code, requests = self.sync([{"ip": "8.8.8.8", "reason": "r"}], api_key="@" + key_file)
        self.assertEqual(code, 0)
        self.assertEqual(requests[0]["headers"]["x-legion-key-id"], KEY_ID)

    def test_legions_own_block_events_are_not_sent_back(self):
        alert_file = os.path.join(self.dir.name, "alert.json")
        with open(alert_file, "w") as f:
            json.dump({"id": "1.2", "rule": {"id": "100950", "groups": ["legion", "legion_response"], "description": "block"}}, f)
        server = Server([])
        try:
            code = self.mod.main(["custom-legion", alert_file, API_KEY, server.url])
        finally:
            server.close()
        self.assertEqual(code, 0)
        self.assertEqual(server.requests, [])

if __name__ == "__main__":
    unittest.main()


class PaymentCheckTests(unittest.TestCase):
    """--payment-check: payment software asks Legion before paying."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "integrations.log")
        self.mod = load_module(self.log)
        self.payment = {"beneficiary": {"account": "DE89370400440532013000", "name": "Acme"}, "amount": 12500, "currency": "EUR"}

    def tearDown(self):
        self.dir.cleanup()

    def ask(self, reply, status=200, payment=None):
        server = Server([(status, {"Content-Type": "application/json"}, json.dumps(reply).encode())])
        out = io.StringIO()
        try:
            code = self.mod.payment_check(server.url, KEY_ID, SECRET, payment if payment is not None else self.payment, out=out)
        finally:
            server.close()
        return code, server.requests, out.getvalue()

    def test_allow_exits_0_and_the_request_is_signed_and_purpose_bound(self):
        code, requests, out = self.ask({"id": "PAY-1", "decision": "allow", "reasons": [], "verify": None})
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["decision"], "allow")
        self.assertEqual(len(requests), 1)
        body = json.loads(requests[0]["body"])
        self.assertEqual(body["action"], "payment-check")
        self.assertEqual(body["amount"], 12500)
        self.assertTrue(requests[0]["headers"]["x-legion-signature"].startswith("v2="))
        self.assertNotIn(SECRET, open(self.log).read())

    def test_hold_exits_3(self):
        code, _, out = self.ask({"id": "PAY-2", "decision": "hold", "reasons": [{"code": "new_beneficiary"}], "verify": "call"})
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["reasons"][0]["code"], "new_beneficiary")

    def test_any_failure_means_do_not_pay(self):
        # Legion refuses, is unreachable, or answers nonsense: never exit 0.
        self.assertEqual(self.ask({"detail": "x"}, status=401)[0], 1)
        self.assertEqual(self.ask({"decision": "maybe"})[0], 1)
        self.assertEqual(self.mod.payment_check("http://127.0.0.1:9/security-events/webhook", KEY_ID, SECRET, self.payment, out=io.StringIO()), 1)
        self.assertEqual(self.mod.payment_check("http://example/other", KEY_ID, SECRET, self.payment, out=io.StringIO()), 1)
        self.assertEqual(self.ask({"decision": "allow"}, payment=["not", "an", "object"])[0], 1)
