"""Tests for the Wazuh -> Legion integration's delivery retries.

    python3 -m unittest integrations/test_custom_legion.py
"""
import hashlib
import hmac
import importlib.util
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


def load_module(log_file):
    os.environ["LEGION_INTEGRATION_LOG"] = log_file
    os.environ["LEGION_BACKOFF_SECONDS"] = "0"
    spec = importlib.util.spec_from_file_location("custom_legion", HERE / "custom-legion.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Server:
    """Answers with the given status codes in order, then 202; records requests."""

    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
                status = outer.statuses.pop(0) if outer.statuses else 202
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

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
        self.assertIn("not delivered after 4 attempt(s)", self.logged())

    def test_retries_rate_limit(self):
        code, reqs = self.run_with([429])
        self.assertEqual((code, len(reqs)), (0, 2))

    def test_does_not_retry_a_rejected_request(self):
        code, reqs = self.run_with([401])
        self.assertEqual((code, len(reqs)), (1, 1))

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


if __name__ == "__main__":
    unittest.main()
