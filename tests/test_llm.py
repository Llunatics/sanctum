"""Unit tests for sanctum.llm — URL/redirect hardening (no real backend)."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from sanctum.llm import LLMError, _check_url, chat_completions_full


class _RedirectToOtherOrigin(BaseHTTPRequestHandler):
    target = None  # set per-test: full URL on another port

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *a):
        pass


class _SameOriginRedirect(BaseHTTPRequestHandler):
    def _handle(self):
        if self.path == "/v1/chat/completions":
            self.send_response(302)
            self.send_header("Location", "/v1/redirected")
            self.end_headers()
        else:
            body = json.dumps(
                {"choices": [{"message": {"role": "assistant",
                                          "content": "ok"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # urllib turns a 302-redirected POST into a GET: serve both.
    do_POST = _handle
    do_GET = _handle

    def log_message(self, *a):
        pass


def _serve(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _BigError(BaseHTTPRequestHandler):
    def do_POST(self):
        body = b"x" * (2 * 1024 * 1024)
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class TestErrorBodyCap(unittest.TestCase):
    def test_huge_error_body_does_not_hang_or_oom(self):
        srv = _serve(_BigError)
        try:
            t0 = __import__("time").time()
            with self.assertRaises(LLMError) as cm:
                chat_completions_full(
                    "http://127.0.0.1:%d/v1" % srv.server_address[1],
                    "m", [{"role": "user", "content": "hi"}], timeout=10)
            self.assertIn("HTTP 500", str(cm.exception))
            # Must fail fast: only the first 8k of the 2MB body is read.
            self.assertLess(__import__("time").time() - t0, 5)
        finally:
            srv.shutdown()


class TestUrlChecks(unittest.TestCase):
    def test_non_http_refused(self):
        for bad in ("file:///etc/passwd", "ftp://x/y", "gopher://x",
                    "not-a-url", ""):
            with self.assertRaises(LLMError, msg=bad):
                _check_url(bad)

    def test_http_ok(self):
        _check_url("http://127.0.0.1:1/v1")  # no network, just parsing


class TestRedirects(unittest.TestCase):
    def test_cross_origin_redirect_refused(self):
        other = _serve(_SameOriginRedirect)
        other_port = other.server_address[1]
        redir = _serve(_RedirectToOtherOrigin)
        _RedirectToOtherOrigin.target = (
            "http://127.0.0.1:%d/v1/chat/completions" % other_port)
        try:
            with self.assertRaises(LLMError) as cm:
                chat_completions_full(
                    "http://127.0.0.1:%d/v1" % redir.server_address[1],
                    "m", [{"role": "user", "content": "hi"}], timeout=5)
            self.assertIn("cross-origin", str(cm.exception))
        finally:
            redir.shutdown()
            other.shutdown()

    def test_same_origin_redirect_followed(self):
        srv = _serve(_SameOriginRedirect)
        try:
            msg = chat_completions_full(
                "http://127.0.0.1:%d/v1" % srv.server_address[1],
                "m", [{"role": "user", "content": "hi"}], timeout=5)
            self.assertEqual(msg.get("content"), "ok")
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()


class TestResponseCapAndChoiceOrder(unittest.TestCase):
    """Deep-8 S18/S19: response-size cap and first-choice selection."""

    def test_read_is_capped_at_max_response_bytes(self):
        # Deep-8 S18: the client must never ask for more than the 10MB cap.
        from unittest import mock

        recorded = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                recorded["n"] = n
                return b'{"choices": [{"message": {"content": "hi"}}]}'

        class FakeOpener:
            def open(self, req, timeout=None):
                return FakeResp()

        with mock.patch("urllib.request.build_opener",
                        return_value=FakeOpener()):
            msg = chat_completions_full("http://127.0.0.1:1/v1", "m",
                                        [{"role": "user", "content": "hi"}])
        self.assertEqual(msg["content"], "hi")
        self.assertLessEqual(recorded["n"], 10 * 1024 * 1024)

    def test_first_choice_is_used(self):
        # Deep-8 S19: with several choices, the first one wins.
        from unittest import mock
        from sanctum import llm
        body = {"choices": [{"message": {"content": "first"}},
                           {"message": {"content": "second"}}]}
        with mock.patch.object(llm, "_post_json", return_value=body):
            msg = chat_completions_full("http://127.0.0.1:1/v1", "m",
                                        [{"role": "user", "content": "hi"}])
        self.assertEqual(msg["content"], "first")
