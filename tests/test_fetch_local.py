"""Safe-fetch behaviour against a local HTTP server (private targets enabled ONLY for this test)."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.security import ssrf


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/r":
            self.send_response(302); self.send_header("Location", "/page"); self.end_headers(); return
        if self.path == "/loop":
            self.send_response(302); self.send_header("Location", "/loop"); self.end_headers(); return
        body = b"<title>Big</title>" + b"A" * 3_000_000 if self.path == "/big" else b"<title>Hello</title>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body)


@pytest.fixture()
def server(monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ALLOW_PRIVATE_TARGETS", "1")
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_follows_redirect(server):
    r = ssrf.safe_fetch(server + "/r")
    assert r.ok and "Hello" in r.html and [c["status"] for c in r.chain] == [302, 200]


def test_response_size_limit(server):
    r = ssrf.safe_fetch(server + "/big", max_bytes=100_000)
    assert r.truncated and len(r.html) <= 100_000


def test_redirect_loop_stops(server):
    r = ssrf.safe_fetch(server + "/loop", max_redirects=3)
    assert not r.ok and "redirect" in r.error.lower()
