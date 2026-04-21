from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts" / "verify_oidc_live_config.py"


class _OIDCHandler(BaseHTTPRequestHandler):
    issuer_base = ""

    def do_GET(self):  # noqa: N802
        if self.path == "/.well-known/openid-configuration":
            body = {
                "issuer": self.issuer_base,
                "authorization_endpoint": f"{self.issuer_base}/authorize",
                "token_endpoint": f"{self.issuer_base}/token",
                "jwks_uri": f"{self.issuer_base}/jwks",
            }
            payload = json.dumps(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A003
        return


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def test_verify_oidc_live_config_script_passes_with_live_discovery():
    port = _free_port()
    issuer = f"http://127.0.0.1:{port}"
    _OIDCHandler.issuer_base = issuer
    server = HTTPServer(("127.0.0.1", port), _OIDCHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = {
            **dict(os.environ),
            "OIDC_ISSUER_URL": issuer,
            "OIDC_CLIENT_ID": "client-id",
            "OIDC_CLIENT_SECRET": "client-secret",
            "OIDC_REDIRECT_URI": "http://127.0.0.1:8000/auth/oidc/callback",
        }
        proc = subprocess.run(
            [sys.executable, str(_script_path()), "--require-configured"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    finally:
        server.shutdown()
        server.server_close()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert '"ok": true' in proc.stdout
