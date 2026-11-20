"""Tiny webhook receiver for local docker-compose runs.

POST /hooks/{tenant}  -> verifies the HMAC signature with that tenant's secret, stores the event
GET  /events/{tenant} -> returns events received for that tenant (to show isolation)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRETS = json.loads(os.getenv("WEBHOOK_SECRETS", "{}"))  # {"acme": "...", "globex": "..."}
EVENTS: dict[str, list] = defaultdict(list)


def _expected(secret: str, ts: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        parts = self.path.strip("/").split("/")
        if len(parts) != 2 or parts[0] != "hooks":
            return self._send(404, {"error": "not found"})
        tenant = parts[1]
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        secret = SECRETS.get(tenant)
        sig, ts = self.headers.get("X-Risk-Signature", ""), self.headers.get("X-Risk-Timestamp", "")
        if not secret or not hmac.compare_digest(_expected(secret, ts, body), sig):
            print(f"[mock-webhook] REJECTED bad signature for tenant={tenant}", flush=True)
            return self._send(401, {"error": "bad signature"})
        event = json.loads(body)
        EVENTS[tenant].append(event)
        ids = [t["transaction_id"] for t in event.get("transactions", [])]
        print(
            f"[mock-webhook] tenant={tenant} severity={event.get('severity')} txns={ids} reason={event.get('reason')}",
            flush=True,
        )
        return self._send(200, {"received": True})

    def do_GET(self):  # noqa: N802
        parts = self.path.strip("/").split("/")
        if parts == ["health"]:
            return self._send(200, {"ok": True})
        if len(parts) == 2 and parts[0] == "events":
            return self._send(200, {"events": EVENTS.get(parts[1], [])})
        return self._send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(os.getenv("PORT", "9000"))
    print(f"[mock-webhook] listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
