from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

SERVICE_ROLE_KEY = "sb_service_role_PENNY_DEMO_SUPER_PRIVATE_DO_NOT_SHIP_2026"
SEED = json.loads((Path(__file__).parent / "seed_data.json").read_text(encoding="utf-8"))


class Handler(BaseHTTPRequestHandler):
    server_version = "PennyPlantedApp/0.1"

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_value(self) -> str:
        api_key = self.headers.get("apikey", "")
        authorization = self.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            return authorization.split(" ", 1)[1]
        return api_key

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._json(200, {"status": "healthy"})
            return
        if path == "/rest/v1/private_notes":
            if self._auth_value() == SERVICE_ROLE_KEY:
                self._json(200, SEED["private_notes"])
                return
            self._json(403, {"error": "anon key cannot read private_notes"})
            return
        if path.startswith("/api/orders/"):
            order_id = path.rsplit("/", 1)[-1]
            order = SEED["orders"].get(order_id)
            if order is None:
                self._json(404, {"error": "not found"})
                return
            self._json(200, order)
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    port = int(os.environ.get("PORT", "8787"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Penny planted app listening on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
