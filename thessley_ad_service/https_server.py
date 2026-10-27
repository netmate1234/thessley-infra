"""Small TLS HTTP transport for the standalone AD API.

This adapter is intentionally independent of the Linux Thessley PAM listener so
the same route logic can be hosted by an isolated Windows lab service later.
"""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .http_api import RawBodyRoute

MAX_BODY_BYTES = 64 * 1024
_MACHINE_AUTH_HEADERS = (
    "x-thessley-machine-id",
    "x-thessley-timestamp",
    "x-thessley-nonce",
    "x-thessley-signature",
)


def _auth_headers(headers) -> dict[str, str]:
    selected: dict[str, str] = {}
    for name in _MACHINE_AUTH_HEADERS:
        values = headers.get_all(name, [])
        if len(values) > 1 or (values and len(values[0]) > 256):
            raise ValueError("Invalid machine authentication headers.")
        if values:
            selected[name] = values[0]
    return selected


def make_server(address: tuple[str, int], certfile: str, keyfile: str,
                routes: dict[str, "RawBodyRoute"]) -> ThreadingHTTPServer:
    """Create a bounded POST-only JSON server with TLS 1.2 or newer."""

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: dict) -> None:
            raw = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            try:
                path = urlsplit(self.path)
            except ValueError:
                self._reply(400, {"result": "error", "message": "Invalid request path."})
                return
            route = routes.get(path.path) if not path.query and not path.fragment else None
            if route is None:
                self._reply(404, {"result": "error", "message": "Not found."})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get_content_type() != "application/json"):
                self._reply(400, {"result": "error", "message": "Invalid request body."})
                return
            try:
                length = int(lengths[0])
            except (TypeError, ValueError):
                length = 0
            if not 1 <= length <= MAX_BODY_BYTES:
                self._reply(400, {"result": "error", "message": "Invalid request body."})
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise ValueError
                auth = _auth_headers(self.headers)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self._reply(400, {"result": "error", "message": "Invalid request body."})
                return
            try:
                status, reply = route.handler(self.client_address[0], body, raw, auth)
                if (isinstance(status, bool) or not isinstance(status, int)
                        or not 100 <= status <= 599 or not isinstance(reply, dict)):
                    raise ValueError("invalid API response")
            except Exception:
                status, reply = 500, {"result": "error", "message": "Could not process this request."}
            self._reply(status, reply)

        def do_GET(self) -> None:
            self._reply(405, {"result": "error", "message": "POST required."})

        def log_message(self, _format: str, *_args) -> None:
            return

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, _request, _client_address) -> None:
            return

    httpd = Server(address, Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def serve(server: ThreadingHTTPServer, stop: threading.Event) -> None:
    """Serve until the caller signals stop; always close the listening socket."""
    thread = threading.Thread(target=server.serve_forever, name="thessley-ad-https", daemon=True)
    thread.start()
    try:
        stop.wait()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
