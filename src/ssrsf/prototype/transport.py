"""Small, bounded JSON HTTP transport for the private Compose testbed."""
from __future__ import annotations

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from .store import Denied

MAX_BODY = 8192


class RemoteError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def request(url, token, body, timeout=5):
    # Explicitly avoid environment proxies for private service traffic and secrets.
    req = Request(url, json.dumps(body, allow_nan=False).encode(),
                  {"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
    try:
        with build_opener(ProxyHandler({})).open(req, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as exc:
        status = exc.code
        try:
            payload = json.loads(exc.read(MAX_BODY))
            message = payload.get("error", "Request rejected") if isinstance(payload, dict) else "Request rejected"
        except (ValueError, OSError):
            message = "Request rejected"
        finally:
            exc.close()
        raise RemoteError(status, message if isinstance(message, str) else "Request rejected") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise RemoteError(503, "Service unavailable") from exc


def authenticated(header, credentials):
    if not isinstance(header, str) or not header.startswith("Bearer "):
        raise Denied("Missing credential")
    supplied = header[7:]
    for identity, token in credentials.items():
        if hmac.compare_digest(supplied.encode(), token.encode()):
            return identity
    raise Denied("Invalid credential")


def server(address, dispatch, credentials):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass  # Do not log credentials, document bodies or bearer task grants.

        def reply(self, code, payload):
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.reply(200 if self.path == "/health" else 404,
                       {"ok": self.path == "/health"})

        def do_POST(self):
            try:
                identity = authenticated(self.headers.get("Authorization"), credentials)
            except Denied:
                self.reply(401, {"error": "Authentication required"})
                return
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                    raise Denied("One content length required")
                size = int(lengths[0])
                if not 0 < size <= MAX_BODY or self.headers.get("Content-Type") != "application/json":
                    raise Denied("Invalid content type or body size")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise Denied("Incomplete body")
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise Denied("Expected JSON object")
                result = dispatch(identity, self.path, body)
            except Denied as exc:
                self.reply(403, {"error": str(exc)})
            except (ValueError, UnicodeError, TypeError):
                self.reply(400, {"error": "Malformed request"})
            except RemoteError as exc:
                self.reply(503 if exc.status >= 500 else 403, {"error": "Upstream request failed"})
            except Exception:
                self.reply(503, {"error": "Operation unavailable; retry with the same id"})
            else:
                self.reply(200, result)

    return ThreadingHTTPServer(address, Handler)
