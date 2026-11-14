"""Public gateway with two fixed paths to the private benchmark workers."""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen


TARGETS = {
    "/open": os.environ.get("OPEN_WORKER_HOST"),
    "/blocked": os.environ.get("BLOCKED_WORKER_HOST"),
    "/acl-blocked": os.environ.get("ACL_BLOCKED_WORKER_HOST"),
}


def route_request(path, query, targets=TARGETS, fetch=urlopen):
    if path == "/health":
        return 200, {"status": "ok"}
    host = targets.get(path)
    if host is None:
        return 404, {"error": "not_found"}
    address = f"http://{host}:8080/run"
    if query:
        address += f"?{query}"
    try:
        with fetch(address, timeout=2) as response:
            return response.status, json.load(response)
    except (TimeoutError, URLError):
        return 502, {"error": "upstream_unavailable"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urlsplit(self.path)
        status, body = route_request(request.path, request.query)
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
