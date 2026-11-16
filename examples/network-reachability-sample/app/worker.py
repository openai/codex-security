"""Intentionally vulnerable HTTP worker for a synthetic reachability benchmark."""

import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


def route_request(path, query, diagnostics_enabled=None):
    if diagnostics_enabled is None:
        diagnostics_enabled = os.environ.get("ENABLE_DIAGNOSTIC") == "1"
    if path == "/health":
        return 200, {"status": "ok"}
    if path == "/run":
        command = query.get("cmd", ["sample"])[0]
        # NR-001/002/003: the same command injection runs on three instances.
        result = subprocess.run(
            f"printf '%s\\n' {command}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return 200, {"output": result.stdout, "exit_code": result.returncode}
    if path == "/diagnostic":
        if not diagnostics_enabled:
            return 404, {"error": "not_found"}
        expression = query.get("expr", ["1 + 1"])[0]
        # NR-004: deployed workers disable this route; the gateway also omits it.
        return 200, {"result": str(eval(expression))}  # noqa: S307
    return 404, {"error": "not_found"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        request = urlsplit(self.path)
        status, body = route_request(request.path, parse_qs(request.query))
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
