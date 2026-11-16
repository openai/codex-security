"""Loopback HTTP entry point for the order API."""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from .data import TOKENS, create_database, list_orders, lookup_order
from .reports import orders_by_region


class OrderServer(HTTPServer):
    def __init__(self, port=0):
        self.database = create_database()
        super().__init__(("127.0.0.1", port), OrderHandler)

    def server_close(self):
        super().server_close()
        self.database.close()


class OrderHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        pass

    def reply(self, status, body):
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        status, body = route_request(
            self.path, self.headers.get("Authorization", ""), self.server.database
        )
        self.reply(status, body)


def route_request(path, authorization, database):
    target = urlsplit(path)
    if target.path == "/health":
        return 200, {"status": "ok"}

    token = authorization.removeprefix("Bearer ")
    tenant_id = TOKENS.get(token)
    if not authorization.startswith("Bearer ") or tenant_id is None:
        return 401, {"error": "unauthorized"}

    if target.path == "/api/orders":
        return 200, {"orders": [dict(row) for row in list_orders(database, tenant_id)]}
    if target.path.startswith("/api/orders/"):
        order_id = unquote(target.path.removeprefix("/api/orders/"))
        order = lookup_order(database, order_id)
        if order is None:
            return 404, {"error": "order not found"}
        return 200, {"order": dict(order)}
    if target.path == "/api/reports/orders":
        region = parse_qs(target.query).get("region", [""])[0]
        rows = orders_by_region(database, tenant_id, region)
        return 200, {"orders": [dict(row) for row in rows]}
    return 404, {"error": "not found"}


def create_server(port=0):
    return OrderServer(port)


if __name__ == "__main__":
    server = create_server(int(os.environ.get("PORT", "4312")))
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
