"""Deliberately vulnerable local fixture. Do not deploy this application."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# These identities, tokens, and records are synthetic demo data.
TOKENS = {"demo-alice": "alice", "demo-bob": "bob"}
INVOICES = {
    "1001": {"id": "1001", "owner": "alice", "amount": 25},
    "1002": {"id": "1002", "owner": "bob", "amount": 80},
}


class InvoiceHandler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        user = TOKENS.get(token)
        if user is None:
            return self.reply(401, {"error": "unauthorized"})
        if not self.path.startswith("/invoices/"):
            return self.reply(404, {"error": "not found"})
        invoice = INVOICES.get(self.path.removeprefix("/invoices/"))
        if invoice is None:
            return self.reply(404, {"error": "not found"})
        # BUG: authentication does not establish ownership of this invoice.
        return self.reply(200, invoice)

    def log_message(self, format, *args):
        pass


def create_server():
    return ThreadingHTTPServer(("127.0.0.1", 0), InvoiceHandler)


if __name__ == "__main__":
    with create_server() as server:
        print(f"http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()
