"""Exercise the fixture over real HTTP and save the observed evidence."""

import argparse
import json
import runpy
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    app = runpy.run_path(str(Path(__file__).with_name("app.py")))
    server = app["create_server"]()
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def get(invoice, token=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            headers = (
                {} if token is None else {"Authorization": f"Bearer {token}"}
            )
            connection.request("GET", f"/invoices/{invoice}", headers=headers)
            response = connection.getresponse()
            return {"status": response.status, "body": json.loads(response.read())}
        finally:
            connection.close()

    try:
        anonymous = get("1002")
        own_invoice = get("1001", "demo-alice")
        other_invoice = get("1002", "demo-alice")
        assert anonymous["status"] == 401, "Authentication control failed"
        assert own_invoice["status"] == 200, "Own-account control failed"
        evidence = {
            "anonymous": anonymous,
            "own_invoice": own_invoice,
            "other_invoice": other_invoice,
            "cross_account_read": (
                other_invoice["status"] == 200
                and other_invoice["body"].get("owner") == "bob"
            ),
        }
    finally:
        server.shutdown()
        server.server_close()
        worker.join()

    evidence["server_stopped"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
