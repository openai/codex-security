"""Behavior checks for the synthetic security workflow sample."""

import json
import sys
import threading
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.data import create_database, list_orders, lookup_order
from app.reports import orders_by_region
from app.server import OrderHandler, create_server


class QueryScenarios(unittest.TestCase):
    def test_order_and_report_queries_expose_cross_tenant_rows(self):
        database = create_database()
        self.addCleanup(database.close)
        self.assertEqual(
            [row["id"] for row in list_orders(database, "acme")],
            ["A-101", "A-102"],
        )
        self.assertEqual(lookup_order(database, "B-201")["tenant_id"], "beacon")
        self.assertEqual(
            [row["id"] for row in orders_by_region(database, "acme", "west")],
            ["A-101"],
        )
        changed = orders_by_region(database, "acme", "absent' OR 1=1 --")
        self.assertEqual(
            {row["tenant_id"] for row in changed},
            {"acme", "beacon", "cedar"},
        )


class MemoryRequest:
    def __init__(self, request):
        self.input = BytesIO(request)
        self.output = BytesIO()

    def makefile(self, mode, _buffering=None):
        return self.input if mode == "rb" else self.output

    def sendall(self, data):
        self.output.write(data)


class RouteScenariosWithoutSockets(unittest.TestCase):
    def test_authenticated_routes_reach_both_flaws(self):
        database = create_database()
        self.addCleanup(database.close)
        server = SimpleNamespace(
            database=database, server_name="localhost", server_port=80
        )

        def get(path, token=None):
            authorization = f"Authorization: Bearer {token}\r\n" if token else ""
            request = MemoryRequest(
                f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                f"{authorization}\r\n".encode()
            )
            OrderHandler(request, ("127.0.0.1", 1), server)
            head, body = request.output.getvalue().split(b"\r\n\r\n", 1)
            status = int(head.split(b"\r\n", 1)[0].split()[1])
            return status, json.loads(body)

        self.assertEqual(get("/api/orders")[0], 401)
        own_status, own = get("/api/orders", "demo-acme")
        self.assertEqual(own_status, 200)
        self.assertEqual(len(own["orders"]), 2)
        other_status, other = get("/api/orders/B-201", "demo-acme")
        self.assertEqual(other_status, 200)
        self.assertEqual(other["order"]["tenant_id"], "beacon")
        region = quote("absent' OR 1=1 --", safe="")
        report_status, report = get(f"/api/reports/orders?region={region}", "demo-acme")
        self.assertEqual(report_status, 200)
        self.assertEqual(len(report["orders"]), 6)


class SecurityWorkflowScenarios(unittest.TestCase):
    def setUp(self):
        self.server = create_server()
        self.worker = threading.Thread(target=self.server.serve_forever)
        self.worker.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.worker.join(timeout=5)
        self.server.server_close()

    def get(self, path, token=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(self.origin + path, headers=headers)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_order_lookup_crosses_customer_boundary(self):
        self.assertEqual(self.get("/health"), (200, {"status": "ok"}))
        self.assertEqual(self.get("/api/orders")[0], 401)
        status, own_list = self.get("/api/orders", "demo-acme")
        self.assertEqual(status, 200)
        self.assertEqual(
            {order["id"] for order in own_list["orders"]}, {"A-101", "A-102"}
        )
        self.assertEqual(self.get("/api/orders/A-101", "demo-acme")[0], 200)

        for order_id, tenant_id in [
            ("B-201", "beacon"),
            ("B-202", "beacon"),
            ("C-301", "cedar"),
            ("C-302", "cedar"),
        ]:
            with self.subTest(order_id=order_id):
                status, body = self.get(f"/api/orders/{order_id}", "demo-acme")
                self.assertEqual(status, 200)
                self.assertEqual(body["order"]["tenant_id"], tenant_id)

    def test_report_region_input_changes_sql_predicate(self):
        status, normal = self.get("/api/reports/orders?region=west", "demo-acme")
        self.assertEqual(status, 200)
        self.assertEqual([order["id"] for order in normal["orders"]], ["A-101"])
        self.assertEqual(
            self.get("/api/reports/orders?region=absent", "demo-acme"),
            (200, {"orders": []}),
        )

        region = quote("absent' OR 1=1 --", safe="")
        status, changed = self.get(f"/api/reports/orders?region={region}", "demo-acme")
        self.assertEqual(status, 200)
        self.assertEqual(len(changed["orders"]), 6)
        self.assertEqual(
            {order["tenant_id"] for order in changed["orders"]},
            {"acme", "beacon", "cedar"},
        )


class DeploymentInventoryScenario(unittest.TestCase):
    def test_inventory_names_three_distinct_source_roots(self):
        inventory = json.loads((ROOT / "deployment/inventory.json").read_text())
        services = inventory["services"]
        self.assertEqual(
            {service["name"] for service in services},
            {"order-report-api", "billing-api", "analytics-worker"},
        )
        self.assertEqual(len({service["source"] for service in services}), 3)
        for service in services:
            self.assertTrue((ROOT / service["source"]).is_dir())
        self.assertTrue(services[0]["ingress"]["internetExposed"])
        self.assertFalse(services[1]["ingress"]["internetExposed"])
        self.assertIsNone(services[2]["ingress"])


if __name__ == "__main__":
    unittest.main()
