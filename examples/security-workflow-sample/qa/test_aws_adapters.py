"""Checks for the entry points used by the AWS Lambda deployment."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.lambda_handler import handler as order_handler
from deployment.aws.package import package
from deployment.services.analytics.worker import handler as analytics_handler
from deployment.services.billing.service import handler as billing_handler


class LambdaEntryPoints(unittest.TestCase):
    def get(self, path, token=None, query=""):
        headers = {"authorization": f"Bearer {token}"} if token else {}
        response = order_handler(
            {
                "rawPath": path,
                "rawQueryString": query,
                "headers": headers,
                "requestContext": {"http": {"method": "GET"}},
            },
            None,
        )
        return response["statusCode"], json.loads(response["body"])

    def test_order_api_preserves_synthetic_findings(self):
        self.assertEqual(self.get("/api/orders")[0], 401)
        self.assertEqual(
            self.get("/api/orders", "demo-acme")[1]["orders"][0]["id"], "A-101"
        )
        status, other = self.get("/api/orders/B-201", "demo-acme")
        self.assertEqual(status, 200)
        self.assertEqual(other["order"]["tenant_id"], "beacon")
        query = "region=" + quote("absent' OR 1=1 --", safe="")
        status, report = self.get("/api/reports/orders", "demo-acme", query)
        self.assertEqual(status, 200)
        self.assertEqual(
            {row["tenant_id"] for row in report["orders"]},
            {"acme", "beacon", "cedar"},
        )

    def test_negative_controls_have_deployed_entry_points(self):
        with patch.dict("os.environ", {"AUTHORIZED_TENANT_ID": "acme"}):
            balance = billing_handler({"authorized_tenant_id": "beacon"}, None)
        self.assertEqual(balance, {"tenant_id": "acme", "balance_cents": 500})
        self.assertEqual(analytics_handler({}, None), {"acme_order_count": 2})

    def test_archives_exclude_qa_answer_key(self):
        with tempfile.TemporaryDirectory() as directory:
            package(Path(directory))
            with ZipFile(Path(directory) / "order.zip") as archive:
                names = set(archive.namelist())
            self.assertIn("app/lambda_handler.py", names)
            self.assertNotIn("qa/expected-findings.json", names)


if __name__ == "__main__":
    unittest.main()
