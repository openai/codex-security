"""Local behavior checks; AWS security-group claims require a deployed stack."""

import io
import json
import unittest

from app.gateway import route_request as gateway_request
from app.worker import route_request as worker_request


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class ReachabilityBehaviorTests(unittest.TestCase):
    def test_worker_command_input_executes_a_second_benign_command(self):
        status, body = worker_request("/run", {"cmd": ["sample; printf BENCHMARK_PROOF"]})
        self.assertEqual(status, 200)
        self.assertIn("BENCHMARK_PROOF", body["output"])

    def test_gateway_selects_only_fixed_worker_run_paths(self):
        requests = []

        def fetch(url, timeout):
            requests.append((url, timeout))
            return Response(json.dumps({"output": "sample"}).encode())

        targets = {
            "/open": "10.80.1.10",
            "/blocked": "10.80.1.11",
            "/acl-blocked": "10.80.2.10",
        }
        for path in ("/open", "/blocked", "/acl-blocked"):
            status, _ = gateway_request(path, "cmd=sample", targets, fetch)
            self.assertEqual(status, 200)
        self.assertEqual(
            requests,
            [
                ("http://10.80.1.10:8080/run?cmd=sample", 2),
                ("http://10.80.1.11:8080/run?cmd=sample", 2),
                ("http://10.80.2.10:8080/run?cmd=sample", 2),
            ],
        )
        status, _ = gateway_request("/diagnostic", "expr=1", targets, fetch)
        self.assertEqual(status, 404)
        self.assertEqual(len(requests), 3)

    def test_worker_diagnostic_code_is_executable_locally(self):
        status, body = worker_request(
            "/diagnostic", {"expr": ["40 + 2"]}, diagnostics_enabled=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["result"], "42")
        status, body = worker_request(
            "/diagnostic", {"expr": ["40 + 2"]}, diagnostics_enabled=False
        )
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "not_found")


if __name__ == "__main__":
    unittest.main()
