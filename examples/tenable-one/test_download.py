import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch
from urllib.parse import parse_qs, urlsplit

from download import download, tenable_request

EXPORT = "/api/v1/t1/inventory/export"
ASSET = "6e51b7ca-7ca3-48d0-990f-65a86af6b9c8"
FIRST = "8a907774-2830-44f8-98ff-530a128ca621"
SECOND = "ab55b579-f403-48f7-a459-87fb541dc4fb"
URL = "https://example.org/example/repo"
ASSET_EXPORT = (
    f"asset_id,asset_name,asset_class\r\n{ASSET},example/repo,CODE_REPOSITORY\r\n".encode()
)
HEADERS = b"finding_id,finding_name,asset_id,state,finding_severity,finding_description,finding_solution,file_path,code_line_number\r\n"


def finding(finding_id, asset=ASSET):
    return f"{finding_id},Sample finding,{asset},ACTIVE,HIGH,Details,Fix,src/main.py,7\r\n".encode()


def export(job, *chunks, state="FINISHED"):
    # POST, two status polls, then one GET per returned chunk.
    return [
        json.dumps({"export_id": job}),
        json.dumps({"export_id": job, "status": "PROCESSING"}),
        json.dumps(
            {"export_id": job, "status": state, "chunks_available": list(range(len(chunks)))}
        ),
        *chunks,
    ]


class DownloadTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name) / "selection.json"
        self.request = Mock()
        self.sleep = Mock()

    def run_download(self, *responses, ids=(FIRST,)):
        self.request.side_effect = responses
        download(ASSET, ids, URL, self.output, self.request, self.sleep)

    def test_scoped_exports_poll_and_read_all_chunks(self):
        # Give each job an ID distinct from its requested asset or finding ID.
        self.run_download(
            *export(FIRST, ASSET_EXPORT),
            *export(SECOND, HEADERS, HEADERS + finding(FIRST)),
            *export(ASSET, HEADERS + finding(SECOND)),
            ids=(FIRST, SECOND),
        )
        requests = iter(self.request.call_args_list)
        for kind, selected, job, header, count in [
            ("assets", ASSET, FIRST, ASSET_EXPORT.splitlines()[0], 1),
            ("findings", FIRST, SECOND, HEADERS, 2),
            ("findings", SECOND, ASSET, HEADERS, 1),
        ]:
            method, path, payload = next(requests).args
            endpoint = urlsplit(path)
            self.assertEqual((method, endpoint.path), ("POST", f"{EXPORT}/{kind}"))
            query = parse_qs(endpoint.query)
            self.assertEqual(query["file_format"], ["CSV"])
            self.assertEqual(query["use_readable_name"], ["false"])
            self.assertCountEqual(
                query["properties"][0].split(","), header.decode().strip().split(",")
            )
            field = "asset_id" if kind == "assets" else "finding_id"
            self.assertEqual(
                payload["filters"], [{"property": field, "operator": "=", "value": [selected]}]
            )
            prefix = f"{EXPORT}/{job}"
            for suffix in ["status", "status", *(f"download/{i}" for i in range(count))]:
                self.assertEqual(next(requests), call("GET", f"{prefix}/{suffix}"))
        self.assertIsNone(next(requests, None))
        self.assertEqual(self.sleep.call_count, 3)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["asset"]["asset_id"], ASSET)
        self.assertEqual(result["repository_url"], URL)
        self.assertEqual([r["finding_id"] for r in result["findings"]], [FIRST, SECOND])
        for row in result["findings"]:
            self.assertEqual((row["code_file_path"], row["code_line_number"]), ("src/main.py", 7))

    def test_unexpected_export_rows_are_rejected_atomically(self):
        for data in (b"", finding(SECOND), finding(FIRST) * 2, finding(FIRST, asset=SECOND)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.run_download(*export(FIRST, ASSET_EXPORT), *export(SECOND, HEADERS + data))
            self.assertFalse(self.output.exists())
        mixed = ASSET_EXPORT + f"{SECOND},example/other,CODE_REPOSITORY\r\n".encode()
        with self.assertRaisesRegex(ValueError, "unrequested asset"):
            self.run_download(*export(FIRST, mixed))
        self.assertFalse(self.output.exists())

    def test_job_error_leaves_no_artifact(self):
        with self.assertRaisesRegex(ValueError, "ERROR"):
            self.run_download(*export(FIRST, state="ERROR"))
        self.assertFalse(self.output.exists())

    def test_invalid_selection_fails_before_queueing(self):
        for ids in ([], [FIRST, FIRST]):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.run_download(ids=ids)
        self.output.write_bytes(b"previous")
        with self.assertRaises(FileExistsError):
            self.run_download()
        self.assertEqual(self.output.read_bytes(), b"previous")
        self.request.assert_not_called()

    def test_invalid_credentials_never_appear_in_diagnostics(self):
        malformed = "synthetic-private-value\r\nnext-header"
        for access, secret in ((malformed, "example-secret"), ("example-access", malformed)):
            with self.subTest(access=access), self.assertRaises(ValueError) as error:
                tenable_request(access, secret)
            self.assertNotIn("synthetic-", str(error.exception))

    def test_http_retries_only_pending_chunk_gets_and_never_follows_redirects(self):
        chunk = f"{EXPORT}/{FIRST}/download/0"
        status = f"{EXPORT}/{FIRST}/status"
        for method, path, statuses in [
            ("GET", chunk, [204, 204, 200]),
            ("GET", chunk, [204] * 5),
            ("GET", status, [204]),
            ("POST", f"{EXPORT}/assets", [204]),
            ("GET", status, [302]),
        ]:
            with (
                self.subTest(statuses=statuses, path=path),
                patch("download.time.sleep") as sleep,
                patch("download.http.client.HTTPSConnection") as connect,
            ):
                responses = [Mock(status=code) for code in statuses]
                responses[-1].read.return_value = b"ready"
                responses[-1].getheader.return_value = "https://other.example.org/redirect"
                connection = connect.return_value
                connection.getresponse.side_effect = responses
                request = tenable_request("example-access", "example-secret")
                if statuses[-1] == 200:
                    self.assertEqual(request(method, path), b"ready")
                else:
                    with self.assertRaisesRegex(ValueError, str(statuses[-1])):
                        request(method, path)
                self.assertEqual(connect.call_count, len(statuses))
                for origin in connect.call_args_list:
                    self.assertEqual(origin.args, ("cloud.tenable.com",))
                    self.assertGreater(origin.kwargs["timeout"], 0)
                for attempt in connection.request.call_args_list:
                    self.assertEqual(attempt.args, (method, path))
                    self.assertEqual(
                        attempt.kwargs["headers"]["X-ApiKeys"],
                        "accessKey=example-access;secretKey=example-secret",
                    )
                self.assertEqual(connection.close.call_count, len(statuses))
                self.assertEqual(sleep.call_count, len(statuses) - 1)


if __name__ == "__main__":
    unittest.main()
