import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from download import download, tenable_request

EXPORT = "/api/v1/t1/inventory/export"
ASSET = "6e51b7ca-7ca3-48d0-990f-65a86af6b9c8"
FIRST = "8a907774-2830-44f8-98ff-530a128ca621"
SECOND = "ab55b579-f403-48f7-a459-87fb541dc4fb"
OTHER = "542f72fe-eacb-4c8e-afee-5b3b990e1a14"
URL = "https://example.org/example/repo"
HEADERS = b"finding_id,finding_name,asset_id,state,finding_severity,finding_description,finding_solution,file_path,code_line_number\r\n"
JOBS = {
    ASSET: "313cbcb2-a81d-47b1-be60-4368988e8cd6",
    FIRST: "bf80146b-9dad-41cf-9217-b1e06c901825",
    SECOND: "111fe87d-1b5d-4f00-9b3d-c85436428a32",
}


def finding(finding_id, asset=ASSET):
    return f"{finding_id},Sample finding,{asset},ACTIVE,HIGH,Details,Fix,src/main.py,7\r\n".encode()


class DownloadTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.output = Path(temp.name) / "selection.json"
        self.sleep = Mock()
        self.queued = []
        self.failure = False
        self.polls = {}
        self.chunks = {
            JOBS[ASSET]: {
                1: f"asset_id,asset_name,asset_class\r\n{ASSET},example/repo,CODE_REPOSITORY\r\n".encode()
            },
            JOBS[FIRST]: {1: HEADERS, 2: HEADERS + finding(FIRST)},
            JOBS[SECOND]: {1: HEADERS + finding(SECOND)},
        }

    def request(self, method, path, payload=None):
        url = urlsplit(path)
        if method == "POST":
            self.assertIn(url.path, {f"{EXPORT}/assets", f"{EXPORT}/findings"})
            query = parse_qs(url.query)
            self.assertEqual(query["file_format"], ["CSV"])
            self.assertEqual(query["use_readable_name"], ["false"])
            (entry,) = payload["filters"]
            (selected,) = entry["value"]
            if url.path.endswith("/assets"):
                self.assertEqual(selected, ASSET)
                field = "asset_id"
                expected_fields = {"asset_id", "asset_name", "asset_class"}
            else:
                self.assertIn(selected, (FIRST, SECOND))
                field = "finding_id"
                expected_fields = set(HEADERS.decode().strip().split(","))
            self.assertEqual(set(query["properties"][0].split(",")), expected_fields)
            self.assertEqual(
                payload, {"filters": [{"property": field, "operator": "=", "value": [selected]}]}
            )
            self.queued.append(selected)
            return json.dumps({"export_id": JOBS[selected]}).encode()

        self.assertEqual(method, "GET")
        self.assertTrue(url.path.startswith(EXPORT + "/"))
        job, action, *rest = url.path.removeprefix(EXPORT + "/").split("/")
        self.assertIn(job, self.chunks)
        if action == "status":
            count = self.polls.get(job, 0)
            self.polls[job] = count + 1
            state = "ERROR" if self.failure else ("FINISHED" if count else "PROCESSING")
            return json.dumps(
                {
                    "export_id": job,
                    "status": state,
                    "chunks_available": list(self.chunks[job]) if state == "FINISHED" else [],
                }
            ).encode()
        self.assertEqual(action, "download")
        (chunk,) = rest
        return self.chunks[job][int(chunk)]

    def run_download(self, *finding_ids):
        download(ASSET, list(finding_ids), URL, self.output, self.request, self.sleep)

    def test_scoped_export_polls_and_reads_all_chunks(self):
        self.run_download(FIRST, SECOND)
        self.assertCountEqual(self.queued, [ASSET, FIRST, SECOND])
        self.assertTrue(self.sleep.called)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["format"], "tenable-one-code-repository/v1")
        self.assertEqual(result["asset"]["asset_id"], ASSET)
        self.assertEqual(result["repository_url"], URL)
        self.assertCountEqual([row["finding_id"] for row in result["findings"]], [FIRST, SECOND])
        for row in result["findings"]:
            self.assertEqual(row["finding_name"], "Sample finding")
            self.assertEqual(row["code_file_path"], "src/main.py")
            self.assertEqual(row["code_line_number"], 7)

    def test_missing_unexpected_duplicate_or_misbound_results_fail(self):
        for invalid in (b"", finding(OTHER), finding(FIRST) * 2, finding(FIRST, asset=OTHER)):
            with self.subTest(invalid=invalid):
                self.chunks[JOBS[FIRST]] = {1: HEADERS + invalid}
                with self.assertRaises(ValueError):
                    self.run_download(FIRST)
                self.assertFalse(self.output.exists())

    def test_server_job_failure_leaves_no_artifact(self):
        self.failure = True
        with self.assertRaises((ValueError, RuntimeError)):
            self.run_download(FIRST)
        self.assertFalse(self.output.exists())

    def test_asset_export_must_contain_only_the_selected_asset(self):
        self.chunks[JOBS[ASSET]][1] += f"{OTHER},example/other,CODE_REPOSITORY\r\n".encode()
        with self.assertRaises(ValueError):
            self.run_download(FIRST)
        self.assertFalse(self.output.exists())

    def test_empty_or_repeated_requested_ids_fail_before_queueing(self):
        for ids in ([], [FIRST, FIRST]):
            with self.subTest(ids=ids):
                with self.assertRaises(ValueError):
                    self.run_download(*ids)
                self.assertFalse(self.queued)
                self.assertFalse(self.output.exists())

    def test_existing_selection_is_never_replaced(self):
        self.output.write_text("previous")
        with self.assertRaises((ValueError, FileExistsError)):
            self.run_download(FIRST)
        self.assertEqual(self.output.read_text(), "previous")

    @patch("download.http.client.HTTPSConnection")
    def test_redirect_does_not_forward_the_authenticated_request(self, connect):
        connection = connect.return_value
        response = connection.getresponse.return_value
        response.status = 302
        response.getheader.return_value = "https://other.example.org/redirect"
        request = tenable_request("example-access", "example-secret")
        with self.assertRaisesRegex(ValueError, "302"):
            request("GET", f"{EXPORT}/{JOBS[FIRST]}/status")
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[0], "cloud.tenable.com")
        self.assertGreater(connect.call_args.kwargs["timeout"], 0)
        connection.request.assert_called_once()
        self.assertEqual(
            connection.request.call_args.kwargs["headers"]["X-ApiKeys"],
            "accessKey=example-access;secretKey=example-secret",
        )
        connection.close.assert_called_once()

    @patch("download.http.client.HTTPSConnection")
    def test_invalid_credential_never_appears_in_diagnostics(self, connect):
        malformed = "synthetic-private-value\r\nnext-header"
        for access, secret in ((malformed, "synthetic-secret"), ("synthetic-access", malformed)):
            with self.subTest(access=access), self.assertRaises(ValueError) as error:
                tenable_request(access, secret)
            self.assertNotIn("synthetic-", str(error.exception))
        connect.assert_not_called()

    @patch("download.time.sleep")
    @patch("download.http.client.HTTPSConnection")
    def test_pending_chunk_retries_only_the_same_download(self, connect, sleep):
        path = f"{EXPORT}/{JOBS[FIRST]}/download/2"
        connection = connect.return_value
        ready = Mock(status=200)
        ready.read.return_value = HEADERS + finding(FIRST)
        connection.getresponse.side_effect = [Mock(status=204), Mock(status=204), ready]
        request = tenable_request("example-access", "example-secret")
        self.assertEqual(request("GET", path), ready.read.return_value)
        self.assertEqual(
            [call.args for call in connection.request.call_args_list], [("GET", path)] * 3
        )
        self.assertEqual(sleep.call_count, 2)

    @patch("download.time.sleep")
    @patch("download.http.client.HTTPSConnection")
    def test_pending_chunk_eventually_fails(self, connect, sleep):
        path = f"{EXPORT}/{JOBS[FIRST]}/download/2"
        connection = connect.return_value
        # A finite sequence also makes an unbounded retry a prompt test failure.
        connection.getresponse.side_effect = [Mock(status=204)] * 100
        request = tenable_request("example-access", "example-secret")
        with self.assertRaises(ValueError):
            request("GET", path)
        self.assertGreater(sleep.call_count, 0)
        self.assertEqual(connection.request.call_count, sleep.call_count + 1)
        self.assertTrue(
            all(call.args == ("GET", path) for call in connection.request.call_args_list)
        )

    @patch("download.time.sleep")
    @patch("download.http.client.HTTPSConnection")
    def test_no_content_on_status_or_submission_errors_immediately(self, connect, sleep):
        connection = connect.return_value
        connection.getresponse.return_value.status = 204
        request = tenable_request("example-access", "example-secret")
        for method, path in (
            ("GET", f"{EXPORT}/{JOBS[FIRST]}/status"),
            ("POST", f"{EXPORT}/assets"),
        ):
            with self.subTest(method=method):
                connection.request.reset_mock()
                with self.assertRaisesRegex(ValueError, "204"):
                    request(method, path)
                connection.request.assert_called_once()
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
