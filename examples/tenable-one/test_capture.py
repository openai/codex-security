import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CAPTURE = Path(__file__).with_name("capture.py")
ASSET_ID = "6e51b7ca-7ca3-48d0-990f-65a86af6b9c8"
OTHER_ID = "3b1febad-1a8a-414a-8302-20cff925f4af"
URL = "https://example.org/example/repo"
ASSET = {"asset_id": ASSET_ID, "asset_name": "example/repo", "asset_class": "CODE_REPOSITORY"}
DEVICE = {**ASSET, "asset_id": OTHER_ID, "asset_class": "DEVICE"}
FINDING = {
    "asset_id": ASSET_ID,
    "finding_id": "Demo:0001",
    "finding_name": "Example finding",
    "severity": "HIGH",
    "state": "ACTIVE",
}
LOCATIONS = ["--path-column", "src", "--line-column", "pos"]


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.output = self.directory / "selection.json"
        self.assets = self.csv("assets", ASSET, DEVICE)

    def csv(self, name, *rows):
        path = self.directory / (name + ".csv")
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0])
            writer.writeheader()
            writer.writerows(rows)
        return path

    def capture(self, *chunks_and_flags, error=None):
        args = [
            sys.executable,
            CAPTURE,
            "--assets",
            self.assets,
            "--asset-id",
            ASSET_ID,
            "--repository-url",
            URL,
            "--output",
            self.output,
            "--findings",
            *chunks_and_flags,
        ]
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        if error is not None:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(error, result.stderr)
            return None
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(self.output.read_text())

    def test_selected_fields_and_case_sensitive_ids_across_chunks(self):
        # The description exceeds csv's default field limit and includes quoted CSV syntax.
        description = "x" * 131072 + ' "two lines",\nand a comma.'
        evidence = {"description": description, "solution": "Use the existing guard."}
        first = {**FINDING, **evidence, "src": "lib/example.py", "pos": "7", "other": "ignored"}
        second = {**first, "finding_id": "demo:0001", "src": "", "pos": ""}
        result = self.capture(self.csv("first", first), self.csv("second", second), *LOCATIONS)
        self.assertEqual(
            result,
            {
                "format": "tenable-one-code-repository/v1",
                "asset": ASSET,
                "repository_url": URL,
                "findings": [
                    {
                        **FINDING,
                        **evidence,
                        "code_file_path": "lib/example.py",
                        "code_line_number": 7,
                    },
                    {**FINDING, **evidence, "finding_id": "demo:0001"},
                ],
            },
        )

    def test_default_vendor_headers_without_mapped_locations(self):
        row = {
            "asset_id": ASSET_ID,
            "finding_id": FINDING["finding_id"],
            "state": FINDING["state"],
            "finding_detection_name": FINDING["finding_name"],
            "finding_severity": FINDING["severity"],
            "finding_solution": "Fix",
            "finding_description": "Details",
            "code_file_path": "ignored.py",
            "code_line_number": "9",
        }
        result = self.capture(self.csv("chunk", row))
        self.assertEqual(
            result["findings"], [{**FINDING, "solution": "Fix", "description": "Details"}]
        )

    def test_header_only_export(self):
        chunk = self.directory / "empty.csv"
        chunk.write_text("asset_id,finding_id,finding_detection_name,finding_severity,state\n")
        self.assertEqual(self.capture(chunk)["findings"], [])

    def test_mixed_assets_duplicate_ids_and_inconsistent_or_missing_headers(self):
        first = self.csv("first", FINDING)
        for row, error in [
            ({**FINDING, "asset_id": OTHER_ID}, "different or missing asset_id"),
            ({**FINDING, "finding_name": "Conflicting title"}, "duplicate finding_id"),
            ({**FINDING, "extra": "value"}, "column names or order differ"),
            ({k: v for k, v in FINDING.items() if k != "state"}, "missing CSV columns"),
        ]:
            with self.subTest(error=error):
                self.capture(first, self.csv("second", row), error=error)
                self.assertFalse(self.output.exists())
        self.capture(first, "--path-column", "not_exported", error="missing CSV columns")

    def test_asset_selection_requires_one_matching_repository(self):
        chunk = self.csv("chunk", FINDING)
        for rows, error in [
            ([DEVICE], "not found"),
            ([ASSET, ASSET], "multiple inventory rows"),
            ([{**ASSET, "asset_class": "DEVICE"}], "must have asset_class CODE_REPOSITORY"),
        ]:
            with self.subTest(error=error):
                self.assets = self.csv("assets", *rows)
                self.capture(chunk, error=error)
                self.assertFalse(self.output.exists())

    def test_zero_line_number_keeps_an_optional_path(self):
        first = {**FINDING, "src": "lib/example.py", "pos": "0"}
        second = {**first, "finding_id": "Demo:0002", "src": ""}
        result = self.capture(self.csv("chunk", first, second), *LOCATIONS)
        self.assertEqual(
            result["findings"],
            [
                {**FINDING, "code_file_path": first["src"]},
                {**FINDING, "finding_id": "Demo:0002"},
            ],
        )

    def test_invalid_line_number_is_rejected(self):
        for line in ("-1", "3.5", "line twelve"):
            with self.subTest(line=line):
                chunk = self.csv("chunk", {**FINDING, "src": "lib/example.py", "pos": line})
                self.capture(chunk, *LOCATIONS, error="must be a nonnegative integer")

    def test_existing_output_is_preserved(self):
        self.output.write_bytes(b"previous")
        self.capture(self.csv("chunk", FINDING), error="selection.json")
        self.assertEqual(self.output.read_bytes(), b"previous")


if __name__ == "__main__":
    unittest.main()
