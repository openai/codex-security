import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CAPTURE = Path(__file__).with_name("capture.py")
ASSET_ID = "6e51b7ca-7ca3-48d0-990f-65a86af6b9c8"
DEVICE_ID = "3b1febad-1a8a-414a-8302-20cff925f4af"
REPOSITORY_URL = "https://example.org/example/repo"
ASSET = {"asset_id": ASSET_ID, "asset_name": "example/repo", "asset_class": "CODE_REPOSITORY"}
DEVICE = {"asset_id": DEVICE_ID, "asset_name": "example/repo", "asset_class": "DEVICE"}
FINDING = {
    "asset_id": ASSET_ID,
    "finding_id": "Demo:0001",
    "finding_name": "Example finding",
    "severity": "HIGH",
    "state": "ACTIVE",
}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.output = self.directory / "selection.json"
        self.assets = self.csv("assets.csv", [ASSET, DEVICE])

    def csv(self, name, rows):
        path = self.directory / name
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        return path

    def run_capture(self, chunks, *options):
        return subprocess.run(
            [
                sys.executable,
                str(CAPTURE),
                "--assets",
                str(self.assets),
                "--findings",
                *map(str, chunks),
                "--asset-id",
                ASSET_ID,
                "--repository-url",
                REPOSITORY_URL,
                "--output",
                str(self.output),
                *options,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_rejected(self, chunks, *options):
        result = self.run_capture(chunks, *options)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_capture_combines_chunks_and_maps_only_requested_fields(self):
        first = {
            **FINDING,
            "description": 'Two lines, with "quotes"\nand a comma.',
            "solution": "Use the existing guard.",
            "src": "lib/example.py",
            "pos": "7",
            "other": "extra vendor field",
        }
        second = {**first, "finding_id": "demo:0001", "src": "", "pos": ""}
        chunks = [self.csv("part1.csv", [first]), self.csv("part2.csv", [second])]
        result = self.run_capture(chunks, "--path-column", "src", "--line-column", "pos")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {**FINDING, "description": first["description"], "solution": first["solution"]}
        self.assertEqual(
            json.loads(self.output.read_text()),
            {
                "format": "tenable-one-code-repository/v1",
                "asset": ASSET,
                "repository_url": REPOSITORY_URL,
                "findings": [
                    {**expected, "code_file_path": "lib/example.py", "code_line_number": 7},
                    {**expected, "finding_id": second["finding_id"]},
                ],
            },
        )

    def test_optional_location_columns_are_never_guessed(self):
        row = {**FINDING, "code_file_path": "unused.py", "code_line_number": "9"}
        result = self.run_capture([self.csv("part.csv", [row])])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["findings"], [FINDING])

    def test_findings_export_maps_vendor_fields(self):
        row = {
            "asset_id": ASSET_ID,
            "finding_id": FINDING["finding_id"],
            "finding_detection_name": FINDING["finding_name"],
            "finding_severity": FINDING["severity"],
            "state": FINDING["state"],
            "finding_solution": "Use the existing guard.",
            "finding_description": "Example observation",
        }
        result = self.run_capture([self.csv("tenable.csv", [row])])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(self.output.read_text())["findings"],
            [
                {
                    **FINDING,
                    "solution": row["finding_solution"],
                    "description": row["finding_description"],
                }
            ],
        )

    def test_header_only_default_export(self):
        chunk = self.directory / "empty.csv"
        chunk.write_text("asset_id,finding_id,finding_detection_name,finding_severity,state\r\n")
        result = self.run_capture([chunk])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["findings"], [])

    def test_mixed_asset_ids_fail_even_in_later_chunk(self):
        first = self.csv("first.csv", [FINDING])
        later = self.csv("later.csv", [{**FINDING, "asset_id": DEVICE_ID, "finding_id": "Other"}])
        self.assert_rejected([first, later])

    def test_duplicate_finding_ids_across_chunks_fail(self):
        first = self.csv("first.csv", [FINDING])
        later = self.csv("later.csv", [{**FINDING, "finding_name": "Conflicting title"}])
        self.assert_rejected([first, later])

    def test_asset_selection_requires_one_matching_repository(self):
        chunk = self.csv("part.csv", [FINDING])
        for rows in ([DEVICE], [ASSET, ASSET], [{**ASSET, "asset_class": "DEVICE"}]):
            with self.subTest(rows=rows):
                self.assets = self.csv("assets.csv", rows)
                self.assert_rejected([chunk])

    def test_each_chunk_requires_complete_consistent_headers(self):
        first = self.csv("first.csv", [FINDING])
        missing = {key: value for key, value in FINDING.items() if key != "state"}
        self.assert_rejected([self.csv("missing.csv", [missing])])
        other = self.csv("other.csv", [{**FINDING, "finding_id": "Other", "extra": "value"}])
        self.assert_rejected([first, other])
        self.assert_rejected([first], "--path-column", "not_exported")

    def test_zero_line_number_retains_finding_and_available_path(self):
        first = {**FINDING, "src": "lib/example.py", "pos": "0"}
        second = {**FINDING, "finding_id": "Demo:0002", "src": "", "pos": "0"}
        chunk = self.csv("part.csv", [first, second])
        result = self.run_capture([chunk], "--path-column", "src", "--line-column", "pos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(self.output.read_text())["findings"],
            [
                {**FINDING, "code_file_path": first["src"]},
                {**FINDING, "finding_id": second["finding_id"]},
            ],
        )

    def test_long_csv_description_is_retained(self):
        description = "Beginning\n" + "x" * 131072 + "\nEnd"
        chunk = self.csv("part.csv", [{**FINDING, "finding_description": description}])
        result = self.run_capture([chunk])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(self.output.read_text())["findings"][0]["description"], description
        )

    def test_invalid_line_number_is_rejected(self):
        for invalid in ("-1", "3.5", "line twelve"):
            with self.subTest(invalid=invalid):
                row = {**FINDING, "src": "lib/example.py", "pos": invalid}
                chunk = self.csv("part.csv", [row])
                self.assert_rejected([chunk], "--path-column", "src", "--line-column", "pos")

    def test_existing_output_is_preserved(self):
        previous = b"existing selection\n"
        self.output.write_bytes(previous)
        result = self.run_capture([self.csv("part.csv", [FINDING])])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
