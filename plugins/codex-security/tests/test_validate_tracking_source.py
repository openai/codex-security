from __future__ import annotations

import copy
import hashlib
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from workbench_test_support import ScanFixtureTestCase, load_script

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCAN = PLUGIN_ROOT / "examples" / "completed-scan"


VALIDATOR = load_script("validate_tracking_source")


def test_tracking_cli_lists_the_checked_in_finding(capsys) -> None:
    assert VALIDATOR.main([str(EXAMPLE_SCAN)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "csf_852f90d6e1177502ff113d4a\n"
    assert captured.err == ""


class ValidateTrackingSourceTest(ScanFixtureTestCase):
    validator = VALIDATOR
    example_scan = EXAMPLE_SCAN

    def test_tampered_findings_are_rejected(self) -> None:
        findings_path = self.scan_dir / "findings.json"
        findings_path.write_text(
            findings_path.read_text(encoding="utf-8") + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "sealed artifact changed"):
            VALIDATOR.validate_source(self.scan_dir)

    def test_digest_matching_invalid_json_is_rejected(self) -> None:
        findings_bytes = b"{invalid json\n"
        (self.scan_dir / "findings.json").write_bytes(findings_bytes)
        manifest = self.read_json("scan-manifest.json")
        artifact = next(
            item
            for item in manifest["scan"]["artifacts"]
            if item["path"] == manifest["scan"]["findingsRef"]
        )
        artifact["sha256"] = hashlib.sha256(findings_bytes).hexdigest()
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(
            VALIDATOR.FINALIZER.ContractError,
            "findings.json: invalid JSON",
        ):
            VALIDATOR.validate_source(self.scan_dir)

    def test_digest_matching_invalid_coverage_is_rejected(self) -> None:
        coverage = self.read_json("coverage.json")
        coverage["scanId"] = "wrong-scan-id"
        self.rewrite_sealed_artifact("coverage.json", coverage)

        with self.assertRaisesRegex(
            VALIDATOR.FINALIZER.ContractError,
            "coverage.scanId: must match manifest scan id",
        ):
            VALIDATOR.validate_source(self.scan_dir)

    def test_noncanonical_artifact_path_fails_without_a_traceback(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        artifact = next(
            item for item in manifest["scan"]["artifacts"] if item["path"] == "findings.json"
        )
        artifact["path"] = "./findings.json"
        self.write_json("scan-manifest.json", manifest)
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            exit_code = VALIDATOR.main([str(self.scan_dir)])

        self.assertEqual(exit_code, 2)
        self.assertIn("tracking source preflight failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_report_only_directory_is_rejected(self) -> None:
        report_dir = Path(self.temp_dir.name) / "report-only"
        report_dir.mkdir()
        (report_dir / "report.html").write_text("<html></html>", encoding="utf-8")

        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "scan-manifest.json"):
            VALIDATOR.validate_source(report_dir)

    def test_max_size_batch_can_be_listed_or_selected_by_fingerprint(self) -> None:
        findings = self.read_json("findings.json")
        template = findings["findings"][0]
        for index in range(1, 25):
            sibling = copy.deepcopy(template)
            sibling["identity"]["instance"] = f"archive-write-{index:02d}"
            sibling.pop("findingId")
            sibling.pop("occurrenceId")
            sibling.pop("fingerprints")
            findings["findings"].append(sibling)

        manifest = self.read_json("scan-manifest.json")
        VALIDATOR.FINALIZER._populate_unsealed_finding_identities(manifest, findings)
        self.rewrite_sealed_artifact("findings.json", findings)

        listed = VALIDATOR.validate_source(self.scan_dir)
        finding_ids = [finding["findingId"] for finding in listed]

        self.assertEqual(len(finding_ids), 25)
        self.assertEqual(len(set(finding_ids)), 25)

        finding = findings["findings"][-1]
        selected = VALIDATOR.validate_source(
            self.scan_dir, fingerprint=finding["fingerprints"]["primary"]
        )
        self.assertEqual([item["findingId"] for item in selected], [finding["findingId"]])


if __name__ == "__main__":
    unittest.main()
