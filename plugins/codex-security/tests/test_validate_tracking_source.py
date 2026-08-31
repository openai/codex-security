from __future__ import annotations

import copy
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCAN = PLUGIN_ROOT / "examples" / "completed-scan"


def load_validator() -> ModuleType:
    script = PLUGIN_ROOT / "scripts" / "validate_tracking_source.py"
    spec = importlib.util.spec_from_file_location("validate_tracking_source", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


def test_completed_example_passes_tracking_validation() -> None:
    assert VALIDATOR.validate_source(EXAMPLE_SCAN)


class ValidateTrackingSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scan_dir = Path(self.temp_dir.name) / "scan"
        shutil.copytree(EXAMPLE_SCAN, self.scan_dir)
        manifest = json.loads((self.scan_dir / "scan-manifest.json").read_text())
        findings = json.loads((self.scan_dir / "findings.json").read_text())
        coverage = json.loads((self.scan_dir / "coverage.json").read_text())
        report = VALIDATOR.FINALIZER._generate_report_projection(manifest, findings, coverage)
        (self.scan_dir / "report.md").write_bytes(report)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def read_json(self, name: str) -> dict[str, object]:
        return json.loads((self.scan_dir / name).read_text(encoding="utf-8"))

    def write_json(self, name: str, payload: object) -> None:
        (self.scan_dir / name).write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

    def rewrite_findings_and_seal(self, findings: dict[str, object]) -> None:
        self.write_json("findings.json", findings)
        manifest = self.read_json("scan-manifest.json")
        findings_bytes = (self.scan_dir / "findings.json").read_bytes()
        artifact = next(
            item
            for item in manifest["scan"]["artifacts"]
            if item["path"] == manifest["scan"]["findingsRef"]
        )
        artifact["sha256"] = VALIDATOR.FINALIZER._sha256_bytes(findings_bytes)
        self.write_json("scan-manifest.json", manifest)

    def rewrite_coverage_and_seal(self, coverage: dict[str, object]) -> None:
        self.write_json("coverage.json", coverage)
        manifest = self.read_json("scan-manifest.json")
        coverage_bytes = (self.scan_dir / "coverage.json").read_bytes()
        artifact = next(
            item
            for item in manifest["scan"]["artifacts"]
            if item["path"] == manifest["scan"]["coverageRef"]
        )
        artifact["sha256"] = VALIDATOR.FINALIZER._sha256_bytes(coverage_bytes)
        self.write_json("scan-manifest.json", manifest)

    def test_selects_the_finding_from_a_sealed_scan(self) -> None:
        findings = VALIDATOR.validate_source(self.scan_dir)

        self.assertEqual(findings[0]["findingId"], "csf_852f90d6e1177502ff113d4a")

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
        artifact["sha256"] = VALIDATOR.FINALIZER._sha256_bytes(findings_bytes)
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(
            VALIDATOR.FINALIZER.ContractError,
            "findings.json: invalid JSON",
        ):
            VALIDATOR.validate_source(self.scan_dir)

    def test_digest_matching_invalid_coverage_is_rejected(self) -> None:
        coverage = self.read_json("coverage.json")
        coverage["scanId"] = "wrong-scan-id"
        self.rewrite_coverage_and_seal(coverage)

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

    def test_multiple_findings_can_be_listed_or_selected(self) -> None:
        findings = self.read_json("findings.json")
        sibling = copy.deepcopy(findings["findings"][0])
        sibling["identity"]["instance"] = "second-archive-write"
        sibling.pop("findingId")
        sibling.pop("occurrenceId")
        sibling.pop("fingerprints")
        findings["findings"].append(sibling)
        manifest = self.read_json("scan-manifest.json")
        VALIDATOR.FINALIZER._populate_unsealed_finding_identities(manifest, findings)
        self.rewrite_findings_and_seal(findings)

        listed = VALIDATOR.validate_source(self.scan_dir)
        self.assertEqual(len(listed), 2)

        selected = VALIDATOR.validate_source(
            self.scan_dir,
            fingerprint=sibling["fingerprints"]["primary"],
        )
        self.assertEqual(selected[0]["findingId"], sibling["findingId"])

    def test_lists_twenty_five_findings_for_a_max_size_batch(self) -> None:
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
        self.rewrite_findings_and_seal(findings)

        listed = VALIDATOR.validate_source(self.scan_dir)
        finding_ids = [finding["findingId"] for finding in listed]

        self.assertEqual(len(finding_ids), 25)
        self.assertEqual(len(set(finding_ids)), 25)

    def test_cli_prints_only_the_selected_finding_id(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = VALIDATOR.main([str(self.scan_dir)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "csf_852f90d6e1177502ff113d4a\n")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
