"""Exercise read-only validation of sealed bundles, including legacy evidence and unsealed inputs."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from workbench_test_support import ScanFixtureTestCase, load_script

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCAN = PLUGIN_ROOT / "examples" / "legacy-completed-scan"


VALIDATOR = load_script("validate_scan_contract")


class ValidateScanContractTest(ScanFixtureTestCase):
    validator = VALIDATOR
    example_scan = EXAMPLE_SCAN

    def test_accepts_sealed_contract_without_mutating_it(self) -> None:
        before = {
            path.name: path.read_bytes() for path in self.scan_dir.iterdir() if path.is_file()
        }
        validated = VALIDATOR.validate_contract(self.scan_dir)
        after = {path.name: path.read_bytes() for path in self.scan_dir.iterdir() if path.is_file()}

        self.assertEqual(validated["manifest"]["scan"]["status"], "completed")
        self.assertEqual(before, after)

    def test_accepts_legacy_unknown_nested_evidence_reference(self) -> None:
        findings = self.read_json("findings.json")
        findings["findings"][0]["attackPath"] = {
            "dataFlow": {"evidenceRefs": ["legacy-missing-evidence"]}
        }
        self.rewrite_sealed_artifact("findings.json", findings)

        validated = VALIDATOR.validate_contract(self.scan_dir)

        self.assertEqual(validated["findings"], findings)

    def test_completion_checks_locations_against_the_registered_file_scope(self) -> None:
        for path in ("src/extract.py", "src/other.py"):
            with self.subTest(path=path):
                coverage = self.read_json("coverage.json")
                coverage.update(includePaths=[path], mode="scoped_path")
                self.rewrite_sealed_artifact("coverage.json", coverage)
                manifest = self.read_json("scan-manifest.json")
                scan = manifest["scan"]
                scan["scope"]["includePaths"] = [path]
                self.write_json("scan-manifest.json", manifest)
                binding = {
                    "scanId": scan["id"],
                    "startedAt": scan["startedAt"],
                    "completedAt": scan["completedAt"],
                    "producer": scan["producer"],
                    "allowedTargetKinds": [scan["target"]["kind"]],
                    "target": scan["target"],
                    "scope": {"includePaths": [path], "excludePaths": []},
                    "coverageMode": "scoped_path",
                }
                options = {"completion_binding": binding, "finding_scope": [(path, True)]}
                if path == "src/extract.py":
                    result = VALIDATOR.validate_contract(self.scan_dir, **options)
                    self.assertEqual(result["reportSha256"], self.sha256_file("report.md"))
                else:
                    with self.assertRaisesRegex(
                        VALIDATOR.FINALIZER.ContractError, "no location in the requested scope"
                    ):
                        VALIDATOR.validate_contract(self.scan_dir, **options)

    def test_accepts_canonical_document_beyond_previous_size_limit(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        manifest["metadata"] = "x" * (16 * 1024 * 1024)
        self.write_json("scan-manifest.json", manifest)

        validated = VALIDATOR.validate_contract(self.scan_dir)

        self.assertEqual(len(validated["manifest"]["metadata"]), 16 * 1024 * 1024)

    def test_rejects_unsafe_values_in_sealed_finding_extensions(self) -> None:
        findings = self.read_json("findings.json")
        for value, reason in (
            (1e20, "unsafe integer-valued JSON numbers"),
            ("bad-" + chr(0xD800), "well-formed Unicode"),
        ):
            with self.subTest(reason=reason):
                findings["findings"][0].setdefault("extensions", {})["unsafe"] = value
                self.rewrite_sealed_artifact("findings.json", findings)

                with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, reason):
                    VALIDATOR.validate_contract(self.scan_dir)

    def test_rejects_missing_report(self) -> None:
        (self.scan_dir / "report.md").unlink()

        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "report.md"):
            VALIDATOR.validate_contract(self.scan_dir)

    def test_rejects_unsealed_manifest(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"].pop("sealedAt")
        manifest["scan"].pop("artifacts")
        self.write_json("scan-manifest.json", manifest)

        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "sealed"):
            VALIDATOR.validate_contract(self.scan_dir)

    def test_finalizer_then_validator_cli_smoke(self) -> None:
        (self.scan_dir / "report.md").unlink()
        scan_dir = self.scan_dir.resolve()
        finalizer = PLUGIN_ROOT / "scripts" / "finalize_scan_contract.py"
        validator = PLUGIN_ROOT / "scripts" / "validate_scan_contract.py"

        finalized = subprocess.run(
            [sys.executable, "-B", str(finalizer), "--scan-dir", str(scan_dir)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(finalized.returncode, 0, finalized.stderr)

        validated = subprocess.run(
            [sys.executable, "-B", str(validator), "--scan-dir", str(scan_dir)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        receipt = json.loads(validated.stdout)
        self.assertEqual(receipt["status"], "valid")
        self.assertEqual(receipt["manifestPath"], str(scan_dir / "scan-manifest.json"))
        self.assertEqual(validated.stderr, "")


if __name__ == "__main__":
    unittest.main()
