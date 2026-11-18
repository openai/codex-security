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

    def validate_cli(self, *options: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(PLUGIN_ROOT / "scripts" / "validate_scan_contract.py"),
                "--scan-dir",
                str(self.scan_dir),
                *options,
            ],
            capture_output=True,
            text=True,
        )

    def assert_rejection(self, reason: str, location: str | None = None) -> None:
        result = self.validate_cli("--json-errors")
        self.assertEqual(result.returncode, 2, result.stderr)
        expected = {"status": "invalid", "reason": reason}
        if location:
            expected["location"] = location
        self.assertEqual(json.loads(result.stdout), expected)
        self.assertIn("scan contract validation failed:", result.stderr)

    def test_rejection_receipts_keep_the_existing_cli_streams_and_exit_codes(self) -> None:
        default = self.validate_cli()
        structured = self.validate_cli("--json-errors")
        self.assertEqual(structured.returncode, 0, structured.stderr)
        self.assertEqual((structured.stdout, structured.stderr), (default.stdout, default.stderr))

        (self.scan_dir / "report.md").unlink()
        default = self.validate_cli()
        structured = self.validate_cli("--json-errors")
        self.assertEqual(default.returncode, 2)
        self.assertEqual(default.stdout, "")
        self.assertIn("report.md", default.stderr)
        self.assertEqual(default.stderr, structured.stderr)
        self.assert_rejection("missing_artifact", "report.md")

    def test_completion_field_rejections(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        del manifest["scan"]["completedAt"]
        self.write_json("scan-manifest.json", manifest)
        self.assert_rejection("missing_required_field", "manifest.scan.completedAt")
        manifest["scan"]["completedAt"] = []
        self.write_json("scan-manifest.json", manifest)
        self.assert_rejection("invalid_required_field", "manifest.scan.completedAt")

    def test_artifact_rejections(self) -> None:
        path = self.scan_dir / "findings.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assert_rejection("artifact_digest_mismatch", "findings.json")
        path.write_text("{")
        self.assert_rejection("invalid_json", "findings.json")
        path.unlink()
        self.assert_rejection("missing_artifact", "findings.json")

        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"] = [
            item for item in manifest["scan"]["artifacts"] if item["path"] != "findings.json"
        ]
        self.write_json("scan-manifest.json", manifest)
        self.assert_rejection("missing_artifact_record", "findings.json")

    def test_rejection_receipt_omits_custom_paths_and_values(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        manifest["scan"]["artifacts"].append(
            {"path": "artifacts/custom.txt", "sha256": "0" * 64, "mediaType": "text/plain"}
        )
        self.write_json("scan-manifest.json", manifest)
        self.assert_rejection("missing_artifact")

        manifest["scan"]["target"]["kind"] = "custom target"
        self.write_json("scan-manifest.json", manifest)
        self.assert_rejection("validation_failed")

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

        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "manifest.scan.artifacts"):
            VALIDATOR.validate_contract(self.scan_dir)

    def test_ignores_legacy_timestamp_and_requires_intact_sealed_artifacts(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        del manifest["scan"]["sealedAt"]
        self.write_json("scan-manifest.json", manifest)
        manifest_path = self.scan_dir / "scan-manifest.json"
        original = manifest_path.read_bytes()

        validated = VALIDATOR.validate_contract(self.scan_dir)

        self.assertNotIn("sealedAt", validated["manifest"]["scan"])
        self.assertEqual(validated["findings"], self.read_json("findings.json"))
        self.assertEqual(manifest_path.read_bytes(), original)

        manifest["scan"]["sealedAt"] = "obsolete and unrelated to completion"
        self.write_json("scan-manifest.json", manifest)
        self.assertEqual(
            VALIDATOR.validate_contract(self.scan_dir)["findings"], validated["findings"]
        )

        manifest["scan"]["complete"] = False
        self.write_json("scan-manifest.json", manifest)
        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "incomplete scan"):
            VALIDATOR.validate_contract(self.scan_dir)
        manifest_path.write_bytes(original)

        findings_path = self.scan_dir / "findings.json"
        findings_path.write_bytes(findings_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(VALIDATOR.FINALIZER.ContractError, "sealed artifact changed"):
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
