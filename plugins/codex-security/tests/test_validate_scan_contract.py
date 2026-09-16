from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCAN = PLUGIN_ROOT / "examples" / "completed-scan"


def load_validator() -> ModuleType:
    script = PLUGIN_ROOT / "scripts" / "validate_scan_contract.py"
    spec = importlib.util.spec_from_file_location("validate_scan_contract", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


class ValidateScanContractTest(unittest.TestCase):
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
        (self.scan_dir / name).write_text(json.dumps(payload, indent=2) + "\n")

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
        self.write_json("findings.json", findings)
        manifest = self.read_json("scan-manifest.json")
        findings_artifact = next(
            artifact
            for artifact in manifest["scan"]["artifacts"]
            if artifact["path"] == "findings.json"
        )
        findings_artifact["sha256"] = VALIDATOR.FINALIZER._sha256_file(
            self.scan_dir / "findings.json"
        )
        self.write_json("scan-manifest.json", manifest)

        validated = VALIDATOR.validate_contract(self.scan_dir)

        self.assertEqual(validated["findings"], findings)

    def test_accepts_canonical_document_beyond_previous_size_limit(self) -> None:
        manifest = self.read_json("scan-manifest.json")
        manifest["metadata"] = "x" * (16 * 1024 * 1024)
        self.write_json("scan-manifest.json", manifest)

        validated = VALIDATOR.validate_contract(self.scan_dir)

        self.assertEqual(len(validated["manifest"]["metadata"]), 16 * 1024 * 1024)

    def test_rejects_unsafe_values_in_sealed_finding_extensions(self) -> None:
        original_manifest = (self.scan_dir / "scan-manifest.json").read_bytes()
        original_findings = (self.scan_dir / "findings.json").read_bytes()
        for value, reason in (
            (1e20, "unsafe integer-valued JSON numbers"),
            ("bad-" + chr(0xD800), "well-formed Unicode"),
        ):
            with self.subTest(reason=reason):
                (self.scan_dir / "scan-manifest.json").write_bytes(original_manifest)
                (self.scan_dir / "findings.json").write_bytes(original_findings)
                findings = self.read_json("findings.json")
                findings["findings"][0].setdefault("extensions", {})["unsafe"] = value
                self.write_json("findings.json", findings)
                manifest = self.read_json("scan-manifest.json")
                for artifact in manifest["scan"]["artifacts"]:
                    if artifact["path"] == "findings.json":
                        artifact["sha256"] = VALIDATOR.FINALIZER._sha256_file(
                            self.scan_dir / "findings.json"
                        )
                        break
                self.write_json("scan-manifest.json", manifest)

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

    def test_cli_prints_machine_readable_receipt(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = VALIDATOR.main(["--scan-dir", str(self.scan_dir)])

        receipt = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(receipt["status"], "valid")
        self.assertEqual(
            receipt["manifestPath"],
            str(self.scan_dir.resolve() / "scan-manifest.json"),
        )
        self.assertEqual(stderr.getvalue(), "")

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
        self.assertEqual(json.loads(validated.stdout)["status"], "valid")


if __name__ == "__main__":
    unittest.main()
