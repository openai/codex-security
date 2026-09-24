from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = PLUGIN_ROOT / "examples" / "completed-scan"
spec = importlib.util.spec_from_file_location(
    "sarif_finalizer", PLUGIN_ROOT / "scripts" / "finalize_scan_contract.py"
)
assert spec is not None and spec.loader is not None
FINALIZER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(FINALIZER)

TARGET_DRIFT_WARNING = (
    "Working-tree contents changed while the scan was running; "
    "results were saved for the original snapshot."
)


class SarifProjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((EXAMPLE_DIR / "scan-manifest.json").read_text())
        self.findings = json.loads((EXAMPLE_DIR / "findings.json").read_text())
        self.finding = self.findings["findings"][0]

    def test_sarif_merges_shared_rule_metadata_without_mixing_results(self) -> None:
        first = copy.deepcopy(self.finding)
        first["severity"] = {"level": "low"}
        first["remediation"] = "Apply the first control."
        second = copy.deepcopy(self.finding)
        second["identity"]["instance"] = "second"
        second["severity"] = {"level": "critical", "score": 9.7, "scoringSystem": "CVSS:3.1"}
        second["taxonomy"] = {
            "category": "archive-extraction",
            "cwe": ["cwe-022", "CWE-23", "unknown"],
        }
        second["remediation"] = "Apply the second control."
        findings = {**self.findings, "findings": [first, second]}
        FINALIZER._populate_unsealed_finding_identities(self.manifest, findings)
        run = FINALIZER.build_sarif(self.manifest, findings)["runs"][0]
        self.assertEqual(
            run, FINALIZER.build_sarif(self.manifest, {"findings": [second, first]})["runs"][0]
        )
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(
            rules[0]["properties"],
            {
                "security-severity": "9.7",
                "tags": [
                    "archive-extraction",
                    "external/cwe/cwe-022",
                    "external/cwe/cwe-023",
                    "path-traversal",
                    "security",
                ],
            },
        )
        results = {result["properties"]["occurrenceId"]: result for result in run["results"]}
        for own, other in ((first, second), (second, first)):
            result = results[own["occurrenceId"]]
            self.assertIn(own["remediation"], rules[0]["help"]["markdown"])
            self.assertIn(own["remediation"], result["message"]["text"])
            self.assertNotIn(other["remediation"], result["message"]["text"])
            self.assertEqual(result["properties"]["severity"], own["severity"]["level"])
            self.assertEqual(result["ruleIndex"], 0)

    def test_sarif_security_severity_mapping(self) -> None:
        for level, score, expected in (
            ("critical", None, "9.5"),
            ("high", None, "8.0"),
            ("medium", None, "5.0"),
            ("low", None, "2.0"),
            ("informational", None, None),
            ("high", 0, None),
            ("high", 6.25, "6.25"),
            ("critical", 10, "10"),
        ):
            with self.subTest(level=level, score=score):
                finding = copy.deepcopy(self.finding)
                finding["severity"] = {"level": level}
                if score is not None:
                    finding["severity"].update(score=score, scoringSystem="CVSS:3.1")
                finding["taxonomy"]["cwe"] = []
                properties = FINALIZER._sarif_rule(finding["ruleId"], [finding])["properties"]
                self.assertEqual(properties.get("security-severity"), expected)
                self.assertEqual(properties["tags"], ["path-traversal", "security"])


class SarifRunWarningTest(unittest.TestCase):
    """Run warnings that leave coverage complete still reach SARIF consumers."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scan_dir = Path(self.temp_dir.name).resolve()
        self.manifest = json.loads((EXAMPLE_DIR / "scan-manifest.json").read_text())
        scan = self.manifest["scan"]
        for sealed_field in ("sealedAt", "artifacts"):
            scan.pop(sealed_field, None)
        for name in ("findings.json", "coverage.json", "report.md"):
            (self.scan_dir / name).write_bytes((EXAMPLE_DIR / name).read_bytes())
        (self.scan_dir / "scan-manifest.json").write_text(json.dumps(self.manifest))

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_complete_scan_run_warnings_reach_the_sarif_projection(self) -> None:
        prepared = FINALIZER._prepare_scan_finalization(
            self.scan_dir, completion_warnings=[TARGET_DRIFT_WARNING]
        )
        FINALIZER._write_prepared_scan_finalization(prepared)

        coverage = json.loads((self.scan_dir / "coverage.json").read_text())
        sealed_manifest = json.loads((self.scan_dir / "scan-manifest.json").read_text())
        coverage_artifact = next(
            artifact
            for artifact in sealed_manifest["scan"]["artifacts"]
            if artifact["path"] == "coverage.json"
        )
        sarif = json.loads((self.scan_dir / "exports" / "results.sarif").read_text())
        run = sarif["runs"][0]

        # The drift warning left coverage complete, so completeness alone would
        # never have produced an invocations block for it.
        self.assertEqual(coverage["completeness"], "complete")
        self.assertEqual(coverage["warnings"], [TARGET_DRIFT_WARNING])
        self.assertEqual(run["properties"]["codexSecurityCoverageCompleteness"], "complete")
        self.assertEqual(
            run["invocations"],
            [
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {"level": "warning", "message": {"text": TARGET_DRIFT_WARNING}}
                    ],
                }
            ],
        )
        # The warnings ride the seal, so a later file-based projection still sees them.
        self.assertEqual(
            FINALIZER.build_sarif_projection(self.scan_dir)["runs"][0]["invocations"],
            run["invocations"],
        )
        self.assertEqual(
            coverage_artifact["sha256"],
            FINALIZER._sha256_bytes((self.scan_dir / "coverage.json").read_bytes()),
        )

    def test_scan_without_run_warnings_keeps_its_previous_sarif_shape(self) -> None:
        prepared = FINALIZER._prepare_scan_finalization(self.scan_dir, completion_warnings=[])
        FINALIZER._write_prepared_scan_finalization(prepared)

        coverage = json.loads((self.scan_dir / "coverage.json").read_text())
        run = json.loads((self.scan_dir / "exports" / "results.sarif").read_text())["runs"][0]

        self.assertNotIn("warnings", coverage)
        self.assertNotIn("invocations", run)
        self.assertNotIn("codexSecurityCoverageCompleteness", run["properties"])

    def test_file_based_finalization_preserves_draft_warnings(self) -> None:
        coverage_path = self.scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["warnings"] = [TARGET_DRIFT_WARNING]
        coverage_path.write_text(json.dumps(coverage))

        FINALIZER.finalize_scan(self.scan_dir)

        sealed = json.loads(coverage_path.read_text())
        run = json.loads((self.scan_dir / "exports" / "results.sarif").read_text())["runs"][0]
        self.assertEqual(sealed["warnings"], [TARGET_DRIFT_WARNING])
        self.assertEqual(
            run["invocations"][0]["toolExecutionNotifications"],
            [{"level": "warning", "message": {"text": TARGET_DRIFT_WARNING}}],
        )

    def test_warning_already_carried_by_a_deferred_row_is_not_reported_twice(self) -> None:
        # Recovery warnings are sealed as warnings and as deferred rows at once,
        # so the deferred row is the one notification that should carry them.
        recovered = "Skipped malformed finding 1: findings.findings[0].summary is empty."
        (self.scan_dir / "coverage.json").write_text(
            json.dumps(
                {
                    **json.loads((EXAMPLE_DIR / "coverage.json").read_text()),
                    "completeness": "partial",
                    "deferred": [{"id": "discarded-finding-1", "reason": recovered}],
                }
            )
        )
        prepared = FINALIZER._prepare_scan_finalization(
            self.scan_dir, completion_warnings=[recovered, TARGET_DRIFT_WARNING]
        )
        FINALIZER._write_prepared_scan_finalization(prepared)

        coverage = json.loads((self.scan_dir / "coverage.json").read_text())
        run = json.loads((self.scan_dir / "exports" / "results.sarif").read_text())["runs"][0]

        self.assertEqual(coverage["warnings"], [recovered, TARGET_DRIFT_WARNING])
        self.assertEqual(
            run["invocations"][0]["toolExecutionNotifications"],
            [
                {"level": "warning", "message": {"text": TARGET_DRIFT_WARNING}},
                {"level": "warning", "message": {"text": recovered}},
            ],
        )
