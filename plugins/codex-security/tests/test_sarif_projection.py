from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import load_script

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = PLUGIN_ROOT / "examples" / "legacy-completed-scan"
FINALIZER = load_script("finalize_scan_contract", module_name="sarif_finalizer")


class SarifProjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((EXAMPLE_DIR / "scan-manifest.json").read_text())
        self.findings = json.loads((EXAMPLE_DIR / "findings.json").read_text())
        self.finding = self.findings["findings"][0]

    @pytest.mark.cross_platform
    def test_sarif_preserves_alert_identity_when_finding_text_changes(self) -> None:
        finding = self.finding
        finding["extensions"] = {"candidateId": "candidate-example"}
        run = FINALIZER.build_sarif(self.manifest, self.findings)["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        result = run["results"][0]
        self.assertNotEqual(rule["name"], finding["ruleId"])
        self.assertEqual(rule["shortDescription"]["text"], rule["name"])
        self.assertIn(finding["remediation"], rule["help"]["text"])
        for field in ("findingId", "occurrenceId"):
            self.assertEqual(result["properties"][field], finding[field])
        self.assertEqual(result["properties"]["candidateId"], "candidate-example")
        for text in (
            finding["title"],
            finding["summary"],
            *finding["remediationTests"],
            *finding["preventiveControls"],
        ):
            self.assertIn(text, result["message"]["text"])

        finding.update(
            title="A new title", summary="A changed summary", remediation="A different fix."
        )
        changed = FINALIZER.build_sarif(self.manifest, self.findings)["runs"][0]
        self.assertEqual(changed["tool"]["driver"]["rules"][0]["name"], rule["name"])
        for field in ("ruleId", "ruleIndex", "locations", "partialFingerprints", "properties"):
            self.assertEqual(changed["results"][0][field], result[field])

    @pytest.mark.cross_platform
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
        self.assertEqual(results[first["occurrenceId"]]["level"], "note")
        for own, other in ((first, second), (second, first)):
            result = results[own["occurrenceId"]]
            self.assertIn(own["remediation"], rules[0]["help"]["markdown"])
            self.assertIn(own["remediation"], result["message"]["text"])
            self.assertNotIn(other["remediation"], result["message"]["text"])
            self.assertEqual(result["properties"]["severity"], own["severity"]["level"])
            self.assertEqual(result["ruleIndex"], 0)

    @pytest.mark.cross_platform
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
                finding["taxonomy"] = {"category": "sql-injection", "cwe": []}
                run = FINALIZER.build_sarif(self.manifest, {"findings": [finding]})["runs"][0]
                properties = {"tags": ["security", "sql-injection"]}
                if expected is not None:
                    properties["security-severity"] = expected
                self.assertEqual(run["tool"]["driver"]["rules"][0]["properties"], properties)

    def test_sarif_normalizes_long_cwe_identifiers_as_text(self) -> None:
        for label, digits, tag in (
            ("zero-padded", "0" * 5000 + "22", "external/cwe/cwe-022"),
            ("all-zero", "0" * 5000, None),
            ("significant digits", "9" * 5000, "external/cwe/cwe-" + "9" * 5000),
        ):
            with self.subTest(label=label):
                cwe = f"CWE-{digits}"
                finding = copy.deepcopy(self.finding)
                finding["taxonomy"]["cwe"] = [cwe]
                findings = {**self.findings, "findings": [finding]}
                FINALIZER._validate_findings(self.manifest, findings)
                FINALIZER._validate_current_findings(findings, PLUGIN_ROOT / "schemas")
                FINALIZER.validate_against_schema(
                    findings, PLUGIN_ROOT / "schemas" / "findings.schema.json"
                )
                run = FINALIZER.build_sarif(self.manifest, findings)["runs"][0]
                rule = run["tool"]["driver"]["rules"][0]
                self.assertEqual(
                    rule["properties"]["tags"],
                    ([tag] if tag is not None else []) + ["path-traversal", "security"],
                )
                self.assertIn(cwe, rule["fullDescription"]["text"])
                self.assertIn(cwe, run["results"][0]["message"]["text"])
                self.assertEqual(finding["taxonomy"]["cwe"], [cwe])

    def test_sarif_preserves_cwe_tag_rules_and_original_spelling(self) -> None:
        cwes = [
            "CWE-1",
            "cWe-022",
            "CWE-00022",
            "CWE-1234",
            "CWE-0",
            "CWE-000",
            "CWE--22",
            "CWE-+22",
            " CWE-22",
            "CWE-22 ",
            "CWE-２２",
            "CWE-٢٢",
            "unknown",
        ]
        self.finding["taxonomy"]["cwe"] = cwes.copy()
        run = FINALIZER.build_sarif(self.manifest, self.findings)["runs"][0]
        rule = run["tool"]["driver"]["rules"][0]
        self.assertEqual(
            rule["properties"]["tags"],
            [
                "external/cwe/cwe-001",
                "external/cwe/cwe-022",
                "external/cwe/cwe-1234",
                "path-traversal",
                "security",
            ],
        )
        self.assertIn(f"Weaknesses: {', '.join(sorted(cwes))}.", rule["fullDescription"]["text"])
        self.assertIn(f"Weaknesses: {', '.join(cwes)}", run["results"][0]["message"]["text"])
        self.assertEqual(self.finding["taxonomy"]["cwe"], cwes)

    def test_sarif_projection_reports_run_warnings_without_changing_status_or_seal(self) -> None:
        warning = "Optional writeup unavailable: notes/review.md\nThe finding was retained."
        for status in ("completed", "failed", "interrupted", "canceled"):
            for warnings in (None, [], [warning]):
                with (
                    self.subTest(status=status, warnings=warnings),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    scan_dir = Path(directory) / "scan"
                    shutil.copytree(EXAMPLE_DIR, scan_dir)
                    manifest = copy.deepcopy(self.manifest)
                    manifest["scan"]["status"] = status
                    if warnings is not None:
                        manifest["scan"]["warnings"] = warnings
                    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest) + "\n")
                    before = {
                        name: (scan_dir / name).read_bytes()
                        for name in ("scan-manifest.json", "findings.json", "coverage.json")
                    }

                    contents = FINALIZER.build_findings_export(scan_dir, "sarif")
                    run = json.loads(contents)["runs"][0]
                    if status == "completed" and not warnings:
                        self.assertNotIn("invocations", run)
                    else:
                        self.assertEqual(
                            run["invocations"],
                            [
                                {
                                    "executionSuccessful": status == "completed",
                                    "toolExecutionNotifications": [
                                        {"level": "warning", "message": {"text": message}}
                                        for message in warnings or []
                                    ],
                                }
                            ],
                        )
                    FINALIZER.write_sarif_projection(scan_dir)
                    self.assertEqual((scan_dir / "exports/results.sarif").read_bytes(), contents)
                    self.assertEqual(
                        before, {name: (scan_dir / name).read_bytes() for name in before}
                    )

    def test_sarif_projection_appends_unique_run_warnings_after_deferred_reasons(self) -> None:
        deferred_reason = "Review of a deferred surface is incomplete."
        warning = "Optional writeup unavailable."
        for warnings, messages in (
            (None, [deferred_reason, deferred_reason]),
            ([], [deferred_reason, deferred_reason]),
            (
                [warning, deferred_reason, warning, warning + " "],
                [deferred_reason, deferred_reason, warning, warning + " "],
            ),
        ):
            with self.subTest(warnings=warnings), tempfile.TemporaryDirectory() as directory:
                scan_dir = Path(directory) / "scan"
                shutil.copytree(EXAMPLE_DIR, scan_dir)
                manifest = copy.deepcopy(self.manifest)
                if warnings is not None:
                    manifest["scan"]["warnings"] = warnings
                coverage_path = scan_dir / "coverage.json"
                coverage = json.loads(coverage_path.read_bytes())
                coverage["deferred"] = [
                    {"id": f"deferred-{index}", "reason": deferred_reason} for index in range(2)
                ]
                coverage_path.write_text(json.dumps(coverage) + "\n")
                for artifact in manifest["scan"]["artifacts"]:
                    if artifact["path"] == "coverage.json":
                        artifact["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
                (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest) + "\n")

                invocation = FINALIZER.build_sarif_projection(scan_dir)["runs"][0]["invocations"][0]

                self.assertTrue(invocation["executionSuccessful"])
                self.assertEqual(
                    invocation["toolExecutionNotifications"],
                    [{"level": "warning", "message": {"text": message}} for message in messages],
                )

    def test_sarif_projection_preserves_inventoried_exports(self) -> None:
        relative_path = "exports/results.sarif"
        error = "SARIF output path cannot overwrite a sealed scan artifact"
        for artifact_path, compact in (
            (relative_path, True),
            (relative_path, False),
            ("exports/sealed-results.sarif", False),
        ):
            with (
                self.subTest(artifact_path=artifact_path, compact=compact),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                scan_dir = root / "scan"
                shutil.copytree(EXAMPLE_DIR, scan_dir)
                FINALIZER.finalize_scan(scan_dir)
                sarif_path = scan_dir / relative_path
                if compact:
                    original = sarif_path.read_bytes()
                    sarif_path.write_text(json.dumps(json.loads(original), separators=(",", ":")))
                    self.assertNotEqual(sarif_path.read_bytes(), original)
                if artifact_path != relative_path:
                    os.link(sarif_path, scan_dir / artifact_path)
                manifest_path = scan_dir / "scan-manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                manifest["scan"]["artifacts"].append(
                    {
                        "path": artifact_path,
                        "sha256": hashlib.sha256(
                            (scan_dir / artifact_path).read_bytes()
                        ).hexdigest(),
                        "mediaType": "application/sarif+json",
                    }
                )
                manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
                before = {path: path.read_bytes() for path in scan_dir.rglob("*") if path.is_file()}
                self.assertEqual(
                    FINALIZER.build_findings_export(scan_dir, "json"),
                    before[scan_dir / "findings.json"],
                )

                with self.assertRaisesRegex(FINALIZER.SealedArtifactError, error):
                    FINALIZER.write_sarif_projection(scan_dir)
                self.assertEqual(before, {path: path.read_bytes() for path in before})

                stderr = io.StringIO()
                with (
                    redirect_stderr(stderr),
                    mock.patch.object(
                        FINALIZER, "write_sarif_projection", wraps=FINALIZER.write_sarif_projection
                    ) as write_projection,
                ):
                    FINALIZER.finalize_scan(scan_dir)
                write_projection.assert_not_called()
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(before, {path: path.read_bytes() for path in before})
                self.assertEqual(
                    FINALIZER.build_findings_export(scan_dir, "json"),
                    before[scan_dir / "findings.json"],
                )
                if artifact_path != relative_path:
                    self.assertTrue(sarif_path.samefile(scan_dir / artifact_path))

                contents = FINALIZER.build_findings_export(scan_dir, "sarif")
                self.assertEqual(json.loads(contents), json.loads(sarif_path.read_bytes()))
                output = root / "results.sarif"
                FINALIZER.write_export_output(scan_dir, output, "sarif", contents)
                self.assertEqual(output.read_bytes(), contents)
                self.assertEqual(before, {path: path.read_bytes() for path in before})
