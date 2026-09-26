from __future__ import annotations

import copy
import importlib.util
import json
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
