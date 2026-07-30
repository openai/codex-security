#!/usr/bin/env python3
"""Guard: informational findings must appear in report.md projections."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


def load_report_projection():
    path = Path(__file__).with_name("report_projection.py")
    spec = importlib.util.spec_from_file_location("report_projection", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InformationalReportProjectionTests(unittest.TestCase):
    def test_informational_is_reportable(self) -> None:
        module = load_report_projection()
        self.assertIn("informational", module.REPORTABLE_SEVERITIES)

    def test_informational_only_scan_is_not_empty(self) -> None:
        module = load_report_projection()
        finding = {
            "title": "Informational note",
            "severity": {
                "level": "informational",
                "rationale": "Documented hardening opportunity.",
                "changeConditions": "None.",
            },
            "confidence": {
                "level": "high",
                "rationale": "Direct code evidence.",
            },
            "taxonomy": {"category": "security-misconfiguration", "cwe": ["CWE-693"]},
            "summary": "An informational finding for projection coverage.",
            "locations": [{"path": "README.md", "startLine": 1}],
            "remediation": {"summary": "No urgent action required."},
            "validation": {"summary": "Validated against schema."},
        }
        manifest = {
            "scan": {
                "target": {
                    "displayName": "demo",
                    "kind": "git",
                    "ref": "main",
                    "url": "https://example.com/demo.git",
                },
                "scope": {
                    "summary": "Repository scan",
                    "includePaths": ["."],
                    "excludePaths": [],
                    "limitations": [],
                    "runtimeStatus": "not recorded",
                    "validationMode": "static",
                },
                "threatModel": {"summary": "Demo threat model."},
            }
        }
        findings = {"findings": [finding]}
        coverage = {
            "mode": "repository",
            "inventoryStrategy": "git",
            "completeness": "complete",
            "includePaths": ["."],
            "excludePaths": [],
            "explicitExclusions": [],
        }
        markdown = module.build_report_markdown(manifest, findings, coverage)
        self.assertNotIn("### No findings", markdown)
        self.assertIn("informational", markdown)
        self.assertIn("Informational note", markdown)


if __name__ == "__main__":
    unittest.main()
