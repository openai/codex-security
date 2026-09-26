"""Assemble new file-authored scan envelopes before their first write."""

from __future__ import annotations

import copy
from typing import Any


def build_scan_draft(
    *, scan: dict[str, Any], findings: list[dict[str, Any]], coverage: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """Wrap newly authored semantics with one identity; do not read or repair artifacts.

    The producer supplies its resolved scan metadata, finding records, and coverage
    fields before writing canonical files. Validation and sealing remain with the
    finalizer (or the SDK for an SDK-owned scan).
    """
    scan = copy.deepcopy(scan)
    scan_id = scan["id"]
    scan["findingsRef"] = "findings.json"
    scan["coverageRef"] = "coverage.json"
    return {
        "scan-manifest.json": {
            "documentType": "codex-security.scan-manifest",
            "schemaVersion": "1.0",
            "scan": scan,
        },
        "findings.json": {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": scan_id,
            "findings": copy.deepcopy(findings),
        },
        "coverage.json": {
            **copy.deepcopy(coverage),
            "documentType": "codex-security.coverage",
            "schemaVersion": "1.0",
            "scanId": scan_id,
        },
    }
