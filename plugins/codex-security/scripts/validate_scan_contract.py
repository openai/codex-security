#!/usr/bin/env python3
"""Validate a sealed Codex Security scan contract without mutating it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# Keep sibling helpers importable when Python starts in isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import finalize_scan_contract as FINALIZER


def validate_contract(
    scan_dir: Path,
    *,
    completion_binding: dict[str, Any] | None = None,
    finding_scope: list[tuple[str, bool]] | None = None,
) -> dict[str, Any]:
    """Validate the sealed artifacts and return the manifest, original findings, and review summary.

    Legacy finding records are adapted for validation only. ContractError propagates
    when a required artifact, digest, schema, or evidence check fails.
    When completing a scan, also check the registered request and hash the report.
    """

    scan_dir = FINALIZER._require_scan_directory(scan_dir.expanduser().resolve(strict=True))
    schema_dir = Path(__file__).resolve().parents[1] / "schemas"
    manifest, _ = FINALIZER._read_scan_local_json_bytes(
        scan_dir,
        "scan-manifest.json",
        "scan-manifest.json",
    )
    FINALIZER._validate_manifest(manifest)
    FINALIZER.validate_against_schema(manifest, schema_dir / "scan-manifest.schema.json")

    scan = FINALIZER._require_dict(manifest, "scan", "manifest")
    findings, coverage, _ = FINALIZER._read_sealed_artifacts(scan_dir, scan)
    findings_for_validation = FINALIZER._legacy_sealed_findings_for_validation(findings)
    FINALIZER._validate_findings(manifest, findings_for_validation)
    FINALIZER._validate_derived_finding_identities(manifest, findings)
    FINALIZER._validate_coverage(manifest, coverage, scan_dir)
    FINALIZER._validate_sealed_coverage_receipts(scan, coverage)
    FINALIZER.validate_against_schema(findings_for_validation, schema_dir / "findings.schema.json")
    FINALIZER.validate_against_schema(coverage, schema_dir / "coverage.schema.json")
    validated = {
        "scanDir": str(scan_dir),
        "manifest": manifest,
        "findings": findings,
        "review": FINALIZER.review_summary(coverage),
    }
    if completion_binding is None:
        FINALIZER._require_scan_local_file(scan_dir, "report.md", "report.md")
        return validated

    FINALIZER._validate_completion_binding(manifest, findings, coverage, completion_binding)
    if scan.get("complete") is False:
        raise FINALIZER.ContractError("manifest.scan.complete: expected a final scan")
    for index, finding in enumerate(findings["findings"]):
        if not FINALIZER.finding_has_in_scope_location(
            finding, finding_scope, scan["scope"]["excludePaths"]
        ):
            raise FINALIZER.ContractError(f"findings[{index}]: no location in the requested scope")
    FINALIZER._prepare_derived_writeups(scan_dir, findings)
    FINALIZER._require_hardening_portfolio_file(scan_dir, scan)
    with os.fdopen(
        FINALIZER.open_scan_local_file_descriptor(scan_dir, "report.md", "report.md"), "rb"
    ) as report:
        report_bytes = report.read()
    if not report_bytes.strip():
        raise FINALIZER.ContractError("report.md: expected a nonempty report")
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    for artifact in scan["artifacts"]:
        if artifact["path"] == "report.md" and artifact["sha256"] != report_digest:
            raise FINALIZER.ContractError("report.md: sealed artifact changed")
    validated["reportSha256"] = report_digest
    return validated


def receipt(validated: dict[str, Any]) -> dict[str, Any]:
    """Return the CLI success payload with paths to the validated manifest, findings, and report."""
    scan_dir = Path(validated["scanDir"])
    scan = validated["manifest"]["scan"]
    return {
        "status": "valid",
        "scanDir": str(scan_dir),
        "manifestPath": str(scan_dir / "scan-manifest.json"),
        "findingsPath": str(scan_dir / scan["findingsRef"]),
        "reportPath": str(scan_dir / "report.md"),
    }


def main(argv: list[str] | None = None) -> int:
    """Print the validation receipt on success or report a validation error to stderr and return 2."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        validated = validate_contract(args.scan_dir)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"scan contract validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt(validated), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
