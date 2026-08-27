#!/usr/bin/env python3
"""Validate a sealed Codex Security scan contract without mutating it."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_finalizer() -> ModuleType:
    script = Path(__file__).resolve().with_name("finalize_scan_contract.py")
    spec = importlib.util.spec_from_file_location("codex_security_scan_contract", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scan contract validator: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINALIZER = _load_finalizer()


def validate_contract(scan_dir: Path) -> dict[str, Any]:
    """Return validated canonical documents for one sealed scan."""

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
    findings_ref = scan["findingsRef"]
    coverage_ref = scan["coverageRef"]
    findings, findings_bytes = FINALIZER._read_scan_local_json_bytes(
        scan_dir,
        findings_ref,
        findings_ref,
    )
    coverage, coverage_bytes = FINALIZER._read_scan_local_json_bytes(
        scan_dir,
        coverage_ref,
        coverage_ref,
    )
    FINALIZER._validate_existing_seal(
        scan_dir,
        scan,
        artifact_contents={
            findings_ref: findings_bytes,
            coverage_ref: coverage_bytes,
        },
    )
    findings_for_validation = FINALIZER._legacy_sealed_findings_for_validation(findings)
    FINALIZER._validate_findings(manifest, findings_for_validation)
    FINALIZER._validate_derived_finding_identities(manifest, findings)
    FINALIZER._validate_coverage(manifest, coverage, scan_dir)
    FINALIZER._validate_sealed_coverage_receipts(scan, coverage)
    FINALIZER.validate_against_schema(
        findings_for_validation, schema_dir / "findings.schema.json"
    )
    FINALIZER.validate_against_schema(coverage, schema_dir / "coverage.schema.json")
    FINALIZER._require_scan_local_file(scan_dir, "report.md", "report.md")
    return {
        "scanDir": str(scan_dir),
        "manifest": manifest,
        "findings": findings,
        "coverage": coverage,
    }


def receipt(validated: dict[str, Any]) -> dict[str, Any]:
    scan_dir = Path(validated["scanDir"])
    scan = validated["manifest"]["scan"]
    return {
        "status": "valid",
        "scanDir": str(scan_dir),
        "manifestPath": str(scan_dir / "scan-manifest.json"),
        "findingsPath": str(scan_dir / scan["findingsRef"]),
        "coveragePath": str(scan_dir / scan["coverageRef"]),
        "reportPath": str(scan_dir / "report.md"),
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        validated = validate_contract(args.scan_dir)
    except (OSError, ValueError, RecursionError) as exc:
        print(f"scan contract validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt(validated), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
