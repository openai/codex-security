#!/usr/bin/env python3
"""Validate a sealed scan and list or select findings for tracking."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_scan_contract_validator() -> ModuleType:
    script = Path(__file__).resolve().with_name("validate_scan_contract.py")
    spec = importlib.util.spec_from_file_location("codex_security_scan_validator", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load scan contract validator: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAN_CONTRACT = _load_scan_contract_validator()
FINALIZER = SCAN_CONTRACT.FINALIZER
validate_contract = SCAN_CONTRACT.validate_contract


def _select_findings(
    findings: list[dict[str, Any]],
    finding_id: str | None,
    fingerprint: str | None,
) -> list[dict[str, Any]]:
    if finding_id is not None:
        matches = [finding for finding in findings if finding["findingId"] == finding_id]
    elif fingerprint is not None:
        matches = [
            finding for finding in findings if finding["fingerprints"]["primary"] == fingerprint
        ]
    else:
        return findings

    if len(matches) != 1:
        raise ValueError("the selector did not resolve exactly one finding")
    return matches


def validate_source(
    scan_dir: Path,
    *,
    finding_id: str | None = None,
    fingerprint: str | None = None,
) -> list[dict[str, Any]]:
    if finding_id is not None and fingerprint is not None:
        raise ValueError("use only one of --finding-id or --fingerprint")

    validated = validate_contract(scan_dir)
    findings_document = validated["findings"]
    return _select_findings(
        findings_document["findings"],
        finding_id,
        fingerprint,
    )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_dir", type=Path)
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--finding-id")
    selector.add_argument("--fingerprint")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        findings = validate_source(
            args.scan_dir,
            finding_id=args.finding_id,
            fingerprint=args.fingerprint,
        )
    except (OSError, ValueError, RecursionError) as exc:
        print(f"tracking source preflight failed: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding["findingId"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
