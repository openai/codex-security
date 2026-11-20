#!/usr/bin/env python3
"""Validate a sealed Codex Security scan contract without mutating it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

# Keep sibling helpers importable when Python starts in isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import finalize_scan_contract as FINALIZER
from workbench.storage import create_private_temporary_directory

_PUBLIC_LOCATIONS = {
    "coverage.json",
    "findings.json",
    "report.md",
    "scan-manifest.json",
    "manifest.scan.completedAt",
    "manifest.scan.sealedAt",
}


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
    manifest, manifest_bytes = FINALIZER._read_scan_local_json_bytes(
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
    validated["manifestSha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    return validated


def publish_scan_bundle(
    validated: dict[str, Any], *, owner_suggestions_digest: str | None = None
) -> dict[str, Any]:
    """Publish an atomic snapshot of the files admitted by completion validation."""
    scan_dir = Path(validated["scanDir"])
    scan = validated["manifest"]["scan"]
    digests = {artifact["path"]: artifact["sha256"] for artifact in scan["artifacts"]}
    digests.update(
        {
            "scan-manifest.json": validated["manifestSha256"],
            "report.md": validated["reportSha256"],
        }
    )
    references = {
        finding["writeup"]["reportPath"]
        for finding in validated["findings"]["findings"]
        if "writeup" in finding
    }
    if "hardening" in scan:
        references.add(scan["hardening"]["portfolioPath"])
    if owner_suggestions_digest is not None:
        digests["owner-suggestions.json"] = owner_suggestions_digest

    pending = create_private_temporary_directory(scan_dir, prefix=".bundle-")
    bundle = scan_dir / "bundle"
    try:
        paths = digests.keys() | references
        for path in sorted(paths):
            with os.fdopen(
                FINALIZER.open_scan_local_file_descriptor(scan_dir, path, path), "rb"
            ) as source:
                contents = source.read()
            if path in digests and hashlib.sha256(contents).hexdigest() != digests[path]:
                raise FINALIZER.ContractError(
                    f"The validated file {path} changed before publication."
                )
            FINALIZER.write_scan_local_bytes(pending, path, contents)

        # Derive these projections from the accepted files. The working directory
        # may contain unrelated exports or an old threat model.
        FINALIZER._write_sarif_projection_if_possible(pending, sealed_paths=list(paths))
        FINALIZER.write_threat_model_projection_if_possible(pending, validated["manifest"])
        artifacts = _bundle_artifacts(pending)
        if os.path.lexists(bundle):
            if _bundle_artifacts(bundle) != artifacts:
                raise FINALIZER.ContractError("bundle: conflicts with an existing scan handoff")
        else:
            pending.rename(bundle)
        return {"bundleDirectory": str(bundle), "artifacts": artifacts}
    except OSError as exc:
        raise FINALIZER.ContractError(f"Could not publish the scan bundle: {exc}") from exc
    finally:
        if pending.exists():
            shutil.rmtree(pending)


def _bundle_artifacts(directory: Path) -> list[dict[str, Any]]:
    """Describe the published files and reject unexpected directories on retries."""
    FINALIZER._require_scan_directory(directory, "scan bundle")
    artifacts = []
    directories = set()
    parents = set()
    for root, children, files in os.walk(directory):
        directories.update((Path(root) / child).relative_to(directory) for child in children)
        for name in files:
            path = (Path(root) / name).relative_to(directory)
            parents.update(path.parents[:-1])
            relative = path.as_posix()
            with os.fdopen(
                FINALIZER.open_scan_local_file_descriptor(directory, relative, relative), "rb"
            ) as source:
                size = os.fstat(source.fileno()).st_size
                digest = hashlib.sha256()
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            artifacts.append({"path": relative, "sha256": digest.hexdigest(), "bytes": size})
    if directories != parents:
        raise FINALIZER.ContractError("bundle: contains an unexpected directory")
    return sorted(artifacts, key=lambda artifact: artifact["path"])


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
    parser.add_argument(
        "--json-errors",
        action="store_true",
        help="also write a machine-readable rejection receipt to stdout on validation failure",
    )
    args = parser.parse_args(argv)
    try:
        validated = validate_contract(args.scan_dir)
    except (OSError, ValueError, RecursionError) as exc:
        if args.json_errors:
            rejection = {"status": "invalid", "reason": "validation_failed"}
            if isinstance(exc, FINALIZER.ContractError):
                rejection["reason"] = exc.reason
                if exc.location is not None and exc.location in _PUBLIC_LOCATIONS:
                    rejection["location"] = exc.location
            print(json.dumps(rejection, sort_keys=True))
        print(f"scan contract validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt(validated), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
