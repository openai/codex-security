"""Project an independent scan's observations and evidence into its parent scan.

This private helper is shared by SDK composition and stopped-result recovery.
Callers retain ownership of semantic merge decisions and provisional identities.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from contextlib import closing
from os.path import normcase
from pathlib import Path, PurePosixPath
from typing import Any, TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    _legacy_sealed_findings_for_validation,
    _prepare_scan_finalization,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    scan_root_identity,
)


class RootIdentity(TypedDict):
    dev: str
    ino: str


class ProjectionRequest(TypedDict):
    parentScanId: str
    sourceScanId: str
    sourceDirectory: str
    parentDirectory: str
    expectedParentIdentity: RootIdentity


class ProjectedScan(TypedDict):
    scanId: str
    scanDir: str
    draft: dict[str, Any]
    sourceFindings: list[dict[str, Any]]


def _scope_path(value: str) -> str:
    # Canonical paths use POSIX separators; scope matching keeps native case semantics.
    return normcase(value).replace("\\", "/")


def _project_candidate_id(source_scan_id: str, candidate_id: str) -> str:
    return f"{source_scan_id}:{hashlib.sha256(candidate_id.encode()).hexdigest()}"


def project_scan_artifacts(
    parent_scan_id: str,
    source_scan_id: str,
    source_directory: Path,
    parent_directory: Path,
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
    *,
    expected_parent_identity: tuple[int, int] | None = None,
) -> ProjectedScan:
    """Project validated documents without changing their source or accepting identities."""
    parent_directory, identity = scan_root_identity(parent_directory)
    if expected_parent_identity is not None and identity != expected_parent_identity:
        raise ContractError("scan directory: changed after artifact restoration setup")
    prefix = source_directory.relative_to(parent_directory).as_posix()
    scan = manifest["scan"]
    scopes = {PurePosixPath(_scope_path(scope)) for scope in scan["scope"]["includePaths"]}

    def in_scope(value: str) -> bool:
        path = PurePosixPath(_scope_path(value))
        if path.is_absolute() or ".." in path.parts:
            return False
        return path in scopes or any(parent in scopes for parent in path.parents)

    originals = copy.deepcopy(
        [
            finding
            for finding in findings["findings"]
            if any(in_scope(location["path"]) for location in finding["locations"])
        ]
    )
    # Merge the compatible view while retaining the exact sealed originals as provenance.
    projected = _legacy_sealed_findings_for_validation({"findings": originals})["findings"]
    for index, finding in enumerate(projected):
        for field in ("findingId", "occurrenceId", "fingerprints"):
            finding.pop(field, None)
        candidate_id = finding_candidate_id(finding)
        provenance = finding.setdefault("provenance", {})
        provenance["sourceFindingIds"] = [f"{source_scan_id}:{index}"]
        if candidate_id is not None:
            provenance["candidateId"] = _project_candidate_id(source_scan_id, candidate_id)
        writeup = finding.get("writeup")
        if isinstance(writeup, dict):
            # The child is already beneath the parent. Retain its original tree and
            # relative Markdown links; consumers use verified scan-local descriptors.
            relative = writeup["reportPath"]
            descriptor = open_scan_local_file_descriptor(
                source_directory, relative, "Scan merge evidence"
            )
            os.close(descriptor)
            writeup["reportPath"] = f"{prefix}/{relative}"

    semantic_coverage = copy.deepcopy(coverage)
    for field in (
        "documentType",
        "schemaVersion",
        "scanId",
        "mode",
        "includePaths",
        "excludePaths",
        "receiptRefs",
        "inventoryStrategy",
        # Child draft-history closures do not resolve work in the parent.
        "resolvedDeferred",
    ):
        semantic_coverage.pop(field, None)
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        for row in semantic_coverage.get(field, []):
            if not isinstance(row, dict):
                continue
            if isinstance(row.get("id"), str):
                row["id"] = f"{source_scan_id}/{row['id']}"
            if isinstance(row.get("candidateId"), str):
                candidate = row["candidateId"]
                row["sourceCandidateId"] = candidate
                row["candidateId"] = _project_candidate_id(source_scan_id, candidate)
            if isinstance(row.get("surfaceIds"), list):
                row["surfaceIds"] = [f"{source_scan_id}/{value}" for value in row["surfaceIds"]]
            if isinstance(row.get("receiptRefs"), list):
                row["receiptRefs"] = [f"{prefix}/{value}" for value in row["receiptRefs"]]
    scope = copy.deepcopy(scan["scope"])
    scope.pop("includePaths", None)
    scope.pop("excludePaths", None)
    draft = {
        "scanId": parent_scan_id,
        **({"complete": False} if scan.get("complete") is False else {}),
        **({"scope": scope} if scope else {}),
        **({"threatModel": copy.deepcopy(scan["threatModel"])} if "threatModel" in scan else {}),
        "findings": projected,
        "coverage": semantic_coverage,
    }
    return {
        "scanId": source_scan_id,
        "scanDir": str(source_directory),
        "draft": draft,
        "sourceFindings": originals,
    }


def project_completed_scan(request: ProjectionRequest) -> ProjectedScan:
    source_directory, _, manifest, findings, coverage, sealed, _ = _prepare_scan_finalization(
        Path(request["sourceDirectory"])
    )
    scan = manifest["scan"]
    if scan["id"] != request["sourceScanId"]:
        raise ContractError("Scan projection source does not match the requested scan")
    if not sealed or scan["status"] != "completed" or scan.get("complete") is False:
        raise ContractError("Only a sealed completed scan can be merged as a completed scan")
    # Use the saved receipt, not only the hashes supplied by the artifact itself.
    import workbench_db

    with closing(workbench_db.connect()) as connection:
        source = workbench_db.require_scan(connection, request["sourceScanId"])
        workbench_db.require_recorded_manifest_digest(source, source_directory)
        workbench_db.verify_manifest_binding(source, manifest)
    expected = request["expectedParentIdentity"]
    return project_scan_artifacts(
        request["parentScanId"],
        request["sourceScanId"],
        source_directory,
        Path(request["parentDirectory"]),
        manifest,
        findings,
        coverage,
        expected_parent_identity=(int(expected["dev"]), int(expected["ino"])),
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        result = project_completed_scan(json.load(sys.stdin))
        json.dump(result, sys.stdout, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        sys.stdout.write("\n")
    except (ContractError, OSError, ValueError) as exc:
        sys.exit(str(exc))
