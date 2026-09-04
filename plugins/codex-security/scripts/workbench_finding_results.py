"""Finding details and artifact projections for saved workbench scans."""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workbench_scan_history as scan_history
from finalize_scan_contract import ContractError, _loads_json, open_scan_local_file_descriptor
from finding_preview import bounded_finding_details
from workbench_constants import (
    FINDING_ABSOLUTE_PATH_BYTES,
    FINDING_LEVEL_BYTES,
    FINDING_LOCATION_PATH_BYTES,
    FINDING_LOCATION_ROLE_BYTES,
    FINDING_LOCATIONS_LIMIT,
    FINDING_REMEDIATION_BYTES,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
)
from workbench_source_excerpt import finding_source_excerpt, safe_source_path
from workbench_target import require_scan_target_identity
from workbench_validation import bounded_output_text

FINDING_ARTIFACT_DIRECTORIES_LIMIT = 80
FINDING_ARTIFACTS_LIMIT = 40
FINDING_WRITEUP_REPORT_PATH = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")


def finding_result(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    occurrence: sqlite3.Row,
    *,
    full_details: bool,
    indexed_finding: dict[str, Any] | None,
    remediation_state: dict[str, Any],
    related: list[dict[str, Any]],
) -> dict[str, Any]:
    stored_details = read_finding_details(occurrence["details_json"])
    details = dict(stored_details if full_details else bounded_finding_details(stored_details))
    for field in (
        "artifactPaths",
        "currentTargetPath",
        "knownScanIds",
        "knownSince",
        "matches",
        "occurrenceCount",
        "related",
        "scanDir",
        "scanId",
        "sourceExcerpt",
        "status",
        "targetId",
        "targetPath",
        "updatedAt",
    ):
        details.pop(field, None)
    confidence = details.get("confidence")
    confidence = confidence if isinstance(confidence, dict) else {}
    severity = details.get("severity")
    severity = severity if isinstance(severity, dict) else {}
    locations = []
    try:
        target = require_scan_target_identity(scan, target_path=scan["target_path"])
    except SystemExit:
        current_target = connection.execute(
            "SELECT current_path FROM security_targets WHERE id = ?", (scan["target_id"],)
        ).fetchone()
        try:
            target = (
                require_scan_target_identity(scan, target_path=current_target["current_path"])
                if current_target is not None
                else None
            )
        except SystemExit:
            target = None
    for row in connection.execute(
        """
        SELECT relative_path, start_line, end_line, role
        FROM finding_locations
        WHERE occurrence_id = ?
        ORDER BY CASE WHEN role = 'root_control' THEN 0 ELSE 1 END, sort_order
        LIMIT ?
        """,
        (occurrence["id"], -1 if full_details else FINDING_LOCATIONS_LIMIT),
    ):
        absolute_path = safe_source_path(target, row["relative_path"]) if target else None
        location = {
            "endLine": row["end_line"],
            "path": (
                row["relative_path"]
                if full_details
                else bounded_output_text(row["relative_path"], FINDING_LOCATION_PATH_BYTES)
            ),
            "role": (
                row["role"]
                if full_details
                else bounded_output_text(row["role"], FINDING_LOCATION_ROLE_BYTES)
                if row["role"] is not None
                else None
            ),
            "startLine": row["start_line"],
        }
        if absolute_path is not None:
            location["absolutePath"] = (
                str(absolute_path)
                if full_details
                else bounded_output_text(absolute_path, FINDING_ABSOLUTE_PATH_BYTES)
            )
        locations.append(location)
    triage = finding_triage_result(connection, occurrence["id"], indexed_finding)
    result = {
        **details,
        "confidence": {
            **confidence,
            "level": bounded_output_text(occurrence["confidence"], FINDING_LEVEL_BYTES),
        },
        "createdAt": occurrence["created_at"],
        "findingId": occurrence["finding_id"],
        "locations": locations,
        "occurrenceId": occurrence["id"],
        "remediationState": remediation_state,
        "remediation": (
            occurrence["remediation"]
            if full_details
            else bounded_output_text(occurrence["remediation"], FINDING_REMEDIATION_BYTES)
        ),
        "severity": {
            **severity,
            "level": bounded_output_text(occurrence["severity"], FINDING_LEVEL_BYTES),
        },
        "status": triage["status"],
        "summary": (
            occurrence["summary"]
            if full_details
            else bounded_output_text(occurrence["summary"], FINDING_SUMMARY_BYTES)
        ),
        "title": (
            occurrence["title"]
            if full_details
            else bounded_output_text(occurrence["title"], FINDING_TITLE_BYTES)
        ),
        "triage": triage,
    }
    matches, known_since, known_scan_ids = scan_history.finding_matches(
        connection,
        occurrence["id"],
        indexed_finding["occurrence_ids"] if indexed_finding is not None else {occurrence["id"]},
    )
    if indexed_finding is not None:
        matches = [
            match for match in matches if match["occurrenceId"] in indexed_finding["occurrence_ids"]
        ]
        known_since = indexed_finding["known_since"]
        known_scan_ids = indexed_finding["known_scan_ids"]
        if indexed_finding["occurrence_count"] > 1:
            result["occurrenceCount"] = indexed_finding["occurrence_count"]
    elif scan["target_id"] is not None and scan["status"] == "complete":
        matches = []
    if related:
        result["related"] = related
    if matches:
        result["matches"] = matches
    if matches or result.get("occurrenceCount", 0) > 1:
        result["knownSince"] = known_since
        result["knownScanIds"] = known_scan_ids
    source_excerpt = finding_source_excerpt(scan, target, locations)
    if source_excerpt:
        result["sourceExcerpt"] = source_excerpt
    artifact_paths = finding_artifact_paths(Path(scan["scan_dir"]), details)
    result["artifactPaths"] = artifact_paths
    return result


def finding_artifact_paths(scan_dir: Path, details: dict[str, Any]) -> list[str]:
    writeup = details.get("writeup")
    if not isinstance(writeup, dict):
        return []
    report_path = writeup.get("reportPath")
    if (
        not isinstance(report_path, str)
        or FINDING_WRITEUP_REPORT_PATH.fullmatch(report_path) is None
    ):
        return []
    report_relative = PurePosixPath(report_path)
    artifacts = []
    if scan_local_regular_file(scan_dir, report_path):
        artifacts.append(report_path)

    poc_relative = report_relative.parent / "poc"
    poc_root = scan_dir.joinpath(*poc_relative.parts)
    try:
        if not stat.S_ISDIR(poc_root.stat(follow_symlinks=False).st_mode):
            return artifacts
    except OSError:
        return artifacts

    directories_seen = 0
    for current_directory, directory_names, file_names in os.walk(
        poc_root, topdown=True, followlinks=False
    ):
        directories_seen += 1
        if directories_seen > FINDING_ARTIFACT_DIRECTORIES_LIMIT:
            directory_names[:] = []
            break
        current_path = Path(current_directory)
        directory_names[:] = [
            name for name in sorted(directory_names) if not (current_path / name).is_symlink()
        ]
        for file_name in sorted(file_names):
            candidate = current_path / file_name
            try:
                relative_path = candidate.relative_to(scan_dir).as_posix()
            except ValueError:
                continue
            if not scan_local_regular_file(scan_dir, relative_path):
                continue
            artifacts.append(relative_path)
            if len(artifacts) >= FINDING_ARTIFACTS_LIMIT:
                return artifacts
    return artifacts


def scan_local_regular_file(scan_dir: Path, relative_path: str) -> bool:
    if len(relative_path.encode("utf-8")) > FINDING_LOCATION_PATH_BYTES:
        return False
    try:
        descriptor = open_scan_local_file_descriptor(
            scan_dir,
            relative_path,
            f"finding artifact {relative_path}",
        )
    except (ContractError, OSError):
        return False
    try:
        return stat.S_ISREG(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)


def read_finding_details(value: str) -> dict[str, Any]:
    try:
        details = _loads_json(value)
    except (TypeError, ValueError):
        return {}
    return details if isinstance(details, dict) else {}


def finding_management_updated_at(connection: sqlite3.Connection, scan_id: str) -> str | None:
    return connection.execute(
        """
        SELECT MAX(updated_at)
        FROM (
            SELECT triage.updated_at
            FROM finding_triage AS triage
            JOIN finding_occurrences AS occurrences ON occurrences.id = triage.occurrence_id
            WHERE occurrences.scan_id = ?
            UNION ALL
            SELECT remediation.updated_at
            FROM finding_remediation_attempts AS remediation
            JOIN finding_occurrences AS occurrences ON occurrences.id = remediation.occurrence_id
            WHERE occurrences.scan_id = ?
        )
        """,
        (scan_id, scan_id),
    ).fetchone()[0]


def scan_finding_triage(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    indexed_findings: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        row["id"]: finding_triage_result(connection, row["id"], indexed_findings.get(row["id"]))
        for row in connection.execute(
            "SELECT id FROM finding_occurrences WHERE scan_id = ?", (scan["id"],)
        )
    }


def finding_triage_result(
    connection: sqlite3.Connection,
    occurrence_id: str,
    indexed_finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    decision_id = indexed_finding["decision_occurrence_id"] if indexed_finding is not None else None
    row = connection.execute(
        "SELECT status, close_reason, note, updated_at FROM finding_triage WHERE occurrence_id = ?",
        (decision_id or occurrence_id,),
    ).fetchone()
    triage = (
        {
            "closeReason": row["close_reason"],
            "note": row["note"],
            "status": row["status"],
            "updatedAt": row["updated_at"],
        }
        if row is not None
        else {"status": "open"}
    )
    if indexed_finding is not None and triage["status"] != indexed_finding["status"]:
        return {"status": indexed_finding["status"]}
    return triage


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
