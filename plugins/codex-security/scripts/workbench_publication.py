"""Validate, record, and export findings from completed scans."""

from __future__ import annotations

import argparse
import csv
import io
import os
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from finalize_scan_contract import (
    ContractError,
    csv_cell,
    finalize_scan,
    finding_candidate_id,
    write_sarif_projection,
    write_scan_local_bytes,
)


@dataclass(frozen=True)
class WorkbenchPublicationContext:
    ARTIFACTS: dict[str, str]
    artifact_path: Callable[..., Path | None]
    available_artifact_path: Callable[[Path, Path], Path | None]
    database_path: Callable[[], Path]
    expected_coverage_mode: Callable[[sqlite3.Row], str]
    now: Callable[[], str]
    pin_legacy_manifest_digest: Callable[[sqlite3.Connection, str, str], None]
    published_manifest_digest: Callable[[Path, dict[str, Any]], str]
    read_json_object: Callable[[Path], dict[str, Any]]
    require_canonical_scan_directory: Callable[[Path], Path]
    require_recorded_manifest_digest: Callable[[sqlite3.Row, Path], str]
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row]
    scan_result: Callable[[sqlite3.Connection, sqlite3.Row], dict[str, Any]]
    verify_manifest_binding: Callable[[sqlite3.Row, dict[str, Any]], None]
    workspace_state: Callable[[sqlite3.Connection, str], dict[str, Any]]


def linear_publication_input(
    db: WorkbenchPublicationContext,
    args: argparse.Namespace,
    *,
    recording: bool,
) -> tuple[dict[str, Any], dict[str, str], list[dict[str, str]]]:
    payload = db.read_json_object(Path(args.input_file))
    required = {"scanId", "scanDirectory", "destination", "findings"}
    if recording:
        required.add("publications")
    if set(payload) != required:
        raise SystemExit("Linear publication input contains unexpected or missing fields.")

    scan_id = payload["scanId"]
    scan_directory = payload["scanDirectory"]
    destination = payload["destination"]
    findings = payload["findings"]
    if not isinstance(scan_id, str) or not isinstance(scan_directory, str):
        raise SystemExit("Linear publication input must identify the exact completed scan.")
    if (
        not isinstance(destination, dict)
        or not {"type", "teamId"}.issubset(destination)
        or not set(destination).issubset({"type", "teamId", "projectId"})
        or destination.get("type") != "linear"
        or not isinstance(destination.get("teamId"), str)
        or not destination["teamId"].strip()
        or (
            "projectId" in destination
            and (
                not isinstance(destination["projectId"], str)
                or not destination["projectId"].strip()
            )
        )
    ):
        raise SystemExit(
            "Linear publication input must identify the exact team and optional project."
        )
    if not isinstance(findings, list):
        raise SystemExit("Linear publication input must include the planned scan findings.")

    seen_finding_ids: set[str] = set()
    seen_occurrence_ids: set[str] = set()
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {"findingId", "occurrenceId"}
            or not isinstance(finding.get("findingId"), str)
            or not finding["findingId"].strip()
            or not isinstance(finding.get("occurrenceId"), str)
            or not finding["occurrenceId"].strip()
        ):
            raise SystemExit("Linear publication input contains an invalid finding identity.")
        if (
            finding["findingId"] in seen_finding_ids
            or finding["occurrenceId"] in seen_occurrence_ids
        ):
            raise SystemExit("Linear publication input repeats a finding or occurrence.")
        seen_finding_ids.add(finding["findingId"])
        seen_occurrence_ids.add(finding["occurrenceId"])

    return payload, destination, findings


def verify_linear_publication_scan(
    db: WorkbenchPublicationContext,
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    findings: list[dict[str, str]],
) -> sqlite3.Row:
    try:
        scan = db.require_scan(connection, payload["scanId"])
    except SystemExit as exc:
        raise SystemExit(
            "The completed scan is not present in the local Codex Security scan-history database. "
            "Use the state directory where the scan was completed."
        ) from exc
    if scan["id"] != payload["scanId"]:
        raise SystemExit("Linear publication must use the exact completed scan identifier.")
    if scan["status"] != "complete":
        raise SystemExit("Only completed scans can publish findings to Linear.")

    requested_directory = db.require_canonical_scan_directory(Path(payload["scanDirectory"]))
    recorded_directory = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    if os.path.normcase(requested_directory) != os.path.normcase(recorded_directory):
        raise SystemExit(
            "The selected scan directory does not match its local Codex Security scan history."
        )
    if "seal_manifest_digest" in scan.keys():
        db.require_recorded_manifest_digest(scan, recorded_directory)

    stored_findings = {
        row["id"]: row["finding_id"]
        for row in connection.execute(
            "SELECT id, finding_id FROM finding_occurrences WHERE scan_id = ?",
            (scan["id"],),
        )
    }
    for finding in findings:
        if stored_findings.get(finding["occurrenceId"]) != finding["findingId"]:
            raise SystemExit(
                "A selected finding or occurrence does not belong to the completed scan "
                "in local Codex Security scan history."
            )
    if len(stored_findings) != len(findings):
        raise SystemExit(
            "The completed scan findings do not exactly match local Codex Security scan history."
        )
    return scan


def inspect_linear_publication(
    db: WorkbenchPublicationContext,
    args: argparse.Namespace,
) -> dict[str, Any]:
    payload, destination, findings = linear_publication_input(db, args, recording=False)
    database_uri = f"file:{quote(str(db.database_path()), safe='')}?mode=ro"
    with closing(sqlite3.connect(database_uri, uri=True, timeout=5)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        scan = verify_linear_publication_scan(db, connection, payload, findings)
        recorded: dict[str, dict[str, str]] = {}
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'finding_publications'"
        ).fetchone():
            for row in connection.execute(
                """
                SELECT finding_id, occurrence_id, external_id, external_url
                FROM finding_publications
                WHERE scan_id = ? AND destination_type = ? AND team_id = ? AND project_id IS ?
                ORDER BY created_at, external_id
                """,
                (
                    scan["id"],
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                ),
            ):
                recorded.setdefault(
                    row["occurrence_id"],
                    {
                        "findingId": row["finding_id"],
                        "occurrenceId": row["occurrence_id"],
                        "issueIdentifier": row["external_id"],
                        **({"url": row["external_url"]} if row["external_url"] is not None else {}),
                    },
                )
        return {
            "scanId": scan["id"],
            "destination": destination,
            "findingCount": len(findings),
            "recorded": [
                recorded[finding["occurrenceId"]]
                for finding in findings
                if finding["occurrenceId"] in recorded
            ],
        }


def prepare_linear_publication(
    db: WorkbenchPublicationContext,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    payload, destination, findings = linear_publication_input(db, args, recording=False)
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = verify_linear_publication_scan(db, connection, payload, findings)
        result = {
            "scanId": scan["id"],
            "destination": destination,
            "findingCount": len(findings),
        }
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def record_linear_publications(
    db: WorkbenchPublicationContext,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    payload, destination, findings = linear_publication_input(db, args, recording=True)
    publications = payload["publications"]
    if not isinstance(publications, list):
        raise SystemExit("Linear publication results must be an array.")
    planned = {finding["findingId"]: finding["occurrenceId"] for finding in findings}
    current: dict[str, dict[str, str]] = {}
    external_ids: set[str] = set()
    for publication in publications:
        if (
            not isinstance(publication, dict)
            or not {"findingId", "occurrenceId", "issueIdentifier"}.issubset(publication)
            or not set(publication).issubset(
                {"findingId", "occurrenceId", "issueIdentifier", "url"}
            )
            or not isinstance(publication.get("findingId"), str)
            or not isinstance(publication.get("occurrenceId"), str)
            or not isinstance(publication.get("issueIdentifier"), str)
            or not publication["issueIdentifier"].strip()
            or (
                "url" in publication
                and (not isinstance(publication["url"], str) or not publication["url"].strip())
            )
        ):
            raise SystemExit("Linear publication results contain an invalid issue association.")
        finding_id = publication["findingId"]
        issue_identifier = publication["issueIdentifier"]
        if planned.get(finding_id) != publication["occurrenceId"]:
            raise SystemExit(
                "A created Linear issue does not match its planned finding and occurrence."
            )
        if finding_id in current or issue_identifier in external_ids:
            raise SystemExit("Linear publication results repeat a finding or issue identifier.")
        current[finding_id] = publication
        external_ids.add(issue_identifier)

    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = verify_linear_publication_scan(db, connection, payload, findings)
        timestamp = db.now()
        for publication in publications:
            conflicting = connection.execute(
                """
                SELECT occurrence_id, external_url
                FROM finding_publications
                WHERE destination_type = ? AND team_id = ? AND project_id IS ?
                    AND external_id = ?
                """,
                (
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                    publication["issueIdentifier"],
                ),
            ).fetchone()
            if (
                conflicting is not None
                and conflicting["occurrence_id"] != publication["occurrenceId"]
            ):
                raise SystemExit(
                    "This Linear issue is already associated with a different finding."
                )
            if (
                conflicting is not None
                and "url" in publication
                and conflicting["external_url"] != publication["url"]
            ):
                raise SystemExit("This Linear issue is already associated with a different URL.")

            connection.execute(
                """
                INSERT INTO finding_publications (
                    scan_id, finding_id, occurrence_id, destination_type,
                    team_id, project_id, external_id, external_url, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    scan["id"],
                    publication["findingId"],
                    publication["occurrenceId"],
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                    publication["issueIdentifier"],
                    publication.get("url"),
                    timestamp,
                ),
            )

        created = []
        for finding in findings:
            publication = current.get(finding["findingId"])
            if publication is None:
                continue
            row = connection.execute(
                """
                SELECT finding_id, occurrence_id, external_id, external_url
                FROM finding_publications
                WHERE scan_id = ? AND occurrence_id = ? AND destination_type = ?
                    AND team_id = ? AND project_id IS ? AND external_id = ?
                """,
                (
                    scan["id"],
                    publication["occurrenceId"],
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                    publication["issueIdentifier"],
                ),
            ).fetchone()
            if row is None:
                raise SystemExit("A created Linear issue could not be read from scan history.")
            created.append(
                {
                    "findingId": row["finding_id"],
                    "occurrenceId": row["occurrence_id"],
                    "issueIdentifier": row["external_id"],
                    **({"url": row["external_url"]} if row["external_url"] is not None else {}),
                }
            )
        result = {"scanId": scan["id"], "destination": destination, "created": created}
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def export_findings(
    db: WorkbenchPublicationContext,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    scan = db.require_scan(connection, args.scan_id)
    if scan["status"] != "complete" and not (
        scan["status"] == "failed" and scan["seal_manifest_digest"]
    ):
        raise SystemExit(
            "Findings can be exported after the scan completes or preserves stopped results."
        )
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    db.verify_manifest_binding(scan, db.read_json_object(scan_dir / db.ARTIFACTS["manifest"]))
    try:
        manifest, _, _ = finalize_scan(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
        )
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    db.verify_manifest_binding(scan, manifest)
    manifest_digest = db.published_manifest_digest(scan_dir, manifest)
    db.pin_legacy_manifest_digest(connection, scan["id"], manifest_digest)
    if args.format == "json":
        path = db.artifact_path(scan_dir, db.ARTIFACTS["findings"], required=True)
    elif args.format == "sarif":
        try:
            write_sarif_projection(scan_dir)
        except ContractError as exc:
            raise SystemExit(str(exc)) from exc
        path = db.artifact_path(scan_dir, "exports/results.sarif", required=True)
    else:
        path = write_csv_export(db, connection, scan)
    if path is None:
        raise SystemExit(f"Could not export Codex Security findings as {args.format.upper()}.")
    return {
        "export": {"format": args.format, "path": str(path)},
        "scan": db.scan_result(connection, scan),
        "workspace": db.workspace_state(connection, scan["workspace_id"]),
    }


def write_csv_export(
    db: WorkbenchPublicationContext,
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
) -> Path:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    deep_scan = scan["mode"] == "deep"
    candidate_ids_by_occurrence: dict[str, str] = {}
    if deep_scan:
        findings_document = db.read_json_object(scan_dir / db.ARTIFACTS["findings"])
        findings = findings_document.get("findings")
        if not isinstance(findings, list):
            raise SystemExit("findings.json must contain a findings array.")
        for finding in findings:
            if not isinstance(finding, dict):
                raise SystemExit("findings.json entries must be objects.")
            occurrence_id = finding.get("occurrenceId")
            candidate_id = finding_candidate_id(finding)
            if isinstance(occurrence_id, str) and isinstance(candidate_id, str):
                candidate_ids_by_occurrence[occurrence_id] = candidate_id
    columns = (
        "occurrence_id",
        "finding_id",
        *(("candidate_id",) if deep_scan else ()),
        "title",
        "summary",
        "severity",
        "confidence",
        "status",
        "close_reason",
        "note",
        "remediation",
        "path",
        "start_line",
        "end_line",
    )
    writer.writerow(columns)
    for row in finding_export_rows(connection, scan["id"]):
        writer.writerow(
            (
                csv_cell(row["occurrence_id"]),
                csv_cell(row["finding_id"]),
                *(
                    (csv_cell(candidate_ids_by_occurrence.get(row["occurrence_id"])),)
                    if deep_scan
                    else ()
                ),
                csv_cell(row["title"]),
                csv_cell(row["summary"]),
                csv_cell(row["severity"]),
                csv_cell(row["confidence"]),
                csv_cell(row["status"]),
                csv_cell(row["close_reason"]),
                csv_cell(row["note"]),
                csv_cell(row["remediation"]),
                csv_cell(row["relative_path"]),
                row["start_line"],
                row["end_line"],
            )
        )
    try:
        write_scan_local_bytes(
            scan_dir,
            "exports/findings.csv",
            output.getvalue().encode("utf-8"),
        )
    except ContractError as exc:
        raise SystemExit(
            "exports: expected a regular directory inside the scan directory."
        ) from exc
    destination = scan_dir / "exports" / "findings.csv"
    path = db.available_artifact_path(scan_dir, destination)
    if path is None:
        raise SystemExit("findings.csv: expected a regular file inside the scan directory.")
    return path


def finding_export_rows(connection: sqlite3.Connection, scan_id: str) -> sqlite3.Cursor:
    return connection.execute(
        """
        SELECT
            occurrences.id AS occurrence_id,
            occurrences.finding_id,
            occurrences.title,
            occurrences.summary,
            occurrences.severity,
            occurrences.confidence,
            occurrences.remediation,
            COALESCE(triage.status, 'open') AS status,
            triage.close_reason,
            triage.note,
            locations.relative_path,
            locations.start_line,
            locations.end_line
        FROM finding_occurrences AS occurrences
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        LEFT JOIN finding_locations AS locations
            ON locations.occurrence_id = occurrences.id
            AND locations.sort_order = (
                SELECT primary_location.sort_order
                FROM finding_locations AS primary_location
                WHERE primary_location.occurrence_id = occurrences.id
                ORDER BY
                    CASE WHEN primary_location.role = 'root_control' THEN 0 ELSE 1 END,
                    primary_location.sort_order
                LIMIT 1
            )
        WHERE occurrences.scan_id = ?
        ORDER BY occurrences.created_at, occurrences.id
        """,
        (scan_id,),
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
