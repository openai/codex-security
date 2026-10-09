"""Validate, record, and export findings from sealed scans."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    SealedArtifactError,
    build_threat_model_export,
    csv_cell,
    finalize_scan,
    finding_candidate_id,
    finding_csv_columns,
    write_export_output,
    write_sarif_projection,
)
from validate_scan_contract import validate_contract


def destination_key(destination: Any) -> str:
    if not isinstance(destination, dict):
        raise SystemExit("Finding issues require an exact tracker destination.")
    kind = destination.get("type")
    if kind == "linear":
        required, optional = {"type", "teamId"}, {"projectId"}
        parts = [kind, destination.get("teamId"), destination.get("projectId")]
    elif kind == "jira":
        required, optional = {"type", "cloudId", "projectId"}, set()
        parts = [kind, destination.get("cloudId"), destination.get("projectId")]
    elif kind in {"github-issue", "github-advisory"}:
        required, optional = {"type", "hostname", "repository"}, set()
        parts = [kind, destination.get("hostname"), destination.get("repository")]
    else:
        raise SystemExit("Unsupported finding issue destination.")
    if not required.issubset(destination) or not set(destination).issubset(required | optional):
        raise SystemExit("Finding issues require the exact provider destination fields.")
    if any(not isinstance(value, str) or not value.strip() for value in destination.values()):
        raise SystemExit("Finding issue destination fields must be nonempty strings.")
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":"))


def verify_publication_history(
    db: Any,
    connection: sqlite3.Connection,
    scan_id: str,
    scan_directory: str,
    findings: list[dict[str, Any]],
) -> None:
    try:
        scan = db.require_scan(connection, scan_id)
    except SystemExit as exc:
        raise SystemExit(
            "The completed scan is not present in the local Codex Security scan-history database. "
            "Use the state directory where the scan was completed."
        ) from exc
    if scan["id"] != scan_id:
        raise SystemExit("Publication must use the exact completed scan identifier.")
    if scan["status"] != "complete":
        raise SystemExit("Only completed scans can publish findings to Linear.")
    requested_directory = db.require_canonical_scan_directory(Path(scan_directory))
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
            "SELECT id, finding_id FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        )
    }
    expected = {finding["occurrenceId"]: finding["findingId"] for finding in findings}
    if stored_findings != expected:
        raise SystemExit(
            "The completed scan findings do not exactly match local Codex Security scan history."
        )


def issue_receipt(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "scanId": row["scan_id"],
        "findingId": row["finding_id"],
        "occurrenceId": row["occurrence_id"],
        "issueIdentifier": row["external_id"],
        "operation": row["operation"],
        **({"url": row["external_url"]} if row["external_url"] is not None else {}),
        **({"readback": json.loads(row["readback_json"])} if row["readback_json"] else {}),
    }


def inspect_issue_receipts(
    connection: sqlite3.Connection,
    destination: dict[str, str],
    key: str,
    finding_ids: list[str],
) -> list[dict[str, Any]]:
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    selection = json.dumps(finding_ids)
    if "finding_issue_receipts" in tables:
        rows = connection.execute(
            "SELECT * FROM finding_issue_receipts WHERE destination_key = ? "
            "AND finding_id IN (SELECT value FROM json_each(?)) ORDER BY id",
            (key, selection),
        )
    elif "finding_publications" in tables and destination["type"] == "linear":
        rows = connection.execute(
            "SELECT *, 'create' AS operation, NULL AS readback_json FROM finding_publications "
            "WHERE destination_type = 'linear' AND team_id = ? AND project_id IS ? "
            "AND finding_id IN (SELECT value FROM json_each(?)) ORDER BY id",
            (destination["teamId"], destination.get("projectId"), selection),
        )
    else:
        return []
    return [issue_receipt(row) for row in rows]


def validate_issue_receipts(receipts: Any, selected: dict[str, str]) -> list[dict[str, Any]]:
    if not isinstance(receipts, list):
        raise SystemExit("Finding issue receipts must be an array.")
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise SystemExit("Each finding issue receipt must be an object.")
        if any(
            not isinstance(receipt.get(field), str) or not receipt[field].strip()
            for field in ("findingId", "occurrenceId", "issueIdentifier")
        ):
            raise SystemExit("A finding issue receipt is missing its source or issue identity.")
        if selected.get(receipt["findingId"]) != receipt["occurrenceId"]:
            raise SystemExit(
                "A finding issue receipt does not belong to the selected sealed findings."
            )
        if receipt.get("operation") not in {"create", "update", "reuse"}:
            raise SystemExit("A finding issue receipt requires create, update, or reuse.")
        if "url" in receipt and (not isinstance(receipt["url"], str) or not receipt["url"].strip()):
            raise SystemExit("A finding issue URL must be a nonempty string when supplied.")
        if "readback" in receipt:
            readback = receipt["readback"]
            if (
                not isinstance(readback, dict)
                or readback.get("status") not in {"verified", "failed"}
                or ("error" in readback and not isinstance(readback["error"], str))
            ):
                raise SystemExit("A finding issue readback requires verified or failed status.")
    return receipts


def finding_issues(db: Any, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("action") not in {
        "inspect",
        "prepare",
        "record",
    }:
        raise SystemExit("Finding issues require inspect, prepare, or record action.")
    if not isinstance(payload.get("scanDirectory"), str):
        raise SystemExit("Finding issues require a sealed scan directory.")
    require_history = payload.get("requireHistory", False)
    if not isinstance(require_history, bool):
        raise SystemExit("requireHistory must be a boolean.")
    key = destination_key(payload.get("destination"))
    try:
        validated = validate_contract(Path(payload["scanDirectory"]))
    except (OSError, ValueError, RecursionError) as exc:
        raise SystemExit(f"Finding issue source validation failed: {exc}") from exc
    scan_id = validated["manifest"]["scan"]["id"]
    if "expectedScanId" in payload and payload["expectedScanId"] != scan_id:
        raise SystemExit("Scan artifacts do not match the selected scan identifier.")
    findings = validated["findings"]["findings"]
    available = {finding["findingId"]: finding["occurrenceId"] for finding in findings}
    finding_ids = payload.get("findingIds", list(available))
    if not isinstance(finding_ids, list) or any(
        not isinstance(finding_id, str) or finding_id not in available for finding_id in finding_ids
    ):
        raise SystemExit("Selected finding IDs must belong to the sealed scan.")
    selected = {finding_id: available[finding_id] for finding_id in finding_ids}
    receipts = (
        validate_issue_receipts(payload.get("receipts"), selected)
        if payload["action"] == "record"
        else []
    )
    result = {
        "scanId": scan_id,
        "destination": payload["destination"],
        "findingCount": len(selected),
        "storeExists": True,
        "receipts": [],
    }
    path = db.database_path()
    if payload["action"] == "inspect" or require_history:
        try:
            path.stat()
        except FileNotFoundError:
            if require_history:
                raise SystemExit(
                    "Cannot publish findings because the local Codex Security scan-history database "
                    "does not exist. Use the state directory where this scan was completed."
                ) from None
            result["storeExists"] = False
            return result
        except PermissionError:
            pass  # Let SQLite report the open failure used by the host's state fallback.
    if payload["action"] == "inspect":
        database_uri = f"file:{quote(str(path), safe='')}?mode=ro"
        try:
            connection = sqlite3.connect(database_uri, uri=True, timeout=5)
        except sqlite3.OperationalError as exc:
            if str(exc) == "unable to open database file":
                exc._codex_security_state_unavailable = True
            raise
        connection.row_factory = sqlite3.Row
    else:
        connection = db.connect()
    with closing(connection):
        connection.execute("BEGIN" if payload["action"] == "inspect" else "BEGIN IMMEDIATE")
        with connection:
            if require_history:
                verify_publication_history(db, connection, scan_id, validated["scanDir"], findings)
            if payload["action"] == "inspect":
                result["receipts"] = inspect_issue_receipts(
                    connection, payload["destination"], key, list(selected)
                )
            elif payload["action"] == "record":
                timestamp = db.now()
                for receipt in receipts:
                    conflicting = connection.execute(
                        "SELECT 1 FROM finding_issue_receipts "
                        "WHERE destination_key = ? AND external_id = ? AND finding_id != ? LIMIT 1",
                        (key, receipt["issueIdentifier"], receipt["findingId"]),
                    ).fetchone()
                    if conflicting is not None:
                        raise SystemExit(
                            "The issue identifier is already associated with another finding "
                            "in this destination."
                        )
                    readback = (
                        json.dumps(receipt["readback"], ensure_ascii=False)
                        if "readback" in receipt
                        else None
                    )
                    connection.execute(
                        """
                        INSERT INTO finding_issue_receipts (
                            scan_id, finding_id, occurrence_id, destination_key,
                            external_id, external_url, operation, readback_json, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (occurrence_id, destination_key, external_id, operation)
                        DO UPDATE SET
                            external_url = COALESCE(excluded.external_url, external_url),
                            readback_json = COALESCE(excluded.readback_json, readback_json),
                            updated_at = excluded.updated_at
                        """,
                        (
                            scan_id,
                            receipt["findingId"],
                            receipt["occurrenceId"],
                            key,
                            receipt["issueIdentifier"],
                            receipt.get("url"),
                            receipt["operation"],
                            readback,
                            timestamp,
                            timestamp,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM finding_issue_receipts WHERE occurrence_id = ? "
                        "AND destination_key = ? AND external_id = ? AND operation = ?",
                        (
                            receipt["occurrenceId"],
                            key,
                            receipt["issueIdentifier"],
                            receipt["operation"],
                        ),
                    ).fetchone()
                    result["receipts"].append(issue_receipt(row))
    return result


def export_findings(
    db: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    scan = db.require_scan(connection, args.scan_id)
    artifact = getattr(args, "artifact", "findings")
    args.format = args.format or ("md" if artifact == "threat-model" else "csv")
    if artifact == "threat-model":
        if args.format != "md":
            raise SystemExit("Threat models can only be exported as Markdown (md).")
    else:
        if args.format == "md":
            raise SystemExit("Markdown export requires --artifact threat-model.")
        if scan["status"] != "complete" and not (
            scan["status"] == "failed" and scan["seal_manifest_digest"]
        ):
            raise SystemExit(
                "Findings can be exported after the scan completes or preserves stopped results."
            )
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    manifest_path = scan_dir / db.ARTIFACTS["manifest"]
    db.verify_manifest_binding(scan, db.read_json_object(manifest_path))
    if getattr(args, "validate_only", False):
        # SDK/CLI exports use their requested destination without modifying saved artifacts.
        return {"scan": {"scanId": scan["id"], "scanDir": str(scan_dir)}}
    if artifact == "threat-model":
        path = scan_dir / "exports" / "threatmodel.md"
        try:
            contents = build_threat_model_export(scan_dir)
            write_export_output(scan_dir, path, "md", contents)
        except ContractError as exc:
            raise SystemExit(str(exc)) from exc
        return {
            "export": {"artifact": artifact, "format": "md", "path": str(path)},
            "scan": db.scan_result(connection, scan),
            "workspace": db.workspace_state(connection, scan["workspace_id"]),
        }
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
    db: Any,
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
    columns = finding_csv_columns(deep_scan)
    writer.writerow(columns)
    for row in finding_export_rows(connection, scan["id"]):
        values = dict(row)
        values["path"] = row["relative_path"]
        values["candidate_id"] = candidate_ids_by_occurrence.get(row["occurrence_id"])
        writer.writerow(csv_cell(values[column]) for column in columns)
    destination = scan_dir / "exports" / "findings.csv"
    try:
        write_export_output(
            scan_dir,
            destination,
            "csv",
            output.getvalue().encode("utf-8"),
        )
    except SealedArtifactError as exc:
        raise SystemExit(str(exc)) from exc
    except ContractError as exc:
        raise SystemExit(
            "exports: expected a regular directory inside the scan directory."
        ) from exc
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
