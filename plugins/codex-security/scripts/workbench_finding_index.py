"""Persist normalized scan findings and their occurrences."""

from __future__ import annotations

import argparse
import json
import sqlite3
from typing import Any


def upsert_finding(
    connection: sqlite3.Connection,
    finding: dict[str, Any],
    timestamp: str,
    repository_id: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO findings (
            id, fingerprint, rule_id, identity_anchor, identity_instance,
            details_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            fingerprint = excluded.fingerprint,
            rule_id = excluded.rule_id,
            identity_anchor = excluded.identity_anchor,
            identity_instance = excluded.identity_instance,
            details_json = excluded.details_json,
            updated_at = excluded.updated_at
        """,
        (
            finding["findingId"],
            finding["fingerprints"]["primary"],
            finding["ruleId"],
            finding["identity"]["anchor"],
            finding["identity"].get("instance"),
            json.dumps(finding, allow_nan=False, sort_keys=True),
            timestamp,
            timestamp,
        ),
    )
    if repository_id is not None:
        connection.execute(
            "INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id) VALUES (?, ?)",
            (repository_id, finding["findingId"]),
        )


def index_findings(
    connection: sqlite3.Connection,
    scan_id: str,
    document: dict[str, Any],
    timestamp: str,
) -> None:
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise SystemExit("findings.json must contain a findings array.")
    repository_id = connection.execute(
        "SELECT target_id FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()["target_id"]
    for finding in findings:
        if not isinstance(finding, dict):
            raise SystemExit("findings.json entries must be objects.")
        severity = finding["severity"]
        confidence = finding["confidence"]
        upsert_finding(connection, finding, timestamp, repository_id)
        connection.execute(
            """
            INSERT INTO finding_occurrences (
                id, finding_id, scan_id, title, summary, severity, confidence, remediation,
                details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                finding_id = excluded.finding_id,
                scan_id = excluded.scan_id,
                title = excluded.title,
                summary = excluded.summary,
                severity = excluded.severity,
                confidence = excluded.confidence,
                remediation = excluded.remediation,
                details_json = excluded.details_json
            """,
            (
                finding["occurrenceId"],
                finding["findingId"],
                scan_id,
                finding["title"],
                finding["summary"],
                severity["level"],
                confidence["level"],
                finding["remediation"],
                json.dumps(finding, allow_nan=False, sort_keys=True),
                timestamp,
            ),
        )
        connection.execute(
            "DELETE FROM finding_locations WHERE occurrence_id = ?",
            (finding["occurrenceId"],),
        )
        for index, location in enumerate(finding["locations"]):
            connection.execute(
                """
                INSERT INTO finding_locations (
                    occurrence_id, relative_path, start_line, end_line, role, sort_order
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    finding["occurrenceId"],
                    location["path"],
                    location["startLine"],
                    location.get("endLine", location["startLine"]),
                    location.get("role"),
                    index,
                ),
            )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
