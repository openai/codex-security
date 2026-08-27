"""Persist normalized scan findings and their occurrences."""

from __future__ import annotations

import argparse
import json
import sqlite3
from typing import Any


def index_findings(
    connection: sqlite3.Connection,
    scan_id: str,
    document: dict[str, Any],
    timestamp: str,
) -> None:
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise SystemExit("findings.json must contain a findings array.")
    for finding in findings:
        if not isinstance(finding, dict):
            raise SystemExit("findings.json entries must be objects.")
        identity = finding["identity"]
        fingerprints = finding["fingerprints"]
        severity = finding["severity"]
        confidence = finding["confidence"]
        connection.execute(
            """
            INSERT INTO findings (
                id, fingerprint, rule_id, identity_anchor, identity_instance, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                fingerprint = excluded.fingerprint,
                rule_id = excluded.rule_id,
                identity_anchor = excluded.identity_anchor,
                identity_instance = excluded.identity_instance,
                updated_at = excluded.updated_at
            """,
            (
                finding["findingId"],
                fingerprints["primary"],
                finding["ruleId"],
                identity["anchor"],
                identity.get("instance"),
                timestamp,
                timestamp,
            ),
        )
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
