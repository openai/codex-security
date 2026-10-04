"""Small query fixtures backed by the actual workbench migrations."""

import sqlite3

from workbench_schema import MIGRATIONS, apply_migrations

STAMP = "2026-01-01T00:00:00Z"


def migrated_connection():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    apply_migrations(connection, MIGRATIONS, lambda: STAMP, lambda _: None)
    return connection


def seed(connection, table, columns, values, replace=False):
    values = dict(zip(columns, values, strict=True))
    defaults = {
        "security_targets": {
            "current_path": f"/synthetic/{values.get('id')}",
            "created_at": STAMP,
            "updated_at": STAMP,
            "display_name": "Fixture",
        },
        "workspaces": {"created_at": STAMP, "updated_at": STAMP},
        "scans": {
            "workspace_id": values.get("id"),
            "target_path": "/synthetic/repository",
            "target_revision": "synthetic",
            "scope": ".",
            "mode": "standard",
            "scan_dir": f"/synthetic/scans/{values.get('id')}",
            "status": "complete",
            "phase": "reporting",
            "started_at": STAMP,
            "created_at": STAMP,
            "updated_at": STAMP,
        },
        "findings": {
            "fingerprint": values.get("id"),
            "rule_id": "synthetic",
            "identity_anchor": "fixture",
            "created_at": STAMP,
            "updated_at": STAMP,
        },
        "finding_occurrences": {
            "title": "Fixture",
            "summary": "Synthetic evidence",
            "severity": "high",
            "confidence": "high",
            "remediation": "Fix",
            "created_at": STAMP,
        },
        "finding_locations": {"start_line": 1, "end_line": 1},
        "finding_triage": {"updated_at": STAMP},
        "scan_comparisons": {"result_json": "{}", "created_at": STAMP, "updated_at": STAMP},
        "scan_comparison_matches": {"reason": "Synthetic confirmed match"},
    }
    row = {**defaults.get(table, {}), **values}
    if table == "scans":
        seed(connection, "workspaces", ("id",), (row["workspace_id"],))
        if (
            row.get("target_id")
            and connection.execute(
                "SELECT 1 FROM security_targets WHERE id = ?", (row["target_id"],)
            ).fetchone()
            is None
        ):
            seed(connection, "security_targets", ("id",), (row["target_id"],))
    elif table == "finding_occurrences":
        if (
            connection.execute(
                "SELECT 1 FROM findings WHERE id = ?", (row["finding_id"],)
            ).fetchone()
            is None
        ):
            seed(connection, "findings", ("id",), (row["finding_id"],))
    elif table == "scan_comparison_matches":
        for side in ("before", "after"):
            row.setdefault(
                f"{side}_scan_id",
                connection.execute(
                    "SELECT scan_id FROM finding_occurrences WHERE id = ?",
                    (row[f"{side}_occurrence_id"],),
                ).fetchone()[0],
            )
        if (
            connection.execute(
                "SELECT 1 FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
                (row["before_scan_id"], row["after_scan_id"]),
            ).fetchone()
            is None
        ):
            seed(
                connection,
                "scan_comparisons",
                ("before_scan_id", "after_scan_id"),
                (row["before_scan_id"], row["after_scan_id"]),
            )
    connection.execute(
        f"INSERT {'OR REPLACE ' if replace else ''}INTO {table} ({', '.join(row)}) VALUES ({', '.join('?' for _ in row)})",
        tuple(row.values()),
    )


def seed_many(connection, table, columns, rows, replace=False):
    for values in rows:
        seed(connection, table, columns, values, replace)
