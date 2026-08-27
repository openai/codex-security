"""Storage operations for complete findings imported without a scan."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_finding_index import upsert_finding


def store_findings(
    connection: sqlite3.Connection, entries: list[dict[str, Any]], timestamp: str
) -> dict[str, Any]:
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            for entry in entries:
                finding = entry["finding"]
                embedding = entry["embedding"]
                identity = (
                    finding["fingerprints"]["primary"],
                    finding["ruleId"],
                    finding["identity"]["anchor"],
                    finding["identity"].get("instance"),
                )
                current = connection.execute(
                    "SELECT fingerprint, rule_id, identity_anchor, identity_instance "
                    "FROM findings WHERE id = ?",
                    (finding["findingId"],),
                ).fetchone()
                if current is not None and tuple(current) != identity:
                    raise sqlite3.IntegrityError("The stored finding identity cannot be replaced.")
                upsert_finding(connection, finding, timestamp)
                connection.execute(
                    """
                    INSERT INTO finding_embeddings (finding_id, model, vector_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        model = excluded.model, vector_json = excluded.vector_json
                    """,
                    (
                        finding["findingId"],
                        embedding["model"],
                        json.dumps(embedding["vector"], allow_nan=False),
                    ),
                )
    except sqlite3.IntegrityError:
        return {"error": "finding_conflict"}
    return {"findingIds": [entry["finding"]["findingId"] for entry in entries]}


def list_stored_findings(
    connection: sqlite3.Connection, *, limit: int, offset: int
) -> dict[str, Any]:
    connection.execute("BEGIN")
    with connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM findings WHERE details_json IS NOT NULL"
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT details_json FROM findings WHERE details_json IS NOT NULL
            ORDER BY created_at, id LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    next_offset = offset + len(rows)
    return {
        "findings": [json.loads(row["details_json"]) for row in rows],
        "limit": limit,
        "offset": offset,
        "total": total,
        "nextOffset": next_offset if next_offset < total else None,
    }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
