"""Storage operations for complete findings imported without a scan."""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_finding_index import upsert_finding


def store_findings(
    connection: sqlite3.Connection,
    entries: list[dict[str, Any]],
    timestamp: str,
    repository_id: str | None = None,
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
                upsert_finding(connection, finding, timestamp, repository_id)
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


def find_potential_duplicates(
    connection: sqlite3.Connection, finding_id: str, repository_id: str | None
) -> dict[str, Any]:
    """Rank IDs and vectors in the requested scope before loading finding documents."""
    connection.execute("BEGIN")
    with connection:
        if repository_id is None:
            source = "finding_embeddings AS embeddings"
            predicate = ""
            scope_parameters: tuple[str, ...] = ()
        else:
            source = (
                "finding_repositories AS repositories JOIN finding_embeddings AS embeddings "
                "ON embeddings.finding_id = repositories.finding_id"
            )
            predicate = "repositories.repository_id = ? AND "
            scope_parameters = (repository_id,)
        anchor = connection.execute(
            f"SELECT embeddings.model, embeddings.vector_json FROM {source} "
            f"WHERE {predicate}embeddings.finding_id = ?",
            (*scope_parameters, finding_id),
        ).fetchone()
        if anchor is None:
            return {"error": "finding_not_indexed"}
        rows = connection.execute(
            f"SELECT embeddings.finding_id, embeddings.vector_json FROM {source} "
            "JOIN findings ON findings.id = embeddings.finding_id "
            f"WHERE {predicate}embeddings.model = ? AND embeddings.finding_id != ? "
            "ORDER BY findings.created_at, findings.id",
            (*scope_parameters, anchor["model"], finding_id),
        )
        ranked: list[tuple[str, float]] = []
        try:
            vector = normalized_vector(json.loads(anchor["vector_json"]))
            for row in rows:
                candidate = json.loads(row["vector_json"])
                if len(candidate) != len(vector):
                    continue
                other = normalized_vector(candidate)
                similarity = sum(left * right for left, right in zip(vector, other))
                if similarity >= 0.55:
                    ranked.append((row["finding_id"], similarity))
        except ValueError:
            return {"error": "embedding_failed"}
        # Stable sorting retains insertion-time / finding-ID order for ties.
        ranked.sort(key=lambda candidate: candidate[1], reverse=True)
        selected_ids = [finding_id, *(candidate[0] for candidate in ranked[:50])]
        documents = {
            row["id"]: json.loads(row["details_json"])
            for row in connection.execute(
                "SELECT id, details_json FROM findings WHERE id IN ("
                + ",".join("?" for _ in selected_ids)
                + ")",
                selected_ids,
            )
        }
        return {
            "finding": documents[finding_id],
            "potentialDuplicates": [documents[id] for id in selected_ids[1:]],
        }


def normalized_vector(vector: list[float]) -> list[float]:
    norm = math.hypot(*vector)
    if norm == 0 or not math.isfinite(norm):
        raise ValueError("A stored embedding cannot be compared.")
    return [value / norm for value in vector]


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
