"""Prepare and cache embeddings without publishing findings to an HTTP service."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_finding_index import upsert_finding
from workbench_target_state import stable_target_id


def cache_key(space: str, document: str) -> str:
    return hashlib.sha256(f"{space}\0{document}".encode()).hexdigest()


def local_dedupe(
    connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    action = payload["action"]
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if action == "prepare":
                return prepare(connection, payload, timestamp)
            if action == "embed":
                for entry in payload["entries"]:
                    row = connection.execute(
                        "SELECT details_json FROM findings WHERE id = ?", (entry["findingId"],)
                    ).fetchone()
                    if (
                        row is None
                        or cache_key(payload["space"], row["details_json"]) != entry["cacheKey"]
                    ):
                        raise ValueError("finding_changed")
                    embedding = entry["embedding"]
                    vector = embedding["vector"]
                    if (
                        embedding["model"] != payload["model"]
                        or len(vector) != payload["dimensions"]
                        or not all(isinstance(v, (int, float)) and math.isfinite(v) for v in vector)
                        or not math.isfinite(math.hypot(*vector))
                        or math.hypot(*vector) == 0
                    ):
                        raise ValueError("embedding_failed")
                    connection.execute(
                        "INSERT INTO local_finding_embeddings (finding_id, model, vector_json, cache_key) "
                        "VALUES (?, ?, ?, ?) ON CONFLICT(finding_id) DO UPDATE SET "
                        "model = excluded.model, vector_json = excluded.vector_json, "
                        "cache_key = excluded.cache_key",
                        (
                            entry["findingId"],
                            embedding["model"],
                            json.dumps(vector, allow_nan=False),
                            entry["cacheKey"],
                        ),
                    )
                return {}
            raise ValueError("invalid_request")
    except sqlite3.IntegrityError:
        return {"error": "finding_conflict"}
    except ValueError as exc:
        return {"error": str(exc)}


def prepare(
    connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    # Artifact seals establish consistency, not permission to select another local corpus.
    target = Path(payload["repositoryPath"]).resolve()
    registered = connection.execute(
        "SELECT id FROM security_targets WHERE current_path = ?", (str(target),)
    ).fetchone()
    target_id = registered["id"] if registered is not None else stable_target_id(target)
    if (
        payload["anchorRepositoryId"] != target_id
        or payload.get("repositoryId", target_id) != target_id
    ):
        raise ValueError("target_mismatch")
    if not payload["findings"]:
        return {"cacheKeys": {}, "findingsToEmbed": []}
    # A sealed historical scan selects logical IDs; never overwrite their current bodies.
    for finding in payload["findings"]:
        existing = connection.execute(
            "SELECT fingerprint, rule_id, identity_anchor, identity_instance, details_json "
            "FROM findings WHERE id = ?",
            (finding["findingId"],),
        ).fetchone()
        identity = (
            finding["fingerprints"]["primary"],
            finding["ruleId"],
            finding["identity"]["anchor"],
            finding["identity"].get("instance"),
        )
        if existing is not None and tuple(existing)[:4] != identity:
            raise sqlite3.IntegrityError("Conflicting finding identity")
        if existing is None or existing["details_json"] is None:
            upsert_finding(connection, finding, timestamp, payload["anchorRepositoryId"])
        else:
            connection.execute(
                "INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id) VALUES (?, ?)",
                (payload["anchorRepositoryId"], finding["findingId"]),
            )
    repository_id = payload.get("repositoryId")
    rows = connection.execute(
        "SELECT findings.id, findings.details_json, embeddings.cache_key FROM findings "
        "LEFT JOIN local_finding_embeddings AS embeddings ON findings.id = embeddings.finding_id "
        + (
            "WHERE EXISTS (SELECT 1 FROM finding_repositories WHERE finding_id = findings.id "
            "AND repository_id = ?) "
            if repository_id is not None
            else ""
        )
        + "ORDER BY findings.created_at, findings.id",
        (repository_id,) if repository_id is not None else (),
    )
    cache_keys = {}
    findings_to_embed = []
    for row in rows:
        if row["details_json"] is None:
            raise ValueError("finding_not_indexed")
        key = cache_key(payload["space"], row["details_json"])
        cache_keys[row["id"]] = key
        if key != row["cache_key"]:
            findings_to_embed.append(json.loads(row["details_json"]))
    return {"cacheKeys": cache_keys, "findingsToEmbed": findings_to_embed}


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
