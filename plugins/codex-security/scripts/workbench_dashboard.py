"""Read-only dashboard projections for stored findings and duplicate groups."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_findings import list_dedupe_groups


FINDING_RECORDS = """
SELECT findings.id, json_extract(details_json, '$.title') AS title,
    COALESCE(repositories.ids, '[]') AS repositoryIds,
    json_extract(details_json, '$.severity.level') AS severity,
    findings.created_at AS createdAt, findings.updated_at AS updatedAt
FROM findings LEFT JOIN (
    SELECT finding_id, json_group_array(repository_id) AS ids
    FROM finding_repositories GROUP BY finding_id
) AS repositories ON repositories.finding_id = findings.id
WHERE details_json IS NOT NULL
"""

GROUP_RECORDS = """
SELECT groups.id, groups.id AS title,
    (SELECT json_group_array(DISTINCT repository_id)
     FROM finding_dedupe_group_members AS members
     JOIN finding_repositories ON finding_repositories.finding_id = members.finding_id
     WHERE members.group_id = groups.id) AS repositoryIds,
    groups.created_at AS createdAt, groups.created_at AS updatedAt,
    (SELECT COUNT(*) FROM finding_dedupe_group_members WHERE group_id = groups.id) AS memberCount
FROM finding_dedupe_groups AS groups
"""

RECORDS = {
    "findings": FINDING_RECORDS,
    "groups": GROUP_RECORDS,
}


def item(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["repositoryIds"] = json.loads(result["repositoryIds"])
    return result


def detail(connection: sqlite3.Connection, view: str, selected: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"item": selected}
    selected_id = selected["id"]
    if view == "findings":
        result["finding"] = json.loads(connection.execute(
            "SELECT details_json FROM findings WHERE id = ?", (selected_id,),
        ).fetchone()[0])
        result["groups"] = list_dedupe_groups(connection, selected_id)["groups"]
    else:
        result["group"] = {
            "groupId": selected_id, "createdAt": selected["createdAt"],
            "findingIds": [r[0] for r in connection.execute(
                "SELECT finding_id FROM finding_dedupe_group_members WHERE group_id = ? ORDER BY finding_id",
                (selected_id,),
            )],
        }
    return result


def dashboard(connection: sqlite3.Connection, query: dict[str, Any]) -> dict[str, Any]:
    """One snapshot, no artifact reads, model calls, or writes."""
    view = query["view"]
    records = RECORDS[view]
    clauses: list[str] = []
    values: list[Any] = []
    if query.get("query"):
        connection.create_function("casefold", 1, str.casefold, deterministic=True)
        columns = ["id", "title", "repositoryIds"]
        clauses.append("(" + " OR ".join(f"instr(casefold(COALESCE({c}, '')), casefold(?)) > 0" for c in columns) + ")")
        values.extend([query["query"]] * len(columns))
    if query.get("repository"):
        clauses.append("EXISTS (SELECT 1 FROM json_each(repositoryIds) WHERE value = ?)")
        values.append(query["repository"])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    order = "createdAt DESC, id" if query["sort"] == "newest" else "updatedAt DESC, id"
    connection.execute("BEGIN")
    with connection:
        repositories = connection.execute("""
            SELECT DISTINCT repository_id AS id, repository_id AS label
            FROM finding_repositories ORDER BY repository_id
        """).fetchall()
        total = connection.execute(f"SELECT COUNT(*) FROM ({records}) {where}", values).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM ({records}) {where} ORDER BY {order} LIMIT ? OFFSET ?",
            (*values, query["limit"], query["offset"]),
        ).fetchall()
        selected = connection.execute(
            f"SELECT * FROM ({records}) WHERE id = ?", (query["id"],),
        ).fetchone() if query.get("id") else None
        next_offset = query["offset"] + len(rows)
        return {
            "overview": {
                "findings": connection.execute("SELECT COUNT(*) FROM findings WHERE details_json IS NOT NULL").fetchone()[0],
                "groups": connection.execute("SELECT COUNT(*) FROM finding_dedupe_groups").fetchone()[0],
            },
            "repositories": [dict(row) for row in repositories],
            "items": [item(row) for row in rows], "total": total,
            "limit": query["limit"], "offset": query["offset"],
            "nextOffset": next_offset if next_offset < total else None,
            "detail": detail(connection, view, item(selected)) if selected is not None else None,
        }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
