"""Durable state for the opt-in local scan, publication, and dedupe workflow."""

from __future__ import annotations

import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from workbench_target import directory_content_digest, git_output, git_revision


def read_workflow(connection: sqlite3.Connection, workflow_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT state_json FROM finding_workflows WHERE id = ?", (workflow_id,)
    ).fetchone()
    return json.loads(row["state_json"]) if row is not None else None


def save_workflow(connection: sqlite3.Connection, state: dict[str, Any], timestamp: str) -> None:
    connection.execute(
        """INSERT INTO finding_workflows (id, state_json, created_at, updated_at)
        VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
        state_json = excluded.state_json, updated_at = excluded.updated_at""",
        (state["id"], json.dumps(state, allow_nan=False), timestamp, timestamp),
    )


def bind_workflow(state: dict[str, Any], binding: dict[str, Any]) -> None:
    for field, value in binding.items():
        if field not in {
            "repositoryPath", "scanRequestDigest", "scanId", "scanDir",
            "artifactDigest", "destination", "scope",
        }:
            raise SystemExit("Unknown workflow binding.")
        if field in state and state[field] != value:
            raise SystemExit(
                f"Workflow {state['id']} is already bound to a different {field}. "
                "Use another --workflow-id."
            )
        state[field] = value


def register_workflow_scan(
    connection: sqlite3.Connection, workflow_id: str, scan_id: str, scan_dir: str, timestamp: str
) -> None:
    """Called inside the scan-registration transaction, before model execution."""
    state = read_workflow(connection, workflow_id)
    if state is None:
        raise SystemExit("The workflow must be started before registering its scan.")
    if state["stages"]["scan"]["status"] == "completed":
        raise SystemExit("The workflow scan is already complete.")
    previous = state.get("scanId")
    if previous is not None:
        row = connection.execute("SELECT status FROM scans WHERE id = ?", (previous,)).fetchone()
        if row is not None and row["status"] == "complete":
            raise SystemExit("Reuse the workflow's completed scan instead of registering another.")
    state["scanId"] = scan_id
    state["scanDir"] = scan_dir
    save_workflow(connection, state, timestamp)


def finding_workflow(
    connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    workflow_id = payload["id"]
    if not isinstance(workflow_id, str) or not workflow_id.strip():
        raise SystemExit("workflowId must be a nonempty string.")
    if payload["action"] == "get":
        return {"workflow": read_workflow(connection, workflow_id)}
    if payload["action"] == "source":
        target = Path(payload["repository"]).resolve(strict=True)
        return {"source": {
            "repository": str(target),
            "revision": git_revision(target),
            "refsDigest": hashlib.sha256((git_output(target, "show-ref") or "").encode()).hexdigest(),
            "content": directory_content_digest(target, include_ignored=True),
        }}
    if payload["action"] == "get-review":
        row = connection.execute(
            "SELECT result_json FROM finding_workflow_reviews WHERE workflow_id = ? AND review_key = ?",
            (workflow_id, payload["key"]),
        ).fetchone()
        return {"review": json.loads(row["result_json"]) if row is not None else None}
    if payload["action"] == "save-review":
        with connection:
            connection.execute(
                """INSERT INTO finding_workflow_reviews
                (workflow_id, review_key, binding_json, result_json, created_at)
                VALUES (?, ?, ?, ?, ?) ON CONFLICT(workflow_id, review_key) DO NOTHING""",
                (workflow_id, payload["key"], json.dumps(payload["binding"], allow_nan=False),
                 json.dumps(payload["result"], allow_nan=False), timestamp),
            )
        return {}
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        state = read_workflow(connection, workflow_id)
        if state is None:
            state = {
                "id": workflow_id,
                "stages": {stage: {"status": "pending"} for stage in ("scan", "publish", "dedupe")},
            }
        bind_workflow(state, payload.get("binding", {}))
        action = payload["action"]
        if action != "bind":
            stage = payload["stage"]
            if stage not in state["stages"]:
                raise SystemExit("Unknown workflow stage.")
            current = state["stages"][stage]
            if current["status"] != "completed":
                if action == "begin":
                    current["status"] = "running"
                elif action == "complete":
                    state["stages"][stage] = {"status": "completed", "result": payload["result"]}
                elif action == "fail":
                    current.update(status="failed", error=payload["error"])
                elif action == "prepare-dedupe":
                    current.update(result=payload["result"], pendingWrite=payload["pendingWrite"])
                else:
                    raise SystemExit("Unknown workflow action.")
        save_workflow(connection, state, timestamp)
        return {"workflow": state}
