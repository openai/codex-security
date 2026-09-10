#!/usr/bin/env python3
"""Read saved scan diagnostics and owned rollout events for a feedback attachment."""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
from collections import defaultdict, deque
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import quote

# Collection must not create bytecode or initialize the workbench on a feedback read.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from workbench_db import database_path
from workbench_scan_usage import (
    _codex_state_database,
    _reject_nonstandard_json_number,
    _rollout_path,
    _session_parent_thread_id,
    _timestamp,
)

SCAN_FIELDS = {
    "id": "scanId",
    "mode": "mode",
    "status": "status",
    "phase": "phase",
    "failure_message": "failureMessage",
    "scan_dir": "scanDir",
    "started_at": "startedAt",
    "completed_at": "completedAt",
    "updated_at": "updatedAt",
    "continuation_thread_id": "continuationThreadId",
    "deep_scan_owner_thread_id": "deepScanOwnerThreadId",
}
WORKER_FIELDS = {
    "id": "id",
    "kind": "kind",
    "status": "status",
    "merge_state": "mergeState",
    "attempt": "attempt",
    "sdk_thread_id": "sdkThreadId",
    "error_message": "error",
    "created_at": "createdAt",
    "started_at": "startedAt",
    "completed_at": "completedAt",
    "updated_at": "updatedAt",
}
ATTEMPT_FIELDS = {
    "worker_id": "workerId",
    **{
        key: value
        for key, value in WORKER_FIELDS.items()
        if key not in {"id", "kind", "merge_state"}
    },
}
RUN_FIELDS = {
    "status": "status",
    "phase": "phase",
    "error_message": "error",
    "publication_error_message": "publicationError",
    "created_at": "createdAt",
    "completed_at": "completedAt",
    "updated_at": "updatedAt",
}


@dataclass(frozen=True)
class SessionLog:
    thread_id: str
    parent_thread_id: str | None
    started_at: datetime | None
    working_directory: str | None
    path: Path


@dataclass(frozen=True)
class ScanFeedback:
    diagnostics: dict[str, Any]
    sessions: list[SessionLog]

    def events(self) -> Iterator[dict[str, Any]]:
        for session in self.sessions:
            yield from session_events(session)


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    # Table names here are source constants, never request or database values.
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def _projection(row: Mapping[str, Any], fields: Mapping[str, str]) -> dict[str, Any]:
    return {output: row[column] for column, output in fields.items() if column in row.keys()}


def _scan_rows(connection: sqlite3.Connection, request: Mapping[str, Any]) -> list[sqlite3.Row]:
    columns = _columns(connection, "scans")
    if not {"id", "workspace_id"}.issubset(columns):
        return []
    fields = [f"scans.{key}" for key in SCAN_FIELDS if key in columns]
    workspace_columns = _columns(connection, "workspaces")
    workspace_join = ""
    thread_columns = []
    if {"id", "thread_id"}.issubset(workspace_columns):
        workspace_join = " LEFT JOIN workspaces ON workspaces.id = scans.workspace_id"
        fields.append("workspaces.thread_id AS workspace_thread_id")
        thread_columns.append("workspaces.thread_id")
    thread_columns.extend(
        f"scans.{column}"
        for column in ("continuation_thread_id", "deep_scan_owner_thread_id")
        if column in columns
    )
    select = "SELECT " + ", ".join(fields) + " FROM scans" + workspace_join
    selected = {}
    # Individual bound lookups also support owner subtrees larger than SQLite's
    # parameter limit, without creating temporary tables in this read-only path.
    for scan_id in request.get("scanIds", []):
        for row in connection.execute(select + " WHERE scans.id = ?", (scan_id,)):
            selected[row["id"]] = row
    if thread_columns:
        where = " WHERE " + " OR ".join(f"{column} = ?" for column in thread_columns)
        for thread_id in request.get("threadIds", []):
            for row in connection.execute(select + where, (thread_id,) * len(thread_columns)):
                selected[row["id"]] = row
    return list(selected.values())


def _scan_records(
    connection: sqlite3.Connection, table: str, scan_id: str, fields: Mapping[str, str]
) -> list[dict[str, Any]]:
    columns = _columns(connection, table)
    if "scan_id" not in columns:
        return []
    selected = [column for column in fields if column in columns]
    if not selected:
        return []
    return [
        _projection(row, fields)
        for row in connection.execute(
            f"SELECT {', '.join(selected)} FROM {table} WHERE scan_id = ?", (scan_id,)
        )
    ]


def _raw_events(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with path.open("rb") as source:
            for line in source:
                try:
                    event = json.loads(line, parse_constant=_reject_nonstandard_json_number)
                except (ValueError, UnicodeError):
                    continue
                if isinstance(event, dict):
                    yield event
    except OSError:
        # One deleted or unreadable rollout must not discard the other workers.
        return


def _session(path: Path) -> SessionLog | None:
    events = _raw_events(path)
    try:
        event = next(events, None)
    finally:
        events.close()
    if event is None or event.get("type") != "session_meta":
        return None
    metadata = event.get("payload")
    if not isinstance(metadata, dict):
        return None
    thread_id = metadata.get("id") or metadata.get("session_id")
    if not isinstance(thread_id, str) or not thread_id:
        return None
    cwd = metadata.get("cwd")
    return SessionLog(
        thread_id,
        _session_parent_thread_id(metadata),
        _timestamp(metadata.get("timestamp")),
        cwd if isinstance(cwd, str) else None,
        path,
    )


def _session_index() -> dict[str, SessionLog]:
    home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser().resolve()
    sessions: dict[str, SessionLog] = {}
    for directory in (home / "sessions", home / "archived_sessions"):
        for path in directory.rglob("*.jsonl"):
            session = _session(path)
            if session is not None:
                sessions.setdefault(session.thread_id, session)
    return sessions


def _state_sessions(roots: Sequence[str], sessions: dict[str, SessionLog]) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = defaultdict(set)
    path = _codex_state_database()
    if path is None:
        return edges
    try:
        with closing(
            sqlite3.connect(f"file:{quote(str(path), safe='')}?mode=ro", uri=True)
        ) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            has_threads = {"id", "rollout_path"}.issubset(_columns(connection, "threads"))
            has_edges = {"parent_thread_id", "child_thread_id"}.issubset(
                _columns(connection, "thread_spawn_edges")
            )
            pending = deque(roots)
            seen = set()
            while pending:
                thread_id = pending.popleft()
                if thread_id in seen:
                    continue
                seen.add(thread_id)
                if has_threads:
                    row = connection.execute(
                        "SELECT rollout_path FROM threads WHERE id = ?", (thread_id,)
                    ).fetchone()
                    rollout = _rollout_path(row["rollout_path"]) if row is not None else None
                    session = _session(rollout) if rollout is not None else None
                    if session is not None and session.thread_id == thread_id:
                        sessions[thread_id] = session
                if has_edges:
                    for row in connection.execute(
                        "SELECT child_thread_id FROM thread_spawn_edges WHERE parent_thread_id = ?",
                        (thread_id,),
                    ):
                        child = row["child_thread_id"]
                        if isinstance(child, str) and child:
                            edges[thread_id].add(child)
                            pending.append(child)
    except (OSError, sqlite3.Error):
        pass
    return edges


def _artifact_directory(scan_directory: Path, cwd: str) -> bool:
    artifacts = scan_directory / "artifacts"
    working = Path(cwd)
    if working == artifacts:
        return True
    try:
        parts = working.relative_to(artifacts / "deep_discovery" / "workers").parts
    except ValueError:
        return False
    return len(parts) == 2 and parts[0] != ".." and parts[1] == "output"


def _legacy_worker(
    session: SessionLog, scan: Mapping[str, Any], roots: Sequence[SessionLog]
) -> bool:
    if (
        scan.get("mode") != "deep"
        or session.parent_thread_id is not None
        or session.working_directory is None
        or session.started_at is None
        or not isinstance(scan.get("scanDir"), str)
    ):
        return False
    started = _timestamp(scan.get("startedAt"))
    if started is None or session.started_at < started:
        return False
    if scan.get("status") != "running":
        completed = _timestamp(scan.get("completedAt") or scan.get("updatedAt"))
        if completed is None or session.started_at >= completed:
            return False
    directory = Path(scan["scanDir"])
    directories = [directory]
    marker = directory.name.rfind(".previous-")
    if marker > 0:
        original = directory.with_name(directory.name[:marker])
        if any(
            root.working_directory is not None and Path(root.working_directory) == original
            for root in roots
        ):
            directories.append(original)
    return any(_artifact_directory(root, session.working_directory) for root in directories)


def _owned_sessions(
    roots: Sequence[str], scan: Mapping[str, Any], sessions: dict[str, SessionLog]
) -> list[SessionLog]:
    edges = _state_sessions(roots, sessions)
    root_sessions = [sessions[root] for root in roots if root in sessions]
    legacy_roots = [
        session.thread_id
        for session in sessions.values()
        if _legacy_worker(session, scan, root_sessions)
    ]
    # Legacy retry roots can also have descendants known only to the state DB.
    for parent, children in _state_sessions(legacy_roots, sessions).items():
        edges[parent].update(children)
    for session in sessions.values():
        if session.parent_thread_id is not None:
            edges[session.parent_thread_id].add(session.thread_id)
    pending = deque([*roots, *legacy_roots])
    seen = set()
    owned = []
    while pending:
        thread_id = pending.popleft()
        if thread_id in seen:
            continue
        seen.add(thread_id)
        if thread_id in sessions:
            owned.append(sessions[thread_id])
        pending.extend(sorted(edges.get(thread_id, ())))
    return owned


def session_events(session: SessionLog) -> Iterator[dict[str, Any]]:
    """Preserve saved scan-log replay filtering and the {threadId, event} schema."""
    replaying = False
    for event in _raw_events(session.path):
        payload = event.get("payload")
        if event.get("type") == "session_meta" and isinstance(payload, dict):
            replaying = (payload.get("id") or payload.get("session_id")) != session.thread_id
        if replaying:
            started_at = payload.get("started_at") if isinstance(payload, dict) else None
            if (
                event.get("type") != "event_msg"
                or not isinstance(payload, dict)
                or payload.get("type") != "task_started"
                or type(started_at) not in (int, float)
                or session.started_at is None
                or started_at < math.floor(session.started_at.timestamp())
            ):
                continue
            replaying = False
        yield {"threadId": session.thread_id, "event": event}


def collect_feedback(request: Mapping[str, Any]) -> list[ScanFeedback]:
    """Resolve matching saved scans without creating or migrating any state."""
    path = database_path()
    if not path.is_file():
        return []
    with closing(
        sqlite3.connect(f"file:{quote(str(path), safe='')}?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        scans = _scan_rows(connection, request)
        if not scans:
            return []
        sessions = _session_index()
        result = []
        for scan in scans:
            diagnostics = _projection(scan, SCAN_FIELDS)
            workers = _scan_records(connection, "deep_scan_workers", scan["id"], WORKER_FIELDS)
            attempts = _scan_records(
                connection, "deep_scan_worker_attempts", scan["id"], ATTEMPT_FIELDS
            )
            runs = _scan_records(connection, "deep_scan_runs", scan["id"], RUN_FIELDS)
            if runs:
                diagnostics["deepScan"] = runs[0]
            if workers:
                diagnostics["workers"] = workers
            if attempts:
                diagnostics["workerAttempts"] = attempts
            roots = [
                scan[column]
                for column in (
                    "continuation_thread_id",
                    "deep_scan_owner_thread_id",
                    "workspace_thread_id",
                )
                if column in scan.keys() and isinstance(scan[column], str) and scan[column]
            ]
            roots.extend(
                worker["sdkThreadId"]
                for worker in [*workers, *attempts]
                if isinstance(worker.get("sdkThreadId"), str) and worker["sdkThreadId"]
            )
            result.append(ScanFeedback(diagnostics, _owned_sessions(roots, diagnostics, sessions)))
        return result


def write_feedback(request: Mapping[str, Any], output: TextIO) -> bool:
    """Stream a single attachment; leave stdout empty when no saved scan matches."""
    scans = collect_feedback(request)
    if not scans:
        return False
    output.write('{"scans":[')
    for index, scan in enumerate(scans):
        if index:
            output.write(",")
        diagnostics = {
            **scan.diagnostics,
            "sessions": [
                {
                    "threadId": session.thread_id,
                    "parentThreadId": session.parent_thread_id,
                    "path": str(session.path),
                }
                for session in scan.sessions
            ],
        }
        encoded = json.dumps(diagnostics, ensure_ascii=False, separators=(",", ":"))
        output.write(encoded[:-1] + ',"events":[')
        for event_index, event in enumerate(scan.events()):
            if event_index:
                output.write(",")
            json.dump(event, output, ensure_ascii=False, separators=(",", ":"))
        output.write("]}")
    output.write("]}\n")
    return True


def main() -> None:
    argparse.ArgumentParser(
        description=(
            "Read one JSON line containing scanIds or threadIds from stdin and write "
            "a feedback attachment to stdout."
        )
    ).parse_args()
    write_feedback(json.loads(sys.stdin.readline()), sys.stdout)


if __name__ == "__main__":
    main()
