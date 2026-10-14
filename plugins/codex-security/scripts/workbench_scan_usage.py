"""Measure scan-owned Codex token usage from the live thread graph."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

TOKEN_FIELDS = {
    "input_tokens": "inputTokens",
    "cached_input_tokens": "cachedInputTokens",
    "cache_write_input_tokens": "cacheWriteInputTokens",
    "output_tokens": "outputTokens",
    "reasoning_output_tokens": "reasoningOutputTokens",
    "total_tokens": "totalTokens",
}
STATE_DATABASE_NAME = re.compile(r"state_(\d+)\.sqlite")
STATE_DATABASE_TIMEOUT_SECONDS = 1.0


@dataclass(frozen=True)
class RolloutSession:
    thread_id: str
    parent_thread_id: str | None
    path: Path


@dataclass
class RolloutUsage:
    tokens: dict[str, int]
    warnings: set[str]
    tokens_updated_at: datetime | None
    rate_limits: dict[str, dict[str, Any]]


def stored_scan_cost_fields(value: str | None) -> dict[str, Any]:
    """Project measured usage without changing the existing legacy cost contract."""

    if value is None:
        return {}
    stored = json.loads(value, parse_constant=_reject_nonstandard_json_number)
    if not isinstance(stored, dict):
        return {}
    if "usage" not in stored:
        return {"cost": stored}
    return {
        "usage": stored["usage"],
        **({"cost": stored["cost"]} if isinstance(stored.get("cost"), dict) else {}),
    }


def reconcile_completed_scan_cost(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    cost_json: str,
) -> None:
    """Persist authoritative SDK cost without discarding measured worker usage."""

    existing = json.loads(scan["cost_json"]) if scan["cost_json"] is not None else {}
    if isinstance(existing, dict) and "usage" in existing:
        cost_json = json.dumps(
            {**existing, "cost": json.loads(cost_json)},
            separators=(",", ":"),
            allow_nan=False,
        )
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'complete'",
            (cost_json, scan["id"]),
        )


def collect_scan_usage(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    thread_id: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Count only complete, attributable rollout events inside this scan's window."""

    roots = _scan_root_thread_ids(connection, scan, thread_id)
    parent_ids = set(_scan_root_thread_ids(connection, scan, thread_id, include_workers=False))
    if not roots:
        return _unavailable_usage("scan_thread_unavailable")

    state_database = _codex_state_database()
    if state_database is None:
        return _unavailable_usage("codex_state_unavailable")

    started_at = _timestamp(scan["started_at"])
    observed_at = datetime.now(timezone.utc)
    stopped_at = _timestamp(completed_at or scan["completed_at"]) or observed_at
    if started_at is None:
        return _unavailable_usage("scan_window_unavailable")

    warnings: set[str] = set()
    if (
        scan["mode"] == "deep"
        and connection.execute(
            "SELECT 1 FROM deep_scan_workers WHERE scan_id = ? AND attempt > 1 LIMIT 1",
            (scan["id"],),
        ).fetchone()
    ):
        warnings.add("worker_attempts_unavailable")
    try:
        sessions, missing_thread_ids = _discover_rollout_sessions(
            state_database,
            roots,
            warnings,
        )
    except (OSError, sqlite3.Error, ValueError):
        return _unavailable_usage("codex_state_unavailable")

    if not sessions:
        return _unavailable_usage("scan_thread_unavailable", warnings=warnings)

    by_role = {role: {**_empty_token_usage(), "threadCount": 0} for role in ("parent", "workers")}
    rate_limits: dict[str, dict[str, Any]] = {}
    tokens_updated_at = None
    accepted_thread_ids: set[str] = set()
    excluded_thread_ids: set[str] = set()
    for session in sessions:
        if session.parent_thread_id in excluded_thread_ids:
            excluded_thread_ids.add(session.thread_id)
            continue
        if (
            session.parent_thread_id is not None
            and session.parent_thread_id not in accepted_thread_ids
        ):
            missing_thread_ids.add(session.thread_id)
            warnings.add("thread_lineage_incomplete")
            continue
        try:
            usage = _read_rollout_usage(
                session,
                started_at=started_at,
                completed_at=stopped_at,
            )
        except (OSError, UnicodeError, ValueError):
            missing_thread_ids.add(session.thread_id)
            warnings.add("rollout_unavailable")
            continue
        if "thread_outside_scan_window" in usage.warnings:
            excluded_thread_ids.add(session.thread_id)
            continue
        warnings.update(usage.warnings)
        if "thread_identity_mismatch" in usage.warnings or (
            "thread_ownership_unavailable" in usage.warnings
        ):
            missing_thread_ids.add(session.thread_id)
            continue
        accepted_thread_ids.add(session.thread_id)
        role = by_role["parent" if session.thread_id in parent_ids else "workers"]
        _add_token_usage(role, usage.tokens)
        role["threadCount"] += 1
        if usage.tokens_updated_at is not None:
            tokens_updated_at = max(
                tokens_updated_at or usage.tokens_updated_at, usage.tokens_updated_at
            )
        for key, snapshot in usage.rate_limits.items():
            if key not in rate_limits or snapshot["observedAt"] > rate_limits[key]["observedAt"]:
                rate_limits[key] = snapshot

    if not accepted_thread_ids:
        return _unavailable_usage("scan_thread_unavailable", warnings=warnings)

    if any(
        usage["cachedInputTokens"] + usage["cacheWriteInputTokens"] > usage["inputTokens"]
        or usage["totalTokens"] != usage["inputTokens"] + usage["outputTokens"]
        for usage in by_role.values()
    ):
        return _unavailable_usage("token_breakdown_unavailable", warnings=warnings)

    result: dict[str, Any] = {
        "coverage": "partial" if missing_thread_ids or warnings else "complete",
        "source": "codex_rollout",
        **{key: sum(role[key] for role in by_role.values()) for key in TOKEN_FIELDS.values()},
        "threadCount": len(accepted_thread_ids),
        "byRole": by_role,
        "window": {"startedAt": started_at.isoformat(), "endedAt": stopped_at.isoformat()},
        "observedAt": observed_at.isoformat(),
        "accountRateLimits": [rate_limits[key] for key in sorted(rate_limits)],
    }
    if tokens_updated_at is not None:
        result["tokensUpdatedAt"] = tokens_updated_at.isoformat()
    if missing_thread_ids:
        result["missingThreadCount"] = len(missing_thread_ids)
    if warnings:
        result["warnings"] = sorted(warnings)
    return result


def _scan_root_thread_ids(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    supplied_thread_id: str | None,
    *,
    include_owner_threads: bool = True,
    include_workers: bool = True,
) -> list[str]:
    candidates: list[str | None] = [supplied_thread_id]
    if include_owner_threads:
        if "continuation_thread_id" in scan.keys():
            candidates.append(scan["continuation_thread_id"])
        if "deep_scan_owner_thread_id" in scan.keys():
            candidates.append(scan["deep_scan_owner_thread_id"])
        workspace = connection.execute(
            "SELECT thread_id FROM workspaces WHERE id = ?",
            (scan["workspace_id"],),
        ).fetchone()
        if workspace is not None:
            candidates.append(workspace["thread_id"])
    if include_workers and scan["mode"] == "deep":
        candidates.extend(
            row["sdk_thread_id"]
            for row in connection.execute(
                """
                SELECT DISTINCT sdk_thread_id
                FROM deep_scan_workers
                WHERE scan_id = ? AND sdk_thread_id IS NOT NULL
                ORDER BY sdk_thread_id
                """,
                (scan["id"],),
            )
        )
    roots: dict[str, None] = {}
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            roots[candidate] = None
    return list(roots)


def _scan_execution_thread_ids(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[str]:
    # CLI recipes identify dedicated executions; Desktop continuations can be shared.
    return _scan_root_thread_ids(
        connection,
        scan,
        scan["continuation_thread_id"] if scan["recipe_json"] is not None else None,
        include_owner_threads=False,
    )


def _codex_state_database() -> Path | None:
    configured_database = os.environ.get("CODEX_STATE_DB", "").strip()
    if configured_database:
        path = Path(configured_database).expanduser()
        return path.resolve() if path.is_file() and os.access(path, os.R_OK) else None

    configured_home = os.environ.get("CODEX_HOME", "")
    codex_home = Path(configured_home) if configured_home.strip() else Path.home() / ".codex"
    configured_sqlite_home = os.environ.get("CODEX_SQLITE_HOME", "")
    search_roots = [
        *([Path(configured_sqlite_home)] if configured_sqlite_home.strip() else []),
        codex_home,
        codex_home / "sqlite",
    ]
    seen: set[Path] = set()
    for search_root in search_roots:
        try:
            if search_root.parts[:1] == ("~",):
                search_root = search_root.expanduser()
            resolved_root = search_root.resolve()
            if resolved_root in seen:
                continue
            seen.add(resolved_root)
            candidates = [
                (int(match.group(1)), path)
                for path in resolved_root.glob("state_*.sqlite")
                if (match := STATE_DATABASE_NAME.fullmatch(path.name)) is not None
                and path.is_file()
                and os.access(path, os.R_OK)
            ]
        except (OSError, RuntimeError, ValueError):
            continue
        if candidates:
            return max(candidates, key=lambda item: item[0])[1].resolve()
    return None


def _discover_rollout_sessions(
    state_database: Path,
    roots: list[str],
    warnings: set[str],
) -> tuple[list[RolloutSession], set[str]]:
    database = sqlite3.connect(
        state_database.as_uri() + "?mode=ro",
        uri=True,
        timeout=STATE_DATABASE_TIMEOUT_SECONDS,
    )
    try:
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only = ON")
        for table, required in (
            ("threads", {"id", "rollout_path"}),
            ("thread_spawn_edges", {"parent_thread_id", "child_thread_id"}),
        ):
            columns = {str(row["name"]) for row in database.execute(f"PRAGMA table_info({table})")}
            if not required.issubset(columns):
                raise ValueError("Codex state graph does not expose the required thread columns.")
        sessions: dict[str, RolloutSession] = {}
        missing_thread_ids: set[str] = set()
        for root in roots:
            row = database.execute(
                "SELECT id, rollout_path FROM threads WHERE id = ?",
                (root,),
            ).fetchone()
            if row is None:
                missing_thread_ids.add(root)
                warnings.add("scan_root_unavailable")
                continue
            if root not in sessions:
                path = _rollout_path(row["rollout_path"])
                if path is None:
                    missing_thread_ids.add(root)
                    warnings.add("rollout_unavailable")
                    continue
                sessions[root] = RolloutSession(root, None, path)
            descendants = database.execute(
                """
                WITH RECURSIVE descendants(
                    depth, parent_thread_id, child_thread_id, ancestry, cycle
                ) AS (
                    SELECT
                        1,
                        edges.parent_thread_id,
                        edges.child_thread_id,
                        '|' || edges.parent_thread_id || '|' || edges.child_thread_id || '|',
                        edges.parent_thread_id = edges.child_thread_id
                    FROM thread_spawn_edges AS edges
                    WHERE edges.parent_thread_id = ?

                    UNION ALL

                    SELECT
                        descendants.depth + 1,
                        edges.parent_thread_id,
                        edges.child_thread_id,
                        descendants.ancestry || edges.child_thread_id || '|',
                        instr(descendants.ancestry, '|' || edges.child_thread_id || '|') > 0
                    FROM thread_spawn_edges AS edges
                    JOIN descendants ON edges.parent_thread_id = descendants.child_thread_id
                    WHERE descendants.cycle = 0
                )
                SELECT
                    descendants.depth,
                    descendants.parent_thread_id,
                    descendants.child_thread_id,
                    descendants.cycle,
                    threads.rollout_path
                FROM descendants
                LEFT JOIN threads ON threads.id = descendants.child_thread_id
                ORDER BY descendants.depth, descendants.child_thread_id
                """,
                (root,),
            )
            for descendant in descendants:
                child_id = descendant["child_thread_id"]
                parent_id = descendant["parent_thread_id"]
                if not isinstance(child_id, str) or not isinstance(parent_id, str):
                    warnings.add("thread_lineage_incomplete")
                    continue
                if descendant["cycle"]:
                    missing_thread_ids.add(child_id)
                    warnings.add("thread_lineage_cycle")
                    continue
                if child_id in sessions:
                    continue
                path = _rollout_path(descendant["rollout_path"])
                if path is None:
                    missing_thread_ids.add(child_id)
                    warnings.add("rollout_unavailable")
                    continue
                sessions[child_id] = RolloutSession(child_id, parent_id, path)
        return list(sessions.values()), missing_thread_ids
    finally:
        database.close()


def _rollout_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            return None

        if resolved == candidate:
            return resolved

        if sys.platform == "darwin" and candidate.parts[1] in {"var", "tmp"}:
            expected = Path("/private", *candidate.parts[1:])
            if resolved == expected:
                return resolved
    except (OSError, RuntimeError):
        return None
    return None


def _read_rollout_usage(
    session: RolloutSession,
    *,
    started_at: datetime,
    completed_at: datetime | None,
) -> RolloutUsage:
    usage = RolloutUsage(_empty_token_usage(), set(), None, {})
    warnings = usage.warnings
    previous = _empty_token_usage()
    boundary_reached = False
    turn_in_progress = False

    with session.path.open("rb") as source:
        for line_number, raw_line in enumerate(source, start=1):
            if not raw_line.endswith(b"\n"):
                warnings.add("rollout_record_incomplete")
                continue
            try:
                event = json.loads(raw_line)
            except (UnicodeError, ValueError):
                if line_number == 1:
                    raise ValueError("The rollout session metadata is unreadable.") from None
                if boundary_reached:
                    warnings.add("rollout_record_invalid")
                continue
            if not isinstance(event, dict):
                if boundary_reached:
                    warnings.add("rollout_record_invalid")
                continue
            payload = event.get("payload")
            if line_number == 1:
                if event.get("type") != "session_meta" or not isinstance(payload, dict):
                    warnings.add("thread_identity_mismatch")
                    return usage
                recorded_id = payload.get("id") or payload.get("session_id")
                if recorded_id != session.thread_id:
                    warnings.add("thread_identity_mismatch")
                    return usage
                recorded_parent = _session_parent_thread_id(payload)
                if session.parent_thread_id is not None:
                    if recorded_parent != session.parent_thread_id:
                        warnings.add("thread_identity_mismatch")
                        return usage
                boundary_reached = (
                    session.parent_thread_id is None
                    and not recorded_parent
                    and not payload.get("forked_from_id")
                )
                continue

            if not isinstance(payload, dict):
                continue
            if not boundary_reached:
                if _is_owned_task_start(session.thread_id, event, payload):
                    task_started_at = _timestamp(event.get("timestamp"))
                    if task_started_at is None:
                        warnings.add("thread_ownership_unavailable")
                        return usage
                    if task_started_at < started_at or (
                        completed_at is not None and task_started_at > completed_at
                    ):
                        warnings.add("thread_outside_scan_window")
                        return usage
                    boundary_reached = True
                    turn_in_progress = True
                elif event.get("type") == "event_msg" and payload.get("type") == "token_count":
                    inherited_usage = _token_snapshot(payload)
                    if inherited_usage is not None:
                        previous = inherited_usage
                continue
            if event.get("type") != "event_msg":
                continue
            timestamp = _timestamp(event.get("timestamp"))
            if timestamp is not None and (completed_at is None or timestamp <= completed_at):
                if payload.get("type") == "task_started":
                    turn_in_progress = True
                elif payload.get("type") in {"task_complete", "turn_aborted"}:
                    turn_in_progress = False
            if payload.get("type") != "token_count":
                continue
            in_window = (
                timestamp is not None
                and timestamp >= started_at
                and (completed_at is None or timestamp <= completed_at)
            )
            if in_window:
                rate_limits = _rate_limit_snapshot(payload.get("rate_limits"), timestamp)
                if rate_limits is not None:
                    key = rate_limits["limitId"]
                    if (
                        key not in usage.rate_limits
                        or rate_limits["observedAt"] >= usage.rate_limits[key]["observedAt"]
                    ):
                        usage.rate_limits[key] = rate_limits
            if "info" in payload and payload["info"] is None:
                continue
            snapshot = _token_snapshot(payload)
            if timestamp is None or snapshot is None:
                warnings.add("token_record_invalid")
                continue
            delta = {
                key: value - previous[key] if value >= previous[key] else value
                for key, value in snapshot.items()
            }
            previous = snapshot
            if not in_window:
                continue
            usage.tokens_updated_at = max(usage.tokens_updated_at or timestamp, timestamp)
            if delta["totalTokens"] <= 0:
                continue
            _add_token_usage(usage.tokens, delta)

    if not boundary_reached:
        warnings.add("thread_ownership_unavailable")
    elif usage.tokens_updated_at is None:
        warnings.add("token_record_missing")
    if turn_in_progress:
        warnings.add("turn_in_progress")
    return usage


def _rate_limit_snapshot(value: object, timestamp: datetime) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {
        "limitId": value.get("limit_id") or "codex",
        "observedAt": timestamp.isoformat(),
    }
    for name in ("primary", "secondary"):
        window = value.get(name)
        if window is None:
            result[name] = None
            continue
        if not isinstance(window, dict):
            return None
        result[name] = {
            "usedPercent": window.get("used_percent"),
            "windowMinutes": window.get("window_minutes"),
            "resetsAt": window.get("resets_at"),
        }
    return result if valid_account_rate_limit(result) else None


def valid_account_rate_limit(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "limitId",
        "observedAt",
        "primary",
        "secondary",
    }:
        return False
    if not isinstance(value["limitId"], str) or _timestamp(value["observedAt"]) is None:
        return False
    for name in ("primary", "secondary"):
        window = value[name]
        if window is None:
            continue
        if not isinstance(window, dict) or set(window) != {
            "usedPercent",
            "windowMinutes",
            "resetsAt",
        }:
            return False
        percent = window["usedPercent"]
        if type(percent) not in (int, float) or not math.isfinite(percent):
            return False
        if any(
            window[key] is not None and type(window[key]) is not int
            for key in ("windowMinutes", "resetsAt")
        ):
            return False
    return True


def _session_parent_thread_id(payload: Mapping[str, Any]) -> str | None:
    source = payload.get("source")
    if isinstance(source, dict):
        subagent = source.get("subagent")
        if isinstance(subagent, dict):
            thread_spawn = subagent.get("thread_spawn")
            if isinstance(thread_spawn, dict):
                parent = thread_spawn.get("parent_thread_id")
                if isinstance(parent, str) and parent:
                    return parent
    for key in ("parent_thread_id", "forked_from_id"):
        parent = payload.get(key)
        if isinstance(parent, str) and parent:
            return parent
    return None


def _is_owned_task_start(
    thread_id: str,
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> bool:
    if event.get("type") != "event_msg" or payload.get("type") != "task_started":
        return False
    turn_id = payload.get("turn_id")
    if not isinstance(turn_id, str) or not turn_id:
        return False
    # Fresh Codex worker thread/turn IDs use a same-process monotonic UUIDv7 generator.
    thread_order = _uuid7_order(thread_id)
    turn_order = _uuid7_order(turn_id)
    if thread_order is None:
        return True
    return turn_order is not None and turn_order >= thread_order


def _uuid7_order(value: str) -> int | None:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed.int if parsed.version == 7 else None


def _token_snapshot(payload: Mapping[str, Any]) -> dict[str, int] | None:
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    usage = info.get("total_token_usage")
    if not isinstance(usage, dict):
        return None
    cache_write = usage.get("cache_write_input_tokens", usage.get("cache_write_tokens", 0))
    legacy_cache_write = usage.get("cache_write_tokens")
    input_tokens = usage.get("input_tokens")
    cached_input_tokens = usage.get("cached_input_tokens", 0)
    if (
        cache_write == 0
        and type(legacy_cache_write) is int
        and legacy_cache_write > 0
        and type(input_tokens) is int
        and type(cached_input_tokens) is int
        and cached_input_tokens + legacy_cache_write <= input_tokens
    ):
        cache_write = legacy_cache_write
    result: dict[str, int] = {}
    for source_key, result_key in TOKEN_FIELDS.items():
        value = (
            cache_write if source_key == "cache_write_input_tokens" else usage.get(source_key, 0)
        )
        if type(value) is not int or value < 0:
            return None
        if source_key in {"input_tokens", "output_tokens", "total_tokens"} and (
            source_key not in usage
        ):
            return None
        result[result_key] = value
    if result["cachedInputTokens"] + result["cacheWriteInputTokens"] > result["inputTokens"]:
        return None
    result["totalTokens"] = result["inputTokens"] + result["outputTokens"]
    return result


def _empty_token_usage() -> dict[str, int]:
    return {field: 0 for field in TOKEN_FIELDS.values()}


def _add_token_usage(target: dict[str, int], addition: Mapping[str, int]) -> None:
    for key in TOKEN_FIELDS.values():
        target[key] += addition[key]


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = (
            datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
            if value.endswith("Z")
            else datetime.fromisoformat(value)
        )
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _unavailable_usage(reason: str, *, warnings: set[str] | None = None) -> dict[str, Any]:
    return {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": sorted({reason, *(warnings or set())}),
    }


def _reject_nonstandard_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
