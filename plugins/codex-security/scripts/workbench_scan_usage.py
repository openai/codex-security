"""Measure scan-owned Codex token usage from the live thread graph."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))
from snapshot_sqlite import readonly_sqlite_uri
from workbench.storage import archive_source_directory, worker_usage_directory

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
    """Associate a thread and its optional parent with the path of the rollout used for usage accounting."""

    thread_id: str
    parent_thread_id: str | None
    path: Path


@dataclass
class _ResponseCounterRecord:
    start: int
    end: int
    timestamp: datetime
    kind: str
    offset: int = 0


@dataclass
class RolloutUsage:
    """Collect token counts, their update time, warnings, and account rate-limit observations for a rollout."""

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

    stored = stored_scan_cost_fields(scan["cost_json"])
    completion = stored.get("usage", {}).get("completion")
    native = collect_scan_usage_safely(
        connection,
        scan,
        thread_id=completion["threadId"] if completion else None,
        completed_turn_id=completion["turnId"] if completion and completion["finalized"] else None,
    )
    fields = merge_scan_usage_fields(stored, stored_scan_cost_fields(cost_json), {"usage": native})
    if completion:
        usage = {**fields["usage"], "completion": completion}
        if not completion["finalized"]:
            if usage["coverage"] == "complete":
                usage["coverage"] = "partial"
            usage["warnings"] = sorted({*usage.get("warnings", []), "turn_in_progress"})
        fields["usage"] = usage
    cost_json = json.dumps(
        fields if "usage" in fields else fields["cost"],
        separators=(",", ":"),
        allow_nan=False,
    )
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'complete'",
            (cost_json, scan["id"]),
        )


def merge_scan_usage_fields(*observations: Mapping[str, Any]) -> dict[str, Any]:
    """Reconcile overlapping measurements without summing the same execution twice."""

    merged: dict[str, Any] = {}
    latest_coverage: dict[str, Any] | None = None
    rate_limits: dict[str, dict[str, Any]] = {}
    for observation in observations:
        if isinstance(observation.get("cost"), dict):
            merged["cost"] = observation["cost"]
        usage = observation.get("usage")
        if not isinstance(usage, dict):
            continue
        for snapshot in usage.get("accountRateLimits", []):
            key = snapshot["limitId"]
            if key not in rate_limits or snapshot["observedAt"] >= rate_limits[key]["observedAt"]:
                rate_limits[key] = snapshot
        previous = merged.get("usage")
        if previous is None or _usage_quality(usage) >= _usage_quality(previous):
            merged["usage"] = usage
        if usage.get("coverage") not in ("complete", "partial"):
            continue
        latest_coverage = (
            usage if latest_coverage is None else _merge_usage_coverage(latest_coverage, usage)
        )
    cost = merged.get("cost")
    usage = merged.get("usage")
    if usage is not None and latest_coverage is not None and latest_coverage is not usage:
        usage = {**usage}
        for field in (
            "coverage",
            "coverageScope",
            "threadCount",
            "missingThreadCount",
            "warnings",
            "observedAt",
            "completion",
            "byRole",
        ):
            if field in latest_coverage:
                usage[field] = latest_coverage[field]
            else:
                usage.pop(field, None)
        # Counts describe the coverage observation, even when its scope narrows.
        # Its whole role breakdown must still sum to the retained token subtotal.
        if "byRole" in usage and any(
            usage.get(field) != latest_coverage.get(field) for field in TOKEN_FIELDS.values()
        ):
            usage.pop("byRole")
        merged["usage"] = usage
    cost_warning = "cost_estimate_covers_earlier_usage"
    if (
        cost is not None
        and usage is not None
        and usage.get("coverage") in ("complete", "partial")
        and type(usage.get("totalTokens")) is int
    ):
        warnings = set(usage.get("warnings", []))
        warnings.discard(cost_warning)
        if usage["totalTokens"] > cost["inputTokens"] + cost["outputTokens"]:
            warnings.add(cost_warning)
        if warnings != set(usage.get("warnings", [])):
            updated = {**usage}
            updated["coverage"] = (
                "partial"
                if warnings - {cost_warning} or usage.get("missingThreadCount", 0)
                else "complete"
            )
            if warnings:
                updated["warnings"] = sorted(warnings)
            else:
                updated.pop("warnings", None)
            merged["usage"] = updated
    if rate_limits:
        merged["usage"] = {
            **merged["usage"],
            "accountRateLimits": list(rate_limits.values()),
        }
    return merged


def _merge_usage_coverage(previous: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    if previous == observed:
        return observed
    previous_at = _timestamp(previous.get("observedAt"))
    observed_at = _timestamp(observed.get("observedAt"))
    if previous_at is not None and observed_at is not None and previous_at > observed_at:
        previous, observed = observed, previous
    previous_scope = previous.get("coverageScope")
    observed_scope = observed.get("coverageScope")
    covers_previous = (
        previous_scope is not None
        and observed_scope is not None
        and set(previous_scope).issubset(observed_scope)
    )
    scope_gap = previous_scope is not None and observed_scope is not None and not covers_previous
    unresolved_previous = (previous["coverage"] == "partial" and not covers_previous) or scope_gap
    merged = {**observed}
    if unresolved_previous:
        merged["coverage"] = "partial"
        merged["missingThreadCount"] = max(
            previous.get("missingThreadCount", 0), observed.get("missingThreadCount", 0)
        )
        warnings = set(previous.get("warnings", [])) | set(observed.get("warnings", []))
        if scope_gap:
            # A newer subset can grow while still staying below the older
            # aggregate. Neither subtotal proves complete usage for the union.
            warnings.add("usage_scope_incomplete")
        if warnings:
            merged["warnings"] = sorted(warnings)
        if previous.get("completion", {}).get("finalized") is False:
            merged["completion"] = previous["completion"]
    if previous_scope is not None and observed_scope is not None:
        merged["coverageScope"] = sorted(set(previous_scope) | set(observed_scope))
    elif previous_scope is not None and observed["coverage"] == "complete":
        merged["coverageScope"] = previous_scope
    elif unresolved_previous:
        # An older subtotal without scope cannot prove which gaps a later
        # collector has resolved. Retain that uncertainty across future merges.
        merged.pop("coverageScope", None)
    return merged


def _usage_quality(
    usage: Mapping[str, Any], *, observed_at: datetime | None = None
) -> tuple[int, bool, datetime]:
    return (
        usage.get("totalTokens", -1),
        usage.get("cacheWriteInputTokensReported") is not False,
        observed_at
        or _timestamp(usage.get("observedAt"))
        or datetime.min.replace(tzinfo=timezone.utc),
    )


def collect_scan_usage_safely(
    connection: sqlite3.Connection, scan: sqlite3.Row, **options: Any
) -> dict[str, Any]:
    try:
        return collect_scan_usage(connection, scan, **options)
    except (Exception, SystemExit) as exc:
        try:
            print(f"Could not collect scan token usage: {exc}", file=sys.stderr)
        except OSError:
            # A closed diagnostic stream must not replace the unavailable-usage result.
            pass
        return _unavailable_usage("usage_collection_failed")


def collect_scan_usage(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    thread_id: str | None = None,
    validation_thread_id: str | None = None,
    completed_at: str | None = None,
    completed_turn_id: str | None = None,
) -> dict[str, Any]:
    """Count attributable session receipts during the scan window and report missing coverage.

    The optional thread and completion arguments identify the finishing turn when
    the scan record alone is insufficient. Return an unavailable usage record when
    the window, Codex state, or relevant threads cannot be established.
    """

    attribution = scan_execution_attribution(connection, scan)
    if attribution and attribution.get("legacy"):
        attribution = None
    roots = (
        list(
            dict.fromkeys(
                [
                    *(
                        [attribution["owner"]["threadId"]]
                        if attribution["owner"].get("threadId")
                        else []
                    ),
                    *attribution["executionThreadIds"],
                ]
            )
        )
        if attribution
        else _scan_root_thread_ids(connection, scan, thread_id)
    )
    parent_ids = set(_scan_root_thread_ids(connection, scan, thread_id, include_workers=False))
    execution_roots = set(attribution["executionThreadIds"]) if attribution else None
    if validation_thread_id:
        if execution_roots is not None and validation_thread_id != attribution["owner"].get(
            "threadId"
        ):
            execution_roots.add(validation_thread_id)
        roots.append(validation_thread_id)
        parent_ids.add(validation_thread_id)
    warnings: set[str] = set()
    worker_directories = _scan_worker_directories(connection, scan, warnings)
    if attribution and attribution["owner"].get("threadId"):
        parent_ids.add(attribution["owner"]["threadId"])
    current_database = _codex_state_database()
    worker_codex_home = None
    if scan["mode"] == "deep":
        from deep_scan_workbench import recorded_deep_scan_codex_home

        run = connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
        ).fetchone()
        home = recorded_deep_scan_codex_home(run) if run is not None else None
        if home is not None:
            worker_codex_home = Path(home)
    groups = [(current_database, roots)]
    worker_roots: set[str] = set()
    recorded_roots: set[str] = set()
    if worker_codex_home is not None:
        worker_roots = set(
            _scan_root_thread_ids(connection, scan, None, include_owner_threads=False)
        )
        recorded_roots = worker_roots | (
            {attribution["owner"]["threadId"]}
            if attribution and attribution["owner"].get("threadId")
            else set()
        )
        # Workers retain their Codex home, but inherit an explicit current
        # SQLite home. Their earlier and resumed sessions can be in either index.
        worker_database = _codex_state_database(worker_codex_home)
        if worker_database != current_database:
            groups.append((worker_database, [root for root in roots if root in recorded_roots]))
    started_at = _timestamp(scan["started_at"])
    observed_at = datetime.now(timezone.utc)
    stopped_at = _timestamp(completed_at or scan["completed_at"]) or observed_at
    if started_at is None:
        return _unavailable_usage("scan_window_unavailable")

    receipts, missing_receipts, receipt_scope = _worker_usage_receipts(
        scan, started_at, stopped_at, warnings
    )
    sessions: dict[str, list[RolloutSession]] = {}
    missing_thread_ids: set[str] = set()
    seen_thread_ids: set[str] = set()
    for state_database, group_roots in groups:
        if not group_roots and not worker_directories:
            continue
        try:
            if state_database is None:
                raise FileNotFoundError("Codex state is unavailable")
            discovered, missing = _discover_rollout_sessions(
                state_database,
                group_roots,
                warnings,
                descendant_roots=execution_roots,
                worker_directories=worker_directories,
                scan_directory=Path(scan["scan_dir"]) if worker_directories else None,
                started_at=started_at,
                completed_at=stopped_at,
            )
        except (OSError, sqlite3.Error, ValueError):
            warnings.add("codex_state_unavailable")
            missing_thread_ids.update(group_roots)
            continue
        missing_thread_ids.update(missing)
        for session in discovered:
            copies = sessions.setdefault(session.thread_id, [])
            if session not in copies:
                copies.append(session)
            seen_thread_ids.add(session.thread_id)

    if worker_codex_home is not None and recorded_roots:
        # An external SQLite location can change on recovery. Native rollouts
        # still live in the recorded worker home; they retain their lineage.
        for session in _discover_recorded_worker_sessions(
            worker_codex_home,
            recorded_roots,
            descendant_roots=execution_roots,
        ):
            copies = sessions.setdefault(session.thread_id, [])
            if session not in copies:
                copies.append(session)
            seen_thread_ids.add(session.thread_id)

    # Absence from one known index is not missing usage when another has it.
    missing_thread_ids.difference_update(seen_thread_ids)
    if not missing_thread_ids:
        warnings.difference_update(
            {"scan_root_unavailable", "codex_state_unavailable", "rollout_unavailable"}
        )

    if not sessions and not receipts:
        return _unavailable_usage(
            "codex_state_unavailable"
            if "codex_state_unavailable" in warnings
            else "scan_thread_unavailable",
            warnings=warnings,
        )

    rate_limits: dict[str, dict[str, Any]] = {}
    tokens_updated_at = None
    accepted_thread_ids: set[str] = set()
    measured_threads: dict[str, dict[str, int]] = {}
    complete_native_thread_ids: set[str] = set()
    excluded_thread_ids: set[str] = set()
    thread_models: dict[str, dict[str | None, dict[str, int]]] = {}
    for copies in _parent_first_rollout_copies(sessions):
        session = copies[0]
        owner_turn_id = None
        if (
            attribution
            and session.thread_id not in execution_roots
            and session.thread_id in parent_ids
            and session.parent_thread_id is None
        ):
            owner = attribution["owner"]
            if session.thread_id != owner.get("threadId") or not owner.get("turnId"):
                missing_thread_ids.add(session.thread_id)
                warnings.add("scan_owner_turn_unavailable")
                continue
            owner_turn_id = owner["turnId"]
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
        models: dict[str | None, dict[str, int]] = {}
        try:
            usage = _read_rollout_copies_usage(
                copies,
                started_at=started_at,
                completed_at=stopped_at,
                owner_turn_id=owner_turn_id,
                model_usage=models,
                completed_turn_id=completed_turn_id if session.thread_id == thread_id else None,
                is_scan_owner=(
                    scan["mode"] == "deep"
                    and session.thread_id == scan["deep_scan_owner_thread_id"]
                ),
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
        for key, snapshot in usage.rate_limits.items():
            if key not in rate_limits or snapshot["observedAt"] > rate_limits[key]["observedAt"]:
                rate_limits[key] = snapshot
        if usage.warnings & {"token_usage_unavailable", "token_breakdown_unavailable"}:
            missing_thread_ids.add(session.thread_id)
            continue
        measured_threads[session.thread_id] = usage.tokens
        thread_models[session.thread_id] = models
        if not usage.warnings:
            complete_native_thread_ids.add(session.thread_id)
        if usage.tokens_updated_at is not None:
            tokens_updated_at = max(
                tokens_updated_at or usage.tokens_updated_at, usage.tokens_updated_at
            )

    runtime_receipts_used = False
    for receipt_thread_id, receipt in receipts.items():
        native = measured_threads.get(receipt_thread_id)
        extends_native = native is None or receipt.tokens["totalTokens"] > native["totalTokens"]
        fills_cache_write_usage = (
            native is not None
            and receipt.tokens["totalTokens"] == native["totalTokens"]
            and native.get("cacheWriteInputTokensReported") is False
            and receipt.tokens.get("cacheWriteInputTokensReported") is not False
        )
        if extends_native or fills_cache_write_usage:
            measured_threads[receipt_thread_id] = receipt.tokens
            thread_models.pop(receipt_thread_id, None)
            accepted_thread_ids.add(receipt_thread_id)
            runtime_receipts_used = True
            if extends_native:
                complete_native_thread_ids.discard(receipt_thread_id)
                # Numeric SDK subtotals cannot establish that descendants and
                # compaction requests are present when their rollouts are absent.
                missing_thread_ids.add(receipt_thread_id)
                warnings.add("worker_rollout_usage_incomplete")
            if receipt.tokens_updated_at is not None:
                tokens_updated_at = max(
                    tokens_updated_at or receipt.tokens_updated_at, receipt.tokens_updated_at
                )
    unresolved_receipts = missing_receipts - complete_native_thread_ids
    if unresolved_receipts:
        missing_thread_ids.update(unresolved_receipts)
        warnings.add("worker_usage_unavailable")
    if not accepted_thread_ids:
        return _unavailable_usage("scan_thread_unavailable", warnings=warnings)
    if not measured_threads:
        reason = (
            "token_breakdown_unavailable"
            if "token_breakdown_unavailable" in warnings
            else "token_usage_unavailable"
        )
        return _unavailable_usage(reason, warnings=warnings, rate_limits=rate_limits)

    by_role = {role: {**_empty_token_usage(), "threadCount": 0} for role in ("parent", "workers")}
    for measured_id, tokens in measured_threads.items():
        role = by_role["parent" if measured_id in parent_ids else "workers"]
        _add_token_usage(role, tokens)
        role["threadCount"] += 1
    if any(
        usage["cachedInputTokens"] + usage["cacheWriteInputTokens"] > usage["inputTokens"]
        or usage["totalTokens"] != usage["inputTokens"] + usage["outputTokens"]
        for usage in by_role.values()
    ):
        return _unavailable_usage(
            "token_breakdown_unavailable", warnings=warnings, rate_limits=rate_limits
        )

    if (completed_turn_id is not None or runtime_receipts_used) and tokens_updated_at is not None:
        stopped_at = max(stopped_at, tokens_updated_at)
    result: dict[str, Any] = {
        "coverage": "partial" if missing_thread_ids or warnings else "complete",
        "source": "codex_runtime" if runtime_receipts_used else "codex_rollout",
        **{key: sum(role[key] for role in by_role.values()) for key in TOKEN_FIELDS.values()},
        "threadCount": len(measured_threads),
        "coverageScope": sorted(
            receipt_scope
            | {f"thread:{identity}" for identity in measured_threads}
            | {
                identity if identity.startswith("worker-attempt:") else f"thread:{identity}"
                for identity in missing_thread_ids
            }
        ),
        "byRole": by_role,
        "window": {"startedAt": started_at.isoformat(), "endedAt": stopped_at.isoformat()},
        "observedAt": observed_at.isoformat(),
        "accountRateLimits": [rate_limits[key] for key in sorted(rate_limits)],
    }
    if any(role.get("cacheWriteInputTokensReported") is False for role in by_role.values()):
        result["cacheWriteInputTokensReported"] = False
    if tokens_updated_at is not None:
        result["tokensUpdatedAt"] = tokens_updated_at.isoformat()
    if missing_thread_ids:
        result["missingThreadCount"] = len(missing_thread_ids)
    if warnings:
        result["warnings"] = sorted(warnings)
    model_usage: dict[str | None, dict[str, int]] = {}
    for measured_id, tokens in measured_threads.items():
        models = thread_models.get(measured_id, {})
        # A cumulative worker receipt or a late cache refinement may lack a
        # model breakdown. Keep that thread's total once as unpriced usage.
        if any(
            sum(part[k] for part in models.values()) != tokens[k] for k in TOKEN_FIELDS.values()
        ):
            models = {None: tokens}
        for model, part in models.items():
            _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), part)
    if model_usage and (attribution or any(model is not None for model in model_usage)):
        result["modelUsage"] = [{"model": model, **counts} for model, counts in model_usage.items()]
    return result


def _parent_first_rollout_copies(
    sessions: dict[str, list[RolloutSession]],
) -> list[list[RolloutSession]]:
    """Preserve discovery order while visiting recovered parents before children."""
    ordered: dict[str, list[RolloutSession]] = {}
    for thread_id in sessions:
        lineage: dict[str, list[RolloutSession]] = {}
        current: str | None = thread_id
        while current in sessions and current not in ordered and current not in lineage:
            copies = sessions[current]
            lineage[current] = copies
            current = copies[0].parent_thread_id
        ordered.update(reversed(tuple(lineage.items())))
    return list(ordered.values())


def _read_rollout_copies_usage(
    copies: list[RolloutSession],
    *,
    started_at: datetime,
    completed_at: datetime | None,
    owner_turn_id: str | None,
    model_usage: dict[str | None, dict[str, int]],
    completed_turn_id: str | None = None,
    is_scan_owner: bool = False,
) -> RolloutUsage:
    readings = []
    for session in copies:
        local_models: dict[str | None, dict[str, int]] = {}
        response_ids: set[str] = set()
        try:
            usage = _read_rollout_usage(
                session,
                started_at=started_at,
                completed_at=completed_at,
                owner_turn_id=owner_turn_id,
                model_usage=local_models,
                accepted_response_ids=response_ids,
                completed_turn_id=completed_turn_id,
                is_scan_owner=is_scan_owner,
            )
        except (OSError, UnicodeError, ValueError):
            continue
        readings.append((usage, usage.warnings, local_models, response_ids))
    if not readings:
        raise ValueError("No readable rollout copy.")
    attributable = [
        reading
        for reading in readings
        if not reading[1].intersection(
            {
                "thread_identity_mismatch",
                "thread_ownership_unavailable",
                "thread_outside_scan_window",
                "token_usage_unavailable",
            }
        )
    ]
    # Restored indexes can reference a prefix and its complete continuation.
    # Keep totals and model attribution from the same copy, counting it once.
    usage, warnings, selected_models, _ = max(
        attributable or readings,
        key=lambda reading: (len(reading[3]), reading[0].tokens["totalTokens"], -len(reading[1])),
    )
    for model, tokens in selected_models.items():
        _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), tokens)
    return usage


def capture_scan_usage_owner(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    """Bind the active native turn once; joining a scan does not bind later conversation work."""
    roots = _scan_root_thread_ids(connection, scan, None)
    owner = roots[0] if roots else None
    result = {
        "threadId": owner,
        "turnId": None,
        "startedAt": scan["started_at"],
        "dedicated": scan["recipe_json"] is not None,
    }
    database = _codex_state_database()
    if owner is None or database is None:
        return result
    try:
        sessions, _ = _discover_rollout_sessions(
            database,
            [owner],
            set(),
            descendant_roots=set(),
            worker_directories={},
            started_at=_timestamp(scan["started_at"]) or datetime.now(timezone.utc),
            completed_at=None,
        )
        if not sessions:
            return result
        with _rollout_lines(sessions[0].path) as source:
            for line in source:
                if not line.endswith(b"\n"):
                    continue
                event = json.loads(line)
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    continue
                if event.get("type") == "turn_context" or (
                    event.get("type") == "event_msg" and payload.get("type") == "task_started"
                ):
                    turn_id = payload.get("turn_id")
                    if isinstance(turn_id, str):
                        result["turnId"] = turn_id
                elif event.get("type") == "event_msg" and payload.get("type") == "task_complete":
                    result["turnId"] = None
    except (OSError, ValueError, sqlite3.Error):
        # Accounting availability must not prevent a scan from starting.
        pass
    return result


def scan_execution_attribution(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> dict[str, Any] | None:
    if scan["mode"] != "deep":
        return None
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
    ).fetchone()
    if run is None:
        executions = _scan_execution_thread_ids(connection, scan)
        if scan["recipe_json"] is None or not executions:
            return None
        # The registered CLI parent is dedicated to this scan before it starts
        # the coordinator. Its live usage already belongs to the scan window.
        return {
            "formatVersion": 1,
            "executionThreadIds": executions,
            "owner": capture_scan_usage_owner(connection, scan),
            "startedAt": scan["started_at"],
            "completedAt": scan["completed_at"],
        }
    owner_json = run["usage_owner_json"] if "usage_owner_json" in run.keys() else None
    legacy = owner_json is None
    if owner_json is None:
        roots = _scan_root_thread_ids(connection, scan, None)
        owner = {
            "threadId": roots[0] if roots else None,
            "turnId": None,
            "startedAt": scan["started_at"],
            "dedicated": scan["recipe_json"] is not None,
        }
    else:
        owner = json.loads(owner_json)
    executions = _scan_execution_thread_ids(connection, scan)
    if owner.get("dedicated") and owner.get("threadId") not in executions:
        executions.append(owner["threadId"])
    return {
        "formatVersion": 1,
        **({"legacy": True} if legacy else {}),
        "executionThreadIds": executions,
        "owner": owner,
        "startedAt": scan["started_at"],
        "completedAt": scan["completed_at"],
    }


def scan_execution_fields(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    return {
        "threadIds": _scan_root_thread_ids(connection, scan, None),
        "executionThreadIds": _scan_execution_thread_ids(connection, scan),
        "executionAttribution": scan_execution_attribution(connection, scan),
    }


def _discover_recorded_worker_sessions(
    codex_home: Path, roots: set[str], *, descendant_roots: set[str] | None = None
) -> list[RolloutSession]:
    recorded: dict[str, list[RolloutSession]] = {}
    children: dict[str, set[str]] = {}
    for candidate in sorted(
        path
        for directory in ("sessions", "archived_sessions")
        for path in (codex_home / directory).rglob("*.jsonl*")
        if path.name.endswith((".jsonl", ".jsonl.zst"))
    ):
        path = _rollout_path(str(candidate))
        if path is None:
            continue
        try:
            with _rollout_lines(path) as stream:
                metadata = json.loads(next(stream, b""))
        except (OSError, UnicodeError, ValueError):
            continue
        if not isinstance(metadata, dict) or metadata.get("type") != "session_meta":
            continue
        payload = metadata.get("payload")
        if not isinstance(payload, dict):
            continue
        thread_id = payload.get("id") or payload.get("session_id")
        if not isinstance(thread_id, str):
            continue
        parent_id = _session_parent_thread_id(payload)
        recorded.setdefault(thread_id, []).append(RolloutSession(thread_id, parent_id, path))
        if parent_id is not None:
            children.setdefault(parent_id, set()).add(thread_id)

    sessions: list[RolloutSession] = []
    included = set(roots)
    pending = deque(sorted(roots))
    while pending:
        thread_id = pending.popleft()
        for session in recorded.get(thread_id, []):
            sessions.append(
                RolloutSession(
                    thread_id,
                    None if thread_id in roots else session.parent_thread_id,
                    session.path,
                )
            )
        if (
            descendant_roots is not None
            and thread_id in roots
            and thread_id not in descendant_roots
        ):
            continue
        for child_id in sorted(children.get(thread_id, set()) - included):
            included.add(child_id)
            pending.append(child_id)
    return sessions


def _require_state_columns(
    connection: sqlite3.Connection,
    table: str,
    required: set[str],
) -> None:
    statements = {
        "threads": "PRAGMA table_info(threads)",
        "thread_spawn_edges": "PRAGMA table_info(thread_spawn_edges)",
    }
    columns = {str(row["name"]) for row in connection.execute(statements[table])}
    if not required.issubset(columns):
        raise ValueError("Codex state graph does not expose the required thread columns.")


def _worker_usage_receipts(
    scan: Mapping[str, Any],
    started_at: datetime,
    completed_at: datetime,
    warnings: set[str],
) -> tuple[dict[str, RolloutUsage], set[str], set[str]]:
    if scan["mode"] != "deep":
        return {}, set(), set()
    directory = worker_usage_directory(scan["id"])
    try:
        if directory.resolve(strict=True) != directory:
            raise ValueError("Worker usage directory is not a canonical protected directory.")
    except FileNotFoundError:
        return {}, set(), set()
    except (OSError, RuntimeError, ValueError):
        warnings.add("worker_usage_receipt_unavailable")
        return {}, {"worker-receipts"}, {"worker-receipts"}
    receipts: dict[str, RolloutUsage] = {}
    missing: set[str] = set()
    attempts: set[str] = set()
    scope: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        try:
            if _rollout_path(str(path)) is None:
                raise ValueError("Worker usage receipt path is unavailable.")
            receipt = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(receipt, dict)
                or receipt.get("schemaVersion") != 1
                or receipt.get("source") != "codex_sdk"
                or receipt.get("usageScope") != "thread_cumulative"
                or receipt.get("scanId") != scan["id"]
                or receipt.get("kind") not in ("discovery", "dedup", "compare")
                or receipt.get("attemptId") != path.stem
            ):
                raise ValueError("Worker usage receipt identity is invalid.")
            attempt_id = receipt["attemptId"]
            begin = _timestamp(receipt.get("startedAt"))
            observed = _timestamp(receipt.get("observedAt"))
            if begin is None or observed is None:
                raise ValueError("Worker usage receipt timestamps are invalid.")
            if begin < started_at or begin > completed_at or attempt_id in attempts:
                continue
            attempts.add(attempt_id)
            scope.add(f"worker-attempt:{attempt_id}")
            thread_id = receipt.get("threadId")
            if isinstance(thread_id, str) and thread_id:
                scope.add(f"thread:{thread_id}")
            tokens = _usage_counts(receipt.get("usage"))
            if not isinstance(thread_id, str) or not thread_id or tokens is None:
                missing.add(
                    thread_id
                    if isinstance(thread_id, str) and thread_id
                    else f"worker-attempt:{attempt_id}"
                )
                continue
            previous = receipts.get(thread_id)
            if previous is None or _usage_quality(tokens, observed_at=observed) > _usage_quality(
                previous.tokens, observed_at=previous.tokens_updated_at
            ):
                receipts[thread_id] = RolloutUsage(tokens, set(), observed, {})
        except (OSError, UnicodeError, ValueError) as exc:
            warnings.add("worker_usage_receipt_unavailable")
            missing.add(f"worker-attempt:{path.stem}")
            scope.add(f"worker-attempt:{path.stem}")
            try:
                print(f"Could not read worker token usage: {exc}", file=sys.stderr)
            except OSError:
                # The receipt warning and missing-attempt scope are already retained.
                pass
    return receipts, missing, scope


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
                FROM deep_scan_worker_threads
                WHERE scan_id = ?
                UNION
                SELECT sdk_thread_id FROM deep_scan_attempt_sessions
                WHERE scan_id = ?
                ORDER BY sdk_thread_id
                """,
                (scan["id"], scan["id"]),
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


def _scan_worker_directories(
    connection: sqlite3.Connection, scan: sqlite3.Row, warnings: set[str]
) -> dict[str, bool]:
    if scan["mode"] != "deep":
        return {}
    if connection.execute(
        "SELECT 1 FROM deep_scan_runs WHERE scan_id = ? AND worker_usage_gap = 1", (scan["id"],)
    ).fetchone():
        warnings.add("worker_thread_unavailable")
    artifacts = Path(scan["scan_dir"]) / "artifacts"
    # Comparison turns run in this directory without a discovery worker row.
    directories = {str(artifacts / "deep_discovery"): False}
    for row in connection.execute(
        "SELECT kind, artifact_dir, started_at, sdk_thread_id, attempt FROM deep_scan_workers "
        "WHERE scan_id = ? AND kind IN ('discovery', 'dedup')",
        (scan["id"],),
    ):
        if row["kind"] == "discovery":
            if row["sdk_thread_id"] and row["attempt"] == 1:
                continue  # The first attempt already has an exact thread identity.
            # An attempt that started without a saved ID must be found by its assigned cwd.
            missing_thread = bool(row["started_at"] and not row["sdk_thread_id"])
            directories[row["artifact_dir"]] = missing_thread
        else:
            directories[str(artifacts)] = False
        if row["attempt"] > 1 and row["started_at"] and not row["sdk_thread_id"]:
            # Retries share a cwd. A rollout from an older attempt cannot prove the new one.
            warnings.add("worker_thread_unavailable")
    return directories


def _codex_state_database(worker_codex_home: Path | None = None) -> Path | None:
    configured_home = os.environ.get("CODEX_HOME", "")
    current_home = Path(configured_home) if configured_home.strip() else Path.home() / ".codex"
    if current_home.parts[:1] == ("~",):
        current_home = current_home.expanduser()
    codex_home = worker_codex_home if worker_codex_home is not None else current_home
    same_home = worker_codex_home is None or codex_home.resolve() == current_home.resolve()
    configured_database = os.environ.get("CODEX_STATE_DB", "") if same_home else ""
    if configured_database.strip():
        path = Path(configured_database)
        if path.parts[:1] == ("~",):
            path = path.expanduser()
        return path.resolve() if path.is_file() and os.access(path, os.R_OK) else None

    configured_sqlite_home = os.environ.get("CODEX_SQLITE_HOME", "") if same_home else ""
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
    *,
    descendant_roots: set[str] | None = None,
    worker_directories: dict[str, bool],
    scan_directory: Path | None = None,
    started_at: datetime,
    completed_at: datetime | None,
) -> tuple[list[RolloutSession], set[str]]:
    database = sqlite3.connect(
        readonly_sqlite_uri(state_database),
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
            if table == "threads" and worker_directories and not {"cwd", "created_at"} <= columns:
                worker_directories = {}
                warnings.add("worker_directories_unavailable")
        sessions: dict[str, RolloutSession] = {}
        missing_thread_ids: set[str] = set()
        root_ids: dict[str, str | None] = dict.fromkeys(roots)
        started_millisecond = started_at.replace(microsecond=started_at.microsecond // 1000 * 1000)
        completed_timestamp = int(completed_at.timestamp()) if completed_at is not None else None
        directory_expression = "cwd"
        if worker_directories and os.name == "nt":
            from windows_scan_local_files import _normalized_windows_path

            database.create_function(
                "codex_security_path_key", 1, _normalized_windows_path, deterministic=True
            )
            directory_expression = "codex_security_path_key(cwd)"
            worker_directories = {
                _normalized_windows_path(path): required
                for path, required in worker_directories.items()
            }
            if scan_directory is not None:
                scan_directory = Path(_normalized_windows_path(scan_directory))
        unmatched = {path for path, required in worker_directories.items() if required}
        directory_sources = {path: {path} for path in worker_directories}
        if worker_directories and scan_directory and ".previous-" in scan_directory.name:
            # Archived files move, but session working directories describe where execution ran.
            # Confirm the original output with an already-bound session before including peers.
            bound_directories = {
                Path(row[0])
                for row in database.execute(
                    f"SELECT DISTINCT {directory_expression} FROM threads WHERE cwd IS NOT NULL "
                    "AND id IN (SELECT value FROM json_each(?))",
                    (json.dumps(roots),),
                )
            }
            relatives = {
                Path(path).relative_to(scan_directory): path
                for path in worker_directories
                if Path(path).is_relative_to(scan_directory)
            }
            originals = {
                original
                for path in bound_directories | {Path(path) for path in worker_directories}
                if (original := archive_source_directory(scan_directory, path)) is not None
            }
            for original in originals:
                candidates = {original / relative: path for relative, path in relatives.items()}
                # Older archives kept absolute discovery paths in their original directory.
                if (
                    original in bound_directories
                    or candidates.keys() & bound_directories
                    or any(Path(path).is_relative_to(original) for path in worker_directories)
                ):
                    for candidate, path in candidates.items():
                        directory_sources.setdefault(str(candidate), set()).add(path)
        for directory in sorted(directory_sources):
            for row in database.execute(
                "SELECT id FROM threads WHERE cwd IS NOT NULL "
                f"AND {directory_expression} = ? AND created_at >= ? "
                "AND (? IS NULL OR created_at <= ?) ORDER BY id",
                (directory, int(started_at.timestamp()), completed_timestamp, completed_timestamp),
            ):
                root_ids[row["id"]] = directory
        for root, directory in root_ids.items():
            row = database.execute(
                "SELECT id, rollout_path FROM threads WHERE id = ?",
                (root,),
            ).fetchone()
            if row is None:
                missing_thread_ids.add(root)
                warnings.add("scan_root_unavailable")
                continue
            path = _rollout_path(row["rollout_path"])
            if path is None:
                missing_thread_ids.add(root)
                warnings.add("rollout_unavailable")
                continue
            if root not in roots:
                try:
                    with _rollout_lines(path) as source:
                        metadata = json.loads(next(source, b""))
                except (OSError, ValueError):
                    missing_thread_ids.add(root)
                    warnings.add("rollout_unavailable")
                    continue
                if (
                    isinstance(metadata, dict)
                    and metadata.get("type") == "session_meta"
                    and isinstance(payload := metadata.get("payload"), dict)
                    and (payload.get("id") or payload.get("session_id")) == root
                    and (created_at := _timestamp(payload.get("timestamp"))) is not None
                    and (
                        created_at < started_millisecond
                        or completed_at is not None
                        and created_at > completed_at
                    )
                ):
                    continue
            if directory is not None:
                unmatched.difference_update(directory_sources[directory])
            sessions[root] = RolloutSession(root, None, path)
            if descendant_roots is not None and root in roots and root not in descendant_roots:
                continue
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
        if unmatched:
            warnings.add("worker_thread_unavailable")
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
        try:
            candidate.lstat()
        except FileNotFoundError:
            # Native cold storage may compress an indexed JSONL file in place.
            if candidate.suffix != ".jsonl":
                return None
            candidate = candidate.with_suffix(".jsonl.zst")
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


@contextmanager
def _rollout_lines(path: Path, *, verify_end: bool = False):
    if path.suffix != ".zst":
        with path.open("rb") as source:
            yield source
        return
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        try:
            from backports import zstd
        except ImportError:
            zstd = None
    if zstd is not None:
        try:
            with zstd.open(path, "rb") as source:
                yield source
                # A requested completion turn may stop parsing before the frame checksum.
                if verify_end:
                    while source.read(64 * 1024):
                        pass
        except (zstd.ZstdError, EOFError) as error:
            raise ValueError("Invalid compressed Codex rollout.") from error
        return
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(
            [
                os.environ.get("CODEX_MCP_NODE_PATH") or "node",
                str(Path(__file__).with_name("read_codex_session.mjs")),
                str(path),
            ],
            stdout=subprocess.PIPE,
            stderr=errors,
        ) as child:
            exhausted = False

            def lines():
                nonlocal exhausted
                yield from child.stdout
                exhausted = True

            try:
                iterator = lines()
                yield iterator
                if verify_end:
                    for _ in iterator:
                        pass
            finally:
                if not exhausted and child.poll() is None:
                    child.terminate()
                child.stdout.close()
                status = child.wait()
                if exhausted and status != 0:
                    errors.seek(0)
                    raise OSError(errors.read().decode("utf-8", errors="replace"))


def _read_rollout_usage(
    session: RolloutSession,
    *,
    started_at: datetime,
    completed_at: datetime | None,
    owner_turn_id: str | None = None,
    model_usage: dict[str | None, dict[str, int]] | None = None,
    accepted_response_ids: set[str] | None = None,
    completed_turn_id: str | None = None,
    is_scan_owner: bool = False,
) -> RolloutUsage:
    result = RolloutUsage(_empty_token_usage(), set(), None, {})
    total = result.tokens
    counter_total = _empty_token_usage()
    warnings = result.warnings
    previous = _empty_token_usage()
    after_compaction = False
    previous_cache_writes_reported = True
    prefix_unclassified = 0
    prefix_missing_cache: set[str] = set()
    ambiguous_legacy_cache = False
    boundary_reached = False
    usage_observed = False
    completed_legacy_usage = _empty_token_usage()
    current_turn_id: str | None = None
    current_model: str | None = None
    completed_turn_measured = False
    direct_control_session = False
    started_turns: set[str] = set()
    open_turns: set[str] = set()
    closed_turns: set[str] = set()
    measured_turns: set[str] = set()
    observed_response_usage = _empty_token_usage()
    current_response_usage_observed = False
    turn_legacy_usage = _empty_token_usage()
    turn_legacy_models: dict[str | None, dict[str, int]] = {}
    response_ids: set[str] = set()
    response_usage_observed = False
    response_tokens = 0
    expected_response_tokens = 0
    response_baseline_tokens = 0
    response_counter_baseline: tuple[int, datetime] | None = None
    response_counter_records: dict[str, _ResponseCounterRecord] = {}

    def record_receipt_counter(
        response_id: str, tokens: int, cumulative: int, timestamp: datetime, kind: str
    ) -> None:
        response_counter_records.setdefault(
            response_id, _ResponseCounterRecord(cumulative - tokens, cumulative, timestamp, kind)
        )

    def reconcile_receipt_counters() -> None:
        nonlocal response_baseline_tokens, expected_response_tokens, excluded_response_tokens
        timeline = [
            (identity, record, False) for identity, record in response_counter_records.items()
        ]
        if response_counter_baseline is not None:
            tokens, baseline_timestamp = response_counter_baseline
            timeline.insert(
                0,
                (
                    None,
                    _ResponseCounterRecord(tokens, tokens, baseline_timestamp, "baseline"),
                    True,
                ),
            )
        # Native timestamps place delayed receipts in the original reset window.
        timeline.sort(key=lambda item: item[1].timestamp)
        offset = window_tokens = baseline = expected = 0
        intervals: list[_ResponseCounterRecord] = []
        excluded: dict[str, tuple[int, int]] = {}
        for identity, record, anchor in timeline:
            if anchor:
                if record.end < window_tokens:
                    offset += window_tokens
                    intervals = []
                window_tokens = record.end
                baseline = offset + record.end
                continue
            if (
                record.end < window_tokens
                and (not intervals or record.timestamp != intervals[-1].timestamp)
            ) or any(record.start < prior.end and record.end > prior.start for prior in intervals):
                offset += window_tokens
                window_tokens = 0
                intervals = []
            record.offset = offset
            intervals.append(record)
            window_tokens = max(window_tokens, record.end)
            end = offset + record.end
            if record.kind == "baseline":
                baseline = max(baseline, end)
            elif record.kind == "owned":
                expected = max(expected, end)
            else:
                excluded[identity] = (record.end - record.start, end)
        response_baseline_tokens = baseline
        expected_response_tokens = expected
        excluded_response_tokens = excluded

    excluded_response_tokens: dict[str, tuple[int, int]] = {}
    local_models: dict[str | None, dict[str, int]] = {}

    previous_turns_reported_cache_writes = True
    previous_unreported_models: set[str | None] = set()

    def begin_turn(turn_id: str | None) -> None:
        nonlocal current_turn_id, current_response_usage_observed, observed_response_usage
        nonlocal turn_legacy_usage, turn_legacy_models, ambiguous_legacy_cache
        nonlocal previous_turns_reported_cache_writes, previous_unreported_models
        if turn_id == current_turn_id:
            return
        if not current_response_usage_observed:
            _add_token_usage(completed_legacy_usage, turn_legacy_usage)
            if ambiguous_legacy_cache:
                warnings.add("token_breakdown_unavailable")
        previous_turns_reported_cache_writes = (
            total.get("cacheWriteInputTokensReported") is not False
        )
        previous_unreported_models = {
            model
            for model, tokens in local_models.items()
            if tokens.get("cacheWriteInputTokensReported") is False
        }
        ambiguous_legacy_cache = False
        observed_response_usage = _empty_token_usage()
        current_response_usage_observed = False
        turn_legacy_usage = _empty_token_usage()
        turn_legacy_models = {}
        current_turn_id = turn_id

    def past_scan_end(timestamp: datetime, turn_id: object) -> bool:
        # The requested completion turn may finish after the scan was marked complete.
        return (
            completed_at is not None
            and timestamp > completed_at
            and (completed_turn_id is None or turn_id != completed_turn_id)
        )

    with _rollout_lines(session.path, verify_end=True) as source:
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
            if event.get("type") in {"session_meta", "turn_context"} and isinstance(payload, dict):
                model = payload.get("model")
                if isinstance(model, str) and model:
                    current_model = model
            if line_number == 1:
                if event.get("type") != "session_meta" or not isinstance(payload, dict):
                    warnings.add("thread_identity_mismatch")
                    return result
                recorded_id = payload.get("id") or payload.get("session_id")
                if recorded_id != session.thread_id:
                    warnings.add("thread_identity_mismatch")
                    return result
                recorded_parent = _session_parent_thread_id(payload)
                if session.parent_thread_id is not None:
                    if recorded_parent != session.parent_thread_id:
                        warnings.add("thread_identity_mismatch")
                        return result
                boundary_reached = (
                    session.parent_thread_id is None
                    and not recorded_parent
                    and not payload.get("forked_from_id")
                )
                direct_control_session = (
                    boundary_reached
                    and is_scan_owner
                    and payload.get("originator") == "codex_security_deep_scan"
                )
                continue

            if not isinstance(payload, dict):
                continue
            if event.get("type") == "turn_context":
                begin_turn(payload.get("turn_id"))
            if not boundary_reached:
                if _is_owned_task_start(session.thread_id, event, payload):
                    task_started_at = _timestamp(event.get("timestamp"))
                    if task_started_at is None:
                        warnings.add("thread_ownership_unavailable")
                        return result
                    if task_started_at < started_at or past_scan_end(
                        task_started_at, payload.get("turn_id")
                    ):
                        warnings.add("thread_outside_scan_window")
                        return result
                    boundary_reached = True
                elif event.get("type") == "event_msg" and payload.get("type") == "token_count":
                    inherited_usage = _token_snapshot(payload)
                    if inherited_usage is not None:
                        missing_cache = _missing_cache_fields(payload)
                        baseline = _retain_cache_baseline(previous, inherited_usage, missing_cache)
                        if baseline is None:
                            warnings.add("token_breakdown_unavailable")
                        else:
                            previous = baseline
                            prefix_unclassified = _uncached_input(baseline)
                            prefix_missing_cache = missing_cache
                        timestamp = _timestamp(event.get("timestamp"))
                        if timestamp is not None:
                            response_counter_baseline = (inherited_usage["totalTokens"], timestamp)
                if not boundary_reached:
                    continue
            if event.get("type") == "event_msg" and payload.get("type") == "task_started":
                # The same owner can resume as a model-backed coordinator. Only
                # a provably post-scan turn leaves the original control zero intact.
                timestamp = _timestamp(event.get("timestamp"))
                if timestamp is None or not past_scan_end(timestamp, payload.get("turn_id")):
                    direct_control_session = False
                if (
                    completed_turn_id is not None
                    and current_turn_id == completed_turn_id
                    and payload.get("turn_id") != completed_turn_id
                ):
                    break
                begin_turn(payload.get("turn_id"))
                if owner_turn_id is not None and current_turn_id != owner_turn_id:
                    continue
                if not isinstance(current_turn_id, str) or not current_turn_id or timestamp is None:
                    warnings.add("turn_record_invalid")
                elif not past_scan_end(timestamp, current_turn_id):
                    started_turns.add(current_turn_id)
                    open_turns.add(current_turn_id)
                continue
            if event.get("type") == "event_msg" and payload.get("type") in {
                "task_complete",
                "turn_aborted",
            }:
                timestamp = _timestamp(event.get("timestamp"))
                terminal_turn_id = payload.get("turn_id") or current_turn_id
                if owner_turn_id is not None and terminal_turn_id != owner_turn_id:
                    continue
                if (
                    not isinstance(terminal_turn_id, str)
                    or not terminal_turn_id
                    or timestamp is None
                ):
                    warnings.add("turn_record_invalid")
                elif not past_scan_end(timestamp, terminal_turn_id):
                    open_turns.discard(terminal_turn_id)
                    if timestamp >= started_at:
                        if terminal_turn_id in started_turns:
                            closed_turns.add(terminal_turn_id)
                        if payload.get("type") == "turn_aborted":
                            warnings.add("turn_interrupted")
            if (
                completed_turn_id is not None
                and event.get("type") == "event_msg"
                and payload.get("type") == "task_complete"
                and payload.get("turn_id") == completed_turn_id
            ):
                break
            if event.get("type") == "compacted":
                after_compaction = True
                timestamp = _timestamp(event.get("timestamp"))
                if (
                    timestamp is not None
                    and timestamp >= started_at
                    and not past_scan_end(timestamp, current_turn_id)
                    and (owner_turn_id is None or current_turn_id == owner_turn_id)
                    and "compaction_response_id" not in payload
                    and not current_response_usage_observed
                ):
                    warnings.add("compaction_usage_unavailable")
                continue
            if event.get("type") == "token_usage_record":
                response_id = payload.get("response_id")
                usage = _token_snapshot({"info": {"total_token_usage": payload.get("usage")}})
                if (
                    not isinstance(response_id, str)
                    or not response_id
                    or usage is None
                    or not isinstance(payload.get("thread_id"), str)
                ):
                    warnings.add("token_record_invalid")
                    continue
                if payload["thread_id"] != session.thread_id or response_id in response_ids:
                    continue
                timestamp = _timestamp(event.get("timestamp"))
                if timestamp is None:
                    warnings.add("token_record_invalid")
                    continue
                cumulative = _token_snapshot(
                    {"info": {"total_token_usage": payload.get("thread_token_usage")}}
                )
                receipt_turn_id = payload.get("turn_id")
                if past_scan_end(timestamp, receipt_turn_id):
                    continue
                if cumulative is not None:
                    record_receipt_counter(
                        response_id,
                        usage["totalTokens"],
                        cumulative["totalTokens"],
                        timestamp,
                        "baseline"
                        if timestamp < started_at
                        else "excluded"
                        if owner_turn_id is not None
                        and payload.get("turn_id", current_turn_id) != owner_turn_id
                        else "owned",
                    )
                turn_usage = _usage_counts(payload.get("turn_token_usage"))
                receipt_turn_id = payload.get("turn_id")
                if owner_turn_id is None or receipt_turn_id == owner_turn_id:
                    if isinstance(receipt_turn_id, str):
                        measured_turns.add(receipt_turn_id)
                    if current_turn_id is None:
                        current_turn_id = receipt_turn_id
                        if isinstance(current_turn_id, str):
                            open_turns.add(current_turn_id)
                    _add_token_usage(observed_response_usage, usage)
                if timestamp < started_at:
                    if turn_usage is not None:
                        observed_response_usage = turn_usage
                    continue
                if (
                    owner_turn_id is not None
                    and payload.get("turn_id", current_turn_id) != owner_turn_id
                ):
                    continue
                response_ids.add(response_id)
                if accepted_response_ids is not None:
                    accepted_response_ids.add(response_id)
                if not current_response_usage_observed:
                    current_response_usage_observed = True
                    for key in TOKEN_FIELDS.values():
                        total[key] -= turn_legacy_usage[key]
                    if previous_turns_reported_cache_writes:
                        total.pop("cacheWriteInputTokensReported", None)
                    for model, tokens in turn_legacy_models.items():
                        if model not in previous_unreported_models:
                            local_models[model].pop("cacheWriteInputTokensReported", None)
                        for key in TOKEN_FIELDS.values():
                            local_models[model][key] -= tokens[key]
                    local_models = {
                        model: tokens
                        for model, tokens in local_models.items()
                        if any(tokens.values())
                    }
                response_usage_observed = True
                if completed_turn_id is not None and receipt_turn_id == completed_turn_id:
                    completed_turn_measured = True
                if turn_usage is not None and any(
                    turn_usage[key] > observed_response_usage[key] for key in TOKEN_FIELDS.values()
                ):
                    warnings.add("token_record_incomplete")
                result.tokens_updated_at = max(result.tokens_updated_at or timestamp, timestamp)
                response_tokens += usage["totalTokens"]
                usage_observed = True
                model = payload.get("model", current_model)
                if not isinstance(model, str):
                    model = None
                _add_token_usage(total, usage)
                _add_token_usage(local_models.setdefault(model, _empty_token_usage()), usage)
                continue
            if event.get("type") != "event_msg" or payload.get("type") != "token_count":
                continue
            timestamp = _timestamp(event.get("timestamp"))
            in_window = (
                timestamp is not None
                and timestamp >= started_at
                and not past_scan_end(timestamp, current_turn_id)
                and (owner_turn_id is None or current_turn_id == owner_turn_id)
            )
            if in_window:
                limits = _rate_limit_snapshot(payload.get("rate_limits"), timestamp)
                if limits is not None:
                    key = limits["limitId"]
                    if (
                        key not in result.rate_limits
                        or limits["observedAt"] >= result.rate_limits[key]["observedAt"]
                    ):
                        result.rate_limits[key] = limits
            # Native rate-limit updates can carry no token usage.
            if "info" in payload and payload["info"] is None:
                continue
            snapshot = _token_snapshot(payload)
            if timestamp is None or snapshot is None:
                warnings.add("token_record_invalid")
                continue
            reset = snapshot["totalTokens"] < previous["totalTokens"]
            if reset and after_compaction:
                previous = _empty_token_usage()
                previous_cache_writes_reported = True
                prefix_unclassified = 0
                prefix_missing_cache.clear()
                reset = False
            after_compaction = False
            if (
                reset
                and current_turn_id is not None
                and (owner_turn_id is None or owner_turn_id == current_turn_id)
                and timestamp >= started_at
                and not past_scan_end(timestamp, current_turn_id)
            ):
                warnings.add("token_counter_regressed")
                continue
            if reset:
                prefix_unclassified = 0
            missing_cache = _missing_cache_fields(payload)
            cache_writes_reported = "cacheWriteInputTokens" not in missing_cache
            baseline = _retain_cache_baseline(previous, snapshot, missing_cache)
            if baseline is None:
                if not past_scan_end(timestamp, current_turn_id):
                    warnings.add("token_breakdown_unavailable")
                continue
            if baseline is previous:
                cache_writes_reported = previous_cache_writes_reported and cache_writes_reported
            refines_classification = (
                baseline["inputTokens"] >= previous["inputTokens"]
                and baseline["outputTokens"] >= previous["outputTokens"]
                and baseline["cachedInputTokens"] >= previous["cachedInputTokens"]
                and baseline["cacheWriteInputTokens"] >= previous["cacheWriteInputTokens"]
                and (
                    (not previous_cache_writes_reported and cache_writes_reported)
                    or baseline["cachedInputTokens"] > previous["cachedInputTokens"]
                    or baseline["cacheWriteInputTokens"] > previous["cacheWriteInputTokens"]
                )
            )
            previous_cache_writes_reported = cache_writes_reported
            delta = {
                key: snapshot[key] - previous[key]
                if not reset and snapshot[key] >= previous[key]
                else snapshot[key]
                for key in TOKEN_FIELDS.values()
            }
            if (
                snapshot.get("cacheWriteInputTokensReported") is False
                or previous.get("cacheWriteInputTokensReported") is False
            ):
                delta["cacheWriteInputTokensReported"] = False
            previous = baseline
            if past_scan_end(timestamp, current_turn_id):
                continue
            if isinstance(current_turn_id, str) and (
                owner_turn_id is None or current_turn_id == owner_turn_id
            ):
                measured_turns.add(current_turn_id)
            if timestamp < started_at:
                prefix_unclassified = _uncached_input(baseline)
                prefix_missing_cache = missing_cache
                response_baseline_tokens = snapshot["totalTokens"]
                response_counter_baseline = (snapshot["totalTokens"], timestamp)
                response_counter_records.clear()
                continue
            if owner_turn_id is not None and current_turn_id != owner_turn_id:
                continue
            is_completion_turn = (
                completed_turn_id is not None and current_turn_id == completed_turn_id
            )
            usage_observed = True
            if is_completion_turn:
                completed_turn_measured = True
            result.tokens_updated_at = max(result.tokens_updated_at or timestamp, timestamp)
            delta["totalTokens"] = delta["inputTokens"] + delta["outputTokens"]
            if not current_response_usage_observed:
                local_models.setdefault(current_model, _empty_token_usage())
            if delta["totalTokens"] <= 0 and not refines_classification:
                continue
            cache_write_capacity = (
                _uncached_input(turn_legacy_usage) + delta["inputTokens"]
                if refines_classification
                else delta["inputTokens"]
            )
            # Late cumulative cache details can classify an earlier legacy turn.
            completed_capacity = (
                _uncached_input(completed_legacy_usage)
                if refines_classification and not current_response_usage_observed
                else 0
            )
            if (
                prefix_unclassified > 0
                and refines_classification
                and (
                    any(delta[key] > 0 for key in prefix_missing_cache)
                    # Even explicit counters can revise earlier input when the
                    # newly classified tokens exceed all in-scan capacity.
                    or delta["cachedInputTokens"] + delta["cacheWriteInputTokens"]
                    > cache_write_capacity + completed_capacity
                )
            ):
                # The newly classified tokens could have occurred before this scan.
                ambiguous_legacy_cache = True
            for key in ("cacheWriteInputTokens", "cachedInputTokens"):
                current = min(delta[key], cache_write_capacity)
                completed = min(delta[key] - current, completed_capacity)
                if completed and ambiguous_legacy_cache:
                    warnings.add("token_breakdown_unavailable")
                delta[key] = current
                cache_write_capacity -= current
                completed_capacity -= completed
                completed_legacy_usage[key] += completed
                total[key] += completed
            delta["reasoningOutputTokens"] = min(
                delta["reasoningOutputTokens"], delta["outputTokens"]
            )
            _add_token_usage(counter_total, delta)
            if not current_response_usage_observed:
                _add_token_usage(turn_legacy_usage, delta)
                _add_token_usage(
                    turn_legacy_models.setdefault(current_model, _empty_token_usage()), delta
                )
                _add_token_usage(total, delta)
                _add_token_usage(
                    local_models.setdefault(current_model, _empty_token_usage()), delta
                )

    if not current_response_usage_observed and ambiguous_legacy_cache:
        warnings.add("token_breakdown_unavailable")
    reconcile_receipt_counters()

    if (
        counter_total["inputTokens"] > total["inputTokens"]
        or counter_total["outputTokens"] > total["outputTokens"]
    ):
        remainder = {key: max(0, counter_total[key] - total[key]) for key in TOKEN_FIELDS.values()}
        remainder["totalTokens"] = remainder["inputTokens"] + remainder["outputTokens"]
        if (
            remainder["cachedInputTokens"] + remainder["cacheWriteInputTokens"]
            > remainder["inputTokens"]
        ):
            # Conflicting cache categories cannot classify the additional input.
            remainder["cachedInputTokens"] = remainder["cacheWriteInputTokens"] = 0
        _add_token_usage(total, remainder)
        _add_token_usage(local_models.setdefault(None, _empty_token_usage()), remainder)
        if response_usage_observed and remainder["totalTokens"]:
            warnings.add("token_receipts_incomplete")
    if response_usage_observed:
        warnings.discard("token_counter_regressed")
    if (
        expected_response_tokens
        - response_baseline_tokens
        - sum(
            tokens
            for tokens, cumulative in excluded_response_tokens.values()
            if response_baseline_tokens < cumulative <= expected_response_tokens
        )
        > response_tokens
    ):
        if "token_record_incomplete" not in warnings:
            warnings.add("token_receipts_incomplete")
    if model_usage is not None:
        for model, usage in local_models.items():
            _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), usage)
    if not boundary_reached:
        warnings.add("thread_ownership_unavailable")
    elif not usage_observed and not direct_control_session:
        warnings.add("token_usage_unavailable")
    if completed_turn_id is not None:
        open_turns.discard(completed_turn_id)
    if open_turns:
        warnings.add("turn_in_progress")
    if boundary_reached and result.tokens_updated_at is None and not direct_control_session:
        warnings.add("token_record_missing")
    if closed_turns - measured_turns:
        warnings.add("token_record_missing")
    if completed_turn_id is not None and not completed_turn_measured:
        warnings.add("completion_turn_unavailable")
    return result


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


def _missing_cache_fields(payload: Mapping[str, Any]) -> set[str]:
    usage = payload["info"]["total_token_usage"]
    missing: set[str] = set()
    if "cached_input_tokens" not in usage:
        missing.add("cachedInputTokens")
    if "cache_write_input_tokens" not in usage and "cache_write_tokens" not in usage:
        missing.add("cacheWriteInputTokens")
    return missing


def _uncached_input(usage: dict[str, int]) -> int:
    return usage["inputTokens"] - usage["cachedInputTokens"] - usage["cacheWriteInputTokens"]


def _retain_cache_baseline(
    previous: dict[str, int], snapshot: dict[str, int], missing: set[str]
) -> dict[str, int] | None:
    baseline = snapshot
    if (
        missing
        and snapshot["inputTokens"] >= previous["inputTokens"]
        and snapshot["outputTokens"] >= previous["outputTokens"]
    ):
        baseline = {**snapshot, **{key: previous[key] for key in missing}}
        if (
            baseline["cachedInputTokens"] + baseline["cacheWriteInputTokens"]
            > baseline["inputTokens"]
        ):
            return None
    if (
        baseline["inputTokens"] == previous["inputTokens"]
        and baseline["outputTokens"] == previous["outputTokens"]
        and (
            baseline["cachedInputTokens"] < previous["cachedInputTokens"]
            or baseline["cacheWriteInputTokens"] < previous["cacheWriteInputTokens"]
        )
    ):
        return previous
    return baseline


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
    return _usage_counts(info.get("total_token_usage"))


def _usage_counts(usage: object) -> dict[str, int] | None:
    if not isinstance(usage, dict):
        return None
    cache_write = usage.get("cache_write_input_tokens", usage.get("cache_write_tokens", 0))
    legacy_cache_write = usage.get("cache_write_tokens")
    input_tokens = usage.get("input_tokens")
    cached_input_tokens = usage.get("cached_input_tokens", 0)
    if (
        type(cache_write) is int
        and cache_write == 0
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
    if (
        usage.get("cache_write_input_tokens_reported") is False
        or usage.get("cache_write_input_tokens") is None
        and usage.get("cache_write_tokens") is None
    ):
        result["cacheWriteInputTokensReported"] = False
    return result


def _empty_token_usage() -> dict[str, int]:
    return {field: 0 for field in TOKEN_FIELDS.values()}


def _add_token_usage(target: dict[str, int], addition: Mapping[str, int]) -> None:
    for key in TOKEN_FIELDS.values():
        target[key] += addition[key]
    if addition.get("cacheWriteInputTokensReported") is False:
        target["cacheWriteInputTokensReported"] = False


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = (
            datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
            if value.endswith("Z")
            else datetime.fromisoformat(value)
        )
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _unavailable_usage(
    reason: str,
    *,
    warnings: set[str] | None = None,
    rate_limits: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": sorted({reason, *(warnings or set())}),
    }
    if rate_limits:
        result["accountRateLimits"] = [rate_limits[key] for key in sorted(rate_limits)]
    return result


def _reject_nonstandard_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
