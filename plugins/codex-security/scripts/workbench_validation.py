"""Shared validation helpers for Codex Security workbench commands."""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import finalize_scan_contract as finalizer
from workbench_scan_usage import TOKEN_FIELDS
from workbench_scan_usage import (
    _reject_nonstandard_json_number as reject_nonstandard_json_number,
)

reject_non_finite_json = finalizer._reject_non_finite_json


def timestamp_key(value: str) -> datetime:
    return finalizer.parse_timestamp(value)


def require_uuid(value: str, label: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise SystemExit(f"{label} must be a UUID.") from exc


def optional_text(value: str | None, *, maximum: int | None = None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if maximum is not None and len(normalized) > maximum:
        raise SystemExit(f"Text value must be no longer than {maximum} characters.")
    return normalized or None


def sqlite_busy(error: sqlite3.OperationalError) -> bool:
    return "locked" in str(error).lower() or "busy" in str(error).lower()


path_within_scope = finalizer.path_within_scope


def latest_publication_reducer(db: Any, connection: Any, scan_id: str) -> Any | None:
    # Publication follows the durable reducer sequence, not completion timestamps.
    def reducer_order(worker: Any) -> tuple[int, str]:
        match = re.fullmatch(r"dedup-([0-9]+)", Path(worker["prompt_path"]).parent.name)
        return (int(match[1]) if match else 0, worker["id"])

    return max(
        (
            worker
            for worker in db.saved_results._saved_workers(connection, scan_id)
            if worker["kind"] == "dedup"
            and worker["status"] == "succeeded"
            and worker["result_manifest_path"]
        ),
        key=reducer_order,
        default=None,
    )


def has_verified_selected_result(
    db: Any, connection: Any, scan: Any, *, reducer: Any = None
) -> bool:
    """Verify persisted Deep publication authority before using the artifact read contract."""
    if scan["mode"] != "deep":
        return False
    run = db.deep_scan.find_supported_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run) if run is not None else None
    try:
        if selection is not None:
            db.saved_results._require_selected_result(scan, selection)
            return selection["resultPath"] is not None
        if run is None or run["workflow_version"] not in {
            "deep-scan-mcp/v1",
            "deep-security-scan/v1",
        }:
            return False
        if reducer is None:
            reducer = latest_publication_reducer(db, connection, scan["id"])
        accepted = reducer["accepted_result_path"] if reducer is not None else None
        digests = db.saved_results._accepted_source_digests(connection, scan["id"])
        if accepted is None or accepted not in digests:
            return False
        scan_dir = Path(scan["scan_dir"])
        db.saved_results._read_saved_result(
            scan_dir,
            Path(accepted).relative_to(scan_dir).as_posix(),
            scan["id"],
            kind="dedup",
            accepted_source_digests=digests,
        )
    except (finalizer.ContractError, ValueError) as exc:
        raise finalizer.RecoverableContractError(str(exc)) from exc
    return True


def validate_completed_scan_artifacts(db: Any, scan: sqlite3.Row) -> None:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    db.verify_manifest_binding(scan, db.read_json_object(scan_dir / db.ARTIFACTS["manifest"]))
    try:
        manifest = db._prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
        )[2]
    except db.ContractError as exc:
        raise SystemExit(str(exc)) from exc
    db.verify_manifest_binding(scan, manifest)
    db.published_manifest_digest(scan_dir, manifest)


def require_close_note(close_reason: str | None, note: str | None) -> None:
    if note is None and close_reason == "false_positive":
        raise SystemExit("Explain why this finding is a false positive.")
    if note is None and close_reason == "wont_fix":
        raise SystemExit("Explain why this finding will not be fixed.")


def user_context_argument(args: argparse.Namespace) -> str | None:
    value = sys.stdin.read() if getattr(args, "user_context_stdin", False) else args.user_context
    return optional_text(value)


SCAN_USAGE_TOKEN_KEYS = tuple(TOKEN_FIELDS.values())


def _valid_legacy_scan_cost(cost: object) -> bool:
    token_keys = ("inputTokens", "cachedInputTokens", "cacheWriteInputTokens", "outputTokens")
    return (
        isinstance(cost, dict)
        and isinstance(cost.get("model"), str)
        and bool(cost["model"])
        and all(type(cost.get(key)) is int and cost[key] >= 0 for key in token_keys)
        and cost["cachedInputTokens"] + cost["cacheWriteInputTokens"] <= cost["inputTokens"]
        and type(cost.get("estimatedUsd")) in (int, float)
        and math.isfinite(cost["estimatedUsd"])
        and cost["estimatedUsd"] >= 0
    )


def _valid_measured_scan_usage(usage: object) -> bool:
    if not isinstance(usage, dict):
        return False
    coverage = usage.get("coverage")
    thread_count = usage.get("threadCount")
    if (
        coverage not in {"complete", "partial", "unavailable"}
        or usage.get("source") != "codex_rollout"
        or type(thread_count) is not int
        or thread_count < 0
    ):
        return False
    completion = usage.get("completion")
    if "completion" in usage and (
        not isinstance(completion, dict)
        or set(completion) != {"threadId", "turnId", "finalized"}
        or not isinstance(completion["threadId"], str)
        or not completion["threadId"]
        or not isinstance(completion["turnId"], str)
        or not completion["turnId"]
        or type(completion["finalized"]) is not bool
        or not completion["finalized"]
        and coverage == "complete"
    ):
        return False
    warnings = usage.get("warnings", [])
    if (
        not isinstance(warnings, list)
        or len(warnings) > 32
        or any(
            not isinstance(warning, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", warning) is None
            for warning in warnings
        )
        or len(set(warnings)) != len(warnings)
    ):
        return False
    if coverage == "unavailable":
        return thread_count == 0 and set(usage).issubset(
            {"coverage", "source", "threadCount", "warnings", "completion"}
        )

    allowed_keys = {
        "coverage",
        "source",
        "threadCount",
        "missingThreadCount",
        "warnings",
        "modelUsage",
        "completion",
        *SCAN_USAGE_TOKEN_KEYS,
    }
    if thread_count == 0 or not set(usage).issubset(allowed_keys):
        return False
    if (
        not all(type(usage.get(key)) is int and usage[key] >= 0 for key in SCAN_USAGE_TOKEN_KEYS)
        or usage["cachedInputTokens"] + usage["cacheWriteInputTokens"] > usage["inputTokens"]
    ):
        return False
    if "modelUsage" in usage:
        parts = usage["modelUsage"]
        if not isinstance(parts, list) or not parts:
            return False
        for part in parts:
            if not isinstance(part, dict) or set(part) != {"model", *SCAN_USAGE_TOKEN_KEYS}:
                return False
            if part["model"] is not None and not isinstance(part["model"], str):
                return False
            if (
                not all(type(part[key]) is int and part[key] >= 0 for key in SCAN_USAGE_TOKEN_KEYS)
                or part["cachedInputTokens"] + part["cacheWriteInputTokens"] > part["inputTokens"]
            ):
                return False
        if any(sum(part[key] for part in parts) != usage[key] for key in SCAN_USAGE_TOKEN_KEYS):
            return False
    missing = usage.get("missingThreadCount", 0)
    if type(missing) is not int or missing < 0:
        return False
    if coverage == "complete" and (warnings or missing):
        return False
    if coverage == "partial" and not (warnings or missing):
        return False
    return True


def parse_scan_cost(value: str | None, *, allow_lower_bound: bool = False) -> str | None:
    if value is None:
        return None
    if len(value.encode("utf-8")) > 8192:
        raise SystemExit("Scan cost must be no larger than 8 KiB.")
    try:
        cost = json.loads(value, parse_constant=reject_nonstandard_json_number)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise SystemExit("Scan cost must be a valid JSON object.") from exc
    if allow_lower_bound and isinstance(cost, dict) and set(cost) == {"lowerBound"}:
        if not _valid_legacy_scan_cost(cost["lowerBound"]):
            raise SystemExit("Scan cost lower bound must be a valid measured cost.")
    elif isinstance(cost, dict) and "usage" in cost:
        if (
            not set(cost).issubset({"usage", "cost"})
            or not _valid_measured_scan_usage(cost["usage"])
            or "cost" in cost
            and not _valid_legacy_scan_cost(cost["cost"])
        ):
            raise SystemExit("Scan cost includes invalid measured token usage.")
    elif not _valid_legacy_scan_cost(cost):
        raise SystemExit(
            "Scan cost must include a model, nonnegative token counts, and an estimated USD amount."
        )
    return json.dumps(cost, separators=(",", ":"), allow_nan=False)


def bounded_output_text(value: Any, maximum_bytes: int) -> str:
    encoded = str(value).encode("utf-8")[:maximum_bytes]
    return encoded.decode("utf-8", errors="ignore")


def require_occurrence(connection: sqlite3.Connection, occurrence_id: str) -> sqlite3.Row:
    occurrence_id = optional_text(occurrence_id, maximum=256)
    if occurrence_id is None:
        raise SystemExit("occurrence-id is required.")
    row = connection.execute(
        "SELECT * FROM finding_occurrences WHERE id = ?", (occurrence_id,)
    ).fetchone()
    if row is None:
        raise SystemExit("Codex Security finding occurrence not found.")
    return row


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
