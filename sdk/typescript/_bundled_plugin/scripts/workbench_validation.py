"""Shared validation helpers for Codex Security workbench commands."""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))


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


def path_within_scope(path: str, scope: str) -> bool:
    candidate = PurePosixPath(path)
    requested = PurePosixPath(scope)
    if candidate.is_absolute() or ".." in candidate.parts:
        return False
    if requested == PurePosixPath("."):
        return True
    return candidate == requested or requested in candidate.parents


def require_close_note(close_reason: str | None, note: str | None) -> None:
    if note is None and close_reason == "false_positive":
        raise SystemExit("Explain why this finding is a false positive.")
    if note is None and close_reason == "wont_fix":
        raise SystemExit("Explain why this finding will not be fixed.")


def user_text(value: str | None) -> str | None:
    return optional_text(value)


def reject_nonstandard_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


SCAN_USAGE_TOKEN_KEYS = (
    "inputTokens",
    "cachedInputTokens",
    "cacheWriteInputTokens",
    "outputTokens",
    "reasoningOutputTokens",
    "totalTokens",
)


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


def _valid_scan_token_counts(usage: object) -> bool:
    return (
        isinstance(usage, dict)
        and set(usage) == set(SCAN_USAGE_TOKEN_KEYS)
        and all(type(usage.get(key)) is int and usage[key] >= 0 for key in SCAN_USAGE_TOKEN_KEYS)
        and usage["cachedInputTokens"] + usage["cacheWriteInputTokens"] <= usage["inputTokens"]
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
            {"coverage", "source", "threadCount", "warnings"}
        )

    allowed_keys = {
        "coverage",
        "source",
        "threadCount",
        "missingThreadCount",
        "warnings",
        *SCAN_USAGE_TOKEN_KEYS,
    }
    if thread_count == 0 or not set(usage).issubset(allowed_keys):
        return False
    counts = {key: usage.get(key) for key in SCAN_USAGE_TOKEN_KEYS}
    if not _valid_scan_token_counts(counts):
        return False
    missing = usage.get("missingThreadCount", 0)
    if type(missing) is not int or missing < 0:
        return False
    if coverage == "complete" and (warnings or missing):
        return False
    if coverage == "partial" and not (warnings or missing):
        return False
    return True


def parse_scan_cost(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value.encode("utf-8")) > 8192:
        raise SystemExit("Scan cost must be no larger than 8 KiB.")
    try:
        cost = json.loads(value, parse_constant=reject_nonstandard_json_number)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise SystemExit("Scan cost must be a valid JSON object.") from exc
    if isinstance(cost, dict) and "usage" in cost:
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


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
