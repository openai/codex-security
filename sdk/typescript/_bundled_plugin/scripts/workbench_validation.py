"""Shared validation helpers for Codex Security workbench commands."""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_constants import (
    MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES,
    MAX_CAPABILITY_PREFLIGHT_PERSISTED_JSON_BYTES,
)


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


def require_close_reason(close_reason: str | None, note: str | None) -> None:
    if note is None and close_reason == "false_positive":
        raise SystemExit("Explain why this finding is a false positive.")
    if note is None and close_reason == "wont_fix":
        raise SystemExit("Explain why this finding will not be fixed.")


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


def capability_preflight_json(
    value: str | None,
    *,
    checked_target_path: str | None,
    checked_mode: str,
) -> str | None:
    normalized = optional_text(value)
    if normalized is None:
        return None
    if len(normalized.encode("utf-8")) > MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES:
        raise SystemExit(
            "Capability preflight must be no larger than "
            f"{MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES} bytes."
        )
    try:
        payload = json.loads(normalized, parse_constant=reject_nonstandard_json_number)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("Capability preflight must be valid JSON.") from exc
    if not isinstance(payload, dict):
        raise SystemExit("Capability preflight must be a JSON object.")
    _require_object_keys(
        payload,
        required={"issues", "profile", "status"},
        optional={"remediation"},
        label="Capability preflight",
    )
    profile = _bounded_preflight_text(payload.get("profile"), 128, "profile")
    status = payload.get("status")
    if status not in {"ready", "blocked", "incomplete"}:
        raise SystemExit("Capability preflight status is invalid.")
    issues = payload.get("issues")
    if not isinstance(issues, list) or len(issues) > 32:
        raise SystemExit("Capability preflight issues must be an array of at most 32 objects.")
    normalized_issues: list[dict[str, str]] = []
    for index, issue in enumerate(issues):
        if not isinstance(issue, dict):
            raise SystemExit("Capability preflight issues must be an array of at most 32 objects.")
        label = f"Capability preflight issue {index + 1}"
        _require_object_keys(
            issue,
            required={"capability", "reason", "severity", "status"},
            optional=set(),
            label=label,
        )
        severity = issue.get("severity")
        issue_status = issue.get("status")
        if severity not in {"block", "warn", "suggest"} or issue_status not in {
            "fail",
            "unknown",
        }:
            raise SystemExit(f"{label} has an invalid severity or status.")
        normalized_issues.append(
            {
                "capability": _bounded_preflight_text(
                    issue.get("capability"), 128, f"issue {index + 1} capability"
                ),
                "reason": _bounded_preflight_text(
                    issue.get("reason"), 1200, f"issue {index + 1} reason"
                ),
                "severity": severity,
                "status": issue_status,
            }
        )
    remediation = payload.get("remediation")
    normalized_remediation: dict[str, Any] | None = None
    if remediation is not None:
        if not isinstance(remediation, dict):
            raise SystemExit("Capability preflight remediation must be a JSON object.")
        _require_object_keys(
            remediation,
            required=set(),
            optional={"note", "patches", "summary"},
            label="Capability preflight remediation",
        )
        normalized_remediation = {}
        for key, maximum in (("note", 2400), ("summary", 1200)):
            if key in remediation:
                normalized_remediation[key] = _bounded_preflight_text(
                    remediation.get(key), maximum, f"remediation {key}"
                )
        if "patches" in remediation:
            patches = remediation.get("patches")
            if not isinstance(patches, list) or len(patches) > 32:
                raise SystemExit(
                    "Capability preflight remediation patches must be an array of at most 32 objects."
                )
            normalized_remediation["patches"] = [
                _normalize_preflight_patch(patch, index) for index, patch in enumerate(patches)
            ]
    has_unknown = any(issue.get("status") == "unknown" for issue in issues)
    has_blocking_failure = any(
        issue.get("severity") == "block" and issue.get("status") == "fail" for issue in issues
    )
    expected_status = (
        "blocked" if has_blocking_failure else "incomplete" if has_unknown else "ready"
    )
    if status != expected_status:
        raise SystemExit(
            f"Capability preflight status must be {expected_status} for the supplied issues."
        )
    normalized_payload: dict[str, Any] = {
        "profile": profile,
        "status": status,
        "issues": normalized_issues,
        "checkedTargetPath": checked_target_path,
        "checkedMode": checked_mode,
    }
    if normalized_remediation is not None:
        normalized_payload["remediation"] = normalized_remediation
    serialized = json.dumps(
        normalized_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    serialized = _escape_json_surrogates(serialized)
    if len(serialized.encode("utf-8")) > MAX_CAPABILITY_PREFLIGHT_PERSISTED_JSON_BYTES:
        raise SystemExit(
            "Persisted capability preflight must be no larger than "
            f"{MAX_CAPABILITY_PREFLIGHT_PERSISTED_JSON_BYTES} bytes."
        )
    return serialized


def capability_preflight_input(value: str | None, path: Path | None) -> str | None:
    if path is None:
        return value
    try:
        if path.stat().st_size > MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES:
            raise SystemExit(
                "Capability preflight must be no larger than "
                f"{MAX_CAPABILITY_PREFLIGHT_INPUT_JSON_BYTES} bytes."
            )
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SystemExit("Capability preflight JSON file could not be read as UTF-8.") from exc


def _require_object_keys(
    value: dict[str, Any], *, required: set[str], optional: set[str], label: str
) -> None:
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise SystemExit(f"{label} is missing required fields: {', '.join(sorted(missing))}.")
    if extra:
        raise SystemExit(f"{label} has unsupported fields: {', '.join(sorted(extra))}.")


def _bounded_preflight_text(value: Any, maximum: int, label: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"Capability preflight {label} must be text.")
    normalized = value.strip()
    if not normalized or _javascript_string_length(normalized) > maximum:
        raise SystemExit(f"Capability preflight {label} must contain 1 to {maximum} characters.")
    return normalized


def _javascript_string_length(value: str) -> int:
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def _escape_json_surrogates(value: str) -> str:
    return "".join(
        f"\\u{ord(character):04x}" if 0xD800 <= ord(character) <= 0xDFFF else character
        for character in value
    )


def _normalize_preflight_patch(value: Any, index: int) -> dict[str, Any]:
    label = f"Capability preflight remediation patch {index + 1}"
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object.")
    _require_object_keys(
        value,
        required={"path", "value"},
        optional={"kind"},
        label=label,
    )
    normalized: dict[str, Any] = {
        "path": _bounded_preflight_text(value.get("path"), 256, f"patch {index + 1} path")
    }
    if "kind" in value:
        kind = value.get("kind")
        if kind not in {"config", "host_setting"}:
            raise SystemExit(f"{label} has an invalid kind.")
        normalized["kind"] = kind
    patch_value = value.get("value")
    if isinstance(patch_value, str):
        if _javascript_string_length(patch_value) > 2048:
            raise SystemExit(f"{label} value must be no longer than 2048 characters.")
    elif isinstance(patch_value, bool):
        pass
    elif isinstance(patch_value, (int, float)):
        try:
            finite = math.isfinite(float(patch_value))
        except OverflowError:
            finite = False
        if not finite:
            raise SystemExit(f"{label} value must be a finite number.")
    else:
        raise SystemExit(f"{label} value must be text, a number, or a boolean.")
    normalized["value"] = patch_value
    return normalized


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
