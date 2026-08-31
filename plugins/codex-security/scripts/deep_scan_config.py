"""Resolve per-user Codex Security Deep Scan orchestration settings."""

from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

DEFAULT_WORKERS = 4
DEFAULT_SUBAGENTS = 3
DEFAULT_STOP_AFTER_NO_NEW = 4
DEFAULT_STOP_AFTER_CONSECUTIVE_ERRORS = 3
DEFAULT_MAX_DISCOVERY_RUNS = 40
DEFAULT_MAX_TIME_HOURS = 96
MAX_TIME_HOURS = 96
CONFIG_KEYS = {
    "workers",
    "subagents",
    "stop_after_no_new",
    "stop_after_consecutive_errors",
    "max_discovery_runs",
    "max_time_hours",
}


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()


def config_path() -> Path:
    configured = os.environ.get("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return codex_home() / "codex-security" / "config.toml"


def resolve_deep_scan_config(available_parallelism: int) -> dict[str, int | float]:
    if isinstance(available_parallelism, bool) or available_parallelism < 1:
        raise SystemExit("Available parallelism must be a positive integer.")
    path = config_path()
    configured: dict[str, Any] = {}
    if path.exists():
        try:
            with path.open("rb") as source:
                document: object = tomllib.load(source)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise SystemExit(f"Cannot read Codex Security configuration at {path}: {exc}") from exc
        if not isinstance(document, dict):
            raise SystemExit(f"Codex Security configuration at {path} must be a TOML table.")
        deep_scan: object = document.get("deep_scan", {})
        if not isinstance(deep_scan, dict):
            raise SystemExit(
                f"Codex Security configuration [deep_scan] at {path} must be a TOML table."
            )
        unknown = sorted(set(deep_scan) - CONFIG_KEYS)
        if unknown:
            raise SystemExit(
                f"Unknown Codex Security Deep Scan configuration {', '.join(unknown)} in {path}."
            )
        configured = deep_scan

    workers: object = configured.get("workers", DEFAULT_WORKERS)
    if workers == "auto":
        resolved_workers = DEFAULT_WORKERS
    else:
        resolved_workers = require_integer(workers, "deep_scan.workers", minimum=1)
    stop_after_no_new = require_integer(
        configured.get("stop_after_no_new", DEFAULT_STOP_AFTER_NO_NEW),
        "deep_scan.stop_after_no_new",
        minimum=1,
    )
    return {
        "workers": resolved_workers,
        "subagents": require_integer(
            configured.get("subagents", DEFAULT_SUBAGENTS),
            "deep_scan.subagents",
            minimum=0,
        ),
        "stopAfterNoNew": stop_after_no_new,
        "stopAfterConsecutiveErrors": require_integer(
            configured.get("stop_after_consecutive_errors", DEFAULT_STOP_AFTER_CONSECUTIVE_ERRORS),
            "deep_scan.stop_after_consecutive_errors",
            minimum=1,
        ),
        "maxDiscoveryRuns": require_integer(
            configured.get("max_discovery_runs", DEFAULT_MAX_DISCOVERY_RUNS),
            "deep_scan.max_discovery_runs",
            minimum=1,
        ),
        "maxTimeHours": require_positive_number(
            configured.get("max_time_hours", DEFAULT_MAX_TIME_HOURS),
            "deep_scan.max_time_hours",
        ),
    }


def require_integer(value: object, label: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = (
            "a non-negative integer"
            if minimum == 0
            else "a positive integer"
            if minimum == 1
            else f"an integer of at least {minimum}"
        )
        raise SystemExit(f"{label} must be {qualifier}.")
    return value


def require_positive_number(value: object, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SystemExit(f"{label} must be a positive finite number no greater than 96.")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite or value <= 0 or value > MAX_TIME_HOURS:
        raise SystemExit(f"{label} must be a positive finite number no greater than 96.")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--available-parallelism", type=int, required=True)
    args = parser.parse_args()
    import json

    print(json.dumps(resolve_deep_scan_config(args.available_parallelism), sort_keys=True))


if __name__ == "__main__":
    main()
