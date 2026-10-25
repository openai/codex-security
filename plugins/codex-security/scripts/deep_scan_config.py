"""Resolve per-user Codex Security Deep Scan orchestration settings."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench.runtime_toml import tomllib

DEFAULTS = json.loads(
    Path(__file__).with_name("deep_scan_defaults.json").read_text(encoding="utf-8")
)
DEFAULT_WORKERS = DEFAULTS["workers"]
DEFAULT_SUBAGENTS = DEFAULTS["subagents"]
DEFAULT_STOP_AFTER_NO_NEW = DEFAULTS["stopAfterNoNew"]
DEFAULT_STOP_AFTER_CONSECUTIVE_ERRORS = DEFAULTS["stopAfterConsecutiveErrors"]
DEFAULT_MAX_DISCOVERY_RUNS = DEFAULTS["maxDiscoveryRuns"]
DEFAULT_MAX_TIME_HOURS = DEFAULTS["maxTimeHours"]
MAX_TIME_HOURS = 96
CONFIG_FIELDS = {
    "workers": "workers",
    "subagents": "subagents",
    "stopAfterNoNew": "stop_after_no_new",
    "stopAfterConsecutiveErrors": "stop_after_consecutive_errors",
    "maxDiscoveryRuns": "max_discovery_runs",
    "maxTimeHours": "max_time_hours",
}
CONFIG_KEYS = set(CONFIG_FIELDS.values())


def codex_home() -> Path:
    return Path(
        os.environ["CODEX_HOME"] if os.environ.get("CODEX_HOME", "").strip() else "~/.codex"
    ).expanduser()


def config_path() -> Path:
    configured = os.environ.get("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return codex_home() / "codex-security" / "config.toml"


def resolve_deep_scan_config(available_parallelism: int) -> dict[str, int | float]:
    return resolve_deep_scan_setup(available_parallelism)["settings"]


def resolve_deep_scan_setup(
    available_parallelism: int, project_json: str | None = None
) -> dict[str, Any]:
    project = json.loads(project_json) if project_json is not None else None
    overrides = project["settings"] if project is not None else {}
    unknown = sorted(set(overrides) - set(CONFIG_FIELDS))
    if unknown:
        raise SystemExit(f"Unknown Deep Scan project settings: {', '.join(unknown)}.")
    if isinstance(available_parallelism, bool) or available_parallelism < 1:
        raise SystemExit("Available parallelism must be a positive integer.")
    path = config_path()
    configured: dict[str, Any] = {}
    exists = path.exists()
    if exists and not all(name in overrides for name in CONFIG_FIELDS):
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

    settings: dict[str, int | float] = {}
    sources: dict[str, str] = {}
    for name, key in CONFIG_FIELDS.items():
        value = overrides.get(name, configured.get(key, DEFAULTS[name]))
        sources[name] = (
            "project" if name in overrides else "legacy" if key in configured else "default"
        )
        if name == "workers" and value == "auto":
            value = DEFAULT_WORKERS
        settings[name] = (
            require_positive_number(value, "deep_scan.max_time_hours")
            if name == "maxTimeHours"
            else require_integer(value, f"deep_scan.{key}", minimum=0 if name == "subagents" else 1)
        )
    return {
        "settings": settings,
        "sources": sources,
        **({"legacyConfigPath": str(path)} if exists else {}),
        **({"projectConfigPath": project["path"]} if project is not None else {}),
    }


def require_integer(value: object, label: str, *, minimum: int) -> int:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
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
    if not 0 < value <= MAX_TIME_HOURS:
        raise SystemExit(f"{label} must be a positive finite number no greater than 96.")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--available-parallelism", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(resolve_deep_scan_config(args.available_parallelism), sort_keys=True))


if __name__ == "__main__":
    main()
