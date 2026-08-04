#!/usr/bin/env python3
"""Evaluate Claude Security capability profiles against the current session.

The Codex original discovered and layered `config.toml` files to decide whether
sandboxing, approval policy, and native multi-agent v2 were configured
correctly. Claude Code exposes none of that as user configuration, so this
rewrite evaluates only facts the caller can actually observe about its own
session: which tools are on its tool surface, and which plugin skills it can
name. Everything the caller does not assert stays `unknown` rather than being
guessed, and an unknown value never counts as satisfied.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = PLUGIN_ROOT / "preflight" / "capability-profiles.toml"
SEVERITIES = ("block", "warn", "suggest")


def load_registry(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            document = tomllib.load(source)
    except OSError as exc:
        raise SystemExit(f"Cannot read capability profiles at {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"Capability profiles at {path} are not valid TOML: {exc}") from exc
    if not isinstance(document, dict):
        raise SystemExit(f"Capability profiles at {path} must be a TOML table.")
    return document


def parse_runtime_checks(values: list[str]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for value in values:
        name, separator, raw = value.partition("=")
        if not separator or not name.strip():
            raise SystemExit(
                f"--runtime-check must be name=true or name=false, got: {value!r}"
            )
        normalized = raw.strip().lower()
        if normalized not in {"true", "false"}:
            raise SystemExit(
                f"--runtime-check {name.strip()} must be true or false, got: {raw!r}"
            )
        checks[name.strip()] = normalized == "true"
    return checks


def evaluate_capability(
    name: str,
    definition: dict[str, Any],
    runtime_checks: dict[str, bool],
    available_skills: list[str] | None,
) -> dict[str, Any]:
    kind = definition.get("kind")
    reason = definition.get("reason", "")

    if kind == "runtime":
        if name not in runtime_checks:
            return {
                "capability": name,
                "kind": kind,
                "status": "unknown",
                "reason": reason,
                "detail": (
                    f"Pass --runtime-check {name}=true or {name}=false after inspecting the "
                    "current tool surface."
                ),
            }
        satisfied = runtime_checks[name]
        return {
            "capability": name,
            "kind": kind,
            "status": "pass" if satisfied else "fail",
            "reason": reason,
            "detail": "Reported available by the caller."
            if satisfied
            else "Reported unavailable by the caller.",
        }

    if kind == "plugin_skills":
        required = [str(value) for value in definition.get("required", [])]
        if available_skills is None:
            return {
                "capability": name,
                "kind": kind,
                "status": "unknown",
                "reason": reason,
                "detail": (
                    "Pass --available-plugin-skill for each claude-security skill this session "
                    "actually exposes. A missing list is not evidence that the skills exist."
                ),
                "requiredSkills": required,
            }
        missing = [skill for skill in required if skill not in available_skills]
        return {
            "capability": name,
            "kind": kind,
            "status": "pass" if not missing else "fail",
            "reason": reason,
            "detail": "All required phase skills are available."
            if not missing
            else f"Missing plugin skills: {', '.join(missing)}.",
            "requiredSkills": required,
            "missingSkills": missing,
        }

    return {
        "capability": name,
        "kind": kind,
        "status": "unknown",
        "reason": reason,
        "detail": f"Unsupported capability kind: {kind!r}.",
    }


def overall_status(results: list[dict[str, Any]]) -> str:
    if any(item["severity"] == "block" and item["status"] == "fail" for item in results):
        return "blocked"
    if any(item["severity"] == "block" and item["status"] == "unknown" for item in results):
        return "incomplete"
    return "ready"


def remediation_for(result: dict[str, Any]) -> str | None:
    if result["status"] == "pass":
        return None
    if result["capability"] == "delegated_workers":
        return (
            "Run every phase in this session instead of delegating. Coverage is unchanged; "
            "the scan is slower and uses more parent context."
        )
    if result["capability"] == "shell_commands":
        return (
            "Skip the optional ranking, inventory, and preview helpers and review files "
            "directly. Record the skipped helpers in coverage limitations."
        )
    if result["capability"] == "deep_scan_phase_skills":
        return (
            "Start the scan through the claude-security CLI so the plugin is loaded with "
            "--plugin-dir, which registers every phase skill."
        )
    if result["capability"] in {"repository_tools", "write_scan_artifacts"}:
        return (
            "This session cannot perform a scan. Re-run through the claude-security CLI, which "
            "grants read, write, and search access to the scan directory and repository."
        )
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--cwd", default=None, help="Accepted for compatibility; unused.")
    parser.add_argument("--runtime-check", action="append", default=[])
    parser.add_argument("--available-plugin-skill", action="append", default=None)
    parser.add_argument("--profiles-path", type=Path, default=PROFILE_PATH)
    arguments = parser.parse_args()

    registry = load_registry(arguments.profiles_path)
    profiles = registry.get("profiles", {})
    if arguments.profile not in profiles:
        raise SystemExit(
            f"Unknown capability profile {arguments.profile!r}. "
            f"Available: {', '.join(sorted(profiles))}."
        )
    profile = profiles[arguments.profile]
    capabilities = registry.get("capabilities", {})
    runtime_checks = parse_runtime_checks(arguments.runtime_check)
    available_skills = arguments.available_plugin_skill

    results: list[dict[str, Any]] = []
    for requirement in profile.get("requirements", []):
        name = requirement.get("capability")
        severity = requirement.get("severity", "warn")
        if severity not in SEVERITIES:
            raise SystemExit(f"Requirement {name!r} has an unsupported severity {severity!r}.")
        definition = capabilities.get(name)
        if definition is None:
            raise SystemExit(f"Profile {arguments.profile!r} references unknown capability {name!r}.")
        evaluated = evaluate_capability(name, definition, runtime_checks, available_skills)
        evaluated["severity"] = severity
        remediation = remediation_for(evaluated)
        if remediation is not None:
            evaluated["remediation"] = remediation
        results.append(evaluated)

    payload = {
        "documentType": "claude-security.capability-preflight",
        "schemaVersion": "1.0",
        "profile": arguments.profile,
        "description": profile.get("description", ""),
        "status": overall_status(results),
        "results": results,
    }
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
