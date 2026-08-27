#!/usr/bin/env python3
"""Evaluate Codex Security capability profiles against the current Codex setup."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = PLUGIN_ROOT / "preflight" / "capability-profiles.toml"
DEFAULT_CODEX_HOME = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()


def default_system_config() -> Path:
    if os.name == "nt":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(program_data) / "OpenAI" / "Codex" / "config.toml"
    return Path("/etc/codex/config.toml")


SYSTEM_CONFIG = default_system_config()
DEFAULT_CONFIG = DEFAULT_CODEX_HOME / "config.toml"
VALID_SEVERITIES = {"block", "warn", "suggest"}
VALID_MULTI_AGENT_OWNERS = {"native", "codex-bridge"}
VALID_MULTI_AGENT_VERSIONS = {"v1", "v2"}
VALID_MULTI_AGENT_PROVENANCE = {
    "app-server",
    "thread-context",
    "tool-surface",
    "verified-bridge",
}
NATIVE_V2_DEFAULT_SESSION_CAP = 4
CONFIG_PROFILE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
# Of the config roots evaluated here, only features is valid in legacy ConfigProfile.
LEGACY_CONFIG_PROFILE_CAPABILITY_FIELDS = {"features"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--profile", help="Capability profile id to evaluate.")
    selector.add_argument(
        "--skill", help="Top-level skill id to resolve through the registry routes."
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
        help="Capability registry path. Defaults to the bundled registry.",
    )
    config_input = parser.add_mutually_exclusive_group()
    config_input.add_argument(
        "--config",
        type=Path,
        action="append",
        help=(
            "Codex config.toml layer, from lower to higher precedence. "
            "Repeat to override automatic cwd-based discovery."
        ),
    )
    parser.add_argument(
        "--cwd",
        type=Path,
        default=Path.cwd(),
        help="Working directory used to discover trusted project config layers.",
    )
    parser.add_argument(
        "--codex-config-profile",
        help="Selected Codex config profile name, when the session uses one.",
    )
    parser.add_argument(
        "--multi-agent-runtime-owner",
        choices=sorted(VALID_MULTI_AGENT_OWNERS),
        help=(
            "Verified owner of the active multi-agent runtime. Do not infer bridge "
            "ownership from a backend_config value alone."
        ),
    )
    parser.add_argument(
        "--multi-agent-runtime-version",
        choices=sorted(VALID_MULTI_AGENT_VERSIONS),
        help="Version exposed by the active multi-agent tool surface.",
    )
    parser.add_argument(
        "--multi-agent-session-cap",
        type=positive_int,
        help="Resolved V2 session cap from the active runtime; includes the root thread.",
    )
    parser.add_argument(
        "--multi-agent-runtime-provenance",
        choices=sorted(VALID_MULTI_AGENT_PROVENANCE),
        help="Evidence source for explicitly supplied multi-agent runtime facts.",
    )
    parser.add_argument(
        "--runtime-check",
        action="append",
        default=[],
        metavar="NAME=BOOL",
        help="Known runtime capability, such as delegation_available=true.",
    )
    parser.add_argument(
        "--available-plugin-skill",
        action="append",
        metavar="SKILL_NAME",
        help=(
            "Plugin-local skill name exposed by the current runtime, such as "
            "security-scan. Repeat only for skills from the capability's plugin."
        ),
    )
    parser.add_argument(
        "--effective-config",
        action="append",
        default=[],
        metavar="PATH=JSON",
        help="Known effective config value, such as agents.max_threads=8.",
    )
    return parser.parse_args()


def read_toml(path: Path, *, required: bool) -> dict[str, Any]:
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except FileNotFoundError:
        if required:
            raise
        return {}


def parse_bool(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError(f"expected true or false, got {value!r}")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def parse_assignment(raw: str) -> tuple[str, str]:
    key, separator, value = raw.partition("=")
    if not separator or not key or not value:
        raise ValueError(f"expected NAME=VALUE, got {raw!r}")
    return key, value


def parse_runtime_checks(values: list[str]) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for raw in values:
        key, value = parse_assignment(raw)
        checks[key] = parse_bool(value)
    return checks


def parse_available_plugin_skills(values: list[str] | None) -> set[str] | None:
    if values is None:
        return None
    for value in values:
        if ":" in value:
            raise ValueError(
                f"expected plugin-local skill name, got {value!r}; omit the plugin prefix"
            )
    return set(values)


def parse_effective_config(values: list[str]) -> dict[str, Any]:
    config: dict[str, Any] = {}
    for raw in values:
        key, value = parse_assignment(raw)
        try:
            config[key] = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError(f"expected JSON value for {key!r}, got {value!r}") from error
    return config


def lookup_dotted(config: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = config
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def lookup_layered_value(
    path: str, config_layers: list[tuple[Path, dict[str, Any]]]
) -> tuple[bool, Any]:
    for _config_path, config in reversed(config_layers):
        found, actual = lookup_dotted(config, path)
        if found:
            return True, actual
    return False, None


def iter_config_views(
    config_layers: list[tuple[Path, dict[str, Any]]], config_profile: str | None
) -> Iterator[tuple[str, dict[str, Any]]]:
    for config_path, config in reversed(config_layers):
        if config_profile is not None:
            profiles = config.get("profiles")
            if isinstance(profiles, dict):
                profile_config = profiles.get(config_profile)
                if isinstance(profile_config, dict):
                    supported_profile_config = {
                        key: value
                        for key, value in profile_config.items()
                        if key in LEGACY_CONFIG_PROFILE_CAPABILITY_FIELDS
                    }
                    if supported_profile_config:
                        yield (
                            f"{config_path} [profiles.{config_profile}]",
                            supported_profile_config,
                        )
        yield str(config_path), config


def resolve_project_root(cwd: Path, config_layers: list[tuple[Path, dict[str, Any]]]) -> Path:
    found, configured_markers = lookup_layered_value("project_root_markers", config_layers)
    markers = configured_markers if found else [".git"]
    if not isinstance(markers, list) or not all(isinstance(marker, str) for marker in markers):
        raise ValueError("project_root_markers must be an array of strings")
    if not markers:
        return cwd
    for candidate in (cwd, *cwd.parents):
        if any((candidate / marker).exists() for marker in markers):
            return candidate
    return cwd


def project_trust_level(
    config_layers: list[tuple[Path, dict[str, Any]]], project_root: Path
) -> str | None:
    for _path, config in reversed(config_layers):
        projects = config.get("projects")
        if not isinstance(projects, dict):
            continue
        project = projects.get(str(project_root))
        if not isinstance(project, dict) and os.name == "nt":
            project_key = os.path.normcase(os.path.realpath(project_root))
            project = next(
                (
                    value
                    for path, value in projects.items()
                    if os.path.normcase(os.path.realpath(path)) == project_key
                ),
                None,
            )
        if not isinstance(project, dict):
            continue
        trust_level = project.get("trust_level")
        if isinstance(trust_level, str):
            return trust_level
    return None


def project_config_paths(project_root: Path, cwd: Path) -> list[Path]:
    relative = cwd.relative_to(project_root)
    directories = [project_root]
    current = project_root
    for part in relative.parts:
        current /= part
        directories.append(current)
    return [directory / ".codex" / "config.toml" for directory in directories]


def discover_config_paths(
    *, cwd: Path, profile_layer_path: Path | None
) -> tuple[list[Path], dict[str, Any]]:
    resolved_cwd = cwd.expanduser().resolve()
    if not resolved_cwd.is_dir():
        raise ValueError(f"cwd must be a directory, got {str(resolved_cwd)!r}")

    base_paths = [SYSTEM_CONFIG, DEFAULT_CONFIG]
    if profile_layer_path is not None:
        base_paths.append(profile_layer_path)
    base_layers = [(path, read_toml(path, required=False)) for path in base_paths]
    project_root = resolve_project_root(resolved_cwd, base_layers)
    trust_level = project_trust_level(base_layers, project_root)
    paths = [*base_paths]
    if trust_level == "trusted":
        paths.extend(project_config_paths(project_root, resolved_cwd))
    return paths, {
        "cwd": str(resolved_cwd),
        "project_root": str(project_root),
        "project_trust_level": trust_level,
        "project_layers_loaded": trust_level == "trusted",
    }


def compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "==":
        return actual == expected
    if op == ">=":
        return isinstance(actual, int) and not isinstance(actual, bool) and actual >= expected
    raise ValueError(f"unsupported comparison operator: {op!r}")


def lookup_config_value(
    path: str,
    *,
    config_layers: list[tuple[Path, dict[str, Any]]],
    effective_config: dict[str, Any],
    config_profile: str | None,
    default: Any = None,
    has_default: bool = False,
) -> tuple[bool, Any, str | None]:
    if path in effective_config:
        return True, effective_config[path], "effective-config"
    for source, config in iter_config_views(config_layers, config_profile):
        found, actual = lookup_dotted(config, path)
        if found:
            return True, actual, source
    if has_default:
        return True, default, "documented-default"
    return False, None, None


def resolve_active_config_profile(
    *,
    config_layers: list[tuple[Path, dict[str, Any]]],
    override: str | None,
    cli_profile_selected: bool,
) -> tuple[str | None, str | None]:
    if cli_profile_selected:
        if override is None:
            raise ValueError("CLI profile selection requires an explicit config profile name")
        return override, None

    if override is None:
        found, configured = lookup_layered_value("profile", config_layers)
        if not found:
            return None, None
        if not isinstance(configured, str):
            raise ValueError("profile must be a string")
        profile = configured
    else:
        profile = override

    profile_values = [
        config.get("profiles", {}).get(profile)
        for _path, config in config_layers
        if isinstance(config.get("profiles"), dict) and profile in config["profiles"]
    ]
    if not profile_values:
        raise ValueError(f"config profile {profile!r} not found")
    if any(not isinstance(value, dict) for value in profile_values):
        raise ValueError(f"config profile {profile!r} must be a table")
    return profile, profile


def config_profile_layer_path(profile: str | None) -> Path | None:
    if profile is None:
        return None
    if not CONFIG_PROFILE_NAME.fullmatch(profile):
        raise ValueError(
            f"invalid config profile name {profile!r}; pass a plain name such as 'work'"
        )
    path = DEFAULT_CODEX_HOME / f"{profile}.config.toml"
    return path if path.is_file() else None


def parse_multi_agent_v2_enabled(feature_config: Any) -> bool | None:
    if isinstance(feature_config, bool):
        return feature_config
    if not isinstance(feature_config, dict):
        raise ValueError("features.multi_agent_v2 must be a boolean or table")
    if "enabled" not in feature_config:
        return None
    enabled = feature_config["enabled"]
    if not isinstance(enabled, bool):
        raise ValueError("features.multi_agent_v2.enabled must be a boolean")
    return enabled


def merge_toml_value(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = dict(base)
        for key, value in overlay.items():
            merged[key] = merge_toml_value(merged[key], value) if key in merged else value
        return merged
    return overlay


def lookup_multi_agent_v2_enabled(
    *,
    config_layers: list[tuple[Path, dict[str, Any]]],
    effective_config: dict[str, Any],
    config_profile: str | None,
) -> tuple[bool, bool | None, str | None]:
    if "features.multi_agent_v2.enabled" in effective_config:
        enabled = effective_config["features.multi_agent_v2.enabled"]
        if not isinstance(enabled, bool):
            raise ValueError("features.multi_agent_v2.enabled must be a boolean")
        return True, enabled, "effective-config"

    v2_configs = []
    config_views = list(iter_config_views(config_layers, config_profile))
    for source, config in reversed(config_views):
        found, feature_config = lookup_dotted(config, "features.multi_agent_v2")
        if found:
            v2_configs.append((source, feature_config))

    if "features.multi_agent_v2" in effective_config:
        v2_configs.append(("effective-config", effective_config["features.multi_agent_v2"]))

    if not v2_configs:
        return False, None, None

    merged_v2_config: Any = None
    enabled_source: str | None = None
    for index, (source, feature_config) in enumerate(v2_configs):
        tables_merge = isinstance(merged_v2_config, dict) and isinstance(feature_config, dict)
        if index and not tables_merge:
            enabled_source = None
        merged_v2_config = (
            merge_toml_value(merged_v2_config, feature_config) if index else feature_config
        )
        if isinstance(feature_config, bool) or (
            isinstance(feature_config, dict) and "enabled" in feature_config
        ):
            enabled_source = source

    enabled = parse_multi_agent_v2_enabled(merged_v2_config)
    return (
        (True, enabled, enabled_source)
        if enabled is not None
        else (True, False, "documented-default")
    )


def resolve_multi_agent_context(
    *,
    config_layers: list[tuple[Path, dict[str, Any]]],
    effective_config: dict[str, Any],
    config_profile: str | None,
    runtime_owner: str | None,
    runtime_version: str | None,
    runtime_session_cap: int | None,
    runtime_provenance: str | None,
    validate_multi_agent_config: bool,
) -> dict[str, Any]:
    runtime_facts_supplied = any(
        value is not None for value in (runtime_owner, runtime_version, runtime_session_cap)
    )
    if runtime_facts_supplied and runtime_provenance is None:
        raise ValueError(
            "explicit multi-agent runtime facts require --multi-agent-runtime-provenance"
        )
    if runtime_provenance is not None and not runtime_facts_supplied:
        raise ValueError(
            "--multi-agent-runtime-provenance requires an explicit runtime owner, version, or cap"
        )
    if runtime_owner == "codex-bridge" and runtime_provenance != "verified-bridge":
        raise ValueError(
            "codex-bridge ownership requires --multi-agent-runtime-provenance verified-bridge"
        )
    if runtime_owner == "native" and runtime_provenance == "verified-bridge":
        raise ValueError("native ownership cannot use verified-bridge provenance")

    feature_found, enabled, feature_source = lookup_multi_agent_v2_enabled(
        config_layers=config_layers,
        effective_config=effective_config,
        config_profile=config_profile,
    )

    if runtime_version is not None:
        version = runtime_version
        version_source = "runtime-fact"
    elif feature_found:
        version = "v2" if enabled else "v1"
        version_source = feature_source
    elif runtime_owner == "codex-bridge":
        version = "v2"
        version_source = "runtime-owner"
    else:
        version = "unknown"
        version_source = None

    if runtime_owner is not None:
        owner = runtime_owner
        owner_source = "runtime-fact"
    elif feature_found:
        owner = "native"
        owner_source = feature_source
    else:
        owner = "unknown"
        owner_source = None

    if owner == "codex-bridge" and version != "v2":
        raise ValueError("codex-bridge ownership requires multi-agent runtime version v2")
    if runtime_session_cap is not None and version != "v2":
        raise ValueError("--multi-agent-session-cap is valid only for a V2 runtime")

    bridge_cap_found, bridge_cap, bridge_cap_source = lookup_config_value(
        "multiagent_config.max_concurrency",
        config_layers=config_layers,
        effective_config=effective_config,
        config_profile=config_profile,
    )
    if (
        bridge_cap_found
        and owner != "codex-bridge"
        and (validate_multi_agent_config or runtime_facts_supplied)
    ):
        raise ValueError(
            "multiagent_config.max_concurrency does not prove bridge ownership; "
            "pass --multi-agent-runtime-owner codex-bridge only when the active runtime "
            "is verified as bridge-managed"
        )
    if bridge_cap_found and runtime_session_cap is not None and bridge_cap != runtime_session_cap:
        raise ValueError(
            "conflicting bridge concurrency facts: multiagent_config.max_concurrency "
            f"from {bridge_cap_source} is {bridge_cap!r}, but --multi-agent-session-cap is "
            f"{runtime_session_cap!r}"
        )

    agent_threads_found, agent_threads, agent_threads_source = lookup_config_value(
        "agents.max_threads",
        config_layers=config_layers,
        effective_config=effective_config,
        config_profile=config_profile,
    )
    if owner != "codex-bridge" and feature_found and enabled and agent_threads_found:
        raise ValueError("agents.max_threads cannot be set when multi_agent_v2 is enabled")

    if version == "v1":
        mode = "v1"
    elif version == "v2" and owner == "codex-bridge":
        mode = "bridge-v2"
    elif version == "v2" and owner == "native":
        mode = "v2"
    else:
        mode = "unknown"
    return {
        "mode": mode,
        "owner": owner,
        "owner_source": owner_source,
        "version": version,
        "version_source": version_source,
        "runtime_provenance": runtime_provenance,
        "config_v2_enabled": feature_found and bool(enabled),
        "agent_max_threads_configured": agent_threads_found,
        "agent_max_threads": agent_threads if agent_threads_found else None,
        "agent_max_threads_source": agent_threads_source if agent_threads_found else None,
    }


def evaluate_multi_agent_capacity(
    result: dict[str, Any],
    capability: dict[str, Any],
    *,
    config_layers: list[tuple[Path, dict[str, Any]]],
    effective_config: dict[str, Any],
    config_profile: str | None,
    multi_agent_context: dict[str, Any],
    runtime_session_cap: int | None,
) -> dict[str, Any]:
    multi_agent_mode = str(multi_agent_context["mode"])
    if multi_agent_mode == "unknown":
        return {**result, "status": "unknown", "check": "active_multi_agent_mode"}

    if multi_agent_mode == "v1":
        path = "agents.max_threads"
        found, actual, source = lookup_config_value(
            path,
            config_layers=config_layers,
            effective_config=effective_config,
            config_profile=config_profile,
            default=capability.get("v1_default"),
            has_default="v1_default" in capability,
        )
        worker_slots = actual
    else:
        if runtime_session_cap is not None:
            path = "runtime.multi_agent.session_cap"
            found, actual, source = True, runtime_session_cap, "runtime-fact"
        elif multi_agent_context["owner"] == "codex-bridge":
            path = "multiagent_config.max_concurrency"
            found, actual, source = lookup_config_value(
                path,
                config_layers=config_layers,
                effective_config=effective_config,
                config_profile=config_profile,
            )
        elif multi_agent_context["owner"] == "native" and multi_agent_context["config_v2_enabled"]:
            path = "features.multi_agent_v2.max_concurrent_threads_per_session"
            found, actual, source = lookup_config_value(
                path,
                config_layers=config_layers,
                effective_config=effective_config,
                config_profile=config_profile,
                default=NATIVE_V2_DEFAULT_SESSION_CAP,
                has_default=True,
            )
        else:
            path = "runtime.multi_agent.session_cap"
            found, actual, source = False, None, None
        worker_slots = (
            actual - 1 if isinstance(actual, int) and not isinstance(actual, bool) else actual
        )

    if not found:
        return {**result, "status": "unknown", "path": path, "multi_agent_mode": multi_agent_mode}
    return {
        **result,
        "status": "pass"
        if compare(worker_slots, capability["op"], capability["value"])
        else "fail",
        "path": path,
        "actual": worker_slots,
        "configured_value": actual,
        "expected": {"op": capability["op"], "value": capability["value"]},
        "source": source,
        "multi_agent_mode": multi_agent_mode,
    }


def resolve_profile(registry: dict[str, Any], *, profile: str | None, skill: str | None) -> str:
    if profile:
        return profile
    routes = {route["skill"]: route["profile"] for route in registry["routes"]}
    try:
        return routes[str(skill)]
    except KeyError as error:
        raise ValueError(f"no capability profile route for skill {skill!r}") from error


def evaluate_requirement(
    requirement: dict[str, Any],
    *,
    capabilities: dict[str, dict[str, Any]],
    config_layers: list[tuple[Path, dict[str, Any]]],
    effective_config: dict[str, Any],
    config_profile: str | None,
    runtime_checks: dict[str, bool],
    available_plugin_skills: set[str] | None,
    multi_agent_context: dict[str, Any],
    runtime_session_cap: int | None,
) -> dict[str, Any]:
    capability_id = requirement["capability"]
    capability = capabilities[capability_id]
    result = {
        "capability": capability_id,
        "severity": requirement["severity"],
        "reason": requirement["reason"],
    }

    if capability["kind"] == "runtime":
        check = capability["check"]
        if check not in runtime_checks:
            return {**result, "status": "unknown", "check": check}
        actual = runtime_checks[check]
        return {**result, "status": "pass" if actual else "fail", "actual": actual, "check": check}

    if capability["kind"] == "multi_agent_mode":
        actual = {
            "owner": multi_agent_context["owner"],
            "version": multi_agent_context["version"],
        }
        expected = {
            "owner": capability["owner"],
            "version": capability["version"],
        }
        if "unknown" in actual.values():
            return {
                **result,
                "status": "unknown",
                "check": "active_multi_agent_mode",
                "actual": actual,
                "expected": expected,
            }
        return {
            **result,
            "status": "pass" if actual == expected else "fail",
            "actual": actual,
            "expected": expected,
        }

    if capability["kind"] == "plugin_skills":
        required = capability["required"]
        required_skill_ids = [f"{capability['plugin']}:{skill}" for skill in required]
        if available_plugin_skills is None:
            return {
                **result,
                "status": "unknown",
                "check": "available_plugin_skills",
                "required": required_skill_ids,
            }
        unavailable = [
            f"{capability['plugin']}:{skill}"
            for skill in required
            if skill not in available_plugin_skills
        ]
        return {
            **result,
            "status": "fail" if unavailable else "pass",
            "unavailable": unavailable,
            "required": required_skill_ids,
        }

    if capability["kind"] == "multi_agent_capacity":
        return evaluate_multi_agent_capacity(
            result,
            capability,
            config_layers=config_layers,
            effective_config=effective_config,
            config_profile=config_profile,
            multi_agent_context=multi_agent_context,
            runtime_session_cap=runtime_session_cap,
        )

    if capability["kind"] == "config_absent":
        path = capability["path"]
        found, actual, source = lookup_config_value(
            path,
            config_layers=config_layers,
            effective_config=effective_config,
            config_profile=config_profile,
        )
        if not found:
            return {**result, "status": "pass", "path": path, "expected": "unset"}
        return {
            **result,
            "status": "fail",
            "path": path,
            "actual": actual,
            "expected": "unset",
            "source": source,
        }

    path = capability["path"]
    found, actual, source = lookup_config_value(
        path,
        config_layers=config_layers,
        effective_config=effective_config,
        config_profile=config_profile,
        default=capability.get("default"),
        has_default="default" in capability,
    )
    if not found:
        return {**result, "status": "unknown", "path": path}
    return {
        **result,
        "status": "pass" if compare(actual, capability["op"], capability["value"]) else "fail",
        "path": path,
        "actual": actual,
        "expected": {"op": capability["op"], "value": capability["value"]},
        "source": source,
    }


def validate_registry(registry: dict[str, Any]) -> None:
    capabilities = registry["capabilities"]
    profiles = registry["profiles"]
    for profile_id, profile in profiles.items():
        for requirement in profile["requirements"]:
            if requirement["capability"] not in capabilities:
                raise ValueError(
                    f"profile {profile_id!r} references unknown capability {requirement['capability']!r}"
                )
            if requirement["severity"] not in VALID_SEVERITIES:
                raise ValueError(
                    f"profile {profile_id!r} has unsupported severity {requirement['severity']!r}"
                )


def profile_requires_multi_agent_config(
    profile: dict[str, Any], capabilities: dict[str, dict[str, Any]]
) -> bool:
    def is_runtime_path(path: Any) -> bool:
        return isinstance(path, str) and (
            path in {"agents", "features", "features.multi_agent_v2", "multiagent_config"}
            or path.startswith(("agents.", "multiagent_config.", "features.multi_agent_v2."))
        )

    for requirement in profile["requirements"]:
        capability = capabilities[requirement["capability"]]
        if (
            capability["kind"] in {"multi_agent_capacity", "multi_agent_mode"}
            or requirement.get("modes")
            or is_runtime_path(capability.get("path"))
        ):
            return True
    remediation = profile.get("remediation", {})
    return bool(remediation.get("variants")) or any(
        is_runtime_path(patch.get("path")) for patch in remediation.get("patches", [])
    )


def resolve_remediation(
    profile: dict[str, Any], *, multi_agent_context: dict[str, Any]
) -> dict[str, Any]:
    multi_agent_mode = str(multi_agent_context["mode"])
    remediation = dict(profile.get("remediation", {}))
    variants = remediation.pop("variants", [])
    remediation["multi_agent_mode"] = multi_agent_mode
    for variant in variants:
        if variant["mode"] == multi_agent_mode:
            if multi_agent_mode == "v2" and multi_agent_context["owner"] != "native":
                break
            variant_patches = variant.get("patches", [])
            if multi_agent_mode == "v2" and not multi_agent_context["agent_max_threads_configured"]:
                variant_patches = [
                    patch
                    for patch in variant_patches
                    if not (
                        patch.get("kind") == "remove" and patch.get("path") == "agents.max_threads"
                    )
                ]
            remediation["patches"] = remediation.get("patches", []) + variant_patches
            return remediation
    if variants:
        remediation["note"] = (
            "Do not apply a concurrency patch until the active runtime version and config "
            "ownership are known."
        )
    return remediation


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    registry = read_toml(args.registry, required=True)
    validate_registry(registry)
    profile_id = resolve_profile(registry, profile=args.profile, skill=args.skill)
    try:
        profile = registry["profiles"][profile_id]
    except KeyError as error:
        raise ValueError(f"unknown capability profile: {profile_id!r}") from error

    cli_profile_selected = args.codex_config_profile is not None
    if args.config:
        config_paths = args.config
        config_discovery = None
        config_resolution = "manual-layers"
        project_config_paths_set: set[Path] = set()
        profile_layer_path = None
    else:
        profile_layer_path = config_profile_layer_path(args.codex_config_profile)
        config_paths, config_discovery = discover_config_paths(
            cwd=args.cwd,
            profile_layer_path=profile_layer_path,
        )
        config_resolution = "cwd-discovery"
        project_config_paths_set = set(config_paths[3 if profile_layer_path else 2 :])
    config_layers = []
    for path in config_paths:
        config = read_toml(path, required=False)
        if path in project_config_paths_set:
            # Codex strips project-local profile selection and definitions before
            # resolving the merged config. Mirror that denylist here.
            config = dict(config)
            config.pop("profile", None)
            config.pop("profiles", None)
        config_layers.append((path, config))
    config_profile, embedded_config_profile = resolve_active_config_profile(
        config_layers=config_layers,
        override=args.codex_config_profile,
        cli_profile_selected=cli_profile_selected,
    )
    runtime_checks = parse_runtime_checks(args.runtime_check)
    available_plugin_skills = parse_available_plugin_skills(args.available_plugin_skill)
    effective_config = parse_effective_config(args.effective_config)
    multi_agent_context = resolve_multi_agent_context(
        config_layers=config_layers,
        effective_config=effective_config,
        config_profile=embedded_config_profile,
        runtime_owner=args.multi_agent_runtime_owner,
        runtime_version=args.multi_agent_runtime_version,
        runtime_session_cap=args.multi_agent_session_cap,
        runtime_provenance=args.multi_agent_runtime_provenance,
        validate_multi_agent_config=profile_requires_multi_agent_config(
            profile, registry["capabilities"]
        ),
    )
    results = [
        evaluate_requirement(
            requirement,
            capabilities=registry["capabilities"],
            config_layers=config_layers,
            effective_config=effective_config,
            runtime_checks=runtime_checks,
            available_plugin_skills=available_plugin_skills,
            config_profile=embedded_config_profile,
            multi_agent_context=multi_agent_context,
            runtime_session_cap=args.multi_agent_session_cap,
        )
        for requirement in profile["requirements"]
        if not requirement.get("modes") or multi_agent_context["mode"] in requirement["modes"]
    ]
    failed = [result for result in results if result["status"] == "fail"]
    unknown = [result for result in results if result["status"] == "unknown"]
    if any(result["severity"] == "block" for result in failed):
        status = "blocked"
    elif any(result["severity"] == "block" for result in unknown):
        status = "incomplete"
    else:
        status = "ready"
    return {
        "version": registry["version"],
        "profile": profile_id,
        "description": profile["description"],
        "config_resolution": config_resolution,
        "user_config_path": None if args.config else str(profile_layer_path or DEFAULT_CONFIG),
        "config_paths": [str(path) for path in config_paths],
        "config_discovery": config_discovery,
        "config_profile": config_profile,
        "config_profile_path": str(profile_layer_path) if profile_layer_path else None,
        "multi_agent_mode": multi_agent_context["mode"],
        "multi_agent_context": multi_agent_context,
        "status": status,
        "results": results,
        "failed": failed,
        "unknown": unknown,
        "remediation": resolve_remediation(
            profile,
            multi_agent_context=multi_agent_context,
        ),
    }


def main() -> int:
    try:
        payload = evaluate(parse_args())
    except (KeyError, OSError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"status": "error", "error": str(error)}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    if payload["status"] == "blocked":
        return 1
    return 2 if payload["status"] == "incomplete" else 0


if __name__ == "__main__":
    sys.exit(main())
