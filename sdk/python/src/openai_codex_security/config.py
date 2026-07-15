from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeAlias

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

from .errors import ConfigurationError

JsonObject: TypeAlias = dict[str, Any]

DEFAULT_CODEX_CONFIG: JsonObject = {
    "cli_auth_credentials_store": "file",
    "features": {
        "plugins": True,
        "multi_agent": True,
        "enable_fanout": True,
        "goals": True,
    },
    "agents": {
        "max_threads": 12,
        "max_depth": 2,
    },
}
NATIVE_V2_CODEX_CONFIG: JsonObject = {
    "cli_auth_credentials_store": "file",
    "features": {
        "plugins": True,
        "goals": True,
        "multi_agent_v2": {
            "enabled": True,
            "max_concurrent_threads_per_session": 9,
        },
    },
}
_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(slots=True)
class CodexSecurityConfig:
    """Configuration for the isolated Codex Security runtime."""

    plugin_path: str | os.PathLike[str] | None = None
    codex_overrides: JsonObject = field(default_factory=dict)


def merged_codex_config(
    config: CodexSecurityConfig,
    *,
    plugin_root: Path | None = None,
) -> JsonObject:
    overrides = copy.deepcopy(config.codex_overrides)
    _validate_overrides(overrides)
    uses_native_multi_agent_v2 = plugin_root is not None and _supports_native_multi_agent_v2(
        plugin_root
    )
    if uses_native_multi_agent_v2:
        _validate_native_multi_agent_v2_overrides(overrides)
    defaults = NATIVE_V2_CODEX_CONFIG if uses_native_multi_agent_v2 else DEFAULT_CODEX_CONFIG
    return _deep_merge(copy.deepcopy(defaults), overrides)


def _supports_native_multi_agent_v2(plugin_root: Path) -> bool:
    profiles_path = plugin_root / "preflight/capability-profiles.toml"
    if not profiles_path.is_file():
        return False
    try:
        with profiles_path.open("rb") as source:
            data = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(
            f"Selected plugin has an unreadable capability profile: {profiles_path}: {exc}"
        ) from exc

    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ConfigurationError("Selected plugin capability profiles must be a TOML table.")
    deep_profile = profiles.get("deep_security_scan")
    if deep_profile is None:
        return False
    if not isinstance(deep_profile, dict):
        raise ConfigurationError(
            "Selected plugin deep_security_scan capability profile must be a TOML table."
        )
    requirements = deep_profile.get("requirements", [])
    if not isinstance(requirements, list) or not all(
        isinstance(requirement, dict) for requirement in requirements
    ):
        raise ConfigurationError(
            "Selected plugin deep_security_scan requirements must be TOML tables."
        )
    if any(
        requirement.get("capability") == "native_multi_agent_v2"
        and requirement.get("severity") == "block"
        for requirement in requirements
    ):
        return True

    remediation = deep_profile.get("remediation", {})
    if not isinstance(remediation, dict):
        raise ConfigurationError(
            "Selected plugin deep_security_scan remediation must be a TOML table."
        )
    variants = remediation.get("variants", [])
    if not isinstance(variants, list) or not all(isinstance(variant, dict) for variant in variants):
        raise ConfigurationError(
            "Selected plugin deep_security_scan remediation variants must be TOML tables."
        )
    for variant in variants:
        if variant.get("mode") != "v2":
            continue
        patches = variant.get("patches", [])
        if not isinstance(patches, list) or not all(isinstance(patch, dict) for patch in patches):
            raise ConfigurationError("Selected plugin v2 remediation patches must be TOML tables.")
        return any(
            patch.get("path") == "features.multi_agent_v2.enabled" and patch.get("value") is True
            for patch in patches
        )
    return False


def write_codex_config(path: Path, config: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"{'.'.join(_toml_key(part) for part in key)} = {_toml_value(value)}"
        for key, value in _flatten(config)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _validate_overrides(overrides: JsonObject) -> None:
    if not isinstance(overrides, dict):
        raise ConfigurationError("codex_overrides must be a JSON object.")
    if "plugins" in overrides or "marketplaces" in overrides:
        raise ConfigurationError("Codex Security owns plugin loading configuration.")
    features = overrides.get("features")
    if isinstance(features, dict) and "plugins" in features:
        raise ConfigurationError("Codex Security owns plugin loading configuration.")


def _validate_native_multi_agent_v2_overrides(overrides: JsonObject) -> None:
    agents = overrides.get("agents")
    if isinstance(agents, dict) and "max_threads" in agents:
        raise ConfigurationError(
            "The selected Codex Security plugin requires native multi-agent v2; "
            "agents.max_threads is a legacy v1 setting. Use "
            "features.multi_agent_v2.max_concurrent_threads_per_session instead."
        )
    if "features" not in overrides:
        return
    features = overrides["features"]
    if not isinstance(features, dict):
        raise ConfigurationError(
            "The selected Codex Security plugin requires native multi-agent v2; "
            "features must remain a table containing features.multi_agent_v2."
        )
    if "multi_agent_v2" not in features:
        return
    multi_agent_v2 = features["multi_agent_v2"]
    if not isinstance(multi_agent_v2, dict):
        raise ConfigurationError(
            "The selected Codex Security plugin requires native multi-agent v2; "
            "features.multi_agent_v2 must remain a table with enabled = true."
        )
    if "enabled" in multi_agent_v2 and multi_agent_v2["enabled"] is not True:
        raise ConfigurationError(
            "The selected Codex Security plugin requires native multi-agent v2; "
            "features.multi_agent_v2.enabled cannot be disabled."
        )


def _deep_merge(base: JsonObject, overrides: JsonObject) -> JsonObject:
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(dict(base[key]), value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _flatten(value: JsonObject, prefix: tuple[str, ...] = ()):
    for key in sorted(value):
        if not isinstance(key, str) or not key:
            raise ConfigurationError("Codex configuration keys must be non-empty strings.")
        item = value[key]
        path = (*prefix, key)
        if isinstance(item, dict):
            if not item:
                raise ConfigurationError(f"Empty Codex configuration object at {'.'.join(path)}.")
            yield from _flatten(item, path)
        else:
            yield path, item


def _toml_key(value: str) -> str:
    return value if _BARE_KEY.fullmatch(value) else json.dumps(value)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if value is None:
        raise ConfigurationError("TOML-backed Codex overrides cannot contain null values.")
    raise ConfigurationError(f"Unsupported Codex configuration value: {type(value).__name__}")
