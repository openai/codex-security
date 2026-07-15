from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from openai_codex_security import CodexSecurityConfig, ConfigurationError
from openai_codex_security.config import merged_codex_config, write_codex_config
from openai_codex_security.runtime import bundled_plugin_root


def _write_v2_profile(plugin_root: Path, *, severity: str = "block") -> None:
    profiles = plugin_root / "preflight/capability-profiles.toml"
    profiles.parent.mkdir(parents=True)
    profiles.write_text(
        "[profiles.deep_security_scan]\n"
        "[[profiles.deep_security_scan.requirements]]\n"
        'capability = "native_multi_agent_v2"\n'
        f'severity = "{severity}"\n',
        encoding="utf-8",
    )


def test_security_defaults_and_overrides_merge() -> None:
    merged = merged_codex_config(
        CodexSecurityConfig(
            codex_overrides={
                "agents": {"max_threads": 4},
                "model_reasoning_effort": "high",
            }
        )
    )
    assert merged["features"]["plugins"] is True
    assert merged["features"]["multi_agent"] is True
    assert merged["features"]["enable_fanout"] is True
    assert merged["features"]["goals"] is True
    assert merged["agents"] == {"max_threads": 4, "max_depth": 2}
    assert merged["cli_auth_credentials_store"] == "file"
    assert merged["model_reasoning_effort"] == "high"


def test_native_multi_agent_v2_defaults_follow_plugin_contract(tmp_path: Path) -> None:
    plugin_root = tmp_path / "plugin"
    _write_v2_profile(plugin_root)

    merged = merged_codex_config(CodexSecurityConfig(), plugin_root=plugin_root)

    assert merged["features"] == {
        "plugins": True,
        "goals": True,
        "multi_agent_v2": {
            "enabled": True,
            "max_concurrent_threads_per_session": 9,
        },
    }
    assert "agents" not in merged


def test_bundled_plugin_uses_native_multi_agent_v2_defaults() -> None:
    merged = merged_codex_config(
        CodexSecurityConfig(),
        plugin_root=bundled_plugin_root(),
    )

    assert merged["features"]["multi_agent_v2"] == {
        "enabled": True,
        "max_concurrent_threads_per_session": 9,
    }
    assert "agents" not in merged


def test_bundled_plugin_deep_scan_preflight_accepts_defaults(tmp_path: Path) -> None:
    plugin_root = bundled_plugin_root()
    config_path = tmp_path / "config.toml"
    write_codex_config(
        config_path,
        merged_codex_config(CodexSecurityConfig(), plugin_root=plugin_root),
    )
    args = [
        sys.executable,
        str(plugin_root / "scripts/config_preflight.py"),
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    ]
    for skill in (
        "attack-path-analysis",
        "finding-discovery",
        "security-scan",
        "threat-model",
        "validation",
    ):
        args.extend(("--available-plugin-skill", skill))

    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    payload = json.loads(completed.stdout)

    assert completed.returncode == 0, payload
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "v2"
    capabilities = {item["capability"]: item for item in payload["results"]}
    assert capabilities["native_multi_agent_v2"]["status"] == "pass"
    assert capabilities["sdk_v2_child_config_compatible"]["status"] == "pass"
    assert capabilities.keys().isdisjoint(
        {"delegated_workers", "usable_worker_slots_6", "usable_worker_slots_8", "agent_depth_2"}
    )


def test_native_multi_agent_v2_defaults_allow_codex_overrides(tmp_path: Path) -> None:
    plugin_root = tmp_path / "plugin"
    _write_v2_profile(plugin_root)
    config = CodexSecurityConfig(
        codex_overrides={"features": {"multi_agent_v2": {"max_concurrent_threads_per_session": 6}}}
    )

    merged = merged_codex_config(config, plugin_root=plugin_root)

    assert merged["features"]["multi_agent_v2"] == {
        "enabled": True,
        "max_concurrent_threads_per_session": 6,
    }


def test_native_multi_agent_v2_rejects_legacy_thread_override(tmp_path: Path) -> None:
    plugin_root = tmp_path / "plugin"
    _write_v2_profile(plugin_root)

    with pytest.raises(ConfigurationError, match="agents.max_threads.*legacy v1"):
        merged_codex_config(
            CodexSecurityConfig(codex_overrides={"agents": {"max_threads": 2}}),
            plugin_root=plugin_root,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"features": {"multi_agent_v2": {"enabled": False}}},
        {"features": {"multi_agent_v2": False}},
        {"features": {"multi_agent_v2": True}},
        {"features": False},
    ],
)
def test_native_multi_agent_v2_rejects_disabling_overrides(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_v2_profile(plugin_root)

    with pytest.raises(ConfigurationError, match="requires native multi-agent v2"):
        merged_codex_config(
            CodexSecurityConfig(codex_overrides=overrides),
            plugin_root=plugin_root,
        )


def test_nonblocking_native_multi_agent_v2_requirement_keeps_legacy_defaults(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_v2_profile(plugin_root, severity="warn")

    merged = merged_codex_config(CodexSecurityConfig(), plugin_root=plugin_root)

    assert merged["features"]["multi_agent"] is True
    assert merged["agents"]["max_threads"] == 12


def test_malformed_capability_profile_is_rejected(tmp_path: Path) -> None:
    profiles = tmp_path / "plugin/preflight/capability-profiles.toml"
    profiles.parent.mkdir(parents=True)
    profiles.write_text("[profiles\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="unreadable capability profile"):
        merged_codex_config(CodexSecurityConfig(), plugin_root=tmp_path / "plugin")


@pytest.mark.parametrize(
    "overrides",
    [
        {"plugins": {}},
        {"marketplaces": {}},
        {"features": {"plugins": False}},
    ],
)
def test_plugin_loading_overrides_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError, match="plugin loading"):
        merged_codex_config(CodexSecurityConfig(codex_overrides=overrides))


def test_config_writer_emits_toml(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    write_codex_config(
        path,
        {
            "features": {"plugins": True, "goals": True},
            "agents": {"max_threads": 12},
            "model_reasoning_effort": "high",
        },
    )
    text = path.read_text(encoding="utf-8")
    assert "features.plugins = true" in text
    assert "agents.max_threads = 12" in text
    assert 'model_reasoning_effort = "high"' in text
