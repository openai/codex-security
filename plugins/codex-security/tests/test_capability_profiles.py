from __future__ import annotations

import builtins
import json
import ntpath
import os
import runpy
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_SCRIPT = PLUGIN_ROOT / "scripts" / "config_preflight.py"
DEEP_SCAN_CONFIG_SCRIPT = PLUGIN_ROOT / "scripts" / "deep_scan_config.py"
SYSTEM_CONFIG_PATH = (
    str(Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "OpenAI" / "Codex" / "config.toml")
    if os.name == "nt"
    else "/etc/codex/config.toml"
)


def test_preflight_uses_windows_system_config(monkeypatch) -> None:
    namespace = runpy.run_path(str(PREFLIGHT_SCRIPT), run_name="config_preflight_test")
    default_config = namespace["default_system_config"]
    environment = {"ProgramData": r"D:\Shared Data"}
    monkeypatch.setitem(
        default_config.__globals__, "os", SimpleNamespace(name="nt", environ=environment)
    )
    monkeypatch.setitem(default_config.__globals__, "Path", PureWindowsPath)
    assert default_config() == PureWindowsPath(r"D:\Shared Data\OpenAI\Codex\config.toml")
    environment.clear()
    assert default_config() == PureWindowsPath(r"C:\ProgramData\OpenAI\Codex\config.toml")


def test_preflight_matches_windows_project_path_aliases(monkeypatch) -> None:
    namespace = runpy.run_path(str(PREFLIGHT_SCRIPT), run_name="config_preflight_test")
    trust_level = namespace["project_trust_level"]
    monkeypatch.setitem(trust_level.__globals__, "os", SimpleNamespace(name="nt", path=ntpath))
    root = PureWindowsPath(r"C:\Work\Repository")
    layers = [
        (Path("config.toml"), {"projects": {"c:/work/REPOSITORY": {"trust_level": "trusted"}}})
    ]
    assert trust_level(layers, root) == "trusted"
    assert trust_level(layers, PureWindowsPath(r"C:\Work\Repository Other")) is None
    layers.append((Path("profile.toml"), {"projects": {str(root): {"trust_level": "untrusted"}}}))
    assert trust_level(layers, root) == "untrusted"


def test_preflight_falls_back_to_tomli_without_stdlib_tomllib(monkeypatch) -> None:
    real_import = builtins.__import__
    monkeypatch.setitem(sys.modules, "tomli", tomllib)

    def import_without_tomllib(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tomllib":
            raise ModuleNotFoundError("No module named 'tomllib'", name="tomllib")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_tomllib)

    namespace = runpy.run_path(str(PREFLIGHT_SCRIPT), run_name="config_preflight_test")

    assert namespace["tomllib"] is tomllib


def test_deep_scan_config_falls_back_to_tomli_without_stdlib_tomllib(monkeypatch) -> None:
    real_import = builtins.__import__
    monkeypatch.setitem(sys.modules, "tomli", tomllib)

    def import_without_tomllib(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tomllib":
            raise ModuleNotFoundError("No module named 'tomllib'", name="tomllib")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_tomllib)

    namespace = runpy.run_path(str(DEEP_SCAN_CONFIG_SCRIPT), run_name="deep_scan_config_test")

    assert namespace["tomllib"] is tomllib


def test_capability_profiles_parse_and_route_top_level_scan_skills() -> None:
    data = tomllib.loads((PLUGIN_ROOT / "preflight" / "capability-profiles.toml").read_text())

    assert data["version"] == 1
    assert set(data["profiles"]) == {
        "deep_security_scan",
        "security_diff_scan",
        "security_scan",
    }
    assert {route["skill"]: route["profile"] for route in data["routes"]} == {
        "deep-security-scan": "deep_security_scan",
        "security-diff-scan": "security_diff_scan",
        "security-scan": "security_scan",
    }


def test_standard_and_deep_scan_profiles_do_not_require_goals() -> None:
    data = tomllib.loads((PLUGIN_ROOT / "preflight" / "capability-profiles.toml").read_text())
    for profile_id in ("security_scan", "deep_security_scan"):
        profile = data["profiles"][profile_id]
        requirements = {requirement["capability"] for requirement in profile["requirements"]}
        assert requirements.isdisjoint({"goal_tools", "goals_enabled"})
        assert not any(
            patch["path"] == "features.goals"
            for patch in profile.get("remediation", {}).get("patches", [])
        )
    assert data["profiles"]["deep_security_scan"]["requirements"] == []
    assert {
        requirement["capability"]
        for requirement in data["profiles"]["security_diff_scan"]["requirements"]
    } >= {"goal_tools", "goals_enabled"}


def test_deep_scan_does_not_add_capability_requirements_beyond_standard_scan() -> None:
    data = tomllib.loads((PLUGIN_ROOT / "preflight" / "capability-profiles.toml").read_text())
    deep_requirements = {
        requirement["capability"]
        for requirement in data["profiles"]["deep_security_scan"]["requirements"]
    }
    standard_requirements = {
        requirement["capability"]
        for requirement in data["profiles"]["security_scan"]["requirements"]
    }

    assert deep_requirements.issubset(standard_requirements)


def run_preflight(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PREFLIGHT_SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, **env} if env else None,
    )


def available_deep_scan_skills_except(excluded: str | None = None) -> tuple[str, ...]:
    return tuple(
        item
        for skill in (
            "attack-path-analysis",
            "finding-discovery",
            "security-scan",
            "threat-model",
            "validation",
        )
        if skill != excluded
        for item in ("--available-plugin-skill", skill)
    )


def available_deep_scan_skills() -> tuple[str, ...]:
    return available_deep_scan_skills_except()


def standalone_v1() -> tuple[str, ...]:
    return (
        "--multi-agent-runtime-owner",
        "native",
        "--multi-agent-runtime-version",
        "v1",
        "--multi-agent-runtime-provenance",
        "app-server",
    )


def test_deep_scan_preflight_is_ready_with_required_capabilities(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[features]\ngoals = true\n\n"
        "[features.multi_agent_v2]\nenabled = true\n"
        "max_concurrent_threads_per_session = 4\n"
    )

    result = run_preflight(
        "--skill",
        "deep-security-scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["profile"] == "deep_security_scan"
    assert payload["status"] == "ready"
    assert payload["failed"] == []
    assert payload["unknown"] == []


def test_standard_and_deep_preflight_do_not_probe_goal_tools(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = false\n")

    for profile in ("security_scan", "deep_security_scan"):
        result = run_preflight(
            "--profile",
            profile,
            "--config",
            str(config_path),
            "--runtime-check",
            "delegation_available=true",
            *standalone_v1(),
        )
        payload = json.loads(result.stdout)
        assert result.returncode == 0
        assert payload["status"] == "ready"
        assert not {"goal_tools", "goals_enabled"} & {
            item["capability"] for item in payload["results"]
        }
        assert not any(
            patch["path"] == "features.goals" for patch in payload["remediation"].get("patches", [])
        )


def test_deep_preflight_compatibility_profile_has_no_runtime_requirements(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = false\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["results"] == []
    assert payload["unknown"] == []
    assert payload["remediation"].get("patches", []) == []


def test_deep_preflight_ignores_unrelated_bridge_backend_configuration(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[multiagent_config]\nmax_concurrency = 4\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["results"] == []


def test_deep_scan_preflight_accepts_native_v1_with_legacy_thread_limits(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[agents]\nmax_threads = 8\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "v1"
    assert payload["failed"] == []
    assert payload["unknown"] == []
    assert payload["remediation"].get("patches", []) == []


def test_deep_scan_preflight_accepts_model_selected_v2_with_legacy_thread_limits(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[agents]\nmax_threads = 8\n\n"
        "[features]\ngoals = true\n\n"
        "[features.multi_agent_v2]\nenabled = false\n"
    )

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        "--multi-agent-runtime-owner",
        "native",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-session-cap",
        "4",
        "--multi-agent-runtime-provenance",
        "thread-context",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "v2"
    assert payload["failed"] == []
    assert payload["unknown"] == []
    assert payload["remediation"].get("patches", []) == []


def test_scan_profiles_do_not_require_or_remediate_csv_fanout() -> None:
    data = tomllib.loads((PLUGIN_ROOT / "preflight" / "capability-profiles.toml").read_text())

    assert "fanout_enabled" not in data["capabilities"]
    for profile in data["profiles"].values():
        assert all(
            requirement["capability"] != "fanout_enabled" for requirement in profile["requirements"]
        )
        assert all(
            patch.get("path") != "features.enable_fanout"
            for patch in profile.get("remediation", {}).get("patches", [])
        )


def test_deep_scan_preflight_does_not_require_available_skill_enumeration(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[features]\ngoals = true\n\n[features.multi_agent_v2]\nenabled = true\n"
    )

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["unknown"] == []


def test_deep_scan_preflight_does_not_block_on_partial_skill_enumeration(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[features]\ngoals = true\n\n[features.multi_agent_v2]\nenabled = true\n"
    )

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills_except("validation"),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["failed"] == []


def test_deep_scan_preflight_rejects_prefixed_plugin_skill_id(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--available-plugin-skill",
        "codex-security:validation",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload == {
        "error": (
            "expected plugin-local skill name, got 'codex-security:validation'; "
            "omit the plugin prefix"
        ),
        "status": "error",
    }


def test_preflight_rejects_multi_agent_mode_override() -> None:
    result = run_preflight(
        "--profile",
        "security_scan",
        "--multi-agent-mode",
        "v1",
    )

    assert result.returncode == 2
    assert "unrecognized arguments: --multi-agent-mode v1" in result.stderr


def test_preflight_keeps_unknown_warning_capabilities_advisory(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        *standalone_v1(),
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert {item["check"] for item in payload["unknown"]} == {"delegation_available"}


def test_preflight_keeps_unknown_suggested_capabilities_advisory(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert {item["check"] for item in payload["unknown"]} == {"goal_tools_available"}


def test_preflight_uses_enabled_goals_default(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert goals["actual"] is True
    assert goals["source"] == "documented-default"


def test_security_scan_keeps_configured_capacity_when_delegation_is_unavailable(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[features]\ngoals = true\n\n"
        "[features.multi_agent_v2]\nenabled = true\n"
        "max_concurrent_threads_per_session = 9\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=false",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    delegation = next(
        item for item in payload["failed"] if item["capability"] == "delegated_workers"
    )
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert delegation["severity"] == "warn"
    assert delegation["actual"] is False
    assert worker_slots["status"] == "pass"
    assert worker_slots["configured_value"] == 9
    assert worker_slots["actual"] == 8


def test_diff_scan_still_suggests_enabling_disabled_goals(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = false\n")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["failed"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert goals["severity"] == "suggest"
    assert goals["actual"] is False
    assert {"path": "features.goals", "value": True} in payload["remediation"]["patches"]


def test_preflight_applies_config_layers_in_cli_order(tmp_path: Path) -> None:
    user_config = tmp_path / "user-config.toml"
    project_config = tmp_path / "project-config.toml"
    user_config.write_text("[agents]\nmax_threads = 6\nmax_depth = 1\n")
    project_config.write_text(
        "[agents]\nmax_threads = 8\nmax_depth = 2\n\n[features]\ngoals = true\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(user_config),
        "--config",
        str(project_config),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert worker_slots["actual"] == 8
    assert worker_slots["source"] == str(project_config)


def test_preflight_discovers_trusted_project_layers_from_cwd(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    cwd = project_root / "package"
    codex_home.mkdir()
    (project_root / ".git").mkdir(parents=True)
    (project_root / ".codex").mkdir()
    (cwd / ".codex").mkdir(parents=True)
    (codex_home / "config.toml").write_text(
        f'[projects."{project_root}"]\ntrust_level = "trusted"\n\n[agents]\nmax_threads = 8\n'
    )
    (project_root / ".codex" / "config.toml").write_text("[agents]\nmax_depth = 1\n")
    (cwd / ".codex" / "config.toml").write_text(
        "[agents]\nmax_depth = 2\n\n[features]\ngoals = true\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--cwd",
        str(cwd),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["config_resolution"] == "cwd-discovery"
    assert payload["user_config_path"] == str(codex_home / "config.toml")
    assert payload["config_paths"] == [
        SYSTEM_CONFIG_PATH,
        str(codex_home / "config.toml"),
        str(project_root / ".codex" / "config.toml"),
        str(cwd / ".codex" / "config.toml"),
    ]
    assert payload["config_discovery"] == {
        "cwd": str(cwd),
        "project_layers_loaded": True,
        "project_root": str(project_root),
        "project_trust_level": "trusted",
    }
    assert worker_slots["actual"] == 8
    assert worker_slots["source"] == str(codex_home / "config.toml")


def test_preflight_expands_tilde_codex_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    codex_home = home / ".codex"
    cwd = tmp_path / "repo"
    codex_home.mkdir(parents=True)
    cwd.mkdir()
    config_path = codex_home / "config.toml"
    config_path.write_text("[agents]\nmax_threads = 8\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--cwd",
        str(cwd),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"HOME": str(home), "CODEX_HOME": "~/.codex"},
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["user_config_path"] == str(config_path)
    assert payload["config_paths"] == [SYSTEM_CONFIG_PATH, str(config_path)]
    assert worker_slots["actual"] == 8
    assert worker_slots["source"] == str(config_path)


def test_preflight_skips_untrusted_project_layers(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    codex_home.mkdir()
    (project_root / ".git").mkdir(parents=True)
    (project_root / ".codex").mkdir()
    (codex_home / "config.toml").write_text(
        f'[projects."{project_root}"]\ntrust_level = "untrusted"\n\n'
        "[agents]\nmax_threads = 4\nmax_depth = 1\n"
    )
    (project_root / ".codex" / "config.toml").write_text("[agents]\nmax_depth = 2\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--cwd",
        str(project_root),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["config_paths"] == [
        SYSTEM_CONFIG_PATH,
        str(codex_home / "config.toml"),
    ]
    assert payload["config_discovery"]["project_layers_loaded"] is False
    worker_slots = next(
        item for item in payload["failed"] if item["capability"] == "usable_worker_slots_6"
    )
    assert worker_slots["actual"] == 4
    assert worker_slots["source"] == str(codex_home / "config.toml")


def test_preflight_loads_legacy_selected_profile_from_manual_config_map(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'profile = "scan"\n\n[features]\ngoals = false\n\n[profiles.scan.features]\ngoals = true\n'
    )

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["config_paths"] == [str(config_path)]
    assert payload["config_profile_path"] is None
    assert payload["config_profile"] == "scan"
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert goals["actual"] is True
    assert goals["source"] == f"{config_path} [profiles.scan]"


def test_embedded_profile_ignores_unsupported_agents_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'profile = "scan"\n\n'
        "[agents]\nmax_threads = 4\nmax_depth = 1\n\n"
        "[features]\ngoals = true\n\n"
        "[profiles.scan.agents]\nmax_threads = 8\nmax_depth = 2\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["failed"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert worker_slots["actual"] == 4
    assert worker_slots["source"] == str(config_path)


def test_higher_layer_overrides_lower_embedded_profile(tmp_path: Path) -> None:
    user_config = tmp_path / "user.toml"
    project_config = tmp_path / "project.toml"
    user_config.write_text('profile = "scan"\n\n[profiles.scan.features]\ngoals = true\n')
    project_config.write_text("[features]\ngoals = false\n")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(user_config),
        "--config",
        str(project_config),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert goals["status"] == "fail"
    assert goals["actual"] is False
    assert goals["source"] == str(project_config)


def test_preflight_loads_current_cli_profile_layer(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    codex_home.mkdir()
    (project_root / ".git").mkdir(parents=True)
    (project_root / ".codex").mkdir()
    (codex_home / "config.toml").write_text(
        f'[projects."{project_root}"]\ntrust_level = "trusted"\n\n[features]\ngoals = false\n'
    )
    profile_path = codex_home / "scan.config.toml"
    profile_path.write_text("[features]\ngoals = true\n")
    (project_root / ".codex" / "config.toml").write_text("")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--cwd",
        str(project_root),
        "--codex-config-profile",
        "scan",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert payload["config_paths"] == [
        SYSTEM_CONFIG_PATH,
        str(codex_home / "config.toml"),
        str(profile_path),
        str(project_root / ".codex" / "config.toml"),
    ]
    assert payload["config_profile"] == "scan"
    assert payload["config_profile_path"] == str(profile_path)
    assert payload["user_config_path"] == str(profile_path)
    assert goals["actual"] is True
    assert goals["source"] == str(profile_path)


def test_trusted_project_config_overrides_current_cli_profile_layer(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    codex_home.mkdir()
    (project_root / ".root-marker").mkdir(parents=True)
    (project_root / ".codex").mkdir()
    (codex_home / "config.toml").write_text("[features]\ngoals = true\n")
    (codex_home / "scan.config.toml").write_text(
        'project_root_markers = [".root-marker"]\n\n'
        "[features]\ngoals = true\n\n"
        f'[projects."{project_root}"]\ntrust_level = "trusted"\n'
    )
    project_config = project_root / ".codex" / "config.toml"
    project_config.write_text("[features]\ngoals = false\n")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--cwd",
        str(project_root),
        "--codex-config-profile",
        "scan",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["config_discovery"]["project_root"] == str(project_root)
    assert payload["config_discovery"]["project_layers_loaded"] is True
    assert goals["status"] == "fail"
    assert goals["severity"] == "suggest"
    assert goals["actual"] is False
    assert goals["source"] == str(project_config)


def test_missing_current_cli_profile_file_is_an_empty_layer(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    codex_home.mkdir()
    project_root.mkdir()
    (codex_home / "config.toml").write_text("[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--cwd",
        str(project_root),
        "--codex-config-profile",
        "missing",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["config_profile"] == "missing"
    assert payload["config_profile_path"] is None


def test_current_cli_profile_name_uses_cli_v2_grammar(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    codex_home.mkdir()
    project_root.mkdir()
    (codex_home / "config.toml").write_text("")

    accepted = run_preflight(
        "--profile",
        "security_scan",
        "--cwd",
        str(project_root),
        "--codex-config-profile=_scan-1",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )
    rejected = run_preflight(
        "--profile",
        "security_scan",
        "--cwd",
        str(project_root),
        "--codex-config-profile",
        "scan.fast",
        env={"CODEX_HOME": str(codex_home)},
    )

    assert accepted.returncode == 0
    assert json.loads(accepted.stdout)["config_profile"] == "_scan-1"
    assert rejected.returncode == 2
    assert "invalid config profile name 'scan.fast'" in json.loads(rejected.stdout)["error"]


def test_preflight_auto_selects_quoted_profile_name(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'profile = "scan.fast"\n\n[profiles."scan.fast".features]\ngoals = true\n'
    )

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["config_profile"] == "scan.fast"
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert goals["actual"] is True


def test_preflight_rejects_missing_legacy_selected_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text('profile = "missing"\n')

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
    )

    assert result.returncode == 2
    assert json.loads(result.stdout) == {
        "error": "config profile 'missing' not found",
        "status": "error",
    }


def test_cli_profile_overrides_config_selected_profile(tmp_path: Path) -> None:
    base_config = tmp_path / "config.toml"
    profile_config = tmp_path / "scan.config.toml"
    base_config.write_text(
        'profile = "default"\n\n'
        "[features]\ngoals = false\n\n"
        "[profiles.default.features]\ngoals = false\n"
    )
    profile_config.write_text("[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--config",
        str(base_config),
        "--config",
        str(profile_config),
        "--codex-config-profile",
        "scan",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert payload["config_profile"] == "scan"
    assert payload["config_profile_path"] is None
    assert goals["actual"] is True
    assert goals["source"] == str(profile_config)


def test_project_profile_selection_and_definitions_are_ignored(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    project_root = tmp_path / "repo"
    codex_home.mkdir()
    (project_root / ".git").mkdir(parents=True)
    (project_root / ".codex").mkdir()
    (codex_home / "config.toml").write_text(
        f'profile = "global"\n\n[projects."{project_root}"]\ntrust_level = "trusted"\n\n'
        "[profiles.global.features]\ngoals = true\n"
    )
    (project_root / ".codex" / "config.toml").write_text(
        'profile = "project"\n\n[profiles.project.features]\ngoals = false\n'
    )

    result = run_preflight(
        "--profile",
        "security_diff_scan",
        "--cwd",
        str(project_root),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *standalone_v1(),
        env={"CODEX_HOME": str(codex_home)},
    )

    payload = json.loads(result.stdout)
    goals = next(item for item in payload["results"] if item["capability"] == "goals_enabled")
    assert result.returncode == 0
    assert payload["config_profile"] == "global"
    assert goals["actual"] is True


def test_profile_native_v2_cap_overrides_base_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'profile = "scan"\n\n'
        "[features]\ngoals = false\n\n"
        "[features.multi_agent_v2]\nenabled = false\n\n"
        "[profiles.scan.features]\ngoals = true\n\n"
        "[profiles.scan.features.multi_agent_v2]\nenabled = true\n"
        "max_concurrent_threads_per_session = 9\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v2"
    assert worker_slots["configured_value"] == 9
    assert worker_slots["actual"] == 8
    assert worker_slots["source"] == f"{config_path} [profiles.scan]"


def test_partial_embedded_profile_v2_table_inherits_base_enabled(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'profile = "scan"\n\n'
        "[features]\ngoals = true\n\n"
        "[features.multi_agent_v2]\nenabled = true\n\n"
        "[profiles.scan.features.multi_agent_v2]\n"
        "max_concurrent_threads_per_session = 9\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v2"
    assert worker_slots["configured_value"] == 9
    assert worker_slots["source"] == f"{config_path} [profiles.scan]"


def test_higher_partial_v2_table_inherits_lower_enabled(tmp_path: Path) -> None:
    user_config = tmp_path / "user.toml"
    project_config = tmp_path / "project.toml"
    user_config.write_text(
        "[features]\ngoals = true\n\n[features.multi_agent_v2]\nenabled = true\n"
    )
    project_config.write_text("[features.multi_agent_v2]\nmax_concurrent_threads_per_session = 9\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(user_config),
        "--config",
        str(project_config),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["results"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v2"
    assert worker_slots["configured_value"] == 9
    assert worker_slots["source"] == str(project_config)


def test_higher_partial_v2_table_replaces_lower_boolean(tmp_path: Path) -> None:
    user_config = tmp_path / "user.toml"
    project_config = tmp_path / "project.toml"
    user_config.write_text("[features]\ngoals = true\nmulti_agent_v2 = true\n")
    project_config.write_text("[features.multi_agent_v2]\nmax_concurrent_threads_per_session = 9\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(user_config),
        "--config",
        str(project_config),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v1"
    assert payload["multi_agent_context"]["version_source"] == "documented-default"


def test_deep_scan_preflight_accepts_native_v2_without_parent_slots(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[features]\ngoals = true\n\n[features.multi_agent_v2]\nenabled = true\n"
    )

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "v2"
    assert {item["capability"] for item in payload["results"]}.isdisjoint(
        {
            "delegated_workers",
            "usable_worker_slots_6",
            "usable_worker_slots_8",
            "agent_depth_2",
            "native_multi_agent_v2",
        }
    )


def test_model_selected_native_v2_does_not_require_observed_parent_cap(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[agents]\nmax_depth = 2\n\n[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--multi-agent-runtime-owner",
        "native",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-runtime-provenance",
        "app-server",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v2"
    assert payload["multi_agent_context"]["owner"] == "native"
    assert payload["status"] == "ready"
    assert payload["unknown"] == []


def test_deep_scan_preflight_does_not_require_verified_parent_runtime_owner(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-session-cap",
        "9",
        "--multi-agent-runtime-provenance",
        "tool-surface",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "unknown"
    assert payload["multi_agent_context"]["owner"] == "unknown"
    assert payload["unknown"] == []
    assert not any(
        patch["path"] == "features.multi_agent_v2.max_concurrent_threads_per_session"
        for patch in payload["remediation"].get("patches", [])
    )


def test_preflight_rejects_native_v2_agents_max_threads_conflict(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[agents]\nmax_threads = 9\n\n"
        "[features.multi_agent_v2]\nenabled = true\n"
        "max_concurrent_threads_per_session = 9\n"
    )

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
    )

    assert result.returncode == 2
    assert json.loads(result.stdout) == {
        "error": "agents.max_threads cannot be set when multi_agent_v2 is enabled",
        "status": "error",
    }


def test_preflight_supports_boolean_native_v2_feature(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = true\nmulti_agent_v2 = true\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v2"
    assert payload["multi_agent_context"]["owner"] == "native"


def test_higher_precedence_boolean_feature_overrides_lower_table(tmp_path: Path) -> None:
    lower_config = tmp_path / "lower.toml"
    higher_config = tmp_path / "higher.toml"
    lower_config.write_text(
        "[features]\ngoals = true\n\n"
        "[features.multi_agent_v2]\nenabled = true\n"
        "max_concurrent_threads_per_session = 9\n"
    )
    higher_config.write_text(
        "[agents]\nmax_threads = 8\nmax_depth = 2\n\n[features]\nmulti_agent_v2 = false\n"
    )

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(lower_config),
        "--config",
        str(higher_config),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v1"
    assert payload["multi_agent_context"]["owner"] == "native"


def test_security_scan_warns_for_insufficient_bridge_worker_slots(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--effective-config",
        "multiagent_config.max_concurrency=4",
        "--multi-agent-runtime-owner",
        "codex-bridge",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-runtime-provenance",
        "verified-bridge",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
    )

    payload = json.loads(result.stdout)
    worker_slots = next(
        item for item in payload["failed"] if item["capability"] == "usable_worker_slots_6"
    )
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert worker_slots["severity"] == "warn"
    assert worker_slots["actual"] == 3
    assert worker_slots["configured_value"] == 4
    assert worker_slots["path"] == "multiagent_config.max_concurrency"
    assert worker_slots["multi_agent_mode"] == "bridge-v2"


def test_preflight_rejects_unverified_bridge_backend_fact(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--effective-config",
        "multiagent_config.max_concurrency=4",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["status"] == "error"
    assert "does not prove bridge ownership" in payload["error"]


def test_preflight_requires_provenance_for_runtime_facts(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--multi-agent-runtime-owner",
        "native",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-session-cap",
        "4",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload == {
        "error": "explicit multi-agent runtime facts require --multi-agent-runtime-provenance",
        "status": "error",
    }


def test_preflight_requires_verified_bridge_provenance(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("")

    result = run_preflight(
        "--profile",
        "security_scan",
        "--config",
        str(config_path),
        "--multi-agent-runtime-owner",
        "codex-bridge",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-runtime-provenance",
        "thread-context",
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload == {
        "error": (
            "codex-bridge ownership requires --multi-agent-runtime-provenance verified-bridge"
        ),
        "status": "error",
    }


def test_deep_scan_preflight_accepts_verified_bridge_owned_runtime(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[agents]\nmax_depth = 2\n\n[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--effective-config",
        "multiagent_config.max_concurrency=4",
        "--multi-agent-runtime-owner",
        "codex-bridge",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-runtime-provenance",
        "verified-bridge",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "bridge-v2"
    assert payload["multi_agent_context"]["owner"] == "codex-bridge"
    assert payload["failed"] == []


def test_deep_scan_preflight_accepts_native_v2_from_static_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[features]\ngoals = true\n\n"
        "[features.multi_agent_v2]\nenabled = true\n"
        "max_concurrent_threads_per_session = 9\n"
    )

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["multi_agent_mode"] == "v2"
    assert payload["multi_agent_context"]["owner"] == "native"
    assert payload["status"] == "ready"
    assert payload["results"] == []
    assert payload["remediation"].get("patches", []) == []


def test_deep_scan_bridge_mode_omits_inapplicable_native_remediation(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[agents]\nmax_depth = 2\n\n[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--effective-config",
        "multiagent_config.max_concurrency=9",
        "--multi-agent-runtime-owner",
        "codex-bridge",
        "--multi-agent-runtime-version",
        "v2",
        "--multi-agent-runtime-provenance",
        "verified-bridge",
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    patches = payload["remediation"].get("patches", [])
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert patches == []
    assert "note" not in payload["remediation"]


def test_deep_scan_preflight_omits_concurrency_patch_when_mode_is_unknown(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[agents]\nmax_depth = 2\n\n[features]\ngoals = true\n")

    result = run_preflight(
        "--profile",
        "deep_security_scan",
        "--config",
        str(config_path),
        "--runtime-check",
        "delegation_available=true",
        "--runtime-check",
        "goal_tools_available=true",
        *available_deep_scan_skills(),
    )

    payload = json.loads(result.stdout)
    patches = payload["remediation"].get("patches", [])
    assert result.returncode == 0
    assert payload["status"] == "ready"
    assert payload["multi_agent_mode"] == "unknown"
    assert payload["unknown"] == []
    assert not any(patch["path"] == "agents.max_threads" for patch in patches)
