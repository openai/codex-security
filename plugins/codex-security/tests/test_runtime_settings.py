from __future__ import annotations

import runpy
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


@pytest.mark.parametrize("configured", [None, "", "  ", "explicit"])
def test_config_and_state_share_blank_home_semantics(tmp_path, monkeypatch, configured):
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CODEX_SECURITY_STATE_DIR", raising=False)
    monkeypatch.delenv("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", raising=False)
    expected = home / ".codex"
    if configured is None:
        monkeypatch.delenv("CODEX_HOME", raising=False)
    else:
        if configured == "explicit":
            configured = str(tmp_path / "selected codex")
            expected = Path(configured)
        monkeypatch.setenv("CODEX_HOME", configured)
    deep = runpy.run_path(str(SCRIPTS / "deep_scan_config.py"))
    preflight = runpy.run_path(str(SCRIPTS / "config_preflight.py"))
    storage = runpy.run_path(str(SCRIPTS / "workbench" / "storage.py"))
    assert deep["config_path"]() == expected / "codex-security" / "config.toml"
    assert preflight["DEFAULT_CONFIG"] == expected / "config.toml"
    assert storage["state_dir"]() == expected / "state" / "plugins" / "codex-security"


def test_integral_toml_counts_match_sdk_values(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text(
        "[deep_scan]\nworkers=4.0\nsubagents=2.0\nstop_after_no_new=3.0\n"
        "stop_after_consecutive_errors=5.0\nmax_discovery_runs=8.0\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", str(config))
    deep = runpy.run_path(str(SCRIPTS / "deep_scan_config.py"))
    values = deep["resolve_deep_scan_config"](8)
    assert values | {"maxTimeHours": 0} == {
        "workers": 4,
        "subagents": 2,
        "stopAfterNoNew": 3,
        "stopAfterConsecutiveErrors": 5,
        "maxDiscoveryRuns": 8,
        "maxTimeHours": 0,
    }
    assert all(type(value) is int for name, value in values.items() if name != "maxTimeHours")


@pytest.mark.parametrize("value", [True, 1.5, float("inf"), float("nan"), "4"])
def test_count_validation_still_rejects_nonintegers(value):
    deep = runpy.run_path(str(SCRIPTS / "deep_scan_config.py"))
    with pytest.raises(SystemExit, match="positive integer"):
        deep["require_integer"](value, "workers", minimum=1)


@pytest.mark.parametrize("absolute", [False, True])
def test_nonblank_home_preserves_literal_spaces(tmp_path, monkeypatch, absolute):
    monkeypatch.chdir(tmp_path)
    home = tmp_path / " selected home "
    home.mkdir()
    (tmp_path / "selected home").mkdir()
    (home / "config.toml").write_text("# selected configuration\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(home) if absolute else home.name)
    monkeypatch.delenv("CODEX_SECURITY_STATE_DIR", raising=False)
    monkeypatch.delenv("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", raising=False)
    deep = runpy.run_path(str(SCRIPTS / "deep_scan_config.py"))
    preflight = runpy.run_path(str(SCRIPTS / "config_preflight.py"))
    storage = runpy.run_path(str(SCRIPTS / "workbench" / "storage.py"))
    assert deep["config_path"]().resolve() == home / "codex-security" / "config.toml"
    assert preflight["DEFAULT_CONFIG"].resolve() == home / "config.toml"
    assert preflight["DEFAULT_CONFIG"].read_text(encoding="utf-8") == "# selected configuration\n"
    assert storage["state_dir"]() == home / "state" / "plugins" / "codex-security"
