from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import run_workbench


def deep_environment(codex_home: Path) -> dict[str, str]:
    return {"CODEX_HOME": str(codex_home)}


def begin_target_scan(
    state_dir: Path, codex_home: Path, target: Path, scan_root: Path
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-deep-scan",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(scan_root),
        "--available-parallelism",
        "16",
        environment=deep_environment(codex_home),
    )


@pytest.mark.parametrize(
    ("settings", "model", "effort"),
    (
        ("", None, None),
        ('discovery_model = "gpt-5.6-luna"\n', "gpt-5.6-luna", None),
        ('discovery_reasoning_effort = "xhigh"\n', None, "xhigh"),
        (
            'discovery_model = "gpt-5.6-luna"\ndiscovery_reasoning_effort = "xhigh"\n',
            "gpt-5.6-luna",
            "xhigh",
        ),
    ),
)
def test_discovery_model_settings_are_independent_and_optional(
    tmp_path: Path, settings: str, model: str | None, effort: str | None
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[deep_scan]\n" + settings)
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]

    assert deep_scan["config"].get("discoveryModel") == model
    assert deep_scan["config"].get("discoveryReasoningEffort") == effort
    if model is None:
        assert "discoveryModel" not in deep_scan["config"]
    if effort is None:
        assert "discoveryReasoningEffort" not in deep_scan["config"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT discovery_model, discovery_reasoning_effort FROM deep_scan_runs"
        ).fetchone() == (model, effort)


@pytest.mark.parametrize(
    ("setting", "value"),
    (
        ("discovery_model", '""'),
        ("discovery_model", '"   "'),
        ("discovery_model", "false"),
        ("discovery_reasoning_effort", '""'),
        ("discovery_reasoning_effort", "12"),
    ),
)
def test_invalid_discovery_model_setting_fails_before_scan_creation(
    tmp_path: Path, setting: str, value: str
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(f"[deep_scan]\n{setting} = {value}\n")
    target = tmp_path / "target"
    target.mkdir()

    failed = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-deep-scan",
        "--target-path",
        str(target),
        "--available-parallelism",
        "8",
        environment=deep_environment(codex_home),
        check=False,
    )

    assert f"deep_scan.{setting} must be a non-empty string" in str(failed["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (0,)
