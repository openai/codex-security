from __future__ import annotations

import json
import uuid

from workbench_test_support import (
    begin_deep_scan,
    create_workspace,
    get_scan,
    resume_deep_scan,
    run_workbench,
    save_workspace,
    start_workspace_scan,
)


def test_native_setup_snapshots_limits_before_first_coordinator(tmp_path, monkeypatch):
    state = tmp_path / "state"
    target = tmp_path / "repository"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    legacy = tmp_path / "defaults.toml"
    legacy.write_text("[deep_scan]\nworkers=7\nsubagents=2\nmax_time_hours=4\n")
    monkeypatch.setenv("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", str(legacy))
    project = {
        "path": str(target / "security.yaml"),
        "settings": {
            "workers": 2,
            "subagents": 1,
            "stopAfterNoNew": 2,
            "maxDiscoveryRuns": 4,
            "maxTimeHours": 0.5,
        },
    }
    selection = ("--deep-scan-project-json", json.dumps(project))
    preview = run_workbench(
        state,
        "inspect-setup",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
        *selection,
    )["deepScanConfig"]
    assert preview["settings"] == project["settings"] | {"stopAfterConsecutiveErrors": 3}
    assert preview["projectConfigPath"] == project["path"]
    assert preview["sources"]["workers"] == "project"
    assert preview["sources"]["stopAfterConsecutiveErrors"] == "default"
    workspace_id = str(uuid.uuid4())
    create_workspace(state, workspace_id, "--thread-id", "project-owner")
    saved = save_workspace(state, workspace_id, str(target), ".", "deep", *selection)
    assert saved["deepScanConfig"] == preview
    # The original settings survive changes even before the coordinator starts.
    legacy.write_text("invalid TOML")
    scan_id, _ = start_workspace_scan(state, workspace_id, tmp_path / "scans")
    initial = resume_deep_scan(state, scan_id, "project-owner")["deepScan"]
    assert initial["config"] == preview["settings"]
    assert (
        resume_deep_scan(state, scan_id, "project-owner")["deepScan"]["config"] == initial["config"]
    )
    assert get_scan(state, scan_id)["workspace"]["deepScanConfig"] == preview


def test_headless_project_limits_are_isolated_from_unrelated_scans(tmp_path, monkeypatch):
    state = tmp_path / "state"
    target = tmp_path / "repository"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    legacy = tmp_path / "defaults.toml"
    legacy.write_text("[deep_scan]\nworkers=7\nmax_time_hours=4\n")
    monkeypatch.setenv("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH", str(legacy))
    first = begin_deep_scan(
        state,
        "project-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--deep-scan-project-json",
        json.dumps(
            {"path": str(target / "security.json"), "settings": {"workers": 2, "maxTimeHours": 0.5}}
        ),
    )["deepScan"]
    assert begin_deep_scan(state, "other-owner", "--target-path", str(target), "--join-only") == {
        "newScanTarget": str(target.resolve())
    }
    second = begin_deep_scan(
        state, "other-owner", "--target-path", str(target), "--scan-root", str(tmp_path / "scans")
    )["deepScan"]
    assert first["config"]["workers"] == 2
    assert first["config"]["maxTimeHours"] == 0.5
    assert second["config"]["workers"] == 7
    assert second["config"]["maxTimeHours"] == 4
    repeated = begin_deep_scan(state, "project-owner", "--target-path", str(target), "--join-only")[
        "deepScan"
    ]
    assert repeated["scanId"] == first["scanId"]
    assert repeated["config"] == first["config"]
    assert (
        get_scan(state, second["scanId"])["workspace"]["deepScanConfig"]["sources"]["workers"]
        == "legacy"
    )
