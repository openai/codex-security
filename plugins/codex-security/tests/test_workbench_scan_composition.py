from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest import mock

import pytest
from workbench_test_support import SCRIPT, run_workbench, write_checkpoint, write_completed_contract

CHECKPOINT = "artifacts/deep-scan/checkpoint.json"
EXECUTION_THREADS = "artifacts/deep-scan/execution-threads.json"


def recipe(target: Path, mode: str = "standard") -> dict:
    return {
        "repository": str(target),
        "target": {"kind": "repository", "paths": []},
        "mode": mode,
        "config": {"model": "synthetic-model", "model_reasoning_effort": "high"},
        **({"deepScan": {"maxDiscoveryRuns": 8}} if mode == "deep" else {}),
    }


def register(
    state: Path, target: Path, directory: Path, *, mode="standard", parent=None, paths=()
) -> dict:
    missing = []
    current = directory
    while not current.exists():
        missing.append(current)
        current = current.parent
    for path in reversed(missing):
        path.mkdir(mode=0o700)
    saved_recipe = recipe(target, mode)
    if paths:
        saved_recipe["target"] = {"kind": "paths", "paths": list(paths)}
    return run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(saved_recipe),
        *(("--parent-scan-id", parent) if parent else ()),
    )


def checkpoint(state: Path, scan: dict, *, passes=(), merged=(), terminal=None) -> dict:
    value = {
        "version": 2,
        "startedAt": "2026-01-01T00:00:00Z",
        "passes": list(passes),
        "mergedScanIds": list(merged),
        "aggregate": [],
        "noNewStreak": 0,
        "consecutiveErrors": 0,
        **({"terminalReason": terminal} if terminal else {}),
    }
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(value),
    )
    return value


def test_checkpoint_read_blocks_other_threads_and_atomic_writers(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    original = checkpoint(state, scan)
    updated = {**original, "noNewStreak": 1}
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    read_checkpoint = workbench_api["read_composition_checkpoint"]
    reading, release_read, thread_waiting, thread_acquired = (Event() for _ in range(4))

    def paused_read(scan_dir: Path, relative: str, context: str) -> dict:
        descriptor = workbench_api["open_scan_local_file_descriptor"](scan_dir, relative, context)
        with os.fdopen(descriptor, "rb") as source:
            reading.set()
            assert release_read.wait(10)
            return json.load(source)

    def competing_thread() -> None:
        thread_waiting.set()
        with workbench_api["scan_completion_lock"](scan["scanId"]):
            thread_acquired.set()

    writer_script = """
import runpy, sys
sys.path.insert(0, sys.argv[1])
from workbench import storage
acquire = storage.acquire_completion_file_lock
def announce_acquire(descriptor):
    print("waiting", flush=True)
    acquire(descriptor)
storage.acquire_completion_file_lock = announce_acquire
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
    with (
        mock.patch.dict(read_checkpoint.__globals__, _read_scan_local_json=paused_read),
        ThreadPoolExecutor(max_workers=3) as executor,
    ):
        reader = executor.submit(
            read_checkpoint, {"id": scan["scanId"], "scan_dir": scan["scanDir"]}
        )
        writer = None
        try:
            assert reading.wait(5)
            contender = executor.submit(competing_thread)
            assert thread_waiting.wait(5)
            assert not thread_acquired.wait(0.1)
            writer = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    writer_script,
                    str(SCRIPT.parent),
                    str(SCRIPT),
                    "save-scan-artifact",
                    "--scan-id",
                    scan["scanId"],
                    "--artifact-path",
                    CHECKPOINT,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            writer.stdin.write(json.dumps(updated))
            writer.stdin.close()
            writer.stdin = None
            assert executor.submit(writer.stdout.readline).result(timeout=5).strip() == "waiting"
            with pytest.raises(subprocess.TimeoutExpired):
                writer.wait(timeout=0.1)
            assert json.loads((Path(scan["scanDir"]) / CHECKPOINT).read_text()) == original
        finally:
            release_read.set()
            if writer is not None:
                try:
                    stdout, stderr = writer.communicate(timeout=10)
                finally:
                    if writer.poll() is None:
                        writer.kill()
                        writer.communicate()
        assert reader.result(timeout=5) == original
        contender.result(timeout=5)
        assert writer.returncode == 0, stderr
        assert json.loads(stdout)["scanId"] == scan["scanId"]
    assert json.loads((Path(scan["scanDir"]) / CHECKPOINT).read_text()) == updated


def test_standard_resume_retains_registration_before_and_after_thread_binding(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan")
    resume = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resume["scanId"] == scan["scanId"]
    assert resume["threadId"] is None
    assert resume["recipe"] == recipe(target)
    run_workbench(state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "execution")
    resume = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resume["threadId"] == "execution"
    assert len(run_workbench(state, "list-scans")["scans"]) == 1
    (target / "app.py").write_text("print('changed')\n")
    rejected = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False)
    assert "original checkout revision or contents changed" in rejected["stderr"]


@pytest.mark.parametrize("compact", [False, True])
def test_resume_distinguishes_empty_artifact_drafts_from_sealed_results(
    tmp_path: Path, compact: bool
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state, directory = tmp_path / "state", tmp_path / "scan"
    scan = register(state, target, directory)
    run_workbench(state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "execution")
    path = directory / "scan-manifest.json"
    path.write_text(json.dumps({"scan": {"artifacts": []}}))
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert "sealedProducerVersion" not in resumed
    assert not (directory / "findings.json").exists()

    write_completed_contract(directory, scan["scanId"], target)
    manifest = json.loads(path.read_text())
    manifest["scan"]["artifacts"] = []
    if compact:
        del manifest["scan"]["producer"]
    path.write_text(json.dumps(manifest))
    draft = path.read_bytes()

    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert "sealedProducerVersion" not in resumed
    assert path.read_bytes() == draft

    run_workbench(state, "prepare-scan-completion", "--scan-id", scan["scanId"])
    sealed = path.read_bytes()
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resumed["sealedProducerVersion"] == json.loads(sealed)["scan"]["producer"]["version"]
    assert path.read_bytes() == sealed


@pytest.mark.parametrize("rejoin_context", [None, "Different optional context."])
def test_native_parent_binds_once_and_keeps_native_claim(
    tmp_path: Path, rejoin_context: str | None
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    arguments = (
        "begin-deep-scan",
        "--thread-id",
        "native-owner",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
    )
    created = run_workbench(state, *arguments, "--user-context", "Original optional context.")
    scan = created["scan"]
    arguments += ("--user-context", rejoin_context) if rejoin_context else ()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET handoff_status = 'pending'")
    rejected = run_workbench(state, *arguments, check=False)
    assert "owned by another continuation" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET handoff_status = 'delivered'")
    joined = run_workbench(state, *arguments)
    assert joined["startDisposition"] == "joined"
    for key in ("scanId", "scanDir", "handoffClaimToken", "userContext"):
        assert joined["scan"][key] == scan[key]
    token = scan["handoffClaimToken"]
    registration = {
        "recipe": recipe(target, "deep"),
        "scanId": scan["scanId"],
        "threadId": "native-owner",
        "claimToken": token,
    }
    bind = (
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        scan["scanDir"],
        "--registration-json-stdin",
    )
    rejected = run_workbench(
        state,
        *bind,
        input_text=json.dumps({**registration, "claimToken": None}),
        check=False,
    )
    assert "owned by another continuation" in rejected["stderr"]
    first = run_workbench(state, *bind, input_text=json.dumps(registration))
    assert first["threadId"] is None
    assert first["claimToken"] == token
    assert run_workbench(state, *bind, input_text=json.dumps(registration))["threadId"] is None
    joined = run_workbench(state, *arguments)
    for key in ("scanId", "scanDir", "handoffClaimToken", "userContext"):
        assert joined["scan"][key] == scan[key]
    context_args = (
        "update-scan-context",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "native-owner",
        "--claim-token",
        token,
    )
    assert (
        run_workbench(state, *context_args, "--user-context", "Before merger.")["scan"][
            "userContext"
        ]
        == "Before merger."
    )
    rejected = run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "sdk-execution",
        check=False,
    )
    assert rejected["returncode"] != 0
    run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "sdk-execution",
        "--claim-token",
        token,
    )
    delivered = run_workbench(
        state,
        "mark-handoff-delivered",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "native-owner",
        "--claim-token",
        token,
    )
    assert delivered["results"]["handoffStatus"] == "delivered"
    assert delivered["results"]["continuationThreadId"] == "sdk-execution"
    assert (
        run_workbench(state, *context_args, "--user-context", "After merger.")["scan"][
            "userContext"
        ]
        == "After merger."
    )
    for owner, claim in (
        ("other-owner", token),
        ("sdk-execution", token),
        ("native-owner", "00000000-0000-4000-8000-000000000000"),
    ):
        rejected = run_workbench(
            state,
            "begin-deep-scan",
            "--scan-id",
            scan["scanId"],
            "--thread-id",
            owner,
            "--claim-token",
            claim,
            check=False,
        )
        assert rejected["returncode"] != 0
        rejected = run_workbench(
            state,
            "update-scan-context",
            "--scan-id",
            scan["scanId"],
            "--thread-id",
            owner,
            "--claim-token",
            claim,
            "--user-context",
            "Unauthorized replacement.",
            check=False,
        )
        assert rejected["returncode"] != 0
        rejected_delivery = run_workbench(
            state,
            "mark-handoff-delivered",
            "--scan-id",
            scan["scanId"],
            "--thread-id",
            owner,
            "--claim-token",
            claim,
            check=False,
        )
        assert rejected_delivery["returncode"] != 0
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["userContext"]
        == "After merger."
    )
    rebound = run_workbench(state, *bind, input_text=json.dumps(registration))
    assert rebound["threadId"] == "sdk-execution"
    resumed = run_workbench(
        state,
        "get-cli-scan-resume",
        "--scan-id",
        scan["scanId"],
        "--claim-token",
        token,
    )
    assert resumed["threadId"] == "sdk-execution"
    assert len(run_workbench(state, "list-scans")["scans"]) == 1
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_runs").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_workers").fetchone()[0] == 0
    rejected = run_workbench(
        state,
        "cancel-scan",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "other-owner",
        check=False,
    )
    assert rejected["returncode"] != 0
    run_workbench(state, "cancel-scan", "--scan-id", scan["scanId"], "--thread-id", "native-owner")
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["progress"]["status"]
        == "canceled"
    )

    joined = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "native-owner",
        "--claim-token",
        token,
    )
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["progress"]["status"] == "canceled"
    rejected = run_workbench(
        state,
        "get-cli-scan-resume",
        "--scan-id",
        scan["scanId"],
        "--claim-token",
        token,
        check=False,
    )
    assert rejected["returncode"] != 0


@pytest.mark.parametrize("target_entry", [False, True])
@pytest.mark.parametrize("recipe_maximum", [None, 9])
def test_native_legacy_settings_are_returned_only_without_a_saved_recipe(
    tmp_path: Path, target_entry: bool, recipe_maximum: int | None
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    created = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "native-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    assert "deepScanSettings" not in created
    scan = created["scan"]
    token = None if target_entry else scan["handoffClaimToken"]
    if target_entry:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET handoff_claim_token = NULL, continuation_thread_id = NULL "
                "WHERE id = ?",
                (scan["scanId"],),
            )
    joined_args = (
        "begin-deep-scan",
        "--thread-id",
        "native-owner",
        *(
            ("--target-path", str(target))
            if target_entry
            else ("--scan-id", scan["scanId"], "--claim-token", token)
        ),
    )
    assert "deepScanSettings" not in run_workbench(state, *joined_args)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
            "status, phase, workers, subagents, stop_after_no_new, "
            "stop_after_consecutive_errors, max_discovery_runs, max_time_hours, "
            "discovery_runs_dispatched, completion_sequence, consecutive_no_new, consecutive_errors, "
            "created_at, updated_at) "
            "VALUES (?, 1, 'synthetic-legacy', 'running', 'setup', 2, 0, 3, 4, 8, 0.5, 3, 2, 2, 1, ?, ?)",
            (scan["scanId"], "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        legacy = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
    for _ in range(2):
        joined = run_workbench(state, *joined_args)
        assert joined["startDisposition"] == "joined"
        assert joined["scan"]["scanId"] == scan["scanId"]
        assert joined["scan"]["scanDir"] == scan["scanDir"]
        assert joined["scan"]["handoffClaimToken"] == token
        assert joined["scan"]["progress"]["independentReviews"] == {
            "active": 0,
            "completed": 2,
            "maximum": 8,
            "consolidating": False,
        }
        assert joined["deepScanSettings"] == {
            "workers": 2,
            "subagents": 0,
            "stopAfterNoNew": 3,
            "stopAfterConsecutiveErrors": 4,
            "maxDiscoveryRuns": 8,
            "maxTimeHours": 0.5,
        }
    rejected = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "other-owner",
        *(("--claim-token", token) if token else ()),
        check=False,
    )
    assert "owning Codex thread" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT * FROM deep_scan_runs").fetchone() == legacy
        assert connection.execute(
            "SELECT deep_scan_owner_thread_id, continuation_thread_id, handoff_claim_token FROM scans"
        ).fetchall() == [("native-owner", None if target_entry else "native-owner", token)]
    saved_recipe = recipe(target, "deep")
    if recipe_maximum is None:
        del saved_recipe["deepScan"]
    else:
        saved_recipe["deepScan"]["maxDiscoveryRuns"] = recipe_maximum
    run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        scan["scanDir"],
        "--registration-json-stdin",
        input_text=json.dumps(
            {
                "recipe": saved_recipe,
                "scanId": scan["scanId"],
                "threadId": "native-owner",
                "claimToken": token,
            }
        ),
    )
    joined = run_workbench(state, *joined_args)
    assert joined["scan"]["scanId"] == scan["scanId"]
    assert joined["recipe"] == saved_recipe
    assert "deepScanSettings" not in joined
    assert joined["compositionCheckpoint"]["legacy"]["originThreadId"] == "native-owner"
    assert joined["compositionCheckpoint"]["legacy"]["discoveryRuns"] == 3
    assert joined["compositionCheckpoint"]["noNewStreak"] == 2
    assert joined["compositionCheckpoint"]["consecutiveErrors"] == 1
    assert joined["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": 2,
        "maximum": recipe_maximum or 8,
        "consolidating": False,
    }
    scan_dir = Path(scan["scanDir"])
    saved_checkpoint = json.loads((scan_dir / CHECKPOINT).read_text())
    children = []
    for index in range(1, 3):
        directory = f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, scan_dir / directory, parent=scan["scanId"])
        children.append(child)
        saved_checkpoint["passes"].append({"directory": directory, "scanId": child["scanId"]})
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        *(("--claim-token", token) if token else ()),
        input_text=json.dumps(saved_checkpoint),
    )
    child = children[0]
    write_completed_contract(
        Path(child["scanDir"]), child["scanId"], target, relative_path="app.py"
    )
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    joined = run_workbench(state, *joined_args)
    assert joined["scan"]["progress"]["independentReviews"] == {
        "active": 1,
        "completed": 3,
        "maximum": recipe_maximum or 8,
        "consolidating": True,
    }


@pytest.mark.parametrize(
    "legacy",
    [
        None,
        {},
        {
            "coverage": {"deferred": ["full coverage"]},
            "discoveryRuns": 3,
            "cost": {"estimatedUsd": 2},
            "originThreadId": "legacy-thread",
        },
    ],
)
def test_scan_context_projects_composition_metadata_without_changing_checkpoint(
    tmp_path: Path, legacy: dict | None
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep")
    assert (
        run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["compositionCheckpoint"]
        is None
    )
    saved = checkpoint(state, parent)
    saved.update(
        aggregate={
            "findings": [{"details": "full finding"}],
            "coverage": {"surfaces": ["full surface"]},
        },
        legacy=legacy,
        mergeFailures=2,
        terminalReason=None,
    )
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(saved),
    )
    checkpoint_path = Path(parent["scanDir"]) / CHECKPOINT
    full_checkpoint = checkpoint_path.read_bytes()
    expected = {key: value for key, value in saved.items() if key != "aggregate"}
    if isinstance(legacy, dict):
        expected["legacy"] = {key: value for key, value in legacy.items() if key != "coverage"}
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert context["compositionCheckpoint"] == expected
    assert checkpoint_path.read_bytes() == full_checkpoint
    assert json.loads(full_checkpoint) == saved


def test_composition_checkpoint_advances_discovery_without_regressing_resumed_progress(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        "artifacts/note.txt",
        input_text="synthetic note",
    )
    assert (
        run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]["progress"]["phase"]
        == "preflight"
    )
    for phase in ("preflight", "threat_model", "discovery", "validation", "reporting"):
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute("UPDATE scans SET phase = ? WHERE id = ?", (phase, parent["scanId"]))
            connection.execute(
                "UPDATE scan_progress SET phase_items_total = 4, phase_items_completed = 2, "
                "phase_progress_unit = 'checks' WHERE scan_id = ?",
                (parent["scanId"],),
            )
        checkpoint(state, parent)
        progress = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"][
            "progress"
        ]
        advanced = phase in ("preflight", "threat_model")
        assert progress["phase"] == ("discovery" if advanced else phase)
        assert progress["phaseProgress"] == (
            {"total": 0, "completed": 0, "unit": None}
            if advanced
            else {"total": 4, "completed": 2, "unit": "checks"}
        )
    ordinary = register(state, target, tmp_path / "ordinary")
    checkpoint(state, ordinary)
    assert (
        run_workbench(state, "get-scan", "--scan-id", ordinary["scanId"])["scan"]["progress"][
            "phase"
        ]
        == "preflight"
    )


def test_parent_reads_completed_child_after_registration_checkpoint_crash(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state, "set-scan-thread", "--scan-id", parent["scanId"], "--thread-id", "merge-thread"
    )
    parent_dir = Path(parent["scanDir"])
    pass_directory = "artifacts/deep-scan/passes/pass-1"
    directory = parent_dir / pass_directory
    saved = checkpoint(state, parent, passes=[{"directory": pass_directory}])
    child = register(state, target, directory, parent=parent["scanId"])
    run_workbench(
        state, "set-scan-thread", "--scan-id", child["scanId"], "--thread-id", "child-thread"
    )
    unrelated = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    run_workbench(
        state, "set-scan-thread", "--scan-id", unrelated["scanId"], "--thread-id", "rerun-thread"
    )
    write_completed_contract(directory, child["scanId"], target, relative_path="app.py")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    child_bytes = (directory / "scan-manifest.json").read_bytes()
    visible = run_workbench(state, "list-scans")["scans"]
    assert {item["scanId"] for item in visible} == {parent["scanId"], unrelated["scanId"]}
    assert run_workbench(state, "list-global-findings")["findings"] == []
    assert (
        run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["findingCount"] == 1
    )
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert context["scan"]["progress"]["phase"] == "discovery"
    assert context["compositionCheckpoint"] == {
        key: value for key, value in saved.items() if key != "aggregate"
    }
    assert context["scan"]["executionThreadIds"] == ["merge-thread", "child-thread"]
    assert context["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": 1,
        "maximum": 8,
        "consolidating": True,
    }
    recovered = run_workbench(state, "list-scans", "--scan-root", str(directory))["scans"]
    assert [item["scanId"] for item in recovered] == [child["scanId"]]
    assert recovered[0]["parentScanId"] == parent["scanId"]
    write_completed_contract(
        parent_dir,
        parent["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    blocked = run_workbench(state, "complete-scan", "--scan-id", parent["scanId"], check=False)
    assert "must finish and save its aggregate" in blocked["stderr"]
    saved["passes"][0]["scanId"] = child["scanId"]
    saved["mergedScanIds"] = [child["scanId"]]
    saved["terminalReason"] = "saturated"
    saved["aggregate"] = {
        "scanId": parent["scanId"],
        "findings": json.loads((parent_dir / "findings.json").read_text())["findings"],
        "coverage": json.loads((parent_dir / "coverage.json").read_text()),
    }
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(saved),
    )
    prepared = run_workbench(state, "prepare-scan-completion", "--scan-id", parent["scanId"])
    assert prepared["scan"]["progress"]["phase"] == "reporting"
    assert prepared["scan"]["progress"]["status"] == "running"
    run_workbench(state, "complete-scan", "--scan-id", parent["scanId"])
    assert (directory / "scan-manifest.json").read_bytes() == child_bytes
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert context["scan"]["progress"]["status"] == "complete"
    assert context["scan"]["findingCount"] == 1
    assert context["scan"]["progress"]["independentReviews"]["consolidating"] is False
    assert json.loads((parent_dir / "coverage.json").read_text())["completeness"] == "complete"
    assert json.loads((parent_dir / CHECKPOINT).read_text()) == saved
    indexed = run_workbench(state, "list-global-findings")["findings"]
    assert len(indexed) == 1
    assert indexed[0]["scanId"] == parent["scanId"]
    assert indexed[0]["knownScanIds"] == [parent["scanId"]]
    assert run_workbench(state, "list-repositories")["repositories"][0]["scanCount"] == 2
    (parent_dir / EXECUTION_THREADS).write_text(json.dumps(["follow-up", "follow-up"]))
    completed = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert completed["continuationThreadId"] == "merge-thread"
    assert completed["threadIds"] == ["merge-thread", "follow-up", "child-thread"]
    assert completed["executionThreadIds"] == completed["threadIds"]


def test_failed_deep_scan_keeps_followup_thread_before_composition_checkpoint(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic failure."
    )
    metadata = Path(scan["scanDir"]) / EXECUTION_THREADS
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps(["failed-follow-up", "repeated-follow-up"]))
    context = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])
    assert context["compositionCheckpoint"] is None
    assert context["scan"]["continuationThreadId"] is None
    assert context["scan"]["progress"]["status"] == "failed"
    assert context["scan"]["threadIds"] == ["failed-follow-up", "repeated-follow-up"]
    assert context["scan"]["executionThreadIds"] == context["scan"]["threadIds"]


@pytest.mark.parametrize("missing", ["checkpoint", "output"])
def test_history_hides_composition_children_without_parent_artifacts(
    tmp_path: Path, missing: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    parent_dir = tmp_path / "scan"
    parent = register(state, target, parent_dir, mode="deep")
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, parent_dir / child_path, parent=parent["scanId"])
    checkpoint(state, parent, passes=[{"directory": child_path, "scanId": child["scanId"]}])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for day, scan in enumerate((parent, rerun, child), 1):
            connection.execute(
                "UPDATE scans SET started_at = ? WHERE id = ?",
                (f"2026-01-0{day}T00:00:00Z", scan["scanId"]),
            )
    for scan in (rerun, child):
        write_completed_contract(
            Path(scan["scanDir"]), scan["scanId"], target, relative_path="app.py"
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    if missing == "checkpoint":
        (parent_dir / CHECKPOINT).unlink()
    else:
        parent_dir.rename(tmp_path / "removed-output")

    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        rerun["scanId"],
    }
    assert (
        run_workbench(state, "list-scans", "--status", "complete", "--limit", "1")["scans"][0][
            "scanId"
        ]
        == rerun["scanId"]
    )
    indexed = run_workbench(state, "list-global-findings")["findings"]
    assert len(indexed) == 1
    assert indexed[0]["scanId"] == rerun["scanId"]
    assert indexed[0]["occurrenceCount"] == 1
    assert indexed[0]["knownScanIds"] == [rerun["scanId"]]
    visible = run_workbench(state, "get-scan", "--scan-id", rerun["scanId"])["scan"]
    assert "knownScanIds" not in visible["findings"][0]
    assert "matches" not in visible["findings"][0]
    repository = run_workbench(state, "list-repositories")["repositories"][0]
    assert repository["scanCount"] == 2
    assert repository["latestScan"]["scanId"] == rerun["scanId"]
    explicit = run_workbench(state, "list-scans", "--scan-root", child["scanDir"])["scans"]
    assert [scan["scanId"] for scan in explicit] == [child["scanId"]]
    assert (
        run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["findingCount"] == 1
    )


def test_archiving_composition_preserves_children_and_reuses_pass_directories(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, directory / child_path, parent=parent["scanId"])
    saved = checkpoint(state, parent, passes=[{"directory": child_path}])
    unrelated = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    for scan in (child, unrelated):
        write_completed_contract(
            Path(scan["scanDir"]),
            scan["scanId"],
            target,
            relative_path="app.py",
            identity_anchor=scan["scanId"],
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption."
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        old_scans = {row["id"]: dict(row) for row in connection.execute("SELECT * FROM scans")}
        old_artifacts = [dict(row) for row in connection.execute("SELECT * FROM scan_artifacts")]
        old_findings = connection.execute("SELECT * FROM finding_occurrences").fetchall()
    child_manifest = (directory / child_path / "scan-manifest.json").read_bytes()
    archived = tmp_path / "scan.previous-test"
    directory.rename(archived)
    directory.mkdir(mode=0o700)
    current = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe(target, "deep")),
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
    )

    archived_child = run_workbench(state, "get-scan", "--scan-id", child["scanId"])
    assert archived_child["scan"]["scanDir"] == str(archived / child_path)
    assert archived_child["scan"]["findingCount"] == 1
    assert (archived / child_path / "scan-manifest.json").read_bytes() == child_manifest
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert context["compositionCheckpoint"] == {
        key: value for key, value in saved.items() if key != "aggregate"
    }
    assert context["scan"]["progress"]["independentReviews"]["completed"] == 1
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        current["scanId"],
        unrelated["scanId"],
    }
    assert {
        finding["scanId"] for finding in run_workbench(state, "list-global-findings")["findings"]
    } == {parent["scanId"], unrelated["scanId"]}
    assert run_workbench(state, "list-repositories")["repositories"][0]["scanCount"] == 3
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        for scan_id, old in old_scans.items():
            if scan_id != unrelated["scanId"]:
                old["scan_dir"] = str(archived / Path(old["scan_dir"]).relative_to(directory))
                old.pop("updated_at")
            actual = dict(
                connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            )
            assert {key: actual[key] for key in old} == old
        for artifact in old_artifacts:
            if artifact["scan_id"] != unrelated["scanId"]:
                artifact["path"] = str(archived / Path(artifact["path"]).relative_to(directory))
            actual = connection.execute(
                "SELECT * FROM scan_artifacts WHERE scan_id = ? AND kind = ?",
                (artifact["scan_id"], artifact["kind"]),
            ).fetchone()
            assert dict(actual) == artifact
            assert Path(actual["path"]).is_file()
        assert connection.execute("SELECT * FROM finding_occurrences").fetchall() == old_findings
    replacement = register(state, target, directory / child_path, parent=current["scanId"])
    assert replacement["scanId"] != child["scanId"]
    assert replacement["scanDir"] == str(directory / child_path)


@pytest.mark.parametrize("action", ["fail-scan", "cancel-scan"])
def test_stopped_standard_cannot_resume_and_preserves_checkpoint(
    tmp_path: Path, action: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan")
    write_completed_contract(Path(scan["scanDir"]), scan["scanId"], target, relative_path="app.py")
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "synthetic interruption") if action == "fail-scan" else ()),
    )
    before = (Path(scan["scanDir"]) / "scan-manifest.json").read_bytes()
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False)
    assert "completed, failed, and canceled scans cannot resume" in resumed["stderr"]
    assert (Path(scan["scanDir"]) / "scan-manifest.json").read_bytes() == before
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findingCount"] == 1
    )


def test_stopped_standard_does_not_rebind_another_scans_coverage(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan")
    directory = Path(scan["scanDir"])
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    coverage = json.loads((directory / "coverage.json").read_text())
    coverage["scanId"] = "00000000-0000-4000-8000-000000000000"
    raw = json.dumps(coverage).encode()
    (directory / "coverage.json").write_bytes(raw)
    for name in ("scan-manifest.json", "findings.json", "report.md"):
        (directory / name).unlink()
    run_workbench(state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Interrupted.")
    assert (directory / "coverage.json").read_bytes() == raw
    assert not (directory / "scan-manifest.json").exists()
    assert not (directory / "findings.json").exists()
    assert not list((directory / "checkpoints").glob("*.json"))
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findingCount"] == 0
    )


@pytest.mark.parametrize("accepted_membership", ["merged", "represented"])
def test_native_cancel_retains_accepted_and_later_unmerged_findings(
    tmp_path: Path, accepted_membership: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index, anchor in enumerate(("accepted-finding", "separate-unmerged-finding"), 1):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"])
        write_completed_contract(
            directory, child["scanId"], target, relative_path="app.py", identity_anchor=anchor
        )
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        protected = {
            name: (directory / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json")
        }
        children.append((child, directory, protected))
    first, _, first_bytes = children[0]
    original = json.loads(first_bytes["findings.json"])["findings"][0]
    accepted = copy.deepcopy(original)
    accepted["provenance"]["sourceFindingIds"] = [f"{first['scanId']}:0"]
    accepted["provenance"]["sourceFindings"] = [{"id": f"{first['scanId']}:0", "finding": original}]
    saved = checkpoint(
        state,
        parent,
        passes=[
            {"directory": directory.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
            for child, directory, _ in children
        ],
        merged=[first["scanId"]] if accepted_membership == "merged" else [],
    )
    saved["noNewStreak"] = 2
    saved["aggregate"] = {
        "scanId": parent["scanId"],
        "findings": [accepted],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [{"reason": "Accepted pass still needs dependency review."}],
        },
    }
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(saved),
    )
    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert context["progress"]["status"] == "canceled"
    assert context["findingCount"] == 2
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
    preserved = next(finding for finding in retained if finding["identity"] == accepted["identity"])
    assert preserved["findingId"] == accepted["findingId"]
    assert preserved["provenance"]["sourceFindings"] == accepted["provenance"]["sourceFindings"]
    later, _, later_bytes = children[1]
    recovered = next(
        finding
        for finding in retained
        if finding["provenance"]["sourceFindingIds"] == [f"{later['scanId']}:0"]
    )
    assert recovered["identity"]["anchor"] == "separate-unmerged-finding"
    assert (
        recovered["provenance"]["sourceFindings"][0]["finding"]
        == json.loads(later_bytes["findings.json"])["findings"][0]
    )
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert any(row["reason"].startswith("Accepted pass still") for row in coverage["deferred"])
    assert any("artifacts/deep-scan/passes/pass-2" in row["reason"] for row in coverage["deferred"])
    for child, directory, protected in children:
        for name, contents in protected.items():
            assert (directory / name).read_bytes() == contents
        assert (
            run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["progress"][
                "status"
            ]
            == "complete"
        )
    assert json.loads((parent_dir / CHECKPOINT).read_text()) == saved


@pytest.mark.parametrize("has_aggregate", [False, True])
@pytest.mark.parametrize(
    ("terminal_reason", "child_state"),
    [
        ("capped", "failed"),
        ("capped", "canonical"),
        ("capped", "checkpoint"),
        ("capped", "coverage"),
        ("saturated", "checkpoint"),
    ],
)
def test_terminal_scoped_parent_preserves_unmerged_child_results(
    tmp_path: Path, has_aggregate: bool, child_state: str, terminal_reason: str
) -> None:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src/app.py").write_text("\n" * 50)
    (target / "outside.py").write_text("print('outside selected scope')\n")
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep", paths=["src"])
    parent_dir = Path(parent["scanDir"])
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], paths=["src"])
        write_completed_contract(
            directory,
            child["scanId"],
            target,
            relative_path="src/app.py",
            identity_anchor=f"independent-{index}",
            include_paths=["src"],
            coverage_mode="scoped_path",
            inventory_strategy="scoped_path",
        )
        findings = json.loads((directory / "findings.json").read_text())["findings"]
        outside = copy.deepcopy(findings[0])
        outside["identity"]["anchor"] = f"outside-{index}"
        outside["locations"][0]["path"] = "outside.py"
        outside["writeup"] = {"reportPath": "findings/outside/outside.md"}
        report = directory / "findings/outside/outside.md"
        report.parent.mkdir(parents=True)
        report.write_text("# Outside the selected scope\n")
        findings[0]["locations"].insert(0, copy.deepcopy(outside["locations"][0]))
        findings.insert(0, outside)
        (directory / "findings.json").write_text(json.dumps({"findings": findings}))
        coverage = json.loads((directory / "coverage.json").read_text())
        (directory / "artifacts").mkdir()
        (directory / "artifacts/receipt.json").write_text(json.dumps({"pass": index}))
        coverage["surfaces"][0]["receiptRefs"] = ["artifacts/receipt.json"]
        if index == 2 and child_state == "coverage":
            coverage["surfaces"][0]["disposition"] = "needs_follow_up"
            coverage["deferred"] = [
                {
                    "id": "unvalidated",
                    "reason": "Candidate requires validation.",
                    "candidate": {
                        "title": "Unvalidated observation",
                        "summary": "Needs a source trace.",
                    },
                    "surfaceIds": ["surface_archive_extraction"],
                }
            ]
        (directory / "coverage.json").write_text(json.dumps(coverage))
        if index == 1:
            run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        elif child_state == "canonical":
            run_workbench(
                state,
                "fail-scan",
                "--scan-id",
                child["scanId"],
                "--defer-publication",
                "--message",
                "Discovery deadline reached.",
            )
        else:
            if child_state != "coverage":
                write_checkpoint(
                    directory / "checkpoints",
                    {
                        "scanId": child["scanId"],
                        "findings": findings,
                        "coverage": coverage,
                        "complete": False,
                    },
                )
                (directory / "coverage.json").unlink()
            for name in ("scan-manifest.json", "findings.json", "report.md"):
                (directory / name).unlink()
            if child_state in {"failed", "coverage"}:
                run_workbench(
                    state,
                    "fail-scan",
                    "--scan-id",
                    child["scanId"],
                    "--message",
                    "Discovery deadline reached.",
                )
        protected = {
            path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob("*")
            if path.is_file()
        }
        children.append((child, directory, protected))
    first, first_dir, _ = children[0]
    original = json.loads((first_dir / "findings.json").read_text())["findings"][1]
    accepted = copy.deepcopy(original)
    accepted["provenance"]["sourceFindingIds"] = [f"{first['scanId']}:0"]
    accepted["provenance"]["sourceFindings"] = [{"id": f"{first['scanId']}:0", "finding": original}]
    saved = checkpoint(
        state,
        parent,
        passes=[
            {"directory": directory.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
            for child, directory, _ in children
        ],
        merged=[first["scanId"]] if has_aggregate else [],
        terminal=terminal_reason,
    )
    saved["noNewStreak"] = 2
    saved["consecutiveErrors"] = 1
    saved["aggregate"] = (
        {
            "scanId": parent["scanId"],
            "findings": [accepted],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "deferred": [{"reason": "Accepted partial coverage."}],
            },
        }
        if has_aggregate
        else None
    )
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(saved),
    )
    checkpoint_bytes = (parent_dir / CHECKPOINT).read_bytes()
    write_completed_contract(
        parent_dir,
        parent["scanId"],
        target,
        relative_path="src/app.py",
        include_paths=["src"],
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    manifest_before = json.loads((parent_dir / "scan-manifest.json").read_text())
    coverage_path = parent_dir / "coverage.json"
    submitted_coverage = json.loads(coverage_path.read_text())
    submitted_coverage["deferred"] = [{"id": "limit", "reason": "Configured cost limit reached."}]
    coverage_path.write_text(json.dumps(submitted_coverage))
    (parent_dir / "findings.json").write_text(
        json.dumps({"findings": [accepted] if has_aggregate else []})
    )
    run_workbench(state, "prepare-scan-completion", "--scan-id", parent["scanId"])
    prepared = {
        name: (parent_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    for _ in range(2):
        run_workbench(state, "complete-scan", "--scan-id", parent["scanId"])
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert context["findingCount"] == (1 if child_state == "coverage" else 2)
    assert context["progress"]["status"] == "complete"
    assert context["progress"]["independentReviews"]["active"] == 0
    findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    manifest = json.loads((parent_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"] == manifest_before["scan"]["target"]
    assert manifest["scan"]["scope"] == manifest_before["scan"]["scope"]
    assert coverage["mode"] == "scoped_path"
    assert coverage["includePaths"] == ["src"]
    assert coverage["completeness"] == "partial"
    assert submitted_coverage["deferred"][0] in coverage["deferred"]
    assert (parent_dir / CHECKPOINT).read_bytes() == checkpoint_bytes
    for name, contents in prepared.items():
        assert (parent_dir / name).read_bytes() == contents
    for index, (child, directory, protected) in enumerate(children, 1):
        source_id = f"{child['scanId']}:0"
        if index == 2 and child_state == "coverage":
            assert all(source_id not in item["provenance"]["sourceFindingIds"] for item in findings)
            row = next(
                row for row in coverage["deferred"] if row["id"] == f"{child['scanId']}/unvalidated"
            )
            assert row["candidate"] == {
                "title": "Unvalidated observation",
                "summary": "Needs a source trace.",
            }
            assert row["surfaceIds"] == [f"{child['scanId']}/surface_archive_extraction"]
        else:
            finding = next(
                item for item in findings if item["provenance"]["sourceFindingIds"] == [source_id]
            )
            source = finding["provenance"]["sourceFindings"][0]
            original = next(
                item
                for item in json.loads((directory / "findings.json").read_text())["findings"]
                if item["identity"]["anchor"] == f"independent-{index}"
            )
            if index == 2 and child_state == "canonical":
                for key in original:
                    assert source["finding"][key] == original[key]
            else:
                assert source["finding"] == original
            assert [location["path"] for location in finding["locations"]] == [
                "outside.py",
                "src/app.py",
            ]
        assert not (parent_dir / f"findings/{child['scanId']}-outside").exists()
        if index == 1 and has_aggregate:
            assert finding["findingId"] == accepted["findingId"]
            assert finding["identity"] == accepted["identity"]
        else:
            row = next(
                row
                for row in coverage["surfaces"]
                if row["id"] == f"{child['scanId']}/surface_archive_extraction"
            )
            assert row["receiptRefs"] == [
                f"artifacts/deep-scan/passes/pass-{index}/artifacts/receipt.json"
            ]
        for name, contents in protected.items():
            assert (directory / name).read_bytes() == contents
        assert run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["progress"][
            "status"
        ] == ("complete" if index == 1 else "failed")
    assert any("artifacts/deep-scan/passes/pass-2" in row["reason"] for row in coverage["deferred"])
    assert [scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]] == [
        parent["scanId"]
    ]


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
def test_deferred_stop_retains_drained_child_and_cost_before_freezing(
    tmp_path: Path, action: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"])
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    checkpoint(state, parent, passes=[{"directory": child_dir.relative_to(parent_dir).as_posix()}])
    run_workbench(
        state, "set-scan-thread", "--scan-id", parent["scanId"], "--thread-id", "native-owner"
    )
    stop = (
        action,
        "--scan-id",
        parent["scanId"],
        "--defer-publication",
        *(
            ("--thread-id", "native-owner")
            if action == "cancel-scan"
            else ("--message", "Stopped.")
        ),
    )
    wrong_authority = (
        ("--thread-id", "other-owner")
        if action == "cancel-scan"
        else ("--claim-token", "00000000-0000-4000-8000-000000000001")
    )
    assert run_workbench(state, *stop, *wrong_authority, check=False)["returncode"] != 0
    run_workbench(state, *stop)
    assert run_workbench(state, *stop, *wrong_authority, check=False)["returncode"] != 0
    usage = {
        "coverage": "complete",
        "source": "codex_rollout",
        "threadCount": 1,
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "reasoningOutputTokens": 0,
        "totalTokens": 15,
    }
    child_cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.01,
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        rerun_before = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (rerun["scanId"],)
        ).fetchone()
        stopped = connection.execute(
            "SELECT status, completed_at, canceled_at, retained_source_digests_json FROM scans WHERE id = ?",
            (parent["scanId"],),
        ).fetchone()
        assert stopped[0] == "failed"
        assert (stopped[2] is not None) == (action == "cancel-scan")
        assert stopped[3] is None
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ?",
            (json.dumps({"usage": usage}), parent["scanId"]),
        )
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ?",
            (json.dumps({"usage": usage, "cost": child_cost}), child["scanId"]),
        )
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    payload = {
        "scanId": child["scanId"],
        "findings": json.loads((child_dir / "findings.json").read_text())["findings"],
        "coverage": json.loads((child_dir / "coverage.json").read_text()),
        "complete": False,
    }
    write_checkpoint(child_dir / "checkpoints", payload)
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (child_dir / name).unlink()
    for tokens, include_usage in ((10, False), (10, False), (20, False), (20, True)):
        cost = {
            "model": "synthetic-model",
            "inputTokens": tokens,
            "cachedInputTokens": 0,
            "cacheWriteInputTokens": 0,
            "outputTokens": 5,
            "estimatedUsd": tokens / 1000,
        }
        updated = run_workbench(
            state,
            "fail-scan",
            "--scan-id",
            parent["scanId"],
            "--message",
            "Drained.",
            "--cost-json",
            json.dumps({"usage": usage, "cost": cost} if include_usage else cost),
        )
        assert updated["scan"]["cost"] == cost
        assert updated["scan"]["usage"] == usage
    run_workbench(state, *stop)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT status, completed_at, canceled_at, retained_source_digests_json FROM scans WHERE id = ?",
                (parent["scanId"],),
            ).fetchone()
            == stopped
        )
    preserve = (
        "preserve-scan-results",
        "--scan-id",
        parent["scanId"],
        "--after-stop",
        "--thread-id",
        "native-owner",
    )
    assert (
        run_workbench(state, *preserve, "--thread-id", "other-owner", check=False)["returncode"]
        != 0
    )
    assert (
        run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["progress"]["status"]
        == "running"
    )
    retained = run_workbench(state, *preserve)
    assert retained["scan"]["findingCount"] == 1
    assert retained["scan"]["cost"] == cost
    assert retained["scan"]["progress"]["independentReviews"]["active"] == 0
    retained_child = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
    assert retained_child["progress"]["status"] == "failed"
    assert retained_child["cost"] == child_cost
    assert retained_child["usage"] == usage
    published = {
        name: (parent_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    frozen = json.loads(published["scan-manifest.json"])["scan"]["preservedSources"]
    assert frozen
    child_published = {name: (child_dir / name).read_bytes() for name in published}
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        child_stopped = connection.execute(
            "SELECT status, completed_at, canceled_at, cost_json, retained_source_digests_json FROM scans WHERE id = ?",
            (child["scanId"],),
        ).fetchone()
    assert child_stopped[1] is not None
    assert child_stopped[4] is not None
    payload["findings"][0]["summary"] = "A later checkpoint must not replace retained evidence."
    write_checkpoint(child_dir / "checkpoints", payload)
    run_workbench(state, *stop)
    assert run_workbench(state, *preserve)["scan"]["findingCount"] == 1
    assert {name: (parent_dir / name).read_bytes() for name in published} == published
    assert {name: (child_dir / name).read_bytes() for name in published} == child_published
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute("SELECT * FROM scans WHERE id = ?", (rerun["scanId"],)).fetchone()
            == rerun_before
        )
        assert (
            connection.execute(
                "SELECT status, completed_at, canceled_at, cost_json, retained_source_digests_json FROM scans WHERE id = ?",
                (child["scanId"],),
            ).fetchone()
            == child_stopped
        )
        row = connection.execute(
            "SELECT completed_at, canceled_at, retained_source_digests_json FROM scans WHERE id = ?",
            (parent["scanId"],),
        ).fetchone()
    assert row[:2] == stopped[1:3]
    assert json.loads(row[2]) == frozen


@pytest.mark.parametrize("child_state", ["complete", "checkpoint"])
def test_cancel_before_first_merge_preserves_ordinary_children(
    tmp_path: Path, child_state: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"])
        write_completed_contract(directory, child["scanId"], target, relative_path="app.py")
        findings_path = directory / "findings.json"
        findings = json.loads(findings_path.read_text())["findings"]
        findings[0]["provenance"]["candidateId"] = "shared-candidate"
        findings[0]["provenance"]["preservedIdentity"] = dict(findings[0]["identity"])
        findings[0]["writeup"] = {"reportPath": "findings/proof/proof.md"}
        report_dir = directory / "findings/proof"
        report_dir.mkdir(parents=True)
        (report_dir / "proof.md").write_text(f"# Observation {index}\n[Trace](trace.txt)\n")
        (report_dir / "trace.txt").write_text(f"trace-{index}\n")
        findings_path.write_text(json.dumps({"scanId": child["scanId"], "findings": findings}))
        (directory / "artifacts").mkdir()
        (directory / "artifacts/receipt.json").write_text(json.dumps({"pass": index}))
        coverage_path = directory / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["completeness"] = "partial"
        coverage["surfaces"] = [
            {
                "id": "shared-surface",
                "label": f"Pass {index}",
                "disposition": "needs_follow_up",
                "candidateId": "coverage-candidate",
                "receiptRefs": ["artifacts/receipt.json"],
            }
        ]
        coverage["deferred"] = [
            {
                "id": "shared-deferred",
                "reason": "Dependency review remains.",
                "surfaceIds": ["shared-surface"],
            }
        ]
        coverage_path.write_text(json.dumps(coverage))
        if child_state == "complete":
            run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
            findings = json.loads(findings_path.read_text())["findings"]
            protected = {
                name: (directory / name).read_bytes()
                for name in (
                    "scan-manifest.json",
                    "findings.json",
                    "coverage.json",
                )
            }
        else:
            write_checkpoint(
                directory / "checkpoints",
                {
                    "scanId": child["scanId"],
                    "findings": findings,
                    "coverage": coverage,
                    "complete": False,
                },
            )
            for name in ("scan-manifest.json", "findings.json", "coverage.json"):
                (directory / name).unlink()
            protected = {}
        children.append((child, directory, findings[0], protected))
    saved = checkpoint(
        state,
        parent,
        passes=[
            {
                "directory": directory.relative_to(parent_dir).as_posix(),
                "scanId": child["scanId"],
            }
            for child, directory, _, _ in children
        ],
    )
    saved["aggregate"] = None
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(saved),
    )
    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])
    assert (
        run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]["findingCount"] == 2
    )
    assert [scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]] == [
        parent["scanId"]
    ]
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    for child, directory, original, protected in children:
        source_id = f"{child['scanId']}:0"
        finding = next(
            value for value in retained if value["provenance"]["sourceFindingIds"] == [source_id]
        )
        source = finding["provenance"]["sourceFindings"][0]
        assert source["id"] == source_id
        if child_state == "complete":
            assert source["finding"] == original
        else:
            for field in ("codeEvidence", "locations", "validation", "writeup"):
                assert source["finding"][field] == original[field]
        report = parent_dir / finding["writeup"]["reportPath"]
        assert report.read_bytes() == (directory / "findings/proof/proof.md").read_bytes()
        assert (report.parent / "trace.txt").read_bytes() == (
            directory / "findings/proof/trace.txt"
        ).read_bytes()
        row = next(
            row for row in coverage["surfaces"] if row["id"] == f"{child['scanId']}/shared-surface"
        )
        receipt = f"{directory.relative_to(parent_dir).as_posix()}/artifacts/receipt.json"
        assert row["receiptRefs"] == [receipt]
        assert (parent_dir / receipt).is_file()
        assert row["candidateId"].startswith(child["scanId"] + ":")
        deferred = next(
            row for row in coverage["deferred"] if row["id"] == f"{child['scanId']}/shared-deferred"
        )
        assert deferred["surfaceIds"] == [row["id"]]
        for name, contents in protected.items():
            assert (directory / name).read_bytes() == contents
    assert json.loads((parent_dir / CHECKPOINT).read_text()) == saved
    manifest = json.loads((parent_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["status"] == "canceled"
    assert manifest["sealedAt"]
    assert manifest["preservedSources"]


def test_running_pass_retains_paid_receipt_before_resume_and_failure(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan")
    run_workbench(state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "paid-pass")
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    receipt = run_workbench(
        state, "preserve-scan-results", "--scan-id", scan["scanId"], "--cost-json", json.dumps(cost)
    )["scan"]
    assert receipt["progress"]["status"] == "running"
    assert receipt["cost"] == cost
    assert (
        run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])["threadId"]
        == "paid-pass"
    )
    assert (
        run_workbench(state, "list-scans", "--scan-root", scan["scanDir"])["scans"][0]["cost"]
        == cost
    )
    run_workbench(state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Retry exhausted.")
    assert run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["cost"] == cost


def test_native_budget_completion_checks_claim_before_publication(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state = tmp_path / "state"
    scan = run_workbench(
        state,
        "begin-deep-scan",
        "--target-path",
        str(target),
        "--thread-id",
        "native-owner",
        "--scan-root",
        str(tmp_path / "scans"),
    )["scan"]
    token = scan["handoffClaimToken"]
    run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        scan["scanDir"],
        "--registration-json-stdin",
        input_text=json.dumps(
            {
                "scanId": scan["scanId"],
                "threadId": "native-owner",
                "claimToken": token,
                "recipe": {**recipe(target, "deep"), "maxCostUsd": 0.001},
            }
        ),
    )
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        "--claim-token",
        token,
        input_text=json.dumps(
            {
                "version": 2,
                "passes": [],
                "mergedScanIds": [],
                "aggregate": None,
                "terminalReason": "capped",
            }
        ),
    )
    directory = Path(scan["scanDir"])
    write_completed_contract(
        directory, scan["scanId"], target, relative_path="app.py", coverage_mode="deep_repository"
    )
    original = (directory / "coverage.json").read_bytes()
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.002,
    }
    arguments = (
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan["scanId"],
        "--cost-json",
        json.dumps(cost),
    )
    rejected = run_workbench(state, *arguments, check=False)
    assert "owned by another continuation" in rejected["stderr"]
    assert (directory / "coverage.json").read_bytes() == original
    completed = run_workbench(state, *arguments, "--claim-token", token)["scan"]
    assert completed["progress"]["status"] == "complete"
    joined = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "native-owner",
        "--claim-token",
        token,
    )["scan"]
    assert joined["progress"]["status"] == "complete"
