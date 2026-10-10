from __future__ import annotations

import copy
import io
import json
import os
import sqlite3
import subprocess
import sys
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier, Event
from unittest import mock

import pytest
from workbench_test_support import (
    SCRIPT,
    checkpoint,
    recipe,
    register,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)

CHECKPOINT = "artifacts/deep-scan/checkpoint.json"
EXECUTION_THREADS = "artifacts/deep-scan/execution-threads.json"


def _scan_workspace(tmp_path: Path, source: str = "print('fixture')\n") -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(source)
    return tmp_path / "state", target


@pytest.mark.parametrize("accepted", [False, True])
def test_explicit_recovery_materializes_unfrozen_composition_after_checkpoint_failure(
    tmp_path: Path, workbench_api, accepted: bool
) -> None:
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    findings = json.loads((child_dir / "findings.json").read_text())
    findings["findings"][0]["writeup"] = {"reportPath": "findings/proof/proof.md"}
    (child_dir / "findings.json").write_text(json.dumps(findings))
    report_dir = child_dir / "findings/proof"
    report_dir.mkdir(parents=True)
    (report_dir / "proof.md").write_text("# Retained observation\n[Trace](trace.txt)\n")
    (report_dir / "trace.txt").write_text("Synthetic supporting evidence\n")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    child_bytes = {name: (child_dir / name).read_bytes() for name in names}
    saved = checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
        merged=[child["scanId"]] if accepted else [],
    )
    if accepted:
        saved["aggregate"] = workbench_api["saved_results"].project_scan_artifacts(
            parent["scanId"],
            child["scanId"],
            child_dir,
            parent_dir,
            *(json.loads(child_bytes[name]) for name in names),
        )["draft"]
        run_workbench(
            state,
            "save-scan-artifact",
            "--scan-id",
            parent["scanId"],
            "--artifact-path",
            CHECKPOINT,
            input_text=json.dumps(saved),
        )
    composition_bytes = (parent_dir / CHECKPOINT).read_bytes()
    wrapper = tmp_path / "fail_first_parent_checkpoint.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(SCRIPT.parent)!r})\n"
        "import workbench_db, workbench_saved_results\n"
        "original = workbench_saved_results.write_scan_local_bytes\n"
        "def write(directory, relative, payload, **kwargs):\n"
        f"    if str(directory) == {str(parent_dir)!r} and relative.startswith('checkpoints/'):\n"
        "        raise OSError('Synthetic first parent checkpoint failure.')\n"
        "    return original(directory, relative, payload, **kwargs)\n"
        "workbench_saved_results.write_scan_local_bytes = write\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    stopped = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "fail-scan",
            "--scan-id",
            parent["scanId"],
            "--message",
            "Synthetic scan interruption.",
        ],
        capture_output=True,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
        text=True,
        check=False,
    )
    assert stopped.returncode == 0, stopped.stderr
    failed = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert failed["resultsRecoveryNeeded"]
    assert any("Synthetic first parent checkpoint failure" in item for item in failed["warnings"])
    assert not list((parent_dir / "checkpoints").glob("*.json"))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (parent["scanId"],)
        ).fetchone() == (None,)

    recovery = ("recover-scan-results", "--scan-id", parent["scanId"])
    recovered = run_workbench(state, *recovery)["scan"]
    assert recovered["findingCount"] == 1
    assert not recovered["resultsRecoveryNeeded"]
    assert recovered["findings"][0]["title"] == findings["findings"][0]["title"]
    assert json.loads((parent_dir / "coverage.json").read_text())["completeness"] == "partial"
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"][0]
    report = parent_dir / retained["writeup"]["reportPath"]
    assert report.read_bytes() == (report_dir / "proof.md").read_bytes()
    assert (report.parent / "trace.txt").read_bytes() == (report_dir / "trace.txt").read_bytes()
    assert {name: (child_dir / name).read_bytes() for name in names} == child_bytes
    assert (parent_dir / CHECKPOINT).read_bytes() == composition_bytes

    published = {name: (parent_dir / name).read_bytes() for name in (*names, "report.md")}
    frozen = json.loads(published["scan-manifest.json"])["scan"]["preservedSources"]
    assert frozen
    sources = {path.name: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    saved["aggregate"] = {
        "scanId": parent["scanId"],
        "findings": [retained],
        "coverage": json.loads(published["coverage.json"]),
    }
    saved["aggregate"]["findings"][0]["title"] = (
        "Later composition must not replace frozen evidence"
    )
    (parent_dir / CHECKPOINT).write_text(json.dumps(saved))
    for manifest_only in (False, True):
        if manifest_only:
            with sqlite3.connect(state / "workbench.sqlite3") as connection:
                connection.execute(
                    "UPDATE scans SET retained_source_digests_json = NULL WHERE id = ?",
                    (parent["scanId"],),
                )
        assert run_workbench(state, *recovery)["scan"]["findingCount"] == 1
        assert {name: (parent_dir / name).read_bytes() for name in published} == published
        assert {
            path.name: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")
        } == sources
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            recorded = connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (parent["scanId"],)
            ).fetchone()[0]
        assert json.loads(recorded) == frozen


@pytest.mark.parametrize("name", ["current", "legacy"])
def test_checkpoint_reads_shared_sdk_fixtures(tmp_path, workbench_api, monkeypatch, name):
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    fixture = Path(__file__).parent / "fixtures/composition-checkpoints" / f"{name}.json"
    original = json.loads(fixture.read_text())
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=fixture.read_text(),
    )
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    stored = {"id": scan["scanId"], "scan_dir": scan["scanDir"]}
    loaded = workbench_api["load_composition"].__globals__["read_composition_checkpoint"](stored)
    assert loaded == original
    encoded = json.dumps(
        loaded, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    assert json.loads(encoded) == original
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=encoded.decode(),
    )
    assert (
        workbench_api["load_composition"].__globals__["read_composition_checkpoint"](stored)
        == original
    )


def test_checkpoint_read_blocks_other_threads_and_atomic_writers(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    original = checkpoint(state, scan)
    updated = {**original, "noNewStreak": 1}
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    read_checkpoint = workbench_api["load_composition"].__globals__["read_composition_checkpoint"]
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
    state, target = _scan_workspace(tmp_path)
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


@pytest.mark.parametrize("other_context", [None, "Different optional context."])
def test_native_parent_serializes_concurrent_starts_with_different_context(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch, other_context: str | None
) -> None:
    state, target = _scan_workspace(tmp_path)
    run_workbench(state, "database-info")
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with mock.patch.object(
        sys,
        "argv",
        [
            "workbench",
            "begin-deep-scan",
            "--thread-id",
            "native-owner",
            "--target-path",
            str(target),
            "--scan-root",
            str(tmp_path / "scans"),
        ],
    ):
        args = workbench_api["parse_args"]("test")
    history = workbench_api["scan_history"]
    existing_scan = history.existing_deep_scan_for_target
    initial_lookups = Barrier(2)

    def synchronized_lookup(connection, *identity):
        existing = existing_scan(connection, *identity)
        if not connection.in_transaction:
            initial_lookups.wait(timeout=10)
        return existing

    def start(context):
        request = copy.copy(args)
        request.user_context = context
        with closing(workbench_api["connect"]()) as connection:
            return workbench_api["begin_deep_scan"](connection, request)

    monkeypatch.setattr(history, "existing_deep_scan_for_target", synchronized_lookup)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(start, ["Original optional context.", other_context]))
    assert sorted(result["startDisposition"] for result in results) == ["created", "joined"]
    created = next(result["scan"] for result in results if result["startDisposition"] == "created")
    joined = next(result["scan"] for result in results if result["startDisposition"] == "joined")
    for key in ("scanId", "scanDir", "handoffClaimToken", "userContext"):
        assert joined[key] == created[key]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)


@pytest.fixture
def native_scan_completion(tmp_path: Path):
    state, target = _scan_workspace(tmp_path)
    arguments = (
        "begin-deep-scan",
        "--thread-id",
        "native-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--user-context",
        "Original optional context.",
    )
    started = run_workbench(state, *arguments)
    scan = started["scan"]
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
                "recipe": recipe(target, "deep"),
            }
        ),
    )
    directory = Path(scan["scanDir"])
    write_completed_contract(
        directory, scan["scanId"], target, relative_path="app.py", coverage_mode="deep_repository"
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
                "startedAt": "2026-01-01T00:00:00Z",
                "passes": [],
                "mergedScanIds": [],
                "aggregate": {
                    "scanId": scan["scanId"],
                    "findings": json.loads((directory / "findings.json").read_text())["findings"],
                    "coverage": json.loads((directory / "coverage.json").read_text()),
                },
                "noNewStreak": 0,
                "consecutiveErrors": 0,
                "terminalReason": "saturated",
            }
        ),
    )
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }

    def complete():
        return run_workbench(
            state,
            "complete-scan",
            "--scan-id",
            scan["scanId"],
            "--claim-token",
            token,
            "--cost-json",
            json.dumps(cost),
        )["scan"]

    return state, target, arguments, started, complete


@pytest.mark.parametrize("saved_recipe", [False, True])
@pytest.mark.parametrize("saved_thread", [False, True])
def test_native_legacy_rejoin_requires_verified_sealed_results(
    native_scan_completion, saved_recipe: bool, saved_thread: bool
) -> None:
    state, _, arguments, started, complete = native_scan_completion
    scan = started["scan"]
    directory = Path(scan["scanDir"])
    if saved_thread:
        run_workbench(
            state,
            "set-scan-thread",
            "--scan-id",
            scan["scanId"],
            "--thread-id",
            "merge-execution",
            "--claim-token",
            scan["handoffClaimToken"],
        )
    joins = (
        arguments,
        (
            "begin-deep-scan",
            "--scan-id",
            scan["scanId"],
            "--thread-id",
            "native-owner",
            "--claim-token",
            scan["handoffClaimToken"],
        ),
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
            "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
            "manifest_path, terminal_reason, created_at, updated_at) "
            "SELECT id, 1, 'synthetic-recovery', 'succeeded', 'terminal', 1, 0, 1, 1, "
            "?, 'saturated', started_at, updated_at FROM scans WHERE id = ?",
            (str(directory / "scan-manifest.json"), scan["scanId"]),
        )
    for join in joins:
        rejected = run_workbench(state, *join, check=False)
        assert "retired runtime" in rejected["stderr"]
    run_workbench(
        state,
        "prepare-scan-completion",
        "--scan-id",
        scan["scanId"],
        "--claim-token",
        scan["handoffClaimToken"],
    )
    (directory / CHECKPOINT).unlink()
    if not saved_recipe:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET recipe_json = NULL WHERE id = ?", (scan["scanId"],)
            )
    sealed = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    for join in joins:
        joined = run_workbench(state, *join)
        assert joined["startDisposition"] == "joined"
        assert joined["scan"]["scanId"] == scan["scanId"]
        assert joined["scan"]["handoffClaimToken"] == scan["handoffClaimToken"]
        assert joined["scan"]["progress"]["status"] == "running"
        assert {name: (directory / name).read_bytes() for name in sealed} == sealed
    (directory / "findings.json").write_bytes(sealed["findings.json"] + b" ")
    for join in joins:
        rejected = run_workbench(state, *join, check=False)
        assert "Cannot resume sealed scan" in rejected["stderr"]
    (directory / "findings.json").write_bytes(sealed["findings.json"])
    assert complete()["progress"]["status"] == "complete"
    assert {name: (directory / name).read_bytes() for name in sealed} == sealed


def test_native_registration_returns_verified_sealed_resume(native_scan_completion) -> None:
    state, target, _, started, _ = native_scan_completion
    scan = started["scan"]
    directory = Path(scan["scanDir"])
    token = scan["handoffClaimToken"]
    registration = {
        "scanId": scan["scanId"],
        "threadId": "native-owner",
        "claimToken": token,
        "recipe": recipe(target, "deep"),
    }

    def bind(**kwargs):
        return run_workbench(
            state,
            "register-cli-scan",
            "--repository",
            str(target),
            "--scan-dir",
            str(directory),
            "--registration-json-stdin",
            input_text=json.dumps(registration),
            **kwargs,
        )

    assert "sealedProducerVersion" not in bind()
    run_workbench(
        state, "prepare-scan-completion", "--scan-id", scan["scanId"], "--claim-token", token
    )
    manifest = directory / "scan-manifest.json"
    sealed = manifest.read_bytes()
    resumed = bind()
    assert resumed["sealedProducerVersion"] == json.loads(sealed)["scan"]["producer"]["version"]
    assert resumed["claimToken"] == token
    assert resumed["compositionCheckpoint"]["terminalReason"] == "saturated"
    assert resumed["scan"]["progress"]["status"] == "running"
    assert manifest.read_bytes() == sealed
    with (directory / "findings.json").open("a") as findings:
        findings.write(" ")
    rejected = bind(check=False)
    assert rejected["returncode"] != 0
    assert "Cannot resume sealed scan" in rejected["stderr"]
    assert manifest.read_bytes() == sealed


def test_native_target_retry_reuses_completed_result(
    native_scan_completion,
) -> None:
    state, _, arguments, started, complete = native_scan_completion
    scan = started["scan"]
    completed = []
    artifacts = {}

    def finish():
        completed.append(complete())
        artifacts.update(
            (path, path.read_bytes()) for path in Path(scan["scanDir"]).rglob("*") if path.is_file()
        )

    finish()
    retry = run_workbench(state, *arguments)
    assert retry["startDisposition"] == "joined"
    assert retry["scan"]["progress"]["status"] == "complete"
    for key in ("scanId", "scanDir", "handoffClaimToken", "cost", "findings"):
        assert retry["scan"][key] == completed[0][key]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
    assert {path: path.read_bytes() for path in artifacts} == artifacts
    assert run_workbench(state, *arguments)["scan"]["scanId"] == scan["scanId"]
    assert {path: path.read_bytes() for path in artifacts} == artifacts


@pytest.mark.parametrize("change", ["context", "snapshot", "owner", "explicit_start"])
def test_completed_native_result_does_not_prevent_new_scans(native_scan_completion, change):
    state, target, arguments, started, complete = native_scan_completion
    complete()
    if change == "context":
        arguments = (*arguments[:-1], "Different optional context.")
    elif change == "snapshot":
        (target / "app.py").write_text("print('changed')\n")
    elif change == "owner":
        arguments = tuple(
            "another-owner" if value == "native-owner" else value for value in arguments
        )
    if change == "explicit_start":
        created = run_workbench(state, "start-scan", "--workspace-id", started["workspace"]["id"])[
            "results"
        ]
    else:
        result = run_workbench(state, *arguments)
        assert result["startDisposition"] == "created"
        created = result["scan"]
    assert created["scanId"] != started["scan"]["scanId"]
    assert created["progress"]["status"] == "running"


@pytest.mark.parametrize("rejoin_context", [None, "Different optional context."])
def test_native_parent_binds_once_and_keeps_native_claim(
    tmp_path: Path, rejoin_context: str | None
) -> None:
    state, target = _scan_workspace(tmp_path)
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
        run_workbench(state, "get-cli-scan-resume", "--scan-id", parent["scanId"])[
            "compositionCheckpoint"
        ]
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
        expected["legacy"] = legacy
    context = run_workbench(state, "get-cli-scan-resume", "--scan-id", parent["scanId"])
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
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state, "set-scan-thread", "--scan-id", parent["scanId"], "--thread-id", "merge-thread"
    )
    parent_dir = Path(parent["scanDir"])
    pass_directory = "artifacts/deep-scan/passes/pass-1"
    directory = parent_dir / pass_directory
    saved = checkpoint(state, parent, passes=[{"directory": pass_directory}])
    child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
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
    assert "compositionCheckpoint" not in context
    assert context["scan"]["executionThreadIds"] == ["merge-thread", "child-thread"]
    assert context["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": 1,
        "maximum": 8,
        "consolidating": False,
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


@pytest.mark.parametrize("legacy_reviews", [0, 3])
@pytest.mark.parametrize("with_child", [False, True])
def test_get_scan_counts_saved_reviews_without_reading_composition_checkpoint(
    tmp_path: Path, workbench_api, monkeypatch, legacy_reviews: int, with_child: bool
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    if with_child:
        child = register(
            state,
            target,
            tmp_path / "parent/artifacts/deep-scan/passes/pass-1",
            parent=parent["scanId"],
            role="deep_pass",
        )
        write_completed_contract(
            Path(child["scanDir"]), child["scanId"], target, relative_path="app.py"
        )
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    value = checkpoint(state, parent, passes=[{"directory": "artifacts/deep-scan/passes/pass-1"}])
    if legacy_reviews:
        value["legacy"] = {"discoveryRuns": legacy_reviews, "coverage": {"completeness": "partial"}}
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, "
                "phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
                "completion_sequence, created_at, updated_at) "
                "SELECT id, 1, 'synthetic-legacy', 'succeeded', 'terminal', 1, 0, 3, 8, ?, "
                "started_at, updated_at FROM scans WHERE id = ?",
                (legacy_reviews, parent["scanId"]),
            )
    path = Path(parent["scanDir"]) / CHECKPOINT
    path.write_text(json.dumps(value))
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    load = workbench_api["load_composition"]
    reader = load.__globals__["read_composition_checkpoint"]
    with mock.patch.dict(load.__globals__, read_composition_checkpoint=mock.Mock(wraps=reader)):
        with workbench_api["connect"]() as connection:
            context = workbench_api["scan_context"](connection, parent["scanId"])
        load.__globals__["read_composition_checkpoint"].assert_not_called()
    assert context["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": legacy_reviews + int(with_child),
        "maximum": 8,
        "consolidating": False,
    }
    assert "compositionCheckpoint" not in context
    assert json.loads(path.read_text()) == value
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"]
    }


def test_explicit_child_membership_does_not_depend_on_directory_or_checkpoint(
    tmp_path: Path,
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent_dir = tmp_path / "parent"
    parent = register(state, target, parent_dir, mode="deep")
    # A generic rerun remains public even when its directory resembles a pass.
    rerun = register(
        state,
        target,
        parent_dir / "artifacts/deep-scan/passes/ordinary-rerun",
        parent=parent["scanId"],
    )
    child = register(
        state, target, parent_dir / "saved-child", parent=parent["scanId"], role="deep_pass"
    )
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        rerun["scanId"],
    }
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert "compositionCheckpoint" not in context
    assert context["scan"]["progress"]["independentReviews"]["active"] == 1
    write_completed_contract(
        Path(child["scanDir"]), child["scanId"], target, relative_path="app.py"
    )
    run_workbench(
        state,
        "fail-scan",
        "--scan-id",
        parent["scanId"],
        "--message",
        "Stopped.",
        "--defer-publication",
    )
    run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"], "--after-stop")
    retained = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert retained["findingCount"] == 1
    assert retained["warnings"] == []
    assert (
        run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["progress"]["status"]
        == "failed"
    )
    assert (
        run_workbench(state, "get-scan", "--scan-id", rerun["scanId"])["scan"]["progress"]["status"]
        == "running"
    )


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
    assert "compositionCheckpoint" not in context
    assert context["scan"]["continuationThreadId"] is None
    assert context["scan"]["progress"]["status"] == "failed"
    assert context["scan"]["threadIds"] == ["failed-follow-up", "repeated-follow-up"]
    assert context["scan"]["executionThreadIds"] == context["scan"]["threadIds"]


@pytest.mark.parametrize("missing", ["checkpoint", "output"])
def test_history_hides_composition_children_without_parent_artifacts(
    tmp_path: Path, missing: str
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent_dir = tmp_path / "scan"
    parent = register(state, target, parent_dir, mode="deep")
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, parent_dir / child_path, parent=parent["scanId"], role="deep_pass"
    )
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
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, directory / child_path, parent=parent["scanId"], role="deep_pass"
    )
    checkpoint(state, parent, passes=[{"directory": child_path}])
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
    assert "compositionCheckpoint" not in context
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
    replacement = register(
        state, target, directory / child_path, parent=current["scanId"], role="deep_pass"
    )
    assert replacement["scanId"] != child["scanId"]
    assert replacement["scanDir"] == str(directory / child_path)


@pytest.mark.parametrize("action", ["fail-scan", "cancel-scan"])
def test_stopped_standard_cannot_resume_and_preserves_checkpoint(
    tmp_path: Path, action: str
) -> None:
    state, target = _scan_workspace(tmp_path)
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
    state, target = _scan_workspace(tmp_path, "\n" * 50)
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
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index, anchor in enumerate(("accepted-finding", "separate-unmerged-finding"), 1):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
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
        child = register(
            state, target, directory, parent=parent["scanId"], role="deep_pass", paths=["src"]
        )
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
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
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
    retained = run_workbench(
        state, *preserve, "--cost-json", json.dumps({"usage": usage, "cost": cost})
    )
    assert retained["scan"]["findingCount"] == 1
    assert retained["scan"]["cost"] == cost
    assert retained["scan"]["usage"] == usage
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
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
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
    state, target = _scan_workspace(tmp_path)
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
    state, target = _scan_workspace(tmp_path)
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


def test_composed_recovery_records_child_failure_and_continues(workbench_api, monkeypatch) -> None:
    saved = workbench_api["saved_results"]
    root = Path("/synthetic-scan")
    children = [
        {"id": "broken", "scan_dir": str(root / "broken")},
        {"id": "retained", "scan_dir": str(root / "retained")},
    ]
    composition = workbench_api["load_composition"].__globals__["CompositionView"](
        None, tuple(children), (), None
    )
    db = mock.Mock(
        require_scan=lambda _, child_id: next(
            child for child in children if child["id"] == child_id
        )
    )
    monkeypatch.setattr(saved, "save_pending_checkpoint", lambda *_: None)
    retained_coverage = {"surfaces": [{"id": "retained/surface", "summary": "Saved work"}]}
    with mock.patch.object(
        saved,
        "_stopped_child_draft",
        side_effect=[
            ValueError("Synthetic malformed artifact"),
            {"findings": [], "coverage": retained_coverage},
        ],
    ):
        result = saved.save_composed_checkpoint(
            db, None, {"id": "parent", "scan_dir": str(root)}, root, composition
        )
    assert result["coverage"]["surfaces"] == retained_coverage["surfaces"]
    assert result["coverage"]["deferred"][0] == {
        "id": "unmerged-broken",
        "reason": "Independent scan did not complete and merge. Saved work: broken. "
        "Recovery failed: Synthetic malformed artifact",
    }
    assert result["complete"] is False


@pytest.mark.parametrize("alias", ["exact", "case", "directory"])
def test_stopped_projection_retains_report_and_colliding_evidence(tmp_path: Path, alias: str):
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    findings_path = child_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    document["findings"][0]["writeup"] = {"reportPath": "findings/issue/issue.md"}
    findings_path.write_text(json.dumps(document))
    reports = child_dir / "findings/issue"
    reports.mkdir(parents=True)
    report = reports / "issue.md"
    report.write_text("# Original report\n")
    name = f"{child['scanId']}-issue.md"
    evidence = reports / (name.upper() if alias == "case" else name)
    if alias == "directory":
        evidence.mkdir()
        evidence = evidence / "trace.txt"
    evidence.write_text("Synthetic supporting evidence\n")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
    )
    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])
    saved = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert saved["progress"]["status"] == "canceled"
    assert not any(
        "conflicts with its projected report" in warning for warning in saved.get("warnings", [])
    )
    projected = parent_dir / "findings" / child["scanId"] / "issue/issue.md"
    assert projected.read_bytes() == report.read_bytes()
    assert (projected.parent / evidence.relative_to(reports)).read_bytes() == evidence.read_bytes()
    parent_findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
    assert (
        parent_findings[0]["writeup"]["reportPath"] == projected.relative_to(parent_dir).as_posix()
    )
    assert report.read_text() == "# Original report\n"
    assert evidence.read_text() == "Synthetic supporting evidence\n"


@pytest.mark.parametrize("saved_recipe", [False, True])
@pytest.mark.parametrize("artifact_state", ["unsealed", "sealed", "tampered"])
def test_native_legacy_registration_only_rejoins_validated_sealed_results(
    native_scan_completion, workbench_api, monkeypatch, saved_recipe: bool, artifact_state: str
) -> None:
    state, target, _, started, complete = native_scan_completion
    scan = started["scan"]
    directory = Path(scan["scanDir"])
    token = scan["handoffClaimToken"]
    run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "saved-execution",
        "--claim-token",
        token,
    )
    if artifact_state != "unsealed":
        run_workbench(
            state, "prepare-scan-completion", "--scan-id", scan["scanId"], "--claim-token", token
        )
    if artifact_state == "tampered":
        findings_path = directory / "findings.json"
        findings_path.write_bytes(findings_path.read_bytes() + b" ")
    checkpoint_path = directory / CHECKPOINT
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["legacy"] = {"discoveryRuns": 1, "coverage": {"completeness": "complete"}}
    checkpoint_path.write_text(json.dumps(checkpoint))
    identity_query = (
        "SELECT recipe_json, continuation_thread_id, deep_scan_owner_thread_id, handoff_claim_token "
        "FROM scans WHERE id = ?"
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        if not saved_recipe:
            connection.execute(
                "UPDATE scans SET recipe_json = NULL WHERE id = ?", (scan["scanId"],)
            )
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at, "
            "terminal_reason, manifest_path) "
            "SELECT id, 1, 'synthetic-legacy', 'succeeded', 'terminal', 1, 0, 3, 8, started_at, "
            "updated_at, 'saturated', ? FROM scans WHERE id = ?",
            (str(directory / "scan-manifest.json"), scan["scanId"]),
        )
        original_identity = connection.execute(identity_query, (scan["scanId"],)).fetchone()
    originals = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", CHECKPOINT)
    }
    registration = {
        "scanId": scan["scanId"],
        "threadId": "native-owner",
        "claimToken": token,
        "recipe": recipe(target, "deep"),
    }
    register_scan = workbench_api["register_cli_scan"]
    verifier = mock.Mock(wraps=register_scan.__globals__["sealed_scan_producer_version"])
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    args = Namespace(repository=str(target), scan_dir=str(directory), registration_json_stdin=True)
    with (
        closing(sqlite3.connect(state / "workbench.sqlite3")) as connection,
        mock.patch("sys.stdin", io.StringIO(json.dumps(registration))),
        mock.patch.dict(register_scan.__globals__, sealed_scan_producer_version=verifier),
    ):
        connection.row_factory = sqlite3.Row
        if artifact_state == "sealed":
            rebound = register_scan(connection, args)
        else:
            error = (
                "retired runtime" if artifact_state == "unsealed" else "Cannot resume sealed scan"
            )
            with pytest.raises(SystemExit, match=error):
                register_scan(connection, args)
        assert verifier.call_count == 1
    if artifact_state == "sealed":
        assert rebound["scanId"] == scan["scanId"]
        assert rebound["threadId"] == "saved-execution"
        resumed = run_workbench(
            state, "get-cli-scan-resume", "--scan-id", scan["scanId"], "--claim-token", token
        )
        assert resumed["threadId"] == "saved-execution"
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert (
                connection.execute(identity_query, (scan["scanId"],)).fetchone()[1:]
                == original_identity[1:]
            )
        assert (
            resumed["sealedProducerVersion"]
            == json.loads(originals["scan-manifest.json"])["scan"]["producer"]["version"]
        )
        assert complete()["progress"]["status"] == "complete"
    else:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert (
                connection.execute(identity_query, (scan["scanId"],)).fetchone()
                == original_identity
            )
    assert {name: (directory / name).read_bytes() for name in originals} == originals


def test_stopped_parent_keeps_writeup_and_colliding_evidence(tmp_path: Path) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    pass_directory = "artifacts/deep-scan/passes/pass-1"
    child_dir = parent_dir / pass_directory
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    findings_path = child_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"][0]["writeup"] = {"reportPath": "findings/check/check.md"}
    other = copy.deepcopy(findings["findings"][0])
    other["identity"]["anchor"] = "another-finding"
    other["writeup"]["reportPath"] = "findings/check-3/check-3.md"
    findings["findings"].append(other)
    findings_path.write_text(json.dumps(findings))
    source = child_dir / "findings/check"
    source.mkdir(parents=True)
    base = f"{child['scanId']}-check"
    evidence_name = f"{base}.MD".upper().replace("K", "\u212a")
    evidence_directory = f"{base}-2.md"
    report = f"# Validated finding\n\n[Evidence]({evidence_name})\n"
    (source / "check.md").write_text(report)
    (source / evidence_name).write_text("Supporting evidence.\n")
    (source / evidence_directory).mkdir()
    (source / evidence_directory / "trace.txt").write_text("Source trace.\n")
    other_report = child_dir / "findings/check-3/check-3.md"
    other_report.parent.mkdir()
    other_report.write_text("# Another finding\n")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    checkpoint(state, parent, passes=[{"directory": pass_directory, "scanId": child["scanId"]}])

    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])

    retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
    assert len(retained) == 2
    assert {finding["writeup"]["reportPath"] for finding in retained} == {
        f"findings/{child['scanId']}/check/check.md",
        f"findings/{child['scanId']}/check-3/check-3.md",
    }
    projected = parent_dir / "findings" / child["scanId"] / "check"
    assert (projected / "check.md").read_text() == report
    assert (projected / evidence_name).read_text() == "Supporting evidence.\n"
    assert (projected / evidence_directory / "trace.txt").read_text() == "Source trace.\n"
    assert (
        parent_dir / "findings" / child["scanId"] / "check-3/check-3.md"
    ).read_text() == "# Another finding\n"


@pytest.mark.parametrize(
    ("child_state", "action"),
    [("complete", "cancel-scan"), ("checkpoint", "cancel-scan"), ("complete", "fail-scan")],
)
@pytest.mark.parametrize("with_model", [False, True])
def test_stopped_composition_retains_child_context_and_export(
    tmp_path, workbench_api, child_state, action, with_model
):
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    model = {
        "format": "markdown",
        "content": "# Synthetic model\n\nQueue producers cross the trust boundary.\n",
        "origin": "generated",
    }
    scope = {
        "summary": "Queue processing",
        "assumptions": ["Producer input is untrusted."],
        "sourceScans": {"sourceOwned": "opaque context"},
    }
    manifest_path = child_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if with_model:
        manifest["scan"]["threatModel"] = model
    manifest["scan"]["scope"].update(scope)
    manifest_path.write_text(json.dumps(manifest))
    if child_state == "complete":
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    else:
        write_checkpoint(
            child_dir / "checkpoints",
            {
                "scanId": child["scanId"],
                "complete": False,
                **({"threatModel": model} if with_model else {}),
                "scope": scope,
                "findings": json.loads((child_dir / "findings.json").read_text())["findings"],
                "coverage": json.loads((child_dir / "coverage.json").read_text()),
            },
        )
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (child_dir / name).unlink()
    original_child = {
        path.relative_to(child_dir): path.read_bytes()
        for path in child_dir.rglob("*")
        if path.is_file()
    }
    checkpoint(
        state,
        parent,
        passes=[
            {
                "directory": child_dir.relative_to(parent_dir).as_posix(),
                "scanId": child["scanId"],
            }
        ],
    )
    extra = ("--message", "Synthetic interrupted composition.") if action == "fail-scan" else ()
    run_workbench(state, action, "--scan-id", parent["scanId"], *extra)
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert stopped["findingCount"] == 1
    assert stopped["threatModelAvailable"] is with_model
    saved = json.loads((parent_dir / "scan-manifest.json").read_text())["scan"]
    if with_model:
        assert saved["threatModel"]["content"] == model["content"]
    assert saved["scope"]["summary"] == scope["summary"]
    assert saved["scope"]["assumptions"] == scope["assumptions"]
    assert saved["scope"]["sourceScans"] == [
        {
            "scanId": child["scanId"],
            "scope": scope,
            **({"threatModel": model} if with_model else {}),
        }
    ]
    if with_model:
        exported = run_workbench(
            state, "export-findings", "--scan-id", parent["scanId"], "--artifact", "threat-model"
        )
        assert model["content"] in Path(exported["export"]["path"]).read_text()
    original_parent = (parent_dir / "scan-manifest.json").read_bytes()
    repeated_command = "recover-scan-results" if action == "fail-scan" else "get-scan"
    recovered = run_workbench(state, repeated_command, "--scan-id", parent["scanId"])["scan"]
    assert recovered["threatModelAvailable"] is with_model
    assert (parent_dir / "scan-manifest.json").read_bytes() == original_parent
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        record = workbench_api["require_scan"](connection, parent["scanId"])
        replayed = workbench_api["saved_results"].merge_saved_results(
            parent_dir,
            parent["scanId"],
            workbench_api["workbench_completion_binding"](record, saved["completedAt"]),
            [],
            [],
            stopped=True,
            reason="Synthetic frozen-source replay.",
            frozen_source_digests=saved["preservedSources"],
        )
    assert replayed is not None
    assert replayed[0]["scan"]["scope"] == saved["scope"]
    if with_model:
        assert replayed[0]["scan"]["threatModel"] == saved["threatModel"]
    assert {path: (child_dir / path).read_bytes() for path in original_child} == original_child


@pytest.mark.parametrize(
    "parent_sources",
    [{"sourceOwned": "parent context"}, "parent context", [{"scope": "prior context"}]],
)
@pytest.mark.parametrize("parent_summary", [False, True])
def test_stopped_composition_preserves_opaque_parent_scope(
    tmp_path, parent_sources, parent_summary
):
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    manifest = json.loads((child_dir / "scan-manifest.json").read_text())
    manifest["scan"]["scope"]["summary"] = "Child context"
    (child_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    value = checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
    )
    value["aggregate"] = {
        "scanId": parent["scanId"],
        "findings": [],
        "coverage": {"completeness": "partial"},
        "scope": {
            **({"summary": "Parent context"} if parent_summary else {}),
            "sourceScans": parent_sources,
        },
    }
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(value),
    )
    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert stopped["findingCount"] == 1
    saved = json.loads((parent_dir / "scan-manifest.json").read_text())["scan"]
    assert saved["scope"]["summary"] == ("Parent context" if parent_summary else "Child context")
    assert saved["scope"]["sourceScans"] == (
        [*parent_sources, {"scanId": child["scanId"], "scope": {"summary": "Child context"}}]
        if isinstance(parent_sources, list)
        else parent_sources
    )


@pytest.mark.parametrize(
    ("terminal_reason", "child_state"),
    [("capped", "complete"), ("saturated", "complete"), ("capped", "failed")],
)
@pytest.mark.parametrize("with_model", [False, True])
@pytest.mark.parametrize("parent_context", [False, True])
def test_terminal_composition_seals_recovered_child_context(
    tmp_path: Path, terminal_reason: str, child_state: str, with_model: bool, parent_context: bool
) -> None:
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep", paths=["app.py"])
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, child_dir, parent=parent["scanId"], role="deep_pass", paths=["app.py"]
    )
    write_completed_contract(
        child_dir,
        child["scanId"],
        target,
        relative_path="app.py",
        include_paths=["app.py"],
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    model = {"format": "markdown", "content": "# Child context\n", "origin": "generated"}
    child_manifest_path = child_dir / "scan-manifest.json"
    child_manifest = json.loads(child_manifest_path.read_text())
    child_manifest["scan"]["scope"].update(
        summary="Child scope", assumptions=["Synthetic trust boundary."]
    )
    if with_model:
        child_manifest["scan"]["threatModel"] = model
    child_manifest_path.write_text(json.dumps(child_manifest))
    if child_state == "complete":
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    else:
        run_workbench(
            state,
            "fail-scan",
            "--scan-id",
            child["scanId"],
            "--defer-publication",
            "--message",
            "Synthetic discovery deadline.",
        )
    child_originals = {
        path.relative_to(child_dir): path.read_bytes()
        for path in child_dir.rglob("*")
        if path.is_file()
    }
    checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
        terminal=terminal_reason,
    )
    write_completed_contract(
        parent_dir,
        parent["scanId"],
        target,
        relative_path="app.py",
        include_paths=["app.py"],
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    parent_manifest_path = parent_dir / "scan-manifest.json"
    parent_manifest = json.loads(parent_manifest_path.read_text())
    if parent_context:
        parent_manifest["scan"]["scope"]["summary"] = "Authoritative parent scope"
        parent_manifest["scan"]["scope"]["sourceScans"] = {"parentOwned": "opaque context"}
        if with_model:
            parent_manifest["scan"]["threatModel"] = {**model, "content": "# Parent context\n"}
    parent_manifest_path.write_text(json.dumps(parent_manifest))
    (parent_dir / "findings.json").write_text(json.dumps({"findings": []}))
    run_workbench(state, "prepare-scan-completion", "--scan-id", parent["scanId"])
    run_workbench(state, "complete-scan", "--scan-id", parent["scanId"])
    result = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert result["progress"]["status"] == "complete"
    assert result["findingCount"] == 1
    assert result["threatModelAvailable"] is with_model
    saved = json.loads(parent_manifest_path.read_text())["scan"]
    assert saved["target"] == parent_manifest["scan"]["target"]
    for key in ("includePaths", "excludePaths"):
        assert saved["scope"].get(key) == parent_manifest["scan"]["scope"].get(key)
    assert saved["scope"]["summary"] == (
        "Authoritative parent scope" if parent_context else "Child scope"
    )
    assert saved["scope"]["assumptions"] == ["Synthetic trust boundary."]
    if parent_context:
        assert saved["scope"]["sourceScans"] == {"parentOwned": "opaque context"}
    else:
        assert saved["scope"]["sourceScans"][0]["scanId"] == child["scanId"]
    if with_model:
        expected_model = "# Parent context\n" if parent_context else model["content"]
        assert saved["threatModel"]["content"] == expected_model
        exported = run_workbench(
            state, "export-findings", "--scan-id", parent["scanId"], "--artifact", "threat-model"
        )
        assert expected_model in Path(exported["export"]["path"]).read_text()
    sealed = {
        name: (parent_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    run_workbench(state, "complete-scan", "--scan-id", parent["scanId"])
    assert {name: (parent_dir / name).read_bytes() for name in sealed} == sealed
    assert {path: (child_dir / path).read_bytes() for path in child_originals} == child_originals
