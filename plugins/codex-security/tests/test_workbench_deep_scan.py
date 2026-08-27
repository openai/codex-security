from __future__ import annotations

import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_workspace,
    mark_deep_coordinator_succeeded,
    run_workbench,
    stable_target_id,
    write_completed_contract,
)


def deep_environment(codex_home: Path) -> dict[str, str]:
    return {"CODEX_HOME": str(codex_home)}


def begin_target_scan(
    state_dir: Path,
    codex_home: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-deep-scan",
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        thread_id,
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


def claim_deep_scan_coordinator(
    state_dir: Path,
    codex_home: Path,
    scan_id: str,
    *,
    thread_id: str = "thread-deep-scan",
    handoff_claim_token: str | None = None,
    coordinator_generation: int | None = None,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "claim-deep-scan-coordinator",
        "--scan-id",
        scan_id,
        "--thread-id",
        thread_id,
        *(("--claim-token", handoff_claim_token) if handoff_claim_token is not None else ()),
        *(
            ("--coordinator-generation", str(coordinator_generation))
            if coordinator_generation
            else ()
        ),
        environment=deep_environment(codex_home),
    )


def expire_deep_scan_coordinator(state_dir: Path, scan_id: str) -> None:
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
            ("2000-01-01T00:00:00Z", scan_id),
        )


def worker_paths(scan_dir: Path, name: str) -> tuple[Path, Path, Path]:
    artifact_dir = scan_dir / "artifacts" / "deep_discovery" / name
    artifact_dir.mkdir(parents=True)
    prompt_path = artifact_dir / "prompt.md"
    prompt_path.write_text(f"Prompt for {name}\n")
    result_path = artifact_dir / "result.json"
    return prompt_path, artifact_dir, result_path


def write_canonical_artifacts(scan_dir: Path) -> dict[str, Path]:
    discovery_dir = scan_dir / "artifacts" / "02_discovery"
    discovery_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "inScopeFilesPath": discovery_dir / "in_scope_files.txt",
        "candidateLedgerPath": discovery_dir / "candidate_ledger.jsonl",
    }
    for path in paths.values():
        path.write_text("")
    return paths


def upsert_worker(
    state_dir: Path,
    codex_home: Path,
    *,
    scan_id: str,
    worker_id: str,
    kind: str,
    status: str,
    prompt_path: Path,
    artifact_dir: Path,
    result_path: Path | None = None,
    attempt: int | None = None,
    thread_id: str | None = None,
    error: str | None = None,
    replaceable_failure_kind: str | None = None,
    coordinator_generation: int | None = None,
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--kind",
        kind,
        "--status",
        status,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        *(("--result-manifest-path", str(result_path)) if result_path is not None else ()),
        *(("--attempt", str(attempt)) if attempt is not None else ()),
        *(("--sdk-thread-id", thread_id) if thread_id is not None else ()),
        *(("--error-message", error) if error is not None else ()),
        *(
            ("--replaceable-failure-kind", replaceable_failure_kind)
            if replaceable_failure_kind is not None
            else ()
        ),
        *(
            ("--coordinator-generation", str(coordinator_generation))
            if coordinator_generation is not None
            else ()
        ),
        environment=deep_environment(codex_home),
    )


def dispatch_discovery_worker(
    state_dir: Path,
    codex_home: Path,
    *,
    scan_id: str,
    scan_dir: Path,
    name: str,
    succeed: bool = True,
    coordinator_generation: int | None = None,
) -> tuple[str, Path, Path, Path]:
    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, name)
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt_path,
        artifact_dir=artifact_dir,
        attempt=1,
        coordinator_generation=coordinator_generation,
    )
    if succeed:
        result_path.write_text("{}\n")
        upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=worker_id,
            kind="discovery",
            status="succeeded",
            prompt_path=prompt_path,
            artifact_dir=artifact_dir,
            result_path=result_path,
            attempt=1,
            coordinator_generation=coordinator_generation,
        )
    return worker_id, prompt_path, artifact_dir, result_path


def commit_reducer(
    state_dir: Path,
    codex_home: Path,
    *,
    scan_id: str,
    scan_dir: Path,
    name: str,
    input_worker_ids: list[str],
    new_findings_count: int,
    coordinator_generation: int | None = None,
) -> dict[str, object]:
    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, name)
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        *(item for input_id in input_worker_ids for item in ("--input-worker-id", input_id)),
        *(
            ("--coordinator-generation", str(coordinator_generation))
            if coordinator_generation is not None
            else ()
        ),
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="dedup",
        status="running",
        prompt_path=prompt_path,
        artifact_dir=artifact_dir,
        attempt=1,
        coordinator_generation=coordinator_generation,
    )
    write_canonical_artifacts(scan_dir)
    result_path.write_text("{}\n")
    committed = run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--result-manifest-path",
        str(result_path),
        "--new-findings-count",
        str(new_findings_count),
        *(
            ("--coordinator-generation", str(coordinator_generation))
            if coordinator_generation is not None
            else ()
        ),
        environment=deep_environment(codex_home),
    )["deepScan"]
    return committed


def test_existing_generation_safely_claims_and_reclaims_without_schema_migration(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    scan_id = str(
        begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]["scanId"]
    )

    def claim() -> dict[str, object]:
        return claim_deep_scan_coordinator(state_dir, codex_home, scan_id)

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (39,)
    assert claim()["deepScan"]["coordinatorGeneration"] == 2
    assert claim()["coordinatorDisposition"] == "observing"
    expire_deep_scan_coordinator(state_dir, scan_id)
    renewed = claim_deep_scan_coordinator(state_dir, codex_home, scan_id, coordinator_generation=2)
    assert renewed["deepScan"]["coordinatorGeneration"] == 2
    assert claim()["coordinatorDisposition"] == "observing"
    expire_deep_scan_coordinator(state_dir, scan_id)
    heartbeat = (
        Path(str(renewed["deepScan"]["scanDir"]))
        / "artifacts"
        / "deep_discovery"
        / "coordinator-heartbeat-2.json"
    )
    heartbeat.parent.mkdir(parents=True, exist_ok=True)
    heartbeat.write_text(
        json.dumps(
            {"coordinatorGeneration": 2, "updatedAt": datetime.now(timezone.utc).isoformat()}
        )
    )
    assert claim()["coordinatorDisposition"] == "observing"
    heartbeat.write_text(
        json.dumps(
            {"coordinatorGeneration": 3, "updatedAt": datetime.now(timezone.utc).isoformat()}
        )
    )
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: claim(), range(4)))

    assert sum(result["coordinatorDisposition"] == "adopted" for result in results) == 1
    assert sum(result["coordinatorDisposition"] == "observing" for result in results) == 3
    assert {result["deepScan"]["coordinatorGeneration"] for result in results} == {3}


def test_legacy_generation_with_active_worker_observes_grace_then_adopts(tmp_path: Path) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = str(run["scanId"]), Path(str(run["scanDir"]))
    dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="legacy-active",
        succeed=False,
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(), scan_id),
        )

    observed = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    assert observed["coordinatorDisposition"] == "observing"
    assert observed["deepScan"]["coordinatorGeneration"] == 1
    assert observed["deepScan"]["workers"][0]["status"] == "running"

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat(), scan_id),
        )
    adopted = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    assert adopted["coordinatorDisposition"] == "adopted"
    assert adopted["deepScan"]["coordinatorGeneration"] == 2
    assert adopted["deepScan"]["workers"][0]["status"] == "canceled"
    assert adopted["deepScan"]["dispatchedCount"] == 0


def test_expired_coordinator_preserves_incomplete_setup(tmp_path: Path) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id = str(run["scanId"])
    inventory = Path(str(run["scanDir"])) / "artifacts" / "02_discovery" / "in_scope_files.txt"

    claimed = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]
    assert (claimed["phase"], claimed["coordinatorGeneration"]) == ("setup", 2)
    assert not inventory.exists()

    expire_deep_scan_coordinator(state_dir, scan_id)
    recovered = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]
    assert (recovered["phase"], recovered["coordinatorGeneration"]) == ("setup", 3)
    assert not inventory.exists()


def test_paused_discovery_resumes_after_restart_with_original_handoff_claim(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    config = codex_home / "codex-security" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        "[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = 2\nmax_discovery_runs = 2\n"
    )
    thread_id, handoff_claim_token = "track-c-continuation", str(uuid.uuid4())
    saved = create_saved_workspace(state_dir, target, thread_id="workspace-thread", mode="deep")
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    scan_id = str(started["results"]["scanId"])
    for command, arguments in (
        ("claim-handoff-delivery", ("--claim-token", handoff_claim_token)),
        (
            "attach-scan-continuation-thread",
            ("--claim-token", handoff_claim_token, "--thread-id", thread_id),
        ),
        (
            "mark-handoff-delivered",
            ("--claim-token", handoff_claim_token, "--thread-id", thread_id),
        ),
    ):
        run_workbench(state_dir, command, "--scan-id", scan_id, *arguments)
    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        thread_id,
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    assert begun["deepScan"]["coordinatorGeneration"] == 1
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )
    completed_worker = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="track-c-completed-discovery",
    )[0]
    paused = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert (paused["progress"]["status"], paused["progress"]["phase"]) == ("running", "discovery")
    assert paused["progress"]["independentReviews"] == {
        "completed": 1,
        "active": 0,
        "consolidating": False,
    }
    assert (paused["reportAvailable"], paused["findingCount"], paused["artifacts"]) == (
        False,
        0,
        {},
    )
    manifest = scan_dir / "artifacts" / "deep_discovery" / "coordinator-manifest.json"
    assert not manifest.exists()

    expire_deep_scan_coordinator(state_dir, scan_id)
    missing_claim = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        thread_id,
        check=False,
        environment=deep_environment(codex_home),
    )
    assert "owned by another continuation" in str(missing_claim["stderr"])
    resumed = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        thread_id,
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )
    assert resumed["startDisposition"] == "joined"
    adopted = claim_deep_scan_coordinator(
        state_dir,
        codex_home,
        scan_id,
        thread_id=thread_id,
        handoff_claim_token=handoff_claim_token,
    )
    assert adopted["coordinatorDisposition"] == "adopted"
    recovered = adopted["deepScan"]
    assert (recovered["status"], recovered["phase"], recovered["coordinatorGeneration"]) == (
        "running",
        "discovery",
        2,
    )
    assert [worker["id"] for worker in recovered["workers"]] == [completed_worker]

    replacement_worker = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="track-c-resumed-discovery",
        coordinator_generation=2,
    )[0]
    reduced = commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="track-c-recovered-reducer",
        input_worker_ids=[completed_worker, replacement_worker],
        new_findings_count=0,
        coordinator_generation=2,
    )
    assert reduced["noNewStreak"] == 2
    manifest.write_text('{"status":"succeeded"}\n')
    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert (finished["status"], finished["phase"], finished["manifestPath"]) == (
        "succeeded",
        "terminal",
        str(manifest),
    )
    assert len([worker for worker in finished["workers"] if worker["kind"] == "discovery"]) == 2
    parent = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )["scan"]
    assert (
        parent["progress"]["status"],
        parent["progress"]["phase"],
        parent["failureMessage"],
    ) == (
        "running",
        "validation",
        None,
    )


@pytest.mark.parametrize(
    "crash_point",
    ["before_commit_with_baseline", "before_commit_without_baseline", "after_commit"],
)
@pytest.mark.parametrize("copy_publication", [False, True])
def test_expired_coordinator_recovers_reducer_publication_after_process_death(
    tmp_path: Path, crash_point: str, copy_publication: bool
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = str(run["scanId"]), Path(str(run["scanDir"]))
    claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    accepted = [
        dispatch_discovery_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"accepted-before-crash-{index}",
            coordinator_generation=2,
        )[0]
        for index in range(2)
    ]
    reducer_id = str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(scan_dir, "crashed-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(artifact_dir),
        *(argument for worker_id in accepted for argument in ("--input-worker-id", worker_id)),
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
        coordinator_generation=2,
    )
    canonical = write_canonical_artifacts(scan_dir)["candidateLedgerPath"]
    canonical.write_text('{"candidate":"previously committed"}\n')
    if crash_point == "before_commit_without_baseline":
        canonical.unlink()
    staged = artifact_dir / "canonical" / canonical.name
    staged.parent.mkdir()
    staged.write_text('{"candidate":"newly published"}\n')
    result.write_text("{}\n")
    hook = "finish_staged_file" if crash_point == "after_commit" else "promote_staged_file"
    call_original = "    original(*args, **kwargs)\n" if hook == "promote_staged_file" else ""
    copy_override = (
        "deep_scan_workbench.create_publication_copy = shutil.copy2\n" if copy_publication else ""
    )
    wrapper = tmp_path / "crash_reducer.py"
    wrapper.write_text(
        "import os, shutil, signal, sys\n"
        f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'scripts')!r})\n"
        "import deep_scan_workbench\n"
        f"{copy_override}"
        f"original = deep_scan_workbench.{hook}\n"
        "def crash(*args, **kwargs):\n"
        f"{call_original}"
        "    os.kill(os.getpid(), signal.SIGKILL)\n"
        f"deep_scan_workbench.{hook} = crash\n"
        "import workbench_db\n"
        "workbench_db.main()\n"
    )
    crashed = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "commit-deep-scan-dedup",
            "--scan-id",
            scan_id,
            "--worker-id",
            reducer_id,
            "--result-manifest-path",
            str(result),
            "--candidate-ledger-path",
            str(staged),
            "--new-findings-count",
            "1",
            "--coordinator-generation",
            "2",
        ],
        env={
            **os.environ,
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
            **deep_environment(codex_home),
        },
        capture_output=True,
        text=True,
    )
    assert crashed.returncode == -signal.SIGKILL, crashed.stderr

    expire_deep_scan_coordinator(state_dir, scan_id)
    recovered = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]
    reducer = next(worker for worker in recovered["workers"] if worker["id"] == reducer_id)
    if crash_point == "after_commit":
        assert reducer["status"] == "succeeded"
        assert canonical.read_text() == staged.read_text()
    elif crash_point == "before_commit_with_baseline":
        assert reducer["status"] == "canceled"
        assert canonical.read_text() == '{"candidate":"previously committed"}\n'
    else:
        assert reducer["status"] == "canceled"
        assert not canonical.exists()
    assert list(canonical.parent.glob(f".{canonical.name}.*.backup")) == []


@pytest.mark.parametrize(
    ("reducer_status", "replace_all_inputs", "should_finish"),
    (("running", True, True), ("failed", True, True), ("failed", False, False)),
)
def test_expired_generation_preserves_receipts_and_recovers_abandoned_workers(
    tmp_path: Path, reducer_status: str, replace_all_inputs: bool, should_finish: bool
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 3\nsubagents = 0\nstop_after_no_new = 1\nmax_discovery_runs = 4\n"
    )
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = str(run["scanId"]), Path(str(run["scanDir"]))
    claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    accepted = [
        dispatch_discovery_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"accepted-{index}",
            coordinator_generation=2,
        )[0]
        for index in range(3)
    ]
    active = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="abandoned-discovery",
        succeed=False,
        coordinator_generation=2,
    )[0]
    reducer = str(uuid.uuid4())
    prompt, artifacts, _ = worker_paths(scan_dir, "abandoned-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer,
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(artifacts),
        *(item for worker in accepted for item in ("--input-worker-id", worker)),
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )
    if reducer_status == "failed":
        upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=reducer,
            kind="dedup",
            status="failed",
            prompt_path=prompt,
            artifact_dir=artifacts,
            attempt=1,
            error="fixture reducer failure",
            coordinator_generation=2,
        )
    expire_deep_scan_coordinator(state_dir, scan_id)
    recovered = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]
    by_id = {worker["id"]: worker for worker in recovered["workers"]}

    assert (recovered["status"], recovered["dispatchedCount"]) == ("running", 3)
    assert all(by_id[worker]["status"] == "succeeded" for worker in accepted)
    assert all(by_id[worker]["mergeState"] == "buffered" for worker in accepted)
    assert by_id[active]["status"] == "canceled"
    assert by_id[reducer]["status"] == ("canceled" if reducer_status == "running" else "failed")
    replacement_inputs = accepted if replace_all_inputs else accepted[:-1]
    resumed = commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="recovered-reducer",
        input_worker_ids=replacement_inputs,
        new_findings_count=0,
        coordinator_generation=3,
    )
    assert resumed["status"] == "running"
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    result = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        "--coordinator-generation",
        "3",
        *(
            item
            for worker in accepted[len(replacement_inputs) :]
            for item in ("--omitted-worker-id", worker)
        ),
        environment=deep_environment(codex_home),
        check=should_finish,
    )
    if not should_finish:
        assert "after a worker has failed" in str(result["stderr"])
        return
    finished = result["deepScan"]
    assert finished["status"] == "succeeded"


@pytest.mark.parametrize("legacy", (False, True))
def test_expired_generation_refunds_shutdown_canceled_discovery(
    tmp_path: Path, legacy: bool
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = str(run["scanId"]), Path(str(run["scanDir"]))
    coordinator_generation = None if legacy else 2
    if not legacy:
        claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="accepted-before-shutdown",
        coordinator_generation=coordinator_generation,
    )
    worker_id, prompt, artifacts, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="canceled-by-shutdown",
        succeed=False,
        coordinator_generation=coordinator_generation,
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="canceled",
        prompt_path=prompt,
        artifact_dir=artifacts,
        attempt=1,
        error=None if legacy else "coordinator_shutdown: mcp_transport_closed",
        coordinator_generation=coordinator_generation,
    )
    expire_deep_scan_coordinator(state_dir, scan_id)

    recovered = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]
    assert recovered["dispatchedCount"] == 1
    assert next(worker for worker in recovered["workers"] if worker["id"] == worker_id)[
        "error"
    ].startswith("coordinator_shutdown_recovered:")
    expire_deep_scan_coordinator(state_dir, scan_id)
    assert (
        claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]["dispatchedCount"]
        == 1
    )


@pytest.mark.parametrize(
    "mutation", ("worker", "progress", "failure", "dedup", "commit", "finish", "renewal")
)
def test_expired_generation_cannot_mutate_recovered_scan(tmp_path: Path, mutation: str) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = str(run["scanId"]), Path(str(run["scanDir"]))
    claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    worker, prompt, artifacts, result = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="stale-discovery",
        succeed=False,
        coordinator_generation=2,
    )
    result.write_text("{}\n")
    expire_deep_scan_coordinator(state_dir, scan_id)
    assert (
        claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"][
            "coordinatorGeneration"
        ]
        == 3
    )
    operations = {
        "worker": (
            "upsert-deep-scan-worker",
            "--worker-id",
            worker,
            "--kind",
            "discovery",
            "--status",
            "succeeded",
            "--prompt-path",
            str(prompt),
            "--artifact-dir",
            str(artifacts),
            "--result-manifest-path",
            str(result),
        ),
        "progress": ("update-progress", "--phase", "discovery"),
        "failure": ("fail-deep-scan", "--message", "stale coordinator"),
        "dedup": (
            "claim-deep-scan-dedup",
            "--worker-id",
            str(uuid.uuid4()),
            "--prompt-path",
            str(prompt),
            "--artifact-dir",
            str(artifacts),
            "--input-worker-id",
            worker,
        ),
        "commit": (
            "commit-deep-scan-dedup",
            "--worker-id",
            worker,
            "--result-manifest-path",
            str(result),
            "--new-findings-count",
            "0",
        ),
        "finish": (
            "finish-deep-scan",
            "--terminal-reason",
            "capped",
            "--manifest-path",
            str(result),
        ),
        "renewal": ("claim-deep-scan-coordinator", "--thread-id", "thread-deep-scan"),
    }
    command, *arguments = operations[mutation]
    rejected = run_workbench(
        state_dir,
        command,
        "--scan-id",
        scan_id,
        *arguments,
        "--coordinator-generation",
        "2",
        check=False,
        environment=deep_environment(codex_home),
    )

    assert rejected["returncode"] != 0
    assert "coordinator" in str(rejected["stderr"]).lower()
    persisted = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert (persisted["status"], persisted["coordinatorGeneration"]) == ("running", 3)


@pytest.mark.parametrize(
    ("artifact_name", "failure_kind", "expected_error"),
    [
        (
            "inScopeFilesPath",
            "missing",
            "Canonical in-scope inventory path must be an existing path inside the scan directory.",
        ),
        (
            "candidateLedgerPath",
            "missing",
            None,
        ),
        (
            "inScopeFilesPath",
            "symlink",
            "Canonical in-scope inventory path must be a canonical non-symlink path.",
        ),
        (
            "candidateLedgerPath",
            "symlink",
            "Canonical candidate ledger path must be a canonical non-symlink path.",
        ),
    ],
)
def test_reducer_commit_requires_safe_standard_canonical_artifacts(
    tmp_path: Path, artifact_name: str, failure_kind: str, expected_error: str | None
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    input_worker_ids = [
        dispatch_discovery_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"canonical-input-{index}",
        )[0]
        for index in range(2)
    ]

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, "canonical-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        *(item for input_id in input_worker_ids for item in ("--input-worker-id", input_id)),
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="running",
        prompt_path=prompt_path,
        artifact_dir=artifact_dir,
        attempt=1,
    )

    canonical = write_canonical_artifacts(scan_dir)
    artifact = canonical[artifact_name]
    artifact.unlink()
    if failure_kind == "symlink":
        replacement = artifact_dir / f"replacement-{artifact_name}.txt"
        replacement.write_text("")
        artifact.symlink_to(replacement)
    result_path.write_text("{}\n")
    staged_ledger = artifact_dir / "staged-candidate-ledger.jsonl"
    staged_ledger.write_text("")
    commit_args = (
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--result-manifest-path",
        str(result_path),
        "--candidate-ledger-path",
        str(staged_ledger),
        "--new-findings-count",
        "0",
    )
    if expected_error is None:
        committed = run_workbench(
            state_dir,
            *commit_args,
            environment=deep_environment(codex_home),
        )["deepScan"]
        assert committed["canonicalArtifacts"] is None
        assert artifact.read_text() == staged_ledger.read_text()
        return
    rejected = run_workbench(
        state_dir,
        *commit_args,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert expected_error in str(rejected["stderr"])

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM deep_scan_workers WHERE id = ?", (reducer_id,)
        ).fetchone() == ("running",)
        assert connection.execute(
            """
            SELECT merge_state FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'discovery'
            ORDER BY completion_sequence
            """,
            (scan_id,),
        ).fetchall() == [("merging",), ("merging",)]
        assert (
            connection.execute(
                """
            SELECT canonical_inventory_path, canonical_finding_report_path,
                canonical_candidates_path, dedupe_report_path, seed_research_path,
                work_ledger_path, raw_candidates_path, coverage_ledger_path, findings_dir
            FROM deep_scan_runs
            WHERE scan_id = ?
            """,
                (scan_id,),
            ).fetchone()
            == (None,) * 9
        )

    if failure_kind == "symlink":
        artifact.unlink()
    artifact.write_text("")
    committed = run_workbench(
        state_dir,
        *commit_args,
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert committed["canonicalArtifacts"] is None


def test_scan_progress_projects_active_and_completed_independent_reviews(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    started = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(started["deepScan"]["scanId"])
    scan_dir = Path(str(started["deepScan"]["scanDir"]))

    def independent_reviews() -> dict[str, int | bool]:
        context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
        return context["scan"]["progress"]["independentReviews"]

    assert independent_reviews() == {"active": 0, "completed": 0, "consolidating": False}

    first_prompt, first_artifacts, first_result = worker_paths(scan_dir, "discovery-1")
    second_prompt, second_artifacts, _ = worker_paths(scan_dir, "discovery-2")
    first_worker_id = str(uuid.uuid4())
    second_worker_id = str(uuid.uuid4())
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=first_worker_id,
        kind="discovery",
        status="running",
        prompt_path=first_prompt,
        artifact_dir=first_artifacts,
        attempt=1,
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=second_worker_id,
        kind="discovery",
        status="running",
        prompt_path=second_prompt,
        artifact_dir=second_artifacts,
        attempt=1,
    )
    assert independent_reviews() == {"active": 2, "completed": 0, "consolidating": False}

    first_result.write_text("{}\n")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=first_worker_id,
        kind="discovery",
        status="succeeded",
        prompt_path=first_prompt,
        artifact_dir=first_artifacts,
        result_path=first_result,
        attempt=1,
    )
    assert independent_reviews() == {"active": 1, "completed": 1, "consolidating": False}

    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=second_worker_id,
        kind="discovery",
        status="canceled",
        prompt_path=second_prompt,
        artifact_dir=second_artifacts,
        attempt=1,
    )
    assert independent_reviews() == {"active": 0, "completed": 1, "consolidating": False}


def test_reducer_claim_updates_review_pass_once_and_projects_consolidation(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    started = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(started["deepScan"]["scanId"])
    scan_dir = Path(str(started["deepScan"]["scanDir"]))
    first_worker_id, _, _, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="discovery-1",
    )
    second_worker_id, _, _, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="discovery-2",
    )
    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, _ = worker_paths(scan_dir, "dedup-1")
    claim_args = (
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--input-worker-id",
        first_worker_id,
        "--input-worker-id",
        second_worker_id,
    )

    for _ in range(2):
        run_workbench(state_dir, *claim_args, environment=deep_environment(codex_home))
        progress = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"]
        assert progress["reviewPass"] == 1
        assert progress["independentReviews"] == {
            "active": 0,
            "completed": 2,
            "consolidating": True,
        }


@pytest.mark.parametrize(
    ("workers_configuration", "available_parallelism", "expected_workers"),
    [
        (None, 1, 4),
        (None, 16, 4),
        ('workers = "auto"\n', 1, 4),
        ('workers = "auto"\n', 16, 4),
        ("workers = 1\n", 16, 1),
        ("workers = 6\n", 1, 6),
    ],
)
def test_deep_scan_worker_defaults_do_not_depend_on_available_parallelism(
    tmp_path: Path,
    workers_configuration: str | None,
    available_parallelism: int,
    expected_workers: int,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    if workers_configuration is not None:
        config_path = codex_home / "codex-security" / "config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("[deep_scan]\n" + workers_configuration)
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-deep-scan",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        "--available-parallelism",
        str(available_parallelism),
        environment=deep_environment(codex_home),
    )["deepScan"]

    assert deep_scan["config"] == {
        "workers": expected_workers,
        "subagents": 3,
        "stopAfterNoNew": 4,
        "stopAfterConsecutiveErrors": 3,
        "maxDiscoveryRuns": 40,
        "maxTimeHours": 96,
    }


def test_deep_scan_prefers_explicit_config_path(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    shared_config_path = codex_home / "codex-security" / "config.toml"
    shared_config_path.parent.mkdir(parents=True)
    shared_config_path.write_text("[deep_scan]\nworkers = 2\n")
    isolated_config_path = tmp_path / "isolated-deep-scan.toml"
    isolated_config_path.write_text("[deep_scan]\nworkers = 7\n")
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-deep-scan",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        "--available-parallelism",
        "16",
        environment={
            **deep_environment(codex_home),
            "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH": str(isolated_config_path),
        },
    )["deepScan"]

    assert deep_scan["config"]["workers"] == 7


def test_target_begin_is_atomic_idempotent_and_snapshots_config(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\n"
        'workers = "auto"\n'
        "subagents = 2\n"
        "stop_after_no_new = 4\n"
        "max_discovery_runs = 12\n"
        "max_time_hours = 2.5\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text("print('fixture')\n")
    scan_root = tmp_path / "scans"

    first = begin_target_scan(state_dir, codex_home, target, scan_root)
    assert first["startDisposition"] == "created"
    deep_scan = first["deepScan"]
    assert deep_scan["status"] == "running"
    assert deep_scan["phase"] == "setup"
    assert deep_scan["config"] == {
        "workers": 4,
        "subagents": 2,
        "stopAfterNoNew": 4,
        "stopAfterConsecutiveErrors": 3,
        "maxDiscoveryRuns": 12,
        "maxTimeHours": 2.5,
    }
    assert deep_scan["workers"] == []
    scan_id = str(deep_scan["scanId"])
    scan_dir = Path(str(deep_scan["scanDir"]))
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["contract"]["target"]["targetId"] == stable_target_id(target)
    assert scan["progress"]["coverage"]["filesTotal"] == 1
    assert deep_scan["canonicalArtifacts"] is None

    config_path.write_text("[deep_scan]\nworkers = 1\nmax_time_hours = 8\n")
    second = begin_target_scan(state_dir, codex_home, target, scan_root)
    assert second["startDisposition"] == "joined"
    assert second["deepScan"]["scanId"] == deep_scan["scanId"]
    assert second["deepScan"]["config"] == deep_scan["config"]

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM workspaces").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_runs").fetchone() == (1,)
        assert connection.execute("SELECT max_time_hours FROM deep_scan_runs").fetchone() == (2.5,)
        assert (
            connection.execute(
                """
            SELECT canonical_inventory_path, canonical_finding_report_path,
                canonical_candidates_path, dedupe_report_path, seed_research_path,
                work_ledger_path, raw_candidates_path, coverage_ledger_path, findings_dir
            FROM deep_scan_runs
            """
            ).fetchone()
            == (None,) * 9
        )
        assert connection.execute("SELECT handoff_status FROM scans").fetchone() == ("delivered",)
        assert connection.execute("SELECT target_id FROM scans").fetchone() == (
            stable_target_id(target),
        )
        assert connection.execute("SELECT target_id FROM workspaces").fetchone() == (
            stable_target_id(target),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE deep_scan_runs SET canonical_inventory_path = 'partial'")

    mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="source.py",
        coverage_mode="deep_repository",
    )
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"


def test_sdk_scan_begin_claims_its_existing_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text("print('fixture')\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    user_context = "Treat intentionally planted vulnerabilities as reportable."
    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--registration-json-stdin",
        input_text=json.dumps(
            {
                "recipe": {
                    "config": {},
                    "mode": "deep",
                    "repository": str(target),
                    "target": {"kind": "repository", "paths": []},
                },
                "userContext": user_context,
            }
        ),
    )
    scan_id = str(registered["scanId"])

    premature = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "orchestration must finish and persist its manifest" in str(premature["stderr"])

    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "sdk-thread",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
    )

    assert begun["deepScan"]["scanId"] == scan_id
    assert begun["deepScan"]["scanDir"] == str(scan_dir)
    assert begun["deepScan"]["userContext"] == user_context
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
        assert connection.execute("SELECT thread_id FROM workspaces").fetchone() == ("sdk-thread",)
        assert connection.execute("SELECT deep_scan_owner_thread_id FROM scans").fetchone() == (
            "sdk-thread",
        )

    rejected = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "another-thread",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "owning Codex thread" in str(rejected["stderr"])


def test_sdk_scan_rejects_invalid_handoff_before_claiming_ownership(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "deep",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
            }
        ),
    )
    scan_id = str(registered["scanId"])
    claim_token = str(uuid.uuid4())
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_claim_token = ? WHERE id = ?",
            (claim_token, scan_id),
        )

    rejected = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "unauthorized-thread",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )

    assert "owned by another continuation" in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT thread_id FROM workspaces").fetchone() == (None,)
        assert connection.execute("SELECT deep_scan_owner_thread_id FROM scans").fetchone() == (
            None,
        )

    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "authorized-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        environment=deep_environment(codex_home),
    )
    assert begun["deepScan"]["scanId"] == scan_id


def test_target_begin_preserves_url_user_context(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text("print('fixture')\n")
    user_context = "Repository: https://github.com/example/security-review"
    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-deep-url-context",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--user-context",
        user_context,
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    assert begun["deepScan"]["userContext"] == user_context
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT user_context FROM workspaces").fetchone() == (
            user_context,
        )
        assert connection.execute("SELECT user_context FROM scans").fetchone() == (user_context,)


@pytest.mark.parametrize(
    ("configuration", "expected_no_new", "expected_errors"),
    [
        ("[deep_scan]\n", 4, 3),
        ("[deep_scan]\nstop_after_no_new = 9\n", 9, 3),
        ("[deep_scan]\nstop_after_consecutive_errors = 3\n", 4, 3),
        (
            "[deep_scan]\nstop_after_no_new = 7\nstop_after_consecutive_errors = 2\n",
            7,
            2,
        ),
    ],
)
def test_discovery_error_threshold_defaults_to_three_independently_of_no_new_threshold(
    tmp_path: Path,
    configuration: str,
    expected_no_new: int,
    expected_errors: int,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(configuration)
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]

    assert deep_scan["config"]["stopAfterNoNew"] == expected_no_new
    assert deep_scan["config"]["stopAfterConsecutiveErrors"] == expected_errors
    assert deep_scan["consecutiveErrors"] == 0


@pytest.mark.parametrize(("configured_hours", "expected_hours"), ((None, 96), (0.5, 0.5), (96, 96)))
def test_deep_scan_snapshots_configured_discovery_time_limit(
    tmp_path: Path, configured_hours: int | float | None, expected_hours: int | float
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\n"
        + ("" if configured_hours is None else f"max_time_hours = {configured_hours}\n")
    )
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]

    assert deep_scan["config"]["maxTimeHours"] == expected_hours
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT max_time_hours FROM deep_scan_runs").fetchone() == (
            expected_hours,
        )


def test_replaceable_discovery_failures_count_once_and_reset_on_success(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    failed_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "refused-discovery")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )

    for _ in range(2):
        result = upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=failed_id,
            kind="discovery",
            status="canceled",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
            attempt=1,
            error="policy_refusal: request refused by cybersecurity policy",
            replaceable_failure_kind="policy_refusal",
        )["deepScan"]
        assert result["consecutiveErrors"] == 1

    failed_worker = next(worker for worker in result["workers"] if worker["id"] == failed_id)
    assert failed_worker["status"] == "canceled"
    assert "policy_refusal" in str(failed_worker["error"])

    successful_id, _, _, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="successful-replacement",
    )
    recovered = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert recovered["consecutiveErrors"] == 0
    assert recovered["dispatchedCount"] == 2
    replacement = next(worker for worker in recovered["workers"] if worker["id"] == successful_id)
    assert replacement["status"] == "succeeded"


def test_failed_reducer_rebuffers_claimed_inputs_for_same_generation_replacement(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 3\nsubagents = 0\nstop_after_no_new = 6\nmax_discovery_runs = 6\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id = str(begun["scanId"])
    scan_dir = Path(str(begun["scanDir"]))
    claim_deep_scan_coordinator(state_dir, codex_home, scan_id)

    previously_merged = [
        dispatch_discovery_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"previously-merged-{index}",
            coordinator_generation=2,
        )[0]
        for index in range(2)
    ]
    commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="previous-reducer",
        input_worker_ids=previously_merged,
        new_findings_count=1,
        coordinator_generation=2,
    )
    canonical_ledger = scan_dir / "artifacts" / "02_discovery" / "candidate_ledger.jsonl"
    canonical_ledger.write_text('{"candidate":"previously committed"}\n')

    claimed_inputs = [
        dispatch_discovery_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"claimed-{index}",
            coordinator_generation=2,
        )[0]
        for index in range(2)
    ]
    unclaimed_input = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="unclaimed-discovery",
        coordinator_generation=2,
    )[0]
    discovery_failure, discovery_prompt, discovery_dir, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="failed-discovery",
        succeed=False,
        coordinator_generation=2,
    )
    counter_before_failure = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=discovery_failure,
        kind="discovery",
        status="canceled",
        prompt_path=discovery_prompt,
        artifact_dir=discovery_dir,
        attempt=1,
        error="transient_error: fixture discovery failure",
        replaceable_failure_kind="transient_error",
        coordinator_generation=2,
    )["deepScan"]["consecutiveErrors"]
    assert counter_before_failure == 1

    failed_reducer = str(uuid.uuid4())
    failed_prompt, failed_dir, _ = worker_paths(scan_dir, "failed-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        failed_reducer,
        "--prompt-path",
        str(failed_prompt),
        "--artifact-dir",
        str(failed_dir),
        *(item for worker in claimed_inputs for item in ("--input-worker-id", worker)),
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_reducer,
        kind="dedup",
        status="running",
        prompt_path=failed_prompt,
        artifact_dir=failed_dir,
        attempt=1,
        coordinator_generation=2,
    )

    failed = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_reducer,
        kind="dedup",
        status="failed",
        prompt_path=failed_prompt,
        artifact_dir=failed_dir,
        attempt=1,
        error="fixture reducer exhausted its attempts",
        coordinator_generation=2,
    )["deepScan"]
    failed_workers = {worker["id"]: worker for worker in failed["workers"]}
    assert failed["phase"] == "discovery"
    assert failed["consecutiveErrors"] == counter_before_failure
    assert all(failed_workers[worker]["mergeState"] == "merged" for worker in previously_merged)
    assert all(failed_workers[worker]["mergeState"] == "buffered" for worker in claimed_inputs)
    assert failed_workers[unclaimed_input]["mergeState"] == "buffered"
    assert failed_workers[failed_reducer]["status"] == "failed"
    assert failed_workers[failed_reducer]["error"] == "fixture reducer exhausted its attempts"
    assert canonical_ledger.read_text() == '{"candidate":"previously committed"}\n'

    replacement_reducer = str(uuid.uuid4())
    replacement_prompt, replacement_dir, replacement_result = worker_paths(
        scan_dir, "replacement-reducer"
    )
    replacement_inputs = [*claimed_inputs, unclaimed_input]
    claimed = run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        replacement_reducer,
        "--prompt-path",
        str(replacement_prompt),
        "--artifact-dir",
        str(replacement_dir),
        *(item for worker in replacement_inputs for item in ("--input-worker-id", worker)),
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert claimed["phase"] == "reducing"

    replayed = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_reducer,
        kind="dedup",
        status="failed",
        prompt_path=failed_prompt,
        artifact_dir=failed_dir,
        attempt=1,
        error="fixture reducer exhausted its attempts",
        coordinator_generation=2,
    )["deepScan"]
    replayed_workers = {worker["id"]: worker for worker in replayed["workers"]}
    assert replayed["phase"] == "reducing"
    assert replayed["consecutiveErrors"] == counter_before_failure
    assert all(replayed_workers[worker]["mergeState"] == "merging" for worker in replacement_inputs)

    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=replacement_reducer,
        kind="dedup",
        status="running",
        prompt_path=replacement_prompt,
        artifact_dir=replacement_dir,
        attempt=1,
        coordinator_generation=2,
    )
    replacement_result.write_text("{}\n")
    committed = run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        replacement_reducer,
        "--result-manifest-path",
        str(replacement_result),
        "--new-findings-count",
        "0",
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )["deepScan"]
    committed_workers = {worker["id"]: worker for worker in committed["workers"]}
    assert committed["consecutiveErrors"] == counter_before_failure
    assert all(
        committed_workers[worker]["mergeState"] == "merged"
        for worker in [*previously_merged, *replacement_inputs]
    )
    assert committed_workers[failed_reducer]["status"] == "failed"
    assert canonical_ledger.read_text() == '{"candidate":"previously committed"}\n'

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        receipts = connection.execute(
            "SELECT discovery_worker_id FROM deep_scan_dedup_inputs "
            "WHERE dedup_worker_id = ? ORDER BY input_order",
            (failed_reducer,),
        ).fetchall()
    assert [worker for (worker,) in receipts] == claimed_inputs

    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        "--coordinator-generation",
        "2",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert finished["status"] == "succeeded"
    assert finished["consecutiveErrors"] == counter_before_failure


def test_ordinary_discovery_cancellation_does_not_increment_failure_streak(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "user-canceled-discovery")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )

    result = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="canceled",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )["deepScan"]

    assert result["consecutiveErrors"] == 0


@pytest.mark.parametrize("invalid_threshold", ("0", "-1", "true", '"2"'))
def test_invalid_discovery_error_threshold_fails_before_scan_creation(
    tmp_path: Path, invalid_threshold: str
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(f"[deep_scan]\nstop_after_consecutive_errors = {invalid_threshold}\n")
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

    assert "deep_scan.stop_after_consecutive_errors must be a positive integer" in str(
        failed["stderr"]
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (0,)


@pytest.mark.parametrize("invalid_hours", ("0", "-0.5", "true", '"2"', "nan", "inf", "96.5"))
def test_invalid_discovery_time_limit_fails_before_scan_creation(
    tmp_path: Path, invalid_hours: str
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(f"[deep_scan]\nmax_time_hours = {invalid_hours}\n")
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

    assert "deep_scan.max_time_hours must be a positive finite number no greater than 96" in str(
        failed["stderr"]
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (0,)


def test_target_continuation_reuses_terminal_coordinator_across_threads(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('stable snapshot')\n")
    scan_root = tmp_path / "scans"

    first = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-before-continuation",
    )
    scan_id = str(first["deepScan"]["scanId"])
    scan_dir = Path(str(first["deepScan"]["scanDir"]))
    manifest = mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[deep_scan]\nsubagents = -1\n")

    continued = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-after-continuation",
    )
    assert continued["startDisposition"] == "joined"
    assert continued["deepScan"]["scanId"] == scan_id
    assert continued["deepScan"]["manifestPath"] == str(manifest)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM workspaces").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_runs").fetchone() == (1,)
        assert connection.execute(
            "SELECT deep_scan_owner_thread_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("thread-before-continuation",)


def test_target_continuation_does_not_reuse_a_different_snapshot(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    fixture = target / "fixture.py"
    fixture.write_text("print('first snapshot')\n")
    scan_root = tmp_path / "scans"

    first = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-first-snapshot",
    )
    first_scan_id = str(first["deepScan"]["scanId"])
    first_scan_dir = Path(str(first["deepScan"]["scanDir"]))
    mark_deep_coordinator_succeeded(state_dir, first_scan_id, first_scan_dir)

    fixture.write_text("print('changed snapshot')\n")
    changed = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-changed-snapshot",
    )
    assert changed["startDisposition"] == "created"
    assert changed["deepScan"]["scanId"] != first_scan_id


def test_target_continuation_does_not_reuse_another_threads_app_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('app scan')\n")
    scan_root = tmp_path / "scans"
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--thread-id",
        "app-thread",
        "--target-path",
        str(target),
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(scan_root),
        environment=deep_environment(codex_home),
    )
    app_scan_id = str(started["results"]["scanId"])
    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "app-thread",
        "--scan-id",
        app_scan_id,
        environment=deep_environment(codex_home),
    )
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    mark_deep_coordinator_succeeded(state_dir, app_scan_id, scan_dir)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE scans
            SET handoff_status = 'delivered', handoff_claim_token = ?
            WHERE id = ?
            """,
            (str(uuid.uuid4()), app_scan_id),
        )

    headless = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="headless-thread",
    )
    assert headless["startDisposition"] == "created"
    assert headless["deepScan"]["scanId"] != app_scan_id


def test_parent_scan_cannot_complete_before_deep_orchestration_manifest(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])

    rejected = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "orchestration must finish and persist its manifest" in str(rejected["stderr"])
    persisted = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert persisted["status"] == "running"


def test_concurrent_target_begin_creates_one_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: begin_target_scan(state_dir, codex_home, target, scan_root),
                range(2),
            )
        )

    assert {result["deepScan"]["scanId"] for result in results} == {
        results[0]["deepScan"]["scanId"]
    }
    assert {result["startDisposition"] for result in results} == {"created", "joined"}


def test_app_workspaces_cannot_start_duplicate_owned_target_scans(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    workspace_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    for workspace_id in workspace_ids:
        run_workbench(
            state_dir,
            "create-workspace",
            "--workspace-id",
            workspace_id,
            "--thread-id",
            "thread-owner",
            "--target-path",
            str(target),
            "--mode",
            "deep",
            environment=deep_environment(codex_home),
        )
        run_workbench(
            state_dir,
            "save-workspace",
            "--workspace-id",
            workspace_id,
            "--target-path",
            str(target),
            "--scope",
            ".",
            "--mode",
            "deep",
            environment=deep_environment(codex_home),
        )

    first = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_ids[0],
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    duplicate = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_ids[1],
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "already has an active Deep Scan" in str(duplicate["stderr"])

    run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        str(first["results"]["scanId"]),
        "--thread-id",
        "thread-owner",
        environment=deep_environment(codex_home),
    )
    second = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_ids[1],
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    assert second["results"]["scanId"] != first["results"]["scanId"]


def test_app_scan_begin_validates_mode_and_owner(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--thread-id",
        "thread-owner",
        "--target-path",
        str(target),
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    attached = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "thread-continuation",
    )
    assert attached["results"]["continuationThreadId"] == "thread-continuation"

    wrong_owner = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-owner",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "owning Codex thread" in str(wrong_owner["stderr"])

    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "thread-continuation",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--available-parallelism",
        "8",
        environment=deep_environment(codex_home),
    )
    assert begun["startDisposition"] == "created"
    assert begun["deepScan"]["config"]["workers"] == 4
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    prompt, artifact_dir, _ = worker_paths(scan_dir, "setup-worker")
    worker_id = str(uuid.uuid4())
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="setup",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )
    setup_complete = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="setup",
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )
    assert setup_complete["deepScan"]["workers"][0]["status"] == "succeeded"


@pytest.mark.parametrize("handoff_action", ("release", "takeover"))
def test_stale_deep_continuation_cannot_begin_after_handoff_transfer(
    tmp_path: Path, handoff_action: str
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target, thread_id="workspace-thread", mode="deep")
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    scan_id = str(started["results"]["scanId"])
    stale_token = str(uuid.uuid4())
    replacement_token = str(uuid.uuid4())
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE scans
            SET handoff_claimed_at = ?, handoff_claim_token = ?,
                continuation_thread_id = ?, deep_scan_owner_thread_id = ?
            WHERE id = ?
            """,
            (
                "2000-01-01T00:00:00Z",
                stale_token,
                "stale-deep-continuation",
                "stale-deep-continuation",
                scan_id,
            ),
        )
    if handoff_action == "release":
        run_workbench(
            state_dir,
            "release-handoff-delivery",
            "--scan-id",
            scan_id,
            "--claim-token",
            stale_token,
        )
    run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement_token,
        *(("--take-over-stale",) if handoff_action == "takeover" else ()),
    )

    stale_thread = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "stale-deep-continuation",
        "--scan-id",
        scan_id,
        "--claim-token",
        stale_token,
        environment=deep_environment(codex_home),
        check=False,
    )
    original_thread = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "workspace-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        stale_token,
        environment=deep_environment(codex_home),
        check=False,
    )
    tokenless_original_thread = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "workspace-thread",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )

    assert "owning Codex thread" in str(stale_thread["stderr"])
    assert "owned by another continuation" in str(original_thread["stderr"])
    assert "owned by another continuation" in str(tokenless_original_thread["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        owner, coordinator_count = connection.execute(
            """
            SELECT deep_scan_owner_thread_id,
                (SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = scans.id)
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
        assert (owner, coordinator_count) == (None, 0)

    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement_token,
        "--thread-id",
        "replacement-deep-continuation",
    )
    begun = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
        "replacement-deep-continuation",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement_token,
        environment=deep_environment(codex_home),
    )

    assert begun["startDisposition"] == "created"


def test_pending_app_workspace_does_not_block_target_bootstrap(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--thread-id",
        "thread-deep-scan",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )

    started = begin_target_scan(
        state_dir,
        codex_home,
        target,
        tmp_path / "scans",
    )
    assert started["startDisposition"] == "created"
    assert started["deepScan"]["status"] == "running"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM workspaces").fetchone() == (2,)


def test_maximum_one_discovery_run_allows_hard_cap_singleton_reducer(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n")
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    deep_scan = begun["deepScan"]
    assert deep_scan["config"]["maxDiscoveryRuns"] == 1
    scan_id = str(deep_scan["scanId"])
    scan_dir = Path(str(deep_scan["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(scan_dir, "singleton-worker")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )
    result.write_text("{}\n")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=result,
        attempt=1,
    )
    reducer_id = str(uuid.uuid4())
    reducer_prompt, reducer_dir, reducer_result = worker_paths(scan_dir, "singleton-reducer")
    claimed = run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(reducer_prompt),
        "--artifact-dir",
        str(reducer_dir),
        "--input-worker-id",
        worker_id,
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert claimed["phase"] == "reducing"
    persisted_worker = next(worker for worker in claimed["workers"] if worker["id"] == worker_id)
    assert persisted_worker["mergeState"] == "merging"
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="running",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
        attempt=1,
    )
    write_canonical_artifacts(scan_dir)
    reducer_result.write_text("{}\n")
    committed = run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--result-manifest-path",
        str(reducer_result),
        "--new-findings-count",
        "1",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert committed["status"] == "running"
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    below_threshold = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "before reaching its no-new-findings threshold" in str(below_threshold["stderr"])
    failed_setup_id = str(uuid.uuid4())
    failed_setup_prompt, failed_setup_dir, _ = worker_paths(scan_dir, "failed-setup")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_setup_id,
        kind="setup",
        status="running",
        prompt_path=failed_setup_prompt,
        artifact_dir=failed_setup_dir,
        attempt=1,
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_setup_id,
        kind="setup",
        status="failed",
        prompt_path=failed_setup_prompt,
        artifact_dir=failed_setup_dir,
        attempt=1,
        error="Setup failed.",
    )
    rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "after a worker has failed" in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("DELETE FROM deep_scan_workers WHERE id = ?", (failed_setup_id,))
    capped = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert capped["status"] == "succeeded"
    assert capped["terminalReason"] == "capped"
    assert capped["manifestPath"] == str(manifest)


@pytest.mark.parametrize(
    ("configured_hours", "elapsed", "deadline_reached"),
    (
        (None, timedelta(hours=95, minutes=59), False),
        (None, timedelta(hours=96), True),
        (2.5, timedelta(hours=2, minutes=29), False),
        (2.5, timedelta(hours=2, minutes=30), True),
        (96, timedelta(hours=95, minutes=59), False),
        (96, timedelta(hours=96), True),
    ),
)
def test_discovery_deadline_caps_after_reducing_a_single_discovery_result(
    tmp_path: Path,
    configured_hours: int | float | None,
    elapsed: timedelta,
    deadline_reached: bool,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\n"
        + ("" if configured_hours is None else f"max_time_hours = {configured_hours}\n")
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    assert begun["deepScan"]["config"]["maxTimeHours"] == (
        96 if configured_hours is None else configured_hours
    )
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="deadline-discovery",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - elapsed).isoformat(), scan_id),
        )

    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    premature_completion = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    if not deadline_reached:
        assert "before reaching its configured maximum" in str(premature_completion["stderr"])
        reducer_prompt, reducer_dir, _ = worker_paths(scan_dir, "premature-reducer")
        premature_reducer = run_workbench(
            state_dir,
            "claim-deep-scan-dedup",
            "--scan-id",
            scan_id,
            "--worker-id",
            str(uuid.uuid4()),
            "--prompt-path",
            str(reducer_prompt),
            "--artifact-dir",
            str(reducer_dir),
            "--input-worker-id",
            worker_id,
            environment=deep_environment(codex_home),
            check=False,
        )
        assert "requires two buffered discovery results" in str(premature_reducer["stderr"])
        return

    assert "without canonical discovery artifacts" in str(premature_completion["stderr"])
    reduced = commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="deadline-reducer",
        input_worker_ids=[worker_id],
        new_findings_count=1,
    )
    assert reduced["dispatchedCount"] == 1
    assert reduced["config"]["maxDiscoveryRuns"] == 3
    ledger_path = scan_dir / "artifacts" / "02_discovery" / "candidate_ledger.jsonl"
    existing_finding = '{"title": "Finding recorded before the deadline"}\n'
    ledger_path.write_text(existing_finding)

    capped = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert capped["status"] == "succeeded"
    assert capped["terminalReason"] == "capped"
    assert capped["manifestPath"] == str(manifest)
    assert ledger_path.read_text() == existing_finding


@pytest.mark.parametrize(
    ("configured_hours", "cancel_discovery"),
    ((0.5, False), (0.5, True), (1e-12, False)),
)
def test_discovery_deadline_caps_without_a_completed_discovery(
    tmp_path: Path,
    configured_hours: float,
    cancel_discovery: bool,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        f"[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = {configured_hours}\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    canonical = write_canonical_artifacts(scan_dir)
    canonical["inScopeFilesPath"].write_text("fixture.py\n")
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    if cancel_discovery:
        worker_id, prompt, artifact_dir, _ = dispatch_discovery_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name="deadline-canceled-discovery",
            succeed=False,
        )
        upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=worker_id,
            kind="discovery",
            status="canceled",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
            attempt=1,
        )

    running = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert running["status"] == "running"
    assert running["canonicalArtifacts"] is None
    if configured_hours > 1e-12:
        premature = run_workbench(
            state_dir,
            "finish-deep-scan",
            "--scan-id",
            scan_id,
            "--terminal-reason",
            "capped",
            "--manifest-path",
            str(manifest),
            environment=deep_environment(codex_home),
            check=False,
        )
        assert "before reaching its configured maximum" in str(premature["stderr"])

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            (
                (
                    datetime.now(timezone.utc)
                    - timedelta(hours=configured_hours)
                    - timedelta(seconds=1)
                ).isoformat(),
                scan_id,
            ),
        )

    capped = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert capped["status"] == "succeeded"
    assert capped["terminalReason"] == "capped"
    assert capped["completionSequence"] == 0
    assert capped["manifestPath"] == str(manifest)
    assert capped["canonicalArtifacts"] == {name: str(path) for name, path in canonical.items()}
    assert canonical["candidateLedgerPath"].read_text() == ""
    assert canonical["inScopeFilesPath"].read_text() == "fixture.py\n"
    assert [worker["status"] for worker in capped["workers"]] == (
        ["canceled"] if cancel_discovery else []
    )

    persisted = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert persisted["canonicalArtifacts"] == capped["canonicalArtifacts"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_workers WHERE scan_id = ? AND kind = 'dedup'",
            (scan_id,),
        ).fetchone() == (0,)


@pytest.mark.parametrize("candidate_ledger", ('{"candidate_id":"unvalidated"}\n', "\n"))
def test_zero_discovery_deadline_rejects_nonempty_candidate_ledger(
    tmp_path: Path,
    candidate_ledger: str,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = 0.5\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    canonical = write_canonical_artifacts(scan_dir)
    canonical["candidateLedgerPath"].write_text(candidate_ledger)
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), scan_id),
        )

    rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "without a successful dedup worker" in str(rejected["stderr"])
    assert canonical["candidateLedgerPath"].read_text() == candidate_ledger
    running = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert running["status"] == "running"
    assert running["canonicalArtifacts"] is None


def test_capped_completion_requires_canonical_artifacts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n")
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "failed-discovery")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="failed",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
        error="Retries exhausted.",
    )
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "without canonical discovery artifacts" in str(rejected["stderr"])


def test_capped_completion_rejects_buffered_workers_and_omissions(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 2\nstop_after_no_new = 10\nmax_discovery_runs = 3\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    first_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="first",
    )
    second_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="second",
    )
    committed = commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="first-reducer",
        input_worker_ids=[first_id, second_id],
        new_findings_count=1,
    )
    assert committed["status"] == "running"
    buffered_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="buffered-at-cap",
    )
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    buffered_rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "while discovery output remains buffered" in str(buffered_rejected["stderr"])

    omitted_rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest),
        "--omitted-worker-id",
        buffered_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "cannot declare omitted buffered workers" in str(omitted_rejected["stderr"])


def prepare_failure_capped_deep_scan(
    tmp_path: Path,
) -> tuple[Path, Path, Path, str]:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[deep_scan]\nworkers = 2\nmax_discovery_runs = 10\n")
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    first_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="first-accepted",
    )
    second_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="second-accepted",
    )
    commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="committed-aggregate",
        input_worker_ids=[first_id, second_id],
        new_findings_count=1,
    )
    write_completed_contract(scan_dir, scan_id, target, coverage_mode="deep_repository")
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["completeness"] = "partial"
    coverage["deferred"].append(
        {"reason": "Deep Scan stopped before completion: reducer retries were exhausted"}
    )
    coverage_path.write_text(json.dumps(coverage))
    return state_dir, codex_home, scan_dir, scan_id


def test_failure_capped_completion_preserves_partial_results_and_exact_omissions(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, scan_dir, scan_id = prepare_failure_capped_deep_scan(tmp_path)
    buffered_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="buffered-after-aggregate",
    )
    failed_id, failed_prompt, failed_dir, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="terminal-failure",
        succeed=False,
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=failed_id,
        kind="discovery",
        status="failed",
        prompt_path=failed_prompt,
        artifact_dir=failed_dir,
        attempt=1,
        error="Worker retries exhausted.",
    )
    finish_args = (
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(scan_dir / "scan-manifest.json"),
    )

    without_omission = run_workbench(
        state_dir, *finish_args, environment=deep_environment(codex_home), check=False
    )
    assert "exactly identify all buffered discovery workers" in str(without_omission["stderr"])

    finished = run_workbench(
        state_dir,
        *finish_args,
        "--omitted-worker-id",
        buffered_id,
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert finished["status"] == "succeeded"
    assert finished["terminalReason"] == "capped"
    assert finished["config"]["maxDiscoveryRuns"] == 10
    assert finished["dispatchedCount"] == 4
    assert json.loads((scan_dir / "coverage.json").read_text())["completeness"] == "partial"
    assert len(json.loads((scan_dir / "findings.json").read_text())["findings"]) == 1
    assert (
        next(worker for worker in finished["workers"] if worker["id"] == failed_id)["status"]
        == "failed"
    )
    assert (
        next(worker for worker in finished["workers"] if worker["id"] == buffered_id)["mergeState"]
        == "buffered"
    )

    replayed = run_workbench(
        state_dir,
        *finish_args,
        "--omitted-worker-id",
        buffered_id,
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert replayed == finished


def test_late_worker_rejection_does_not_mutate_frozen_stopped_results(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, coverage_mode="deep_repository")
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    provisional = findings["findings"].pop()
    provisional["extensions"] = {"candidateId": "candidate-late-rejection"}
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["completeness"] = "partial"
    coverage["surfaces"] = []
    coverage_path.write_text(json.dumps(coverage))

    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, "late-rejection")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt_path,
        artifact_dir=artifact_dir,
        attempt=1,
    )
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [provisional],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    encoded = json.dumps(checkpoint).encode()
    checkpoint_dir = artifact_dir / "checkpoints"
    checkpoint_dir.mkdir()
    (checkpoint_dir / f"{hashlib.sha256(encoded).hexdigest()}.json").write_bytes(encoded)

    stopped = run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after the provisional checkpoint.",
        environment=deep_environment(codex_home),
    )["scan"]
    assert stopped["findingCount"] == 1

    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    "completeness": "complete",
                    "surfaces": [
                        {
                            "candidateId": "candidate-late-rejection",
                            "label": "Late worker disposition",
                            "disposition": "rejected",
                            "receiptRefs": [],
                        }
                    ],
                    "explicitExclusions": [],
                    "deferred": [],
                },
            }
        )
    )

    refreshed = run_workbench(
        state_dir, "get-scan", "--scan-id", scan_id, environment=deep_environment(codex_home)
    )["scan"]
    final_findings = json.loads(findings_path.read_text())["findings"]
    final_coverage = json.loads(coverage_path.read_text())
    assert refreshed["findingCount"] == len(final_findings) == 1
    assert final_findings[0]["summary"] == provisional["summary"]
    assert not any(
        item.get("candidateId") == "candidate-late-rejection"
        and item.get("disposition") == "rejected"
        for item in final_coverage["surfaces"]
    )


def test_failure_capped_completion_recovers_canceled_reducer_inputs(tmp_path: Path) -> None:
    state_dir, codex_home, scan_dir, scan_id = prepare_failure_capped_deep_scan(tmp_path)
    buffered_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="claimed-before-failure",
    )
    reducer_id = str(uuid.uuid4())
    reducer_prompt, reducer_dir, _ = worker_paths(scan_dir, "canceled-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(reducer_prompt),
        "--artifact-dir",
        str(reducer_dir),
        "--input-worker-id",
        buffered_id,
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="running",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
        attempt=1,
    )
    finish_args = (
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(scan_dir / "scan-manifest.json"),
        "--omitted-worker-id",
        buffered_id,
    )
    active_rejected = run_workbench(
        state_dir, *finish_args, environment=deep_environment(codex_home), check=False
    )
    assert "while workers are active" in str(active_rejected["stderr"])

    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="canceled",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
        attempt=1,
    )
    finished = run_workbench(state_dir, *finish_args, environment=deep_environment(codex_home))[
        "deepScan"
    ]
    assert finished["status"] == "succeeded"
    assert (
        next(worker for worker in finished["workers"] if worker["id"] == reducer_id)["status"]
        == "canceled"
    )
    assert (
        next(worker for worker in finished["workers"] if worker["id"] == buffered_id)["mergeState"]
        == "buffered"
    )


@pytest.mark.parametrize("invalid_case", ["ordinary_partial", "complete", "missing_coverage"])
def test_failure_capped_completion_rejects_unmarked_or_missing_canonical_coverage(
    tmp_path: Path, invalid_case: str
) -> None:
    state_dir, codex_home, scan_dir, scan_id = prepare_failure_capped_deep_scan(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    if invalid_case == "ordinary_partial":
        coverage["deferred"] = [{"reason": "Some source files were not reviewed."}]
    elif invalid_case == "complete":
        coverage["completeness"] = "complete"
    else:
        coverage_path.unlink()
    if invalid_case != "missing_coverage":
        coverage_path.write_text(json.dumps(coverage))

    rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(scan_dir / "scan-manifest.json"),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert (
        "Canonical parent coverage.json must be an existing path"
        if invalid_case == "missing_coverage"
        else "cannot finish capped before reaching its configured maximum"
    ) in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, manifest_path FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == ("running", None)


def test_saturated_completion_rejects_merging_workers(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 2\nstop_after_no_new = 2\nmax_discovery_runs = 3\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    first_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="first",
    )
    second_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="second",
    )
    committed = commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="first-reducer",
        input_worker_ids=[first_id, second_id],
        new_findings_count=0,
    )
    assert committed["noNewStreak"] == 2
    merging_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="merging-input",
    )
    reducer_id = str(uuid.uuid4())
    reducer_prompt, reducer_dir, _ = worker_paths(scan_dir, "abandoned-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(reducer_prompt),
        "--artifact-dir",
        str(reducer_dir),
        "--input-worker-id",
        merging_id,
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="canceled",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
    )
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "while discovery output is merging" in str(rejected["stderr"])


def test_running_worker_updates_preserve_identity_and_dispatch_count(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "running-worker")
    update = {
        "scan_id": scan_id,
        "worker_id": worker_id,
        "kind": "discovery",
        "status": "running",
        "prompt_path": prompt,
        "artifact_dir": artifact_dir,
        "attempt": 1,
    }

    initial = upsert_worker(state_dir, codex_home, **update)["deepScan"]
    initial_worker = next(worker for worker in initial["workers"] if worker["id"] == worker_id)
    repeated = upsert_worker(state_dir, codex_home, **update)["deepScan"]
    repeated_worker = next(worker for worker in repeated["workers"] if worker["id"] == worker_id)

    assert initial["dispatchedCount"] == repeated["dispatchedCount"] == 1
    assert repeated_worker["startedAt"] == initial_worker["startedAt"]
    assert repeated_worker["attempt"] == initial_worker["attempt"] == 1
    assert repeated_worker["sdkThreadId"] is None

    started = upsert_worker(state_dir, codex_home, **update, thread_id="thread-worker")["deepScan"]
    replayed = upsert_worker(state_dir, codex_home, **update, thread_id="thread-worker")["deepScan"]
    started_worker = next(worker for worker in started["workers"] if worker["id"] == worker_id)
    replayed_worker = next(worker for worker in replayed["workers"] if worker["id"] == worker_id)

    assert started["dispatchedCount"] == replayed["dispatchedCount"] == 1
    assert replayed_worker["sdkThreadId"] == started_worker["sdkThreadId"] == "thread-worker"
    assert replayed_worker["startedAt"] == initial_worker["startedAt"]


def test_terminal_worker_updates_are_exact_idempotent_replays(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(scan_dir, "terminal-worker")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )
    result.write_text("{}\n")
    accepted = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=result,
        attempt=1,
    )["deepScan"]
    accepted_worker = next(worker for worker in accepted["workers"] if worker["id"] == worker_id)
    replayed = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=result,
        attempt=1,
    )["deepScan"]
    replayed_worker = next(worker for worker in replayed["workers"] if worker["id"] == worker_id)
    assert replayed_worker == accepted_worker

    replacement_result = artifact_dir / "replacement-result.json"
    replacement_result.write_text("{}\n")
    replacement = run_workbench(
        state_dir,
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--status",
        "succeeded",
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(artifact_dir),
        "--result-manifest-path",
        str(replacement_result),
        "--attempt",
        "1",
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "terminal state is immutable" in str(replacement["stderr"])
    later_attempt = run_workbench(
        state_dir,
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--status",
        "succeeded",
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(artifact_dir),
        "--result-manifest-path",
        str(result),
        "--attempt",
        "2",
        environment=deep_environment(codex_home),
        check=False,
    )
    assert later_attempt["returncode"] != 0
    assert "terminal state is immutable" in str(later_attempt["stderr"])


def test_discovery_buffer_prefix_dedup_and_saturation_are_transactional(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "[deep_scan]\nworkers = 2\nstop_after_no_new = 3\nmax_discovery_runs = 4\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    deep_scan = begun["deepScan"]
    scan_id = str(deep_scan["scanId"])
    scan_dir = Path(str(deep_scan["scanDir"]))
    for index in range(3):
        worker_id = str(uuid.uuid4())
        prompt, artifact_dir, result = worker_paths(scan_dir, f"worker-{index}")
        upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=worker_id,
            kind="discovery",
            status="running",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
            attempt=1,
        )
        result.write_text("{}\n")
        accepted = upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=worker_id,
            kind="discovery",
            status="succeeded",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
            result_path=result,
            attempt=1,
        )
        assert accepted["deepScan"]["workers"][-1]["mergeState"] == "buffered"

    ordered_workers = sorted(
        (worker for worker in accepted["deepScan"]["workers"] if worker["kind"] == "discovery"),
        key=lambda worker: worker["completionSequence"],
    )
    assert [worker["completionSequence"] for worker in ordered_workers] == [1, 2, 3]
    reducer_id = str(uuid.uuid4())
    reducer_prompt, reducer_dir, reducer_result = worker_paths(scan_dir, "reducer")
    claimed = run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(reducer_prompt),
        "--artifact-dir",
        str(reducer_dir),
        *(item for worker in ordered_workers[:2] for item in ("--input-worker-id", worker["id"])),
        environment=deep_environment(codex_home),
    )
    assert claimed["deepScan"]["phase"] == "reducing"
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=reducer_id,
        kind="dedup",
        status="running",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
        attempt=1,
        error="Transient reducer failure.",
    )
    write_canonical_artifacts(scan_dir)
    reducer_result.write_text("{}\n")
    committed = run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--result-manifest-path",
        str(reducer_result),
        "--new-findings-count",
        "0",
        environment=deep_environment(codex_home),
    )
    assert committed["deepScan"]["status"] == "running"
    assert committed["deepScan"]["terminalReason"] is None
    assert committed["deepScan"]["noNewStreak"] == 2
    assert committed["deepScan"]["canonicalArtifacts"] is None
    committed_reducer = next(
        worker for worker in committed["deepScan"]["workers"] if worker["id"] == reducer_id
    )
    assert committed_reducer["error"] is None
    omitted = next(
        worker
        for worker in committed["deepScan"]["workers"]
        if worker["id"] == ordered_workers[2]["id"]
    )
    assert omitted["status"] == "succeeded"
    assert omitted["mergeState"] == "buffered"
    second_reducer_id = str(uuid.uuid4())
    second_prompt, second_dir, second_result = worker_paths(scan_dir, "second-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        second_reducer_id,
        "--prompt-path",
        str(second_prompt),
        "--artifact-dir",
        str(second_dir),
        "--input-worker-id",
        str(omitted["id"]),
        environment=deep_environment(codex_home),
    )
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=second_reducer_id,
        kind="dedup",
        status="running",
        prompt_path=second_prompt,
        artifact_dir=second_dir,
        attempt=1,
    )
    second_result.write_text("{}\n")
    late_worker_id, late_prompt, late_dir, late_result = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="late-worker",
        succeed=False,
    )
    saturated_reduction = run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        second_reducer_id,
        "--result-manifest-path",
        str(second_result),
        "--new-findings-count",
        "0",
        environment=deep_environment(codex_home),
    )
    assert saturated_reduction["deepScan"]["status"] == "running"
    assert saturated_reduction["deepScan"]["phase"] == "discovery"
    assert saturated_reduction["deepScan"]["terminalReason"] is None
    assert saturated_reduction["deepScan"]["completedAt"] is None
    assert saturated_reduction["deepScan"]["noNewStreak"] == 3
    late_worker = next(
        worker
        for worker in saturated_reduction["deepScan"]["workers"]
        if worker["id"] == late_worker_id
    )
    assert late_worker["status"] == "running"
    manifest = scan_dir / "artifacts" / "deep_discovery" / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    active_rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "while workers are active" in str(active_rejected["stderr"])

    late_result.write_text("{}\n")
    accepted_late = upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=late_worker_id,
        kind="discovery",
        status="succeeded",
        prompt_path=late_prompt,
        artifact_dir=late_dir,
        result_path=late_result,
        attempt=1,
    )["deepScan"]
    accepted_late_worker = next(
        worker for worker in accepted_late["workers"] if worker["id"] == late_worker_id
    )
    assert accepted_late_worker["mergeState"] == "buffered"

    omitted_rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "exactly identify all buffered discovery workers" in str(omitted_rejected["stderr"])
    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        "--omitted-worker-id",
        late_worker_id,
        environment=deep_environment(codex_home),
    )
    assert finished["deepScan"]["status"] == "succeeded"
    assert finished["deepScan"]["terminalReason"] == "saturated"
    assert finished["deepScan"]["manifestPath"] == str(manifest)
    replayed = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        "--omitted-worker-id",
        late_worker_id,
        environment=deep_environment(codex_home),
    )
    assert replayed == finished
    mismatched_replay = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "terminal state is immutable" in str(mismatched_replay["stderr"])


def test_get_deep_scan_does_not_invent_compact_artifacts_for_legacy_success(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    committed = commit_reducer(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="legacy-reducer",
        input_worker_ids=[
            dispatch_discovery_worker(
                state_dir,
                codex_home,
                scan_id=scan_id,
                scan_dir=scan_dir,
                name=f"legacy-discovery-{index}",
            )[0]
            for index in range(2)
        ],
        new_findings_count=0,
    )
    compact_files = write_canonical_artifacts(scan_dir)
    assert committed["canonicalArtifacts"] is None
    for path in compact_files.values():
        path.unlink()

    legacy_dir = scan_dir / "artifacts" / "legacy-discovery"
    legacy_dir.mkdir(parents=True)
    legacy_files = {
        "canonical_inventory_path": legacy_dir / "canonical_inventory.md",
        "canonical_finding_report_path": legacy_dir / "finding_discovery_report.md",
        "canonical_candidates_path": legacy_dir / "canonical_candidates.jsonl",
        "dedupe_report_path": legacy_dir / "dedupe_report.md",
        "seed_research_path": legacy_dir / "seed_research.md",
        "work_ledger_path": legacy_dir / "work_ledger.jsonl",
        "raw_candidates_path": legacy_dir / "raw_candidates.jsonl",
        "coverage_ledger_path": legacy_dir / "coverage_ledger.md",
        "findings_dir": legacy_dir / "findings",
    }
    for name, path in legacy_files.items():
        if name == "findings_dir":
            path.mkdir()
        else:
            path.write_text("")
    manifest = legacy_dir / "coordinator-manifest.json"
    manifest.write_text('{"status":"succeeded"}\n')
    legacy_columns = ", ".join(legacy_files)
    legacy_updates = ", ".join(f"{name} = ?" for name in legacy_files)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            f"SELECT {legacy_columns} FROM deep_scan_runs WHERE scan_id = ?",
            (scan_id,),
        ).fetchone() == (None,) * len(legacy_files)
        connection.execute(
            f"""
            UPDATE deep_scan_runs
            SET {legacy_updates}, status = 'succeeded', phase = 'terminal',
                terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at
            WHERE scan_id = ?
            """,
            (*map(str, legacy_files.values()), str(manifest), scan_id),
        )

    persisted = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert persisted["status"] == "succeeded"
    assert persisted["manifestPath"] == str(manifest)
    assert persisted["canonicalArtifacts"] is None
    assert all(path.exists() for path in legacy_files.values())
    assert not any(path.exists() for path in compact_files.values())


def test_finish_preserves_legacy_succeeded_without_manifest_compatibility(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated',
                completed_at = updated_at
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
    manifest = scan_dir / "legacy-coordinator-manifest.json"
    manifest.write_text("{}\n")

    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )
    assert finished["deepScan"]["manifestPath"] == str(manifest)
    replayed = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )
    assert replayed == finished

    replacement = scan_dir / "replacement-manifest.json"
    replacement.write_text("{}\n")
    mismatched = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "saturated",
        "--manifest-path",
        str(replacement),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "terminal state is immutable" in str(mismatched["stderr"])


def test_cancel_scan_cancels_coordinator_and_active_workers(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    deep_scan = begun["deepScan"]
    scan_id = str(deep_scan["scanId"])
    scan_dir = Path(str(deep_scan["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "worker")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
    )

    run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )
    canceled = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert canceled["status"] == "canceled"
    assert canceled["phase"] == "terminal"
    assert canceled["cancelRequested"] is True
    assert canceled["workers"][0]["status"] == "canceled"


def test_failure_manifest_is_confined_persisted_and_exactly_replayable(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id, *_ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="active-worker",
        succeed=False,
    )
    outside_manifest = tmp_path / "outside-failure-manifest.json"
    outside_manifest.write_text("{}\n")
    confined = run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Coordinator failed.",
        "--manifest-path",
        str(outside_manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "inside the scan directory" in str(confined["stderr"])

    manifest = scan_dir / "failure-manifest.json"
    manifest.write_text("{}\n")
    failed = run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Coordinator failed.",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )
    deep_scan = failed["deepScan"]
    assert deep_scan["status"] == "failed"
    assert deep_scan["manifestPath"] == str(manifest)
    assert (
        next(worker for worker in deep_scan["workers"] if worker["id"] == worker_id)["status"]
        == "canceled"
    )
    parent = run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
    )["scan"]
    assert parent["progress"]["status"] == "failed"
    assert parent["failureMessage"] == "Coordinator failed."

    replayed = run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Coordinator failed.",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
    )
    assert replayed == failed

    replacement = scan_dir / "replacement-failure-manifest.json"
    replacement.write_text("{}\n")
    for extra_args in (
        ("--message", "Different failure.", "--manifest-path", str(manifest)),
        ("--message", "Coordinator failed.", "--manifest-path", str(replacement)),
        (
            "--deep-status",
            "interrupted",
            "--message",
            "Coordinator failed.",
            "--manifest-path",
            str(manifest),
        ),
    ):
        mismatched = run_workbench(
            state_dir,
            "fail-deep-scan",
            "--scan-id",
            scan_id,
            *extra_args,
            environment=deep_environment(codex_home),
            check=False,
        )
        assert "terminal failure state is immutable" in str(mismatched["stderr"])

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET failure_message = 'Diverged parent failure.' WHERE id = ?",
            (scan_id,),
        )
    incoherent_parent = run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Coordinator failed.",
        "--manifest-path",
        str(manifest),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "parent failure must exactly match" in str(incoherent_parent["stderr"])


@pytest.mark.parametrize("with_manifest", [False, True])
def test_cancel_scan_overrides_succeeded_deep_run_during_parent_tail(
    tmp_path: Path, with_manifest: bool
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    deep_scan = begun["deepScan"]
    scan_id = str(deep_scan["scanId"])
    manifest = Path(str(deep_scan["scanDir"])) / "coordinator-manifest.json"
    if with_manifest:
        manifest.write_text("{}\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated',
                manifest_path = ?, completed_at = updated_at
            WHERE scan_id = ?
            """,
            (str(manifest) if with_manifest else None, scan_id),
        )

    run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )
    canceled = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert canceled["status"] == "canceled"
    assert canceled["cancelRequested"] is True
    assert canceled["manifestPath"] == (str(manifest) if with_manifest else None)
    scan = run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
    )["scan"]
    assert scan["progress"]["status"] == "canceled"


@pytest.mark.parametrize("deep_status", ["failed", "interrupted"])
def test_saturated_run_without_manifest_can_be_marked_failed_or_interrupted(
    tmp_path: Path, deep_status: str
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated',
                completed_at = updated_at
            WHERE scan_id = ?
            """,
            (scan_id,),
        )

    message = f"The coordinator {deep_status} before its manifest was persisted."
    terminal = run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--deep-status",
        deep_status,
        "--message",
        message,
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert terminal["status"] == deep_status
    assert terminal["error"] == message
    scan = run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
    )["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["failureMessage"] == terminal["error"]


def test_succeeded_run_with_manifest_cannot_be_marked_interrupted(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    deep_scan = begun["deepScan"]
    scan_id = str(deep_scan["scanId"])
    manifest = Path(str(deep_scan["scanDir"])) / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated',
                manifest_path = ?, completed_at = updated_at
            WHERE scan_id = ?
            """,
            (str(manifest), scan_id),
        )

    for deep_status in ("failed", "interrupted"):
        rejected = run_workbench(
            state_dir,
            "fail-deep-scan",
            "--scan-id",
            scan_id,
            "--deep-status",
            deep_status,
            "--message",
            "Must remain successful.",
            environment=deep_environment(codex_home),
            check=False,
        )
        assert "Only a running Deep Scan" in str(rejected["stderr"])
    persisted = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert persisted["status"] == "succeeded"
    assert persisted["manifestPath"] == str(manifest)

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE scans
            SET status = 'complete', completed_at = updated_at
            WHERE id = ?
            """,
            (scan_id,),
        )
    completed_cancel = run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "Only a running scan can be canceled" in str(completed_cancel["stderr"])
    unchanged = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert unchanged["status"] == "succeeded"
    assert unchanged["manifestPath"] == str(manifest)


def test_invalid_user_configuration_fails_before_scan_creation(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[deep_scan]\nsubagents = -1\n")
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
    assert "deep_scan.subagents must be a non-negative integer" in str(failed["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (0,)
