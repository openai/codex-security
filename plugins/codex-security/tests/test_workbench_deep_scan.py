"""Exercise deep scan registration, coordinator claims, iteration ordering, and terminal state transitions."""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from workbench_test_support import (
    attach_continuation,
    begin_deep_scan,
    cancel_scan,
    create_saved_workspace,
    create_workspace,
    empty_target_paths,
    fail_scan,
    finish_deep_scan,
    get_deep_scan,
    get_scan,
    load_script,
    mark_deep_coordinator_succeeded,
    read_fixture_deep_scan,
    read_review_state,
    resume_deep_scan,
    run_workbench,
    save_workspace,
    saved_draft,
    scan_claim_command,
    scan_command,
    seal_legacy_reducer,
    seed_legacy_reducer,
    stable_target_id,
    start_delivered_scan,
    start_scan_command,
    update_progress,
    upsert_deep_worker,
    worker_paths,
    write_checkpoint,
    write_completed_contract,
)


def deep_environment(codex_home: Path) -> dict[str, str]:
    return {"CODEX_HOME": str(codex_home)}


def write_deep_config(codex_home: Path, content: str) -> Path:
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(content)
    return config_path


def begin_target_scan(
    state_dir: Path,
    codex_home: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-deep-scan",
    user_context: str | None = None,
    service_tier: str | None = None,
) -> dict[str, object]:
    return begin_deep_scan(
        state_dir,
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(scan_root),
        *(("--user-context-stdin",) if user_context is not None else ()),
        *(("--service-tier", service_tier) if service_tier is not None else ()),
        environment=deep_environment(codex_home),
        input_text=user_context,
    )


def start_empty_target_scan(tmp_path: Path, *, config: str | None = None) -> DeepScan:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    if config is not None:
        write_deep_config(codex_home, config)
    target = tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    return DeepScan(state_dir, codex_home, str(run["scanId"]), Path(str(run["scanDir"])))


@pytest.mark.cross_platform
def test_target_admission_stops_at_the_first_non_directory_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "check_deep_scan_target.py"
    check_selected_targets = runpy.run_path(str(script))["check_selected_targets"]
    events = []

    class FileEntry:
        def is_dir(self, *, follow_symlinks):
            assert not follow_symlinks
            return False

    def entries():
        events.append("read")
        yield FileEntry()
        pytest.fail("admission read a second directory entry")

    @contextmanager
    def scandir(path):
        assert Path(path) == tmp_path
        try:
            yield entries()
        finally:
            events.append("closed")

    monkeypatch.setattr(os, "scandir", scandir)
    check_selected_targets(tmp_path, ["."], [])
    assert events == ["read", "closed"]


def restore_v53_schema(state_dir: Path) -> None:
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("DROP TRIGGER retain_unverified_deep_scan_worker_attempt")
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN worker_usage_gap")
        connection.execute("DROP TRIGGER classify_legacy_scan_recipe")
        connection.execute("DROP VIEW scan_lifecycles")
        connection.execute("ALTER TABLE scans DROP COLUMN windows_resume_target_identity")
        connection.execute("ALTER TABLE scans DROP COLUMN windows_resume_output_identity")
        connection.execute("ALTER TABLE scans DROP COLUMN log_completed_at")
        connection.execute("ALTER TABLE scans DROP COLUMN launch_kind")
        connection.execute("ALTER TABLE scans DROP COLUMN launch_plugin_version")
        connection.execute("ALTER TABLE scans DROP COLUMN launch_package_version")
        connection.execute("ALTER TABLE scans DROP COLUMN launch_surface")
        connection.executescript("""
            DROP TABLE external_finding_publications;
            DROP TABLE external_finding_import_members;
            DROP TABLE external_finding_imports;
            DROP TRIGGER scans_assign_inserted_completion_sequence;
            DROP TRIGGER scans_assign_updated_completion_sequence;
            DROP INDEX scans_completion_sequence;
            DROP INDEX scans_by_target_path;
            DROP INDEX scans_by_repository_generation;
            DROP INDEX security_targets_by_repository_identity;
            ALTER TABLE scans DROP COLUMN completion_sequence;
            ALTER TABLE scans DROP COLUMN repository_generation;
            ALTER TABLE security_targets DROP COLUMN repository_identity;
            ALTER TABLE security_targets DROP COLUMN git_checkout_root;
            ALTER TABLE workspaces DROP COLUMN rejected_checkout_roots_json;
            ALTER TABLE workspaces DROP COLUMN target_path_unvalidated;
        """)
        connection.execute(
            "ALTER TABLE scan_severity_classifications DROP COLUMN rubric_binding_json"
        )
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN service_tier")
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN terminal_reviewed_surface_count")
        connection.execute("ALTER TABLE scans DROP COLUMN retained_checkpoint_heads_json")
        connection.execute("ALTER TABLE workspaces DROP COLUMN deep_scan_config_json")
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN pending_target_project_path")
        connection.execute("DELETE FROM schema_migrations WHERE version > 53")


def claim_deep_scan_coordinator(
    state_dir: Path,
    codex_home: Path,
    scan_id: str,
    *,
    thread_id: str = "thread-deep-scan",
    handoff_claim_token: str | None = None,
    coordinator_generation: int | None = None,
    check: bool = True,
) -> dict[str, object]:
    return scan_command(
        state_dir,
        "claim-deep-scan-coordinator",
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
        check=check,
    )


def expire_deep_scan_coordinator(state_dir: Path, scan_id: str) -> None:
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
            ("2000-01-01T00:00:00Z", scan_id),
        )


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


@dataclass(frozen=True)
class DeepScan:
    """Keep a test scan ID, state directory, and Codex home together when issuing worker and coordinator commands."""

    state_dir: Path
    codex_home: Path
    id: str
    directory: Path

    def command(self, command: str, *args: str, check: bool = True) -> dict[str, object]:
        return scan_command(
            self.state_dir,
            command,
            self.id,
            *args,
            environment=deep_environment(self.codex_home),
            check=check,
        )

    def read(self, thread_id: str) -> dict[str, object]:
        return get_deep_scan(
            self.state_dir, self.id, thread_id, environment=deep_environment(self.codex_home)
        )["deepScan"]

    def upsert_worker(
        self,
        *,
        worker_id: str,
        kind: str = "discovery",
        status: str = "running",
        prompt_path: Path,
        artifact_dir: Path,
        result_path: Path | None = None,
        attempt: int | None = 1,
        thread_id: str | None = None,
        error: str | None = None,
        replaceable_failure_kind: str | None = None,
        terminal_failure: bool = False,
        coordinator_generation: int | None = None,
        check: bool = True,
    ) -> dict[str, object]:
        return upsert_deep_worker(
            self.state_dir,
            self.id,
            worker_id,
            kind,
            status,
            str(prompt_path),
            str(artifact_dir),
            *(("--result-manifest-path", str(result_path)) if result_path is not None else ()),
            *(("--attempt", str(attempt)) if attempt is not None else ()),
            *(("--sdk-thread-id", thread_id) if thread_id is not None else ()),
            *(("--error-message", error) if error is not None else ()),
            *(("--terminal-failure",) if terminal_failure else ()),
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
            environment=deep_environment(self.codex_home),
            check=check,
        )

    def dispatch_discovery_worker(
        self,
        *,
        name: str,
        succeed: bool = True,
        coordinator_generation: int | None = None,
    ) -> tuple[str, Path, Path, Path]:
        worker_id = str(uuid.uuid4())
        prompt_path, artifact_dir, result_path = worker_paths(self.directory, name)
        self.upsert_worker(
            worker_id=worker_id,
            prompt_path=prompt_path,
            artifact_dir=artifact_dir,
            coordinator_generation=coordinator_generation,
        )
        if succeed:
            result_path.write_text("{}\n")
            self.upsert_worker(
                worker_id=worker_id,
                status="succeeded",
                prompt_path=prompt_path,
                artifact_dir=artifact_dir,
                result_path=result_path,
                coordinator_generation=coordinator_generation,
            )
        return worker_id, prompt_path, artifact_dir, result_path

    def seed_legacy_reducer(
        self,
        worker_id: str,
        prompt_path: Path,
        artifact_dir: Path,
        input_worker_ids: list[str],
    ) -> None:
        seed_legacy_reducer(
            self.state_dir,
            self.id,
            worker_id,
            str(prompt_path),
            str(artifact_dir),
            *input_worker_ids,
        )

    def finish(
        self, reason: str, manifest: Path | str, *extra: str, check: bool = True
    ) -> dict[str, object]:
        return finish_deep_scan(
            self.state_dir,
            self.id,
            reason,
            str(manifest),
            *extra,
            environment=deep_environment(self.codex_home),
            check=check,
        )

    def record_iteration(
        self,
        *,
        name: str,
        input_worker_ids: list[str],
        new_findings_count: int,
        coordinator_generation: int | None = None,
    ) -> dict[str, object]:
        _, _, result = worker_paths(self.directory, name)
        write_canonical_artifacts(self.directory)
        result.write_text(json.dumps({"scanId": self.id, "findings": []}))
        snapshot = read_fixture_deep_scan(
            self.state_dir, self.id, deep_environment(self.codex_home)
        )
        streak = snapshot["deepScan"]["noNewStreak"]
        return self.command(
            "record-deep-scan-iteration",
            "--worker-id",
            str(uuid.uuid4()),
            "--result-manifest-path",
            str(result),
            "--no-new-streak",
            str(0 if new_findings_count else streak + len(input_worker_ids)),
            "--consecutive-errors",
            "0",
            *(arg for source in input_worker_ids for arg in ("--input-worker-id", source)),
            *(
                ("--coordinator-generation", str(coordinator_generation))
                if coordinator_generation is not None
                else ()
            ),
        )["deepScan"]


def test_iteration_commits_all_sources_once_in_launch_order(tmp_path: Path) -> None:
    deep = start_empty_target_scan(tmp_path)
    sources = [deep.dispatch_discovery_worker(name=name)[0] for name in ("second", "first")]
    _, _, result = worker_paths(deep.directory, "dedup-0001")
    result.write_text(json.dumps({"scanId": deep.id, "findings": []}))
    record = (
        "--worker-id",
        str(uuid.uuid4()),
        "--result-manifest-path",
        str(result),
        "--no-new-streak",
        "1",
        "--consecutive-errors",
        "2",
    )

    def save(ids, *, check=True):
        return deep.command(
            "record-deep-scan-iteration",
            *record,
            *(arg for source in ids for arg in ("--input-worker-id", source)),
            check=check,
        )

    assert "unmerged completed scan" in save([sources[1], str(uuid.uuid4())], check=False)["stderr"]
    before = deep.read("thread-deep-scan")
    assert all(w["mergeState"] == "buffered" for w in before["workers"])
    for _ in range(2):
        saved = save(list(reversed(sources)))["deepScan"]
        assert saved["noNewStreak"] == 1
        assert saved["consecutiveErrors"] == 2
        assert len([w for w in saved["workers"] if w["kind"] == "dedup"]) == 1
        assert [i["discoveryWorkerId"] for i in saved["dedupInputs"]] == list(reversed(sources))
    assert "other completed scans" in save(sources, check=False)["stderr"]


@pytest.mark.parametrize("legacy_archive", [False, True])
def test_archived_deep_scan_keeps_its_discovery_and_checkpoint_paths(
    tmp_path: Path, legacy_archive: bool
) -> None:
    deep = start_empty_target_scan(tmp_path)
    worker, *_ = deep.dispatch_discovery_worker(name="discovery-0001")
    deep.record_iteration(name="dedup-0001", input_worker_ids=[worker], new_findings_count=1)
    manifest = deep.directory / "coordinator.json"
    manifest.write_text("{}")
    before = deep.command(
        "fail-deep-scan", "--message", "Stopped", "--manifest-path", str(manifest)
    )["deepScan"]

    target = tmp_path / "target"
    registration = run_workbench(
        deep.state_dir,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(deep.directory),
        "--archive-existing",
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "deep",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        environment=deep_environment(deep.codex_home),
    )
    archived = Path(registration["archivedScanDir"])
    if legacy_archive:
        with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET manifest_path = ? WHERE scan_id = ?",
                (str(manifest), deep.id),
            )
            connection.executemany(
                "UPDATE deep_scan_workers SET prompt_path = ?, artifact_dir = ?, "
                "result_manifest_path = ? WHERE id = ?",
                [
                    (row["promptPath"], row["artifactDir"], row["resultManifestPath"], row["id"])
                    for row in before["workers"]
                ],
            )
    after = deep.read("thread-deep-scan")
    assert Path(after["manifestPath"]) == archived / manifest.name
    for old, current in zip(before["workers"], after["workers"], strict=True):
        assert old["id"] == current["id"]
        for field in ("promptPath", "artifactDir", "resultManifestPath"):
            path = Path(current[field])
            assert path == archived / Path(old[field]).relative_to(deep.directory)
            assert path.exists()
    replay = deep.command(
        "fail-deep-scan", "--message", "Stopped", "--manifest-path", after["manifestPath"]
    )
    assert replay["deepScan"]["manifestPath"] == after["manifestPath"]
    worker_output = Path(
        next(row["artifactDir"] for row in after["workers"] if row["id"] == worker)
    )
    checkpoint = write_checkpoint(worker_output / "checkpoints", saved_draft(deep.id))
    assert deep.command("get-scan")["scan"]["resultsRecoveryNeeded"]
    deep.command("recover-scan-results")
    saved = json.loads((archived / "scan-manifest.json").read_text())
    assert checkpoint.relative_to(archived).as_posix() in saved["scan"]["preservedSources"]


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
        schema_version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        assert schema_version == (load_script("workbench_schema").MIGRATIONS[-1][0],)
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
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
            == schema_version
        )


def test_legacy_generation_with_active_worker_observes_grace_then_adopts(tmp_path: Path) -> None:
    deep = start_empty_target_scan(tmp_path)
    deep.dispatch_discovery_worker(
        name="legacy-active",
        succeed=False,
    )
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(), deep.id),
        )

    observed = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    assert observed["coordinatorDisposition"] == "observing"
    assert observed["deepScan"]["coordinatorGeneration"] == 1
    assert observed["deepScan"]["workers"][0]["status"] == "running"

    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat(), deep.id),
        )
    adopted = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    assert adopted["coordinatorDisposition"] == "adopted"
    assert adopted["deepScan"]["coordinatorGeneration"] == 2
    assert adopted["deepScan"]["workers"][0]["status"] == "canceled"
    assert adopted["deepScan"]["dispatchedCount"] == 0
    assert adopted["deepScan"]["discoveryStarted"] is True


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


def test_observer_and_successor_see_discovery_progress_before_first_dispatch(
    tmp_path: Path,
) -> None:
    deep = start_empty_target_scan(tmp_path)
    owner = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)["deepScan"]
    assert owner["discoveryStarted"] is False

    deep.command(
        "update-progress",
        "--phase",
        "discovery",
        "--coordinator-generation",
        str(owner["coordinatorGeneration"]),
    )
    before = deep.read("thread-deep-scan")
    observed = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    assert observed["coordinatorDisposition"] == "observing"
    assert observed["deepScan"]["updatedAt"] == before["updatedAt"]

    expire_deep_scan_coordinator(deep.state_dir, deep.id)
    adopted = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    assert adopted["coordinatorDisposition"] == "adopted"
    for run in (before, observed["deepScan"], adopted["deepScan"]):
        assert run["phase"] == "setup"
        assert run["discoveryStarted"] is True
        assert run["dispatchedCount"] == 0
        assert run["workers"] == []


@pytest.mark.cross_platform
def test_paused_discovery_resumes_after_restart_with_original_handoff_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    target.mkdir()
    write_deep_config(
        codex_home,
        "[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = 2\nmax_discovery_runs = 2\n",
    )
    thread_id, handoff_claim_token = "track-c-continuation", str(uuid.uuid4())
    saved = create_saved_workspace(state_dir, target, thread_id="workspace-thread", mode="deep")
    started = start_scan_command(
        state_dir,
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
        scan_command(state_dir, command, scan_id, *arguments)
    begun = resume_deep_scan(
        state_dir,
        scan_id,
        thread_id,
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    assert begun["deepScan"]["coordinatorGeneration"] == 1
    update_progress(
        state_dir,
        scan_id,
        "--phase",
        "discovery",
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    completed_worker = deep.dispatch_discovery_worker(
        name="track-c-completed-discovery",
    )[0]
    paused = get_scan(state_dir, scan_id)["scan"]
    assert (paused["progress"]["status"], paused["progress"]["phase"]) == ("running", "discovery")
    assert paused["progress"]["independentReviews"] == {
        "completed": 1,
        "active": 0,
        "maximum": 2,
        "consolidating": True,
    }
    assert (paused["reportAvailable"], paused["findingCount"], paused["artifacts"]) == (
        False,
        0,
        {},
    )
    manifest = scan_dir / "artifacts" / "deep_discovery" / "coordinator-manifest.json"
    assert not manifest.exists()

    expire_deep_scan_coordinator(state_dir, scan_id)
    missing_claim = resume_deep_scan(
        state_dir, scan_id, thread_id, check=False, environment=deep_environment(codex_home)
    )
    assert "owned by another continuation" in str(missing_claim["stderr"])
    resumed = resume_deep_scan(
        state_dir,
        scan_id,
        thread_id,
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )
    assert resumed["startDisposition"] == "joined"

    def claim(token: str | None, *, check: bool = True) -> dict[str, object]:
        return claim_deep_scan_coordinator(
            state_dir,
            codex_home,
            scan_id,
            thread_id=thread_id,
            handoff_claim_token=token,
            check=check,
        )

    rejected = claim(None, check=False)
    assert rejected["returncode"] != 0
    assert "another continuation" in rejected["stderr"]
    adopted = claim(handoff_claim_token)
    assert adopted["coordinatorDisposition"] == "adopted"
    assert claim(handoff_claim_token)["coordinatorDisposition"] == "observing"
    stale = update_progress(
        state_dir,
        scan_id,
        "--phase",
        "discovery",
        "--claim-token",
        handoff_claim_token,
        "--coordinator-generation",
        "1",
        check=False,
        environment=deep_environment(codex_home),
    )
    assert stale["returncode"] != 0
    assert "newer generation" in stale["stderr"]
    recovered = adopted["deepScan"]
    assert (recovered["status"], recovered["phase"], recovered["coordinatorGeneration"]) == (
        "running",
        "discovery",
        2,
    )
    assert [worker["id"] for worker in recovered["workers"]] == [completed_worker]

    replacement_worker = deep.dispatch_discovery_worker(
        name="track-c-resumed-discovery",
        coordinator_generation=2,
    )[0]
    reduced = deep.record_iteration(
        name="track-c-recovered-reducer",
        input_worker_ids=[completed_worker, replacement_worker],
        new_findings_count=0,
        coordinator_generation=2,
    )
    assert reduced["noNewStreak"] == 2
    manifest.write_text('{"status":"succeeded"}\n')
    finished = deep.finish("saturated", manifest, "--coordinator-generation", "2")["deepScan"]
    assert (finished["status"], finished["phase"], finished["manifestPath"]) == (
        "succeeded",
        "terminal",
        str(manifest),
    )
    assert len([worker for worker in finished["workers"] if worker["kind"] == "discovery"]) == 2
    parent = update_progress(
        state_dir,
        scan_id,
        "--phase",
        "validation",
        "--claim-token",
        handoff_claim_token,
        environment=deep_environment(codex_home),
    )["scan"]
    assert parent["lifecycle"] == paused["lifecycle"]
    assert parent["lifecycle"]["scanId"] == scan_id
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
    deep = start_empty_target_scan(tmp_path)
    claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    accepted = [
        deep.dispatch_discovery_worker(
            name=f"accepted-before-crash-{index}",
            coordinator_generation=2,
        )[0]
        for index in range(2)
    ]
    reducer_id = str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(deep.directory, "crashed-reducer")
    deep.seed_legacy_reducer(reducer_id, prompt, artifact_dir, accepted)
    deep.upsert_worker(
        worker_id=reducer_id,
        kind="dedup",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        coordinator_generation=2,
    )
    canonical = write_canonical_artifacts(deep.directory)["candidateLedgerPath"]
    canonical.write_text('{"candidate":"previously committed"}\n')
    if crash_point == "before_commit_without_baseline":
        canonical.unlink()
    staged = artifact_dir / "canonical" / canonical.name
    staged.parent.mkdir()
    staged.write_text('{"candidate":"newly published"}\n')
    result.write_text("{}\n")
    # An older reducer could exit between replacing the ledger and committing SQLite.
    if canonical.exists():
        canonical.rename(canonical.with_name(f".{canonical.name}.legacy.backup"))
    if copy_publication:
        canonical.write_bytes(staged.read_bytes())
    else:
        os.link(staged, canonical)
    if crash_point == "after_commit":
        seal_legacy_reducer(
            deep.state_dir,
            deep.id,
            reducer_id,
            str(result),
            1,
            environment=deep_environment(deep.codex_home),
        )

    expire_deep_scan_coordinator(deep.state_dir, deep.id)
    recovered = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)["deepScan"]
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
@pytest.mark.cross_platform
def test_expired_generation_preserves_receipts_and_recovers_abandoned_workers(
    tmp_path: Path, reducer_status: str, replace_all_inputs: bool, should_finish: bool
) -> None:
    deep = start_empty_target_scan(
        tmp_path,
        config="[deep_scan]\nworkers = 3\nsubagents = 0\nstop_after_no_new = 1\nmax_discovery_runs = 4\n",
    )
    claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    accepted = [
        deep.dispatch_discovery_worker(
            name=f"accepted-{index}",
            coordinator_generation=2,
        )[0]
        for index in range(3)
    ]
    active = deep.dispatch_discovery_worker(
        name="abandoned-discovery",
        succeed=False,
        coordinator_generation=2,
    )[0]
    reducer = str(uuid.uuid4())
    prompt, artifacts, _ = worker_paths(deep.directory, "abandoned-reducer")
    deep.seed_legacy_reducer(reducer, prompt, artifacts, accepted)
    if reducer_status == "failed":
        deep.upsert_worker(
            worker_id=reducer,
            kind="dedup",
            status="failed",
            prompt_path=prompt,
            artifact_dir=artifacts,
            error="fixture reducer failure",
            coordinator_generation=2,
        )
    expire_deep_scan_coordinator(deep.state_dir, deep.id)
    recovered = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)["deepScan"]
    by_id = {worker["id"]: worker for worker in recovered["workers"]}

    assert (recovered["status"], recovered["dispatchedCount"]) == ("running", 3)
    assert all(by_id[worker]["status"] == "succeeded" for worker in accepted)
    assert all(by_id[worker]["mergeState"] == "buffered" for worker in accepted)
    assert by_id[active]["status"] == "canceled"
    assert by_id[reducer]["status"] == ("canceled" if reducer_status == "running" else "failed")
    replacement_inputs = accepted if replace_all_inputs else accepted[:-1]
    resumed = deep.record_iteration(
        name="recovered-reducer",
        input_worker_ids=replacement_inputs,
        new_findings_count=0,
        coordinator_generation=3,
    )
    assert resumed["status"] == "running"
    manifest = deep.directory / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    result = deep.finish(
        "saturated",
        manifest,
        "--coordinator-generation",
        "3",
        *(
            item
            for worker in accepted[len(replacement_inputs) :]
            for item in ("--omitted-worker-id", worker)
        ),
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
    deep = start_empty_target_scan(tmp_path)
    coordinator_generation = None if legacy else 2
    if not legacy:
        claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    deep.dispatch_discovery_worker(
        name="accepted-before-shutdown",
        coordinator_generation=coordinator_generation,
    )
    worker_id, prompt, artifacts, _ = deep.dispatch_discovery_worker(
        name="canceled-by-shutdown",
        succeed=False,
        coordinator_generation=coordinator_generation,
    )
    deep.upsert_worker(
        worker_id=worker_id,
        status="canceled",
        prompt_path=prompt,
        artifact_dir=artifacts,
        error=None if legacy else "coordinator_shutdown: mcp_transport_closed",
        coordinator_generation=coordinator_generation,
    )
    expire_deep_scan_coordinator(deep.state_dir, deep.id)

    recovered = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)["deepScan"]
    assert recovered["dispatchedCount"] == 1
    assert next(worker for worker in recovered["workers"] if worker["id"] == worker_id)[
        "error"
    ].startswith("coordinator_shutdown_recovered:")
    expire_deep_scan_coordinator(deep.state_dir, deep.id)
    assert (
        claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)["deepScan"][
            "dispatchedCount"
        ]
        == 1
    )


@pytest.mark.parametrize("terminal,cancel", [(False, False), (True, False), (True, True)])
def test_worker_failure_diagnostic_survives_coordinator_adoption(
    tmp_path: Path, terminal: bool, cancel: bool
) -> None:
    deep = start_empty_target_scan(tmp_path)
    claim = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    generation = claim["deepScan"]["coordinatorGeneration"]
    worker, prompt, artifacts, _ = deep.dispatch_discovery_worker(
        name="discovery-1", succeed=False, coordinator_generation=generation
    )
    message = "Worker stopped by policy."
    failed = deep.upsert_worker(
        worker_id=worker,
        prompt_path=prompt,
        artifact_dir=artifacts,
        status="failed",
        error=message,
        terminal_failure=terminal,
        coordinator_generation=generation,
    )["deepScan"]
    expected = message if terminal else None
    assert (failed["status"], failed["error"]) == ("running", expected)
    assert failed["workers"][0]["error"] == message

    expire_deep_scan_coordinator(deep.state_dir, deep.id)
    adopted = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    assert adopted["coordinatorDisposition"] == "adopted"
    assert adopted["deepScan"]["error"] == expected
    generation = ("--coordinator-generation", str(adopted["deepScan"]["coordinatorGeneration"]))
    manifest = deep.directory / "finish.json"
    manifest.write_text("{}")
    if terminal:
        assert message in deep.finish("capped", manifest, *generation, check=False)["stderr"]
    if cancel:
        deep.command("cancel-scan", "--thread-id", "thread-deep-scan")
        final = deep.read("thread-deep-scan")
        assert (final["status"], final["error"]) == ("canceled", None)
    else:
        final = deep.command("fail-deep-scan", "--message", "Cleanup failed.", *generation)[
            "deepScan"
        ]
        assert final["error"] == (expected or "Cleanup failed.")
    assert final["workers"][0]["error"] == message


@pytest.mark.cross_platform
def test_expired_generation_cannot_mutate_recovered_scan(tmp_path: Path) -> None:
    deep = start_empty_target_scan(tmp_path)
    claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)
    worker, prompt, artifacts, result = deep.dispatch_discovery_worker(
        name="stale-discovery",
        succeed=False,
        coordinator_generation=2,
    )
    result.write_text("{}\n")
    expire_deep_scan_coordinator(deep.state_dir, deep.id)
    recovered = claim_deep_scan_coordinator(deep.state_dir, deep.codex_home, deep.id)["deepScan"]
    assert (recovered["status"], recovered["coordinatorGeneration"]) == ("running", 3)
    operations = (
        (
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
        ("update-progress", "--phase", "discovery"),
        ("fail-deep-scan", "--message", "stale coordinator"),
        (
            "record-deep-scan-iteration",
            "--worker-id",
            str(uuid.uuid4()),
            "--result-manifest-path",
            str(result),
            "--input-worker-id",
            worker,
            "--no-new-streak",
            "0",
            "--consecutive-errors",
            "0",
        ),
        (
            "finish-deep-scan",
            "--terminal-reason",
            "capped",
            "--manifest-path",
            str(result),
        ),
        ("claim-deep-scan-coordinator", "--thread-id", "thread-deep-scan"),
    )
    for command, *arguments in operations:
        rejected = deep.command(command, *arguments, "--coordinator-generation", "2", check=False)
        assert rejected["returncode"] != 0, command
        assert "coordinator" in str(rejected["stderr"]).lower(), command
        persisted = deep.read("thread-deep-scan")
        assert persisted == recovered, command


def test_scan_progress_projects_active_and_completed_independent_reviews(
    tmp_path: Path,
) -> None:
    deep = start_empty_target_scan(tmp_path)

    def independent_reviews() -> dict[str, int | bool]:
        context = get_scan(deep.state_dir, deep.id)
        assert get_scan(deep.state_dir, deep.id, "--progress-only") == {
            "scan": {"progress": context["scan"]["progress"]}
        }
        return context["scan"]["progress"]["independentReviews"]

    assert independent_reviews() == {
        "active": 0,
        "completed": 0,
        "maximum": 40,
        "consolidating": False,
    }

    first_prompt, first_artifacts, first_result = worker_paths(deep.directory, "discovery-1")
    second_prompt, second_artifacts, _ = worker_paths(deep.directory, "discovery-2")
    first_worker_id = str(uuid.uuid4())
    second_worker_id = str(uuid.uuid4())
    deep.upsert_worker(
        worker_id=first_worker_id,
        prompt_path=first_prompt,
        artifact_dir=first_artifacts,
    )
    deep.upsert_worker(
        worker_id=second_worker_id,
        prompt_path=second_prompt,
        artifact_dir=second_artifacts,
    )
    assert independent_reviews() == {
        "active": 2,
        "completed": 0,
        "maximum": 40,
        "consolidating": False,
    }

    first_result.write_text("{}\n")
    deep.upsert_worker(
        worker_id=first_worker_id,
        status="succeeded",
        prompt_path=first_prompt,
        artifact_dir=first_artifacts,
        result_path=first_result,
    )
    assert independent_reviews() == {
        "active": 1,
        "completed": 1,
        "maximum": 40,
        "consolidating": False,
    }

    deep.upsert_worker(
        worker_id=second_worker_id,
        status="canceled",
        prompt_path=second_prompt,
        artifact_dir=second_artifacts,
    )
    assert independent_reviews() == {
        "active": 0,
        "completed": 1,
        "maximum": 40,
        "consolidating": True,
    }
    deep.record_iteration(
        name="dedup-0001", input_worker_ids=[first_worker_id], new_findings_count=0
    )
    assert independent_reviews()["consolidating"] is False


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
        write_deep_config(codex_home, "[deep_scan]\n" + workers_configuration)
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = begin_deep_scan(
        state_dir,
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
    write_deep_config(codex_home, "[deep_scan]\nworkers = 2\n")
    isolated_config_path = tmp_path / "isolated-deep-scan.toml"
    isolated_config_path.write_text("[deep_scan]\nworkers = 7\n")
    target = tmp_path / "target"
    target.mkdir()

    deep_scan = begin_deep_scan(
        state_dir,
        "thread-deep-scan",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        environment={
            **deep_environment(codex_home),
            "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH": str(isolated_config_path),
        },
    )["deepScan"]

    assert deep_scan["config"]["workers"] == 7


def test_target_begin_is_atomic_idempotent_and_snapshots_config(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    config_path = write_deep_config(
        codex_home,
        "[deep_scan]\n"
        'workers = "auto"\n'
        "subagents = 2\n"
        "stop_after_no_new = 4\n"
        "max_discovery_runs = 12\n"
        "max_time_hours = 2.5\n",
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text("print('fixture')\n")
    scan_root = tmp_path / "scans"

    first = begin_target_scan(state_dir, codex_home, target, scan_root, service_tier="default")
    assert first["startDisposition"] == "created"
    deep_scan = first["deepScan"]
    assert deep_scan["serviceTier"] == "default"
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
    scan = get_scan(state_dir, scan_id)["scan"]
    assert scan["contract"]["target"]["targetId"] == stable_target_id(target)
    assert scan["progress"]["coverage"]["filesTotal"] == 1
    assert deep_scan["canonicalArtifacts"] is None

    config_path.write_text("[deep_scan]\nworkers = 1\nmax_time_hours = 8\n")
    second = begin_target_scan(state_dir, codex_home, target, scan_root, service_tier="priority")
    assert second["startDisposition"] == "joined"
    assert second["deepScan"]["scanId"] == deep_scan["scanId"]
    assert second["deepScan"]["config"] == deep_scan["config"]
    assert second["deepScan"]["serviceTier"] == "default"

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
    completed = scan_command(state_dir, "complete-scan", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"


def test_sdk_scan_begin_claims_its_existing_scan(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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

    premature = scan_command(
        state_dir, "complete-scan", scan_id, environment=deep_environment(codex_home), check=False
    )
    assert "orchestration must finish and persist its manifest" in str(premature["stderr"])

    def model_begin(thread: str) -> dict[str, object]:
        return begin_deep_scan(
            state_dir,
            thread,
            "--scan-id",
            scan_id,
            "--model-thread-id",
            thread,
            environment=deep_environment(codex_home),
            check=False,
        )

    assert "awaiting its owning Codex thread" in str(model_begin("other-thread")["stderr"])
    scan_command(state_dir, "set-scan-thread", scan_id, "--thread-id", "sdk-thread")
    assert "owning Codex thread" in str(model_begin("other-thread")["stderr"])
    begun = begin_deep_scan(
        state_dir,
        "sdk-thread",
        "--scan-id",
        scan_id,
        "--model-thread-id",
        "sdk-thread",
        "--service-tier",
        "priority",
        environment=deep_environment(codex_home),
    )

    assert begun["deepScan"]["serviceTier"] == "priority"
    assert begun["deepScan"]["scanId"] == scan_id
    assert begun["deepScan"]["scanDir"] == str(scan_dir)
    assert begun["deepScan"]["userContext"] == user_context
    restore_v53_schema(state_dir)
    # An existing run from a host without tier metadata keeps using its config.
    resumed = resume_deep_scan(
        state_dir,
        scan_id,
        "sdk-thread",
        "--service-tier",
        "default",
        environment=deep_environment(codex_home),
    )
    assert resumed["deepScan"]["serviceTier"] is None
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (1,)
        assert connection.execute("SELECT thread_id FROM workspaces").fetchone() == ("sdk-thread",)
        assert connection.execute(
            "SELECT pending_target_project_path FROM deep_scan_runs"
        ).fetchone() == (None,)
        assert connection.execute("SELECT deep_scan_owner_thread_id FROM scans").fetchone() == (
            "sdk-thread",
        )

    rejected = begin_deep_scan(
        state_dir,
        "another-thread",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "owning Codex thread" in str(rejected["stderr"])


def test_sdk_scan_rejects_invalid_handoff_before_claiming_ownership(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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

    rejected = begin_deep_scan(
        state_dir,
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

    begun = begin_deep_scan(
        state_dir,
        "authorized-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        environment=deep_environment(codex_home),
    )
    assert begun["deepScan"]["scanId"] == scan_id


def test_target_begin_preserves_url_user_context(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    (target / "source.py").write_text("print('fixture')\n")
    user_context = "Repository: https://github.com/example/security-review"
    begun = begin_deep_scan(
        state_dir,
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
    write_deep_config(codex_home, configuration)
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
    write_deep_config(
        codex_home,
        "[deep_scan]\n"
        + ("" if configured_hours is None else f"max_time_hours = {configured_hours}\n"),
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
    deep = start_empty_target_scan(tmp_path)
    failed_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(deep.directory, "refused-discovery")
    deep.upsert_worker(
        worker_id=failed_id,
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )

    for _ in range(2):
        result = deep.upsert_worker(
            worker_id=failed_id,
            status="canceled",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
            error="policy_refusal: request refused by cybersecurity policy",
            replaceable_failure_kind="policy_refusal",
        )["deepScan"]
        assert result["consecutiveErrors"] == 1

    failed_worker = next(worker for worker in result["workers"] if worker["id"] == failed_id)
    assert failed_worker["status"] == "canceled"
    assert "policy_refusal" in str(failed_worker["error"])

    successful_id, _, _, _ = deep.dispatch_discovery_worker(
        name="successful-replacement",
    )
    recovered = deep.read("thread-deep-scan")
    assert recovered["consecutiveErrors"] == 0
    assert recovered["dispatchedCount"] == 2
    replacement = next(worker for worker in recovered["workers"] if worker["id"] == successful_id)
    assert replacement["status"] == "succeeded"


def test_ordinary_discovery_cancellation_does_not_increment_failure_streak(
    tmp_path: Path,
) -> None:
    deep = start_empty_target_scan(tmp_path)
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(deep.directory, "user-canceled-discovery")
    deep.upsert_worker(
        worker_id=worker_id,
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )

    result = deep.upsert_worker(
        worker_id=worker_id,
        status="canceled",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )["deepScan"]

    assert result["consecutiveErrors"] == 0


def assert_rejected_config(tmp_path: Path, setting: str, value: str, requirement: str) -> None:
    codex_home = tmp_path / "codex-home"
    write_deep_config(codex_home, f"[deep_scan]\n{setting} = {value}\n")
    state_dir, target = empty_target_paths(tmp_path)
    failed = begin_deep_scan(
        state_dir,
        "thread-deep-scan",
        "--target-path",
        str(target),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert f"deep_scan.{setting} must be {requirement}" in str(failed["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (0,)


@pytest.mark.parametrize("invalid_threshold", ("0", "-1", "true", '"2"'))
def test_invalid_discovery_error_threshold_fails_before_scan_creation(
    tmp_path: Path, invalid_threshold: str
) -> None:
    assert_rejected_config(
        tmp_path, "stop_after_consecutive_errors", invalid_threshold, "a positive integer"
    )


@pytest.mark.parametrize(
    "invalid_hours", ("0", "-0.5", "true", '"2"', "nan", "inf", "96.5", "9" * 400)
)
def test_invalid_discovery_time_limit_fails_before_scan_creation(
    tmp_path: Path, invalid_hours: str
) -> None:
    assert_rejected_config(
        tmp_path, "max_time_hours", invalid_hours, "a positive finite number no greater than 96"
    )


@pytest.mark.parametrize("user_context", (None, "Review authentication only."))
def test_target_continuation_reuses_terminal_coordinator_across_threads(
    tmp_path: Path,
    user_context: str | None,
) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    (target / "fixture.py").write_text("print('stable snapshot')\n")
    scan_root = tmp_path / "scans"

    first = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-before-continuation",
        user_context=user_context,
    )
    scan_id = str(first["deepScan"]["scanId"])
    scan_dir = Path(str(first["deepScan"]["scanDir"]))
    manifest = mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
    write_deep_config(codex_home, "[deep_scan]\nsubagents = -1\n")

    continued = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-after-continuation",
        user_context=user_context,
    )
    assert continued["startDisposition"] == "joined"
    assert continued["deepScan"]["scanId"] == scan_id
    assert continued["deepScan"]["manifestPath"] == str(manifest)
    assert continued["deepScan"]["userContext"] == user_context
    assert get_scan(state_dir, scan_id)["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": 0,
        "maximum": 40,
        "consolidating": True,
    }
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
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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


def test_sealed_target_result_replays_only_the_pending_request(tmp_path: Path) -> None:
    state_dir, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    source = target / "source.py"
    source.write_text("print('source')\n")
    project = tmp_path / "selected.yaml"
    project.write_text("scan: {max_time_minutes: 30}\n")
    selected = "../selected.yaml"
    owner, context = "owner-thread", "Review authentication."

    def begin(thread: str, focus: str = context, selection: str = selected, *extra: str):
        return begin_deep_scan(
            state_dir,
            thread,
            "--target-path",
            str(target),
            "--scan-root",
            str(tmp_path / "scans"),
            "--user-context",
            focus,
            "--project-config-path",
            selection,
            *extra,
            environment=deep_environment(tmp_path / "home"),
        )

    launched = begin(
        owner,
        context,
        selected,
        "--deep-scan-project-json",
        json.dumps(
            {
                "path": str(project),
                "settings": {"maxTimeHours": 0.5},
            }
        ),
    )["deepScan"]
    scan_id, scan_dir = launched["scanId"], Path(launched["scanDir"])
    mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="source.py", coverage_mode="deep_repository"
    )
    assert scan_command(state_dir, "complete-scan", scan_id)["scan"]["reportAvailable"]
    progress = get_scan(state_dir, scan_id, "--progress-only")["scan"]["progress"]
    assert progress["independentReviews"]["consolidating"] is False
    project.unlink()

    # A probe neither reopens the selected file nor consumes the result.
    for thread in [owner, "continuation-thread"]:
        replay = begin(thread, context, selected, "--join-only")
        assert replay["startDisposition"] == "joined"
        assert replay["deepScan"]["scanId"] == scan_id
        assert replay["deepScan"]["config"]["maxTimeHours"] == 0.5
    new_target = {"newScanTarget": str(target)}
    assert begin(owner, "Other context", selected, "--join-only") == new_target
    assert begin(owner, context, "../other.yaml", "--join-only") == new_target
    source.write_text("print('changed')\n")
    assert begin(owner, context, selected, "--join-only") == new_target
    source.write_text("print('source')\n")
    assert begin(owner, context, selected, "--join-only")["deepScan"]["scanId"] == scan_id
    scan_command(state_dir, "acknowledge-deep-scan-result", scan_id)
    assert begin(owner, context, selected, "--join-only") == new_target


@pytest.mark.parametrize("already_complete", (False, True))
def test_v53_headless_target_recovers_its_unfinished_result_after_upgrade(
    tmp_path: Path, already_complete: bool
) -> None:
    state_dir, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text("print('source')\n")
    home, scan_root = tmp_path / "home", tmp_path / "scans"
    run = begin_target_scan(state_dir, home, target, scan_root)["deepScan"]
    scan_id, scan_dir = run["scanId"], Path(run["scanDir"])

    def finish() -> None:
        mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
        write_completed_contract(
            scan_dir, scan_id, target, relative_path="source.py", coverage_mode="deep_repository"
        )
        assert scan_command(state_dir, "complete-scan", scan_id)["scan"]["reportAvailable"]

    if already_complete:
        finish()
    restore_v53_schema(state_dir)
    if already_complete:
        assert (
            begin_target_scan(state_dir, home, target, scan_root)["startDisposition"] == "created"
        )
        return

    assert begin_target_scan(state_dir, home, target, scan_root)["deepScan"]["scanId"] == scan_id
    finish()
    different = begin_deep_scan(
        state_dir,
        "replacement-thread",
        "--target-path",
        str(target),
        "--project-config-path",
        "another.yaml",
        "--join-only",
    )
    assert different == {"newScanTarget": str(target)}
    replay = begin_target_scan(state_dir, home, target, scan_root, thread_id="replacement-thread")
    assert replay["startDisposition"] == "joined"
    assert replay["deepScan"]["scanId"] == scan_id
    scan_command(state_dir, "acknowledge-deep-scan-result", scan_id)
    assert begin_target_scan(state_dir, home, target, scan_root)["startDisposition"] == "created"


def test_sealed_target_prefers_its_own_pending_scan(tmp_path: Path) -> None:
    target, state_dir, home = tmp_path / "target", tmp_path / "state", tmp_path / "home"
    target.mkdir()
    (target / "source.py").write_text("print('source')\n")
    scan_root = tmp_path / "scans"
    owners = ("first-thread", "second-thread")
    runs = [
        begin_target_scan(state_dir, home, target, scan_root, thread_id=thread)["deepScan"]
        for thread in owners
    ]
    for run in runs:
        scan_id, scan_dir = run["scanId"], Path(run["scanDir"])
        mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
        write_completed_contract(
            scan_dir, scan_id, target, relative_path="source.py", coverage_mode="deep_repository"
        )
        scan_command(state_dir, "complete-scan", scan_id)
    for thread, run in zip(owners, runs, strict=True):
        replay = begin_target_scan(state_dir, home, target, scan_root, thread_id=thread)
        assert replay["deepScan"]["scanId"] == run["scanId"]


@pytest.mark.parametrize("sealed", (False, True))
def test_target_continuation_does_not_reuse_another_threads_app_scan(
    tmp_path: Path,
    sealed: bool,
) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    (target / "fixture.py").write_text("print('app scan')\n")
    scan_root = tmp_path / "scans"
    workspace_id = str(uuid.uuid4())
    create_workspace(
        state_dir,
        workspace_id,
        "--thread-id",
        "app-thread",
        "--target-path",
        str(target),
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )
    save_workspace(
        state_dir, workspace_id, str(target), ".", "deep", environment=deep_environment(codex_home)
    )
    started = start_delivered_scan(
        state_dir,
        workspace_id,
        "--scan-root",
        str(scan_root),
        environment=deep_environment(codex_home),
    )
    app_scan_id = str(started["scanId"])
    begun = begin_deep_scan(
        state_dir, "app-thread", "--scan-id", app_scan_id, environment=deep_environment(codex_home)
    )
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    mark_deep_coordinator_succeeded(state_dir, app_scan_id, scan_dir)
    if sealed:
        # A tokenless desktop run remains ineligible through the upgrade and automatic sealing.
        restore_v53_schema(state_dir)
        write_completed_contract(
            scan_dir,
            app_scan_id,
            target,
            relative_path="fixture.py",
            coverage_mode="deep_repository",
        )
        scan_command(state_dir, "complete-scan", app_scan_id)
    else:
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
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])

    rejected = scan_command(
        state_dir, "complete-scan", scan_id, environment=deep_environment(codex_home), check=False
    )
    assert "orchestration must finish and persist its manifest" in str(rejected["stderr"])
    persisted = get_deep_scan(
        state_dir, scan_id, "thread-deep-scan", environment=deep_environment(codex_home)
    )["deepScan"]
    assert persisted["status"] == "running"


def test_concurrent_target_begin_creates_one_scan(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    workspace_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    for workspace_id in workspace_ids:
        create_workspace(
            state_dir,
            workspace_id,
            "--thread-id",
            "thread-owner",
            "--target-path",
            str(target),
            "--mode",
            "deep",
            environment=deep_environment(codex_home),
        )
        save_workspace(
            state_dir,
            workspace_id,
            str(target),
            ".",
            "deep",
            environment=deep_environment(codex_home),
        )

    first = start_scan_command(
        state_dir,
        workspace_ids[0],
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    duplicate = start_scan_command(
        state_dir,
        workspace_ids[1],
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "already has an active Deep Scan" in str(duplicate["stderr"])

    cancel_scan(
        state_dir,
        str(first["results"]["scanId"]),
        "thread-owner",
        environment=deep_environment(codex_home),
    )
    second = start_scan_command(
        state_dir,
        workspace_ids[1],
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    assert second["results"]["scanId"] != first["results"]["scanId"]


def test_app_scan_begin_validates_mode_and_owner(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    workspace_id = str(uuid.uuid4())
    create_workspace(
        state_dir,
        workspace_id,
        "--thread-id",
        "thread-owner",
        "--target-path",
        str(target),
        "--mode",
        "deep",
        environment=deep_environment(codex_home),
    )
    save_workspace(
        state_dir, workspace_id, str(target), ".", "deep", environment=deep_environment(codex_home)
    )
    started = start_scan_command(
        state_dir,
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
        environment=deep_environment(codex_home),
    )
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)
    attached = attach_continuation(state_dir, scan_id, claim_token, "thread-continuation")
    assert attached["results"]["continuationThreadId"] == "thread-continuation"

    wrong_owner = begin_deep_scan(
        state_dir,
        "thread-owner",
        "--scan-id",
        scan_id,
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "owning Codex thread" in str(wrong_owner["stderr"])

    begun = begin_deep_scan(
        state_dir,
        "thread-continuation",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        environment=deep_environment(codex_home),
    )
    assert begun["startDisposition"] == "created"
    assert begun["deepScan"]["config"]["workers"] == 4
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    prompt, artifact_dir, _ = worker_paths(scan_dir, "setup-worker")
    worker_id = str(uuid.uuid4())
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    deep.upsert_worker(
        worker_id=worker_id,
        kind="setup",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=None,
    )
    setup_complete = deep.upsert_worker(
        worker_id=worker_id,
        kind="setup",
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=None,
    )
    assert setup_complete["deepScan"]["workers"][0]["status"] == "succeeded"


@pytest.mark.parametrize("handoff_action", ("release", "takeover"))
def test_stale_deep_continuation_cannot_begin_after_handoff_transfer(
    tmp_path: Path, handoff_action: str
) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    saved = create_saved_workspace(state_dir, target, thread_id="workspace-thread", mode="deep")
    started = start_scan_command(
        state_dir,
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
        scan_claim_command(state_dir, "release-handoff-delivery", scan_id, stale_token)
    scan_claim_command(
        state_dir,
        "claim-handoff-delivery",
        scan_id,
        replacement_token,
        *(("--take-over-stale",) if handoff_action == "takeover" else ()),
    )

    stale_thread = begin_deep_scan(
        state_dir,
        "stale-deep-continuation",
        "--scan-id",
        scan_id,
        "--claim-token",
        stale_token,
        environment=deep_environment(codex_home),
        check=False,
    )
    original_thread = begin_deep_scan(
        state_dir,
        "workspace-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        stale_token,
        environment=deep_environment(codex_home),
        check=False,
    )
    tokenless_original_thread = begin_deep_scan(
        state_dir,
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

    attach_continuation(state_dir, scan_id, replacement_token, "replacement-deep-continuation")
    begun = begin_deep_scan(
        state_dir,
        "replacement-deep-continuation",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement_token,
        environment=deep_environment(codex_home),
    )

    assert begun["startDisposition"] == "created"


def test_pending_app_workspace_does_not_block_target_bootstrap(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    workspace_id = str(uuid.uuid4())
    create_workspace(
        state_dir,
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


def test_one_scan_can_be_checkpointed_at_the_iteration_cap(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    write_deep_config(codex_home, "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n")
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    deep_scan = begun["deepScan"]
    assert deep_scan["config"]["maxDiscoveryRuns"] == 1
    scan_id = str(deep_scan["scanId"])
    scan_dir = Path(str(deep_scan["scanDir"]))
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    worker_id, prompt, artifact_dir, result = deep.dispatch_discovery_worker(
        name="singleton-worker",
    )
    committed = deep.record_iteration(
        name="dedup-0001",
        input_worker_ids=[worker_id],
        new_findings_count=1,
    )
    assert next(w for w in committed["workers"] if w["id"] == worker_id)["mergeState"] == "merged"
    assert committed["status"] == "running"
    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    below_threshold = deep.finish("saturated", manifest, check=False)
    assert "before reaching its no-new-findings threshold" in str(below_threshold["stderr"])
    failed_setup_id = str(uuid.uuid4())
    failed_setup_prompt, failed_setup_dir, _ = worker_paths(scan_dir, "failed-setup")
    deep.upsert_worker(
        worker_id=failed_setup_id,
        kind="setup",
        prompt_path=failed_setup_prompt,
        artifact_dir=failed_setup_dir,
    )
    deep.upsert_worker(
        worker_id=failed_setup_id,
        kind="setup",
        status="failed",
        prompt_path=failed_setup_prompt,
        artifact_dir=failed_setup_dir,
        error="Setup failed.",
    )
    rejected = deep.finish("capped", manifest, check=False)
    assert "after a worker has failed" in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("DELETE FROM deep_scan_workers WHERE id = ?", (failed_setup_id,))
    capped = deep.finish("capped", manifest)["deepScan"]
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
def test_discovery_deadline_caps_after_one_completed_scan(
    tmp_path: Path,
    configured_hours: int | float | None,
    elapsed: timedelta,
    deadline_reached: bool,
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    write_deep_config(
        codex_home,
        "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\n"
        + ("" if configured_hours is None else f"max_time_hours = {configured_hours}\n"),
    )
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    assert begun["deepScan"]["config"]["maxTimeHours"] == (
        96 if configured_hours is None else configured_hours
    )
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    worker_id, *_ = deep.dispatch_discovery_worker(
        name="deadline-discovery",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - elapsed).isoformat(), scan_id),
        )

    manifest = scan_dir / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    premature_completion = deep.finish("capped", manifest, check=False)
    if not deadline_reached:
        assert "before reaching its configured maximum" in str(premature_completion["stderr"])
        return

    assert "without canonical discovery artifacts" in str(premature_completion["stderr"])
    reduced = deep.record_iteration(
        name="deadline-reducer",
        input_worker_ids=[worker_id],
        new_findings_count=1,
    )
    assert reduced["dispatchedCount"] == 1
    assert reduced["config"]["maxDiscoveryRuns"] == 3
    ledger_path = scan_dir / "artifacts" / "02_discovery" / "candidate_ledger.jsonl"
    existing_finding = '{"title": "Finding recorded before the deadline"}\n'
    ledger_path.write_text(existing_finding)

    capped = deep.finish("capped", manifest)["deepScan"]
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
    write_deep_config(
        codex_home,
        f"[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = {configured_hours}\n",
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

    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    if cancel_discovery:
        worker_id, prompt, artifact_dir, _ = deep.dispatch_discovery_worker(
            name="deadline-canceled-discovery",
            succeed=False,
        )
        deep.upsert_worker(
            worker_id=worker_id,
            status="canceled",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
        )

    running = deep.read("thread-deep-scan")
    assert running["status"] == "running"
    assert running["canonicalArtifacts"] is None
    if configured_hours > 1e-12:
        premature = deep.finish("capped", manifest, check=False)
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

    capped = deep.finish("capped", manifest)["deepScan"]
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

    persisted = deep.read("thread-deep-scan")
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
    deep = start_empty_target_scan(
        tmp_path,
        config="[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = 0.5\n",
    )
    canonical = write_canonical_artifacts(deep.directory)
    canonical["candidateLedgerPath"].write_text(candidate_ledger)
    manifest = deep.directory / "coordinator-manifest.json"
    manifest.write_text("{}\n")
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), deep.id),
        )

    rejected = deep.finish("capped", manifest, check=False)
    assert "without a saved iteration" in str(rejected["stderr"])
    assert canonical["candidateLedgerPath"].read_text() == candidate_ledger
    running = deep.read("thread-deep-scan")
    assert running["status"] == "running"
    assert running["canonicalArtifacts"] is None


def test_capped_completion_requires_canonical_artifacts(tmp_path: Path) -> None:
    deep = start_empty_target_scan(
        tmp_path,
        config="[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n",
    )
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(deep.directory, "failed-discovery")
    deep.upsert_worker(
        worker_id=worker_id,
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )
    deep.upsert_worker(
        worker_id=worker_id,
        status="failed",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        error="Retries exhausted.",
    )
    manifest = deep.directory / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    rejected = deep.finish("capped", manifest, check=False)
    assert "without canonical discovery artifacts" in str(rejected["stderr"])


def test_capped_completion_rejects_buffered_workers_and_omissions(tmp_path: Path) -> None:
    deep = start_empty_target_scan(
        tmp_path,
        config="[deep_scan]\nworkers = 2\nstop_after_no_new = 10\nmax_discovery_runs = 3\n",
    )
    first_id, *_ = deep.dispatch_discovery_worker(
        name="first",
    )
    second_id, *_ = deep.dispatch_discovery_worker(
        name="second",
    )
    committed = deep.record_iteration(
        name="first-reducer",
        input_worker_ids=[first_id, second_id],
        new_findings_count=1,
    )
    assert committed["status"] == "running"
    buffered_id, *_ = deep.dispatch_discovery_worker(
        name="buffered-at-cap",
    )
    manifest = deep.directory / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    buffered_rejected = deep.finish("capped", manifest, check=False)
    assert "while discovery output remains buffered" in str(buffered_rejected["stderr"])

    omitted_rejected = deep.finish(
        "capped", manifest, "--omitted-worker-id", buffered_id, check=False
    )
    assert "cannot declare omitted buffered workers" in str(omitted_rejected["stderr"])


def prepare_failure_capped_deep_scan(
    tmp_path: Path,
) -> DeepScan:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    write_deep_config(codex_home, "[deep_scan]\nworkers = 2\nmax_discovery_runs = 10\n")
    target = tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    first_id, *_ = deep.dispatch_discovery_worker(
        name="first-accepted",
    )
    second_id, *_ = deep.dispatch_discovery_worker(
        name="second-accepted",
    )
    deep.record_iteration(
        name="committed-aggregate",
        input_worker_ids=[first_id, second_id],
        new_findings_count=1,
    )
    write_completed_contract(scan_dir, scan_id, target, coverage_mode="deep_repository")
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"].append(
        {"reason": "Deep Scan stopped before completion: reducer retries were exhausted"}
    )
    coverage_path.write_text(json.dumps(coverage))
    return deep


@pytest.mark.parametrize("worker_kind", ["discovery", "dedup"])
@pytest.mark.parametrize("legacy_succeeded", [False, True], ids=["finish", "legacy-parent"])
def test_capped_completion_cannot_use_review_notes_to_hide_worker_failures(
    tmp_path: Path, worker_kind: str, legacy_succeeded: bool
) -> None:
    deep = prepare_failure_capped_deep_scan(tmp_path)
    worker_id, prompt, artifact_dir, _ = deep.dispatch_discovery_worker(
        name="after-accepted-aggregate",
        succeed=worker_kind == "dedup",
    )
    if worker_kind == "dedup":
        discovery_id = worker_id
        worker_id = str(uuid.uuid4())
        prompt, artifact_dir, _ = worker_paths(deep.directory, "unrecovered-reducer")
        deep.seed_legacy_reducer(worker_id, prompt, artifact_dir, [discovery_id])
        deep.upsert_worker(
            worker_id=worker_id,
            kind="dedup",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
        )
    deep.upsert_worker(
        worker_id=worker_id,
        kind=worker_kind,
        status="failed",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        error="Worker retries exhausted.",
    )
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET max_discovery_runs = discovery_runs_dispatched WHERE scan_id = ?",
            (deep.id,),
        )
    artifacts = {
        name: (deep.directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    if legacy_succeeded:
        with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
                "terminal_reason = 'capped', manifest_path = ? WHERE scan_id = ?",
                (str(deep.directory / "scan-manifest.json"), deep.id),
            )
        rejected = deep.command("complete-scan", check=False)
    else:
        rejected = deep.finish("capped", deep.directory / "scan-manifest.json", check=False)
    assert "cannot finish after a worker has failed" in str(rejected["stderr"])
    assert {name: (deep.directory / name).read_bytes() for name in artifacts} == artifacts
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?",
            (deep.id,),
        ).fetchone() == ("succeeded" if legacy_succeeded else "running",)
    stopped = fail_scan(
        deep.state_dir,
        deep.id,
        "Worker retries exhausted.",
        environment=deep_environment(deep.codex_home),
    )["scan"]
    assert stopped["progress"]["status"] == "failed"
    assert stopped["findingCount"] == 1
    assert (
        json.loads((deep.directory / "scan-manifest.json").read_text())["scan"]["status"]
        == "failed"
    )


def test_legacy_succeeded_capped_completion_replays_without_rewriting_artifacts(
    tmp_path: Path,
) -> None:
    deep = prepare_failure_capped_deep_scan(tmp_path)
    buffered_id, *_ = deep.dispatch_discovery_worker(
        name="legacy-omitted",
    )
    manifest_path = str(deep.directory / "scan-manifest.json")
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'capped', manifest_path = ? WHERE scan_id = ?",
            (manifest_path, deep.id),
        )
    artifacts = {
        name: (deep.directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    replayed = deep.finish("capped", manifest_path, "--omitted-worker-id", buffered_id)["deepScan"]
    assert replayed["status"] == "succeeded"
    assert {name: (deep.directory / name).read_bytes() for name in artifacts} == artifacts
    rejected = deep.finish("capped", manifest_path, check=False)
    assert "terminal state is immutable" in str(rejected["stderr"])
    publication = deep.command("complete-scan", check=False)
    assert "while discovery output remains buffered" in str(publication["stderr"])
    assert {name: (deep.directory / name).read_bytes() for name in artifacts} == artifacts


def test_late_worker_rejection_supersedes_stopped_checkpoint_finding(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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

    coverage["surfaces"] = []
    coverage_path.write_text(json.dumps(coverage))

    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, "late-rejection")
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    deep.upsert_worker(
        worker_id=worker_id,
        prompt_path=prompt_path,
        artifact_dir=artifact_dir,
    )
    checkpoint = saved_draft(scan_id, findings=[provisional])
    encoded = json.dumps(checkpoint).encode()
    checkpoint_dir = artifact_dir / "checkpoints"
    checkpoint_dir.mkdir()
    (checkpoint_dir / f"{hashlib.sha256(encoded).hexdigest()}.json").write_bytes(encoded)

    stopped = fail_scan(
        state_dir,
        scan_id,
        "Stopped after the provisional checkpoint.",
        environment=deep_environment(codex_home),
    )["scan"]
    assert stopped["findingCount"] == 1

    result_path.write_text(
        json.dumps(
            saved_draft(
                scan_id,
                surfaces=[
                    {
                        "candidateId": "candidate-late-rejection",
                        "label": "Late worker disposition",
                        "disposition": "rejected",
                        "receiptRefs": [],
                    }
                ],
                complete=True,
            )
        )
    )

    recovery_needed = get_scan(state_dir, scan_id, environment=deep_environment(codex_home))["scan"]
    assert recovery_needed["resultsRecoveryNeeded"] is True
    recovered = deep.command("recover-scan-results")["scan"]
    final_findings = json.loads(findings_path.read_text())["findings"]
    final_coverage = read_review_state(state_dir, scan_dir)
    assert recovered["findingCount"] == len(final_findings) == 0
    assert any(
        item.get("candidateId") == "candidate-late-rejection"
        and item.get("disposition") == "rejected"
        for item in final_coverage["surfaces"]
    )


def test_capped_completion_does_not_discard_canceled_reducer_inputs(tmp_path: Path) -> None:
    deep = prepare_failure_capped_deep_scan(tmp_path)
    buffered_id, *_ = deep.dispatch_discovery_worker(
        name="claimed-before-failure",
    )
    reducer_id = str(uuid.uuid4())
    reducer_prompt, reducer_dir, _ = worker_paths(deep.directory, "canceled-reducer")
    deep.seed_legacy_reducer(reducer_id, reducer_prompt, reducer_dir, [buffered_id])
    deep.upsert_worker(
        worker_id=reducer_id,
        kind="dedup",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
    )
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET max_discovery_runs = discovery_runs_dispatched WHERE scan_id = ?",
            (deep.id,),
        )
    finish_args = (
        "finish-deep-scan",
        "--scan-id",
        deep.id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(deep.directory / "scan-manifest.json"),
        "--omitted-worker-id",
        buffered_id,
    )
    active_rejected = run_workbench(
        deep.state_dir, *finish_args, environment=deep_environment(deep.codex_home), check=False
    )
    assert "while workers are active" in str(active_rejected["stderr"])

    deep.upsert_worker(
        worker_id=reducer_id,
        kind="dedup",
        status="canceled",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
    )
    rejected = run_workbench(
        deep.state_dir, *finish_args, environment=deep_environment(deep.codex_home), check=False
    )
    assert "while discovery output is merging" in str(rejected["stderr"])
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?",
            (deep.id,),
        ).fetchone() == ("running",)
        assert connection.execute(
            "SELECT merge_state FROM deep_scan_workers WHERE id = ?",
            (buffered_id,),
        ).fetchone() == ("merging",)

    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'capped', manifest_path = ? WHERE scan_id = ?",
            (str(deep.directory / "scan-manifest.json"), deep.id),
        )
    publication = deep.command("complete-scan", check=False)
    assert "while discovery output is merging" in str(publication["stderr"])


@pytest.mark.parametrize(
    "stop_note",
    [
        "Deep Scan stopped before completion: reducer retries were exhausted",
        "Some source files were not reviewed.",
        None,
    ],
)
def test_capped_completion_uses_configured_limits_independently_of_review_notes(
    tmp_path: Path, stop_note: str | None
) -> None:
    deep = prepare_failure_capped_deep_scan(tmp_path)
    coverage_path = deep.directory / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [{"reason": stop_note}] if stop_note else []
    coverage_path.write_text(json.dumps(coverage))
    rejected = deep.finish("capped", deep.directory / "scan-manifest.json", check=False)
    assert "cannot finish capped before reaching its configured maximum" in str(rejected["stderr"])
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, manifest_path FROM deep_scan_runs WHERE scan_id = ?",
            (deep.id,),
        ).fetchone() == ("running", None)


def test_saturated_completion_rejects_merging_workers(tmp_path: Path) -> None:
    deep = start_empty_target_scan(
        tmp_path,
        config="[deep_scan]\nworkers = 2\nstop_after_no_new = 2\nmax_discovery_runs = 3\n",
    )
    first_id, *_ = deep.dispatch_discovery_worker(
        name="first",
    )
    second_id, *_ = deep.dispatch_discovery_worker(
        name="second",
    )
    committed = deep.record_iteration(
        name="first-reducer",
        input_worker_ids=[first_id, second_id],
        new_findings_count=0,
    )
    assert committed["noNewStreak"] == 2
    merging_id, *_ = deep.dispatch_discovery_worker(
        name="merging-input",
    )
    reducer_id = str(uuid.uuid4())
    reducer_prompt, reducer_dir, _ = worker_paths(deep.directory, "abandoned-reducer")
    deep.seed_legacy_reducer(reducer_id, reducer_prompt, reducer_dir, [merging_id])
    deep.upsert_worker(
        worker_id=reducer_id,
        kind="dedup",
        status="canceled",
        prompt_path=reducer_prompt,
        artifact_dir=reducer_dir,
        attempt=None,
    )
    manifest = deep.directory / "coordinator-manifest.json"
    manifest.write_text("{}\n")

    rejected = deep.finish("saturated", manifest, check=False)
    assert "while discovery output is merging" in str(rejected["stderr"])


def test_running_worker_updates_preserve_identity_and_dispatch_count(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(scan_dir, "running-worker")
    update = {
        "worker_id": worker_id,
        "prompt_path": prompt,
        "artifact_dir": artifact_dir,
    }

    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    initial = deep.upsert_worker(**update)["deepScan"]
    initial_worker = next(worker for worker in initial["workers"] if worker["id"] == worker_id)
    repeated = deep.upsert_worker(**update)["deepScan"]
    repeated_worker = next(worker for worker in repeated["workers"] if worker["id"] == worker_id)

    assert initial["dispatchedCount"] == repeated["dispatchedCount"] == 1
    assert repeated_worker["startedAt"] == initial_worker["startedAt"]
    assert repeated_worker["attempt"] == initial_worker["attempt"] == 1
    assert repeated_worker["sdkThreadId"] is None

    started = deep.upsert_worker(**update, thread_id="thread-worker")["deepScan"]
    replayed = deep.upsert_worker(**update, thread_id="thread-worker")["deepScan"]
    started_worker = next(worker for worker in started["workers"] if worker["id"] == worker_id)
    replayed_worker = next(worker for worker in replayed["workers"] if worker["id"] == worker_id)

    assert started["dispatchedCount"] == replayed["dispatchedCount"] == 1
    assert replayed_worker["sdkThreadId"] == started_worker["sdkThreadId"] == "thread-worker"
    assert replayed_worker["startedAt"] == initial_worker["startedAt"]


def test_terminal_worker_updates_are_exact_idempotent_replays(tmp_path: Path) -> None:
    deep = start_empty_target_scan(tmp_path)
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(deep.directory, "terminal-worker")
    deep.upsert_worker(
        worker_id=worker_id,
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )
    result.write_text("{}\n")
    accepted = deep.upsert_worker(
        worker_id=worker_id,
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=result,
    )["deepScan"]
    accepted_worker = next(worker for worker in accepted["workers"] if worker["id"] == worker_id)
    replayed = deep.upsert_worker(
        worker_id=worker_id,
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=result,
    )["deepScan"]
    replayed_worker = next(worker for worker in replayed["workers"] if worker["id"] == worker_id)
    assert replayed_worker == accepted_worker

    replacement_result = artifact_dir / "replacement-result.json"
    replacement_result.write_text("{}\n")
    replacement = deep.upsert_worker(
        worker_id=worker_id,
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=replacement_result,
        check=False,
    )
    assert "terminal state is immutable" in str(replacement["stderr"])
    later_attempt = deep.upsert_worker(
        worker_id=worker_id,
        status="succeeded",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        result_path=result,
        attempt=2,
        check=False,
    )
    assert later_attempt["returncode"] != 0
    assert "terminal state is immutable" in str(later_attempt["stderr"])


def test_get_deep_scan_does_not_invent_compact_artifacts_for_legacy_success(
    tmp_path: Path,
) -> None:
    deep = start_empty_target_scan(tmp_path)
    committed = deep.record_iteration(
        name="legacy-reducer",
        input_worker_ids=[
            deep.dispatch_discovery_worker(
                name=f"legacy-discovery-{index}",
            )[0]
            for index in range(2)
        ],
        new_findings_count=0,
    )
    compact_files = write_canonical_artifacts(deep.directory)
    assert committed["canonicalArtifacts"] is None
    for path in compact_files.values():
        path.unlink()

    legacy_dir = deep.directory / "artifacts" / "legacy-discovery"
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
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            f"SELECT {legacy_columns} FROM deep_scan_runs WHERE scan_id = ?",
            (deep.id,),
        ).fetchone() == (None,) * len(legacy_files)
        connection.execute(
            f"""
            UPDATE deep_scan_runs
            SET {legacy_updates}, status = 'succeeded', phase = 'terminal',
                terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at
            WHERE scan_id = ?
            """,
            (*map(str, legacy_files.values()), str(manifest), deep.id),
        )

    persisted = deep.read("thread-deep-scan")
    assert persisted["status"] == "succeeded"
    assert persisted["manifestPath"] == str(manifest)
    assert persisted["canonicalArtifacts"] is None
    assert all(path.exists() for path in legacy_files.values())
    assert not any(path.exists() for path in compact_files.values())


def test_finish_preserves_legacy_succeeded_without_manifest_compatibility(
    tmp_path: Path,
) -> None:
    deep = start_empty_target_scan(tmp_path)
    with sqlite3.connect(deep.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated',
                completed_at = updated_at
            WHERE scan_id = ?
            """,
            (deep.id,),
        )
    manifest = deep.directory / "legacy-coordinator-manifest.json"
    manifest.write_text("{}\n")

    finished = deep.finish("saturated", manifest)
    assert finished["deepScan"]["manifestPath"] == str(manifest)
    replayed = deep.finish("saturated", manifest)
    assert replayed == finished

    replacement = deep.directory / "replacement-manifest.json"
    replacement.write_text("{}\n")
    mismatched = deep.finish("saturated", replacement, check=False)
    assert "terminal state is immutable" in str(mismatched["stderr"])


def test_cancel_scan_cancels_coordinator_and_active_workers(tmp_path: Path) -> None:
    deep = start_empty_target_scan(tmp_path)
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(deep.directory, "worker")
    deep.upsert_worker(
        worker_id=worker_id,
        prompt_path=prompt,
        artifact_dir=artifact_dir,
    )

    cancel_scan(
        deep.state_dir, deep.id, "thread-deep-scan", environment=deep_environment(deep.codex_home)
    )
    canceled = deep.read("thread-deep-scan")
    assert canceled["status"] == "canceled"
    assert canceled["phase"] == "terminal"
    assert canceled["cancelRequested"] is True
    assert canceled["workers"][0]["status"] == "canceled"


def test_failure_manifest_is_confined_persisted_and_exactly_replayable(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")
    scan_id = str(begun["deepScan"]["scanId"])
    scan_dir = Path(str(begun["deepScan"]["scanDir"]))
    deep = DeepScan(state_dir, codex_home, scan_id, scan_dir)
    worker_id, *_ = deep.dispatch_discovery_worker(
        name="active-worker",
        succeed=False,
    )
    outside_manifest = tmp_path / "outside-failure-manifest.json"
    outside_manifest.write_text("{}\n")
    confined = deep.command(
        "fail-deep-scan",
        "--message",
        "Coordinator failed.",
        "--manifest-path",
        str(outside_manifest),
        check=False,
    )
    assert "inside the scan directory" in str(confined["stderr"])

    manifest = scan_dir / "failure-manifest.json"
    manifest.write_text("{}\n")
    failed = deep.command(
        "fail-deep-scan", "--message", "Coordinator failed.", "--manifest-path", str(manifest)
    )
    deep_scan = failed["deepScan"]
    assert deep_scan["status"] == "failed"
    assert deep_scan["manifestPath"] == str(manifest)
    assert (
        next(worker for worker in deep_scan["workers"] if worker["id"] == worker_id)["status"]
        == "canceled"
    )
    parent = get_scan(state_dir, scan_id, environment=deep_environment(codex_home))["scan"]
    assert parent["progress"]["status"] == "failed"
    assert parent["failureMessage"] == "Coordinator failed."

    replayed = deep.command(
        "fail-deep-scan", "--message", "Coordinator failed.", "--manifest-path", str(manifest)
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
        mismatched = deep.command("fail-deep-scan", *extra_args, check=False)
        assert "terminal failure state is immutable" in str(mismatched["stderr"])

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET failure_message = 'Diverged parent failure.' WHERE id = ?",
            (scan_id,),
        )
    incoherent_parent = deep.command(
        "fail-deep-scan",
        "--message",
        "Coordinator failed.",
        "--manifest-path",
        str(manifest),
        check=False,
    )
    assert "parent failure must exactly match" in str(incoherent_parent["stderr"])


@pytest.mark.parametrize("with_manifest", [False, True])
def test_cancel_scan_overrides_succeeded_deep_run_during_parent_tail(
    tmp_path: Path, with_manifest: bool
) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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

    cancel_scan(state_dir, scan_id, "thread-deep-scan", environment=deep_environment(codex_home))
    canceled = get_deep_scan(
        state_dir, scan_id, "thread-deep-scan", environment=deep_environment(codex_home)
    )["deepScan"]
    assert canceled["status"] == "canceled"
    assert canceled["cancelRequested"] is True
    assert canceled["manifestPath"] == (str(manifest) if with_manifest else None)
    scan = get_scan(state_dir, scan_id, environment=deep_environment(codex_home))["scan"]
    assert scan["progress"]["status"] == "canceled"
    assert scan["progress"]["independentReviews"]["consolidating"] is False


@pytest.mark.parametrize("deep_status", ["failed", "interrupted"])
def test_saturated_run_without_manifest_can_be_marked_failed_or_interrupted(
    tmp_path: Path, deep_status: str
) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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
    terminal = scan_command(
        state_dir,
        "fail-deep-scan",
        scan_id,
        "--deep-status",
        deep_status,
        "--message",
        message,
        environment=deep_environment(codex_home),
    )["deepScan"]
    assert terminal["status"] == deep_status
    assert terminal["error"] == message
    scan = get_scan(state_dir, scan_id, environment=deep_environment(codex_home))["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["progress"]["independentReviews"]["consolidating"] is False
    assert scan["failureMessage"] == terminal["error"]
    assert scan["logCompletedAt"] == terminal["completedAt"]


def test_succeeded_run_with_manifest_cannot_be_marked_interrupted(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    state_dir, target = empty_target_paths(tmp_path)
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
        rejected = scan_command(
            state_dir,
            "fail-deep-scan",
            scan_id,
            "--deep-status",
            deep_status,
            "--message",
            "Must remain successful.",
            environment=deep_environment(codex_home),
            check=False,
        )
        assert "Only a running Deep Scan" in str(rejected["stderr"])
    persisted = get_deep_scan(
        state_dir, scan_id, "thread-deep-scan", environment=deep_environment(codex_home)
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
    completed_cancel = cancel_scan(
        state_dir,
        scan_id,
        "thread-deep-scan",
        environment=deep_environment(codex_home),
        check=False,
    )
    assert "Only a running scan can be canceled" in str(completed_cancel["stderr"])
    unchanged = get_deep_scan(
        state_dir, scan_id, "thread-deep-scan", environment=deep_environment(codex_home)
    )["deepScan"]
    assert unchanged["status"] == "succeeded"
    assert unchanged["manifestPath"] == str(manifest)


def test_invalid_user_configuration_fails_before_scan_creation(tmp_path: Path) -> None:
    assert_rejected_config(tmp_path, "subagents", "-1", "a non-negative integer")
