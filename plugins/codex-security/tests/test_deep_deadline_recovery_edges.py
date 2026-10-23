from __future__ import annotations

import copy
import json
import os
import signal
import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_workbench_standard_deep_results import (
    deep_scan_fixture,
    standard_finding,
    write_saved_parent,
)
from workbench_test_support import (
    finish_deep_scan,
    get_scan,
    run_workbench,
    saved_draft,
    worker_paths,
    write_checkpoint,
)


def deadline_fixture(
    tmp_path: Path, checkpoint_kind: str = "empty", *, include_paths: list[str] | None = None
) -> SimpleNamespace:
    state, home, target, directory, scan_id = deep_scan_fixture(
        tmp_path, include_paths=include_paths
    )
    environment = {"CODEX_HOME": str(home)}
    claimed = run_workbench(
        state,
        "claim-deep-scan-coordinator",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment=environment,
    )
    generation = str(claimed["deepScan"]["coordinatorGeneration"])
    finding = standard_finding(tmp_path, scan_id, target)
    if checkpoint_kind != "empty":
        prompt, output, _ = worker_paths(directory, "deadline-worker")
        args = (
            "upsert-deep-scan-worker",
            "--scan-id",
            scan_id,
            "--worker-id",
            str(uuid.uuid4()),
            "--kind",
            "discovery",
            "--prompt-path",
            str(prompt),
            "--artifact-dir",
            str(output),
            "--attempt",
            "1",
            "--coordinator-generation",
            generation,
        )
        run_workbench(state, *args, "--status", "running", environment=environment)
        draft = saved_draft(
            scan_id if checkpoint_kind == "valid" else str(uuid.uuid4()),
            findings=[finding],
            deferred=[{"id": "review", "reason": "Synthetic review remains."}],
        )
        draft["threatModel"] = {"summary": "Synthetic worker model."}
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
        run_workbench(state, *args, "--status", "canceled", environment=environment)
    artifacts = directory / "artifacts/02_discovery"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "in_scope_files.txt").write_text("app.py\n")
    (artifacts / "candidate_ledger.jsonl").write_text("")
    manifest = directory / "artifacts/deep_discovery/coordinator-manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text('{"status":"succeeded","discoveryCount":0}\n')
    database = state / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00Z' WHERE scan_id = ?",
            (scan_id,),
        )
    return SimpleNamespace(
        state=state,
        directory=directory,
        scan_id=scan_id,
        generation=generation,
        environment=environment,
        manifest=manifest,
        database=database,
        finding=finding,
    )


def finish(scan: SimpleNamespace, *, canonical: bool = False, check: bool = True):
    return finish_deep_scan(
        scan.state,
        scan.scan_id,
        "capped",
        str(scan.directory / "scan-manifest.json" if canonical else scan.manifest),
        "--coordinator-generation",
        scan.generation,
        environment=scan.environment,
        check=check,
    )


def canonical_parent(scan: SimpleNamespace, draft: dict, timestamp: int = 100):
    write_saved_parent(scan.directory, draft, timestamp)
    path = scan.directory / "scan-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["scan"]["id"] = scan.scan_id
    if "threatModel" in draft:
        manifest["scan"]["threatModel"] = draft["threatModel"]
    path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.directory / name, ns=(timestamp, timestamp))


def assert_retained_finding(scan: SimpleNamespace):
    findings = json.loads((scan.directory / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["ruleId"] == scan.finding["ruleId"]
    assert findings[0]["identity"] == scan.finding["identity"]
    assert findings[0]["severity"] == scan.finding["severity"]


@pytest.mark.parametrize("canonical", [False, True])
@pytest.mark.parametrize("same_identity", [False, True])
@pytest.mark.parametrize(
    ("field", "value"), [("severity", None), ("code_evidence", []), ("root_cause", None)]
)
def test_deadline_recovers_partial_worker_findings_before_completion(
    tmp_path, canonical, same_identity, field, value
):
    scan = deadline_fixture(tmp_path, "valid")
    if canonical:
        canonical_parent(scan, saved_draft(scan.scan_id))
    head = next(scan.directory.glob("artifacts/**/checkpoint-head.json"))
    selected = head.parent / "checkpoints" / json.loads(head.read_text())["checkpoint"]
    draft = json.loads(selected.read_text())
    partial = copy.deepcopy(scan.finding)
    if not same_identity:
        partial["ruleId"] = "synthetic.partial"
        partial["identity"] = {"anchor": "partial"}
        partial["provenance"]["candidateId"] = "partial-candidate"
    if field == "severity":
        partial.pop(field)
    else:
        partial[field] = value
        partial["severity"]["level"] = "critical"
    draft["findings"].append(partial)
    checkpoint = write_checkpoint(head.parent / "checkpoints", draft)
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    source_bytes = {path: path.read_bytes() for path in (selected, checkpoint, head)}

    terminal = finish(scan, canonical=canonical)["deepScan"]
    assert terminal["status"] == "succeeded"
    assert terminal["terminalReason"] == "capped"
    assert_retained_finding(scan)
    warnings = get_scan(scan.state, scan.scan_id)["scan"]["warnings"]
    assert any(field in warning for warning in warnings)
    coverage = json.loads((scan.directory / "coverage.json").read_text())
    assert any(field in row["reason"] for row in coverage["deferred"])
    assert all(path.read_bytes() == contents for path, contents in source_bytes.items())
    run_workbench(
        scan.state,
        "complete-scan",
        "--scan-id",
        scan.scan_id,
        environment=scan.environment,
    )
    manifest = json.loads((scan.directory / "scan-manifest.json").read_text())
    assert manifest["scan"]["status"] == "completed"
    assert "sealedAt" in manifest["scan"]
    assert_retained_finding(scan)


@pytest.mark.parametrize("checkpoint_kind", ["empty", "valid", "invalid"])
def test_coordinator_deadline_preserves_only_usable_worker_checkpoints(
    tmp_path: Path, checkpoint_kind: str
):
    scan = deadline_fixture(tmp_path, checkpoint_kind)
    terminal = finish(scan)["deepScan"]
    assert terminal["status"] == "succeeded"
    assert terminal["terminalReason"] == "capped"
    findings = scan.directory / "findings.json"
    if checkpoint_kind == "valid":
        assert_retained_finding(scan)
        coverage = json.loads((scan.directory / "coverage.json").read_text())
        assert "completeness" not in coverage
        assert any(row.get("id", "").endswith("/review") for row in coverage["deferred"])
        manifest = json.loads((scan.directory / "scan-manifest.json").read_text())
        assert "sealedAt" not in manifest["scan"]
    else:
        assert not findings.exists()
    warnings = get_scan(scan.state, scan.scan_id)["scan"]["warnings"]
    assert bool(warnings) is (checkpoint_kind == "invalid")


@pytest.mark.parametrize("valid_parent", [False, True])
def test_deadline_validates_optional_parent_model_before_worker_fallback(
    tmp_path: Path, valid_parent: bool
):
    scan = deadline_fixture(tmp_path, "valid")
    draft = saved_draft(scan.scan_id)
    draft["threatModel"] = {"summary": "Synthetic parent model." if valid_parent else 7}
    canonical_parent(scan, draft)
    assert finish(scan, canonical=True)["deepScan"]["status"] == "succeeded"
    assert_retained_finding(scan)
    model = json.loads((scan.directory / "scan-manifest.json").read_text())["scan"]["threatModel"]
    assert model["summary"] == (
        "Synthetic parent model." if valid_parent else "Synthetic worker model."
    )
    assert bool(get_scan(scan.state, scan.scan_id)["scan"]["warnings"]) is not valid_parent


def test_deadline_recovery_does_not_snapshot_untouched_optional_sarif(tmp_path):
    scan = deadline_fixture(tmp_path, "valid")
    external = tmp_path / "optional-export.sarif"
    external.write_text("Unchanged optional export.\n")
    sarif = scan.directory / "exports/results.sarif"
    sarif.parent.mkdir()
    try:
        sarif.symlink_to(external)
    except OSError:
        if os.name == "nt":
            pytest.skip("Symbolic links are unavailable")
        raise
    assert finish(scan)["deepScan"]["status"] == "succeeded"
    assert_retained_finding(scan)
    completion = run_workbench(
        scan.state,
        "complete-scan",
        "--scan-id",
        scan.scan_id,
        check=False,
        environment=scan.environment,
    )
    assert completion["returncode"] == 0
    assert "automatic SARIF export failed" in completion["stderr"]
    assert sarif.is_symlink()
    assert os.readlink(sarif) == str(external)
    assert external.read_text() == "Unchanged optional export.\n"


@pytest.mark.parametrize("include_paths", [None, ["app.py"], ["unrelated.py"]])
@pytest.mark.parametrize("source", ["parent", "worker", "both"])
def test_deadline_recovery_applies_requested_scope_to_parent_and_worker_findings(
    tmp_path, include_paths, source
):
    scan = deadline_fixture(
        tmp_path, "empty" if source == "parent" else "valid", include_paths=include_paths
    )
    if source != "worker":
        draft = saved_draft(scan.scan_id, findings=[scan.finding])
        draft["coverage"].update(
            mode="scoped_path" if include_paths is not None else "deep_repository",
            inventoryStrategy="scoped_path" if include_paths is not None else "repository",
            includePaths=include_paths or ["."],
            excludePaths=[],
        )
        canonical_parent(scan, draft)
    workers = scan.directory / "artifacts/deep_discovery"
    original = {p: p.read_bytes() for p in workers.rglob("*.json") if p != scan.manifest}
    assert finish(scan)["deepScan"]["status"] == "succeeded"
    findings = json.loads((scan.directory / "findings.json").read_text())["findings"]
    head = json.loads((scan.directory / "checkpoint-head.json").read_text())["checkpoint"]
    checkpoint = json.loads((scan.directory / "checkpoints" / head).read_text())
    expected = 0 if include_paths == ["unrelated.py"] else 1
    assert len(findings) == len(checkpoint["findings"]) == expected
    assert all(path.read_bytes() == contents for path, contents in original.items())


@pytest.mark.parametrize("with_worker", [False, True])
@pytest.mark.parametrize("inventory", [None, "", "invalid_strategy", 7, "scoped_path"])
def test_scoped_deadline_recovers_interrupted_inventory_before_final_publication(
    tmp_path: Path, with_worker: bool, inventory: object
):
    scan = deadline_fixture(tmp_path, "valid" if with_worker else "empty", include_paths=["app.py"])
    draft = saved_draft(scan.scan_id)
    draft["coverage"].update(mode="scoped_path", includePaths=["app.py"], excludePaths=[])
    if inventory is None:
        draft["coverage"].pop("inventoryStrategy", None)
    else:
        draft["coverage"]["inventoryStrategy"] = inventory
    canonical_parent(scan, draft)
    worker_sources = {
        path: path.read_bytes() for path in scan.directory.glob("artifacts/**/checkpoints/*.json")
    }

    terminal = finish(scan)["deepScan"]
    assert terminal["status"] == "succeeded"
    assert terminal["terminalReason"] == "capped"
    assert terminal["completionSequence"] == 0
    recovered = json.loads((scan.directory / "coverage.json").read_text())
    assert recovered["mode"] == "scoped_path"
    assert recovered["inventoryStrategy"] == "scoped_path"
    assert recovered["includePaths"] == ["app.py"]
    assert "sealedAt" not in json.loads((scan.directory / "scan-manifest.json").read_text())["scan"]

    completed = run_workbench(
        scan.state,
        "complete-scan",
        "--scan-id",
        scan.scan_id,
        environment=scan.environment,
    )["scan"]
    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == int(with_worker)
    if with_worker:
        assert_retained_finding(scan)
    manifest = json.loads((scan.directory / "scan-manifest.json").read_text())
    assert manifest["scan"]["status"] == "completed"
    assert "sealedAt" in manifest["scan"]
    assert all(path.read_bytes() == contents for path, contents in worker_sources.items())


@pytest.mark.parametrize("failure", ["publication", "commit"])
def test_failed_deadline_without_parent_head_restores_all_recovery_evidence(
    tmp_path: Path, failure: str
):
    scan = deadline_fixture(tmp_path, "valid")
    canonical_parent(scan, saved_draft(scan.scan_id, findings=[scan.finding]))
    assert not (scan.directory / "checkpoint-head.json").exists()
    unrelated = scan.directory / "artifacts/unrelated-worker/checkpoints/keep.json"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("Synthetic unrelated evidence.\n")
    before = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan.directory.rglob("*")
        if path.is_file()
    }
    trigger = (
        "BEFORE UPDATE OF completion_warnings_json ON scans"
        if failure == "publication"
        else "BEFORE UPDATE OF status ON deep_scan_runs WHEN NEW.status = 'succeeded'"
    )
    with sqlite3.connect(scan.database) as connection:
        connection.execute(
            f"CREATE TRIGGER reject_deadline {trigger} "
            "BEGIN SELECT RAISE(ABORT, 'synthetic deadline failure'); END"
        )
    failed = finish(scan, canonical=True, check=False)
    assert failed["returncode"] != 0
    assert "synthetic deadline failure" in failed["stderr"]
    after = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan.directory.rglob("*")
        if path.is_file()
    }
    assert after == before
    with sqlite3.connect(scan.database) as connection:
        connection.execute("DROP TRIGGER reject_deadline")
    assert finish(scan, canonical=True)["deepScan"]["status"] == "succeeded"
    assert_retained_finding(scan)


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize(
    "checkpoint_kind,staged,existing_target",
    [("valid", False, True), ("valid", True, True), ("empty", True, False), ("empty", True, True)],
)
def test_deadline_interrupt_preserves_only_committed_publication(
    tmp_path, monkeypatch, workbench_api, committed, checkpoint_kind, staged, existing_target
):
    scan = deadline_fixture(tmp_path, checkpoint_kind)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(scan.state))
    monkeypatch.setenv("CODEX_HOME", scan.environment["CODEX_HOME"])
    deep_scan = workbench_api["deep_scan"]
    deep_scan.configure(SimpleNamespace(**workbench_api))
    original_manifest = scan.manifest.read_bytes()
    if not existing_target:
        scan.manifest.unlink()
    staged_path = scan.manifest.with_name("staged-manifest.json") if staged else None
    if staged_path:
        staged_path.write_bytes(original_manifest + b"\n")
    arguments = SimpleNamespace(
        omitted_worker_id=[],
        manifest_path=str(scan.manifest),
        staged_manifest_path=str(staged_path) if staged_path else None,
        terminal_reason="capped",
        coordinator_generation=int(scan.generation),
        scan_id=scan.scan_id,
    )
    with sqlite3.connect(scan.database) as connection:
        connection.row_factory = sqlite3.Row

        class InterruptedCommit:
            def __getattr__(self, name):
                return getattr(connection, name)

            def commit(self):
                # Both success and SQLite auto-rollback end the transaction.
                (connection.commit if committed else connection.rollback)()
                signal.raise_signal(signal.SIGINT)

        with pytest.raises(KeyboardInterrupt):
            deep_scan.finish_deep_scan(InterruptedCommit(), arguments)
        status = connection.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()[0]
    assert status == ("succeeded" if committed else "running")
    published = committed and checkpoint_kind == "valid"
    assert (scan.directory / "findings.json").exists() is published
    assert (scan.directory / "checkpoint-head.json").exists() is published
    if committed or existing_target:
        assert scan.manifest.read_bytes() == original_manifest + (
            b"\n" if staged and committed else b""
        )
    else:
        assert not scan.manifest.exists()
    if staged_path:
        assert staged_path.exists() is not committed
    with sqlite3.connect(scan.database) as connection:
        connection.row_factory = sqlite3.Row
        assert (
            deep_scan.finish_deep_scan(connection, arguments)["deepScan"]["status"] == "succeeded"
        )
    assert scan.manifest.read_bytes() == original_manifest + (b"\n" if staged else b"")
    if checkpoint_kind == "valid":
        assert_retained_finding(scan)


@pytest.mark.parametrize("write_kind", ["parent-checkpoint", "head-observation", "source-order"])
def test_mid_merge_failure_removes_only_created_recovery_evidence(
    tmp_path: Path, monkeypatch, workbench_api, write_kind: str
):
    from workbench import retained_coverage, saved_sources

    scan = deadline_fixture(tmp_path, "valid")
    canonical_parent(scan, saved_draft(scan.scan_id, findings=[scan.finding]))
    before = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan.directory.rglob("*")
        if path.is_file()
    }
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes
    unrelated = scan.directory / "artifacts/unrelated-worker/checkpoints/keep.json"
    failed = False

    def fail_during_merge(directory, relative, contents):
        nonlocal failed
        write(directory, relative, contents)
        matches = {
            "parent-checkpoint": relative.startswith("checkpoints/"),
            "head-observation": "/checkpoint-heads/" in "/" + relative,
            "source-order": relative.startswith("source-order/"),
        }
        if not failed and matches[write_kind]:
            failed = True
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text("Unrelated worker evidence.\n")
            raise RuntimeError("Synthetic merge failure")

    monkeypatch.setattr(saved, "write_scan_local_bytes", fail_during_merge)
    monkeypatch.setattr(saved_sources, "write_scan_local_bytes", fail_during_merge)
    monkeypatch.setattr(retained_coverage, "write_scan_local_bytes", fail_during_merge)
    with sqlite3.connect(scan.database) as connection:
        connection.row_factory = sqlite3.Row
        record = workbench_api["require_scan"](connection, scan.scan_id)
        with pytest.raises(RuntimeError, match="Synthetic merge failure"):
            saved.preserve_deep_deadline_draft(SimpleNamespace(**workbench_api), connection, record)
    after = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan.directory.rglob("*")
        if path.is_file() and path != unrelated
    }
    assert after == before
    assert unrelated.read_text() == "Unrelated worker evidence.\n"


@pytest.mark.parametrize("snapshot_failure", [False, True])
def test_failed_head_snapshot_does_not_interrupt_publication_rollback(
    tmp_path, monkeypatch, workbench_api, snapshot_failure
):
    from workbench import retained_coverage, saved_sources

    scan = deadline_fixture(tmp_path, "valid")
    canonical_parent(scan, saved_draft(scan.scan_id, findings=[scan.finding]))
    before = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan.directory.rglob("*")
        if path.is_file()
    }
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes
    failed_snapshots = []

    def fail_before_snapshot_directory(directory, relative, contents):
        if snapshot_failure and "/checkpoint-heads/" in relative:
            assert not (directory / relative).parent.exists()
            failed_snapshots.append(relative)
            raise OSError("Synthetic head snapshot write failure")
        write(directory, relative, contents)

    monkeypatch.setattr(saved, "write_scan_local_bytes", fail_before_snapshot_directory)
    monkeypatch.setattr(saved_sources, "write_scan_local_bytes", fail_before_snapshot_directory)
    monkeypatch.setattr(retained_coverage, "write_scan_local_bytes", fail_before_snapshot_directory)
    with sqlite3.connect(scan.database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TRIGGER reject_deadline BEFORE UPDATE OF completion_warnings_json ON scans "
            "BEGIN SELECT RAISE(ABORT, 'synthetic publication failure'); END"
        )
        record = workbench_api["require_scan"](connection, scan.scan_id)
        with pytest.raises(sqlite3.IntegrityError, match="synthetic publication failure"):
            saved.preserve_deep_deadline_draft(SimpleNamespace(**workbench_api), connection, record)
    assert bool(failed_snapshots) is snapshot_failure
    assert all(not (scan.directory / path).exists() for path in failed_snapshots)
    after = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan.directory.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.parametrize("directory", ["checkpoints", "checkpoint-heads", "source-order"])
def test_deadline_rollback_preserves_preexisting_dangling_recovery_entry(
    tmp_path: Path, workbench_api, directory: str
):
    scan = deadline_fixture(tmp_path)
    canonical_parent(scan, saved_draft(scan.scan_id, findings=[scan.finding]))
    saved = workbench_api["saved_results"]
    original = {
        path.relative_to(scan.directory): (path.read_bytes(), path.stat())
        for path in scan.directory.rglob("*")
        if path.is_file()
    }
    with sqlite3.connect(scan.database) as connection:
        connection.row_factory = sqlite3.Row
        record = workbench_api["require_scan"](connection, scan.scan_id)
        binding = workbench_api["workbench_completion_binding"](record, workbench_api["now"]())
        saved.merge_saved_results(
            scan.directory, scan.scan_id, binding, [], [], stopped=True, reason="Synthetic stop."
        )
        created = {
            path.relative_to(scan.directory)
            for path in scan.directory.rglob("*")
            if path.is_file() and path.relative_to(scan.directory) not in original
        }
        relative = next(path for path in created if path.parent == Path(directory))
        for path in created:
            (scan.directory / path).unlink()
        for path, (contents, metadata) in original.items():
            target = scan.directory / path
            target.write_bytes(contents)
            os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        target = scan.directory / relative
        try:
            target.symlink_to("missing-target")
        except OSError:
            if os.name == "nt":
                pytest.skip("Symbolic links are unavailable")
            raise
        with pytest.raises(saved.ContractError) as rejected:
            saved.write_scan_local_bytes(scan.directory, relative.as_posix(), b"{}")
        try:
            publication = saved.preserve_deep_deadline_draft(
                SimpleNamespace(**workbench_api), connection, record
            )
        except saved.ContractError as error:
            assert str(error) == str(rejected.value)
        else:
            warnings = json.loads(
                connection.execute(
                    "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan.scan_id,)
                ).fetchone()[0]
            )
            assert any(str(rejected.value) in warning for warning in warnings)
            connection.rollback()
            saved._restore_published_outputs(*publication)
    assert target.is_symlink()
    assert os.readlink(target) == "missing-target"
    assert {
        path.relative_to(scan.directory)
        for path in scan.directory.rglob("*")
        if path.is_file() or path.is_symlink()
    } == {*original, relative}
