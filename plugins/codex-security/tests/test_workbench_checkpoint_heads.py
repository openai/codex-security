from __future__ import annotations

import copy
import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import accepted_standard_worker, deep_scan_fixture
from workbench_test_support import (
    replay_saved_results,
    run_workbench,
    saved_discovery_worker,
    write_checkpoint,
    write_completed_contract,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finalize_scan_contract
import workbench_saved_results as saved


def drafts(scan_id: str) -> tuple[dict, dict]:
    pending = {
        "scanId": scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [{"id": "review", "reason": "Review remains."}],
        },
    }
    closed = copy.deepcopy(pending)
    closed["coverage"].update(
        completeness="complete",
        deferred=[],
        resolvedDeferred=[{"id": "review", "reason": "Review completed."}],
    )
    return pending, closed


def select(output: Path, checkpoint: Path, observed: int) -> None:
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(observed, observed))


@pytest.mark.parametrize("selection", ["same", "reopened"])
@pytest.mark.parametrize("has_result", [False, True])
def test_late_head_changes_require_explicit_recovery(
    tmp_path: Path, selection: str, has_result: bool
) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    pending, closed = drafts(scan_id)
    reopened = write_checkpoint(result.parent / "checkpoints", pending)
    completed = write_checkpoint(result.parent / "checkpoints", closed)
    os.utime(reopened, ns=(100, 100))
    os.utime(completed, ns=(150, 150))
    if has_result:
        result.write_text(json.dumps(pending))
        os.utime(result, ns=(100, 100))
    else:
        result.unlink()
    select(result.parent, completed, 200)
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        "--deep-status",
        "failed",
        environment=environment,
    )
    manifest_path = scan_dir / "scan-manifest.json"
    first_manifest = manifest_path.read_bytes()
    frozen = json.loads(first_manifest)["scan"]["preservedSources"]
    assert any("/checkpoint-heads/" in path for path in frozen)
    assert not any(path.endswith("checkpoint-head.json") for path in frozen)
    assert not any(
        row["id"] == "review"
        for row in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
    )
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )

    select(result.parent, reopened if selection == "reopened" else completed, 300)
    snapshots = list((result.parent / "checkpoint-heads").iterdir())
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    assert list((result.parent / "checkpoint-heads").iterdir()) == snapshots
    run_workbench(
        state,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment=environment,
    )
    assert manifest_path.read_bytes() == first_manifest
    recovered = run_workbench(
        state, "recover-scan-results", "--scan-id", scan_id, environment=environment
    )
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert any(row["id"] == "review" for row in coverage["deferred"]) is (selection == "reopened")
    published = manifest_path.read_bytes()
    run_workbench(state, "recover-scan-results", "--scan-id", scan_id, environment=environment)
    assert manifest_path.read_bytes() == published
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )


@pytest.fixture
def checkpoint_scan():
    scan_id = "head-observation"
    pending, closed = drafts(scan_id)
    binding = {
        "status": "interrupted",
        "allowedTargetKinds": ["git_revision"],
        "target": {"kind": "git_revision", "repository": "synthetic", "revision": "head"},
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "deep_repository",
    }
    return scan_id, pending, closed, binding


@pytest.mark.parametrize("layout", ["parent", "worker", "archived"])
def test_frozen_observations_survive_live_head_changes(
    tmp_path: Path, checkpoint_scan, layout: str
) -> None:
    scan_id, pending, closed, binding = checkpoint_scan
    output = tmp_path if layout == "parent" else tmp_path / "worker" / "output"
    output.mkdir(parents=True, exist_ok=True)
    directory = output if layout != "archived" else output.parent / "attempts" / "attempt-01"
    completed = write_checkpoint(directory / "checkpoints", closed)
    reopened = write_checkpoint(directory / "checkpoints", pending)
    os.utime(completed, ns=(100, 100))
    os.utime(reopened, ns=(200, 200))
    select(directory, completed, 300)
    workers = (
        []
        if layout == "parent"
        else [saved_discovery_worker(output, "worker", 1 if layout == "worker" else 2)]
    )

    def merge(frozen=None):
        return saved.merge_saved_results(
            tmp_path,
            scan_id,
            binding,
            workers,
            [],
            stopped=True,
            reason="interrupted",
            frozen_source_digests=frozen,
        )

    first = merge()
    frozen = first[0]["scan"]["preservedSources"]
    snapshot = next(path for path in frozen if "/checkpoint-heads/" in f"/{path}")
    assert pending["coverage"]["deferred"][0] not in first[2]["deferred"]
    for checkpoint in (reopened, completed):
        select(directory, checkpoint, 400)
        replay = merge(frozen)
        assert replay[2] == first[2]
    legacy = {
        path: digest
        for path, digest in frozen.items()
        if path != snapshot and not path.startswith("source-order/")
    }
    assert pending["coverage"]["deferred"][0] in merge(legacy)[2]["deferred"]
    observation = json.loads((tmp_path / snapshot).read_text())
    observation["observedAtNs"] = str(int(observation["observedAtNs"]) + 1)
    (tmp_path / snapshot).write_text(json.dumps(observation))
    with pytest.raises(
        saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
    ):
        merge(frozen)


def test_multiple_parent_observations_keep_latest_selection_and_pending_ties(
    tmp_path: Path, checkpoint_scan
) -> None:
    scan_id, pending, closed, binding = checkpoint_scan
    completed = write_checkpoint(tmp_path / "checkpoints", closed)
    reopened = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(completed, ns=(100, 100))
    os.utime(reopened, ns=(200, 200))
    for checkpoint, observed in ((completed, 300), (reopened, 400), (completed, 500)):
        select(tmp_path, checkpoint, observed)
        saved._capture_saved_source(tmp_path, "checkpoint-head.json", scan_id)
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    assert pending["coverage"]["deferred"][0] not in first[2]["deferred"]
    select(tmp_path, reopened, 500)
    tied = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    assert pending["coverage"]["deferred"][0] in tied[2]["deferred"]
    replay = replay_saved_results(saved, tied, tmp_path, scan_id, binding, [], stopped=True)
    assert replay[2] == tied[2]


@pytest.mark.parametrize("observed", [100, 1_700_000_000_000_000_001])
def test_head_snapshot_reads_content_and_time_from_one_descriptor(
    tmp_path: Path, checkpoint_scan, monkeypatch: pytest.MonkeyPatch, observed: int
) -> None:
    scan_id, pending, closed, _ = checkpoint_scan
    completed = write_checkpoint(tmp_path / "checkpoints", closed)
    reopened = write_checkpoint(tmp_path / "checkpoints", pending)
    select(tmp_path, completed, observed)
    replacement = tmp_path / "replacement.json"
    replacement.write_text(json.dumps({"checkpoint": reopened.name}))
    os.utime(replacement, ns=(observed + 1, observed + 1))
    open_file = finalize_scan_contract.open_scan_local_file_descriptor

    def replace_after_open(scan_dir, relative, context):
        descriptor = open_file(scan_dir, relative, context)
        if relative == "checkpoint-head.json":
            replacement.replace(scan_dir / relative)
        return descriptor

    monkeypatch.setattr(
        finalize_scan_contract, "open_scan_local_file_descriptor", replace_after_open
    )
    captured = saved._capture_saved_source(tmp_path, "checkpoint-head.json", scan_id)
    snapshot = next(path for path in captured if path.startswith("checkpoint-heads/"))
    assert json.loads((tmp_path / snapshot).read_text()) == {
        "checkpoint": completed.name,
        "observedAtNs": str(observed),
    }


def test_legacy_live_head_sources_keep_their_recorded_digest(
    tmp_path: Path, checkpoint_scan
) -> None:
    scan_id, pending, closed, binding = checkpoint_scan
    checkpoint = write_checkpoint(tmp_path / "checkpoints", closed)
    os.utime(checkpoint, ns=(100, 100))
    select(tmp_path, checkpoint, 200)
    paths = [checkpoint.relative_to(tmp_path).as_posix(), "checkpoint-head.json"]
    frozen = {path: saved._read_saved_result(tmp_path, path, scan_id)[1] for path in paths}
    first = saved.merge_saved_results(
        tmp_path,
        scan_id,
        binding,
        [],
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=frozen,
    )
    assert first is not None
    assert pending["coverage"]["deferred"][0] not in first[2]["deferred"]
    assert first[0]["scan"]["preservedSources"] == frozen
    select(tmp_path, checkpoint, 300)
    with pytest.raises(
        saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
    ):
        saved.merge_saved_results(
            tmp_path,
            scan_id,
            binding,
            [],
            [],
            stopped=True,
            reason="interrupted",
            frozen_source_digests=frozen,
        )


@pytest.mark.parametrize("evidence", ["deferred", "reported"])
@pytest.mark.parametrize("head_time", [200, 50, 100], ids=["newer", "older", "tied"])
def test_parent_head_selection_matches_frozen_publication_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: str, head_time: int
) -> None:
    from test_workbench_saved_source_order import call_workbench

    state, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    worker = json.loads(worker_result.read_text())
    child_work = {"id": "child-review", "reason": "Worker review remains."}
    worker["coverage"].update(completeness="partial", deferred=[child_work])
    worker_result.write_text(json.dumps(worker))

    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(
        contract, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    initial = {
        key: json.loads((contract / filename).read_text())
        for key, filename in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    if evidence == "reported":
        finalize_scan_contract._populate_unsealed_finding_identities(
            initial["manifest"], initial["findings"]
        )
        initial["findings"]["findings"][0]["provenance"]["workerId"] = worker_id
    initial["manifest"] = {
        "scan": {
            "target": initial["manifest"]["scan"]["target"],
            "scope": initial["manifest"]["scan"]["scope"],
            "complete": False,
        }
    }
    parent_work = {"id": "parent-review", "reason": "Parent review remains."}
    initial["coverage"].update(surfaces=[], deferred=[])
    if evidence == "deferred":
        initial["findings"]["findings"] = []
        initial["coverage"].update(completeness="partial", deferred=[parent_work])
    else:
        initial["findings"]["findings"][0]["extensions"] = {"candidateId": "candidate-review"}
        initial["coverage"]["surfaces"] = [
            {
                "id": "candidate-surface",
                "label": "Candidate review",
                "disposition": "reported",
                "candidateId": "candidate-review",
                "receiptRefs": [],
            }
        ]
    staged_dir = scan_dir / "drafts"
    staged_dir.mkdir()
    staged = staged_dir / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(initial))
    write_args = ("write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    run_workbench(state, *write_args, environment={"CODEX_HOME": str(codex_home)})
    original_head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    original_checkpoint = scan_dir / "checkpoints" / original_head["checkpoint"]
    os.utime(original_checkpoint, ns=(100, 100))
    os.utime(scan_dir / "coverage.json", ns=(100, 100))
    select(scan_dir, original_checkpoint, 100)

    terminal = copy.deepcopy(initial)
    terminal["manifest"]["scan"].pop("complete")
    terminal["findings"]["findings"] = []
    terminal["coverage"].update(completeness="complete", deferred=[], surfaces=[])
    if evidence == "reported":
        terminal["coverage"]["surfaces"] = [
            {
                "id": "candidate-surface",
                "label": "Candidate review",
                "disposition": "rejected",
                "candidateId": "candidate-review",
                "receiptRefs": [],
                "finding": initial["findings"]["findings"][0],
            }
        ]
    staged.write_text(json.dumps(terminal))
    write_bytes = saved.write_scan_local_bytes

    def fail_canonical_write(root, relative, contents):
        if relative == "findings.json":
            raise OSError("injected canonical write failure")
        write_bytes(root, relative, contents)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", fail_canonical_write)
        with pytest.raises(OSError, match="injected canonical write failure"):
            call_workbench(patch, state, codex_home, *write_args)
    terminal_head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    terminal_checkpoint = scan_dir / "checkpoints" / terminal_head["checkpoint"]
    assert terminal_checkpoint != original_checkpoint
    os.utime(terminal_checkpoint, ns=(head_time, head_time))
    select(scan_dir, terminal_checkpoint, head_time)
    assert json.loads((scan_dir / "coverage.json").read_text()) == initial["coverage"]

    first = []

    def fail_publication(prepared):
        first.append(copy.deepcopy((prepared[3], prepared[4])))
        raise OSError("injected stopped publication failure")

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        call_workbench(patch, state, codex_home, "cancel-scan", "--scan-id", scan_id)
    assert len(first) == 1
    run_workbench(
        state,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )
    replay = (
        json.loads((scan_dir / "findings.json").read_text()),
        json.loads((scan_dir / "coverage.json").read_text()),
    )
    for findings, coverage in (first[0], replay):
        assert child_work in coverage["deferred"]
        if evidence == "deferred":
            assert (parent_work in coverage["deferred"]) is (head_time <= 100)
        else:
            assert len(findings["findings"]) == (1 if head_time <= 100 else 0)
            if head_time <= 100:
                for field in (
                    "findingId",
                    "occurrenceId",
                    "fingerprints",
                    "identity",
                    "provenance",
                ):
                    assert (
                        findings["findings"][0][field] == initial["findings"]["findings"][0][field]
                    )
            if head_time > 100:
                assert any(
                    row.get("disposition") == "rejected"
                    and row.get("candidateId") == "candidate-review"
                    for row in coverage["surfaces"]
                )
    assert replay[0]["findings"] == first[0][0]["findings"]
    assert replay[1] == first[0][1]
