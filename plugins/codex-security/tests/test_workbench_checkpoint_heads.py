from __future__ import annotations

import copy
import json
import os
import sys
import uuid
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    deep_scan_fixture,
    write_saved_parent,
)
from workbench_test_support import (
    create_saved_workspace,
    fail_deep_scan,
    get_scan,
    preserve_scan_results,
    replay_saved_results,
    run_workbench,
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    scan_command,
    start_delivered_scan,
    write_checkpoint,
    write_completed_contract,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finalize_scan_contract
import workbench_saved_results as saved


def drafts(scan_id: str) -> tuple[dict, dict]:
    pending = saved_draft(
        scan_id, deferred=[{"id": "review", "reason": "Review remains."}], complete=True
    )
    closed = saved_draft(
        scan_id,
        closures=[{"id": "review", "reason": "Review completed."}],
        complete=True,
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
    fail_deep_scan(state, codex_home, scan_id, deep_status="failed")
    manifest_path = scan_dir / "scan-manifest.json"
    first_manifest = manifest_path.read_bytes()
    frozen = json.loads(first_manifest)["scan"]["preservedSources"]
    assert any("/checkpoint-heads/" in path for path in frozen)
    assert not any(path.endswith("checkpoint-head.json") for path in frozen)
    assert not any(
        row["id"] == "review"
        for row in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
    )
    assert get_scan(state, scan_id)["scan"]["resultsRecoveryNeeded"] is False

    select(result.parent, reopened if selection == "reopened" else completed, 300)
    snapshots = list((result.parent / "checkpoint-heads").iterdir())
    assert get_scan(state, scan_id)["scan"]["resultsRecoveryNeeded"] is True
    assert list((result.parent / "checkpoint-heads").iterdir()) == snapshots
    preserve_scan_results(state, scan_id, "standard-worker-thread", environment=environment)
    assert manifest_path.read_bytes() == first_manifest
    recovered = scan_command(state, "recover-scan-results", scan_id, environment=environment)
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert any(row["id"] == "review" for row in coverage["deferred"]) is (selection == "reopened")
    published = manifest_path.read_bytes()
    scan_command(state, "recover-scan-results", scan_id, environment=environment)
    assert manifest_path.read_bytes() == published
    assert get_scan(state, scan_id)["scan"]["resultsRecoveryNeeded"] is False


@pytest.fixture
def checkpoint_scan():
    scan_id = "head-observation"
    pending, closed = drafts(scan_id)
    binding = saved_binding("deep_repository", repository="synthetic")
    return scan_id, pending, closed, binding


@pytest.mark.parametrize("has_receipts", [False, True])
@pytest.mark.parametrize("has_canonical", [False, True])
def test_recovery_keeps_one_surface_with_optional_empty_receipts(
    tmp_path: Path, checkpoint_scan, has_receipts: bool, has_canonical: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    surface = {"id": "api", "label": "API", "disposition": "needs_follow_up"}
    draft = saved_draft(scan_id, surfaces=[surface])
    if has_receipts:
        surface["receiptRefs"] = []
    checkpoint = write_checkpoint(tmp_path / "checkpoints", draft)
    select(tmp_path, checkpoint, 50)
    original = checkpoint.read_bytes()
    if has_canonical:
        canonical = copy.deepcopy(draft)
        canonical["coverage"]["surfaces"][0]["receiptRefs"] = []
        write_saved_parent(tmp_path, canonical, 100)
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, [], stopped=True)
    for result in (first, replay):
        assert result[2]["surfaces"] == [{**surface, "receiptRefs": []}]
    assert checkpoint.read_bytes() == original


@pytest.mark.parametrize("mode", ["repository", "branch_diff"])
@pytest.mark.parametrize("retain_pending", [False, True])
def test_file_authored_resolution_can_leave_manifest_unchanged(
    tmp_path: Path, checkpoint_scan, mode: str, retain_pending: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    binding["coverageMode"] = mode
    if mode == "branch_diff":
        binding["allowedTargetKinds"] = ["git_diff"]
        binding["target"] = {
            "kind": "git_diff",
            "repository": "synthetic",
            "baseRevision": "a" * 40,
            "headRevision": "b" * 40,
        }
    independent = {"id": "file-review", "reason": "Independent review remains."}
    pending = saved_draft(
        scan_id, deferred=[{"candidateId": "candidate", "reason": "Review remains."}, independent]
    )
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(200, 200))
    completed = saved_draft(
        scan_id,
        deferred=[independent] if retain_pending else [],
        surfaces=[
            {
                "id": "candidate",
                "candidateId": "candidate",
                "label": "Candidate",
                "disposition": "rejected",
            }
        ],
        complete=True,
    )
    write_saved_parent(tmp_path, completed, 300)
    manifest = tmp_path / "scan-manifest.json"
    os.utime(manifest, ns=(100, 100))
    warnings = []
    result = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], warnings, stopped=False, reason=""
    )
    # Headless file-authored documents replace their older checkpoint coverage.
    assert result[2]["completeness"] == ("partial" if retain_pending else "complete")
    assert result[2]["deferred"] == ([independent] if retain_pending else [])
    assert warnings == []


@pytest.mark.parametrize("update", [{"reason": ""}, {"paths": [1]}, {"reason": "Updated review."}])
def test_file_authored_deferred_update_preserves_valid_checkpoint_evidence(
    tmp_path: Path, checkpoint_scan, update: dict
) -> None:
    scan_id, pending, _, binding = checkpoint_scan
    pending["complete"] = False
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    current = copy.deepcopy(pending)
    current["coverage"]["deferred"][0].update(update)
    write_saved_parent(tmp_path, current, 200)
    warnings: list[str] = []
    _, _, coverage = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], warnings, stopped=True, reason="interrupted"
    )
    finalize_scan_contract._recover_unsealed_coverage(
        coverage,
        Path(saved.__file__).resolve().parent.parent / "schemas",
        tmp_path,
        warnings,
        [],
    )
    expected = "Updated review." if update.get("reason") == "Updated review." else "Review remains."
    assert [row["reason"] for row in coverage["deferred"] if row["id"] != "scan-stopped"] == [
        expected
    ]


@pytest.mark.parametrize("layout", ["parent", "worker", "archived"])
@pytest.mark.parametrize("anonymous", [False, True])
@pytest.mark.parametrize("linked", [False, True])
def test_recovery_preserves_accepted_generic_surface_closeout(
    tmp_path: Path, checkpoint_scan, layout: str, anonymous: bool, linked: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    output = tmp_path if layout == "parent" else tmp_path / "worker" / "output"
    output.mkdir(parents=True, exist_ok=True)
    directory = output if layout != "archived" else output.parent / "attempts" / "attempt-01"
    directory.mkdir(parents=True, exist_ok=True)
    surface = {"id": "api", "label": "API", "disposition": "needs_follow_up"}
    task = {"id": "review", "reason": "Review remains."}
    if linked:
        task["surfaceIds"] = ["api"]
    pending = saved_draft(scan_id, surfaces=[surface], deferred=[task])
    legacy = copy.deepcopy(pending)
    if anonymous:
        legacy["coverage"]["surfaces"][0].pop("id")
    checkpoint = write_checkpoint(directory / "checkpoints", legacy)
    os.utime(checkpoint, ns=(100, 100))
    # A prior writer returned the assigned surface ID, but its checkpoint was anonymous.
    published = copy.deepcopy(pending)
    published["coverage"]["surfaces"][0]["receiptRefs"] = []
    if layout == "parent":
        write_saved_parent(directory, published, 150)
    else:
        result = directory / "result.json"
        result.write_text(json.dumps(published))
        os.utime(result, ns=(150, 150))
    closed_surface = {**surface, "disposition": "no_issue_found", "receiptRefs": []}
    closed = saved_draft(
        scan_id,
        surfaces=[closed_surface],
        closures=[{"id": "review", "reason": "Review completed."}],
        complete=True,
    )
    completed = write_checkpoint(directory / "checkpoints", closed)
    os.utime(completed, ns=(200, 200))
    select(directory, completed, 300)
    workers = (
        []
        if layout == "parent"
        else [saved_discovery_worker(output, "worker", 1 if layout == "worker" else 2)]
    )
    original = {path: path.read_bytes() for path in directory.rglob("*.json")}
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    for result in (
        first,
        replay_saved_results(saved, first, tmp_path, scan_id, binding, workers),
    ):
        assert result[2]["surfaces"] == [closed_surface]
        assert result[2]["deferred"] == [{"id": "scan-stopped", "reason": "interrupted"}]
    assert all(path.read_bytes() == contents for path, contents in original.items())


@pytest.mark.parametrize("identity", [["review"], {"name": "review"}])
@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("closure", [False, True])
def test_malformed_parent_deferred_id_reaches_existing_recovery_diagnostics(
    tmp_path: Path, checkpoint_scan, identity, complete: bool, closure: bool
) -> None:
    scan_id, pending, _, binding = checkpoint_scan
    pending["complete"] = False
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    current = copy.deepcopy(pending)
    current["complete"] = complete
    current["coverage"]["deferred"][0]["id"] = identity
    if closure:
        current["coverage"]["resolvedDeferred"] = [
            {"id": "finished", "reason": "Independent review completed."}
        ]
    write_saved_parent(tmp_path, current, 200)
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding)
    for result in (first, replay):
        coverage = result[2]
        assert current["coverage"]["deferred"][0] in coverage["deferred"]
        warnings: list[str] = []
        finalize_scan_contract._recover_unsealed_coverage(
            coverage,
            Path(saved.__file__).resolve().parent.parent / "schemas",
            tmp_path,
            warnings,
            [],
        )
        assert warnings
        assert all(isinstance(row["id"], str) for row in coverage["deferred"])
        assert coverage["completeness"] == "partial"


@pytest.mark.parametrize("layout", ["parent", "worker", "archived"])
@pytest.mark.parametrize("rewrite", [False, True])
def test_recovery_preserves_distinct_legacy_tasks_with_one_id(
    tmp_path: Path, checkpoint_scan, layout: str, rewrite: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    output = tmp_path if layout == "parent" else tmp_path / "worker" / "output"
    output.mkdir(parents=True, exist_ok=True)
    directory = output if layout != "archived" else output.parent / "attempts" / "attempt-01"
    directory.mkdir(parents=True, exist_ok=True)
    tasks = [
        {"id": "review", "reason": "Review API.", "paths": ["api.py"]},
        {"id": "review", "reason": "Review worker.", "paths": ["worker.py"]},
    ]
    legacy = saved_draft(scan_id, deferred=tasks)
    checkpoint = write_checkpoint(directory / "checkpoints", legacy)
    os.utime(checkpoint, ns=(100, 100))
    if rewrite:
        rewritten = saved_draft(scan_id, deferred=tasks[:1])
        checkpoint = write_checkpoint(directory / "checkpoints", rewritten)
        os.utime(checkpoint, ns=(150, 150))
    closed = saved_draft(
        scan_id, closures=[{"id": "review", "reason": "API reviewed."}], complete=True
    )
    completed = write_checkpoint(directory / "checkpoints", closed)
    os.utime(completed, ns=(200, 200))
    select(directory, completed, 300)
    workers = (
        []
        if layout == "parent"
        else [saved_discovery_worker(output, "worker", 1 if layout == "worker" else 2)]
    )
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding, workers)
    assert first[2] == replay[2] == repeated[2]
    for result in (first, replay, repeated):
        retained = [row for row in result[2]["deferred"] if row["id"] != "scan-stopped"]
        assert [{key: value for key, value in row.items() if key != "id"} for row in retained] == [
            {key: value for key, value in row.items() if key != "id"} for row in tasks
        ]
        assert not result[2].get("resolvedDeferred")


@pytest.mark.parametrize("layout", ["parent", "worker", "archived"])
@pytest.mark.parametrize("alias", ["id", "candidateId"])
@pytest.mark.parametrize("outcome", ["reported", "rejected"])
@pytest.mark.parametrize("rewrite", [False, True])
def test_recovery_keeps_generic_work_that_collides_with_candidate_aliases(
    tmp_path: Path, checkpoint_scan, layout: str, alias: str, outcome: str, rewrite: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    binding["target"]["targetId"] = "synthetic-target"
    output = tmp_path if layout == "parent" else tmp_path / "worker" / "output"
    directory = output if layout != "archived" else output.parent / "attempts" / "attempt-01"
    directory.mkdir(parents=True, exist_ok=True)
    candidate = {
        "id": "candidate-task",
        "candidateId": "candidate-a",
        "reason": "Review candidate.",
    }
    generic = {
        "id": candidate[alias],
        "reason": "Independent generic review remains.",
        "surfaceIds": ["generic-surface"],
    }
    other = {"id": "other-review", "reason": "Other review.", "surfaceIds": ["generic-surface"]}
    surface = {"id": "generic-surface", "label": "Generic review", "disposition": "needs_follow_up"}
    pending = saved_draft(scan_id, deferred=[generic, candidate, other], surfaces=[surface])
    checkpoint = write_checkpoint(directory / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    if rewrite:
        checkpoint = write_checkpoint(
            directory / "checkpoints", saved_draft(scan_id, deferred=[candidate, other])
        )
        os.utime(checkpoint, ns=(150, 150))
    terminal = saved_draft(
        scan_id,
        closures=[{"id": "other-review", "reason": "Other review completed."}],
        surfaces=[
            {**surface, "disposition": "no_issue_found"},
            {
                "id": "candidate-surface",
                "candidateId": "candidate-a",
                "label": "Candidate",
                "disposition": outcome,
            },
        ],
        complete=True,
    )
    if outcome == "reported":
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, scan_id, tmp_path, relative_path="app.py")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding.setdefault("extensions", {})["candidateId"] = "candidate-a"
        terminal["findings"] = [finding]
    completed = write_checkpoint(directory / "checkpoints", terminal)
    os.utime(completed, ns=(200, 200))
    select(directory, completed, 300)
    workers = (
        []
        if layout == "parent"
        else [saved_discovery_worker(output, "worker", 1 if layout == "worker" else 2)]
    )
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding, workers)
    assert first[2] == replay[2] == repeated[2]
    for result in (first, replay, repeated):
        assert [row for row in result[2]["deferred"] if row["id"] != "scan-stopped"] == [generic]
        assert (
            sum(
                row["label"] == "Generic review" and row["disposition"] == "needs_follow_up"
                for row in result[2]["surfaces"]
            )
            == 1
        )
        assert any(
            row.get("candidateId") == "candidate-a" and row["disposition"] == outcome
            for row in result[2]["surfaces"]
        )
        assert bool(result[1]["findings"]) is (outcome == "reported")


@pytest.mark.parametrize("complete", [False, True, None])
def test_selected_parent_replaces_stale_completion_marker(
    tmp_path: Path, checkpoint_scan, complete: bool | None
) -> None:
    scan_id, _, closed, binding = checkpoint_scan
    closed["complete"] = complete is False
    write_saved_parent(tmp_path, closed, 100)
    tasks = [{"id": "review", "reason": "Review reopened."}] if complete is False else []
    progress = saved_draft(scan_id, deferred=tasks, complete=complete)
    if complete is None:
        progress.pop("complete")
    checkpoint = write_checkpoint(tmp_path / "checkpoints", progress)
    os.utime(checkpoint, ns=(200, 200))
    select(tmp_path, checkpoint, 300)
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding)
    for result in (first, replay):
        assert result[0]["scan"].get("complete", True) is (complete is not False)
        for task in tasks:
            assert task in result[2]["deferred"]


@pytest.mark.parametrize("layout", ["worker", "result", "archived"])
@pytest.mark.parametrize("evidence", ["missing", "malformed", "unrelated", "valid"])
def test_reported_surface_requires_its_own_valid_candidate_finding(
    tmp_path: Path, checkpoint_scan, layout: str, evidence: str
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    binding["target"]["targetId"] = "synthetic-target"
    output = tmp_path / "worker" / "output"
    directory = output if layout != "archived" else output.parent / "attempts" / "attempt-01"
    directory.mkdir(parents=True, exist_ok=True)
    pending = saved_draft(
        scan_id,
        deferred=[{"id": "candidate-task", "candidateId": "candidate-a", "reason": "Review."}],
    )
    checkpoint = write_checkpoint(directory / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    terminal = saved_draft(
        scan_id,
        complete=True,
        surfaces=[
            {
                "id": "candidate-surface",
                "candidateId": "candidate-a",
                "label": "Candidate review",
                "disposition": "reported",
            }
        ],
    )
    if layout == "result":
        terminal["coverage"]["deferred"] = copy.deepcopy(pending["coverage"]["deferred"])
    if evidence != "missing":
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, scan_id, tmp_path, relative_path="app.py")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding.setdefault("extensions", {})["candidateId"] = (
            "candidate-b" if evidence == "unrelated" else "candidate-a"
        )
        if evidence == "malformed":
            finding.pop("title")
        terminal["findings"] = [finding]
    completed = write_checkpoint(directory / "checkpoints", terminal)
    os.utime(completed, ns=(200, 200))
    if layout == "result":
        result = directory / "result.json"
        result.write_text(json.dumps(terminal))
        os.utime(result, ns=(300, 300))
    else:
        select(directory, completed, 300)
    workers = [saved_discovery_worker(output, "worker", 2 if layout == "archived" else 1)]
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding, workers)
    for result in (first, replay, repeated):
        pending_candidates = {
            row.get("candidateId") for row in result[2]["deferred"] if isinstance(row, dict)
        }
        assert ("candidate-a" in pending_candidates) is (evidence != "valid")
        assert bool(result[1]["findings"]) is (evidence != "missing")


@pytest.mark.parametrize("command", ["complete-scan", "prepare-scan-completion"])
@pytest.mark.parametrize("complete", [False, True, None])
def test_completion_checks_selected_parent_checkpoint(
    tmp_path: Path, command: str, complete: bool | None
) -> None:
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n")
    workspace = create_saved_workspace(state, target)
    started = start_delivered_scan(
        state,
        "--workspace-id",
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(started["results"]["scanDir"])
    write_completed_contract(scan_dir, scan_id, target, relative_path="app.py")
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = complete is False
    manifest["scan"]["scope"]["limitations"] = ["The dependency boundary is still unreviewed."]
    manifest["scan"]["threatModel"] = {"summary": "The earlier threat model."}
    manifest_path.write_text(json.dumps(manifest))
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    if complete is False:
        coverage.update(
            completeness="partial", deferred=[{"id": "review", "reason": "Review reopened."}]
        )
    draft = {
        "scanId": scan_id,
        "findings": json.loads((scan_dir / "findings.json").read_text())["findings"],
        "coverage": coverage,
        "scope": {"limitations": ["Only static analysis was performed."]},
        "threatModel": {"summary": "The reviewed threat model."},
    }
    if complete is not None:
        draft["complete"] = complete
    artifacts = ("scan-manifest.json", "findings.json", "coverage.json")
    for name in artifacts:
        os.utime(scan_dir / name, ns=(100, 100))
    checkpoint = write_checkpoint(scan_dir / "checkpoints", draft)
    os.utime(checkpoint, ns=(200, 200))
    select(scan_dir, checkpoint, 300)
    original = {
        name: (scan_dir / name).read_bytes() for name in (*artifacts, "checkpoint-head.json")
    }
    checkpoint_files = {
        path.relative_to(scan_dir)
        for directory in ("checkpoints", "checkpoint-heads")
        for path in (scan_dir / directory).glob("*.json")
    }

    result = scan_command(state, command, scan_id, check=False)

    scan = get_scan(state, scan_id)["scan"]
    if complete is False:
        assert result["returncode"] != 0
        assert "The latest saved scan draft is incomplete" in result["stderr"]
        assert scan["progress"]["status"] == "running"
        assert {name: (scan_dir / name).read_bytes() for name in original} == original
        assert (scan_dir / "checkpoint-head.json").stat().st_mtime_ns == 300
        assert {
            path.relative_to(scan_dir)
            for directory in ("checkpoints", "checkpoint-heads")
            for path in (scan_dir / directory).glob("*.json")
        } == checkpoint_files
    else:
        assert result["returncode"] == 0, result["stderr"]
        assert scan["progress"]["status"] == (
            "complete" if command == "complete-scan" else "running"
        )
        completed = json.loads(manifest_path.read_text())["scan"]
        assert completed.get("complete", True) is True
        assert completed["sealedAt"]
        assert completed["scope"] == {**manifest["scan"]["scope"], **draft["scope"]}
        assert completed["threatModel"] == draft["threatModel"]
        assert completed["target"] == manifest["scan"]["target"]


@pytest.mark.parametrize("stopped", [False, True])
@pytest.mark.parametrize("complete", [False, True, None])
def test_selected_parent_retains_semantic_context_through_frozen_recovery(
    tmp_path: Path, checkpoint_scan, stopped: bool, complete: bool | None
) -> None:
    scan_id, _, closed, binding = checkpoint_scan
    write_saved_parent(tmp_path, closed, 100)
    manifest_path = tmp_path / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"].update(
        target=binding["target"],
        scope={**binding["scope"], "limitations": ["The earlier limitation."]},
        threatModel={"summary": "The earlier threat model."},
    )
    manifest_path.write_text(json.dumps(manifest))
    selected = saved_draft(scan_id, complete=complete)
    if complete is None:
        selected.pop("complete")
    selected["scope"] = {
        "includePaths": ["stale-path"],
        "excludePaths": ["stale-exclusion"],
        "limitations": ["Only static analysis was performed."],
    }
    selected["threatModel"] = {
        "summary": "The reviewed threat model.",
        "assumptions": ["The caller controls request fields."],
    }
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(tmp_path / name, ns=(100, 100))
    checkpoint = write_checkpoint(tmp_path / "checkpoints", selected)
    os.utime(checkpoint, ns=(200, 200))
    select(tmp_path, checkpoint, 300)
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], [], stopped=stopped, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, stopped=stopped)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding, stopped=stopped)
    for result in (first, replay, repeated):
        scan = result[0]["scan"]
        assert scan["threatModel"] == selected["threatModel"]
        assert scan["scope"] == {**selected["scope"], **binding["scope"]}
        assert scan["target"] == binding["target"]


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


@pytest.mark.parametrize("decision_owner", ["same", "unowned", "other"])
@pytest.mark.parametrize("evidence", ["deferred", "reported"])
@pytest.mark.parametrize(
    ("destination", "head_time"),
    [
        ("findings.json", 200),
        ("findings.json", 50),
        ("findings.json", 100),
        ("coverage.json", 200),
        ("scan-manifest.json", 200),
    ],
)
def test_parent_head_selection_matches_frozen_publication_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    evidence: str,
    head_time: int,
    destination: str,
    decision_owner: str,
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
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan_dir / filename, ns=(100, 100))
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
    if evidence == "reported" and decision_owner != "unowned":
        terminal["coverage"]["surfaces"][0]["sourceWorkerId"] = (
            worker_id if decision_owner == "same" else "independent-worker"
        )
    staged.write_text(json.dumps(terminal))
    write_bytes = saved.write_scan_local_bytes

    def fail_canonical_write(root, relative, contents):
        if relative == destination:
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
    assert (
        json.loads((scan_dir / "coverage.json").read_text())
        == (terminal if destination == "scan-manifest.json" else initial)["coverage"]
    )

    first = []

    def fail_publication(prepared, *, projection_warnings=None):
        first.append(copy.deepcopy((prepared[3], prepared[4])))
        raise OSError("injected stopped publication failure")

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        call_workbench(patch, state, codex_home, "cancel-scan", "--scan-id", scan_id)
    assert len(first) == 1
    preserve_scan_results(
        state, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
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
            retained = head_time <= 100 or decision_owner != "same"
            assert len(findings["findings"]) == int(retained)
            if retained:
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


@pytest.mark.parametrize("head_time", [100, 200, 300])
def test_selected_worker_checkpoint_preserves_terminal_coverage(
    tmp_path: Path, checkpoint_scan, head_time: int
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    surface = {
        "id": "existing",
        "label": "Existing",
        "disposition": "no_issue_found",
        "receiptRefs": [],
    }
    result = saved_draft(scan_id, surfaces=[surface], complete=True)
    selected = copy.deepcopy(result)
    additions = {
        "surfaces": [{**surface, "id": "newly-reviewed", "label": "Newly reviewed"}],
        "explicitExclusions": [{"pattern": "vendor/**", "reason": "External dependency."}],
        "openQuestions": [{"question": "Should a later review include dependencies?"}],
    }
    for field, rows in additions.items():
        selected["coverage"].setdefault(field, []).extend(rows)
    output = tmp_path / "worker"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(json.dumps(result))
    os.utime(result_path, ns=(200, 200))
    checkpoint = write_checkpoint(output / "checkpoints", selected)
    os.utime(checkpoint, ns=(head_time, head_time))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(head_time, head_time))
    unselected = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan_id,
            surfaces=[{**surface, "id": "unselected", "label": "Unselected"}],
            complete=True,
        ),
    )
    os.utime(unselected, ns=(400, 400))
    original_bytes = {
        path: path.read_bytes() for path in (result_path, checkpoint, head, unselected)
    }
    workers = [saved_discovery_worker(output)]
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers, stopped=True)
    for documents in (first, replay):
        coverage = documents[2]
        assert surface in coverage["surfaces"]
        assert not any(row["id"] == "unselected" for row in coverage["surfaces"])
        for field, rows in additions.items():
            assert any(
                all(row.get(key) == value for key, value in rows[0].items())
                for row in coverage.get(field, [])
            ) is (head_time >= 200)
    assert replay[2] == first[2]
    assert all(path.read_bytes() == contents for path, contents in original_bytes.items())


@pytest.mark.parametrize("head_time", [100, 200, 300])
def test_terminal_selected_checkpoint_replaces_result_coverage(tmp_path, head_time):
    scan_id = "selected-terminal"
    binding = saved_binding("deep_repository", repository="synthetic")
    before = {"id": "api", "label": "API", "disposition": "needs_follow_up", "receiptRefs": []}
    after = {**before, "disposition": "no_issue_found"}
    old_question = {"question": "Is the API review complete?"}
    old_exclusion = {"id": "excluded", "pattern": "vendor/**", "reason": "Awaiting review."}
    new_exclusion = {**old_exclusion, "reason": "Reviewed dependency scope."}
    result = saved_draft(scan_id, surfaces=[before], complete=True)
    result["coverage"].update(openQuestions=[old_question], explicitExclusions=[old_exclusion])
    selected = copy.deepcopy(result)
    selected["coverage"].update(
        surfaces=[after], openQuestions=[], explicitExclusions=[new_exclusion]
    )
    output = tmp_path / "worker"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(json.dumps(result))
    os.utime(result_path, ns=(200, 200))
    checkpoint = write_checkpoint(output / "checkpoints", selected)
    os.utime(checkpoint, ns=(head_time, head_time))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(head_time, head_time))
    workers = [saved_discovery_worker(output)]
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers, stopped=True)
    for observed in (first, replay):
        coverage = observed[2]
        assert coverage["surfaces"] == ([after] if head_time >= 200 else [before])
        assert coverage.get("openQuestions", []) == ([] if head_time >= 200 else [old_question])
        assert coverage["explicitExclusions"] == (
            [new_exclusion] if head_time >= 200 else [old_exclusion]
        )


@pytest.mark.parametrize("complete", [False, True])
def test_multiple_selected_terminal_observations(tmp_path, complete):
    scan_id = "selected-history"
    binding = saved_binding("deep_repository", repository="synthetic")
    before = {"id": "api", "label": "API", "disposition": "needs_follow_up", "receiptRefs": []}
    after = {**before, "disposition": "no_issue_found"}
    output = tmp_path / "worker"
    output.mkdir()
    result = saved_draft(scan_id, surfaces=[before], complete=True)
    (output / "result.json").write_text(json.dumps(result))
    os.utime(output / "result.json", ns=(200, 200))
    head = output / "checkpoint-head.json"
    intermediate = copy.deepcopy(result)
    intermediate["coverage"]["openQuestions"] = [{"question": "Review question."}]
    intermediate_checkpoint = write_checkpoint(output / "checkpoints", intermediate)
    os.utime(intermediate_checkpoint, ns=(250, 250))
    head.write_text(json.dumps({"checkpoint": intermediate_checkpoint.name}))
    os.utime(head, ns=(250, 250))
    workers = [saved_discovery_worker(output)]
    saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    terminal = saved_draft(scan_id, surfaces=[after], complete=complete)
    checkpoint = write_checkpoint(output / "checkpoints", terminal)
    os.utime(checkpoint, ns=(300, 300))
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(300, 300))
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers)
    for result in (first, replay):
        if complete:
            assert result[2]["surfaces"] == [after]
            assert result[2].get("openQuestions", []) == []
        else:
            assert result[2].get("openQuestions", []) == [{"question": "Review question."}]


def test_older_attempt_selected_head_cannot_supersede_current_result(tmp_path):
    scan_id = "selected-archive"
    binding = saved_binding("deep_repository", repository="synthetic")
    current = {
        "id": "api",
        "label": "Current review",
        "disposition": "no_issue_found",
        "receiptRefs": [],
    }
    outdated = {**current, "label": "Old attempt"}
    output = tmp_path / "worker"
    output.mkdir()
    (output / "result.json").write_text(
        json.dumps(saved_draft(scan_id, surfaces=[current], complete=True))
    )
    os.utime(output / "result.json", ns=(200, 200))
    archived = output / "attempts" / "attempt-1"
    checkpoint = write_checkpoint(
        archived / "checkpoints", saved_draft(scan_id, surfaces=[outdated], complete=True)
    )
    os.utime(checkpoint, ns=(300, 300))
    head = archived / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(300, 300))
    workers = [saved_discovery_worker(output, attempt=2)]
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers)
    for result in (first, replay):
        assert result[2]["surfaces"] == [current]
