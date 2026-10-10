from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import pytest
from workbench_test_support import (
    replay_saved_results,
    saved_binding,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finalize_scan_contract
import workbench_saved_results as saved


def write_saved_parent(scan_dir: Path, draft: dict, modified: int) -> None:
    scan_dir.mkdir(parents=True, exist_ok=True)
    scan = {key: draft[key] for key in ("complete", "scope", "threatModel") if key in draft}
    documents = {
        "manifest": {"scan": scan},
        "findings": {"findings": draft["findings"]},
        "coverage": draft["coverage"],
    }
    for key, filename in (
        ("manifest", "scan-manifest.json"),
        ("findings", "findings.json"),
        ("coverage", "coverage.json"),
    ):
        (scan_dir / filename).write_text(json.dumps(documents[key]))
        os.utime(scan_dir / filename, ns=(modified, modified))


def select(output: Path, checkpoint: Path, observed: int) -> None:
    """Accept a semantic draft using the committed snapshot contract."""
    draft = json.loads(checkpoint.read_text())
    write_saved_parent(output, draft, observed)
    documents = {
        key: json.loads((output / filename).read_text())
        for key, filename in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["reconciledCheckpointIds"] = [checkpoint.name]
    committed = output / "artifacts/scan-draft.json"
    committed.parent.mkdir(exist_ok=True)
    committed.write_text(json.dumps(documents))
    os.utime(committed, ns=(observed, observed))


def replay_saved_results(module, documents, scan_dir, scan_id, binding, *, stopped=True):
    sources = documents[0]["scan"]["preservedSources"]
    _, parent = module._read_saved_parent_result(scan_dir, scan_id)
    selected = f"checkpoints/{module._digest(parent)}.json"
    return module.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        [],
        stopped=stopped,
        reason="interrupted",
        frozen_source_digests=sources,
        selected_parent_checkpoint=selected if selected in sources else None,
    )


@pytest.fixture
def checkpoint_scan():
    scan_id = "saved-observation"
    pending, closed = drafts(scan_id)
    return scan_id, pending, closed, saved_binding(repository="synthetic")


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
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, stopped=True)
    for result in (first, replay):
        assert [
            {**row, "receiptRefs": row.get("receiptRefs", [])} for row in result[2]["surfaces"]
        ] == [{**surface, "receiptRefs": []}]
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
        tmp_path, scan_id, binding, warnings, stopped=False, reason=""
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
        tmp_path, scan_id, binding, warnings, stopped=True, reason="interrupted"
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
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
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


@pytest.mark.parametrize("rewrite", [False, True])
def test_recovery_preserves_distinct_legacy_tasks_with_one_id(
    tmp_path: Path, checkpoint_scan, rewrite: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    output = tmp_path
    output.mkdir(parents=True, exist_ok=True)
    directory = output
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
    pending = directory / "checkpoints/pending"
    pending.mkdir()
    for path in (directory / "checkpoints").glob("*.json"):
        if path != completed:
            (pending / path.name).write_bytes(path.read_bytes())
            os.utime(pending / path.name, ns=(path.stat().st_mtime_ns, path.stat().st_mtime_ns))
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding)
    assert first[2] == replay[2] == repeated[2]
    for result in (first, replay, repeated):
        retained = [row for row in result[2]["deferred"] if row["id"] != "scan-stopped"]
        assert [{key: value for key, value in row.items() if key != "id"} for row in retained] == [
            {key: value for key, value in row.items() if key != "id"} for row in tasks
        ]
        assert not result[2].get("resolvedDeferred")


@pytest.mark.parametrize("alias", ["id", "candidateId"])
@pytest.mark.parametrize("outcome", ["reported", "rejected"])
@pytest.mark.parametrize("rewrite", [False, True])
def test_recovery_keeps_generic_work_that_collides_with_candidate_aliases(
    tmp_path: Path, checkpoint_scan, alias: str, outcome: str, rewrite: bool
) -> None:
    scan_id, _, _, binding = checkpoint_scan
    binding["target"]["targetId"] = "synthetic-target"
    output = tmp_path
    directory = output
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
    pending = directory / "checkpoints/pending"
    pending.mkdir()
    for path in (directory / "checkpoints").glob("*.json"):
        if path != completed:
            (pending / path.name).write_bytes(path.read_bytes())
            os.utime(pending / path.name, ns=(path.stat().st_mtime_ns, path.stat().st_mtime_ns))
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding)
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
        tmp_path, scan_id, binding, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding)
    for result in (first, replay):
        assert result[0]["scan"].get("complete", True) is (complete is not False)
        for task in tasks:
            assert task in result[2]["deferred"]


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
        **binding["scope"],
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
        tmp_path, scan_id, binding, [], stopped=stopped, reason="interrupted"
    )
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, stopped=stopped)
    repeated = replay_saved_results(saved, replay, tmp_path, scan_id, binding, stopped=stopped)
    for result in (first, replay, repeated):
        scan = result[0]["scan"]
        assert scan["threatModel"] == selected["threatModel"]
        assert scan["scope"] == {**selected["scope"], **binding["scope"]}
        assert scan["target"] == binding["target"]
