from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from test_workbench_saved_source_order import call_workbench
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    deep_scan_fixture,
    write_saved_parent,
)
from workbench_test_support import run_workbench, saved_discovery_worker, write_checkpoint


@pytest.fixture
def saved_results():
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import workbench_saved_results

    return workbench_saved_results


def saved_draft(scan_id: str, *, deferred=(), surfaces=(), closures=(), complete=False):
    return {
        "scanId": scan_id,
        "complete": complete,
        "findings": [],
        "coverage": {
            "completeness": "partial" if deferred else "complete",
            "surfaces": list(surfaces),
            "explicitExclusions": [],
            "deferred": list(deferred),
            **({"resolvedDeferred": list(closures)} if closures else {}),
        },
    }


def save_worker(root: Path, module, worker_id: str, drafts: list[dict], result: dict):
    output = root / worker_id
    checkpoints = output / "checkpoints"
    checkpoints.mkdir(parents=True)
    for index, draft in enumerate(drafts, 1):
        path = checkpoints / f"{module._digest(draft)}.json"
        path.write_text(json.dumps(draft))
        os.utime(path, ns=(index * 100, index * 100))
    result_path = output / "result.json"
    result_path.write_text(json.dumps(result))
    os.utime(result_path, ns=(1000, 1000))
    return saved_discovery_worker(output, worker_id, 1)


def recover(root: Path, module, workers, frozen=None):
    binding = {
        "status": "interrupted",
        "allowedTargetKinds": ["git_revision"],
        "target": {
            "kind": "git_revision",
            "targetId": "synthetic",
            "displayName": "test",
            "revision": "head",
        },
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "deep_repository",
    }
    result = module.merge_saved_results(
        root,
        "identity-scan",
        binding,
        workers,
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=frozen,
    )
    assert result is not None
    return result


def cancel_and_preserve(monkeypatch, saved_results, state, codex_home, scan_dir, scan_id):
    """Retry publication from frozen sources after the initial write fails."""
    prepared_coverage = []

    def fail_publication(prepared):
        prepared_coverage.append(prepared[4])
        raise OSError("injected publication failure")

    with monkeypatch.context() as patch:
        patch.setattr(saved_results, "_write_prepared_scan_finalization", fail_publication)
        call_workbench(patch, state, codex_home, "cancel-scan", "--scan-id", scan_id)
    assert len(prepared_coverage) == 1
    run_workbench(
        state,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )
    return prepared_coverage[0], json.loads((scan_dir / "coverage.json").read_text())


@pytest.mark.parametrize("named_history", [False, True])
def test_distinct_raw_candidate_survives_another_workers_generic_closure(
    tmp_path: Path, saved_results, named_history: bool
):
    first = {
        "reason": "Caller needs validation.",
        "paths": ["api.py"],
        "candidate": {"title": "First caller"},
    }
    second = {**first, "candidate": {"title": "Independent caller"}}
    first_id = "candidate-review"
    drafts = [
        saved_draft("identity-scan", deferred=[first]),
        saved_draft("identity-scan", deferred=[second]),
    ]
    if named_history:
        drafts.insert(0, saved_draft("identity-scan", deferred=[{**first, "id": first_id}]))
    rejected = saved_draft(
        "identity-scan",
        surfaces=[
            {
                "id": "rejection",
                "label": "First caller",
                "candidateId": first_id,
                "candidate": first["candidate"],
                "disposition": "rejected",
            }
        ],
    )
    worker = save_worker(tmp_path, saved_results, "reviewer", drafts, rejected)
    other = saved_draft(
        "identity-scan",
        closures=[{"id": "generic-review", "reason": "Source review completed."}],
        complete=True,
    )
    closure_worker = save_worker(tmp_path, saved_results, "other", [], other)
    result = recover(tmp_path, saved_results, [worker, closure_worker])
    replay = recover(
        tmp_path, saved_results, [worker, closure_worker], result[0]["scan"]["preservedSources"]
    )
    for documents in (result, replay):
        pending = documents[2]["deferred"]
        assert any(row.get("candidate") == second["candidate"] for row in pending)
        assert any(row.get("candidate") == first["candidate"] for row in pending)


def test_two_unmatched_raw_candidates_keep_distinct_stable_ids(tmp_path: Path, saved_results):
    generic = {"reason": "Review remains.", "paths": ["api.py"]}
    generic_id = "generic-review"
    first = {**generic, "candidate": {"title": "First caller"}}
    second = {**generic, "candidate": {"title": "Second caller"}}
    closure = saved_draft(
        "identity-scan",
        closures=[{"id": generic_id, "reason": "Generic review completed."}],
        complete=True,
    )
    worker = save_worker(
        tmp_path,
        saved_results,
        "reviewer",
        [
            saved_draft("identity-scan", deferred=[{**generic, "id": generic_id}]),
            closure,
            saved_draft("identity-scan", deferred=[first]),
            saved_draft("identity-scan", deferred=[second]),
        ],
        saved_draft("identity-scan"),
    )
    documents = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], documents[0]["scan"]["preservedSources"])
    pending = [row for row in documents[2]["deferred"] if "candidate" in row]
    assert {row["candidate"]["title"] for row in pending} == {"First caller", "Second caller"}
    assert len({row["id"] for row in pending}) == 2
    assert replay[2] == documents[2]


def test_unnamed_changed_observation_stays_pending(tmp_path: Path, saved_results):
    generic = {"reason": "Review remains.", "paths": ["api.py"], "notes": "Initial review."}
    identity = "source-review"
    closed = saved_draft(
        "identity-scan", closures=[{"id": identity, "reason": "Reviewed."}], complete=True
    )
    reopened = {**generic, "notes": "New evidence requires another review."}
    worker = save_worker(
        tmp_path,
        saved_results,
        "reviewer",
        [
            saved_draft("identity-scan", deferred=[{**generic, "id": identity}]),
            closed,
            saved_draft("identity-scan", deferred=[reopened]),
        ],
        saved_draft("identity-scan"),
    )
    documents = recover(tmp_path, saved_results, [worker])
    pending = [row for row in documents[2]["deferred"] if row.get("notes") == reopened["notes"]]
    assert len(pending) == 1 and pending[0]["id"] != identity


@pytest.mark.parametrize("payload_field", ["candidate", "finding"])
@pytest.mark.parametrize("raw_modified", [200, 300], ids=["tied", "newer"])
@pytest.mark.parametrize("layout", ["parent", "worker"])
def test_new_work_survives_accepted_candidate_rejection(
    tmp_path: Path, saved_results, payload_field: str, raw_modified: int, layout: str
):
    generic = {"reason": "Review remains.", "paths": ["api.py"], "surfaceIds": ["entry"]}
    candidate_id = "candidate-review"
    candidate = {
        **generic,
        "id": candidate_id,
        "notes": "Candidate review.",
        payload_field: {"title": "Caller validation."},
    }
    rejection = {
        "id": "candidate-result",
        "label": "Caller",
        "disposition": "rejected",
        "candidateId": candidate_id,
        payload_field: candidate[payload_field],
        "receiptRefs": [],
    }
    rejected = saved_draft("identity-scan", surfaces=[rejection], complete=True)
    reopened = {**generic, "notes": "Independent source review."}
    new_candidate = {
        **candidate,
        "id": "independent-caller",
        payload_field: {"title": "Another caller needs validation."},
    }
    raw = saved_draft(
        "identity-scan", deferred=[reopened, new_candidate], surfaces=[rejection], complete=True
    )
    drafts = [saved_draft("identity-scan", deferred=[candidate]), rejected, raw]
    if layout == "worker":
        worker = save_worker(tmp_path, saved_results, "reviewer", drafts, rejected)
        workers = [worker]
        output = Path(worker["artifact_dir"])
        os.utime(output / "result.json", ns=(200, 200))
        checkpoints = [
            output / "checkpoints" / f"{saved_results._digest(draft)}.json" for draft in drafts
        ]
    else:
        workers = []
        output = tmp_path
        write_saved_parent(output, rejected, 200)
        checkpoints = [write_checkpoint(output / "checkpoints", draft) for draft in drafts]
        for index, checkpoint in enumerate(checkpoints, 1):
            os.utime(checkpoint, ns=(index * 100, index * 100))
    os.utime(checkpoints[2], ns=(raw_modified, raw_modified))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoints[1].name}))
    os.utime(head, ns=(200, 200))
    documents = recover(tmp_path, saved_results, workers)
    replay = recover(tmp_path, saved_results, workers, documents[0]["scan"]["preservedSources"])
    for result in (documents, replay):
        pending = [row for row in result[2]["deferred"] if row.get("id") != "scan-stopped"]
        assert new_candidate in pending
        pending.remove(new_candidate)
        assert len(pending) == 1
        assert {key: value for key, value in pending[0].items() if key != "id"} == reopened
        assert isinstance(pending[0]["id"], str)
        assert result[2]["surfaces"] == [rejection]
    assert replay[2] == documents[2]


@pytest.mark.parametrize("candidate_identity", ["id_only", "explicit", "alias"])
@pytest.mark.parametrize("outcome", ["rejected", "unresolved", "other_worker"])
def test_generic_surface_recovery_uses_resolved_candidate_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_results,
    candidate_identity: str,
    outcome: str,
):
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    candidate = {
        "id": "caller-review",
        "reason": "Caller needs validation.",
        "candidate": {"title": "Caller validation."},
        "surfaceIds": ["api"],
    }
    if candidate_identity != "id_only":
        candidate["candidateId"] = "caller-review"
    if candidate_identity == "alias":
        candidate["id"] = "pending-caller"
    generic = {"id": "generic-review", "reason": "Source review remains.", "surfaceIds": ["api"]}
    pending_surface = {
        "id": "api",
        "label": "API",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    rejection = {
        "id": "candidate-outcome",
        "label": "Caller review",
        "candidateId": "caller-review",
        "candidate": candidate["candidate"],
        "disposition": "rejected",
        "receiptRefs": [],
    }
    initial = saved_draft(scan_id, deferred=[candidate, generic], surfaces=[pending_surface])
    rejected_here = outcome == "rejected"
    accepted = saved_draft(
        scan_id,
        deferred=[generic] if rejected_here else [candidate, generic],
        surfaces=[pending_surface, rejection] if rejected_here else [pending_surface],
        complete=True,
    )
    closed = saved_draft(
        scan_id,
        surfaces=[{**pending_surface, "disposition": "no_issue_found"}],
        closures=[{"id": generic["id"], "reason": "Source review completed."}],
        complete=True,
    )
    if rejected_here:
        closed["coverage"]["surfaces"].append(rejection)
    checkpoints = [
        write_checkpoint(result_path.parent / "checkpoints", draft)
        for draft in (initial, accepted, closed)
    ]
    for index, checkpoint in enumerate(checkpoints, 1):
        os.utime(checkpoint, ns=(index * 100, index * 100))
    result_path.write_text(json.dumps(accepted))
    os.utime(result_path, ns=(200, 200))
    # The terminal checkpoint survives a failed replacement of result.json.
    head = result_path.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoints[2 if rejected_here else 1].name}))
    observed = 300 if rejected_here else 200
    os.utime(head, ns=(observed, observed))
    if outcome == "other_worker":
        _, other_result = accepted_standard_worker(
            state, codex_home, scan_dir, scan_id, name="other-worker"
        )
        other_result.write_text(
            json.dumps(saved_draft(scan_id, surfaces=[rejection], complete=True))
        )
        os.utime(other_result, ns=(200, 200))

    first_coverage, recovered = cancel_and_preserve(
        monkeypatch, saved_results, state, codex_home, scan_dir, scan_id
    )
    for coverage in (first_coverage, recovered):
        api_surfaces = [row for row in coverage["surfaces"] if row["id"] == "api"]
        assert len(api_surfaces) == 1
        expected_disposition = "no_issue_found" if rejected_here else "needs_follow_up"
        assert api_surfaces[0]["disposition"] == expected_disposition
        assert not any(row["id"] == generic["id"] for row in coverage["deferred"])
        assert (
            any(row["id"] == candidate["id"] for row in coverage["deferred"]) is not rejected_here
        )
        if outcome != "unresolved":
            assert rejection in coverage["surfaces"]
    assert recovered["surfaces"] == first_coverage["surfaces"]
    assert recovered["deferred"] == first_coverage["deferred"]


@pytest.mark.parametrize(
    ("payload_field", "close_first"),
    [(None, False), ("candidate", False), ("finding", False), (None, True)],
    ids=["generic", "candidate", "finding", "close-first"],
)
@pytest.mark.parametrize("explicit_ids", [False, True], ids=["inferred", "explicit"])
def test_split_deferred_rows_keep_distinct_ids_in_frozen_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_results,
    payload_field: str | None,
    explicit_ids: bool,
    close_first: bool,
):
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    combined = {
        "id": "combined-review",
        "reason": "Review remains.",
        "paths": ["a.py", "b.py"],
    }
    if payload_field:
        combined[payload_field] = {"title": "Caller validation."}
    split = [{**combined, "paths": [path]} for path in combined["paths"]]
    for index, row in enumerate(split):
        if explicit_ids:
            row["id"] = f"part-{index + 1}"
        else:
            row.pop("id")
    expected_ids = {row["id"] for row in split} if explicit_ids else None
    initial = saved_draft(scan_id, deferred=[combined])
    pending = saved_draft(scan_id, deferred=split)
    checkpoints = [
        write_checkpoint(result_path.parent / "checkpoints", draft) for draft in (initial, pending)
    ]
    for index, checkpoint in enumerate(checkpoints, 1):
        os.utime(checkpoint, ns=(index * 100, index * 100))
    result_path.write_text(json.dumps(initial))
    os.utime(result_path, ns=(100, 100))
    head = result_path.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoints[0].name}))
    os.utime(head, ns=(100, 100))
    if close_first:
        first_id = split[0]["id"] if explicit_ids else saved_results._saved_coverage_id(split[0])
        terminal = saved_draft(
            scan_id,
            closures=[{"id": first_id, "reason": "First path reviewed."}],
            complete=True,
        )
        terminal_checkpoint = write_checkpoint(result_path.parent / "checkpoints", terminal)
        os.utime(terminal_checkpoint, ns=(300, 300))
        head.write_text(json.dumps({"checkpoint": terminal_checkpoint.name}))
        os.utime(head, ns=(300, 300))
        if explicit_ids:
            expected_ids.remove(first_id)
    first_coverage, replay = cancel_and_preserve(
        monkeypatch, saved_results, state, codex_home, scan_dir, scan_id
    )
    for coverage in (first_coverage, replay):
        retained = [row for row in coverage["deferred"] if row.get("paths") in [["a.py"], ["b.py"]]]
        assert len(retained) == (1 if close_first and explicit_ids else 2)
        assert len({row["id"] for row in retained}) == len(retained)
        if explicit_ids:
            assert {row["id"] for row in retained} == expected_ids
        assert all(row["id"] != combined["id"] for row in retained)
        if explicit_ids:
            assert {row["id"] for row in retained} == (
                {"part-2"} if close_first else {"part-1", "part-2"}
            )
        if payload_field:
            assert all(row[payload_field] == combined[payload_field] for row in retained)
    assert replay == first_coverage


@pytest.mark.parametrize("layout", ["parent", "worker"])
@pytest.mark.parametrize(
    "observation", ["generic", "candidate", "finding", "explicit-update", "omitted-alias"]
)
def test_unnamed_observation_does_not_replace_saved_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_results,
    layout: str,
    observation: str,
):
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    broad = {
        "id": "caller-review",
        "reason": "Review the caller paths.",
        "paths": ["app.py", "extra.py"],
        "notes": "Both caller paths require review.",
    }
    raw_row = {"reason": broad["reason"], "paths": ["app.py"]}
    if observation in {"candidate", "finding", "omitted-alias"}:
        field = "candidate" if observation == "omitted-alias" else observation
        broad[field] = {"title": "Caller validation.", "evidence": "Both callers."}
        raw_row[field] = {"title": "Caller validation."}
        if observation == "omitted-alias":
            broad["candidateId"] = "owned-candidate"
    expected = (
        {**broad, "paths": ["app.py"], "notes": "Only the remaining caller needs review."}
        if observation == "explicit-update"
        else broad
    )
    initial = saved_draft(scan_id, deferred=[broad])
    accepted = saved_draft(scan_id, deferred=[expected], complete=observation == "explicit-update")
    raw = saved_draft(scan_id, deferred=[raw_row])
    output = scan_dir if layout == "parent" else result_path.parent
    drafts = [initial, accepted, raw] if observation == "explicit-update" else [initial, raw]
    checkpoints = [write_checkpoint(output / "checkpoints", draft) for draft in drafts]
    for index, checkpoint in enumerate(checkpoints, 1):
        os.utime(checkpoint, ns=(index * 100, index * 100))
    accepted_index = 1 if observation == "explicit-update" else 0
    observed = (accepted_index + 1) * 100
    if layout == "worker":
        result_path.write_text(json.dumps(accepted))
        os.utime(result_path, ns=(observed, observed))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoints[accepted_index].name}))
    os.utime(head, ns=(observed, observed))
    first_coverage, replay = cancel_and_preserve(
        monkeypatch, saved_results, state, codex_home, scan_dir, scan_id
    )
    for coverage in (first_coverage, replay):
        pending = [row for row in coverage["deferred"] if row["id"] != "scan-stopped"]
        assert expected in pending
        unnamed = [row for row in pending if row.get("id") != expected["id"]]
        assert len(unnamed) == 1
        assert {key: value for key, value in unnamed[0].items() if key != "id"} == raw_row
        assert "candidateId" not in unnamed[0]
    assert replay == first_coverage


@pytest.mark.parametrize("close_summary", [False, True])
def test_legacy_summary_stays_pending_after_an_explicit_closure(
    tmp_path: Path, saved_results, close_summary: bool
):
    summary = {"reason": "Review API callers.", "paths": ["api.py"]}
    detailed = [
        {**summary, "id": "caller-a", "notes": "First caller."},
        {**summary, "id": "caller-b", "notes": "Second caller."},
    ]
    generated = saved_results._saved_coverage_id(summary)
    closure_id = generated if close_summary else "caller-a"
    worker = save_worker(
        tmp_path,
        saved_results,
        "reviewer",
        [
            saved_draft("identity-scan", deferred=detailed),
            saved_draft("identity-scan", deferred=[summary]),
            saved_draft(
                "identity-scan", closures=[{"id": closure_id, "reason": "Reviewed."}], complete=True
            ),
        ],
        saved_draft("identity-scan"),
    )
    first = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], first[0]["scan"]["preservedSources"])
    for documents in (first, replay):
        pending = documents[2]["deferred"]
        assert detailed[1] in pending
        assert (detailed[0] in pending) is close_summary
        assert any(
            {key: value for key, value in row.items() if key != "id"} == summary for row in pending
        )
    assert replay[2] == first[2]
