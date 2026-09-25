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
from workbench_test_support import run_workbench, write_checkpoint


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
    return {
        "id": worker_id,
        "kind": "discovery",
        "artifact_dir": str(output),
        "result_manifest_path": None,
        "attempt": 1,
    }


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
    first_id = saved_results._identified_deferred_rows({"deferred": [first]})[0]["id"]
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
        assert (any(row.get("candidate") == first["candidate"] for row in pending)) is (
            not named_history
        )
        independent = [row for row in pending if row.get("candidate") == second["candidate"]]
        assert all(row["id"] != first_id for row in independent)


def test_two_unmatched_raw_candidates_keep_distinct_stable_ids(tmp_path: Path, saved_results):
    generic = {"reason": "Review remains.", "paths": ["api.py"]}
    generic_id = saved_results._identified_deferred_rows({"deferred": [generic]})[0]["id"]
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
            saved_draft("identity-scan", deferred=[generic]),
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
    assert all(row["id"] != generic_id for row in pending)
    assert replay[2] == documents[2]


def test_generic_reopening_keeps_its_derived_id_with_changed_metadata(
    tmp_path: Path, saved_results
):
    generic = {"reason": "Review remains.", "paths": ["api.py"], "notes": "Initial review."}
    identity = saved_results._identified_deferred_rows({"deferred": [generic]})[0]["id"]
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
    assert len(pending) == 1 and pending[0]["id"] == identity


@pytest.mark.parametrize("payload_field", ["candidate", "finding"])
@pytest.mark.parametrize("raw_modified", [200, 300], ids=["tied", "newer"])
@pytest.mark.parametrize("layout", ["parent", "worker"])
def test_new_raw_generic_work_survives_accepted_candidate_rejection(
    tmp_path: Path, saved_results, payload_field: str, raw_modified: int, layout: str
):
    generic = {"reason": "Review remains.", "paths": ["api.py"], "surfaceIds": ["entry"]}
    candidate_id = saved_results._identified_deferred_rows({"deferred": [generic]})[0]["id"]
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
    raw = saved_draft("identity-scan", deferred=[reopened], surfaces=[rejection], complete=True)
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
        assert len(pending) == 1
        assert {key: value for key, value in pending[0].items() if key != "id"} == reopened
        assert pending[0]["id"] == f"{candidate_id}-2"
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
    recovered = json.loads((scan_dir / "coverage.json").read_text())
    for coverage in (prepared_coverage[0], recovered):
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
    assert recovered["surfaces"] == prepared_coverage[0]["surfaces"]
    assert recovered["deferred"] == prepared_coverage[0]["deferred"]


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
    expected_ids = {
        row["id"] for row in saved_results._identified_deferred_rows({"deferred": split})
    }
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
        first_id = saved_results._identified_deferred_rows({"deferred": split})[0]["id"]
        terminal = saved_draft(
            scan_id,
            closures=[{"id": first_id, "reason": "First path reviewed."}],
            complete=True,
        )
        terminal_checkpoint = write_checkpoint(result_path.parent / "checkpoints", terminal)
        os.utime(terminal_checkpoint, ns=(300, 300))
        head.write_text(json.dumps({"checkpoint": terminal_checkpoint.name}))
        os.utime(head, ns=(300, 300))
        expected_ids.remove(first_id)
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
    replay = json.loads((scan_dir / "coverage.json").read_text())
    for coverage in (prepared_coverage[0], replay):
        retained = [row for row in coverage["deferred"] if row.get("paths") in [["a.py"], ["b.py"]]]
        assert len(retained) == (1 if close_first else 2)
        assert {row["id"] for row in retained} == expected_ids
        assert all(row["id"] != combined["id"] for row in retained)
        if explicit_ids:
            assert {row["id"] for row in retained} == (
                {"part-2"} if close_first else {"part-1", "part-2"}
            )
        if payload_field:
            assert all(row[payload_field] == combined[payload_field] for row in retained)
    assert replay == prepared_coverage[0]


@pytest.mark.parametrize("payload_field", [None, "candidate", "finding"])
def test_duplicate_observations_keep_their_saved_identity(
    tmp_path: Path, saved_results, payload_field: str | None
):
    named = {"id": "saved-review", "reason": "Review remains.", "paths": ["a.py", "b.py"]}
    if payload_field:
        named[payload_field] = {"title": "Caller validation."}
    raw = {key: value for key, value in named.items() if key != "id"}
    initial = saved_draft("identity-scan", deferred=[named])
    repeated = saved_draft("identity-scan", deferred=[raw, raw])
    worker = save_worker(tmp_path, saved_results, "reviewer", [initial, repeated], initial)
    first = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], first[0]["scan"]["preservedSources"])
    for documents in (first, replay):
        assert [row for row in documents[2]["deferred"] if row["id"] != "scan-stopped"] == [named]
    assert replay[2] == first[2]


@pytest.mark.parametrize("closed", [None, "detailed", "summary"])
@pytest.mark.parametrize(
    "candidate_reserved", [False, True], ids=["generic-only", "candidate-owned"]
)
@pytest.mark.parametrize("saved_summary", [False, True], ids=["raw", "repeated"])
def test_ambiguous_generic_summary_has_an_independent_recoverable_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    saved_results,
    closed: str | None,
    saved_summary: bool,
    candidate_reserved: bool,
):
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    summary = {"reason": "Review API callers.", "paths": ["api.py"]}
    detailed = saved_results._identified_deferred_rows(
        {
            "deferred": [
                {**summary, "notes": "First caller."},
                {**summary, "notes": "Second caller."},
            ]
        }
    )
    summary_id = f"{detailed[0]['id']}-{4 if candidate_reserved else 3}"
    candidate_rows = (
        [
            {
                "id": f"{detailed[0]['id']}-3",
                "reason": "Candidate review remains.",
                "candidate": {"title": "Independent caller."},
            }
        ]
        if candidate_reserved
        else []
    )
    initial = saved_draft(scan_id, deferred=[*detailed, *candidate_rows])
    raw = saved_draft(scan_id, deferred=[summary])
    checkpoints = [
        write_checkpoint(result_path.parent / "checkpoints", draft) for draft in (initial, raw)
    ]
    for index, checkpoint in enumerate(checkpoints, 1):
        os.utime(checkpoint, ns=(index * 100, index * 100))
    accepted = initial
    selected = checkpoints[0]
    observed = 100
    if saved_summary:
        accepted = saved_draft(
            scan_id, deferred=[*detailed, *candidate_rows, {**summary, "id": summary_id}]
        )
        selected = write_checkpoint(result_path.parent / "checkpoints", accepted)
        observed = 250
        os.utime(selected, ns=(observed, observed))
    result_path.write_text(json.dumps(accepted))
    os.utime(result_path, ns=(observed, observed))
    if closed:
        identity = detailed[0]["id"] if closed == "detailed" else summary_id
        terminal = saved_draft(
            scan_id,
            closures=[{"id": identity, "reason": "Selected review completed."}],
            complete=True,
        )
        selected = write_checkpoint(result_path.parent / "checkpoints", terminal)
        observed = 300
        os.utime(selected, ns=(observed, observed))
    head = result_path.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(observed, observed))
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
    replay = json.loads((scan_dir / "coverage.json").read_text())
    expected = [row for row in detailed if closed != "detailed" or row != detailed[0]]
    expected.extend(candidate_rows)
    if closed != "summary":
        expected.append({**summary, "id": summary_id})
    for coverage in (prepared_coverage[0], replay):
        pending = [row for row in coverage["deferred"] if row["id"] != "scan-stopped"]
        assert len(pending) == len(expected)
        assert all(row in pending for row in expected)
    assert replay == prepared_coverage[0]


def test_equivalent_saved_ids_do_not_change_repeated_summary_identity(
    tmp_path: Path, saved_results
):
    row = {"reason": "Review remains.", "paths": ["api.py"]}
    named = [{**row, "id": "review-a"}, {**row, "id": "review-b"}]
    initial = saved_draft("identity-scan", deferred=named)
    observations = [
        {
            **saved_draft("identity-scan", deferred=[row]),
            "threatModel": {"summary": f"Checkpoint {index}."},
        }
        for index in range(3)
    ]
    worker = save_worker(tmp_path, saved_results, "reviewer", [initial, *observations], initial)
    first = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], first[0]["scan"]["preservedSources"])
    expected = [*named, *saved_results._identified_deferred_rows({"deferred": [row]})]
    for documents in (first, replay):
        pending = [item for item in documents[2]["deferred"] if item["id"] != "scan-stopped"]
        assert len(pending) == len(expected)
        assert all(item in pending for item in expected)
    assert replay[2] == first[2]


@pytest.mark.parametrize("ambiguous_first", [True, False], ids=["ambiguous-first", "exact-first"])
def test_ambiguous_fallback_reserves_later_inferred_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, saved_results, ambiguous_first: bool
):
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    common = {"reason": "Review API callers.", "paths": ["api.py"]}
    named = saved_results._identified_deferred_rows(
        {
            "deferred": [
                {**common, "group": "A", "notes": "First caller."},
                {**common, "group": "A", "notes": "Second caller."},
                {**common, "group": "B"},
            ]
        }
    )
    summary = {**common, "group": "A"}
    exact = {key: value for key, value in named[2].items() if key != "id"}
    initial = saved_draft(scan_id, deferred=named)
    raw = saved_draft(scan_id, deferred=[summary, exact] if ambiguous_first else [exact, summary])
    closed = saved_draft(
        scan_id,
        closures=[{"id": named[2]["id"], "reason": "Group B review completed."}],
        complete=True,
    )
    checkpoints = [
        write_checkpoint(result_path.parent / "checkpoints", draft)
        for draft in (initial, raw, closed)
    ]
    for index, checkpoint in enumerate(checkpoints, 1):
        os.utime(checkpoint, ns=(index * 100, index * 100))
    result_path.write_text(json.dumps(initial))
    os.utime(result_path, ns=(100, 100))
    head = result_path.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoints[2].name}))
    os.utime(head, ns=(300, 300))
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
    replay = json.loads((scan_dir / "coverage.json").read_text())
    expected = [*named[:2], {**summary, "id": f"{named[0]['id']}-4"}]
    for coverage in (prepared_coverage[0], replay):
        pending = [row for row in coverage["deferred"] if row["id"] != "scan-stopped"]
        assert len(pending) == len(expected)
        assert all(row in pending for row in expected)
    assert replay == prepared_coverage[0]


@pytest.mark.parametrize("layout", ["parent", "worker"])
@pytest.mark.parametrize(
    ("payload_field", "candidate_id"),
    [
        ("candidate", "candidate-review"),
        ("finding", "candidate-review"),
        ("candidate", "caller-review"),
    ],
    ids=["candidate-alias", "finding-alias", "same-id"],
)
def test_recovered_deferred_identity_keeps_its_candidate_alias(
    tmp_path: Path, saved_results, layout: str, payload_field: str, candidate_id: str
):
    raw_row = {
        "reason": "Review the candidate caller.",
        "paths": ["api.py"],
        payload_field: {"title": "Caller validation."},
    }
    named = {**raw_row, "id": "caller-review", "candidateId": candidate_id}
    initial = saved_draft("identity-scan", deferred=[named])
    raw = saved_draft("identity-scan", deferred=[raw_row])
    if layout == "worker":
        worker = save_worker(tmp_path, saved_results, "reviewer", [initial, raw], initial)
        workers = [worker]
        output = Path(worker["artifact_dir"])
        os.utime(output / "result.json", ns=(100, 100))
        selected = output / "checkpoints" / f"{saved_results._digest(initial)}.json"
    else:
        workers = []
        output = tmp_path
        write_saved_parent(output, initial, 100)
        checkpoints = [write_checkpoint(output / "checkpoints", draft) for draft in (initial, raw)]
        for index, checkpoint in enumerate(checkpoints, 1):
            os.utime(checkpoint, ns=(index * 100, index * 100))
        selected = checkpoints[0]
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(100, 100))
    first = recover(tmp_path, saved_results, workers)
    replay = recover(tmp_path, saved_results, workers, first[0]["scan"]["preservedSources"])
    for documents in (first, replay):
        pending = [row for row in documents[2]["deferred"] if row["id"] != "scan-stopped"]
        assert pending == [named]
    assert replay[2] == first[2]


@pytest.mark.parametrize("layout", ["parent", "worker"])
@pytest.mark.parametrize("observation", ["generic", "candidate", "finding", "explicit-update"])
def test_abbreviated_observation_keeps_latest_saved_context(
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
    if observation in {"candidate", "finding"}:
        broad[observation] = {"title": "Caller validation.", "evidence": "Both callers."}
        raw_row[observation] = {"title": "Caller validation."}
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
    replay = json.loads((scan_dir / "coverage.json").read_text())
    for coverage in (prepared_coverage[0], replay):
        pending = [row for row in coverage["deferred"] if row["id"] != "scan-stopped"]
        assert pending == [expected]
    assert replay == prepared_coverage[0]
