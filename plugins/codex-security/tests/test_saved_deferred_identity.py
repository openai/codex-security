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
from workbench_test_support import (
    fail_deep_scan,
    preserve_scan_results,
    run_workbench,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
)


@pytest.fixture
def saved_results():
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import workbench_saved_results

    return workbench_saved_results


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


@pytest.mark.parametrize("field", ["disposition", "completeness"])
def test_malformed_coverage_does_not_interrupt_saved_evidence(
    tmp_path: Path, saved_results, field: str
):
    draft = saved_draft("identity-scan", deferred=[{"id": "review", "reason": "Review remains."}])
    if field == "disposition":
        draft["coverage"]["surfaces"] = [
            {"id": "review", "candidateId": "review", "disposition": ["rejected"]}
        ]
    else:
        draft["coverage"]["completeness"] = ["complete"]
    write_saved_parent(tmp_path, draft, 100)
    worker = save_worker(tmp_path, saved_results, "reviewer", [], draft)
    result = recover(tmp_path, saved_results, [worker])
    assert any(row["id"] == "review" for row in result[2]["deferred"])


def test_missing_parent_identity_is_identical_on_frozen_replay(tmp_path: Path, saved_results):
    finding = {
        "ruleId": "fixture.review",
        "title": "Synthetic review finding",
        "summary": "Retain the saved result.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin"},
    }
    draft = saved_draft("identity-scan", findings=[finding])
    write_saved_parent(tmp_path, draft, 100)
    first = recover(tmp_path, saved_results, [])
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (tmp_path / name).unlink()
    replay = recover(tmp_path, saved_results, [], first[0]["scan"]["preservedSources"])
    assert len(first[1]["findings"]) == len(replay[1]["findings"]) == 1
    assert first[1]["findings"][0]["identity"] == replay[1]["findings"][0]["identity"]


@pytest.mark.parametrize("stopped", [False, True])
@pytest.mark.parametrize("saved_anchor", ["stable-anchor", 42])
@pytest.mark.parametrize("explicit_end_line", [False, True])
def test_missing_parent_identity_reuses_established_checkpoint(
    tmp_path: Path, saved_results, stopped, saved_anchor, explicit_end_line
):
    from finalize_scan_contract import _recover_unsealed_findings
    from workbench_test_support import saved_binding

    finding = {
        "ruleId": "fixture.review",
        "title": "Synthetic review finding",
        "summary": "Retain the saved result.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin"},
    }
    checkpoint = write_checkpoint(
        tmp_path / "checkpoints",
        saved_draft(
            "identity-scan",
            complete=True,
            findings=[{**finding, "identity": {"anchor": saved_anchor}}],
        ),
    )
    os.utime(checkpoint, ns=(100, 100))
    if explicit_end_line:
        finding["locations"][0]["endLine"] = 1
    write_saved_parent(
        tmp_path, saved_draft("identity-scan", complete=True, findings=[finding]), 200
    )
    binding = saved_binding()
    binding["target"] = {
        "kind": "git_revision",
        "targetId": "synthetic",
        "displayName": "test",
        "revision": "head",
    }
    warnings = []
    documents = saved_results.merge_saved_results(
        tmp_path, "identity-scan", binding, [], warnings, stopped=stopped, reason="interrupted"
    )
    documents[0]["scan"].update(id="identity-scan", target=binding["target"])
    documents[1]["scanId"] = "identity-scan"
    _recover_unsealed_findings(
        documents[0],
        documents[1],
        Path(__file__).resolve().parents[1] / "schemas",
        tmp_path,
        warnings,
    )
    expected = saved_anchor if isinstance(saved_anchor, str) else "synthetic-review-finding"
    assert [row["identity"] for row in documents[1]["findings"]] == [{"anchor": expected}], warnings


@pytest.mark.parametrize("artifacts", ["omitted", None, []])
@pytest.mark.parametrize("outcome", ["failed", "canceled"])
def test_empty_artifact_envelope_remains_a_recoverable_draft(tmp_path: Path, artifacts, outcome):
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    write_saved_parent(
        scan_dir,
        saved_draft(scan_id, deferred=[{"id": "review", "reason": "Review remains."}]),
        100,
    )
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if artifacts != "omitted":
        manifest["scan"]["artifacts"] = artifacts
    manifest_path.write_text(json.dumps(manifest))
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan_id,
        "--artifact-path",
        "artifacts/review.txt",
        input_text="Synthetic review receipt.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    assert (scan_dir / "artifacts/review.txt").read_text() == "Synthetic review receipt."
    if outcome == "failed":
        fail_deep_scan(state, codex_home, scan_id)
    else:
        run_workbench(
            state,
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment={"CODEX_HOME": str(codex_home)},
        )
    sealed = json.loads(manifest_path.read_text())
    assert sealed["scan"]["status"] == outcome
    assert sealed["scan"]["sealedAt"]
    original = manifest_path.read_bytes()
    if outcome == "failed":
        run_workbench(
            state,
            "recover-scan-results",
            "--scan-id",
            scan_id,
            environment={"CODEX_HOME": str(codex_home)},
        )
    else:
        run_workbench(
            state,
            "preserve-scan-results",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment={"CODEX_HOME": str(codex_home)},
        )
    assert manifest_path.read_bytes() == original


@pytest.mark.parametrize("reason", ["Review remains.", "Unicode review: é \ud800"])
@pytest.mark.parametrize("task_count", [1, 2])
def test_torn_worker_closure_reuses_observed_legacy_identity(
    tmp_path: Path, saved_results, reason: str, task_count: int
) -> None:
    anonymous = {"reason": reason, "paths": ["src/example.py"]}
    identity = "deferred-observed-review"
    named = [
        {
            "id": identity if index == 0 else f"{identity}-{index + 1}",
            "paths": anonymous["paths"],
            "reason": reason,
        }
        for index in range(task_count)
    ]
    normalized = saved_draft("identity-scan", deferred=named)
    worker = save_worker(
        tmp_path,
        saved_results,
        "reviewer",
        [
            saved_draft("identity-scan", deferred=[anonymous.copy() for _ in range(task_count)]),
            normalized,
        ],
        normalized,
    )
    other = save_worker(
        tmp_path,
        saved_results,
        "other",
        [],
        saved_draft("identity-scan", deferred=[{**anonymous, "id": "independent-review"}]),
    )
    output = tmp_path / "reviewer"
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            "identity-scan",
            deferred=named[1:],
            closures=[{"id": identity, "reason": "Review completed."}],
            complete=True,
        ),
    )
    os.utime(checkpoint, ns=(1100, 1100))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(1200, 1200))
    originals = {path: path.read_bytes() for path in output.rglob("*.json")}
    result = recover(tmp_path, saved_results, [worker, other])
    replay = recover(
        tmp_path, saved_results, [worker, other], result[0]["scan"]["preservedSources"]
    )
    for documents in (result, replay):
        assert {row["id"] for row in documents[2]["deferred"]} == {
            "independent-review",
            "scan-stopped",
            *(row["id"] for row in named[1:]),
        }
    assert all(path.read_bytes() == value for path, value in originals.items())


def cancel_and_preserve(monkeypatch, saved_results, state, codex_home, scan_dir, scan_id):
    """Retry publication from frozen sources after the initial write fails."""
    prepared_coverage = []

    def fail_publication(prepared, *, projection_warnings=None):
        prepared_coverage.append(prepared[4])
        raise OSError("injected publication failure")

    with monkeypatch.context() as patch:
        patch.setattr(saved_results, "_write_prepared_scan_finalization", fail_publication)
        call_workbench(patch, state, codex_home, "cancel-scan", "--scan-id", scan_id)
    assert len(prepared_coverage) == 1
    preserve_scan_results(
        state, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
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


def test_accepted_generic_update_keeps_its_id_in_frozen_recovery(tmp_path: Path, saved_results):
    original = {"id": "source-review", "reason": "Review remains.", "paths": ["api.py"]}
    updated = {**original, "reason": "Review the remaining caller.", "paths": ["caller.py"]}
    initial = saved_draft("identity-scan", deferred=[original], complete=True)
    progress = saved_draft("identity-scan", deferred=[updated])
    worker = save_worker(tmp_path, saved_results, "reviewer", [initial, progress], initial)
    output = Path(worker["artifact_dir"])
    result = output / "result.json"
    os.utime(result, ns=(100, 100))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": f"{saved_results._digest(progress)}.json"}))
    os.utime(head, ns=(200, 200))
    originals = {path: path.read_bytes() for path in [result, *output.glob("checkpoints/*.json")]}
    documents = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], documents[0]["scan"]["preservedSources"])
    for document in (documents, replay):
        pending = [row for row in document[2]["deferred"] if row["id"] != "scan-stopped"]
        assert pending == [updated]
    assert replay[2] == documents[2]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


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


@pytest.mark.parametrize("same_title", [False, True])
def test_worker_local_candidates_remain_distinct_on_frozen_recovery(
    tmp_path, saved_results, same_title
):
    finding = {
        "ruleId": "fixture.review",
        "title": "First review",
        "summary": "Retain the saved result.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin", "candidateId": "candidate-1"},
    }
    workers = [
        save_worker(
            tmp_path,
            saved_results,
            worker,
            [],
            saved_draft("identity-scan", findings=[{**finding, "title": title}]),
        )
        for worker, title in [
            ("reviewer-a", "First review"),
            ("reviewer-b", "First review" if same_title else "Second review"),
        ]
    ]
    documents = recover(tmp_path, saved_results, workers)
    replay = recover(tmp_path, saved_results, workers, documents[0]["scan"]["preservedSources"])
    for result in (documents, replay):
        rows = result[1]["findings"]
        assert len(rows) == 2
        assert {row["provenance"]["workerId"] for row in rows} == {"reviewer-a", "reviewer-b"}
        assert len({json.dumps(row["identity"], sort_keys=True) for row in rows}) == 2
    assert documents[1] == replay[1]


@pytest.mark.cross_platform
@pytest.mark.parametrize("revised", [False, True])
def test_recovery_finalization_coalesces_repeated_authored_reports(
    tmp_path, saved_results, revised
):
    from finalize_scan_contract import _recover_unsealed_findings

    first = {
        "ruleId": "fixture.review",
        "title": "Existing report",
        "summary": "Synthetic evidence.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin", "candidateId": "candidate-1"},
        "identity": {"anchor": "shared"},
        "extensions": {"reportId": "report-1"},
    }
    latest = (
        {
            **first,
            "summary": "Synthetic evidence with additional detail.",
            "severity": {"level": "high"},
        }
        if revised
        else first
    )
    draft = saved_draft("identity-scan", findings=[first, latest])
    worker = save_worker(tmp_path, saved_results, "reviewer", [draft], draft)
    manifest, findings, _ = recover(tmp_path, saved_results, [worker])
    manifest["scan"]["id"] = "identity-scan"
    findings["scanId"] = "identity-scan"
    _recover_unsealed_findings(
        manifest, findings, Path(__file__).resolve().parents[1] / "schemas", tmp_path, []
    )
    assert len(findings["findings"]) == 1
    assert findings["findings"][0]["identity"] == first["identity"]
    assert findings["findings"][0]["summary"] == latest["summary"]


@pytest.mark.cross_platform
@pytest.mark.parametrize("identifier", ["reportId", "ledgerRowId"])
@pytest.mark.parametrize("saved_result", [False, True])
def test_recovery_finalization_preserves_distinct_reports_at_a_revised_location(
    tmp_path, saved_results, identifier, saved_result
):
    from finalize_scan_contract import _recover_unsealed_findings

    first = {
        "ruleId": "fixture.review",
        "title": "Existing report",
        "summary": "Synthetic evidence.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 2}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin", "candidateId": "candidate-1"},
        "identity": {"anchor": "shared"},
    }
    independent = {
        **first,
        "title": "Independent report",
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "provenance": {"source": "local_plugin"},
        "extensions": {identifier: "report-2"},
    }
    revised = {
        **first,
        "locations": independent["locations"],
        "extensions": {identifier: "report-1"},
    }
    del revised["identity"]
    drafts = [
        saved_draft("identity-scan", findings=[first]),
        saved_draft("identity-scan", findings=[independent, revised]),
    ]
    output = tmp_path / "reviewer"
    for sequence, draft in enumerate(drafts, 1):
        path = write_checkpoint(output / "checkpoints", draft)
        os.utime(path, ns=(sequence * 1_000_000_000, sequence * 1_000_000_000))
    if saved_result:
        result = output / "result.json"
        result.write_text(json.dumps(drafts[-1]))
        os.utime(result, ns=(3_000_000_000, 3_000_000_000))
    worker = saved_discovery_worker(output, "reviewer")
    sources = {path: path.read_bytes() for path in output.rglob("*.json")}
    documents = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], documents[0]["scan"]["preservedSources"])
    for manifest, findings, _ in (documents, replay):
        # The moved checkpoint revises the existing report without adding a third row.
        assert len(findings["findings"]) == 2
        manifest["scan"]["id"] = "identity-scan"
        findings["scanId"] = "identity-scan"
        warnings = []
        _recover_unsealed_findings(
            manifest,
            findings,
            Path(__file__).resolve().parents[1] / "schemas",
            tmp_path,
            warnings,
        )
        rows = findings["findings"]
        assert {row["extensions"][identifier] for row in rows} == {"report-1", "report-2"}, warnings
        assert len(rows) == 2
        assert all(row["locations"] == independent["locations"] for row in rows)
        assert len({json.dumps(row["identity"], sort_keys=True) for row in rows}) == 2
        existing = next(row for row in rows if row["extensions"][identifier] == "report-1")
        assert any(
            previous["locations"] == first["locations"]
            for previous in existing["provenance"]["previousFindings"]
        )
    assert documents[1] == replay[1]
    assert all(path.read_bytes() == original for path, original in sources.items())


@pytest.mark.parametrize("metadata", ["extensions", "provenance"])
@pytest.mark.parametrize("identifier", ["reportId", "ledgerRowId"])
def test_worker_report_metadata_enrichment_matches_published_identity(
    tmp_path, saved_results, metadata, identifier
):
    first = {
        "ruleId": "fixture.review",
        "title": "Synthetic report",
        "summary": "Retain the saved result.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin"},
        "extensions": {identifier: "report-1"},
    }
    second = {**first, metadata: {**first[metadata], "candidateId": "candidate-1"}}
    drafts = [saved_draft("identity-scan", findings=[value]) for value in (first, second)]
    worker = save_worker(tmp_path, saved_results, "reviewer", drafts, drafts[1])
    documents = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], documents[0]["scan"]["preservedSources"])
    for result in (documents, replay):
        assert len(result[1]["findings"]) == 1
        assert result[1]["findings"][0]["identity"] == {
            "anchor": "candidate-1",
            "instance": "report-1",
        }
    assert documents[1] == replay[1]


@pytest.mark.parametrize("metadata", ["provenance", "extensions"])
def test_parent_represents_worker_versions_before_candidate_enrichment(
    tmp_path, saved_results, metadata
):
    first = {
        "ruleId": "fixture.review",
        "title": "Synthetic review",
        "summary": "Synthetic evidence.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin"},
    }
    latest = {**first, metadata: {**first.get(metadata, {}), "candidateId": "candidate-1"}}
    reduced = {
        **latest,
        "summary": "Consolidated evidence.",
        "provenance": {
            **latest["provenance"],
            "sourceFindingIds": ["reviewer:0"],
            "sourceFindings": [{"id": "reviewer:0", "finding": latest}],
        },
    }
    parent = {**reduced, "identity": {"anchor": "candidate-1"}}
    write_saved_parent(
        tmp_path, saved_draft("identity-scan", findings=[parent], complete=True), 2000
    )
    worker = save_worker(
        tmp_path,
        saved_results,
        "reviewer",
        [saved_draft("identity-scan", findings=[first])],
        saved_draft("identity-scan", findings=[latest], complete=True),
    )
    output = tmp_path / "reducer"
    output.mkdir()
    draft = {"scanId": "identity-scan", "complete": True, "findings": [reduced]}
    result = output / "result.json"
    result.write_text(json.dumps(draft))
    os.utime(result, ns=(1500, 1500))
    checkpoint = write_checkpoint(output / "checkpoints", draft)
    os.utime(checkpoint, ns=(1500, 1500))
    reducer = {
        "id": "reducer",
        "kind": "dedup",
        "status": "succeeded",
        "completed_at": "2026-05-31T18:08:00Z",
        "artifact_dir": str(output),
        "result_manifest_path": str(result),
        "attempt": 1,
    }
    documents = recover(tmp_path, saved_results, [worker, reducer])
    replay = recover(
        tmp_path, saved_results, [worker, reducer], documents[0]["scan"]["preservedSources"]
    )
    for recovered in (documents, replay):
        assert len(recovered[1]["findings"]) == 1
        assert recovered[1]["findings"][0]["summary"] == "Consolidated evidence."
        assert recovered[1]["findings"][0]["identity"] == {"anchor": "candidate-1"}
    assert documents[1] == replay[1]


@pytest.mark.cross_platform
@pytest.mark.parametrize("reversed_rows", [False, True])
@pytest.mark.parametrize("revised_identity", ["explicit", "implicit", "anonymous"])
def test_worker_revision_keeps_assigned_sibling_on_frozen_recovery(
    tmp_path, saved_results, reversed_rows, revised_identity
):
    first = {
        "ruleId": "fixture.review",
        "title": "Synthetic first review",
        "summary": "Original first evidence.",
        "identity": {"anchor": "shared-review", "instance": "first"},
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin", "candidateId": "candidate-1"},
    }
    sibling = {
        **{key: value for key, value in first.items() if key != "identity"},
        "title": "Independent review",
        "summary": "Independent evidence remains active.",
    }
    if revised_identity == "anonymous":
        first.pop("identity")
    original, unchanged = (first, sibling) if revised_identity == "explicit" else (sibling, first)
    revised = {**original, "title": "Revised review", "summary": "Revised evidence."}
    rows = [first, sibling]
    latest_rows = [revised, sibling] if revised_identity == "explicit" else [first, revised]
    if reversed_rows:
        rows.reverse()
        latest_rows.reverse()
    initial = saved_draft("identity-scan", findings=rows)
    latest = saved_draft("identity-scan", findings=latest_rows, complete=True)
    worker = save_worker(tmp_path, saved_results, "reviewer", [initial, latest], initial)
    output = Path(worker["artifact_dir"])
    # Publication stopped after selecting the reconciled checkpoint, before replacing result.json.
    os.utime(output / "result.json", ns=(100, 100))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": f"{saved_results._digest(latest)}.json"}))
    os.utime(head, ns=(300, 300))
    documents = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], documents[0]["scan"]["preservedSources"])
    for result in (documents, replay):
        findings = result[1]["findings"]
        assert len(findings) == (3 if revised_identity == "anonymous" else 2)
        retained = next(row for row in findings if row["title"] == revised["title"])
        assert retained["summary"] == revised["summary"]
        if revised_identity == "explicit":
            assert retained["identity"] == first["identity"]
        assert any(row["summary"] == unchanged["summary"] for row in findings)
        if revised_identity == "anonymous":
            assert any(row["summary"] == original["summary"] for row in findings)
        else:
            assert any(
                row["summary"] == original["summary"]
                for row in retained["provenance"]["previousFindings"]
            )
    assert documents[1] == replay[1]


@pytest.mark.cross_platform
@pytest.mark.parametrize("identifier", ["reportId", "ledgerRowId"])
@pytest.mark.parametrize("reversed_rows", [False, True])
@pytest.mark.parametrize("with_independent", [False, True])
def test_claimed_report_does_not_resolve_an_independent_recovery_match(
    tmp_path, saved_results, identifier, reversed_rows, with_independent
):
    from finalize_scan_contract import _recover_unsealed_findings

    first = {
        "ruleId": "fixture.review",
        "title": "First independent report",
        "summary": "Synthetic evidence.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete the review.",
        "provenance": {"source": "local_plugin"},
        "extensions": {identifier: "report-1"},
    }
    independent = {
        **{key: value for key, value in first.items() if key != "extensions"},
        "title": "Second independent report",
        "locations": [{"path": "src/example.py", "startLine": 2}],
        "provenance": {"source": "local_plugin", "candidateId": "candidate-2"},
    }
    latest = {
        **first,
        "title": "New report at second location",
        "locations": independent["locations"],
        "identity": {"anchor": "new-report"},
    }
    initial_rows = [first, independent] if with_independent else [first]
    latest_rows = [first, latest]
    if reversed_rows:
        initial_rows.reverse()
        latest_rows.reverse()
    initial = saved_draft("identity-scan", findings=initial_rows)
    terminal = saved_draft("identity-scan", findings=latest_rows, complete=True)
    worker = save_worker(tmp_path, saved_results, "reviewer", [initial, terminal], initial)
    output = Path(worker["artifact_dir"])
    os.utime(output / "result.json", ns=(150, 150))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": f"{saved_results._digest(initial)}.json"}))
    os.utime(head, ns=(150, 150))
    sources = {path: path.read_bytes() for path in output.rglob("*.json")}
    documents = recover(tmp_path, saved_results, [worker])
    replay = recover(tmp_path, saved_results, [worker], documents[0]["scan"]["preservedSources"])
    expected = {row["title"] for row in [*initial_rows, latest]}
    for manifest, findings, _ in (documents, replay):
        manifest["scan"]["id"] = "identity-scan"
        findings["scanId"] = "identity-scan"
        warnings = []
        _recover_unsealed_findings(
            manifest,
            findings,
            Path(__file__).resolve().parents[1] / "schemas",
            tmp_path,
            warnings,
        )
        assert {row["title"] for row in findings["findings"]} == expected
        assert len(findings["findings"]) == len(expected)
        assert warnings == []
    assert documents[1] == replay[1]
    assert all(path.read_bytes() == original for path, original in sources.items())


@pytest.mark.parametrize("reverse_checkpoints", [False, True])
def test_latest_eligible_worker_revision_survives_out_of_scope_result(
    tmp_path, saved_results, monkeypatch, reverse_checkpoints
):
    first = {
        "ruleId": "fixture.review",
        "title": "Synthetic review",
        "summary": "Older assessment 0",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic fixture."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "src/example.py", "startLine": 1}],
        "remediation": "Complete review.",
        "provenance": {"source": "local_plugin", "candidateId": "candidate-1"},
        "identity": {"anchor": "stable"},
    }
    latest = {
        **first,
        "summary": "Confirmed newer high severity assessment",
        "severity": {"level": "high"},
    }
    excluded = {
        **latest,
        "summary": "Excluded revision",
        "locations": [{"path": "unselected/example.py", "startLine": 1}],
    }
    worker = save_worker(
        tmp_path,
        saved_results,
        "reviewer",
        [saved_draft("identity-scan", findings=[row]) for row in (first, latest)],
        saved_draft("identity-scan", findings=[excluded]),
    )
    checkpoint_paths = saved_results._checkpoint_paths
    monkeypatch.setattr(
        saved_results,
        "_checkpoint_paths",
        lambda *args: sorted(checkpoint_paths(*args), reverse=reverse_checkpoints),
    )
    binding = {
        "status": "interrupted",
        "allowedTargetKinds": ["git_revision"],
        "target": {
            "kind": "git_revision",
            "targetId": "synthetic",
            "displayName": "Synthetic",
            "revision": "head",
        },
        "scope": {"includePaths": ["src"], "excludePaths": []},
        "coverageMode": "scoped_path",
    }
    frozen = None
    original = None
    for _ in range(2):
        warnings = []
        documents = saved_results.merge_saved_results(
            tmp_path,
            "identity-scan",
            binding,
            [worker],
            warnings,
            stopped=True,
            reason="Synthetic interruption",
            frozen_source_digests=frozen,
        )
        assert documents is not None
        findings = documents[1]["findings"]
        assert len(findings) == 1
        assert findings[0]["summary"] == latest["summary"]
        assert findings[0]["severity"] == latest["severity"]
        assert any(
            row["summary"] == first["summary"]
            for row in findings[0]["provenance"]["previousFindings"]
        )
        assert warnings == ["Skipped out-of-scope finding from reviewer/result.json."]
        assert documents[2]["completeness"] == "partial"
        if original is not None:
            assert documents == original
        original = documents
        frozen = documents[0]["scan"]["preservedSources"]
