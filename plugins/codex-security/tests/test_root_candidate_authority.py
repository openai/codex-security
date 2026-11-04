from __future__ import annotations

import copy
import hashlib
import json
import os
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import (
    read_review_state,
    saved_draft,
    select_checkpoint,
    sort_checkpoint_entries,
    write_checkpoint,
    write_result_draft,
)


def canonical_disposition(scan, disposition, complete_marker):
    findings = copy.deepcopy(scan.findings)
    if disposition == "rejected":
        findings = []
    else:
        field = "provenance" if disposition == "provenance-reported" else "extensions"
        findings[0].setdefault(field, {})["candidateId"] = "candidate-review"
    coverage = {
        **scan.coverage,
        "surfaces": [
            {
                "id": "reviewed-surface",
                "candidateId": "candidate-review",
                "label": "Reviewed surface",
                "disposition": disposition.removeprefix("provenance-"),
                "receiptRefs": [],
            }
        ],
        "deferred": [],
    }
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    if complete_marker:
        manifest["scan"]["complete"] = True
    for name, document in (
        ("scan-manifest.json", manifest),
        ("findings.json", {"findings": findings}),
        ("coverage.json", coverage),
    ):
        path = scan.scan_dir / name
        path.write_text(json.dumps(document))
        os.utime(path, ns=(200, 200))


@pytest.mark.parametrize("disposition", ["reported", "rejected", "provenance-reported"])
@pytest.mark.parametrize("complete_marker", [False, True], ids=["legacy-terminal", "terminal"])
@pytest.mark.parametrize("pending_time", [100, 200, 300], ids=["older", "tied", "newer"])
@pytest.mark.parametrize("flow", ["complete", "prepare", "stop", "interrupted-stop"])
def test_canonical_candidate_resolution_keeps_legacy_checkpoint_authority(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    disposition,
    complete_marker,
    pending_time,
    flow,
):
    scan = publication_scan(mode="standard")
    pending = saved_draft(
        scan.scan_id,
        deferred=[{"candidateId": "candidate-review", "reason": "Validation is pending."}],
    )
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", pending, mtime_ns=pending_time)
    canonical_disposition(scan, disposition, complete_marker)
    original = checkpoint.read_bytes()
    saved = workbench_api["saved_results"]
    prepared_coverage = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_coverage.append(copy.deepcopy(prepared[4]))
        if flow == "interrupted-stop":
            raise OSError("Synthetic candidate publication interruption")
        return write(prepared, **kwargs)

    if flow in {"complete", "prepare"}:
        completed = scan.complete(prepare_only=flow == "prepare")
        assert completed["progress"]["status"] == ("running" if flow == "prepare" else "complete")
    else:
        with monkeypatch.context() as patch:
            patch.setattr(saved, "_write_prepared_scan_finalization", publish)
            scan.fail()
        if flow == "interrupted-stop":
            row = workbench_db.execute(
                "SELECT * FROM scans WHERE id = ?", (scan.scan_id,)
            ).fetchone()
            assert row["retained_source_digests_json"]
            assert row["seal_manifest_digest"] is None
            # A retry must make the same choice from frozen sources, even after a
            # later file-authored draft reopens this candidate.
            late = {**scan.coverage, "deferred": pending["coverage"]["deferred"]}
            (scan.scan_dir / "coverage.json").write_text(json.dumps(late))
        scan.preserve()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert "completeness" not in coverage
    for document in [coverage, *prepared_coverage]:
        assert any(
            row.get("candidateId") == "candidate-review" for row in document["deferred"]
        ) is (pending_time > 200)
        assert any(
            row.get("candidateId") == "candidate-review"
            and row["disposition"] == disposition.removeprefix("provenance-")
            for row in document["surfaces"]
        )
    if flow in {"stop", "interrupted-stop"}:
        before = (scan.scan_dir / "scan-manifest.json").read_bytes()
        recovered = scan.recover()
        assert not recovered["resultsRecoveryNeeded"]
        assert (scan.scan_dir / "scan-manifest.json").read_bytes() == before
        assert read_review_state(workbench_db, scan.scan_dir) == coverage
    assert checkpoint.read_bytes() == original


@pytest.mark.parametrize("disposition", ["reported", "rejected", "provenance-reported"])
def test_accepted_pending_root_tie_survives_canonical_disposition(
    workbench_api, workbench_db, publication_scan, disposition
):
    scan = publication_scan(mode="standard")
    pending = saved_draft(
        scan.scan_id,
        deferred=[{"candidateId": "candidate-review", "reason": "Accepted pending review."}],
    )
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", pending, mtime_ns=100)
    select_checkpoint(scan.scan_dir, checkpoint, mtime_ns=200)
    saved = workbench_api["saved_results"]
    saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    canonical_disposition(scan, disposition, True)
    scan.fail()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert "completeness" not in coverage
    assert any(row.get("candidateId") == "candidate-review" for row in coverage["deferred"])
    scan.recover()
    assert read_review_state(workbench_db, scan.scan_dir) == coverage


@pytest.mark.parametrize("disposition", ["reported", "rejected", "provenance-reported"])
@pytest.mark.parametrize("pending_time", [99, 100, 101], ids=["older", "tied", "newer"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_restored_root_observation_keeps_tied_pending_payload(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    disposition,
    pending_time,
    interrupted,
):
    scan = publication_scan(mode="standard")
    canonical_disposition(scan, disposition, True)
    saved = workbench_api["saved_results"]
    _, terminal = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", terminal, mtime_ns=50)
    for observed in (100, 300, 100):
        select_checkpoint(scan.scan_dir, checkpoint, mtime_ns=observed)
        saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    pending = saved_draft(
        scan.scan_id,
        deferred=[{"candidateId": "candidate-review", "reason": "Review remains pending."}],
    )
    write_checkpoint(scan.scan_dir / "checkpoints", pending, mtime_ns=pending_time)
    prepared_coverage = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_coverage.append(copy.deepcopy(prepared[4]))
        if interrupted:
            raise OSError("Synthetic restored-observation publication interruption")
        return write(prepared, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        scan.fail()
    scan.preserve()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert len(prepared_coverage) == 1
    for document in [coverage, *prepared_coverage]:
        assert any(
            row.get("candidateId") == "candidate-review" for row in document["deferred"]
        ) is (pending_time >= 100)
    scan.recover()
    assert read_review_state(workbench_db, scan.scan_dir) == coverage


@pytest.mark.parametrize(
    "root_complete", [False, True, None], ids=["partial", "terminal", "legacy"]
)
@pytest.mark.parametrize(
    "complete_worker_last", [False, True], ids=["partial-last", "complete-last"]
)
@pytest.mark.parametrize("disposition", ["reported", "rejected"])
@pytest.mark.parametrize("flow", ["stop", "recover"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_root_outcome_uses_its_own_completion_marker(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    root_complete,
    complete_worker_last,
    disposition,
    flow,
    interrupted,
):
    scan = publication_scan()
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    canonical_disposition(scan, disposition, True)
    _, root_draft = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    if root_complete is None:
        root_draft.pop("complete")
    else:
        root_draft["complete"] = root_complete
    for name, document in (
        ("findings.json", {"findings": []}),
        ("coverage.json", scan.coverage),
    ):
        (scan.scan_dir / name).write_text(json.dumps(document))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))

    results = sorted(
        [scan.add_worker(), scan.add_worker()],
        key=lambda path: path.parent.name,
    )
    # Registration timestamps are equal, so IDs determine both arrival orders.
    for result, worker_complete in zip(results, [not complete_worker_last, complete_worker_last]):
        write_result_draft(
            result,
            saved_draft(
                scan.scan_id,
                complete=worker_complete,
            ),
            mtime_ns=100,
        )
    assert [
        row["result_manifest_path"]
        for row in workbench_db.execute(
            "SELECT result_manifest_path FROM deep_scan_workers "
            "WHERE scan_id = ? ORDER BY created_at, id",
            (scan.scan_id,),
        )
    ] == [str(result) for result in results]
    stop_args = Namespace(
        scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."
    )
    if flow == "recover":
        saved.fail_scan(context, workbench_db, stop_args)
    selected = write_checkpoint(scan.scan_dir / "checkpoints", root_draft, mtime_ns=100)
    select_checkpoint(scan.scan_dir, selected, mtime_ns=200)
    pending = write_checkpoint(
        scan.scan_dir / "checkpoints",
        saved_draft(
            scan.scan_id,
            deferred=[{"candidateId": "candidate-review", "reason": "Validation is pending."}],
        ),
        mtime_ns=200,
    )
    originals = {path: path.read_bytes() for path in [selected, pending, *results]}
    prepared_coverage = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_coverage.append(copy.deepcopy(prepared[4]))
        if interrupted:
            raise OSError("Synthetic mixed-source publication interruption")
        return write(prepared, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        if flow == "stop":
            saved.fail_scan(context, workbench_db, stop_args)
        elif interrupted:
            with pytest.raises(OSError, match="Synthetic mixed-source publication interruption"):
                scan.recover()
        else:
            scan.recover()
    published = scan.preserve()
    assert not published["resultsRecoveryNeeded"]
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert len(prepared_coverage) == 1
    for document in [coverage, *prepared_coverage]:
        assert any(
            row.get("candidateId") == "candidate-review" for row in document["deferred"]
        ) is (root_complete is False)
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert read_review_state(workbench_db, scan.scan_dir) == coverage
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("wrapped", [False, True], ids=["flat", "wrapped"])
@pytest.mark.parametrize(
    "recorded_heads", [False, True], ids=["absent-selection", "empty-selection"]
)
@pytest.mark.parametrize("reverse_roots", [False, True])
@pytest.mark.parametrize("reverse_listing", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("later_selection", ["rejected", "pending"])
def test_legacy_tied_root_parent_preserves_accepted_pending_evidence(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    wrapped,
    recorded_heads,
    reverse_roots,
    reverse_listing,
    interrupted,
    later_selection,
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    finding = copy.deepcopy(scan.findings[0])
    finding["extensions"] = {"candidateId": "candidate-review"}
    reported = saved_draft(scan.scan_id, complete=True, findings=[finding])
    rejected = saved_draft(
        scan.scan_id,
        complete=True,
        surfaces=[
            {
                "id": "reviewed-surface",
                "candidateId": "candidate-review",
                "label": "Reviewed surface",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ],
    )
    pending = saved_draft(
        scan.scan_id,
        complete=True,
        deferred=[{"candidateId": "candidate-review", "reason": "Validation remains pending."}],
    )
    roots = [("rejected", rejected), ("pending", pending)]
    if reverse_roots:
        roots.reverse()
    captures = {}
    checkpoints = {}
    head = scan.scan_dir / "checkpoint-head.json"
    for name, draft in [("reported", reported), *roots]:
        draft["coverage"] = {**scan.coverage, **draft["coverage"]}
        checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", draft)
        observed = 100 if name == "reported" else 500
        os.utime(checkpoint, ns=(observed, observed))
        select_checkpoint(scan.scan_dir, checkpoint, mtime_ns=observed)
        captures.update(
            saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
        )
        checkpoints[name] = checkpoint
    head.unlink()
    frozen = {path: digest for path, (digest, _) in captures.items()}
    retained = (
        {
            "sources": frozen,
            "sourceTimes": {path: observed for path, (_, observed) in captures.items()},
        }
        if wrapped
        else frozen
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET status = 'failed', completed_at = ?, retained_source_digests_json = ?, "
            "retained_checkpoint_heads_json = ? WHERE id = ?",
            (scan.timestamp, json.dumps(retained), "{}" if recorded_heads else None, scan.scan_id),
        )
    originals = {path: (scan.scan_dir / path).read_bytes() for path in frozen}
    sort_checkpoint_entries(monkeypatch, reverse=reverse_listing)
    prepared_documents = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_documents.append(copy.deepcopy((prepared[3], prepared[4])))
        if interrupted:
            raise OSError("Synthetic legacy-root publication interruption")
        return write(prepared, **kwargs)

    preserve_args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        if interrupted:
            with pytest.raises(OSError, match="Synthetic legacy-root publication interruption"):
                saved.preserve_scan_results(context, workbench_db, preserve_args)
        else:
            saved.preserve_scan_results(context, workbench_db, preserve_args)
    published = saved.preserve_scan_results(context, workbench_db, preserve_args)["scan"]
    assert published["findingCount"] == 1
    assert not published["resultsRecoveryNeeded"]
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = manifest_path.read_bytes()
    assert json.loads(manifest)["scan"]["preservedCheckpointHeads"] == {}
    findings = json.loads((scan.scan_dir / "findings.json").read_text())
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert len(prepared_documents) == 1
    for current_findings, current_coverage in [(findings, coverage), *prepared_documents]:
        assert len(current_findings["findings"]) == 1
        assert any(
            row.get("candidateId") == "candidate-review" for row in current_coverage["deferred"]
        )
    replayed = scan.recover()
    assert replayed["findingCount"] == 1
    assert not replayed["resultsRecoveryNeeded"]
    before_sources = json.loads(manifest)["scan"]["preservedSources"]
    after_sources = json.loads(manifest_path.read_text())["scan"]["preservedSources"]
    assert before_sources.items() <= after_sources.items()
    added = after_sources.keys() - before_sources.keys()
    # Explicit recovery records ordering missing from flat legacy captures.
    assert len(added) == (0 if wrapped else 1)
    for relative in added:
        assert relative.startswith("source-order/")
        payload = (scan.scan_dir / relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == after_sources[relative]
        assert json.loads(payload) == {
            "scanId": scan.scan_id,
            "sources": {
                path: {"digest": digest, "observedAtNs": str(observed)}
                for path, (digest, observed) in captures.items()
            },
        }
    assert json.loads((scan.scan_dir / "findings.json").read_text()) == findings
    assert read_review_state(workbench_db, scan.scan_dir) == coverage
    if wrapped:
        assert manifest_path.read_bytes() == manifest
    manifest = manifest_path.read_bytes()
    scan.recover()
    assert manifest_path.read_bytes() == manifest

    select_checkpoint(scan.scan_dir, checkpoints[later_selection], mtime_ns=600)
    recovered = scan.recover()
    assert recovered["findingCount"] == (0 if later_selection == "rejected" else 1)
    assert not recovered["resultsRecoveryNeeded"]
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert any(row.get("candidateId") == "candidate-review" for row in coverage["deferred"]) is (
        later_selection == "pending"
    )
    assert all(
        (scan.scan_dir / path).read_bytes() == contents for path, contents in originals.items()
    )


@pytest.mark.parametrize("wrapped", [False, True], ids=["flat", "wrapped"])
@pytest.mark.parametrize("flow", ["preserve", "recover"])
@pytest.mark.parametrize("accepted_first", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("accepted_time", [99, 100, 101], ids=["older", "tied", "newer"])
@pytest.mark.parametrize("identity", ["candidate-only", "explicit", "alias"])
def test_legacy_pending_ties_aggregate_accepted_provenance(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    wrapped,
    flow,
    accepted_first,
    interrupted,
    accepted_time,
    identity,
):
    scan = publication_scan(mode="standard")
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    finding = copy.deepcopy(scan.findings[0])
    finding["extensions"] = {"candidateId": "candidate-review"}
    pending = {"candidateId": "candidate-review", "reason": "Accepted pending review."}
    if identity != "candidate-only":
        pending["id"] = "pending-review" if identity == "alias" else "candidate-review"
    unobserved = {**pending, "reason": "Unobserved pending details."}
    rejected = saved_draft(
        scan.scan_id,
        complete=True,
        surfaces=[
            {
                "id": "reviewed-surface",
                "candidateId": "candidate-review",
                "label": "Reviewed surface",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ],
    )
    observations = [
        (saved_draft(scan.scan_id, findings=[finding], complete=True), 50),
        (saved_draft(scan.scan_id, deferred=[pending]), accepted_time),
        (rejected, 100),
        (
            saved_draft(
                scan.scan_id,
                deferred=[{"id": "independent-review", "reason": "Another task remains."}],
            ),
            200,
        ),
    ]
    captures = {}
    head = scan.scan_dir / "checkpoint-head.json"
    for draft, observed in observations:
        draft["coverage"] = {**scan.coverage, **draft["coverage"]}
        checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", draft, mtime_ns=observed)
        select_checkpoint(scan.scan_dir, checkpoint, mtime_ns=observed)
        captures.update(
            saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
        )
    head.unlink()
    raw = saved_draft(scan.scan_id, deferred=[unobserved])
    raw["coverage"] = {**scan.coverage, **raw["coverage"]}
    unobserved_path = write_checkpoint(scan.scan_dir / "checkpoints", raw, mtime_ns=100)
    captures.update(
        saved._capture_saved_source(
            scan.scan_dir, unobserved_path.relative_to(scan.scan_dir).as_posix(), scan.scan_id
        )
    )
    frozen = {path: digest for path, (digest, _) in captures.items()}
    retained = (
        {
            "sources": frozen,
            "sourceTimes": {path: observed for path, (_, observed) in captures.items()},
        }
        if wrapped
        else frozen
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET status = 'failed', completed_at = ?, retained_source_digests_json = ?, "
            "retained_checkpoint_heads_json = '{}' WHERE id = ?",
            (scan.timestamp, json.dumps(retained), scan.scan_id),
        )
    originals = {path: (scan.scan_dir / path).read_bytes() for path in frozen}
    sort_checkpoint_entries(
        monkeypatch, key=lambda name: (name == unobserved_path.name) == accepted_first
    )
    prepared_documents = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_documents.append(copy.deepcopy((prepared[3], prepared[4])))
        if interrupted:
            raise OSError("Synthetic tied-pending publication interruption")
        return write(prepared, **kwargs)

    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    action = saved.preserve_scan_results if flow == "preserve" else saved.recover_scan_results
    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        if interrupted:
            with pytest.raises(OSError, match="Synthetic tied-pending publication interruption"):
                action(context, workbench_db, args)
        else:
            action(context, workbench_db, args)
    published = saved.preserve_scan_results(context, workbench_db, args)["scan"]
    retained_pending = accepted_time >= 100
    assert published["findingCount"] == int(retained_pending)
    assert not published["resultsRecoveryNeeded"]
    findings = json.loads((scan.scan_dir / "findings.json").read_text())
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert len(prepared_documents) == 1
    for current_findings, current_coverage in [(findings, coverage), *prepared_documents]:
        assert len(current_findings["findings"]) == int(retained_pending)
        candidate_rows = [
            row
            for row in current_coverage["deferred"]
            if row.get("candidateId") == "candidate-review"
        ]
        assert bool(candidate_rows) is retained_pending
        if retained_pending:
            assert pending["reason"] in {row["reason"] for row in candidate_rows}
        assert any(row["id"] == "independent-review" for row in current_coverage["deferred"])
    recovered = saved.recover_scan_results(context, workbench_db, args)["scan"]
    assert recovered["findingCount"] == int(retained_pending)
    assert not recovered["resultsRecoveryNeeded"]
    assert json.loads((scan.scan_dir / "findings.json").read_text()) == findings
    assert read_review_state(workbench_db, scan.scan_dir) == coverage
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = manifest_path.read_bytes()
    saved.recover_scan_results(context, workbench_db, args)
    assert manifest_path.read_bytes() == manifest
    assert all(
        (scan.scan_dir / path).read_bytes() == contents for path, contents in originals.items()
    )
