from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker, complete
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("host_coverage", [True, False], ids=["accepted-projection", "legacy"])
@pytest.mark.parametrize("retry_publication", [False, True], ids=["publish", "retry-publication"])
@pytest.mark.parametrize(
    "parent_draft",
    [True, False, "projected"],
    ids=["parent-draft", "no-parent", "projected-parent"],
)
def test_stopped_recovery_preserves_accepted_coverage_without_worker_id_collisions(
    workbench_api,
    workbench_db,
    publication_scan,
    host_coverage,
    parent_draft,
    retry_publication,
    monkeypatch,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    source_coverage = {
        "completeness": "partial",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "reviews": [],
    }
    source_files = []
    for disposition in ("needs_follow_up", "rejected"):
        result = add_worker(workbench_db, scan)
        worker_id = result.parent.name
        if parent_draft == "projected":
            output = scan.scan_dir / "artifacts" / worker_id / "output"
            output.mkdir(parents=True)
            result = output / "result.json"
            with workbench_db:
                workbench_db.execute(
                    "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? "
                    "WHERE id = ?",
                    (str(output), str(result), worker_id),
                )
        surface = {
            "id": "surface-1",
            "candidateId": "candidate-1",
            "label": "Independent review",
            "disposition": disposition,
            "receiptRefs": [],
        }
        if parent_draft == "projected":
            receipt = result.parent / "artifacts" / "review.txt"
            receipt.parent.mkdir()
            receipt.write_text("Synthetic review evidence.\n")
            surface["receiptRefs"] = ["artifacts/review.txt"]
        deferred = {"candidateId": "candidate-1", "reason": "Validation remains unresolved."}
        coverage = {
            "completeness": "partial" if disposition == "needs_follow_up" else "complete",
            "surfaces": [surface],
            "explicitExclusions": [],
            "deferred": [deferred] if disposition == "needs_follow_up" else [],
        }
        result.write_text(
            json.dumps(
                {"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": coverage}
            )
        )
        source_files.append(result)
        prefix = f"{worker_id}-attempt-1"
        provenance = {"workerId": worker_id, "attempt": 1, "candidateId": "candidate-1"}
        source_coverage["reviews"].append(
            {"workerId": worker_id, "attempt": 1, "completeness": coverage["completeness"]}
        )
        source_coverage["surfaces"].append(
            {
                **surface,
                "id": f"{prefix}-surface-1",
                "receiptRefs": [
                    f"{result.parent.relative_to(scan.scan_dir).as_posix()}/{ref}"
                    for ref in surface["receiptRefs"]
                ],
                "provenance": {**provenance, "sourceId": "surface-1"},
            }
        )
        if coverage["deferred"]:
            source_coverage["deferred"].append(
                {
                    **deferred,
                    "id": f"{prefix}-deferred-1",
                    "candidateId": f"{prefix}-candidate-1",
                    "provenance": provenance,
                }
            )
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
            "WHERE result_manifest_path = ?",
            (str(reducer),),
        )
    aggregate = {"scanId": scan.scan_id, "complete": True, "findings": []}
    if host_coverage:
        aggregate["sourceCoverage"] = copy.deepcopy(source_coverage)
    reducer.write_text(json.dumps(aggregate))
    source_files.append(reducer)
    saved_bytes = {path: path.read_bytes() for path in source_files}
    if parent_draft == "projected":
        (scan.scan_dir / "coverage.json").write_text(json.dumps(source_coverage))
    if not parent_draft:
        for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / filename).unlink()

    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(
                workbench_api["saved_results"],
                "_write_prepared_scan_finalization",
                fail_publication,
            )
        stopped = workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
    if retry_publication:
        assert stopped["resultsRecoveryNeeded"] is True
        frozen = workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
        assert frozen is not None
        if parent_draft == "projected":
            mutable_coverage = copy.deepcopy(source_coverage)
            mutable_coverage["deferred"].append(
                {"id": "outside-frozen-sources", "reason": "Written after sources were frozen."}
            )
            (scan.scan_dir / "coverage.json").write_text(json.dumps(mutable_coverage))
        stopped = workbench_api["recover_scan_results"](
            workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
        assert stopped["resultsRecoveryNeeded"] is False

    assert stopped["progress"]["status"] == "failed"
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert len(coverage["deferred"]) == 2
    assert coverage["deferred"][-1]["id"] == "scan-stopped"
    assert len(coverage["surfaces"]) == 2
    if host_coverage or parent_draft == "projected":
        for field in ("reviews", "surfaces", "deferred"):
            assert (
                coverage[field][:-1] if field == "deferred" else coverage[field]
            ) == source_coverage[field]
        assert all(
            (scan.scan_dir / ref).is_file()
            for surface in coverage["surfaces"]
            for ref in surface["receiptRefs"]
        )
    else:
        assert coverage["deferred"][0]["candidateId"] == "candidate-1"
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    workbench_api["preserve_scan_results"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())


@pytest.mark.parametrize("review_source", ["reducer", "parent"])
@pytest.mark.parametrize(
    "pending_state", ["canceled", "unreviewed", "new-attempt", "unmerged", "merged"]
)
def test_stopped_recovery_keeps_unmerged_coverage_after_accepted_review(
    workbench_api, workbench_db, publication_scan, review_source, pending_state
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    accepted = add_worker(workbench_db, scan)
    accepted.write_text(
        json.dumps(
            {"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": scan.coverage}
        )
    )
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
            "WHERE result_manifest_path = ?",
            (str(reducer),),
        )
    reviews = [{"workerId": accepted.parent.name, "attempt": 1, "completeness": "complete"}]
    pending = add_worker(
        workbench_db, scan, status="canceled" if pending_state == "canceled" else "succeeded"
    )
    if pending_state != "unreviewed":
        reviews.append({"workerId": pending.parent.name, "attempt": 1, "completeness": "partial"})
    if pending_state in {"new-attempt", "unmerged"}:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET attempt = ?, merge_state = ? "
                "WHERE result_manifest_path = ?",
                (
                    2 if pending_state == "new-attempt" else 1,
                    "none" if pending_state == "unmerged" else "merged",
                    str(pending),
                ),
            )
    aggregate = {"scanId": scan.scan_id, "complete": True, "findings": []}
    if review_source == "reducer":
        aggregate["sourceCoverage"] = {**scan.coverage, "reviews": reviews}
    else:
        (scan.scan_dir / "coverage.json").write_text(
            json.dumps({**scan.coverage, "reviews": reviews})
        )
    reducer.write_text(json.dumps(aggregate))
    deferred = {"id": "pending-review", "reason": "The independent review remains unresolved."}
    pending.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": False,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "deferred": [deferred]},
            }
        )
    )

    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["reviews"] == reviews
    if pending_state == "merged":
        retained = next(
            item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]
        )
        assert retained["provenance"] == {
            "workerId": pending.parent.name,
            "attempt": 1,
            "sourceId": deferred["id"],
        }
    else:
        assert deferred in coverage["deferred"]


@pytest.mark.parametrize("stopped", [False, True], ids=["completion", "recovery"])
@pytest.mark.parametrize(
    "provenance",
    [
        {"candidateId": ["candidate-1"]},
        {"candidateId": {"value": "candidate-1"}},
        {"workerId": ["worker-1"], "candidateId": "candidate-1"},
        {"workerId": {"value": "worker-1"}, "candidateId": "candidate-1"},
        {"workerId": 1, "candidateId": 2},
        {"workerId": "worker-1", "candidateId": "candidate-1"},
    ],
    ids=[
        "list-candidate",
        "object-candidate",
        "list-worker",
        "object-worker",
        "numbers",
        "strings",
    ],
)
def test_standard_publication_preserves_uninterpreted_coverage_provenance(
    workbench_api, workbench_db, publication_scan, stopped, provenance
):
    scan = publication_scan(mode="standard")
    deferred = {
        "id": "remaining-review",
        "reason": "Another surface remains.",
        "provenance": provenance,
    }
    scan.coverage.update(completeness="partial", deferred=[deferred])
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))

    if stopped:
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
        published = workbench_api["recover_scan_results"](
            workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
    else:
        published = complete(workbench_api, workbench_db, scan)

    assert published["resultsRecoveryNeeded"] is False
    assert published["findingCount"] == 1
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert deferred in coverage["deferred"]
    assert (scan.scan_dir / "report.md").is_file()


@pytest.mark.parametrize(
    "provenance, pending",
    [
        ({"candidateId": ["candidate-1"]}, False),
        ({"workerId": ["worker-1"], "candidateId": "candidate-1"}, False),
        ({"workerId": "worker-1", "candidateId": "candidate-1"}, False),
    ],
    ids=["local-candidate", "local-worker", "descriptive-worker"],
)
def test_standard_recovery_resolves_local_candidates_with_uninterpreted_provenance(
    workbench_api, workbench_db, publication_scan, provenance, pending
):
    scan = publication_scan(mode="standard")
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = False
    manifest_path.write_text(json.dumps(manifest))
    scan.coverage["surfaces"][0]["candidateId"] = "candidate-1"
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    deferred = {
        "id": "older-review",
        "candidateId": "candidate-1",
        "reason": "Earlier validation remained unresolved.",
        "provenance": provenance,
    }
    write_checkpoint(
        scan.scan_dir / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {"completeness": "partial", "surfaces": [], "deferred": [deferred]},
        },
    )

    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert (deferred in coverage["deferred"]) is pending


@pytest.mark.parametrize("retry_publication", [False, True])
def test_partial_parent_projection_keeps_only_missing_worker_records(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    output = scan.scan_dir / "artifacts" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    receipt = output / "artifacts" / "evidence.txt"
    receipt.parent.mkdir()
    receipt.write_text("Retained source review evidence.\n")
    surface = {
        "id": "missing-review",
        "label": "Missing source projection",
        "disposition": "needs_follow_up",
        "receiptRefs": ["artifacts/evidence.txt"],
    }
    pending = [
        {"id": "one", "reason": "First proof remains unresolved."},
        {"id": "two", "reason": "Second proof remains unresolved."},
    ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "deferred": pending,
                    "surfaces": [surface],
                },
            }
        )
    )
    projected = {
        **pending[0],
        "id": f"{worker_id}-attempt-1-deferred-1",
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "one"},
    }
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "deferred": [projected],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
            }
        )
    )
    original = result.read_bytes()
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(
                workbench_api["saved_results"],
                "_write_prepared_scan_finalization",
                fail_publication,
            )
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert sorted(
        item["reason"] for item in coverage["deferred"] if item["id"] != "scan-stopped"
    ) == sorted(item["reason"] for item in pending)
    assert result.read_bytes() == original
    retained_surface = next(
        item for item in coverage["surfaces"] if item["label"] == surface["label"]
    )
    assert retained_surface["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()]
    assert receipt.read_text() == "Retained source review evidence.\n"


@pytest.mark.parametrize("retry_publication", [False, True])
def test_standard_recovery_keeps_distinct_candidate_with_descriptive_provenance(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry_publication
):
    scan = publication_scan(mode="standard")
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = False
    manifest_path.write_text(json.dumps(manifest))
    scan.coverage["surfaces"][0]["candidateId"] = "candidate-A"
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    deferred = {
        "id": "distinct-review",
        "candidateId": "candidate-B",
        "reason": "Independent validation remains unresolved.",
        "provenance": {"candidateId": "candidate-A", "description": "Related earlier review."},
    }
    checkpoint = write_checkpoint(
        scan.scan_dir / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [deferred],
            },
        },
    )
    original = checkpoint.read_bytes()
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(
                workbench_api["saved_results"],
                "_write_prepared_scan_finalization",
                fail_publication,
            )
        stopped = workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
    assert stopped["resultsRecoveryNeeded"] is retry_publication
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    assert recovered["findingCount"] == 1
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert deferred in coverage["deferred"]
    assert coverage["completeness"] == "partial"
    assert checkpoint.read_bytes() == original
    published = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    assert deferred["reason"] in published["report.md"].decode()
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert all((scan.scan_dir / name).read_bytes() == data for name, data in published.items())
    assert checkpoint.read_bytes() == original


def test_deep_recovery_reconciles_recognized_projected_candidates(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = False
    manifest_path.write_text(json.dumps(manifest))
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    deferred = [
        {"id": candidate, "candidateId": candidate, "reason": f"Review {candidate}."}
        for candidate in ("candidate-A", "candidate-B")
    ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "deferred": deferred},
            }
        )
    )
    original = result.read_bytes()
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
                "surfaces": [
                    {
                        "id": f"{worker_id}-attempt-1-surface-1",
                        "label": "Resolved review",
                        "candidateId": f"{worker_id}-attempt-1-candidate-1",
                        "disposition": "rejected",
                        "receiptRefs": [],
                        "provenance": {
                            "workerId": worker_id,
                            "attempt": 1,
                            "candidateId": "candidate-A",
                        },
                    }
                ],
            }
        )
    )
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item["id"] != "scan-stopped"]
    assert len(pending) == 1
    assert pending[0]["provenance"]["candidateId"] == "candidate-B"
    assert pending[0]["provenance"]["workerId"] == worker_id
    assert result.read_bytes() == original
