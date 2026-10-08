from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import add_worker, complete
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("scope", [".", "subdir"])
@pytest.mark.parametrize("other_outcome", ["rejected", "reported"])
@pytest.mark.parametrize("host_coverage", [True, False], ids=["accepted-projection", "legacy"])
@pytest.mark.parametrize("retry_publication", [False, True], ids=["publish", "retry-publication"])
@pytest.mark.parametrize(
    "parent_draft",
    [True, False, "projected", "interrupted"],
    ids=["parent-draft", "no-parent", "projected-parent", "interrupted-parent"],
)
def test_stopped_recovery_preserves_accepted_coverage_without_worker_id_collisions(
    workbench_api,
    workbench_db,
    publication_scan,
    host_coverage,
    scope,
    other_outcome,
    parent_draft,
    retry_publication,
    monkeypatch,
    archived=False,
):
    scan = publication_scan(scope=scope)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = ? WHERE scan_id = ?",
            ("deep-security-scan/v2" if host_coverage else "deep-scan-mcp/v1", scan.scan_id),
        )
    projected_parent = parent_draft in ("projected", "interrupted")
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    source_coverage = {
        "completeness": "partial",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "reviews": [],
    }
    source_files = []
    aggregate_findings = []
    for disposition in ("needs_follow_up", other_outcome):
        result = add_worker(workbench_db, scan)
        worker_id = result.parent.name
        if projected_parent:
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
        if projected_parent:
            receipt = result.parent / "artifacts" / "review.txt"
            receipt.parent.mkdir()
            receipt.write_text("Synthetic review evidence.\n")
            surface["receiptRefs"] = ["artifacts/review.txt"]
            source_files.append(receipt)
        deferred = {"candidateId": "candidate-1", "reason": "Validation remains unresolved."}
        coverage = {
            "completeness": "partial" if disposition == "needs_follow_up" else "complete",
            "surfaces": [surface],
            "explicitExclusions": [],
            "deferred": [deferred] if disposition == "needs_follow_up" else [],
            "reviews": [{"workerId": "other-worker", "attempt": 99, "completeness": "complete"}],
        }
        findings = []
        if disposition == "reported":
            finding = copy.deepcopy(scan.findings[0])
            finding["provenance"]["candidateId"] = "candidate-1"
            finding["provenance"]["workerId"] = worker_id
            findings.append(finding)
            aggregate_findings.extend(findings)
        result.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": True,
                    "findings": findings,
                    "coverage": coverage,
                }
            )
        )
        if archived:
            archive = result.parent.parent / "attempts" / "attempt-01"
            archive.parent.mkdir(parents=True)
            shutil.move(result.parent, archive)
            output = result.parent
            output.mkdir()
            (output / "result.json").write_text(
                json.dumps(
                    {
                        "scanId": scan.scan_id,
                        "complete": True,
                        "findings": [],
                        "coverage": {
                            "completeness": "partial",
                            "surfaces": [],
                            "explicitExclusions": [],
                            "deferred": [],
                        },
                    }
                )
            )
            source_files.append(output / "result.json")
            result = archive / "result.json"
            receipt = archive / "artifacts" / "review.txt"
            source_files[-2] = receipt
            with workbench_db:
                workbench_db.execute(
                    "UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,)
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
    aggregate = {"scanId": scan.scan_id, "complete": True, "findings": aggregate_findings}
    if host_coverage:
        aggregate["sourceCoverage"] = copy.deepcopy(source_coverage)
    reducer.write_text(json.dumps(aggregate))
    source_files.append(reducer)
    saved_bytes = {path: path.read_bytes() for path in source_files}
    if parent_draft == "projected":
        (scan.scan_dir / "coverage.json").write_text(
            json.dumps({**scan.coverage, **source_coverage})
        )
    if not parent_draft:
        for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / filename).unlink()
    if parent_draft == "interrupted":
        for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
            os.utime(scan.scan_dir / filename, ns=(100, 100))
        coverage_path = scan.scan_dir / "coverage.json"
        old_coverage = coverage_path.read_bytes()
        staged = scan.scan_dir / "drafts" / "00000000-0000-4000-8000-000000000000.json"
        staged.parent.mkdir()
        staged.write_text(
            json.dumps(
                {
                    "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
                    "findings": {"findings": aggregate_findings},
                    "coverage": {**scan.coverage, **source_coverage},
                }
            )
        )
        saved_results = workbench_api["saved_results"]
        write_bytes = saved_results.write_scan_local_bytes

        def interrupt_coverage(root, relative, contents):
            if relative == "coverage.json":
                raise OSError("Synthetic parent coverage interruption.")
            write_bytes(root, relative, contents)

        with monkeypatch.context() as interrupted:
            interrupted.setattr(saved_results, "write_scan_local_bytes", interrupt_coverage)
            with pytest.raises(OSError, match="Synthetic parent coverage interruption"):
                saved_results.write_scan_draft(
                    workbench_api["_WORKBENCH_DB_CONTEXT"],
                    workbench_db,
                    Namespace(
                        scan_id=scan.scan_id,
                        claim_token=None,
                        draft_path=str(staged),
                        checkpoint_path=None,
                        expected_draft_digest=None,
                    ),
                )
        head_path = scan.scan_dir / "checkpoint-head.json"
        checkpoint = scan.scan_dir / "checkpoints" / json.loads(head_path.read_text())["checkpoint"]
        assert coverage_path.read_bytes() == old_coverage
        assert head_path.stat().st_mtime_ns > coverage_path.stat().st_mtime_ns
        assert (
            json.loads(checkpoint.read_text())["coverage"]["reviews"] == source_coverage["reviews"]
        )
        saved_bytes.update({path: path.read_bytes() for path in (head_path, checkpoint)})

    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(
                workbench_api["saved_results"],
                "_write_prepared_scan_finalization",
                fail_publication,
            )
        stopped = workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
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
        stopped = workbench_api["saved_results"].recover_scan_results(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
        assert stopped["resultsRecoveryNeeded"] is False

    assert stopped["progress"]["status"] == "failed"
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["mode"] == ("scoped_path" if scope != "." else "deep_repository")
    assert coverage["inventoryStrategy"] == ("scoped_path" if scope != "." else "repository")
    assert len(coverage["deferred"]) == 2, json.dumps(coverage)
    assert coverage["deferred"][-1]["id"] == "scan-stopped"
    assert len(coverage["surfaces"]) == 2
    assert all(review["workerId"] != "other-worker" for review in coverage.get("reviews", []))
    if host_coverage or projected_parent:
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
    workbench_api["saved_results"].preserve_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())


@pytest.mark.parametrize("review_source", ["reducer", "parent"])
@pytest.mark.parametrize(
    "pending_state",
    ["canceled", "unreviewed", "new-attempt", "unmerged", "merging", "buffered", "merged"],
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
    if pending_state in {"new-attempt", "unmerged", "merging", "buffered"}:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET attempt = ?, merge_state = ? "
                "WHERE result_manifest_path = ?",
                (
                    2 if pending_state == "new-attempt" else 1,
                    "none"
                    if pending_state == "unmerged"
                    else "merged"
                    if pending_state == "new-attempt"
                    else pending_state,
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
    if pending_state == "new-attempt":
        old_projection = {
            **deferred,
            "id": f"{pending.parent.name}-attempt-1-deferred-1",
            "provenance": {
                "workerId": pending.parent.name,
                "attempt": 1,
                "sourceId": deferred["id"],
            },
        }
        if review_source == "reducer":
            aggregate["sourceCoverage"]["deferred"] = [old_projection]
            reducer.write_text(json.dumps(aggregate))
        else:
            (scan.scan_dir / "coverage.json").write_text(
                json.dumps({**scan.coverage, "reviews": reviews, "deferred": [old_projection]})
            )
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

    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
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
        workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
        published = workbench_api["saved_results"].recover_scan_results(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
    else:
        published = complete(workbench_api, workbench_db, scan)

    assert published["resultsRecoveryNeeded"] is False
    assert published["findingCount"] == 1
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert deferred in coverage["deferred"]
    assert (scan.scan_dir / "report.md").is_file()


@pytest.mark.parametrize("finding_state", ["valid", "empty", "invalid"])
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
    workbench_api, workbench_db, publication_scan, provenance, pending, finding_state
):
    scan = publication_scan(mode="standard")
    if finding_state != "valid":
        (scan.scan_dir / "findings.json").write_text(
            json.dumps(
                {"findings": [] if finding_state == "empty" else [{"candidateId": "candidate-1"}]}
            )
        )
        pending = True
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

    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert (deferred in coverage["deferred"]) is pending


@pytest.mark.parametrize("retry_publication", [False, True])
@pytest.mark.parametrize("archived", [False, True])
@pytest.mark.parametrize("candidate_tagged", [False, True])
@pytest.mark.parametrize("duplicate_surface", [False, True])
def test_partial_parent_projection_keeps_only_missing_worker_records(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    retry_publication,
    archived,
    candidate_tagged,
    duplicate_surface,
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
    if duplicate_surface:
        pending[1]["surfaceIds"] = [surface["id"]]
    if candidate_tagged:
        for item in pending:
            item["candidateId"] = item["id"]
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
                    "surfaces": [surface, {**surface, "label": "Other same-ID source review"}]
                    if duplicate_surface
                    else [surface],
                },
            }
        )
    )
    if archived:
        prior = output.parent / "attempts" / "attempt-01" / "result.json"
        prior.parent.mkdir(parents=True)
        prior.write_bytes(result.read_bytes())
        archived_receipt = prior.parent / "artifacts" / "evidence.txt"
        archived_receipt.parent.mkdir()
        archived_receipt.write_bytes(receipt.read_bytes())
        receipt = archived_receipt
        current = json.loads(result.read_text())
        current["coverage"]["surfaces"][0]["receiptRefs"] = [
            receipt.relative_to(scan.scan_dir).as_posix()
        ]
        result.write_text(json.dumps(current))
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,)
            )
    reviews = [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}]
    if archived:
        reviews.append({"workerId": worker_id, "attempt": 2, "completeness": "partial"})
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
                "reviews": reviews,
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
        workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert sorted(
        item["reason"] for item in coverage["deferred"] if item["id"] != "scan-stopped"
    ) == sorted(item["reason"] for item in pending)
    assert all(
        item["provenance"]["attempt"] == 1
        for item in coverage["deferred"]
        if item["id"] != "scan-stopped"
    )
    assert result.read_bytes() == original
    retained_surface = next(
        item
        for item in coverage["surfaces"]
        if item["label"] == surface["label"] and isinstance(item.get("provenance"), dict)
    )
    assert retained_surface["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()]
    assert retained_surface["provenance"]["attempt"] == 1
    if duplicate_surface:
        second_gap = next(
            item for item in coverage["deferred"] if item.get("reason") == pending[1]["reason"]
        )
        assert set(second_gap["surfaceIds"]) == {
            item["id"]
            for item in coverage["surfaces"]
            if item.get("provenance", {}).get("sourceId") == surface["id"]
        }
        assert len(second_gap["surfaceIds"]) == 2
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
        stopped = workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
    assert stopped["resultsRecoveryNeeded"] is retry_publication
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
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
    workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )
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
    documents = {
        "manifest": json.loads(manifest_path.read_text()),
        "findings": {"findings": []},
        "coverage": json.loads((scan.scan_dir / "coverage.json").read_text()),
    }
    staged = scan.scan_dir / "drafts" / f"{scan.scan_id}.json"
    staged.parent.mkdir(exist_ok=True)
    staged.write_text(json.dumps(documents))
    workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            draft_path=str(staged),
            checkpoint_path=None,
            expected_draft_digest=None,
        ),
    )
    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item["id"] != "scan-stopped"]
    assert len(pending) == 1
    assert pending[0]["provenance"]["candidateId"] == "candidate-B"
    assert pending[0]["provenance"]["workerId"] == worker_id
    assert result.read_bytes() == original


@pytest.mark.parametrize(
    "prior_receipt,merge_state",
    [
        (False, "merged"),
        ("carried", "merged"),
        ("omitted", "merged"),
        (False, "merging"),
        (False, "buffered"),
    ],
)
@pytest.mark.parametrize("projection_source", ["parent", "reducer"])
def test_generic_closeout_preserves_projected_surface_receipts(
    workbench_api, workbench_db, publication_scan, projection_source, prior_receipt, merge_state
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = ? WHERE id = ?", (merge_state, worker_id)
        )
    output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    receipt = result.parent / "artifacts" / "review.txt"
    receipt.parent.mkdir()
    receipt.write_text("Synthetic completed review.\n")
    surface = {
        "id": "reviewed-surface",
        "label": "Independent review",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/review.txt"],
    }
    prior_surface = {**surface, "disposition": "needs_follow_up"}
    checkpoint_root = result.parent / "checkpoints"
    attempt = 1
    if prior_receipt:
        attempt = 2
        archive = output.parent / "attempts" / "attempt-01"
        checkpoint_root = archive / "checkpoints"
        previous_receipt = archive / "artifacts" / "prior.txt"
        previous_receipt.parent.mkdir(parents=True)
        previous_receipt.write_text("Prior synthetic review.\n")
        prior_surface["receiptRefs"] = ["artifacts/prior.txt"]
        if prior_receipt == "carried":
            surface["receiptRefs"].append(previous_receipt.relative_to(scan.scan_dir).as_posix())
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,)
            )
    pending_checkpoint = write_checkpoint(
        checkpoint_root,
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [prior_surface],
                "deferred": [
                    {"id": "review", "reason": "Review remains.", "surfaceIds": [surface["id"]]}
                ],
            },
        },
    )
    os.utime(pending_checkpoint, ns=(100, 100))
    source = {
        "completeness": "complete",
        "surfaces": [surface],
        "explicitExclusions": [],
        "deferred": [],
        "resolvedDeferred": [{"id": "review", "reason": "Review completed."}],
    }
    result.write_text(
        json.dumps({"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": source})
    )
    os.utime(result, ns=(200, 200))
    projected = {
        **surface,
        "id": f"{worker_id}-attempt-{attempt}-surface-1",
        "receiptRefs": [receipt.relative_to(scan.scan_dir).as_posix(), *surface["receiptRefs"][1:]],
        "provenance": {"workerId": worker_id, "attempt": attempt, "sourceId": surface["id"]},
    }
    projection = {
        "completeness": "complete",
        "surfaces": [projected],
        "explicitExclusions": [],
        "deferred": [],
        "reviews": [{"workerId": worker_id, "attempt": attempt, "completeness": "complete"}],
    }
    if projection_source == "parent":
        (scan.scan_dir / "coverage.json").write_text(json.dumps(projection))
    else:
        reducer = add_worker(workbench_db, scan)
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE result_manifest_path = ?",
                (str(reducer),),
            )
        reducer.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": True,
                    "findings": [],
                    "sourceCoverage": projection,
                }
            )
        )
    if prior_receipt == "omitted":
        projected["receiptRefs"].append(previous_receipt.relative_to(scan.scan_dir).as_posix())
    saved = {file: file.read_bytes() for file in (scan.scan_dir / "artifacts").rglob("*.json")}
    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    for replay in (False, True):
        if replay:
            workbench_api["saved_results"].recover_scan_results(
                workbench_api["_WORKBENCH_DB_CONTEXT"],
                workbench_db,
                Namespace(scan_id=scan.scan_id),
            )
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert coverage["surfaces"] == [projected]
        assert len(coverage["deferred"]) == 1
        assert coverage["deferred"][0]["id"] == "scan-stopped"
        assert (
            scan.scan_dir / coverage["surfaces"][0]["receiptRefs"][0]
        ).read_text() == "Synthetic completed review.\n"
        assert all(file.read_bytes() == contents for file, contents in saved.items())


@pytest.mark.parametrize("projection_source", ["parent", "reducer", "checkpoint"])
@pytest.mark.parametrize(
    "retained,merge_state",
    [
        (False, "merged"),
        (True, "merged"),
        ("changed", "merged"),
        ("changed-surface", "merged"),
        ("same-attempt-changed-surface", "merged"),
        ("same-attempt-receipts", "merged"),
        ("same-attempt-multiple", "merged"),
        (True, "merging"),
        (True, "buffered"),
    ],
    ids=[
        "missing-projection",
        "retained-projection",
        "changed-projection",
        "changed-surface",
        "same-attempt-changed-surface",
        "same-attempt-receipts",
        "same-attempt-multiple",
        "merging-projection",
        "buffered-projection",
    ],
)
def test_reopened_generic_work_uses_worker_projection(
    workbench_api,
    workbench_db,
    publication_scan,
    projection_source,
    retained,
    merge_state,
    monkeypatch,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    if retained == "same-attempt-receipts":
        output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
        output.mkdir(parents=True)
        result = output / "result.json"
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
                (str(output), str(result), worker_id),
            )
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = ? WHERE id = ?", (merge_state, worker_id)
        )
    surface = {
        "id": "surface",
        "label": "Reopened review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    pending = {
        "id": "review",
        "reason": "A later observation reopens this review.",
        "surfaceIds": ["surface"],
    }
    prior_surfaces = []
    if retained == "same-attempt-receipts":
        (result.parent / "artifacts").mkdir()
        for name in ("current.txt", "prior.txt"):
            (result.parent / "artifacts" / name).write_text(f"Synthetic {name} receipt.\n")
        surface["receiptRefs"] = ["artifacts/current.txt"]
        prior_surfaces = [
            {**surface, "disposition": "no_issue_found", "receiptRefs": ["artifacts/prior.txt"]}
        ]
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": [],
            "coverage": {
                "completeness": "complete",
                "surfaces": prior_surfaces,
                "explicitExclusions": [],
                "deferred": [],
                "resolvedDeferred": []
                if retained == "same-attempt-multiple"
                else [{"id": "review", "reason": "Earlier review completed."}],
            },
        },
    )
    os.utime(checkpoint, ns=(100, 100))
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    "completeness": "partial",
                    "surfaces": [surface],
                    "explicitExclusions": [],
                    "deferred": [pending],
                },
            }
        )
    )
    os.utime(result, ns=(200, 200))
    if retained == "same-attempt-multiple":
        intermediate = json.loads(result.read_text())
        intermediate["complete"] = False
        intermediate["coverage"]["surfaces"][0]["label"] = "Intermediate review"
        intermediate["coverage"]["deferred"][0].update(
            id="intermediate", reason="Intermediate review remains."
        )
        saved_intermediate = write_checkpoint(result.parent / "checkpoints", intermediate)
        os.utime(saved_intermediate, ns=(150, 150))
        current = json.loads(result.read_text())
        current["complete"] = False
        equal = write_checkpoint(result.parent / "checkpoints", current)
        os.utime(equal, ns=(200, 200))
        result.unlink()
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET result_manifest_path = NULL WHERE id = ?",
                (worker_id,),
            )
    attempt = 2 if retained == "changed-surface" else 1
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = ? WHERE id = ?", (attempt, worker_id)
        )
    provenance = {"workerId": worker_id, "attempt": attempt}
    projected_surface = {
        **surface,
        "id": f"{worker_id}-attempt-{attempt}-surface-1",
        "provenance": {**provenance, "sourceId": "surface"},
    }
    if retained == "same-attempt-receipts":
        projected_surface["receiptRefs"] = [
            (result.parent / "artifacts/current.txt").relative_to(scan.scan_dir).as_posix(),
            (result.parent / "artifacts/prior.txt").relative_to(scan.scan_dir).as_posix(),
        ]
    projected_pending = {
        **pending,
        "id": f"{worker_id}-attempt-{attempt}-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {**provenance, "sourceId": "review"},
    }
    previous_pending = {**projected_pending, "reason": "An earlier distinct observation."}
    projection = {
        "completeness": "partial",
        "surfaces": [projected_surface],
        "explicitExclusions": [],
        "deferred": [previous_pending if retained == "changed" else projected_pending]
        if retained
        else [],
        "reviews": [{**provenance, "completeness": "partial"}],
    }
    if retained in (
        "changed-surface",
        "same-attempt-changed-surface",
        "same-attempt-receipts",
        "same-attempt-multiple",
    ):
        previous_surface = {
            **projected_surface,
            "id": f"{worker_id}-attempt-1-surface-1",
            "label": "Earlier review",
            "provenance": {**projected_surface["provenance"], "attempt": 1},
        }
        previous_pending = {
            **previous_pending,
            "id": f"{worker_id}-attempt-1-deferred-1",
            "surfaceIds": [previous_surface["id"]],
            "provenance": {**previous_pending["provenance"], "attempt": 1},
        }
        projection["surfaces"] = [previous_surface]
        projection["deferred"] = [previous_pending]
        projection["reviews"].append(
            {"workerId": worker_id, "attempt": 1, "completeness": "partial"}
        )
    if projection_source == "parent":
        (scan.scan_dir / "coverage.json").write_text(json.dumps(projection))
    else:
        reducer = add_worker(workbench_db, scan)
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE result_manifest_path = ?",
                (str(reducer),),
            )
        reducer.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": True,
                    "findings": [],
                    "sourceCoverage": projection,
                }
            )
        )
    if projection_source == "checkpoint":
        write_checkpoint(reducer.parent / "checkpoints", json.loads(reducer.read_text()))
        reducer.unlink()
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET status = 'failed', result_manifest_path = NULL "
                "WHERE artifact_dir = ?",
                (str(reducer.parent),),
            )
        assert not reducer.exists()
        state = workbench_db.execute(
            "SELECT status, result_manifest_path FROM deep_scan_workers WHERE artifact_dir = ?",
            (str(reducer.parent),),
        ).fetchone()
        assert tuple(state) == ("failed", None)
    saved = {
        path: path.read_bytes()
        for directory in (scan.scan_dir / "workers", scan.scan_dir / "artifacts")
        for path in directory.rglob("*")
        if path.is_file()
    }
    with monkeypatch.context() as interrupted:

        def fail_publication(*args, **kwargs):
            raise OSError("Synthetic publication interruption.")

        interrupted.setattr(
            workbench_api["saved_results"], "_write_prepared_scan_finalization", fail_publication
        )
        stopped = workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
    assert stopped["resultsRecoveryNeeded"] is True
    frozen_merges = []
    merge = workbench_api["saved_results"].merge_saved_results

    def observe_merge(*args, **kwargs):
        frozen_merges.append(kwargs.get("frozen_source_digests"))
        return merge(*args, **kwargs)

    monkeypatch.setattr(workbench_api["saved_results"], "merge_saved_results", observe_merge)
    for _ in range(2):
        recovered = workbench_api["saved_results"].recover_scan_results(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
        assert recovered["resultsRecoveryNeeded"] is False
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        if retained in (
            "same-attempt-changed-surface",
            "same-attempt-receipts",
            "same-attempt-multiple",
        ):
            assert len(coverage["surfaces"]) == (3 if retained == "same-attempt-multiple" else 2)
            assert len({row["id"] for row in coverage["surfaces"]}) == len(coverage["surfaces"])
            assert (
                next(
                    row for row in coverage["surfaces"] if row["label"] == previous_surface["label"]
                )
                == previous_surface
            )
            recovered_surface = next(
                row for row in coverage["surfaces"] if row["label"] == surface["label"]
            )
            assert recovered_surface["id"] != previous_surface["id"]
            assert {key: value for key, value in recovered_surface.items() if key != "id"} == {
                key: value for key, value in projected_surface.items() if key != "id"
            }
        elif retained == "changed-surface":
            assert len(coverage["surfaces"]) == 2
            assert projected_surface in coverage["surfaces"]
            assert previous_surface in coverage["surfaces"]
        else:
            assert coverage["surfaces"] == [projected_surface]
        pending_rows = [row for row in coverage["deferred"] if row["id"] != "scan-stopped"]
        if retained in (
            "same-attempt-changed-surface",
            "same-attempt-receipts",
            "same-attempt-multiple",
        ):
            assert len(pending_rows) == (3 if retained == "same-attempt-multiple" else 2)
            assert len({row["id"] for row in pending_rows}) == len(pending_rows)
            if retained == "same-attempt-multiple":
                middle = next(
                    row for row in coverage["surfaces"] if row["label"] == "Intermediate review"
                )
                pending_middle = next(
                    row for row in pending_rows if row["reason"] == "Intermediate review remains."
                )
                assert pending_middle["surfaceIds"] == [middle["id"]]
            assert previous_pending in pending_rows
            recovered_pending = next(
                row for row in pending_rows if row["reason"] == pending["reason"]
            )
            assert recovered_pending["surfaceIds"] == [recovered_surface["id"]]
            assert recovered_pending["provenance"] == projected_pending["provenance"]
        elif retained == "changed-surface":
            assert len(pending_rows) == 2
            assert projected_pending in pending_rows
            assert previous_pending in pending_rows
        elif retained == "changed":
            assert len(pending_rows) == 2
            assert {row["reason"] for row in pending_rows} == {
                pending["reason"],
                previous_pending["reason"],
            }
            assert len({row["id"] for row in pending_rows}) == 2
            assert all(row["surfaceIds"] == [projected_surface["id"]] for row in pending_rows)
            assert all(row["provenance"] == projected_pending["provenance"] for row in pending_rows)
        else:
            assert pending_rows == [projected_pending]
        assert all(path.read_bytes() == contents for path, contents in saved.items())

    assert frozen_merges and frozen_merges[0]
    if projection_source == "checkpoint":
        assert any("/checkpoints/" in path for path in frozen_merges[0])


@pytest.mark.parametrize("retry_publication", [False, True])
def test_frozen_parent_projection_keeps_selected_surface_notes(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {"completeness": "complete"},
            }
        )
    )
    coverage = copy.deepcopy(scan.coverage)
    coverage["surfaces"] = [
        {
            "id": "selected-review",
            "label": "Accepted review",
            "disposition": "no_issue_found",
            "receiptRefs": [],
        }
    ]
    coverage["reviews"] = [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}]
    current = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": scan.findings,
        "coverage": coverage,
    }
    old = copy.deepcopy(current)
    old["coverage"]["surfaces"][0]["notes"] = "Earlier accepted review notes."
    current["coverage"]["surfaces"][0]["notes"] = "Current accepted review notes."
    prior = write_checkpoint(scan.scan_dir / "checkpoints", old)
    selected = write_checkpoint(scan.scan_dir / "checkpoints", current)
    os.utime(prior, ns=(100, 100))
    os.utime(selected, ns=(200, 200))
    (scan.scan_dir / "coverage.json").write_text(json.dumps(current["coverage"]))
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / filename, ns=(300, 300))
    saved = {path: path.read_bytes() for path in (prior, selected, result)}
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(
                workbench_api["saved_results"],
                "_write_prepared_scan_finalization",
                fail_publication,
            )
        workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    notes = [row.get("notes") for row in coverage["surfaces"]]
    assert notes == ["Current accepted review notes."]
    assert all(path.read_bytes() == data for path, data in saved.items())


@pytest.mark.parametrize("stale_owner", [False, True, "unmatched"])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_retained_source_finding_owner_does_not_close_another_worker_gap(
    workbench_api, workbench_db, publication_scan, monkeypatch, stale_owner, retry_publication
):
    scan = publication_scan()
    first = add_worker(workbench_db, scan)
    second = add_worker(workbench_db, scan)
    owner_a, owner_b = first.parent.name, second.parent.name
    pending = {
        "id": "pending",
        "candidateId": "candidate-C",
        "reason": "Independent worker proof remains.",
    }
    first.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {"completeness": "partial", "surfaces": [], "deferred": [pending]},
            }
        )
    )
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"].update(candidateId="candidate-C", workerId=owner_b)
    second.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [finding],
                "coverage": {"completeness": "complete", "surfaces": [], "deferred": []},
            }
        )
    )
    retained = copy.deepcopy(finding)
    retained["provenance"]["workerId"] = owner_a if stale_owner else owner_b
    if stale_owner != "unmatched":
        retained["provenance"]["sourceFindings"] = [{"id": f"{owner_b}:0", "finding": finding}]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": [retained]}))
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": [],
                "deferred": [
                    {
                        **pending,
                        "id": f"{owner_a}-attempt-1-deferred-1",
                        "candidateId": f"{owner_a}-attempt-1-candidate-1",
                        "provenance": {
                            "workerId": owner_a,
                            "attempt": 1,
                            "sourceId": "pending",
                            "candidateId": "candidate-C",
                        },
                    }
                ],
                "reviews": [
                    {"workerId": owner_a, "attempt": 1, "completeness": "partial"},
                    {"workerId": owner_b, "attempt": 1, "completeness": "complete"},
                ],
            }
        )
    )
    originals = {path: path.read_bytes() for path in (first, second)}
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(
                workbench_api["saved_results"],
                "_write_prepared_scan_finalization",
                fail_publication,
            )
        workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert any(row.get("reason") == pending["reason"] for row in coverage["deferred"])
    assert recovered["findingCount"] == 1
    assert all(path.read_bytes() == data for path, data in originals.items())


@pytest.mark.parametrize("independent_worker", [False, True])
@pytest.mark.parametrize("changed", [False, True])
def test_stopped_retry_copies_keep_one_observation_per_worker(
    workbench_api, workbench_db, publication_scan, independent_worker, changed
):
    import shutil

    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET status = 'running', attempt = 2, artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    receipt = output / "artifacts" / "review.txt"
    receipt.parent.mkdir()
    receipt.write_text("Synthetic retained receipt.\n")
    surface = {
        "id": "original-review",
        "label": "Original review",
        "disposition": "needs_follow_up",
        "receiptRefs": ["artifacts/review.txt"],
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [surface],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    saved = write_checkpoint(output / "checkpoints", draft)
    (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": saved.name}))
    archive = output.parent / "attempts" / "attempt-01"
    shutil.copytree(output, archive)
    if changed:
        newer = copy.deepcopy(draft)
        newer["coverage"]["surfaces"][0]["notes"] = "New independent review notes."
        selected = write_checkpoint(output / "checkpoints", newer)
        (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": selected.name}))
    if independent_worker:
        second = add_worker(workbench_db, scan)
        second.write_text(json.dumps(draft))
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET status = 'running' WHERE result_manifest_path = ?",
                (str(second),),
            )
        other_receipt = second.parent / "artifacts" / "review.txt"
        other_receipt.parent.mkdir()
        other_receipt.write_text("Synthetic retained receipt.\n")
    source_bytes = {
        p: p.read_bytes() for p in (scan.scan_dir / "artifacts").rglob("*") if p.is_file()
    }
    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit interrupted."
        ),
    )
    for replay in (False, True):
        if replay:
            workbench_api["saved_results"].recover_scan_results(
                workbench_api["_WORKBENCH_DB_CONTEXT"],
                workbench_db,
                Namespace(scan_id=scan.scan_id),
            )
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        rows = [row for row in coverage["surfaces"] if row["label"] == "Original review"]
        assert len(rows) == 1 + int(changed) + int(independent_worker)
        assert all(path.read_bytes() == data for path, data in source_bytes.items())


@pytest.mark.parametrize("publication", ["interrupted", "completed", "legacy", "after-completed"])
def test_stopped_recovery_binds_reducer_projection_to_host_checkpoint(
    workbench_api, workbench_db, publication_scan, publication
):
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    if publication == "after-completed":
        prior = add_worker(workbench_db, scan)
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE result_manifest_path = ?",
                (str(prior),),
            )
        accepted_prior = {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": [],
            "sourceCoverage": {
                "completeness": "complete",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
                "reviews": [],
            },
        }
        write_checkpoint(prior.parent / "checkpoints", accepted_prior)
        prior.write_text(json.dumps(accepted_prior))
    discovery = add_worker(workbench_db, scan)
    discovery.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    "completeness": "partial",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [
                        {"id": "review", "reason": "Supported validation remains unresolved."}
                    ],
                },
            }
        )
    )
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none', status = ? WHERE result_manifest_path = ?",
            (
                "failed" if publication in ("interrupted", "after-completed") else "succeeded",
                str(reducer),
            ),
        )
    reducer.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "sourceCoverage": {
                    "completeness": "complete",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                    "reviews": [
                        {
                            "workerId": discovery.parent.name,
                            "attempt": 99,
                            "completeness": "complete",
                        }
                    ],
                },
            }
        )
    )
    worker_id = discovery.parent.name
    accepted = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "sourceCoverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [
                {
                    "id": f"{worker_id}-attempt-1-deferred-1",
                    "reason": "Supported validation remains unresolved.",
                    "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
                }
            ],
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    }
    if publication != "legacy":
        write_checkpoint(reducer.parent / "checkpoints", accepted)
    if publication not in ("interrupted", "after-completed"):
        reducer.write_text(json.dumps(accepted))
    saved = {path: path.read_bytes() for path in (scan.scan_dir / "workers").rglob("*.json")}
    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Synthetic stop."
        ),
    )
    for replay in (False, True):
        if replay:
            workbench_api["saved_results"].recover_scan_results(
                workbench_api["_WORKBENCH_DB_CONTEXT"],
                workbench_db,
                Namespace(scan_id=scan.scan_id),
            )
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert coverage["reviews"] == [
            {
                "workerId": discovery.parent.name,
                "attempt": 1,
                "completeness": "partial",
            }
        ]
        assert any(
            row.get("reason") == "Supported validation remains unresolved."
            for row in coverage["deferred"]
        )
        assert all(path.read_bytes() == contents for path, contents in saved.items())


@pytest.mark.skipif(os.name == "nt", reason="directory access modes require POSIX")
@pytest.mark.parametrize("merge_state", ["merging", "buffered", "merged"])
@pytest.mark.parametrize("variant", ["retained", "additional", "changed"])
def test_precommit_deferred_links_keep_actual_host_surface(
    workbench_api, workbench_db, publication_scan, merge_state, variant
):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the real checkpoint producer")
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    discovery = add_worker(workbench_db, scan)
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = ? WHERE result_manifest_path = ?",
            (merge_state, str(discovery)),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', status = 'failed', merge_state = 'none' WHERE result_manifest_path = ?",
            (str(reducer),),
        )
    reducer.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "sourceCoverage": {
                    "completeness": "complete",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                    "reviews": [],
                },
            }
        )
    )
    command = [
        node,
        "--experimental-strip-types",
        str(Path(__file__).resolve().parents[1] / "mcp-app/tests/precommit_reducer_fixture.mjs"),
        str(scan.scan_dir),
        str(discovery),
        str(reducer),
        variant,
        scan.scan_id,
    ]
    result = subprocess.run(command, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    saved = {p: p.read_bytes() for p in (scan.scan_dir / "workers").rglob("*.json")}
    api = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    api.fail_scan(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            cost_json=None,
            message="Synthetic stopped publication.",
        ),
    )
    for replay in (False, True):
        if replay:
            api.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        surfaces = {
            row["id"]
            for row in coverage["surfaces"]
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
        pending = [
            row
            for row in coverage["deferred"]
            if row.get("reason") == "Accepted later review remains."
        ]
        assert pending
        for row in pending:
            assert set(row["surfaceIds"]) <= surfaces, (row, surfaces)
            if variant != "changed":
                assert proof["retainedHostSurface"] in row["surfaceIds"]
        assert all(path.read_bytes() == value for path, value in saved.items())


@pytest.mark.skipif(os.name == "nt", reason="directory access modes require POSIX")
@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("second", [False, True])
@pytest.mark.parametrize("merge_state", ["merging", "buffered", "merged"])
def test_retained_two_surface_actual_recovery(
    workbench_api, workbench_db, publication_scan, count, second, merge_state
):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the real checkpoint producer")
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    worker = add_worker(workbench_db, scan)
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = ? WHERE result_manifest_path = ?",
            (merge_state, str(worker)),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', status = 'failed', merge_state = 'none' WHERE result_manifest_path = ?",
            (str(reducer),),
        )
    reducer.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "sourceCoverage": {
                    "completeness": "complete",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                    "reviews": [],
                },
            }
        )
    )
    result = subprocess.run(
        [
            node,
            "--experimental-strip-types",
            str(Path(__file__).resolve().parents[1] / "mcp-app/tests/retained_reducer_fixture.mjs"),
            str(scan.scan_dir),
            str(worker),
            str(reducer),
            str(count),
            str(second).lower(),
            scan.scan_id,
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    saved = {p: p.read_bytes() for p in (scan.scan_dir / "workers").rglob("*.json")}
    api, context = workbench_api["saved_results"], workbench_api["_WORKBENCH_DB_CONTEXT"]
    api.fail_scan(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            cost_json=None,
            message="Synthetic interrupted reduction.",
        ),
    )
    for replay in (False, True):
        if replay:
            api.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        reasons = ["Retained accepted proof remains."] + (
            ["Independent second proof remains."] if second else []
        )
        rows = [row for row in coverage["deferred"] if row.get("reason") in reasons]
        assert len(rows) == len(reasons), rows
        assert sorted(row["reason"] for row in rows) == sorted(reasons)
        for row in rows:
            assert set(row["surfaceIds"]) == set(proof["expectedSurfaceIds"])
        assert all(p.read_bytes() == content for p, content in saved.items())


@pytest.mark.parametrize("archived", [False, True], ids=["current", "headless-archive"])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_archived_projected_worker_candidates_keep_independent_pending_evidence(
    workbench_api, workbench_db, publication_scan, monkeypatch, archived, retry_publication
):
    test_stopped_recovery_preserves_accepted_coverage_without_worker_id_collisions(
        workbench_api,
        workbench_db,
        publication_scan,
        True,
        ".",
        "rejected",
        "projected",
        retry_publication,
        monkeypatch,
        archived=archived,
    )
