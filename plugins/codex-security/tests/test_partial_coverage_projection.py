from __future__ import annotations

import copy
import hashlib
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("parent_surfaces", ["missing", "projected", "renamed", "no-parent"])
@pytest.mark.parametrize("merge_state", ["buffered", "merging", "merged"])
def test_missing_deferred_projection_links_first_duplicate_surface(
    workbench_api, workbench_db, publication_scan, parent_surfaces, merge_state
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = ? WHERE id = ?",
            (merge_state, worker_id),
        )
    surfaces = [
        {
            "id": "shared-surface",
            "label": label,
            "disposition": disposition,
            "receiptRefs": [],
        }
        for label, disposition in (
            ("Archive route", "needs_follow_up"),
            ("Archive settings", "no_issue_found"),
        )
    ]
    deferred = {
        "id": "pending",
        "reason": "Verify entry boundaries.",
        "surfaceIds": ["shared-surface"],
    }
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "surfaces": surfaces,
                    "deferred": [deferred],
                },
            }
        )
    )
    original = result.read_bytes()
    projected = [
        {
            **surface,
            "id": f"{worker_id}-attempt-1-surface-{index}",
            "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
        }
        for index, surface in enumerate(surfaces, 1)
    ]
    if parent_surfaces == "renamed":
        projected[0]["id"] = "canonical-first-surface"
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
                "surfaces": [] if parent_surfaces == "missing" else projected,
            }
        )
    )
    if parent_surfaces == "no-parent":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage_path = scan.scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == 1
    assert pending[0]["surfaceIds"] == [projected[0]["id"]]
    assert len(coverage["surfaces"]) == len(projected)
    assert all(surface in coverage["surfaces"] for surface in projected)
    assert result.read_bytes() == original
    published = coverage_path.read_bytes()
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert coverage_path.read_bytes() == published
    late = write_checkpoint(
        result.parent / "checkpoints",
        {
            **json.loads(result.read_text()),
            "complete": False,
            "coverage": {**scan.coverage, "openQuestions": ["Late worker checkpoint."]},
        },
    )
    original_late = late.read_bytes()
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert coverage_path.read_bytes() == published
    assert result.read_bytes() == original
    assert late.read_bytes() == original_late


@pytest.mark.parametrize("parent_review", [False, True])
def test_missing_accepted_result_does_not_project_an_archived_attempt(
    workbench_api, workbench_db, publication_scan, parent_review
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    result = scan.scan_dir / "artifacts" / worker_id / "output" / "result.json"
    result.parent.mkdir(parents=True)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = 2, artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(result.parent), str(result), worker_id),
        )
    archive = result.parent.parent / "attempts" / "attempt-01"
    receipt = archive / "artifacts" / "prior.txt"
    receipt.parent.mkdir(parents=True)
    receipt.write_text("Prior attempt receipt.\n")
    checkpoint = write_checkpoint(
        archive / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": [
                    {
                        "id": "prior-surface",
                        "label": "Prior unfinished review",
                        "disposition": "needs_follow_up",
                        "receiptRefs": ["artifacts/prior.txt"],
                    }
                ],
                "deferred": [{"reason": "Prior proof gap.", "surfaceIds": ["prior-surface"]}],
            },
        },
    )
    original = checkpoint.read_bytes()
    if parent_review:
        (scan.scan_dir / "coverage.json").write_text(
            json.dumps(
                {
                    **scan.coverage,
                    "reviews": [{"workerId": worker_id, "attempt": 2, "completeness": "complete"}],
                }
            )
        )
    else:
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    surface = next(
        item for item in coverage["surfaces"] if item["label"] == "Prior unfinished review"
    )
    assert surface["id"] == "prior-surface"
    assert "provenance" not in surface
    assert surface["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()]
    assert len(coverage.get("reviews", [])) == int(parent_review)
    pending = next(
        item for item in coverage["deferred"] if item.get("reason") == "Prior proof gap."
    )
    assert pending["surfaceIds"] == [surface["id"]]
    assert checkpoint.read_bytes() == original


@pytest.mark.parametrize("failed_first", [False, True])
def test_failed_worker_reviews_do_not_replace_accepted_reviews(
    workbench_api, workbench_db, publication_scan, failed_first
):
    scan = publication_scan()
    # These fixture rows share created_at; recovery reads them in worker-ID order.
    first, second = sorted([add_worker(workbench_db, scan), add_worker(workbench_db, scan)])
    failed, accepted = (first, second) if failed_first else (second, first)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET status = 'failed', merge_state = 'none' WHERE id = ?",
            (failed.parent.name,),
        )
    review = {"workerId": accepted.parent.name, "attempt": 1, "completeness": "partial"}
    originals = {}
    drafts = {}
    for label, result in (("accepted", accepted), ("failed", failed)):
        coverage = {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [
                {
                    "id": f"{label}-surface",
                    "label": f"{label} source review",
                    "disposition": "needs_follow_up",
                    "receiptRefs": [],
                }
            ],
            "deferred": [
                {
                    "id": f"{label}-gap",
                    "reason": f"{label} source needs proof.",
                    "surfaceIds": [f"{label}-surface"],
                }
            ],
            "explicitExclusions": [
                {
                    "id": f"{label}-exclusion",
                    "pattern": "vendor/",
                    "reason": f"{label} source excludes external dependencies.",
                }
            ],
            "openQuestions": [{"question": f"Which controls apply to the {label} source?"}],
        }
        if result == failed:
            coverage["reviews"] = [{**review, "completeness": "complete"}]
        draft = {
            "scanId": scan.scan_id,
            "complete": result == accepted,
            "findings": [],
            "coverage": coverage,
        }
        result.write_text(json.dumps(draft))
        checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
        originals.update({path: path.read_bytes() for path in (result, checkpoint)})
        drafts[label] = draft
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    coverage_path = scan.scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    assert coverage["reviews"] == [review]
    for field in ("surfaces", "deferred", "explicitExclusions", "openQuestions"):
        assert all(item in coverage[field] for item in drafts["failed"]["coverage"][field])
    assert any(
        item.get("reason") == "accepted source needs proof." for item in coverage["deferred"]
    )
    published = coverage_path.read_bytes()
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert coverage_path.read_bytes() == published
    late = write_checkpoint(
        accepted.parent / "checkpoints",
        {
            **drafts["accepted"],
            "complete": False,
            "coverage": {**scan.coverage, "openQuestions": ["Late worker checkpoint."]},
        },
    )
    originals[late] = late.read_bytes()
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    assert coverage_path.read_bytes() == published
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert late.relative_to(scan.scan_dir).as_posix() in manifest["scan"]["preservedSources"]
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.parametrize("worker_count", [1, 2])
@pytest.mark.parametrize("missing_parent_surfaces", [False, True])
@pytest.mark.parametrize("retained_deferred", [False, True])
@pytest.mark.parametrize("idless_surface", [False, True])
def test_missing_projection_keeps_surface_links_and_independent_reviews(
    workbench_api,
    workbench_db,
    publication_scan,
    worker_count,
    missing_parent_surfaces,
    retained_deferred,
    idless_surface,
):
    scan = publication_scan()
    surface = {
        "id": "source-surface",
        "label": "Source review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    deferred = {
        "id": "pending-check",
        "reason": "Validation remains unresolved.",
        "candidateId": "pending-candidate",
        "surfaceIds": [surface["id"]],
    }
    worker_surfaces = (
        [{"label": "Background review", "disposition": "reviewed", "receiptRefs": []}]
        if idless_surface
        else []
    ) + [surface]
    reviews, surfaces, deferred_records, originals = [], [], [], {}
    for _ in range(worker_count):
        result = add_worker(workbench_db, scan)
        worker_id = result.parent.name
        reviews.append({"workerId": worker_id, "attempt": 1, "completeness": "partial"})
        if idless_surface:
            surfaces.append(
                {
                    **worker_surfaces[0],
                    "id": f"{worker_id}-attempt-1-surface-1",
                    "provenance": {"workerId": worker_id, "attempt": 1},
                }
            )
        surfaces.append(
            {
                **surface,
                "id": f"{worker_id}-attempt-1-surface-{len(worker_surfaces)}",
                "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
            }
        )
        deferred_records.append(
            {
                **deferred,
                "id": f"{worker_id}-attempt-1-deferred-1",
                "candidateId": f"{worker_id}-attempt-1-candidate-{hashlib.sha256(deferred['candidateId'].encode()).hexdigest()}",
                "surfaceIds": [surfaces[-1]["id"]],
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": deferred["id"],
                    "candidateId": deferred["candidateId"],
                },
            }
        )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": True,
                    "findings": [],
                    "coverage": {
                        **scan.coverage,
                        "completeness": "partial",
                        "surfaces": worker_surfaces,
                        "deferred": [deferred],
                    },
                }
            )
        )
        originals[result] = result.read_bytes()
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": None if missing_parent_surfaces else surfaces,
                "deferred": deferred_records if retained_deferred else [],
                "reviews": reviews,
            }
        )
    )
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            cost_json=None,
            message="Stopped.",
        ),
    )
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))[
        "scan"
    ]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == worker_count
    by_surface_id = {item["id"]: item for item in coverage["surfaces"]}
    for item in pending:
        if not missing_parent_surfaces:
            linked = by_surface_id[item["surfaceIds"][0]]
            assert linked["provenance"]["workerId"] == item["provenance"]["workerId"]
        assert item["provenance"]["attempt"] == 1
        assert item["provenance"]["sourceId"] == deferred["id"]
        assert item["provenance"]["candidateId"] == deferred["candidateId"]
    assert {item["provenance"]["workerId"] for item in pending} == {
        item["workerId"] for item in reviews
    }
    if missing_parent_surfaces:
        # The existing finalizer repairs malformed collections and reports a warning.
        assert coverage["surfaces"] == []
        assert recovered["warnings"]
    else:
        assert len(by_surface_id) == worker_count * len(worker_surfaces)
    assert coverage["completeness"] == "partial"
    assert all(path.read_bytes() == data for path, data in originals.items())
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("attempt", [1, 2])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_previous_attempt_resolution_does_not_clear_current_gap(
    workbench_api, workbench_db, publication_scan, attempt, retry_publication, monkeypatch
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    deferred = {"candidateId": "candidate-1", "reason": "Validate the current attempt."}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "deferred": [deferred]},
            }
        )
    )
    original = result.read_bytes()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = ? WHERE id = ?", (attempt, worker_id)
        )
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
                "surfaces": [
                    {
                        "id": "resolved",
                        "label": "Earlier disposition",
                        "disposition": "rejected",
                        "candidateId": "projected-candidate",
                        "receiptRefs": [],
                        "provenance": {
                            "workerId": worker_id,
                            "attempt": 1,
                            "candidateId": "candidate-1",
                        },
                    }
                ],
            }
        )
    )
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
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )["scan"]
    assert stopped["resultsRecoveryNeeded"] is retry_publication
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == (0 if attempt == 1 else 1)
    assert result.read_bytes() == original


def test_recovery_compares_open_questions_using_canonical_normalization(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    questions = [
        "  Which deployment controls apply?  ",
        {"question": "  Which runtime settings apply?  ", "followUpPrompt": " \t"},
    ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "openQuestions": questions},
            }
        )
    )
    original = result.read_bytes()
    projected = [
        {"question": question, "provenance": {"workerId": worker_id, "attempt": 1}}
        for question in ("Which deployment controls apply?", "Which runtime settings apply?")
    ]
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
                "openQuestions": projected,
            }
        )
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
    assert coverage["openQuestions"] == projected
    assert result.read_bytes() == original


@pytest.mark.parametrize("parent_projection", ["raw", "projected", "missing"])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_rejected_retry_preserves_original_finding_history(
    workbench_api, workbench_db, publication_scan, monkeypatch, parent_projection, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    candidate_id = "candidate-1"
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"]["candidateId"] = candidate_id
    previous = result.parent / "attempts" / "attempt-01" / "result.json"
    previous.parent.mkdir(parents=True)
    previous.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": False,
                "findings": [finding],
                "coverage": scan.coverage,
            }
        )
    )
    surface = {
        "id": "review",
        "candidateId": candidate_id,
        "label": "Rejected candidate",
        "disposition": "rejected",
        "receiptRefs": [],
    }
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "surfaces": [surface]},
            }
        )
    )
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,))
    other_result = add_worker(workbench_db, scan)
    other_result.write_text(
        json.dumps({"scanId": scan.scan_id, "findings": [], "coverage": scan.coverage})
    )
    projected_surfaces = [
        {
            **surface,
            "id": f"{owner}-attempt-{attempt}-surface-1",
            "candidateId": f"{owner}-attempt-{attempt}-candidate-{hashlib.sha256(candidate_id.encode()).hexdigest()}",
            "provenance": {
                "workerId": owner,
                "attempt": attempt,
                "sourceId": surface["id"],
                "candidateId": candidate_id,
            },
        }
        for owner, attempt in ((worker_id, 2), (worker_id, 1), (other_result.parent.name, 1))
    ]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "surfaces": projected_surfaces if parent_projection == "projected" else [surface],
                "reviews": [
                    {"workerId": owner, "attempt": attempt, "completeness": "complete"}
                    for owner, attempt in (
                        (worker_id, 2),
                        (worker_id, 1),
                        (other_result.parent.name, 1),
                    )
                ]
                if parent_projection == "projected"
                else [],
            }
        )
    )
    if parent_projection == "missing":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    originals = {path: path.read_bytes() for path in (previous, result, other_result)}
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
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )["scan"]
    assert stopped["resultsRecoveryNeeded"] is retry_publication
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    assert recovered["findingCount"] == 0
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    for item in coverage["surfaces"]:
        provenance = item.get("provenance")
        if provenance is None or (
            provenance["workerId"] == worker_id and provenance["attempt"] == 2
        ):
            assert item["previousFindings"] == [finding]
        else:
            assert "previousFindings" not in item
    assert all(path.read_bytes() == original for path, original in originals.items())
    published = (scan.scan_dir / "coverage.json").read_bytes()
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("older_complete", [False, True])
@pytest.mark.parametrize(
    "recovery", [None, "retry", "missing", "changed", "incomplete", "late", "fallback-late"]
)
def test_stopped_recovery_keeps_current_parent_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, older_complete, recovery
):
    retry_publication = recovery not in {None, "fallback-late"}
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    deferred = {"candidateId": "candidate-1", "reason": "The current review remains unresolved."}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "deferred": [deferred]},
            }
        )
    )
    reducer = add_worker(workbench_db, scan)
    reducer.write_text(json.dumps({"scanId": scan.scan_id, "findings": []}))
    reducer_checkpoint = write_checkpoint(
        reducer.parent / "checkpoints", json.loads(reducer.read_text())
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
            (reducer.parent.name,),
        )
    reviews = [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}]
    obsolete = write_checkpoint(
        scan.scan_dir / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": older_complete,
            "previousParentCheckpoints": [],
            "findings": [],
            "coverage": {
                **scan.coverage,
                "reviews": reviews,
                "openQuestions": ["This question was answered by the final parent draft."],
                "surfaces": [
                    {
                        "id": "old-disposition",
                        "label": "Earlier disposition",
                        "disposition": "rejected",
                        "candidateId": "projected-candidate",
                        "receiptRefs": [],
                        "provenance": {
                            "workerId": worker_id,
                            "attempt": 1,
                            "candidateId": "candidate-1",
                        },
                    }
                ],
            },
        },
    )
    question = {
        "question": "Which deployment control remains unverified?",
        "provenance": {"workerId": worker_id, "attempt": 1},
    }
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "reviews": reviews,
                "openQuestions": [question],
            }
        )
    )
    if recovery == "incomplete":
        manifest_path = scan.scan_dir / "scan-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["scan"]["complete"] = False
        manifest_path.write_text(json.dumps(manifest))
    original_sources = {
        path: path.read_bytes() for path in (result, reducer, reducer_checkpoint, obsolete)
    }
    if recovery == "fallback-late":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
        obsolete.unlink()
        del original_sources[obsolete]
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
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )["scan"]
    assert stopped["resultsRecoveryNeeded"] is retry_publication
    frozen_sources = {
        path: path.read_bytes() for path in (scan.scan_dir / "checkpoints").glob("*.json")
    }
    if recovery == "missing":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    elif recovery == "changed":
        (scan.scan_dir / "coverage.json").write_text(
            json.dumps({**scan.coverage, "openQuestions": ["Late parent content must be ignored."]})
        )
    elif recovery in {"late", "fallback-late"}:
        late = write_checkpoint(
            scan.scan_dir / "checkpoints",
            {
                "scanId": scan.scan_id,
                "complete": False,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "openQuestions": ["Late proof gap."],
                },
            },
        )
        original_sources[late] = late.read_bytes()
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    expected_questions = [] if recovery == "fallback-late" else [question]
    if recovery in {"late", "fallback-late"}:
        expected_questions.append({"question": "Late proof gap."})
    if recovery == "incomplete":
        expected_questions.append(
            {"question": "This question was answered by the final parent draft."}
        )
    assert coverage["openQuestions"] == expected_questions
    assert coverage.get("reviews", []) == reviews
    assert [item["id"] for item in coverage["surfaces"]] == (
        ["old-disposition"] if recovery == "incomplete" else []
    )
    assert (
        len([item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]])
        == 1
    )
    assert all(path.read_bytes() == original for path, original in original_sources.items())
    assert all(path.read_bytes() == original for path, original in frozen_sources.items())
    published = (scan.scan_dir / "coverage.json").read_bytes()
    workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
