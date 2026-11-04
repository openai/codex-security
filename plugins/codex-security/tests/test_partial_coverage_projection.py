from __future__ import annotations

import copy
import hashlib
import json
import os
import uuid
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import (
    read_review_state,
    select_checkpoint,
    write_checkpoint,
    write_result_draft,
)


@pytest.fixture
def stop_scan(workbench_api, monkeypatch):
    saved = workbench_api["saved_results"]

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption.")

    def stop(scan, interrupt_publication):
        with monkeypatch.context() as patch:
            if interrupt_publication:
                patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
            stopped = scan.fail()
        assert stopped["resultsRecoveryNeeded"] is interrupt_publication

    return stop


@pytest.mark.parametrize("attempt", [1, 2])
@pytest.mark.parametrize("has_head", [False, True])
@pytest.mark.parametrize("newer_parent", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_parent_candidate_outcome_compares_headless_worker_chronology(
    workbench_db,
    publication_scan,
    stop_scan,
    attempt,
    has_head,
    newer_parent,
    retry_publication,
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = ? WHERE id = ?", (attempt, worker_id)
        )
    candidate = "pending-candidate"
    surface = {
        "id": "worker-surface",
        "candidateId": candidate,
        "label": "Worker follow-up",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    task = {"id": "worker-task", "candidateId": candidate, "reason": "Validate worker evidence."}
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [surface],
            "deferred": [task],
        },
    }
    write_result_draft(result, draft, mtime_ns=300)
    originals = {result: result.read_bytes()}
    if has_head:
        checkpoint = write_checkpoint(result.parent / "checkpoints", draft, mtime_ns=300)
        head = select_checkpoint(result.parent, checkpoint, mtime_ns=300)
        originals.update({path: path.read_bytes() for path in (checkpoint, head)})
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    parent = scan.scan_dir / "coverage.json"
    parent.write_text(
        json.dumps(
            {
                **scan.coverage,
                "surfaces": [
                    {
                        **surface,
                        "id": "parent-rejection",
                        "label": "Parent reviewed candidate",
                        "disposition": "rejected",
                        "provenance": {
                            "workerId": worker_id,
                            "attempt": attempt,
                            "candidateId": candidate,
                            "sourceId": surface["id"],
                        },
                    }
                ],
                "reviews": [{"workerId": worker_id, "attempt": attempt, "completeness": "partial"}],
            }
        )
    )
    modified = 400 if newer_parent else 200
    os.utime(parent, ns=(modified, modified))
    stop_scan(scan, retry_publication)
    scan.recover()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    pending = [row for row in coverage["deferred"] if row.get("reason") == task["reason"]]
    assert len(pending) == int(not newer_parent)
    assert any(
        row.get("label") == surface["label"] and row.get("disposition") == "needs_follow_up"
        for row in coverage["surfaces"]
    ) is (not newer_parent)
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize(
    "parent_surfaces", ["missing", "projected", "renamed", "second-only", "no-parent", "edited"]
)
@pytest.mark.parametrize("tagged_surface", [False, True])
@pytest.mark.parametrize("merge_state", ["buffered", "merging", "merged"])
def test_missing_deferred_projection_links_first_duplicate_surface(
    workbench_db, publication_scan, parent_surfaces, merge_state, tagged_surface
):
    scan = publication_scan()
    result = scan.add_worker()
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
    if tagged_surface:
        surfaces[0]["candidateId"] = "source-candidate"
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
    if tagged_surface:
        projected[0]["provenance"]["candidateId"] = surfaces[0]["candidateId"]
        projected[0]["candidateId"] = (
            f"{worker_id}-attempt-1-candidate-"
            + hashlib.sha256(surfaces[0]["candidateId"].encode()).hexdigest()
        )
    if parent_surfaces == "renamed":
        projected[0]["id"] = "canonical-first-surface"
    if parent_surfaces == "edited":
        projected[0]["label"] = "Parent requested a different review."
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
                "deferred": [
                    {
                        "id": f"{worker_id}-attempt-1-deferred-1",
                        "reason": "Parent requested different proof.",
                        "surfaceIds": [projected[0]["id"]],
                    }
                ]
                if parent_surfaces == "edited"
                else [],
                "surfaces": []
                if parent_surfaces == "missing"
                else projected[1:]
                if parent_surfaces == "second-only"
                else projected,
            }
        )
    )
    if parent_surfaces == "no-parent":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    if tagged_surface:
        earlier = copy.deepcopy(json.loads(result.read_text()))
        earlier["coverage"]["surfaces"][0]["disposition"] = "no_issue_found"
        earlier["coverage"]["deferred"] = []
        earlier["coverage"]["resolvedDeferred"] = [
            {"id": deferred["id"], "reason": "Earlier source follow-up completed."}
        ]
        write_checkpoint(result.parent / "checkpoints", earlier, mtime_ns=100)
        os.utime(result, ns=(300, 300))
        if parent_surfaces != "no-parent":
            os.utime(scan.scan_dir / "coverage.json", ns=(200, 200))
    scan.fail()
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published
    coverage = read_review_state(workbench_db, scan.scan_dir)
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == 1
    if parent_surfaces == "edited":
        worker_surface = next(
            surface for surface in coverage["surfaces"] if surface["label"] == surfaces[0]["label"]
        )
        assert worker_surface["id"] != projected[0]["id"]
        assert pending[0]["surfaceIds"] == [worker_surface["id"]]
        parent_task = next(
            task
            for task in coverage["deferred"]
            if task["reason"] == "Parent requested different proof."
        )
        assert parent_task["surfaceIds"] == [projected[0]["id"]]
        assert len(coverage["surfaces"]) == len(projected) + 1
    else:
        assert pending[0]["surfaceIds"] == [projected[0]["id"]]
        assert len(coverage["surfaces"]) == len(projected)
    assert all(surface in coverage["surfaces"] for surface in projected)
    assert result.read_bytes() == original

    # Replay a new checkpoint with both worker-only coverage and a conflicting parent edit.
    if (parent_surfaces, merge_state, tagged_surface) not in {
        ("no-parent", "buffered", False),
        ("edited", "merged", True),
    }:
        return
    late = write_checkpoint(
        result.parent / "checkpoints",
        {
            **json.loads(original),
            "complete": False,
            "coverage": {**scan.coverage, "openQuestions": ["Late worker checkpoint."]},
        },
    )
    original_late = late.read_bytes()
    scan.recover()
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_bytes())
    assert late.relative_to(scan.scan_dir).as_posix() in manifest["scan"]["preservedSources"]
    assert read_review_state(workbench_db, scan.scan_dir) == coverage
    assert result.read_bytes() == original
    assert late.read_bytes() == original_late


@pytest.mark.parametrize("parent_review", [False, True])
def test_missing_accepted_result_does_not_project_an_archived_attempt(
    workbench_db, publication_scan, parent_review
):
    scan = publication_scan()
    result = scan.add_worker()
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
    scan.fail()
    scan.recover()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    surface = next(
        item for item in coverage["surfaces"] if item["label"] == "Prior unfinished review"
    )
    assert surface["id"] == f"{worker_id}/prior-surface"
    assert surface["workerId"] == worker_id
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
    workbench_db, publication_scan, failed_first
):
    scan = publication_scan()
    # These fixture rows share created_at; recovery reads them in worker-ID order.
    first, second = sorted([scan.add_worker(), scan.add_worker()])
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
    scan.fail()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert coverage["reviews"] == [review]
    for field in ("surfaces", "deferred", "explicitExclusions", "openQuestions"):
        for item in drafts["failed"]["coverage"][field]:
            expected = {**item, "workerId": failed.parent.name}
            if field != "openQuestions":
                expected["id"] = f"{failed.parent.name}/{item['id']}"
            if field == "deferred":
                expected["surfaceIds"] = [
                    f"{failed.parent.name}/{surface_id}" for surface_id in item["surfaceIds"]
                ]
            assert expected in coverage[field]
    assert any(
        item.get("reason") == "accepted source needs proof." for item in coverage["deferred"]
    )
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published
    late = write_checkpoint(
        accepted.parent / "checkpoints",
        {
            **drafts["accepted"],
            "complete": False,
            "coverage": {**scan.coverage, "openQuestions": ["Late worker checkpoint."]},
        },
    )
    originals[late] = late.read_bytes()
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    assert read_review_state(workbench_db, scan.scan_dir) == coverage
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert late.relative_to(scan.scan_dir).as_posix() in manifest["scan"]["preservedSources"]
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.parametrize("worker_count", [1, 2])
@pytest.mark.parametrize("missing_parent_surfaces", [False, True])
@pytest.mark.parametrize("retained_deferred", [False, True])
@pytest.mark.parametrize("idless_surface", [False, True])
def test_missing_projection_keeps_surface_links_and_independent_reviews(
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
        result = scan.add_worker()
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
    scan.fail()
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = read_review_state(workbench_db, scan.scan_dir)
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
    assert "completeness" not in coverage
    assert all(path.read_bytes() == data for path, data in originals.items())
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published


@pytest.mark.parametrize("attempt", [1, 2])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_previous_attempt_resolution_does_not_clear_current_gap(
    workbench_db, publication_scan, attempt, retry_publication, stop_scan
):
    scan = publication_scan()
    result = scan.add_worker()
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
    parent_path = scan.scan_dir / "coverage.json"
    parent_path.write_text(
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
    # This parent disposition follows the worker result; tied observations stay pending.
    observed = result.stat().st_mtime_ns // 1_000_000_000 * 1_000_000_000
    os.utime(result, ns=(observed, observed))
    parent_observed = observed + 2_000_000_000
    os.utime(parent_path, ns=(parent_observed, parent_observed))
    stop_scan(scan, retry_publication)
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = read_review_state(workbench_db, scan.scan_dir)
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == (0 if attempt == 1 else 1)
    assert result.read_bytes() == original


@pytest.mark.parametrize("selected_checkpoint", [False, True])
def test_recovery_compares_open_questions_using_canonical_normalization(
    workbench_db, publication_scan, selected_checkpoint
):
    scan = publication_scan()
    result = scan.add_worker()
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
    if selected_checkpoint:
        checkpoint = write_checkpoint(result.parent / "checkpoints", json.loads(result.read_text()))
        os.utime(result, ns=(100, 100))
        os.utime(checkpoint, ns=(150, 150))
        select_checkpoint(result.parent, checkpoint)
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
    scan.fail()
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert coverage["openQuestions"] == projected
    assert result.read_bytes() == original


@pytest.mark.parametrize("parent_projection", ["raw", "projected", "missing"])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_rejected_retry_preserves_original_finding_history(
    workbench_db, publication_scan, stop_scan, parent_projection, retry_publication
):
    scan = publication_scan()
    result = scan.add_worker()
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
    other_result = scan.add_worker()
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
    stop_scan(scan, retry_publication)
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    assert recovered["findingCount"] == 0
    coverage = read_review_state(workbench_db, scan.scan_dir)
    for item in coverage["surfaces"]:
        provenance = item.get("provenance")
        if provenance is None or (
            provenance["workerId"] == worker_id and provenance["attempt"] == 2
        ):
            assert item["previousFindings"] == [finding]
        else:
            assert "previousFindings" not in item
    assert all(path.read_bytes() == original for path, original in originals.items())
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published


@pytest.mark.parametrize("older_complete", [False, True])
@pytest.mark.parametrize(
    "recovery", [None, "retry", "missing", "changed", "incomplete", "late", "fallback-late"]
)
def test_stopped_recovery_keeps_current_parent_projection(
    workbench_db, publication_scan, stop_scan, older_complete, recovery
):
    retry_publication = recovery not in {None, "fallback-late"}
    scan = publication_scan()
    result = scan.add_worker()
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
    reducer = scan.add_worker()
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
    stop_scan(scan, retry_publication)
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
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = read_review_state(workbench_db, scan.scan_dir)
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
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published


@pytest.mark.parametrize("select_head", [False, True])
def test_matching_accepted_checkpoint_preserves_receipt_path(
    workbench_db, publication_scan, select_head
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    result = (
        scan.scan_dir
        / "artifacts"
        / "deep_discovery"
        / "workers"
        / worker_id
        / "output"
        / "result.json"
    )
    result.parent.mkdir(parents=True)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(result.parent), str(result), worker_id),
        )
    receipt = result.parent / "artifacts" / "evidence.txt"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text("Synthetic source-review evidence.")
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "complete",
            "deferred": [],
            "surfaces": [
                {
                    "id": "source-review",
                    "label": "Accepted source review",
                    "disposition": "no_issue_found",
                    "receiptRefs": ["artifacts/evidence.txt"],
                }
            ],
        },
    }
    result.write_text(json.dumps(draft))
    checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
    os.utime(result, ns=(100, 100))
    os.utime(checkpoint, ns=(150, 150))
    if select_head:
        select_checkpoint(result.parent, checkpoint, mtime_ns=200)
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    scan.fail()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    matching = [row for row in coverage["surfaces"] if row.get("label") == "Accepted source review"]
    assert matching
    assert all(
        row["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()] for row in matching
    )
    assert len(matching) == 1
    assert matching[0]["disposition"] == "no_issue_found"
    assert receipt.read_text() == "Synthetic source-review evidence."


@pytest.mark.parametrize("retry_publication", [False, True])
def test_accepted_worker_missing_completeness_keeps_valid_findings(
    workbench_db, publication_scan, stop_scan, retry_publication
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    finding = copy.deepcopy(scan.findings[0])
    finding["summary"] = "Synthetic accepted worker evidence."
    finding["identity"] = {"anchor": "accepted-worker-report"}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [finding],
                "coverage": {
                    key: value for key, value in scan.coverage.items() if key != "completeness"
                },
            }
        )
    )
    original = result.read_bytes()
    stop_scan(scan, retry_publication)
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert any(row["summary"] == finding["summary"] for row in findings)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert {"workerId": worker_id, "attempt": 1, "completeness": "partial"} in coverage["reviews"]
    assert "completeness" not in coverage
    assert result.read_bytes() == original


@pytest.mark.parametrize("retry_publication", [False, True])
def test_idless_accepted_surface_matches_projection_after_checkpoint_id_inference(
    workbench_db, publication_scan, stop_scan, retry_publication
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    surface = {
        "label": "Accepted source review",
        "disposition": "no_issue_found",
        "receiptRefs": [],
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {**scan.coverage, "surfaces": [surface]},
    }
    result.write_text(json.dumps(draft))
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        {
            **draft,
            "complete": False,
            "coverage": {**scan.coverage, "surfaces": [{**surface, "id": "older-source-id"}]},
        },
        mtime_ns=100,
    )
    os.utime(result, ns=(200, 200))
    projected = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "provenance": {"workerId": worker_id, "attempt": 1},
    }
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "surfaces": [projected],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
            }
        )
    )
    originals = {path: path.read_bytes() for path in (result, checkpoint)}
    stop_scan(scan, retry_publication)
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert coverage["surfaces"] == [projected]
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.parametrize("claimed_worker", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
@pytest.mark.parametrize("selected_checkpoint", [False, True])
def test_parent_candidate_provenance_cannot_override_accepted_worker_evidence(
    publication_scan,
    stop_scan,
    claimed_worker,
    retry_publication,
    selected_checkpoint,
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"]["candidateId"] = "source-candidate"
    finding["summary"] = "Accepted independent source evidence."
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [finding],
                "coverage": scan.coverage,
            }
        )
    )
    originals = {result: result.read_bytes()}
    if selected_checkpoint:
        checkpoint = write_checkpoint(result.parent / "checkpoints", json.loads(result.read_text()))
        head = select_checkpoint(result.parent, checkpoint)
        pending_result = json.loads(result.read_text())
        pending_result["findings"] = []
        pending_result["coverage"] = {
            **scan.coverage,
            "completeness": "partial",
            "deferred": [
                {
                    "id": "source-review",
                    "candidateId": "source-candidate",
                    "reason": "Verify source evidence.",
                }
            ],
        }
        write_result_draft(result, pending_result, mtime_ns=100)
        os.utime(checkpoint, ns=(300, 300))
        os.utime(head, ns=(300, 300))
        originals = {path: path.read_bytes() for path in (result, checkpoint, head)}
    rejection = {
        "id": "parent-review",
        "candidateId": "source-candidate",
        "label": "Parent candidate assessment",
        "disposition": "rejected",
        "receiptRefs": [],
    }
    if claimed_worker:
        rejection["provenance"] = {
            "workerId": worker_id,
            "attempt": 1,
            "candidateId": "source-candidate",
        }
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "surfaces": [rejection],
            }
        )
    )
    os.utime(scan.scan_dir / "coverage.json", ns=(400, 400))
    stop_scan(scan, retry_publication)
    recovered = scan.recover()
    assert recovered["resultsRecoveryNeeded"] is False
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert [row["summary"] for row in findings] == [finding["summary"]]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("other_worker", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_projected_generic_closure_updates_parent_copy_in_its_worker_namespace(
    workbench_db, publication_scan, stop_scan, other_worker, retry_publication
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    surface = {
        "id": "source-surface",
        "label": "Source follow-up",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    task = {
        "id": "source-task",
        "reason": "Complete source follow-up.",
        "surfaceIds": [surface["id"]],
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [surface],
            "deferred": [task],
        },
    }
    result.write_text(json.dumps(draft))
    projected_surface = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
    }
    projected_task = {
        **task,
        "id": f"{worker_id}-attempt-1-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": task["id"]},
    }
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    parent_coverage = scan.scan_dir / "coverage.json"
    parent_coverage.write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": [projected_surface],
                "deferred": [projected_task],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
            }
        )
    )
    closure_result = scan.add_worker() if other_worker else result
    if other_worker:
        closure_result.write_text(json.dumps({**draft, "coverage": scan.coverage}))
    closure = {
        **draft,
        "coverage": {
            **scan.coverage,
            "surfaces": [{**surface, "disposition": "no_issue_found"}],
            "deferred": [],
            "resolvedDeferred": [{"id": task["id"], "reason": "Source follow-up completed."}],
        },
    }
    checkpoint = write_checkpoint(closure_result.parent / "checkpoints", closure)
    os.utime(result, ns=(100, 100))
    os.utime(parent_coverage, ns=(200, 200))
    os.utime(checkpoint, ns=(300, 300))
    select_checkpoint(closure_result.parent, checkpoint)
    originals = {path: path.read_bytes() for path in {result, closure_result, checkpoint}}
    stop_scan(scan, retry_publication)
    scan.recover()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    pending = [row for row in coverage["deferred"] if row.get("reason") == task["reason"]]
    assert len(pending) == int(other_worker)
    source_surfaces = [
        row
        for row in coverage["surfaces"]
        if row.get("provenance", {}).get("workerId") == worker_id
    ]
    assert len(source_surfaces) == 1
    assert source_surfaces[0]["disposition"] == (
        "needs_follow_up" if other_worker else "no_issue_found"
    )
    assert all(path.read_bytes() == value for path, value in originals.items())
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published


@pytest.mark.parametrize("disposition", ["rejected", "reported"])
@pytest.mark.parametrize("retry_publication", [False, True])
@pytest.mark.parametrize("parent_review", ["earlier", "copied-later", "changed-later"])
def test_selected_candidate_outcome_removes_its_projected_parent_pending_rows(
    workbench_db,
    publication_scan,
    stop_scan,
    disposition,
    retry_publication,
    parent_review,
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    candidate = "source-candidate"
    surface = {
        "id": "source-surface",
        "candidateId": candidate,
        "label": "Candidate follow-up",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    task = {
        "id": "source-task",
        "candidateId": candidate,
        "reason": "Complete candidate follow-up.",
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [surface],
            "deferred": [task],
        },
    }
    result.write_text(json.dumps(draft))
    projected_candidate = (
        f"{worker_id}-attempt-1-candidate-{hashlib.sha256(candidate.encode()).hexdigest()}"
    )
    projected = {
        field: [
            {
                **row,
                "id": f"{worker_id}-attempt-1-{name}-1",
                "candidateId": projected_candidate,
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": row["id"],
                    "candidateId": candidate,
                },
            }
        ]
        for field, name, row in (("surfaces", "surface", surface), ("deferred", "deferred", task))
    }
    if parent_review == "changed-later":
        projected["surfaces"][0]["label"] = "Parent requested additional review."
        projected["deferred"][0]["reason"] = "Parent requested additional proof."
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage_path = scan.scan_dir / "coverage.json"
    coverage_path.write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                **projected,
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
            }
        )
    )
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"]["candidateId"] = candidate
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        {
            **draft,
            "findings": [finding] if disposition == "reported" else [],
            "coverage": {
                **scan.coverage,
                "surfaces": [{**surface, "disposition": disposition}],
                "deferred": [],
            },
        },
    )
    os.utime(result, ns=(100, 100))
    modified = 200 if parent_review == "earlier" else 400
    os.utime(coverage_path, ns=(modified, modified))
    os.utime(checkpoint, ns=(300, 300))
    select_checkpoint(result.parent, checkpoint, mtime_ns=300)
    originals = {path: path.read_bytes() for path in (result, checkpoint)}
    stop_scan(scan, retry_publication)
    scan.recover()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    if parent_review != "changed-later":
        assert not any(row.get("reason") == task["reason"] for row in coverage["deferred"])
    assert any(
        row.get("reason") == "Parent requested additional proof." for row in coverage["deferred"]
    ) is (parent_review == "changed-later")
    assert any(
        row.get("disposition") == "needs_follow_up"
        and row.get("provenance", {}).get("workerId") == worker_id
        for row in coverage["surfaces"]
    ) is (parent_review == "changed-later")
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == int(disposition == "reported")
    assert all(path.read_bytes() == value for path, value in originals.items())
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published


@pytest.mark.parametrize("retry_publication", [False, True])
@pytest.mark.parametrize(
    "change",
    [
        "new linked surface",
        "revised linked surface",
        "reopened accepted surface",
        "reopened mixed receipts",
        "candidate id fallback",
        "closed sibling candidate",
        "mixed receipts",
        "repeated pending",
        "unchanged",
    ],
)
def test_selected_worker_projection_keeps_links_and_pending_authority(
    workbench_db, publication_scan, stop_scan, change, retry_publication
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    prefix = f"{worker_id}-attempt-1"
    candidate = "source-candidate"
    surface = {
        "id": "source-surface",
        "label": "Source follow-up",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    task = {
        "id": "source-task",
        "reason": "Complete source follow-up.",
        "surfaceIds": [surface["id"]],
    }
    surfaces, deferred = [surface], [task]
    if change == "candidate id fallback":
        task.update(id=candidate, candidate=copy.deepcopy(scan.findings[0]))
        surface["candidateId"] = candidate
    elif change == "closed sibling candidate":
        deferred.append({**task, "id": "candidate-task", "candidateId": candidate})
    elif change in {"new linked surface", "reopened accepted surface", "reopened mixed receipts"}:
        surface["disposition"] = "no_issue_found"
        deferred = []
    if change in {"mixed receipts", "reopened mixed receipts"}:
        result = (
            scan.scan_dir
            / "artifacts"
            / "deep_discovery"
            / "workers"
            / worker_id
            / "output"
            / "result.json"
        )
        result.parent.mkdir(parents=True)
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
                (str(result.parent), str(result), worker_id),
            )
        surface["receiptRefs"] = ["artifacts/old.txt"]
        for name in ("old", "new"):
            receipt = result.parent / "artifacts" / f"{name}.txt"
            receipt.parent.mkdir(exist_ok=True)
            receipt.write_text(f"Synthetic {name} receipt.\n")
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": surfaces,
            "deferred": deferred,
        },
    }
    if change == "reopened mixed receipts":
        draft["coverage"]["resolvedDeferred"] = [
            {"id": task["id"], "reason": "Earlier source follow-up completed."}
        ]
    result.write_text(json.dumps(draft))
    projected = {}
    for field, name, rows in (
        ("surfaces", "surface", surfaces),
        ("deferred", "deferred", deferred),
    ):
        projected[field] = []
        for index, original in enumerate(rows, 1):
            row = copy.deepcopy(original)
            row["id"] = f"{prefix}-{name}-{index}"
            row["provenance"] = {"workerId": worker_id, "attempt": 1, "sourceId": original["id"]}
            if "candidateId" in original:
                row["provenance"]["candidateId"] = original["candidateId"]
                row["candidateId"] = (
                    f"{prefix}-candidate-{hashlib.sha256(candidate.encode()).hexdigest()}"
                )
            if field == "surfaces":
                row["receiptRefs"] = [
                    (result.parent / ref).relative_to(scan.scan_dir).as_posix()
                    for ref in original["receiptRefs"]
                ]
            else:
                row["surfaceIds"] = [f"{prefix}-surface-1"]
            projected[field].append(row)
    coverage_path = scan.scan_dir / "coverage.json"
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage_path.write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                **projected,
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
            }
        )
    )
    checkpoint = None
    if change != "unchanged":
        updated = copy.deepcopy(draft)
        if change in {
            "new linked surface",
            "revised linked surface",
            "reopened accepted surface",
            "reopened mixed receipts",
        }:
            updated_id = "new-surface" if change == "new linked surface" else surface["id"]
            updated_task = (
                task["id"]
                if change in {"revised linked surface", "reopened mixed receipts"}
                else "new-task"
            )
            updated["coverage"].update(
                surfaces=[
                    {
                        **surface,
                        "id": updated_id,
                        "label": "New follow-up",
                        "disposition": "needs_follow_up",
                    }
                ],
                deferred=[{**task, "id": updated_task, "surfaceIds": [updated_id]}],
            )
            if change == "reopened mixed receipts":
                updated["coverage"].pop("resolvedDeferred")
                updated["coverage"]["surfaces"][0]["receiptRefs"] = ["artifacts/new.txt"]
        elif change == "candidate id fallback":
            updated["coverage"].update(
                surfaces=[{**surface, "disposition": "rejected"}], deferred=[]
            )
        elif change in {"closed sibling candidate", "mixed receipts"}:
            updated["coverage"].update(
                surfaces=[
                    {
                        **surface,
                        "disposition": "no_issue_found",
                        "receiptRefs": ["artifacts/new.txt"] if change == "mixed receipts" else [],
                    }
                ],
                deferred=[],
                resolvedDeferred=[{"id": task["id"], "reason": "Source follow-up completed."}],
            )
            if change == "closed sibling candidate":
                updated["coverage"]["surfaces"].append(
                    {
                        **surface,
                        "id": "candidate-surface",
                        "candidateId": candidate,
                        "label": "Candidate proof",
                        "disposition": "rejected",
                    }
                )
        checkpoint = write_checkpoint(result.parent / "checkpoints", updated, mtime_ns=300)
        select_checkpoint(result.parent, checkpoint)
    os.utime(result, ns=(100, 100))
    os.utime(coverage_path, ns=(200, 200))
    if change == "reopened mixed receipts":
        result.write_text(json.dumps(updated))
        checkpoint.write_text(json.dumps(draft))
        (result.parent / "checkpoint-head.json").unlink()
        os.utime(checkpoint, ns=(100, 100))
        os.utime(result, ns=(300, 300))
    originals = {
        path: path.read_bytes() for path in [result] + ([checkpoint] if checkpoint else [])
    }
    stop_scan(scan, retry_publication)
    scan.recover()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    pending = [row for row in coverage["deferred"] if row.get("reason") == task["reason"]]
    assert len(pending) == int(
        change
        in {
            "new linked surface",
            "revised linked surface",
            "reopened accepted surface",
            "reopened mixed receipts",
            "repeated pending",
            "unchanged",
        }
    )
    if change in {
        "new linked surface",
        "revised linked surface",
        "reopened accepted surface",
        "reopened mixed receipts",
    }:
        linked = next(
            row for row in coverage["surfaces"] if row["id"] == pending[0]["surfaceIds"][0]
        )
        assert linked["label"] == "New follow-up"
        if change == "reopened mixed receipts":
            assert set(linked["receiptRefs"]) == {
                (result.parent / "artifacts" / f"{name}.txt").relative_to(scan.scan_dir).as_posix()
                for name in ("old", "new")
            }
        assert len({row["id"] for row in coverage["surfaces"]}) == len(coverage["surfaces"])
    elif change in {"closed sibling candidate", "mixed receipts"}:
        saved_surface = next(
            row for row in coverage["surfaces"] if row.get("label") == surface["label"]
        )
        assert saved_surface["disposition"] == "no_issue_found", json.dumps(saved_surface)
        if change == "mixed receipts":
            assert set(saved_surface["receiptRefs"]) == {
                (result.parent / "artifacts" / f"{name}.txt").relative_to(scan.scan_dir).as_posix()
                for name in ("old", "new")
            }
    assert all(path.read_bytes() == content for path, content in originals.items())
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    scan.recover()
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published


def publish_review_projection(workbench_api, connection, scan, coverage):
    # Publish through an active coordinator before exercising stopped recovery.
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'running', coordinator_generation = 2, "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    documents = {
        "deepScanPublication": {"coordinatorGeneration": 2, "resultPath": None},
        "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
        "findings": {"findings": []},
        "coverage": coverage,
    }
    staged = scan.scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.parent.mkdir(exist_ok=True)
    staged.write_text(json.dumps(documents))
    saved = workbench_api["saved_results"]
    saved.write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        connection,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            draft_path=str(staged),
            checkpoint_path=None,
            expected_draft_digest=None,
        ),
    )


def stop_and_recover_projection(workbench_api, connection, scan, stop_scan, retry):
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    stop_scan(scan, retry)
    saved.recover_scan_results(context, connection, Namespace(scan_id=scan.scan_id))
    published = (scan.scan_dir / "scan-manifest.json").read_bytes()
    saved.recover_scan_results(context, connection, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == published
    return read_review_state(connection, scan.scan_dir)


@pytest.mark.parametrize("spelling", ["unchanged", "equivalent", "scan relative", "omitted"])
@pytest.mark.parametrize("parent", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_linked_archived_receipts_preserve_accepted_surface_links(
    workbench_api, workbench_db, publication_scan, stop_scan, spelling, parent, retry
):
    scan = publication_scan()
    initial = scan.add_worker()
    worker_id = initial.parent.name
    output = scan.scan_dir / "artifacts" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    receipt = output / "artifacts" / "review.txt"
    receipt.parent.mkdir()
    receipt.write_text("Synthetic completed review.\n")
    surface = {
        "id": "source-surface",
        "label": "Source review",
        "disposition": "needs_follow_up",
        "receiptRefs": ["artifacts/review.txt"],
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [surface],
            "deferred": [],
        },
    }
    result.write_text(json.dumps(draft))
    projected = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "receiptRefs": [receipt.relative_to(scan.scan_dir).as_posix()],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
    }
    coverage_path = scan.scan_dir / "coverage.json"
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage_path.write_text(
        json.dumps(
            {
                **scan.coverage,
                "surfaces": [projected],
                "deferred": [],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
            }
        )
    )
    selected = copy.deepcopy(draft)
    selected["complete"] = False
    selected["coverage"]["deferred"] = [
        {"id": "pending", "reason": "Verify accepted source review.", "surfaceIds": [surface["id"]]}
    ]
    if spelling == "equivalent":
        selected["coverage"]["surfaces"][0]["receiptRefs"] = ["artifacts/./review.txt"]
    elif spelling == "scan relative":
        selected["coverage"]["surfaces"][0]["receiptRefs"] = [
            receipt.relative_to(scan.scan_dir).as_posix()
        ]
    elif spelling == "omitted":
        selected["coverage"]["surfaces"] = []
    checkpoint = write_checkpoint(output / "checkpoints", selected)
    head = select_checkpoint(output, checkpoint)
    for path, stamp in ((result, 100), (coverage_path, 200), (checkpoint, 300), (head, 300)):
        os.utime(path, ns=(stamp, stamp))
    if not parent:
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    originals = {path: path.read_bytes() for path in (result, checkpoint, head)}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, stop_scan, retry)
    pending = [
        row for row in coverage["deferred"] if row.get("reason") == "Verify accepted source review."
    ]
    assert len(pending) == 1
    assert pending[0]["surfaceIds"] == [projected["id"]]
    assert coverage["surfaces"] == [projected]
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize(
    ("source", "parent", "closure"),
    [
        ("worker", False, False),
        ("worker", True, False),
        ("worker", True, True),
        ("worker-scan-relative", True, False),
        ("worker-scan-relative", True, True),
        ("shared", False, False),
        ("shared", True, False),
        ("worker-collision", False, False),
        ("worker-collision", True, False),
    ],
)
@pytest.mark.parametrize("equivalent", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_recovery_projects_receipts_from_their_source_directory(
    workbench_api,
    workbench_db,
    publication_scan,
    stop_scan,
    source,
    parent,
    closure,
    equivalent,
    retry,
):
    scan = publication_scan()
    initial = scan.add_worker()
    worker_id = initial.parent.name
    output = scan.scan_dir / "artifacts" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    shared = source == "shared"
    ref = "artifacts/01_context/false_positive_feedback.json" if shared else "artifacts/review.txt"
    if source == "worker-collision":
        parent_receipt = scan.scan_dir / ref
        parent_receipt.parent.mkdir(exist_ok=True, parents=True)
        parent_receipt.write_text("Synthetic unrelated parent review.\n")
    receipt = (scan.scan_dir if shared else output) / ref
    receipt.parent.mkdir(exist_ok=True, parents=True)
    receipt.write_text("Synthetic completed source review.\n")
    if source == "worker-scan-relative":
        ref = receipt.relative_to(scan.scan_dir).as_posix()
    source_ref = ref.replace("artifacts/", "artifacts/./", 1) if equivalent else ref
    surface = {
        "id": "review",
        "label": "Completed source review",
        "disposition": "no_issue_found",
        "receiptRefs": [source_ref],
    }
    worker_coverage = {**scan.coverage, "surfaces": [surface], "deferred": []}
    if closure:
        worker_coverage["resolvedDeferred"] = [
            {"id": "review", "reason": "Source review completed."}
        ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": worker_coverage,
            }
        )
    )
    original = result.read_bytes()
    projected = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "receiptRefs": [receipt.relative_to(scan.scan_dir).as_posix()],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
    if parent:
        publish_review_projection(
            workbench_api,
            workbench_db,
            scan,
            {
                **scan.coverage,
                "surfaces": [projected],
                "deferred": [],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
            },
        )
    else:
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, stop_scan, retry)
    assert coverage["surfaces"] == [projected]
    assert result.read_bytes() == original


def test_deferred_projection_preserves_each_referenced_source_surface(
    workbench_db, publication_scan
):
    scan = publication_scan()
    result = scan.add_worker()
    worker_id = result.parent.name
    surfaces = [
        {
            "id": f"source-{index}",
            "label": f"Source boundary {index}",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
        for index in range(12)
    ]
    deferred = [
        {"id": f"task-{index}", "reason": f"Verify source {index}.", "surfaceIds": [surface["id"]]}
        for index, surface in enumerate(surfaces)
    ]
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": surfaces,
            "deferred": deferred,
        },
    }
    result.write_text(json.dumps(draft))
    original = result.read_bytes()
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    scan.fail()
    coverage = read_review_state(workbench_db, scan.scan_dir)
    projected = {row["provenance"]["sourceId"]: row for row in coverage["surfaces"]}
    assert set(projected) == {surface["id"] for surface in surfaces}
    pending = {
        row["provenance"]["sourceId"]: row for row in coverage["deferred"] if row.get("surfaceIds")
    }
    assert set(pending) == {row["id"] for row in deferred}
    for task in deferred:
        row = pending[task["id"]]
        assert row["surfaceIds"] == [projected[task["surfaceIds"][0]]["id"]]
        assert row["provenance"]["workerId"] == worker_id
    assert result.read_bytes() == original
