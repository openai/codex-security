from __future__ import annotations

import copy
import json
import os
import subprocess
import uuid
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("retained", [False, True], ids=["missing", "retained"])
@pytest.mark.parametrize("optional_ids", [False, True], ids=["absent-ids", "present-ids"])
@pytest.mark.parametrize("field", ["surfaces", "deferred", "explicitExclusions", "openQuestions"])
def test_recovery_preserves_descriptive_provenance(
    workbench_api, workbench_db, publication_scan, retained, optional_ids, field
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    prefix = f"{worker_id}-attempt-1"
    descriptions = {
        "description": "Synthetic source note.",
        "details": {"basis": ["source review"], "resolved": False},
        "optional": None,
    }
    imported = {
        **descriptions,
        "workerId": "imported-worker",
        "attempt": 999,
        "sourceId": "imported-source",
        "candidateId": "imported-candidate",
    }
    records = {
        "surfaces": {
            "id": "source-surface",
            "label": "Synthetic surface",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        },
        "deferred": {
            "id": "source-deferred",
            "reason": "Synthetic follow-up remains unresolved.",
            "surfaceIds": ["source-surface"],
        },
        "explicitExclusions": {"pattern": "vendor/**", "reason": "Review separately."},
        "openQuestions": {"question": "Which deployment controls apply?"},
    }
    item = records[field]
    if optional_ids:
        item.setdefault("id", "source-record")
        item["candidateId"] = "source-candidate"
    item["provenance"] = copy.deepcopy(imported)
    expected = copy.deepcopy(item)
    expected["provenance"] = {**descriptions, "workerId": worker_id, "attempt": 1}
    if "id" in item:
        expected["provenance"]["sourceId"] = item["id"]
    if optional_ids:
        expected["provenance"]["candidateId"] = "source-candidate"
    if field == "surfaces":
        expected["id"] = f"{prefix}-surface-1"
    elif field == "deferred":
        expected["id"] = f"{prefix}-deferred-1"
        expected["surfaceIds"] = [f"{prefix}-surface-1"]
        if optional_ids:
            expected["candidateId"] = f"{prefix}-candidate-1"
    source_coverage = {**scan.coverage, field: [item]}
    if field == "deferred":
        source_coverage["surfaces"] = [records["surfaces"]]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": source_coverage,
            }
        )
    )
    original = result.read_bytes()
    parent = {
        **scan.coverage,
        field: [expected] if retained else [],
        "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
    }
    if field == "deferred" and retained:
        parent["surfaces"] = [
            {
                **records["surfaces"],
                "id": f"{prefix}-surface-1",
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": "source-surface",
                },
            }
        ]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(parent))
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    published = (scan.scan_dir / "coverage.json").read_bytes()
    coverage = json.loads(published)
    actual = coverage[field]
    if field == "deferred":
        actual = [record for record in actual if record.get("id") != "scan-stopped"]
        assert actual[0]["surfaceIds"] == [coverage["surfaces"][0]["id"]]
    assert coverage["completeness"] == "partial"
    assert result.read_bytes() == original
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
    assert result.read_bytes() == original
    if field == "explicitExclusions" and not retained and not optional_ids:
        actual_id = actual[0].pop("id")
        assert actual_id.startswith("saved-")
    assert actual == [expected]


@pytest.mark.parametrize("parent_review", [False, True], ids=["reconstructed", "retained"])
@pytest.mark.parametrize("retry_publication", [False, True], ids=["direct", "failed-retry"])
def test_recovery_uses_host_reviews_without_discovery_review_extensions(
    workbench_api, workbench_db, publication_scan, monkeypatch, parent_review, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    host_review = {"workerId": worker_id, "attempt": 1, "completeness": "complete"}
    imported_review = {
        "workerId": "synthetic-other-worker",
        "attempt": 99,
        "completeness": "complete",
    }
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "reviews": [imported_review]},
            }
        )
    )
    original = result.read_bytes()
    if parent_review:
        (scan.scan_dir / "coverage.json").write_text(
            json.dumps({**scan.coverage, "reviews": [host_review]})
        )
    else:
        # Reconstruct the review from an accepted host checkpoint, never from
        # the discovery's untrusted reviews extension.
        publish_review_projection(
            workbench_api, workbench_db, scan, {**scan.coverage, "reviews": [host_review]}
        )
        (scan.scan_dir / "coverage.json").unlink()
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication failure.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        stopped = saved.fail_scan(
            context,
            workbench_db,
            Namespace(
                scan_id=scan.scan_id,
                claim_token=None,
                cost_json=None,
                message="Stopped.",
            ),
        )
    assert stopped["scan"]["resultsRecoveryNeeded"] is retry_publication
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["reviews"] == [host_review]
    assert imported_review not in coverage["reviews"]
    assert result.read_bytes() == original
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("missing_completeness", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_malformed_saved_completeness_preserves_other_valid_coverage(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    missing_completeness,
    retry_publication,
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    source = {
        **scan.coverage,
        "surfaces": [
            {"id": "reviewed", "label": "Retained evidence", "disposition": "no_issue_found"}
        ],
    }
    if missing_completeness:
        source.pop("completeness")
    result.write_text(
        json.dumps({"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": source})
    )
    original = result.read_bytes()
    saved = workbench_api["saved_results"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    recovered = saved.recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert not recovered["resultsRecoveryNeeded"]
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert any(row["label"] == "Retained evidence" for row in coverage["surfaces"])
    assert coverage["completeness"] == "partial"
    assert result.read_bytes() == original


@pytest.mark.parametrize("retained_attempt", [1, 2])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_missing_deferred_uses_retained_surface_from_its_reviewed_attempt(
    workbench_api, workbench_db, publication_scan, monkeypatch, retained_attempt, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,))
    surface = {
        "id": "retained",
        "label": "Retained surface",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    deferred = {"id": "new-gap", "reason": "Verify retained surface.", "surfaceIds": ["retained"]}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "surfaces": [surface],
                    "deferred": [deferred],
                },
            }
        )
    )
    projected_id = f"{worker_id}-attempt-{retained_attempt}-surface-1"
    parent = {
        **scan.coverage,
        "completeness": "partial",
        "surfaces": [
            {
                **surface,
                "id": projected_id,
                "provenance": {
                    "workerId": worker_id,
                    "attempt": retained_attempt,
                    "sourceId": "retained",
                },
            }
        ],
        "deferred": [],
        "reviews": [
            {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
            for attempt in {retained_attempt, 2}
        ],
    }
    (scan.scan_dir / "coverage.json").write_text(json.dumps(parent))
    original = result.read_bytes()
    saved = workbench_api["saved_results"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    saved.recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )
    published = (scan.scan_dir / "coverage.json").read_bytes()
    coverage = json.loads(published)
    task = next(row for row in coverage["deferred"] if row["reason"] == deferred["reason"])
    assert task["surfaceIds"] == [projected_id]
    assert projected_id in {row["id"] for row in coverage["surfaces"]}
    assert result.read_bytes() == original
    saved.recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("missing_surface", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
@pytest.mark.parametrize("with_receipt", [False, True])
def test_retry_recovery_restores_original_attempt_and_retained_deferral(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    missing_surface,
    retry_publication,
    with_receipt,
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    if with_receipt:
        output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
        output.mkdir(parents=True)
        result = output / "result.json"
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
                (str(output), str(result), worker_id),
            )
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,))
    surface = {
        "id": "first-surface",
        "label": "First attempt evidence",
        "disposition": "needs_follow_up",
        "receiptRefs": ["artifacts/review.txt"] if with_receipt else [],
    }
    deferred = {
        "id": "first-gap",
        "reason": "First attempt still needs validation.",
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
            "deferred": [deferred],
        },
    }
    archived = (
        (result.parent.parent if result.parent.name == "output" else result.parent)
        / "attempts"
        / "attempt-1"
        / "result.json"
    )
    archived.parent.mkdir(parents=True)
    if with_receipt:
        for root in (result.parent, archived.parent):
            receipt = root / "artifacts/review.txt"
            receipt.parent.mkdir(exist_ok=True)
            receipt.write_text("Original synthetic review evidence.\n")
    archived.write_text(json.dumps({**draft, "complete": False}))
    result.write_text(json.dumps(draft))
    prefix = f"{worker_id}-attempt-1"
    projected_surface = {
        **surface,
        "id": f"{prefix}-surface-1",
        "receiptRefs": [
            result.relative_to(scan.scan_dir).parent.as_posix() + "/artifacts/review.txt"
        ]
        if with_receipt
        else [],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
    }
    projected_deferred = {
        **deferred,
        "id": f"{prefix}-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": deferred["id"]},
    }
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": [] if missing_surface else [projected_surface],
                "deferred": [projected_deferred],
                "reviews": [
                    {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                    for attempt in (1, 2)
                ],
            }
        )
    )
    originals = {path: path.read_bytes() for path in (result, archived)}
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"] == [projected_surface]
    tasks = [row for row in coverage["deferred"] if row.get("reason") == deferred["reason"]]
    assert tasks == [projected_deferred]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("interrupted_parent", [False, True])
def test_selected_parent_checkpoint_supplies_review_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, interrupted_parent
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    surface = {"id": "review", "label": "Reviewed surface", "disposition": "needs_follow_up"}
    deferred = {"id": "gap", "reason": "Validate the reviewed surface.", "surfaceIds": ["review"]}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "surfaces": [surface],
                    "deferred": [deferred],
                },
            }
        )
    )
    prefix = f"{worker_id}-attempt-1"
    projected_surface = {
        **surface,
        "id": f"{prefix}-surface-1",
        "receiptRefs": [],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
    projected_deferred = {
        **deferred,
        "id": f"{prefix}-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "gap"},
    }
    documents = {
        "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
        "findings": {"findings": []},
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [projected_surface],
            "deferred": [projected_deferred],
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    }
    drafts = scan.scan_dir / "drafts"
    drafts.mkdir()
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    original_write = saved.write_scan_local_bytes

    def interrupt_coverage(root, relative, contents):
        if relative == "coverage.json":
            raise OSError("Synthetic parent publication interruption.")
        original_write(root, relative, contents)

    with monkeypatch.context() as interrupted:
        if interrupted_parent:
            interrupted.setattr(saved, "write_scan_local_bytes", interrupt_coverage)
        args = Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            draft_path=str(staged),
            checkpoint_path=None,
            expected_draft_digest=None,
        )
        if interrupted_parent:
            with pytest.raises(OSError, match="Synthetic parent publication interruption"):
                saved.write_scan_draft(context, workbench_db, args)
        else:
            saved.write_scan_draft(context, workbench_db, args)
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"] == [projected_surface]
    assert [row for row in coverage["deferred"] if row.get("reason") == deferred["reason"]] == [
        projected_deferred
    ]


@pytest.mark.parametrize("padded", [False, True])
def test_retained_worker_string_question_is_not_duplicated(
    workbench_api, workbench_db, publication_scan, padded
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    question = (
        "  Which deployment controls apply?  " if padded else "Which deployment controls apply?"
    )
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "openQuestions": [question]},
            }
        )
    )
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "openQuestions": [
                    {"question": question, "provenance": {"workerId": worker_id, "attempt": 1}}
                ],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
            }
        )
    )
    saved = workbench_api["saved_results"]
    saved.fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["openQuestions"] == [
        {"question": question.strip(), "provenance": {"workerId": worker_id, "attempt": 1}}
    ]


def publish_review_projection(
    workbench_api, connection, scan, coverage, *, findings=None, complete=None
):
    documents = {
        "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
        "findings": {"findings": [] if findings is None else findings},
        "coverage": coverage,
    }
    if complete is not None:
        documents["manifest"]["scan"]["complete"] = complete
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


def stop_and_recover_projection(workbench_api, connection, scan, monkeypatch, retry):
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    with monkeypatch.context() as interrupted:
        if retry:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            context,
            connection,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    saved.recover_scan_results(context, connection, Namespace(scan_id=scan.scan_id))
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, connection, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
    return json.loads(published)


@pytest.mark.parametrize("closure", [False, True], ids=["unchanged", "generic-closure"])
@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
def test_generic_surface_update_preserves_host_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, closure, retry
):
    scan = publication_scan()
    initial = add_worker(workbench_db, scan)
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
    receipt.write_text("Synthetic completed source review.\n")
    surface = {
        "id": "review",
        "label": "Completed source review",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/review.txt"],
    }
    source = {**scan.coverage, "surfaces": [surface], "deferred": []}
    if closure:
        source["resolvedDeferred"] = [{"id": "review", "reason": "Source review completed."}]
    result.write_text(
        json.dumps({"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": source})
    )
    original = result.read_bytes()
    projected = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "receiptRefs": [receipt.relative_to(scan.scan_dir).as_posix()],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
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
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert coverage["surfaces"] == [projected]
    assert result.read_bytes() == original


@pytest.mark.parametrize("duplicate_ids", [False, True], ids=["distinct-ids", "legacy-alias"])
@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
def test_ambiguous_surfaces_preserve_only_host_projections(
    workbench_api, workbench_db, publication_scan, monkeypatch, duplicate_ids, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    surfaces = [
        {
            "id": "review" if duplicate_ids else f"review-{index}",
            "label": f"Independent source review {index}",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
        for index in (1, 2)
    ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "surfaces": surfaces},
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
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": projected,
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert coverage["surfaces"] == projected
    assert result.read_bytes() == original


@pytest.mark.parametrize("field", ["explicitExclusions", "openQuestions"])
@pytest.mark.parametrize(
    "missing", [False, True], ids=["complete-projection", "partial-projection"]
)
@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
def test_partial_projection_keeps_distinct_descriptive_provenance(
    workbench_api, workbench_db, publication_scan, monkeypatch, field, missing, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    base = (
        {"pattern": "vendor/**", "reason": "Review separately."}
        if field == "explicitExclusions"
        else {"question": "Which deployment controls apply?"}
    )
    records = [
        {**base, "provenance": {"description": f"Independent source note {index}"}}
        for index in (1, 2)
    ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, field: records},
            }
        )
    )
    original = result.read_bytes()
    projected = [
        {**record, "provenance": {**record["provenance"], "workerId": worker_id, "attempt": 1}}
        for record in (records[:1] if missing else records)
    ]
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            field: projected,
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
        },
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert [row["provenance"]["description"] for row in coverage[field]] == [
        record["provenance"]["description"] for record in records
    ]
    assert result.read_bytes() == original


@pytest.mark.parametrize("same_worker", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_reported_parent_surface_uses_the_finding_worker_namespace(
    workbench_api, workbench_db, publication_scan, monkeypatch, same_worker, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    finding_result = result if same_worker else add_worker(workbench_db, scan)
    finding_worker = finding_result.parent.name
    candidate = "shared-candidate"
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"] = {
        "source": "local_plugin",
        "workerId": finding_worker,
        "attempt": 1,
        "candidateId": candidate,
    }
    surface = {
        "id": "review",
        "candidateId": candidate,
        "label": "Independent review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    task = {"id": "gap", "candidateId": candidate, "reason": "Validate independent evidence."}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [finding] if same_worker else [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "surfaces": [surface],
                    "deferred": [task],
                },
            }
        )
    )
    if not same_worker:
        finding_result.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": True,
                    "findings": [finding],
                    "coverage": scan.coverage,
                }
            )
        )
    originals = {path: path.read_bytes() for path in {result, finding_result}}
    projected = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "disposition": "reported",
        "provenance": {
            "workerId": worker_id,
            "attempt": 1,
            "sourceId": "review",
            "candidateId": candidate,
        },
    }
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "surfaces": [projected],
            "deferred": [],
            "reviews": [
                {"workerId": owner, "attempt": 1, "completeness": "partial"}
                for owner in {worker_id, finding_worker}
            ],
        },
        findings=[finding],
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    pending = [row for row in coverage["deferred"] if row.get("reason") == task["reason"]]
    assert len(pending) == int(not same_worker)
    if pending:
        assert pending[0]["provenance"]["workerId"] == worker_id
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("clear_question", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_historical_parent_review_marker_does_not_restore_cleared_question(
    workbench_api, workbench_db, publication_scan, monkeypatch, clear_question, retry
):
    scan = publication_scan()
    question = {"question": "Which deployment applies?"}
    earlier = {
        **scan.coverage,
        "completeness": "partial",
        "openQuestions": [question],
        "reviews": [],
    }
    publish_review_projection(workbench_api, workbench_db, scan, earlier, complete=False)
    current = {**earlier, "openQuestions": [] if clear_question else [question]}
    publish_review_projection(workbench_api, workbench_db, scan, current, complete=True)
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert coverage.get("openQuestions", []) == ([] if clear_question else [question])


@pytest.mark.parametrize("padded", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_incomplete_standard_question_matches_its_canonical_text(
    workbench_api, workbench_db, publication_scan, monkeypatch, padded, retry
):
    scan = publication_scan(mode="standard")
    question = "Which deployment applies?"
    raw = f"  {question}  " if padded else question
    write_checkpoint(
        scan.scan_dir / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {**scan.coverage, "completeness": "partial", "openQuestions": [raw]},
        },
    )
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            "openQuestions": [{"question": question}],
        },
        complete=False,
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert coverage["openQuestions"] == [{"question": question}]


@pytest.mark.parametrize("ambiguous", [False, True])
@pytest.mark.parametrize("reopened", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_reopened_pending_rows_use_the_existing_host_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, ambiguous, reopened, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    surface = {
        "id": "review",
        "label": "Reviewed surface",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    tasks = [
        {"id": "gap", "reason": f"Validate evidence {index}.", "surfaceIds": ["review"]}
        for index in range(2 if ambiguous else 1)
    ]
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [surface],
            "deferred": tasks,
        },
    }
    if reopened:
        earlier = write_checkpoint(
            result.parent / "checkpoints",
            {
                **draft,
                "complete": False,
                "coverage": {
                    **scan.coverage,
                    "surfaces": [],
                    "deferred": [],
                    "resolvedDeferred": [{"id": "gap", "reason": "Earlier closure."}],
                },
            },
        )
        os.utime(earlier, ns=(100, 100))
    result.write_text(json.dumps(draft))
    os.utime(result, ns=(200, 200))
    original = result.read_bytes()
    projected_surface = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
    projected_tasks = [
        {
            **task,
            "id": f"{worker_id}-attempt-1-deferred-{index}",
            "surfaceIds": [projected_surface["id"]],
            "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "gap"},
        }
        for index, task in enumerate(tasks, 1)
    ]
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [projected_surface],
            "deferred": projected_tasks,
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert [
        row for row in coverage["deferred"] if row.get("id") != "scan-stopped"
    ] == projected_tasks
    assert coverage["surfaces"] == [projected_surface]
    assert result.read_bytes() == original


@pytest.mark.skipif(
    not (
        Path(__file__).resolve().parents[1] / "mcp-app/node_modules/esbuild/package.json"
    ).is_file(),
    reason="Requires installed MCP JavaScript integration dependencies.",
)
@pytest.mark.parametrize("interrupted_reducer", [False, True], ids=["accepted", "interrupted"])
@pytest.mark.parametrize("retry_publication", [False, True], ids=["direct", "failed-retry"])
def test_recovery_excludes_unaccepted_reducer_review_summaries(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    interrupted_reducer,
    retry_publication,
):
    scan = publication_scan()
    discovery = add_worker(workbench_db, scan)
    worker_id = discovery.parent.name
    discovery.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "coverage": scan.coverage,
            }
        )
    )
    reducer = add_worker(
        workbench_db, scan, status="failed" if interrupted_reducer else "succeeded"
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
            (reducer.parent.name,),
        )
    imported_review = {
        "workerId": "synthetic-unaccepted-review",
        "attempt": 99,
        "completeness": "complete",
    }
    exclusion = {"pattern": "synthetic-vendor/**", "reason": "Retained reducer evidence."}
    reducer.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "coverage": {
                    **scan.coverage,
                    "reviews": [imported_review],
                    "explicitExclusions": [exclusion],
                },
            }
        )
    )
    # This control publishes the parent before the worker results; explicit
    # timestamps keep that chronology independent of filesystem clock resolution.
    for path in [
        scan.scan_dir / name for name in ["coverage.json", "findings.json", "scan-manifest.json"]
    ]:
        os.utime(path, ns=(100, 100))
    for path in (scan.scan_dir / "checkpoints").glob("*.json"):
        os.utime(path, ns=(100, 100))
    os.utime(discovery, ns=(200, 200))
    os.utime(reducer, ns=(300, 300))
    original = reducer.read_bytes()
    helper = (
        Path(__file__).resolve().parents[1]
        / "mcp-app"
        / "tests"
        / "interrupted_reducer_fixture.mjs"
    )
    subprocess.run(
        [
            "node",
            "--experimental-strip-types",
            str(helper),
            str(scan.scan_dir),
            str(discovery),
            str(reducer),
            str(interrupted_reducer).lower(),
        ],
        check=True,
    )
    if interrupted_reducer:
        assert reducer.read_bytes() == original
    else:
        assert json.loads(reducer.read_text())["sourceCoverage"]["reviews"] == [
            {"workerId": worker_id, "attempt": 1, "completeness": "complete"}
        ]
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication failure.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        stopped = saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    assert stopped["scan"]["resultsRecoveryNeeded"] is retry_publication
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    published = (scan.scan_dir / "coverage.json").read_bytes()
    coverage = json.loads(published)
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["summary"] == scan.findings[0]["summary"]
    if interrupted_reducer:
        assert any(
            all(row.get(key) == value for key, value in exclusion.items())
            for row in coverage["explicitExclusions"]
        )
        assert reducer.read_bytes() == original
    assert coverage["reviews"] == [
        {"workerId": worker_id, "attempt": 1, "completeness": "complete"}
    ]
    assert imported_review not in coverage["reviews"]
    assert imported_review["workerId"] not in (scan.scan_dir / "report.md").read_text()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("complete_markers", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_tied_parent_observations_retain_both_worker_review_markers(
    workbench_api, workbench_db, publication_scan, monkeypatch, complete_markers, retry
):
    scan = publication_scan()
    results = [add_worker(workbench_db, scan), add_worker(workbench_db, scan)]
    workers = [result.parent.name for result in results]
    projections = []
    for index, (result, owner) in enumerate(zip(results, workers), 1):
        surface = {
            "id": "source-surface",
            "label": f"Independent surface {index}",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
        task = {
            "id": "source-task",
            "reason": f"Review {surface['label']}.",
            "surfaceIds": [surface["id"]],
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
                        "surfaces": [surface],
                        "deferred": [task],
                    },
                }
            )
        )
        prefix = f"{owner}-attempt-1"
        projected_surface = {
            **surface,
            "id": f"{prefix}-surface-1",
            "provenance": {"workerId": owner, "attempt": 1, "sourceId": surface["id"]},
        }
        projected_task = {
            **task,
            "id": f"{prefix}-deferred-1",
            "surfaceIds": [projected_surface["id"]],
            "provenance": {"workerId": owner, "attempt": 1, "sourceId": task["id"]},
        }
        projections.append(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": [projected_surface],
                "deferred": [projected_task],
                "reviews": [
                    {"workerId": worker, "attempt": 1, "completeness": "partial"}
                    for worker in (workers if complete_markers else [owner])
                ],
            }
        )
    publish_review_projection(workbench_api, workbench_db, scan, projections[0])
    saved = workbench_api["saved_results"]
    original_write = saved.write_scan_local_bytes

    def fail_coverage(root, relative, contents):
        if relative == "coverage.json":
            raise OSError("Synthetic tied parent publication failure.")
        original_write(root, relative, contents)

    with monkeypatch.context() as interrupted:
        interrupted.setattr(saved, "write_scan_local_bytes", fail_coverage)
        with pytest.raises(OSError, match="Synthetic tied parent publication failure"):
            publish_review_projection(workbench_api, workbench_db, scan, projections[1])
    tied = 2_000_000_000
    for path in [
        scan.scan_dir / name
        for name in ["coverage.json", "findings.json", "scan-manifest.json", "checkpoint-head.json"]
    ]:
        os.utime(path, ns=(tied, tied))
    for path in (scan.scan_dir / "checkpoints").glob("*.json"):
        os.utime(path, ns=(tied, tied))
    originals = {path: path.read_bytes() for path in results}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert len(coverage["surfaces"]) == 2
    tasks = [row for row in coverage["deferred"] if row.get("id") != "scan-stopped"]
    assert len(tasks) == 2
    assert {row["provenance"]["workerId"] for row in coverage["surfaces"]} == set(workers)
    assert {row["workerId"] for row in coverage["reviews"]} == set(workers)
    surfaces = {row["id"]: row["label"] for row in coverage["surfaces"]}
    for task in tasks:
        assert surfaces[task["surfaceIds"][0]] in task["reason"]
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("inserted", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_new_selected_worker_surface_links_keep_retained_surface_identity(
    workbench_api, workbench_db, publication_scan, monkeypatch, inserted, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker = result.parent.name
    first = {
        "id": "first",
        "label": "First retained surface",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    second = {
        "id": "second",
        "label": "Second newly selected surface",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [first],
            "deferred": [],
        },
    }
    result.write_text(json.dumps(draft))
    projected = {
        **first,
        "id": f"{worker}-attempt-1-surface-1",
        "provenance": {"workerId": worker, "attempt": 1, "sourceId": "first"},
    }
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [projected],
            "deferred": [],
            "reviews": [{"workerId": worker, "attempt": 1, "completeness": "partial"}],
        },
    )
    task = {
        "id": "follow-up",
        "reason": "Review second newly selected surface."
        if inserted
        else "Review first retained surface.",
        "surfaceIds": ["second" if inserted else "first"],
    }
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        {
            **draft,
            "coverage": {
                **draft["coverage"],
                "surfaces": [second, first] if inserted else [first],
                "deferred": [task],
            },
        },
    )
    head = result.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    originals = {path: path.read_bytes() for path in [result, checkpoint, head]}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    surfaces = {row["label"]: row for row in coverage["surfaces"]}
    assert surfaces[first["label"]]["id"] == projected["id"]
    expected = second if inserted else first
    pending = next(row for row in coverage["deferred"] if row.get("reason") == task["reason"])
    assert pending["surfaceIds"] == [surfaces[expected["label"]]["id"]]
    assert len(surfaces) == (2 if inserted else 1)
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("field", ["surfaces", "deferred"])
@pytest.mark.parametrize(
    "named_result", [0, 1, 2], ids=["optional-id", "explicit-id", "distinct-ids"]
)
@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
def test_restored_optional_worker_id_matches_accepted_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, field, named_result, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker = result.parent.name
    item = (
        {"label": "Synthetic pending surface", "disposition": "needs_follow_up", "receiptRefs": []}
        if field == "surfaces"
        else {"reason": "Review the synthetic pending task."}
    )
    named = {**item, "id": "source-record"}
    source = named if named_result else item
    records = [source]
    checkpoint_records = [named]
    if named_result == 2:
        sibling = {**named, "id": "source-sibling"}
        records.append(sibling)
        checkpoint_records.append(sibling)
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {**scan.coverage, field: records},
    }
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        {**draft, "complete": False, "coverage": {**draft["coverage"], field: checkpoint_records}},
    )
    result.write_text(json.dumps(draft))
    kind = "surface" if field == "surfaces" else "deferred"
    projection = {
        **source,
        "id": f"{worker}-attempt-1-{kind}-1",
        "provenance": {
            "workerId": worker,
            "attempt": 1,
            **({"sourceId": "source-record"} if named_result else {}),
        },
    }
    projections = [projection]
    if named_result == 2:
        projections.append(
            {
                **projection,
                "id": f"{worker}-attempt-1-{kind}-2",
                "provenance": {**projection["provenance"], "sourceId": "source-sibling"},
            }
        )
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            field: projections,
            "reviews": [{"workerId": worker, "attempt": 1, "completeness": "complete"}],
        },
    )
    originals = {path: path.read_bytes() for path in [result, checkpoint]}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    records = [record for record in coverage[field] if record.get("id") != "scan-stopped"]
    assert records == projections
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize(
    "projected_alias", [False, True], ids=["raw-candidate", "projected-candidate"]
)
@pytest.mark.parametrize(
    "worker_state", ["pending", "canceled", "accepted-pending", "host-projection"]
)
@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
def test_parent_extensions_do_not_resolve_unreviewed_child_candidate(
    workbench_api, workbench_db, publication_scan, monkeypatch, worker_state, retry, projected_alias
):
    scan = publication_scan()
    accepted_worker = worker_state == "host-projection"
    result = add_worker(
        workbench_db,
        scan,
        status="running"
        if worker_state == "pending"
        else "canceled"
        if worker_state == "canceled"
        else "succeeded",
    )
    worker = result.parent.name
    pending = {
        "id": "pending-surface",
        "candidateId": "candidate-1",
        "label": "Unresolved synthetic child candidate",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    task = {"id": "pending-task", "candidateId": "candidate-1", "reason": "Review child evidence."}
    draft = {
        "scanId": scan.scan_id,
        "complete": False,
        "findings": [],
        "coverage": {**scan.coverage, "surfaces": [pending], "deferred": [task]},
    }
    checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
    rejected = {**pending, "disposition": "rejected"}
    result.write_text(
        json.dumps(
            {
                **draft,
                "complete": True,
                "coverage": {**draft["coverage"], "surfaces": [rejected], "deferred": []},
            }
            if accepted_worker
            else {**draft, "complete": worker_state == "accepted-pending"}
        )
    )
    projected = {
        **rejected,
        "id": f"{worker}-attempt-1-surface-1",
        "candidateId": f"{worker}-attempt-1-candidate-1" if projected_alias else "candidate-1",
        "provenance": {
            "workerId": worker,
            "attempt": 1,
            "sourceId": pending["id"],
            "candidateId": "candidate-1",
        },
    }
    review = {"workerId": worker, "attempt": 1, "completeness": "complete"}
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {**scan.coverage, "surfaces": [projected], "deferred": [], "reviews": [review]},
        complete=False,
    )
    originals = {path: path.read_bytes() for path in [result, checkpoint]}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert projected in coverage["surfaces"]
    assert review in coverage["reviews"]
    accepted_review = accepted_worker or (projected_alias and worker_state == "accepted-pending")
    assert (
        any(row.get("reason") == task["reason"] for row in coverage["deferred"])
        is not accepted_review
    )
    assert (
        any(row.get("disposition") == "needs_follow_up" for row in coverage["surfaces"])
        is not accepted_review
    )
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize(
    "receipt_state",
    ["copied", "changed", "missing-archive", "shared-archive", "shared-archive-missing"],
)
def test_reconstructed_retry_surface_compares_receipt_bytes(
    workbench_api, workbench_db, publication_scan, monkeypatch, receipt_state, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ?, attempt = 2 WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    archived = output.parent / "attempts" / "attempt-01" / "result.json"
    archived.parent.mkdir(parents=True)
    surface = {
        "id": "review",
        "label": "Synthetic source evidence",
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
            "deferred": [
                {"id": "gap", "reason": "Validate this source.", "surfaceIds": ["review"]}
            ],
        },
    }
    result.write_text(json.dumps(draft))
    archived.write_text(json.dumps({**draft, "complete": False}))
    for directory in (output, archived.parent):
        receipt = directory / "artifacts/review.txt"
        receipt.parent.mkdir()
        receipt.write_text("Original synthetic evidence.\n")
    if receipt_state == "changed":
        (output / "artifacts/review.txt").write_text("Changed synthetic evidence.\n")
    if receipt_state in {"missing-archive", "shared-archive-missing"}:
        (archived.parent / "artifacts/review.txt").unlink()
    if receipt_state.startswith("shared-archive"):
        draft["coverage"]["surfaces"][0]["receiptRefs"] = [
            (archived.parent / "artifacts/review.txt").relative_to(scan.scan_dir).as_posix()
        ]
        result.write_text(json.dumps(draft))
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "reviews": [
                {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                for attempt in (1, 2)
            ],
        },
    )
    originals = {path: path.read_bytes() for path in (result, archived)}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    expected_attempt = (
        1 if receipt_state == "copied" or receipt_state.startswith("shared-archive") else 2
    )
    assert len(coverage["surfaces"]) == 1
    retained = coverage["surfaces"][0]
    assert retained["provenance"]["attempt"] == expected_attempt
    assert retained["id"] == f"{worker_id}-attempt-{expected_attempt}-surface-1"
    if receipt_state == "shared-archive-missing":
        assert retained["receiptRefs"] == []
        assert retained["disposition"] == "needs_follow_up"
        assert coverage["completeness"] == "partial"
    else:
        assert retained["receiptRefs"] == [
            (
                (archived.parent if receipt_state.startswith("shared-archive") else output)
                / "artifacts/review.txt"
            )
            .relative_to(scan.scan_dir)
            .as_posix()
        ]
    gap = next(row for row in coverage["deferred"] if row.get("reason") == "Validate this source.")
    assert gap["surfaceIds"] == [retained["id"]]
    assert all(path.read_bytes() == data for path, data in originals.items())


@pytest.mark.parametrize("count", [20, 40])
def test_dense_retained_projection_keeps_every_linked_record(
    workbench_api, workbench_db, publication_scan, count
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    surfaces = [
        {
            "id": f"surface-{index}",
            "label": f"Synthetic surface {index}",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
        for index in range(count)
    ]
    deferred = [
        {
            "id": f"gap-{index}",
            "reason": f"Synthetic remaining review {index}",
            "surfaceIds": [surfaces[index]["id"]],
        }
        for index in range(count)
    ]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "surfaces": surfaces, "deferred": deferred},
            }
        )
    )
    original = result.read_bytes()
    projected_surfaces = [
        {
            **row,
            "id": f"{worker_id}-attempt-1-surface-{index + 1}",
            "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": row["id"]},
        }
        for index, row in enumerate(surfaces)
    ]
    projected_deferred = [
        {
            **row,
            "id": f"{worker_id}-attempt-1-deferred-{index + 1}",
            "surfaceIds": [projected_surfaces[index]["id"]],
            "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": row["id"]},
        }
        for index, row in enumerate(deferred)
    ]
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "surfaces": projected_surfaces,
            "deferred": projected_deferred,
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    )
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"] == projected_surfaces
    assert [
        row for row in coverage["deferred"] if row.get("id") != "scan-stopped"
    ] == projected_deferred
    assert result.read_bytes() == original


@pytest.mark.parametrize("archived", [False, True], ids=["one-attempt", "two-attempts"])
@pytest.mark.parametrize("mode", ["idless", "explicit"])
@pytest.mark.parametrize(
    ("projection", "with_receipt_refs"),
    [("full", True), ("partial", True), ("none", True), ("none", False)],
)
@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
def test_legacy_occurrences_survive_supported_parent_projection(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    projection,
    with_receipt_refs,
    retry,
    archived,
):
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-scan-mcp/v1' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    if archived:
        output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
        output.mkdir(parents=True)
        result = output / "result.json"
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET attempt = 2, artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
                (str(output), str(result), worker_id),
            )
    surface = {
        "label": "Synthetic repeated legacy observation",
        "disposition": "needs_follow_up",
    }
    if with_receipt_refs:
        surface["receiptRefs"] = []
    surfaces = [
        {**surface, **({"id": "legacy-first"} if mode == "explicit" else {})},
        {**surface, **({"id": "legacy-second"} if mode == "explicit" else {})},
    ]
    # Accepted older worker outputs can persist two equal rows without IDs.
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "surfaces": surfaces},
            }
        )
    )
    original = result.read_bytes()
    originals = {result: original}
    if archived:
        archive = result.parent.parent / "attempts/attempt-1/result.json"
        archive.parent.mkdir(parents=True)
        prior = json.loads(original)
        prior["coverage"]["surfaces"] = prior["coverage"]["surfaces"][:1]
        archive.write_text(json.dumps(prior))
        originals[archive] = archive.read_bytes()
    surfaces = json.loads(original)["coverage"]["surfaces"]
    assert len(surfaces) == 2
    projected = []
    for index, surface in enumerate(surfaces, 1):
        attempt = index if archived else 1
        provenance = {"workerId": worker_id, "attempt": attempt}
        if "id" in surface:
            provenance["sourceId"] = surface["id"]
        projected.append(
            {
                **copy.deepcopy(surface),
                "receiptRefs": surface.get("receiptRefs", []),
                "id": f"{worker_id}-attempt-{attempt}-surface-{index}",
                "provenance": provenance,
            }
        )
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": (
                projected
                if projection == "full"
                else projected[:1]
                if projection == "partial"
                else []
            ),
            "reviews": [
                {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                for attempt in ((1, 2) if archived else (1,))
            ],
        },
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert len(coverage["surfaces"]) == 2
    assert coverage["surfaces"][0] == projected[0]
    assert [row["provenance"]["attempt"] for row in coverage["surfaces"]] == (
        [1, 2] if archived else [1, 1]
    )
    assert coverage["surfaces"][1]["id"] == (
        f"{worker_id}-attempt-{2 if archived else 1}-surface-2"
    )
    for path, saved in originals.items():
        assert path.read_bytes() == saved
