from __future__ import annotations

import copy
import json
import uuid
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


def publish_review_projection(
    workbench_api, connection, scan, coverage, *, findings=None, complete=None
):
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'running', coordinator_generation = 2, "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    documents = {
        "deepScanPublication": {"coordinatorGeneration": 2, "resultPath": None},
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


@pytest.mark.parametrize(
    ("missing_surface", "retry_publication", "with_receipt", "accepted_attempt"),
    [
        (missing, retry, receipt, 1)
        for missing in (False, True)
        for retry in (False, True)
        for receipt in (False, True)
    ]
    + [(False, False, True, 2), (False, True, True, 2)],
)
def test_retry_recovery_restores_original_attempt_and_retained_deferral(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    missing_surface,
    retry_publication,
    with_receipt,
    accepted_attempt,
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
    prefix = f"{worker_id}-attempt-{accepted_attempt}"
    projected_surface = {
        **surface,
        "id": f"{prefix}-surface-1",
        "receiptRefs": [
            result.relative_to(scan.scan_dir).parent.as_posix() + "/artifacts/review.txt"
        ]
        if with_receipt
        else [],
        "provenance": {
            "workerId": worker_id,
            "attempt": accepted_attempt,
            "sourceId": surface["id"],
        },
    }
    projected_deferred = {
        **deferred,
        "id": f"{prefix}-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {
            "workerId": worker_id,
            "attempt": accepted_attempt,
            "sourceId": deferred["id"],
        },
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
    coverage = stop_and_recover_projection(
        workbench_api, workbench_db, scan, monkeypatch, retry_publication
    )
    if missing_surface:
        projected_surface["id"] = f"{worker_id}-attempt-2-surface-1"
        projected_deferred["surfaceIds"] = [projected_surface["id"]]
    assert coverage["surfaces"] == [projected_surface]
    tasks = [row for row in coverage["deferred"] if row.get("reason") == deferred["reason"]]
    assert tasks == [projected_deferred]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize(
    "receipt_state",
    [
        "copied",
        "changed",
        "changed-retained-parent",
        "copied-archive-path-retained-parent",
        "changed-archive-path-retained-parent",
        "copied-nested-archive-path-retained-parent",
        "changed-nested-archive-path-retained-parent",
        "missing-archive",
        "shared-archive",
        "shared-archive-missing",
    ],
)
def test_reconstructed_retry_surface_compares_receipt_bytes(
    workbench_api, workbench_db, publication_scan, monkeypatch, receipt_state, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    current_attempt = 3 if "nested" in receipt_state else 2
    output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ?, attempt = ? WHERE id = ?",
            (str(output), str(result), current_attempt, worker_id),
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
    current_receipt = output / "artifacts/review.txt"
    if "archive-path" in receipt_state:
        current_receipt = output / "artifacts/archived-receipts/attempt-01/artifacts/review.txt"
        current_receipt.parent.mkdir(parents=True)
        current_receipt.write_bytes((archived.parent / "artifacts/review.txt").read_bytes())
        draft["coverage"]["surfaces"][0]["receiptRefs"] = [
            current_receipt.relative_to(output).as_posix()
        ]
        result.write_text(json.dumps(draft))
    saved_sources = [result, archived]
    if "nested" in receipt_state:
        second_archive = output.parent / "attempts/attempt-02/result.json"
        second_archive.parent.mkdir(parents=True)
        second_archive.write_text(json.dumps({**draft, "complete": False}))
        saved_sources.append(second_archive)
        second_receipt = second_archive.parent / current_receipt.relative_to(output)
        second_receipt.parent.mkdir(parents=True)
        second_receipt.write_bytes(current_receipt.read_bytes())
        nested_receipt = (
            output / "artifacts/archived-receipts/attempt-02" / current_receipt.relative_to(output)
        )
        nested_receipt.parent.mkdir(parents=True)
        nested_receipt.write_bytes(current_receipt.read_bytes())
        current_receipt = nested_receipt
        draft["coverage"]["surfaces"][0]["receiptRefs"] = [
            current_receipt.relative_to(output).as_posix()
        ]
        result.write_text(json.dumps(draft))
    retained_parent = receipt_state.endswith("retained-parent")
    parent_identity_attempt = current_attempt if "nested" in receipt_state else 1
    parent_surface = {
        **surface,
        "id": f"{worker_id}-attempt-{parent_identity_attempt}-surface-1",
        "receiptRefs": [current_receipt.relative_to(scan.scan_dir).as_posix()],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "surfaces": [parent_surface] if retained_parent else [],
            "reviews": [
                {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                for attempt in range(1, current_attempt + 1)
            ],
        },
    )
    if receipt_state.startswith("changed") and retained_parent:
        current_receipt.write_text("Changed synthetic evidence.\n")
    originals = {path: path.read_bytes() for path in saved_sources}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    expected_attempt = (
        1 if receipt_state.startswith(("copied", "shared-archive")) else current_attempt
    )
    if receipt_state.startswith("changed") and retained_parent:
        assert parent_surface in coverage["surfaces"]
        current_surfaces = [row for row in coverage["surfaces"] if row != parent_surface]
        assert len(current_surfaces) == 1
        retained = current_surfaces[0]
    else:
        assert len(coverage["surfaces"]) == 1
        retained = coverage["surfaces"][0]
    assert retained["provenance"]["attempt"] == expected_attempt
    if retained_parent and receipt_state.startswith("copied"):
        assert retained["id"] == parent_surface["id"]
    else:
        assert retained["id"].startswith(f"{worker_id}-attempt-{current_attempt}-surface-1")
        if retained_parent:
            assert retained["id"] != parent_surface["id"]
    if receipt_state == "shared-archive-missing":
        assert retained["receiptRefs"] == []
        assert retained["disposition"] == "needs_follow_up"
        assert "completeness" not in coverage
    else:
        assert retained["receiptRefs"] == [
            (
                archived.parent / "artifacts/review.txt"
                if receipt_state.startswith("shared-archive")
                else current_receipt
            )
            .relative_to(scan.scan_dir)
            .as_posix()
        ]
    gap = next(row for row in coverage["deferred"] if row.get("reason") == "Validate this source.")
    assert gap["surfaceIds"] == [retained["id"]]
    assert all(path.read_bytes() == data for path, data in originals.items())


@pytest.mark.parametrize("retry", [False, True], ids=["direct", "failed-retry"])
@pytest.mark.parametrize(
    ("field", "archived", "projection"),
    [
        ("openQuestionStrings", True, "none"),
        ("openQuestionStrings", True, "partial"),
        ("deferred", False, "full"),
    ],
)
def test_recovery_preserves_non_surface_occurrence_origins(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry, field, archived, projection
):
    string_questions = field == "openQuestionStrings"
    if string_questions:
        field = "openQuestions"
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
    row = {
        "deferred": {"reason": "Synthetic repeated remaining review."},
        "explicitExclusions": {"pattern": "vendor/**", "reason": "Review separately."},
        "openQuestions": {"question": "Which synthetic deployment controls apply?"},
    }[field]
    saved_row = row["question"] if string_questions else row
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {**scan.coverage, "completeness": "partial", field: [saved_row, saved_row]},
    }
    result.write_text(json.dumps(draft))
    originals = {result: result.read_bytes()}
    if archived:
        archive = result.parent.parent / "attempts/attempt-1/result.json"
        archive.parent.mkdir(parents=True)
        prior = copy.deepcopy(draft)
        prior["coverage"][field] = prior["coverage"][field][:1]
        archive.write_text(json.dumps(prior))
        originals[archive] = archive.read_bytes()
    projected = []
    for index in (1, 2):
        attempt = index if archived else 1
        projected.append(
            {
                **row,
                **(
                    {"id": f"{worker_id}-attempt-{attempt}-deferred-{index}"}
                    if field == "deferred"
                    else {}
                ),
                "provenance": {"workerId": worker_id, "attempt": attempt},
            }
        )
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            field: projected
            if projection == "full"
            else projected[:1]
            if projection == "partial"
            else [],
            "reviews": [
                {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                for attempt in ((1, 2) if archived else (1,))
            ],
        },
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    rows = [row for row in coverage[field] if row.get("id") != "scan-stopped"]
    assert len(rows) == 2
    assert [row["provenance"]["attempt"] for row in rows] == ([1, 2] if archived else [1, 1])
    if field == "deferred":
        assert len({row["id"] for row in rows}) == 2
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_selected_parent_projection_consumes_each_occurrence_once(
    workbench_api, workbench_db, publication_scan, monkeypatch, complete, retry
):
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = ? WHERE scan_id = ?",
            ("deep-scan-mcp/v1", scan.scan_id),
        )
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    task = {"reason": "Synthetic repeated accepted review."}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "deferred": [task, task]},
            }
        )
    )
    original = result.read_bytes()
    projected = [
        {
            **task,
            "id": identity,
            "provenance": {"workerId": worker_id, "attempt": 1},
        }
        for identity in ("retained-first", "retained-second")
    ]
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "completeness": "partial",
            "deferred": copy.deepcopy(projected),
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
        complete=complete,
    )
    accepted = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert accepted["deferred"] == projected
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    retained = [row for row in coverage["deferred"] if row.get("id") != "scan-stopped"]
    assert result.read_bytes() == original
    assert retained == projected


@pytest.mark.parametrize(
    "case",
    [
        "retained_parent_null",
        "raw_null",
        "raw_many_null_rows",
        "parent_attempt_list",
        "parent_attempt_object",
    ],
)
def test_reviewed_missing_deferred_recovers_malformed_worker_surfaces(
    workbench_api, workbench_db, publication_scan, monkeypatch, case
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
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
    projected_surface = {
        **surface,
        "id": f"{worker_id}-attempt-1-surface-1",
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
    }
    raw = {
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
    parent = {
        **scan.coverage,
        "completeness": "partial",
        "surfaces": [projected_surface],
        "deferred": [],
        "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
    }
    if case == "retained_parent_null":
        parent["surfaces"] = None
        parent["deferred"] = [
            {
                **deferred,
                "id": f"{worker_id}-attempt-1-deferred-1",
                "candidateId": f"{worker_id}-attempt-1-candidate-1",
                "surfaceIds": [projected_surface["id"]],
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": deferred["id"],
                    "candidateId": deferred["candidateId"],
                },
            }
        ]
    elif case == "raw_null":
        raw["coverage"]["surfaces"] = None
    elif case == "raw_many_null_rows":
        raw["coverage"]["deferred"] = [None] * 30 + [deferred]
    else:
        projected_surface["provenance"]["attempt"] = [] if case.endswith("list") else {}
    result.write_text(json.dumps(raw))
    original = result.read_bytes()
    (scan.scan_dir / "coverage.json").write_text(json.dumps(parent))
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, False)
    assert isinstance(coverage["surfaces"], list)
    assert "completeness" not in coverage
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == 1
    assert pending[0]["provenance"]["workerId"] == worker_id
    assert pending[0]["provenance"]["attempt"] == 1
    assert result.read_bytes() == original


@pytest.mark.parametrize("retry", [False, True])
def test_retained_surface_occurrences_match_each_receipt(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    surfaces, projected = [], []
    for name in ("first", "second"):
        receipt = result.parent / "artifacts" / f"{name}.txt"
        receipt.parent.mkdir(exist_ok=True)
        receipt.write_text(f"Synthetic {name} source evidence.\n")
        surface = {
            "id": "review",
            "label": "Synthetic source review",
            "disposition": "needs_follow_up",
            "receiptRefs": [f"artifacts/{name}.txt"],
        }
        surfaces.append(surface)
        projected.append(
            {
                **surface,
                "id": f"retained-{name}",
                "receiptRefs": [receipt.relative_to(scan.scan_dir).as_posix()],
                "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
            }
        )
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "surfaces": surfaces},
            }
        )
    )
    original = result.read_bytes()
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "surfaces": projected,
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    )
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert coverage["surfaces"] == projected
    assert result.read_bytes() == original


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("tampered", [False, True])
@pytest.mark.parametrize("local_collision", [False, True])
def test_canonical_shared_receipt_keeps_authenticated_owner_on_retry(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry, tampered, local_collision
):
    scan = publication_scan()
    initial = add_worker(workbench_db, scan)
    worker_id = initial.parent.name
    output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ?, attempt = 2 WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    ref = "artifacts/01_context/synthetic-evidence.txt"
    shared, local = scan.scan_dir / ref, output / ref
    for receipt, contents in (
        (shared, "Synthetic shared evidence.\n"),
        (local, "Different synthetic retry evidence.\n"),
    ):
        if receipt == local and not local_collision:
            continue
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(contents)
    surface = {
        "id": "review",
        "label": "Synthetic shared review",
        "disposition": "needs_follow_up",
        "receiptRefs": [ref],
        "provenance": {"scanReceiptRefs": [ref]},
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
                {"id": "gap", "reason": "Validate the shared source.", "surfaceIds": ["review"]}
            ],
        },
    }
    archived = output.parent / "attempts/attempt-01/result.json"
    archived.parent.mkdir(parents=True)
    archived_draft = {**draft, "complete": False}
    archived.write_text(json.dumps(archived_draft))
    checkpoints = [
        write_checkpoint(archived.parent / "checkpoints", archived_draft),
        write_checkpoint(output / "checkpoints", draft),
    ]
    if tampered:
        # The surface still matches, but the complete payload no longer does.
        draft["coverage"]["openQuestions"] = ["Additional synthetic review context."]
    result.write_text(json.dumps(draft))
    parent = {
        **surface,
        "id": f"{worker_id}-attempt-2-surface-1",
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "surfaces": [parent],
            "reviews": [
                {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                for attempt in (1, 2)
            ],
        },
    )
    originals = {
        path: path.read_bytes()
        for path in [result, archived, shared, local, *checkpoints]
        if path.is_file()
    }
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    if tampered:
        assert parent in coverage["surfaces"]
        current = [row for row in coverage["surfaces"] if row != parent]
        assert len(current) == 1
        assert current[0]["provenance"]["attempt"] == 2
        selected = local if local_collision else shared
        assert current[0]["receiptRefs"] == [selected.relative_to(scan.scan_dir).as_posix()]
    else:
        assert coverage["surfaces"] == [parent]
        pending = next(
            row
            for row in coverage["deferred"]
            if row.get("reason") == "Validate the shared source."
        )
        assert pending["surfaceIds"] == [parent["id"]]
    assert all("scanReceiptRefs" not in row.get("provenance", {}) for row in coverage["surfaces"])
    assert all(path.read_bytes() == data for path, data in originals.items())


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize(
    "change",
    ["unchanged", "changed-copy", "other-owner", "changed-closure", "new-closure", "receipt-only"],
)
def test_third_retry_receipt_repair_preserves_bound_canonical_identity(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry, change
):
    scan = publication_scan()
    initial = add_worker(workbench_db, scan)
    worker_id = initial.parent.name
    output = scan.scan_dir / "artifacts/deep_discovery/workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ?, attempt = 3 WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    original = "artifacts/original.md"
    replacement = "artifacts/replacement.md"
    first_copy = f"artifacts/archived-receipts/attempt-01/{original}"
    second_copy = f"artifacts/archived-receipts/attempt-02/{replacement}"
    nested_copy = f"artifacts/archived-receipts/attempt-02/{first_copy}"
    first = output.parent / "attempts/attempt-01"
    second = output.parent / "attempts/attempt-02"
    for directory, refs in (
        (first, [original]),
        (second, [replacement, first_copy]),
        (output, [replacement, first_copy, second_copy, nested_copy]),
    ):
        for ref in refs:
            receipt = directory / ref
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text(
                "Synthetic original evidence.\n"
                if ref.endswith("original.md")
                else "Synthetic replacement evidence.\n"
            )
    prefix = output.relative_to(scan.scan_dir).as_posix()
    surface = {"id": "api", "label": "Synthetic API", "disposition": "no_issue_found"}
    closure = {"id": "review", "reason": "Synthetic review completed."}
    for directory, refs, pending in (
        (first, ["artifacts/missing.md", f"{prefix}/{original}"], True),
        (second, [f"{prefix}/{replacement}", f"{prefix}/{first_copy}"], False),
        (
            output,
            [f"{prefix}/{ref}" for ref in (replacement, first_copy, second_copy, nested_copy)],
            False,
        ),
    ):
        if change == "receipt-only":
            pending = False
            if directory != first:
                refs = [f"{prefix}/{replacement}"]
        coverage = {
            **scan.coverage,
            "completeness": "partial" if pending else "complete",
            "surfaces": [
                {
                    **surface,
                    "disposition": "needs_follow_up" if pending else "no_issue_found",
                    "receiptRefs": refs,
                }
            ],
            "deferred": (
                [{"id": "review", "reason": "Synthetic review pending.", "surfaceIds": ["api"]}]
                if pending
                else []
            ),
            **({} if pending or change == "receipt-only" else {"resolvedDeferred": [closure]}),
        }
        if directory == output and change in {"changed-closure", "new-closure"}:
            coverage["resolvedDeferred"] = [
                {
                    "id": "review" if change == "changed-closure" else "new-review",
                    "reason": "Synthetic new review outcome.",
                }
            ]
        draft = {"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": coverage}
        (directory / "result.json").write_text(json.dumps(draft))
        checkpoint = write_checkpoint(directory / "checkpoints", draft)
        (directory / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    source = json.loads(result.read_text())["coverage"]["surfaces"][0]
    parent_owner = "other-worker" if change == "other-owner" else worker_id
    parent = {
        **source,
        "id": f"{parent_owner}-attempt-3-surface-1",
        "provenance": {"workerId": parent_owner, "attempt": 2, "sourceId": "api"},
    }
    accepted_closure = {
        **closure,
        "id": f"{worker_id}-attempt-2-resolved-review",
    }
    publish_review_projection(
        workbench_api,
        workbench_db,
        scan,
        {
            **scan.coverage,
            "surfaces": [parent],
            "deferred": [],
            "resolvedDeferred": [] if change == "receipt-only" else [accepted_closure],
            "reviews": [
                {"workerId": worker_id, "attempt": attempt, "completeness": "complete"}
                for attempt in (2, 3)
            ],
        },
    )
    if change == "changed-copy":
        (output / second_copy).write_text("Synthetic changed copy evidence.\n")
    originals = {path: path.read_bytes() for path in output.parent.rglob("*") if path.is_file()}
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    if change not in {"changed-copy", "other-owner"}:
        assert len(coverage["surfaces"]) == 1
        retained = coverage["surfaces"][0]
        assert retained["id"] == parent["id"]
        assert retained["provenance"] == parent["provenance"]
    else:
        assert parent in coverage["surfaces"]
        current = [row for row in coverage["surfaces"] if row != parent]
        assert len(current) == 1
        retained = current[0]
        assert retained["provenance"]["workerId"] == worker_id
        assert retained["provenance"]["attempt"] == (3 if change == "changed-copy" else 2)
        assert retained["id"] != parent["id"]
    assert retained["disposition"] == "no_issue_found"
    assert not any(ref.endswith("/missing.md") for ref in retained["receiptRefs"])
    assert all((scan.scan_dir / ref).is_file() for ref in retained["receiptRefs"])
    expected_closures = [] if change == "receipt-only" else [accepted_closure]
    if change in {"changed-closure", "new-closure"}:
        current_closure = {
            "id": f"{worker_id}-attempt-3-resolved-"
            + ("review" if change == "changed-closure" else "new-review"),
            "reason": "Synthetic new review outcome.",
        }
        expected_closures = (
            [current_closure]
            if change == "changed-closure"
            else [accepted_closure, current_closure]
        )
    if change == "new-closure":
        assert current_closure in coverage["resolvedDeferred"]
        assert all(
            row["id"] != accepted_closure["id"] or row == accepted_closure
            for row in coverage["resolvedDeferred"]
        )
    else:
        assert sorted(coverage.get("resolvedDeferred", []), key=lambda row: row["id"]) == sorted(
            expected_closures, key=lambda row: row["id"]
        )
    assert all(path.read_bytes() == data for path, data in originals.items())
