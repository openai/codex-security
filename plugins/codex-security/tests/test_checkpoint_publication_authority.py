from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("archived", [False, True], ids=["current", "archived"])
@pytest.mark.parametrize("has_head", [True, False], ids=["committed-head", "legacy"])
@pytest.mark.parametrize("complete", [False, True], ids=["checkpoint", "complete"])
def test_recovery_honors_rejection_committed_before_result_replacement(
    workbench_api, workbench_db, publication_scan, archived, has_head, complete
):
    scan = publication_scan()
    provisional = copy.deepcopy(scan.findings[0])
    provisional["extensions"] = {"candidateId": "candidate-rejected"}
    retained = copy.deepcopy(scan.findings[0])
    retained["identity"]["anchor"] = "independent-finding"
    retained["extensions"] = {"candidateId": "candidate-retained"}
    retained["locations"][0]["startLine"] = 20
    retained["locations"][0]["endLine"] = 21
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result_path = add_worker(workbench_db, scan, status="canceled")
    if archived:
        result_path = result_path.parent / "attempts" / "attempt-1" / "result.json"
        result_path.parent.mkdir(parents=True)
    previous = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [provisional, retained],
        "coverage": scan.coverage,
    }
    result_path.write_text(json.dumps(previous))
    old_checkpoint = write_checkpoint(result_path.parent / "checkpoints", previous)
    rejected = {
        **previous,
        "complete": complete,
        "findings": [retained],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-rejected",
                    "label": "Validated candidate disposition",
                    "disposition": "rejected",
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(result_path.parent / "checkpoints", rejected)
    if has_head:
        (result_path.parent / "checkpoint-head.json").write_text(
            json.dumps({"checkpoint": checkpoint.name})
        )
    saved_bytes = {path: path.read_bytes() for path in (result_path, old_checkpoint, checkpoint)}

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert stopped["findingCount"] == len(findings) == (1 if has_head else 2)
    assert any(finding["identity"]["anchor"] == "independent-finding" for finding in findings)
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())
    if has_head:
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert any(
            surface.get("candidateId") == "candidate-rejected"
            and surface.get("disposition") == "rejected"
            for surface in coverage["surfaces"]
        )


def save_disposition(scan, directory, disposition):
    directory.mkdir(parents=True, exist_ok=True)
    finding = copy.deepcopy(scan.findings[0])
    finding["extensions"] = {"candidateId": "candidate-disposition"}
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [finding] if disposition == "reported" else [],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-disposition",
                    "label": "Validated candidate disposition",
                    "disposition": disposition,
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(directory / "checkpoints", draft)
    (directory / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    return draft


@pytest.mark.parametrize("archived", [False, True], ids=["current-head", "newer-archive"])
@pytest.mark.parametrize("disposition", ["reported", "rejected"])
def test_newer_checkpoint_disposition_precedes_older_archived_head(
    workbench_api, workbench_db, publication_scan, archived, disposition
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    old = result.parent / "attempts" / "attempt-1"
    save_disposition(scan, old, "rejected" if disposition == "reported" else "reported")
    current = result.parent / "attempts" / "attempt-2" if archived else result.parent
    draft = save_disposition(scan, current, disposition)
    (current / "result.json").write_text(json.dumps(draft))

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    assert stopped["findingCount"] == (1 if disposition == "reported" else 0)


@pytest.mark.parametrize("head_change", ["replaced", "removed", "missing-checkpoint"])
def test_frozen_stopped_replay_ignores_later_worker_head_changes(
    workbench_api, workbench_db, publication_scan, monkeypatch, head_change
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]

    def fail_before_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", fail_before_publication)
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["retained_source_digests_json"]
    assert row["seal_manifest_digest"] is None
    head = result.parent / "checkpoint-head.json"
    if head_change == "replaced":
        save_disposition(scan, result.parent, "reported")
    elif head_change == "removed":
        head.unlink()
    else:
        head.write_text(json.dumps({"checkpoint": "a" * 64 + ".json"}))

    replayed = workbench_api["preserve_scan_results"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]

    assert replayed["findingCount"] == 0
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == []
    assert json.loads(result.read_text()) == previous


def test_explicit_recovery_observes_head_change_between_existing_checkpoints(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]
    assert stopped["findingCount"] == 0

    save_disposition(scan, result.parent, "reported")

    context = workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]
    assert context["resultsRecoveryNeeded"] is True
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


def test_legacy_frozen_publication_keeps_result_fallback_without_saved_heads(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    (result.parent / "checkpoint-head.json").unlink()

    def fail_before_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(
            workbench_api["saved_results"],
            "_write_prepared_scan_finalization",
            fail_before_publication,
        )
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    save_disposition(scan, result.parent, "rejected")

    replayed = workbench_api["preserve_scan_results"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]

    assert replayed["findingCount"] == 1
