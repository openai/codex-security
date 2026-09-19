from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


def save_checkpoint(scan, result, *, rejected=False):
    candidate = copy.deepcopy(scan.findings[0])
    candidate["extensions"] = {"candidateId": "candidate-disposition"}
    retained = copy.deepcopy(candidate)
    retained["extensions"] = {"candidateId": "candidate-retained"}
    retained["identity"]["anchor"] = "independent-finding"
    retained["locations"][0]["startLine"] = 20
    retained["locations"][0]["endLine"] = 21
    draft = {
        "scanId": scan.scan_id,
        "complete": False,
        "findings": [retained] if rejected else [candidate, retained],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-disposition",
                    "label": "Validated candidate disposition",
                    "disposition": "rejected" if rejected else "reported",
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
    (result.parent / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    return draft, checkpoint


def stop(workbench_api, connection, scan):
    return workbench_api["fail_scan"](
        connection,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]


def preserve(workbench_api, connection, scan):
    return workbench_api["preserve_scan_results"](
        connection,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]


@pytest.mark.parametrize("has_head", [False, True])
def test_legacy_stop_does_not_create_frozen_checkpoint_metadata(
    workbench_api, workbench_db, publication_scan, has_head
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    draft, _ = save_checkpoint(scan, result)
    result.write_text(json.dumps(draft))
    if not has_head:
        (result.parent / "checkpoint-head.json").unlink()

    stopped = stop(workbench_api, workbench_db, scan)
    assert stopped["findingCount"] == 2
    assert stopped["failureMessage"] == "Audit stopped."
    assert preserve(workbench_api, workbench_db, scan)["findingCount"] == 2
    assert (
        workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))[
            "scan"
        ]["findingCount"]
        == 2
    )
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["retained_source_digests_json"]
    assert row["retained_checkpoint_heads_json"] is None
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert "preservedCheckpointHeads" not in manifest["scan"]


@pytest.fixture
def frozen_stop(workbench_api, workbench_db, publication_scan, monkeypatch):
    import finalize_scan_contract

    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous, _ = save_checkpoint(scan, result)
    result.write_text(json.dumps(previous))
    _, selected = save_checkpoint(scan, result, rejected=True)
    directory = result.parent.relative_to(scan.scan_dir).as_posix()
    heads = {directory: selected.relative_to(scan.scan_dir).as_posix()}
    original_outputs = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
    }
    write_bytes = finalize_scan_contract.write_scan_local_bytes
    failed_writes = []

    def obstruct_coverage(directory, relative, payload, **kwargs):
        if relative != "coverage.json" or failed_writes:
            return write_bytes(directory, relative, payload, **kwargs)
        failed_writes.append(json.loads((directory / "findings.json").read_text()))
        path = directory / relative
        before = path.read_bytes()
        path.unlink()
        path.mkdir()
        try:
            return write_bytes(directory, relative, payload, **kwargs)
        finally:
            path.rmdir()
            path.write_bytes(before)

    with monkeypatch.context() as patch:
        patch.setattr(finalize_scan_contract, "write_scan_local_bytes", obstruct_coverage)
        stop(workbench_api, workbench_db, scan)
    assert len(failed_writes) == 1
    assert "scanId" in failed_writes[0]
    assert all(
        (scan.scan_dir / name).read_bytes() == contents
        for name, contents in original_outputs.items()
    )
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["retained_source_digests_json"]
    assert row["seal_manifest_digest"] is None
    # A later writer freezes this existing checkpoint map before output writes.
    # Seed its recorded input; this release only consumes that saved authority.
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = ? WHERE id = ?",
            (json.dumps(heads, sort_keys=True), scan.scan_id),
        )
    return scan, result, heads


@pytest.mark.parametrize("head_change", ["replaced", "removed", "missing-checkpoint"])
def test_reader_replays_frozen_rejection_after_real_output_fault(
    workbench_api, workbench_db, frozen_stop, head_change
):
    scan, result, heads = frozen_stop
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    head = result.parent / "checkpoint-head.json"
    if head_change == "replaced":
        save_checkpoint(scan, result)
    elif head_change == "removed":
        head.unlink()
    else:
        head.write_text(json.dumps({"checkpoint": "a" * 64 + ".json"}))

    replayed = preserve(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == 1
    assert replayed["failureMessage"] == "Audit stopped."
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["identity"]["anchor"] == "independent-finding"
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert any(
        surface.get("candidateId") == "candidate-disposition"
        and surface.get("disposition") == "rejected"
        for surface in coverage["surfaces"]
    )
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["preservedCheckpointHeads"] == heads
    after = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert after["retained_source_digests_json"] == row["retained_source_digests_json"]
    assert after["retained_checkpoint_heads_json"] == row["retained_checkpoint_heads_json"]
    assert preserve(workbench_api, workbench_db, scan)["findingCount"] == 1


def test_reader_requires_writer_to_select_new_recovery_heads(
    workbench_api, workbench_db, frozen_stop
):
    scan, result, _ = frozen_stop
    assert preserve(workbench_api, workbench_db, scan)["findingCount"] == 1
    save_checkpoint(scan, result)
    before_db = list(workbench_db.iterdump())
    before_files = {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()}
    with pytest.raises(SystemExit, match="newer version"):
        workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert list(workbench_db.iterdump()) == before_db
    assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*") if path.is_file()} == (
        before_files
    )
