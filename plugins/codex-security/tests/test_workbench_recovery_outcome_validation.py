from __future__ import annotations

import copy
import json
import os
from types import SimpleNamespace

import pytest
from test_deep_scan_successful_publication import complete
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import saved_draft, write_checkpoint


@pytest.mark.parametrize(
    ("label", "error"),
    [
        pytest.param(None, None, id="absent-rejection"),
        pytest.param("Reviewed candidate", None, id="valid-rejection"),
        pytest.param("Invalid \ud800", "well-formed Unicode", id="surrogate-label"),
        pytest.param("\u0085", "label: expected a non-empty string", id="nel-label"),
        pytest.param(" ", "label: expected a non-empty string", id="blank-label"),
    ],
)
def test_stopped_scan_requires_valid_rejection_evidence_before_sealing(
    workbench_api, workbench_db, publication_scan, label, error
):
    scan = publication_scan(mode="standard")
    report_path = scan.scan_dir / "report.md"
    report_path.unlink()
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"] = {"source": "local_plugin", "candidateId": "candidate-a"}
    checkpoint = write_checkpoint(
        scan.scan_dir / "checkpoints", saved_draft(scan.scan_id, findings=[finding])
    )
    os.utime(checkpoint, ns=(100, 100))
    checkpoint_bytes = checkpoint.read_bytes()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    scan.coverage["surfaces"] = (
        []
        if label is None
        else [
            {
                "id": "rejection",
                "candidateId": "candidate-a",
                "label": label,
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ]
    )
    coverage_path = scan.scan_dir / "coverage.json"
    coverage_path.write_text(json.dumps(scan.coverage))
    coverage_bytes = coverage_path.read_bytes()

    workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        SimpleNamespace(
            scan_id=scan.scan_id,
            cost_json=None,
            claim_token=None,
            message="Synthetic interruption",
        ),
    )

    row = workbench_db.execute(
        "SELECT status, completion_warnings_json FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()
    assert row["status"] == "failed"
    assert checkpoint.read_bytes() == checkpoint_bytes
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    warnings = json.loads(row["completion_warnings_json"])
    if error:
        assert not manifest.get("sealedAt")
        assert not report_path.exists()
        assert coverage_path.read_bytes() == coverage_bytes
        assert any(
            "result publication needs follow-up" in warning and error in warning
            for warning in warnings
        )
    else:
        assert manifest["sealedAt"]
        assert report_path.is_file()
        assert warnings == []
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert [item["title"] for item in findings] == ([finding["title"]] if label is None else [])
        surfaces = json.loads(coverage_path.read_text())["surfaces"]
        assert [(item.get("candidateId"), item["disposition"]) for item in surfaces] == (
            [] if label is None else [("candidate-a", "rejected")]
        )


@pytest.mark.parametrize(
    ("reason", "invalid"),
    [
        pytest.param("Review completed.", False, id="valid-closure"),
        pytest.param("Invalid \ud800", True, id="surrogate-reason"),
    ],
)
def test_standard_completion_requires_valid_closure_evidence_before_sealing(
    workbench_api, workbench_db, publication_scan, reason, invalid
):
    scan = publication_scan(mode="standard")
    report_path = scan.scan_dir / "report.md"
    report_path.unlink()
    checkpoint = write_checkpoint(
        scan.scan_dir / "checkpoints",
        saved_draft(
            scan.scan_id,
            deferred=[{"id": "review", "reason": "Review authorization remains pending."}],
        ),
    )
    os.utime(checkpoint, ns=(100, 100))
    checkpoint_bytes = checkpoint.read_bytes()
    scan.coverage["deferred"] = []
    closure = {"id": "review", "reason": reason}
    scan.coverage["resolvedDeferred"] = [closure]
    coverage_path = scan.scan_dir / "coverage.json"
    coverage_path.write_text(json.dumps(scan.coverage))
    coverage_bytes = coverage_path.read_bytes()

    if invalid:
        with pytest.raises(SystemExit, match="well-formed Unicode"):
            complete(workbench_api, workbench_db, scan)
    else:
        completed = complete(workbench_api, workbench_db, scan)
        assert completed["warnings"] == []

    assert checkpoint.read_bytes() == checkpoint_bytes
    status = workbench_db.execute(
        "SELECT status FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    if invalid:
        assert status == "running"
        assert not manifest.get("sealedAt")
        assert not report_path.exists()
        assert coverage_path.read_bytes() == coverage_bytes
    else:
        assert status == "complete"
        assert manifest["sealedAt"]
        assert report_path.is_file()
        coverage = json.loads(coverage_path.read_text())
        assert coverage["deferred"] == []
        assert coverage["resolvedDeferred"] == [closure]
