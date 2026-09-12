from __future__ import annotations

import hashlib
import json
from argparse import Namespace

import pytest
from test_checkpoint_publication_authority import save_disposition
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


def snapshot(connection, scan_dir):
    return {
        "database": "\n".join(connection.iterdump()),
        "files": {
            path.relative_to(scan_dir).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in scan_dir.rglob("*")
            if path.is_file()
        },
    }


@pytest.mark.parametrize("operation", ["preserve", "recover"])
@pytest.mark.parametrize(
    "protocol",
    ["supported", "supported-v2", "supported-mcp-v1", "future-workflow", "future-selection"],
)
def test_stopped_result_publication_requires_supported_protocol(
    workbench_api, workbench_db, publication_scan, monkeypatch, operation, protocol
):
    scan = publication_scan()
    supported_workflows = {
        "supported": "deep-security-scan/v1",
        "supported-v2": "deep-security-scan/v2",
        "supported-mcp-v1": "deep-scan-mcp/v1",
    }
    if protocol in supported_workflows:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_runs SET workflow_version = ? WHERE scan_id = ?",
                (supported_workflows[protocol], scan.scan_id),
            )
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    draft = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(draft))

    def interrupt_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(
            workbench_api["saved_results"],
            "_write_prepared_scan_finalization",
            interrupt_publication,
        )
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id,
                claim_token=None,
                cost_json=None,
                message="Original worker stop.",
            ),
        )
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["status"] == "failed"
    assert row["retained_source_digests_json"]
    assert row["seal_manifest_digest"] is None

    with workbench_db:
        if protocol == "future-workflow":
            workbench_db.execute(
                "UPDATE deep_scan_runs SET workflow_version = 'future/v99' WHERE scan_id = ?",
                (scan.scan_id,),
            )
        elif protocol == "future-selection":
            workbench_db.execute(
                "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
                "finalization_input_json = ? WHERE scan_id = ?",
                (json.dumps({"version": 99}), scan.scan_id),
            )
    before = snapshot(workbench_db, scan.scan_dir)
    error = None
    try:
        if operation == "preserve":
            workbench_api["preserve_scan_results"](
                workbench_db,
                Namespace(
                    scan_id=scan.scan_id,
                    claim_token=None,
                    thread_id=None,
                    coordinator_generation=None,
                ),
            )
        else:
            workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    except SystemExit as failure:
        error = str(failure)
    after = snapshot(workbench_db, scan.scan_dir)
    changed_files = sorted(
        path
        for path in before["files"].keys() | after["files"].keys()
        if before["files"].get(path) != after["files"].get(path)
    )
    print(
        json.dumps(
            {
                "operation": operation,
                "protocol": protocol,
                "error": error,
                "database_changed": before["database"] != after["database"],
                "changed_files": changed_files,
            }
        )
    )
    if protocol in supported_workflows:
        assert error is None
        assert before != after
        row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
        assert row["seal_manifest_digest"]
        assert row["failure_message"] == "Original worker stop."
        run = workbench_db.execute(
            "SELECT workflow_version FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()
        assert run["workflow_version"] == supported_workflows[protocol]
    else:
        assert error is not None and "unsupported" in error.lower()
        assert after == before
