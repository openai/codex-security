from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import register, run_workbench, write_completed_contract


@pytest.mark.parametrize(
    "interruption", [None, "parent_checkpoint", "publication", "publication_conflict"]
)
def test_stopping_pre_index_scan_preserves_checkpoint_history(
    tmp_path: Path, workbench_api, monkeypatch, interruption: str | None
) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    deferred = {"id": "historical-review", "reason": "Saved before pending indexes existed."}
    historical = {
        "scanId": scan["scanId"],
        "complete": False,
        "findings": findings["findings"],
        "coverage": {"deferred": [deferred]},
    }
    contents = json.dumps(historical).encode()
    name = f"{hashlib.sha256(contents).hexdigest()}.json"
    history = scan_dir / "checkpoints"
    history.mkdir(mode=0o700)
    (history / name).write_bytes(contents)
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    manifest_path = scan_dir / "scan-manifest.json"
    parent_manifest = json.loads(manifest_path.read_text())
    parent_manifest["scan"]["complete"] = False
    manifest_path.write_text(json.dumps(parent_manifest))

    if interruption == "publication_conflict":
        drafts = scan_dir / "drafts"
        drafts.mkdir(mode=0o700)
        identifier = "00000000-0000-4000-8000-000000000001"
        incoming = drafts / f"{identifier}.checkpoint.json"
        incoming.write_text(json.dumps({"scanId": scan["scanId"], "findings": [], "coverage": {}}))
        conflict = run_workbench(
            state,
            "write-scan-draft",
            "--scan-id",
            scan["scanId"],
            "--draft-path",
            str(drafts / f"{identifier}.json"),
            "--checkpoint-path",
            str(incoming),
            "--expected-draft-digest",
            "0" * 64,
            check=False,
        )
        assert conflict["returncode"] != 0
        assert "scan_draft_conflict" in conflict["stderr"]

    saved = workbench_api["saved_results"]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    original_write = saved.write_scan_local_bytes

    def interrupted_write(directory, relative, payload):
        original_write(directory, relative, payload)
        if relative.startswith("checkpoints/"):
            raise OSError("Synthetic interruption after saving the parent checkpoint")

    def interrupted_publication(prepared):
        raise OSError("Synthetic interruption after freezing saved sources")

    with monkeypatch.context() as patch:
        if interruption == "parent_checkpoint":
            patch.setattr(saved, "write_scan_local_bytes", interrupted_write)
        elif interruption == "publication":
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupted_publication)
        with workbench_api["connect"]() as connection:
            workbench_api["fail_scan"](
                connection,
                argparse.Namespace(
                    scan_id=scan["scanId"],
                    claim_token=None,
                    cost_json=None,
                    message="Synthetic stop.",
                ),
            )

    if interruption is not None:
        run_workbench(state, "recover-scan-results", "--scan-id", scan["scanId"])
    stopped = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert stopped["findingCount"] == 1
    assert stopped["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert deferred in coverage["deferred"]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    preserved = manifest["scan"]["preservedSources"]
    assert f"checkpoints/{name}" in preserved
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        frozen = json.loads(
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan["scanId"],)
            ).fetchone()[0]
        )
    assert frozen == preserved
    assert (history / name).read_bytes() == contents

    retried = run_workbench(state, "recover-scan-results", "--scan-id", scan["scanId"])["scan"]
    assert retried["findingCount"] == 1
    assert json.loads((scan_dir / "scan-manifest.json").read_text()) == manifest
