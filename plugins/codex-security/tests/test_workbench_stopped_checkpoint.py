from __future__ import annotations

import argparse
import copy
import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.fixture
def staged_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    write_completed_contract(scan_dir, scan_id, repository, relative_path="clean.ts")
    findings = json.loads((scan_dir / "findings.json").read_text())
    finding = findings["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    canonical = {
        filename: (scan_dir / filename).read_bytes()
        for filename in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    accepted = semantic(scan_id, ["clean.ts"])
    accepted["coverage"].update(
        deferred=[],
        surfaces=[
            {
                "id": "validated-candidate",
                "candidateId": "candidate-1",
                "label": "Validated source control",
                "disposition": "rejected",
                "reason": "The source control prevents this candidate.",
                "receiptRefs": [],
            }
        ],
    )
    drafts = scan_dir / "drafts"
    drafts.mkdir()
    draft_path = drafts / f"{uuid.uuid4()}.json"
    staged_checkpoint = drafts / f"{uuid.uuid4()}.checkpoint.json"
    staged_checkpoint.write_text(json.dumps(accepted))
    draft_path.write_text(
        json.dumps(
            {
                "manifest": json.loads(canonical["scan-manifest.json"]),
                "findings": {**findings, "findings": []},
                "coverage": {
                    **json.loads(canonical["coverage.json"]),
                    **copy.deepcopy(accepted["coverage"]),
                },
            }
        )
    )
    return (
        state,
        repository,
        scan_dir,
        scan_id,
        finding,
        canonical,
        accepted,
        staged_checkpoint,
        draft_path,
    )


@pytest.mark.parametrize(
    "failure_point", ["checkpoint-head.json", "findings.json", "coverage.json"]
)
def test_failure_publication_uses_checkpoint_accepted_before_canonical_replace(
    staged_scan, workbench_api, monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    (
        state,
        repository,
        scan_dir,
        scan_id,
        finding,
        canonical,
        accepted,
        staged_checkpoint,
        draft_path,
    ) = staged_scan
    saved_results = workbench_api["saved_results"]
    write = saved_results.write_scan_local_bytes

    def interrupted_write(root: Path, relative: str, contents: bytes):
        if relative == failure_point:
            raise RuntimeError("Synthetic interruption before canonical replacement")
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        patch.setattr(saved_results, "write_scan_local_bytes", interrupted_write)
        if failure_point == "checkpoint-head.json":

            def interrupted_head(*args):
                raise RuntimeError("Synthetic interruption before canonical replacement")

            patch.setattr(saved_results, "_write_checkpoint_head", interrupted_head)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            with pytest.raises(RuntimeError, match="before canonical replacement"):
                workbench_api["write_scan_draft"](
                    connection,
                    argparse.Namespace(
                        scan_id=scan_id,
                        claim_token=None,
                        checkpoint_path=str(staged_checkpoint),
                        draft_path=str(draft_path),
                        expected_draft_digest=None,
                    ),
                )
    for filename, data in canonical.items():
        if failure_point != "coverage.json" or filename != "findings.json":
            assert (scan_dir / filename).read_bytes() == data
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        path, snapshot, acceptance = connection.execute(
            "SELECT checkpoint_path, snapshot_json, acceptance_id FROM scan_checkpoints WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        assert connection.execute(
            "SELECT pending_draft_checkpoint_acceptance_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (acceptance,)
    assert json.loads(snapshot) == accepted
    retained_paths = [scan_dir / path, staged_checkpoint, draft_path, repository / "clean.ts"]
    retained_bytes = {path: path.read_bytes() for path in retained_paths}

    failed = run_workbench(
        state, "fail-scan", "--scan-id", scan_id, "--message", "Interrupted canonical write"
    )["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 0
    assert json.loads((scan_dir / "findings.json").read_text())["findings"] == []
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    decision = next(row for row in coverage["surfaces"] if row.get("candidateId") == "candidate-1")
    assert decision["disposition"] == "rejected"
    if failure_point != "coverage.json":
        assert decision["previousFindings"][0]["codeEvidence"] == finding["codeEvidence"]
    resume = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resume["checkpoint"]["sources"][0]["findings"] == []
    assert resume["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert all(path.read_bytes() == data for path, data in retained_bytes.items())


@pytest.mark.parametrize("publication", ["completed", "checkpointless", "newer_acceptance"])
def test_draft_publication_leaves_later_canonical_decisions_current(
    staged_scan, workbench_api, monkeypatch: pytest.MonkeyPatch, publication: str
) -> None:
    state, _, scan_dir, scan_id, _, canonical, _, checkpoint, draft = staged_scan

    def publish(checkpoint_path):
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            workbench_api["write_scan_draft"](
                connection,
                argparse.Namespace(
                    scan_id=scan_id,
                    claim_token=None,
                    checkpoint_path=checkpoint_path,
                    draft_path=str(draft),
                    expected_draft_digest=None,
                ),
            )

    if publication != "completed":
        saved_results = workbench_api["saved_results"]
        write = saved_results.write_scan_local_bytes

        def interrupted_write(root, relative, contents):
            if relative == "findings.json":
                raise RuntimeError("Synthetic interruption before canonical replacement")
            return write(root, relative, contents)

        with monkeypatch.context() as patch:
            patch.setattr(saved_results, "write_scan_local_bytes", interrupted_write)
            with pytest.raises(RuntimeError, match="before canonical replacement"):
                publish(str(checkpoint))

    if publication == "newer_acceptance":
        latest = semantic(scan_id, ["clean.ts"])
        latest["findings"] = json.loads(canonical["findings.json"])["findings"]
        save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", latest))
    else:
        publish(None if publication == "checkpointless" else str(checkpoint))

    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        pending = connection.execute(
            "SELECT pending_draft_checkpoint_acceptance_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
        if publication == "newer_acceptance":
            assert pending is not None
            assert (
                pending
                != connection.execute(
                    "SELECT acceptance_id FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence DESC LIMIT 1",
                    (scan_id,),
                ).fetchone()[0]
            )
        else:
            assert pending is None
            assert json.loads((scan_dir / "findings.json").read_bytes())["findings"] == []
    # A later canonical-only update remains current once the accepted draft was published.
    for filename, contents in canonical.items():
        (scan_dir / filename).write_bytes(contents)
    failed = run_workbench(
        state, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after canonical update"
    )["scan"]
    assert failed["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_bytes())
    assert not any(row.get("disposition") == "rejected" for row in coverage["surfaces"])
