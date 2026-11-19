"""Registered Standard scans retain declared file reviews alongside partial coverage."""

import hashlib
import json
import sqlite3
import subprocess
import uuid
from pathlib import Path

import pytest
from test_workbench_completion_binding import register_cli_scan
from workbench_test_support import (
    get_scan,
    initialize_git_repository,
    read_draft_documents,
    run_workbench,
    scan_command,
    write_completed_contract,
)


@pytest.mark.cross_platform
@pytest.mark.parametrize("prepare", [False, True], ids=["direct", "prepared"])
def test_standard_file_review_receipts_allow_partial_completion(tmp_path: Path, prepare: bool):
    state, repository, scan_dir = tmp_path / "state", tmp_path / "repository", tmp_path / "scan"
    initialize_git_repository(repository)
    reviewed = "-reviewed.py"
    unread = ["README.md", "pending.py"]
    for name in (reviewed, "pending.py"):
        (repository / name).write_bytes(b"pass")
    subprocess.run(["git", "add", "--", reviewed, "pending.py"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Add review inputs"], cwd=repository, check=True)
    registered = register_cli_scan(state, repository, scan_dir)
    scan_id = registered["scanId"]
    assert registered["scopeFileCount"] == 3
    contents = (repository / reviewed).read_bytes()
    coverage = get_scan(state, scan_id)["scan"]["progress"]["coverage"]
    assert coverage.get("filesReviewed", 0) == 0

    template = tmp_path / "contract"
    template.mkdir()
    write_completed_contract(
        template,
        scan_id,
        repository,
        relative_path=reviewed,
        target_kind="git_revision",
        target_revision=registered["targetRevision"],
    )
    documents = read_draft_documents(template)
    documents["findings"]["findings"] = []
    deferred = [{"id": "unread", "reason": "Review time expired.", "paths": unread}]
    documents["reviewState"] = documents.pop("coverage")
    documents["reviewState"].update(surfaces=[], deferred=deferred)
    drafts = scan_dir / "drafts"
    drafts.mkdir(exist_ok=True)

    def submit(paths, *, complete=False):
        draft = drafts / f"{uuid.uuid4()}.json"
        documents["manifest"]["scan"]["complete"] = complete
        draft.write_text(json.dumps(documents))
        checkpoint = drafts / f"{uuid.uuid4()}.checkpoint.json"
        review = {"deferred": deferred}
        if paths is not None:
            review["reviewedFiles"] = paths
        checkpoint.write_text(
            json.dumps(
                {"scanId": scan_id, "complete": complete, "findings": [], "reviewState": review}
            )
        )
        return scan_command(
            state,
            "write-scan-draft",
            scan_id,
            "--draft-path",
            str(draft),
            "--checkpoint-path",
            str(checkpoint),
        )

    assert submit([reviewed])["status"] == "draft_written"
    detail = get_scan(state, scan_id)["scan"]
    compact = get_scan(state, scan_id, "--progress-only")["scan"]
    history = run_workbench(state, "list-scans")["scans"][0]
    for entry in (detail, compact, history):
        assert entry["progress"]["coverage"] == {**coverage, "filesReviewed": 1}
    with sqlite3.connect(state / "workbench.sqlite3") as db:

        def receipt():
            return db.execute(
                "SELECT relative_path, content_sha256, closed_at FROM standard_reviewed_files "
                "WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()

        original = receipt()
        assert len(original) == 1
        assert original[0][:2] == (reviewed, hashlib.sha256(contents).hexdigest())
        assert original[0][2]
        assert submit([reviewed, reviewed])["status"] == "draft_written"
        assert receipt() == original
        for invalid in (["pending.py", "absent.py"], {"pending.py": False}):
            assert "Skipped this batch of file review receipts" in submit(invalid)["warnings"][0]
            assert receipt() == original

    assert submit(None, complete=True)["status"] == "draft_written"
    if prepare:
        prepared = scan_command(state, "prepare-scan-completion", scan_id)["scan"]["progress"]
        assert prepared["status"] == "running"
        assert prepared["coverage"] == {**coverage, "filesReviewed": 1}
    result = scan_command(state, "complete-scan", scan_id)["scan"]["progress"]
    assert result["status"] == "complete"
    assert result["coverage"] == {**coverage, "filesReviewed": 1}
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    accepted = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
    assert accepted["reviewState"]["deferred"] == deferred


@pytest.mark.cross_platform
def test_stopped_scan_retains_finding_after_rejected_file_receipt(tmp_path: Path):
    state, repository, scan_dir = tmp_path / "state", tmp_path / "repository", tmp_path / "scan"
    initialize_git_repository(repository)
    registered = register_cli_scan(state, repository, scan_dir)
    scan_id = registered["scanId"]
    template = tmp_path / "contract"
    template.mkdir()
    write_completed_contract(
        template,
        scan_id,
        repository,
        relative_path="README.md",
        target_kind="git_revision",
        target_revision=registered["targetRevision"],
    )
    documents = read_draft_documents(template)
    documents["manifest"]["scan"]["complete"] = False
    findings = documents["findings"]["findings"]
    drafts = scan_dir / "drafts"
    drafts.mkdir(exist_ok=True)
    draft = drafts / f"{uuid.uuid4()}.json"
    draft.write_text(json.dumps(documents))
    checkpoint = drafts / f"{uuid.uuid4()}.checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "complete": False,
                "findings": findings,
                "reviewState": {"reviewedFiles": ["README.md"]},
            }
        )
    )
    (repository / "README.md").write_text("Changed after review.")

    result = scan_command(
        state,
        "write-scan-draft",
        scan_id,
        "--draft-path",
        str(draft),
        "--checkpoint-path",
        str(checkpoint),
    )
    assert result["status"] == "draft_written"
    assert "registered Git blob: README.md" in result["warnings"][0]
    scan_command(state, "cancel-scan", scan_id)
    detail = get_scan(state, scan_id)["scan"]
    assert detail["progress"]["coverage"].get("filesReviewed", 0) == 0
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    accepted = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
    assert accepted["findings"][0]["title"] == findings[0]["title"]
    assert (
        json.loads((scan_dir / "findings.json").read_text())["findings"][0]["title"]
        == findings[0]["title"]
    )
