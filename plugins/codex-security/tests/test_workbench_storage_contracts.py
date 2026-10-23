from __future__ import annotations

import argparse
import errno
import hashlib
import json
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    register,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)


def test_cost_receipts_replace_flat_and_wrapped_inputs_without_nesting(tmp_path: Path) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    scan = register(state, target, scan_dir)
    usage = {"coverage": "unavailable", "source": "codex_rollout", "threadCount": 0}
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    for receipt in ({"usage": usage}, {"usage": usage, "cost": cost}, cost):
        saved = run_workbench(
            state,
            "preserve-scan-results",
            "--scan-id",
            scan["scanId"],
            "--cost-json",
            json.dumps(receipt),
        )["scan"]
        assert saved["usage"] == usage
        if "model" in receipt or "cost" in receipt:
            assert saved["cost"] == cost
    failed = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop."
    )
    assert failed["scan"]["cost"] == cost
    replacement = {**cost, "estimatedUsd": 0.002}
    repeated = run_workbench(
        state,
        "fail-scan",
        "--scan-id",
        scan["scanId"],
        "--message",
        "Synthetic stop.",
        "--cost-json",
        json.dumps({"usage": usage, "cost": replacement}),
    )
    assert repeated["scan"]["cost"] == replacement
    assert repeated["scan"]["usage"] == usage


def test_draft_acknowledges_only_reconciled_pending_checkpoints(tmp_path: Path) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    earlier = write_checkpoint(
        scan_dir / "checkpoints", {"scanId": scan["scanId"], "findings": [], "coverage": {}}
    )
    concurrent = write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan["scanId"],
            "findings": [],
            "coverage": {"openQuestions": ["Pending review"]},
        },
    )
    pending = scan_dir / "checkpoints/pending"
    pending.mkdir()
    for path in (earlier, concurrent):
        (pending / path.name).write_bytes(path.read_bytes())
    drafts = scan_dir / "drafts"
    drafts.mkdir(mode=0o700)
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps({**documents, "reconciledCheckpointIds": [earlier.name]}))
    run_workbench(
        state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(staged)
    )
    pending = scan_dir / "checkpoints/pending"
    assert not (pending / earlier.name).exists()
    assert (pending / concurrent.name).read_bytes() == concurrent.read_bytes()
    assert earlier.is_file()  # The immutable evidence is retained after acknowledgment.
    assert not staged.exists()  # The locked publisher owns successful cleanup.
    incoming = drafts / f"{uuid.uuid4()}.checkpoint.json"
    incoming.write_text(
        json.dumps(
            {
                "scanId": scan["scanId"],
                "complete": False,
                "findings": [],
                "coverage": {"openQuestions": ["New review"]},
            }
        )
    )
    staged.write_text(json.dumps(documents))
    conflict = run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        "--draft-path",
        str(staged),
        "--checkpoint-path",
        str(incoming),
        "--expected-draft-digest",
        "0" * 64,
        check=False,
    )
    assert conflict["returncode"] != 0
    assert "scan_draft_conflict" in conflict["stderr"]
    assert len(list(pending.glob("*.json"))) == 2


def test_stopped_scan_preserves_parent_with_malformed_pending_checkpoint(tmp_path: Path) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir, mode="deep")
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    contents = b"{incomplete"
    name = f"{hashlib.sha256(contents).hexdigest()}.json"
    history = scan_dir / "checkpoints"
    history.mkdir(mode=0o700)
    (history / name).write_bytes(contents)

    stopped = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop."
    )["scan"]

    assert stopped["findingCount"] == 1
    assert stopped["reportAvailable"] is True
    assert any("Preserved unreadable checkpoint" in warning for warning in stopped["warnings"])
    assert (history / name).read_bytes() == contents
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["status"] == "failed"
    assert manifest["sealedAt"]
    assert f"checkpoints/{name}" not in manifest["preservedSources"]


@pytest.mark.parametrize("before_history", [False, True])
def test_checkpoint_recovers_after_publication_runs_out_of_space(
    tmp_path: Path, workbench_api, monkeypatch, before_history: bool
) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {}
    for key, name in (
        ("manifest", "scan-manifest.json"),
        ("findings", "findings.json"),
        ("coverage", "coverage.json"),
    ):
        documents[key] = json.loads((scan_dir / name).read_text())
        (scan_dir / name).unlink()
    drafts = scan_dir / "drafts"
    drafts.mkdir(mode=0o700)
    draft = drafts / f"{uuid.uuid4()}.json"
    draft.write_text(json.dumps(documents))
    checkpoint = drafts / f"{uuid.uuid4()}.checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            {
                "scanId": scan["scanId"],
                "findings": documents["findings"]["findings"],
                "coverage": documents["coverage"],
            }
        )
    )
    checkpoint_bytes = checkpoint.read_bytes()
    name = f"{hashlib.sha256(checkpoint_bytes).hexdigest()}.json"
    saved = workbench_api["saved_results"]
    original_write = saved.write_scan_local_bytes
    history_saved = False

    def write(directory, relative, payload):
        nonlocal history_saved
        if history_saved or (before_history and relative == f"checkpoints/{name}"):
            raise OSError(errno.ENOSPC, "Synthetic disk full during checkpoint publication")
        original_write(directory, relative, payload)
        if relative == f"checkpoints/{name}":
            history_saved = True

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", write)
        with workbench_api["connect"]() as connection:
            with pytest.raises(OSError, match="Synthetic disk full"):
                saved.write_scan_draft(
                    workbench_api["_WORKBENCH_DB_CONTEXT"],
                    connection,
                    argparse.Namespace(
                        scan_id=scan["scanId"],
                        claim_token=None,
                        draft_path=str(draft),
                        checkpoint_path=str(checkpoint),
                        expected_draft_digest=None,
                    ),
                )
    pending = scan_dir / "checkpoints" / "pending" / name
    history = scan_dir / "checkpoints" / name
    assert pending.read_bytes() == checkpoint_bytes
    assert history.exists() is not before_history
    # Discard caller-owned stages before checking recovery from durable evidence.
    draft.unlink()
    checkpoint.unlink()
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop."
    )["scan"]
    assert stopped["findingCount"] == 1
    assert stopped["reportAvailable"] is True
    assert stopped["resultsRecoveryNeeded"] is False
    assert pending.read_bytes() == checkpoint_bytes
    assert history.read_bytes() == checkpoint_bytes
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    assert f"checkpoints/{name}" in manifest["preservedSources"]
