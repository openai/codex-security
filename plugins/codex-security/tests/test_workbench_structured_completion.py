from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    get_scan,
    publish_scan_draft,
    run_workbench,
    scan_command,
    write_checkpoint,
    write_completed_contract,
)


def start_scan(
    tmp_path: Path, *, recipe_options: dict[str, Any] | None = None
) -> tuple[Path, Path, str]:
    state_dir, target, scan_dir = tmp_path / "state", tmp_path / "target", tmp_path / "scan"
    target.mkdir()
    scan_dir.mkdir(mode=0o700)
    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
                **(recipe_options or {}),
            }
        ),
    )
    scan_id = str(registered["scanId"])
    write_completed_contract(scan_dir, scan_id, target)
    return state_dir, scan_dir, scan_id


@pytest.mark.parametrize("command", ["prepare-scan-completion", "complete-scan"])
@pytest.mark.parametrize("checkpoint", [None, "incomplete", "unselected"])
def test_standard_completion_requires_accepted_terminal_draft(
    tmp_path: Path, command: str, checkpoint: str | None
) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    if checkpoint:
        manifest = json.loads(manifest_path.read_text())
        manifest["scan"]["complete"] = checkpoint != "incomplete"
        manifest_path.write_text(json.dumps(manifest))
        publish_scan_draft(state_dir, scan_dir, scan_id)
        if checkpoint == "unselected":
            (scan_dir / "checkpoint-head.json").unlink()
        # File-authored completion cannot supply a selected terminal checkpoint.
        manifest = json.loads(manifest_path.read_text())
        manifest["scan"].pop("complete")
        manifest_path.write_text(json.dumps(manifest))
    before = {path.name: path.read_bytes() for path in scan_dir.glob("*.json")}

    rejected = scan_command(state_dir, command, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "record_codex_security_scan_draft with complete:true" in rejected["stderr"]
    assert {path.name: path.read_bytes() for path in scan_dir.glob("*.json")} == before
    assert get_scan(state_dir, scan_id)["scan"]["progress"]["status"] == "running"


@pytest.mark.parametrize("command", ["prepare-scan-completion", "complete-scan"])
@pytest.mark.parametrize("complete", [False, True])
def test_standard_completion_rejects_changed_accepted_checkpoint(
    tmp_path: Path, command: str, complete: bool
) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = complete
    manifest_path.write_text(json.dumps(manifest))
    publish_scan_draft(state_dir, scan_dir, scan_id)
    head_path = scan_dir / "checkpoint-head.json"
    checkpoint_path = scan_dir / "checkpoints" / json.loads(head_path.read_text())["checkpoint"]
    checkpoint = json.loads(checkpoint_path.read_text())
    checkpoint["complete"] = True
    checkpoint["findings"] = []
    checkpoint_path.write_text(json.dumps(checkpoint))
    before = {path.name: path.read_bytes() for path in scan_dir.glob("*.json")}

    rejected = scan_command(state_dir, command, scan_id, check=False)

    assert rejected["returncode"] != 0
    assert "accepted checkpoint digest mismatch" in rejected["stderr"]
    assert {path.name: path.read_bytes() for path in scan_dir.glob("*.json")} == before
    assert get_scan(state_dir, scan_id)["scan"]["progress"]["status"] == "running"


@pytest.mark.parametrize("late_files", ["malformed", "different", "missing"])
def test_standard_completion_uses_accepted_draft_after_later_file_edits(
    tmp_path: Path, late_files: str
) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    original = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert publish_scan_draft(state_dir, scan_dir, scan_id)["status"] == "draft_written"
    accepted_head = (scan_dir / "checkpoint-head.json").read_bytes()
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        path = scan_dir / name
        if late_files == "malformed":
            path.write_text("not JSON")
        elif late_files == "missing":
            path.unlink()
        else:
            document = json.loads(path.read_text())
            if name == "findings.json":
                document["findings"] = []
            elif name == "coverage.json":
                document["inventoryStrategy"] = "scoped_input"
                document["surfaces"] = [{"label": "Invalid later rewrite"}]
            else:
                document["scan"]["threatModel"] = {"summary": "Unsubmitted rewrite"}
            path.write_text(json.dumps(document))

    prepared = scan_command(state_dir, "prepare-scan-completion", scan_id)

    assert prepared["scan"]["progress"]["status"] == "running"
    assert (scan_dir / "checkpoint-head.json").read_bytes() == accepted_head
    assert (scan_dir / "report.md").is_file()
    sealed = {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    for _ in range(2):
        completed = scan_command(state_dir, "complete-scan", scan_id)
        assert completed["scan"]["progress"]["status"] == "complete"
        assert completed["scan"]["findingCount"] == 1
        assert {name: (scan_dir / name).read_bytes() for name in sealed} == sealed
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert finding["title"] == original["title"]


def test_standard_completion_preserves_checkpoint_findings_and_followup(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    pending = {"id": "unreviewed-entry", "label": "Second entry", "disposition": "needs_follow_up"}
    coverage["surfaces"].append(pending)
    coverage_path.write_text(json.dumps(coverage))
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = False
    manifest_path.write_text(json.dumps(manifest))
    publish_scan_draft(state_dir, scan_dir, scan_id)
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = True
    manifest_path.write_text(json.dumps(manifest))
    publish_scan_draft(state_dir, scan_dir, scan_id)

    completed = scan_command(state_dir, "complete-scan", scan_id)

    assert completed["scan"]["findingCount"] == 1
    assert any(
        row["id"] == pending["id"] and row["disposition"] == "needs_follow_up"
        for row in json.loads(coverage_path.read_text())["surfaces"]
    )


def test_standard_completion_does_not_promote_a_later_unselected_checkpoint(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    publish_scan_draft(state_dir, scan_dir, scan_id)
    head_path = scan_dir / "checkpoint-head.json"
    accepted_head = head_path.read_bytes()
    selected = json.loads(accepted_head)["checkpoint"]
    unselected = json.loads((scan_dir / "checkpoints" / selected).read_text())
    unselected["complete"] = False
    unselected["findings"][0]["title"] = "Unsubmitted finding rewrite"
    checkpoint = write_checkpoint(scan_dir / "checkpoints", unselected)
    later = head_path.stat().st_mtime_ns + 1_000_000_000
    os.utime(checkpoint, ns=(later, later))

    completed = scan_command(state_dir, "complete-scan", scan_id)

    assert completed["scan"]["findingCount"] == 1
    assert head_path.read_bytes() == accepted_head
    assert json.loads((scan_dir / "findings.json").read_text())["findings"][0]["title"] != (
        "Unsubmitted finding rewrite"
    )


def test_standard_completion_preserves_accepted_hardening(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    portfolio = scan_dir / "hardening/hardening.md"
    portfolio.parent.mkdir()
    portfolio.write_text("# Hardening\n\nReview the remaining entry points.\n")
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    hardening = {"portfolioPath": "hardening/hardening.md"}
    manifest["scan"]["hardening"] = hardening
    manifest_path.write_text(json.dumps(manifest))
    publish_scan_draft(state_dir, scan_dir, scan_id)
    manifest["scan"].pop("hardening")
    manifest_path.write_text(json.dumps(manifest))

    scan_command(state_dir, "complete-scan", scan_id)

    assert json.loads(manifest_path.read_text())["scan"]["hardening"] == hardening


def test_rejected_standard_draft_keeps_accepted_head(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id = start_scan(tmp_path)
    publish_scan_draft(state_dir, scan_dir, scan_id)
    accepted_head = (scan_dir / "checkpoint-head.json").read_bytes()
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["manifest"]["scan"]["target"]["kind"] = "git_diff"
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))

    rejected = scan_command(
        state_dir, "write-scan-draft", scan_id, "--draft-path", str(staged), check=False
    )

    assert rejected["returncode"] != 0
    assert (scan_dir / "checkpoint-head.json").read_bytes() == accepted_head
    assert scan_command(state_dir, "complete-scan", scan_id)["scan"]["findingCount"] == 1


@pytest.mark.parametrize(
    "recipe_options",
    [
        {"mock": True},
        {"validationMode": "custom"},
        {"import": {"format": "json", "sourcePath": "synthetic.json"}},
    ],
)
def test_host_authored_completion_remains_supported(
    tmp_path: Path, recipe_options: dict[str, Any]
) -> None:
    state_dir, _, scan_id = start_scan(tmp_path, recipe_options=recipe_options)

    assert scan_command(state_dir, "complete-scan", scan_id)["scan"]["findingCount"] == 1
