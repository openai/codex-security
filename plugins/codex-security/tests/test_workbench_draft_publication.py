from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import deep_scan_fixture
from workbench_test_support import run_workbench, write_completed_contract


@pytest.mark.parametrize("filename", ["findings.json", "coverage.json"])
@pytest.mark.parametrize("previous", ["unfinished", "symlink"])
def test_terminal_deep_draft_compares_previous_bytes_without_parsing_review_documents(
    tmp_path: Path, filename: str, previous: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(
        contract_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    documents = {
        key: json.loads((contract_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    model = {"format": "markdown", "content": "# Saved model\n"}
    documents["manifest"] = {
        "scan": {
            **{key: documents["manifest"]["scan"][key] for key in ("target", "scope")},
            "threatModel": model,
        }
    }
    documents["findings"]["findings"] = []
    documents["coverage"].update(completeness="complete", surfaces=[], deferred=[])
    drafts = scan_dir / "drafts"
    drafts.mkdir(exist_ok=True)
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))
    args = ("write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(state_dir, *args, environment=environment)
    old_document = scan_dir / filename
    if previous == "symlink":
        outside = tmp_path / "outside.json"
        outside.write_text("unfinished review document")
        old_document.unlink()
        old_document.symlink_to(outside)
        rejected = run_workbench(
            state_dir,
            *args,
            "--expected-draft-digest",
            "0" * 64,
            environment=environment,
            check=False,
        )
        assert rejected["returncode"] != 0
        assert "expected a file inside the scan directory" in str(rejected["stderr"])
        assert old_document.is_symlink()
        assert outside.read_text() == "unfinished review document"
        return
    old_document.write_text("unfinished review document")
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    before = {name: (scan_dir / name).read_bytes() for name in (*names, "checkpoint-head.json")}
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b"\0present\0" + before[name] + b"\0")
    rejected = run_workbench(
        state_dir,
        *args,
        "--expected-draft-digest",
        "0" * 64,
        environment=environment,
        check=False,
    )
    assert "scan_draft_conflict" in str(rejected["stderr"])
    assert all((scan_dir / name).read_bytes() == contents for name, contents in before.items())
    result = run_workbench(
        state_dir, *args, "--expected-draft-digest", digest.hexdigest(), environment=environment
    )
    assert result["status"] == "draft_written"
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"] == model
    assert json.loads((scan_dir / "findings.json").read_text())["findings"] == []
    assert json.loads((scan_dir / "coverage.json").read_text())["deferred"] == []
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    checkpoint = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
    assert checkpoint["threatModel"] == model
    assert (scan_dir / "threatmodel.md").read_text().startswith(model["content"])


@pytest.mark.parametrize("initialized", [False, True])
@pytest.mark.parametrize("complete", [False, True])
def test_deep_setup_draft_before_orchestration(
    tmp_path: Path, initialized: bool, complete: bool
) -> None:
    if initialized:
        state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    else:
        state_dir, codex_home = tmp_path / "state", tmp_path / "codex-home"
        target, scan_dir = tmp_path / "target", tmp_path / "scan"
        target.mkdir()
        (target / "app.py").write_text("value = request.args['value']\n")
        scan_dir.mkdir(mode=0o700)
        registered = run_workbench(
            state_dir,
            "register-cli-scan",
            "--scan-dir",
            str(scan_dir),
            "--repository",
            str(target),
            "--recipe-json",
            json.dumps(
                {
                    "config": {},
                    "mode": "deep",
                    "repository": str(target),
                    "target": {"kind": "repository", "paths": []},
                }
            ),
        )
        scan_id = str(registered["scanId"])
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(
        contract_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    documents = {
        key: json.loads((contract_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    model = {"format": "markdown", "content": "# Supplied setup model\n"}
    documents["manifest"] = {
        "scan": {
            **{key: documents["manifest"]["scan"][key] for key in ("target", "scope")},
            "threatModel": model,
            **({} if complete else {"complete": False}),
        }
    }
    documents["findings"]["findings"] = []
    documents["coverage"].update(completeness="complete", surfaces=[], deferred=[])
    drafts = scan_dir / "drafts"
    drafts.mkdir(exist_ok=True)
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))
    args = ("write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    environment = {"CODEX_HOME": str(codex_home)}
    if complete and not initialized:
        rejected = run_workbench(state_dir, *args, environment=environment, check=False)
        assert rejected["returncode"] != 0
        assert "orchestration state not found" in str(rejected["stderr"])
        assert not (scan_dir / "checkpoint-head.json").exists()
        return
    result = run_workbench(state_dir, *args, environment=environment)
    assert result["status"] == "draft_written"
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    checkpoint = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
    assert checkpoint["threatModel"] == model
    assert (checkpoint.get("complete") is not False) is complete
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"] == model
    assert (scan_dir / "threatmodel.md").read_text().startswith(model["content"])
    if initialized and complete:
        selected = {
            name: (scan_dir / name).read_bytes()
            for name in (
                "scan-manifest.json",
                "findings.json",
                "coverage.json",
                "checkpoint-head.json",
                "threatmodel.md",
            )
        }
        checkpoints = set((scan_dir / "checkpoints").iterdir())
        documents["manifest"]["scan"].update(
            complete=False, threatModel={"summary": "Unselected progress"}
        )
        staged.write_text(json.dumps(documents))
        assert run_workbench(state_dir, *args, environment=environment)["status"] == "draft_written"
        assert all(
            (scan_dir / name).read_bytes() == contents for name, contents in selected.items()
        )
        added = set((scan_dir / "checkpoints").iterdir()) - checkpoints
        assert len(added) == 1
        retained = json.loads(added.pop().read_text())
        assert retained["complete"] is False
        assert retained["threatModel"] == {"summary": "Unselected progress"}
