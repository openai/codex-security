from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
from workbench_test_support import (
    initialize_git_repository,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("reviewed", [False, True])
def test_continuation_preserves_selected_ignored_file_identity(
    tmp_path: Path, changed: bool, reviewed: bool
) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / ".gitignore").write_text("selected.ignored\n")
    subprocess.run(["git", "add", ".gitignore"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Ignore selected fixture"], cwd=repository, check=True)
    source = repository / "selected.ignored"
    original = b"original reviewed contents\n"
    source.write_bytes(original)
    subprocess.run(["git", "check-ignore", "-q", source.name], cwd=repository, check=True)
    state = tmp_path / "state"
    recipe = {
        "repository": str(repository),
        "target": {"kind": "paths", "paths": [source.name]},
        "mode": "standard",
        "config": {},
        "validationMode": "custom",
    }

    def register(name: str, parent: str | None = None) -> tuple[Path, str]:
        root = tmp_path / name
        root.mkdir(mode=0o700)
        result = run_workbench(
            state,
            "register-cli-scan",
            "--repository",
            str(repository),
            "--scan-dir",
            str(root),
            "--recipe-json",
            json.dumps(recipe),
            *(["--parent-scan-id", parent] if parent else []),
        )
        return root, result["scanId"]

    root, parent = register("parent")
    snapshot = {
        "scanId": parent,
        "complete": reviewed,
        "scope": {"validationMode": "custom"},
        "findings": [],
        "coverage": {
            "completeness": "complete" if reviewed else "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
            "reviewedFiles": [source.name] if reviewed else [],
        },
    }
    if not reviewed:
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, parent, repository, relative_path=source.name)
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding["extensions"] = {"candidateId": "candidate-1"}
        snapshot["findings"] = [finding]
        snapshot["coverage"]["deferred"] = [
            {"candidateId": "candidate-1", "reason": "Full-file review remains incomplete."}
        ]
    paths = []
    for validated in (False, True) if reviewed else (False,):
        if validated:
            # Custom validation accepts findings without repeating source-review credit.
            snapshot["coverage"]["reviewedFiles"] = []
        path = write_checkpoint(root / "checkpoints", snapshot)
        paths.append((path, path.read_bytes()))
        run_workbench(
            state,
            "record-scan-checkpoint",
            "--scan-id",
            parent,
            "--checkpoint-path",
            str(path),
            *(["--custom-validation-complete"] if validated else []),
        )
    if changed:
        source.write_bytes(b"changed contents that have not been reviewed\n")
    child_root, child = register("child", parent)
    if changed:
        rejected = run_workbench(
            state,
            "continue-scan-checkpoint",
            "--scan-id",
            child,
            "--parent-scan-id",
            parent,
            check=False,
        )
        assert rejected["returncode"] != 0
        assert "original reviewed source" in rejected["stderr"]
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert connection.execute(
                "SELECT reviewed_at FROM scan_review_files WHERE scan_id = ?", (child,)
            ).fetchall() == [(None,)]
            assert connection.execute(
                "SELECT COUNT(*) FROM scan_checkpoints WHERE scan_id = ?", (child,)
            ).fetchone() == (0,)
        source.write_bytes(original)
        child_root, child = register("restored-source-child", parent)
    resumed = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child, "--parent-scan-id", parent
    )
    assert resumed["completionReady"] is reviewed
    assert resumed["checkpoint"]["reviewedFiles"] == ([source.name] if reviewed else [])
    assert resumed["checkpoint"]["remainingFiles"] == ([] if reviewed else [source.name])
    assert resumed["checkpoint"]["sources"][0]["customValidationComplete"] is reviewed
    if not reviewed:
        retained = json.loads((child_root / "findings.json").read_text())["findings"]
        assert len(retained) == 1
        assert retained[0]["codeEvidence"] == finding["codeEvidence"]
        deferred = json.loads((child_root / "coverage.json").read_text())["deferred"]
        assert [entry["candidateId"] for entry in deferred] == ["candidate-1"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        parent_digest = connection.execute(
            "SELECT content_sha256 FROM scan_review_files WHERE scan_id = ?", (parent,)
        ).fetchone()[0]
        assert connection.execute(
            "SELECT content_sha256, reviewed_at IS NOT NULL FROM scan_review_files WHERE scan_id = ?",
            (child,),
        ).fetchall() == [(parent_digest, int(reviewed))]
    assert all(path.read_bytes() == contents for path, contents in paths)
