from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
from workbench_test_support import initialize_git_repository, run_workbench, write_checkpoint


@pytest.mark.parametrize("changed", [False, True])
def test_custom_continuation_preserves_reviewed_ignored_file_identity(
    tmp_path: Path, changed: bool
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
        "complete": True,
        "scope": {"validationMode": "custom"},
        "findings": [],
        "coverage": {
            "completeness": "complete",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
            "reviewedFiles": [source.name],
        },
    }
    paths = []
    for validated in (False, True):
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
    _, child = register("child", parent)
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
        _, child = register("restored-source-child", parent)
    resumed = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child, "--parent-scan-id", parent
    )
    assert resumed["completionReady"] is True
    assert resumed["checkpoint"]["reviewedFiles"] == [source.name]
    assert resumed["checkpoint"]["remainingFiles"] == []
    assert resumed["checkpoint"]["sources"][0]["customValidationComplete"] is True
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        parent_digest = connection.execute(
            "SELECT content_sha256 FROM scan_review_files WHERE scan_id = ?", (parent,)
        ).fetchone()[0]
        assert connection.execute(
            "SELECT content_sha256, reviewed_at IS NOT NULL FROM scan_review_files WHERE scan_id = ?",
            (child,),
        ).fetchall() == [(parent_digest, 1)]
    assert all(path.read_bytes() == contents for path, contents in paths)
