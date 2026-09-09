from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from test_workbench_scan_history import create_cli_scan, run_workbench
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("completeness", ["complete", "partial"])
def test_deep_resume_uses_sealed_coverage_with_coverage_less_reducer(
    tmp_path: Path, completeness: str
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "src").mkdir()
    (repository / "src" / "extract.py").write_text("print('fixture')\n")
    scan = create_cli_scan(
        state, tmp_path / "scans", repository, mode="deep", completeness=completeness
    )
    snapshot = {"scanId": scan["scanId"], "findings": []}
    source = Path(scan["scanDir"]) / "artifacts" / "deep_discovery" / "reducer"
    checkpoint = write_checkpoint(source / "checkpoints", snapshot)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_checkpoints "
            "(scan_id, source_path, checkpoint_path, content_sha256, snapshot_json, recorded_at, acceptance_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan["scanId"],
                str(source),
                str(checkpoint),
                checkpoint.stem,
                json.dumps(snapshot),
                "2026-09-01T00:00:00Z",
                "fixture-acceptance",
            ),
        )
    if completeness == "complete":
        result = run_workbench(
            state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False
        )
        assert result["returncode"] != 0
        assert "already completed" in result["stderr"]
    else:
        result = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
        assert result["resumeMode"] == "checkpoint"
        assert result["checkpoint"]["sources"][0]["coverage"] == {}


@pytest.mark.parametrize("marker", [None, False, True])
def test_reseeding_preserves_the_inference_boundary(tmp_path: Path, marker: bool | None) -> None:
    state, repository, parent_dir, parent_id = scan_fixture(tmp_path)
    save(
        state,
        parent_id,
        write_checkpoint(parent_dir / "checkpoints", semantic(parent_id, ["clean.ts"])),
    )
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    seed = ["continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id]
    run_workbench(state, *seed)
    assert (
        run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)["inferenceStarted"]
        is False
    )
    if marker is True:
        run_workbench(state, "start-scan-inference", "--scan-id", child_id)
    elif marker is None:
        # A migrated seeded attempt has no proof that inference never started.
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET inference_started = NULL WHERE id = ?", (child_id,)
            )
    run_workbench(state, *seed)
    assert (
        run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)["inferenceStarted"]
        is marker
    )
