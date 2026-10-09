from __future__ import annotations

import json
import runpy
import sqlite3
import subprocess
from pathlib import Path

import pytest
from workbench_test_support import (
    SCRIPT,
    create_saved_git_workspace,
    initialize_git_repository,
    run_workbench,
    start_delivered_scan,
    write_completed_contract,
)


def test_migration_does_not_infer_repository_from_current_origin(tmp_path: Path) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    initialize_git_repository(target)
    workspace = create_saved_git_workspace(state, target)
    started = start_delivered_scan(
        state, "--workspace-id", str(workspace["id"]), "--scan-root", str(tmp_path / "scans")
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("ALTER TABLE scans DROP COLUMN target_remote")
        connection.execute("ALTER TABLE scans DROP COLUMN target_repository_path")
        connection.execute("ALTER TABLE scans DROP COLUMN target_provenance_recorded")
        connection.execute("DELETE FROM schema_migrations WHERE version = 48")
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/current.git"],
        cwd=target,
        check=True,
    )
    run_workbench(state, "get-scan", "--scan-id", str(started["results"]["scanId"]))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT target_remote, target_repository_path, target_provenance_recorded FROM scans"
        ).fetchall() == [(None, None, 0)]


@pytest.mark.parametrize("has_remote", [False, True])
@pytest.mark.parametrize("field", ["remote", "repositoryPath"])
def test_sealed_manifest_must_match_saved_repository_provenance(
    tmp_path: Path, has_remote: bool, field: str
) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    revision = initialize_git_repository(target)
    if has_remote:
        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/example/original.git"],
            cwd=target,
            check=True,
        )
    workspace = create_saved_git_workspace(state, target)
    started = start_delivered_scan(
        state, "--workspace-id", str(workspace["id"]), "--scan-root", str(tmp_path / "scans")
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir, scan_id, target, target_kind="git_revision", target_revision=revision
    )
    run_workbench(state, "complete-scan", "--scan-id", scan_id)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        namespace["verify_manifest_binding"](scan, manifest)
        manifest["scan"]["target"][field] = (
            "https://github.com/example/changed.git" if field == "remote" else "nested"
        )
        with pytest.raises(SystemExit, match="must match saved scan provenance"):
            namespace["verify_manifest_binding"](scan, manifest)


def test_initial_completion_rejects_presealed_unrecorded_remote(tmp_path: Path) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    revision = initialize_git_repository(target)
    workspace = create_saved_git_workspace(state, target)
    started = start_delivered_scan(
        state, "--workspace-id", str(workspace["id"]), "--scan-root", str(tmp_path / "scans")
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(
        scan_dir, scan_id, target, target_kind="git_revision", target_revision=revision
    )
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["target"].update(
        remote="https://github.com/example/invented.git", repositoryPath="."
    )
    manifest_path.write_text(json.dumps(manifest))
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    namespace["finalize_scan"](scan_dir)
    assert json.loads(manifest_path.read_text())["scan"]["sealedAt"]
    completed = run_workbench(state, "complete-scan", "--scan-id", scan_id, check=False)
    assert completed["returncode"] != 0
    assert "must match saved scan provenance" in completed["stderr"]


@pytest.mark.parametrize("presealed", [False, True])
def test_legacy_scan_cannot_claim_frozen_repository_provenance(
    tmp_path: Path, presealed: bool
) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    revision = initialize_git_repository(target)
    workspace = create_saved_git_workspace(state, target)
    started = start_delivered_scan(
        state, "--workspace-id", str(workspace["id"]), "--scan-root", str(tmp_path / "scans")
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_provenance_recorded = 0, "
            "target_remote = NULL, target_repository_path = NULL WHERE id = ?",
            (scan_id,),
        )
    write_completed_contract(
        scan_dir, scan_id, target, target_kind="git_revision", target_revision=revision
    )
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["target"].update(
        remote="https://github.com/example/invented.git", repositoryPath="."
    )
    manifest_path.write_text(json.dumps(manifest))
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    if presealed:
        namespace["finalize_scan"](scan_dir)
    completed = run_workbench(state, "complete-scan", "--scan-id", scan_id, check=False)
    if presealed:
        assert completed["returncode"] != 0
        assert "must match saved scan provenance" in completed["stderr"]
    else:
        assert completed["returncode"] == 0, completed
        manifest = json.loads(manifest_path.read_text())
        assert manifest["scan"]["sealedAt"]
        assert "repositoryPath" not in manifest["scan"]["target"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        with pytest.raises(SystemExit, match="must match saved scan provenance"):
            namespace["verify_repository_provenance"](scan, {"repositoryPath": "."})
