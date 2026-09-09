from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from test_workbench_scan_checkpoints import scan_fixture, semantic
from test_workbench_standard_deep_results import accepted_standard_worker, deep_scan_fixture
from workbench_test_support import run_workbench, write_checkpoint


def test_custom_validation_attestation_rolls_back_with_its_checkpoint(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("# source\n")
    scan = tmp_path / "scan"
    scan.mkdir(mode=0o700)
    state = tmp_path / "state"
    scan_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
                "mode": "standard",
                "config": {},
                "validationMode": "custom",
            }
        ),
    )["scanId"]
    snapshot = semantic(scan_id, ["source.py"])
    snapshot["scope"] = {"validationMode": "custom"}
    path = write_checkpoint(scan / "checkpoints", snapshot)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "CREATE TRIGGER reject_attestation BEFORE UPDATE OF "
            "custom_validation_checkpoint_acceptance_id ON scans "
            "BEGIN SELECT RAISE(FAIL, 'Synthetic attestation failure'); END"
        )
    failed = run_workbench(
        state,
        "record-scan-checkpoint",
        "--scan-id",
        scan_id,
        "--checkpoint-path",
        str(path),
        "--custom-validation-complete",
        check=False,
    )
    assert failed["returncode"] != 0
    assert "Synthetic attestation failure" in failed["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (0,)
        assert connection.execute(
            "SELECT custom_validation_checkpoint_acceptance_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (None,)
        connection.execute("DROP TRIGGER reject_attestation")
    # A durable head can replay semantic evidence after rollback, but cannot
    # manufacture the host completion that failed to commit with it.
    replayed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    source = replayed["checkpoint"]["sources"][0]
    assert source["scope"]["validationMode"] == "custom"
    assert source["customValidationComplete"] is False
    assert json.loads(path.read_bytes()) == snapshot


def test_custom_validation_attestation_requires_original_custom_recipe(tmp_path: Path) -> None:
    state, _, scan, scan_id = scan_fixture(tmp_path)
    path = write_checkpoint(scan / "checkpoints", semantic(scan_id, []))
    rejected = run_workbench(
        state,
        "record-scan-checkpoint",
        "--scan-id",
        scan_id,
        "--checkpoint-path",
        str(path),
        "--custom-validation-complete",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "original root scan recipe" in rejected["stderr"]


def test_deep_worker_checkpoint_cannot_attest_parent_custom_validation(tmp_path: Path) -> None:
    state, codex_home, _, scan, scan_id = deep_scan_fixture(tmp_path)
    _, result = accepted_standard_worker(state, codex_home, scan, scan_id)
    path = write_checkpoint(result.parent / "checkpoints", semantic(scan_id, []))
    rejected = run_workbench(
        state,
        "record-scan-checkpoint",
        "--scan-id",
        scan_id,
        "--checkpoint-path",
        str(path),
        "--custom-validation-complete",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "original root scan recipe" in rejected["stderr"]
