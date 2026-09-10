from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path, PureWindowsPath

import pytest
from test_workbench_scan_checkpoints import save, semantic
from workbench_test_support import run_workbench, write_checkpoint


def register_scan(tmp_path: Path, repository: Path) -> tuple[Path, Path, str]:
    state = tmp_path / "state"
    output = tmp_path / "scan"
    output.mkdir(mode=0o700)
    result = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(output),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
                "mode": "standard",
                "config": {},
            }
        ),
    )
    return state, output, result["scanId"]


@pytest.mark.skipif(os.name != "posix", reason="Raw non-UTF-8 filenames use POSIX filesystem bytes")
def test_non_utf8_review_filename_survives_registration_checkpoint_and_resume(tmp_path: Path):
    repository = tmp_path / "repository"
    repository.mkdir()
    filename = os.fsdecode(b"legacy-\xff.ts")
    (repository / filename).write_bytes(b"export const legacy = true;\n")
    (repository / "clean.ts").write_text("export const count = 1;\n")
    state, output, scan_id = register_scan(tmp_path, repository)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert dict(
            connection.execute(
                "SELECT relative_path, typeof(relative_path) FROM scan_review_files "
                "WHERE scan_id = ?",
                (scan_id,),
            )
        ) == {"clean.ts": "text", b"legacy-\xff.ts": "blob"}
    save(state, scan_id, write_checkpoint(output / "checkpoints", semantic(scan_id, ["clean.ts"])))
    checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert checkpoint["reviewedFiles"] == ["clean.ts"]
    assert [os.fsencode(path) for path in checkpoint["remainingFiles"]] == [b"legacy-\xff.ts"]
    saved = write_checkpoint(output / "checkpoints", semantic(scan_id, [filename]))
    save(state, scan_id, saved)
    checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert {os.fsencode(path) for path in checkpoint["reviewedFiles"]} == {
        b"clean.ts",
        b"legacy-\xff.ts",
    }
    assert checkpoint["remainingFiles"] == []
    assert checkpoint["sources"][0]["coverage"]["reviewedFiles"] == [filename]


def test_case_distinct_review_files_survive_windows_path_equality(
    tmp_path: Path, workbench_api, monkeypatch
):
    repository = tmp_path / "repository"
    repository.mkdir()
    upper = repository / "Parser.ts"
    lower = repository / "parser.ts"
    upper.write_text("export const upper = true;\n")
    if lower.exists():
        pytest.skip("The fixture filesystem does not support case-distinct files")
    lower.write_text("export const lower = true;\n")
    state, output, scan_id = register_scan(tmp_path, repository)
    checkpoints = workbench_api["scan_checkpoints"]
    enumerate_paths = checkpoints.repo_scope_paths

    class WindowsEqualityPath(type(Path())):
        # Keep real filesystem operations while reproducing WindowsPath's
        # lexical equality when the test runs on a Unix host.
        def __hash__(self):
            return hash(PureWindowsPath(str(self)))

        def __eq__(self, other):
            return PureWindowsPath(str(self)) == PureWindowsPath(str(other))

    def windows_paths(*args, **kwargs):
        return [WindowsEqualityPath(path) for path in enumerate_paths(*args, **kwargs)]

    assert WindowsEqualityPath(upper) == WindowsEqualityPath(lower)
    assert not upper.samefile(lower)
    monkeypatch.setattr(checkpoints, "repo_scope_paths", windows_paths)
    inventory = checkpoints.review_file_inventory(repository, ["."])
    assert dict(inventory) == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (upper, lower)
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("DELETE FROM scan_review_files WHERE scan_id = ?", (scan_id,))
        checkpoints.freeze_review_files(connection, scan_id, inventory)
    save(state, scan_id, write_checkpoint(output / "checkpoints", semantic(scan_id, [upper.name])))
    checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert checkpoint["reviewedFiles"] == [upper.name]
    assert checkpoint["remainingFiles"] == [lower.name]
    save(state, scan_id, write_checkpoint(output / "checkpoints", semantic(scan_id, [lower.name])))
    checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert checkpoint["reviewedFiles"] == [upper.name, lower.name]
    assert checkpoint["remainingFiles"] == []
