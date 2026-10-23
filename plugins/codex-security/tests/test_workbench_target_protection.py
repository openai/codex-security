from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import uuid
from pathlib import Path

import pytest
from workbench_test_support import get_scan, load_script, run_workbench


def link_directory(target: Path, link: Path) -> None:
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True)
    else:
        link.symlink_to(target, target_is_directory=True)


def linked_target(root: Path) -> tuple[Path, Path, Path]:
    repository = root / "repository"
    (repository / ".git").mkdir(parents=True)
    target = root / "destination"
    target.mkdir()
    (target / "fixture.txt").write_text("Synthetic target.\n")
    alias = repository / "linked-target"
    link_directory(target, alias)
    return repository, target, alias


def begin(state: Path, target: Path, scans: Path, *, owner: str = "synthetic-owner") -> dict:
    return run_workbench(
        state,
        "begin-deep-scan",
        "--target-path",
        str(target),
        "--thread-id",
        owner,
        "--scan-root",
        str(scans),
    )


def saved_roots(state: Path, table: str, row_id: str) -> list[str] | None:
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        saved = connection.execute(
            f"SELECT target_protection_roots_json FROM {table} WHERE id = ?", (row_id,)
        ).fetchone()[0]
    return json.loads(saved) if saved is not None else None


def test_deep_scan_retains_target_provenance_across_rejoin(tmp_path: Path) -> None:
    repository, target, alias = linked_target(tmp_path)
    state, scans = tmp_path / "state", tmp_path / "scans"
    started = begin(state, alias, scans)
    scan = started["scan"]
    expected = [str(repository.resolve()), str(target.resolve())]
    assert scan["targetPath"] == str(target.resolve())
    assert scan["targetProtectionRoots"] == expected
    assert saved_roots(state, "workspaces", started["workspace"]["id"]) == expected
    assert saved_roots(state, "scans", scan["scanId"]) == expected

    alias.rmdir() if os.name == "nt" else alias.unlink()
    for arguments in (
        ("--scan-id", scan["scanId"], "--claim-token", scan["handoffClaimToken"]),
        ("--target-path", str(target)),
    ):
        rejoined = run_workbench(
            state,
            "begin-deep-scan",
            *arguments,
            "--thread-id",
            "synthetic-owner",
            "--scan-root",
            str(scans),
        )
        assert rejoined["scan"]["scanId"] == scan["scanId"]
        assert rejoined["scan"]["targetProtectionRoots"] == expected
    assert saved_roots(state, "scans", scan["scanId"]) == expected


@pytest.mark.parametrize("incomplete_scope", [False, True])
def test_workspace_round_trip_preserves_roots_and_scan_copy(
    tmp_path: Path, incomplete_scope: bool
) -> None:
    repository, target, alias = linked_target(tmp_path)
    state = tmp_path / "state"
    workspace_id = str(uuid.uuid4())
    created = run_workbench(
        state,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--thread-id",
        "synthetic-owner",
        "--target-path",
        str(alias),
        *(["--scope", "../outside"] if incomplete_scope else []),
    )
    canonical = created["targetPath"]
    assert canonical == str(target.resolve())
    run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        canonical,
        "--scope",
        ".",
        "--mode",
        "deep",
    )
    started = run_workbench(
        state,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )["results"]
    expected = [str(repository.resolve()), str(target.resolve())]
    assert started["targetProtectionRoots"] == expected
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE workspaces SET target_protection_roots_json = '[]' WHERE id = ?",
            (workspace_id,),
        )
    assert get_scan(state, started["scanId"])["scan"]["targetProtectionRoots"] == expected


def test_workspace_target_change_replaces_roots(tmp_path: Path) -> None:
    _repository, _target, alias = linked_target(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    state = tmp_path / "state"
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state, "create-workspace", "--workspace-id", workspace_id, "--target-path", str(alias)
    )
    run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(other),
        "--scope",
        ".",
        "--mode",
        "standard",
    )
    assert saved_roots(state, "workspaces", workspace_id) == [str(other.resolve())]


def test_distinct_scans_keep_their_own_target_roots(tmp_path: Path) -> None:
    state, scans = tmp_path / "state", tmp_path / "scans"
    for name in ("first", "second"):
        root = tmp_path / name
        root.mkdir()
        repository, target, alias = linked_target(root)
        started = begin(state, alias, scans, owner=name)
        assert started["scan"]["targetProtectionRoots"] == [
            str(repository.resolve()),
            str(target.resolve()),
        ]


def test_explicit_alias_join_adds_protection_without_losing_prior_roots(tmp_path: Path) -> None:
    repository, target, alias = linked_target(tmp_path)
    state, scans = tmp_path / "state", tmp_path / "scans"
    first = begin(state, alias, scans)
    other = tmp_path / "other-repository"
    (other / ".git").mkdir(parents=True)
    link_directory(target, other / "selected")
    joined = begin(state, other / "selected", scans)
    expected = [str(repository), str(target), str(other)]
    assert joined["scan"]["scanId"] == first["scan"]["scanId"]
    assert joined["scan"]["targetProtectionRoots"] == expected
    assert saved_roots(state, "workspaces", first["workspace"]["id"]) == expected


def test_plain_target_fallback_does_not_protect_parent(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.txt").write_text("Synthetic target.\n")
    started = begin(tmp_path / "state", target, tmp_path / "scans")
    assert started["scan"]["targetProtectionRoots"] == [str(target.resolve())]


def test_target_protection_preserves_symlink_parent_traversal(tmp_path: Path) -> None:
    target_protection_roots = load_script("workbench_target").target_protection_roots

    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    destination = tmp_path / "destination"
    (destination / ".git").mkdir(parents=True)
    (destination / "nested").mkdir()
    (destination / "target").mkdir()
    link_directory(destination / "nested", repository / "link")
    (repository / "target").mkdir()
    selected = repository / "link" / ".." / "target"
    assert selected.resolve() == destination / "target"
    assert target_protection_roots(str(selected)) == [str(repository), str(destination)]


@pytest.mark.parametrize("kind", ["absent", "legacy"])
def test_legacy_rows_do_not_invent_target_provenance(tmp_path: Path, kind: str) -> None:
    repository, target, alias = linked_target(tmp_path)
    state = tmp_path / "state"
    scans = tmp_path / "scans"
    started = begin(state, alias, scans)
    scan = started["scan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET target_protection_roots_json = NULL")
        connection.execute("UPDATE workspaces SET target_protection_roots_json = NULL")
        if kind == "legacy":
            connection.execute("ALTER TABLE scans DROP COLUMN target_protection_roots_json")
            connection.execute("ALTER TABLE workspaces DROP COLUMN target_protection_roots_json")
            connection.execute("DELETE FROM schema_migrations WHERE version = 56")
    restored = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan["scanId"],
        "--claim-token",
        scan["handoffClaimToken"],
        "--thread-id",
        "synthetic-owner",
    )
    assert "targetProtectionRoots" not in restored["scan"]
    assert saved_roots(state, "scans", scan["scanId"]) is None
    repaired = begin(state, alias, scans)
    assert repaired["scan"]["scanId"] == scan["scanId"]
    expected = [str(repository), str(target)]
    assert repaired["scan"]["targetProtectionRoots"] == expected
    assert saved_roots(state, "workspaces", started["workspace"]["id"]) == expected
    assert get_scan(state, scan["scanId"])["scan"]["targetProtectionRoots"] == expected
