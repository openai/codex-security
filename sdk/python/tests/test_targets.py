from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from openai_codex_security import DiffTarget, InvalidTargetError
from openai_codex_security.targets import normalize_target


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _git_output(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "src").mkdir()
    (repo / "src/app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return repo


def test_repository_target(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = normalize_target(repo, "repository")
    assert target.kind == "repository"
    assert target.paths == ()


def test_path_target_is_repository_relative(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = normalize_target(repo, ["src", repo / "src/app.py"])
    assert target.kind == "paths"
    assert target.paths == ("src", "src/app.py")


def test_path_target_rejects_empty_path(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    with pytest.raises(InvalidTargetError, match="empty path"):
        normalize_target(repo, [""])


def test_ref_diff_requires_valid_refs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = normalize_target(repo, DiffTarget.refs(base="HEAD", head="HEAD"))
    assert target.kind == "refs"
    assert target.base == _git_output(repo, "rev-parse", "HEAD")
    assert target.head == _git_output(repo, "rev-parse", "HEAD")
    assert target.base_ref == "HEAD"
    assert target.head_ref == "HEAD"

    with pytest.raises(InvalidTargetError, match="unknown Git ref"):
        normalize_target(repo, DiffTarget.refs(base="missing", head="HEAD"))


def test_diff_target_requires_git_worktree_root(tmp_path: Path) -> None:
    repo = _repo(tmp_path)

    with pytest.raises(InvalidTargetError, match="Git worktree root"):
        normalize_target(repo / "src", DiffTarget.refs(base="HEAD", head="HEAD"))


def test_working_tree_target(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = normalize_target(repo, DiffTarget.working_tree(base="HEAD"))
    assert target.kind == "working_tree"
    assert target.base == _git_output(repo, "rev-parse", "HEAD")
    assert target.head == _git_output(repo, "rev-parse", "HEAD")
    assert target.base_ref == "HEAD"


def test_diff_target_rejects_invalid_public_states() -> None:
    with pytest.raises(InvalidTargetError, match="Unsupported diff target kind"):
        DiffTarget(kind="typo", base="HEAD")  # type: ignore[arg-type]
    with pytest.raises(InvalidTargetError, match="head ref"):
        DiffTarget(kind="refs", base="HEAD", head=None)
    with pytest.raises(InvalidTargetError, match="cannot specify a head"):
        DiffTarget(kind="working_tree", base="HEAD", head="HEAD")


def test_plain_path_string_is_not_a_path_sequence(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(InvalidTargetError, match="target"):
        normalize_target(repo, "src")
