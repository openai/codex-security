from __future__ import annotations

import json
import runpy
import subprocess
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rust_scan_guidance(monkeypatch):
    scripts = PLUGIN_ROOT / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    namespace = runpy.run_path(str(scripts / "workbench" / "scan_guidance.py"))
    return namespace["rust_scan_guidance"]


def write_file(repository: Path, name: str, content: str = "example\n") -> Path:
    path = repository / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def make_repository(tmp_path: Path, *, with_git: bool = True) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    if with_git:
        git(repository, "init", "-q")
    return repository


def commit(repository: Path) -> str:
    git(repository, "add", "--all")
    git(repository, "commit", "-qm", "fixture")
    return git(repository, "rev-parse", "HEAD")


def diff_target(repository: Path, kind: str, base: str) -> dict[str, str]:
    head = base if kind == "working_tree" else commit(repository)
    return {"kind": kind, "baseRevision": base, "headRevision": head}


@pytest.mark.parametrize(
    "scopes", [["src"], ["src/lib.rs"], ["docs", "src"], ["docs", "src/lib.rs"]]
)
def test_rust_in_selected_directory_file_or_multiple_scopes(
    tmp_path: Path, rust_scan_guidance, scopes: list[str]
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "src/lib.rs", "pub fn example() {}\n")
    write_file(repository, "docs/readme.md")

    guidance = rust_scan_guidance(repository, scopes, plugin_root=PLUGIN_ROOT)

    assert json.dumps(str(PLUGIN_ROOT / "skills" / "unsafe-rust-review" / "SKILL.md")) in guidance


@pytest.mark.parametrize("scopes", [["app"], ["app/main.py"], ["app", "docs"]])
def test_rust_elsewhere_does_not_select_guidance(
    tmp_path: Path, rust_scan_guidance, scopes: list[str]
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "native/lib.rs")
    write_file(repository, "app/main.py")
    write_file(repository, "docs/readme.md")

    assert rust_scan_guidance(repository, scopes, plugin_root=PLUGIN_ROOT) == ""


@pytest.mark.parametrize("tracked", [False, True])
def test_git_ignored_rust_is_selected_only_when_tracked(
    tmp_path: Path, rust_scan_guidance, tracked: bool
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, ".gitignore", "ignored/\n")
    write_file(repository, "ignored/lib.rs")
    if tracked:
        git(repository, "add", "--force", "--", "ignored/lib.rs")

    assert bool(rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT)) is tracked


@pytest.mark.parametrize("with_git", [False, True])
def test_explicitly_selected_ignored_rust_file_selects_guidance(
    tmp_path: Path, rust_scan_guidance, with_git: bool
) -> None:
    repository = make_repository(tmp_path, with_git=with_git)
    write_file(repository, ".gitignore", "ignored/\n")
    write_file(repository, "ignored/lib.rs")

    assert rust_scan_guidance(repository, ["ignored/lib.rs"], plugin_root=PLUGIN_ROOT)


@pytest.mark.parametrize("ignore_name", [".gitignore", ".ignore"])
def test_non_git_directory_respects_ignore_files(
    tmp_path: Path, rust_scan_guidance, ignore_name: str
) -> None:
    repository = make_repository(tmp_path, with_git=False)
    write_file(repository, ignore_name, "ignored/\n")
    write_file(repository, "ignored/lib.rs")
    write_file(repository, "app.py")

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT) == ""

    write_file(repository, "src/lib.rs")

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT)


def test_rust_text_and_cargo_metadata_do_not_select_guidance(
    tmp_path: Path, rust_scan_guidance
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "README.md", "```rust\nunsafe fn example() {}\n```\n")
    write_file(repository, "Cargo.toml", '[package]\nname = "example"\nversion = "0.1.0"\n')
    write_file(repository, "Cargo.lock", 'version = 3\n[[package]]\nname = "example"\n')

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT) == ""


@pytest.mark.parametrize("kind", ["working_tree", "commit", "range"])
def test_deleted_rust_in_selected_diff_selects_guidance(
    tmp_path: Path, rust_scan_guidance, kind: str
) -> None:
    repository = make_repository(tmp_path)
    source = write_file(repository, "src/lib.rs")
    base = commit(repository)
    source.unlink()
    target = diff_target(repository, kind, base)

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT, diff_target=target)


@pytest.mark.parametrize("kind", ["working_tree", "commit", "range"])
def test_unchanged_rust_does_not_select_guidance_for_unrelated_diff(
    tmp_path: Path, rust_scan_guidance, kind: str
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "src/lib.rs")
    write_file(repository, "app.py", "before\n")
    base = commit(repository)
    write_file(repository, "app.py", "after\n")
    target = diff_target(repository, kind, base)

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT, diff_target=target) == ""


@pytest.mark.parametrize("state", ["untracked", "staged", "unstaged"])
def test_working_tree_diff_selects_each_kind_of_rust_change(
    tmp_path: Path, rust_scan_guidance, state: str
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "app.py")
    if state == "unstaged":
        write_file(repository, "src/lib.rs", "pub fn before() {}\n")
    base = commit(repository)
    write_file(repository, "src/lib.rs", "pub fn after() {}\n")
    if state == "staged":
        git(repository, "add", "--", "src/lib.rs")
    target = diff_target(repository, "working_tree", base)

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT, diff_target=target)


@pytest.mark.parametrize("kind", ["commit", "range"])
def test_committed_diff_selects_rust_from_requested_revisions_not_checkout(
    tmp_path: Path, rust_scan_guidance, kind: str
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "app.py")
    base = commit(repository)
    source = write_file(repository, "src/lib.rs")
    target = diff_target(repository, kind, base)
    source.unlink()
    commit(repository)

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT, diff_target=target)


@pytest.mark.parametrize("kind", ["working_tree", "commit", "range"])
def test_diff_uses_existing_exclusions_for_rust_paths(
    tmp_path: Path, rust_scan_guidance, kind: str
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "app.py")
    base = commit(repository)
    write_file(repository, "docs/example.rs")
    write_file(repository, "vendor/library.rs")
    target = diff_target(repository, kind, base)

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT, diff_target=target) == ""


@pytest.mark.parametrize("kind", [None, "working_tree", "commit", "range"])
def test_selection_does_not_read_source_contents(
    tmp_path: Path, monkeypatch, rust_scan_guidance, kind: str | None
) -> None:
    repository = make_repository(tmp_path)
    other = write_file(repository, "app.py")
    base = commit(repository)
    source = write_file(repository, "src/lib.rs", "pub fn example() {}\n")
    target = diff_target(repository, kind, base) if kind is not None else None
    source_paths = {source.resolve(), other.resolve()}
    original_open = Path.open

    def open_without_source_contents(path: Path, *args, **kwargs):
        assert path.resolve() not in source_paths, f"Selection read source contents: {path}"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_without_source_contents)

    assert rust_scan_guidance(repository, ["."], plugin_root=PLUGIN_ROOT, diff_target=target)
