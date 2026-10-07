from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from source_cases import SOURCE_CASES

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "generate_rank_input.py"
GOLDEN_DIR = Path(__file__).resolve().parent / "goldens"


def run_cli(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def test_cli_loads_preview_helper_with_safe_path() -> None:
    result = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Codex Security scan worklist helper" in result.stdout


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def git(repo: Path, *args: str, input: str | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        input=input,
        text=True,
    )
    return result.stdout.strip()


def initialize_repo(repo: Path) -> None:
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "codex-security-tests@example.com")
    git(repo, "config", "user.name", "Codex Security Tests")


def test_make_repo_rank_input_matches_golden_and_filters_noise(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "zeta.py").write_text("zeta = 2", encoding="utf-8")
    (repo / "src" / "alpha.py").write_text("alpha = 1", encoding="utf-8")
    (repo / "src" / "binary.py").write_bytes(b"value\x00binary")
    (repo / "src" / "binary.unlisted").write_bytes(b"x" * (64 * 1024 + 1) + b"\0binary")
    (repo / "tests" / "ignored.py").write_text("ignored = True", encoding="utf-8")
    (repo / "README.md").write_text("ignored", encoding="utf-8")
    output = tmp_path / "rank_input.jsonl"

    run_cli(
        "make-repo-rank-input",
        "--repo",
        str(repo),
        "--scope",
        "src",
        "--out",
        str(output),
    )

    assert output.read_text(encoding="utf-8") == (GOLDEN_DIR / "rank_input.jsonl").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("mode", ["repo", "revisions"])
def test_rank_input_keeps_large_generated_python(tmp_path: Path, mode: str) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    initialize_repo(repo)
    git(repo, "commit", "--allow-empty", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    source = "value = " + " + ".join(["x"] * 150000) + "\n"
    (repo / "src" / "generated.py").write_text(source, encoding="utf-8")
    (repo / "src" / "normal.py").write_text("value = 1\n", encoding="utf-8")
    output = tmp_path / "rank_input.jsonl"

    if mode == "repo":
        arguments = ["make-repo-rank-input", "--repo", str(repo), "--scope", "src"]
    else:
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "change")
        arguments = ["make-diff-rank-input", "--repo", str(repo), "--base", base, "--head", "HEAD"]
    run_cli(*arguments, "--preview-bytes", "128", "--out", str(output))

    rows = read_jsonl(output)
    assert [row["path"] for row in rows] == ["src/generated.py", "src/normal.py"]
    preview = rows[0]["preview"]
    assert preview
    assert source.startswith(preview)
    assert len(preview.encode("utf-8")) <= 128
    assert rows[1]["preview"] == "value = 1"


@pytest.mark.parametrize("mode", ["repo", "revisions", "local-patch"])
@pytest.mark.parametrize(
    "source",
    ['{"\\ud800":1}', '{"value":' + "1" * 4301 + "}"],
    ids=["surrogate", "integer-limit"],
)
def test_rank_input_samples_json_without_a_renderable_outline(
    tmp_path: Path, mode: str, source: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    initialize_repo(repo)
    git(repo, "commit", "--allow-empty", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "data.json").write_text(source, encoding="utf-8")
    output = tmp_path / "rank.jsonl"
    if mode == "repo":
        arguments = ["make-repo-rank-input", "--repo", str(repo)]
    else:
        arguments = ["make-diff-rank-input", "--repo", str(repo), "--mode", mode, "--base", base]
        if mode == "revisions":
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "change")
            arguments.extend(["--head", "HEAD"])

    run_cli(*arguments, "--preview-bytes", "128", "--out", str(output))

    rows = read_jsonl(output)
    assert len(rows) == 1
    assert rows[0]["path"] == "data.json"
    assert rows[0]["preview"] == source[:128]


def test_revision_previews_use_the_worktree_read_budget(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    initialize_repo(repo)
    git(repo, "commit", "--allow-empty", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "large.py").write_text(
        "def visible():\n    pass\n" + "# comment\n" * 10000 + "def outside():\n    pass\n",
        encoding="utf-8",
    )
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "change")
    output = tmp_path / "rank.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(repo),
        "--base",
        base,
        "--head",
        "HEAD",
        "--out",
        str(output),
    )

    assert read_jsonl(output)[0]["preview"] == "function visible()"


def test_revision_rank_input_classifies_bytes_beyond_the_preview_sample(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    initialize_repo(repo)
    git(repo, "commit", "--allow-empty", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "binary.py").write_bytes(b"# comment\n" * 10_000 + b"\0")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "change")
    output = tmp_path / "rank.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(repo),
        "--base",
        base,
        "--head",
        "HEAD",
        "--out",
        str(output),
    )

    assert read_jsonl(output) == []


@pytest.mark.parametrize("scope", [".", "src", "src/large.py", "explicit", "overlap", "diff"])
def test_rank_input_streams_classification_and_bounds_previews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    source = repo / "src" / "large.py"
    source.write_bytes(b"def visible():\n    pass\n" + b"# source comment\n" * (128 * 1024))
    output = tmp_path / "rank_input.jsonl"
    arguments = ["make-repo-rank-input", "--repo", str(repo), "--out", str(output)]
    if scope in {"explicit", "overlap"}:
        scopes = tmp_path / "scopes.json"
        scopes.write_text(
            json.dumps(["src/large.py"] if scope == "explicit" else ["src", "src/large.py"])
        )
        arguments.extend(["--scopes-file", str(scopes)])
    elif scope == "diff":
        initialize_repo(repo)
        git(repo, "commit", "--allow-empty", "-qm", "initial")
        arguments[0] = "make-diff-rank-input"
        arguments.extend(["--mode", "local-patch", "--base", "HEAD"])
    else:
        arguments.extend(["--scope", scope])

    original_open = Path.open
    reads: list[int] = []

    def tracked_open(path: Path, *args, **kwargs):
        reader = original_open(path, *args, **kwargs)
        if path == source:
            read = reader.read
            index = len(reads)
            reads.append(0)

            def bounded_read(size: int = -1) -> bytes:
                assert 0 <= size <= 64 * 1024
                data = read(size)
                reads[index] += len(data)
                return data

            reader.read = bounded_read
        return reader

    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *arguments])
    with patch.object(Path, "open", tracked_open):
        runpy.run_path(str(SCRIPT), run_name="__main__")

    assert set(reads) == {64 * 1024, source.stat().st_size}
    rows = read_jsonl(output)
    assert len(rows) == 1
    assert rows[0]["path"] == "src/large.py"
    assert rows[0]["preview"] == "function visible()"


@pytest.mark.parametrize("mode", ["repo", "revisions", "staged", "unstaged"])
def test_rank_input_includes_source_cases(tmp_path: Path, mode: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    initialize_repo(repo)
    for case in SOURCE_CASES:
        source = repo / case.path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(case.before + "\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    for case in SOURCE_CASES:
        (repo / case.path).write_text(case.after + "\n", encoding="utf-8")
    output = tmp_path / "rank_input.jsonl"

    if mode in {"revisions", "staged"}:
        git(repo, "add", ".")
    if mode == "repo":
        arguments = ["make-repo-rank-input", "--repo", str(repo), "--scope", "."]
    else:
        diff_mode = "revisions" if mode == "revisions" else "local-patch"
        arguments = [
            "make-diff-rank-input",
            "--repo",
            str(repo),
            "--base",
            base,
            "--mode",
            diff_mode,
        ]
        if mode == "revisions":
            git(repo, "commit", "-qm", "change")
            arguments.extend(["--head", git(repo, "rev-parse", "HEAD")])
            git(repo, "checkout", "-q", base)

    run_cli(*arguments, "--out", str(output))

    assert read_jsonl(output) == [
        {
            "path": case.path,
            "area": "." if mode == "repo" else "diff",
            "preview": case.after if case.preview is None else case.preview,
        }
        for case in sorted(SOURCE_CASES, key=lambda case: case.path)
    ]


def test_make_repo_rank_input_rejects_scope_outside_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    result = run_cli(
        "make-repo-rank-input",
        "--repo",
        str(repo),
        "--scope",
        str(outside),
        "--out",
        str(tmp_path / "rank.jsonl"),
        check=False,
    )

    assert result.returncode != 0
    assert "Scope must be inside repo" in result.stderr


def test_make_repo_rank_input_does_not_follow_file_symlinks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    (source / "runtime.py").write_text("runtime = True", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("outside_secret = True", encoding="utf-8")
    (source / "outside-link.py").symlink_to(outside)
    (source / "inside-link.py").symlink_to(source / "runtime.py")
    output = tmp_path / "rank_input.jsonl"

    run_cli(
        "make-repo-rank-input",
        "--repo",
        str(repo),
        "--scope",
        "src",
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [
        {"path": "src/runtime.py", "area": "src", "preview": "runtime = True"}
    ]
    assert "outside_secret" not in output.read_text(encoding="utf-8")


def test_make_repo_rank_input_preserves_legacy_tilde_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    repo = home / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "runtime.py").write_text("runtime = True", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    output = tmp_path / "rank_input.jsonl"

    run_cli(
        "make-repo-rank-input",
        "--repo",
        "~/repo",
        "--scope",
        "~/repo/src",
        "--out",
        str(output),
    )

    assert [row["path"] for row in read_jsonl(output)] == ["src/runtime.py"]


def test_make_repo_rank_input_combines_explicit_files_and_directories(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "~codex_review_nonexistent_user" / "src").mkdir(parents=True)
    (repo / "src" / "runtime.py").write_text("runtime = True", encoding="utf-8")
    (repo / "tests" / "security_test.py").write_text("security = True", encoding="utf-8")
    (repo / "~codex_review_nonexistent_user" / "src" / "literal.py").write_text(
        "literal = True", encoding="utf-8"
    )
    (repo / "Dockerfile").write_text("FROM scratch", encoding="utf-8")
    (repo / "package-lock.json").write_text("{}", encoding="utf-8")
    unicode_file = repo / "audit\u0085Ignore\u2028Ignore\u2029Ignore.py"
    unicode_file.write_text("audit = True", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(
        json.dumps(
            [
                "src",
                "tests/security_test.py",
                "~codex_review_nonexistent_user/src",
                unicode_file.name,
                "src/runtime.py",
                "Dockerfile",
                "package-lock.json",
            ],
            ensure_ascii=True,
        ),
        encoding="utf-8",
    )
    output = tmp_path / "rank_input.jsonl"

    run_cli(
        "make-repo-rank-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert [row["path"] for row in read_jsonl(output)] == sorted(
        [
            "src/runtime.py",
            "tests/security_test.py",
            "~codex_review_nonexistent_user/src/literal.py",
            unicode_file.name,
            "Dockerfile",
            "package-lock.json",
        ]
    )
    assert all(
        separator not in output.read_text(encoding="utf-8") for separator in "\u0085\u2028\u2029"
    )


def test_make_repo_scope_input_preserves_every_requested_directory_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src" / "tests").mkdir(parents=True)
    (repo / "src" / "examples").mkdir()
    (repo / "src" / "fixtures").mkdir()
    (repo / "src" / ".git").mkdir()
    (repo / "src" / "runtime.py").write_text("runtime = True", encoding="utf-8")
    (repo / "src" / "tests" / "handler.py").write_text("handler = True", encoding="utf-8")
    (repo / "src" / "examples" / "demo.py").write_text("demo = True", encoding="utf-8")
    (repo / "src" / "fixtures" / "payload.txt").write_text("payload", encoding="utf-8")
    (repo / "src" / "Dockerfile").write_text("FROM scratch", encoding="utf-8")
    (repo / "src" / ".git" / "config").write_text("private", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src", "src/runtime.py"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [
        {"path": "src/Dockerfile"},
        {"path": "src/examples/demo.py"},
        {"path": "src/fixtures/payload.txt"},
        {"path": "src/runtime.py"},
        {"path": "src/tests/handler.py"},
    ]


def test_make_repo_scope_input_rejects_paths_outside_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.py").write_text("outside = True", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["../outside.py"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    result = run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
        check=False,
    )

    assert result.returncode != 0
    assert "Scope must be inside repo" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("scope", ["src/alias.py", "alias/runtime.py", "alias/../src/runtime.py"])
def test_make_repo_scope_input_rejects_explicit_symlink_scopes(tmp_path: Path, scope: str) -> None:
    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    runtime = source / "runtime.py"
    runtime.write_text("runtime = True", encoding="utf-8")
    (source / "alias.py").symlink_to(runtime)
    (repo / "alias").symlink_to(source, target_is_directory=True)
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps([scope]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    result = run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
        check=False,
    )

    assert result.returncode != 0
    assert "must not contain symbolic links" in result.stderr
    assert not output.exists()


def test_make_repo_scope_input_preserves_tracked_ignored_and_binary_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    source = repo / "src"
    vendor = source / "vendor"
    vendor.mkdir(parents=True)
    initialize_repo(repo)
    (repo / ".gitignore").write_text("vendor/\n", encoding="utf-8")
    (source / "logo.png").write_bytes(b"\x89PNG\x00")
    (vendor / "dependency.py").write_text("dependency = True", encoding="utf-8")
    git(repo, "add", "--force", "src/logo.png", "src/vendor/dependency.py")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [
        {"path": "src/logo.png"},
        {"path": "src/vendor/dependency.py"},
    ]


def test_make_repo_scope_input_respects_ignored_directory_descendants(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src" / "node_modules").mkdir(parents=True)
    (repo / "src" / "nested").mkdir()
    (repo / ".gitignore").write_text("node_modules/\n.env\n", encoding="utf-8")
    (repo / "src" / "nested" / ".gitignore").write_text("*.generated\n", encoding="utf-8")
    (repo / "src" / "handler.py").write_text("handler = True", encoding="utf-8")
    (repo / "src" / ".env").write_text("SECRET=private", encoding="utf-8")
    (repo / "src" / "node_modules" / "dependency.js").write_text("dependency", encoding="utf-8")
    (repo / "src" / "nested" / "source.py").write_text("source = True", encoding="utf-8")
    (repo / "src" / "nested" / "output.generated").write_text("generated", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert {row["path"] for row in read_jsonl(output)} == {
        "src/handler.py",
        "src/nested/.gitignore",
        "src/nested/source.py",
    }


def test_make_repo_scope_input_keeps_explicitly_requested_ignored_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "src" / ".env").write_text("SECRET=private", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src/.env"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [{"path": "src/.env"}]


def test_make_repo_scope_input_uses_git_ignore_rules(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    initialize_repo(repo)
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "src" / "handler.py").write_text("handler = True", encoding="utf-8")
    (repo / "src" / ".env").write_text("SECRET=private", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"

    run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [{"path": "src/handler.py"}]


def test_make_repo_scope_input_falls_back_without_git_or_ripgrep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "handler.py").write_text("handler = True", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"
    monkeypatch.setenv("PATH", str(tmp_path / "missing-tools"))

    run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [{"path": "src/handler.py"}]


def test_make_repo_scope_input_fails_closed_when_ignore_rules_cannot_be_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (repo / "src" / ".env").write_text("SECRET=private", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"
    monkeypatch.setenv("PATH", str(tmp_path / "missing-tools"))

    result = run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
        check=False,
    )

    assert result.returncode != 0
    assert "without Git or ripgrep" in result.stderr
    assert not output.exists()


def test_make_repo_scope_input_fails_closed_for_git_private_excludes_without_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git" / "info").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / ".git" / "info" / "exclude").write_text(".env\n", encoding="utf-8")
    (repo / "src" / ".env").write_text("SECRET=private", encoding="utf-8")
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src"]), encoding="utf-8")
    output = tmp_path / "scoped-source-input.jsonl"
    monkeypatch.setenv("PATH", str(tmp_path / "missing-tools"))

    result = run_cli(
        "make-repo-scope-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
        check=False,
    )

    assert result.returncode != 0
    assert "without Git or ripgrep" in result.stderr
    assert not output.exists()


def test_make_repo_rank_input_keeps_explicit_binary_file_without_preview(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with (repo / "payload.bin").open("wb") as payload:
        payload.write(b"header-without-a-nul" * 4096)
        payload.truncate(256 * 1024 * 1024)
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["payload.bin"]), encoding="utf-8")
    output = tmp_path / "rank_input.jsonl"

    run_cli(
        "make-repo-rank-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [{"path": "payload.bin", "area": "payload.bin", "preview": ""}]


def test_make_repo_rank_input_bounds_explicit_source_like_binary(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)
    with (source / "payload.py").open("wb") as payload:
        payload.write(b"header-without-a-nul" * 4096)
        payload.write(b"\0binary")
        payload.truncate(256 * 1024 * 1024)
    scopes = tmp_path / "target-paths.json"
    scopes.write_text(json.dumps(["src", "src/payload.py"]), encoding="utf-8")
    output = tmp_path / "rank_input.jsonl"

    run_cli(
        "make-repo-rank-input",
        "--repo",
        str(repo),
        "--scopes-file",
        str(scopes),
        "--out",
        str(output),
    )

    assert read_jsonl(output) == [{"path": "src/payload.py", "area": "src", "preview": ""}]


@pytest.mark.parametrize("mode", ["revisions", "staged", "unstaged"])
def test_make_diff_rank_input_keeps_changed_and_deleted_text(tmp_path: Path, mode: str) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    initialize_repo(repo)
    (repo / "src" / "alpha.py").write_text("alpha = 1", encoding="utf-8")
    deleted_guard = repo / "src" / "deleted_guard.py"
    deleted_guard.write_text("guard = True", encoding="utf-8")
    deleted_entrypoint = repo / "src" / "entrypoint"
    deleted_entrypoint.write_text("exec service", encoding="utf-8")
    deleted_binary = repo / "src" / "deleted.bin"
    deleted_binary.write_bytes(b"value\x00binary")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    gitlink = git(repo, "rev-parse", "HEAD")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{gitlink},removed-module")
    git(repo, "commit", "--amend", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")

    (repo / "src" / "alpha.py").write_text("alpha = 2", encoding="utf-8")
    (repo / "src" / "beta.py").write_text("beta = 1", encoding="utf-8")
    (repo / "src" / "binary.unlisted").write_bytes(b"x" * (64 * 1024 + 1) + b"\0binary")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI", encoding="utf-8")
    (repo / ".gitmodules").write_text(
        '[submodule "added-module"]\npath = added-module\nurl = ../module.git\n',
        encoding="utf-8",
    )
    deleted_guard.unlink()
    deleted_entrypoint.unlink()
    deleted_binary.unlink()
    (repo / "README.md").write_text("ignored", encoding="utf-8")
    arguments = ["--mode", "local-patch"]
    if mode in {"revisions", "staged"}:
        git(repo, "add", ".")
    git(repo, "update-index", "--force-remove", "removed-module")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{gitlink},added-module")
    if mode == "revisions":
        git(repo, "commit", "-qm", "change")
        arguments = ["--head", git(repo, "rev-parse", "HEAD")]
        git(repo, "checkout", "-q", base)
    output = tmp_path / "diff.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(repo),
        "--base",
        base,
        *arguments,
        "--out",
        str(output),
    )

    rows = read_jsonl(output)
    assert [row["path"] for row in rows] == [
        ".github/workflows/ci.yml",
        ".gitmodules",
        "src/alpha.py",
        "src/beta.py",
        "src/deleted_guard.py",
        "src/entrypoint",
    ]
    assert [row["preview"] for row in rows[-2:]] == ["", ""]


def test_make_diff_rank_input_uses_empty_tree_for_root_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    initialize_repo(repo)
    (repo / "src" / "root.py").write_text("root = True", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "root")
    head = git(repo, "rev-parse", "HEAD")
    empty_tree = git(repo, "hash-object", "-t", "tree", "--stdin", input="")
    output = tmp_path / "root.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(repo),
        "--base",
        empty_tree,
        "--head",
        head,
        "--out",
        str(output),
    )

    assert [row["path"] for row in read_jsonl(output)] == ["src/root.py"]


def test_make_diff_rank_input_supports_shallow_tips_without_merge_base(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    initialize_repo(source)
    (source / "src" / "base.py").write_text("base = True", encoding="utf-8")
    git(source, "add", ".")
    git(source, "commit", "-qm", "base")
    git(source, "branch", "-M", "main")
    git(source, "checkout", "-qb", "feature")
    (source / "src" / "feature.py").write_text("feature = True", encoding="utf-8")
    git(source, "add", ".")
    git(source, "commit", "-qm", "feature")
    git(source, "checkout", "-q", "main")
    (source / "src" / "upstream.py").write_text("upstream = True", encoding="utf-8")
    git(source, "add", ".")
    git(source, "commit", "-qm", "upstream")

    shallow = tmp_path / "shallow"
    subprocess.run(
        [
            "git",
            "clone",
            "--no-local",
            "--depth=1",
            "--branch",
            "feature",
            str(source),
            str(shallow),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    git(shallow, "fetch", "--depth=1", "origin", "main:refs/remotes/origin/main")
    merge_base = subprocess.run(
        ["git", "-C", str(shallow), "merge-base", "origin/main", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert merge_base.returncode == 1
    output = tmp_path / "shallow.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(shallow),
        "--base",
        "origin/main",
        "--head",
        "HEAD",
        "--out",
        str(output),
    )

    assert [row["path"] for row in read_jsonl(output)] == [
        "src/feature.py",
        "src/upstream.py",
    ]


def test_make_diff_rank_input_combines_staged_and_unstaged_patch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    initialize_repo(repo)
    (repo / "src" / "alpha.py").write_text("alpha = 1", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")

    (repo / "src" / "alpha.py").write_text("alpha = 2", encoding="utf-8")
    (repo / "src" / "beta.py").write_text("beta = 1", encoding="utf-8")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yaml").write_text("name: CI", encoding="utf-8")
    git(repo, "add", "src/beta.py")
    index_only = repo / "src" / "index-only.py"
    index_only.write_text("index_only = True", encoding="utf-8")
    git(repo, "add", "src/index-only.py")
    index_only.unlink()
    nested = repo / "nested"
    nested.mkdir()
    initialize_repo(nested)
    (nested / "source.py").write_text("nested = True", encoding="utf-8")
    git(nested, "add", ".")
    git(nested, "commit", "-qm", "nested repository")
    output = tmp_path / "patch.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(repo),
        "--base",
        "HEAD",
        "--mode",
        "local-patch",
        "--out",
        str(output),
    )

    assert [row["path"] for row in read_jsonl(output)] == [
        ".github/workflows/ci.yaml",
        "src/alpha.py",
        "src/beta.py",
        "src/index-only.py",
    ]
    assert read_jsonl(output)[-1]["preview"] == ""


@pytest.mark.parametrize("mode", ["repo", "explicit-file", "revisions", "local-patch"])
def test_make_rank_input_decodes_bom_marked_utf16_source(tmp_path: Path, mode: str) -> None:
    repo = tmp_path / "repo"
    source_dir = repo / "src"
    source_dir.mkdir(parents=True)
    initialize_repo(repo)
    git(repo, "commit", "--allow-empty", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    source = "Write-Output 'café 😀'\n"
    (source_dir / "utf16-le.ps1").write_bytes(b"\xff\xfe" + source.encode("utf-16-le"))
    (source_dir / "utf16-be.ps1").write_bytes(b"\xfe\xff" + source.encode("utf-16-be"))
    (source_dir / "utf8.ps1").write_bytes(source.encode("utf-8"))
    (source_dir / "binary.ps1").write_bytes(b"text\0binary")
    (source_dir / "decoded-nul.ps1").write_bytes(b"\xff\xfe" + "text\0binary".encode("utf-16-le"))
    output = tmp_path / "rank_input.jsonl"
    expected = {
        "src/utf16-be.ps1": source.strip(),
        "src/utf16-le.ps1": source.strip(),
        "src/utf8.ps1": source.strip(),
    }

    if mode in {"repo", "explicit-file"}:
        arguments = ["make-repo-rank-input", "--repo", str(repo)]
        if mode == "explicit-file":
            expected.update({"src/binary.ps1": "", "src/decoded-nul.ps1": ""})
            scopes = tmp_path / "target-paths.json"
            scopes.write_text(json.dumps(list(expected)), encoding="utf-8")
            arguments.extend(["--scopes-file", str(scopes)])
        else:
            arguments.extend(["--scope", "src"])
    else:
        arguments = ["make-diff-rank-input", "--repo", str(repo), "--base", base, "--mode", mode]
        if mode == "revisions":
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "add encoded source")
            arguments.extend(["--head", git(repo, "rev-parse", "HEAD")])
            git(repo, "checkout", "-q", base)

    run_cli(*arguments, "--out", str(output))

    assert {row["path"]: row["preview"] for row in read_jsonl(output)} == expected
