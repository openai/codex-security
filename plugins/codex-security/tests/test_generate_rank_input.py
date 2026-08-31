from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

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
        [sys.executable, "-P", str(SCRIPT), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Codex Security scan worklist helper" in result.stdout


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{json.dumps(row, separators=(',', ':'))}\n" for row in rows),
        encoding="utf-8",
    )


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


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


def make_rank_rows(count: int) -> list[dict[str, object]]:
    return [
        {"path": f"src/file_{index:02d}.py", "area": "src", "preview": f"value = {index}"}
        for index in range(count)
    ]


def rank_result(row: dict[str, object], *, score: int = 5) -> dict[str, object]:
    return {
        "path": row["path"],
        "area": row["area"],
        "score": score,
        "include": True,
        "reason": "runtime surface",
    }


def make_shards_and_pool_plan(
    tmp_path: Path, *, shard_count: int = 5, usable_worker_slots: int = 2
) -> tuple[Path, Path, Path]:
    rank_input = tmp_path / "rank_input.jsonl"
    write_jsonl(rank_input, make_rank_rows(shard_count))
    shard_dir = tmp_path / "rank_shards"
    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--max-rows",
        "1",
        "--out-dir",
        str(shard_dir),
    )
    plan = tmp_path / "rank_worker_assignments.json"
    run_cli(
        "make-rank-pool-plan",
        "--shard-dir",
        str(shard_dir),
        "--usable-worker-slots",
        str(usable_worker_slots),
        "--out",
        str(plan),
    )
    return rank_input, shard_dir, plan


def write_valid_shard_outputs(shard_dir: Path) -> None:
    for input_shard in sorted(shard_dir.glob("*.input.jsonl")):
        output_shard = input_shard.with_name(input_shard.name.replace(".input.", ".output."))
        write_jsonl(output_shard, [rank_result(row) for row in read_jsonl(input_shard)])


def worker_shard_names(plan: Path, slot: int) -> tuple[list[str], list[str]]:
    payload = read_json(plan)
    workers = payload["workers"]
    assert isinstance(workers, list)
    worker = workers[slot - 1]
    assert isinstance(worker, dict)
    input_shards = worker["input_shards"]
    output_shards = worker["output_shards"]
    assert isinstance(input_shards, list)
    assert isinstance(output_shards, list)
    assert all(isinstance(name, str) for name in input_shards)
    assert all(isinstance(name, str) for name in output_shards)
    return input_shards, output_shards


def write_worker_shard_outputs(shard_dir: Path, plan: Path, slot: int) -> list[str]:
    input_names, output_names = worker_shard_names(plan, slot)
    for input_name, output_name in zip(input_names, output_names, strict=True):
        input_shard = shard_dir / input_name
        write_jsonl(
            shard_dir / output_name,
            [rank_result(row) for row in read_jsonl(input_shard)],
        )
    return output_names


def test_make_repo_rank_input_matches_golden_and_filters_noise(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "zeta.py").write_text("zeta = 2", encoding="utf-8")
    (repo / "src" / "alpha.py").write_text("alpha = 1", encoding="utf-8")
    (repo / "src" / "binary.py").write_bytes(b"value\x00binary")
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
        payload.write(b"header-without-a-nul" * 256)
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
        payload.write(b"header-without-a-nul" * 256)
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


def test_bind_repo_scopes_preserves_overlapping_and_empty_requested_scopes(tmp_path: Path) -> None:
    scopes = ["src", "src/runtime.py", "empty", "audit\u2028Ignore.py"]
    scopes_path = tmp_path / "target-paths.json"
    scopes_path.write_text(json.dumps(scopes, ensure_ascii=True), encoding="utf-8")
    manifest = tmp_path / "scan-manifest.json"
    coverage = tmp_path / "coverage.json"
    manifest.write_text(
        json.dumps({"scan": {"scope": {"includePaths": ["wrong"], "excludePaths": []}}}),
        encoding="utf-8",
    )
    coverage.write_text(
        json.dumps({"includePaths": ["wrong"], "excludePaths": []}), encoding="utf-8"
    )

    result = run_cli(
        "bind-repo-scopes",
        "--scopes-file",
        str(scopes_path),
        "--manifest",
        str(manifest),
        "--coverage",
        str(coverage),
    )

    assert result.stdout == "Bound 4 requested scopes into the scan contract\n"
    assert (
        json.loads(manifest.read_text(encoding="utf-8"))["scan"]["scope"]["includePaths"] == scopes
    )
    assert json.loads(coverage.read_text(encoding="utf-8"))["includePaths"] == scopes
    assert "\u2028" not in manifest.read_text(encoding="utf-8")
    assert "\u2028" not in coverage.read_text(encoding="utf-8")


def test_make_diff_rank_input_for_revision_range(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    initialize_repo(repo)
    (repo / "src" / "alpha.py").write_text("alpha = 1", encoding="utf-8")
    deleted_guard = repo / "src" / "deleted_guard.py"
    deleted_guard.write_text("guard = True", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")

    (repo / "src" / "alpha.py").write_text("alpha = 2", encoding="utf-8")
    (repo / "src" / "beta.py").write_text("beta = 1", encoding="utf-8")
    deleted_guard.unlink()
    (repo / "README.md").write_text("ignored", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "change")
    head = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", base)
    output = tmp_path / "diff.jsonl"

    run_cli(
        "make-diff-rank-input",
        "--repo",
        str(repo),
        "--base",
        base,
        "--head",
        head,
        "--out",
        str(output),
    )

    rows = read_jsonl(output)
    assert [row["path"] for row in rows] == [
        "src/alpha.py",
        "src/beta.py",
        "src/deleted_guard.py",
    ]
    assert rows[-1]["preview"] == ""


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
    git(repo, "add", "src/beta.py")
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

    assert [row["path"] for row in read_jsonl(output)] == ["src/alpha.py", "src/beta.py"]


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


def test_copy_and_select_deep_review_inputs(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    write_jsonl(
        rank_input,
        [
            {"path": "a.py", "area": "core", "preview": "a"},
            {"path": "b.py", "area": "api", "preview": "b"},
        ],
    )
    copied = tmp_path / "copied.jsonl"
    run_cli(
        "copy-deep-review-input",
        "--rank-input",
        str(rank_input),
        "--out",
        str(copied),
    )
    assert read_jsonl(copied) == [
        {"path": "a.py", "area": "core"},
        {"path": "b.py", "area": "api"},
    ]

    rank_output = tmp_path / "rank_output.jsonl"
    write_jsonl(
        rank_output,
        [
            {"path": "c.py", "area": "api", "score": 8, "include": True, "reason": "c"},
            {"path": "a.py", "area": "core", "score": 10, "include": True, "reason": "a"},
            {"path": "b.py", "area": "api", "score": 8, "include": True, "reason": "b"},
            {"path": "d.py", "area": "core", "score": 2, "include": False, "reason": "d"},
        ],
    )
    selected = tmp_path / "selected.jsonl"
    run_cli(
        "select-deep-review-input",
        "--rank-output",
        str(rank_output),
        "--top-percent",
        "67",
        "--out",
        str(selected),
    )
    assert read_jsonl(selected) == [
        {"path": "a.py", "area": "core"},
        {"path": "b.py", "area": "api"},
    ]


def test_select_honors_explicit_top_percent_20(tmp_path: Path) -> None:
    rank_output = tmp_path / "rank_output.jsonl"
    rows = make_rank_rows(5)
    write_jsonl(
        rank_output,
        [rank_result(row, score=10 - index) for index, row in enumerate(rows)],
    )
    selected = tmp_path / "selected.jsonl"

    run_cli(
        "select-deep-review-input",
        "--rank-output",
        str(rank_output),
        "--top-percent",
        "20",
        "--out",
        str(selected),
    )

    assert read_jsonl(selected) == [{"path": "src/file_00.py", "area": "src"}]


def test_select_defaults_to_top_percent_100(tmp_path: Path) -> None:
    rank_output = tmp_path / "rank_output.jsonl"
    rows = make_rank_rows(5)
    write_jsonl(
        rank_output,
        [rank_result(row, score=10 - index) for index, row in enumerate(rows)],
    )
    selected = tmp_path / "selected.jsonl"

    run_cli(
        "select-deep-review-input",
        "--rank-output",
        str(rank_output),
        "--out",
        str(selected),
    )

    assert len(read_jsonl(selected)) == 5


def test_select_falls_back_to_all_rows_when_workers_exclude_everything(tmp_path: Path) -> None:
    rank_output = tmp_path / "rank_output.jsonl"
    write_jsonl(
        rank_output,
        [
            {"path": "b.py", "area": "api", "score": 2, "include": False, "reason": "b"},
            {"path": "a.py", "area": "core", "score": 9, "include": False, "reason": "a"},
        ],
    )
    selected = tmp_path / "selected.jsonl"

    run_cli(
        "select-deep-review-input",
        "--rank-output",
        str(rank_output),
        "--out",
        str(selected),
    )

    assert read_jsonl(selected) == [
        {"path": "a.py", "area": "core"},
        {"path": "b.py", "area": "api"},
    ]


def test_make_rank_shards_is_deterministic_and_bounded(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    rows = make_rank_rows(312)
    write_jsonl(rank_input, rows)
    shard_dir = tmp_path / "shards"

    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--out-dir",
        str(shard_dir),
    )

    shards = sorted(shard_dir.glob("*.input.jsonl"))
    assert [path.name for path in shards] == [
        "rank-shard-0001.input.jsonl",
        "rank-shard-0002.input.jsonl",
        "rank-shard-0003.input.jsonl",
    ]
    assert [len(read_jsonl(path)) for path in shards] == [150, 150, 12]
    assert [row for path in shards for row in read_jsonl(path)] == rows

    result = run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--out-dir",
        str(shard_dir),
        check=False,
    )
    assert result.returncode != 0
    assert "already contains shard files" in result.stderr


def test_make_rank_pool_plan_is_deterministic_round_robin_and_exact_once(
    tmp_path: Path,
) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    second_plan = tmp_path / "second_rank_worker_assignments.json"

    run_cli(
        "make-rank-pool-plan",
        "--shard-dir",
        str(shard_dir),
        "--usable-worker-slots",
        "2",
        "--out",
        str(second_plan),
    )

    assert plan.read_bytes() == second_plan.read_bytes()
    assert read_json(plan) == {
        "schema_version": 1,
        "strategy": "round_robin",
        "shard_count": 5,
        "ranking_worker_count": 2,
        "workers": [
            {
                "slot": 1,
                "input_shards": [
                    "rank-shard-0001.input.jsonl",
                    "rank-shard-0003.input.jsonl",
                    "rank-shard-0005.input.jsonl",
                ],
                "output_shards": [
                    "rank-shard-0001.output.jsonl",
                    "rank-shard-0003.output.jsonl",
                    "rank-shard-0005.output.jsonl",
                ],
            },
            {
                "slot": 2,
                "input_shards": [
                    "rank-shard-0002.input.jsonl",
                    "rank-shard-0004.input.jsonl",
                ],
                "output_shards": [
                    "rank-shard-0002.output.jsonl",
                    "rank-shard-0004.output.jsonl",
                ],
            },
        ],
    }


def test_make_rank_pool_plan_caps_workers_at_shard_count(tmp_path: Path) -> None:
    _, _, plan = make_shards_and_pool_plan(tmp_path, shard_count=2, usable_worker_slots=8)

    payload = read_json(plan)
    assert payload["shard_count"] == 2
    assert payload["ranking_worker_count"] == 2
    assert len(payload["workers"]) == 2


def test_make_rank_pool_plan_caps_workers_at_six(tmp_path: Path) -> None:
    _, _, plan = make_shards_and_pool_plan(tmp_path, shard_count=8, usable_worker_slots=12)

    payload = read_json(plan)
    assert payload["shard_count"] == 8
    assert payload["ranking_worker_count"] == 6
    workers = payload["workers"]
    assert isinstance(workers, list)
    assert len(workers) == 6
    assert worker_shard_names(plan, 1)[0] == [
        "rank-shard-0001.input.jsonl",
        "rank-shard-0007.input.jsonl",
    ]
    assert worker_shard_names(plan, 2)[0] == [
        "rank-shard-0002.input.jsonl",
        "rank-shard-0008.input.jsonl",
    ]


def test_empty_rank_input_closes_with_zero_shards_and_workers(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    write_jsonl(rank_input, [])
    shard_dir = tmp_path / "rank_shards"

    shards_result = run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--out-dir",
        str(shard_dir),
    )
    assert shards_result.stdout == f"Wrote 0 rank shards to {shard_dir}\n"

    plan = tmp_path / "rank_worker_assignments.json"
    plan_result = run_cli(
        "make-rank-pool-plan",
        "--shard-dir",
        str(shard_dir),
        "--usable-worker-slots",
        "6",
        "--out",
        str(plan),
    )
    assert plan_result.stdout == f"Assigned 0 rank shards to 0 ranking workers in {plan}\n"
    assert read_json(plan) == {
        "schema_version": 1,
        "strategy": "round_robin",
        "shard_count": 0,
        "ranking_worker_count": 0,
        "workers": [],
    }

    pool_result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
    )
    assert pool_result.stdout == "Validated 0 ranking workers, 0 shards, and 0 ranking rows\n"

    rank_output = tmp_path / "rank_output.jsonl"
    merge_result = run_cli(
        "merge-rank-outputs",
        "--rank-input",
        str(rank_input),
        "--shard-dir",
        str(shard_dir),
        "--out",
        str(rank_output),
    )
    assert merge_result.stdout == f"Merged 0 ranking rows into {rank_output}\n"
    assert rank_output.read_bytes() == b""

    deep_review_input = tmp_path / "deep_review_input.jsonl"
    run_cli(
        "select-deep-review-input",
        "--rank-output",
        str(rank_output),
        "--out",
        str(deep_review_input),
    )
    assert deep_review_input.read_bytes() == b""


def test_make_rank_pool_plan_requires_sibling_rank_shards_directory(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    write_jsonl(rank_input, make_rank_rows(2))
    shard_dir = tmp_path / "other_shards"
    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--max-rows",
        "1",
        "--out-dir",
        str(shard_dir),
    )
    plan = tmp_path / "rank_worker_assignments.json"

    result = run_cli(
        "make-rank-pool-plan",
        "--shard-dir",
        str(shard_dir),
        "--usable-worker-slots",
        "2",
        "--out",
        str(plan),
        check=False,
    )

    assert result.returncode != 0
    assert "must be the assignment plan's sibling rank_shards directory" in result.stderr


def test_validate_rank_pool_requires_sibling_rank_shards_directory(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    other_shard_dir = tmp_path / "other_shards"
    shard_dir.rename(other_shard_dir)

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(other_shard_dir),
        check=False,
    )

    assert result.returncode != 0
    assert "must be the assignment plan's sibling rank_shards directory" in result.stderr


@pytest.mark.parametrize(
    "misplaced_name",
    [
        "rank-shard-0001.input.jsonl",
        "rank-shard-0001.output.jsonl",
    ],
)
def test_validate_rank_pool_rejects_shards_beside_assignment_plan(
    tmp_path: Path, misplaced_name: str
) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    write_valid_shard_outputs(shard_dir)
    (tmp_path / misplaced_name).write_text("{}\n", encoding="utf-8")

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )

    assert result.returncode != 0
    assert "must be stored in the assignment plan's sibling rank_shards directory" in result.stderr
    assert f"misplaced=['{misplaced_name}']" in result.stderr


def test_make_rank_pool_plan_rejects_invalid_slots_and_shard_names(tmp_path: Path) -> None:
    _, shard_dir, _ = make_shards_and_pool_plan(tmp_path)

    result = run_cli(
        "make-rank-pool-plan",
        "--shard-dir",
        str(shard_dir),
        "--usable-worker-slots",
        "0",
        "--out",
        str(tmp_path / "invalid.json"),
        check=False,
    )
    assert result.returncode != 0
    assert "--usable-worker-slots must be at least 1" in result.stderr

    (shard_dir / "rank-shard-0005.input.jsonl").rename(shard_dir / "rank-shard-0006.input.jsonl")
    result = run_cli(
        "make-rank-pool-plan",
        "--shard-dir",
        str(shard_dir),
        "--usable-worker-slots",
        "2",
        "--out",
        str(tmp_path / "invalid.json"),
        check=False,
    )
    assert result.returncode != 0
    assert "contiguous canonical names" in result.stderr


def test_validate_rank_pool_rejects_malformed_and_tampered_plan(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    original_plan = read_json(plan)

    plan.write_text("{not json}\n", encoding="utf-8")
    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )
    assert result.returncode != 0
    assert "invalid JSON" in result.stderr

    workers = original_plan["workers"]
    assert isinstance(workers, list)
    first_worker = workers[0]
    assert isinstance(first_worker, dict)
    input_shards = first_worker["input_shards"]
    output_shards = first_worker["output_shards"]
    assert isinstance(input_shards, list)
    assert isinstance(output_shards, list)
    input_shards[1] = input_shards[0]
    output_shards[1] = output_shards[0]
    plan.write_text(json.dumps(original_plan) + "\n", encoding="utf-8")

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )
    assert result.returncode != 0
    assert "assign each input shard exactly once" in result.stderr
    assert "duplicates=['rank-shard-0001.input.jsonl']" in result.stderr


def test_validate_rank_worker_emits_content_bound_receipt_for_only_its_slot(
    tmp_path: Path,
) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    output_names = write_worker_shard_outputs(shard_dir, plan, slot=1)

    result = run_cli(
        "validate-rank-worker",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        "--slot",
        "1",
    )

    outputs_digest = hashlib.sha256()
    for output_name in output_names:
        outputs_digest.update(output_name.encode("utf-8"))
        outputs_digest.update(b"\0")
        outputs_digest.update((shard_dir / output_name).read_bytes())
        outputs_digest.update(b"\0")
    expected = {
        "schema_version": 1,
        "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        "slot": 1,
        "ranking_worker_count": 2,
        "output_shards": 3,
        "rows": 3,
        "outputs_sha256": outputs_digest.hexdigest(),
        "status": "complete",
    }
    expected_line = "RANK_WORKER_RECEIPT " + json.dumps(
        expected, sort_keys=True, separators=(",", ":")
    )
    assert result.stdout == expected_line + "\n"
    assert result.stderr == ""
    assert not (shard_dir / "rank-shard-0002.output.jsonl").exists()
    assert not (shard_dir / "rank-shard-0004.output.jsonl").exists()


def test_validate_rank_worker_rejects_missing_assigned_output(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    output_names = write_worker_shard_outputs(shard_dir, plan, slot=1)
    missing_output = shard_dir / output_names[1]
    missing_output.unlink()

    result = run_cli(
        "validate-rank-worker",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        "--slot",
        "1",
        check=False,
    )

    assert result.returncode != 0
    assert f"Rank output shard missing: {missing_output}" in result.stderr
    assert result.stdout == ""


def test_validate_rank_worker_rejects_invalid_assigned_output(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    output_names = write_worker_shard_outputs(shard_dir, plan, slot=2)
    invalid_output = shard_dir / output_names[0]
    invalid_output.write_text("{not json}\n", encoding="utf-8")

    result = run_cli(
        "validate-rank-worker",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        "--slot",
        "2",
        check=False,
    )

    assert result.returncode != 0
    assert f"{invalid_output}:1: invalid JSON" in result.stderr
    assert result.stdout == ""


def test_validate_rank_worker_reuses_strict_plan_and_path_validation(tmp_path: Path) -> None:
    _, _, plan = make_shards_and_pool_plan(tmp_path)
    other_shard_dir = tmp_path / "other_shards"
    other_shard_dir.mkdir()

    result = run_cli(
        "validate-rank-worker",
        "--plan",
        str(plan),
        "--shard-dir",
        str(other_shard_dir),
        "--slot",
        "1",
        check=False,
    )

    assert result.returncode != 0
    assert "must be the assignment plan's sibling rank_shards directory" in result.stderr


def test_validate_rank_pool_accepts_complete_multi_shard_workers(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    write_valid_shard_outputs(shard_dir)

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
    )

    assert "Validated 2 ranking workers, 5 shards, and 5 ranking rows" in result.stdout


def test_rank_pool_accepts_parent_completion_for_an_unstarted_worker_slot(
    tmp_path: Path,
) -> None:
    rank_input, shard_dir, plan = make_shards_and_pool_plan(
        tmp_path, shard_count=5, usable_worker_slots=2
    )
    write_worker_shard_outputs(shard_dir, plan, slot=1)
    write_worker_shard_outputs(shard_dir, plan, slot=2)

    for slot in (1, 2):
        receipt = run_cli(
            "validate-rank-worker",
            "--plan",
            str(plan),
            "--shard-dir",
            str(shard_dir),
            "--slot",
            str(slot),
        )
        assert receipt.stdout.startswith("RANK_WORKER_RECEIPT ")

    pool = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
    )
    rank_output = tmp_path / "rank_output.jsonl"
    run_cli(
        "merge-rank-outputs",
        "--rank-input",
        str(rank_input),
        "--shard-dir",
        str(shard_dir),
        "--out",
        str(rank_output),
    )

    assert "Validated 2 ranking workers, 5 shards, and 5 ranking rows" in pool.stdout
    assert [row["path"] for row in read_jsonl(rank_output)] == [
        row["path"] for row in read_jsonl(rank_input)
    ]


def test_validate_rank_pool_rejects_missing_and_unexpected_outputs(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    write_valid_shard_outputs(shard_dir)
    missing_output = shard_dir / "rank-shard-0005.output.jsonl"
    missing_output.unlink()

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )
    assert result.returncode != 0
    assert "missing output shards=['rank-shard-0005.output.jsonl']" in result.stderr

    input_row = read_jsonl(shard_dir / "rank-shard-0005.input.jsonl")[0]
    write_jsonl(missing_output, [rank_result(input_row)])
    write_jsonl(
        shard_dir / "rank-shard-9999.output.jsonl",
        [rank_result(input_row)],
    )
    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )
    assert result.returncode != 0
    assert "unexpected output shards=['rank-shard-9999.output.jsonl']" in result.stderr


def test_validate_rank_pool_rejects_one_bad_shard_from_multi_shard_worker(
    tmp_path: Path,
) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    write_valid_shard_outputs(shard_dir)
    bad_output = shard_dir / "rank-shard-0003.output.jsonl"
    bad_output.write_text("{not json}\n", encoding="utf-8")

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )

    assert result.returncode != 0
    assert "rank-shard-0003.output.jsonl:1: invalid JSON" in result.stderr


def test_validate_rank_pool_rejects_duplicate_output_rows(tmp_path: Path) -> None:
    _, shard_dir, plan = make_shards_and_pool_plan(tmp_path)
    write_valid_shard_outputs(shard_dir)
    output = shard_dir / "rank-shard-0003.output.jsonl"
    row = read_jsonl(output)[0]
    write_jsonl(output, [row, row])

    result = run_cli(
        "validate-rank-pool",
        "--plan",
        str(plan),
        "--shard-dir",
        str(shard_dir),
        check=False,
    )

    assert result.returncode != 0
    assert "contains duplicate paths" in result.stderr


def test_validate_rank_shard_validates_one_pool_output(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    write_jsonl(rank_input, make_rank_rows(7))
    shard_dir = tmp_path / "shards"
    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--max-rows",
        "5",
        "--out-dir",
        str(shard_dir),
    )
    first_input = shard_dir / "rank-shard-0001.input.jsonl"
    first_output = shard_dir / "rank-shard-0001.output.jsonl"
    write_jsonl(first_output, [rank_result(row) for row in read_jsonl(first_input)])

    result = run_cli(
        "validate-rank-shard",
        "--input",
        str(first_input),
        "--output",
        str(first_output),
    )

    assert "Validated 5 ranking rows" in result.stdout
    assert not (shard_dir / "rank-shard-0002.output.jsonl").exists()


def test_merge_rank_outputs_validates_and_restores_authoritative_order(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    rows = make_rank_rows(7)
    write_jsonl(rank_input, rows)
    shard_dir = tmp_path / "shards"
    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--max-rows",
        "5",
        "--out-dir",
        str(shard_dir),
    )
    for input_shard in sorted(shard_dir.glob("*.input.jsonl")):
        output_shard = input_shard.with_name(input_shard.name.replace(".input.", ".output."))
        shard_rows = read_jsonl(input_shard)
        write_jsonl(output_shard, [rank_result(row) for row in reversed(shard_rows)])

    output = tmp_path / "rank_output.jsonl"
    run_cli(
        "merge-rank-outputs",
        "--rank-input",
        str(rank_input),
        "--shard-dir",
        str(shard_dir),
        "--out",
        str(output),
    )

    assert [row["path"] for row in read_jsonl(output)] == [row["path"] for row in rows]


@pytest.mark.parametrize(
    ("output_text", "expected_error"),
    [
        ("{not json}\n", "invalid JSON"),
        (
            '{"path":"a.py","area":"core","score":10,"include":true}\n',
            "missing fields ['reason']",
        ),
        (
            '{"path":"a.py","area":"core","score":true,"include":true,"reason":"x"}\n',
            "score must be an integer",
        ),
        (
            '{"path":"a.py","area":"core","score":11,"include":true,"reason":"x"}\n',
            "score must be from 1 through 10",
        ),
        (
            '{"path":"a.py","area":"core","score":10,"include":"true","reason":"x"}\n',
            "include must be a boolean",
        ),
        (
            '{"path":"a.py","area":"core","score":10,"include":true,"reason":""}\n',
            "reason must be a non-empty string",
        ),
        (
            '{"path":"b.py","area":"core","score":10,"include":true,"reason":"x"}\n',
            "paths do not match its input shard",
        ),
        (
            "",
            "paths do not match its input shard",
        ),
    ],
)
def test_merge_rank_outputs_rejects_invalid_worker_results(
    tmp_path: Path, output_text: str, expected_error: str
) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    write_jsonl(rank_input, [{"path": "a.py", "area": "core", "preview": "a"}])
    shard_dir = tmp_path / "shards"
    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--out-dir",
        str(shard_dir),
    )
    (shard_dir / "rank-shard-0001.output.jsonl").write_text(output_text, encoding="utf-8")

    result = run_cli(
        "merge-rank-outputs",
        "--rank-input",
        str(rank_input),
        "--shard-dir",
        str(shard_dir),
        "--out",
        str(tmp_path / "rank_output.jsonl"),
        check=False,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr


def test_merge_rank_outputs_rejects_missing_and_duplicate_results(tmp_path: Path) -> None:
    rank_input = tmp_path / "rank_input.jsonl"
    rows = [{"path": "a.py", "area": "core", "preview": "a"}]
    write_jsonl(rank_input, rows)
    shard_dir = tmp_path / "shards"
    run_cli(
        "make-rank-shards",
        "--rank-input",
        str(rank_input),
        "--out-dir",
        str(shard_dir),
    )

    result = run_cli(
        "merge-rank-outputs",
        "--rank-input",
        str(rank_input),
        "--shard-dir",
        str(shard_dir),
        "--out",
        str(tmp_path / "rank_output.jsonl"),
        check=False,
    )
    assert "missing output shards" in result.stderr

    output_shard = shard_dir / "rank-shard-0001.output.jsonl"
    duplicate = rank_result(rows[0])
    write_jsonl(output_shard, [duplicate, duplicate])
    result = run_cli(
        "merge-rank-outputs",
        "--rank-input",
        str(rank_input),
        "--shard-dir",
        str(shard_dir),
        "--out",
        str(tmp_path / "rank_output.jsonl"),
        check=False,
    )
    assert "duplicate paths" in result.stderr
