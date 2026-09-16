#!/usr/bin/env python3
"""Generate and post-process Codex Security scan worklists.

This script stays deliberately model-free:

- `make-repo-rank-input` creates the deterministic repository or scoped-path
  JSONL candidate worklist that ranking subagents consume.
- `make-diff-rank-input` creates the deterministic diff-scoped JSONL candidate
  worklist from Git changed paths. It supports committed revision diffs and
  local working-tree patches.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rank_preview import (
    DEFAULT_PREVIEW_BYTES,
    TEXT_CODE_EXTENSIONS,
    preview_for,
    preview_for_bytes,
)
from workbench_target import git_blob_bytes, git_directory_snapshot_paths

EXCLUDED_DIRS = {
    ".cache",
    ".circleci",
    ".devcontainer",
    ".git",
    ".github",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "bench",
    "benchmark",
    "bintest",
    "build",
    "build_config",
    "build_configs",
    "build-tools",
    "build_tools",
    "ci",
    "coverage",
    "deps",
    "dev",
    "dist",
    "doc",
    "docs",
    "example",
    "examples",
    "external",
    "extern",
    "fixture",
    "fixtures",
    "generated",
    "node_modules",
    "sample",
    "samples",
    "target",
    "test",
    "tests",
    "testing",
    "third-party",
    "third_party",
    "tmp",
    "vendor",
}

EXCLUDED_FILENAMES = {
    ".DS_Store",
    "CHANGELOG",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "Dockerfile",
    "Gemfile",
    "Gemfile.lock",
    "LICENSE",
    "LICENSE.md",
    "Makefile",
    "NEWS",
    "NEWS.md",
    "NOTICE",
    "README",
    "README.md",
    "README.rst",
    "Rakefile",
    "SECURITY.md",
    "TODO",
    "TODO.md",
    "docker-compose.yml",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}

DIRECT_SCOPE_PREVIEW_READ_BYTES = 64 * 1024
JsonRow = dict[str, object]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Codex Security scan worklist helper.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    make = subparsers.add_parser(
        "make-repo-rank-input",
        help="Create rank_input.jsonl for subagent-based file ranking.",
    )
    make.add_argument("--repo", required=True, help="Repository root.")
    make.add_argument(
        "--scope",
        default=".",
        help="Path within the repository to scan. Defaults to the repository root.",
    )
    make.add_argument(
        "--scopes-file",
        help="JSON array of repository-relative files and directories to scan together.",
    )
    make.add_argument("--out", required=True, help="Output rank_input.jsonl path.")
    make.add_argument("--area", default="", help="Area label. Defaults to scope.")
    make.add_argument(
        "--preview-bytes",
        type=int,
        default=DEFAULT_PREVIEW_BYTES,
        help=f"Maximum UTF-8 bytes in each preview. Defaults to {DEFAULT_PREVIEW_BYTES}.",
    )

    scoped = subparsers.add_parser(
        "make-repo-scope-input",
        help="List every explicitly scoped file without ranking or reading its contents.",
    )
    scoped.add_argument("--repo", required=True, help="Repository root.")
    scoped.add_argument(
        "--scopes-file",
        required=True,
        help="JSON array of repository-relative files and directories to scan together.",
    )
    scoped.add_argument("--out", required=True, help="Output scoped-source-input.jsonl path.")

    bind = subparsers.add_parser(
        "bind-repo-scopes",
        help="Copy SDK scoped-path targets into the unsealed manifest and coverage documents.",
    )
    bind.add_argument("--scopes-file", required=True, help="JSON array of requested scopes.")
    bind.add_argument("--manifest", required=True, help="Unsealed scan-manifest.json path.")
    bind.add_argument("--coverage", required=True, help="Unsealed coverage.json path.")

    diff = subparsers.add_parser(
        "make-diff-rank-input",
        help="Create rank_input.jsonl from Git changed source-like files.",
    )
    diff.add_argument("--repo", required=True, help="Repository root.")
    diff.add_argument("--base", required=True, help="Git diff base revision.")
    diff.add_argument(
        "--mode",
        choices=("revisions", "local-patch"),
        default="revisions",
        help="Git diff mode: committed revisions or staged plus unstaged local patch.",
    )
    diff.add_argument("--head", default="HEAD", help="Git diff head revision.")
    diff.add_argument("--out", required=True, help="Output rank_input.jsonl path.")
    diff.add_argument("--area", default="diff", help="Area label for ranking rows.")
    diff.add_argument(
        "--preview-bytes",
        type=int,
        default=DEFAULT_PREVIEW_BYTES,
        help=f"Maximum UTF-8 bytes in each preview. Defaults to {DEFAULT_PREVIEW_BYTES}.",
    )

    return parser.parse_args()


def path_is_excluded(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return True
    if path.name in EXCLUDED_FILENAMES:
        return True
    return path.name.endswith((".min.js", ".map"))


def path_is_diff_excluded(path: Path) -> bool:
    """Apply repository exclusions while retaining changed workflow files."""
    if path.parts[:2] == (".github", "workflows"):
        return False
    return path_is_excluded(path)


def windows_stream_component(path: Path) -> str | None:
    """Return the first NTFS alternate-data-stream component."""

    if os.name != "nt":
        return None
    return next(
        (component for component in path.parts if component != path.anchor and ":" in component),
        None,
    )


def resolve_scope(
    repo: Path,
    scope: str,
    *,
    expand_user: bool = True,
    reject_symlinks: bool = False,
) -> Path:
    scope_path = Path(scope).expanduser() if expand_user else Path(scope)
    stream = windows_stream_component(scope_path)
    if stream is not None:
        raise SystemExit(f"Scope must not use an NTFS alternate data stream: {stream}")
    if not scope_path.is_absolute():
        scope_path = repo / scope_path
    if reject_symlinks:
        repository = repo.resolve()
        try:
            relative = scope_path.relative_to(repository)
        except ValueError as exc:
            raise SystemExit(f"Scope must be inside repo: {scope_path}") from exc
        ancestor = repository
        for part in relative.parts:
            if part == "..":
                if ancestor == repository:
                    raise SystemExit(f"Scope must be inside repo: {scope_path}")
                ancestor = ancestor.parent
                continue
            ancestor /= part
            try:
                metadata = ancestor.stat(follow_symlinks=False)
            except OSError as exc:
                raise SystemExit(f"Scope path not found: {ancestor}") from exc
            if ancestor.is_symlink() or getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
                raise SystemExit(f"Requested scope must not contain symbolic links: {ancestor}")
    scope_path = scope_path.resolve()
    repo_resolved = repo.resolve()
    try:
        scope_path.relative_to(repo_resolved)
    except ValueError as exc:
        raise SystemExit(f"Scope must be inside repo: {scope_path}") from exc
    if not scope_path.is_dir() and not scope_path.is_file():
        raise SystemExit(f"Scope path not found: {scope_path}")
    return scope_path


def write_jsonl(output: Path, rows: list[JsonRow]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")))
            handle.write("\n")


def load_scopes_file(scopes_file: Path) -> list[str]:
    try:
        loaded: object = json.loads(scopes_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Unable to read scopes file: {scopes_file}") from exc
    if (
        not isinstance(loaded, list)
        or not loaded
        or any(not isinstance(scope, str) or not scope for scope in loaded)
    ):
        raise SystemExit(f"Scopes file must contain a non-empty JSON string array: {scopes_file}")
    return loaded


def make_repo_rank_input(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")
    scopes = [args.scope]
    explicit_scopes = args.scopes_file is not None
    if explicit_scopes:
        scopes = load_scopes_file(Path(args.scopes_file).expanduser())

    resolved_scopes = [
        resolve_scope(repo, scope, expand_user=not explicit_scopes) for scope in scopes
    ]
    directly_requested_files = {
        scope_abs for scope_abs in resolved_scopes if explicit_scopes and scope_abs.is_file()
    }
    rows_by_path: dict[str, JsonRow] = {}
    for scope_abs in resolved_scopes:
        scope_rel = scope_abs.relative_to(repo)
        area = args.area or scope_rel.as_posix()
        candidates = (scope_abs,) if scope_abs.is_file() else scope_abs.rglob("*")
        for path in candidates:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                path.resolve(strict=True).relative_to(repo)
            except (OSError, ValueError):
                continue
            rel = path.relative_to(repo)
            directly_requested = path in directly_requested_files
            excluded_path = (
                path.relative_to(scope_abs if scope_abs.is_dir() else scope_abs.parent)
                if explicit_scopes
                else rel
            )
            if not directly_requested and (
                path_is_excluded(excluded_path) or path.suffix.lower() not in TEXT_CODE_EXTENSIONS
            ):
                continue

            if (
                directly_requested
                and path.suffix.lower() not in TEXT_CODE_EXTENSIONS
                and path.name not in EXCLUDED_FILENAMES
            ):
                preview = ""
            else:
                preview, is_binary = preview_for(
                    path,
                    args.preview_bytes,
                    max_read_bytes=DIRECT_SCOPE_PREVIEW_READ_BYTES if directly_requested else None,
                )
                if is_binary and not directly_requested:
                    continue
            rows_by_path.setdefault(
                rel.as_posix(),
                {"path": rel.as_posix(), "area": area, "preview": preview},
            )

    rows = sorted(rows_by_path.values(), key=lambda row: str(row["path"]))
    output = Path(args.out).expanduser()
    write_jsonl(output, rows)
    print(f"Wrote {len(rows)} rows to {output}")


def make_repo_scope_input(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")

    scopes = load_scopes_file(Path(args.scopes_file).expanduser())
    rows_by_path: dict[str, JsonRow] = {}
    for scope in scopes:
        scope_path = resolve_scope(repo, scope, expand_user=False, reject_symlinks=True)
        if scope_path.is_file():
            candidates = (scope_path,)
        else:
            git_candidates = git_directory_snapshot_paths(scope_path)
            if git_candidates is not None:
                candidates = git_candidates
            else:
                command = [
                    "rg",
                    "--files",
                    "--hidden",
                    "--no-require-git",
                    "--null",
                    "--glob",
                    "!.git/**",
                    "--",
                    str(scope_path.relative_to(repo)),
                ]
                try:
                    result = subprocess.run(command, cwd=repo, capture_output=True, check=False)
                except OSError as exc:
                    ignore_names = (".gitignore", ".ignore", ".rgignore")
                    ancestors = (scope_path, *scope_path.parents)
                    has_ignore_rules = (
                        any((ancestor / ".git").exists() for ancestor in (repo, *repo.parents))
                        or any(
                            (ancestor / name).is_file()
                            for ancestor in ancestors
                            if ancestor == repo or repo in ancestor.parents
                            for name in ignore_names
                        )
                        or any(
                            path.name in ignore_names
                            for path in scope_path.rglob("*")
                            if path.is_file()
                        )
                    )
                    if has_ignore_rules:
                        raise SystemExit(
                            "Could not safely enumerate ignored scoped files without Git or ripgrep."
                        ) from exc
                    candidates = scope_path.rglob("*")
                else:
                    if result.returncode not in (0, 1):
                        detail = result.stderr.decode("utf-8", errors="replace").strip()
                        raise SystemExit(f"Could not enumerate scoped repository files: {detail}")
                    candidates = (
                        repo / os.fsdecode(path) for path in result.stdout.split(b"\0") if path
                    )
        for path in candidates:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                relative = path.resolve(strict=True).relative_to(repo)
            except (OSError, ValueError):
                continue
            if ".git" in relative.parts:
                continue
            rows_by_path.setdefault(relative.as_posix(), {"path": relative.as_posix()})

    rows = sorted(rows_by_path.values(), key=lambda row: str(row["path"]))
    output = Path(args.out).expanduser()
    write_jsonl(output, rows)
    print(f"Wrote {len(rows)} scoped paths to {output}")


def bind_repo_scopes(args: argparse.Namespace) -> None:
    scopes = load_scopes_file(Path(args.scopes_file).expanduser())
    manifest_path = Path(args.manifest).expanduser()
    coverage_path = Path(args.coverage).expanduser()
    try:
        manifest: object = json.loads(manifest_path.read_text(encoding="utf-8"))
        coverage: object = json.loads(coverage_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or not isinstance(coverage, dict):
            raise ValueError("expected JSON objects")
        scan = manifest.get("scan")
        if not isinstance(scan, dict):
            raise ValueError("manifest.scan must be an object")
        scope = scan.get("scope")
        if not isinstance(scope, dict):
            raise ValueError("manifest.scan.scope must be an object")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("Unable to bind requested scopes into the scan contract") from exc
    scope["includePaths"] = scopes
    coverage["includePaths"] = scopes
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )
    coverage_path.write_text(
        json.dumps(coverage, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Bound {len(scopes)} requested scopes into the scan contract")


def run_git_changed_paths(repo: Path, diff_args: list[str]) -> list[tuple[Path, str]]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "diff",
            "--name-status",
            "-z",
            "--diff-filter=ACMRD",
            *diff_args,
        ],
        check=True,
        capture_output=True,
    )
    fields = result.stdout.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()

    changed: list[tuple[Path, str]] = []
    index = 0
    while index < len(fields):
        status = chr(fields[index][0])
        index += 1
        if status in {"C", "R"}:
            index += 1
        path = repo / os.fsdecode(fields[index])
        index += 1
        changed.append((path, status))
    return changed


def git_changed_paths(repo: Path, base: str, head: str, mode: str) -> list[tuple[Path, str]]:
    if mode == "revisions":
        return run_git_changed_paths(repo, [f"{base}..{head}"])
    if mode == "local-patch":
        unstaged = run_git_changed_paths(repo, [base])
        staged = run_git_changed_paths(repo, ["--cached", base])
        untracked = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "--others", "--exclude-standard", "-z"],
            capture_output=True,
            check=True,
        )
        combined = dict(staged)
        combined.update(unstaged)
        combined.update(
            (repo / os.fsdecode(relative), "A")
            for relative in untracked.stdout.split(b"\0")
            if relative
        )
        return sorted(combined.items())
    raise SystemExit(f"Unknown diff mode: {mode}")


def make_diff_rank_input(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")

    changed = [
        (path, status)
        for path, status in git_changed_paths(repo, args.base, args.head, args.mode)
        if not path_is_diff_excluded(path.relative_to(repo))
        and path.suffix.lower() in TEXT_CODE_EXTENSIONS
    ]
    revision_paths = [
        path.relative_to(repo)
        for path, status in changed
        if args.mode == "revisions" and status != "D"
    ]
    revision_blobs = dict(
        zip(
            revision_paths,
            git_blob_bytes(
                repo,
                [f"{args.head}:{path.as_posix()}" for path in revision_paths],
            ),
        )
    )

    rows: list[JsonRow] = []
    for path, status in changed:
        rel = path.relative_to(repo)

        if status == "D":
            preview = ""
        elif args.mode == "revisions":
            content = revision_blobs[rel]
            if content is None:
                raise SystemExit(
                    f"Unable to read committed diff blob: {args.head}:{rel.as_posix()}"
                )
            preview, is_binary = preview_for_bytes(rel, content, args.preview_bytes)
            if is_binary:
                continue
        elif path.is_symlink():
            preview = ""
        elif path.is_file():
            try:
                path.resolve(strict=True).relative_to(repo)
            except (OSError, ValueError):
                preview = ""
            else:
                preview, is_binary = preview_for(path, args.preview_bytes)
                if is_binary:
                    continue
        else:
            preview = ""
        rows.append({"path": rel.as_posix(), "area": args.area, "preview": preview})

    rows.sort(key=lambda row: str(row["path"]))
    output = Path(args.out).expanduser()
    write_jsonl(output, rows)
    print(f"Wrote {len(rows)} rows to {output}")


def main() -> None:
    args = parse_args()
    if args.command == "make-repo-rank-input":
        make_repo_rank_input(args)
    elif args.command == "make-repo-scope-input":
        make_repo_scope_input(args)
    elif args.command == "bind-repo-scopes":
        bind_repo_scopes(args)
    elif args.command == "make-diff-rank-input":
        make_diff_rank_input(args)
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
