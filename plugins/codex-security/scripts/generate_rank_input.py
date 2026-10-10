#!/usr/bin/env python3
"""Generate and post-process Codex Security scan worklists.

This script stays deliberately model-free:

- `make-repo-rank-input` creates the deterministic repository or scoped-path
  JSONL candidate worklist that ranking subagents consume.
- `make-diff-rank-input` creates the deterministic diff-scoped JSONL candidate
  worklist from Git changed paths. It supports committed revision diffs and
  local working-tree patches.

Candidate selection uses repository scope, native tool ignore rules, and binary detection,
not filename or directory classifications. Ranking inputs use bounded source previews.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_in_scope_files import windows_stream_component
from rank_preview import (
    DEFAULT_PREVIEW_BYTES,
    is_binary_file,
    preview_for,
    preview_for_bytes,
)
from workbench_target import git_blob_samples, git_command, git_directory_snapshot_paths

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

    diff = subparsers.add_parser(
        "make-diff-rank-input",
        help="Create rank_input.jsonl from Git changed text files.",
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


def scope_candidates(repo: Path, scope_path: Path) -> Iterable[Path]:
    """Use Git's inventory in worktrees and ripgrep's ignore rules elsewhere.

    Git retains tracked files and applies its standard exclusions to untracked files.
    Outside Git, ripgrep also honors .ignore and .rgignore alongside .gitignore.
    Explicit file scopes bypass directory ignore rules.
    """
    if scope_path.is_file():
        return (scope_path,)
    git_candidates = git_directory_snapshot_paths(scope_path)
    if git_candidates is not None:
        return git_candidates

    command = [
        "rg",
        "--files",
        "--hidden",
        "--no-require-git",
        "--null",
        # Also exclude descendants when the scope starts inside .git.
        "--glob",
        "!**/.git",
        "--glob",
        "!**/.git/**",
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
            or any(path.name in ignore_names for path in scope_path.rglob("*") if path.is_file())
        )
        if has_ignore_rules:
            raise SystemExit(
                "Could not safely enumerate ignored scoped files without Git or ripgrep."
            ) from exc
        return scope_path.rglob("*")

    if result.returncode not in (0, 1):
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"Could not enumerate scoped repository files: {detail}")
    return (repo / os.fsdecode(path) for path in result.stdout.split(b"\0") if path)


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
        candidates = scope_candidates(repo, scope_abs)
        for path in candidates:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                path.resolve(strict=True).relative_to(repo)
            except (OSError, ValueError):
                continue
            rel = path.relative_to(repo)
            directly_requested = path in directly_requested_files
            if ".git" in rel.parts:
                continue

            preview, is_binary = preview_for(path, args.preview_bytes)
            if is_binary or is_binary_file(path):
                if not directly_requested:
                    continue
                preview = ""
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
        candidates = scope_candidates(repo, scope_path)
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


def run_git_changed_paths(repo: Path, diff_args: list[str]) -> list[tuple[Path, str]]:
    """Return changed regular files from the selected side of each change."""
    result = git_command(
        repo,
        "diff",
        "--ignore-submodules=all",
        "--raw",
        "-z",
        "--diff-filter=ACMRDT",
        *diff_args,
        text=False,
    )
    result.check_returncode()
    fields = result.stdout.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()

    changed: list[tuple[Path, str]] = []
    index = 0
    while index < len(fields):
        metadata = fields[index].split()
        status = chr(metadata[-1][0])
        index += 1
        if status in {"C", "R"}:
            index += 1
        path = repo / os.fsdecode(fields[index])
        index += 1
        selected_mode = metadata[0].removeprefix(b":") if status == "D" else metadata[1]
        if selected_mode.startswith(b"100"):
            changed.append((path, status))
    return changed


def git_changed_paths(repo: Path, base: str, head: str, mode: str) -> list[tuple[Path, str]]:
    if mode == "revisions":
        return run_git_changed_paths(repo, [f"{base}..{head}"])
    if mode == "local-patch":
        unstaged = run_git_changed_paths(repo, [base])
        staged = run_git_changed_paths(repo, ["--cached", base])
        untracked = git_command(
            repo,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            text=False,
        )
        untracked.check_returncode()
        combined = dict(staged)
        combined.update(unstaged)
        combined.update(
            (repo / os.fsdecode(relative), "A")
            for relative in untracked.stdout.split(b"\0")
            if relative and not relative.endswith(b"/")
        )
        return sorted(
            (path, status)
            for path, status in combined.items()
            if status == "D" or (not path.is_symlink() and path.is_file())
        )
    raise SystemExit(f"Unknown diff mode: {mode}")


def make_diff_rank_input(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")

    changed = git_changed_paths(repo, args.base, args.head, args.mode)
    revision_refs = {
        path.relative_to(repo): (
            f"{args.base if status == 'D' else args.head}:{path.relative_to(repo).as_posix()}"
        )
        for path, status in changed
        if args.mode == "revisions" or status == "D"
    }
    revision_samples = dict(
        zip(revision_refs, git_blob_samples(repo, list(revision_refs.values())))
    )

    rows: list[JsonRow] = []
    for path, status in changed:
        rel = path.relative_to(repo)

        preview = ""
        if args.mode == "revisions" or status == "D":
            sample = revision_samples[rel]
            if sample is None:
                revision = args.base if status == "D" else args.head
                raise SystemExit(f"Unable to read committed diff blob: {revision}:{rel.as_posix()}")
            content, is_binary = sample
            if is_binary:
                continue
            if status != "D":
                preview, _ = preview_for_bytes(content, args.preview_bytes)
        elif not path.is_symlink() and path.is_file():
            try:
                path.resolve(strict=True).relative_to(repo)
            except (OSError, ValueError):
                preview = ""
            else:
                preview, is_binary = preview_for(path, args.preview_bytes)
                if is_binary or is_binary_file(path):
                    continue
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
    elif args.command == "make-diff-rank-input":
        make_diff_rank_input(args)
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
