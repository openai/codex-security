#!/usr/bin/env python3
"""Generate and post-process Codex Security scan worklists.

This script stays deliberately model-free:

- `make-repo-rank-input` creates the deterministic repository or scoped-path
  JSONL candidate worklist that ranking subagents consume.
- `make-scope-inventory` creates the exhaustive JSONL file inventory that
  compact standard scans consume without ranking or preview-based filtering.
- `verify-scope-coverage` binds compact standard-scan review and candidate
  artifacts to the host-attested exhaustive file inventory.
- `make-diff-rank-input` creates the deterministic diff-scoped JSONL candidate
  worklist from Git changed paths. It supports committed revision diffs and
  local working-tree patches.
- `make-rank-shards` partitions the ranking input into deterministic shards.
- `make-rank-pool-plan` assigns those shards to a deterministic bounded worker
  pool.
- `validate-rank-worker` validates one worker slot and emits a content-bound
  completion receipt.
- `validate-rank-shard` validates one completed worker output before the
  coordinator accepts it.
- `validate-rank-pool` validates the pool plan and every assigned shard output.
- `merge-rank-outputs` validates and combines worker-local shard outputs.
- `copy-deep-review-input` copies every candidate into the deep-review worklist
  for exhaustive mode.
- `select-deep-review-input` selects the ranked rows for deep review.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize_candidates import (
    MAX_SCOPE_INVENTORY_BYTES,
    MAX_SCOPE_INVENTORY_FILES,
    combine,
    normalize_candidate,
    read_scope_inventory,
)
from rank_preview import DEFAULT_PREVIEW_BYTES, TEXT_CODE_EXTENSIONS, preview_for

STANDARD_SCOPE_EXCLUDED_DIRS = {
    ".git": "Git administrative metadata is not repository source code.",
    ".venv": "Installed Python environments are excluded unless directly requested.",
    "node_modules": (
        "Installed dependency trees are excluded unless directly requested as a scan scope."
    ),
    "vendor": "Vendored dependency trees are excluded unless directly requested.",
}
STANDARD_SCOPE_ALWAYS_DECLARED_DIRS = {".git", "node_modules"}
STANDARD_SCOPE_BINARY_SUFFIXES = {
    ".a", ".bin", ".class", ".dll", ".dylib", ".exe", ".gif", ".gz",
    ".ico", ".jpeg", ".jpg", ".o", ".pdf", ".png", ".pyc", ".so",
    ".wasm", ".webp", ".woff", ".woff2", ".zip",
}
STANDARD_SCOPE_BINARY_REASON = "Binary assets are excluded unless directly requested."
STANDARD_SCOPE_SYMLINK_REASON = (
    "Symbolic links are not followed during standard scope inventory."
)

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

SHARD_INPUT_GLOB = "rank-shard-*.input.jsonl"
SHARD_OUTPUT_GLOB = "rank-shard-*.output.jsonl"
SHARD_INPUT_PATTERN = re.compile(r"^rank-shard-([0-9]{4,})\.input\.jsonl$")
DIRECT_SCOPE_PREVIEW_READ_BYTES = 64 * 1024
RANK_POOL_PLAN_SCHEMA_VERSION = 1
RANK_POOL_STRATEGY = "round_robin"
RANK_POOL_WORKER_CAP = 6
MAX_SCOPE_COVERAGE_BYTES = MAX_SCOPE_INVENTORY_BYTES
MAX_SCOPE_REVIEW_BYTES = MAX_SCOPE_COVERAGE_BYTES + MAX_SCOPE_INVENTORY_FILES * 128
MAX_SCOPE_SOURCE_BYTES = 512 * 1024 * 1024
JsonRow = dict[str, object]
RowValidator = Callable[[JsonRow, Path, int], None]
RankWorkerAssignment = tuple[int, list[str], list[str]]


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

    inventory = subparsers.add_parser(
        "make-scope-inventory",
        help="Create the exhaustive file inventory for a compact standard scan.",
    )
    inventory.add_argument("--repo", required=True, help="Repository root.")
    inventory.add_argument(
        "--scope",
        default=".",
        help="Path within the repository to scan. Defaults to the repository root.",
    )
    inventory.add_argument(
        "--scopes-file",
        help="JSON array of repository-relative files and directories to scan together.",
    )
    inventory.add_argument(
        "--expected-exclusions-json",
        help="Host-registered JSON array of exclusion patterns to attest during traversal.",
    )
    inventory.add_argument(
        "--expected-exclusions-file",
        help="Private host-owned JSON file containing registered exclusion patterns.",
    )
    inventory.add_argument(
        "--max-files",
        type=int,
        default=MAX_SCOPE_INVENTORY_FILES,
        help="Maximum inventoried files, capped at the supported SDK limit.",
    )
    inventory.add_argument(
        "--max-bytes",
        type=int,
        default=MAX_SCOPE_COVERAGE_BYTES,
        help="Maximum inventory bytes, capped at the supported SDK limit.",
    )
    inventory.add_argument("--out", required=True, help="Output scope_inventory.jsonl path.")

    verify_scope = subparsers.add_parser(
        "verify-scope-coverage",
        help="Verify standard review and candidates against the host-owned scope inventory.",
    )
    verify_scope.add_argument("--repo", required=True, help="Repository root.")
    verify_scope.add_argument("--inventory", required=True, help="Protected scope inventory.")
    verify_scope.add_argument("--scan-dir", required=True, help="Standard scan output directory.")

    bind = subparsers.add_parser(
        "bind-repo-scopes",
        help="Copy SDK scoped-path targets into the unsealed manifest and coverage documents.",
    )
    bind.add_argument("--scopes-file", required=True, help="JSON array of requested scopes.")
    bind.add_argument("--manifest", required=True, help="Unsealed scan-manifest.json path.")
    bind.add_argument("--coverage", required=True, help="Unsealed coverage.json path.")

    exclusions = subparsers.add_parser(
        "bind-scope-exclusions",
        help="Bind standard inventory exclusions into the unsealed scan contract.",
    )
    exclusions.add_argument("--repo", required=True, help="Repository root.")
    exclusions.add_argument(
        "--scope",
        default=".",
        help="Path within the repository to scan. Defaults to the repository root.",
    )
    exclusions.add_argument(
        "--scopes-file",
        help="JSON array of repository-relative files and directories to scan together.",
    )
    exclusions.add_argument(
        "--manifest", required=True, help="Unsealed scan-manifest.json path."
    )
    exclusions.add_argument("--coverage", required=True, help="Unsealed coverage.json path.")
    exclusions.add_argument(
        "--inventory", help="Inventory whose captured exclusions should be bound."
    )

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

    shards = subparsers.add_parser(
        "make-rank-shards",
        help="Partition rank_input.jsonl into deterministic worker input shards.",
    )
    shards.add_argument("--rank-input", required=True, help="Deterministic rank input JSONL.")
    shards.add_argument("--out-dir", required=True, help="Directory for worker input shards.")
    shards.add_argument(
        "--max-rows",
        type=int,
        default=150,
        help="Maximum rows per shard. Defaults to 150.",
    )

    pool_plan = subparsers.add_parser(
        "make-rank-pool-plan",
        help="Assign rank shards to a deterministic bounded worker pool.",
    )
    pool_plan.add_argument("--shard-dir", required=True, help="Directory of rank shards.")
    pool_plan.add_argument(
        "--usable-worker-slots",
        required=True,
        type=int,
        help="Usable ranking-worker slots reported by capability preflight; capped at 6.",
    )
    pool_plan.add_argument("--out", required=True, help="Output rank_worker_assignments.json path.")

    validate_shard = subparsers.add_parser(
        "validate-rank-shard",
        help="Validate one worker output against its rank input shard.",
    )
    validate_shard.add_argument("--input", required=True, help="Worker rank input shard.")
    validate_shard.add_argument("--output", required=True, help="Worker rank output shard.")

    validate_worker = subparsers.add_parser(
        "validate-rank-worker",
        help="Validate one assigned ranking-worker slot and emit its completion receipt.",
    )
    validate_worker.add_argument("--plan", required=True, help="Rank pool plan JSON path.")
    validate_worker.add_argument("--shard-dir", required=True, help="Directory of rank shards.")
    validate_worker.add_argument(
        "--slot",
        required=True,
        type=int,
        help="One-based ranking-worker slot from the rank pool plan.",
    )

    validate_pool = subparsers.add_parser(
        "validate-rank-pool",
        help="Validate a rank pool plan and every assigned shard output.",
    )
    validate_pool.add_argument("--plan", required=True, help="Rank pool plan JSON path.")
    validate_pool.add_argument("--shard-dir", required=True, help="Directory of rank shards.")

    merge = subparsers.add_parser(
        "merge-rank-outputs",
        help="Validate worker shard outputs and create rank_output.jsonl.",
    )
    merge.add_argument("--rank-input", required=True, help="Authoritative rank input JSONL.")
    merge.add_argument("--shard-dir", required=True, help="Directory of input and output shards.")
    merge.add_argument("--out", required=True, help="Output rank_output.jsonl path.")

    copy = subparsers.add_parser(
        "copy-deep-review-input",
        help="Create deep_review_input.jsonl directly from rank_input.jsonl.",
    )
    copy.add_argument("--rank-input", required=True, help="Deterministic rank input JSONL.")
    copy.add_argument("--out", required=True, help="Output deep_review_input.jsonl path.")

    select = subparsers.add_parser(
        "select-deep-review-input",
        help="Create deep_review_input.jsonl from worker-produced rank_output.jsonl.",
    )
    select.add_argument("--rank-output", required=True, help="Worker ranking output JSONL.")
    select.add_argument("--out", required=True, help="Output deep_review_input.jsonl path.")
    select.add_argument(
        "--top-percent",
        type=int,
        default=100,
        help="Percent of included files to keep for deep review.",
    )
    return parser.parse_args()


def path_is_excluded(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return True
    if path.name in EXCLUDED_FILENAMES:
        return True
    return path.name.endswith((".min.js", ".map"))


def resolve_scope(repo: Path, scope: str, *, expand_user: bool = True) -> Path:
    scope_path = Path(scope).expanduser() if expand_user else Path(scope)
    if not scope_path.is_absolute():
        scope_path = repo / scope_path
    current = scope_path
    while current != repo:
        if current.is_symlink():
            raise SystemExit(f"Scope must not be a symbolic link or contain one: {current}")
        if current.parent == current:
            break
        current = current.parent
    scope_path = scope_path.resolve()
    repo_resolved = repo.resolve()
    try:
        scope_path.relative_to(repo_resolved)
    except ValueError as exc:
        raise SystemExit(f"Scope must be inside repo: {scope_path}") from exc
    if not scope_path.is_dir() and not scope_path.is_file():
        raise SystemExit(f"Scope path not found: {scope_path}")
    return scope_path


def record_scope_exclusion(
    repository: Path,
    path: Path,
    exclusions: dict[str, dict[str, str]],
    reason: str = STANDARD_SCOPE_SYMLINK_REASON,
) -> None:
    relative = path.relative_to(repository).as_posix()
    pattern = "".join(
        {"[": "[[]", "]": "[]]", "*": "[*]", "?": "[?]"}.get(character, character)
        for character in relative
    )
    exclusions[pattern] = {
        "pattern": pattern,
        "reason": reason,
    }


def record_scope_path_exclusions(
    repository: Path,
    scope: Path,
    exclusions: dict[str, dict[str, str]],
    requested_files: set[Path],
) -> None:
    """Declare concrete paths skipped by the authoritative scope inventory."""

    pending: list[tuple[Path, Iterator[Path]]] = [(scope, scope.iterdir())]
    while pending:
        directory, children = pending[-1]
        try:
            child = next(children)
        except StopIteration:
            pending.pop()
            continue
        except OSError as exc:
            raise SystemExit(f"Unable to safely inventory scope path: {directory}") from exc
        try:
            if child.is_symlink():
                record_scope_exclusion(repository, child, exclusions)
            elif child.name == ".git":
                continue
            elif child.is_dir() and child.name in STANDARD_SCOPE_EXCLUDED_DIRS:
                if child.name not in STANDARD_SCOPE_ALWAYS_DECLARED_DIRS:
                    record_scope_exclusion(
                        repository,
                        child,
                        exclusions,
                        STANDARD_SCOPE_EXCLUDED_DIRS[child.name],
                    )
            elif child.is_dir():
                pending.append((child, child.iterdir()))
            elif child.name in STANDARD_SCOPE_ALWAYS_DECLARED_DIRS:
                relative = child.relative_to(repository).as_posix()
                for pattern in list(exclusions):
                    if fnmatch.fnmatchcase(relative, pattern):
                        exclusions.pop(pattern)
            elif (
                child.suffix.lower() in STANDARD_SCOPE_BINARY_SUFFIXES
                and child not in requested_files
            ):
                record_scope_exclusion(
                    repository, child, exclusions, STANDARD_SCOPE_BINARY_REASON
                )
        except OSError as exc:
            raise SystemExit(f"Unable to safely inventory scope path: {child}") from exc


def record_overlapping_scope_exclusions(
    repository: Path,
    excluded_root: Path,
    requested_scopes: list[Path],
    reason: str,
    exclusions: dict[str, dict[str, str]],
) -> None:
    """Carve directly requested scopes out of a broader excluded directory."""

    pending = [excluded_root]
    while pending:
        current = pending.pop()
        requested = [
            scope
            for scope in requested_scopes
            if scope == current or scope.is_relative_to(current)
        ]
        if not requested:
            record_scope_exclusion(repository, current, exclusions, reason)
            continue
        if any(scope == current and scope.is_dir() for scope in requested):
            continue
        if not current.is_dir():
            continue
        try:
            for child in current.iterdir():
                if child.is_symlink():
                    record_scope_exclusion(repository, child, exclusions)
                else:
                    pending.append(child)
        except OSError as exc:
            raise SystemExit(f"Unable to safely inventory scope path: {current}") from exc


def standard_scope_exclusions(repo: Path, scopes: list[str]) -> list[dict[str, str]]:
    """Declare exact inventory exclusions without excluding directly requested paths."""

    repository = repo.resolve()
    resolved_scopes = [
        resolve_scope(repository, scope, expand_user=False) for scope in scopes
    ]
    requested_files = {scope for scope in resolved_scopes if scope.is_file()}
    exclusions: dict[str, dict[str, str]] = {}
    for scope_path in resolved_scopes:
        if not scope_path.is_dir():
            continue
        narrower_scopes = [
            selected
            for selected in resolved_scopes
            if selected != scope_path
            and selected.is_relative_to(scope_path)
            and any(
                part in STANDARD_SCOPE_EXCLUDED_DIRS
                for part in selected.relative_to(scope_path).parts
            )
        ]
        if narrower_scopes:
            pending = [scope_path]
            while pending:
                directory = pending.pop()
                try:
                    for child in directory.iterdir():
                        if child.is_symlink():
                            record_scope_exclusion(
                                repository, child, exclusions
                            )
                            continue
                        if child.name == ".git" or (
                            child.is_dir() and child.name in STANDARD_SCOPE_EXCLUDED_DIRS
                        ):
                            record_overlapping_scope_exclusions(
                                repository,
                                child,
                                narrower_scopes,
                                STANDARD_SCOPE_EXCLUDED_DIRS[child.name],
                                exclusions,
                            )
                        elif child.is_dir():
                            pending.append(child)
                        elif (
                            child.suffix.lower() in STANDARD_SCOPE_BINARY_SUFFIXES
                            and child not in requested_files
                        ):
                            record_scope_exclusion(
                                repository,
                                child,
                                exclusions,
                                STANDARD_SCOPE_BINARY_REASON,
                            )
                except OSError as exc:
                    raise SystemExit(
                        f"Unable to safely inventory scope path: {directory}"
                    ) from exc
            continue

        scope_prefix = PurePosixPath(scope_path.relative_to(repository).as_posix())
        for directory, reason in STANDARD_SCOPE_EXCLUDED_DIRS.items():
            if directory not in STANDARD_SCOPE_ALWAYS_DECLARED_DIRS:
                continue
            for pattern in (
                (scope_prefix / directory).as_posix(),
                (scope_prefix / "**" / directory).as_posix(),
                (scope_prefix / "**" / directory / "**").as_posix(),
            ):
                if (
                    directory != ".git"
                    and "**" not in pattern
                    and (scope_path / directory).is_file()
                ):
                    continue
                exclusions[pattern] = {"pattern": pattern, "reason": reason}
        record_scope_path_exclusions(
            repository, scope_path, exclusions, requested_files
        )
    return [exclusions[pattern] for pattern in sorted(exclusions)]


def write_jsonl(output: Path, rows: list[JsonRow]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")))
            handle.write("\n")


def write_json(output: Path, payload: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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


def load_jsonl(path: Path, label: str, validator: RowValidator) -> list[JsonRow]:
    if not path.exists():
        raise SystemExit(f"{label} missing: {path}")

    rows: list[JsonRow] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                raise SystemExit(f"{path}:{line_number}: blank JSONL rows are not allowed")
            try:
                parsed: object = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(parsed, dict):
                raise SystemExit(f"{path}:{line_number}: expected a JSON object")
            row = {str(key): value for key, value in parsed.items()}
            validator(row, path, line_number)
            rows.append(row)
    return rows


def require_exact_fields(row: JsonRow, expected: set[str], path: Path, line_number: int) -> None:
    actual = set(row)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if unexpected:
            details.append(f"unexpected fields {unexpected}")
        raise SystemExit(f"{path}:{line_number}: {'; '.join(details)}")


def require_string(
    row: JsonRow, field: str, path: Path, line_number: int, *, allow_empty: bool
) -> None:
    value = row[field]
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        requirement = "a string" if allow_empty else "a non-empty string"
        raise SystemExit(f"{path}:{line_number}: {field} must be {requirement}")


def validate_rank_input_row(row: JsonRow, path: Path, line_number: int) -> None:
    require_exact_fields(row, {"path", "area", "preview"}, path, line_number)
    require_string(row, "path", path, line_number, allow_empty=False)
    require_string(row, "area", path, line_number, allow_empty=True)
    require_string(row, "preview", path, line_number, allow_empty=True)


def validate_rank_output_row(row: JsonRow, path: Path, line_number: int) -> None:
    require_exact_fields(row, {"path", "area", "score", "include", "reason"}, path, line_number)
    require_string(row, "path", path, line_number, allow_empty=False)
    require_string(row, "area", path, line_number, allow_empty=True)
    score = row["score"]
    if isinstance(score, bool) or not isinstance(score, int):
        raise SystemExit(f"{path}:{line_number}: score must be an integer from 1 through 10")
    if not 1 <= score <= 10:
        raise SystemExit(f"{path}:{line_number}: score must be from 1 through 10")
    if not isinstance(row["include"], bool):
        raise SystemExit(f"{path}:{line_number}: include must be a boolean")
    require_string(row, "reason", path, line_number, allow_empty=False)


def require_unique_paths(rows: list[JsonRow], label: str) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for row in rows:
        path = str(row["path"])
        if path in seen:
            duplicates.add(path)
        seen.add(path)
    if duplicates:
        raise SystemExit(f"{label} contains duplicate paths: {sorted(duplicates)}")


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


def make_scope_inventory(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")
    if not 1 <= args.max_files <= MAX_SCOPE_INVENTORY_FILES:
        raise SystemExit("Invalid standard scan scope inventory limit: --max-files")
    if not 1 <= args.max_bytes <= MAX_SCOPE_COVERAGE_BYTES:
        raise SystemExit("Invalid standard scan scope inventory limit: --max-bytes")

    expected_exclusions: list[str] | None = None
    if args.expected_exclusions_json is not None and args.expected_exclusions_file is not None:
        raise SystemExit("Choose one host-registered standard scan scope exclusion source")
    if args.expected_exclusions_json is not None or args.expected_exclusions_file is not None:
        try:
            serialized = (
                Path(args.expected_exclusions_file).read_text(encoding="utf-8")
                if args.expected_exclusions_file is not None
                else args.expected_exclusions_json
            )
            decoded: object = json.loads(serialized)
        except (OSError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise SystemExit("Invalid host-registered standard scan scope exclusions") from exc
        if not isinstance(decoded, list) or any(
            not isinstance(pattern, str) or not pattern for pattern in decoded
        ):
            raise SystemExit("Invalid host-registered standard scan scope exclusions")
        expected_exclusions = decoded

    def excluded_from_registered_scope(path: str) -> bool:
        return expected_exclusions is not None and any(
            PurePosixPath(pattern) == PurePosixPath(path)
            or PurePosixPath(pattern) in PurePosixPath(path).parents
            or fnmatch.fnmatchcase(path, pattern)
            for pattern in expected_exclusions
        )

    explicit_scopes = args.scopes_file is not None
    scoped_exclusions = explicit_scopes or args.scope != "."
    scopes = (
        load_scopes_file(Path(args.scopes_file).expanduser())
        if explicit_scopes
        else [args.scope]
    )
    captured_exclusions = None
    if expected_exclusions is None:
        captured_exclusions = standard_scope_exclusions(repo, scopes)
        expected_exclusions = [exclusion["pattern"] for exclusion in captured_exclusions]
    resolved_scopes = [
        resolve_scope(repo, scope, expand_user=not explicit_scopes) for scope in scopes
    ]

    paths: dict[str, str] = {}
    inventory_bytes = 0
    source_bytes = 0
    for scope_abs in resolved_scopes:
        scope_root = scope_abs if scope_abs.is_dir() else scope_abs.parent
        pending: list[tuple[Path, Iterator[Path]]] = [
            (scope_abs.parent, iter((scope_abs,)))
        ]
        while pending:
            directory, entries = pending[-1]
            try:
                path = next(entries)
            except StopIteration:
                pending.pop()
                continue
            except OSError as exc:
                raise SystemExit(f"Unable to safely inventory scope path: {directory}") from exc
            try:
                candidate_path = path.relative_to(repo).as_posix()
                if path.is_symlink():
                    if expected_exclusions is not None and not excluded_from_registered_scope(
                        candidate_path
                    ):
                        raise SystemExit(
                            "Standard scan scope exclusions changed during inventory preparation: "
                            + candidate_path
                        )
                    continue
                relative = path.resolve(strict=True).relative_to(repo)
                excluded_path = (
                    relative.relative_to(scope_root.relative_to(repo))
                    if scoped_exclusions
                    else relative
                )
                excluded_parts = (
                    excluded_path.parts if path.is_dir() else excluded_path.parts[:-1]
                )
                requested_carve_out = any(
                    selected != scope_abs
                    and selected.is_relative_to(scope_abs)
                    and (selected == path or path.is_relative_to(selected))
                    and not any(
                        part in STANDARD_SCOPE_EXCLUDED_DIRS
                        for part in path.relative_to(selected).parts
                    )
                    for selected in resolved_scopes
                )
                if (
                    (
                        path.name == ".git"
                        or any(part in STANDARD_SCOPE_EXCLUDED_DIRS for part in excluded_parts)
                    )
                    and not requested_carve_out
                ):
                    if path.is_dir() and any(
                        selected != path and selected.is_relative_to(path)
                        for selected in resolved_scopes
                    ):
                        pending.append((path, path.iterdir()))
                        continue
                    if expected_exclusions is not None and not excluded_from_registered_scope(
                        relative.as_posix()
                    ):
                        raise SystemExit(
                            "Standard scan scope exclusions changed during inventory preparation: "
                            + relative.as_posix()
                        )
                    continue
                if path.is_dir():
                    pending.append((path, path.iterdir()))
                elif path.is_file():
                    relative_path = relative.as_posix()
                    if (
                        path.suffix.lower() in STANDARD_SCOPE_BINARY_SUFFIXES
                        and path not in resolved_scopes
                    ):
                        if (
                            expected_exclusions is not None
                            and not excluded_from_registered_scope(relative_path)
                        ):
                            raise SystemExit(
                                "Standard scan scope exclusions changed during inventory preparation: "
                                + relative_path
                            )
                        continue
                    if excluded_from_registered_scope(relative_path):
                        raise SystemExit(
                            "Standard scan scope exclusions changed during inventory preparation: "
                            + relative_path
                        )
                    if relative_path in paths:
                        continue
                    if source_bytes + path.stat().st_size > MAX_SCOPE_SOURCE_BYTES:
                        raise SystemExit(
                            "Exceeded the standard scan scope source byte limit: "
                            + relative_path
                        )
                    digest = hashlib.sha256()
                    with path.open("rb") as contents:
                        for chunk in iter(lambda: contents.read(1024 * 1024), b""):
                            source_bytes += len(chunk)
                            if source_bytes > MAX_SCOPE_SOURCE_BYTES:
                                raise SystemExit(
                                    "Exceeded the standard scan scope source byte limit: "
                                    + relative_path
                                )
                            digest.update(chunk)
                    row = {"path": relative_path, "sha256": digest.hexdigest()}
                    row_bytes = len(
                        (
                            json.dumps(
                                row,
                                ensure_ascii=True,
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
                    if len(paths) >= args.max_files or inventory_bytes + row_bytes > args.max_bytes:
                        raise SystemExit("Exceeded the standard scan scope inventory limit")
                    paths[relative_path] = row["sha256"]
                    inventory_bytes += row_bytes
                else:
                    raise SystemExit(
                        "Unsupported non-regular standard scan scope entry: "
                        + relative.as_posix()
                    )
            except (OSError, ValueError) as exc:
                raise SystemExit(f"Unable to safely inventory scope path: {path}") from exc

    output = Path(args.out).expanduser()
    write_jsonl(
        output,
        [{"path": path, "sha256": digest} for path, digest in sorted(paths.items())],
    )
    if captured_exclusions is not None:
        output.with_suffix(".exclusions.json").write_text(
            json.dumps(captured_exclusions, ensure_ascii=True) + "\n", encoding="utf-8"
        )
    print(f"Wrote {len(paths)} inventory rows to {output}")


def require_standard_scope_artifact(
    scan_dir: Path,
    relative: str,
    label: str,
    *,
    max_bytes: int = MAX_SCOPE_COVERAGE_BYTES,
) -> Path:
    path = scan_dir / relative
    current = path
    while current != scan_dir:
        if current.is_symlink():
            raise SystemExit(f"{label} must not contain a symbolic link: {relative}")
        current = current.parent
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(scan_dir)
        metadata = resolved.stat()
    except (OSError, ValueError) as error:
        raise SystemExit(f"{label} is missing or outside the scan directory: {relative}") from error
    if not resolved.is_file() or metadata.st_size > max_bytes:
        raise SystemExit(f"{label} must be a bounded regular file: {relative}")
    return resolved


def require_standard_closure_text(
    record: dict[str, object],
    field: str,
    path: Path,
    number: int,
    closure: str,
    *,
    allow_empty: bool = False,
) -> str:
    value = record.get(field)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise SystemExit(f"{path}:{number}: incomplete {closure} closure: {field}")
    return value


def validate_standard_validation(
    record: dict[str, object], path: Path, number: int
) -> str:
    disposition = record.get("disposition")
    if not isinstance(disposition, str) or disposition not in {
        "reportable",
        "suppressed",
        "not_applicable",
        "deferred",
    }:
        raise SystemExit(f"{path}:{number}: unsupported candidate validation disposition")
    for field in ("method", "confidence_rationale", "evidence"):
        require_standard_closure_text(record, field, path, number, "validation")
    for field in ("counterevidence_or_proof_gap", "remaining_uncertainty"):
        require_standard_closure_text(
            record, field, path, number, "validation", allow_empty=True
        )
    confidence = record.get("confidence")
    if not isinstance(confidence, str) or confidence not in {"high", "medium", "low"}:
        raise SystemExit(f"{path}:{number}: incomplete validation closure: confidence")
    rubric = record.get("rubric")
    valid_rubric = (
        isinstance(rubric, str)
        and bool(rubric.strip())
        or isinstance(rubric, list)
        and 1 <= len(rubric) <= 5
        and all(isinstance(criterion, str) and criterion.strip() for criterion in rubric)
    )
    if not valid_rubric:
        raise SystemExit(f"{path}:{number}: incomplete validation closure: rubric")
    if disposition == "deferred" and not (
        str(record["counterevidence_or_proof_gap"]).strip()
        or str(record["remaining_uncertainty"]).strip()
    ):
        raise SystemExit(f"{path}:{number}: deferred validation requires an explicit proof gap")
    return disposition


def validate_standard_attack_path(
    record: dict[str, object], path: Path, number: int
) -> str:
    decision = record.get("decision")
    if not isinstance(decision, str) or decision not in {"reportable", "ignore", "deferred"}:
        raise SystemExit(f"{path}:{number}: incomplete attack-path closure: decision")
    for field in ("dataflow", "reachability"):
        value = record.get(field)
        if isinstance(value, dict):
            if not value:
                raise SystemExit(f"{path}:{number}: incomplete attack-path closure: {field}")
        else:
            require_standard_closure_text(record, field, path, number, "attack-path")
    require_standard_closure_text(
        record, "severity_rationale", path, number, "attack-path"
    )
    require_standard_closure_text(
        record, "counterevidence", path, number, "attack-path", allow_empty=True
    )
    for field in ("impact", "likelihood"):
        value = record.get(field)
        if not isinstance(value, str) or value not in {
            "high",
            "medium",
            "low",
            "ignore",
            "unknown",
        }:
            raise SystemExit(f"{path}:{number}: incomplete attack-path closure: {field}")
    conditions = record.get("change_conditions")
    if not (
        isinstance(conditions, str)
        and bool(conditions.strip())
        or isinstance(conditions, list)
        and bool(conditions)
        and all(isinstance(condition, str) and condition.strip() for condition in conditions)
    ):
        raise SystemExit(f"{path}:{number}: incomplete attack-path closure: change_conditions")
    severity = record.get("severity")
    reportable_severity = {"critical", "high", "medium", "low"}
    if decision == "reportable" and severity not in reportable_severity:
        raise SystemExit(f"{path}:{number}: reportable attack path requires reportable severity")
    if decision == "ignore" and severity != "ignore":
        raise SystemExit(f"{path}:{number}: ignored attack path requires ignore severity")
    if decision == "deferred":
        if severity not in reportable_severity | {"unknown"}:
            raise SystemExit(f"{path}:{number}: deferred attack path requires provisional severity")
        require_standard_closure_text(record, "proof_gap", path, number, "attack-path")
    return decision


def validate_standard_finding_payload(
    finding: dict[str, object], candidate: JsonRow, index: int
) -> set[tuple[object, object, object, object]]:
    validation = candidate.get("validation")
    attack_path = candidate.get("attack_path")
    if not isinstance(validation, dict) or not isinstance(attack_path, dict):
        raise SystemExit(f"Standard finding {index} has no complete candidate payload")

    taxonomy = finding.get("taxonomy")
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    finding_validation = finding.get("validation")
    finding_attack_path = finding.get("attackPath")
    if not all(
        isinstance(section, dict)
        for section in (taxonomy, severity, confidence, finding_validation, finding_attack_path)
    ):
        raise SystemExit(f"Standard finding {index} does not preserve its candidate payload")
    assert isinstance(taxonomy, dict)
    assert isinstance(severity, dict)
    assert isinstance(confidence, dict)
    assert isinstance(finding_validation, dict)
    assert isinstance(finding_attack_path, dict)
    conditions = attack_path.get("change_conditions")
    canonical_conditions = "\n".join(conditions) if isinstance(conditions, list) else conditions

    normalized_attack_path = {
        field: {"summary": value} if field in {"dataflow", "reachability"} and isinstance(value, str) else value
        for field, value in attack_path.items()
    }
    fields = (
        ("taxonomy", taxonomy.get("cwe"), candidate.get("cwe_ids")),
        ("severity", severity.get("level"), attack_path.get("severity")),
        (
            "severity rationale",
            severity.get("rationale"),
            attack_path.get("severity_rationale"),
        ),
        (
            "severity change conditions",
            severity.get("changeConditions"),
            canonical_conditions,
        ),
        ("confidence", confidence.get("level"), validation.get("confidence")),
        (
            "confidence rationale",
            confidence.get("rationale"),
            validation.get("confidence_rationale"),
        ),
        ("validation method", finding_validation.get("method"), validation.get("method")),
        ("validation evidence", finding_validation.get("summary"), validation.get("evidence")),
    ) + tuple(
        (
            "attack-path " + field,
            finding_attack_path.get(field),
            normalized_attack_path.get(field),
        )
        for field in ("dataflow", "reachability", "counterevidence", "impact", "likelihood")
    )
    for field, actual, expected in fields:
        if actual != expected:
            raise SystemExit(
                f"Standard finding {index} does not preserve its candidate payload: {field}"
            )

    expected_locations = {
        (
            location["path"],
            location["start_line"],
            location["end_line"],
            location["role"],
        )
        for location in candidate["locations"]
        if isinstance(location, dict)
    }
    actual_locations: set[tuple[object, object, object, object]] = set()
    for location in finding["locations"]:
        if not isinstance(location, dict):
            raise SystemExit(f"Standard finding {index} does not preserve its candidate locations")
        actual_locations.add(
            (
                location.get("path"),
                location.get("startLine"),
                location.get("endLine", location.get("startLine")),
                location.get("role"),
            )
        )
    if not actual_locations or not actual_locations.issubset(expected_locations):
        raise SystemExit(f"Standard finding {index} does not preserve its candidate locations")
    return actual_locations


def verify_scope_coverage(args: argparse.Namespace) -> None:
    try:
        repository = Path(args.repo).expanduser().resolve(strict=True)
        scan_dir = Path(args.scan_dir).expanduser().resolve(strict=True)
        inventory = Path(args.inventory).expanduser().resolve(strict=True)
        if not repository.is_dir() or not scan_dir.is_dir():
            raise ValueError("repository and scan directory must be directories")
        inventory_digests: dict[str, str] = {}
        scope = read_scope_inventory(inventory, repository, content_digests=inventory_digests)
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"Unable to read the authoritative scope inventory: {error}") from error

    review_relative = "artifacts/03_coverage/scope_review.jsonl"
    inventory_relative = "artifacts/02_discovery/scope_inventory.jsonl"
    candidate_relative = "artifacts/02_discovery/candidate_ledger.jsonl"
    durable_inventory = require_standard_scope_artifact(
        scan_dir,
        inventory_relative,
        "Durable standard scope inventory",
    )
    try:
        if durable_inventory.read_bytes() != inventory.read_bytes():
            raise SystemExit(
                "Durable standard scope inventory does not match the authoritative inventory"
            )
    except OSError as error:
        raise SystemExit(f"Unable to attest the durable standard scope inventory: {error}") from error
    review_path = require_standard_scope_artifact(
        scan_dir,
        review_relative,
        "Scope-review ledger",
        max_bytes=MAX_SCOPE_REVIEW_BYTES,
    )

    def validate_scope_review(row: JsonRow, path: Path, number: int) -> None:
        disposition = row.get("disposition")
        if disposition not in {"reviewed", "deferred"}:
            raise SystemExit(f"{path}:{number}: unsupported scope review disposition")
        require_exact_fields(
            row,
            {"path", "disposition"} | ({"reason"} if disposition == "deferred" else set()),
            path,
            number,
        )
        require_string(row, "path", path, number, allow_empty=False)
        if disposition == "deferred":
            require_string(row, "reason", path, number, allow_empty=False)

    reviews = load_jsonl(review_path, "Scope-review ledger", validate_scope_review)
    require_unique_paths(reviews, "Scope-review ledger")
    reviewed_paths = {str(row["path"]) for row in reviews}
    missing = sorted(scope - reviewed_paths)
    unexpected = sorted(reviewed_paths - scope)
    if missing:
        raise SystemExit(
            "Scope-review ledger omits authoritative inventory paths: "
            + ", ".join(repr(path) for path in missing[:10])
        )
    if unexpected:
        raise SystemExit(
            "Scope-review ledger contains paths outside the authoritative scope inventory: "
            + ", ".join(repr(path) for path in unexpected[:10])
        )
    unavailable_reviewed = sorted(
        str(row["path"])
        for row in reviews
        if row["disposition"] == "reviewed"
        and not (repository / str(row["path"])).is_file()
    )
    if unavailable_reviewed:
        raise SystemExit(
            "Scope-review ledger marks unavailable inventory paths as reviewed: "
            + ", ".join(repr(path) for path in unavailable_reviewed[:10])
        )
    changed_reviewed = []
    for row in reviews:
        if row["disposition"] != "reviewed":
            continue
        relative = str(row["path"])
        expected = inventory_digests.get(relative)
        if expected is None:
            continue
        digest = hashlib.sha256()
        try:
            with (repository / relative).open("rb") as contents:
                for chunk in iter(lambda: contents.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise SystemExit(f"Unable to attest reviewed inventory path: {relative}") from exc
        if digest.hexdigest() != expected:
            changed_reviewed.append(relative)
    if changed_reviewed:
        raise SystemExit(
            "Scope-review ledger marks changed inventory paths as reviewed: "
            + ", ".join(repr(path) for path in sorted(changed_reviewed)[:10])
        )

    coverage_path = require_standard_scope_artifact(scan_dir, "coverage.json", "Scan coverage")
    findings_path = require_standard_scope_artifact(scan_dir, "findings.json", "Scan findings")
    try:
        prepared_coverage = getattr(args, "coverage", None)
        prepared_findings = getattr(args, "findings", None)
        if prepared_coverage is None and prepared_findings is None:
            coverage: object = json.loads(coverage_path.read_text(encoding="utf-8"))
            findings: object = json.loads(findings_path.read_text(encoding="utf-8"))
        else:
            coverage = prepared_coverage
            findings = prepared_findings
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"Unable to verify standard scan scope coverage: {error}") from error
    if not isinstance(coverage, dict) or not isinstance(findings, dict):
        raise SystemExit("Standard scan coverage and findings must be JSON objects")
    surfaces = coverage.get("surfaces")
    if not isinstance(surfaces, list):
        raise SystemExit("Standard scan coverage must reference the exhaustive scope-review ledger")
    has_deferred_reviews = any(row["disposition"] == "deferred" for row in reviews)
    if coverage.get("completeness") == "complete" and has_deferred_reviews:
        raise SystemExit("Complete standard scan coverage cannot contain deferred inventory paths")
    surface_ids: set[str] = set()
    sealed_receipts: set[str] = set()
    has_review_receipt = False
    has_complete_scope_receipt = False
    for index, surface in enumerate(surfaces, start=1):
        if not isinstance(surface, dict):
            raise SystemExit(f"Standard scan coverage surface {index} must be an object")
        surface_id = surface.get("id")
        label = surface.get("label")
        disposition = surface.get("disposition")
        receipt_refs = surface.get("receiptRefs")
        if not isinstance(surface_id, str) or not surface_id.strip():
            raise SystemExit(f"Standard scan coverage surface {index} has no valid id")
        if surface_id in surface_ids:
            raise SystemExit(f"Standard scan coverage surface {index} repeats its id")
        surface_ids.add(surface_id)
        if not isinstance(label, str) or not label.strip():
            raise SystemExit(f"Standard scan coverage surface {index} has no valid label")
        if disposition not in {
            "reported",
            "no_issue_found",
            "rejected",
            "not_applicable",
            "needs_follow_up",
        }:
            raise SystemExit(f"Standard scan coverage surface {index} has no valid disposition")
        if not isinstance(receipt_refs, list):
            raise SystemExit(f"Standard scan coverage surface {index} has no valid receipts")
        for receipt in receipt_refs:
            if (
                not isinstance(receipt, str)
                or not receipt.startswith("artifacts/")
                or "\\" in receipt
                or any(part in {"", ".", ".."} for part in receipt.split("/"))
            ):
                raise SystemExit(f"Standard scan coverage surface {index} has an unsafe receipt")
            require_standard_scope_artifact(
                scan_dir,
                receipt,
                "Scope-review ledger" if receipt == review_relative else "Coverage receipt",
                max_bytes=(
                    MAX_SCOPE_REVIEW_BYTES
                    if receipt == review_relative
                    else MAX_SCOPE_COVERAGE_BYTES
                ),
            )
            if (
                receipt == review_relative
                and has_deferred_reviews
                and disposition != "needs_follow_up"
            ):
                raise SystemExit(
                    "Deferred scope-review paths require a needs_follow_up receipt surface"
                )
            sealed_receipts.add(receipt)
            has_review_receipt = has_review_receipt or receipt == review_relative
        has_complete_scope_receipt = has_complete_scope_receipt or (
            review_relative in receipt_refs
            and inventory_relative in receipt_refs
            and candidate_relative in receipt_refs
        )
    if not has_review_receipt:
        raise SystemExit("Standard scan coverage must reference the exhaustive scope-review ledger")
    if inventory_relative not in sealed_receipts:
        raise SystemExit("Standard scan coverage must seal the authoritative scope inventory")
    if candidate_relative not in sealed_receipts:
        raise SystemExit("Standard scan coverage must seal the authoritative candidate ledger")
    if not has_complete_scope_receipt:
        raise SystemExit(
            "Standard scan coverage must seal all authoritative receipts together "
            "on the same coverage surface"
        )

    candidate_path = require_standard_scope_artifact(
        scan_dir,
        candidate_relative,
        "Standard candidate ledger",
    )
    line_counts: dict[Path, int] = {}

    def validate_standard_candidate(row: JsonRow, path: Path, number: int) -> None:
        validation = row.get("validation")
        if not isinstance(validation, dict):
            raise SystemExit(f"{path}:{number}: incomplete validation closure")
        disposition = validate_standard_validation(validation, path, number)
        attack_path = row.get("attack_path")
        if disposition in {"reportable", "deferred"}:
            if not isinstance(attack_path, dict):
                raise SystemExit(f"{path}:{number}: incomplete attack-path closure")
            validate_standard_attack_path(attack_path, path, number)
        elif attack_path is not None:
            raise SystemExit(f"{path}:{number}: unexpected attack-path closure")
        discovery = {
            key: value for key, value in row.items() if key not in {"validation", "attack_path"}
        }
        try:
            normalized = normalize_candidate(discovery, repository, scope, line_counts)
            expected = combine([normalized])[0]
        except (OSError, TypeError, ValueError) as error:
            raise SystemExit(f"{path}:{number}: {error}") from error
        if discovery != expected:
            raise SystemExit(
                f"{path}:{number}: candidate does not match authoritative inventory normalization"
            )

    candidates = load_jsonl(candidate_path, "Standard candidate ledger", validate_standard_candidate)
    candidates_by_id: dict[str, JsonRow] = {}
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        if candidate_id in candidates_by_id:
            raise SystemExit(f"Standard candidate ledger repeats candidate id: {candidate_id}")
        candidates_by_id[candidate_id] = candidate

    final_findings = findings.get("findings")
    if not isinstance(final_findings, list):
        raise SystemExit("Standard scan findings must contain an array of findings")
    reported_ids: set[str] = set()
    reported_locations: dict[str, set[tuple[object, object, object, object]]] = {}
    for index, finding in enumerate(final_findings):
        if not isinstance(finding, dict) or not isinstance(finding.get("locations"), list):
            raise SystemExit(f"Standard finding {index + 1} must contain its source locations")
        if not any(
            isinstance(location, dict) and location.get("path") in scope
            for location in finding["locations"]
        ):
            raise SystemExit(
                f"Standard finding {index + 1} has no location in the authoritative scope inventory"
            )
        extensions = finding.get("extensions")
        candidate_id = extensions.get("candidateId") if isinstance(extensions, dict) else None
        candidate = candidates_by_id.get(candidate_id) if isinstance(candidate_id, str) else None
        validation = candidate.get("validation") if isinstance(candidate, dict) else None
        attack_path = candidate.get("attack_path") if isinstance(candidate, dict) else None
        if not (
            isinstance(validation, dict)
            and validation.get("disposition") == "reportable"
            and isinstance(attack_path, dict)
            and attack_path.get("decision") == "reportable"
        ):
            raise SystemExit(
                f"Standard finding {index + 1} does not match a reportable candidate"
            )
        assert isinstance(candidate, dict)
        candidate_locations = validate_standard_finding_payload(finding, candidate, index + 1)
        previous_locations = reported_locations.get(candidate_id, set())
        if candidate_locations.issubset(previous_locations):
            raise SystemExit(
                f"Standard finding repeats an already reported candidate instance: {candidate_id}"
            )
        assert isinstance(candidate_id, str)
        reported_locations[candidate_id] = previous_locations | candidate_locations
        reported_ids.add(candidate_id)

    deferred = coverage.get("deferred", [])
    if not isinstance(deferred, list):
        raise SystemExit("Standard scan coverage deferred outcomes must be an array")
    deferred_by_id: dict[str, JsonRow] = {}
    for index, entry in enumerate(deferred, start=1):
        if not isinstance(entry, dict):
            raise SystemExit(f"Standard scan deferred outcome {index} must be an object")
        deferred_id = entry.get("id")
        reason = entry.get("reason")
        if not isinstance(deferred_id, str) or not deferred_id.strip():
            raise SystemExit(f"Standard scan deferred outcome {index} has no valid id")
        if not isinstance(reason, str) or not reason.strip():
            raise SystemExit(f"Standard scan deferred outcome {index} has no valid reason")
        if deferred_id in deferred_by_id:
            raise SystemExit(f"Standard scan coverage repeats deferred candidate id: {deferred_id}")
        deferred_by_id[deferred_id] = entry
    if coverage.get("completeness") == "complete" and deferred_by_id:
        raise SystemExit("Complete standard scan coverage cannot contain deferred outcomes")
    for deferred_id in deferred_by_id:
        deferred_candidate = candidates_by_id.get(deferred_id)
        deferred_validation = (
            deferred_candidate.get("validation")
            if isinstance(deferred_candidate, dict)
            else None
        )
        deferred_attack_path = (
            deferred_candidate.get("attack_path")
            if isinstance(deferred_candidate, dict)
            else None
        )
        if not (
            isinstance(deferred_validation, dict)
            and (
                deferred_validation.get("disposition") == "deferred"
                or (
                    isinstance(deferred_attack_path, dict)
                    and deferred_attack_path.get("decision") == "deferred"
                )
            )
        ):
            raise SystemExit(
                "Deferred coverage does not match a deferred candidate: " + deferred_id
            )
    for candidate_id, candidate in candidates_by_id.items():
        validation = candidate["validation"]
        attack_path = candidate.get("attack_path")
        if not isinstance(validation, dict):
            raise SystemExit(f"Standard candidate has no validated outcome: {candidate_id}")
        disposition = validation["disposition"]
        decision = attack_path.get("decision") if isinstance(attack_path, dict) else None
        if disposition == "reportable" and decision == "reportable":
            expected_disposition = "reported"
            if candidate_id not in reported_ids:
                raise SystemExit(f"Reportable candidate has no matching final finding: {candidate_id}")
            expected_locations = {
                (
                    location["path"],
                    location["start_line"],
                    location["end_line"],
                    location["role"],
                )
                for location in candidate["locations"]
                if isinstance(location, dict)
            }
            if not expected_locations.issubset(reported_locations[candidate_id]):
                raise SystemExit(
                    f"Reportable candidate has unreported source locations: {candidate_id}"
                )
        elif disposition == "deferred" or decision == "deferred":
            expected_disposition = "needs_follow_up"
            matching_deferred = deferred_by_id.get(candidate_id)
            if matching_deferred is None:
                raise SystemExit(f"Deferred candidate has no matching coverage entry: {candidate_id}")
            proof_gaps = (
                [attack_path.get("proof_gap")]
                if isinstance(attack_path, dict) and decision == "deferred"
                else [
                    validation.get("counterevidence_or_proof_gap"),
                    validation.get("remaining_uncertainty"),
                ]
            )
            if not any(
                isinstance(proof_gap, str)
                and proof_gap.strip()
                and matching_deferred.get("reason") == proof_gap
                for proof_gap in proof_gaps
            ):
                raise SystemExit(
                    f"Deferred candidate coverage contradicts its recorded proof gap: "
                    f"{candidate_id}"
                )
        elif disposition == "not_applicable":
            expected_disposition = "not_applicable"
        else:
            expected_disposition = "rejected"
        if not any(
            isinstance(surface, dict)
            and surface.get("id") == candidate_id
            and surface.get("disposition") == expected_disposition
            for surface in surfaces
        ):
            raise SystemExit(
                f"Standard candidate has no matching {expected_disposition} coverage: "
                f"{candidate_id}"
            )

    print(f"Verified {len(scope)} reviewed inventory paths and {len(candidates)} candidates")


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


def bind_scope_exclusions(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")
    scopes = (
        load_scopes_file(Path(args.scopes_file).expanduser())
        if args.scopes_file is not None
        else [args.scope]
    )
    if args.inventory is None:
        exclusions = standard_scope_exclusions(repo, scopes)
    else:
        snapshot = Path(args.inventory).expanduser().with_suffix(".exclusions.json")
        try:
            exclusions = json.loads(snapshot.read_text(encoding="utf-8"))
            if not isinstance(exclusions, list) or any(
                not isinstance(exclusion, dict)
                or set(exclusion) != {"pattern", "reason"}
                or any(not isinstance(value, str) or not value for value in exclusion.values())
                for exclusion in exclusions
            ):
                raise ValueError("invalid captured exclusions")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise SystemExit("Unable to read the captured standard scope exclusions") from exc
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
        raise SystemExit("Unable to bind standard scope exclusions into the scan contract") from exc
    excluded_paths = [exclusion["pattern"] for exclusion in exclusions]
    scope["excludePaths"] = excluded_paths
    coverage["excludePaths"] = excluded_paths
    coverage["explicitExclusions"] = exclusions
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )
    coverage_path.write_text(
        json.dumps(coverage, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Bound {len(exclusions)} standard scope exclusions into the scan contract")


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
        text=True,
    )
    fields = result.stdout.split("\0")
    if fields and not fields[-1]:
        fields.pop()

    changed: list[tuple[Path, str]] = []
    index = 0
    while index < len(fields):
        status = fields[index][0]
        index += 1
        if status in {"C", "R"}:
            index += 1
        path = repo / fields[index]
        index += 1
        changed.append((path, status))
    return changed


def git_changed_paths(repo: Path, base: str, head: str, mode: str) -> list[tuple[Path, str]]:
    if mode == "revisions":
        return run_git_changed_paths(repo, [f"{base}..{head}"])
    if mode == "local-patch":
        unstaged = run_git_changed_paths(repo, [base])
        staged = run_git_changed_paths(repo, ["--cached", base])
        combined = dict(staged)
        combined.update(unstaged)
        return sorted(combined.items())
    raise SystemExit(f"Unknown diff mode: {mode}")


def make_diff_rank_input(args: argparse.Namespace) -> None:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise SystemExit(f"Repo path not found: {repo}")

    rows: list[JsonRow] = []
    for path, status in git_changed_paths(repo, args.base, args.head, args.mode):
        rel = path.relative_to(repo)
        if path_is_excluded(rel) or path.suffix.lower() not in TEXT_CODE_EXTENSIONS:
            continue

        if status == "D":
            preview = ""
        elif path.is_file():
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


def make_rank_shards(args: argparse.Namespace) -> None:
    if args.max_rows < 1:
        raise SystemExit("--max-rows must be at least 1")

    rank_input = Path(args.rank_input).expanduser()
    rows = load_jsonl(rank_input, "Rank input", validate_rank_input_row)
    require_unique_paths(rows, "Rank input")

    output_dir = Path(args.out_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted((*output_dir.glob(SHARD_INPUT_GLOB), *output_dir.glob(SHARD_OUTPUT_GLOB)))
    if existing:
        raise SystemExit(f"Rank shard directory already contains shard files: {output_dir}")

    shard_count = 0
    for start in range(0, len(rows), args.max_rows):
        shard_count += 1
        shard_path = output_dir / f"rank-shard-{shard_count:04d}.input.jsonl"
        write_jsonl(shard_path, rows[start : start + args.max_rows])

    print(f"Wrote {shard_count} rank shards to {output_dir}")


def discover_input_shards(shard_dir: Path) -> list[Path]:
    if not shard_dir.is_dir():
        raise SystemExit(f"Rank shard directory missing: {shard_dir}")

    numbered_shards: list[tuple[int, Path]] = []
    for path in shard_dir.glob(SHARD_INPUT_GLOB):
        match = SHARD_INPUT_PATTERN.fullmatch(path.name)
        if match is None:
            raise SystemExit(f"Rank input shard has invalid name: {path.name}")
        numbered_shards.append((int(match.group(1)), path))
    numbered_shards.sort(key=lambda item: (item[0], item[1].name))
    input_shards = [path for _, path in numbered_shards]
    expected_names = [
        f"rank-shard-{index:04d}.input.jsonl" for index in range(1, len(input_shards) + 1)
    ]
    actual_names = [path.name for path in input_shards]
    if actual_names != expected_names:
        raise SystemExit(
            "Rank input shards must use contiguous canonical names; "
            f"expected={expected_names}; actual={actual_names}"
        )
    return input_shards


def output_name_for(input_name: str) -> str:
    return input_name.replace(".input.jsonl", ".output.jsonl")


def require_plan_shard_dir(plan_path: Path, shard_dir: Path) -> None:
    expected = plan_path.parent / "rank_shards"
    if shard_dir.resolve() != expected.resolve():
        raise SystemExit(
            "Rank shard directory must be the assignment plan's sibling rank_shards "
            f"directory; expected={expected}; actual={shard_dir}"
        )


def require_no_misplaced_rank_shards(plan_path: Path) -> None:
    misplaced = sorted(
        (
            *plan_path.parent.glob(SHARD_INPUT_GLOB),
            *plan_path.parent.glob(SHARD_OUTPUT_GLOB),
        ),
        key=lambda path: path.name,
    )
    if misplaced:
        raise SystemExit(
            "Rank shard artifacts must be stored in the assignment plan's sibling "
            f"rank_shards directory; misplaced={[path.name for path in misplaced]}"
        )


def make_rank_pool_plan(args: argparse.Namespace) -> None:
    if args.usable_worker_slots < 1:
        raise SystemExit("--usable-worker-slots must be at least 1")

    shard_dir = Path(args.shard_dir).expanduser()
    output = Path(args.out).expanduser()
    require_plan_shard_dir(output, shard_dir)
    input_shards = discover_input_shards(shard_dir)
    worker_count = min(len(input_shards), args.usable_worker_slots, RANK_POOL_WORKER_CAP)
    workers: list[dict[str, object]] = []
    for worker_index in range(worker_count):
        assigned_inputs = [path.name for path in input_shards[worker_index::worker_count]]
        workers.append(
            {
                "slot": worker_index + 1,
                "input_shards": assigned_inputs,
                "output_shards": [output_name_for(name) for name in assigned_inputs],
            }
        )

    plan: dict[str, object] = {
        "schema_version": RANK_POOL_PLAN_SCHEMA_VERSION,
        "strategy": RANK_POOL_STRATEGY,
        "shard_count": len(input_shards),
        "ranking_worker_count": worker_count,
        "workers": workers,
    }
    write_json(output, plan)
    print(f"Assigned {len(input_shards)} rank shards to {worker_count} ranking workers in {output}")


def load_rank_pool_plan(plan_path: Path) -> tuple[dict[str, object], bytes]:
    if not plan_path.exists():
        raise SystemExit(f"Rank pool plan missing: {plan_path}")
    plan_bytes = plan_path.read_bytes()
    try:
        payload: object = json.loads(plan_bytes)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{plan_path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{plan_path}: expected a JSON object")
    return {str(key): value for key, value in payload.items()}, plan_bytes


def require_integer(value: object, label: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SystemExit(f"{label} must be an integer of at least {minimum}")
    return value


def require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise SystemExit(f"{label} must be a non-empty list")
    if any(not isinstance(item, str) or not item for item in value):
        raise SystemExit(f"{label} entries must be non-empty strings")
    return [item for item in value if isinstance(item, str)]


def assignment_differences(
    assigned_names: list[str], expected_names: list[str]
) -> tuple[list[str], list[str], list[str]]:
    counts = Counter(assigned_names)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    assigned = set(assigned_names)
    expected = set(expected_names)
    return sorted(expected - assigned), duplicates, sorted(assigned - expected)


def validate_rank_pool_plan(
    plan_path: Path, shard_dir: Path
) -> tuple[list[Path], list[str], list[RankWorkerAssignment], bytes]:
    require_plan_shard_dir(plan_path, shard_dir)
    require_no_misplaced_rank_shards(plan_path)
    input_shards = discover_input_shards(shard_dir)
    input_names = [path.name for path in input_shards]
    output_names = [output_name_for(name) for name in input_names]
    plan, plan_bytes = load_rank_pool_plan(plan_path)
    expected_fields = {
        "schema_version",
        "strategy",
        "shard_count",
        "ranking_worker_count",
        "workers",
    }
    actual_fields = set(plan)
    if actual_fields != expected_fields:
        raise SystemExit(
            f"{plan_path}: rank pool plan fields do not match schema; "
            f"missing={sorted(expected_fields - actual_fields)}; "
            f"unexpected={sorted(actual_fields - expected_fields)}"
        )
    schema_version = require_integer(
        plan["schema_version"], f"{plan_path}: schema_version", minimum=1
    )
    if schema_version != RANK_POOL_PLAN_SCHEMA_VERSION:
        raise SystemExit(f"{plan_path}: schema_version must be {RANK_POOL_PLAN_SCHEMA_VERSION}")
    if plan["strategy"] != RANK_POOL_STRATEGY:
        raise SystemExit(f"{plan_path}: strategy must be {RANK_POOL_STRATEGY}")

    shard_count = require_integer(plan["shard_count"], f"{plan_path}: shard_count", minimum=0)
    if shard_count != len(input_shards):
        raise SystemExit(
            f"{plan_path}: shard_count does not match input shards; "
            f"plan={shard_count}; actual={len(input_shards)}"
        )
    worker_count = require_integer(
        plan["ranking_worker_count"], f"{plan_path}: ranking_worker_count", minimum=0
    )
    if shard_count > 0 and worker_count == 0:
        raise SystemExit(
            f"{plan_path}: ranking_worker_count must be at least 1 when input shards exist"
        )
    if worker_count > shard_count:
        raise SystemExit(f"{plan_path}: ranking_worker_count cannot exceed shard_count")
    if worker_count > RANK_POOL_WORKER_CAP:
        raise SystemExit(f"{plan_path}: ranking_worker_count cannot exceed {RANK_POOL_WORKER_CAP}")

    workers = plan["workers"]
    if not isinstance(workers, list) or len(workers) != worker_count:
        raise SystemExit(
            f"{plan_path}: workers must contain exactly {worker_count} worker assignments"
        )

    assigned_inputs: list[str] = []
    assigned_outputs: list[str] = []
    parsed_workers: list[RankWorkerAssignment] = []
    worker_fields = {"slot", "input_shards", "output_shards"}
    for worker_index, raw_worker in enumerate(workers):
        label = f"{plan_path}: workers[{worker_index}]"
        if not isinstance(raw_worker, dict):
            raise SystemExit(f"{label} must be a JSON object")
        worker = {str(key): value for key, value in raw_worker.items()}
        if set(worker) != worker_fields:
            raise SystemExit(
                f"{label} fields do not match schema; "
                f"missing={sorted(worker_fields - set(worker))}; "
                f"unexpected={sorted(set(worker) - worker_fields)}"
            )
        slot = require_integer(worker["slot"], f"{label}.slot", minimum=1)
        if slot != worker_index + 1:
            raise SystemExit(f"{label}.slot must be {worker_index + 1}")
        worker_inputs = require_string_list(worker["input_shards"], f"{label}.input_shards")
        worker_outputs = require_string_list(worker["output_shards"], f"{label}.output_shards")
        if len(worker_inputs) != len(worker_outputs):
            raise SystemExit(f"{label} input_shards and output_shards lengths must match")
        expected_worker_outputs = [output_name_for(name) for name in worker_inputs]
        if worker_outputs != expected_worker_outputs:
            raise SystemExit(f"{label}.output_shards do not match its input_shards")
        assigned_inputs.extend(worker_inputs)
        assigned_outputs.extend(worker_outputs)
        parsed_workers.append((slot, worker_inputs, worker_outputs))

    missing, duplicates, unexpected = assignment_differences(assigned_inputs, input_names)
    if missing or duplicates or unexpected:
        raise SystemExit(
            f"{plan_path}: pool plan must assign each input shard exactly once; "
            f"missing={missing}; duplicates={duplicates}; unexpected={unexpected}"
        )
    missing, duplicates, unexpected = assignment_differences(assigned_outputs, output_names)
    if missing or duplicates or unexpected:
        raise SystemExit(
            f"{plan_path}: pool plan must assign each output shard exactly once; "
            f"missing={missing}; duplicates={duplicates}; unexpected={unexpected}"
        )

    for worker_index, (_, worker_inputs, worker_outputs) in enumerate(parsed_workers):
        expected_inputs = input_names[worker_index::worker_count]
        expected_outputs = output_names[worker_index::worker_count]
        if worker_inputs != expected_inputs or worker_outputs != expected_outputs:
            raise SystemExit(
                f"{plan_path}: worker slot {worker_index + 1} does not match the deterministic "
                f"{RANK_POOL_STRATEGY} assignment"
            )
    return input_shards, output_names, parsed_workers, plan_bytes


def validate_rank_worker_command(args: argparse.Namespace) -> None:
    plan_path = Path(args.plan).expanduser()
    shard_dir = Path(args.shard_dir).expanduser()
    _, _, workers, plan_bytes = validate_rank_pool_plan(plan_path, shard_dir)

    slot = require_integer(args.slot, "--slot", minimum=1)
    worker_count = len(workers)
    if slot > worker_count:
        raise SystemExit(f"--slot must be at most {worker_count}")

    assigned_slot, input_names, output_names = workers[slot - 1]
    if assigned_slot != slot:
        raise SystemExit(f"{plan_path}: worker assignment for slot {slot} is inconsistent")

    row_count = 0
    outputs_digest = hashlib.sha256()
    for input_name, output_name in zip(input_names, output_names, strict=True):
        input_shard = shard_dir / input_name
        output_shard = shard_dir / output_name
        _, output_rows = validate_rank_shard(input_shard, output_shard)
        output_bytes = output_shard.read_bytes()
        row_count += len(output_rows)
        outputs_digest.update(output_name.encode("utf-8"))
        outputs_digest.update(b"\0")
        outputs_digest.update(output_bytes)
        outputs_digest.update(b"\0")

    receipt: dict[str, object] = {
        "schema_version": 1,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "slot": slot,
        "ranking_worker_count": worker_count,
        "output_shards": len(output_names),
        "rows": row_count,
        "outputs_sha256": outputs_digest.hexdigest(),
        "status": "complete",
    }
    print("RANK_WORKER_RECEIPT " + json.dumps(receipt, sort_keys=True, separators=(",", ":")))


def validate_rank_pool_command(args: argparse.Namespace) -> None:
    plan_path = Path(args.plan).expanduser()
    shard_dir = Path(args.shard_dir).expanduser()
    input_shards, expected_output_names, workers, _ = validate_rank_pool_plan(plan_path, shard_dir)

    actual_output_names = {path.name for path in shard_dir.glob(SHARD_OUTPUT_GLOB)}
    expected_outputs = set(expected_output_names)
    if actual_output_names != expected_outputs:
        missing = sorted(expected_outputs - actual_output_names)
        unexpected = sorted(actual_output_names - expected_outputs)
        raise SystemExit(
            "Rank pool outputs are incomplete; "
            f"missing output shards={missing}; unexpected output shards={unexpected}"
        )

    row_count = 0
    for input_shard in input_shards:
        output_shard = input_shard.with_name(output_name_for(input_shard.name))
        _, shard_outputs = validate_rank_shard(input_shard, output_shard)
        row_count += len(shard_outputs)
    print(
        f"Validated {len(workers)} ranking workers, "
        f"{len(input_shards)} shards, and {row_count} ranking rows"
    )


def validate_rank_shard(
    input_shard: Path, output_shard: Path
) -> tuple[list[JsonRow], list[JsonRow]]:
    shard_inputs = load_jsonl(input_shard, "Rank input shard", validate_rank_input_row)
    require_unique_paths(shard_inputs, f"Rank input shard {input_shard.name}")
    shard_outputs = load_jsonl(output_shard, "Rank output shard", validate_rank_output_row)
    require_unique_paths(shard_outputs, f"Rank output shard {output_shard.name}")

    expected_paths = {str(row["path"]) for row in shard_inputs}
    actual_paths = {str(row["path"]) for row in shard_outputs}
    if expected_paths != actual_paths:
        missing = sorted(expected_paths - actual_paths)
        unknown = sorted(actual_paths - expected_paths)
        raise SystemExit(
            f"{output_shard}: paths do not match its input shard; "
            f"missing={missing}; unknown={unknown}"
        )

    area_by_path = {str(row["path"]): row["area"] for row in shard_inputs}
    for row in shard_outputs:
        row_path = str(row["path"])
        if row["area"] != area_by_path[row_path]:
            raise SystemExit(f"{output_shard}: area does not match rank input for {row_path}")
    return shard_inputs, shard_outputs


def validate_rank_shard_command(args: argparse.Namespace) -> None:
    input_shard = Path(args.input).expanduser()
    output_shard = Path(args.output).expanduser()
    _, output_rows = validate_rank_shard(input_shard, output_shard)
    print(f"Validated {len(output_rows)} ranking rows in {output_shard}")


def merge_rank_outputs(args: argparse.Namespace) -> None:
    rank_input = Path(args.rank_input).expanduser()
    authoritative_rows = load_jsonl(rank_input, "Rank input", validate_rank_input_row)
    require_unique_paths(authoritative_rows, "Rank input")

    shard_dir = Path(args.shard_dir).expanduser()
    input_shards = discover_input_shards(shard_dir)
    output_shards = sorted(shard_dir.glob(SHARD_OUTPUT_GLOB))
    expected_output_names = {
        path.name.replace(".input.jsonl", ".output.jsonl") for path in input_shards
    }
    actual_output_names = {path.name for path in output_shards}
    if expected_output_names != actual_output_names:
        missing = sorted(expected_output_names - actual_output_names)
        unexpected = sorted(actual_output_names - expected_output_names)
        details: list[str] = []
        if missing:
            details.append(f"missing output shards {missing}")
        if unexpected:
            details.append(f"unexpected output shards {unexpected}")
        raise SystemExit(f"Rank shard outputs are incomplete: {'; '.join(details)}")

    sharded_inputs: list[JsonRow] = []
    output_by_path: dict[str, JsonRow] = {}
    for input_shard in input_shards:
        output_shard = input_shard.with_name(
            input_shard.name.replace(".input.jsonl", ".output.jsonl")
        )
        shard_inputs, shard_outputs = validate_rank_shard(input_shard, output_shard)
        sharded_inputs.extend(shard_inputs)
        for row in shard_outputs:
            row_path = str(row["path"])
            if row_path in output_by_path:
                raise SystemExit(f"Rank outputs contain duplicate path: {row_path}")
            output_by_path[row_path] = row

    if sharded_inputs != authoritative_rows:
        raise SystemExit("Rank input shards do not exactly partition the authoritative rank input")

    merged = [output_by_path[str(row["path"])] for row in authoritative_rows]
    output = Path(args.out).expanduser()
    write_jsonl(output, merged)
    print(f"Merged {len(merged)} ranking rows into {output}")


def copy_deep_review_input(args: argparse.Namespace) -> None:
    rank_input = Path(args.rank_input).expanduser()
    rows = load_jsonl(rank_input, "Rank input", validate_rank_input_row)
    require_unique_paths(rows, "Rank input")
    selected = [{"path": row["path"], "area": row["area"]} for row in rows]

    output = Path(args.out).expanduser()
    write_jsonl(output, selected)
    print(f"Copied {len(selected)} rows into {output}")


def select_deep_review_input(args: argparse.Namespace) -> None:
    rank_output = Path(args.rank_output).expanduser()
    rows = load_jsonl(rank_output, "Rank output", validate_rank_output_row)
    require_unique_paths(rows, "Rank output")

    included = [row for row in rows if row["include"]]
    base_rows = included if included else rows
    base_rows.sort(key=lambda row: (-int(row["score"]), str(row["path"])))
    keep = max(1, int(len(base_rows) * (args.top_percent / 100.0))) if base_rows else 0
    selected = [{"path": row["path"], "area": row["area"]} for row in base_rows[:keep]]

    output = Path(args.out).expanduser()
    write_jsonl(output, selected)
    print(f"Selected {len(selected)} of {len(base_rows)} rows into {output}")


def main() -> None:
    args = parse_args()
    if args.command == "make-repo-rank-input":
        make_repo_rank_input(args)
    elif args.command == "make-scope-inventory":
        make_scope_inventory(args)
    elif args.command == "verify-scope-coverage":
        verify_scope_coverage(args)
    elif args.command == "bind-repo-scopes":
        bind_repo_scopes(args)
    elif args.command == "bind-scope-exclusions":
        bind_scope_exclusions(args)
    elif args.command == "make-diff-rank-input":
        make_diff_rank_input(args)
    elif args.command == "make-rank-shards":
        make_rank_shards(args)
    elif args.command == "make-rank-pool-plan":
        make_rank_pool_plan(args)
    elif args.command == "validate-rank-shard":
        validate_rank_shard_command(args)
    elif args.command == "validate-rank-worker":
        validate_rank_worker_command(args)
    elif args.command == "validate-rank-pool":
        validate_rank_pool_command(args)
    elif args.command == "merge-rank-outputs":
        merge_rank_outputs(args)
    elif args.command == "copy-deep-review-input":
        copy_deep_review_input(args)
    elif args.command == "select-deep-review-input":
        select_deep_review_input(args)
    else:
        raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
