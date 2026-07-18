#!/usr/bin/env python3
"""Generate and post-process Codex Security scan worklists.

This script stays deliberately model-free:

- `make-repo-rank-input` creates the deterministic repository or scoped-path
  JSONL candidate worklist that ranking subagents consume.
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
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rank_preview import DEFAULT_PREVIEW_BYTES, TEXT_CODE_EXTENSIONS, preview_for

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
RANK_POOL_PLAN_SCHEMA_VERSION = 1
RANK_POOL_STRATEGY = "round_robin"
RANK_POOL_WORKER_CAP = 6
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
    make.add_argument("--out", required=True, help="Output rank_input.jsonl path.")
    make.add_argument("--area", default="", help="Area label. Defaults to scope.")
    make.add_argument(
        "--preview-bytes",
        type=int,
        default=DEFAULT_PREVIEW_BYTES,
        help=f"Maximum UTF-8 bytes in each preview. Defaults to {DEFAULT_PREVIEW_BYTES}.",
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


def resolve_scope(repo: Path, scope: str) -> Path:
    scope_path = Path(scope).expanduser()
    if not scope_path.is_absolute():
        scope_path = repo / scope_path
    scope_path = scope_path.resolve()
    repo_resolved = repo.resolve()
    try:
        scope_path.relative_to(repo_resolved)
    except ValueError as exc:
        raise SystemExit(f"Scope must be inside repo: {scope_path}") from exc
    if not scope_path.is_dir():
        raise SystemExit(f"Scope path not found: {scope_path}")
    return scope_path


def write_jsonl(output: Path, rows: list[JsonRow]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")


def write_json(output: Path, payload: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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
    scope_abs = resolve_scope(repo, args.scope)
    scope_rel = scope_abs.relative_to(repo).as_posix()
    area = args.area or scope_rel

    rows: list[JsonRow] = []
    for path in scope_abs.rglob("*"):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        rel = path.relative_to(repo)
        if path_is_excluded(rel) or path.suffix.lower() not in TEXT_CODE_EXTENSIONS:
            continue

        preview, is_binary = preview_for(path, args.preview_bytes)
        if is_binary:
            continue
        rows.append({"path": rel.as_posix(), "area": area, "preview": preview})

    rows.sort(key=lambda row: str(row["path"]))
    output = Path(args.out).expanduser()
    write_jsonl(output, rows)
    print(f"Wrote {len(rows)} rows to {output}")


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
