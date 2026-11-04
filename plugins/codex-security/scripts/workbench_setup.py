"""Read-only target and setup inspection shared by the MCP server and workbench."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from deep_scan_config import resolve_deep_scan_setup
from workbench_cli import parse_args
from workbench_constants import DIFF_TARGET_KINDS, EMPTY_GIT_TREE, EMPTY_GIT_TREES, optional_text
from workbench_target import (
    git_bytes,
    git_output,
    git_target_metadata,
    require_git_worktree_head,
    worktree_content_digest,
)


def require_target(value: str) -> Path:
    expanded = Path(value).expanduser()
    if not expanded.is_absolute():
        raise SystemExit("Scan target must be an absolute local directory path.")
    target = expanded.resolve()
    if not target.is_dir():
        raise SystemExit(f"Scan target is not a readable local directory: {target}")
    return target


def inspect_target(target: Path) -> dict[str, Any]:
    return {
        "displayName": target.name,
        "targetMetadata": git_target_metadata(target),
        "targetPath": str(target),
    }


def resolve_git_commit(target: Path, revision: str, label: str) -> str:
    value = optional_text(revision, maximum=512)
    if not value:
        raise SystemExit(f"{label} is required.")
    resolved = git_output(
        target,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{value}^{{commit}}",
    )
    if resolved is None:
        raise SystemExit(f"{label} does not resolve to a local Git commit: {value}")
    return resolved


def require_diff_target(
    target: Path,
    kind: str | None,
    base_revision: str | None,
    head_revision: str | None,
    content_digest: str | None,
) -> dict[str, str]:
    current_head = require_review_changes_target(target)
    if kind not in DIFF_TARGET_KINDS:
        raise SystemExit("Choose which Git changes to review before starting a diff scan.")
    if kind == "working_tree":
        base = resolve_git_commit(target, base_revision or "HEAD", "Working-tree base")
        head = resolve_git_commit(target, head_revision or current_head, "Working-tree HEAD")
        current_digest = worktree_content_digest(target)
        if base != current_head or head != current_head:
            raise SystemExit(
                "Repository HEAD changed after these working-tree changes were selected. "
                "Select Uncommitted changes again."
            )
        if content_digest and content_digest != current_digest:
            raise SystemExit(
                "Working-tree contents changed after they were selected. "
                "Select Uncommitted changes again."
            )
        return {
            "kind": kind,
            "baseRevision": current_head,
            "headRevision": current_head,
            "contentDigest": current_digest,
        }
    if kind == "commit":
        head = resolve_git_commit(target, head_revision or "", "Commit")
        commit = git_bytes(target, "cat-file", "-p", head)
        if commit is None:
            raise SystemExit(f"Commit is not available in the local checkout: {head}")
        parent_line = next(
            (
                line
                for line in commit.split(b"\n\n", 1)[0].splitlines()
                if line.startswith(b"parent ")
            ),
            None,
        )
        if parent_line is None:
            parent = EMPTY_GIT_TREES[git_output(target, "rev-parse", "--show-object-format")]
        else:
            parent = resolve_git_commit(
                target,
                parent_line.removeprefix(b"parent ").decode("ascii").strip(),
                "Commit parent",
            )
        if base_revision and base_revision != parent:
            supplied_base = (
                base_revision
                if base_revision == EMPTY_GIT_TREE
                else resolve_git_commit(target, base_revision, "Commit base")
            )
            if supplied_base != parent:
                raise SystemExit("Commit base revision must match the selected commit's parent.")
        return {"kind": kind, "baseRevision": parent, "headRevision": head}
    base = resolve_git_commit(target, base_revision or "", "Base revision")
    head = resolve_git_commit(target, head_revision or "", "Head revision")
    if base == head:
        raise SystemExit("Base and head revisions must identify different commits.")
    return {"kind": kind, "baseRevision": base, "headRevision": head}


def inspect_setup_values(
    target_path: str,
    scope: str,
    mode: str,
    diff_target_kind: str | None,
    diff_base_revision: str | None,
    diff_head_revision: str | None,
    diff_content_digest: str | None,
) -> dict[str, Any]:
    target = require_target(target_path)
    inspected = require_scannable_target(target)
    normalized_scope = require_scope(scope, mode, target)
    if mode == "diff" and normalized_scope != ".":
        raise SystemExit("Review changes requires the whole target; use scope '.'.")
    if mode != "diff" and any(
        value is not None
        for value in (
            diff_target_kind,
            diff_base_revision,
            diff_head_revision,
            diff_content_digest,
        )
    ):
        raise SystemExit("A Git diff target requires Review changes mode.")
    diff_target = (
        require_diff_target(
            target,
            diff_target_kind,
            diff_base_revision,
            diff_head_revision,
            diff_content_digest,
        )
        if mode == "diff"
        else None
    )
    return {
        "diffTarget": diff_target,
        "scope": normalized_scope,
        "target": inspected,
    }


def require_review_changes_target(target: Path) -> str:
    revision = require_git_worktree_head(target)
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None or not Path(repository_root).samefile(target):
        raise SystemExit(
            "Review changes requires the checked-out Git repository root as the target."
        )
    return revision


def require_scannable_target(target: Path) -> dict[str, Any]:
    inspected = inspect_target(target)
    metadata = inspected["targetMetadata"]
    if metadata["isGit"] and not metadata["isWorktree"]:
        raise SystemExit(
            "Codex Security requires a checked-out worktree, not a bare Git repository."
        )
    return inspected


def require_scope(scope: str, mode: str, target: Path) -> str:
    value = scope if scope.strip() else "."
    requested_scope = Path(value)
    if "\\" in value and (os.name != "nt" or not requested_scope.is_absolute()):
        raise SystemExit("Scan scope must use repository-relative POSIX paths.")
    if ".." in requested_scope.parts:
        raise SystemExit("Scan scope must stay inside the scanned target.")
    try:
        resolved_scope = (
            requested_scope if requested_scope.is_absolute() else target / requested_scope
        ).resolve()
        relative_scope = resolved_scope.relative_to(target)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit("Scan scope must stay inside the scanned target.") from exc
    normalized = relative_scope.as_posix() or "."
    if not normalized.strip():
        normalized = "./" + normalized
    if mode == "deep" and normalized != ".":
        raise SystemExit("Deep Scan is repository-wide and cannot use a scoped path.")
    if not resolved_scope.is_dir():
        raise SystemExit("Scan scope must reference an existing directory inside the target.")
    return normalized


def inspect_selected_setup(args: argparse.Namespace) -> dict[str, Any]:
    inspected = inspect_setup_values(
        args.target_path,
        args.scope,
        args.mode,
        args.diff_target_kind,
        args.diff_base_revision,
        args.diff_head_revision,
        args.diff_content_digest,
    )
    if args.mode == "deep":
        inspected["deepScanConfig"] = resolve_deep_scan_setup(
            os.cpu_count() or 1, args.deep_scan_project_json
        )
    elif args.deep_scan_project_json is not None:
        raise SystemExit("Project Deep Scan settings require Deep Scan mode.")
    return inspected


def inspect_command(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "inspect-target":
        return inspect_target(require_target(args.target_path))
    return inspect_selected_setup(args)


def main() -> None:
    sys.stdin.reconfigure(encoding="utf-8")
    args = parse_args("Codex Security workbench persistence.", inspection_only=True)
    print(json.dumps(inspect_command(args), allow_nan=False, sort_keys=True))
