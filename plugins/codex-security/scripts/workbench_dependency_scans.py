"""Dependency scan setup, durable submission, and local package inventory."""

from __future__ import annotations

import argparse
import itertools
import json
import sqlite3
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dependency_scan_reporting import (
    dependency_identity,
    dependency_inventory,
    project_for_chain,
    project_node_id,
)
from workbench_finding_workflows import register_workflow_scan
from workbench_scan_start import (
    archive_scan,
    insert_running_scan,
    scan_diff_identity,
    scan_target_identity,
)
from workbench_target import (
    clean_worktree_content_digest,
    directory_snapshot_regular_file_count,
    worktree_content_digest,
)
from workbench_target_state import ensure_security_target
from workbench_validation import optional_text, reject_non_finite_json, require_uuid


@dataclass(frozen=True)
class WorkbenchDependencyContext:
    """Use the existing workbench validation and projection helpers."""

    scan_contract: Callable[[sqlite3.Row], dict[str, Any]]
    require_target: Callable[[str], Path]
    require_scannable_target: Callable[[Path], None]
    require_canonical_scan_directory: Callable[[Path], Path]
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row]
    require_workspace: Callable[[sqlite3.Connection, str], sqlite3.Row]
    now: Callable[[], str]
    scan_context: Callable[..., dict[str, Any]]
    available_artifact_path: Callable[[Path, Path], Path | None]
    resolve_git_commit: Callable[[Path, str, str], str]
    require_review_changes_target: Callable[[Path], str]


def encoded_model_settings(args: argparse.Namespace) -> str | None:
    """Serialize configured dependency worker settings for durable scan state."""
    value = getattr(args, "model_settings", None)
    if value is None:
        return None
    try:
        parsed = json.loads(value, parse_constant=reject_non_finite_json)
        return json.dumps(parsed, allow_nan=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise SystemExit("Dependency scan model settings must be valid JSON.") from exc


def bind_dependency_job(
    ctx: WorkbenchDependencyContext, connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    """Associate an upstream job with its owning active dependency scan."""
    thread_id = optional_text(args.thread_id, maximum=512)
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = ctx.require_scan(connection, args.scan_id)
        workspace = ctx.require_workspace(connection, scan["workspace_id"])
        owning_thread_id = scan["continuation_thread_id"] or workspace["thread_id"]
        if owning_thread_id is None or owning_thread_id != thread_id:
            raise SystemExit("A dependency scan can only be linked from its owning Codex thread.")
        if scan["status"] != "running" or scan["canceled_at"] or not scan["scan_dependencies"]:
            raise SystemExit(
                "Dependency submission requires a running scan with dependencies enabled."
            )
        if scan["dependency_job_id"] not in {None, args.job_id}:
            raise SystemExit(
                "This Codex Security scan is already linked to another dependency job."
            )
        if scan["dependency_job_id"] is None:
            connection.execute(
                "UPDATE scans SET dependency_job_id = ?, updated_at = ? WHERE id = ?",
                (args.job_id, ctx.now(), scan["id"]),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return ctx.scan_context(connection, scan["id"])


def claim_dependency_submission(
    ctx: WorkbenchDependencyContext, connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    """Record a request before submission and prevent ambiguous retries from creating another job."""
    request = json.loads(args.request_json, parse_constant=reject_non_finite_json)
    request["dependencies"] = sorted(
        request["dependencies"], key=lambda entry: json.dumps(entry, sort_keys=True)
    )
    encoded = json.dumps(request, allow_nan=False, sort_keys=True, separators=(",", ":"))
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = ctx.require_scan(connection, args.scan_id)
        workspace = ctx.require_workspace(connection, scan["workspace_id"])
        owner = scan["continuation_thread_id"] or workspace["thread_id"]
        if owner is None or owner != args.thread_id:
            raise SystemExit(
                "A dependency scan can only be submitted from its owning Codex thread."
            )
        if scan["status"] != "running" or scan["canceled_at"] or not scan["scan_dependencies"]:
            raise SystemExit(
                "Dependency submission requires a running scan with dependencies enabled."
            )
        if scan["dependency_request_json"] is not None:
            if scan["dependency_request_json"] != encoded:
                raise SystemExit("This scan already submitted a different dependency request.")
            if scan["dependency_job_id"] is None:
                raise SystemExit(
                    "A previous dependency submission has no recorded job identifier. Recover and bind that job before retrying; do not submit another job."
                )
        elif scan["dependency_job_id"] is not None:
            raise SystemExit(
                "The existing dependency job has no recorded request. Inspect its progress instead of submitting again."
            )
        else:
            connection.execute(
                "UPDATE scans SET dependency_request_json = ?, updated_at = ? WHERE id = ?",
                (encoded, ctx.now(), scan["id"]),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return ctx.scan_context(connection, scan["id"])


def _cli_scan_recipe_target(
    ctx: WorkbenchDependencyContext, repository: Path, recipe_json: str
) -> tuple[dict[str, Any], dict[str, str] | None]:
    """Resolve the exact local target requested by a CLI launch recipe."""
    recipe = parse_scan_recipe(ctx, recipe_json, repository)
    requested_target = recipe["target"]
    diff_target = None
    if requested_target["kind"] in {"refs", "working_tree"}:
        current_head = ctx.require_review_changes_target(repository)
        base = ctx.resolve_git_commit(repository, requested_target["base"], "Base revision")
        head = ctx.resolve_git_commit(repository, requested_target["head"], "Head revision")
        diff_target = {
            "kind": "range" if requested_target["kind"] == "refs" else "working_tree",
            "baseRevision": base,
            "headRevision": head,
        }
        if requested_target["kind"] == "working_tree":
            if head != current_head:
                raise SystemExit("Working-tree HEAD changed before the scan started.")
            diff_target["contentDigest"] = worktree_content_digest(repository)
    return recipe, diff_target


def inspect_cli_dependencies(
    ctx: WorkbenchDependencyContext, args: argparse.Namespace
) -> dict[str, Any]:
    """Return local dependency target identity without starting a scan."""
    repository = ctx.require_target(args.repository)
    ctx.require_scannable_target(repository)
    recipe, diff_target = _cli_scan_recipe_target(ctx, repository, args.recipe_json)
    revision, snapshot_digest, _, _ = scan_target_identity(repository, diff_target)
    target = {
        "kind": recipe["target"]["kind"],
        "paths": sorted(set(recipe["target"]["paths"])),
    }
    if diff_target is not None:
        target.update(
            base=diff_target["baseRevision"],
            head=diff_target["headRevision"],
        )
        snapshot_digest = diff_target.get("contentDigest")
    elif revision != "unversioned" and snapshot_digest == clean_worktree_content_digest():
        snapshot_digest = None
    return {
        "repository": str(repository),
        "target": target,
        "targetRevision": revision,
        "snapshotDigest": snapshot_digest,
    }


def register_cli_scan(
    ctx: WorkbenchDependencyContext, connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    """Register a CLI scan and preserve its dependency settings and source scope."""
    repository = ctx.require_target(args.repository)
    ctx.require_scannable_target(repository)
    scan_dir = ctx.require_canonical_scan_directory(Path(args.scan_dir).expanduser())
    if scan_dir == repository or repository in scan_dir.parents:
        raise SystemExit("The scan artifact directory must be outside the selected target.")
    if next(scan_dir.iterdir(), None) is not None:
        raise SystemExit("The scan artifact directory must be empty before the scan starts.")

    user_context = None
    workflow_id = None
    if args.registration_json_stdin:
        registration = json.load(sys.stdin)
        recipe_json = json.dumps(registration["recipe"], ensure_ascii=False, separators=(",", ":"))
        user_context = registration.get("userContext")
        workflow_id = registration.get("workflowId")
    else:
        recipe_json = sys.stdin.read() if args.recipe_json_stdin else args.recipe_json
    recipe, diff_target = _cli_scan_recipe_target(ctx, repository, recipe_json)
    paths = recipe["target"]["paths"]
    scope = paths[0] if len(paths) == 1 else "."
    mode = getattr(args, "dependency_mode", None) or (
        "diff" if diff_target is not None else recipe["mode"]
    )
    target_identity = scan_target_identity(repository, diff_target)
    if mode in {"dependency_update", "full_dependency"}:
        scope_file_count = 0
    elif not paths:
        scope_file_count = directory_snapshot_regular_file_count(repository)
    else:
        scope_file_count = sum(
            1
            if (repository / path).is_file()
            else directory_snapshot_regular_file_count(repository / path)
            for path in paths
        )
    parent_scan_id = (
        require_uuid(args.parent_scan_id, "parent-scan-id")
        if args.parent_scan_id is not None
        else None
    )
    timestamp = ctx.now()
    scan_id = str(uuid.uuid4())
    workspace_id = str(uuid.uuid4())

    connection.execute("BEGIN IMMEDIATE")
    try:
        archive_scan(connection, args, scan_dir, timestamp, ctx.require_canonical_scan_directory)
        target_id = ensure_security_target(connection, str(repository))
        if parent_scan_id is not None:
            parent = ctx.require_scan(connection, parent_scan_id)
            if parent["target_id"] != target_id:
                raise SystemExit("A rerun must belong to the same repository as its parent scan.")

        connection.execute(
            """
            INSERT INTO workspaces (
                id, target_id, target_path, target_title, default_scope, default_mode,
                diff_target_kind, diff_base_revision, diff_head_revision,
                diff_content_digest, scan_dependencies, dependency_depth, dependency_scan_target,
                model_settings_json, submitted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                workspace_id,
                target_id,
                str(repository),
                repository.name,
                scope,
                mode,
                *scan_diff_identity(diff_target),
                int(
                    getattr(args, "scan_dependencies", False)
                    or mode in {"dependency_update", "full_dependency"}
                ),
                getattr(args, "dependency_depth", 1),
                getattr(args, "dependency_scan_target", "malware-and-vulnerabilities"),
                encoded_model_settings(args),
                timestamp,
                timestamp,
            ),
        )
        workspace = ctx.require_workspace(connection, workspace_id)
        insert_running_scan(
            connection,
            scan_id=scan_id,
            workspace=workspace,
            target=repository,
            scope=scope,
            diff_target=diff_target,
            target_identity=target_identity,
            target_root=scan_dir.parent,
            target_summary=None,
            scope_file_count=scope_file_count,
            timestamp=timestamp,
            handoff_status="delivered",
            scan_dir=scan_dir,
        )
        connection.execute(
            "UPDATE scans SET recipe_json = ?, parent_scan_id = ?, user_context = ? WHERE id = ?",
            (
                json.dumps(recipe, allow_nan=False, separators=(",", ":"), sort_keys=True),
                parent_scan_id,
                user_context,
                scan_id,
            ),
        )
        if workflow_id is not None:
            register_workflow_scan(connection, workflow_id, scan_id, str(scan_dir), timestamp)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    scan = ctx.require_scan(connection, scan_id)
    return {
        "contract": ctx.scan_contract(scan),
        "scanDir": str(scan_dir),
        "scanId": scan_id,
        "scopeFileCount": scope_file_count,
        "targetId": target_id,
        "targetRevision": scan["target_revision"],
    }


def parse_scan_recipe(
    ctx: WorkbenchDependencyContext, value: str, repository: Path
) -> dict[str, Any]:
    """Validate a saved launch recipe against its local repository."""
    try:
        recipe = json.loads(value, parse_constant=reject_non_finite_json)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise SystemExit("Scan launch recipe must be a valid JSON object.") from exc
    if not isinstance(recipe, dict):
        raise SystemExit("Scan launch recipe must be a JSON object.")
    requested_repository = recipe.get("repository")
    if (
        not isinstance(requested_repository, str)
        or ctx.require_target(requested_repository) != repository
    ):
        raise SystemExit("Scan launch recipe repository must match the scanned repository.")
    if recipe.get("mode") not in {"standard", "deep"}:
        raise SystemExit("Scan launch recipe mode must be standard or deep.")
    if not isinstance(recipe.get("config"), dict):
        raise SystemExit("Scan launch recipe config must be a JSON object.")
    target = recipe.get("target")
    if not isinstance(target, dict) or target.get("kind") not in {
        "repository",
        "paths",
        "refs",
        "working_tree",
    }:
        raise SystemExit("Scan launch recipe target must identify a supported scan target.")
    paths = target.get("paths")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise SystemExit("Scan launch recipe target paths must be an array of strings.")
    if target["kind"] == "paths" and not paths:
        raise SystemExit("A scoped scan launch recipe must include at least one target path.")
    if target["kind"] != "paths" and paths:
        raise SystemExit("Only scoped scan launch recipes can include target paths.")
    for path in paths:
        candidate = PurePosixPath(path)
        if (
            not path
            or candidate.is_absolute()
            or ".." in candidate.parts
            or "\\" in path
            or not (repository / candidate).exists()
            or not (repository / candidate).resolve().is_relative_to(repository)
        ):
            raise SystemExit("Scan launch recipe target paths must exist inside the repository.")
    if target["kind"] in {"refs", "working_tree"}:
        if not isinstance(target.get("base"), str) or not isinstance(target.get("head"), str):
            raise SystemExit("Diff scan launch recipes require resolved base and head revisions.")
    return recipe


def provisional_dependency_inventory(
    ctx: WorkbenchDependencyContext, scan: sqlite3.Row
) -> dict[str, Any] | None:
    """Project only observed package chains while a dependency scan is running."""
    if scan["status"] != "running" or scan["canceled_at"] or not scan["scan_dependencies"]:
        return None

    scan_dir = Path(scan["scan_dir"])
    dependency_dir = scan_dir / "artifacts" / "02_discovery" / "dependency-update-scan"
    discovery_path = ctx.available_artifact_path(
        scan_dir, dependency_dir / "dependency-discovery.json"
    )
    impacts_path = ctx.available_artifact_path(scan_dir, dependency_dir / "dependency-impacts.json")
    if discovery_path is None or impacts_path is None:
        return None

    try:
        discovery = json.loads(
            discovery_path.read_text(encoding="utf-8"),
            parse_constant=reject_non_finite_json,
        )
        impacts = json.loads(
            impacts_path.read_text(encoding="utf-8"),
            parse_constant=reject_non_finite_json,
        )
        if not isinstance(discovery, dict) or not isinstance(impacts, dict):
            return None
        entries = impacts.get("dependencies")
        if not isinstance(entries, list) or not entries:
            return None

        chains_by_identity: list[
            tuple[tuple[str, str, str, str | None, str], dict[str, Any], list[list[str]]]
        ] = []
        for entry in entries:
            if not isinstance(entry, dict):
                return None
            identity = dependency_identity(entry)
            chains = entry.get("dependencyChains")
            if (
                not isinstance(chains, list)
                or not chains
                or any(
                    not isinstance(chain, list)
                    or len(chain) < 2
                    or any(not isinstance(segment, str) or not segment.strip() for segment in chain)
                    or chain[-1] != identity[2]
                    for chain in chains
                )
            ):
                return None
            chains_by_identity.append((identity, entry, chains))

        inventory = dependency_inventory(discovery, impacts, {"packages": []})
        nodes_by_identity = {
            dependency_identity(node): node["id"]
            for node in inventory["nodes"]
            if node["kind"] == "dependency" and "newVersion" in node
        }
        identities_by_chain: dict[tuple[str, str, tuple[str, ...]], set[str]] = {}
        for identity, _, chains in chains_by_identity:
            for chain in chains:
                identities_by_chain.setdefault((identity[0], identity[1], tuple(chain)), set()).add(
                    nodes_by_identity[identity]
                )

        edges: set[tuple[str, str]] = set()
        for identity, entry, chains in chains_by_identity:
            for chain in chains:
                project = project_for_chain(chain[0], entry.get("affectedProjects", []))
                node_ids: list[str | None] = [project_node_id(project)]
                for index in range(1, len(chain) - 1):
                    candidates = identities_by_chain.get(
                        (identity[0], identity[1], tuple(chain[: index + 1])), set()
                    )
                    node_ids.append(next(iter(candidates)) if len(candidates) == 1 else None)
                node_ids.append(nodes_by_identity[identity])
                edges.update(
                    (parent, child)
                    for parent, child in itertools.pairwise(node_ids)
                    if parent is not None and child is not None
                )

        inventory["edges"] = [{"from": parent, "to": child} for parent, child in sorted(edges)]
        return inventory
    except (KeyError, OSError, TypeError, UnicodeError, ValueError):
        return None
