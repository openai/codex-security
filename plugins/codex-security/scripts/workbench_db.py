#!/usr/bin/env python3
"""Codex Security workbench persistence."""

from __future__ import annotations

import argparse
import csv
import errno
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

try:
    import fcntl as posix_file_lock
except ModuleNotFoundError:  # pragma: no cover
    posix_file_lock = None

try:
    import msvcrt as windows_file_lock
except ModuleNotFoundError:  # pragma: no cover
    windows_file_lock = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deep_scan_workbench as deep_scan
import workbench_native_indexes as native_indexes
import workbench_progress as progress
import workbench_remediation as remediation
import workbench_saved_results as saved_results
import workbench_scan_history as scan_history
import workbench_scan_usage as scan_usage
from filesystem_identity import serialize_filesystem_identity as serialize_filesystem_identity
from filesystem_identity import (
    stored_filesystem_identity_matches as stored_filesystem_identity_matches,
)
from finalize_scan_contract import (
    PRODUCER_NAME,
    ContractError,
    RecoverableContractError,
    _prepare_scan_finalization,
    _write_prepared_scan_finalization,
    csv_cell,
    finalize_scan,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    write_sarif_projection,
    write_scan_local_bytes,
)
from finding_preview import bounded_finding_details
from workbench import handoff
from workbench_cli import parse_args
from workbench_constants import (
    ARTIFACTS,
    CLAIM_LEASE_SECONDS,
    DELIVERED_ACTION_LEASE_SECONDS,
    DIFF_TARGET_KINDS,
    EMPTY_GIT_TREE,
    FINDING_ABSOLUTE_PATH_BYTES,
    FINDING_LEVEL_BYTES,
    FINDING_LOCATION_PATH_BYTES,
    FINDING_LOCATION_ROLE_BYTES,
    FINDING_LOCATIONS_LIMIT,
    FINDING_REMEDIATION_BYTES,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
    FINDINGS_PAGE_MAX,
    FINDINGS_RESULT_LIMIT,
    PATCH_PREVIEW_BYTES,
    SQLITE_RETRY_ATTEMPTS,
)
from workbench_feedback import get_scan_feedback
from workbench_finding_index import index_findings
from workbench_remediation import remediation_claim_is_active
from workbench_scan_start import (
    archive_scan,
    compact_timestamp,
    insert_running_scan,
    safe_segment,
    scan_diff_identity,
    scan_target_identity,
    stored_diff_target,
)
from workbench_schema import (
    MIGRATIONS,
)
from workbench_schema import (
    apply_migrations as apply_schema_migrations,
)
from workbench_schema import (
    sql_statements as sql_statements,
)
from workbench_source_excerpt import finding_source_excerpt, safe_source_path
from workbench_target import (
    clean_worktree_content_digest,
    copy_directory_excluding,
    copy_git_worktree_files,
    directory_content_digest,
    directory_snapshot_regular_file_count,
    git_bytes,
    git_command,
    git_output,
    git_revision,
    git_submodule_paths,
    git_target_metadata,
    git_worktree_context,
    remediation_checkout_snapshot,
    require_git_worktree_head,
    require_remediation_target,
    require_scan_target_identity,
    scan_target_warning,
    worktree_content_digest,
    worktree_content_digest_for_context,
)
from workbench_target_state import backfill_security_targets, ensure_security_target
from workbench_validation import (
    bounded_output_text,
    optional_text,
    parse_scan_cost,
    path_within_scope,
    require_close_note,
    require_occurrence,
    require_uuid,
    sqlite_busy,
    user_context_argument,
)

FINDING_ARTIFACT_DIRECTORIES_LIMIT = 80
FINDING_ARTIFACTS_LIMIT = 40
FINDING_WRITEUP_REPORT_PATH = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")
SCAN_RECIPE_MAX_BYTES = 256 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stale_claim_before(seconds: int = CLAIM_LEASE_SECONDS) -> str:
    return (
        (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    )


def state_dir() -> Path:
    state_dir = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser().resolve()
    codex_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
    return (codex_home / "state" / "plugins" / "codex-security").resolve()


def database_path() -> Path:
    return state_dir() / "workbench.sqlite3"


@contextmanager
def scan_completion_lock(scan_id: str) -> Any:
    lock_dir = state_dir() / "completion-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{require_uuid(scan_id, 'scan-id')}.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
        0o600,
    )
    locked = False
    try:
        acquire_completion_file_lock(descriptor)
        locked = True
        yield
    finally:
        try:
            if locked:
                release_completion_file_lock(descriptor)
        finally:
            os.close(descriptor)


def is_file_lock_contention(error: OSError) -> bool:
    return error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


def acquire_completion_file_lock(descriptor: int) -> None:
    if posix_file_lock is not None:
        posix_file_lock.flock(descriptor, posix_file_lock.LOCK_EX)
        return
    if windows_file_lock is None:
        raise SystemExit("Scan completion requires operating-system file locking support.")

    while os.fstat(descriptor).st_size == 0:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            os.write(descriptor, b"\0")
        except OSError as exc:
            if not is_file_lock_contention(exc):
                raise
            time.sleep(0.05)

    while True:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            windows_file_lock.locking(descriptor, windows_file_lock.LK_NBLCK, 1)
            return
        except OSError as exc:
            if not is_file_lock_contention(exc):
                raise
            time.sleep(0.05)


def release_completion_file_lock(descriptor: int) -> None:
    if posix_file_lock is not None:
        posix_file_lock.flock(descriptor, posix_file_lock.LOCK_UN)
        return
    if windows_file_lock is None:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    windows_file_lock.locking(descriptor, windows_file_lock.LK_UNLCK, 1)


def connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(SQLITE_RETRY_ATTEMPTS):
        connection = sqlite3.connect(path, timeout=5)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            apply_migrations(connection)
            connection.execute("PRAGMA journal_mode = WAL")
            path.chmod(0o600)
            return connection
        except sqlite3.OperationalError as exc:
            connection.close()
            if attempt == SQLITE_RETRY_ATTEMPTS - 1 or not sqlite_busy(exc):
                raise
            time.sleep(0.05 * (2**attempt))
    raise AssertionError("SQLite retry loop exhausted unexpectedly.")


def apply_migrations(connection: sqlite3.Connection) -> None:
    apply_schema_migrations(connection, MIGRATIONS, now, backfill_security_targets)


def require_target(value: str) -> Path:
    expanded = Path(value).expanduser()
    if not expanded.is_absolute():
        raise SystemExit("Scan target must be an absolute local directory path.")
    target = expanded.resolve()
    if not target.is_dir():
        raise SystemExit(f"Scan target is not a readable local directory: {target}")
    return target


def inspect_target(target_path: str) -> dict[str, Any]:
    target = require_target(target_path)
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
            (line for line in commit.splitlines() if line.startswith(b"parent ")),
            None,
        )
        if parent_line is None:
            parent = EMPTY_GIT_TREE
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
    require_scannable_target(target)
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
        "target": inspect_target(str(target)),
    }


def inspect_setup(args: argparse.Namespace) -> dict[str, Any]:
    return inspect_setup_values(
        args.target_path,
        args.scope,
        args.mode,
        args.diff_target_kind,
        args.diff_base_revision,
        args.diff_head_revision,
        args.diff_content_digest,
    )


def require_review_changes_target(target: Path) -> str:
    revision = require_git_worktree_head(target)
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None or Path(repository_root).resolve() != target:
        raise SystemExit(
            "Review changes requires the checked-out Git repository root as the target."
        )
    return revision


def require_scannable_target(target: Path) -> None:
    metadata = git_target_metadata(target)
    if metadata["isGit"] and not metadata["isWorktree"]:
        raise SystemExit(
            "Codex Security requires a checked-out worktree, not a bare Git repository."
        )


def expected_target_kinds(scan: sqlite3.Row) -> list[str]:
    if scan["mode"] == "diff":
        return ["git_diff"]
    if scan["target_revision"] == "unversioned":
        return ["directory_snapshot"]
    if scan["target_snapshot_digest"] is None:
        return ["git_worktree", "git_revision"]
    if scan["target_snapshot_digest"] == clean_worktree_content_digest():
        return ["git_revision"]
    return ["git_worktree"]


def requested_scan_paths(scan: sqlite3.Row) -> list[str]:
    if "recipe_json" in scan.keys() and scan["recipe_json"] is not None:
        recipe = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
        target = recipe["target"]
        if target["kind"] == "paths":
            return target["paths"]
    return [scan["scope"]]


def scan_contract(scan: sqlite3.Row) -> dict[str, Any]:
    target = Path(scan["target_path"])
    target_contract = {
        "allowedKinds": expected_target_kinds(scan),
        "displayName": target.name,
        "targetId": scan["target_id"],
    }
    if (
        scan["mode"] != "diff"
        and scan["target_snapshot_digest"]
        and (
            scan["target_revision"] == "unversioned"
            or scan["target_snapshot_digest"] != clean_worktree_content_digest()
        )
    ):
        target_contract["requiredSnapshotDigest"] = scan["target_snapshot_digest"]
    return {
        "diffTarget": stored_diff_target(scan),
        "scope": {
            "requiredExcludePaths": [],
            "requestedPath": scan["scope"],
            **(
                {"requiredIncludePaths": requested_scan_paths(scan)}
                if scan["mode"] != "diff"
                else {}
            ),
        },
        "target": target_contract,
    }


def expected_coverage_mode(scan: sqlite3.Row) -> str:
    if scan["mode"] == "diff":
        mode = {
            "commit": "commit",
            "range": "branch_diff",
            "working_tree": "working_tree",
        }.get(scan["diff_target_kind"])
        if mode is None:
            raise SystemExit("This migrated diff scan does not have a validated change set.")
        return mode
    if scan["scope"] != "." or (
        "recipe_json" in scan.keys()
        and scan["recipe_json"] is not None
        and json.loads(scan["recipe_json"])["target"]["kind"] == "paths"
    ):
        return "scoped_path"
    return "deep_repository" if scan["mode"] == "deep" else "repository"


def workbench_completion_binding(scan: sqlite3.Row, completed_at: str) -> dict[str, Any]:
    contract = scan_contract(scan)
    target_contract = contract["target"]
    plugin_manifest = read_json_object(
        Path(__file__).resolve().parent.parent / ".codex-plugin" / "plugin.json"
    )
    plugin_version = plugin_manifest.get("version")
    if not isinstance(plugin_version, str) or not plugin_version:
        raise SystemExit("plugin.json: expected a nonempty Codex Security plugin version.")
    target: dict[str, Any] = {
        "targetId": target_contract["targetId"],
        "displayName": target_contract["displayName"],
    }
    if scan["mode"] == "diff":
        target["baseRevision"] = scan["diff_base_revision"]
        target["headRevision"] = scan["diff_head_revision"]
        if scan["diff_target_kind"] == "working_tree" and scan["diff_content_digest"]:
            target["snapshotDigest"] = scan["diff_content_digest"]
    else:
        if scan["target_revision"] != "unversioned":
            target["revision"] = scan["target_revision"]
        if "requiredSnapshotDigest" in target_contract:
            target["snapshotDigest"] = target_contract["requiredSnapshotDigest"]

    scope: dict[str, Any] = {
        "includePaths": requested_scan_paths(scan),
        "excludePaths": contract["scope"]["requiredExcludePaths"],
    }

    return {
        "scanId": scan["id"],
        "startedAt": scan["started_at"],
        "completedAt": completed_at,
        "producer": {"name": PRODUCER_NAME, "version": plugin_version},
        "target": target,
        "allowedTargetKinds": target_contract["allowedKinds"],
        "scope": scope,
        "coverageMode": expected_coverage_mode(scan),
    }


def verify_manifest_binding(scan: sqlite3.Row, manifest: dict[str, Any]) -> None:
    manifest_scan = manifest.get("scan")
    if not isinstance(manifest_scan, dict):
        raise SystemExit("scan-manifest.json scan must be an object.")
    if manifest_scan.get("id") != scan["id"]:
        raise SystemExit("scan-manifest.json scan.id must match the workbench scan ID.")
    target = manifest_scan.get("target")
    if not isinstance(target, dict):
        raise SystemExit("scan-manifest.json scan.target must be an object.")
    expected_contract = scan_contract(scan)
    expected_target = expected_contract["target"]
    if target.get("targetId") != expected_target["targetId"]:
        raise SystemExit("scan-manifest.json targetId must match the workbench target.")
    if target.get("displayName") != expected_target["displayName"]:
        raise SystemExit("scan-manifest.json target displayName must match the workbench target.")
    if target.get("kind") not in expected_target["allowedKinds"]:
        raise SystemExit("scan-manifest.json target kind must match the workbench target.")
    if (
        scan["target_revision"] != "unversioned"
        and target.get("kind") in {"git_worktree", "git_revision"}
        and target.get("revision") != scan["target_revision"]
    ):
        raise SystemExit("scan-manifest.json target revision must match the workbench target.")
    if (
        scan["mode"] != "diff"
        and scan["target_snapshot_digest"] is not None
        and target.get("kind") in {"directory_snapshot", "git_worktree"}
        and target.get("snapshotDigest") != scan["target_snapshot_digest"]
    ):
        raise SystemExit(
            "scan-manifest.json target snapshotDigest must match the workbench target snapshot."
        )
    if scan["mode"] == "diff":
        if not scan["diff_target_kind"]:
            raise SystemExit("This migrated diff scan does not have a validated change set.")
        if target.get("baseRevision") != scan["diff_base_revision"]:
            raise SystemExit(
                "scan-manifest.json target baseRevision must match the workbench diff target."
            )
        if target.get("headRevision") != scan["diff_head_revision"]:
            raise SystemExit(
                "scan-manifest.json target headRevision must match the workbench diff target."
            )
        if (
            scan["diff_target_kind"] == "working_tree"
            and target.get("snapshotDigest") != scan["diff_content_digest"]
        ):
            raise SystemExit(
                "scan-manifest.json target snapshotDigest must match the selected "
                "working-tree contents."
            )
    scope = manifest_scan.get("scope")
    if not isinstance(scope, dict):
        raise SystemExit("scan-manifest.json scan.scope must be an object.")
    include_paths = scope.get("includePaths")
    if not isinstance(include_paths, list):
        raise SystemExit("scan-manifest.json scope includePaths must be an array.")
    if scope.get("excludePaths") != []:
        raise SystemExit(
            "scan-manifest.json scope excludePaths must match the workbench scan scope."
        )
    requested_scope = scan["scope"]
    if scan["mode"] != "diff" and include_paths != requested_scan_paths(scan):
        raise SystemExit("scan-manifest.json scope must match the workbench scan scope.")
    for include_path in include_paths:
        if not isinstance(include_path, str) or not path_within_scope(
            include_path, requested_scope
        ):
            raise SystemExit("scan-manifest.json scope must stay inside the workbench scan scope.")


def require_scope(scope: str, mode: str, target: Path) -> str:
    value = scope.strip() or "."
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
    if mode == "deep" and normalized != ".":
        raise SystemExit("Deep Scan is repository-wide and cannot use a scoped path.")
    if not resolved_scope.is_dir():
        raise SystemExit("Scan scope must reference an existing directory inside the target.")
    return normalized


def require_workspace(connection: sqlite3.Connection, workspace_id: str) -> sqlite3.Row:
    workspace_id = require_uuid(workspace_id, "workspace-id")
    row = connection.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,)).fetchone()
    if row is None:
        raise SystemExit("Codex Security workspace not found. Reopen it to continue.")
    return row


def require_scan(connection: sqlite3.Connection, scan_id: str) -> sqlite3.Row:
    scan_id = resolve_scan_id(connection, scan_id)
    row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise SystemExit("Codex Security scan not found.")
    return row


def resolve_scan_id(connection: sqlite3.Connection, scan_id: str) -> str:
    try:
        return str(uuid.UUID(scan_id))
    except ValueError:
        if len(scan_id) < 8:
            raise SystemExit("Scan ID prefixes must be at least eight characters.") from None
        matches = connection.execute(
            "SELECT id FROM scans WHERE substr(id, 1, ?) = ? LIMIT 2",
            (len(scan_id), scan_id.lower()),
        ).fetchall()
        if not matches:
            raise SystemExit("Codex Security scan not found.") from None
        if len(matches) > 1:
            raise SystemExit(
                f'Scan ID prefix "{scan_id}" matches multiple scans; use a longer prefix.'
            ) from None
        return matches[0]["id"]


def create_workspace(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    workspace_id = require_uuid(args.workspace_id, "workspace-id")
    timestamp = now()
    target_path = optional_text(args.target_path, maximum=4096)
    default_scope = optional_text(args.scope, maximum=4096) or "."
    diff_target_kind = args.diff_target_kind if args.mode == "diff" else None
    diff_base_revision = (
        optional_text(args.diff_base_revision, maximum=512) if args.mode == "diff" else None
    )
    diff_head_revision = (
        optional_text(args.diff_head_revision, maximum=512) if args.mode == "diff" else None
    )
    diff_content_digest = (
        optional_text(args.diff_content_digest, maximum=128) if args.mode == "diff" else None
    )
    if target_path:
        try:
            inspected = inspect_setup_values(
                target_path,
                default_scope,
                args.mode,
                diff_target_kind,
                diff_base_revision,
                diff_head_revision,
                diff_content_digest,
            )
            target_path = inspected["target"]["targetPath"]
            default_scope = inspected["scope"]
            if inspected["diffTarget"]:
                diff_target_kind = inspected["diffTarget"]["kind"]
                diff_base_revision = inspected["diffTarget"]["baseRevision"]
                diff_head_revision = inspected["diffTarget"]["headRevision"]
                diff_content_digest = inspected["diffTarget"].get("contentDigest")
        except SystemExit:
            pass
    with connection:
        target_id = (
            ensure_security_target(connection, target_path) if target_path is not None else None
        )
        connection.execute(
            """
            INSERT INTO workspaces (
                id, thread_id, target_id, target_path, target_title, target_summary,
                default_scope, default_mode,
                user_context, diff_target_kind, diff_base_revision, diff_head_revision,
                diff_content_digest, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_id,
                optional_text(args.thread_id, maximum=512),
                target_id,
                target_path,
                optional_text(args.target_title, maximum=200),
                optional_text(args.target_summary, maximum=2400),
                default_scope,
                args.mode,
                user_context_argument(args),
                diff_target_kind,
                diff_base_revision,
                diff_head_revision,
                diff_content_digest,
                timestamp,
                timestamp,
            ),
        )
    return workspace_state(connection, workspace_id)


def save_workspace(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    workspace = require_workspace(connection, args.workspace_id)
    if workspace["active_scan_id"]:
        raise SystemExit("This workspace already has a scan. Open a new workspace to change setup.")
    inspected = inspect_setup_values(
        args.target_path,
        args.scope,
        args.mode,
        args.diff_target_kind,
        args.diff_base_revision,
        args.diff_head_revision,
        args.diff_content_digest,
    )
    target = Path(inspected["target"]["targetPath"])
    scope = inspected["scope"]
    target_path = str(target)
    target_changed = workspace["target_path"] != target_path
    target_title = target.name if target_changed else workspace["target_title"]
    target_summary = (
        optional_text(args.target_summary, maximum=2400)
        if args.target_summary is not None
        else None
        if target_changed
        else workspace["target_summary"]
    )
    diff_target = inspected["diffTarget"]
    if diff_target and not target_summary:
        target_summary = diff_target_summary(diff_target)
    timestamp = now()
    with connection:
        target_id = ensure_security_target(connection, target_path)
        updated = connection.execute(
            """
            UPDATE workspaces
            SET target_id = ?, target_path = ?, target_title = ?, target_summary = ?, default_scope = ?,
                default_mode = ?, user_context = ?, diff_target_kind = ?,
                diff_base_revision = ?, diff_head_revision = ?, diff_content_digest = ?,
                submitted = 1, updated_at = ?
            WHERE id = ? AND active_scan_id IS NULL
            """,
            (
                target_id,
                target_path,
                target_title,
                target_summary,
                scope,
                args.mode,
                user_context_argument(args),
                diff_target["kind"] if diff_target else None,
                diff_target["baseRevision"] if diff_target else None,
                diff_target["headRevision"] if diff_target else None,
                diff_target.get("contentDigest") if diff_target else None,
                timestamp,
                workspace["id"],
            ),
        )
        if updated.rowcount != 1:
            raise SystemExit(
                "This workspace already has a scan. Open a new workspace to change setup."
            )
    return workspace_state(connection, workspace["id"])


def scan_target_root(scan_root: str | None, target: Path) -> Path:
    root = Path(scan_root).expanduser().resolve() if scan_root else state_dir() / "scans"
    target_root = (root / safe_segment(target.name)).resolve()
    if target_root == target or target in target_root.parents:
        raise SystemExit("The scan artifact directory must be outside the selected target.")
    return target_root


def start_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    workspace_id = require_uuid(args.workspace_id, "workspace-id")
    manages_transaction = not connection.in_transaction
    try:
        workspace = require_workspace(connection, workspace_id)
        if not workspace["submitted"] or not workspace["target_path"]:
            raise SystemExit("Save the Codex Security setup before starting the scan.")
        active = connection.execute(
            """
            SELECT *
            FROM scans
            WHERE workspace_id = ? AND status = 'running' AND canceled_at IS NULL
            """,
            (workspace["id"],),
        ).fetchone()
        if active is not None:
            return workspace_state(connection, workspace["id"])
        workspace_version = workspace["updated_at"]
        scan_id = str(uuid.uuid4())
        timestamp = now()
        target = require_target(workspace["target_path"])
        require_scannable_target(target)
        target_metadata = target.stat()
        scope = require_scope(workspace["default_scope"], workspace["default_mode"], target)
        diff_target = None
        if workspace["default_mode"] == "diff":
            diff_target = require_diff_target(
                target,
                workspace["diff_target_kind"],
                workspace["diff_base_revision"],
                workspace["diff_head_revision"],
                workspace["diff_content_digest"],
            )
        target_summary = (
            workspace["target_summary"] if workspace["default_mode"] == "diff" else None
        )
        if diff_target is not None and not target_summary:
            target_summary = diff_target_summary(diff_target)
        scope_file_count = directory_snapshot_regular_file_count(
            target if scope == "." else target / scope
        )
        target_identity = scan_target_identity(
            target,
            diff_target,
            metadata=target_metadata,
        )
        target_root = scan_target_root(args.scan_root, target)
        target_root.mkdir(parents=True, exist_ok=True)
        if manages_transaction:
            connection.execute("BEGIN IMMEDIATE")
        workspace = require_workspace(connection, workspace_id)
        active = connection.execute(
            """
            SELECT *
            FROM scans
            WHERE workspace_id = ? AND status = 'running' AND canceled_at IS NULL
            """,
            (workspace["id"],),
        ).fetchone()
        if active is not None:
            if manages_transaction:
                connection.commit()
            return workspace_state(connection, workspace["id"])
        if workspace["updated_at"] != workspace_version:
            raise SystemExit("Codex Security setup changed while the scan was starting. Try again.")
        current_target = require_remediation_target(str(target))
        current_target_metadata = current_target.stat()
        if (current_target_metadata.st_dev, current_target_metadata.st_ino) != (
            target_metadata.st_dev,
            target_metadata.st_ino,
        ):
            raise SystemExit(
                "The selected scan target changed while the scan was starting. Try again."
            )
        if workspace["default_mode"] == "deep" and workspace["thread_id"] is not None:
            owned_active_scan = deep_scan.existing_deep_scan_for_target(
                connection,
                workspace["thread_id"],
                str(target),
                scope,
            )
            if owned_active_scan is not None:
                raise SystemExit(
                    "This Codex thread already has an active Deep Scan for the selected "
                    "target and scope. Rejoin that scan instead of starting another one."
                )
        insert_running_scan(
            connection,
            scan_id=scan_id,
            workspace=workspace,
            target=target,
            scope=scope,
            diff_target=diff_target,
            target_identity=target_identity,
            target_root=target_root,
            target_summary=target_summary,
            scope_file_count=scope_file_count,
            timestamp=timestamp,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
        )
        if manages_transaction:
            connection.commit()
    except BaseException:
        if manages_transaction:
            connection.rollback()
        raise
    return workspace_state(connection, workspace["id"])


def start_prompt_only_scan(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    return _start_prompt_driven_scan(connection, args, headless_standard=False)


def start_headless_standard_scan(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    return _start_prompt_driven_scan(connection, args, headless_standard=True)


def _start_prompt_driven_scan(
    connection: sqlite3.Connection, args: argparse.Namespace, *, headless_standard: bool
) -> dict[str, Any]:
    thread_id = optional_text(args.thread_id, maximum=512)
    if thread_id is None:
        raise SystemExit("thread-id is required.")
    inspected = inspect_setup_values(
        args.target_path,
        args.scope,
        args.mode,
        args.diff_target_kind,
        args.diff_base_revision,
        args.diff_head_revision,
        args.diff_content_digest,
    )
    target = Path(inspected["target"]["targetPath"])
    target_path = str(target)
    scope = inspected["scope"]
    diff_target = inspected["diffTarget"]
    user_context = user_context_argument(args)
    target_summary = optional_text(args.target_summary, maximum=2400)
    if diff_target is not None and not target_summary:
        target_summary = diff_target_summary(diff_target)
    scope_file_count = directory_snapshot_regular_file_count(
        target if scope == "." else target / scope
    )
    diff_identity = scan_diff_identity(diff_target)
    target_identity = scan_target_identity(target, diff_target)
    target_root = scan_target_root(args.scan_root, target)

    connection.execute("BEGIN IMMEDIATE")
    try:
        current_target = require_remediation_target(target_path)
        current_diff_target = (
            require_diff_target(
                current_target,
                args.diff_target_kind,
                args.diff_base_revision,
                args.diff_head_revision,
                args.diff_content_digest,
            )
            if args.mode == "diff"
            else None
        )
        if (
            scan_target_identity(current_target, current_diff_target) != target_identity
            or scan_diff_identity(current_diff_target) != diff_identity
        ):
            raise SystemExit(
                "The selected scan target changed while the scan was starting. Try again."
            )
        existing = connection.execute(
            """
            SELECT scans.* FROM scans
            JOIN workspaces ON workspaces.active_scan_id = scans.id
            WHERE workspaces.thread_id = ? AND workspaces.target_path = ?
                AND workspaces.default_scope = ? AND workspaces.default_mode = ?
                AND workspaces.user_context IS ? AND workspaces.target_summary IS ?
                AND workspaces.diff_target_kind IS ? AND workspaces.diff_base_revision IS ?
                AND workspaces.diff_head_revision IS ? AND workspaces.diff_content_digest IS ?
                AND workspaces.submitted = 1 AND scans.target_revision = ?
                AND scans.target_snapshot_digest IS ? AND scans.target_device = ?
                AND scans.target_inode = ? AND scans.status = 'running'
                AND scans.handoff_status = 'delivered'
                AND (
                    (? = 0 AND scans.handoff_claim_token IS NULL)
                    OR (
                        ? = 1 AND scans.handoff_claim_token IS NOT NULL
                        AND scans.continuation_thread_id = ?
                    )
                )
            ORDER BY scans.updated_at DESC, scans.started_at DESC, scans.id LIMIT 1
            """,
            (
                thread_id,
                target_path,
                scope,
                args.mode,
                user_context,
                target_summary,
                *diff_identity,
                *target_identity,
                int(headless_standard),
                int(headless_standard),
                thread_id,
            ),
        ).fetchone()
        if existing is not None:
            connection.commit()
            return {**scan_context(connection, existing["id"]), "startDisposition": "joined"}
        target_root.mkdir(parents=True, exist_ok=True)
        workspace_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        timestamp = now()
        target_id = ensure_security_target(connection, target_path)
        connection.execute(
            """
            INSERT INTO workspaces (
                id, thread_id, target_id, target_path, target_title, target_summary, default_scope,
                default_mode, user_context, diff_target_kind, diff_base_revision,
                diff_head_revision, diff_content_digest, submitted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                workspace_id,
                thread_id,
                target_id,
                target_path,
                target.name,
                target_summary,
                scope,
                args.mode,
                user_context,
                *diff_identity,
                timestamp,
                timestamp,
            ),
        )
        workspace = require_workspace(connection, workspace_id)
        insert_running_scan(
            connection,
            scan_id=scan_id,
            workspace=workspace,
            target=target,
            scope=scope,
            diff_target=diff_target,
            target_identity=target_identity,
            target_root=target_root,
            target_summary=target_summary,
            scope_file_count=scope_file_count,
            timestamp=timestamp,
            handoff_status="delivered",
            model=args.model,
            reasoning_effort=args.reasoning_effort,
        )
        if headless_standard:
            claimed = connection.execute(
                """
                UPDATE scans
                SET handoff_claim_token = ?, continuation_thread_id = ?
                WHERE id = ? AND status = 'running' AND handoff_status = 'delivered'
                    AND handoff_claim_token IS NULL AND continuation_thread_id IS NULL
                """,
                (str(uuid.uuid4()), thread_id, scan_id),
            )
            if claimed.rowcount != 1:
                raise SystemExit("Codex Security headless scan ownership could not be recorded.")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {**scan_context(connection, scan_id), "startDisposition": "created"}


def scan_local_file_digest(scan_dir: Path, relative_path: str) -> str:
    digest = hashlib.sha256()
    with open_scan_local_file(scan_dir, relative_path) as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def published_manifest_digest(scan_dir: Path, manifest: dict[str, Any]) -> str:
    canonical = (json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    expected = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    actual = scan_local_file_digest(scan_dir, ARTIFACTS["manifest"])
    if actual != expected:
        raise SystemExit("The sealed scan manifest changed while it was being published.")
    return expected


def require_recorded_manifest_digest(scan: sqlite3.Row, scan_dir: Path) -> None:
    expected = scan["seal_manifest_digest"]
    if expected is None:
        return
    if scan_local_file_digest(scan_dir, ARTIFACTS["manifest"]) != expected:
        raise SystemExit("The sealed scan manifest changed after completion.")


def pin_legacy_manifest_digest(
    connection: sqlite3.Connection, scan_id: str, manifest_digest: str
) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = require_scan(connection, scan_id)
        current = scan["seal_manifest_digest"]
        if current is not None and current != manifest_digest:
            raise SystemExit("The sealed scan manifest changed after completion.")
        if current is None:
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
                (manifest_digest, scan["id"]),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def complete_scan(
    connection: sqlite3.Connection, args: argparse.Namespace, *, prepare_only: bool = False
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    cost_json = None if prepare_only else parse_scan_cost(args.cost_json)
    with scan_completion_lock(scan_id):
        return complete_scan_locked(
            connection,
            scan_id,
            args.claim_token,
            cost_json,
            prepare_only=prepare_only,
            thread_id=getattr(args, "thread_id", None),
        )


def complete_budget_exhausted_scan(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    cost_json = parse_scan_cost(args.cost_json)
    if cost_json is None:
        raise SystemExit("Budget-exhausted scan completion requires the measured scan cost.")
    with scan_completion_lock(scan_id):
        scan = require_scan(connection, scan_id)
        if scan["status"] != "running" or scan["mode"] != "deep" or scan["recipe_json"] is None:
            raise SystemExit("Only a running CLI Deep Scan can complete after its cost limit.")
        recipe = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
        if not isinstance(recipe, dict) or recipe.get("mode") != "deep":
            raise SystemExit("Budget-exhausted scan completion requires a Deep Scan launch recipe.")
        cost = json.loads(cost_json)
        measured = cost.get("cost", cost)
        limit = recipe.get("maxCostUsd")
        if (
            not isinstance(limit, (int, float))
            or isinstance(limit, bool)
            or not isinstance(measured, dict)
            or measured.get("estimatedUsd", 0) <= limit
        ):
            raise SystemExit("Deep Scan has not exceeded its configured cost limit.")
        run = connection.execute(
            "SELECT status, terminal_reason, manifest_path FROM deep_scan_runs WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        if (
            run is None
            or run["status"] != "succeeded"
            or run["terminal_reason"] not in {"saturated", "capped"}
            or not run["manifest_path"]
        ):
            raise SystemExit(
                "Budget-exhausted scan completion requires successfully completed Deep Scan "
                "discovery."
            )
        scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
        candidates = (
            []
            if run["manifest_path"] == str(scan_dir / "scan-manifest.json")
            else budget_exhausted_candidates(scan, scan_dir)
        )
        warning = optional_text(args.message, maximum=2400)
        if warning is None:
            warning = (
                f"Deep Scan reached its cost limit after an estimated "
                f"${measured['estimatedUsd']:.6g}; completed discovery was preserved."
            )
        budget_exhausted_draft(scan, scan_dir, candidates, warning)
        warnings = json.loads(scan["completion_warnings_json"])
        if warning not in warnings:
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ? AND status = 'running'",
                (json.dumps([*warnings, warning]), scan_id),
            )
            connection.commit()
        return complete_scan_locked(connection, scan_id, None, cost_json)


def budget_exhausted_candidates(scan: sqlite3.Row, scan_dir: Path) -> list[dict[str, Any]]:
    artifacts = deep_scan.canonical_discovery_artifacts(scan)
    ledger = Path(artifacts["candidateLedgerPath"])
    try:
        inventory = Path(artifacts["inScopeFilesPath"])
        inventory_descriptor = open_scan_local_file_descriptor(
            scan_dir,
            inventory.relative_to(scan_dir).as_posix(),
            "Canonical Deep Scan in-scope inventory",
        )
        with os.fdopen(inventory_descriptor, "rb") as source:
            lines = re.split(r"\r?\n", source.read().decode("utf-8"))
            in_scope = {re.sub(r"^(?:\./)+", "", line) for line in lines if line}
        descriptor = open_scan_local_file_descriptor(
            scan_dir,
            ledger.relative_to(scan_dir).as_posix(),
            "Canonical Deep Scan candidate ledger",
        )
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            candidates = [
                json.loads(line, parse_constant=reject_non_finite_json)
                for line in source
                if line.strip()
            ]
    except (ContractError, OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"Canonical Deep Scan candidate ledger is invalid: {exc}") from exc

    candidate_ids: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise SystemExit("Canonical Deep Scan candidate ledger rows must be objects.")
        candidate_id = candidate.get("candidate_id")
        locations = candidate.get("locations")
        if (
            not isinstance(candidate_id, str)
            or not candidate_id.strip()
            or candidate_id in {".", ".."}
            or "/" in candidate_id
            or "\\" in candidate_id
            or candidate_id in candidate_ids
            or not isinstance(candidate.get("summary"), str)
            or not candidate["summary"].strip()
            or not isinstance(candidate.get("evidence"), str)
            or not candidate["evidence"].strip()
            or not isinstance(locations, list)
            or not locations
        ):
            raise SystemExit("Canonical Deep Scan candidate ledger contains an invalid candidate.")
        candidate_ids.add(candidate_id)
        for location in locations:
            if not isinstance(location, dict):
                raise SystemExit("Canonical Deep Scan candidate location must be an object.")
            path = location.get("path")
            if (
                not isinstance(path, str)
                or not path
                or "\\" in path
                or "\x00" in path
                or re.match(r"^[A-Za-z]:", path)
                or PurePosixPath(path).is_absolute()
                or any(part in {".", "..", ""} for part in path.split("/"))
            ):
                raise SystemExit(
                    "Canonical Deep Scan candidate location must be repository-relative."
                )
        if not any(location["path"] in in_scope for location in locations):
            raise SystemExit(
                "Canonical Deep Scan candidate must include a location in its in-scope inventory."
            )
    return candidates


def budget_exhausted_draft(
    scan: sqlite3.Row,
    scan_dir: Path,
    candidates: list[dict[str, Any]],
    warning: str,
) -> None:
    documents: dict[str, dict[str, Any]] = {}
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        path = artifact_path(scan_dir, name, required=False)
        if path is not None:
            documents[name] = read_json_object(path)
    if documents and len(documents) != 3:
        raise SystemExit("Budget-exhausted scan contains an incomplete canonical scan draft.")

    if documents:
        manifest = documents["scan-manifest.json"]
        findings = documents["findings.json"]
        coverage = documents["coverage.json"]
        if not isinstance(manifest.get("scan"), dict) or not isinstance(
            findings.get("findings"), list
        ):
            raise SystemExit("Budget-exhausted scan contains an invalid canonical scan draft.")
        for key in ("surfaces", "explicitExclusions", "deferred"):
            if not isinstance(coverage.get(key), list):
                raise SystemExit("Budget-exhausted scan contains invalid canonical coverage.")
        if manifest["scan"].get("sealedAt") is not None or manifest["scan"].get("artifacts"):
            raise SystemExit("Budget-exhausted scan cannot replace an already sealed scan draft.")
    else:
        contract = scan_contract(scan)
        target_contract = contract["target"]
        target: dict[str, Any] = {
            "kind": target_contract["allowedKinds"][0],
            "targetId": target_contract["targetId"],
            "displayName": target_contract["displayName"],
        }
        if scan["target_revision"] != "unversioned":
            target["revision"] = scan["target_revision"]
        if "requiredSnapshotDigest" in target_contract:
            target["snapshotDigest"] = target_contract["requiredSnapshotDigest"]
        manifest = {
            "scan": {
                "target": target,
                "scope": {"limitations": [warning], "validationMode": "incomplete"},
            }
        }
        findings = {"findings": []}
        coverage = {
            "completeness": "partial",
            "inventoryStrategy": (
                "scoped_path" if expected_coverage_mode(scan) == "scoped_path" else "repository"
            ),
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        }

    findings_by_candidate = {
        candidate_id
        for finding in findings["findings"]
        if isinstance(finding, dict)
        and isinstance(candidate_id := finding_candidate_id(finding), str)
    }
    existing_deferred = {
        item.get("candidateId", item.get("id"))
        for item in coverage["deferred"]
        if isinstance(item, dict)
        and isinstance(item.get("candidateId", item.get("id")), str)
    }
    existing_surfaces = {
        item.get("id")
        for item in coverage["surfaces"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        if candidate_id in findings_by_candidate or candidate_id in existing_deferred:
            continue
        paths = list(dict.fromkeys(location["path"] for location in candidate["locations"]))
        surface_id = f"candidate-{candidate_id}"
        validation = candidate.get("validation")
        validation = validation.get("disposition") if isinstance(validation, dict) else None
        attack = candidate.get("attack_path")
        attack = attack.get("decision") if isinstance(attack, dict) else None
        disposition = (
            "needs_follow_up"
            if validation == "deferred" or attack == "deferred"
            else "not_applicable"
            if validation == "not_applicable"
            else "rejected"
            if validation == "suppressed" or attack == "ignore"
            else "needs_follow_up"
        )
        if surface_id not in existing_surfaces:
            coverage["surfaces"].append(
                {
                    "id": surface_id,
                    "label": candidate["summary"],
                    "disposition": disposition,
                    "notes": candidate["evidence"],
                    "receiptRefs": [],
                }
            )
            existing_surfaces.add(surface_id)
        if disposition != "needs_follow_up":
            continue
        coverage["deferred"].append(
            {
                "id": candidate_id,
                "candidateId": candidate_id,
                "reason": (
                    "Validation was deferred because the scan reached its cost limit: "
                    f"{candidate['summary']}. Evidence: {candidate['evidence']}"
                ),
                "paths": paths,
                "surfaceIds": [surface_id],
            }
        )
    if not any(
        isinstance(item, dict)
        and isinstance(reason := item.get("reason"), str)
        and (
            reason == "Validation was deferred because the scan reached its cost limit."
            or reason.startswith(
                "Validation was deferred because the scan reached its cost limit: "
            )
        )
        for item in coverage["deferred"]
    ):
        coverage["deferred"].append(
            {
                "id": "scan-cost-limit",
                "reason": "Validation was deferred because the scan reached its cost limit.",
            }
        )
    coverage["completeness"] = "partial"
    for name, payload in (
        ("findings.json", findings),
        ("coverage.json", coverage),
        ("scan-manifest.json", manifest),
    ):
        try:
            write_scan_local_bytes(
                scan_dir,
                name,
                (json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n").encode(),
            )
        except (ContractError, OSError, TypeError, ValueError) as exc:
            raise SystemExit(f"Budget-exhausted scan draft could not be saved: {exc}") from exc


def complete_scan_locked(
    connection: sqlite3.Connection,
    scan_id: str,
    claim_token: str | None,
    cost_json: str | None,
    *,
    prepare_only: bool = False,
    thread_id: str | None = None,
) -> dict[str, Any]:
    scan = require_scan(connection, scan_id)
    if scan["status"] == "complete":
        scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
        require_recorded_manifest_digest(scan, scan_dir)
        verify_manifest_binding(scan, read_json_object(scan_dir / ARTIFACTS["manifest"]))
        try:
            manifest, _, _ = finalize_scan(
                scan_dir,
                expected_coverage_mode=expected_coverage_mode(scan),
            )
        except ContractError as exc:
            raise SystemExit(str(exc)) from exc
        verify_manifest_binding(scan, manifest)
        manifest_digest = published_manifest_digest(scan_dir, manifest)
        pin_legacy_manifest_digest(connection, scan["id"], manifest_digest)
        if cost_json is not None and scan["recipe_json"] is not None:
            scan_usage.reconcile_completed_scan_cost(connection, scan, cost_json)
        return scan_context(connection, scan["id"])
    if scan["status"] != "running":
        raise SystemExit("Only a running scan can be completed.")
    handoff.require_current_continuation(
        scan,
        claim_token,
        error_message="Scan completion is owned by another continuation.",
    )
    deep_scan.require_deep_scan_ready_for_parent_completion(connection, scan)
    warnings = json.loads(scan["completion_warnings_json"])
    target_warnings: list[str] = []

    def add_warning() -> None:
        if (warning := scan_target_warning(scan)) is not None:
            for items in (target_warnings, warnings):
                if warning not in items:
                    items.append(warning)

    add_warning()
    scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
    completion_timestamp = now()
    completion_binding = workbench_completion_binding(scan, completion_timestamp)
    current_manifest_path = artifact_path(scan_dir, ARTIFACTS["manifest"], required=False)
    if current_manifest_path is not None:
        current_manifest = read_json_object(current_manifest_path)
        if (
            isinstance(current_manifest.get("scan"), dict)
            and current_manifest["scan"].get("complete") is False
        ):
            raise SystemExit(
                "The latest saved scan draft is incomplete; continue the scan before completing it."
            )
    already_sealed = (
        current_manifest_path is not None
        and isinstance(current_manifest.get("scan"), dict)
        and (
            current_manifest["scan"].get("sealedAt") is not None
            or current_manifest["scan"].get("artifacts") is not None
        )
    )
    if scan["recipe_json"] is not None:
        draft_artifacts: dict[str, Path] = {}
        missing_drafts = []
        for file_name in (
            ARTIFACTS["manifest"],
            ARTIFACTS["findings"],
            ARTIFACTS["coverage"],
        ):
            try:
                (scan_dir / file_name).lstat()
            except FileNotFoundError:
                missing_drafts.append(file_name)
                continue
            draft_path = artifact_path(scan_dir, file_name, required=True)
            if draft_path is not None:
                draft_artifacts[file_name] = draft_path
        if missing_drafts:
            raise SystemExit(
                "Scan agent did not create required draft artifacts: "
                f"{', '.join(missing_drafts)}. Check that the scan agent can run shell "
                "commands and write to the scan directory before retrying."
            )
        manifest = read_json_object(draft_artifacts[ARTIFACTS["manifest"]])
        manifest_scan = manifest.get("scan")
        if isinstance(manifest_scan, dict) and manifest_scan.get("sealedAt") is not None:
            completion_binding["startedAt"] = manifest_scan.get("startedAt")
            completion_binding["completedAt"] = manifest_scan.get("completedAt")
    wrote = False
    try:
        prepared = _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=expected_coverage_mode(scan),
            completion_binding=completion_binding,
            completion_warnings=warnings,
            draft_documents=saved_results.merge_saved_results(
                scan_dir,
                scan["id"],
                completion_binding,
                connection.execute(
                    "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
                    (scan["id"],),
                ).fetchall(),
                warnings,
                stopped=False,
                reason="",
            )
            if current_manifest_path is not None and not already_sealed
            else None,
        )
        add_warning()
        wrote = True
        manifest, findings, _ = _write_prepared_scan_finalization(prepared)
    except ContractError as exc:
        if wrote or (
            scan["mode"] == "deep" and not isinstance(exc, RecoverableContractError)
        ):
            args = argparse.Namespace(claim_token=claim_token, cost_json=cost_json)
            args.message, args.scan_id = str(exc), scan_id
            fail_scan_locked(connection, args)
        raise SystemExit(str(exc)) from exc
    artifacts = {
        kind: artifact_path(scan_dir, filename, required=True)
        for kind, filename in ARTIFACTS.items()
    }
    manifest_digest = published_manifest_digest(scan_dir, manifest)
    if prepare_only:
        connection.execute("BEGIN IMMEDIATE")
        try:
            updated = connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ? AND status = 'running'",
                (json.dumps(warnings), scan["id"]),
            )
            if updated.rowcount != 1:
                raise SystemExit("Only a running scan can be prepared for completion.")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        context = scan_context(connection, scan["id"])
        context["targetWarnings"] = target_warnings
        return context

    if cost_json is None:
        measured_usage = scan_usage.collect_scan_usage(
            connection,
            scan,
            thread_id=thread_id,
            completed_at=completion_timestamp,
        )
        cost_json = parse_scan_cost(scan_usage.measured_scan_cost_json(measured_usage))
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = manifest["scan"]["completedAt"]
        scan = require_scan(connection, scan["id"])
        if scan["status"] == "complete":
            connection.commit()
            return scan_context(connection, scan["id"])
        if scan["status"] != "running":
            raise SystemExit("Only a running scan can be completed.")
        deep_scan.require_deep_scan_ready_for_parent_completion(connection, scan)
        handoff.require_current_continuation(
            scan,
            claim_token,
            error_message="Scan completion is owned by another continuation.",
        )
        connection.execute("DELETE FROM scan_artifacts WHERE scan_id = ?", (scan["id"],))
        for kind, path in artifacts.items():
            if path is not None:
                connection.execute(
                    "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
                    (scan["id"], kind, str(path), timestamp),
                )
        connection.execute("DELETE FROM finding_occurrences WHERE scan_id = ?", (scan["id"],))
        index_findings(connection, scan["id"], findings, timestamp)
        finding_count = len(findings.get("findings", []))
        connection.execute(
            """
            UPDATE scan_progress
            SET reportable_findings_count = ?, phase_items_total = ?,
                phase_items_completed = ?, phase_progress_unit = 'report_artifacts',
                updated_at = ?
            WHERE scan_id = ?
            """,
            (finding_count, len(artifacts), len(artifacts), timestamp, scan["id"]),
        )
        updated = connection.execute(
            """
            UPDATE scans
            SET status = 'complete', phase = 'reporting', completed_at = ?, updated_at = ?,
                seal_manifest_digest = ?, cost_json = ?, completion_warnings_json = ?
            WHERE id = ? AND status = 'running'
            """,
            (
                timestamp,
                timestamp,
                manifest_digest,
                cost_json,
                json.dumps(warnings),
                scan["id"],
            ),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can be completed.")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    context = scan_context(connection, scan["id"])
    context["targetWarnings"] = target_warnings
    return context


def register_cli_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    repository = require_target(args.repository)
    require_scannable_target(repository)
    scan_dir = require_canonical_scan_directory(Path(args.scan_dir).expanduser())
    if scan_dir == repository or repository in scan_dir.parents:
        raise SystemExit("The scan artifact directory must be outside the selected target.")
    if next(scan_dir.iterdir(), None) is not None:
        raise SystemExit("The scan artifact directory must be empty before the scan starts.")

    user_context = None
    if args.registration_json_stdin:
        registration = json.load(sys.stdin)
        recipe_json = json.dumps(registration["recipe"], ensure_ascii=False, separators=(",", ":"))
        user_context = registration.get("userContext")
    else:
        recipe_json = sys.stdin.read() if args.recipe_json_stdin else args.recipe_json
    recipe = parse_scan_recipe(recipe_json, repository)
    requested_target = recipe["target"]
    paths = requested_target["paths"]
    scope = paths[0] if len(paths) == 1 else "."
    diff_target = None
    if requested_target["kind"] in {"refs", "working_tree"}:
        current_head = require_review_changes_target(repository)
        base = resolve_git_commit(repository, requested_target["base"], "Base revision")
        head = resolve_git_commit(repository, requested_target["head"], "Head revision")
        diff_target = {
            "kind": "range" if requested_target["kind"] == "refs" else "working_tree",
            "baseRevision": base,
            "headRevision": head,
        }
        if requested_target["kind"] == "working_tree":
            if head != current_head:
                raise SystemExit("Working-tree HEAD changed before the scan started.")
            diff_target["contentDigest"] = worktree_content_digest(repository)
    mode = "diff" if diff_target is not None else recipe["mode"]
    target_identity = scan_target_identity(repository, diff_target)
    scope_file_count = (
        directory_snapshot_regular_file_count(repository)
        if not paths
        else sum(
            1
            if (repository / path).is_file()
            else directory_snapshot_regular_file_count(repository / path)
            for path in paths
        )
    )
    parent_scan_id = (
        require_uuid(args.parent_scan_id, "parent-scan-id")
        if args.parent_scan_id is not None
        else None
    )
    timestamp = now()
    scan_id = str(uuid.uuid4())
    workspace_id = str(uuid.uuid4())

    connection.execute("BEGIN IMMEDIATE")
    try:
        archive_scan(connection, args, scan_dir, timestamp, require_canonical_scan_directory)
        target_id = ensure_security_target(connection, str(repository))
        if parent_scan_id is not None:
            parent = require_scan(connection, parent_scan_id)
            if parent["target_id"] != target_id:
                raise SystemExit("A rerun must belong to the same repository as its parent scan.")

        connection.execute(
            """
            INSERT INTO workspaces (
                id, target_id, target_path, target_title, default_scope, default_mode,
                diff_target_kind, diff_base_revision, diff_head_revision,
                diff_content_digest, submitted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                workspace_id,
                target_id,
                str(repository),
                repository.name,
                scope,
                mode,
                *scan_diff_identity(diff_target),
                timestamp,
                timestamp,
            ),
        )
        workspace = require_workspace(connection, workspace_id)
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
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    scan = require_scan(connection, scan_id)
    return {
        "contract": scan_contract(scan),
        "scanDir": str(scan_dir),
        "scanId": scan_id,
        "scopeFileCount": scope_file_count,
        "targetId": target_id,
        "targetRevision": scan["target_revision"],
    }


def set_scan_thread(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan = require_scan(connection, args.scan_id)
    with connection:
        connection.execute(
            "UPDATE scans SET continuation_thread_id = ?, updated_at = ? WHERE id = ?",
            (args.thread_id, now(), scan["id"]),
        )
    return {"scanId": scan["id"], "threadId": args.thread_id}


def parse_scan_recipe(value: str, repository: Path) -> dict[str, Any]:
    if len(value.encode("utf-8")) > SCAN_RECIPE_MAX_BYTES:
        raise SystemExit("Scan launch recipe must be no larger than 256 KiB.")
    try:
        recipe = json.loads(value, parse_constant=reject_non_finite_json)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise SystemExit("Scan launch recipe must be a valid JSON object.") from exc
    if not isinstance(recipe, dict):
        raise SystemExit("Scan launch recipe must be a JSON object.")
    requested_repository = recipe.get("repository")
    if (
        not isinstance(requested_repository, str)
        or require_target(requested_repository) != repository
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


def get_scan_recipe(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan = require_scan(connection, args.scan_id)
    if scan["recipe_json"] is None:
        raise SystemExit("This scan does not have a saved launch recipe.")
    return {
        "parentScanId": scan["parent_scan_id"],
        "recipe": json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json),
        "scanId": scan["id"],
    }


_WORKBENCH_DB_CONTEXT: saved_results.WorkbenchDbContext


def coverage_for_comparison(scan: sqlite3.Row) -> dict[str, Any]:
    return saved_results.coverage_for_comparison(_WORKBENCH_DB_CONTEXT, scan)


def preserve_scan_results_locked(connection: sqlite3.Connection, scan_id: str) -> bool:
    return saved_results.preserve_scan_results_locked(_WORKBENCH_DB_CONTEXT, connection, scan_id)


def refresh_stopped_scan_results(
    connection: sqlite3.Connection, scan_id: str, *, strict: bool = False
) -> None:
    saved_results.refresh_stopped_scan_results(
        _WORKBENCH_DB_CONTEXT, connection, scan_id, strict=strict
    )


def refresh_all_stopped_scan_results(connection: sqlite3.Connection) -> None:
    scan_ids = [
        row["id"] for row in connection.execute("SELECT id FROM scans WHERE status = 'failed'")
    ]
    for scan_id in scan_ids:
        refresh_stopped_scan_results(connection, scan_id)


def preserve_scan_results(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    return saved_results.preserve_scan_results(_WORKBENCH_DB_CONTEXT, connection, args)


def write_scan_draft(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    return saved_results.write_scan_draft(_WORKBENCH_DB_CONTEXT, connection, args)


def fail_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    return saved_results.fail_scan(_WORKBENCH_DB_CONTEXT, connection, args)


def fail_scan_locked(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    return saved_results.fail_scan_locked(_WORKBENCH_DB_CONTEXT, connection, args)


def cancel_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    return saved_results.cancel_scan(_WORKBENCH_DB_CONTEXT, connection, args)


def cancel_scan_locked(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    return saved_results.cancel_scan_locked(_WORKBENCH_DB_CONTEXT, connection, args)


def preserve_stopped_results_after_transition(connection: sqlite3.Connection, scan_id: str) -> None:
    saved_results.preserve_stopped_results_after_transition(
        _WORKBENCH_DB_CONTEXT, connection, scan_id
    )


def set_finding_triage(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    close_reason = args.close_reason
    if args.status == "open" and close_reason is not None:
        raise SystemExit("An open finding cannot keep a close reason.")
    if args.status == "closed" and close_reason is None:
        raise SystemExit("Choose why this finding is being closed.")
    note = optional_text(args.note, maximum=2400)
    require_close_note(close_reason, note)
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        if args.status == "closed":
            remediation = connection.execute(
                """
                SELECT *
                FROM finding_remediation_attempts
                WHERE occurrence_id = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1
                """,
                (occurrence["id"],),
            ).fetchone()
            if (
                remediation is not None
                and remediation["pending_action"] is not None
                and not (
                    remediation["state"] == "failed"
                    and not remediation_claim_is_active(remediation)
                )
            ):
                raise SystemExit(
                    "Wait for the pending remediation operation to finish before closing this finding."
                )
            if (
                close_reason == "already_fixed"
                and remediation is not None
                and remediation["state"] == "verified"
            ):
                scan = require_scan(connection, occurrence["scan_id"])
                require_remediation_checkout_unchanged(
                    scan,
                    remediation,
                    require_applied_content=True,
                )
        previous_triage = connection.execute(
            "SELECT status, close_reason, note FROM finding_triage WHERE occurrence_id = ?",
            (occurrence["id"],),
        ).fetchone()
        if previous_triage is None or (
            previous_triage["status"],
            previous_triage["close_reason"],
            previous_triage["note"],
        ) != (args.status, close_reason, note):
            connection.execute(
                """
                INSERT INTO finding_decisions (
                    id, occurrence_id, status, close_reason, note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), occurrence["id"], args.status, close_reason, note, timestamp),
            )
        connection.execute(
            """
            INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(occurrence_id) DO UPDATE SET
                status = excluded.status,
                close_reason = excluded.close_reason,
                note = excluded.note,
                updated_at = excluded.updated_at
            """,
            (occurrence["id"], args.status, close_reason, note, timestamp),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, occurrence["scan_id"])


def require_finding_open(connection: sqlite3.Connection, occurrence_id: str) -> None:
    triage = connection.execute(
        "SELECT status FROM finding_triage WHERE occurrence_id = ?",
        (occurrence_id,),
    ).fetchone()
    if triage is not None and triage["status"] == "closed":
        raise SystemExit("Reopen this finding before requesting remediation.")


def request_finding_remediation(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    try:
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        scan = require_scan(connection, occurrence["scan_id"])
        existing = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if existing is not None:
            if existing["occurrence_id"] != occurrence["id"]:
                raise SystemExit("This remediation request belongs to a different finding.")
            return scan_context(connection, occurrence["scan_id"])
        base_revision, base_content_digest = remediation_checkout_snapshot(scan)
        connection.execute("BEGIN IMMEDIATE")
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        existing = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if existing is not None:
            if existing["occurrence_id"] != occurrence["id"]:
                raise SystemExit("This remediation request belongs to a different finding.")
            connection.commit()
            return scan_context(connection, occurrence["scan_id"])
        latest = connection.execute(
            """
            SELECT *
            FROM finding_remediation_attempts
            WHERE occurrence_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (occurrence["id"],),
        ).fetchone()
        if latest is not None:
            active_operation = latest["pending_action"] is not None or latest["state"] in {
                "requested",
                "verifying",
            }
            if active_operation and (
                latest["state"] != "failed" or remediation_claim_is_active(latest)
            ):
                raise SystemExit(
                    "Finish or retry the active remediation operation before regenerating."
                )
            if latest["state"] == "failed" and latest["pending_action"] is not None:
                connection.execute(
                    """
                    UPDATE finding_remediation_attempts
                    SET pending_action = NULL, pending_action_claimed_at = NULL,
                        pending_action_claim_token = NULL,
                        pending_action_delivered_at = NULL, updated_at = ?
                    WHERE request_id = ?
                    """,
                    (timestamp, latest["request_id"]),
                )
            if latest["state"] in {"generated", "applied"}:
                connection.execute(
                    """
                    UPDATE finding_remediation_attempts
                    SET state = 'superseded', version = version + 1,
                        pending_action = NULL, pending_action_claimed_at = NULL,
                        pending_action_claim_token = NULL,
                        pending_action_delivered_at = NULL, updated_at = ?
                    WHERE request_id = ?
                    """,
                    (timestamp, latest["request_id"]),
                )
        connection.execute(
            """
            INSERT INTO finding_remediation_attempts (
                request_id, occurrence_id, state, version, base_revision,
                base_content_digest, pending_action, pending_action_claimed_at,
                pending_action_claim_token, created_at, updated_at
            ) VALUES (?, ?, 'requested', 1, ?, ?, 'generate', ?, ?, ?, ?)
            """,
            (
                request_id,
                occurrence["id"],
                base_revision,
                base_content_digest,
                timestamp,
                action_token,
                timestamp,
                timestamp,
            ),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, occurrence["scan_id"])


def request_finding_remediation_action(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    try:
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        scan = require_scan(connection, occurrence["scan_id"])
        current = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current is None or current["occurrence_id"] != occurrence["id"]:
            raise SystemExit("Codex Security finding remediation request not found.")
        if current["pending_action"] is not None:
            if (
                current["pending_action"] == args.action
                and current["pending_action_claim_token"] == action_token
            ):
                connection.commit()
                return scan_context(connection, occurrence["scan_id"])
            raise SystemExit("Another remediation operation is already pending.")
        if current["version"] != args.expected_version:
            raise SystemExit(
                "This remediation request changed. Refresh it before recording an update."
            )
        required_state = {"apply": "generated", "verify": "applied"}[args.action]
        if current["state"] != required_state:
            raise SystemExit(
                f"Finding remediation cannot request {args.action} from {current['state']}."
            )
        if current["patch_path"] is None or current["patch_digest"] is None:
            raise SystemExit(
                "Generated remediation states require a scan-local patch path and digest."
            )
        require_matching_patch_digest(scan, current["patch_path"], current["patch_digest"])
        require_remediation_checkout_unchanged(
            scan,
            current,
            require_base_content=args.action == "apply",
            require_applied_content=args.action == "verify",
        )
        connection.execute("BEGIN IMMEDIATE")
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        updated = connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action = ?, pending_action_claimed_at = ?,
                pending_action_claim_token = ?, pending_action_delivered_at = NULL,
                version = version + 1, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND version = ? AND pending_action IS NULL
            """,
            (
                args.action,
                timestamp,
                action_token,
                timestamp,
                request_id,
                occurrence["id"],
                args.expected_version,
            ),
        )
        if updated.rowcount != 1:
            raise SystemExit(
                "This remediation request changed. Refresh it before recording an update."
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, occurrence["scan_id"])


def claim_finding_remediation_resend(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        current = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current is None or current["occurrence_id"] != occurrence["id"]:
            raise SystemExit("Codex Security finding remediation request not found.")
        if current["pending_action"] is None:
            raise SystemExit("This remediation attempt does not have a pending host request.")
        if current["pending_action_claim_token"] == action_token:
            connection.commit()
            result = scan_context(connection, occurrence["scan_id"])
            result["actionToken"] = action_token
            return result
        delivered_at = current["pending_action_delivered_at"]
        if delivered_at is not None:
            claimed_token = action_token
            updated = connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET pending_action_claimed_at = ?, pending_action_claim_token = ?,
                    pending_action_delivered_at = NULL, updated_at = ?
                WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                    AND pending_action_claim_token = ? AND pending_action_delivered_at <= ?
                """,
                (
                    timestamp,
                    action_token,
                    timestamp,
                    request_id,
                    occurrence["id"],
                    current["pending_action_claim_token"],
                    stale_claim_before(DELIVERED_ACTION_LEASE_SECONDS),
                ),
            )
            unavailable = (
                "This remediation worker is still within its execution lease. Retry later."
            )
        else:
            claimed_token = action_token
            updated = connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET pending_action_claimed_at = ?, pending_action_claim_token = ?,
                    pending_action_delivered_at = NULL, updated_at = ?
                WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                    AND (
                        pending_action_claim_token IS NULL
                        OR pending_action_claimed_at IS NULL
                        OR pending_action_claimed_at <= ?
                    )
                """,
                (
                    timestamp,
                    action_token,
                    timestamp,
                    request_id,
                    occurrence["id"],
                    stale_claim_before(),
                ),
            )
            unavailable = "This remediation host request is still owned by another panel. Retry after its lease expires."
        if updated.rowcount != 1:
            raise SystemExit(unavailable)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    result = scan_context(connection, occurrence["scan_id"])
    result["actionToken"] = claimed_token
    return result


def mark_finding_remediation_delivered(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    timestamp = now()
    with connection:
        occurrence = require_occurrence(connection, args.occurrence_id)
        updated = connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_delivered_at = ?, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                AND pending_action_claim_token = ?
            """,
            (timestamp, timestamp, request_id, occurrence["id"], action_token),
        )
        if updated.rowcount != 1:
            raise SystemExit(
                "This remediation host request is no longer owned by this action token."
            )
    return scan_context(connection, occurrence["scan_id"])


def release_finding_remediation_claim(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    timestamp = now()
    with connection:
        occurrence = require_occurrence(connection, args.occurrence_id)
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                AND pending_action_claim_token = ?
            """,
            (timestamp, request_id, occurrence["id"], action_token),
        )
    return scan_context(connection, occurrence["scan_id"])


def set_finding_remediation(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    summary = optional_text(args.summary, maximum=2400)
    verification_summary = optional_text(args.verification_summary, maximum=2400)
    try:
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        scan = require_scan(connection, occurrence["scan_id"])
        current = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current is None or current["occurrence_id"] != occurrence["id"]:
            raise SystemExit("Codex Security finding remediation request not found.")
        if current["version"] != args.expected_version:
            raise SystemExit(
                "This remediation request changed. Refresh it before recording an update."
            )
        if current["pending_action_claim_token"] is None:
            raise SystemExit(
                "This remediation attempt does not have an owned pending host request."
            )
        if current["pending_action_claim_token"] != action_token:
            raise SystemExit("This remediation host request is owned by a different action token.")
        require_remediation_transition(current["state"], args.state)
        require_pending_remediation_action(current, args.state)
        patch_path = current["patch_path"]
        if args.patch_path is not None:
            requested_patch_path = require_scan_relative_file(scan, args.patch_path)
            if patch_path is not None and requested_patch_path != patch_path:
                raise SystemExit("A remediation attempt cannot replace its reviewed patch path.")
            patch_path = requested_patch_path
        patch_digest = current["patch_digest"]
        if args.patch_digest is not None:
            requested_patch_digest = require_sha256_digest(args.patch_digest, "patch-digest")
            if patch_digest is not None and requested_patch_digest != patch_digest:
                raise SystemExit("A remediation attempt cannot replace its reviewed patch digest.")
            patch_digest = requested_patch_digest
        base_revision = optional_text(args.base_revision, maximum=512)
        if args.state in {"generated", "applied", "verifying", "verified"}:
            if patch_path is None or patch_digest is None:
                raise SystemExit(
                    "Generated remediation states require a scan-local patch path and digest."
                )
            require_matching_patch_digest(scan, patch_path, patch_digest)
        if args.state == "generated":
            require_remediation_checkout_unchanged(scan, current, require_base_content=True)
        if args.state in {"applied", "verifying", "verified"}:
            if base_revision != current["base_revision"]:
                raise SystemExit(
                    "The remediation base revision changed. Regenerate the patch before applying it."
                )
            if args.state in {"verifying", "verified"}:
                require_remediation_checkout_unchanged(
                    scan,
                    current,
                    require_applied_content=True,
                )
        if args.state == "verified" and verification_summary is None:
            raise SystemExit("Verified remediation requires a verification summary.")
        applied_content_digest = current["applied_content_digest"]
        if args.state == "applied":
            applied_content_digest = require_reviewed_patch_applied(
                scan,
                current,
                patch_path,
            )
        connection.execute("BEGIN IMMEDIATE")
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        replace_failure_summary = current["state"] == "failed" and args.state != "failed"
        updated = connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET state = ?, version = version + 1, patch_path = ?, patch_digest = ?,
                applied_content_digest = ?,
                pending_action = CASE
                    WHEN ? IN ('verifying', 'failed') THEN pending_action ELSE NULL
                END,
                pending_action_claimed_at = CASE
                    WHEN ? = 'verifying' THEN pending_action_claimed_at ELSE NULL
                END,
                pending_action_claim_token = CASE
                    WHEN ? = 'verifying' THEN pending_action_claim_token ELSE NULL
                END,
                pending_action_delivered_at = CASE
                    WHEN ? = 'verifying' THEN pending_action_delivered_at ELSE NULL
                END,
                summary = CASE WHEN ? THEN ? ELSE COALESCE(?, summary) END,
                verification_summary = COALESCE(?, verification_summary),
                updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND version = ?
                AND pending_action_claim_token = ?
            """,
            (
                args.state,
                patch_path,
                patch_digest,
                applied_content_digest,
                args.state,
                args.state,
                args.state,
                args.state,
                replace_failure_summary,
                summary,
                summary,
                verification_summary,
                timestamp,
                request_id,
                occurrence["id"],
                args.expected_version,
                action_token,
            ),
        )
        if updated.rowcount != 1:
            raise SystemExit(
                "This remediation request changed. Refresh it before recording an update."
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, occurrence["scan_id"])


def linear_publication_input(
    args: argparse.Namespace, *, recording: bool
) -> tuple[dict[str, Any], dict[str, str], list[dict[str, str]]]:
    payload = read_json_object(Path(args.input_file))
    required = {"scanId", "scanDirectory", "destination", "findings"}
    if recording:
        required.add("publications")
    if set(payload) != required:
        raise SystemExit("Linear publication input contains unexpected or missing fields.")

    scan_id = payload["scanId"]
    scan_directory = payload["scanDirectory"]
    destination = payload["destination"]
    findings = payload["findings"]
    if not isinstance(scan_id, str) or not isinstance(scan_directory, str):
        raise SystemExit("Linear publication input must identify the exact completed scan.")
    if (
        not isinstance(destination, dict)
        or not {"type", "teamId"}.issubset(destination)
        or not set(destination).issubset({"type", "teamId", "projectId"})
        or destination.get("type") != "linear"
        or not isinstance(destination.get("teamId"), str)
        or not destination["teamId"].strip()
        or (
            "projectId" in destination
            and (
                not isinstance(destination["projectId"], str)
                or not destination["projectId"].strip()
            )
        )
    ):
        raise SystemExit("Linear publication input must identify the exact team and optional project.")
    if not isinstance(findings, list):
        raise SystemExit("Linear publication input must include the planned scan findings.")

    seen_finding_ids: set[str] = set()
    seen_occurrence_ids: set[str] = set()
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {"findingId", "occurrenceId"}
            or not isinstance(finding.get("findingId"), str)
            or not finding["findingId"].strip()
            or not isinstance(finding.get("occurrenceId"), str)
            or not finding["occurrenceId"].strip()
        ):
            raise SystemExit("Linear publication input contains an invalid finding identity.")
        if (
            finding["findingId"] in seen_finding_ids
            or finding["occurrenceId"] in seen_occurrence_ids
        ):
            raise SystemExit("Linear publication input repeats a finding or occurrence.")
        seen_finding_ids.add(finding["findingId"])
        seen_occurrence_ids.add(finding["occurrenceId"])

    return payload, destination, findings


def verify_linear_publication_scan(
    connection: sqlite3.Connection,
    payload: dict[str, Any],
    findings: list[dict[str, str]],
) -> sqlite3.Row:
    try:
        scan = require_scan(connection, payload["scanId"])
    except SystemExit as exc:
        raise SystemExit(
            "The completed scan is not present in the local Codex Security scan-history database. "
            "Use the state directory where the scan was completed."
        ) from exc
    if scan["id"] != payload["scanId"]:
        raise SystemExit("Linear publication must use the exact completed scan identifier.")
    if scan["status"] != "complete":
        raise SystemExit("Only completed scans can publish findings to Linear.")

    requested_directory = require_canonical_scan_directory(Path(payload["scanDirectory"]))
    recorded_directory = require_canonical_scan_directory(Path(scan["scan_dir"]))
    if os.path.normcase(requested_directory) != os.path.normcase(recorded_directory):
        raise SystemExit(
            "The selected scan directory does not match its local Codex Security scan history."
        )
    if "seal_manifest_digest" in scan.keys():
        require_recorded_manifest_digest(scan, recorded_directory)

    stored_findings = {
        row["id"]: row["finding_id"]
        for row in connection.execute(
            "SELECT id, finding_id FROM finding_occurrences WHERE scan_id = ?",
            (scan["id"],),
        )
    }
    for finding in findings:
        if stored_findings.get(finding["occurrenceId"]) != finding["findingId"]:
            raise SystemExit(
                "A selected finding or occurrence does not belong to the completed scan "
                "in local Codex Security scan history."
            )
    if len(stored_findings) != len(findings):
        raise SystemExit(
            "The completed scan findings do not exactly match local Codex Security scan history."
        )
    return scan


def inspect_linear_publication(args: argparse.Namespace) -> dict[str, Any]:
    payload, destination, findings = linear_publication_input(args, recording=False)
    database_uri = f"file:{quote(str(database_path()), safe='')}?mode=ro"
    with closing(sqlite3.connect(database_uri, uri=True, timeout=5)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        scan = verify_linear_publication_scan(connection, payload, findings)
        recorded: dict[str, dict[str, str]] = {}
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'finding_publications'"
        ).fetchone():
            for row in connection.execute(
                """
                SELECT finding_id, occurrence_id, external_id, external_url
                FROM finding_publications
                WHERE scan_id = ? AND destination_type = ? AND team_id = ? AND project_id IS ?
                ORDER BY created_at, external_id
                """,
                (
                    scan["id"],
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                ),
            ):
                recorded.setdefault(
                    row["occurrence_id"],
                    {
                        "findingId": row["finding_id"],
                        "occurrenceId": row["occurrence_id"],
                        "issueIdentifier": row["external_id"],
                        **({"url": row["external_url"]} if row["external_url"] is not None else {}),
                    },
                )
        return {
            "scanId": scan["id"],
            "destination": destination,
            "findingCount": len(findings),
            "recorded": [
                recorded[finding["occurrenceId"]]
                for finding in findings
                if finding["occurrenceId"] in recorded
            ],
        }


def prepare_linear_publication(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    payload, destination, findings = linear_publication_input(args, recording=False)
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = verify_linear_publication_scan(connection, payload, findings)
        result = {
            "scanId": scan["id"],
            "destination": destination,
            "findingCount": len(findings),
        }
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def record_linear_publications(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    payload, destination, findings = linear_publication_input(args, recording=True)
    publications = payload["publications"]
    if not isinstance(publications, list):
        raise SystemExit("Linear publication results must be an array.")
    planned = {finding["findingId"]: finding["occurrenceId"] for finding in findings}
    current: dict[str, dict[str, str]] = {}
    external_ids: set[str] = set()
    for publication in publications:
        if (
            not isinstance(publication, dict)
            or not {"findingId", "occurrenceId", "issueIdentifier"}.issubset(publication)
            or not set(publication).issubset(
                {"findingId", "occurrenceId", "issueIdentifier", "url"}
            )
            or not isinstance(publication.get("findingId"), str)
            or not isinstance(publication.get("occurrenceId"), str)
            or not isinstance(publication.get("issueIdentifier"), str)
            or not publication["issueIdentifier"].strip()
            or (
                "url" in publication
                and (
                    not isinstance(publication["url"], str)
                    or not publication["url"].strip()
                )
            )
        ):
            raise SystemExit("Linear publication results contain an invalid issue association.")
        finding_id = publication["findingId"]
        issue_identifier = publication["issueIdentifier"]
        if planned.get(finding_id) != publication["occurrenceId"]:
            raise SystemExit(
                "A created Linear issue does not match its planned finding and occurrence."
            )
        if finding_id in current or issue_identifier in external_ids:
            raise SystemExit("Linear publication results repeat a finding or issue identifier.")
        current[finding_id] = publication
        external_ids.add(issue_identifier)

    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = verify_linear_publication_scan(connection, payload, findings)
        timestamp = now()
        for publication in publications:
            conflicting = connection.execute(
                """
                SELECT occurrence_id, external_url
                FROM finding_publications
                WHERE destination_type = ? AND team_id = ? AND project_id IS ?
                    AND external_id = ?
                """,
                (
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                    publication["issueIdentifier"],
                ),
            ).fetchone()
            if conflicting is not None and conflicting["occurrence_id"] != publication[
                "occurrenceId"
            ]:
                raise SystemExit("This Linear issue is already associated with a different finding.")
            if (
                conflicting is not None
                and "url" in publication
                and conflicting["external_url"] != publication["url"]
            ):
                raise SystemExit("This Linear issue is already associated with a different URL.")

            connection.execute(
                """
                INSERT INTO finding_publications (
                    scan_id, finding_id, occurrence_id, destination_type,
                    team_id, project_id, external_id, external_url, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    scan["id"],
                    publication["findingId"],
                    publication["occurrenceId"],
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                    publication["issueIdentifier"],
                    publication.get("url"),
                    timestamp,
                ),
            )

        created = []
        for finding in findings:
            publication = current.get(finding["findingId"])
            if publication is None:
                continue
            row = connection.execute(
                """
                SELECT finding_id, occurrence_id, external_id, external_url
                FROM finding_publications
                WHERE scan_id = ? AND occurrence_id = ? AND destination_type = ?
                    AND team_id = ? AND project_id IS ? AND external_id = ?
                """,
                (
                    scan["id"],
                    publication["occurrenceId"],
                    destination["type"],
                    destination["teamId"],
                    destination.get("projectId"),
                    publication["issueIdentifier"],
                ),
            ).fetchone()
            if row is None:
                raise SystemExit("A created Linear issue could not be read from scan history.")
            created.append(
                {
                    "findingId": row["finding_id"],
                    "occurrenceId": row["occurrence_id"],
                    "issueIdentifier": row["external_id"],
                    **({"url": row["external_url"]} if row["external_url"] is not None else {}),
                }
            )
        result = {"scanId": scan["id"], "destination": destination, "created": created}
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def export_findings(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    refresh_stopped_scan_results(connection, args.scan_id, strict=True)
    scan = require_scan(connection, args.scan_id)
    if scan["status"] != "complete" and not (
        scan["status"] == "failed" and scan["seal_manifest_digest"]
    ):
        raise SystemExit(
            "Findings can be exported after the scan completes or preserves stopped results."
        )
    scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
    require_recorded_manifest_digest(scan, scan_dir)
    verify_manifest_binding(scan, read_json_object(scan_dir / ARTIFACTS["manifest"]))
    try:
        manifest, _, _ = finalize_scan(
            scan_dir,
            expected_coverage_mode=expected_coverage_mode(scan),
        )
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    verify_manifest_binding(scan, manifest)
    manifest_digest = published_manifest_digest(scan_dir, manifest)
    pin_legacy_manifest_digest(connection, scan["id"], manifest_digest)
    if args.format == "json":
        path = artifact_path(scan_dir, ARTIFACTS["findings"], required=True)
    elif args.format == "sarif":
        try:
            write_sarif_projection(scan_dir)
        except ContractError as exc:
            raise SystemExit(str(exc)) from exc
        path = artifact_path(scan_dir, "exports/results.sarif", required=True)
    else:
        path = write_csv_export(connection, scan)
    if path is None:
        raise SystemExit(f"Could not export Codex Security findings as {args.format.upper()}.")
    return {
        "export": {"format": args.format, "path": str(path)},
        "scan": scan_result(connection, scan),
        "workspace": workspace_state(connection, scan["workspace_id"]),
    }


def write_csv_export(connection: sqlite3.Connection, scan: sqlite3.Row) -> Path:
    scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    deep_scan = scan["mode"] == "deep"
    candidate_ids_by_occurrence: dict[str, str] = {}
    if deep_scan:
        findings_document = read_json_object(scan_dir / ARTIFACTS["findings"])
        findings = findings_document.get("findings")
        if not isinstance(findings, list):
            raise SystemExit("findings.json must contain a findings array.")
        for finding in findings:
            if not isinstance(finding, dict):
                raise SystemExit("findings.json entries must be objects.")
            occurrence_id = finding.get("occurrenceId")
            candidate_id = finding_candidate_id(finding)
            if isinstance(occurrence_id, str) and isinstance(candidate_id, str):
                candidate_ids_by_occurrence[occurrence_id] = candidate_id
    columns = (
        "occurrence_id",
        "finding_id",
        *(("candidate_id",) if deep_scan else ()),
        "title",
        "summary",
        "severity",
        "confidence",
        "status",
        "close_reason",
        "note",
        "remediation",
        "path",
        "start_line",
        "end_line",
    )
    writer.writerow(columns)
    for row in finding_export_rows(connection, scan["id"]):
        writer.writerow(
            (
                csv_cell(row["occurrence_id"]),
                csv_cell(row["finding_id"]),
                *(
                    (csv_cell(candidate_ids_by_occurrence.get(row["occurrence_id"])),)
                    if deep_scan
                    else ()
                ),
                csv_cell(row["title"]),
                csv_cell(row["summary"]),
                csv_cell(row["severity"]),
                csv_cell(row["confidence"]),
                csv_cell(row["status"]),
                csv_cell(row["close_reason"]),
                csv_cell(row["note"]),
                csv_cell(row["remediation"]),
                csv_cell(row["relative_path"]),
                row["start_line"],
                row["end_line"],
            )
        )
    try:
        write_scan_local_bytes(
            scan_dir,
            "exports/findings.csv",
            output.getvalue().encode("utf-8"),
        )
    except ContractError as exc:
        raise SystemExit(
            "exports: expected a regular directory inside the scan directory."
        ) from exc
    destination = scan_dir / "exports" / "findings.csv"
    path = available_artifact_path(scan_dir, destination)
    if path is None:
        raise SystemExit("findings.csv: expected a regular file inside the scan directory.")
    return path


def finding_export_rows(connection: sqlite3.Connection, scan_id: str) -> sqlite3.Cursor:
    return connection.execute(
        """
        SELECT
            occurrences.id AS occurrence_id,
            occurrences.finding_id,
            occurrences.title,
            occurrences.summary,
            occurrences.severity,
            occurrences.confidence,
            occurrences.remediation,
            COALESCE(triage.status, 'open') AS status,
            triage.close_reason,
            triage.note,
            locations.relative_path,
            locations.start_line,
            locations.end_line
        FROM finding_occurrences AS occurrences
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        LEFT JOIN finding_locations AS locations
            ON locations.occurrence_id = occurrences.id
            AND locations.sort_order = (
                SELECT primary_location.sort_order
                FROM finding_locations AS primary_location
                WHERE primary_location.occurrence_id = occurrences.id
                ORDER BY
                    CASE WHEN primary_location.role = 'root_control' THEN 0 ELSE 1 END,
                    primary_location.sort_order
                LIMIT 1
            )
        WHERE occurrences.scan_id = ?
        ORDER BY occurrences.created_at, occurrences.id
        """,
        (scan_id,),
    )


def require_remediation_transition(current: str, requested: str) -> None:
    allowed = {
        "requested": {"requested", "generated", "failed"},
        "generated": {"generated", "applied", "failed"},
        "applied": {"applied", "verifying", "failed"},
        "verifying": {"verifying", "verified", "failed"},
        "verified": {"verifying", "verified"},
        "failed": {"generated", "applied", "verifying", "verified", "failed"},
    }
    if requested not in allowed.get(current, set()):
        raise SystemExit(f"Finding remediation cannot move from {current} to {requested}.")


def require_pending_remediation_action(current: sqlite3.Row, requested: str) -> None:
    pending_action = current["pending_action"]
    if pending_action is not None:
        allowed = {
            "generate": {"generated", "failed"},
            "apply": {"applied", "failed"},
            "verify": {"verifying", "verified", "failed"},
        }
        if requested not in allowed[pending_action]:
            raise SystemExit(
                f"Pending remediation action {pending_action} cannot record state {requested}."
            )
        return
    required_action = {
        ("requested", "generated"): "generate",
        ("generated", "applied"): "apply",
        ("applied", "verifying"): "verify",
    }.get((current["state"], requested))
    if required_action is not None:
        raise SystemExit(
            f"Request {required_action} before recording remediation state {requested}."
        )


def require_reviewed_patch_applied(
    scan: sqlite3.Row, remediation: sqlite3.Row, patch_path: str
) -> str | None:
    target = require_scan_target_identity(scan)
    _, content_digest = remediation_checkout_snapshot(
        scan, expected_revision=remediation["base_revision"]
    )
    if content_digest == remediation["base_content_digest"]:
        raise SystemExit(
            "The selected checkout is unchanged; apply the reviewed patch before recording it as applied."
        )
    unversioned = remediation["base_revision"] == "unversioned"
    excluded = (Path(scan["scan_dir"]),)
    git_dir = None
    pathspec = None
    if not unversioned:
        _, pathspec = git_worktree_context(target)
        git_dir = git_output(target, "rev-parse", "--absolute-git-dir")
        if git_dir is None:
            raise SystemExit("Could not inspect the selected Git working tree.")
        excluded += git_submodule_paths(target)
    with tempfile.TemporaryDirectory(prefix="codex-security-remediation-") as temporary:
        reviewed_patch = Path(temporary) / "reviewed.patch"
        digest = hashlib.sha256()
        with open_scan_local_file(Path(scan["scan_dir"]), patch_path) as source:
            with reviewed_patch.open("xb") as destination:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    destination.write(chunk)
        if f"sha256:{digest.hexdigest()}" != remediation["patch_digest"]:
            raise SystemExit("Patch digest does not match the scan-local patch file.")
        checkout_root = Path(temporary) / "checkout"
        if unversioned:
            checkout = checkout_root
            copy_directory_excluding(target, checkout, excluded)
        else:
            checkout = copy_git_worktree_files(target, checkout_root, excluded)
        arguments = ["apply", "--reverse", "--whitespace=nowarn"]
        if unversioned:
            arguments.append("--no-index")
        elif pathspec != ".":
            arguments.append(f"--directory={pathspec}")
        arguments.append(str(reviewed_patch))
        applied = git_command(
            checkout if unversioned else checkout_root,
            *arguments,
            text=False,
            git_dir=Path(git_dir) if git_dir is not None else None,
            work_tree=checkout_root if git_dir is not None else None,
        )
        if applied.returncode != 0:
            raise SystemExit(
                "The selected checkout does not contain the reviewed remediation patch. Apply exactly that patch before recording it as applied."
            )
        reverted_digest = (
            directory_content_digest(checkout)
            if unversioned
            else worktree_content_digest_for_context(
                checkout_root,
                pathspec or ".",
                git_dir=Path(git_dir),
                work_tree=checkout_root,
            )
        )
        if reverted_digest != remediation["base_content_digest"] and unversioned:
            checkout = Path(temporary) / "checkout-lf"
            copy_directory_excluding(target, checkout, excluded)
            applied_without_conversion = git_command(
                checkout, "-c", "core.autocrlf=input", *arguments, text=True
            )
            if applied_without_conversion.returncode == 0:
                reverted_digest = directory_content_digest(checkout)
        if reverted_digest != remediation["base_content_digest"]:
            raise SystemExit(
                "The selected checkout contains changes outside the reviewed patch. Remove them before recording the patch as applied."
            )
    return content_digest


def require_remediation_checkout_unchanged(
    scan: sqlite3.Row,
    remediation: sqlite3.Row,
    *,
    require_applied_content: bool = False,
    require_base_content: bool = False,
) -> None:
    _, content_digest = remediation_checkout_snapshot(
        scan, expected_revision=remediation["base_revision"]
    )
    expected_digest = (
        remediation["applied_content_digest"]
        if require_applied_content
        else remediation["base_content_digest"]
        if require_base_content
        else None
    )
    if expected_digest is not None and content_digest != expected_digest:
        raise SystemExit(
            "Working-tree contents changed. Regenerate the remediation patch against the current checkout."
        )


def require_sha256_digest(value: str, label: str) -> str:
    normalized = optional_text(value, maximum=71)
    if (
        normalized is None
        or not normalized.startswith("sha256:")
        or len(normalized) != 71
        or any(
            character not in "0123456789abcdef" for character in normalized.removeprefix("sha256:")
        )
    ):
        raise SystemExit(f"{label} must use sha256:<64 lowercase hex characters>.")
    return normalized


def require_scan_relative_file(scan: sqlite3.Row, value: str) -> str:
    normalized = optional_text(value, maximum=4096)
    if normalized is None or "\\" in normalized:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    parsed = PurePosixPath(normalized)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    path = artifact_path(Path(scan["scan_dir"]), parsed.as_posix(), required=True)
    if path is None:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    return parsed.as_posix()


def require_matching_patch_digest(scan: sqlite3.Row, patch_path: str, patch_digest: str) -> None:
    digest = hashlib.sha256()
    with open_scan_local_file(Path(scan["scan_dir"]), patch_path) as patch:
        while chunk := patch.read(1024 * 1024):
            digest.update(chunk)
    if f"sha256:{digest.hexdigest()}" != patch_digest:
        raise SystemExit("Patch digest does not match the scan-local patch file.")


def open_scan_local_file(scan_dir: Path, relative_path: str) -> Any:
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute() or not parsed.parts or ".." in parsed.parts:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    scan_dir = require_canonical_scan_directory(scan_dir)
    try:
        file_fd = open_scan_local_file_descriptor(
            scan_dir,
            parsed.as_posix(),
            "Patch path",
        )
        return os.fdopen(file_fd, "rb")
    except (ContractError, OSError) as exc:
        raise SystemExit("Patch path must identify a scan-local regular file.") from exc


def diff_target_summary(diff_target: dict[str, str]) -> str:
    kind = diff_target["kind"]
    if kind == "working_tree":
        return "Uncommitted changes"
    if kind == "commit":
        return f"Commit {diff_target['headRevision'][:7]}"
    return f"{diff_target['baseRevision'][:7]}…{diff_target['headRevision'][:7]}"


def workspace_state(
    connection: sqlite3.Connection,
    workspace_id: str,
    *,
    result_scan_id: str | None = None,
    thread_id: str | None = None,
    refresh_stopped: bool = False,
) -> dict[str, Any]:
    workspace = require_workspace(connection, workspace_id)
    if thread_id is not None and workspace["thread_id"] != optional_text(thread_id, maximum=512):
        raise SystemExit("Codex Security workspace not found in this thread.")
    persisted_diff_target = stored_diff_target(workspace)
    result: dict[str, Any] = {
        "id": workspace["id"],
        "diffTarget": persisted_diff_target,
        "mode": workspace["default_mode"],
        "scope": workspace["default_scope"],
        "setup": {"submitted": bool(workspace["submitted"])},
        "setupValidation": {"error": None, "valid": bool(workspace["submitted"])},
        "targetPath": workspace["target_path"],
        "targetSummary": workspace["target_summary"],
        "targetTitle": workspace["target_title"],
        "updatedAt": workspace["updated_at"],
        "userContext": workspace["user_context"],
    }
    selected_scan_id = result_scan_id or workspace["active_scan_id"]
    if selected_scan_id:
        if refresh_stopped:
            refresh_stopped_scan_results(connection, selected_scan_id)
        selected_scan = require_scan(connection, selected_scan_id)
        result["userContext"] = selected_scan["user_context"]
        result["results"] = scan_result(connection, selected_scan)
        return result

    target_metadata = None
    setup_error = None
    validated_diff_target = None
    if workspace["target_path"]:
        try:
            inspected = inspect_setup_values(
                workspace["target_path"],
                workspace["default_scope"],
                workspace["default_mode"],
                workspace["diff_target_kind"],
                workspace["diff_base_revision"],
                workspace["diff_head_revision"],
                workspace["diff_content_digest"],
            )
            target_metadata = inspected["target"]["targetMetadata"]
            validated_diff_target = inspected["diffTarget"]
        except SystemExit as exc:
            setup_error = str(exc)
            try:
                target = require_target(workspace["target_path"])
                target_metadata = git_target_metadata(target)
            except SystemExit:
                pass
    result["diffTarget"] = validated_diff_target or persisted_diff_target
    result["setupValidation"] = {
        "error": setup_error,
        "valid": setup_error is None and bool(target_metadata),
    }
    if target_metadata:
        result["targetMetadata"] = target_metadata
    return result


def scan_context(
    connection: sqlite3.Connection,
    scan_id: str,
    occurrence_id: str | None = None,
) -> dict[str, Any]:
    scan = require_scan(connection, scan_id)
    workspace = workspace_state(connection, scan["workspace_id"], result_scan_id=scan["id"])
    context = {
        "otherRunningDeepScans": deep_scan.other_running_deep_scans(connection, scan["id"]),
        "scan": (
            workspace["results"]
            if occurrence_id is None
            else scan_result(connection, scan, occurrence_id=occurrence_id)
        ),
        "workspace": workspace,
    }
    if scan["recipe_json"] is not None:
        context["parentScanId"] = scan["parent_scan_id"]
        context["recipe"] = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
    return context


def list_findings(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    refresh_stopped_scan_results(connection, args.scan_id)
    scan = require_scan(connection, args.scan_id)
    backfill_legacy_finding_details(connection, scan)
    limit = min(args.limit, FINDINGS_PAGE_MAX)
    rows = scan_history.finding_occurrence_rows(
        connection,
        scan["id"],
        offset=args.offset,
        limit=limit,
        query=args.query,
        severity=args.severity,
        status=args.status,
    )
    conditions, values = scan_history.finding_occurrence_conditions(
        scan["id"], query=args.query, severity=args.severity, status=args.status
    )
    total = connection.execute(
        f"""
        SELECT COUNT(*)
        FROM finding_occurrences AS occurrences
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        WHERE {conditions}
        """,
        values,
    ).fetchone()[0]
    next_offset = args.offset + len(rows)
    return {
        "findingsPage": {
            "findings": [finding_result(connection, scan, row) for row in rows],
            "limit": limit,
            "nextOffset": next_offset if next_offset < total else None,
            "offset": args.offset,
            "scanId": scan["id"],
            "total": total,
        }
    }


def scan_result(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    occurrence_id: str | None = None,
) -> dict[str, Any]:
    backfill_legacy_finding_details(connection, scan)
    progress = connection.execute(
        "SELECT * FROM scan_progress WHERE scan_id = ?", (scan["id"],)
    ).fetchone()
    artifact_rows = connection.execute(
        "SELECT kind, path FROM scan_artifacts WHERE scan_id = ?", (scan["id"],)
    )
    artifacts = {}
    for row in artifact_rows:
        if row["kind"] not in ARTIFACTS:
            continue
        path = available_artifact_path(Path(scan["scan_dir"]), Path(row["path"]))
        if path is not None:
            artifacts[row["kind"]] = str(path)
    sarif_path = available_artifact_path(
        Path(scan["scan_dir"]), Path(scan["scan_dir"]) / "exports" / "results.sarif"
    )
    if sarif_path is not None:
        artifacts["sarifReport"] = str(sarif_path)
    occurrence_rows = scan_history.finding_occurrence_rows(
        connection, scan["id"], offset=0, limit=FINDINGS_RESULT_LIMIT
    )
    if occurrence_id is not None and all(row["id"] != occurrence_id for row in occurrence_rows):
        occurrence = require_occurrence(connection, occurrence_id)
        if occurrence["scan_id"] != scan["id"]:
            raise SystemExit("This finding does not belong to the selected scan.")
        occurrence_rows.append(occurrence)
    finding_count = connection.execute(
        "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?", (scan["id"],)
    ).fetchone()[0]
    severity_counts = {
        row["severity"]: row["count"]
        for row in connection.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM finding_occurrences
            WHERE scan_id = ?
            GROUP BY severity
            """,
            (scan["id"],),
        )
    }
    remediation_available, remediation_unavailable_reason = remediation_availability(scan)
    independent_reviews = (
        deep_scan.independent_review_progress(connection, scan["id"])
        if scan["mode"] == "deep"
        else None
    )
    progress_result = {
        "candidates": {"reportable": progress["reportable_findings_count"]},
        "coverage": {
            "closedRows": progress["review_items_completed"],
            "filesTotal": progress["scope_file_count"],
            "worklistRows": progress["review_items_total"],
        },
        "phase": scan["phase"],
        "phaseProgress": {
            "completed": progress["phase_items_completed"],
            "total": progress["phase_items_total"],
            "unit": progress["phase_progress_unit"],
        },
        "preflightProgress": {
            "completed": progress["preflight_checks_completed"],
            "total": progress["preflight_checks_total"],
        },
        "preflightIssues": json.loads(progress["preflight_issues_json"]),
        "reviewPass": progress["deep_review_pass"],
        "status": "canceled" if scan["canceled_at"] else scan["status"],
        "updatedAt": progress["updated_at"],
    }
    if independent_reviews is not None:
        progress_result["independentReviews"] = {
            "active": independent_reviews["active"],
            "completed": independent_reviews["completed"],
            "consolidating": independent_reviews["consolidating"],
        }
    return {
        "artifacts": artifacts,
        "canceledAt": scan["canceled_at"],
        **scan_usage.stored_scan_cost_fields(scan["cost_json"]),
        "contract": scan_contract(scan),
        "continuationThreadId": scan["continuation_thread_id"],
        "failureMessage": scan["failure_message"],
        "findings": [finding_result(connection, scan, row) for row in occurrence_rows],
        "findingCount": finding_count,
        "findingsTruncated": finding_count > len(occurrence_rows),
        "severityCounts": severity_counts,
        "handoffClaimedAt": scan["handoff_claimed_at"],
        "handoffClaimToken": scan["handoff_claim_token"],
        "handoffStatus": scan["handoff_status"],
        "mode": scan["mode"],
        "model": scan["model"],
        "diffTarget": stored_diff_target(scan),
        "progress": progress_result,
        "reasoningEffort": scan["reasoning_effort"],
        "remediationAvailable": remediation_available,
        "remediationUnavailableReason": remediation_unavailable_reason,
        "reportAvailable": "markdownReport" in artifacts,
        "scanDir": scan["scan_dir"],
        "scanId": scan["id"],
        "scope": scan["scope"],
        "targetPath": scan["target_path"],
        "targetRevision": scan["target_revision"],
        "targetSummary": scan["target_summary"],
        "updatedAt": max(
            scan["updated_at"],
            progress["updated_at"],
            str(independent_reviews["updatedAt"]) if independent_reviews is not None else "",
            finding_management_updated_at(connection, scan["id"]) or "",
        ),
        "userContext": scan["user_context"],
        "warnings": json.loads(scan["completion_warnings_json"]),
    }


def remediation_availability(scan: sqlite3.Row) -> tuple[bool, str | None]:
    if scan["status"] != "complete":
        return False, remediation.SCAN_STATUS_ERROR
    try:
        current_revision = git_revision(require_scan_target_identity(scan))
    except SystemExit as exc:
        return False, str(exc)
    expected_revision = scan["target_revision"]
    if current_revision == expected_revision:
        return True, None
    return (
        False,
        (
            "Remediation is unavailable because the selected checkout is not at the revision "
            "that was scanned. Check out the scanned revision or start a new scan."
        ),
    )


def backfill_legacy_finding_details(connection: sqlite3.Connection, scan: sqlite3.Row) -> None:
    if scan["status"] != "complete" or connection.in_transaction:
        return
    legacy_rows = connection.execute(
        """
        SELECT id, finding_id, title, summary, severity, confidence, remediation
        FROM finding_occurrences
        WHERE scan_id = ? AND details_json = '{}'
        """,
        (scan["id"],),
    ).fetchall()
    if not legacy_rows:
        return

    try:
        scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
        require_recorded_manifest_digest(scan, scan_dir)
        verify_manifest_binding(scan, read_json_object(scan_dir / ARTIFACTS["manifest"]))
        manifest, findings_document, _ = finalize_scan(
            scan_dir,
            expected_coverage_mode=expected_coverage_mode(scan),
        )
        verify_manifest_binding(scan, manifest)
        manifest_digest = published_manifest_digest(scan_dir, manifest)
    except (ContractError, OSError, SystemExit, ValueError):
        return

    findings = findings_document.get("findings")
    if not isinstance(findings, list):
        return
    by_occurrence = {
        finding.get("occurrenceId"): finding
        for finding in findings
        if isinstance(finding, dict) and isinstance(finding.get("occurrenceId"), str)
    }
    updates = []
    for row in legacy_rows:
        finding = by_occurrence.get(row["id"])
        if not legacy_finding_matches(row, finding):
            continue
        updates.append(
            (
                json.dumps(finding, allow_nan=False, sort_keys=True),
                scan["id"],
                row["id"],
            )
        )
    if not updates:
        return

    connection.execute("BEGIN IMMEDIATE")
    try:
        current = require_scan(connection, scan["id"])
        recorded_digest = current["seal_manifest_digest"]
        if recorded_digest is not None and recorded_digest != manifest_digest:
            raise SystemExit("The sealed scan manifest changed after completion.")
        connection.executemany(
            """
            UPDATE finding_occurrences
            SET details_json = ?
            WHERE scan_id = ? AND id = ? AND details_json = '{}'
            """,
            updates,
        )
        if recorded_digest is None:
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
                (manifest_digest, scan["id"]),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def legacy_finding_matches(row: sqlite3.Row, finding: Any) -> bool:
    if not isinstance(finding, dict):
        return False
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    return (
        finding.get("findingId") == row["finding_id"]
        and finding.get("title") == row["title"]
        and finding.get("summary") == row["summary"]
        and finding.get("remediation") == row["remediation"]
        and isinstance(severity, dict)
        and severity.get("level") == row["severity"]
        and isinstance(confidence, dict)
        and confidence.get("level") == row["confidence"]
    )


def finding_result(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    occurrence: sqlite3.Row,
) -> dict[str, Any]:
    details = bounded_finding_details(read_finding_details(occurrence["details_json"]))
    confidence = details.get("confidence")
    confidence = confidence if isinstance(confidence, dict) else {}
    severity = details.get("severity")
    severity = severity if isinstance(severity, dict) else {}
    locations = []
    try:
        target = require_scan_target_identity(scan)
    except SystemExit:
        target = None
    for row in connection.execute(
        """
        SELECT relative_path, start_line, end_line, role
        FROM finding_locations
        WHERE occurrence_id = ?
        ORDER BY CASE WHEN role = 'root_control' THEN 0 ELSE 1 END, sort_order
        LIMIT ?
        """,
        (occurrence["id"], FINDING_LOCATIONS_LIMIT),
    ):
        absolute_path = safe_source_path(target, row["relative_path"]) if target else None
        location = {
            "endLine": row["end_line"],
            "path": bounded_output_text(row["relative_path"], FINDING_LOCATION_PATH_BYTES),
            "role": (
                bounded_output_text(row["role"], FINDING_LOCATION_ROLE_BYTES)
                if row["role"] is not None
                else None
            ),
            "startLine": row["start_line"],
        }
        if absolute_path is not None:
            location["absolutePath"] = bounded_output_text(
                absolute_path, FINDING_ABSOLUTE_PATH_BYTES
            )
        locations.append(location)
    result = {
        **details,
        "confidence": {
            **confidence,
            "level": bounded_output_text(occurrence["confidence"], FINDING_LEVEL_BYTES),
        },
        "createdAt": occurrence["created_at"],
        "findingId": occurrence["finding_id"],
        "locations": locations,
        "occurrenceId": occurrence["id"],
        "remediationState": finding_remediation_result(connection, occurrence["id"]),
        "remediation": bounded_output_text(occurrence["remediation"], FINDING_REMEDIATION_BYTES),
        "severity": {
            **severity,
            "level": bounded_output_text(occurrence["severity"], FINDING_LEVEL_BYTES),
        },
        "summary": bounded_output_text(occurrence["summary"], FINDING_SUMMARY_BYTES),
        "title": bounded_output_text(occurrence["title"], FINDING_TITLE_BYTES),
        "triage": finding_triage_result(connection, occurrence["id"]),
    }
    matches, known_since, known_scan_ids = scan_history.finding_matches(
        connection, occurrence["id"], scan["id"], scan["started_at"]
    )
    if matches:
        result["matches"] = matches
        result["knownSince"] = known_since
        result["knownScanIds"] = known_scan_ids
    result.pop("artifactPaths", None)
    source_excerpt = finding_source_excerpt(scan, target, locations)
    if source_excerpt:
        result["sourceExcerpt"] = source_excerpt
    artifact_paths = finding_artifact_paths(Path(scan["scan_dir"]), details)
    result["artifactPaths"] = artifact_paths
    return result


def finding_artifact_paths(scan_dir: Path, details: dict[str, Any]) -> list[str]:
    writeup = details.get("writeup")
    if not isinstance(writeup, dict):
        return []
    report_path = writeup.get("reportPath")
    if (
        not isinstance(report_path, str)
        or FINDING_WRITEUP_REPORT_PATH.fullmatch(report_path) is None
    ):
        return []
    report_relative = PurePosixPath(report_path)
    artifacts = []
    if scan_local_regular_file(scan_dir, report_path):
        artifacts.append(report_path)

    poc_relative = report_relative.parent / "poc"
    poc_root = scan_dir.joinpath(*poc_relative.parts)
    try:
        if not stat.S_ISDIR(poc_root.stat(follow_symlinks=False).st_mode):
            return artifacts
    except OSError:
        return artifacts

    directories_seen = 0
    for current_directory, directory_names, file_names in os.walk(
        poc_root, topdown=True, followlinks=False
    ):
        directories_seen += 1
        if directories_seen > FINDING_ARTIFACT_DIRECTORIES_LIMIT:
            directory_names[:] = []
            break
        current_path = Path(current_directory)
        directory_names[:] = [
            name for name in sorted(directory_names) if not (current_path / name).is_symlink()
        ]
        for file_name in sorted(file_names):
            candidate = current_path / file_name
            try:
                relative_path = candidate.relative_to(scan_dir).as_posix()
            except ValueError:
                continue
            if not scan_local_regular_file(scan_dir, relative_path):
                continue
            artifacts.append(relative_path)
            if len(artifacts) >= FINDING_ARTIFACTS_LIMIT:
                return artifacts
    return artifacts


def scan_local_regular_file(scan_dir: Path, relative_path: str) -> bool:
    if len(relative_path.encode("utf-8")) > FINDING_LOCATION_PATH_BYTES:
        return False
    try:
        descriptor = open_scan_local_file_descriptor(
            scan_dir,
            relative_path,
            f"finding artifact {relative_path}",
        )
    except (ContractError, OSError):
        return False
    try:
        return stat.S_ISREG(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)


def read_finding_details(value: str) -> dict[str, Any]:
    try:
        details = json.loads(value, parse_constant=reject_non_finite_json)
    except (TypeError, ValueError):
        return {}
    return details if isinstance(details, dict) else {}


def finding_management_updated_at(connection: sqlite3.Connection, scan_id: str) -> str | None:
    return connection.execute(
        """
        SELECT MAX(updated_at)
        FROM (
            SELECT triage.updated_at
            FROM finding_triage AS triage
            JOIN finding_occurrences AS occurrences ON occurrences.id = triage.occurrence_id
            WHERE occurrences.scan_id = ?
            UNION ALL
            SELECT remediation.updated_at
            FROM finding_remediation_attempts AS remediation
            JOIN finding_occurrences AS occurrences ON occurrences.id = remediation.occurrence_id
            WHERE occurrences.scan_id = ?
        )
        """,
        (scan_id, scan_id),
    ).fetchone()[0]


def finding_triage_result(connection: sqlite3.Connection, occurrence_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT status, close_reason, note, updated_at FROM finding_triage WHERE occurrence_id = ?",
        (occurrence_id,),
    ).fetchone()
    if row is None:
        return {"status": "open"}
    return {
        "closeReason": row["close_reason"],
        "note": row["note"],
        "status": row["status"],
        "updatedAt": row["updated_at"],
    }


def finding_remediation_result(
    connection: sqlite3.Connection, occurrence_id: str
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT remediation.request_id, remediation.state, remediation.version,
            remediation.base_revision, remediation.base_content_digest,
            remediation.applied_content_digest, remediation.pending_action,
            remediation.pending_action_claimed_at, remediation.pending_action_claim_token,
            remediation.pending_action_delivered_at,
            remediation.patch_path, remediation.patch_digest, remediation.summary,
            remediation.verification_summary, remediation.updated_at, scans.scan_dir
        FROM finding_remediation_attempts AS remediation
        JOIN finding_occurrences AS occurrences ON occurrences.id = remediation.occurrence_id
        JOIN scans ON scans.id = occurrences.scan_id
        WHERE remediation.occurrence_id = ?
        ORDER BY remediation.created_at DESC, remediation.rowid DESC
        LIMIT 1
        """,
        (occurrence_id,),
    ).fetchone()
    if row is None:
        return {"state": "idle"}
    patch, patch_stats = patch_artifact_preview(
        Path(row["scan_dir"]), row["patch_path"], row["patch_digest"]
    )
    return {
        "baseRevision": row["base_revision"],
        "actionClaimedAt": row["pending_action_claimed_at"],
        "actionClaimToken": row["pending_action_claim_token"],
        "actionDeliveredAt": row["pending_action_delivered_at"],
        "pendingAction": row["pending_action"],
        "patchDigest": row["patch_digest"],
        "patchPath": row["patch_path"],
        "patch": patch,
        "patchStats": patch_stats,
        "requestId": row["request_id"],
        "state": row["state"],
        "summary": row["summary"],
        "updatedAt": row["updated_at"],
        "verificationSummary": row["verification_summary"],
        "version": row["version"],
    }


def patch_artifact_preview(
    scan_dir: Path, relative_path: str | None, expected_digest: str | None
) -> tuple[str | None, dict[str, int | bool] | None]:
    if relative_path is None or expected_digest is None:
        return None, None
    digest = hashlib.sha256()
    preview = bytearray()
    additions = 0
    deletions = 0
    file_count = 0
    old_headers = 0
    new_headers = 0
    at_line_start = True
    try:
        with open_scan_local_file(scan_dir, relative_path) as patch:
            while chunk := patch.readline(1024 * 1024):
                digest.update(chunk)
                if len(preview) <= PATCH_PREVIEW_BYTES:
                    preview.extend(chunk[: PATCH_PREVIEW_BYTES + 1 - len(preview)])
                if at_line_start:
                    if chunk.startswith(b"diff --git "):
                        file_count += 1
                    elif chunk.startswith(b"+++ "):
                        new_headers += 1
                    elif chunk.startswith(b"--- "):
                        old_headers += 1
                    elif chunk.startswith(b"+"):
                        additions += 1
                    elif chunk.startswith(b"-"):
                        deletions += 1
                at_line_start = chunk.endswith(b"\n")
    except SystemExit:
        return None, None
    if f"sha256:{digest.hexdigest()}" != expected_digest:
        return None, None
    preview_truncated = len(preview) > PATCH_PREVIEW_BYTES
    preview_text = preview[:PATCH_PREVIEW_BYTES].decode("utf-8", errors="replace")
    if preview_truncated:
        preview_text = f"{preview_text}\n... patch preview truncated ..."
    return preview_text, {
        "additions": additions,
        "deletions": deletions,
        "fileCount": file_count or min(old_headers, new_headers),
        "previewTruncated": preview_truncated,
    }


def available_artifact_path(scan_dir: Path, candidate: Path) -> Path | None:
    try:
        resolved_scan_dir = require_canonical_scan_directory(scan_dir)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_scan_dir)
    except (FileNotFoundError, RuntimeError, SystemExit, ValueError):
        return None
    if os.path.normcase(resolved) != os.path.normcase(candidate) or not candidate.is_file():
        return None
    return resolved


def artifact_path(scan_dir: Path, file_name: str, *, required: bool) -> Path | None:
    scan_dir = require_canonical_scan_directory(scan_dir)
    candidate = scan_dir / file_name
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(scan_dir.resolve())
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        if not required and isinstance(exc, FileNotFoundError):
            return None
        raise SystemExit(
            f"{file_name}: expected a regular file inside the scan directory."
        ) from exc
    if os.path.normcase(resolved) != os.path.normcase(candidate) or not candidate.is_file():
        raise SystemExit(f"{file_name}: expected a regular non-symlink file.")
    return resolved


def require_canonical_scan_directory(scan_dir: Path) -> Path:
    scan_dir = scan_dir.absolute()
    try:
        metadata = scan_dir.lstat()
        resolved = scan_dir.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(
            "Scan directory must be an existing canonical non-symlink directory."
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or os.path.normcase(resolved) != os.path.normcase(
        scan_dir
    ):
        raise SystemExit("Scan directory must be an existing canonical non-symlink directory.")
    # Re-check privacy on every resolution so a mid-scan rename/replace under a
    # shared parent cannot substitute another user's forged artifact tree.
    if os.name != "nt":
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SystemExit(
                "Scan directory must not be accessible to other users (chmod 700)."
            )
        geteuid = getattr(os, "geteuid", None)
        effective_uid = geteuid() if geteuid is not None else None
        if effective_uid is not None and metadata.st_uid != effective_uid:
            raise SystemExit("Scan directory must be owned by the current user.")
        for parent in scan_dir.parents:
            try:
                parent_metadata = parent.lstat()
            except OSError as exc:
                raise SystemExit("Scan output parent could not be inspected.") from exc
            if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(
                parent_metadata.st_mode
            ):
                raise SystemExit("Scan output parent must be a non-symlink directory.")
            if effective_uid is not None and parent_metadata.st_uid not in {
                0,
                effective_uid,
            }:
                raise SystemExit("Scan output parent must have a trusted owner.")
            if (
                stat.S_IMODE(parent_metadata.st_mode) & 0o022
                and not parent_metadata.st_mode & stat.S_ISVTX
            ):
                raise SystemExit(
                    "Scan output parent must not be group- or world-writable without the sticky bit."
                )
    return scan_dir


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_non_finite_json,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"{path.name}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{path.name}: expected a JSON object.")
    return payload


def reject_non_finite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is not supported")


_WORKBENCH_DB_CONTEXT = saved_results.WorkbenchDbContext(
    ARTIFACTS=ARTIFACTS,
    artifact_path=artifact_path,
    deep_scan=deep_scan,
    expected_coverage_mode=expected_coverage_mode,
    handoff=handoff,
    index_findings=index_findings,
    now=now,
    optional_text=optional_text,
    parse_scan_cost=parse_scan_cost,
    published_manifest_digest=published_manifest_digest,
    read_json_object=read_json_object,
    require_canonical_scan_directory=require_canonical_scan_directory,
    require_recorded_manifest_digest=require_recorded_manifest_digest,
    require_scan=require_scan,
    require_uuid=require_uuid,
    require_workspace=require_workspace,
    scan_completion_lock=scan_completion_lock,
    scan_context=scan_context,
    verify_manifest_binding=verify_manifest_binding,
    workbench_completion_binding=workbench_completion_binding,
    workspace_state=workspace_state,
)


def main() -> None:
    # Workbench callers send UTF-8 even when Windows uses a legacy code page.
    sys.stdin.reconfigure(encoding="utf-8")
    args = parse_args(__doc__)
    deep_scan.configure(
        deep_scan.DeepScanDependencies(
            now=now,
            state_dir=state_dir,
            require_scan=require_scan,
            require_workspace=require_workspace,
            require_target=require_target,
            require_remediation_target=require_remediation_target,
            require_scannable_target=require_scannable_target,
            require_scope=require_scope,
            ensure_security_target=ensure_security_target,
            require_canonical_scan_directory=require_canonical_scan_directory,
            safe_segment=safe_segment,
            compact_timestamp=compact_timestamp,
            scan_completion_lock=scan_completion_lock,
            preserve_stopped_results=preserve_stopped_results_after_transition,
        )
    )
    if args.command == "inspect-target":
        result = inspect_target(args.target_path)
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return
    if args.command == "inspect-setup":
        result = inspect_setup(args)
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return
    if args.command == "inspect-linear-publication":
        result = inspect_linear_publication(args)
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return
    with closing(connect()) as connection:
        remediation.require_available(connection, args, require_scan)
        if args.command == "create-workspace":
            result = create_workspace(connection, args)
        elif args.command == "get-workspace":
            result = workspace_state(
                connection,
                args.workspace_id,
                thread_id=args.thread_id,
                refresh_stopped=True,
            )
        elif args.command == "save-workspace":
            result = save_workspace(connection, args)
        elif args.command == "start-scan":
            result = start_scan(connection, args)
        elif args.command == "start-prompt-only-scan":
            result = start_prompt_only_scan(connection, args)
        elif args.command == "start-headless-standard-scan":
            result = start_headless_standard_scan(connection, args)
        elif args.command == "begin-deep-scan":
            result = deep_scan.begin_deep_scan(connection, args)
        elif args.command == "get-deep-scan":
            result = deep_scan.get_deep_scan(connection, args)
        elif args.command == "claim-deep-scan-coordinator":
            result = deep_scan.claim_deep_scan_coordinator(connection, args)
        elif args.command == "upsert-deep-scan-worker":
            result = deep_scan.upsert_deep_scan_worker(connection, args)
        elif args.command == "claim-deep-scan-dedup":
            result = deep_scan.claim_deep_scan_dedup(connection, args)
        elif args.command == "commit-deep-scan-dedup":
            result = deep_scan.commit_deep_scan_dedup(connection, args)
        elif args.command == "finish-deep-scan":
            result = deep_scan.finish_deep_scan(connection, args)
        elif args.command == "fail-deep-scan":
            result = deep_scan.fail_deep_scan(connection, args)
        elif args.command == "record-deep-scan-publication-failure":
            result = deep_scan.record_deep_scan_publication_failure(connection, args)
        elif args.command == "get-scan":
            refresh_stopped_scan_results(connection, args.scan_id)
            result = scan_context(connection, args.scan_id, args.occurrence_id)
        elif args.command == "get-scan-feedback":
            result = get_scan_feedback(connection, require_scan(connection, args.scan_id))
        elif args.command == "list-scans":
            refresh_all_stopped_scan_results(connection)
            result = scan_history.list_scans(connection, args)
        elif args.command == "list-unmatched-scan-pairs":
            result = scan_history.list_unmatched_scan_pairs(
                connection,
                args,
                backfill_finding_details=backfill_legacy_finding_details,
                read_coverage=coverage_for_comparison,
            )
        elif args.command == "register-cli-scan":
            result = register_cli_scan(connection, args)
        elif args.command == "set-scan-thread":
            result = set_scan_thread(connection, args)
        elif args.command == "get-scan-recipe":
            result = get_scan_recipe(connection, args)
        elif args.command == "compare-scans":
            result = scan_history.compare_scans(
                connection,
                args,
                require_scan=require_scan,
                read_coverage=coverage_for_comparison,
                backfill_finding_details=backfill_legacy_finding_details,
                include_matching_inputs=args.include_matching_inputs,
                require_matches=args.require_matches,
            )
        elif args.command == "save-scan-comparison":
            result = scan_history.save_scan_comparison(
                connection,
                args,
                now=now,
                require_scan=require_scan,
                read_coverage=coverage_for_comparison,
            )
        elif args.command == "list-global-findings":
            refresh_all_stopped_scan_results(connection)
            result = native_indexes.list_global_findings(connection, args)
        elif args.command == "list-repositories":
            refresh_all_stopped_scan_results(connection)
            result = native_indexes.list_repositories(connection, args)
        elif args.command == "list-findings":
            result = list_findings(connection, args)
        elif args.command in {"update-progress", "update-scan-context"}:
            result = progress.update(
                connection, args, now, require_scan, require_workspace, scan_context
            )
        elif args.command in {"prepare-scan-completion", "complete-scan"}:
            result = complete_scan(
                connection, args, prepare_only=args.command == "prepare-scan-completion"
            )
        elif args.command == "complete-budget-exhausted-scan":
            result = complete_budget_exhausted_scan(connection, args)
        elif args.command == "cancel-scan":
            result = cancel_scan(connection, args)
        elif args.command == "fail-scan":
            result = fail_scan(connection, args)
        elif args.command == "preserve-scan-results":
            result = preserve_scan_results(connection, args)
        elif args.command == "write-scan-draft":
            result = write_scan_draft(connection, args)
        elif args.command == "mark-handoff-delivered":
            result = handoff.mark_handoff_delivered(
                connection,
                args,
                now=now,
                require_scan=require_scan,
                require_workspace=require_workspace,
                workspace_state=workspace_state,
            )
        elif args.command == "claim-handoff-delivery":
            result = handoff.claim_handoff_delivery(
                connection,
                args,
                now=now,
                require_scan=require_scan,
                stale_claim_before=stale_claim_before,
                workspace_state=workspace_state,
            )
        elif args.command == "release-handoff-delivery":
            result = handoff.release_handoff_delivery(
                connection,
                args,
                now=now,
                require_scan=require_scan,
                workspace_state=workspace_state,
            )
        elif args.command == "attach-scan-continuation-thread":
            result = handoff.attach_scan_continuation_thread(
                connection,
                args,
                now=now,
                require_scan=require_scan,
                workspace_state=workspace_state,
            )
        elif args.command == "set-finding-triage":
            result = set_finding_triage(connection, args)
        elif args.command == "request-finding-remediation":
            result = request_finding_remediation(connection, args)
        elif args.command == "request-finding-remediation-action":
            result = request_finding_remediation_action(connection, args)
        elif args.command == "claim-finding-remediation-resend":
            result = claim_finding_remediation_resend(connection, args)
        elif args.command == "mark-finding-remediation-delivered":
            result = mark_finding_remediation_delivered(connection, args)
        elif args.command == "release-finding-remediation-claim":
            result = release_finding_remediation_claim(connection, args)
        elif args.command == "cancel-finding-remediation-request":
            result = scan_context(
                connection, remediation.cancel_finding_remediation_request(connection, args)
            )
        elif args.command == "set-finding-remediation":
            result = set_finding_remediation(connection, args)
        elif args.command == "prepare-linear-publication":
            result = prepare_linear_publication(connection, args)
        elif args.command == "record-linear-publications":
            result = record_linear_publications(connection, args)
        elif args.command == "export-findings":
            result = export_findings(connection, args)
        elif args.command == "database-info":
            result = {"databasePath": str(database_path())}
        else:
            raise SystemExit(f"Unknown command: {args.command}")
    print(json.dumps(result, allow_nan=False, sort_keys=True))


if __name__ == "__main__":
    main()
