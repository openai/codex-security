#!/usr/bin/env python3
"""Codex Security workbench persistence."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from contextlib import ExitStack, closing, contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

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
import workbench_finding_results as finding_results
import workbench_native_indexes as native_indexes
import workbench_progress as progress
import workbench_publication as publication
import workbench_remediation as remediation_state
import workbench_saved_results as saved_results
import workbench_scan_history as scan_history
import workbench_scan_usage as scan_usage
from finalize_scan_contract import (
    ContractError,
    RecoverableContractError,
    _prepare_scan_finalization,
    _write_prepared_scan_finalization,
    finalize_scan,
    manifest_is_sealed,
    open_scan_local_file_descriptor,
)
from windows_scan_local_files import pin_replay_metadata
from workbench import handoff
from workbench.storage import (
    create_private_directory,
    resolve_scan_root,
    saved_deep_workers,
    state_dir,
)
from workbench_cli import parse_args
from workbench_constants import (
    ARTIFACTS,
    CLAIM_LEASE_SECONDS,
    DELIVERED_ACTION_LEASE_SECONDS,
    FINDINGS_RESULT_LIMIT,
    SQLITE_RETRY_ATTEMPTS,
)
from workbench_feedback import get_scan_feedback
from workbench_finding_index import index_findings
from workbench_finding_workflows import finding_workflow, register_workflow_scan
from workbench_instruction_digest import (
    bundled_instruction_digest,
    pin_prepared_instruction_digests,
    selected_instruction_digest,
    verify_sealed_instruction_digests,
)
from workbench_scan_start import (
    archive_scan,
    insert_running_scan,
    prepare_cli_scan_target,
    register_windows_resume_output,
    restore_cli_scan_archive,
    safe_segment,
    scan_diff_identity,
    scan_target_identity,
    stored_diff_target,
)
from workbench_schema import (
    MIGRATIONS,
    migration_target_paths,
    recorded_git_checkout_roots,
)
from workbench_schema import (
    apply_migrations as apply_schema_migrations,
)
from workbench_setup import (
    inspect_command,
    inspect_selected_setup,
    inspect_setup_values,
    require_diff_target,
    require_review_changes_target,
    require_scannable_target,
    require_scope,
    require_target,
    resolve_git_commit,
)
from workbench_source_scopes import (
    capture_source_scopes,
    expected_target_kinds,
    public_scan_recipe,
    requested_finding_scope,
    requested_scan_file_paths,
    requested_scan_paths,
)
from workbench_target import (
    checked_scan_target,
    clean_worktree_content_digest,
    copy_directory_excluding,
    copy_git_worktree_files,
    diff_scope_file_count,
    directory_content_digest,
    directory_snapshot_regular_file_count,
    git_command,
    git_output,
    git_revision,
    git_submodule_entries,
    git_target_metadata,
    git_worktree_context,
    rejected_checkout_roots,
    remediation_checkout_snapshot,
    require_remediation_target,
    require_scan_target_identity,
    require_scan_target_unchanged,
    restore_directory_junctions,
    scan_target_warning,
    scoped_git_discovery,
    scoped_regular_file_count,
    worktree_content_digest,
    worktree_content_digest_for_context,
)
from workbench_target_state import (
    RepositoryIdentityCache,
    RepositoryScanScope,
    backfill_security_targets,
    ensure_security_target,
    register_security_target,
    require_scan_checkout_owner,
)
from workbench_validation import (
    optional_text,
    parse_scan_cost,
    path_within_scope,
    read_json_object,
    reject_non_finite_json,
    require_close_note,
    require_occurrence,
    require_uuid,
    sqlite_busy,
    user_context_argument,
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stale_claim_before(seconds: int = CLAIM_LEASE_SECONDS) -> str:
    return (
        (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    )


def database_path() -> Path:
    return state_dir() / "workbench.sqlite3"


@contextmanager
def scan_completion_lock(scan_id: str) -> Any:
    """Hold the cross-process lock for a scan ID until the context exits."""
    lock_dir = state_dir() / "completion-locks"
    create_private_directory(lock_dir)
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


def connect(
    *,
    deferred: bool = False,
    discovery_roots: tuple[Path, ...] = (),
    in_memory: bool = False,
) -> sqlite3.Connection:
    """Open the workbench SQLite database and bring its schema up to date.

    Args:
        deferred (bool): Let the first migration attempt defer its write lock.
            Retries after lock contention use an immediate transaction.

        discovery_roots: Additional local paths for bounded target discovery.
        in_memory: Keep a fresh profile read entirely in memory.

    Returns:
        sqlite3.Connection: A caller-owned connection with named rows, foreign
            keys enabled, and write-ahead logging.

    Raises:
        sqlite3.OperationalError: Opening or configuring the database fails, or
            lock contention persists after retries.
    """
    path = database_path()
    guidance = (
        f"Workbench database: {path}. Ensure the state directory and SQLite journal files "
        "are writable, or set CODEX_SECURITY_STATE_DIR to a writable directory outside "
        "the scanned repository."
    )
    try:
        if not in_memory:
            create_private_directory(path.parent)
    except OSError:
        print(guidance, file=sys.stderr)
        raise
    for attempt in range(SQLITE_RETRY_ATTEMPTS):
        try:
            connection = sqlite3.connect(":memory:" if in_memory else path, timeout=5)
        except sqlite3.OperationalError:
            print(guidance, file=sys.stderr)
            raise
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            # Keep writer admission retries; readers only wait when a repair needs to write.
            apply_migrations(
                connection, immediate=not deferred or attempt > 0, discovery_roots=discovery_roots
            )
            connection.execute("PRAGMA journal_mode = WAL")
            if not in_memory:
                path.chmod(0o600)
            return connection
        except sqlite3.OperationalError as exc:
            connection.close()
            if attempt == SQLITE_RETRY_ATTEMPTS - 1 or not sqlite_busy(exc):
                print(guidance, file=sys.stderr)
                raise
            time.sleep(0.05 * (2**attempt))
    raise AssertionError("SQLite retry loop exhausted unexpectedly.")


def begin_immediate_with_retry(connection: sqlite3.Connection) -> None:
    for attempt in range(SQLITE_RETRY_ATTEMPTS):
        try:
            connection.execute("BEGIN IMMEDIATE")
            return
        except sqlite3.OperationalError as exc:
            if attempt == SQLITE_RETRY_ATTEMPTS - 1 or not sqlite_busy(exc):
                raise
            time.sleep(0.05 * (2**attempt))


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    immediate: bool = False,
    discovery_roots: tuple[Path, ...] = (),
) -> None:
    apply_schema_migrations(
        connection,
        MIGRATIONS,
        now,
        backfill_security_targets,
        immediate=immediate,
        discovery_roots=discovery_roots,
    )


def scan_contract(scan: sqlite3.Row) -> dict[str, Any]:
    """Return the target identity, scope requirements, and diff target recorded for this scan."""
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
            "filePaths": requested_scan_file_paths(scan),
            **(
                {"requiredIncludePaths": requested_scan_paths(scan)}
                if scan["mode"] != "diff"
                else {}
            ),
        },
        "target": target_contract,
    }


expected_coverage_mode = scan_history.expected_coverage_mode


def workbench_completion_binding(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    completed_at: str,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return scan_history.workbench_completion_binding(
        _WORKBENCH_DB_CONTEXT, connection, scan, completed_at, manifest
    )


def verify_manifest_binding(
    scan: sqlite3.Row, manifest: dict[str, Any], connection: sqlite3.Connection
) -> None:
    """Raise SystemExit if the supplied manifest does not match the registered scan, target, or scope."""
    manifest_scan = manifest.get("scan")
    if not isinstance(manifest_scan, dict):
        raise SystemExit("scan-manifest.json scan must be an object.")
    if manifest_scan.get("id") != scan["id"]:
        raise SystemExit("scan-manifest.json scan.id must match the workbench scan ID.")
    if manifest_is_sealed(manifest_scan):
        verify_sealed_instruction_digests(scan, manifest_scan, connection)
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
    """Return a canonical UUID or resolve a unique scan ID prefix of at least eight characters.

    Raise SystemExit for a prefix that is too short, ambiguous, or absent from the database.
    """
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
    target_path = args.target_path if optional_text(args.target_path, maximum=4096) else None
    default_scope = args.scope if optional_text(args.scope, maximum=4096) else "."
    if any(len(value) > 4096 for value in (target_path, default_scope) if value is not None):
        raise SystemExit("Text value must be no longer than 4096 characters.")
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
    target_path_unvalidated = False
    rejected_roots = None
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
            # Setup may fail on scope even when the target itself is valid.
            try:
                require_target(target_path)
            except SystemExit:
                target_path_unvalidated = True
                rejected_roots = rejected_checkout_roots(target_path)
    with connection:
        target_id = (
            ensure_security_target(connection, target_path)
            if target_path is not None and not target_path_unvalidated
            else None
        )
        connection.execute(
            """
            INSERT INTO workspaces (
                id, thread_id, target_id, target_path, target_title, target_summary,
                default_scope, default_mode,
                user_context, diff_target_kind, diff_base_revision, diff_head_revision,
                diff_content_digest, created_at, updated_at, target_path_unvalidated, rejected_checkout_roots_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                target_path_unvalidated,
                json.dumps(rejected_roots) if rejected_roots is not None else None,
            ),
        )
    return workspace_state(connection, workspace_id)


def save_workspace(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    workspace = require_workspace(connection, args.workspace_id)
    if workspace["active_scan_id"]:
        raise SystemExit("This workspace already has a scan. Open a new workspace to change setup.")
    inspected = inspect_selected_setup(args)
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
                deep_scan_config_json = ?, submitted = 1, updated_at = ?, target_path_unvalidated = 0,
                -- JSON null keeps PATH discovery disabled after a legacy rejection.
                rejected_checkout_roots_json = COALESCE(rejected_checkout_roots_json,
                    CASE WHEN target_path_unvalidated = 1 AND target_id IS NULL THEN 'null' END)
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
                *scan_diff_identity(diff_target or None),
                json.dumps(inspected["deepScanConfig"]) if "deepScanConfig" in inspected else None,
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
    root = resolve_scan_root(scan_root)
    target_root = root / safe_segment(target.name)
    if os.name != "nt":
        target_root = target_root.resolve()
    if target_root == target or target in target_root.parents:
        raise SystemExit("The scan artifact directory must be outside the selected target.")
    return target_root


def scan_scope_file_count(
    target: Path, paths: list[str], diff_target: dict[str, str] | None
) -> int | None:
    if diff_target is not None:
        return diff_scope_file_count(target, diff_target)
    return sum(
        1 if (target / path).is_file() else directory_snapshot_regular_file_count(target / path)
        for path in paths
    )


def require_working_tree_unchanged(target: Path, diff_target: dict[str, str] | None) -> None:
    if (
        diff_target is not None
        and diff_target["kind"] == "working_tree"
        and (
            git_revision(target) != diff_target["headRevision"]
            or worktree_content_digest(target, expected_digest=diff_target["contentDigest"])
            != diff_target["contentDigest"]
        )
    ):
        raise SystemExit("The selected scan target changed while the scan was starting. Try again.")


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
            require_scan_checkout_owner(connection, active)
            return workspace_state(connection, workspace["id"], result_scan_id=active["id"])
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
        scope_file_count = scan_scope_file_count(target, [scope], diff_target)
        target_identity = scan_target_identity(
            target,
            diff_target,
            metadata=target_metadata,
        )
        source_scopes = capture_source_scopes(
            target,
            target_identity,
            [scope],
            diff_target_kind=diff_target["kind"] if diff_target is not None else None,
        )
        target_root = scan_target_root(args.scan_root, target)
        create_private_directory(target_root, scan_output=True)
        instruction_digest = selected_instruction_digest()
        require_working_tree_unchanged(target, diff_target)
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
            require_scan_checkout_owner(connection, active)
            if manages_transaction:
                connection.commit()
            return workspace_state(connection, workspace["id"], result_scan_id=active["id"])
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
        registration = register_security_target(connection, str(current_target))
        if registration.target_id != workspace["target_id"]:
            raise SystemExit(
                "The saved workspace no longer matches the selected repository target."
            )
        insert_running_scan(
            connection,
            scan_id=scan_id,
            workspace=workspace,
            target=target,
            scope=scope,
            diff_target=diff_target,
            target_identity=target_identity,
            repository_generation=registration.repository_generation,
            source_scopes=source_scopes,
            target_root=target_root,
            target_summary=target_summary,
            scope_file_count=scope_file_count,
            instruction_digest=instruction_digest,
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
    return workspace_state(connection, workspace["id"], result_scan_id=scan_id)


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
    scope_file_count = scan_scope_file_count(target, [scope], diff_target)
    diff_identity = scan_diff_identity(diff_target)
    target_identity = scan_target_identity(target, diff_target)
    source_scopes = capture_source_scopes(
        target,
        target_identity,
        [scope],
        diff_target_kind=diff_target["kind"] if diff_target is not None else None,
    )
    target_root = scan_target_root(args.scan_root, target)

    instruction_digest = selected_instruction_digest()
    busy_timeout = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
    for attempt in range(SQLITE_RETRY_ATTEMPTS):
        try:
            # Wait before hashing, then release the writer slot while reading the target.
            connection.execute("BEGIN IMMEDIATE")
            connection.rollback()
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
            # If another writer arrived during hashing, retry without waiting on a stale hash.
            connection.execute("PRAGMA busy_timeout = 0")
            try:
                connection.execute("BEGIN IMMEDIATE")
            finally:
                connection.execute(f"PRAGMA busy_timeout = {busy_timeout}")
            existing = connection.execute(
                """
                SELECT scans.* FROM scans
                JOIN workspaces ON workspaces.active_scan_id = scans.id
                WHERE COALESCE(scans.continuation_thread_id, workspaces.thread_id) = ?
                    AND scans.recipe_json IS NULL AND workspaces.target_path = ?
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
                            AND scans.continuation_thread_id = workspaces.thread_id
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
                ),
            ).fetchone()
            if existing is not None:
                require_scan_checkout_owner(connection, existing)
                connection.commit()
                return {
                    **scan_context(connection, existing["id"], model_thread_id=thread_id),
                    "startDisposition": "joined",
                }
            create_private_directory(target_root, scan_output=True)
            workspace_id = str(uuid.uuid4())
            scan_id = str(uuid.uuid4())
            timestamp = now()
            registration = register_security_target(connection, target_path)
            target_id = registration.target_id
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
                repository_generation=registration.repository_generation,
                source_scopes=source_scopes,
                target_root=target_root,
                target_summary=target_summary,
                scope_file_count=scope_file_count,
                instruction_digest=instruction_digest,
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
                    raise SystemExit(
                        "Codex Security headless scan ownership could not be recorded."
                    )
            connection.commit()
            break
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if attempt == SQLITE_RETRY_ATTEMPTS - 1 or not sqlite_busy(exc):
                raise
            time.sleep(0.05 * (2**attempt))
        except BaseException:
            connection.rollback()
            raise
    return {**scan_context(connection, scan_id), "startDisposition": "created"}


def scan_local_file_digest(scan_dir: Path, relative_path: str) -> str:
    """Return the SHA-256 of the scan-local file contents, prefixed with sha256:."""
    digest = hashlib.sha256()
    with open_scan_local_file(scan_dir, relative_path) as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def published_manifest_digest(scan_dir: Path, manifest: dict[str, Any]) -> str:
    """Return the canonical manifest digest or raise SystemExit if the published bytes differ."""
    canonical = (json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    expected = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    actual = scan_local_file_digest(scan_dir, ARTIFACTS["manifest"])
    if actual != expected:
        raise SystemExit("The sealed scan manifest changed while it was being published.")
    return expected


def require_recorded_manifest_digest(scan: sqlite3.Row, scan_dir: Path) -> None:
    """Raise SystemExit if the saved manifest differs from the digest recorded when the scan was sealed."""
    expected = scan["seal_manifest_digest"]
    if expected is None:
        return
    if scan_local_file_digest(scan_dir, ARTIFACTS["manifest"]) != expected:
        raise SystemExit("The sealed scan manifest changed after completion.")


def pin_legacy_manifest_digest(
    connection: sqlite3.Connection, scan_id: str, manifest_digest: str
) -> None:
    """Record a previously missing digest in a write transaction, rejecting a conflict with an existing digest."""
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        scan = require_scan(connection, scan_id)
        current = scan["seal_manifest_digest"]
        if current is not None and current != manifest_digest:
            raise SystemExit("The sealed scan manifest changed after completion.")
        if current is None:
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
                (manifest_digest, scan["id"]),
            )


def complete_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    prepare_only: bool = False,
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
            turn_id=getattr(args, "turn_id", None),
            model_thread_id=getattr(args, "model_thread_id", None),
        )


def read_scan_usage(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    # Validation can finish after the scan's recorded completion timestamp.
    usage = scan_usage.collect_scan_usage(
        connection,
        require_scan(connection, args.scan_id),
        thread_id=args.thread_id,
        validation_thread_id=args.validation_thread_id,
        completed_at=now(),
    )
    if "cacheWriteInputTokens" in usage:
        usage.setdefault("cacheWriteInputTokensReported", True)
    return usage


def finalize_scan_usage(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    with scan_completion_lock(scan_id):
        scan = require_scan(connection, scan_id)
        stored = json.loads(scan["cost_json"]) if scan["cost_json"] is not None else {}
        usage = stored.get("usage", {})
        completion = usage.get("completion")
        if scan["status"] != "complete" or not completion:
            raise SystemExit("The scan has no pending completion usage.")
        if completion["threadId"] != args.thread_id or completion["turnId"] != args.turn_id:
            raise SystemExit("The scan usage belongs to a different completion turn.")
        if not completion["finalized"]:
            usage = scan_usage.collect_scan_usage_safely(
                connection,
                scan,
                thread_id=args.thread_id,
                completed_turn_id=args.turn_id,
            )
            if usage["coverage"] == "unavailable":
                if not usage.get("accountRateLimits"):
                    return scan_context(connection, scan_id)
                usage = {**stored["usage"], "accountRateLimits": usage["accountRateLimits"]}
            else:
                if args.turn_status != "completed":
                    if usage["coverage"] == "complete":
                        usage["coverage"] = "partial"
                    usage["warnings"] = [
                        *usage.get("warnings", []),
                        f"scan_turn_{args.turn_status}",
                    ]
                usage["completion"] = {**completion, "finalized": True}
            fields = scan_usage.merge_scan_usage_fields(stored, {"usage": usage})
            fields["usage"]["completion"] = usage["completion"]
            cost_json = parse_scan_cost(json.dumps(fields))
            with connection:
                connection.execute(
                    "UPDATE scans SET cost_json = ? WHERE id = ?", (cost_json, scan_id)
                )
        return scan_context(connection, scan_id)


def complete_budget_exhausted_scan(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    """Complete a running CLI Deep Scan using the measured cost and saved results after its budget is exhausted."""
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
        warning = optional_text(args.message)
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
    scan: sqlite3.Row, scan_dir: Path, candidates: list[dict[str, Any]], warning: str
) -> None:
    saved_results.budget_exhausted_draft(sys.modules[__name__], scan, scan_dir, candidates, warning)


def complete_scan_locked(
    connection: sqlite3.Connection,
    scan_id: str,
    claim_token: str | None,
    cost_json: str | None,
    *,
    prepare_only: bool = False,
    thread_id: str | None = None,
    turn_id: str | None = None,
    model_thread_id: str | None = None,
) -> dict[str, Any]:
    scan = require_scan(connection, scan_id)
    handoff.require_tokenless_scan_owner(connection, scan, model_thread_id)
    if scan["status"] not in {"running", "complete"}:
        raise SystemExit("Only a running scan can be completed.")
    handoff.require_current_continuation(
        scan,
        claim_token,
        error_message="Scan completion is owned by another continuation.",
    )
    if scan["status"] == "complete":
        return saved_results.refresh_completed_scan(
            _WORKBENCH_DB_CONTEXT, connection, scan, cost_json
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
    current_manifest_path = artifact_path(scan_dir, ARTIFACTS["manifest"], required=False)
    current_manifest = None
    if current_manifest_path is not None:
        current_manifest = read_json_object(current_manifest_path)
    already_sealed = (
        current_manifest_path is not None
        and isinstance(current_manifest.get("scan"), dict)
        and manifest_is_sealed(current_manifest["scan"])
    )
    completion_binding = workbench_completion_binding(
        connection, scan, completion_timestamp, current_manifest
    )
    if scan["recipe_json"] is not None:
        missing_drafts = []
        for file_name in (
            ARTIFACTS["manifest"],
            ARTIFACTS["findings"],
        ):
            try:
                (scan_dir / file_name).lstat()
            except FileNotFoundError:
                missing_drafts.append(file_name)
                continue
            artifact_path(scan_dir, file_name, required=True)
        if missing_drafts:
            raise SystemExit(
                "Scan agent did not create required draft artifacts: "
                f"{', '.join(missing_drafts)}. Check that the scan agent can run shell "
                "commands and write to the scan directory before retrying."
            )
    merge_parent_draft = (
        scan["mode"] != "deep" and current_manifest_path is not None and not already_sealed
    )
    wrote = False
    try:
        with (
            saved_results.preserve_parent_head_on_error(scan_dir)
            if merge_parent_draft
            else nullcontext()
        ):
            draft_documents = (
                saved_results.merge_saved_results(
                    scan_dir,
                    scan["id"],
                    completion_binding,
                    saved_deep_workers(connection, scan),
                    warnings,
                    stopped=False,
                    scan_mode=scan["mode"],
                    reason="",
                )
                if merge_parent_draft
                else None
            )
            completion_manifest = draft_documents[0] if draft_documents else current_manifest
            if (
                completion_manifest is not None
                and isinstance(completion_manifest.get("scan"), dict)
                and completion_manifest["scan"].get("complete") is False
            ):
                raise RecoverableContractError(
                    "The latest saved scan draft is incomplete; continue the scan before completing it."
                )
            prepared = _prepare_scan_finalization(
                scan_dir,
                expected_coverage_mode=expected_coverage_mode(scan),
                completion_binding=completion_binding,
                recover_unsealed=scan["mode"] != "deep",
                allow_missing_writeups=True,
                draft_documents=draft_documents,
                finding_scope=requested_finding_scope(scan) if scan["mode"] == "deep" else None,
            )
        warnings.extend(warning for warning in prepared.warnings if warning not in warnings)
        add_warning()
        with connection:
            prepared_scan = prepared.manifest["scan"]
            if prepared.was_sealed:
                published_manifest_digest(scan_dir, prepared.manifest)
            else:
                # Bind the producer before a new seal can become visible.
                pin_prepared_instruction_digests(connection, scan_id, prepared_scan["producer"])
            if warnings != json.loads(scan["completion_warnings_json"]):
                # Retain pre-publication diagnostics even if output writes fail.
                connection.execute(
                    "UPDATE scans SET completion_warnings_json = ? WHERE id = ? AND status = 'running'",
                    (json.dumps(warnings), scan_id),
                )
            if scan["mode"] == "deep" and (
                not prepared.was_sealed
                or "coverageRef" in prepared_scan
                or "surfaces" in prepared_scan.get("reviewState", {})
            ):
                # A summary-only seal omits surfaces. Keep the count from its first preparation.
                connection.execute(
                    "UPDATE deep_scan_runs SET terminal_reviewed_surface_count = ? WHERE scan_id = ?",
                    (len(prepared.coverage["surfaces"]), scan_id),
                )
        wrote = True
        manifest, findings, _ = _write_prepared_scan_finalization(
            prepared, projection_warnings=warnings
        )
    except ContractError as exc:
        # Only a coordinator-selected parent is fenced for output-write replay.
        selected_deep_parent = scan["mode"] == "deep" and deep_scan.require_deep_scan_run(
            connection, scan_id
        )["manifest_path"] == str(scan_dir / ARTIFACTS["manifest"])
        if (wrote and not selected_deep_parent) or (
            scan["mode"] == "deep"
            and not wrote
            and not already_sealed
            and not isinstance(exc, RecoverableContractError)
        ):
            args = argparse.Namespace(claim_token=claim_token, cost_json=cost_json)
            args.message, args.scan_id = str(exc), scan_id
            saved_results.fail_scan_locked(_WORKBENCH_DB_CONTEXT, connection, args)
        raise SystemExit(str(exc)) from exc
    artifacts = {
        kind: artifact_path(scan_dir, filename, required=True)
        for kind, filename in ARTIFACTS.items()
    }
    manifest_digest = published_manifest_digest(scan_dir, manifest)
    reported_count = progress.reported_scope_file_count(_WORKBENCH_DB_CONTEXT, scan)
    if prepare_only:
        connection.execute("BEGIN IMMEDIATE")
        with connection:
            updated = connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ? AND status = 'running'",
                (json.dumps(warnings), scan["id"]),
            )
            if updated.rowcount != 1:
                raise SystemExit("Only a running scan can be prepared for completion.")
            if prepared.was_sealed:
                pin_prepared_instruction_digests(connection, scan_id, manifest["scan"]["producer"])
            if reported_count is not None:
                connection.execute(
                    """
                    UPDATE scan_progress SET scope_file_count = ?, updated_at = ?
                    WHERE scan_id = (SELECT id FROM scans WHERE id = ? AND scan_dir = ?
                        AND handoff_status = ? AND handoff_claim_token IS ?)
                    """,
                    (
                        reported_count,
                        completion_timestamp,
                        scan_id,
                        scan["scan_dir"],
                        scan["handoff_status"],
                        scan["handoff_claim_token"],
                    ),
                )
        context = scan_context(connection, scan["id"])
        context["targetWarnings"] = target_warnings
        return context

    measured_usage = scan_usage.collect_scan_usage_safely(
        connection,
        scan,
        thread_id=thread_id,
        completed_at=completion_timestamp,
    )
    cost_fields = scan_usage.merge_scan_usage_fields(
        scan_usage.stored_scan_cost_fields(cost_json), {"usage": measured_usage}
    )
    measured_usage = cost_fields["usage"]
    if thread_id is not None and turn_id is not None:
        measured_usage["completion"] = {
            "threadId": thread_id,
            "turnId": turn_id,
            "finalized": False,
        }
        if measured_usage["coverage"] == "complete":
            measured_usage["coverage"] = "partial"
        measured_usage["warnings"] = sorted(
            {*measured_usage.get("warnings", []), "turn_in_progress"}
        )
    cost_json = parse_scan_cost(json.dumps(cost_fields))
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = manifest["scan"]["completedAt"]
        scan = require_scan(connection, scan["id"])
        handoff.require_tokenless_scan_owner(connection, scan, model_thread_id)
        if scan["status"] not in {"running", "complete"}:
            raise SystemExit("Only a running scan can be completed.")
        handoff.require_current_continuation(
            scan,
            claim_token,
            error_message="Scan completion is owned by another continuation.",
        )
        if scan["status"] == "complete":
            connection.commit()
            return scan_context(connection, scan["id"])
        deep_scan.require_deep_scan_ready_for_parent_completion(connection, scan)
        if scan["scan_dir"] != str(scan_dir):
            reported_count = None
        if prepared.was_sealed:
            pin_prepared_instruction_digests(connection, scan_id, manifest["scan"]["producer"])
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
                scope_file_count = COALESCE(?, scope_file_count), updated_at = ?
            WHERE scan_id = ?
            """,
            (
                finding_count,
                len(artifacts),
                len(artifacts),
                reported_count,
                timestamp,
                scan["id"],
            ),
        )
        updated = connection.execute(
            """
            UPDATE scans
            SET status = 'complete', phase = 'reporting', completed_at = ?, updated_at = ?,
                log_completed_at = ?, seal_manifest_digest = ?, cost_json = ?,
                completion_warnings_json = ?
            WHERE id = ? AND status = 'running'
            """,
            (
                timestamp,
                timestamp,
                now(),
                manifest_digest,
                cost_json,
                json.dumps(warnings),
                scan["id"],
            ),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can be completed.")
    context = scan_context(connection, scan["id"])
    context["targetWarnings"] = target_warnings
    return context


def require_cli_scan_directory(repository: Path, args: argparse.Namespace) -> Path:
    # Registration uses an empty output, including the replacement created with
    # the original DACL after archival. Check that ACL before moving any results.
    scan_dir = require_canonical_scan_directory(
        Path(args.scan_dir).expanduser(), writable_output=True
    )
    if scan_dir == repository or repository in scan_dir.parents or scan_dir in repository.parents:
        raise SystemExit(
            "The scan artifact directory must be outside and not contain the selected target."
        )
    if (not args.archive_existing or args.archived_scan_dir is not None) and next(
        scan_dir.iterdir(), None
    ) is not None:
        raise SystemExit("The scan artifact directory must be empty before the scan starts.")
    return scan_dir


def register_cli_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    before_archive: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Register the scan recipe and target identity, archiving any previous output atomically."""
    # A selected plugin may replace __main__ while delegating to this workbench.
    before_output_change = before_archive or getattr(
        sys, "_codex_security_before_output_change", None
    )

    def acknowledge_output_change() -> None:
        nonlocal before_output_change
        if before_output_change is not None:
            before_output_change()
            before_output_change = None

    repository = require_target(args.repository)
    require_scannable_target(repository)
    if not args.archive_existing or args.archived_scan_dir is not None:
        # Preserve early output rejection when this call will not move the directory.
        require_cli_scan_directory(repository, args)
    user_context = None
    workflow_id = None
    custom_validation_sources = None
    hosted = False
    surface = None
    package_version = None
    if args.registration_json_stdin:
        registration = json.load(sys.stdin)
        custom_validation_sources = registration.get("customValidationSources")
        recipe_json = json.dumps(registration["recipe"], ensure_ascii=False, separators=(",", ":"))
        hosted = registration.get("hosted") is True
        user_context = registration.get("userContext")
        workflow_id = registration.get("workflowId")
        if registration.get("surface") in ("cli", "sdk"):
            surface = registration["surface"]
        if isinstance(registration.get("packageVersion"), str):
            package_version = registration["packageVersion"] or None
    else:
        recipe_json = sys.stdin.read() if args.recipe_json_stdin else args.recipe_json
    recipe = parse_scan_recipe(recipe_json, repository)
    launch_kind = "scan"
    if isinstance(recipe.get("import"), dict):
        launch_kind = "import"
    elif recipe.get("mock") is True:
        launch_kind = "mock"
    requested_target = recipe["target"]
    paths = requested_target["paths"]
    recipe.pop("_codexSecurityFileScopes", None)
    # Capture host-observed kinds once; resumes and publication use the saved recipe.
    recipe.pop("scopeFilePaths", None)
    if file_paths := [path for path in paths if (repository / path).is_file()]:
        recipe["scopeFilePaths"] = file_paths
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
    instruction_digest = None
    if not recipe.get("mock") and "import" not in recipe:
        if recipe.get("validationMode") != "custom":
            instruction_digest = selected_instruction_digest()
        elif isinstance(custom_validation_sources, dict) and custom_validation_sources:
            instruction_digest = selected_instruction_digest(custom_validation_sources)
    target_identity, resume_target = prepare_cli_scan_target(
        repository, diff_target, mode, launch_kind
    )
    source_scopes = capture_source_scopes(
        repository,
        target_identity,
        paths or ["."],
        diff_target_kind=diff_target["kind"] if diff_target is not None else None,
    )
    scope_file_count = (
        scoped_regular_file_count(repository, paths)
        if mode == "standard" and len(paths) > 1
        else scan_scope_file_count(repository, paths or ["."], diff_target)
    )
    require_working_tree_unchanged(repository, diff_target)
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
        with ExitStack() as archive:
            deadline = None
            while True:
                registration = register_security_target(connection, str(repository))
                target_id = registration.target_id
                if parent_scan_id is not None:
                    parent = require_scan(connection, parent_scan_id)
                    parent_scope = RepositoryScanScope(
                        registration.repository_generation, target_id
                    )
                    if not parent_scope.contains(parent):
                        raise SystemExit(
                            "A rerun must belong to the same repository as its parent scan."
                        )
                # Revalidate the output and its owner under the current write lock.
                scan_dir = require_cli_scan_directory(repository, args)
                try:
                    archived_scan_dir = archive.enter_context(
                        archive_scan(
                            connection,
                            args,
                            scan_dir,
                            timestamp,
                            require_canonical_scan_directory,
                            before_archive=acknowledge_output_change,
                        )
                    )
                    break
                except PermissionError as exc:
                    # A Windows patch writer can temporarily pin the source of this rename.
                    if (
                        getattr(exc, "winerror", None) not in {5, 32}
                        or exc.filename != str(scan_dir)
                        or not exc.filename2
                    ):
                        raise
                    if deadline is None:
                        timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
                        deadline = time.monotonic() + timeout / 1000
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise
                    connection.rollback()
                    scan_dir = None  # Revalidate the directory and its owner under the next lock.
                    time.sleep(min(0.05, remaining))
                    connection.execute("BEGIN IMMEDIATE")
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
                repository_generation=registration.repository_generation,
                source_scopes=source_scopes,
                target_root=scan_dir.parent,
                target_summary=None,
                scope_file_count=scope_file_count,
                instruction_digest=instruction_digest,
                timestamp=timestamp,
                handoff_status="delivered",
                scan_dir=scan_dir,
                surface=surface,
                package_version=package_version,
                launch_kind=launch_kind,
                hosted=hosted,
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
            if resume_target is not None:
                archive.enter_context(
                    register_windows_resume_output(
                        connection, scan_id, scan_dir, resume_target, acknowledge_output_change
                    )
                )
            scan = connection.execute(
                "SELECT scans.*, snapshot AS lifecycle_json FROM scans "
                "JOIN scan_lifecycles ON scan_id = scans.id WHERE scans.id = ?",
                (scan_id,),
            ).fetchone()
            connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {
        **({"archivedScanDir": str(archived_scan_dir)} if archived_scan_dir is not None else {}),
        "contract": scan_contract(scan),
        "lifecycle": json.loads(scan["lifecycle_json"]),
        **({"phase": scan["phase"]} if mode == "standard" else {}),
        **(
            {"canSaveTimeBudgetStart": True}
            if "maxTimeMinutes" in recipe and mode in {"standard", "diff"}
            else {}
        ),
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
            """UPDATE scans SET continuation_thread_id = ?1, updated_at = ?2,
               recipe_json = CASE WHEN ?3 IS NULL THEN recipe_json
                   ELSE json_insert(recipe_json, '$.timeBudgetStartedAt', ?3) END
               WHERE id = ?4""",
            (args.thread_id, now(), getattr(args, "time_budget_started_at", None), scan["id"]),
        )
    return {"scanId": scan["id"], "threadId": args.thread_id}


def set_scan_cost_limit(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    limit = args.max_cost_usd
    if not math.isfinite(limit) or limit <= 0:
        raise SystemExit("The scan cost limit must be a positive finite USD amount.")
    with scan_completion_lock(scan_id), connection:
        scan = require_scan(connection, scan_id)
        if scan["status"] != "running" or scan["recipe_json"] is None:
            raise SystemExit("Only a running CLI scan can increase its cost limit.")
        recipe = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
        previous = recipe.get("maxCostUsd")
        if (
            not isinstance(previous, (int, float))
            or isinstance(previous, bool)
            or limit <= previous
        ):
            raise SystemExit("The new cost limit must exceed the current limit.")
        recipe["maxCostUsd"] = limit
        connection.execute(
            "UPDATE scans SET recipe_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(recipe, allow_nan=False), now(), scan["id"]),
        )
    return {"scanId": scan["id"], "maxCostUsd": limit}


def parse_scan_recipe(value: str, repository: Path) -> dict[str, Any]:
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


def coverage_summary_for_history(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> dict[str, Any]:
    return scan_history.coverage_summary_for_history(
        _WORKBENCH_DB_CONTEXT, connection, scan, require_canonical_scan_directory
    )


def coverage_for_comparison(scan: sqlite3.Row) -> dict[str, Any]:
    return saved_results.coverage_for_comparison(_WORKBENCH_DB_CONTEXT, scan)


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
    with connection:
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        scan = require_scan(connection, occurrence["scan_id"])
        scan_history.require_finding_checkout_owner(connection, scan)
        indexed_finding = _indexed_scan_findings(connection, scan).get(occurrence["id"])
        triaged_occurrences = [occurrence]
        verification_ids = {occurrence["id"]}
        verification_loaded = False
        if indexed_finding is not None:
            triaged_occurrences = connection.execute(
                """
                SELECT occurrences.*
                FROM finding_occurrences AS occurrences
                JOIN scans ON scans.id = occurrences.scan_id
                WHERE occurrences.id IN (SELECT value FROM json_each(?))
                ORDER BY scans.rowid, occurrences.id
                """,
                (json.dumps(sorted(indexed_finding["occurrence_ids"])),),
            ).fetchall()
        if args.status == "closed":
            for checked_occurrence in triaged_occurrences:
                remediation = remediation_state.latest_attempt(connection, checked_occurrence["id"])
                if (
                    remediation is not None
                    and remediation["pending_action"] is not None
                    and not (
                        remediation["state"] == "failed"
                        and not remediation_state.remediation_claim_is_active(remediation)
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
                    if checked_occurrence["id"] not in verification_ids and not verification_loaded:
                        active_finding = _indexed_scan_findings(
                            connection,
                            scan,
                            include_resolved=False,
                            verification_occurrence_id=occurrence["id"],
                        ).get(occurrence["id"])
                        if active_finding is not None:
                            verification_ids.update(active_finding["active_occurrence_ids"])
                        verification_loaded = True
                    if checked_occurrence["id"] in verification_ids:
                        checked_scan = require_scan(connection, checked_occurrence["scan_id"])
                        require_remediation_checkout_unchanged(
                            checked_scan,
                            remediation,
                            require_applied_content=True,
                        )
        admission_sequence = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) FROM scan_admissions"
        ).fetchone()[0]
        for triaged_occurrence in triaged_occurrences:
            previous_triage = connection.execute(
                "SELECT status, close_reason, note, "
                "(SELECT admission_sequence FROM finding_decisions "
                "WHERE occurrence_id = finding_triage.occurrence_id "
                "ORDER BY decision_sequence DESC LIMIT 1) AS admission_sequence "
                "FROM finding_triage WHERE occurrence_id = ?",
                (triaged_occurrence["id"],),
            ).fetchone()
            changed = (
                previous_triage is None
                or (indexed_finding is not None and indexed_finding["status"] != args.status)
                or previous_triage["admission_sequence"] != admission_sequence
                or (
                    previous_triage["status"],
                    previous_triage["close_reason"],
                    previous_triage["note"],
                )
                != (args.status, close_reason, note)
            )
            if changed:
                connection.execute(
                    """
                    INSERT INTO finding_decisions (
                        id, occurrence_id, status, close_reason, note, created_at,
                        decision_sequence, scan_sequence, admission_sequence
                    ) VALUES (?, ?, ?, ?, ?, ?,
                        (SELECT COALESCE(MAX(decision_sequence), 0) + 1 FROM finding_decisions),
                        (SELECT COALESCE(MAX(rowid), 0) FROM scans), ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        triaged_occurrence["id"],
                        args.status,
                        close_reason,
                        note,
                        timestamp,
                        admission_sequence,
                    ),
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
                (
                    triaged_occurrence["id"],
                    args.status,
                    close_reason,
                    note,
                    timestamp,
                ),
            )
    return scan_context(connection, occurrence["scan_id"])


def require_finding_open(connection: sqlite3.Connection, occurrence_id: str) -> None:
    occurrence = require_occurrence(connection, occurrence_id)
    scan = require_scan(connection, occurrence["scan_id"])
    scan_history.require_finding_checkout_owner(connection, scan)
    triage = _indexed_scan_findings(connection, scan).get(occurrence_id)
    if triage is None:
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
    with connection:
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
        latest = remediation_state.latest_attempt(connection, occurrence["id"])
        if latest is not None:
            active_operation = latest["pending_action"] is not None or latest["state"] in {
                "requested",
                "verifying",
            }
            if active_operation and (
                latest["state"] != "failed" or remediation_state.remediation_claim_is_active(latest)
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
    return scan_context(connection, occurrence["scan_id"])


def request_finding_remediation_action(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    with connection:
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        scan = require_scan(connection, occurrence["scan_id"])
        current = remediation_state.require_request(connection, request_id, occurrence)
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
    return scan_context(connection, occurrence["scan_id"])


def claim_finding_remediation_resend(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = now()
        occurrence = require_occurrence(connection, args.occurrence_id)
        require_finding_open(connection, occurrence["id"])
        current = remediation_state.require_request(connection, request_id, occurrence)
        if current["pending_action"] is None:
            raise SystemExit("This remediation attempt does not have a pending host request.")
        if current["pending_action_claim_token"] == action_token:
            connection.commit()
            result = scan_context(connection, occurrence["scan_id"])
            result["actionToken"] = action_token
            return result
        delivered_at = current["pending_action_delivered_at"]
        if delivered_at is not None:
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
    result = scan_context(connection, occurrence["scan_id"])
    result["actionToken"] = action_token
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
    with connection:
        # An owned attempt may finish after a saved match inherits a triage closure.
        occurrence = require_occurrence(connection, args.occurrence_id)
        scan = require_scan(connection, occurrence["scan_id"])
        current = remediation_state.require_request(connection, request_id, occurrence)
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
        remediation_state.require_transition(current["state"], args.state)
        remediation_state.require_pending_action(current, args.state)
        patch = sys.stdin.buffer.read() if args.patch_stdin else None
        patch_path, patch_digest = remediation_state.patch_metadata(
            current, args, patch, partial(require_scan_relative_file, scan)
        )
        base_revision = optional_text(args.base_revision, maximum=512)
        if args.state in {"generated", "applied", "verifying", "verified"}:
            if patch_path is None or patch_digest is None:
                raise SystemExit(
                    "Generated remediation states require a scan-local patch path and digest."
                )
            if patch is None:
                require_matching_patch_digest(scan, patch_path, patch_digest)
        if args.state == "generated":
            require_remediation_checkout_unchanged(scan, current, require_base_content=True)
            if patch is not None:
                remediation_state.require_valid_patch(Path(scan["target_path"]), patch)
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

        def record_update() -> None:
            connection.execute("BEGIN IMMEDIATE")
            timestamp = now()
            occurrence = require_occurrence(connection, args.occurrence_id)
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

        if patch is None:
            record_update()
        else:
            try:
                remediation_state.save_patch(
                    _WORKBENCH_DB_CONTEXT,
                    connection,
                    scan["id"],
                    current,
                    patch_path,
                    patch_digest,
                    patch,
                    record_update,
                )
            except (ContractError, OSError, SystemExit) as exc:
                raise SystemExit(f"Could not save the remediation patch: {exc}") from exc
    if getattr(args, "assigned_finding", False):
        return assigned_remediation_context(
            connection,
            occurrence["scan_id"],
            occurrence["id"],
            request_id,
            action_token,
            written_version=args.expected_version + 1,
        )
    return scan_context(connection, occurrence["scan_id"], occurrence["id"])


def assigned_remediation_context(
    connection: sqlite3.Connection,
    scan_id: str,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    *,
    written_version: int | None = None,
) -> dict[str, Any]:
    """After authorization, project only the assigned finding and check the returned action state."""
    occurrence = require_occurrence(connection, occurrence_id)
    if occurrence["details_json"] == "{}":
        backfill_legacy_finding_details(connection, require_scan(connection, scan_id))
        occurrence = require_occurrence(connection, occurrence_id)
    if occurrence["scan_id"] != scan_id:
        raise SystemExit("This finding does not belong to the selected scan.")
    scan = require_scan(connection, scan_id)
    finding = finding_result(connection, scan, occurrence, related=None)
    state = finding["remediationState"]
    if written_version is None:
        if not (
            state.get("requestId") == request_id
            and state.get("actionClaimToken") == action_token
            and state.get("pendingAction")
        ):
            raise SystemExit(
                "This remediation action is no longer owned by the supplied request and action token."
            )
    elif (
        state.get("requestId") != request_id
        or state.get("version") != written_version
        or state.get("actionClaimToken") not in (None, action_token)
    ):
        # The next action may already have started since this write committed.
        return {"occurrenceId": occurrence_id, "requestId": request_id, "version": written_version}
    return {
        "scan": {
            "scanId": scan["id"],
            "targetPath": scan["target_path"],
            "targetRevision": scan["target_revision"],
            "scanDir": scan["scan_dir"],
            "findings": [finding],
        }
    }


def require_reviewed_patch_applied(
    scan: sqlite3.Row, remediation: sqlite3.Row, patch_path: str
) -> str | None:
    target = require_scan_target_identity(scan)
    _, content_digest = remediation_checkout_snapshot(
        scan,
        expected_revision=remediation["base_revision"],
        expected_digest=remediation["base_content_digest"],
    )
    if content_digest == remediation["base_content_digest"]:
        raise SystemExit(
            "The selected checkout is unchanged; apply the reviewed patch before recording it as applied."
        )
    unversioned = remediation["base_revision"] == "unversioned"
    excluded = (Path(scan["scan_dir"]),)
    # Unborn repositories still need their config while metadata junctions are deferred.
    git_dir = git_output(target, "rev-parse", "--absolute-git-dir")
    metadata = Path(git_dir) if git_dir is not None else None
    if not unversioned:
        repository, pathspec = git_worktree_context(target)
        if git_dir is None:
            raise SystemExit("Could not inspect the selected Git working tree.")
        excluded += tuple(path for path, _ in git_submodule_entries(target))
    with (
        tempfile.TemporaryDirectory(prefix="codex-security-remediation-") as temporary,
        ExitStack() as pins,
    ):
        pinned_metadata = pin_replay_metadata(pins, metadata, Path(temporary))
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
            junctions = copy_directory_excluding(target, checkout, excluded)
        else:
            _, junctions = copy_git_worktree_files(target, checkout_root, excluded)
        short, replay_root = remediation_state.reverse_reviewed_patch(
            target,
            checkout_root,
            metadata,
            pinned_metadata,
            remediation["patch_digest"],
            pins,
            reviewed_patch,
            None if unversioned else pathspec,
        )
        restore_directory_junctions(
            target if unversioned else repository,
            checkout if unversioned else checkout_root,
            junctions,
        )
        reverted_digest = (
            directory_content_digest(checkout, replay_git_dir=replay_root)
            if unversioned
            else worktree_content_digest_for_context(
                checkout_root,
                pathspec or ".",
                git_dir=short or metadata,
                work_tree=checkout_root,
                expected_digest=remediation["base_content_digest"],
            )
        )
        if reverted_digest != remediation["base_content_digest"] and unversioned:
            checkout = Path(temporary) / "checkout-lf"
            junctions = copy_directory_excluding(target, checkout, excluded)
            applied_without_conversion = git_command(
                checkout,
                "-c",
                "core.autocrlf=input",
                "apply",
                "--reverse",
                "--whitespace=nowarn",
                "--no-index",
                str(reviewed_patch),
                text=True,
            )
            if applied_without_conversion.returncode == 0:
                restore_directory_junctions(target, checkout, junctions)
                reverted_digest = directory_content_digest(checkout, replay_git_dir=replay_root)
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
    expected_digest = (
        remediation["applied_content_digest"]
        if require_applied_content
        else remediation["base_content_digest"]
        if require_base_content
        else None
    )
    _, content_digest = remediation_checkout_snapshot(
        scan, expected_revision=remediation["base_revision"], expected_digest=expected_digest
    )
    if expected_digest is not None and content_digest != expected_digest:
        raise SystemExit(
            "Working-tree contents changed. Regenerate the remediation patch against the current checkout."
        )


def require_scan_relative_file(scan: sqlite3.Row, value: str) -> str:
    if len(value) > 4096:
        raise SystemExit("Text value must be no longer than 4096 characters.")
    if not value.strip() or "\\" in value:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    artifact_path(Path(scan["scan_dir"]), parsed.as_posix(), required=True)
    return parsed.as_posix()


def require_matching_patch_digest(scan: sqlite3.Row, patch_path: str, patch_digest: str) -> None:
    if scan_local_file_digest(Path(scan["scan_dir"]), patch_path) != patch_digest:
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
    result_scan: dict[str, Any] | None = None,
    thread_id: str | None = None,
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
        **(
            {"deepScanConfig": json.loads(workspace["deep_scan_config_json"])}
            if workspace["deep_scan_config_json"] is not None
            else {}
        ),
        "setupValidation": {"error": None, "valid": bool(workspace["submitted"])},
        "targetPath": workspace["target_path"],
        "targetSummary": workspace["target_summary"],
        "targetTitle": workspace["target_title"],
        "updatedAt": workspace["updated_at"],
        "userContext": workspace["user_context"],
    }
    selected_scan_id = result_scan_id or workspace["active_scan_id"]
    if selected_scan_id:
        if result_scan is None:
            result_scan = scan_result(connection, require_scan(connection, selected_scan_id))
        result["userContext"] = result_scan["userContext"]
        result["results"] = result_scan
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
                # Target metadata is optional; retain the original setup error for the caller.
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
    *,
    model_thread_id: str | None = None,
) -> dict[str, Any]:
    scan = require_scan(connection, scan_id)
    # Legacy backfill may write before scan_result reloads the row for its response.
    handoff.require_tokenless_scan_owner(connection, scan, model_thread_id)
    result = scan_result(
        connection, scan, occurrence_id=occurrence_id, model_thread_id=model_thread_id
    )
    workspace_result = result
    if len(result["findings"]) > FINDINGS_RESULT_LIMIT:
        workspace_result = dict(
            result, findings=result["findings"][:FINDINGS_RESULT_LIMIT], findingsTruncated=True
        )
    workspace = workspace_state(
        connection,
        scan["workspace_id"],
        result_scan_id=scan["id"],
        result_scan=workspace_result,
    )
    context = {
        "otherRunningDeepScans": deep_scan.other_running_deep_scans(connection, scan["id"]),
        "scan": result,
        "workspace": workspace,
    }
    if scan["recipe_json"] is not None:
        context["parentScanId"] = scan["parent_scan_id"]
        context["recipe"] = public_scan_recipe(scan)
    return context


def _indexed_scan_findings(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    through_scan: sqlite3.Row | None = None,
    include_resolved: bool = True,
    verification_occurrence_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    return native_indexes.indexed_scan_findings(
        connection,
        scan,
        read_coverage=coverage_for_comparison,
        through_scan=through_scan,
        include_resolved=include_resolved,
        verification_occurrence_id=verification_occurrence_id,
    )


def scan_finding_triage(
    connection: sqlite3.Connection, scan: sqlite3.Row, *, through_scan: sqlite3.Row | None = None
) -> dict[str, dict[str, Any]]:
    return finding_results.scan_finding_triage(
        connection, scan, _indexed_scan_findings(connection, scan, through_scan=through_scan)
    )


def get_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan = require_scan(connection, args.scan_id)
    if getattr(args, "check_target", False):
        require_scan_target_unchanged(scan)
    if getattr(args, "metadata_only", False):
        owner = scan_history.scan_has_current_owner(
            connection, scan, RepositoryIdentityCache(connection)
        )
        return {
            "scan": {
                "scanId": scan["id"],
                "scanDir": scan["scan_dir"],
                "targetPath": scan["target_path"],
                "progress": {"status": "canceled" if scan["canceled_at"] else scan["status"]},
                "remediationAvailable": owner and remediation_availability(scan)[0],
            }
        }
    context_claim = getattr(args, "context_claim_token", None)
    if args.occurrence_id is not None or not scan_history.is_unbound_standard_handoff(
        connection, scan, context_claim
    ):
        scan_history.require_finding_checkout_owner(connection, scan)
    if getattr(args, "progress_only", False):
        scan = connection.execute(
            """
            SELECT scans.id, scans.mode, scans.phase, scans.status, scans.canceled_at,
                   progress.*, progress.updated_at AS progress_updated_at
            FROM scans JOIN scan_progress AS progress ON progress.scan_id = scans.id
            WHERE scans.id = ?
            """,
            (resolve_scan_id(connection, args.scan_id),),
        ).fetchone()
        if scan is None:
            raise SystemExit("Codex Security scan not found.")
        progress_result, _ = progress.scan_progress_result(connection, scan)
        return {"scan": {"progress": progress_result}}
    request_id = getattr(args, "request_id", None)
    action_token = getattr(args, "action_token", None)
    if request_id is not None or action_token is not None:
        scan_id = require_uuid(args.scan_id, "scan-id")
        request_id = require_uuid(request_id or "", "request-id")
        action_token = require_uuid(action_token or "", "action-token")
        authorized = connection.execute(
            """
            SELECT 1 FROM finding_remediation_attempts AS action
            JOIN finding_occurrences AS finding ON finding.id = action.occurrence_id
            WHERE finding.scan_id = ? AND finding.id = ? AND action.request_id = ?
                AND action.pending_action_claim_token = ? AND action.pending_action IS NOT NULL
            """,
            (scan_id, args.occurrence_id, request_id, action_token),
        ).fetchone()
        if authorized is None:
            raise SystemExit(
                "This remediation action is no longer owned by the supplied request and action token."
            )
        return assigned_remediation_context(
            connection, scan_id, args.occurrence_id, request_id, action_token
        )
    model_thread = getattr(args, "model_thread_id", None)
    if context_claim is not None:
        scan = require_scan(connection, args.scan_id)
        handoff.require_tokenless_scan_owner(connection, scan, model_thread)
        if scan["handoff_status"] == "pending":
            detail = (
                "Pass the handoffClaimToken returned by the Codex Security scan launcher."
                if scan["handoff_claim_token"]
                else "Claim the pending Codex Security scan handoff before loading its context."
            )
            raise SystemExit(f"This Codex Security scan handoff has not been delivered. {detail}")
        if context_claim:
            context_claim = handoff.require_handoff_claim_token(context_claim)
        if scan["handoff_claim_token"] and scan["handoff_claim_token"] != context_claim:
            if not model_thread:
                raise SystemExit("Scan context requires its current continuation claim.")
            owner = (
                scan["continuation_thread_id"]
                or require_workspace(connection, scan["workspace_id"])["thread_id"]
            )
            if model_thread != owner:
                raise SystemExit("Scan context is owned by another continuation.")
        if (
            args.occurrence_id is not None
            and connection.execute(
                "SELECT 1 FROM finding_occurrences WHERE scan_id = ? AND id = ?",
                (scan["id"], args.occurrence_id),
            ).fetchone()
            is None
        ):
            raise SystemExit("This finding was not found in the selected scan.")
    result = scan_context(
        connection, args.scan_id, args.occurrence_id, model_thread_id=model_thread
    )
    if result["scan"]["progress"]["status"] != "running":
        try:
            result["scan"] = dict(
                result["scan"], coverage=coverage_summary_for_history(connection, scan)
            )
        except (OSError, RuntimeError, SystemExit):
            pass  # Historical artifacts may no longer be available or verifiable.
    return result


def list_findings(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan = require_scan(connection, args.scan_id)
    scan_history.require_finding_checkout_owner(connection, scan)
    backfill_legacy_finding_details(connection, scan)
    indexed = _indexed_scan_findings(connection, scan)
    connection.create_function(
        "codex_security_aggregate_status",
        2,
        lambda occurrence_id, status: indexed.get(occurrence_id, {}).get("status", status),
        deterministic=True,
    )
    limit = args.limit
    rows = scan_history.finding_occurrence_rows(
        connection,
        scan["id"],
        offset=args.offset,
        limit=limit,
        query=args.query,
        severity=args.severity,
        status=args.status,
        aggregate_status=True,
    )
    conditions, values = scan_history.finding_occurrence_conditions(
        scan["id"],
        query=args.query,
        severity=args.severity,
        status=args.status,
        aggregate_status=True,
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
    relations = scan_history.finding_relations(connection, scan["id"], (row["id"] for row in rows))
    return {
        "findingsPage": {
            "findings": [
                finding_result(
                    connection,
                    scan,
                    row,
                    indexed_finding=indexed.get(row["id"]),
                    related=relations.get(row["id"], []),
                )
                for row in rows
            ],
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
    model_thread_id: str | None = None,
) -> dict[str, Any]:
    """Assemble the workbench view of a saved scan, backfilling older finding details as needed.

    An occurrence ID selects one finding from that scan. An occurrence belonging
    to a different scan raises SystemExit.
    """
    backfill_legacy_finding_details(connection, scan)
    scan = scan_history.scan_with_progress(connection, scan["id"])
    handoff.require_tokenless_scan_owner(connection, scan, model_thread_id)
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
    model_fields = saved_results.threat_model_fields(_WORKBENCH_DB_CONTEXT, connection, scan)
    if path := model_fields.get("threatModelPath"):
        artifacts["threatModel"] = path
    occurrence_rows = scan_history.finding_occurrence_rows(
        connection, scan["id"], offset=0, limit=FINDINGS_RESULT_LIMIT
    )
    if occurrence_id is not None:
        occurrence = require_occurrence(connection, occurrence_id)
        if occurrence["scan_id"] != scan["id"]:
            raise SystemExit("This finding does not belong to the selected scan.")
        if all(row["id"] != occurrence["id"] for row in occurrence_rows):
            occurrence_rows.append(occurrence)
    indexed_findings = (
        _indexed_scan_findings(connection, scan)
        if occurrence_rows
        and (
            scan["status"] == "complete"
            or (scan["status"] == "failed" and scan["seal_manifest_digest"] is not None)
        )
        else {}
    )
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
    finding_count = sum(severity_counts.values())
    remediation_available, remediation_unavailable_reason = remediation_availability(scan)
    progress_result, review_updated_at = progress.scan_progress_result(connection, scan)
    current_target = connection.execute(
        "SELECT current_path FROM security_targets WHERE id = ?", (scan["target_id"],)
    ).fetchone()
    relations = scan_history.finding_relations(
        connection, scan["id"], (row["id"] for row in occurrence_rows)
    )
    return {
        "artifacts": artifacts,
        **model_fields,
        "canceledAt": scan["canceled_at"],
        "logCompletedAt": scan["log_completed_at"],
        **scan_usage.stored_scan_cost_fields(scan["cost_json"]),
        "contract": scan_contract(scan),
        "continuationThreadId": scan["continuation_thread_id"],
        "threadIds": scan_usage._scan_root_thread_ids(connection, scan, None),
        "executionThreadIds": scan_usage._scan_execution_thread_ids(connection, scan),
        "failureMessage": scan["failure_message"],
        "lifecycle": json.loads(scan["lifecycle_json"]),
        "findings": [
            finding_result(
                connection,
                scan,
                row,
                indexed_finding=indexed_findings.get(row["id"]),
                related=relations.get(row["id"], []),
            )
            for row in occurrence_rows
        ],
        "findingCount": finding_count,
        "findingsTruncated": finding_count > len(occurrence_rows),
        "severityCounts": severity_counts,
        "handoffClaimedAt": scan["handoff_claimed_at"],
        "handoffClaimToken": scan["handoff_claim_token"],
        "handoffStatus": scan["handoff_status"],
        "mode": scan["mode"],
        "model": scan["model"],
        "diffTarget": stored_diff_target(scan),
        "name": scan["name"],
        "progress": progress_result,
        "reasoningEffort": scan["reasoning_effort"],
        "remediationAvailable": remediation_available,
        "remediationUnavailableReason": remediation_unavailable_reason,
        "reportAvailable": "markdownReport" in artifacts,
        "resultsRecoveryNeeded": saved_results.scan_results_recovery_needed(
            _WORKBENCH_DB_CONTEXT, connection, scan
        ),
        "scanDir": scan["scan_dir"],
        "scanId": scan["id"],
        "scope": scan["scope"],
        "targetPath": scan["target_path"],
        **(
            {"currentTargetPath": current_target["current_path"]}
            if current_target is not None and current_target["current_path"] != scan["target_path"]
            else {}
        ),
        "targetRevision": scan["target_revision"],
        "targetSummary": scan["target_summary"],
        "updatedAt": max(
            scan["updated_at"],
            scan["progress_updated_at"],
            review_updated_at,
            finding_results.finding_management_updated_at(connection, scan["id"]) or "",
        ),
        "userContext": scan["user_context"],
        "warnings": json.loads(scan["completion_warnings_json"]),
    }


def remediation_availability(scan: sqlite3.Row) -> tuple[bool, str | None]:
    if scan["status"] != "complete":
        return False, remediation_state.SCAN_STATUS_ERROR
    try:
        with checked_scan_target(scan) as target:
            current_revision = git_revision(target)
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
        verify_manifest_binding(
            scan, read_json_object(scan_dir / ARTIFACTS["manifest"]), connection
        )
        manifest, findings_document, _ = finalize_scan(
            scan_dir,
            expected_coverage_mode=expected_coverage_mode(scan),
            verify_manifest=lambda manifest: verify_manifest_binding(scan, manifest, connection),
        )
        manifest_digest = published_manifest_digest(scan_dir, manifest)
    except (ContractError, OSError, SystemExit, ValueError):
        return

    by_occurrence = {finding["occurrenceId"]: finding for finding in findings_document["findings"]}
    updates = []
    for row in legacy_rows:
        finding = by_occurrence.get(row["id"])
        if not finding_results.legacy_finding_matches(row, finding):
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

    begin_immediate_with_retry(connection)
    with connection:
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


def finding_result(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    occurrence: sqlite3.Row,
    *,
    full_details: bool = False,
    indexed_finding: dict[str, Any] | None = None,
    related: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if full_details:
        indexed_finding = _indexed_scan_findings(connection, scan).get(occurrence["id"])
    return finding_results.finding_result(
        connection,
        scan,
        occurrence,
        full_details=full_details,
        indexed_finding=indexed_finding,
        remediation_state=finding_remediation_result(connection, occurrence["id"]),
        related=(
            related
            if related is not None
            else scan_history.finding_relations(connection, scan["id"], (occurrence["id"],)).get(
                occurrence["id"], []
            )
        ),
    )


finding_remediation_result = partial(
    remediation_state.finding_remediation_result, open_scan_file=open_scan_local_file
)


def patch_artifact_preview(
    scan_dir: Path, relative_path: str | None, expected_digest: str | None
) -> tuple[str | None, dict[str, int | bool] | None]:
    return remediation_state.patch_artifact_preview(
        scan_dir, relative_path, expected_digest, open_scan_local_file
    )


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


def require_canonical_scan_directory(scan_dir: Path, *, writable_output: bool = False) -> Path:
    scan_dir = scan_dir.absolute()
    try:
        metadata = scan_dir.lstat()
        resolved = scan_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SystemExit(
            "Scan directory must be an existing canonical non-symlink directory."
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or os.path.normcase(resolved) != os.path.normcase(
        scan_dir
    ):
        raise SystemExit("Scan directory must be an existing canonical non-symlink directory.")
    # Re-check ownership and parents so the scan directory cannot be substituted.
    if os.name == "nt":
        from windows_scan_local_files import require_windows_output_path

        try:
            require_windows_output_path(scan_dir, writable_output=writable_output)
        except OSError as exc:
            raise SystemExit(str(exc)) from exc
    else:
        geteuid = getattr(os, "geteuid", None)
        effective_uid = geteuid() if geteuid is not None else None
        if effective_uid is not None and metadata.st_uid != effective_uid:
            raise SystemExit("Scan directory must be owned by the current user.")
        for parent in scan_dir.parents:
            try:
                parent_metadata = parent.lstat()
            except OSError as exc:
                raise SystemExit("Scan output parent could not be inspected.") from exc
            if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
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


_WORKBENCH_PUBLICATION_CONTEXT = SimpleNamespace(**globals(), finding_triage=scan_finding_triage)


_WORKBENCH_DB_CONTEXT = SimpleNamespace(**globals())


def main(*, before_archive: Callable[[], None] | None = None) -> None:
    # Workbench callers send UTF-8 even when Windows uses a legacy code page.
    sys.stdin.reconfigure(encoding="utf-8")
    args = parse_args(__doc__)
    command_context = SimpleNamespace(
        **globals(),
        preserve_stopped_results=preserve_stopped_results_after_transition,
    )
    deep_scan.configure(command_context)
    if args.command == "measure-deep-scan-instructions":
        selected = json.load(sys.stdin)
        digest = bundled_instruction_digest(selected["pluginRoot"], selected["roleDigests"])
        print(json.dumps({"instructionDigest": digest}))
        return
    if args.command == "resolve-scan-root":
        print(json.dumps({"scanRoot": str(resolve_scan_root(args.scan_root))}))
        return
    if args.command in {"inspect-target", "inspect-setup"}:
        print(json.dumps(inspect_command(args), allow_nan=False, sort_keys=True))
        return
    if args.command in {"save-artifact", "read-artifact"}:
        print(json.dumps(saved_results.read_or_save_artifact(args)))
        return
    if args.command == "finding-issues":
        try:
            result = publication.finding_issues(
                _WORKBENCH_PUBLICATION_CONTEXT, json.load(sys.stdin)
            )
        except sqlite3.OperationalError as exc:
            if not getattr(exc, "_codex_security_state_unavailable", False):
                raise
            print(f"sqlite3.OperationalError: {exc}", file=sys.stderr)
            raise SystemExit(73) from None
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return
    command_targets = tuple(
        Path(value).expanduser()
        for field in ("target_path", "repository")
        for raw in (getattr(args, field, None),)
        for value in (raw if isinstance(raw, list) else [raw])
        if value
    )
    with (
        closing(
            connect(
                deferred=args.command
                in {
                    "get-scan",
                    "get-finding",
                    "read-scan-usage",
                    "list-scans",
                    "database-info",
                    "update-progress",
                },
                discovery_roots=command_targets,
                in_memory=scan_history.reads_missing_history(args, database_path()),
            )
        ) as connection,
        scoped_git_discovery(
            lambda: [*migration_target_paths(connection), *command_targets],
            recorded_git_roots=lambda: recorded_git_checkout_roots(connection),
        ),
    ):
        remediation_state.require_available(connection, args, require_scan)
        handlers = {
            "create-workspace": create_workspace,
            "save-workspace": save_workspace,
            "start-scan": start_scan,
            "begin-deep-scan": deep_scan.begin_deep_scan,
            "acknowledge-deep-scan-result": deep_scan.acknowledge_deep_scan_result,
            "get-deep-scan": deep_scan.get_deep_scan,
            "claim-deep-scan-coordinator": deep_scan.claim_deep_scan_coordinator,
            "upsert-deep-scan-worker": deep_scan.upsert_deep_scan_worker,
            "record-deep-scan-iteration": deep_scan.record_deep_scan_iteration,
            "finish-deep-scan": deep_scan.finish_deep_scan,
            "fail-deep-scan": deep_scan.fail_deep_scan,
            "record-deep-scan-publication-failure": deep_scan.record_deep_scan_publication_failure,
            "list-scans": scan_history.list_scans,
            "register-cli-scan": partial(register_cli_scan, before_archive=before_archive),
            "restore-cli-scan-archive": partial(
                restore_cli_scan_archive, canonical_directory=require_canonical_scan_directory
            ),
            "set-scan-thread": set_scan_thread,
            "set-scan-cost-limit": set_scan_cost_limit,
            "read-scan-usage": read_scan_usage,
            "finalize-scan-usage": finalize_scan_usage,
            "list-global-findings": partial(
                native_indexes.list_global_findings, read_coverage=coverage_for_comparison
            ),
            "list-repositories": partial(
                native_indexes.list_repositories, read_coverage=coverage_for_comparison
            ),
            "list-findings": list_findings,
            "complete-budget-exhausted-scan": complete_budget_exhausted_scan,
            "set-finding-triage": set_finding_triage,
            "request-finding-remediation": request_finding_remediation,
            "request-finding-remediation-action": request_finding_remediation_action,
            "claim-finding-remediation-resend": claim_finding_remediation_resend,
            "mark-finding-remediation-delivered": mark_finding_remediation_delivered,
            "release-finding-remediation-claim": release_finding_remediation_claim,
            "set-finding-remediation": set_finding_remediation,
            "update-progress": partial(progress.update_progress, command_context),
            "update-scan-context": partial(progress.update_context, command_context),
            "cancel-scan": partial(saved_results.cancel_scan, _WORKBENCH_DB_CONTEXT),
            "fail-scan": partial(saved_results.fail_scan, _WORKBENCH_DB_CONTEXT),
            "preserve-scan-results": partial(
                saved_results.preserve_scan_results, _WORKBENCH_DB_CONTEXT
            ),
            "recover-scan-results": partial(
                saved_results.recover_scan_results, _WORKBENCH_DB_CONTEXT
            ),
            "write-scan-draft": partial(saved_results.write_scan_draft, _WORKBENCH_DB_CONTEXT),
            "save-scan-artifact": partial(saved_results.save_scan_artifact, _WORKBENCH_DB_CONTEXT),
            "mark-handoff-delivered": partial(handoff.mark_handoff_delivered, command_context),
            "claim-handoff-delivery": partial(handoff.claim_handoff_delivery, command_context),
            "release-handoff-delivery": partial(handoff.release_handoff_delivery, command_context),
            "attach-scan-continuation-thread": partial(
                handoff.attach_scan_continuation_thread, command_context
            ),
            "export-findings": partial(publication.export_findings, _WORKBENCH_PUBLICATION_CONTEXT),
        }
        if handler := handlers.get(args.command):
            result = handler(connection, args)
        elif args.command == "get-workspace":
            result = workspace_state(
                connection,
                args.workspace_id,
                thread_id=args.thread_id,
            )
        elif args.command == "start-prompt-only-scan":
            result = _start_prompt_driven_scan(connection, args, headless_standard=False)
        elif args.command == "start-headless-standard-scan":
            result = _start_prompt_driven_scan(connection, args, headless_standard=True)
        elif args.command == "get-scan":
            result = get_scan(connection, args)
        elif args.command == "get-finding":
            occurrence = require_occurrence(connection, args.occurrence_id)
            scan = require_scan(connection, occurrence["scan_id"])
            current_target = scan_history.require_finding_checkout_owner(connection, scan)
            backfill_legacy_finding_details(connection, scan)
            occurrence = require_occurrence(connection, occurrence["id"])
            result = {
                "scan": {
                    "findings": [finding_result(connection, scan, occurrence, full_details=True)],
                    "scanDir": scan["scan_dir"],
                    "scanId": scan["id"],
                    "targetPath": scan["target_path"],
                    **(
                        {"currentTargetPath": current_target["target_path"]}
                        if current_target is not None
                        and current_target["target_path"] != scan["target_path"]
                        else {}
                    ),
                }
            }
        elif args.command == "rename-scan":
            result = scan_history.rename_scan(
                connection, require_scan(connection, args.scan_id), args.name
            )
        elif args.command == "get-scan-feedback":
            result = get_scan_feedback(connection, require_scan(connection, args.scan_id))
        elif args.command == "list-unmatched-scan-pairs":
            result = scan_history.list_unmatched_scan_pairs(
                connection,
                args,
                backfill_finding_details=backfill_legacy_finding_details,
                read_coverage=coverage_for_comparison,
            )
        elif args.command == "get-scan-recipe":
            result = scan_history.scan_recipe(require_scan(connection, args.scan_id))
        elif args.command == "get-cli-scan-resume":
            scan = require_scan(connection, args.scan_id)
            try:
                result = scan_history.cli_scan_resume(
                    command_context,
                    connection,
                    scan,
                    require_workspace(connection, scan["workspace_id"]),
                )
            except SystemExit as exc:
                if not args.allow_unavailable:
                    raise
                result = {"unavailable": str(exc)}
        elif args.command == "compare-scans":
            result = scan_history.compare_scans(
                connection,
                args,
                require_scan=require_scan,
                read_coverage=coverage_for_comparison,
                finding_triage=lambda connection, scan, through_scan: scan_finding_triage(
                    connection, scan, through_scan=through_scan
                ),
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
                finding_triage=lambda connection, scan, through_scan: scan_finding_triage(
                    connection, scan, through_scan=through_scan
                ),
            )
        elif args.command in {"prepare-scan-completion", "complete-scan"}:
            result = complete_scan(
                connection, args, prepare_only=args.command == "prepare-scan-completion"
            )
        elif args.command == "cancel-finding-remediation-request":
            result = scan_context(
                connection,
                remediation_state.cancel_finding_remediation_request(connection, args),
            )
        elif args.command == "database-info":
            result = {"databasePath": str(database_path())}
        elif args.command == "finding-workflow":
            result = finding_workflow(connection, json.load(sys.stdin), now())
        else:
            raise SystemExit(f"Unknown command: {args.command}")
    print(json.dumps(result, allow_nan=False, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except ContractError as exc:
        raise SystemExit(str(exc)) from None
