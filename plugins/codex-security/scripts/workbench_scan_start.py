"""Shared scan-start helpers for the Codex Security workbench."""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import sqlite3
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import serialize_filesystem_identity
from finalize_scan_contract import write_scan_local_bytes
from workbench.storage import (
    archive_source_directory,
    create_private_temporary_directory,
    short_archive_prefix,
    state_dir,
)
from workbench_feedback import get_scan_feedback
from workbench_target import (
    directory_content_digest,
    git_bytes,
    git_output,
    git_revision,
    repository_origin,
    worktree_content_digest,
)
from workbench_validation import optional_text, read_json_object


def safe_segment(value: str) -> str:
    """Normalize a filename segment, falling back to ``scan`` for an empty result."""
    segment = re.sub(r"[^\w.-]", "-", value)
    if segment != value:
        segment = segment.strip("-")
    return segment or "scan"


def compact_timestamp() -> str:
    """Return the current UTC time in YYYYMMDDTHHMMSSZ format."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def loaded_plugin_version() -> str:
    """Read the required version string from the loaded plugin's manifest."""
    manifest = read_json_object(
        Path(__file__).resolve().parents[1] / ".codex-plugin" / "plugin.json"
    )
    version = manifest.get("version")
    if not isinstance(version, str) or not version:
        raise SystemExit("plugin.json: expected a nonempty Codex Security plugin version.")
    return version


def scan_target_identity(
    target: Path,
    diff_target: dict[str, str] | None,
    *,
    metadata: os.stat_result | None = None,
    expected_digest: str | None = None,
) -> tuple[str, str | None, int | str, int | str]:
    """Return revision, content digest, device ID, and inode for scan registration.

    An explicit diff uses its head revision and a None digest. Other targets use
    the worktree or directory digest. Device and inode use the SQLite-safe representation.
    """
    if metadata is None:
        metadata = target.stat()
    revision = diff_target["headRevision"] if diff_target else git_revision(target)
    snapshot_digest = None
    if diff_target is None:
        snapshot_digest = (
            directory_content_digest(target)
            if revision == "unversioned"
            else worktree_content_digest(target, expected_digest=expected_digest)
        )
    return (
        revision,
        snapshot_digest,
        serialize_filesystem_identity(metadata.st_dev),
        serialize_filesystem_identity(metadata.st_ino),
    )


@dataclass(frozen=True)
class WindowsResumeTarget:
    path: Path
    snapshot: tuple[str, str | None, int | str, int | str]
    native_id: tuple[int, int] | None


def prepare_cli_scan_target(
    target: Path, diff_target: dict[str, str] | None, mode: str, launch_kind: str
) -> tuple[tuple[str, str | None, int | str, int | str], WindowsResumeTarget | None]:
    if os.name == "nt" and mode == "deep" and launch_kind == "scan":
        from windows_scan_local_files import pinned_resume_checkout

        with pinned_resume_checkout(target) as native:
            snapshot = scan_target_identity(target, diff_target)
            return snapshot, WindowsResumeTarget(target, snapshot, native)
    return scan_target_identity(target, diff_target), None


def scan_diff_identity(
    diff_target: dict[str, str] | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return kind, base, head, and optional digest in database order, or four nulls."""
    if diff_target is None:
        return (None, None, None, None)
    return (
        diff_target["kind"],
        diff_target["baseRevision"],
        diff_target["headRevision"],
        diff_target.get("contentDigest"),
    )


def stored_diff_target(row: sqlite3.Row) -> dict[str, str] | None:
    """Rebuild the diff target from a scan row, or return None for a full scan."""
    if not row["diff_target_kind"]:
        return None
    target = {
        "baseRevision": row["diff_base_revision"],
        "headRevision": row["diff_head_revision"],
        "kind": row["diff_target_kind"],
    }
    if row["diff_content_digest"]:
        target["contentDigest"] = row["diff_content_digest"]
    return target


@contextmanager
def archive_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    scan_dir: Path,
    timestamp: str,
    canonical_directory: Callable[[Path], Path],
    *,
    before_archive: Callable[[], None] | None = None,
) -> Iterator[Path | None]:
    """Yield the archive directory while preparing the original scan path for reuse."""
    archived_scan_dir = (
        canonical_directory(Path(args.archived_scan_dir).expanduser())
        if args.archived_scan_dir is not None
        else None
    )
    if archived_scan_dir is not None and (
        not args.archive_existing
        or archived_scan_dir.parent != scan_dir.parent
        or archive_source_directory(archived_scan_dir, scan_dir) != scan_dir
    ):
        raise SystemExit("The archived scan must be a previous sibling of the scan directory.")

    previous_scan = connection.execute(
        "SELECT id, status FROM scans WHERE scan_dir = ?", (str(scan_dir),)
    ).fetchone()
    if previous_scan is not None:
        if not args.archive_existing:
            raise SystemExit(
                "The scan artifact directory belongs to an existing scan. "
                "Use --archive-existing to preserve that scan and start a new one."
            )
        if previous_scan["status"] == "running":
            raise SystemExit("Cannot archive the output of a running scan.")
    has_contents = next(scan_dir.iterdir(), None) is not None
    if has_contents and (not args.archive_existing or archived_scan_dir is not None):
        raise SystemExit("The scan artifact directory must be empty before the scan starts.")
    if previous_scan is None and not (args.archive_existing and has_contents):
        yield archived_scan_dir
        return
    has_artifacts = (
        connection.execute(
            "SELECT 1 FROM scan_artifacts WHERE scan_id = ? LIMIT 1", (previous_scan["id"],)
        ).fetchone()
        if previous_scan is not None
        else None
    )
    moved = False
    try:
        if archived_scan_dir is None:
            configured_state = state_dir(canonical=False)
            protected_directories = [
                *(path.resolve() for path in (configured_state, *configured_state.parents)),
                *(
                    Path(row[2]).resolve().parent
                    for row in connection.execute("PRAGMA database_list")
                    if row[2]
                ),
            ]
            if any(path == scan_dir or scan_dir in path.parents for path in protected_directories):
                raise SystemExit(
                    "Cannot archive output containing the workbench state or active database."
                )
            if has_artifacts and not has_contents:
                raise SystemExit(
                    "The archived scan directory is required to preserve existing scan artifacts."
                )
            if before_archive is not None:
                before_archive()
            try:
                reserved = tempfile.mkdtemp(
                    prefix=f"{scan_dir.name}.previous-", dir=scan_dir.parent
                )
            except OSError as error:
                if os.name != "posix" or error.errno != errno.ENAMETOOLONG:
                    raise
                reserved = tempfile.mkdtemp(
                    prefix=short_archive_prefix(scan_dir.name), dir=scan_dir.parent
                )
            archived_scan_dir = Path(reserved).resolve()
            archived_scan_dir.rmdir()
            scan_dir.rename(archived_scan_dir)
            moved = True
            if os.name == "nt":
                from windows_scan_local_files import create_directory_with_same_dacl

                create_directory_with_same_dacl(scan_dir, archived_scan_dir)
            else:
                scan_dir.mkdir(mode=0o700)
                scan_dir.chmod(0o700)
        if previous_scan is not None:
            connection.execute(
                "UPDATE scans SET scan_dir = ?, updated_at = ? WHERE id = ?",
                (str(archived_scan_dir), timestamp, previous_scan["id"]),
            )
            connection.execute(
                """UPDATE finding_workflows SET scan_dir = ?,
                    results_json = CASE WHEN json_extract(results_json, '$.scan.sarifPath') = ?
                        THEN json_set(results_json, '$.scan.sarifPath', ?) ELSE results_json END
                    WHERE scan_id = ? AND scan_dir = ?""",
                (
                    str(archived_scan_dir),
                    str(scan_dir / "exports" / "results.sarif"),
                    str(archived_scan_dir / "exports" / "results.sarif"),
                    previous_scan["id"],
                    str(scan_dir),
                ),
            )

            def archive_path(value: str | None) -> str | None:
                if value is None or not Path(value).is_relative_to(scan_dir):
                    return value
                return str(archived_scan_dir / Path(value).relative_to(scan_dir))

            connection.create_function("archive_path", 1, archive_path)
            try:
                for table, columns in (
                    ("scan_artifacts", ("path",)),
                    ("deep_scan_workers", ("prompt_path", "artifact_dir", "result_manifest_path")),
                    (
                        "deep_scan_runs",
                        (
                            "manifest_path",
                            "canonical_inventory_path",
                            "canonical_finding_report_path",
                            "canonical_candidates_path",
                            "dedupe_report_path",
                            "seed_research_path",
                            "work_ledger_path",
                            "raw_candidates_path",
                            "coverage_ledger_path",
                            "findings_dir",
                        ),
                    ),
                ):
                    assignments = ", ".join(
                        f"{column} = archive_path({column})" for column in columns
                    )
                    connection.execute(
                        f"UPDATE {table} SET {assignments} WHERE scan_id = ?",
                        (previous_scan["id"],),
                    )
            finally:
                connection.create_function("archive_path", 1, None)
        # The caller commits registration before leaving this context. Older SDKs
        # supplied an already-moved directory; only restore moves we own.
        yield archived_scan_dir
    except BaseException:
        if moved:
            if not connection.in_transaction:
                current_owner = connection.execute(
                    "SELECT id FROM scans WHERE scan_dir = ?", (str(scan_dir),)
                ).fetchone()
                if current_owner is not None and (
                    previous_scan is None or current_owner["id"] != previous_scan["id"]
                ):
                    # A post-commit interrupt must not undo the saved archive location.
                    raise
            try:
                scan_dir.rmdir()
            except FileNotFoundError:
                # Registration may fail before recreating the empty output directory.
                pass
            archived_scan_dir.rename(scan_dir)
        raise


@contextmanager
def register_windows_resume_output(
    connection: sqlite3.Connection,
    scan_id: str,
    scan_dir: Path,
    target: WindowsResumeTarget,
    before_create: Callable[[], None],
) -> Iterator[None]:
    from windows_scan_local_files import create_deep_resume_output, pinned_resume_checkout

    def committed() -> bool:
        # A signal can arrive after commit. The registered scan then owns its child.
        return (
            not connection.in_transaction
            and connection.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            is not None
        )

    with pinned_resume_checkout(target.path) as current:
        if current != target.native_id or (
            current is None and scan_target_identity(target.path, None) != target.snapshot
        ):
            raise SystemExit(
                "The selected scan target changed while the scan was starting. Try again."
            )
        before_create()
        with create_deep_resume_output(scan_dir, committed) as identity:
            connection.execute(
                "UPDATE scans SET windows_resume_output_identity = ?, windows_resume_target_identity = ? WHERE id = ?",
                (
                    json.dumps(identity),
                    json.dumps(target.native_id) if target.native_id is not None else None,
                    scan_id,
                ),
            )
            yield


def insert_running_scan(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    workspace: sqlite3.Row,
    target: Path,
    scope: str,
    diff_target: dict[str, str] | None,
    target_identity: tuple[str, str | None, int | str, int | str],
    source_scopes: dict[str, Any],
    target_root: Path,
    target_summary: str | None,
    scope_file_count: int | None,
    timestamp: str,
    handoff_status: str = "pending",
    model: str | None = None,
    reasoning_effort: str | None = None,
    scan_dir: Path | None = None,
    surface: str | None = "plugin",
    package_version: str | None = None,
    launch_kind: str = "scan",
) -> str:
    revision = target_identity[0]
    native_scan = scan_dir is None
    user_context = optional_text(workspace["user_context"])
    try:
        plugin_version = loaded_plugin_version()
    except SystemExit:
        # Missing version attribution must not prevent scan registration.
        plugin_version = None
    if scan_dir is None:
        scan_dir = create_private_temporary_directory(
            target_root,
            prefix=f"{safe_segment(revision)}_{compact_timestamp()}_",
        )
    git_prefix = (
        git_bytes(target, "rev-parse", "--show-prefix") if revision != "unversioned" else None
    )
    git_common_directory = (
        git_output(target, "rev-parse", "--path-format=absolute", "--git-common-dir")
        if revision != "unversioned"
        else None
    )
    git_identity = None
    if git_common_directory is not None:
        common_directory = Path(git_common_directory).resolve()
        git_directory_metadata = common_directory.stat()
        git_identity = {
            "commonDirectory": str(common_directory),
            "commonDirectoryIdentity": [
                serialize_filesystem_identity(git_directory_metadata.st_dev),
                serialize_filesystem_identity(git_directory_metadata.st_ino),
            ],
            "origin": repository_origin(git_output(target, "remote", "get-url", "origin")),
        }
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
            target_device, target_inode, target_git_prefix, target_git_identity_json,
            source_scopes_json, scope, mode, user_context,
            deep_scan_owner_thread_id, diff_target_kind, diff_base_revision,
            diff_head_revision, diff_content_digest, target_summary, scan_dir, model,
            reasoning_effort, status, phase, handoff_status, started_at, created_at, updated_at,
            launch_surface, launch_package_version, launch_plugin_version, launch_kind
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            'running', 'preflight', ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            workspace["id"],
            workspace["target_id"],
            str(target),
            *target_identity,
            os.fsdecode(git_prefix).removesuffix("\n") if git_prefix is not None else None,
            json.dumps(git_identity, separators=(",", ":")) if git_identity is not None else None,
            json.dumps(source_scopes, allow_nan=False, separators=(",", ":"), sort_keys=True),
            scope,
            workspace["default_mode"],
            user_context,
            workspace["thread_id"] if workspace["default_mode"] == "deep" else None,
            *scan_diff_identity(diff_target or None),
            target_summary,
            str(scan_dir),
            optional_text(model, maximum=200),
            optional_text(reasoning_effort, maximum=32),
            handoff_status,
            timestamp,
            timestamp,
            timestamp,
            surface,
            package_version,
            plugin_version,
            launch_kind,
        ),
    )
    connection.execute(
        """
        INSERT INTO scan_progress (
            scan_id, scope_file_count, review_items_total, review_items_completed,
            reportable_findings_count, updated_at
        ) VALUES (?, ?, 0, 0, 0, ?)
        """,
        (scan_id, scope_file_count, timestamp),
    )
    connection.execute(
        "UPDATE workspaces SET active_scan_id = ?, updated_at = ? WHERE id = ?",
        (scan_id, timestamp, workspace["id"]),
    )
    if native_scan:
        scan = next(connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)))
        false_positives = get_scan_feedback(connection, scan)["falsePositives"]
        if false_positives:
            write_scan_local_bytes(
                scan_dir,
                "artifacts/01_context/false_positive_feedback.json",
                (json.dumps(false_positives, allow_nan=False) + "\n").encode(),
            )
    return scan_id


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
