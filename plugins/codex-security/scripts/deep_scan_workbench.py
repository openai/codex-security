"""Persist deterministic Codex Security Deep Scan orchestration state."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deep_scan_config import resolve_deep_scan_config
from filesystem_identity import serialize_filesystem_identity
from finalize_scan_contract import (
    _read_scan_local_json,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
)
from workbench.handoff import require_current_continuation
from workbench_saved_results import (
    _restore_published_outputs,
    _snapshot_published_outputs,
    _worker_checkpoint_head,
)
from workbench_scan_usage import capture_scan_usage_owner
from workbench_target import (
    directory_content_digest,
    directory_snapshot_regular_file_count,
    git_revision,
    worktree_content_digest,
)
from workbench_validation import (
    optional_text,
    reject_non_finite_json,
    require_uuid,
    user_context_argument,
)

DEEP_SCAN_WORKER_KINDS = ("setup", "discovery", "dedup")
DEEP_SCAN_WORKER_STATUSES = ("queued", "running", "succeeded", "failed", "canceled")
DEEP_SCAN_REPLACEABLE_FAILURE_KINDS = (
    "policy_refusal",
    "transient_error",
    "invalid_discovery_artifacts",
)
DEEP_SCAN_TERMINAL_REASONS = ("saturated", "capped")
DEEP_SCAN_WORKFLOW_VERSION = "deep-security-scan/v2"
SUPPORTED_DEEP_SCAN_WORKFLOWS = {
    DEEP_SCAN_WORKFLOW_VERSION,
    "deep-scan-mcp/v1",
    "deep-security-scan/v1",
}
DEEP_SCAN_COORDINATOR_LEASE_SECONDS = 30
DEEP_SCAN_LEGACY_COORDINATOR_GRACE_SECONDS = 120
DEEP_SCAN_MAX_ERROR_LENGTH = 2400
DEEP_SCAN_PUBLICATION_ERROR_SEPARATOR = "\nOriginal Deep Scan failure:\n"


def register_subcommands(subparsers: Any, positive_int: Callable[[str], int]) -> None:
    begin_deep_scan = subparsers.add_parser("begin-deep-scan")
    begin_deep_scan.add_argument("--thread-id", required=True)
    begin_target = begin_deep_scan.add_mutually_exclusive_group(required=True)
    begin_target.add_argument("--scan-id")
    begin_target.add_argument("--target-path")
    begin_deep_scan.add_argument("--scope", default=".")
    begin_user_context = begin_deep_scan.add_mutually_exclusive_group()
    begin_user_context.add_argument("--user-context")
    begin_user_context.add_argument("--user-context-stdin", action="store_true")
    begin_deep_scan.add_argument("--scan-root")
    begin_deep_scan.add_argument("--claim-token")
    begin_deep_scan.add_argument("--model")
    begin_deep_scan.add_argument("--reasoning-effort")
    begin_deep_scan.add_argument("--available-parallelism", type=positive_int)
    begin_deep_scan.add_argument("--workflow-version", default=DEEP_SCAN_WORKFLOW_VERSION)

    get_deep_scan = subparsers.add_parser("get-deep-scan")
    get_deep_scan.add_argument("--scan-id", required=True)
    get_deep_scan.add_argument("--thread-id", required=True)

    claim_coordinator = subparsers.add_parser("claim-deep-scan-coordinator")
    claim_coordinator.add_argument("--scan-id", required=True)
    claim_coordinator.add_argument("--thread-id", required=True)
    claim_coordinator.add_argument("--claim-token")
    claim_coordinator.add_argument("--coordinator-generation", type=positive_int)

    upsert_deep_worker = subparsers.add_parser("upsert-deep-scan-worker")
    upsert_deep_worker.add_argument("--scan-id", required=True)
    upsert_deep_worker.add_argument("--worker-id", required=True)
    upsert_deep_worker.add_argument("--kind", choices=DEEP_SCAN_WORKER_KINDS, required=True)
    upsert_deep_worker.add_argument("--status", choices=DEEP_SCAN_WORKER_STATUSES, required=True)
    upsert_deep_worker.add_argument("--prompt-path", required=True)
    upsert_deep_worker.add_argument("--artifact-dir", required=True)
    upsert_deep_worker.add_argument("--result-manifest-path")
    upsert_deep_worker.add_argument("--attempt", type=non_negative_int)
    upsert_deep_worker.add_argument("--sdk-thread-id")
    upsert_deep_worker.add_argument("--error-message")
    upsert_deep_worker.add_argument(
        "--replaceable-failure-kind", choices=DEEP_SCAN_REPLACEABLE_FAILURE_KINDS
    )
    upsert_deep_worker.add_argument("--coordinator-generation", type=positive_int)

    claim_deep_dedup = subparsers.add_parser("claim-deep-scan-dedup")
    claim_deep_dedup.add_argument("--scan-id", required=True)
    claim_deep_dedup.add_argument("--worker-id", required=True)
    claim_deep_dedup.add_argument("--prompt-path", required=True)
    claim_deep_dedup.add_argument("--artifact-dir", required=True)
    claim_deep_dedup.add_argument("--input-worker-id", action="append", required=True)
    claim_deep_dedup.add_argument("--coordinator-generation", type=positive_int)

    commit_deep_dedup = subparsers.add_parser("commit-deep-scan-dedup")
    commit_deep_dedup.add_argument("--scan-id", required=True)
    commit_deep_dedup.add_argument("--worker-id", required=True)
    commit_deep_dedup.add_argument("--result-manifest-path", required=True)
    commit_deep_dedup.add_argument("--candidate-ledger-path")
    commit_deep_dedup.add_argument("--new-findings-count", type=non_negative_int, required=True)
    commit_deep_dedup.add_argument("--coordinator-generation", type=positive_int)

    finish_deep_scan = subparsers.add_parser("finish-deep-scan")
    finish_deep_scan.add_argument("--scan-id", required=True)
    finish_deep_scan.add_argument(
        "--terminal-reason", choices=DEEP_SCAN_TERMINAL_REASONS, required=True
    )
    finish_deep_scan.add_argument("--manifest-path", required=True)
    finish_deep_scan.add_argument("--staged-manifest-path")
    finish_deep_scan.add_argument("--omitted-worker-id", action="append", default=[])
    finish_deep_scan.add_argument("--coordinator-generation", type=positive_int)

    fail_deep_scan = subparsers.add_parser("fail-deep-scan")
    fail_deep_scan.add_argument("--scan-id", required=True)
    fail_deep_scan.add_argument("--message", required=True)
    fail_deep_scan.add_argument("--manifest-path")
    fail_deep_scan.add_argument("--staged-manifest-path")
    fail_deep_scan.add_argument(
        "--deep-status", choices=("failed", "interrupted"), default="failed"
    )
    fail_deep_scan.add_argument("--coordinator-generation", type=positive_int)

    publication_failure = subparsers.add_parser("record-deep-scan-publication-failure")
    publication_failure.add_argument("--scan-id", required=True)
    publication_failure.add_argument("--message", required=True)
    publication_failure.add_argument("--coordinator-generation", type=positive_int)


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return parsed


@dataclass(frozen=True)
class DeepScanDependencies:
    now: Callable[[], str]
    state_dir: Callable[[], Path]
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row]
    require_workspace: Callable[[sqlite3.Connection, str], sqlite3.Row]
    require_target: Callable[[str], Path]
    require_remediation_target: Callable[[str], Path]
    require_scannable_target: Callable[[Path], None]
    require_scope: Callable[[str, str, Path], str]
    ensure_security_target: Callable[[sqlite3.Connection, str], str]
    require_canonical_scan_directory: Callable[[Path], Path]
    safe_segment: Callable[[str], str]
    compact_timestamp: Callable[[], str]
    scan_completion_lock: Callable[[str], Any]
    preserve_stopped_results: Callable[[sqlite3.Connection, str], None]


_dependencies: DeepScanDependencies | None = None


def configure(dependencies: DeepScanDependencies) -> None:
    global _dependencies
    _dependencies = dependencies


def dependencies() -> DeepScanDependencies:
    if _dependencies is None:
        raise RuntimeError("Deep Scan workbench dependencies are not configured.")
    return _dependencies


def now() -> str:
    return dependencies().now()


def _bounded_error_text(message: str, maximum: int) -> str:
    if len(message) <= maximum:
        return message
    digest = hashlib.sha256(message.encode()).hexdigest()
    suffix = f"\n...[truncated; sha256:{digest}]"
    if len(suffix) >= maximum:
        return message[:maximum]
    return f"{message[: maximum - len(suffix)]}{suffix}"


def deep_scan_error(run: sqlite3.Row) -> str | None:
    original = run["error_message"]
    publication = run["publication_error_message"]
    if not isinstance(publication, str):
        return original if isinstance(original, str) else None
    if not isinstance(original, str):
        return publication
    available = DEEP_SCAN_MAX_ERROR_LENGTH - len(DEEP_SCAN_PUBLICATION_ERROR_SEPARATOR)
    publication_budget = min(len(publication), available // 2)
    original_budget = min(len(original), available - publication_budget)
    publication_budget = min(len(publication), available - original_budget)
    return (
        _bounded_error_text(publication, publication_budget)
        + DEEP_SCAN_PUBLICATION_ERROR_SEPARATOR
        + _bounded_error_text(original, original_budget)
    )


def _parse_timestamp(value: str) -> datetime:
    if isinstance(value, str) and value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def state_dir() -> Path:
    return dependencies().state_dir()


def require_scan(connection: sqlite3.Connection, scan_id: str) -> sqlite3.Row:
    return dependencies().require_scan(connection, scan_id)


def require_workspace(connection: sqlite3.Connection, workspace_id: str) -> sqlite3.Row:
    return dependencies().require_workspace(connection, workspace_id)


def require_target(value: str) -> Path:
    return dependencies().require_target(value)


def require_remediation_target(value: str) -> Path:
    return dependencies().require_remediation_target(value)


def require_scannable_target(target: Path) -> None:
    dependencies().require_scannable_target(target)


def require_scope(scope: str, mode: str, target: Path) -> str:
    return dependencies().require_scope(scope, mode, target)


def ensure_security_target(connection: sqlite3.Connection, target_path: str) -> str:
    return dependencies().ensure_security_target(connection, target_path)


def require_canonical_scan_directory(scan_dir: Path) -> Path:
    return dependencies().require_canonical_scan_directory(scan_dir)


def safe_segment(value: str) -> str:
    return dependencies().safe_segment(value)


def compact_timestamp() -> str:
    return dependencies().compact_timestamp()


def scan_completion_lock(scan_id: str) -> Any:
    return dependencies().scan_completion_lock(scan_id)


def require_deep_scan_run(connection: sqlite3.Connection, scan_id: str) -> sqlite3.Row:
    scan_id = require_uuid(scan_id, "scan-id")
    row = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if row is None:
        raise SystemExit("Codex Security Deep Scan orchestration state not found.")
    return row


def require_supported_deep_scan(run: sqlite3.Row) -> None:
    if run["schema_version"] != 1 or run["workflow_version"] not in SUPPORTED_DEEP_SCAN_WORKFLOWS:
        raise SystemExit(
            "This Deep Scan uses an unsupported workflow or schema version. "
            "Resume it with a compatible Codex Security release."
        )

    finalization = deep_scan_finalization_input(run)
    if finalization is not None and (
        run["workflow_version"] != "deep-security-scan/v2"
        or not isinstance(finalization, dict)
        or finalization.get("version") != 1
    ):
        raise SystemExit("This Deep Scan uses an unsupported finalization input version.")


def deep_scan_finalization_input(run: sqlite3.Row) -> dict[str, Any] | None:
    if "finalization_input_json" not in run.keys() or run["finalization_input_json"] is None:
        return None
    return json.loads(run["finalization_input_json"])


def deep_scan_deadline_reached(run: sqlite3.Row) -> bool:
    elapsed = _parse_timestamp(now()) - _parse_timestamp(str(run["created_at"]))
    return elapsed.total_seconds() / 3600 >= run["max_time_hours"]


def require_deep_scan_ready_for_parent_completion(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> None:
    if scan["mode"] != "deep":
        return
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?",
        (scan["id"],),
    ).fetchone()
    if run is not None:
        require_supported_deep_scan(run)
    if run is None or run["status"] != "succeeded" or run["manifest_path"] is None:
        raise SystemExit(
            "Deep Scan discovery orchestration must finish and persist its manifest before "
            "the parent scan can be completed."
        )


def require_owned_scan(
    connection: sqlite3.Connection, scan_id: str, thread_id: str
) -> tuple[sqlite3.Row, sqlite3.Row]:
    scan = require_scan(connection, scan_id)
    workspace = require_workspace(connection, scan["workspace_id"])
    owner = optional_text(thread_id, maximum=512)
    if owner is None:
        raise SystemExit("thread-id is required.")
    persisted_owner = scan["deep_scan_owner_thread_id"] or workspace["thread_id"]
    if persisted_owner != owner:
        raise SystemExit("A scan can only be orchestrated from its owning Codex thread.")
    return scan, workspace


def deep_scan_path(
    scan: sqlite3.Row,
    value: str,
    label: str,
    *,
    kind: str,
) -> str:
    supplied = Path(value).expanduser()
    if not supplied.is_absolute():
        raise SystemExit(f"{label} must be an absolute path inside the scan directory.")
    try:
        resolved = supplied.resolve(strict=True)
        scan_dir = require_canonical_scan_directory(Path(scan["scan_dir"]))
        resolved.relative_to(scan_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"{label} must be an existing path inside the scan directory.") from exc
    if os.path.normcase(resolved) != os.path.normcase(supplied.absolute()):
        raise SystemExit(f"{label} must be a canonical non-symlink path.")
    if kind == "file" and not resolved.is_file():
        raise SystemExit(f"{label} must be a regular file.")
    if kind == "directory" and not resolved.is_dir():
        raise SystemExit(f"{label} must be a directory.")
    return str(resolved)


def deep_scan_output_path(scan: sqlite3.Row, value: str, label: str) -> str:
    supplied = Path(value).expanduser()
    if not supplied.is_absolute():
        raise SystemExit(f"{label} must be an absolute path inside the scan directory.")
    if supplied.exists():
        return deep_scan_path(scan, str(supplied), label, kind="file")
    parent = Path(deep_scan_path(scan, str(supplied.parent), label, kind="directory"))
    output = parent / supplied.name
    if os.path.normcase(output) != os.path.normcase(supplied.absolute()):
        raise SystemExit(f"{label} must be a canonical non-symlink path.")
    return str(output)


def promote_staged_file(staged_path: str, output_path: str) -> tuple[Path, Path, Path | None]:
    staged = Path(staged_path)
    output = Path(output_path)
    if staged == output:
        raise SystemExit("A staged Deep Scan artifact must not be its published output path.")
    backup = output.with_name(f".{output.name}.{uuid.uuid4()}.backup") if output.exists() else None
    if backup is not None:
        os.replace(output, backup)
    try:
        os.replace(staged, output)
    except BaseException:
        if backup is not None:
            os.replace(backup, output)
        raise
    return staged, output, backup


def rollback_staged_file(promotion: tuple[Path, Path, Path | None]) -> None:
    staged, output, backup = promotion
    if output.exists():
        os.replace(output, staged)
    if backup is not None:
        os.replace(backup, output)


def finish_staged_file(promotion: tuple[Path, Path, Path | None]) -> None:
    backup = promotion[2]
    if backup is not None:
        backup.unlink(missing_ok=True)


def create_publication_copy(source: str | Path, destination: str | Path) -> None:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def publication_matches_snapshot(publication: Path, snapshot: Path) -> bool:
    try:
        if publication.samefile(snapshot):
            return True
        if publication.stat().st_size != snapshot.stat().st_size:
            return False
        with publication.open("rb") as published, snapshot.open("rb") as source:
            while True:
                published_chunk = published.read(1024 * 1024)
                source_chunk = source.read(1024 * 1024)
                if published_chunk != source_chunk:
                    return False
                if not published_chunk:
                    return True
    except OSError:
        return False


def canonical_discovery_artifacts(scan: sqlite3.Row) -> dict[str, str]:
    discovery_dir = Path(scan["scan_dir"]) / "artifacts" / "02_discovery"
    artifacts = {
        "inScopeFilesPath": discovery_dir / "in_scope_files.txt",
        "candidateLedgerPath": discovery_dir / "candidate_ledger.jsonl",
    }
    labels = {
        "inScopeFilesPath": "Canonical in-scope inventory path",
        "candidateLedgerPath": "Canonical candidate ledger path",
    }
    return {
        name: deep_scan_path(scan, str(path), labels[name], kind="file")
        for name, path in artifacts.items()
    }


def deep_scan_state(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    if connection.in_transaction:
        return _deep_scan_state(connection, scan_id)
    connection.execute("BEGIN")
    try:
        state = _deep_scan_state(connection, scan_id)
        connection.commit()
        return state
    except BaseException:
        connection.rollback()
        raise


def _deep_scan_state(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    run = require_deep_scan_run(connection, scan_id)
    scan = require_scan(connection, run["scan_id"])
    worker_rows = connection.execute(
        """
        SELECT workers.*, attempts.accepted_result_path
        FROM deep_scan_workers AS workers
        LEFT JOIN deep_scan_attempts AS attempts
            ON attempts.worker_id = workers.id AND attempts.attempt = workers.attempt
        WHERE workers.scan_id = ?
        ORDER BY workers.created_at, workers.id
        """,
        (run["scan_id"],),
    )
    input_rows = connection.execute(
        """
        SELECT *
        FROM deep_scan_dedup_inputs
        WHERE scan_id = ?
        ORDER BY dedup_worker_id, input_order
        """,
        (run["scan_id"],),
    )
    canonical_artifacts = None
    if (
        run["canonical_inventory_path"] is None
        and run["status"] == "succeeded"
        and run["manifest_path"] is not None
        and run["manifest_path"] != str(Path(scan["scan_dir"]) / "scan-manifest.json")
        and (Path(scan["scan_dir"]) / "artifacts" / "02_discovery" / "in_scope_files.txt").exists()
    ):
        canonical_artifacts = canonical_discovery_artifacts(scan)
        if (
            run["terminal_reason"] == "capped"
            and run["completion_sequence"] == 0
            and deep_scan_deadline_reached(run)
            and Path(canonical_artifacts["candidateLedgerPath"]).stat().st_size != 0
        ):
            raise SystemExit(
                "A capped Deep Scan without completed discoveries requires an empty "
                "candidate ledger."
            )
    return {
        "scanId": run["scan_id"],
        "targetPath": scan["target_path"],
        "scope": scan["scope"],
        "model": scan["model"],
        "reasoningEffort": scan["reasoning_effort"],
        "userContext": (
            run["discovery_user_context"]
            if "discovery_user_context" in run.keys()
            else scan["user_context"]
        ),
        "scanDir": scan["scan_dir"],
        "schemaVersion": run["schema_version"],
        "workflowVersion": run["workflow_version"],
        "finalizationInput": deep_scan_finalization_input(run),
        "usageOwner": (
            json.loads(run["usage_owner_json"])
            if "usage_owner_json" in run.keys() and run["usage_owner_json"]
            else None
        ),
        "coordinatorGeneration": run["coordinator_generation"],
        "status": run["status"],
        "phase": run["phase"],
        "config": {
            "workers": run["workers"],
            "subagents": run["subagents"],
            "stopAfterNoNew": run["stop_after_no_new"],
            "stopAfterConsecutiveErrors": run["stop_after_consecutive_errors"],
            "maxDiscoveryRuns": run["max_discovery_runs"],
            "maxTimeHours": run["max_time_hours"],
        },
        "dispatchedCount": run["discovery_runs_dispatched"],
        "completionSequence": run["completion_sequence"],
        "noNewStreak": run["consecutive_no_new"],
        "consecutiveErrors": run["consecutive_errors"],
        "cancelRequested": bool(run["cancel_requested"]),
        "canonicalArtifacts": canonical_artifacts,
        "manifestPath": run["manifest_path"],
        "terminalReason": run["terminal_reason"],
        "error": deep_scan_error(run),
        "createdAt": run["created_at"],
        "updatedAt": run["updated_at"],
        "completedAt": run["completed_at"],
        "workers": [deep_scan_worker_state(row) for row in worker_rows],
        "attempts": [
            {
                "workerId": row["worker_id"],
                "attempt": row["attempt"],
                "status": row["status"],
                "startedAt": row["started_at"],
                "completedAt": row["completed_at"],
                "endReason": row["end_reason"],
                "error": row["error_message"],
                "acceptedResultPath": row["accepted_result_path"],
                "acceptedResultSha256": row["accepted_result_sha256"],
            }
            for row in connection.execute(
                "SELECT * FROM deep_scan_attempts WHERE scan_id = ? ORDER BY worker_id, attempt",
                (scan_id,),
            )
        ],
        "attemptSessions": [
            {
                "workerId": row["worker_id"],
                "attempt": row["attempt"],
                "sdkThreadId": row["sdk_thread_id"],
                "observedAt": row["observed_at"],
            }
            for row in connection.execute(
                "SELECT * FROM deep_scan_attempt_sessions WHERE scan_id = ? "
                "ORDER BY observed_at, worker_id, attempt, sdk_thread_id",
                (scan_id,),
            )
        ],
        "mergeClaims": [
            {
                "workerId": row["worker_id"],
                "previousWorkerId": row["previous_worker_id"],
                "previousResultPath": row["previous_result_path"],
                "previousResultSha256": row["previous_result_sha256"],
            }
            for row in connection.execute(
                "SELECT * FROM deep_scan_merge_claims WHERE scan_id = ? ORDER BY rowid", (scan_id,)
            )
        ],
        "dedupInputs": [
            {
                "dedupWorkerId": row["dedup_worker_id"],
                "discoveryWorkerId": row["discovery_worker_id"],
                "inputOrder": row["input_order"],
                "resultManifestPath": row["result_manifest_path"],
                "resultManifestSha256": row["result_manifest_sha256"],
                "attempt": row["attempt"],
            }
            for row in input_rows
        ],
    }


def independent_review_progress(
    connection: sqlite3.Connection, scan_id: str
) -> dict[str, int | str] | None:
    run = connection.execute(
        """
        SELECT completion_sequence, phase, updated_at, max_discovery_runs
        FROM deep_scan_runs
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchone()
    if run is None:
        return None
    active = connection.execute(
        """
        SELECT COUNT(*)
        FROM deep_scan_workers
        WHERE scan_id = ?
            AND kind = 'discovery'
            AND status IN ('queued', 'running')
        """,
        (scan_id,),
    ).fetchone()[0]
    return {
        "active": int(active),
        "completed": int(run["completion_sequence"]),
        "maximum": int(run["max_discovery_runs"]),
        "consolidating": run["phase"] == "reducing",
        "updatedAt": str(run["updated_at"]),
    }


def deep_scan_worker_state(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "status": row["status"],
        "mergeState": row["merge_state"],
        "promptPath": row["prompt_path"],
        "artifactDir": row["artifact_dir"],
        "resultManifestPath": row["result_manifest_path"],
        "acceptedResultPath": row["accepted_result_path"]
        if "accepted_result_path" in row.keys()
        else None,
        "attempt": row["attempt"],
        "sdkThreadId": row["sdk_thread_id"],
        "completionSequence": row["completion_sequence"],
        "error": row["error_message"],
        "createdAt": row["created_at"],
        "startedAt": row["started_at"],
        "completedAt": row["completed_at"],
        "updatedAt": row["updated_at"],
    }


def deep_scan_result(
    connection: sqlite3.Connection,
    scan_id: str,
    *,
    start_disposition: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"deepScan": deep_scan_state(connection, scan_id)}
    if start_disposition is not None:
        result["startDisposition"] = start_disposition
    return result


def effective_deep_scan_config(args: argparse.Namespace) -> dict[str, int | float]:
    available_parallelism = args.available_parallelism or os.cpu_count() or 1
    return resolve_deep_scan_config(available_parallelism)


def read_deep_scan_execution_settings(scan_dir: Path) -> dict[str, Any]:
    relative_path = "artifacts/deep_discovery/execution-settings.json"
    if not (scan_dir / relative_path).exists():
        raise SystemExit(
            "This Deep Scan has no recorded original execution settings; "
            "its executable and Codex home cannot be recovered."
        )
    saved = _read_scan_local_json(scan_dir, relative_path, "Deep Scan execution settings")
    if saved.get("version") != 1:
        raise SystemExit("This Deep Scan uses an unsupported execution settings version.")
    settings = saved.get("settings")
    if not isinstance(settings, dict) or not all(
        isinstance(settings.get(key), str) for key in ("codexPath", "codexHome")
    ):
        raise SystemExit(
            "Deep Scan execution settings are missing the recorded executable or Codex home."
        )
    return settings


def ensure_deep_scan_run(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    config: dict[str, int | float],
    workflow_version: str,
    timestamp: str,
    args: argparse.Namespace | None = None,
) -> sqlite3.Row:
    existing = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
    ).fetchone()
    if existing is not None:
        require_supported_deep_scan(existing)
        return existing
    if scan["mode"] != "deep":
        raise SystemExit("Deep Scan orchestration requires a scan in deep mode.")
    if scan["status"] != "running":
        raise SystemExit("Only a running Deep Scan can start orchestration.")
    if args is not None and hasattr(args, "execution_settings"):
        # The creation transaction serializes contenders. Persist before the run
        # becomes recoverable; joined callers never replace the original bytes.
        scan_dir = Path(scan["scan_dir"])
        relative_path = "artifacts/deep_discovery/execution-settings.json"
        if (scan_dir / relative_path).exists():
            saved = read_deep_scan_execution_settings(scan_dir)
            # A managed scan directory can survive a rolled-back creation.
            # Keep its saved selections and the returned scan model consistent.
            connection.execute(
                "UPDATE scans SET model = ?, reasoning_effort = ? WHERE id = ?",
                (
                    saved.get("model"),
                    saved.get("reasoningEffort"),
                    scan["id"],
                ),
            )
        else:
            if args.execution_settings is None:
                raise SystemExit("The original Deep Scan execution settings could not be captured.")
            settings = dict(args.execution_settings)
            # The persisted scan remains authoritative when the caller did not
            # supply a model or effort (for example a managed handoff).
            for key, column in (("model", "model"), ("reasoningEffort", "reasoning_effort")):
                if scan[column] is not None:
                    settings[key] = scan[column]
            write_scan_local_bytes(
                scan_dir,
                relative_path,
                (json.dumps({"version": 1, "settings": settings}, indent=2) + "\n").encode(),
            )
    connection.execute(
        """
        INSERT INTO deep_scan_runs (
            scan_id, schema_version, workflow_version, status, phase,
            workers, subagents, stop_after_no_new, stop_after_consecutive_errors,
            max_discovery_runs, max_time_hours, discovery_user_context,
            created_at, updated_at
        ) VALUES (?, 1, ?, 'running', 'setup', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan["id"],
            workflow_version,
            config["workers"],
            config["subagents"],
            config["stopAfterNoNew"],
            config["stopAfterConsecutiveErrors"],
            config["maxDiscoveryRuns"],
            config["maxTimeHours"],
            scan["user_context"],
            timestamp,
            timestamp,
        ),
    )
    run = require_deep_scan_run(connection, scan["id"])
    if "usage_owner_json" in run.keys():
        connection.execute(
            "UPDATE deep_scan_runs SET usage_owner_json = ? WHERE scan_id = ?",
            (json.dumps(capture_scan_usage_owner(connection, scan)), scan["id"]),
        )
        run = require_deep_scan_run(connection, scan["id"])
    return run


def existing_deep_scan_for_target(
    connection: sqlite3.Connection, thread_id: str, target_path: str, scope: str
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT scans.*
        FROM scans
        JOIN workspaces ON workspaces.id = scans.workspace_id
        WHERE workspaces.thread_id = ?
            AND COALESCE(scans.deep_scan_owner_thread_id, workspaces.thread_id) = ?
            AND scans.target_path = ?
            AND scans.scope = ?
            AND scans.mode = 'deep'
            AND scans.status = 'running'
        ORDER BY scans.updated_at DESC, scans.started_at DESC, scans.id
        LIMIT 1
        """,
        (thread_id, thread_id, target_path, scope),
    ).fetchone()


def terminal_deep_scan_for_target_snapshot(
    connection: sqlite3.Connection,
    thread_id: str,
    target_path: str,
    scope: str,
    revision: str,
    snapshot_digest: str,
    target_device: int | str,
    target_inode: int | str,
) -> sqlite3.Row | None:
    """Find discovery completed before a headless continuation changed thread IDs.

    A continuation may safely consume a finished coordinator manifest while the
    parent scan is still open. It must not adopt live orchestration owned by a
    different thread, or reuse results after the repository snapshot changed.
    """
    return connection.execute(
        """
        SELECT scans.*
        FROM scans
        JOIN deep_scan_runs ON deep_scan_runs.scan_id = scans.id
        JOIN workspaces ON workspaces.id = scans.workspace_id
        WHERE scans.target_path = ?
            AND scans.scope = ?
            AND scans.mode = 'deep'
            AND scans.status = 'running'
            AND scans.canceled_at IS NULL
            AND scans.target_revision = ?
            AND scans.target_snapshot_digest = ?
            AND scans.target_device = ?
            AND scans.target_inode = ?
            AND scans.handoff_status = 'delivered'
            AND scans.handoff_claim_token IS NULL
            AND COALESCE(scans.deep_scan_owner_thread_id, workspaces.thread_id) <> ?
            AND workspaces.active_scan_id = scans.id
            AND deep_scan_runs.status = 'succeeded'
            AND deep_scan_runs.phase = 'terminal'
            AND deep_scan_runs.cancel_requested = 0
            AND deep_scan_runs.terminal_reason IN ('saturated', 'capped')
            AND deep_scan_runs.manifest_path IS NOT NULL
            AND deep_scan_runs.completed_at IS NOT NULL
        ORDER BY deep_scan_runs.completed_at DESC, scans.updated_at DESC, scans.id
        LIMIT 1
        """,
        (
            target_path,
            scope,
            revision,
            snapshot_digest,
            target_device,
            target_inode,
            thread_id,
        ),
    ).fetchone()


def begin_deep_scan_for_scan(
    connection: sqlite3.Connection,
    scan_id: str,
    thread_id: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    scan_id = require_uuid(scan_id, "scan-id")
    candidate = require_scan(connection, scan_id)
    existing = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if existing is not None:
        require_supported_deep_scan(existing)
    workspace = require_workspace(connection, candidate["workspace_id"])
    if (
        candidate["mode"] == "deep"
        and candidate["status"] == "running"
        and candidate["recipe_json"] is not None
        and candidate["handoff_status"] == "delivered"
        and candidate["deep_scan_owner_thread_id"] is None
        and workspace["thread_id"] is None
    ):
        require_current_continuation(
            candidate,
            args.claim_token,
            error_message="Deep Scan orchestration is owned by another continuation.",
        )
        timestamp = now()
        with connection:
            claimed_workspace = connection.execute(
                "UPDATE workspaces SET thread_id = ?, updated_at = ? "
                "WHERE id = ? AND thread_id IS NULL",
                (thread_id, timestamp, workspace["id"]),
            )
            claimed_scan = connection.execute(
                "UPDATE scans SET deep_scan_owner_thread_id = ?, updated_at = ? "
                "WHERE id = ? AND deep_scan_owner_thread_id IS NULL "
                "AND handoff_status = 'delivered' AND handoff_claim_token IS ?",
                (thread_id, timestamp, scan_id, candidate["handoff_claim_token"]),
            )
            if claimed_workspace.rowcount != 1 or claimed_scan.rowcount != 1:
                raise SystemExit("A scan can only be orchestrated from its owning Codex thread.")
    scan, _ = require_owned_scan(connection, scan_id, thread_id)
    require_current_continuation(
        scan,
        args.claim_token,
        error_message="Deep Scan orchestration is owned by another continuation.",
    )
    if scan["mode"] != "deep":
        raise SystemExit("Deep Scan orchestration requires a scan in deep mode.")
    if existing is not None:
        return deep_scan_result(connection, scan_id, start_disposition="joined")
    model = optional_text(args.model, maximum=200)
    reasoning_effort = optional_text(args.reasoning_effort, maximum=32)
    config = effective_deep_scan_config(args)
    workflow_version = optional_text(args.workflow_version, maximum=256)
    if workflow_version is None:
        raise SystemExit("workflow-version is required.")
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan, _ = require_owned_scan(connection, scan_id, thread_id)
        require_current_continuation(
            scan,
            args.claim_token,
            error_message="Deep Scan orchestration is owned by another continuation.",
        )
        existing = connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if existing is not None:
            require_supported_deep_scan(existing)
            connection.commit()
            return deep_scan_result(connection, scan_id, start_disposition="joined")
        if model is not None or reasoning_effort is not None:
            connection.execute(
                """
                UPDATE scans
                SET model = COALESCE(?, model), reasoning_effort = COALESCE(?, reasoning_effort)
                WHERE id = ?
                """,
                (model, reasoning_effort, scan_id),
            )
        scan = require_scan(connection, scan_id)
        ensure_deep_scan_run(connection, scan, config, workflow_version, now(), args)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return deep_scan_result(connection, scan_id, start_disposition="created")


def begin_deep_scan_for_target(
    connection: sqlite3.Connection, args: argparse.Namespace, thread_id: str
) -> dict[str, Any]:
    target = require_target(args.target_path)
    require_scannable_target(target)
    scope = require_scope(args.scope, "deep", target)
    target_path = str(target)
    existing = existing_deep_scan_for_target(connection, thread_id, target_path, scope)
    if existing is not None:
        return begin_deep_scan_for_scan(connection, existing["id"], thread_id, args)
    target_metadata = target.stat()
    revision = git_revision(target)
    target_snapshot_digest = (
        directory_content_digest(target)
        if revision == "unversioned"
        else worktree_content_digest(target)
    )
    target_device = serialize_filesystem_identity(target_metadata.st_dev)
    target_inode = serialize_filesystem_identity(target_metadata.st_ino)
    scope_file_count = directory_snapshot_regular_file_count(
        target if scope == "." else target / scope
    )
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = existing_deep_scan_for_target(connection, thread_id, target_path, scope)
        if existing is not None:
            existing_run = connection.execute(
                "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (existing["id"],)
            ).fetchone()
            if existing_run is not None:
                require_supported_deep_scan(existing_run)
            if existing_run is None:
                config = effective_deep_scan_config(args)
                workflow_version = optional_text(args.workflow_version, maximum=256)
                if workflow_version is None:
                    raise SystemExit("workflow-version is required.")
                ensure_deep_scan_run(connection, existing, config, workflow_version, now(), args)
            connection.commit()
            return deep_scan_result(
                connection,
                existing["id"],
                start_disposition="joined" if existing_run is not None else "created",
            )
        current_target = require_remediation_target(target_path)
        current_metadata = current_target.stat()
        if (current_metadata.st_dev, current_metadata.st_ino) != (
            target_metadata.st_dev,
            target_metadata.st_ino,
        ):
            raise SystemExit(
                "The selected scan target changed while the scan was starting. Try again."
            )
        terminal = terminal_deep_scan_for_target_snapshot(
            connection,
            thread_id,
            target_path,
            scope,
            revision,
            target_snapshot_digest,
            target_device,
            target_inode,
        )
        if terminal is not None:
            connection.commit()
            return deep_scan_result(
                connection,
                terminal["id"],
                start_disposition="joined",
            )
        config = effective_deep_scan_config(args)
        workflow_version = optional_text(args.workflow_version, maximum=256)
        if workflow_version is None:
            raise SystemExit("workflow-version is required.")
        root = (
            Path(args.scan_root).expanduser().resolve() if args.scan_root else state_dir() / "scans"
        )
        target_root = (root / safe_segment(target.name)).resolve()
        if target_root == target or target in target_root.parents:
            raise SystemExit("The scan artifact directory must be outside the selected target.")
        target_root.mkdir(parents=True, exist_ok=True)
        user_context = user_context_argument(args)
        model = optional_text(args.model, maximum=200)
        reasoning_effort = optional_text(args.reasoning_effort, maximum=32)
        workspace_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        timestamp = now()
        target_id = ensure_security_target(connection, target_path)
        scan_dir = Path(
            tempfile.mkdtemp(
                prefix=f"{safe_segment(revision)}_{compact_timestamp()}_",
                dir=target_root,
            )
        ).resolve()
        connection.execute(
            """
            INSERT INTO workspaces (
                id, thread_id, target_id, target_path, target_title, default_scope, default_mode,
                user_context, submitted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'deep', ?, 1, ?, ?)
            """,
            (
                workspace_id,
                thread_id,
                target_id,
                target_path,
                target.name,
                scope,
                user_context,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
                target_device, target_inode, scope, mode, user_context,
                deep_scan_owner_thread_id, scan_dir, model, reasoning_effort, status, phase,
                handoff_status, started_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'deep', ?, ?, ?, ?, ?,
                'running', 'preflight', 'delivered', ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                target_id,
                target_path,
                revision,
                target_snapshot_digest,
                target_device,
                target_inode,
                scope,
                user_context,
                thread_id,
                str(scan_dir),
                model,
                reasoning_effort,
                timestamp,
                timestamp,
                timestamp,
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
            (scan_id, timestamp, workspace_id),
        )
        scan = require_scan(connection, scan_id)
        ensure_deep_scan_run(connection, scan, config, workflow_version, timestamp, args)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return deep_scan_result(connection, scan_id, start_disposition="created")


def begin_deep_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    workflow_version = optional_text(args.workflow_version, maximum=256)
    if workflow_version not in SUPPORTED_DEEP_SCAN_WORKFLOWS:
        raise SystemExit("This Deep Scan uses an unsupported workflow version.")
    thread_id = optional_text(args.thread_id, maximum=512)
    if thread_id is None:
        raise SystemExit("thread-id is required.")
    if args.scan_id:
        if args.user_context is not None or args.user_context_stdin or args.scope != ".":
            raise SystemExit("scan-id cannot be combined with target setup fields.")
        return begin_deep_scan_for_scan(connection, args.scan_id, thread_id, args)
    if args.claim_token is not None:
        raise SystemExit("claim-token is only valid with scan-id.")
    return begin_deep_scan_for_target(connection, args, thread_id)


def get_deep_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan, _ = require_owned_scan(connection, args.scan_id, args.thread_id)
    return deep_scan_result(connection, scan["id"])


def coordinator_lease_is_live(
    connection: sqlite3.Connection,
    run: sqlite3.Row,
    scan: sqlite3.Row,
    timestamp: str,
) -> bool:
    if run["coordinator_generation"] == 1:
        active_worker = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND status IN ('queued', 'running')
            LIMIT 1
            """,
            (run["scan_id"],),
        ).fetchone()
        return active_worker is not None and _parse_timestamp(
            str(run["updated_at"])
        ) > _parse_timestamp(timestamp) - timedelta(
            seconds=DEEP_SCAN_LEGACY_COORDINATOR_GRACE_SECONDS
        )
    heartbeat_time = _parse_timestamp(str(run["updated_at"]))
    heartbeat_path = (
        Path(scan["scan_dir"])
        / "artifacts"
        / "deep_discovery"
        / f"coordinator-heartbeat-{run['coordinator_generation']}.json"
    )
    try:
        heartbeat = json.loads(heartbeat_path.read_text(encoding="utf-8"))
        if heartbeat["coordinatorGeneration"] == run["coordinator_generation"]:
            heartbeat_time = max(heartbeat_time, _parse_timestamp(heartbeat["updatedAt"]))
    except (OSError, KeyError, TypeError, ValueError):
        pass
    current_time = _parse_timestamp(timestamp)
    return heartbeat_time > current_time - timedelta(seconds=DEEP_SCAN_COORDINATOR_LEASE_SECONDS)


def require_current_coordinator(run: sqlite3.Row, args: argparse.Namespace) -> None:
    require_supported_deep_scan(run)
    generation = getattr(args, "coordinator_generation", None)
    if run["coordinator_generation"] == 1:
        if generation is not None:
            raise SystemExit("Deep Scan coordinator lease has not been claimed.")
        return
    if generation is None:
        raise SystemExit("Deep Scan mutation requires the current coordinator lease.")
    if generation != run["coordinator_generation"]:
        raise SystemExit("Deep Scan coordinator lease belongs to a newer generation.")


def claim_deep_scan_coordinator(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    with scan_completion_lock(scan_id):
        return claim_deep_scan_coordinator_locked(connection, args, scan_id)


def claim_deep_scan_coordinator_locked(
    connection: sqlite3.Connection, args: argparse.Namespace, scan_id: str
) -> dict[str, Any]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan, _ = require_owned_scan(connection, scan_id, args.thread_id)
        require_current_continuation(
            scan,
            args.claim_token,
            error_message="Deep Scan orchestration is owned by another continuation.",
        )
        run, _ = require_running_deep_scan(connection, scan_id)
        timestamp = now()
        if args.coordinator_generation is not None:
            require_current_coordinator(run, args)
            disposition = "claimed"
        elif coordinator_lease_is_live(connection, run, scan, timestamp):
            connection.commit()
            return {
                **deep_scan_result(connection, scan_id),
                "coordinatorDisposition": "observing",
            }
        else:
            adopted = run["coordinator_generation"] > 1 or run["phase"] != "setup"
            disposition = "adopted" if adopted else "claimed"

        if (
            getattr(args, "require_execution_settings", False)
            and deep_scan_finalization_input(run) is None
        ):
            scan_dir = Path(scan["scan_dir"])
            if (
                run["workflow_version"] == DEEP_SCAN_WORKFLOW_VERSION
                or (scan_dir / "artifacts/deep_discovery/execution-settings.json").exists()
            ):
                read_deep_scan_execution_settings(scan_dir)
        if disposition == "adopted":
            recover_expired_coordinator(connection, run, timestamp)
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET coordinator_generation = coordinator_generation + ?, updated_at = ?
            WHERE scan_id = ? AND status = 'running'
            """,
            (int(args.coordinator_generation != run["coordinator_generation"]), timestamp, scan_id),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return {
        **deep_scan_result(connection, scan_id),
        "coordinatorDisposition": disposition,
    }


def recover_expired_coordinator(
    connection: sqlite3.Connection, run: sqlite3.Row, timestamp: str
) -> None:
    require_supported_deep_scan(run)
    if deep_scan_finalization_input(run) is not None:
        return
    scan_id = run["scan_id"]
    recover_candidate_ledger_publication(connection, scan_id)
    legacy_generation = int(run["coordinator_generation"] == 1)
    interrupted_discoveries = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'discovery'
              AND (
                status IN ('queued', 'running')
                OR (
                    status = 'canceled'
                    AND (
                        error_message LIKE 'coordinator_shutdown:%'
                        OR (? = 1 AND error_message IS NULL)
                    )
                )
              )
            """,
            (scan_id, legacy_generation),
        ).fetchone()[0]
    )
    connection.execute(
        """
        UPDATE deep_scan_workers
        SET merge_state = 'buffered', updated_at = ?
        WHERE scan_id = ? AND merge_state = 'merging'
            AND id IN (
                SELECT inputs.discovery_worker_id
                FROM deep_scan_dedup_inputs AS inputs
                JOIN deep_scan_workers AS reducers ON reducers.id = inputs.dedup_worker_id
                WHERE reducers.scan_id = ?
                    AND reducers.kind = 'dedup'
                    AND (
                        reducers.status IN ('queued', 'running', 'failed')
                        OR (
                            reducers.status = 'canceled'
                            AND (
                                reducers.error_message LIKE 'coordinator_shutdown:%'
                                OR (? = 1 AND reducers.error_message IS NULL)
                            )
                        )
                    )
            )
        """,
        (timestamp, scan_id, scan_id, legacy_generation),
    )
    cancel_active_workers(connection, scan_id, timestamp)
    connection.execute(
        """
        UPDATE deep_scan_workers
        SET error_message = 'coordinator_shutdown_recovered: replacement attempt required',
            updated_at = ?
        WHERE scan_id = ? AND status = 'canceled'
            AND (
                error_message LIKE 'coordinator_shutdown:%'
                OR (? = 1 AND error_message IS NULL)
            )
        """,
        (timestamp, scan_id, legacy_generation),
    )
    connection.execute(
        """
        UPDATE deep_scan_runs
        SET discovery_runs_dispatched = discovery_runs_dispatched - ?,
            phase = CASE WHEN phase = 'setup' THEN 'setup' ELSE 'discovery' END,
            updated_at = ?
        WHERE scan_id = ?
        """,
        (interrupted_discoveries, timestamp, scan_id),
    )


def recover_candidate_ledger_publication(connection: sqlite3.Connection, scan_id: str) -> None:
    scan = require_scan(connection, scan_id)
    ledger = Path(scan["scan_dir"]) / "artifacts" / "02_discovery" / "candidate_ledger.jsonl"
    backups = sorted(
        ledger.parent.glob(f".{ledger.name}.*.backup"),
        key=lambda backup: backup.stat().st_mtime_ns,
        reverse=True,
    )
    if not ledger.exists() and not backups:
        return
    reducers = connection.execute(
        """
        SELECT status, artifact_dir
        FROM deep_scan_workers
        WHERE scan_id = ? AND kind = 'dedup'
          AND status IN ('queued', 'running', 'succeeded')
        ORDER BY updated_at DESC
        """,
        (scan_id,),
    )
    for reducer in reducers:
        snapshot = Path(reducer["artifact_dir"]) / "canonical" / ledger.name
        if not snapshot.exists():
            continue
        published = publication_matches_snapshot(ledger, snapshot)
        interrupted = reducer["status"] != "succeeded"
        if not published and not (interrupted and backups and not ledger.exists()):
            continue
        if interrupted:
            if backups:
                os.replace(backups.pop(0), ledger)
            else:
                ledger.unlink(missing_ok=True)
        for backup in backups:
            backup.unlink(missing_ok=True)
        return


def require_deep_scan_worker(connection: sqlite3.Connection, worker_id: str) -> sqlite3.Row:
    worker_id = require_uuid(worker_id, "worker-id")
    row = connection.execute(
        "SELECT * FROM deep_scan_workers WHERE id = ?", (worker_id,)
    ).fetchone()
    if row is None:
        raise SystemExit("Codex Security Deep Scan worker not found.")
    return row


def require_running_deep_scan(
    connection: sqlite3.Connection, scan_id: str
) -> tuple[sqlite3.Row, sqlite3.Row]:
    run = require_deep_scan_run(connection, scan_id)
    require_supported_deep_scan(run)
    scan = require_scan(connection, run["scan_id"])
    if run["status"] != "running" or run["cancel_requested"]:
        raise SystemExit("Only a running Deep Scan can update orchestration state.")
    if scan["status"] != "running" or scan["canceled_at"] is not None:
        raise SystemExit("Only a running scan can update Deep Scan orchestration state.")
    return run, scan


def require_worker_transition(current: str, requested: str) -> None:
    allowed = {
        "queued": {"queued", "running", "failed", "canceled"},
        "running": {"running", "succeeded", "failed", "canceled"},
        "succeeded": {"succeeded"},
        "failed": {"failed"},
        "canceled": {"canceled"},
    }
    if requested not in allowed[current]:
        raise SystemExit(f"Deep Scan worker cannot transition from {current} to {requested}.")


def snapshot_accepted_result(scan: sqlite3.Row, worker: sqlite3.Row) -> tuple[str, str]:
    source = deep_scan_path(
        scan, worker["result_manifest_path"], "Accepted worker result", kind="file"
    )
    scan_dir = Path(scan["scan_dir"])
    contents = Path(source).read_bytes()
    semantic = json.loads(contents)
    if isinstance(semantic, dict):
        semantic.pop("handoffClaimToken", None)
    directory = Path(worker["artifact_dir"]) / "checkpoints"
    head = (
        _worker_checkpoint_head(
            scan_dir, Path(worker["artifact_dir"]).relative_to(scan_dir).as_posix(), scan["id"]
        )
        if worker["kind"] == "discovery"
        else None
    )
    candidates = [scan_dir / head] if head else sorted(directory.glob("*.json"))
    for checkpoint in candidates:
        safe = deep_scan_path(scan, str(checkpoint), "Accepted worker checkpoint", kind="file")
        checkpoint_bytes = Path(safe).read_bytes()
        if json.loads(checkpoint_bytes) == semantic:
            return safe, hashlib.sha256(checkpoint_bytes).hexdigest()
        if head:
            raise SystemExit(
                "The accepted worker result does not match its current checkpoint head."
            )
    # Legacy/direct file producers may have no checkpoint. Use the existing native
    # checkpoint store; typed artifact writers already supplied the matching copy.
    digest = hashlib.sha256(contents).hexdigest()
    destination = directory / f"{digest}.json"
    if destination.exists():
        raise SystemExit("An existing worker checkpoint does not match its accepted content.")
    write_scan_local_bytes(scan_dir, destination.relative_to(scan_dir).as_posix(), contents)
    return str(destination), digest


def record_worker_attempt(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    worker: sqlite3.Row,
    timestamp: str,
    *,
    observed_thread_id: str | None = None,
    error: str | None = None,
    end_reason: str | None = None,
) -> None:
    if worker["status"] == "queued" or worker["attempt"] < 1:
        return
    connection.execute(
        """
        UPDATE deep_scan_attempts
        SET status = 'replaced', completed_at = ?, end_reason = 'replacement_attempt'
        WHERE worker_id = ? AND attempt < ? AND completed_at IS NULL
        """,
        (timestamp, worker["id"], worker["attempt"]),
    )
    status = worker["status"]
    if end_reason in DEEP_SCAN_REPLACEABLE_FAILURE_KINDS:
        status = "failed"
    if status != "running":
        error = worker["error_message"]
    if status == "running" and error:
        status = "failed"
    completed = timestamp if status != "running" else None
    reason = end_reason or (
        "execution_or_artifact_error" if status == "failed" else status if completed else None
    )
    accepted_path = accepted_sha = None
    if status == "succeeded" and worker["result_manifest_path"]:
        accepted_path, accepted_sha = snapshot_accepted_result(scan, worker)
    connection.execute(
        """
        INSERT INTO deep_scan_attempts (
            scan_id, worker_id, attempt, status, started_at, completed_at,
            end_reason, error_message, accepted_result_path, accepted_result_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(worker_id, attempt) DO UPDATE SET
            status = CASE WHEN deep_scan_attempts.completed_at IS NULL THEN excluded.status
                ELSE deep_scan_attempts.status END,
            completed_at = COALESCE(deep_scan_attempts.completed_at, excluded.completed_at),
            end_reason = COALESCE(deep_scan_attempts.end_reason, excluded.end_reason),
            error_message = COALESCE(excluded.error_message, deep_scan_attempts.error_message),
            accepted_result_path = COALESCE(excluded.accepted_result_path,
                deep_scan_attempts.accepted_result_path),
            accepted_result_sha256 = COALESCE(excluded.accepted_result_sha256,
                deep_scan_attempts.accepted_result_sha256)
        """,
        (
            scan["id"],
            worker["id"],
            worker["attempt"],
            status,
            timestamp,
            completed,
            reason,
            error,
            accepted_path,
            accepted_sha,
        ),
    )
    if observed_thread_id:
        connection.execute(
            """
            INSERT OR IGNORE INTO deep_scan_attempt_sessions (
                scan_id, worker_id, attempt, sdk_thread_id, observed_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (scan["id"], worker["id"], worker["attempt"], observed_thread_id, timestamp),
        )


def worker_result_reference(
    connection: sqlite3.Connection, scan: sqlite3.Row, worker: sqlite3.Row
) -> tuple[str, str]:
    accepted = connection.execute(
        "SELECT accepted_result_path, accepted_result_sha256 FROM deep_scan_attempts "
        "WHERE worker_id = ? AND attempt = ?",
        (worker["id"], worker["attempt"]),
    ).fetchone()
    if accepted is not None and accepted["accepted_result_path"]:
        return accepted["accepted_result_path"], accepted["accepted_result_sha256"]
    # Old accepted workers have no attempt history; freeze their current accepted result on claim.
    return snapshot_accepted_result(scan, worker)


def upsert_deep_scan_worker(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    worker_id = require_uuid(args.worker_id, "worker-id")
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_deep_scan_run(connection, scan_id)
        require_current_coordinator(run, args)
        scan = require_scan(connection, scan_id)
        existing = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE id = ?", (worker_id,)
        ).fetchone()
        replaceable_failure_kind = args.replaceable_failure_kind
        if replaceable_failure_kind is not None and (
            args.kind != "discovery"
            or args.status != "canceled"
            or existing is None
            or existing["status"] not in {"running", "canceled"}
            or optional_text(args.error_message, maximum=2400) is None
        ):
            raise SystemExit(
                "A replaceable Deep Scan failure requires a running discovery worker, "
                "canceled status, and an error message."
            )
        cleanup_update = (
            existing is not None
            and args.status == "canceled"
            and existing["status"] in {"queued", "running", "canceled"}
            and run["status"] in {"succeeded", "failed", "canceled", "interrupted"}
        )
        terminal_repeat = (
            existing is not None
            and existing["status"] == args.status
            and args.status in {"succeeded", "failed", "canceled"}
        )
        if not cleanup_update and not terminal_repeat:
            require_running_deep_scan(connection, scan_id)
        prompt_path = deep_scan_path(scan, args.prompt_path, "Worker prompt path", kind="file")
        artifact_dir = deep_scan_path(
            scan, args.artifact_dir, "Worker artifact directory", kind="directory"
        )
        result_manifest_path = (
            (
                deep_scan_output_path(
                    scan, args.result_manifest_path, "Worker result manifest path"
                )
                if terminal_repeat
                else deep_scan_path(
                    scan, args.result_manifest_path, "Worker result manifest path", kind="file"
                )
            )
            if args.result_manifest_path
            else None
        )
        timestamp = now()
        if existing is None:
            if args.kind == "dedup":
                raise SystemExit("Create dedup workers with claim-deep-scan-dedup.")
            if args.status not in {"queued", "running"}:
                raise SystemExit("A new Deep Scan worker must be queued or running.")
            if (
                args.kind == "setup"
                and connection.execute(
                    "SELECT 1 FROM deep_scan_workers WHERE scan_id = ? AND kind = 'setup'",
                    (scan_id,),
                ).fetchone()
                is not None
            ):
                raise SystemExit("A Deep Scan can have only one setup worker.")
            attempt = (
                args.attempt if args.attempt is not None else (1 if args.status == "running" else 0)
            )
            if args.status == "running" and attempt < 1:
                raise SystemExit("A running Deep Scan worker attempt must be at least one.")
            if args.kind == "discovery":
                if run["discovery_runs_dispatched"] >= run["max_discovery_runs"]:
                    raise SystemExit("Deep Scan maximum discovery runs has been reached.")
                connection.execute(
                    """
                    UPDATE deep_scan_runs
                    SET discovery_runs_dispatched = discovery_runs_dispatched + 1,
                        phase = 'discovery', updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (timestamp, scan_id),
                )
            connection.execute(
                """
                INSERT INTO deep_scan_workers (
                    id, scan_id, kind, status, prompt_path, artifact_dir, attempt,
                    sdk_thread_id, error_message, created_at, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    worker_id,
                    scan_id,
                    args.kind,
                    args.status,
                    prompt_path,
                    artifact_dir,
                    attempt,
                    optional_text(args.sdk_thread_id, maximum=512),
                    optional_text(args.error_message, maximum=2400),
                    timestamp,
                    timestamp if args.status == "running" else None,
                    timestamp,
                ),
            )
            record_worker_attempt(
                connection,
                scan,
                require_deep_scan_worker(connection, worker_id),
                timestamp,
                observed_thread_id=optional_text(args.sdk_thread_id, maximum=512),
                error=optional_text(args.error_message, maximum=2400),
                end_reason=args.replaceable_failure_kind,
            )
            result = deep_scan_result(connection, scan_id)
            connection.commit()
            return result

        if existing["scan_id"] != scan_id or existing["kind"] != args.kind:
            raise SystemExit("Deep Scan worker identity does not match its persisted run and kind.")
        if existing["prompt_path"] != prompt_path or existing["artifact_dir"] != artifact_dir:
            raise SystemExit("Deep Scan worker prompt and artifact paths are immutable.")
        require_worker_transition(existing["status"], args.status)
        if terminal_repeat:
            repeated_attempt = args.attempt if args.attempt is not None else existing["attempt"]
            repeated_thread_id = optional_text(args.sdk_thread_id, maximum=512)
            repeated_error = optional_text(args.error_message, maximum=2400)
            repeated_result_path = result_manifest_path or existing["result_manifest_path"]
            if (
                repeated_attempt != existing["attempt"]
                or repeated_result_path != existing["result_manifest_path"]
                or (
                    repeated_thread_id is not None
                    and repeated_thread_id != existing["sdk_thread_id"]
                )
                or repeated_error is not None
                and repeated_error != existing["error_message"]
            ):
                raise SystemExit("Deep Scan worker terminal state is immutable.")
            receipt = connection.execute(
                "SELECT receipt_json FROM deep_scan_attempts WHERE worker_id = ? AND attempt = ?",
                (worker_id, existing["attempt"]),
            ).fetchone()
            result = deep_scan_result(connection, scan_id)
            if receipt is not None and receipt["receipt_json"]:
                result["deepScan"]["workerReceipt"] = json.loads(receipt["receipt_json"])
            connection.commit()
            return result
        attempt = args.attempt if args.attempt is not None else existing["attempt"]
        if attempt < existing["attempt"]:
            raise SystemExit("Deep Scan worker attempt cannot decrease.")
        if args.status == "running" and attempt < 1:
            raise SystemExit("A running Deep Scan worker attempt must be at least one.")
        if args.kind == "dedup" and args.status == "succeeded":
            raise SystemExit("Commit a successful dedup worker with commit-deep-scan-dedup.")
        if args.kind == "discovery" and args.status == "succeeded" and result_manifest_path is None:
            result_manifest_path = existing["result_manifest_path"]
            if result_manifest_path is None:
                raise SystemExit("A successful Deep Scan worker requires a result manifest.")

        completion_sequence = existing["completion_sequence"]
        merge_state = existing["merge_state"]
        if args.kind == "discovery" and args.status == "succeeded" and completion_sequence is None:
            completion_sequence = run["completion_sequence"] + 1
            merge_state = "buffered"
            connection.execute(
                """
                UPDATE deep_scan_runs
                SET completion_sequence = ?, phase = 'discovery',
                    consecutive_errors = 0, updated_at = ?
                WHERE scan_id = ?
                """,
                (completion_sequence, timestamp, scan_id),
            )
        elif (
            args.kind == "discovery"
            and args.status == "canceled"
            and replaceable_failure_kind is not None
            and existing["status"] == "running"
        ):
            connection.execute(
                """
                UPDATE deep_scan_runs
                SET consecutive_errors = consecutive_errors + 1, updated_at = ?
                WHERE scan_id = ?
                """,
                (timestamp, scan_id),
            )
        elif args.kind == "dedup" and args.status == "failed" and existing["status"] == "running":
            connection.execute(
                """
                UPDATE deep_scan_workers
                SET merge_state = 'buffered', updated_at = ?
                WHERE scan_id = ? AND kind = 'discovery' AND status = 'succeeded'
                    AND merge_state = 'merging'
                    AND id IN (
                        SELECT discovery_worker_id FROM deep_scan_dedup_inputs
                        WHERE scan_id = ? AND dedup_worker_id = ?
                    )
                """,
                (timestamp, scan_id, scan_id, worker_id),
            )
            connection.execute(
                """
                UPDATE deep_scan_runs
                SET phase = 'discovery', updated_at = ?
                WHERE scan_id = ?
                """,
                (timestamp, scan_id),
            )
        completed_at = (
            timestamp
            if args.status in {"succeeded", "failed", "canceled"}
            else existing["completed_at"]
        )
        error_message = optional_text(args.error_message, maximum=2400)
        if error_message is None and args.status != "succeeded":
            error_message = existing["error_message"]
        started_at = existing["started_at"] or (timestamp if args.status == "running" else None)
        connection.execute(
            """
            UPDATE deep_scan_workers
            SET status = ?, result_manifest_path = ?, attempt = ?,
                sdk_thread_id = COALESCE(?, sdk_thread_id),
                completion_sequence = ?, merge_state = ?,
                error_message = ?,
                started_at = ?, completed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                args.status,
                result_manifest_path or existing["result_manifest_path"],
                attempt,
                optional_text(args.sdk_thread_id, maximum=512),
                completion_sequence,
                merge_state,
                error_message,
                started_at,
                completed_at,
                timestamp,
                worker_id,
            ),
        )
        record_worker_attempt(
            connection,
            scan,
            require_deep_scan_worker(connection, worker_id),
            timestamp,
            observed_thread_id=optional_text(args.sdk_thread_id, maximum=512),
            error=optional_text(args.error_message, maximum=2400),
            end_reason=args.replaceable_failure_kind,
        )
        result = deep_scan_result(connection, scan_id)
        if args.status in {"succeeded", "failed", "canceled"}:
            receipt = next(
                worker for worker in result["deepScan"]["workers"] if worker["id"] == worker_id
            )
            result["deepScan"]["workerReceipt"] = receipt
            connection.execute(
                "UPDATE deep_scan_attempts SET receipt_json = ? WHERE worker_id = ? AND attempt = ?",
                (json.dumps(receipt), worker_id, attempt),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def claim_deep_scan_dedup(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    worker_id = require_uuid(args.worker_id, "worker-id")
    input_ids = [require_uuid(value, "input-worker-id") for value in args.input_worker_id]
    if len(set(input_ids)) != len(input_ids):
        raise SystemExit("Dedup input worker IDs must be unique.")
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_deep_scan_run(connection, scan_id)
        scan = require_scan(connection, scan_id)
        require_current_coordinator(run, args)
        prompt_path = deep_scan_path(scan, args.prompt_path, "Dedup prompt path", kind="file")
        artifact_dir = deep_scan_path(
            scan, args.artifact_dir, "Dedup artifact directory", kind="directory"
        )
        existing = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE id = ?", (worker_id,)
        ).fetchone()
        if existing is not None:
            persisted_inputs = [
                row["discovery_worker_id"]
                for row in connection.execute(
                    """
                    SELECT discovery_worker_id
                    FROM deep_scan_dedup_inputs
                    WHERE dedup_worker_id = ?
                    ORDER BY input_order
                    """,
                    (worker_id,),
                )
            ]
            if (
                existing["scan_id"] == scan_id
                and existing["kind"] == "dedup"
                and existing["prompt_path"] == prompt_path
                and existing["artifact_dir"] == artifact_dir
                and persisted_inputs == input_ids
            ):
                result = deep_scan_result(connection, scan_id)
                connection.commit()
                return result
            raise SystemExit("Dedup worker ID is already used by a different reducer claim.")
        require_running_deep_scan(connection, scan_id)
        active_reducer = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status IN ('queued', 'running')
            """,
            (scan_id,),
        ).fetchone()
        if active_reducer is not None:
            raise SystemExit("Only one Deep Scan dedup worker can run at a time.")
        buffered_ids = [
            row["id"]
            for row in connection.execute(
                """
                SELECT id FROM deep_scan_workers
                WHERE scan_id = ? AND kind = 'discovery'
                    AND status = 'succeeded' AND merge_state = 'buffered'
                ORDER BY completion_sequence
                """,
                (scan_id,),
            )
        ]
        if input_ids != buffered_ids[: len(input_ids)]:
            raise SystemExit(
                "A Deep Scan dedup worker must claim an ordered prefix of buffered discovery "
                "results in completion order."
            )
        capped_singleton = (
            len(input_ids) == 1
            and (
                run["discovery_runs_dispatched"] >= run["max_discovery_runs"]
                or deep_scan_deadline_reached(run)
            )
            and connection.execute(
                """
                SELECT 1 FROM deep_scan_workers
                WHERE scan_id = ? AND kind = 'discovery' AND status IN ('queued', 'running')
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
            is None
        )
        successful_reducer = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status = 'succeeded'
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        minimum_inputs = 1 if successful_reducer is not None or capped_singleton else 2
        if len(input_ids) < minimum_inputs:
            raise SystemExit(
                "The first Deep Scan dedup requires two buffered discovery results."
                if minimum_inputs == 2
                else "A Deep Scan dedup requires at least one buffered discovery result."
            )
        timestamp = now()
        connection.execute(
            """
            INSERT INTO deep_scan_workers (
                id, scan_id, kind, status, prompt_path, artifact_dir,
                created_at, updated_at
            ) VALUES (?, ?, 'dedup', 'queued', ?, ?, ?, ?)
            """,
            (worker_id, scan_id, prompt_path, artifact_dir, timestamp, timestamp),
        )
        previous = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ? AND kind = 'dedup' "
            "AND status = 'succeeded' ORDER BY completed_at DESC, rowid DESC LIMIT 1",
            (scan_id,),
        ).fetchone()
        previous_path, previous_sha = (
            worker_result_reference(connection, scan, previous) if previous else (None, None)
        )
        connection.execute(
            """
            INSERT INTO deep_scan_merge_claims (
                worker_id, scan_id, previous_worker_id, previous_result_path, previous_result_sha256
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (worker_id, scan_id, previous["id"] if previous else None, previous_path, previous_sha),
        )
        for input_order, input_id in enumerate(input_ids):
            discovery = require_deep_scan_worker(connection, input_id)
            accepted_path, accepted_sha = worker_result_reference(connection, scan, discovery)
            connection.execute(
                """
                INSERT INTO deep_scan_dedup_inputs (
                    scan_id, dedup_worker_id, discovery_worker_id, input_order,
                    result_manifest_path, result_manifest_sha256, attempt
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    worker_id,
                    input_id,
                    input_order,
                    accepted_path,
                    accepted_sha,
                    discovery["attempt"],
                ),
            )
        connection.execute(
            f"""
            UPDATE deep_scan_workers
            SET merge_state = 'merging', updated_at = ?
            WHERE scan_id = ? AND id IN ({",".join("?" for _ in input_ids)})
            """,
            (timestamp, scan_id, *input_ids),
        )
        connection.execute(
            "UPDATE deep_scan_runs SET phase = 'reducing', updated_at = ? WHERE scan_id = ?",
            (timestamp, scan_id),
        )
        connection.execute(
            """
            UPDATE scan_progress
            SET deep_review_pass = COALESCE(deep_review_pass, 0) + 1, updated_at = ?
            WHERE scan_id = ?
            """,
            (timestamp, scan_id),
        )
        result = deep_scan_result(connection, scan_id)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return result


def commit_deep_scan_dedup(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    with scan_completion_lock(scan_id):
        return commit_deep_scan_dedup_locked(connection, args, scan_id)


def commit_deep_scan_dedup_locked(
    connection: sqlite3.Connection, args: argparse.Namespace, scan_id: str
) -> dict[str, Any]:
    worker_id = require_uuid(args.worker_id, "worker-id")
    promotion: tuple[Path, Path, Path | None] | None = None
    publication_copy: Path | None = None
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_deep_scan_run(connection, scan_id)
        require_current_coordinator(run, args)
        scan = require_scan(connection, scan_id)
        worker = require_deep_scan_worker(connection, worker_id)
        if worker["scan_id"] != scan_id or worker["kind"] != "dedup":
            raise SystemExit("Dedup worker does not belong to this Deep Scan.")
        if worker["status"] == "succeeded":
            receipt = connection.execute(
                "SELECT receipt_json FROM deep_scan_merge_claims WHERE worker_id = ?", (worker_id,)
            ).fetchone()
            result = deep_scan_result(connection, scan_id)
            if receipt is not None and receipt["receipt_json"]:
                result["deepScan"]["committedMerge"] = json.loads(receipt["receipt_json"])
            connection.commit()
            return result
        require_running_deep_scan(connection, scan_id)
        if worker["status"] not in {"queued", "running"}:
            raise SystemExit("Only an active dedup worker can commit a result.")
        if args.candidate_ledger_path:
            candidate_ledger_path = deep_scan_path(
                scan,
                args.candidate_ledger_path,
                "Staged candidate ledger path",
                kind="file",
            )
            discovery_dir = Path(scan["scan_dir"]) / "artifacts" / "02_discovery"
            deep_scan_path(
                scan,
                str(discovery_dir / "in_scope_files.txt"),
                "Canonical in-scope inventory path",
                kind="file",
            )
            canonical_candidate_ledger_path = deep_scan_output_path(
                scan,
                str(discovery_dir / "candidate_ledger.jsonl"),
                "Canonical candidate ledger path",
            )
        else:
            candidate_ledger_path = None
            canonical_candidate_ledger_path = None
        result_manifest_path = deep_scan_path(
            scan,
            args.result_manifest_path,
            "Dedup result manifest path",
            kind="file",
        )
        inputs = list(
            connection.execute(
                """
                SELECT workers.*
                FROM deep_scan_dedup_inputs AS inputs
                JOIN deep_scan_workers AS workers ON workers.id = inputs.discovery_worker_id
                WHERE inputs.dedup_worker_id = ?
                ORDER BY inputs.input_order
                """,
                (worker_id,),
            )
        )
        if not inputs or any(row["merge_state"] != "merging" for row in inputs):
            raise SystemExit("Dedup inputs are not in the claimed merging state.")
        claim = connection.execute(
            "SELECT * FROM deep_scan_merge_claims WHERE worker_id = ?", (worker_id,)
        ).fetchone()
        references = [
            (row["result_manifest_path"], row["result_manifest_sha256"])
            for row in connection.execute(
                "SELECT * FROM deep_scan_dedup_inputs WHERE dedup_worker_id = ? ORDER BY input_order",
                (worker_id,),
            )
        ]
        if claim is not None and claim["previous_result_path"]:
            references.append((claim["previous_result_path"], claim["previous_result_sha256"]))
        for path, digest in references:
            if path is not None and digest is not None:
                safe_path = deep_scan_path(scan, path, "Claimed reducer input", kind="file")
                if hashlib.sha256(Path(safe_path).read_bytes()).hexdigest() != digest:
                    raise SystemExit("A claimed Deep Scan reducer input changed after acceptance.")
        if candidate_ledger_path and canonical_candidate_ledger_path:
            canonical_path = Path(canonical_candidate_ledger_path)
            publication_copy = canonical_path.with_name(
                f".{canonical_path.name}.{uuid.uuid4()}.publish"
            )
            create_publication_copy(candidate_ledger_path, publication_copy)
            promotion = promote_staged_file(
                str(publication_copy),
                canonical_candidate_ledger_path,
            )
        timestamp = now()
        connection.execute(
            """
            UPDATE deep_scan_workers
            SET merge_state = 'merged', updated_at = ?
            WHERE id IN (
                SELECT discovery_worker_id FROM deep_scan_dedup_inputs
                WHERE dedup_worker_id = ?
            )
            """,
            (timestamp, worker_id),
        )
        connection.execute(
            """
            UPDATE deep_scan_workers
            SET status = 'succeeded', result_manifest_path = ?,
                error_message = NULL, started_at = COALESCE(started_at, ?),
                completed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (result_manifest_path, timestamp, timestamp, timestamp, worker_id),
        )
        no_new_streak = (
            0 if args.new_findings_count > 0 else run["consecutive_no_new"] + len(inputs)
        )
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET phase = 'discovery', consecutive_no_new = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (no_new_streak, timestamp, scan_id),
        )
        committed_worker = require_deep_scan_worker(connection, worker_id)
        record_worker_attempt(
            connection,
            scan,
            committed_worker,
            timestamp,
            observed_thread_id=committed_worker["sdk_thread_id"],
        )
        accepted_path, accepted_sha = worker_result_reference(connection, scan, committed_worker)
        result = deep_scan_result(connection, scan_id)
        result["deepScan"]["committedMerge"] = {
            "workerId": worker_id,
            "resultManifestPath": accepted_path,
            "resultManifestSha256": accepted_sha,
            "newFindings": args.new_findings_count,
        }
        connection.execute(
            "INSERT INTO deep_scan_merge_claims (worker_id, scan_id, receipt_json) VALUES (?, ?, ?) "
            "ON CONFLICT(worker_id) DO UPDATE SET receipt_json = excluded.receipt_json",
            (worker_id, scan_id, json.dumps(result["deepScan"]["committedMerge"])),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        if promotion is not None:
            rollback_staged_file(promotion)
        if publication_copy is not None:
            publication_copy.unlink(missing_ok=True)
        raise
    if promotion is not None:
        finish_staged_file(promotion)
    if publication_copy is not None:
        publication_copy.unlink(missing_ok=True)
    return result


def finish_deep_scan(
    connection: sqlite3.Connection, args: argparse.Namespace, select_finalization: bool = False
) -> dict[str, Any]:
    if select_finalization:
        import sys

        args = argparse.Namespace(
            **vars(args),
            select_finalization=True,
            finalization_result_path=json.load(sys.stdin)["resultPath"],
        )
    scan_id = require_uuid(args.scan_id, "scan-id")
    with scan_completion_lock(scan_id):
        return finish_deep_scan_locked(connection, args, scan_id)


def finish_deep_scan_locked(
    connection: sqlite3.Connection, args: argparse.Namespace, scan_id: str
) -> dict[str, Any]:
    omitted_worker_ids = [
        require_uuid(value, "omitted-worker-id") for value in args.omitted_worker_id
    ]
    if len(set(omitted_worker_ids)) != len(omitted_worker_ids):
        raise SystemExit("Omitted Deep Scan worker IDs must be unique.")
    selecting = getattr(args, "select_finalization", False)
    promotion: tuple[Path, Path, Path | None] | None = None
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_deep_scan_run(connection, scan_id)
        require_current_coordinator(run, args)
        scan = require_scan(connection, scan_id)
        if selecting and run["workflow_version"] != "deep-security-scan/v2":
            raise SystemExit("Selected finalization requires the supported v2 workflow.")
        finalization = deep_scan_finalization_input(run)
        if finalization is not None and (
            args.terminal_reason != finalization["terminalReason"]
            or omitted_worker_ids != finalization["omittedWorkerIds"]
        ):
            raise SystemExit(
                "Deep Scan finalization must retain its selected reason and omissions."
            )
        manifest_path = (
            deep_scan_output_path(scan, args.manifest_path, "Deep Scan coordinator manifest path")
            if args.staged_manifest_path or selecting
            else deep_scan_path(
                scan, args.manifest_path, "Deep Scan coordinator manifest path", kind="file"
            )
        )
        standard_scan_manifest = manifest_path == str(Path(scan["scan_dir"]) / "scan-manifest.json")

        failure_capped = False
        if (
            standard_scan_manifest
            and not selecting
            and args.terminal_reason == "capped"
            and (run["status"] == "running" or omitted_worker_ids)
        ):
            for artifact_name in ("scan-manifest.json", "findings.json", "coverage.json"):
                deep_scan_path(
                    scan,
                    str(Path(scan["scan_dir"]) / artifact_name),
                    f"Canonical parent {artifact_name}",
                    kind="file",
                )
            coverage = _read_scan_local_json(
                Path(scan["scan_dir"]), "coverage.json", "Canonical parent coverage.json"
            )
            deferred = coverage.get("deferred")
            failure_capped = (
                coverage.get("completeness") == "partial"
                and isinstance(deferred, list)
                and any(
                    isinstance(item, dict)
                    and isinstance(item.get("reason"), str)
                    and item["reason"].startswith("Deep Scan stopped before completion: ")
                    for item in deferred
                )
                and connection.execute(
                    """
                    SELECT 1 FROM deep_scan_workers
                    WHERE scan_id = ? AND kind = 'dedup' AND status = 'succeeded'
                    LIMIT 1
                    """,
                    (scan_id,),
                ).fetchone()
                is not None
            )
            if failure_capped and run["status"] == "running":
                require_running_deep_scan(connection, scan_id)
                connection.execute(
                    """
                    UPDATE deep_scan_workers
                    SET merge_state = 'buffered', updated_at = ?
                    WHERE scan_id = ? AND kind = 'discovery' AND status = 'succeeded'
                        AND merge_state = 'merging'
                        AND id IN (
                            SELECT inputs.discovery_worker_id
                            FROM deep_scan_dedup_inputs AS inputs
                            JOIN deep_scan_workers AS reducers
                                ON reducers.id = inputs.dedup_worker_id
                                AND reducers.scan_id = inputs.scan_id
                            WHERE inputs.scan_id = ?
                                AND reducers.kind = 'dedup'
                                AND reducers.status IN ('failed', 'canceled')
                        )
                    """,
                    (now(), scan_id, scan_id),
                )
        buffered_worker_ids = [
            row["id"]
            for row in connection.execute(
                """
                SELECT id
                FROM deep_scan_workers
                WHERE scan_id = ? AND kind = 'discovery' AND merge_state = 'buffered'
                ORDER BY completion_sequence, id
                """,
                (scan_id,),
            )
        ]
        omissions_match = (
            set(omitted_worker_ids) == set(buffered_worker_ids)
            if args.terminal_reason == "saturated" or failure_capped
            else not omitted_worker_ids and not buffered_worker_ids
        )
        if run["status"] == "succeeded":
            if (
                run["terminal_reason"] != args.terminal_reason
                or run["manifest_path"] not in {None, manifest_path}
                or not omissions_match
            ):
                raise SystemExit(
                    "Deep Scan terminal state is immutable; finish must exactly replay its "
                    "terminal reason, manifest path, and omitted worker IDs."
                )
            if run["manifest_path"] is None:
                connection.execute(
                    "UPDATE deep_scan_runs SET manifest_path = ?, updated_at = ? WHERE scan_id = ?",
                    (manifest_path, now(), scan_id),
                )
            connection.commit()
            return deep_scan_result(connection, scan_id)
        require_running_deep_scan(connection, scan_id)
        if (
            args.terminal_reason == "saturated"
            and run["consecutive_no_new"] < run["stop_after_no_new"]
        ):
            raise SystemExit(
                "Deep Scan cannot finish saturated before reaching its no-new-findings threshold."
            )
        if (
            args.terminal_reason == "capped"
            and run["discovery_runs_dispatched"] < run["max_discovery_runs"]
            and not deep_scan_deadline_reached(run)
            and not failure_capped
        ):
            raise SystemExit(
                "Deep Scan cannot finish capped before reaching its configured maximum."
            )
        canonical_artifacts = None
        if selecting:
            if not standard_scan_manifest:
                raise SystemExit("Selected Deep Scan finalization requires the parent manifest.")
        elif standard_scan_manifest:
            for artifact_name in ("scan-manifest.json", "findings.json", "coverage.json"):
                deep_scan_path(
                    scan,
                    str(Path(scan["scan_dir"]) / artifact_name),
                    f"Canonical parent {artifact_name}",
                    kind="file",
                )
        else:
            try:
                canonical_artifacts = canonical_discovery_artifacts(scan)
            except SystemExit as exc:
                raise SystemExit(
                    f"Deep Scan cannot finish without canonical discovery artifacts: {exc}"
                ) from exc
        successful_reducer = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status = 'succeeded'
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        zero_discovery_deadline = (
            args.terminal_reason == "capped"
            and deep_scan_deadline_reached(run)
            and run["completion_sequence"] == 0
            and (
                standard_scan_manifest
                or canonical_artifacts is not None
                and Path(canonical_artifacts["candidateLedgerPath"]).stat().st_size == 0
            )
        )
        if successful_reducer is None and not zero_discovery_deadline:
            raise SystemExit("Deep Scan cannot finish without a successful dedup worker.")
        failed_worker = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers AS failed
            WHERE failed.scan_id = ? AND failed.status = 'failed'
                AND (? != 'saturated' OR failed.kind != 'discovery')
                AND (
                    failed.kind != 'dedup'
                    OR NOT EXISTS (
                        SELECT 1 FROM deep_scan_dedup_inputs AS failed_inputs
                        WHERE failed_inputs.dedup_worker_id = failed.id
                    )
                    OR EXISTS (
                        SELECT 1 FROM deep_scan_dedup_inputs AS failed_inputs
                        WHERE failed_inputs.dedup_worker_id = failed.id
                            AND NOT EXISTS (
                                SELECT 1
                                FROM deep_scan_dedup_inputs AS replacement_inputs
                                JOIN deep_scan_workers AS replacement
                                    ON replacement.scan_id = replacement_inputs.scan_id
                                    AND replacement.id = replacement_inputs.dedup_worker_id
                                WHERE replacement_inputs.scan_id = failed.scan_id
                                    AND replacement_inputs.discovery_worker_id =
                                        failed_inputs.discovery_worker_id
                                    AND replacement.kind = 'dedup'
                                    AND replacement.status = 'succeeded'
                            )
                    )
                )
            LIMIT 1
            """,
            (scan_id, args.terminal_reason),
        ).fetchone()
        if failed_worker is not None and not failure_capped:
            raise SystemExit("Deep Scan cannot finish after a worker has failed.")
        if args.terminal_reason == "saturated":
            # Mark any remaining workers canceled, including those whose own
            # cancellation writes failed, so they cannot block completion.
            cancel_active_workers(connection, scan_id, now())
        active_worker = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND status IN ('queued', 'running')
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        if active_worker is not None:
            raise SystemExit("Deep Scan cannot finish while workers are active.")
        merging_worker = connection.execute(
            """
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND merge_state = 'merging'
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()
        if merging_worker is not None:
            raise SystemExit("Deep Scan cannot finish while discovery output is merging.")
        if args.terminal_reason == "capped" and omitted_worker_ids and not failure_capped:
            raise SystemExit("Deep Scan capped completion cannot declare omitted buffered workers.")
        if args.terminal_reason == "capped" and buffered_worker_ids and not failure_capped:
            raise SystemExit(
                "Deep Scan cannot finish capped while discovery output remains buffered."
            )
        if (args.terminal_reason == "saturated" or failure_capped) and not omissions_match:
            raise SystemExit(
                f"Deep Scan {args.terminal_reason} completion must exactly identify all buffered discovery "
                "workers with --omitted-worker-id."
            )
        if selecting:
            selection = selected_deep_scan_finalization(
                connection, run, scan, args, omitted_worker_ids, zero_discovery_deadline
            )
            connection.execute(
                "UPDATE deep_scan_runs SET finalization_input_json = ?, terminal_reason = ?, "
                "phase = 'terminal', updated_at = ? WHERE scan_id = ?",
                (json.dumps(selection), selection["terminalReason"], now(), scan_id),
            )
            connection.commit()
            return deep_scan_result(connection, scan_id)
        if args.staged_manifest_path:
            staged_manifest_path = deep_scan_path(
                scan,
                args.staged_manifest_path,
                "Staged Deep Scan coordinator manifest path",
                kind="file",
            )
            promotion = promote_staged_file(staged_manifest_path, manifest_path)
        timestamp = now()
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = 'succeeded', phase = 'terminal', terminal_reason = ?,
                manifest_path = ?, completed_at = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (args.terminal_reason, manifest_path, timestamp, timestamp, scan_id),
        )
        cancel_active_workers(connection, scan_id, timestamp)
        connection.commit()
    except BaseException:
        connection.rollback()
        if promotion is not None:
            rollback_staged_file(promotion)
        raise
    if promotion is not None:
        finish_staged_file(promotion)
    return deep_scan_result(connection, scan_id)


def selected_deep_scan_finalization(
    connection: sqlite3.Connection,
    run: sqlite3.Row,
    scan: sqlite3.Row,
    args: argparse.Namespace,
    omitted_worker_ids: list[str],
    zero_discovery_deadline: bool,
) -> dict[str, Any]:
    """Select the committed attempt's immutable aggregate before publication."""
    if run["finalization_input_json"] is not None:
        return json.loads(run["finalization_input_json"])
    result_path = getattr(args, "finalization_result_path", None)
    relative: str | None = None
    digest: str | None = None
    if result_path is None:
        if not zero_discovery_deadline:
            raise SystemExit("Deep Scan finalization requires its accepted reducer result.")
    else:
        accepted = connection.execute(
            "SELECT attempts.accepted_result_path, attempts.accepted_result_sha256 "
            "FROM deep_scan_workers AS workers LEFT JOIN deep_scan_attempts AS attempts "
            "ON attempts.worker_id = workers.id AND attempts.attempt = workers.attempt "
            "WHERE workers.id = (SELECT id FROM deep_scan_workers WHERE scan_id = ? "
            "AND kind = 'dedup' AND status = 'succeeded' ORDER BY completed_at DESC, id DESC LIMIT 1) "
            "AND (workers.result_manifest_path = ? OR attempts.accepted_result_path = ?)",
            (scan["id"], result_path, result_path),
        ).fetchone()
        if (
            accepted is None
            or not accepted["accepted_result_path"]
            or not accepted["accepted_result_sha256"]
        ):
            raise SystemExit(
                "Deep Scan finalization requires its committed accepted reducer reference."
            )
        scan_dir = Path(scan["scan_dir"])
        source = Path(
            deep_scan_path(
                scan, accepted["accepted_result_path"], "Selected Deep Scan result", kind="file"
            )
        )
        relative = source.relative_to(scan_dir).as_posix()
        digest = accepted["accepted_result_sha256"]
    selection = {
        "version": 1,
        "resultPath": relative,
        "resultSha256": digest,
        "terminalReason": args.terminal_reason,
        "omittedWorkerIds": omitted_worker_ids,
        "selectedAt": now(),
    }
    return selection


def budget_unmerged_workers(connection: sqlite3.Connection, scan_id: str) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT workers.*, attempts.accepted_result_path, attempts.accepted_result_sha256 "
        "FROM deep_scan_workers AS workers JOIN deep_scan_attempts AS attempts "
        "ON attempts.worker_id = workers.id AND attempts.attempt = workers.attempt "
        "WHERE workers.scan_id = ? AND workers.kind = 'discovery' "
        "AND workers.status = 'succeeded' AND workers.merge_state IN ('buffered', 'merging') "
        "ORDER BY workers.completion_sequence, workers.id",
        (scan_id,),
    ).fetchall()


def prepare_budget_exhausted_deep_scan(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    scan_dir: Path,
    warning: str,
    write_draft: Callable[[dict[str, Any] | None, list[sqlite3.Row]], None],
) -> None:
    """Finish local budget publication without starting or promoting scan work."""
    snapshots = _snapshot_published_outputs(scan_dir)
    connection.execute("BEGIN IMMEDIATE")
    try:
        # The completion lock and this transaction preserve any committed selector.
        run, scan = require_running_deep_scan(connection, scan["id"])
        unmerged = budget_unmerged_workers(connection, scan["id"])
        if run["finalization_input_json"] is not None:
            selection = json.loads(run["finalization_input_json"])
        else:
            reducer = connection.execute(
                "SELECT attempts.accepted_result_path FROM deep_scan_workers AS workers "
                "LEFT JOIN deep_scan_attempts AS attempts ON attempts.worker_id = workers.id "
                "AND attempts.attempt = workers.attempt WHERE workers.scan_id = ? "
                "AND workers.kind = 'dedup' AND workers.status = 'succeeded' "
                "ORDER BY workers.completed_at DESC, workers.id DESC LIMIT 1",
                (scan["id"],),
            ).fetchone()
            if reducer is not None and not reducer["accepted_result_path"]:
                raise SystemExit("Budget completion requires the committed reducer reference.")
            selection = selected_deep_scan_finalization(
                connection,
                run,
                scan,
                argparse.Namespace(
                    finalization_result_path=reducer["accepted_result_path"] if reducer else None,
                    terminal_reason="capped",
                ),
                [row["id"] for row in unmerged],
                reducer is None,
            )
        accepted = None
        if selection["resultPath"] is not None:
            descriptor = open_scan_local_file_descriptor(
                scan_dir, selection["resultPath"], "Accepted reducer"
            )
            with os.fdopen(descriptor, "rb") as source:
                contents = source.read()
            if hashlib.sha256(contents).hexdigest() != selection["resultSha256"]:
                raise SystemExit("The accepted reducer changed before budget completion.")
            accepted = json.loads(contents, parse_constant=reject_non_finite_json)
            if (
                not isinstance(accepted, dict)
                or accepted.get("scanId") != scan["id"]
                or accepted.get("complete", True) is not True
                or not isinstance(accepted.get("sourceCoverage"), dict)
            ):
                raise SystemExit("Budget completion requires the accepted complete reducer.")
        write_draft(accepted, unmerged)
        timestamp = now()
        cancel_active_workers(connection, scan["id"], timestamp)
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = ?, cancel_requested = 1, error_message = ?, "
            "manifest_path = ?, finalization_input_json = ?, completed_at = ?, updated_at = ? "
            "WHERE scan_id = ?",
            (
                selection["terminalReason"],
                warning,
                str(scan_dir / "scan-manifest.json"),
                json.dumps(selection),
                timestamp,
                timestamp,
                scan["id"],
            ),
        )
        warnings = json.loads(scan["completion_warnings_json"])
        if warning not in warnings:
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                (json.dumps([*warnings, warning]), scan["id"]),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        _restore_published_outputs(scan_dir, snapshots)
        raise


def fail_deep_scan(connection: sqlite3.Connection, args: argparse.Namespace) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    with scan_completion_lock(scan_id):
        return fail_deep_scan_locked(connection, args, scan_id)


def fail_deep_scan_locked(
    connection: sqlite3.Connection, args: argparse.Namespace, scan_id: str
) -> dict[str, Any]:
    message = optional_text(args.message, maximum=2400)
    if message is None:
        raise SystemExit("message is required.")
    promotion: tuple[Path, Path, Path | None] | None = None
    connection.execute("BEGIN IMMEDIATE")
    try:
        run = require_deep_scan_run(connection, scan_id)
        require_current_coordinator(run, args)
        scan = require_scan(connection, scan_id)
        manifest_path = None
        if args.manifest_path:
            manifest_path = (
                deep_scan_output_path(scan, args.manifest_path, "Deep Scan failure manifest path")
                if args.staged_manifest_path
                else deep_scan_path(
                    scan,
                    args.manifest_path,
                    "Deep Scan failure manifest path",
                    kind="file",
                )
            )
        if run["status"] in {"failed", "interrupted"} or scan["status"] == "failed":
            if (
                run["status"] == args.deep_status
                and scan["status"] == "failed"
                and run["error_message"] == message
                and run["manifest_path"] == manifest_path
                and scan["failure_message"] == message
            ):
                connection.commit()
                return deep_scan_result(connection, scan_id)
            raise SystemExit(
                "Deep Scan terminal failure state is immutable; failure status, message, "
                "manifest path, and parent failure must exactly match."
            )
        terminal_before_manifest = (
            args.deep_status in {"failed", "interrupted"}
            and run["status"] == "succeeded"
            and run["terminal_reason"] in {"saturated", "capped"}
            and run["manifest_path"] is None
        )
        if (run["status"] != "running" and not terminal_before_manifest) or scan[
            "status"
        ] != "running":
            raise SystemExit("Only a running Deep Scan can be failed or interrupted.")
        if run["manifest_path"] not in {None, manifest_path}:
            raise SystemExit("Deep Scan coordinator manifest path is immutable.")
        if args.staged_manifest_path and manifest_path:
            staged_manifest_path = deep_scan_path(
                scan,
                args.staged_manifest_path,
                "Staged Deep Scan failure manifest path",
                kind="file",
            )
            promotion = promote_staged_file(staged_manifest_path, manifest_path)
        timestamp = now()
        connection.execute(
            """
            UPDATE deep_scan_runs
            SET status = ?, phase = 'terminal', cancel_requested = 1,
                error_message = ?, manifest_path = ?, completed_at = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (args.deep_status, message, manifest_path, timestamp, timestamp, scan_id),
        )
        cancel_active_workers(connection, scan_id, timestamp)
        parent_update = connection.execute(
            """
            UPDATE scans
            SET status = 'failed', failure_message = ?, completed_at = ?, updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (message, timestamp, timestamp, scan_id),
        )
        if parent_update.rowcount != 1:
            raise SystemExit("Deep Scan failure could not be persisted to its parent scan.")
        connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan_id),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        if promotion is not None:
            rollback_staged_file(promotion)
        raise
    if promotion is not None:
        finish_staged_file(promotion)
    dependencies().preserve_stopped_results(connection, scan_id)
    return deep_scan_result(connection, scan_id)


def record_deep_scan_publication_failure(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    message = optional_text(args.message, maximum=2400)
    if message is None:
        raise SystemExit("message is required.")
    with scan_completion_lock(scan_id):
        connection.execute("BEGIN IMMEDIATE")
        try:
            run = require_deep_scan_run(connection, scan_id)
            require_current_coordinator(run, args)
            scan = require_scan(connection, scan_id)
            if (
                run["status"] not in {"failed", "canceled", "interrupted"}
                or scan["status"] != "failed"
            ):
                raise SystemExit(
                    "Saved result publication failures can only update a stopped Deep Scan."
                )
            if scan["seal_manifest_digest"] is not None:
                connection.commit()
                return deep_scan_result(connection, scan_id)
            if run["publication_error_message"] != message:
                timestamp = now()
                connection.execute(
                    """
                    UPDATE deep_scan_runs
                    SET publication_error_message = ?, updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (message, timestamp, scan_id),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
    return deep_scan_result(connection, scan_id)


def clear_deep_scan_publication_failure(connection: sqlite3.Connection, scan_id: str) -> None:
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET publication_error_message = NULL, updated_at = ? "
            "WHERE scan_id = ? AND publication_error_message IS NOT NULL",
            (now(), scan_id),
        )


def fail_from_parent_scan(
    connection: sqlite3.Connection,
    scan_id: str,
    message: str | None,
    timestamp: str,
) -> None:
    connection.execute(
        """
        UPDATE deep_scan_runs
        SET status = 'failed', phase = 'terminal', cancel_requested = 1,
            error_message = ?, completed_at = ?, updated_at = ?
        WHERE scan_id = ? AND status = 'running'
        """,
        (message, timestamp, timestamp, scan_id),
    )
    cancel_active_workers(connection, scan_id, timestamp)


def cancel_from_parent_scan(connection: sqlite3.Connection, scan_id: str, timestamp: str) -> None:
    connection.execute(
        """
        UPDATE deep_scan_runs
        SET status = 'canceled', phase = 'terminal', cancel_requested = 1,
            completed_at = ?, updated_at = ?
        WHERE scan_id = ? AND status IN ('running', 'succeeded')
        """,
        (timestamp, timestamp, scan_id),
    )
    cancel_active_workers(connection, scan_id, timestamp)


def cancel_active_workers(connection: sqlite3.Connection, scan_id: str, timestamp: str) -> None:
    connection.execute(
        "UPDATE deep_scan_attempts SET status = 'canceled', completed_at = ?, "
        "end_reason = 'scan_stopped' WHERE scan_id = ? AND completed_at IS NULL",
        (timestamp, scan_id),
    )
    connection.execute(
        """
        UPDATE deep_scan_workers
        SET status = 'canceled', completed_at = ?, updated_at = ?
        WHERE scan_id = ? AND status IN ('queued', 'running')
        """,
        (timestamp, timestamp, scan_id),
    )


def other_running_deep_scans(
    connection: sqlite3.Connection, current_scan_id: str
) -> list[dict[str, str]]:
    rows = connection.execute(
        """
        SELECT id, target_path, phase, started_at, updated_at
        FROM scans
        WHERE mode = 'deep' AND status = 'running' AND id != ?
        ORDER BY updated_at DESC, started_at DESC, id
        """,
        (current_scan_id,),
    )
    return [
        {
            "phase": row["phase"],
            "scanId": row["id"],
            "startedAt": row["started_at"],
            "targetPath": row["target_path"],
            "updatedAt": row["updated_at"],
        }
        for row in rows
    ]


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
