"""Progress transition helpers for the Codex Security workbench."""

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deep_scan_workbench import independent_review_progress, require_current_coordinator
from finalize_scan_contract import open_scan_local_file_descriptor
from workbench.handoff import require_current_continuation, require_tokenless_scan_owner
from workbench_constants import PHASES
from workbench_validation import optional_text, require_uuid, user_context_argument


def reportable_count(
    current_phase: str, requested_phase: str | None, count: int | None
) -> int | None:
    """Default a missing count to zero on entering validation or a later phase from an earlier phase."""
    if count is None and requested_phase in PHASES[3:] and current_phase in PHASES[:3]:
        return 0
    return count


def update_context(
    wb: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Update user context on a running scan and return the refreshed scan context in the same workbench."""
    scan_id = require_uuid(args.scan_id, "scan-id")
    context = user_context_argument(args)
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        scan = wb.require_scan(connection, scan_id)
        if scan["status"] != "running" or scan["canceled_at"] is not None:
            raise SystemExit("Only a running scan can update context.")
        workspace = wb.require_workspace(connection, scan["workspace_id"])
        if args.workspace_id is not None:
            if args.claim_token is not None:
                raise SystemExit("claim-token is only valid with thread-id.")
            if require_uuid(args.workspace_id, "workspace-id") != workspace["id"]:
                raise SystemExit("This scan does not belong to the selected workspace.")
        else:
            thread_id = optional_text(args.thread_id, maximum=512)
            owning_thread_id = scan["continuation_thread_id"] or workspace["thread_id"]
            if thread_id is None or thread_id != owning_thread_id:
                raise SystemExit("This scan does not belong to the current Codex thread.")
            require_current_continuation(
                scan,
                args.claim_token,
                error_message="Scan context updates are owned by another continuation.",
            )
        timestamp = wb.now()
        connection.execute(
            "UPDATE scans SET user_context = ?, updated_at = ? WHERE id = ?",
            (context, timestamp, scan["id"]),
        )
        if args.workspace_id is not None:
            connection.execute(
                "UPDATE workspaces SET user_context = ?, updated_at = ? WHERE id = ?",
                (context, timestamp, workspace["id"]),
            )
        else:
            connection.execute(
                "UPDATE workspaces SET updated_at = ? WHERE id = ?",
                (timestamp, workspace["id"]),
            )
    return wb.scan_context(connection, scan_id)


def scan_progress_result(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> tuple[dict[str, Any], str]:
    independent_reviews = (
        independent_review_progress(
            connection, scan["id"], parent_running=scan["status"] == "running"
        )
        if scan["mode"] == "deep"
        else None
    )
    progress_result = {
        "candidates": {"reportable": scan["reportable_findings_count"]},
        "coverage": {
            "closedRows": scan["review_items_completed"],
            "filesTotal": scan["scope_file_count"],
            "worklistRows": scan["review_items_total"],
        },
        "phase": scan["phase"],
        "phaseProgress": {
            "completed": scan["phase_items_completed"],
            "total": scan["phase_items_total"],
            "unit": scan["phase_progress_unit"],
        },
        "preflightProgress": {
            "completed": scan["preflight_checks_completed"],
            "total": scan["preflight_checks_total"],
        },
        "preflightIssues": json.loads(scan["preflight_issues_json"]),
        "reviewPass": scan["deep_review_pass"],
        "status": "canceled" if scan["canceled_at"] else scan["status"],
        "updatedAt": scan["progress_updated_at"],
    }
    review_updated_at = ""
    if independent_reviews is not None:
        review_updated_at = str(independent_reviews.pop("updatedAt"))
        progress_result["independentReviews"] = independent_reviews
    return progress_result, review_updated_at


def model_progress(wb: Any, connection: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    scan = wb.scan_history.scan_with_progress(connection, scan_id)
    progress, _ = scan_progress_result(connection, scan)
    result = {"scanId": scan["id"], "progress": progress, "userContext": scan["user_context"]}
    if warnings := json.loads(scan["completion_warnings_json"]):
        result["warnings"] = warnings
    return result


def deep_preflight(scan: sqlite3.Row) -> bool:
    return scan["mode"] == "deep" and scan["phase"] == "preflight" and scan["canceled_at"] is None


def reported_scope_file_count(wb: Any, scan: sqlite3.Row) -> int | None:
    """Read the scoped helper's optional progress count, independently of scan evidence."""
    if (
        scan["mode"] != "standard"
        or scan["launch_kind"] not in (None, "scan")
        or not scan["recipe_json"]
    ):
        return None
    try:
        recipe = json.loads(scan["recipe_json"])
        target = recipe.get("target") if isinstance(recipe, dict) else None
        if not isinstance(target, dict) or target.get("kind") != "paths":
            return None
        repositories = (scan["target_path"], recipe.get("repository"))
        largest_count = 2**53 - 1  # The SDK reports this value as a JavaScript safe integer.
        maximum = (
            max(
                len(json.dumps({"scanId": scan["id"], "repository": repo, "count": largest_count}))
                for repo in repositories
                if isinstance(repo, str)
            )
            + 1
        )  # The helper includes a trailing newline.
        scan_dir = wb.require_canonical_scan_directory(Path(scan["scan_dir"]))
        descriptor = open_scan_local_file_descriptor(
            scan_dir, "scoped-source-input.receipt.json", "Scoped inventory count"
        )
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            return None
        report = json.loads(data)
        if (
            isinstance(report, dict)
            and report.get("scanId") == scan["id"]
            and isinstance(report.get("repository"), str)
            and report["repository"] in repositories
            and type(count := report.get("count")) is int
            and 0 <= count <= largest_count
        ):
            return count
    except (OSError, ValueError, RecursionError, SystemExit):
        # An unreadable optional report leaves the stored estimate in place so the scan can continue.
        pass
    return None


def refresh_scope_file_count(
    wb: Any, connection: sqlite3.Connection, scan_id: str, claim_token: str | None
) -> dict[str, int | None]:
    scan = wb.require_scan(connection, scan_id)
    if scan["status"] != "running":
        return {"scopeFileCount": None}
    ownership_error = "Scan updates are owned by another continuation."
    require_current_continuation(scan, claim_token, error_message=ownership_error)
    count = reported_scope_file_count(wb, scan)
    if count is None:
        return {"scopeFileCount": None}
    timeout = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
    try:
        connection.execute("PRAGMA busy_timeout = 0")
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            current = wb.require_scan(connection, scan_id)
            if current["status"] != "running" or current["scan_dir"] != scan["scan_dir"]:
                return {"scopeFileCount": None}
            require_current_continuation(current, claim_token, error_message=ownership_error)
            connection.execute(
                "UPDATE scan_progress SET scope_file_count = ?, updated_at = ? WHERE scan_id = ?",
                (count, wb.now(), scan_id),
            )
    except sqlite3.OperationalError as exc:
        if not wb.sqlite_busy(exc):
            raise
        return {"scopeFileCount": None, "retry": True}
    finally:
        connection.execute(f"PRAGMA busy_timeout = {timeout}")
    return {"scopeFileCount": count}


def update_progress(
    wb: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Record phase and review counters for a running scan and return its updated context.

    Check continuation and coordinator ownership where applicable. A new phase
    starts with fresh phase counters. A new Deep Scan review pass must start
    with zero completed items. Invalid progress raises SystemExit.
    """
    scan_id = require_uuid(args.scan_id, "scan-id")
    if args.refresh_scope_file_count:
        return refresh_scope_file_count(wb, connection, scan_id, args.claim_token)
    model = optional_text(args.model, maximum=200)
    reasoning_effort = optional_text(args.reasoning_effort, maximum=32)
    with connection:
        scan = None
        if args.model_update:
            connection.execute("BEGIN")
            scan = wb.require_scan(connection, scan_id)
            if not deep_preflight(scan):
                connection.rollback()
                scan = None
        if scan is None:
            # Reread under the writer lock before applying any progress change.
            wb.begin_immediate_with_retry(connection)
            scan = wb.require_scan(connection, scan_id)
        timestamp = wb.now()
        require_tokenless_scan_owner(connection, scan, getattr(args, "model_thread_id", None))
        if scan["status"] != "running":
            raise SystemExit("Only a running scan can update progress.")
        if args.model_update and deep_preflight(scan):
            if scan["handoff_claim_token"] is not None:
                require_current_continuation(
                    scan,
                    args.claim_token,
                    error_message="Scan updates are owned by another continuation.",
                )
            return {"scan": model_progress(wb, connection, scan_id), "deepPreflight": True}
        if scan["mode"] == "deep":
            coordinator = connection.execute(
                "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if coordinator is not None and (
                coordinator["status"] == "running" or args.coordinator_generation is not None
            ):
                require_current_coordinator(coordinator, args)
        elif args.coordinator_generation is not None:
            raise SystemExit("Coordinator leases apply only to Deep Scan progress.")
        require_current_continuation(
            scan,
            args.claim_token,
            error_message="Scan updates are owned by another continuation.",
        )
        if args.deep_review_pass is not None and scan["mode"] != "deep":
            raise SystemExit("Only Deep Scan can record a deep review pass.")
        progress = connection.execute(
            "SELECT * FROM scan_progress WHERE scan_id = ?", (scan["id"],)
        ).fetchone()
        if args.phase is not None and PHASES.index(args.phase) < PHASES.index(scan["phase"]):
            raise SystemExit("Scan progress cannot move to an earlier phase.")
        next_phase = args.phase or scan["phase"]
        phase_changed = next_phase != scan["phase"]
        phase_total = 0 if phase_changed else progress["phase_items_total"]
        phase_completed = 0 if phase_changed else progress["phase_items_completed"]
        phase_unit = None if phase_changed else progress["phase_progress_unit"]
        if args.phase_items_total is not None:
            phase_total = args.phase_items_total
        if args.phase_items_completed is not None:
            phase_completed = args.phase_items_completed
        if args.phase_progress_unit is not None:
            phase_unit = args.phase_progress_unit
        if phase_completed > phase_total:
            raise SystemExit("Completed phase items cannot exceed total phase items.")
        if phase_total > 0 and phase_unit is None:
            raise SystemExit("Phase progress with a nonzero total requires a progress unit.")
        if not phase_changed:
            if (
                args.phase_items_total is not None
                and args.phase_items_total < progress["phase_items_total"]
            ):
                raise SystemExit("Phase item total cannot decrease within a phase.")
            if (
                args.phase_items_completed is not None
                and args.phase_items_completed < progress["phase_items_completed"]
            ):
                raise SystemExit("Completed phase items cannot decrease within a phase.")
            if (
                args.phase_progress_unit is not None
                and progress["phase_progress_unit"] is not None
                and args.phase_progress_unit != progress["phase_progress_unit"]
            ):
                raise SystemExit("Phase progress unit cannot change within a phase.")
        updates: list[str] = [
            "phase_items_total = ?",
            "phase_items_completed = ?",
            "phase_progress_unit = ?",
        ]
        values: list[Any] = [phase_total, phase_completed, phase_unit]
        if next_phase == "preflight" and scan["mode"] != "deep":
            updates.extend(["preflight_checks_total = ?", "preflight_checks_completed = ?"])
            values.extend([phase_total, phase_completed])
        for column, value in (
            ("review_items_total", args.review_items_total),
            ("review_items_completed", args.review_items_completed),
            (
                "reportable_findings_count",
                reportable_count(scan["phase"], args.phase, args.reportable_findings_count),
            ),
            ("deep_review_pass", args.deep_review_pass),
        ):
            if value is not None:
                updates.append(f"{column} = ?")
                values.append(value)
        current_pass = progress["deep_review_pass"] or 0
        requested_pass = args.deep_review_pass or current_pass
        if requested_pass < current_pass:
            raise SystemExit("Deep Scan progress cannot move to an earlier review pass.")
        advancing_pass = requested_pass > current_pass
        if advancing_pass and args.review_items_completed != 0:
            raise SystemExit("A new Deep Scan review pass must start with zero completed items.")
        if not advancing_pass:
            if (
                args.review_items_total is not None
                and args.review_items_total < progress["review_items_total"]
            ):
                raise SystemExit("Review item total cannot decrease within a review pass.")
            if (
                args.review_items_completed is not None
                and args.review_items_completed < progress["review_items_completed"]
            ):
                raise SystemExit("Completed review items cannot decrease within a review pass.")
        total = args.review_items_total
        if total is None:
            total = progress["review_items_total"]
        completed = args.review_items_completed
        if completed is None:
            completed = progress["review_items_completed"]
        if completed > total:
            raise SystemExit("Completed review items cannot exceed total review items.")
        connection.execute(
            """
            UPDATE scans
            SET phase = COALESCE(?, phase), model = COALESCE(?, model),
                reasoning_effort = COALESCE(?, reasoning_effort), updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (args.phase, model, reasoning_effort, timestamp, scan["id"]),
        )
        connection.execute(
            f"UPDATE scan_progress SET {', '.join(updates)}, updated_at = ? WHERE scan_id = ?",
            (*values, timestamp, scan["id"]),
        )
        if args.model_update:
            return {"scan": model_progress(wb, connection, scan_id)}
    return wb.scan_context(connection, scan["id"])


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
