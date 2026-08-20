"""Progress transition helpers for the Codex Security workbench."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deep_scan_workbench import require_current_coordinator
from workbench.handoff import require_current_continuation
from workbench_constants import PHASES
from workbench_validation import optional_text, require_uuid, user_text

MAX_PREFLIGHT_ISSUES = 32


def _javascript_string_length(value: str) -> int:
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def _preflight_issue_text(value: Any, maximum: int, label: str) -> str:
    if not isinstance(value, str):
        raise SystemExit(f"Preflight issue {label} must be text.")
    normalized = value.strip()
    if not normalized or _javascript_string_length(normalized) > maximum:
        raise SystemExit(f"Preflight issue {label} must contain 1 to {maximum} characters.")
    return normalized


def preflight_issues_json(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit("Preflight issues must be valid JSON.") from exc
    if not isinstance(payload, list) or len(payload) > MAX_PREFLIGHT_ISSUES:
        raise SystemExit(
            f"Preflight issues must be an array of at most {MAX_PREFLIGHT_ISSUES} objects."
        )
    normalized: list[dict[str, str]] = []
    expected_keys = {"capability", "reason", "severity", "status"}
    for index, issue in enumerate(payload):
        label = f"{index + 1}"
        if not isinstance(issue, dict) or set(issue) != expected_keys:
            raise SystemExit(
                f"Preflight issue {label} must contain capability, reason, severity, and status."
            )
        severity = issue.get("severity")
        status = issue.get("status")
        if severity not in {"block", "warn"} or status not in {"fail", "unknown"}:
            raise SystemExit(f"Preflight issue {label} has an invalid severity or status.")
        normalized.append(
            {
                "capability": _preflight_issue_text(
                    issue.get("capability"), 128, f"{label} capability"
                ),
                "reason": _preflight_issue_text(issue.get("reason"), 1200, f"{label} reason"),
                "severity": severity,
                "status": status,
            }
        )
    return json.dumps(normalized, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def reportable_count(
    current_phase: str, requested_phase: str | None, count: int | None
) -> int | None:
    if count is None and requested_phase in PHASES[3:] and current_phase in PHASES[:3]:
        return 0
    return count


def update_context(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    require_workspace: Callable[[sqlite3.Connection, str], sqlite3.Row],
    scan_context: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    context = user_text(args.user_context)
    connection.execute("BEGIN IMMEDIATE")
    try:
        scan = require_scan(connection, scan_id)
        if scan["status"] != "running" or scan["canceled_at"] is not None:
            raise SystemExit("Only a running scan can update context.")
        workspace = require_workspace(connection, scan["workspace_id"])
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
        timestamp = now()
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
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, scan_id)


def update(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    require_workspace: Callable[[sqlite3.Connection, str], sqlite3.Row],
    scan_context: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    if args.command == "update-scan-context":
        return update_context(
            connection,
            args,
            now=now,
            require_scan=require_scan,
            require_workspace=require_workspace,
            scan_context=scan_context,
        )
    return update_progress(
        connection,
        args,
        now=now,
        require_scan=require_scan,
        scan_context=scan_context,
    )


def update_progress(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    scan_context: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    model = optional_text(args.model, maximum=200)
    reasoning_effort = optional_text(args.reasoning_effort, maximum=32)
    serialized_preflight_issues = preflight_issues_json(args.preflight_issues_json)
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = now()
        scan = require_scan(connection, scan_id)
        if scan["status"] != "running":
            raise SystemExit("Only a running scan can update progress.")
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
        if serialized_preflight_issues is not None:
            if scan["mode"] == "deep":
                raise SystemExit("Deep Scan preflight progress is owned by its coordinator.")
            if scan["phase"] != "preflight" or args.phase not in {None, "preflight"}:
                raise SystemExit("Preflight issues can only be updated during preflight.")
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
        updates: list[str] = []
        values: list[Any] = []
        if next_phase == "preflight" and scan["mode"] != "deep":
            updates.extend(["preflight_checks_total = ?", "preflight_checks_completed = ?"])
            values.extend([phase_total, phase_completed])
        for column, value in (
            ("preflight_issues_json", serialized_preflight_issues),
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
        updated = connection.execute(
            """
            UPDATE scans
            SET phase = COALESCE(?, phase), model = COALESCE(?, model),
                reasoning_effort = COALESCE(?, reasoning_effort), updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (args.phase, model, reasoning_effort, timestamp, scan["id"]),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can update progress.")
        if updates:
            connection.execute(
                f"UPDATE scan_progress SET {', '.join(updates)}, updated_at = ? WHERE scan_id = ?",
                (*values, timestamp, scan["id"]),
            )
        else:
            connection.execute(
                "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                (timestamp, scan["id"]),
            )
        connection.execute(
            """
            UPDATE scan_progress
            SET phase_items_total = ?, phase_items_completed = ?,
                phase_progress_unit = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (phase_total, phase_completed, phase_unit, timestamp, scan["id"]),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return scan_context(connection, scan["id"])


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
