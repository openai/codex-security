"""Scan handoff state transitions for the Codex Security workbench."""

from __future__ import annotations

import argparse
import sqlite3
from typing import Any

from workbench_validation import optional_text, require_uuid

RECOVERY_HANDOFF_TOKEN_PREFIX = "recovery_"


def require_handoff_claim_token(value: str) -> str:
    """Normalize the claim UUID, retaining the prefix that marks a recovery handoff."""
    recovery_token = value.startswith(RECOVERY_HANDOFF_TOKEN_PREFIX)
    token = value.removeprefix(RECOVERY_HANDOFF_TOKEN_PREFIX) if recovery_token else value
    normalized = require_uuid(token, "claim-token")
    return f"{RECOVERY_HANDOFF_TOKEN_PREFIX}{normalized}" if recovery_token else normalized


def require_tokenless_scan_owner(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    model_thread_id: str | None,
) -> None:
    """Check model callers against a recorded owner. Trusted local callers omit model_thread_id."""
    if model_thread_id is None or scan["handoff_claim_token"] is not None:
        return
    if scan["handoff_status"] == "pending":
        raise SystemExit(
            "This Codex Security scan handoff has not been delivered. "
            "Claim the pending Codex Security scan handoff before continuing."
        )
    owner = scan["continuation_thread_id"] or scan["deep_scan_owner_thread_id"]
    if owner is None:
        owner = connection.execute(
            "SELECT thread_id FROM workspaces WHERE id = ?", (scan["workspace_id"],)
        ).fetchone()[0]
    if owner is None:
        completed_import = scan["launch_kind"] == "import" and scan["status"] == "complete"
        if not completed_import:
            raise SystemExit("This scan is awaiting its owning Codex thread.")
    elif owner != model_thread_id:
        raise SystemExit("This scan requires its owning Codex thread.")


def require_current_continuation(
    scan: sqlite3.Row,
    claim_token: str | None,
    *,
    error_message: str,
) -> None:
    """Require the current claim token, allowing a tokenless continuation for legacy delivered scans."""
    if (
        scan["handoff_status"] == "delivered"
        and scan["handoff_claim_token"] is None
        and claim_token is None
    ):
        return
    if claim_token is None:
        raise SystemExit(error_message)
    if scan["handoff_claim_token"] != require_handoff_claim_token(claim_token):
        raise SystemExit(error_message)


def validate_handoff_delivery_thread(
    owning_thread_id: str | None,
    requesting_thread_id: str,
    claim_token: str,
) -> None:
    """Require the owning thread for delivery unless the caller presents a recovery claim token."""
    if owning_thread_id != requesting_thread_id and not claim_token.startswith(
        RECOVERY_HANDOFF_TOKEN_PREFIX
    ):
        raise SystemExit(
            "A scan handoff can only be marked delivered from its owning Codex thread."
        )


def claim_handoff_delivery(
    wb: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Claim a pending handoff and return the current workspace state.

    The first claim wins. When take_over_stale is requested, replacing an expired
    claim also clears the continuation and deep scan owner. Retrying the same claim
    or losing a competing claim returns the workspace state without changing ownership.
    """
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    timestamp = wb.now()
    with connection:
        scan = wb.require_scan(connection, scan_id)
        if scan["handoff_status"] != "pending" or scan["handoff_claim_token"] == claim_token:
            return wb.workspace_state(connection, scan["workspace_id"])
        updated = connection.execute(
            """
            UPDATE scans
            SET handoff_claimed_at = ?, handoff_claim_token = ?,
                continuation_thread_id = CASE
                    WHEN handoff_claim_token IS NULL THEN continuation_thread_id
                    ELSE NULL
                END,
                deep_scan_owner_thread_id = CASE
                    WHEN handoff_claim_token IS NULL THEN deep_scan_owner_thread_id
                    ELSE NULL
                END,
                updated_at = ?
            WHERE id = ? AND handoff_status = 'pending'
                AND (
                    handoff_claim_token IS NULL
                    OR (
                        ? = 1
                        AND (handoff_claimed_at IS NULL OR handoff_claimed_at <= ?)
                    )
                )
            """,
            (
                timestamp,
                claim_token,
                timestamp,
                scan["id"],
                int(args.take_over_stale),
                wb.stale_claim_before(),
            ),
        )
        if updated.rowcount != 1:
            return wb.workspace_state(connection, scan["workspace_id"])
    return wb.workspace_state(connection, scan["workspace_id"])


def release_handoff_delivery(
    wb: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Release a matching pending claim, detach its continuation, and return the workspace state."""
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    timestamp = wb.now()
    with connection:
        scan = wb.require_scan(connection, scan_id)
        connection.execute(
            """
            UPDATE scans
            SET handoff_claimed_at = NULL, handoff_claim_token = NULL,
                continuation_thread_id = NULL, deep_scan_owner_thread_id = NULL,
                updated_at = ?
            WHERE id = ? AND handoff_status = 'pending'
                AND handoff_claim_token = ?
            """,
            (timestamp, scan["id"], claim_token),
        )
    return wb.workspace_state(connection, scan["workspace_id"])


def attach_scan_continuation_thread(
    wb: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Bind the claimed scan to a continuation and return its workspace state.

    An immediate transaction serializes ownership changes. Reattaching the same
    thread is idempotent. A different thread or mismatched claim token raises SystemExit.
    """
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    thread_id = optional_text(args.thread_id, maximum=512)
    if thread_id is None:
        raise SystemExit("Codex Security continuation thread ID is required.")
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = wb.now()
        scan = wb.require_scan(connection, scan_id)
        if scan["handoff_claim_token"] != claim_token:
            raise SystemExit("Codex Security continuation thread claim token does not match.")
        if scan["continuation_thread_id"] is not None:
            if scan["continuation_thread_id"] != thread_id:
                raise SystemExit(
                    "Codex Security scan continuation is owned by another continuation."
                )
            connection.commit()
            return wb.workspace_state(connection, scan["workspace_id"])
        connection.execute(
            """
            UPDATE scans
            SET continuation_thread_id = ?,
                deep_scan_owner_thread_id = CASE
                    WHEN mode = 'deep' THEN ? ELSE deep_scan_owner_thread_id
                END,
                updated_at = ?
            WHERE id = ? AND continuation_thread_id IS NULL
                AND handoff_claim_token = ?
            """,
            (thread_id, thread_id, timestamp, scan["id"], claim_token),
        )
    return wb.workspace_state(connection, scan["workspace_id"])


def mark_handoff_delivered(
    wb: Any,
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Record delivery for the pending claim and return the workspace state.

    For standard scans this resets preflight progress. The same claim can confirm
    delivery again. A conflicting claim or invalid requesting thread raises SystemExit.
    """
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    thread_id = optional_text(args.thread_id, maximum=512)
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = wb.now()
        scan = wb.require_scan(connection, scan_id)
        if thread_id is not None:
            workspace = wb.require_workspace(connection, scan["workspace_id"])
            validate_handoff_delivery_thread(
                scan["continuation_thread_id"] or workspace["thread_id"],
                thread_id,
                claim_token,
            )
        if scan["handoff_status"] == "delivered":
            if scan["handoff_claim_token"] != claim_token:
                raise SystemExit(
                    "Codex Security handoff delivery is owned by another continuation."
                )
            connection.commit()
            return wb.workspace_state(connection, scan["workspace_id"])
        updated = connection.execute(
            """
            UPDATE scans
            SET handoff_status = 'delivered', handoff_claimed_at = NULL,
                updated_at = ?
            WHERE id = ? AND handoff_status = 'pending'
                AND handoff_claim_token = ?
            """,
            (timestamp, scan["id"], claim_token),
        )
        if updated.rowcount != 1:
            raise SystemExit("Codex Security handoff delivery could not be recorded.")
        if scan["mode"] != "deep":
            connection.execute(
                """
                UPDATE scan_progress
                SET phase_items_total = 0, phase_items_completed = 0,
                    phase_progress_unit = 'checks',
                    preflight_checks_total = 0, preflight_checks_completed = 0,
                    updated_at = ?
                WHERE scan_id = ?
                """,
                (timestamp, scan["id"]),
            )
    return wb.workspace_state(connection, scan["workspace_id"])
