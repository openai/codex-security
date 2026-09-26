"""Scan handoff state transitions for the Codex Security workbench."""

from __future__ import annotations

import argparse
import sqlite3
from collections.abc import Callable
from typing import Any

from workbench_validation import optional_text, require_uuid

RECOVERY_HANDOFF_TOKEN_PREFIX = "recovery_"


def require_handoff_claim_token(value: str) -> str:
    recovery_token = value.startswith(RECOVERY_HANDOFF_TOKEN_PREFIX)
    token = value.removeprefix(RECOVERY_HANDOFF_TOKEN_PREFIX) if recovery_token else value
    normalized = require_uuid(token, "claim-token")
    return f"{RECOVERY_HANDOFF_TOKEN_PREFIX}{normalized}" if recovery_token else normalized


def require_current_continuation(
    scan: sqlite3.Row,
    claim_token: str | None,
    *,
    error_message: str,
) -> None:
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
    if owning_thread_id != requesting_thread_id and not claim_token.startswith(
        RECOVERY_HANDOFF_TOKEN_PREFIX
    ):
        raise SystemExit(
            "A scan handoff can only be marked delivered from its owning Codex thread."
        )


def claim_handoff_delivery(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    stale_claim_before: Callable[[], str],
    workspace_state: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    timestamp = now()
    with connection:
        scan = require_scan(connection, scan_id)
        if scan["handoff_status"] != "pending" or scan["handoff_claim_token"] == claim_token:
            return workspace_state(connection, scan["workspace_id"])
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
                stale_claim_before(),
            ),
        )
        if updated.rowcount != 1:
            return workspace_state(connection, scan["workspace_id"])
    return workspace_state(connection, scan["workspace_id"])


def release_handoff_delivery(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    workspace_state: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    timestamp = now()
    with connection:
        scan = require_scan(connection, scan_id)
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
    return workspace_state(connection, scan["workspace_id"])


def attach_scan_continuation_thread(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    workspace_state: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    thread_id = optional_text(args.thread_id, maximum=512)
    if thread_id is None:
        raise SystemExit("Codex Security continuation thread ID is required.")
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = now()
        scan = require_scan(connection, scan_id)
        if scan["handoff_claim_token"] != claim_token:
            raise SystemExit("Codex Security continuation thread claim token does not match.")
        if scan["continuation_thread_id"] is not None:
            if scan["continuation_thread_id"] != thread_id:
                raise SystemExit(
                    "Codex Security scan continuation is owned by another continuation."
                )
            connection.commit()
            return workspace_state(connection, scan["workspace_id"])
        updated = connection.execute(
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
        if updated.rowcount != 1:
            raise SystemExit("Codex Security continuation thread could not be attached.")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return workspace_state(connection, scan["workspace_id"])


def mark_handoff_delivered(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    require_workspace: Callable[[sqlite3.Connection, str], sqlite3.Row],
    workspace_state: Callable[[sqlite3.Connection, str], dict[str, Any]],
) -> dict[str, Any]:
    scan_id = require_uuid(args.scan_id, "scan-id")
    claim_token = require_handoff_claim_token(args.claim_token)
    thread_id = optional_text(args.thread_id, maximum=512)
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = now()
        scan = require_scan(connection, scan_id)
        if thread_id is not None:
            workspace = require_workspace(connection, scan["workspace_id"])
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
            return workspace_state(connection, scan["workspace_id"])
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
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return workspace_state(connection, scan["workspace_id"])
