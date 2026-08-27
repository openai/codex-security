"""Durable remediation state transitions for the Codex Security workbench."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_constants import CLAIM_LEASE_SECONDS, DELIVERED_ACTION_LEASE_SECONDS
from workbench_validation import require_occurrence, require_uuid

COMMANDS = {
    "request-finding-remediation",
    "request-finding-remediation-action",
    "claim-finding-remediation-resend",
    "mark-finding-remediation-delivered",
    "release-finding-remediation-claim",
    "cancel-finding-remediation-request",
    "set-finding-remediation",
}
SCAN_STATUS_ERROR = "Remediation is available only for successfully completed scans."


def require_available(connection: sqlite3.Connection, args: Any, require_scan: Any) -> None:
    if args.command not in COMMANDS:
        return
    occurrence = require_occurrence(connection, args.occurrence_id)
    if require_scan(connection, occurrence["scan_id"])["status"] != "complete":
        raise SystemExit(SCAN_STATUS_ERROR)


def remediation_claim_is_active(remediation: sqlite3.Row) -> bool:
    if remediation["pending_action_claim_token"] is None:
        return False
    delivered_at = remediation["pending_action_delivered_at"]
    claimed_at = delivered_at or remediation["pending_action_claimed_at"]
    if not isinstance(claimed_at, str):
        return True
    try:
        if claimed_at.endswith(("Z", "z")):
            claimed_at = claimed_at[:-1] + "+00:00"
        parsed = datetime.fromisoformat(claimed_at)
        if parsed.tzinfo is None:
            return True
    except ValueError:
        return True
    lease_seconds = DELIVERED_ACTION_LEASE_SECONDS if delivered_at else CLAIM_LEASE_SECONDS
    return parsed > datetime.now(timezone.utc) - timedelta(seconds=lease_seconds)


def register_cancel_finding_remediation_request(subparsers: Any) -> None:
    parser = subparsers.add_parser("cancel-finding-remediation-request")
    parser.add_argument("--occurrence-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--action-token", required=True)


def cancel_finding_remediation_request(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> str:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    connection.execute("BEGIN IMMEDIATE")
    try:
        occurrence = require_occurrence(connection, args.occurrence_id)
        current = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current is None:
            connection.commit()
            return str(occurrence["scan_id"])
        if current["occurrence_id"] != occurrence["id"]:
            raise SystemExit("This remediation request belongs to a different finding.")
        if current["pending_action"] is None:
            connection.commit()
            return str(occurrence["scan_id"])
        if current["state"] == "failed" and current["pending_action_claim_token"] is None:
            connection.commit()
            return str(occurrence["scan_id"])
        if current["pending_action_claim_token"] != action_token:
            raise SystemExit("This remediation host request is owned by a different action token.")
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if current["state"] == "failed":
            connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
                    pending_action_delivered_at = NULL, updated_at = ?
                WHERE request_id = ? AND pending_action_claim_token = ?
                """,
                (timestamp, request_id, action_token),
            )
        elif current["pending_action"] == "generate":
            _cancel_generation(
                connection, occurrence["id"], request_id, timestamp, current["state"]
            )
            connection.execute(
                "UPDATE scans SET updated_at = ? WHERE id = ?",
                (timestamp, occurrence["scan_id"]),
            )
        else:
            connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET pending_action = NULL, pending_action_claimed_at = NULL,
                    pending_action_claim_token = NULL, pending_action_delivered_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE request_id = ? AND pending_action_claim_token = ?
                """,
                (timestamp, request_id, action_token),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    return str(occurrence["scan_id"])


def _cancel_generation(
    connection: sqlite3.Connection,
    occurrence_id: str,
    request_id: str,
    timestamp: str,
    state: str,
) -> None:
    if state != "requested":
        raise SystemExit("Only a requested patch generation can be canceled.")
    connection.execute(
        "DELETE FROM finding_remediation_attempts WHERE request_id = ?", (request_id,)
    )
    previous = connection.execute(
        """
        SELECT * FROM finding_remediation_attempts
        WHERE occurrence_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1
        """,
        (occurrence_id,),
    ).fetchone()
    if previous is None or previous["state"] != "superseded":
        return
    restored_state = "applied" if previous["applied_content_digest"] is not None else "generated"
    connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET state = ?, version = version + 1, updated_at = ?
        WHERE request_id = ? AND state = 'superseded'
        """,
        (restored_state, timestamp, previous["request_id"]),
    )


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
