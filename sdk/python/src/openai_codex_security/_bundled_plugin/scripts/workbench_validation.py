"""Shared validation helpers for Codex Security workbench commands."""

from __future__ import annotations

import argparse
import sqlite3
import uuid

RECOVERY_HANDOFF_TOKEN_PREFIX = "recovery_"


def require_uuid(value: str, label: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise SystemExit(f"{label} must be a UUID.") from exc


def optional_text(value: str | None, *, maximum: int | None = None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if maximum is not None and len(normalized) > maximum:
        raise SystemExit(f"Text value must be no longer than {maximum} characters.")
    return normalized or None


def require_occurrence(connection: sqlite3.Connection, occurrence_id: str) -> sqlite3.Row:
    occurrence_id = optional_text(occurrence_id, maximum=256)
    if occurrence_id is None:
        raise SystemExit("occurrence-id is required.")
    row = connection.execute(
        "SELECT * FROM finding_occurrences WHERE id = ?", (occurrence_id,)
    ).fetchone()
    if row is None:
        raise SystemExit("Codex Security finding occurrence not found.")
    return row


def require_handoff_claim_token(value: str) -> str:
    recovery_token = value.startswith(RECOVERY_HANDOFF_TOKEN_PREFIX)
    token = value.removeprefix(RECOVERY_HANDOFF_TOKEN_PREFIX) if recovery_token else value
    normalized = require_uuid(token, "claim-token")
    return f"{RECOVERY_HANDOFF_TOKEN_PREFIX}{normalized}" if recovery_token else normalized


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


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
