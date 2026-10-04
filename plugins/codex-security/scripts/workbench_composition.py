"""Persisted Deep Scan relationships and one response-local view of composition state."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from finalize_scan_contract import (
    ContractError,
    _read_scan_local_json,
)
from workbench.storage import scan_completion_lock

COMPOSITION_CHECKPOINT = "artifacts/deep-scan/checkpoint.json"


class _PassDirectory(TypedDict):
    directory: str


class CompositionPass(_PassDirectory, total=False):
    scanId: str
    failed: Literal[True]
    completed: Literal[True]


class _LegacyProgress(TypedDict):
    discoveryRuns: int
    coverage: dict[str, Any]


class LegacyComposition(_LegacyProgress, total=False):
    originThreadId: str | None
    cost: dict[str, Any]


class _CheckpointState(TypedDict):
    version: Literal[2]
    startedAt: str
    passes: list[CompositionPass]
    mergedScanIds: list[str]
    aggregate: dict[str, Any] | None
    noNewStreak: int
    consecutiveErrors: int


class PendingCompositionStop(TypedDict):
    reason: Literal["capped", "failed", "canceled"]
    message: str
    costs: dict[str, dict[str, Any]]


class CompositionCheckpoint(_CheckpointState, total=False):
    mergeFailures: int
    mergeStarted: bool
    costUnavailable: Literal[True]
    legacy: LegacyComposition
    pendingStop: PendingCompositionStop
    terminalReason: Literal["saturated", "capped", "failed", "canceled"]


@dataclass(frozen=True)
class CompositionView:
    checkpoint: CompositionCheckpoint | None
    children: tuple[sqlite3.Row, ...]
    execution_threads: tuple[str, ...]
    legacy_run: sqlite3.Row | None


def read_composition_checkpoint(scan: sqlite3.Row) -> CompositionCheckpoint | None:
    scan_dir = Path(scan["scan_dir"])
    with scan_completion_lock(scan["id"]):
        try:
            checkpoint = _read_scan_local_json(
                scan_dir, COMPOSITION_CHECKPOINT, "Deep Scan checkpoint"
            )
        except ContractError as exc:
            cause = exc.__cause__
            if isinstance(cause, FileNotFoundError) and cause.filename != str(scan_dir.absolute()):
                return None
            raise
    if checkpoint.get("version") != 2:
        raise ContractError("Unsupported Deep Scan checkpoint version.")
    # The host writes this versioned contract. Keep extension fields when reading it.
    return cast(CompositionCheckpoint, checkpoint)


def composition_children(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT * FROM scans WHERE parent_scan_id = ? AND parent_scan_role = 'deep_pass' "
        "ORDER BY started_at, id",
        (scan["id"],),
    ).fetchall()


def composition_execution_threads(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> tuple[str, ...]:
    return tuple(
        row["thread_id"]
        for row in connection.execute(
            "SELECT thread_id FROM scan_execution_threads WHERE scan_id = ? ORDER BY thread_id",
            (scan["id"],),
        )
    )


def load_composition(
    connection: sqlite3.Connection, scan: sqlite3.Row, *, checkpoint: bool = True
) -> CompositionView:
    if scan["mode"] != "deep":
        return CompositionView(None, (), composition_execution_threads(connection, scan), None)
    return CompositionView(
        read_composition_checkpoint(scan) if checkpoint else None,
        tuple(composition_children(connection, scan)),
        composition_execution_threads(connection, scan),
        connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
        ).fetchone(),
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
