"""Persisted Deep Scan relationships and one response-local view of composition state."""

from __future__ import annotations

import argparse
import hashlib
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


class _CheckpointState(TypedDict):
    version: Literal[3]
    startedAt: str
    passes: list[CompositionPass]
    mergedScanIds: list[str]
    aggregate: dict[str, Any] | None
    noNewStreak: int
    consecutiveErrors: int


class CompositionCheckpoint(_CheckpointState, total=False):
    mergeFailures: int
    mergeStarted: bool
    costUnavailable: Literal[True]
    aggregatePath: str | None
    terminalReason: Literal["saturated", "capped", "failed", "canceled"]


@dataclass(frozen=True)
class CompositionView:
    checkpoint: CompositionCheckpoint | None
    children: tuple[sqlite3.Row, ...]
    execution_threads: tuple[str, ...]
    legacy_run: sqlite3.Row | None
    saved_review_count: int = 0
    saved_review_maximum: int | None = None


def read_composition_checkpoint(
    scan: sqlite3.Row, *, load_aggregate: bool = True
) -> CompositionCheckpoint | None:
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
    version = checkpoint.get("version")
    if version not in {2, 3} or (load_aggregate and version != 3):
        raise ContractError(
            "This Deep Scan checkpoint uses an unsupported format. Recover unfinished work "
            "with its original version, or start a new scan."
        )
    if load_aggregate:
        path = checkpoint.get("aggregatePath")
        aggregate = _read_scan_local_json(scan_dir, path, "Deep Scan aggregate") if path else None
        if aggregate is not None:
            for ids, field, directory in (
                ("sourceFindingIds", "sourceFindings", "sources"),
                ("revisionIds", "revisions", "revisions"),
            ):
                keys = aggregate.pop(ids, None)
                if keys is not None:
                    aggregate[field] = {
                        key: _read_scan_local_json(
                            scan_dir,
                            f"artifacts/deep-scan/{directory}/{hashlib.sha256(key.encode()).hexdigest() if directory == 'sources' else key}.json",
                            "Deep Scan retained finding",
                        )
                        for key in keys
                    }
        checkpoint["aggregate"] = aggregate
    else:
        checkpoint.pop("aggregate", None)
        checkpoint.pop("legacy", None)
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
    saved = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?",
        (scan["id"],),
    ).fetchone()
    return CompositionView(
        read_composition_checkpoint(scan, load_aggregate=False) if checkpoint else None,
        tuple(composition_children(connection, scan)),
        composition_execution_threads(connection, scan),
        saved,
        saved["completion_sequence"] if saved is not None else 0,
        saved["max_discovery_runs"] if saved is not None else None,
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
