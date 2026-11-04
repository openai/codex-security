from __future__ import annotations

import importlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.cross_platform


class Python310DateTime(datetime):
    @classmethod
    def fromisoformat(cls, value: str) -> datetime:
        if isinstance(value, str) and value.endswith(("Z", "z")):
            raise ValueError("Python 3.10 rejects Z-suffixed timestamps")
        return datetime.fromisoformat(value)

    @classmethod
    def now(cls, tz=None) -> datetime:
        return datetime(2026, 8, 15, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("fields", "active"),
    [
        ({"pending_action_claimed_at": "2026-08-15T11:58:00Z"}, False),
        ({"pending_action_claimed_at": "2026-08-15T11:58:00z"}, False),
        ({"pending_action_claimed_at": "2026-08-15T13:58:00+02:00"}, False),
        ({"pending_action_claimed_at": "2026-08-15T11:58:01Z"}, True),
        ({"pending_action_delivered_at": "2026-08-15T11:45:00Z"}, False),
        ({"pending_action_delivered_at": "2026-08-15T11:45:01Z"}, True),
        ({"pending_action_claim_token": None}, False),
        ({"pending_action_claimed_at": "not-a-timestamp"}, True),
        ({"pending_action_claimed_at": "2026-08-15T11:00:00"}, True),
    ],
)
def test_remediation_leases_on_python310(monkeypatch, fields, active) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    remediation = importlib.import_module("workbench_remediation")
    monkeypatch.setattr(remediation, "datetime", Python310DateTime)
    claim = {
        "pending_action_claim_token": "claim",
        "pending_action_claimed_at": "2026-08-15T11:30:00Z",
        "pending_action_delivered_at": None,
        **fields,
    }
    assert remediation.remediation_claim_is_active(claim) is active


@pytest.mark.parametrize(
    ("created_at", "timestamp", "reached"),
    [
        ("2026-08-15T00:00:00Z", "2026-08-15T00:59:59Z", False),
        ("2026-08-15T00:00:00Z", "2026-08-15T01:00:00Z", True),
        ("2026-08-15T00:00:00z", "2026-08-15T01:00:00z", True),
        ("2026-08-15T02:00:00+02:00", "2026-08-15T01:00:00Z", True),
    ],
)
def test_deep_scan_deadlines_on_python310(monkeypatch, created_at, timestamp, reached) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    deep = importlib.import_module("deep_scan_workbench")
    monkeypatch.setattr(deep, "datetime", Python310DateTime)
    monkeypatch.setattr(deep, "_dependencies", SimpleNamespace(now=lambda: timestamp))
    assert (
        deep.deep_scan_deadline_reached({"created_at": created_at, "max_time_hours": 1}) is reached
    )


@pytest.mark.parametrize(
    ("generation", "updated_at", "heartbeat", "timestamp", "live"),
    [
        (1, "00:09:59Z", None, "00:10:00Z", True),
        (1, "00:08:00Z", None, "00:10:00Z", False),
        (2, "00:09:59Z", None, "00:10:00Z", True),
        (2, "00:09:30Z", None, "00:10:00Z", False),
        (2, "00:09:00Z", (2, "00:09:45Z"), "00:10:00Z", True),
        (2, "00:09:00Z", (1, "00:09:45Z"), "00:10:00Z", False),
        (2, "00:09:00Z", (2, None), "00:10:00Z", False),
        (2, "11:00:00Z", (2, "11:59:45z"), "12:00:00Z", True),
        (2, "11:00:00Z", (2, "11:59:45z"), "12:00:15Z", False),
    ],
)
def test_deep_scan_coordinator_leases_on_python310(
    monkeypatch, tmp_path: Path, generation, updated_at, heartbeat, timestamp, live
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    deep = importlib.import_module("deep_scan_workbench")
    monkeypatch.setattr(deep, "datetime", Python310DateTime)
    run = {
        "scan_id": "scan",
        "coordinator_generation": generation,
        "updated_at": f"2026-08-15T{updated_at}",
    }
    if heartbeat is not None:
        heartbeat_generation, heartbeat_time = heartbeat
        heartbeat_path = (
            tmp_path / f"artifacts/deep_discovery/coordinator-heartbeat-{generation}.json"
        )
        heartbeat_path.parent.mkdir(parents=True)
        heartbeat_path.write_text(
            json.dumps(
                {
                    "coordinatorGeneration": heartbeat_generation,
                    "updatedAt": None if heartbeat_time is None else f"2026-08-15T{heartbeat_time}",
                }
            ),
            encoding="utf-8",
        )
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE deep_scan_workers (scan_id TEXT, status TEXT)")
        if generation == 1:
            connection.execute("INSERT INTO deep_scan_workers VALUES ('scan', 'running')")
        assert (
            deep.coordinator_lease_is_live(
                connection, run, {"scan_dir": str(tmp_path)}, f"2026-08-15T{timestamp}"
            )
            is live
        )
