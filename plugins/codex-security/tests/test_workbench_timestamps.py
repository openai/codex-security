from __future__ import annotations

import importlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest


class Python310DateTime(datetime):
    @classmethod
    def fromisoformat(cls, value: str) -> datetime:
        if value.endswith(("Z", "z")):
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


def test_deep_scan_deadline_and_heartbeat_on_python310(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    deep = importlib.import_module("deep_scan_workbench")
    monkeypatch.setattr(deep, "datetime", Python310DateTime)
    monkeypatch.setattr(deep, "now", lambda: "2026-08-15T12:00:00Z")
    assert deep.deep_scan_deadline_reached(
        {"created_at": "2026-08-15T11:00:00z", "max_time_hours": 1}
    )
    heartbeat = tmp_path / "artifacts/deep_discovery/coordinator-heartbeat-2.json"
    heartbeat.parent.mkdir(parents=True)
    heartbeat.write_text(
        json.dumps({"coordinatorGeneration": 2, "updatedAt": "2026-08-15T11:59:45z"})
    )
    run = {"coordinator_generation": 2, "updated_at": "2026-08-15T11:00:00Z"}
    with sqlite3.connect(":memory:") as connection:
        assert deep.coordinator_lease_is_live(
            connection, run, {"scan_dir": str(tmp_path)}, "2026-08-15T12:00:00Z"
        )
        assert not deep.coordinator_lease_is_live(
            connection, run, {"scan_dir": str(tmp_path)}, "2026-08-15T12:00:15Z"
        )
