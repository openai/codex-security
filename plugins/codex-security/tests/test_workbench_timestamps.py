from __future__ import annotations

import importlib
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
