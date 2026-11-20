"""Account for interrupted and resumed turns of a Standard scan."""

from datetime import datetime
from pathlib import Path

import pytest
from test_workbench_scan_usage import (
    _event,
    _measure_rollout,
    _response_event,
    _rollout,
    _token_event,
)
from workbench_test_support import usage_counts as _counts


@pytest.mark.parametrize("cumulative_input", [30, 31, None])
def test_resumed_owner_reconciles_crash_and_failed_reconnect_only_with_matching_thread_usage(
    workbench_api, tmp_path: Path, cumulative_input: int | None
) -> None:
    at = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    thread_id = "scan-parent"
    resumed = _response_event(at, thread_id, "second", 10, 2, turn_id="resumed")
    if cumulative_input is None:
        del resumed["payload"]["thread_token_usage"]
    else:
        resumed["payload"]["thread_token_usage"] = _token_event(at, cumulative_input, 5)["payload"][
            "info"
        ]["total_token_usage"]
    events = [
        _event(at, "event_msg", {"type": "task_started", "turn_id": "crashed"}),
        _response_event(at, thread_id, "first", 20, 3, turn_id="crashed"),
        _event(at, "event_msg", {"type": "task_started", "turn_id": "reconnect"}),
        _event(
            at,
            "event_msg",
            {
                "type": "task_complete",
                "turn_id": "reconnect",
                "error": {"message": "Connection failed"},
            },
        ),
        _event(at, "event_msg", {"type": "task_started", "turn_id": "resumed"}),
        resumed,
        _event(at, "event_msg", {"type": "task_complete", "turn_id": "resumed"}),
    ]
    rollout = _rollout(tmp_path, thread_id, events)
    usage = _measure_rollout(workbench_api["scan_usage"], rollout, at, at, resume_owner=True)
    assert usage.tokens == _counts(30, 0, 5)
    assert usage.warnings == (
        set() if cumulative_input == 30 else {"token_record_missing", "turn_in_progress"}
    )
