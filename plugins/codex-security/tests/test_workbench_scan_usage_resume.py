"""Account for interrupted and resumed turns of a Standard scan."""

from pathlib import Path

import pytest
from test_workbench_scan_usage import (
    _event,
    _response_event,
    _start_scan,
    _token_event,
)


@pytest.mark.parametrize("cumulative_input", [30, 31, None])
def test_resumed_owner_reconciles_crash_and_failed_reconnect_only_with_matching_thread_usage(
    tmp_path: Path, cumulative_input: int | None
) -> None:
    fixture = _start_scan(tmp_path, dedicated=True)
    at = fixture.started_at
    thread_id = "scan-parent"
    fixture.command("set-scan-thread", "--thread-id", thread_id)
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
    fixture.write_parent_rollout(events)
    usage = fixture.command("read-scan-usage", "--thread-id", thread_id)
    assert (usage["inputTokens"], usage["outputTokens"], usage["totalTokens"]) == (30, 5, 35)
    assert usage["coverage"] == ("complete" if cumulative_input == 30 else "partial")
    assert set(usage.get("warnings", [])) == (
        set() if cumulative_input == 30 else {"token_record_missing", "turn_in_progress"}
    )
