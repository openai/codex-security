"""Report unreadable Deep Scan worker usage receipts in saved usage coverage."""

from datetime import timedelta
from pathlib import Path

from test_workbench_scan_usage import (
    _rollout,
    _start_scan,
    _state_graph,
    _token_event,
    _worker_usage_directory,
)
from workbench_test_support import fail_scan


def test_unreadable_worker_receipt_directory_is_not_reported_as_a_thread(
    tmp_path: Path,
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = _worker_usage_directory(fixture)
    directory.parent.mkdir(parents=True)
    linked = tmp_path / "linked-worker-usage"
    linked.mkdir()
    directory.symlink_to(linked, target_is_directory=True)
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 2)])},
        [],
    )
    measurement = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert measurement["coverage"] == "partial"
    assert measurement["coverageScope"] == ["thread:scan-parent", "worker-receipts"]
    assert measurement["missingThreadCount"] == 1
    assert measurement["warnings"] == [
        "worker_usage_receipt_unavailable",
        "worker_usage_unavailable",
    ]
