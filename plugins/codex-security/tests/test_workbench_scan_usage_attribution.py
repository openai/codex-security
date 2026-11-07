"""Exercise native receipt attribution, saved owner boundaries, and worker recovery."""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_workbench_scan_usage import (
    _allowance_event,
    _complete_scan,
    _counts,
    _event,
    _measure_rollout,
    _response_event,
    _rollout,
    _start_scan,
    _state_graph,
    _token_event,
)
from test_workbench_scan_usage import (
    scan_usage as scan_usage,
)
from workbench_test_support import fail_scan, run_workbench, upsert_deep_worker


@pytest.mark.parametrize("complete_first", [False, True])
@pytest.mark.parametrize("tail", ["complete", "partial", "invalid"])
def test_rollout_copies_prefer_parsed_cache_and_model_corrections(
    tmp_path: Path, workbench_api, complete_first: bool, tail: str
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    prefix = _rollout(
        tmp_path,
        "worker",
        [
            _event(start, "turn_context", {"turn_id": "scan-turn", "model": "model-before"}),
            _token_event(start, 1_000_000, 0),
        ],
    )
    complete = tmp_path / "complete.jsonl"
    tokens = dict(
        input_tokens=1_000_000,
        cached_input_tokens=900_000,
        cache_write_input_tokens=0,
        output_tokens=0,
        total_tokens=1_000_000,
    )
    receipt = _event(
        start,
        "token_usage_record",
        dict(
            response_id="response-one",
            thread_id="worker",
            turn_id="scan-turn",
            model="model-receipt",
            usage=tokens,
            thread_token_usage=tokens,
        ),
    )
    complete.write_bytes(prefix.read_bytes() + json.dumps(receipt).encode() + b"\n")
    if tail == "partial":
        with complete.open("ab") as stream:
            stream.write(b'{"type":"event_msg"')
    elif tail == "invalid":
        with complete.open("ab") as stream:
            stream.write(b"invalid-record\n")
    paths = [prefix, complete] if not complete_first else [complete, prefix]
    models = {}
    measurement = reader._read_rollout_copies_usage(
        [reader.RolloutSession("worker", None, path) for path in paths],
        started_at=start,
        completed_at=None,
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    expected = _counts(1_000_000, 900_000, 0)
    assert counts == expected
    assert models == {"model-receipt": expected}
    assert warnings == (
        set()
        if tail == "complete"
        else {"rollout_record_incomplete" if tail == "partial" else "rollout_record_invalid"}
    )


def test_rollout_usage_reconciles_stale_cumulative_events_and_models(
    tmp_path: Path, workbench_api
) -> None:
    usage_reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    events = [
        _event(start, "turn_context", {"turn_id": "own-turn", "model": "gpt-5.6-sol"}),
        _token_event(start, 100, 10),
        _token_event(start, 60, 6),
        _event(start, "turn_context", {"turn_id": "own-turn", "model": "gpt-6-astra"}),
        _token_event(start, 200, 20),
    ]
    rollout = _rollout(tmp_path, "worker", events)
    measurement = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("worker", None, rollout),
        started_at=start,
        completed_at=None,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(200, 0, 20)
    assert warnings == {"token_counter_regressed"}
    models = {}
    measurement = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("worker", None, rollout),
        started_at=start,
        completed_at=None,
        model_usage=models,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(200, 0, 20)
    assert warnings == {"token_counter_regressed"}
    assert models == {"gpt-5.6-sol": _counts(100, 0, 10), "gpt-6-astra": _counts(100, 0, 10)}


@pytest.mark.parametrize("prior_receipt", [False, True])
def test_shared_parent_usage_requires_original_turn_and_scan_interval(
    tmp_path: Path, workbench_api, prior_receipt: bool
) -> None:
    usage_reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    end = start + timedelta(seconds=5)
    events = [
        _event(
            start - timedelta(seconds=1),
            "turn_context",
            {"turn_id": "prior", "model": "gpt-5.6-sol"},
        ),
        _token_event(start - timedelta(seconds=1), 100, 10),
        _event(start, "turn_context", {"turn_id": "scan-turn", "model": "gpt-6-astra"}),
        _token_event(start, 110, 12),
        _event(start, "turn_context", {"turn_id": "unrelated", "model": "gpt-5.6-sol"}),
        _token_event(start, 910, 92),
        _event(
            end + timedelta(seconds=1),
            "turn_context",
            {"turn_id": "scan-turn", "model": "gpt-6-astra"},
        ),
        _token_event(end + timedelta(seconds=1), 1000, 100),
    ]
    if prior_receipt:
        events.insert(
            0,
            _response_event(
                start - timedelta(seconds=1),
                "parent",
                "prior-response",
                100,
                10,
                turn_id="prior",
            ),
        )
    models = {}
    measurement = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=end,
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(10, 0, 2)
    assert warnings == set()
    assert models == {"gpt-6-astra": _counts(10, 0, 2)}


@pytest.mark.parametrize(
    "counter_info,receipt_state,expected_warning",
    [
        (None, "complete", None),
        ({}, "complete", "token_record_invalid"),
        ({"total_token_usage": {"input_tokens": -1}}, "complete", "token_record_invalid"),
        (None, "missing-response", "token_receipts_incomplete"),
        (None, "incomplete-line", "rollout_record_incomplete"),
        (None, "invalid-timestamp", "token_record_invalid"),
    ],
    ids=[
        "null-counter",
        "empty-info",
        "malformed-usage",
        "missing-response",
        "incomplete-line",
        "invalid-timestamp",
    ],
)
def test_completion_handles_no_usage_counter_without_hiding_incomplete_receipts(
    tmp_path: Path, counter_info: Any, receipt_state: str, expected_warning: str | None
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    tokens = dict(
        input_tokens=100,
        cached_input_tokens=20,
        cache_write_input_tokens=0,
        output_tokens=10,
        total_tokens=110,
    )
    response = _event(
        counted,
        "token_usage_record",
        dict(
            response_id="response-one",
            thread_id="scan-parent",
            model="gpt-5.6-sol",
            usage=tokens,
            thread_token_usage=(
                {**tokens, "input_tokens": 150, "total_tokens": 160}
                if receipt_state == "missing-response"
                else tokens
            ),
        ),
    )
    counter = _event(
        counted,
        "event_msg",
        {"type": "token_count", "info": counter_info, "rate_limits": None},
    )
    events = [counter, response, counter]
    if receipt_state == "invalid-timestamp":
        events.append(
            {
                **response,
                "timestamp": None,
                "payload": {**response["payload"], "response_id": "response-two"},
            }
        )
    parent = _rollout(tmp_path, "scan-parent", events)
    if receipt_state == "incomplete-line":
        with parent.open("a") as stream:
            stream.write('{"type":"token_usage_record"')
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["totalTokens"] == 110
    assert usage["modelUsage"] == [{"model": "gpt-5.6-sol", **_counts(100, 20, 10)}]
    assert usage["coverage"] == ("partial" if expected_warning else "complete")
    assert usage.get("warnings", []) == ([expected_warning] if expected_warning else [])


@pytest.mark.parametrize("counters", [False, True])
def test_response_receipts_count_compaction_once_across_resets(
    tmp_path: Path, workbench_api, counters: bool
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def usage(input_tokens, cached, output):
        return dict(
            input_tokens=input_tokens,
            cached_input_tokens=cached,
            cache_write_input_tokens=0,
            output_tokens=output,
            reasoning_output_tokens=0,
            total_tokens=input_tokens + output,
        )

    def receipt(response, count, cumulative, model="gpt-5.6-sol", turn="scan-turn", second=1):
        return _event(
            start + timedelta(seconds=second),
            "token_usage_record",
            dict(
                response_id=response,
                thread_id="parent",
                turn_id=turn,
                model=model,
                usage=count,
                thread_token_usage=cumulative,
            ),
        )

    first = receipt("first", usage(100, 80, 10), usage(100, 80, 10))
    compact = receipt("compaction", usage(50, 40, 5), usage(150, 120, 15), model="gpt-6-astra")
    second = receipt("second", usage(120, 90, 12), usage(120, 90, 12))
    events = [
        first,
        *([_token_event(start + timedelta(seconds=1), 100, 10)] if counters else []),
        compact,
        _event(start + timedelta(seconds=1), "compacted", {"message": "Synthetic summary"}),
        compact,
        second,
        *([_token_event(start + timedelta(seconds=1), 220, 22)] if counters else []),
        first,
        _event(
            start + timedelta(seconds=1),
            "event_msg",
            {"type": "task_complete", "turn_id": "scan-turn"},
        ),
        receipt("other", usage(900, 0, 0), usage(900, 0, 0), turn="other-turn"),
        receipt("post", usage(800, 0, 0), usage(1700, 0, 0), second=11),
    ]
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=start + timedelta(seconds=10),
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(270, 210, 27)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(220, 170, 22), "gpt-6-astra": _counts(50, 40, 5)}


def test_delayed_response_receipt_resolves_missing_cumulative_usage(
    tmp_path: Path, workbench_api
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response, tokens, cumulative):
        def usage(value):
            return dict(
                input_tokens=value, cache_write_input_tokens=0, output_tokens=0, total_tokens=value
            )

        return _event(
            start,
            "token_usage_record",
            dict(
                response_id=response,
                thread_id="parent",
                model="gpt-5.6-sol",
                usage=usage(tokens),
                thread_token_usage=usage(cumulative),
            ),
        )

    rollout = _rollout(tmp_path, "parent", [receipt("first", 100, 100), receipt("third", 50, 180)])
    session = reader.RolloutSession("parent", None, rollout)
    measurement = reader._read_rollout_usage(session, started_at=start, completed_at=None)
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(150, 0, 0)
    assert warnings == {"token_receipts_incomplete"}
    with rollout.open("a") as source:
        source.write(json.dumps(receipt("second", 30, 130)) + "\n")
    measurement = reader._read_rollout_usage(session, started_at=start, completed_at=None)
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(180, 0, 0)
    assert warnings == set()


@pytest.mark.parametrize("missing_receipt", [False, True])
def test_completion_retains_child_receipt_gap_across_compaction(
    tmp_path: Path, missing_receipt: bool
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)

    def receipt(thread_id: str, response: str, tokens: int, cumulative: int):
        return _event(
            counted,
            "token_usage_record",
            {
                "response_id": response,
                "thread_id": thread_id,
                "turn_id": f"turn-{thread_id}",
                "model": "gpt-5.6-sol",
                "usage": {
                    "input_tokens": tokens,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": tokens,
                },
                "thread_token_usage": {
                    "input_tokens": cumulative,
                    "output_tokens": 0,
                    "total_tokens": cumulative,
                },
            },
        )

    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            receipt("scan-parent", "parent", 10, 10),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "turn-scan-parent"}),
        ],
    )
    first = receipt("scan-worker", "first", 50 if missing_receipt else 100, 100)
    second = receipt("scan-worker", "second", 100, 100)
    worker = _rollout(
        tmp_path,
        "scan-worker",
        [
            first,
            _event(counted, "compacted", {"message": "Synthetic summary"}),
            first,
            second,
            second,
        ],
        parent_thread_id="scan-parent",
    )
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "scan-worker": worker},
        [("scan-parent", "scan-worker")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    expected = _counts(160 if missing_receipt else 210, 0, 0)
    assert usage["totalTokens"] == expected["totalTokens"]
    assert usage["modelUsage"] == [{"model": "gpt-5.6-sol", **expected}]
    assert usage["coverage"] == ("partial" if missing_receipt else "complete")
    assert usage.get("warnings", []) == (["token_receipts_incomplete"] if missing_receipt else [])


@pytest.mark.parametrize("prior_turn", [False, True])
@pytest.mark.parametrize("outside_after", [False, True])
def test_compaction_before_owned_receipts_does_not_taint_scan_coverage(
    tmp_path: Path, workbench_api, prior_turn: bool, outside_after: bool
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response: str, tokens: int, timestamp: datetime, turn: str):
        return _event(
            timestamp,
            "token_usage_record",
            {
                "response_id": response,
                "thread_id": "parent",
                "turn_id": turn,
                "model": "gpt-5.6-sol",
                "usage": {
                    "input_tokens": tokens,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": tokens,
                },
                "thread_token_usage": {
                    "input_tokens": 100,
                    "output_tokens": 0,
                    "total_tokens": 100,
                },
            },
        )

    previous = start if prior_turn else start - timedelta(seconds=1)
    if outside_after:
        previous = start + timedelta(seconds=1 if prior_turn else 10)
    outside = receipt("prior", 50, previous, "other-turn" if prior_turn else "scan-turn")
    current = receipt("current", 100, start, "scan-turn")
    compacted = _event(previous, "compacted", {"message": "Synthetic previous summary"})
    rollout = _rollout(
        tmp_path,
        "parent",
        [
            *([current, compacted, outside] if outside_after else [outside, compacted, current]),
            _event(start, "event_msg", {"type": "task_complete", "turn_id": "scan-turn"}),
        ],
    )
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, rollout),
        started_at=start,
        completed_at=start + timedelta(seconds=5),
        owner_turn_id="scan-turn",
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(100, 0, 0)
    assert warnings == set()


def test_exact_receipts_replace_overlapping_legacy_counter(tmp_path: Path, workbench_api) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response, tokens, cumulative):
        def usage(value):
            return dict(
                input_tokens=value, cache_write_input_tokens=0, output_tokens=0, total_tokens=value
            )

        return _event(
            start,
            "token_usage_record",
            dict(
                response_id=response,
                thread_id="parent",
                model="gpt-5.6-sol",
                usage=usage(tokens),
                thread_token_usage=usage(cumulative),
            ),
        )

    rollout = _rollout(
        tmp_path,
        "parent",
        [
            _token_event(start, 100, 0),
            receipt("new", 10, 110),
            receipt("old", 100, 100),
            _token_event(start, 10, 0),
        ],
    )
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, rollout),
        started_at=start,
        completed_at=None,
        model_usage=models,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(110, 0, 0)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(110, 0, 0)}


@pytest.mark.parametrize(
    "receipt,counter,expected",
    [
        ((150, 15), (100, 200), (150, 200)),
        ((150, 15), (100, 20), (150, 20)),
        ((100, 50), (110, 10), (110, 50)),
        ((100, 50), (200, 10), (200, 50)),
        ((100, 10), (100, 10), (100, 10)),
    ],
    ids=[
        "counter-output",
        "smaller-counter-output",
        "smaller-counter-input",
        "counter-input",
        "equal-control",
    ],
)
def test_completion_retains_receipt_and_counter_categories(tmp_path, receipt, counter, expected):
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    response = _event(
        counted,
        "token_usage_record",
        {
            "response_id": "category-response",
            "thread_id": "scan-parent",
            "model": "gpt-5.6-sol",
            "usage": {
                "input_tokens": receipt[0],
                "output_tokens": receipt[1],
                "total_tokens": sum(receipt),
            },
            "thread_token_usage": {
                "input_tokens": counter[0],
                "output_tokens": counter[1],
                "total_tokens": sum(counter),
            },
        },
    )
    parent = _rollout(tmp_path, "scan-parent", [response, _token_event(counted, *counter)])
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (usage["inputTokens"], usage["outputTokens"], usage["totalTokens"]) == (
        *expected,
        sum(expected),
    )
    for category in ("inputTokens", "outputTokens", "totalTokens"):
        assert sum(row[category] for row in usage["modelUsage"]) == usage[category]
    assert usage["coverage"] == ("complete" if receipt == counter else "partial")


@pytest.mark.parametrize("counter_input,expected_cached", [(100, 20), (250, 90)])
def test_completion_keeps_cached_subsets_valid_when_categories_diverge(
    tmp_path, counter_input, expected_cached
):
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    response = _event(
        counted,
        "token_usage_record",
        {
            "response_id": "cache-response",
            "thread_id": "scan-parent",
            "model": "gpt-5.6-sol",
            "usage": {
                "input_tokens": 150,
                "cached_input_tokens": 20,
                "output_tokens": 15,
                "total_tokens": 165,
            },
        },
    )
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [response, _token_event(counted, counter_input, 200, cached_input_tokens=90)],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (usage["inputTokens"], usage["cachedInputTokens"], usage["outputTokens"]) == (
        max(150, counter_input),
        expected_cached,
        200,
    )
    for row in usage["modelUsage"]:
        assert row["cachedInputTokens"] + row["cacheWriteInputTokens"] <= row["inputTokens"]
    for key in ("inputTokens", "cachedInputTokens", "outputTokens", "totalTokens"):
        assert sum(row[key] for row in usage["modelUsage"]) == usage[key]


@pytest.mark.parametrize("receipt_owner", ["other-turn", "outside-window"])
def test_owned_legacy_model_survives_unrelated_first_receipt(
    tmp_path: Path, workbench_api, receipt_owner: str
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    end = start + timedelta(seconds=5)
    events = [
        _event(start, "turn_context", {"turn_id": "scan-turn", "model": "gpt-5.6-sol"}),
        _token_event(start, 1000, 10),
        _event(
            end + timedelta(seconds=1) if receipt_owner == "outside-window" else start,
            "token_usage_record",
            {
                "thread_id": "parent",
                "turn_id": "other-turn" if receipt_owner == "other-turn" else "scan-turn",
                "response_id": "unrelated-response",
                "model": "gpt-6-astra",
                "usage": {
                    "input_tokens": 50,
                    "cached_input_tokens": 0,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                    "total_tokens": 50,
                },
            },
        ),
    ]
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=end,
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(1000, 0, 10)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(1000, 0, 10)}


@pytest.mark.parametrize("thread_id", ["legacy-worker", "12345678-1234-4234-8234-123456789abc"])
def test_legacy_worker_usage_excludes_replayed_parent_turns(
    tmp_path: Path, workbench_api, thread_id: str
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    created = start + timedelta(seconds=10, microseconds=500_000)
    rollout = _rollout(
        tmp_path,
        thread_id,
        [_token_event(created + timedelta(seconds=1), 130, 13)],
        parent_thread_id="parent",
        task_started_at=created,
        copied_events=[
            _event(
                created,
                "event_msg",
                {
                    "type": "task_started",
                    "turn_id": "parent-turn",
                    "started_at": int(start.timestamp()),
                },
            ),
            _token_event(created, 100, 10),
        ],
    )
    measurement = reader._read_rollout_usage(
        reader.RolloutSession(thread_id, "parent", rollout), started_at=start, completed_at=None
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(30, 0, 3)
    assert warnings == set()


@pytest.mark.parametrize(
    "missing", ["session timestamp", "task started_at", "boolean task started_at"]
)
def test_legacy_worker_usage_requires_turn_ownership_timestamps(
    tmp_path: Path, workbench_api, missing: str
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    rollout = _rollout(
        tmp_path, "legacy-worker", [_token_event(start, 100, 10)], parent_thread_id="parent"
    )
    records = [json.loads(line) for line in rollout.read_text().splitlines()]
    if missing == "session timestamp":
        records[0]["payload"].pop("timestamp")
    elif missing == "task started_at":
        records[1]["payload"].pop("started_at")
    else:
        records[1]["payload"]["started_at"] = True
    rollout.write_text("".join(json.dumps(record) + "\n" for record in records))
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("legacy-worker", "parent", rollout),
        started_at=start,
        completed_at=None,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(0, 0, 0)
    assert warnings == {"thread_ownership_unavailable"}


@pytest.mark.parametrize(
    ("worker_kind", "legacy_archive"),
    [("discovery", False), ("discovery", True), ("dedup", False)],
)
def test_completion_recovers_replaced_deep_worker_threads(
    tmp_path: Path, worker_kind: str, legacy_archive: bool
) -> None:
    # Compressed variants exercise the bundled Node decoder in the SDK runtime lane.
    fixture = _start_scan(tmp_path, mode="deep")
    fixture = replace(
        fixture,
        started_at=(fixture.started_at - timedelta(seconds=1)).replace(microsecond=500123),
    )
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            (fixture.started_at.isoformat(), fixture.scan_id),
        )
    counted = fixture.started_at + timedelta(microseconds=1)
    before_scan = counted - timedelta(days=1)
    boundary_predecessor = fixture.started_at.replace(microsecond=400000)
    after_scan = counted + timedelta(days=1)
    artifact = fixture.scan_dir / "artifacts" / "usage-worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture target.\n", encoding="utf-8")
    worker_id = str(uuid.uuid4())
    if worker_kind == "dedup":
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_workers "
                "(id, scan_id, kind, status, prompt_path, artifact_dir, created_at, updated_at) "
                "VALUES (?, ?, 'dedup', 'queued', ?, ?, ?, ?)",
                (
                    worker_id,
                    fixture.scan_id,
                    str(prompt),
                    str(artifact),
                    fixture.started_at.isoformat(),
                    fixture.started_at.isoformat(),
                ),
            )
    for attempt, thread_id in enumerate(
        ["sdk-first-attempt", "sdk-current-attempt", "sdk-current-attempt"], start=1
    ):
        upsert_deep_worker(
            fixture.state_dir,
            fixture.scan_id,
            worker_id,
            worker_kind,
            "running",
            str(prompt),
            str(artifact),
            "--attempt",
            str(attempt),
            "--sdk-thread-id",
            thread_id,
            environment=fixture.environment,
        )
    # Legacy runs have no durable owner turn or earlier worker session records.
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET usage_owner_json = NULL WHERE scan_id = ?",
            (fixture.scan_id,),
        )
        connection.execute(
            "DELETE FROM deep_scan_attempt_sessions WHERE scan_id = ?", (fixture.scan_id,)
        )
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "sdk-first-attempt": _rollout(
                tmp_path,
                "sdk-first-attempt",
                [_token_event(counted, 20, 5)],
                session_started_at=fixture.started_at.replace(microsecond=500000),
            ),
            "sdk-first-child": _rollout(
                tmp_path,
                "sdk-first-child",
                [_token_event(counted, 7, 2)],
                parent_thread_id="sdk-first-attempt",
            ),
            "sdk-current-attempt": _rollout(
                tmp_path,
                "sdk-current-attempt",
                [_token_event(counted, 20, 5), _token_event(counted, 30, 8)],
                session_started_at=before_scan,
            ),
            "finding-comparison": _rollout(
                tmp_path, "finding-comparison", [_token_event(counted, 12, 4)]
            ),
            "other-scan-worker": _rollout(
                tmp_path, "other-scan-worker", [_token_event(counted, 80_000, 20_000)]
            ),
            "archived-worker": _rollout(
                tmp_path, "archived-worker", [_token_event(before_scan, 100, 10)]
            ),
            "archived-missing-worker": tmp_path / "archived-missing.jsonl",
            "boundary-archived-worker": _rollout(
                tmp_path,
                "boundary-archived-worker",
                [_token_event(boundary_predecessor, 100, 10)],
                session_started_at=boundary_predecessor,
            ),
            "boundary-archived-child": tmp_path / "boundary-archived-child.jsonl",
            "later-worker": _rollout(tmp_path, "later-worker", [_token_event(after_scan, 100, 10)]),
            "later-missing-worker": tmp_path / "later-missing.jsonl",
        },
        [
            ("sdk-first-attempt", "sdk-first-child"),
            ("boundary-archived-worker", "boundary-archived-child"),
        ],
    )
    working_directory = artifact if worker_kind == "discovery" else fixture.scan_dir / "artifacts"
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.executemany(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = ?",
            [
                (
                    str(fixture.scan_dir / "artifacts" / "deep_discovery"),
                    int(counted.timestamp()),
                    "finding-comparison",
                ),
                (str(working_directory), int(counted.timestamp()), "sdk-first-attempt"),
                (str(working_directory), int(counted.timestamp()), "sdk-first-child"),
                (str(working_directory), int(counted.timestamp()), "sdk-current-attempt"),
                (
                    str(tmp_path / "other-scan" / "artifacts"),
                    int(counted.timestamp()),
                    "other-scan-worker",
                ),
                (str(working_directory), int(before_scan.timestamp()), "archived-worker"),
                (str(working_directory), int(before_scan.timestamp()), "archived-missing-worker"),
                (
                    str(working_directory),
                    int(boundary_predecessor.timestamp()),
                    "boundary-archived-worker",
                ),
                (str(working_directory), int(after_scan.timestamp()), "later-worker"),
                (str(working_directory), int(after_scan.timestamp()), "later-missing-worker"),
            ],
        )
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    completed = _complete_scan(fixture, *arguments)["scan"]
    usage = completed["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "partial",
            "warnings": ["turn_in_progress"],
            "source": "codex_rollout",
            **_counts(79, 0, 22),
            "threadCount": 5,
        }.items()
    )
    run_workbench(
        fixture.state_dir,
        "register-cli-scan",
        "--repository",
        str(fixture.target),
        "--scan-dir",
        str(fixture.scan_dir),
        "--archive-existing",
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "deep",
                "repository": str(fixture.target),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        environment=fixture.environment,
    )
    if legacy_archive:
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as db:
            db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ? WHERE id = ?",
                (str(artifact), worker_id),
            )
    ended = datetime.fromisoformat(completed["usage"]["window"]["endedAt"])
    replacement_started = ended + timedelta(microseconds=1)
    replacement = _rollout(
        tmp_path,
        "new-comparison",
        [_token_event(replacement_started, 100, 10)],
        session_started_at=replacement_started,
    )
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(
            "INSERT INTO threads (id, rollout_path, cwd, created_at) VALUES (?, ?, ?, ?)",
            (
                "new-comparison",
                str(replacement),
                str(fixture.scan_dir / "artifacts" / "deep_discovery"),
                int(ended.timestamp()),
            ),
        )
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert finalized["completion"]["finalized"] is True
    assert (finalized["totalTokens"], finalized["threadCount"]) == (101, 5)


@pytest.mark.parametrize("missing", ["cwd", "created_at"])
def test_deep_usage_retains_bound_sessions_without_directory_metadata(
    tmp_path: Path, missing: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep", dedicated=True)
    fixture.write_parent_rollout([_token_event(fixture.started_at, 10, 3)])
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(f"ALTER TABLE threads DROP COLUMN {missing}")
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["warnings"] == ["worker_directories_unavailable"]
    assert (usage["totalTokens"], usage["threadCount"]) == (13, 1)


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("platform_name", "directory", "recorded_cwd", "matches"),
    [
        ("nt", r"C:\Scans\Job\output", "\\\\?\\c:\\scans\\job\\OUTPUT\\", True),
        ("nt", r"C:\Scans\Job\output", "C:/scans/job/output/", True),
        (
            "nt",
            r"\\server\share\Scans\Job\output",
            "\\\\?\\UNC\\SERVER\\share\\scans\\job\\output\\",
            True,
        ),
        ("nt", r"C:\Scans\Job\output", r"\\?\C:\Scans\Job\other-output", False),
        ("posix", "/scans/Job/output", "/scans/Job/output", True),
        ("posix", "/scans/Job/output", "/scans/job/output", False),
    ],
)
def test_worker_discovery_matches_platform_path_spelling(
    scan_usage,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    directory: str,
    recorded_cwd: str,
    matches: bool,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    environment = {"CODEX_SQLITE_HOME": str(tmp_path / "codex-sqlite")}
    _state_graph(
        environment,
        {
            "current-worker": _rollout(tmp_path, "current-worker", []),
            "replaced-worker": _rollout(tmp_path, "replaced-worker", []),
        },
        [],
    )
    state_database = Path(environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    with sqlite3.connect(state_database) as connection:
        connection.execute(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = ?",
            (recorded_cwd, int(started.timestamp()), "replaced-worker"),
        )
    monkeypatch.setattr(scan_usage, "os", SimpleNamespace(name=platform_name))
    warnings: set[str] = set()

    sessions, missing = scan_usage._discover_rollout_sessions(
        state_database,
        ["current-worker"],
        warnings,
        worker_directories={directory: False},
        started_at=started,
        completed_at=started + timedelta(seconds=1),
    )

    expected_threads = {"current-worker", "replaced-worker"} if matches else {"current-worker"}
    assert {session.thread_id for session in sessions} == expected_threads
    assert missing == set()
    assert warnings == set()


@pytest.mark.parametrize("parent_measured", [False, True])
@pytest.mark.parametrize("worker_measured", [False, True])
def test_completion_uses_latest_account_snapshot_across_owned_sessions(
    tmp_path: Path, parent_measured: bool, worker_measured: bool
) -> None:
    fixture = _start_scan(tmp_path)
    first = fixture.started_at + timedelta(microseconds=1)
    latest = first + timedelta(microseconds=1)

    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            *([_token_event(first, 10, 3)] if parent_measured else []),
            _allowance_event(first, 6),
            _allowance_event(first, 2, "another-limit"),
            _allowance_event(first + timedelta(days=1), 99),
        ],
    )
    worker = _rollout(
        tmp_path,
        "worker",
        [
            *([_token_event(first, 20, 5)] if worker_measured else []),
            _allowance_event(latest, 69),
            _allowance_event(first, 6),
        ],
        parent_thread_id="scan-parent",
    )
    unrelated = _rollout(tmp_path, "unrelated", [_allowance_event(latest, 100)])
    _state_graph(
        fixture.environment,
        {
            "scan-parent": parent,
            "worker": worker,
            "unrelated": unrelated,
        },
        [("scan-parent", "worker")],
    )

    completed = _complete_scan(fixture)
    usage = completed["scan"]["usage"]
    measured = int(parent_measured) + int(worker_measured)
    assert usage["coverage"] == (
        "complete" if measured == 2 else "partial" if measured else "unavailable"
    )
    assert usage["threadCount"] == measured
    if measured:
        assert usage["totalTokens"] == 13 * parent_measured + 25 * worker_measured
        assert usage["byRole"]["parent"]["threadCount"] == int(parent_measured)
        assert usage["byRole"]["workers"]["threadCount"] == int(worker_measured)
        assert datetime.fromisoformat(usage["tokensUpdatedAt"]) == first
        if measured == 1:
            assert usage["missingThreadCount"] == 1
    else:
        assert not set(_counts(0, 0, 0)).intersection(usage)
        assert "byRole" not in usage
        assert "tokensUpdatedAt" not in usage
    if measured < 2:
        assert usage["warnings"] == ["token_record_missing", "token_usage_unavailable"]
    limits = {item["limitId"]: item for item in usage["accountRateLimits"]}
    assert limits["codex"] == {
        "limitId": "codex",
        "observedAt": latest.isoformat(),
        "primary": {"usedPercent": 69, "windowMinutes": 10080, "resetsAt": 1800000000},
        "secondary": None,
    }
    assert limits["another-limit"]["primary"]["usedPercent"] == 2
    assert fixture.command("get-scan")["scan"]["usage"] == usage


@pytest.mark.parametrize("terminal_status", ["complete", "failed"])
def test_large_usage_persists_with_terminal_scan_state(
    tmp_path: Path, terminal_status: str
) -> None:
    fixture = _start_scan(tmp_path)
    usage = {
        "coverage": "complete",
        "source": "codex_rollout",
        "threadCount": 1,
        **_counts(120, 30, 15),
        "accountRateLimits": [
            {
                "limitId": f"fixture-limit-{index}",
                "observedAt": fixture.started_at.isoformat(),
                "primary": {"usedPercent": 6, "windowMinutes": 10080, "resetsAt": 1800000000},
                "secondary": None,
            }
            for index in range(60)
        ],
    }
    cost_json = json.dumps({"usage": usage}, separators=(",", ":"))
    assert len(cost_json.encode("utf-8")) > 8192

    if terminal_status == "complete":
        terminal = _complete_scan(fixture, "--cost-json", cost_json)["scan"]
    else:
        terminal = fail_scan(
            fixture.state_dir,
            fixture.scan_id,
            "Fixture failure.",
            "--cost-json",
            cost_json,
            environment=fixture.environment,
        )["scan"]

    assert terminal["progress"]["status"] == terminal_status
    assert terminal["usage"] == usage
    stored = fixture.command("get-scan")["scan"]
    assert stored["progress"]["status"] == terminal_status
    assert stored["usage"] == usage


def test_completion_collects_large_usage_from_owned_rollouts(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    limit_ids = {f"fixture-limit-{index}" for index in range(60)}
    fixture.write_parent_rollout(
        [
            _token_event(counted, 120, 15, cached_input_tokens=30),
            *[_allowance_event(counted, 6, limit_id) for limit_id in sorted(limit_ids)],
        ]
    )

    completed = _complete_scan(fixture)["scan"]

    assert completed["progress"]["status"] == "complete"
    usage = completed["usage"]
    assert len(json.dumps({"usage": usage}, separators=(",", ":")).encode("utf-8")) > 8192
    assert usage["coverage"] == "complete"
    assert usage["threadCount"] == 1
    assert usage.items() >= _counts(120, 30, 15).items()
    assert {limit["limitId"] for limit in usage["accountRateLimits"]} == limit_ids
    assert fixture.command("get-scan")["scan"]["usage"] == usage


def test_host_final_usage_saves_allowances_before_token_receipts(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    initial = _complete_scan(fixture, *arguments)["scan"]["usage"]
    parent = fixture.write_parent_rollout([_allowance_event(fixture.started_at, 6)])

    pending = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert pending["coverage"] == "unavailable"
    assert pending["completion"] == initial["completion"]
    assert not set(_counts(0, 0, 0)).intersection(pending)
    assert pending["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    assert fixture.command("get-scan")["scan"]["usage"] == pending

    with parent.open("a", encoding="utf-8") as output:
        receipt = _response_event(fixture.started_at, "scan-parent", "final-response", 10, 2)
        output.write(f"{json.dumps(receipt)}\n")
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert finalized["totalTokens"] == 12
    assert finalized["completion"]["finalized"] is True
    assert finalized["accountRateLimits"] == pending["accountRateLimits"]


@pytest.mark.parametrize("limits", [{"limitId": "codex"}, [{"limitId": "codex"}]])
def test_completion_validates_account_snapshots_without_token_usage(
    tmp_path: Path, limits: object
) -> None:
    fixture = _start_scan(tmp_path)
    usage = {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "accountRateLimits": limits,
    }
    rejected = fixture.command(
        "complete-scan", "--cost-json", json.dumps({"usage": usage}), check=False
    )
    assert rejected["returncode"] != 0
    assert "invalid measured token usage" in rejected["stderr"]


@pytest.mark.parametrize("terminal", [None, "task_complete", "turn_aborted"])
def test_completion_marks_worker_without_token_receipt_partial(
    tmp_path: Path, terminal: str | None
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 12, 3)])
    worker = _rollout(
        tmp_path,
        "worker",
        [_event(counted, "event_msg", {"type": terminal})] if terminal else [],
        parent_thread_id="scan-parent",
        task_started_at=counted,
        include_task_complete=False,
    )
    _state_graph(
        fixture.environment, {"scan-parent": parent, "worker": worker}, [("scan-parent", "worker")]
    )

    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    expected_warnings = {"token_record_missing", "token_usage_unavailable"}
    if terminal is None:
        expected_warnings.add("turn_in_progress")
    elif terminal == "turn_aborted":
        expected_warnings.add("turn_interrupted")
    assert set(usage["warnings"]) == expected_warnings
    assert usage["totalTokens"] == 15
    assert usage["threadCount"] == 1
    assert usage["missingThreadCount"] == 1
    assert usage["byRole"]["workers"] == {**_counts(0, 0, 0), "threadCount": 0}
    assert usage["accountRateLimits"] == []


def test_completion_marks_in_flight_usage_partial_even_with_earlier_receipts(
    tmp_path: Path,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    fixture.write_parent_rollout(
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "scan-turn"}),
            _token_event(counted, 12, 3),
            _event(counted + timedelta(days=1), "event_msg", {"type": "task_complete"}),
        ]
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["totalTokens"] == 15
    assert usage["warnings"] == ["turn_in_progress"]


@pytest.mark.parametrize("gap", ["aborted", "in_progress", "completed_without_receipt"])
def test_completion_preserves_receipts_when_later_worker_usage_is_missing(
    tmp_path: Path, gap: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 12, 3)])
    events = [_response_event(counted, "worker", "measured-response", 20, 5)]
    if gap == "aborted":
        events.append(_event(counted, "event_msg", {"type": "turn_aborted"}))
        expected_warning = "turn_interrupted"
    elif gap == "completed_without_receipt":
        events.extend(
            [
                _event(counted, "event_msg", {"type": "task_complete"}),
                _event(counted, "event_msg", {"type": "task_started", "turn_id": "later-turn"}),
                _event(counted, "event_msg", {"type": "task_complete", "turn_id": "later-turn"}),
            ]
        )
        expected_warning = "token_record_missing"
    else:
        expected_warning = "turn_in_progress"
    worker = _rollout(
        tmp_path,
        "worker",
        events,
        parent_thread_id="scan-parent",
        include_task_complete=False,
    )
    _state_graph(
        fixture.environment, {"scan-parent": parent, "worker": worker}, [("scan-parent", "worker")]
    )

    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["warnings"] == [expected_warning]
    assert usage["totalTokens"] == 40
    assert usage["byRole"]["workers"]["totalTokens"] == 25


@pytest.mark.parametrize("worker", [False, True])
@pytest.mark.parametrize("terminal", ["task_complete", "turn_aborted"])
@pytest.mark.parametrize("receipt", ["none", "native", "legacy", "zero"])
def test_closed_turn_coverage_survives_later_success(
    scan_usage, tmp_path: Path, worker: bool, terminal: str, receipt: str
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    thread_id = "worker" if worker else "scan-parent"
    parent_id = "scan-parent" if worker else None
    events = [
        _event(
            started,
            "event_msg",
            {"type": "task_started", "turn_id": "first", "started_at": int(started.timestamp())},
        )
    ]
    if receipt in {"native", "zero"}:
        events.append(
            _response_event(
                started,
                thread_id,
                "first-response",
                20 if receipt == "native" else 0,
                3 if receipt == "native" else 0,
                turn_id="first",
            )
        )
    elif receipt == "legacy":
        events.append(_token_event(started, 20, 3))
    events.extend(
        [
            _event(started, "event_msg", {"type": terminal, "turn_id": "first"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "second"}),
            _response_event(started, thread_id, "second-response", 10, 2, turn_id="second"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "second"}),
        ]
    )
    rollout = _rollout(
        tmp_path, thread_id, events, parent_thread_id=parent_id, include_task_start=False
    )
    usage = _measure_rollout(
        scan_usage, rollout, started, started, thread_id=thread_id, parent_id=parent_id
    )
    assert usage.tokens == (
        _counts(30, 0, 5) if receipt in {"native", "legacy"} else _counts(10, 0, 2)
    )
    assert usage.warnings == ({"token_record_missing"} if receipt == "none" else set()) | (
        {"turn_interrupted"} if terminal == "turn_aborted" else set()
    )


@pytest.mark.parametrize("receipt", [None, "legacy", "native"])
def test_closed_turn_coverage_retains_before_window_receipt_evidence(
    scan_usage, tmp_path: Path, receipt: str | None
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:01+00:00")
    before = started - timedelta(seconds=1)
    events = [_event(before, "event_msg", {"type": "task_started", "turn_id": "first"})]
    if receipt:
        events.append(
            _response_event(before, "scan-parent", "before", 20, 3, turn_id="first")
            if receipt == "native"
            else _token_event(before, 20, 3)
        )
    events.extend(
        [
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "first"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "second"}),
            _response_event(started, "scan-parent", "counted", 10, 2, turn_id="second"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "second"}),
        ]
    )
    rollout = _rollout(tmp_path, "scan-parent", events)
    usage = _measure_rollout(scan_usage, rollout, started, started)
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == (set() if receipt else {"token_record_missing"})


def test_closed_turn_coverage_accepts_delayed_receipt_for_same_turn(
    scan_usage, tmp_path: Path
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    rollout = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(started, "event_msg", {"type": "task_started", "turn_id": "first"}),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "first"}),
            _response_event(started, "scan-parent", "late", 10, 2, turn_id="first"),
        ],
    )
    usage = _measure_rollout(scan_usage, rollout, started, started)
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == set()


def test_closed_turn_coverage_preserves_interruption_after_same_turn_resumes(
    scan_usage,
    tmp_path: Path,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    rollout = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(started, "event_msg", {"type": "task_started", "turn_id": "same-turn"}),
            _event(started, "event_msg", {"type": "turn_aborted", "turn_id": "same-turn"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "same-turn"}),
            _response_event(started, "scan-parent", "recovered", 10, 2, turn_id="same-turn"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "same-turn"}),
        ],
    )
    usage = _measure_rollout(scan_usage, rollout, started, started)
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == {"turn_interrupted"}


def test_closed_turn_coverage_ignores_inherited_and_outside_window_interruptions(
    scan_usage,
    tmp_path: Path,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    before = started - timedelta(seconds=1)
    after = started + timedelta(seconds=1)
    rollout = _rollout(
        tmp_path,
        "worker",
        [
            _response_event(started, "worker", "counted", 10, 2),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "turn-worker"}),
            _event(after, "event_msg", {"type": "task_started", "turn_id": "later"}),
            _event(after, "event_msg", {"type": "turn_aborted", "turn_id": "later"}),
        ],
        parent_thread_id="scan-parent",
        copied_events=[
            _event(before, "event_msg", {"type": "turn_aborted", "turn_id": "inherited"}),
        ],
    )
    usage = _measure_rollout(
        scan_usage, rollout, started, started, thread_id="worker", parent_id="scan-parent"
    )
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == set()


def test_completion_marks_closed_turn_without_receipt_partial(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    fixture.write_parent_rollout(
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "empty"}),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "empty"}),
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "measured"}),
            _response_event(counted, "scan-parent", "response", 10, 2, turn_id="measured"),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "measured"}),
        ]
    )
    assert (
        _complete_scan(fixture)["scan"]["usage"].items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            **_counts(10, 0, 2),
            "threadCount": 1,
            "warnings": ["token_record_missing"],
        }.items()
    )
