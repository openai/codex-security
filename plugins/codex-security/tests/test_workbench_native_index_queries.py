from __future__ import annotations

import ntpath
from argparse import Namespace
from types import SimpleNamespace

import pytest
from workbench_test_support import stable_target_id

SCAN_IDS = [f"00000000-0000-4000-8000-{index:012d}" for index in range(3)]


def query_args(**values):
    return Namespace(
        **{
            "repository": None,
            "scan_root": None,
            "target_id": None,
            "mode": None,
            "query": None,
            "severity": None,
            "status": None,
            "limit": 100,
            "offset": 0,
            **values,
        }
    )


@pytest.fixture
def indexed_collections(workbench_db, tmp_path):
    timestamp = "2026-08-01T00:00:00Z"
    targets = []
    # Populate query inputs directly. Scan completion and index registration stay
    # covered by test_workbench_native_indexes.py's real-process lifecycle tests.
    with workbench_db:
        for index, name in enumerate(("needle-first", "needle-second", "unrelated")):
            target = tmp_path / name
            target.mkdir()
            target = target.resolve()
            targets.append(target)
            target_id = stable_target_id(target)
            workbench_db.execute(
                "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (target_id, str(target), name, timestamp, timestamp),
            )
            workbench_db.execute(
                "INSERT INTO workspaces (id, target_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (f"10000000-0000-4000-8000-{index:012d}", target_id, timestamp, timestamp),
            )
            workbench_db.execute(
                "INSERT INTO scans (id, workspace_id, target_id, target_path, target_revision, "
                "scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?, ?)",
                (
                    SCAN_IDS[index],
                    f"10000000-0000-4000-8000-{index:012d}",
                    target_id,
                    str(target),
                    "synthetic-revision",
                    str(tmp_path / SCAN_IDS[index]),
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            workbench_db.execute(
                "INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
                (SCAN_IDS[index], timestamp),
            )
            workbench_db.execute(
                "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    f"finding-{index}",
                    f"fingerprint-{index}",
                    "synthetic-rule",
                    name,
                    timestamp,
                    timestamp,
                ),
            )
            workbench_db.execute(
                "INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, "
                "confidence, remediation, details_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'high', 'high', ?, ?, ?)",
                (
                    f"occurrence-{index}",
                    f"finding-{index}",
                    SCAN_IDS[index],
                    "Output directory traversal",
                    "Synthetic finding summary",
                    "Constrain the path",
                    '{"taxonomy":{"category":"path-traversal"}}',
                    timestamp,
                ),
            )
    return workbench_db, targets


def test_global_finding_filters_apply_before_pagination(workbench_api, indexed_collections):
    connection, targets = indexed_collections
    query = workbench_api["native_indexes"].list_global_findings
    filters = {"query": "NeEdLe", "severity": "high", "status": "open"}
    first = query(connection, query_args(**filters, limit=1))
    second = query(connection, query_args(**filters, limit=1, offset=1))
    assert first["nextOffset"] == 1
    assert second["nextOffset"] is None
    assert {first["findings"][0]["scanId"], second["findings"][0]["scanId"]} == {
        SCAN_IDS[0],
        SCAN_IDS[1],
    }

    targeted = query(connection, query_args(**filters, target_id=stable_target_id(targets[0])))
    assert [finding["scanId"] for finding in targeted["findings"]] == [SCAN_IDS[0]]
    assert query(connection, query_args(query="needle", severity="low"))["findings"] == []
    unfiltered = query(connection, query_args())
    assert set(unfiltered) == {"findings", "limit", "nextOffset", "offset"}
    assert len(unfiltered["findings"]) == 3


@pytest.mark.parametrize("matched", [False, True])
def test_latest_scan_confirmation_uses_group_membership(
    workbench_api, indexed_collections, matched
):
    connection, targets = indexed_collections
    connection.execute(
        "UPDATE scans SET target_id = ?, started_at = ? WHERE id = ?",
        (stable_target_id(targets[0]), "2026-08-01T00:10:00Z", SCAN_IDS[1]),
    )
    for index, completed_at in [(0, "2026-08-01T00:30:00Z"), (1, "2026-08-01T00:20:00Z")]:
        connection.execute(
            "UPDATE finding_occurrences SET created_at = ? WHERE id = ?",
            (completed_at, f"occurrence-{index}"),
        )
    if matched:
        connection.execute(
            "INSERT INTO scan_comparisons VALUES (?, ?, '{}', 'now', 'now')", SCAN_IDS[:2]
        )
        connection.execute(
            "INSERT INTO scan_comparison_matches VALUES (?, ?, 'occurrence-0', 'occurrence-1', 'same issue')",
            SCAN_IDS[:2],
        )
    else:
        connection.execute(
            "UPDATE finding_occurrences SET finding_id = 'finding-0' WHERE id = 'occurrence-1'"
        )
    query = workbench_api["native_indexes"].list_global_findings
    args = query_args(target_id=stable_target_id(targets[0]))
    (finding,) = query(connection, args)["findings"]
    assert finding["scanId"] == SCAN_IDS[0]
    assert finding["knownScanIds"] == SCAN_IDS[:2]
    assert finding["confirmedInLatestScan"] is True
    connection.execute("DELETE FROM finding_occurrences WHERE id = 'occurrence-1'")
    (finding,) = query(connection, args)["findings"]
    assert finding["confirmedInLatestScan"] is False


@pytest.mark.parametrize(
    ("completion", "status", "updated"),
    [
        ("2026-10-08T03:00:00+02:00", "closed", "2026-10-08T01:00:01.000001Z"),
        ("2026-10-07T23:00:02-02:00", "open", "2026-10-07T23:00:02-02:00"),
        ("2026-10-08T03:00:01.000001+02:00", "closed", "2026-10-08T03:00:01.000001+02:00"),
    ],
)
def test_global_findings_compare_decisions_and_return_original_update_text(
    workbench_api, indexed_collections, completion, status, updated
):
    connection, targets = indexed_collections
    connection.execute(
        "UPDATE scans SET target_id = ? WHERE id = ?", (stable_target_id(targets[0]), SCAN_IDS[1])
    )
    connection.execute(
        "UPDATE finding_occurrences SET finding_id = 'finding-0' WHERE id = 'occurrence-1'"
    )
    connection.execute(
        "UPDATE finding_occurrences SET created_at = ? WHERE id = 'occurrence-0'", (completion,)
    )
    connection.execute("UPDATE scans SET updated_at = ? WHERE id = ?", (completion, SCAN_IDS[0]))
    for index, timestamp, reason in [
        (0, "2026-10-08T01:00:01Z", "false_positive"),
        (1, "2026-10-08T01:00:01.000001Z", "already_fixed"),
    ]:
        connection.execute(
            "INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at) VALUES (?, 'closed', ?, 'Synthetic decision', ?)",
            (f"occurrence-{index}", reason, timestamp),
        )
    before = connection.execute("SELECT id, updated_at FROM scans ORDER BY id").fetchall()
    (finding,) = workbench_api["native_indexes"].list_global_findings(
        connection, query_args(target_id=stable_target_id(targets[0]))
    )["findings"]
    assert finding["status"] == status
    assert finding["updatedAt"] == updated
    assert connection.execute("SELECT id, updated_at FROM scans ORDER BY id").fetchall() == before


@pytest.mark.parametrize(
    ("timestamps", "order"),
    [
        (
            [
                "2026-10-08T03:00:00+02:00",
                "2026-10-08T01:00:00.123Z",
                "2026-10-08T01:00:00.234567Z",
            ],
            [2, 1, 0],
        ),
        (
            [
                "2026-10-08T01:00:00.000Z",
                "2026-10-08T01:00:00Z",
                "2026-10-08t03:00:00.000000+02:00",
            ],
            [0, 1, 2],
        ),
    ],
)
def test_global_finding_pages_follow_completion_order(
    workbench_api, indexed_collections, timestamps, order
):
    connection, _ = indexed_collections
    for index, timestamp in enumerate(timestamps):
        connection.execute(
            "UPDATE finding_occurrences SET created_at = ? WHERE id = ?",
            (timestamp, f"occurrence-{index}"),
        )
    query = workbench_api["native_indexes"].list_global_findings
    pages = [query(connection, query_args(limit=1, offset=index)) for index in range(3)]
    assert [page["findings"][0]["occurrenceId"] for page in pages] == [
        f"occurrence-{index}" for index in order
    ]
    assert [page["findings"][0]["createdAt"] for page in pages] == [
        timestamps[index] for index in order
    ]
    assert [page["nextOffset"] for page in pages] == [1, 2, None]


def test_scan_findings_support_search_severity_and_triage_filters(
    workbench_api, indexed_collections
):
    connection, _ = indexed_collections
    workbench_api["set_finding_triage"](
        connection,
        Namespace(
            occurrence_id="occurrence-0",
            status="closed",
            close_reason="false_positive",
            note="The reported path is not reachable.",
        ),
    )
    query = workbench_api["list_findings"]
    filtered = query(
        connection,
        query_args(
            scan_id=SCAN_IDS[0],
            query="OUTPUT DIRECTORY",
            severity="high",
            status="closed",
            limit=1,
        ),
    )["findingsPage"]
    assert [finding["occurrenceId"] for finding in filtered["findings"]] == ["occurrence-0"]
    assert filtered["total"] == 1
    assert filtered["nextOffset"] is None
    assert (
        query(connection, query_args(scan_id=SCAN_IDS[0], status="open"))["findingsPage"][
            "findings"
        ]
        == []
    )


@pytest.mark.parametrize(
    ("command", "collection", "status"),
    [("list-scans", "scans", "complete"), ("list-repositories", "repositories", "scanned")],
)
def test_collection_filters_apply_before_pagination(
    workbench_api, indexed_collections, command, collection, status
):
    connection, targets = indexed_collections
    query = (
        workbench_api["scan_history"].list_scans
        if command == "list-scans"
        else workbench_api["native_indexes"].list_repositories
    )
    filters = {"query": "NeEdLe", "status": status}
    if command == "list-scans":
        filters["mode"] = "standard"
    first = query(connection, query_args(**filters, limit=1))
    second = query(connection, query_args(**filters, limit=1, offset=1))
    assert first["nextOffset"] == 1
    assert second["nextOffset"] is None
    assert {first[collection][0]["targetId"], second[collection][0]["targetId"]} == {
        stable_target_id(targets[0]),
        stable_target_id(targets[1]),
    }
    targeted = query(
        connection, query_args(**filters, target_id=stable_target_id(targets[0]), limit=None)
    )
    assert [item["targetId"] for item in targeted[collection]] == [stable_target_id(targets[0])]
    unfiltered = query(connection, query_args(limit=None))
    assert set(unfiltered) == {collection}
    assert len(unfiltered[collection]) == 3
    if command == "list-repositories":
        assert query(connection, query_args(status="not_scanned"))[collection] == []
        assert query(connection, query_args(status="open_findings"))[collection]


def test_scan_list_returns_lightweight_running_first_summaries(workbench_api, indexed_collections):
    connection, targets = indexed_collections
    connection.execute(
        "UPDATE scans SET status = 'running', phase = 'preflight' WHERE id = ?",
        (SCAN_IDS[1],),
    )
    connection.execute(
        "UPDATE scans SET status = 'failed', canceled_at = updated_at WHERE id = ?", (SCAN_IDS[0],)
    )
    scans = workbench_api["scan_history"].list_scans(connection)["scans"]

    assert [scan["scanId"] for scan in scans] == [SCAN_IDS[1], SCAN_IDS[0], SCAN_IDS[2]]
    assert scans[0]["targetPath"] == str(targets[1])
    assert scans[0]["targetRevision"] == "synthetic-revision"
    assert scans[0]["progress"]["status"] == "running"
    assert scans[0]["progress"]["phase"] == "preflight"
    assert scans[1]["progress"]["status"] == "canceled"
    assert "artifacts" not in scans[0]
    assert "findings" not in scans[0]


def test_scan_root_filter_matches_windows_path_aliases(
    workbench_api, indexed_collections, tmp_path, monkeypatch
):
    connection, _ = indexed_collections
    root = tmp_path / "Scan Results"
    for scan_id, directory in zip(
        SCAN_IDS, (root / "first", tmp_path / "Scan Results Other", tmp_path / "unrelated")
    ):
        connection.execute("UPDATE scans SET scan_dir = ? WHERE id = ?", (str(directory), scan_id))
    history = workbench_api["scan_history"]
    monkeypatch.setattr(history, "os", SimpleNamespace(name="nt", path=ntpath, sep="\\"))
    args = query_args(scan_root=str(root).upper(), limit=None)

    assert [scan["scanId"] for scan in history.list_scans(connection, args)["scans"]] == [
        SCAN_IDS[0]
    ]
    connection.execute(
        "UPDATE scans SET scan_dir = ? WHERE id = ?", (ntpath.normpath(str(root)), SCAN_IDS[0])
    )
    assert [scan["scanId"] for scan in history.list_scans(connection, args)["scans"]] == [
        SCAN_IDS[0]
    ]


def test_scan_list_probes_requested_repository_once(
    workbench_api, indexed_collections, monkeypatch
):
    connection, targets = indexed_collections
    history = workbench_api["scan_history"]
    probes = []
    git_output = history.git_output

    def record_git_output(target, *arguments):
        probes.append((target, arguments))
        return git_output(target, *arguments)

    monkeypatch.setattr(history, "git_output", record_git_output)
    result = history.list_scans(connection, query_args(repository=str(targets[0]), limit=1))

    assert [scan["scanId"] for scan in result["scans"]] == [SCAN_IDS[0]]
    assert [arguments for target, arguments in probes if target == targets[0]] == [
        ("rev-parse", "--path-format=absolute", "--git-common-dir"),
        ("remote", "get-url", "origin"),
    ]


def test_finding_history_does_not_scan_unrelated_occurrences(workbench_api, indexed_collections):
    connection, _ = indexed_collections
    connection.execute(
        "UPDATE finding_occurrences SET finding_id = 'finding-0' WHERE id = 'occurrence-1'"
    )

    def read_history():
        steps = 0

        def count_step():
            nonlocal steps
            steps += 1
            return 0

        connection.set_progress_handler(count_step, 1)
        try:
            result = workbench_api["scan_history"].finding_matches(
                connection, "occurrence-0", SCAN_IDS[0], "2026-08-01T00:00:00Z"
            )
        finally:
            connection.set_progress_handler(None, 0)
        return result, steps

    expected, baseline_steps = read_history()
    assert [row["occurrenceId"] for row in expected[0]] == ["occurrence-1"]
    connection.executemany(
        "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
        "SELECT ?, ?, rule_id, identity_anchor, created_at, updated_at FROM findings "
        "WHERE id = 'finding-2'",
        ((f"unrelated-{index}", f"unrelated-{index}") for index in range(10_000)),
    )
    connection.execute(
        "INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, "
        "confidence, remediation, details_json, created_at) "
        "SELECT findings.id, findings.id, source.scan_id, source.title, source.summary, "
        "source.severity, source.confidence, source.remediation, source.details_json, source.created_at "
        "FROM findings CROSS JOIN finding_occurrences AS source "
        "WHERE findings.id LIKE 'unrelated-%' AND source.id = 'occurrence-2'"
    )
    actual, populated_steps = read_history()
    assert actual == expected
    # Count SQLite instructions, not elapsed time: unrelated history must stay out of the traversal.
    assert populated_steps <= baseline_steps * 2


@pytest.mark.parametrize(
    ("timestamps", "order"),
    [
        (
            [
                "2026-10-08T03:00:00+02:00",
                "2026-10-08T01:00:00.123Z",
                "2026-10-08T01:00:00.234567Z",
            ],
            [2, 1, 0],
        ),
        (
            [
                "2026-10-08T01:00:00.000Z",
                "2026-10-08T01:00:00Z",
                "2026-10-08t03:00:00.000000+02:00",
            ],
            [0, 1, 2],
        ),
    ],
)
def test_scan_pages_compare_updates_and_preserve_ties(
    workbench_api, indexed_collections, timestamps, order
):
    connection, _ = indexed_collections
    for index, timestamp in enumerate(timestamps):
        column = "scans" if index % 2 else "scan_progress"
        identity = "id" if column == "scans" else "scan_id"
        connection.execute(
            f"UPDATE {column} SET updated_at = ? WHERE {identity} = ?", (timestamp, SCAN_IDS[index])
        )
    before = list(connection.iterdump())
    query = workbench_api["scan_history"].list_scans
    # Repeated helpers share a connection.
    for _ in range(2):
        pages = [query(connection, query_args(limit=1, offset=index)) for index in range(3)]
        scan = connection.execute("SELECT * FROM scans LIMIT 1").fetchone()
        assert workbench_api["get_scan_feedback"](connection, scan)["falsePositives"] == []
        assert [page["scans"][0]["scanId"] for page in pages] == [
            SCAN_IDS[index] for index in order
        ]
        assert [page["scans"][0]["updatedAt"] for page in pages] == [
            timestamps[index] for index in order
        ]
        assert [page["nextOffset"] for page in pages] == [1, 2, None]
    assert list(connection.iterdump()) == before


@pytest.mark.parametrize(
    ("older", "newer", "equal"),
    [
        ("2026-10-08T01:00:00Z", "2026-10-08T01:00:00.100000Z", False),
        ("2026-10-08T03:00:00+02:00", "2026-10-08T01:00:00.100000Z", False),
        ("2026-10-08T03:00:00.100000+02:00", "2026-10-08t01:00:00.100z", True),
        ("2026-10-08T01:00:00.1Z", "2026-10-08T01:00:00.12Z", False),
        ("2026-10-08T01:00:00.1234Z", "2026-10-08T01:00:00.23456Z", False),
        ("2026-10-08T03:00:00.1+02:00", "2026-10-08t01:00:00.100000z", True),
        ("2026-10-08T01:00:00.1234567Z", "2026-10-08T01:00:00.2345678Z", False),
        ("2026-10-08T01:00:00.123456789Z", "2026-10-08T01:00:00.234567891Z", False),
        (
            "2026-10-08T01:00:00." + "123456789" * 8 + "Z",
            "2026-10-08T01:00:00." + "234567891" * 8 + "Z",
            False,
        ),
    ],
)
def test_scan_start_chronology_keeps_latest_and_first_seen_queries_consistent(
    workbench_api, indexed_collections, older, newer, equal
):
    connection, targets = indexed_collections
    target_id = stable_target_id(targets[0])
    for scan_id, timestamp in zip(SCAN_IDS[:2], (older, newer)):
        connection.execute(
            "UPDATE scans SET target_id = ?, started_at = ?, updated_at = ? WHERE id = ?",
            (target_id, timestamp, "2026-10-08T04:00:00Z", scan_id),
        )
        connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            ("2026-10-08T04:00:00Z", scan_id),
        )
    connection.execute(
        "UPDATE finding_occurrences SET finding_id = 'finding-0' WHERE id = 'occurrence-1'"
    )
    connection.execute(
        "INSERT INTO finding_occurrences "
        "(id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at) "
        "SELECT 'latest-only', 'finding-1', scan_id, title, summary, severity, confidence, remediation, details_json, created_at "
        "FROM finding_occurrences WHERE id = 'occurrence-1'"
    )
    before = list(connection.iterdump())
    indexes = workbench_api["native_indexes"]
    findings = {finding["finding_id"]: finding for finding in indexes._indexed_findings(connection)}
    assert findings["finding-1"]["confirmed_in_latest_scan"] is True
    assert findings["finding-0"]["known_since"] == older
    assert findings["finding-0"]["known_scan_ids"] == SCAN_IDS[:2]
    repository = indexes.list_repositories(connection, query_args(target_id=target_id))[
        "repositories"
    ][0]
    assert repository["latestScan"]["scanId"] == SCAN_IDS[1]
    history = workbench_api["scan_history"].list_scans(connection, query_args(target_id=target_id))[
        "scans"
    ]
    assert [scan["scanId"] for scan in history] == (SCAN_IDS[:2] if equal else SCAN_IDS[1::-1])
    assert list(connection.iterdump()) == before
