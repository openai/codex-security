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
