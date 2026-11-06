"""Verify that issue receipts stay bound to their finding and that inspection preserves local state."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import quote, unquote

import pytest
from workbench_test_support import load_script, run_workbench, write_completed_contract

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = load_script("validate_scan_contract")
SCHEMA = load_script("workbench_schema")
RECEIPT_MIGRATION = next(
    version
    for version, name, _ in SCHEMA.MIGRATIONS
    if name == "share finding issue receipts across trackers"
)
LINEAR = {"type": "linear", "teamId": "team-example"}
JIRA = {"type": "jira", "cloudId": "site-example", "projectId": "10001"}


@pytest.fixture
def inspection(tmp_path: Path):
    publication = load_script("workbench_publication")
    scan_dir, validated = source(tmp_path)
    payload = {"action": "inspect", "scanDirectory": str(scan_dir), "destination": LINEAR}
    return publication, payload, validated


@pytest.mark.cross_platform
@pytest.mark.parametrize("root", ["C:\\", "\\\\server\\share\\"])
@pytest.mark.parametrize("extended", [False, True])
def test_inspection_windows_filename_spelling(inspection, monkeypatch, root, extended) -> None:
    publication, payload, validated = inspection
    ordinary = PureWindowsPath(root) / "state %23 # équipe" / "workbench.sqlite3"
    expected = (
        ("\\\\?\\UNC\\" + str(ordinary)[2:])
        if root.startswith("\\\\")
        else "\\\\?\\" + str(ordinary)
    )
    stat = Mock()

    class Filename(PureWindowsPath):
        def stat(self):
            return stat(str(self))

    path = Filename(expected if extended else ordinary)
    connect = Mock(return_value=sqlite3.connect(":memory:"))
    monkeypatch.setattr(publication, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(publication, "validate_contract", lambda _: validated)
    monkeypatch.setattr(publication, "Path", Filename)
    monkeypatch.setattr(publication.sqlite3, "connect", connect)

    result = publication.finding_issues(SimpleNamespace(database_path=lambda: path), payload)

    assert result["storeExists"] is True
    assert {"stat": stat.call_args.args[0], "uri": connect.call_args.args[0]} == {
        "stat": expected,
        "uri": f"file:{quote(expected, safe='')}?mode=ro",
    }
    assert connect.call_args.kwargs == {"uri": True, "timeout": 5}
    assert unquote(connect.call_args.args[0][5:].split("?")[0]) == expected


@pytest.mark.cross_platform
@pytest.mark.parametrize("require_history", [False, True])
def test_inspection_legacy_windows_filename_boundary(
    inspection, monkeypatch, require_history
) -> None:
    publication, payload, validated = inspection

    class Filename(PureWindowsPath):
        def stat(self):
            if not str(self).startswith("\\\\?\\") and len(str(self)) >= 260:
                raise FileNotFoundError("synthetic legacy MAX_PATH failure")

    directory = Filename("C:/") / ("s" * 246)
    path = directory / "workbench.sqlite3"
    assert len(str(directory)) < 260 <= len(str(path))

    monkeypatch.setattr(publication, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(publication, "validate_contract", lambda _: validated)
    monkeypatch.setattr(publication, "Path", Filename)
    monkeypatch.setattr(
        publication.sqlite3, "connect", Mock(return_value=sqlite3.connect(":memory:"))
    )
    monkeypatch.setattr(publication, "verify_publication_history", Mock())
    payload["requireHistory"] = require_history

    try:
        result = publication.finding_issues(SimpleNamespace(database_path=lambda: path), payload)
    except SystemExit as exc:
        pytest.fail(f"Existing database was treated as missing: {exc}")
    assert result["storeExists"] is True


@pytest.mark.parametrize(
    "state_name",
    [
        pytest.param("state %23 # équipe", marks=pytest.mark.cross_platform),
        pytest.param(
            "state ?mode=rw",
            marks=[
                pytest.mark.native_macos,
                pytest.mark.skipif(os.name == "nt", reason="? is not a Windows filename character"),
            ],
        ),
    ],
)
def test_inspection_uri_reads_literal_filename_readonly(
    tmp_path: Path, inspection, monkeypatch, state_name: str
) -> None:
    publication, payload, validated = inspection
    path = tmp_path / state_name / "workbench.sqlite3"
    legacy_database(path, validated, LINEAR)
    original = path.read_bytes()
    real_inspect = publication.inspect_issue_receipts

    def inspect_readonly(connection, *args):
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("CREATE TABLE inspection_must_not_write (value TEXT)")
        return real_inspect(connection, *args)

    monkeypatch.setattr(publication, "inspect_issue_receipts", inspect_readonly)
    result = publication.finding_issues(SimpleNamespace(database_path=lambda: path), payload)
    assert result["receipts"][0]["issueIdentifier"] == "SEC-101"
    assert path.read_bytes() == original
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    "message,tagged", [("unable to open database file", True), ("database is locked", False)]
)
def test_inspection_access_failure_preserves_fallback_tag(
    inspection, monkeypatch, message, tagged
) -> None:
    publication, payload, validated = inspection
    path = Mock()
    path.stat.side_effect = PermissionError("synthetic access failure")
    error = sqlite3.OperationalError(message)
    monkeypatch.setattr(publication, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(publication.sqlite3, "connect", Mock(side_effect=error))
    with pytest.raises(sqlite3.OperationalError) as raised:
        publication.finding_issues(SimpleNamespace(database_path=lambda: path), payload)
    assert raised.value is error
    assert getattr(error, "_codex_security_state_unavailable", False) is tagged


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires native Windows extended-length paths")
@pytest.mark.parametrize("extended", [False, True])
def test_inspection_native_windows_filename_boundary(tmp_path: Path, inspection, extended) -> None:
    publication, payload, validated = inspection
    windows_files = load_script("windows_scan_local_files")
    directory = tmp_path
    while len(str(directory)) < 200:
        directory /= "segment" * 5
    directory /= "s" * (250 - len(str(directory)) - 1)
    path = directory / "workbench.sqlite3"
    assert len(str(directory)) < 260 <= len(str(path))
    native_path = Path(windows_files._extended_path(path))
    native_path.parent.parent.mkdir(parents=True, exist_ok=True)
    legacy_database(native_path, validated, LINEAR)
    original = native_path.read_bytes()

    selected_path = native_path if extended else path
    result = publication.finding_issues(
        SimpleNamespace(database_path=lambda: selected_path), payload
    )

    assert result["storeExists"] is True
    assert result["receipts"][0]["issueIdentifier"] == "SEC-101"
    assert native_path.read_bytes() == original
    assert list(native_path.parent.iterdir()) == [native_path]


def source(tmp_path: Path) -> tuple[Path, dict]:
    scan_dir = tmp_path / "scan"
    shutil.copytree(PLUGIN_ROOT / "examples" / "completed-scan", scan_dir)
    return scan_dir, VALIDATOR.validate_contract(scan_dir)


def receipt_for(validated: dict, **fields) -> dict:
    finding = validated["findings"]["findings"][0]
    return {
        "findingId": finding["findingId"],
        "occurrenceId": finding["occurrenceId"],
        "issueIdentifier": "SEC-101",
        "operation": "create",
        **fields,
    }


def issues(state: Path, scan_dir: Path, action: str, *, destination=None, **fields) -> dict:
    return run_workbench(
        state,
        "finding-issues",
        input_text=json.dumps(
            {
                "action": action,
                "scanDirectory": str(scan_dir),
                "destination": destination or LINEAR,
                **fields,
            }
        ),
    )


def legacy_database(path: Path, validated: dict, destination: dict) -> None:
    path.parent.mkdir()
    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        SCHEMA.apply_migrations(
            connection,
            tuple(migration for migration in SCHEMA.MIGRATIONS if migration[0] < RECEIPT_MIGRATION),
            lambda: "2026-01-01T00:00:00Z",
            lambda _: None,
        )
        receipt = receipt_for(validated)
        connection.execute(
            "INSERT INTO finding_publications (scan_id, finding_id, occurrence_id, destination_type, "
            "team_id, project_id, external_id, external_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                validated["manifest"]["scan"]["id"],
                receipt["findingId"],
                receipt["occurrenceId"],
                "linear",
                destination["teamId"],
                destination.get("projectId"),
                "SEC-101",
                "https://linear.app/example/issue/SEC-101",
                "2026-01-01T00:00:00Z",
            ),
        )
        connection.commit()


@pytest.mark.cross_platform
@pytest.mark.parametrize("existing_directory", [False, True])
def test_inspection_of_portable_source_does_not_create_state(
    tmp_path: Path, existing_directory: bool
) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    if existing_directory:
        state.mkdir()
    result = issues(state, scan_dir, "inspect")
    assert result["scanId"] == validated["manifest"]["scan"]["id"]
    assert result["receipts"] == []
    assert result["storeExists"] is False
    assert state.exists() is existing_directory
    if existing_directory:
        assert list(state.iterdir()) == []


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="requires Unix file permissions",
)
@pytest.mark.parametrize("action", ["inspect", "record"])
def test_inaccessible_state_preserves_sqlite_open_error(tmp_path: Path, action: str) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o000)
    try:
        with pytest.raises(PermissionError):
            (state / "workbench.sqlite3").stat()
        result = run_workbench(
            state,
            "finding-issues",
            input_text=json.dumps(
                {
                    "action": action,
                    "scanDirectory": str(scan_dir),
                    "destination": LINEAR,
                    **({"receipts": [receipt_for(validated)]} if action == "record" else {}),
                }
            ),
            check=False,
        )
        assert result["returncode"] != 0
        assert "sqlite3.OperationalError: unable to open database file" in result["stderr"]
    finally:
        state.chmod(0o700)


@pytest.mark.parametrize("project", [None, "project-example"])
def test_legacy_receipts_are_read_without_migration_and_preserved_on_upgrade(
    tmp_path: Path, project: str | None
) -> None:
    scan_dir, validated = source(tmp_path)
    destination = {"type": "linear", "teamId": "équipe-example"}
    if project is not None:
        destination["projectId"] = project
    state = tmp_path / "state"
    path = state / "workbench.sqlite3"
    legacy_database(path, validated, destination)
    original = path.read_bytes()
    inspected = issues(state, scan_dir, "inspect", destination=destination)
    assert inspected["storeExists"] is True
    assert inspected["receipts"] == [
        {
            **receipt_for(validated),
            "scanId": validated["manifest"]["scan"]["id"],
            "url": "https://linear.app/example/issue/SEC-101",
        }
    ]
    assert path.read_bytes() == original
    prepared = issues(state, scan_dir, "prepare", destination=destination)
    assert prepared["receipts"] == []
    assert prepared["storeExists"] is True
    assert issues(state, scan_dir, "inspect", destination=destination) == inspected
    with closing(sqlite3.connect(path)) as connection:
        assert (
            connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            == SCHEMA.MIGRATIONS[-1][0]
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'finding_publications'"
            ).fetchone()
            is None
        )
        key = connection.execute("SELECT destination_key FROM finding_issue_receipts").fetchone()[0]
        assert key == json.dumps(
            ["linear", "équipe-example", project], ensure_ascii=False, separators=(",", ":")
        )


def test_records_id_only_acceptance_and_failed_readback_without_losing_create(
    tmp_path: Path,
) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    accepted = receipt_for(validated)
    recorded = issues(state, scan_dir, "record", destination=JIRA, receipts=[accepted])
    assert recorded["storeExists"] is True
    assert recorded["receipts"] == [{**accepted, "scanId": validated["manifest"]["scan"]["id"]}]
    failed_read = {"status": "failed", "error": "Read denied; diagnostic sk-synthetic-value"}
    issues(
        state,
        scan_dir,
        "record",
        destination=JIRA,
        receipts=[
            {
                **accepted,
                "url": "https://issues.example.test/browse/SEC-101",
                "readback": failed_read,
            }
        ],
    )
    issues(state, scan_dir, "record", destination=JIRA, receipts=[accepted])
    issues(
        state,
        scan_dir,
        "record",
        destination=JIRA,
        receipts=[
            {
                **accepted,
                "operation": "reuse",
                "readback": {"status": "verified"},
            }
        ],
    )
    history = issues(state, scan_dir, "inspect", destination=JIRA)["receipts"]
    assert len(history) == 2
    assert history[0]["operation"] == "create"
    assert history[0]["url"] == "https://issues.example.test/browse/SEC-101"
    assert history[0]["readback"] == failed_read
    assert history[1]["operation"] == "reuse"
    assert history[1]["readback"] == {"status": "verified"}
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


@pytest.mark.parametrize("operation", ["create", "update", "reuse"])
def test_readback_replay_preserves_the_accepted_receipt_url(tmp_path: Path, operation: str) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    accepted = receipt_for(
        validated, operation=operation, url="https://issues.example.test/browse/SEC-101"
    )
    issues(state, scan_dir, "record", receipts=[accepted])
    readback = {"status": "verified"}
    replayed = issues(
        state,
        scan_dir,
        "record",
        receipts=[
            {**accepted, "url": "https://issues.example.test/browse/SEC-999", "readback": readback}
        ],
    )
    expected = {
        **accepted,
        "scanId": validated["manifest"]["scan"]["id"],
        "readback": readback,
    }
    assert replayed["receipts"] == [expected]
    assert issues(state, scan_dir, "inspect")["receipts"] == [expected]


def test_destination_scope_is_part_of_receipt_identity(tmp_path: Path) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    accepted = receipt_for(validated)
    issues(state, scan_dir, "record", receipts=[accepted])
    destinations = (
        {"type": "linear", "teamId": "different-team"},
        {"type": "linear", "teamId": "team-example", "projectId": "project-example"},
        JIRA,
        {"type": "github-issue", "hostname": "github.com", "repository": "example/repo"},
        {"type": "github-advisory", "hostname": "github.com", "repository": "example/repo"},
    )
    for destination in destinations:
        inspected = issues(state, scan_dir, "inspect", destination=destination)
        assert inspected["receipts"] == [], destination
        issues(state, scan_dir, "record", destination=destination, receipts=[accepted])

    expected = [{**accepted, "scanId": validated["manifest"]["scan"]["id"]}]
    for destination in (LINEAR, *destinations):
        inspected = issues(state, scan_dir, "inspect", destination=destination)
        assert inspected["receipts"] == expected, destination


def test_same_issue_can_track_a_later_occurrence(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    sources = []
    for index in range(2):
        scan_dir = tmp_path / f"scan-{index}"
        scan_dir.mkdir()
        write_completed_contract(scan_dir, str(uuid.uuid4()), target)
        VALIDATOR.FINALIZER.finalize_scan(scan_dir)
        sources.append((scan_dir, VALIDATOR.validate_contract(scan_dir)))
    first_dir, first = sources[0]
    second_dir, second = sources[1]
    created = receipt_for(first)
    reused = receipt_for(second, operation="reuse", readback={"status": "verified"})
    assert created["findingId"] == reused["findingId"]
    assert created["occurrenceId"] != reused["occurrenceId"]
    issues(state, first_dir, "record", receipts=[created])
    assert (
        issues(state, second_dir, "inspect")["receipts"][0]["occurrenceId"]
        == created["occurrenceId"]
    )
    issues(state, second_dir, "record", receipts=[reused])
    history = issues(state, second_dir, "inspect")["receipts"]
    assert [entry["operation"] for entry in history] == ["create", "reuse"]
    assert len({entry["scanId"] for entry in history}) == 2


@pytest.mark.parametrize("operation", ["create", "update", "reuse"])
def test_issue_cannot_move_to_a_different_finding(tmp_path: Path, operation: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    sources = []
    for index in range(2):
        scan_dir = tmp_path / f"scan-{index}"
        scan_dir.mkdir()
        write_completed_contract(
            scan_dir, str(uuid.uuid4()), target, identity_anchor=f"synthetic-finding-{index}"
        )
        VALIDATOR.FINALIZER.finalize_scan(scan_dir)
        sources.append((scan_dir, VALIDATOR.validate_contract(scan_dir)))
    first_dir, first = sources[0]
    second_dir, second = sources[1]
    existing = receipt_for(first)
    conflicting = receipt_for(second, operation=operation)
    assert existing["findingId"] != conflicting["findingId"]
    issues(state, first_dir, "record", receipts=[existing])

    result = run_workbench(
        state,
        "finding-issues",
        input_text=json.dumps(
            {
                "action": "record",
                "scanDirectory": str(second_dir),
                "destination": LINEAR,
                "receipts": [receipt_for(second, issueIdentifier="SEC-102"), conflicting],
            }
        ),
        check=False,
    )
    assert result["returncode"] != 0
    assert "already associated with another finding" in result["stderr"]
    assert issues(state, second_dir, "inspect")["receipts"] == []
    assert issues(state, first_dir, "inspect")["receipts"] == [
        {**existing, "scanId": first["manifest"]["scan"]["id"]}
    ]
    # Issue identifiers are scoped to their destination.
    recorded = issues(state, second_dir, "record", destination=JIRA, receipts=[conflicting])
    assert recorded["receipts"] == [{**conflicting, "scanId": second["manifest"]["scan"]["id"]}]


@pytest.mark.parametrize("mutation", ["finding", "occurrence", "scan", "seal"])
def test_invalid_source_is_rejected_before_creating_state(tmp_path: Path, mutation: str) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    receipt = receipt_for(validated)
    payload = {
        "action": "record",
        "scanDirectory": str(scan_dir),
        "destination": LINEAR,
        "receipts": [receipt],
    }
    if mutation == "finding":
        payload["findingIds"] = ["not-a-finding"]
    elif mutation == "occurrence":
        receipt["occurrenceId"] = "not-an-occurrence"
    elif mutation == "scan":
        payload["expectedScanId"] = "not-this-scan"
    else:
        (scan_dir / "findings.json").write_text("{}")
    result = run_workbench(state, "finding-issues", input_text=json.dumps(payload), check=False)
    assert result["returncode"] != 0
    assert not state.exists()
