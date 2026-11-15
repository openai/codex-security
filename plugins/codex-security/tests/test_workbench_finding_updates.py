"""Standard scans expose only accepted reviewed checkpoints and reconcile them at completion."""

import copy
import json
import sqlite3
import uuid
from argparse import Namespace
from contextlib import closing

from workbench_test_support import (
    empty_target_scan,
    read_draft_documents,
    scan_command,
    write_completed_contract,
)


def test_live_finding_update_replay(tmp_path):
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    contract = tmp_path / "fixture"
    contract.mkdir()
    write_completed_contract(contract, scan_id, target)
    documents = read_draft_documents(contract)
    documents["manifest"]["scan"]["complete"] = False
    findings = documents["findings"]
    finding = findings["findings"][0]
    finding["provenance"]["candidateId"] = "candidate-a"
    retired = copy.deepcopy(finding)
    retired["identity"]["instance"] = "second"
    retired["provenance"]["candidateId"] = "candidate-b"
    findings["findings"].append(retired)
    (scan_dir / "drafts").mkdir(exist_ok=True)
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"

    def publish(*extra, **kwargs):
        staged.write_text(json.dumps(documents))
        return scan_command(
            state, "write-scan-draft", scan_id, "--draft-path", str(staged), *extra, **kwargs
        )

    def feed(*args):
        return scan_command(state, "list-finding-updates", scan_id, *args)

    documents["manifest"]["scan"]["scope"]["validationMode"] = "custom_pending"
    publish()
    assert feed()["updates"] == []
    del documents["manifest"]["scan"]["scope"]["validationMode"]
    rejected = publish("--expected-draft-digest", "0" * 64, check=False)
    assert "scan_draft_conflict" in rejected["stderr"]
    assert feed()["updates"] == []
    publish()
    publish()
    first = feed("--limit", "1")
    assert first["status"] == "running"
    assert first["hasMore"] and first["nextCursor"] == 1
    first_id = first["updates"][0]["findingId"]
    assert first["updates"][0]["kind"] == "reviewed"
    assert first["updates"][0]["locations"] == [{"file": "src/extract.py", "line": 41}]
    second = feed("--after-cursor", "1")
    assert not second["hasMore"] and second["updates"][0]["kind"] == "reviewed"
    progress = scan_command(state, "get-scan", scan_id, "--progress-only")
    assert scan_command(state, "get-scan", scan_id, "--progress-only", "--after-cursor", "1") == {
        **progress,
        "findingUpdates": second,
    }
    second_id = second["updates"][0]["findingId"]
    assert second_id != first_id

    # Explicitly reject a finding in one checkpoint, then let fresh
    # evidence re-admit it. A plain omission of its sibling should do nothing.
    findings["findings"] = []
    surfaces = documents["coverage"]["surfaces"]
    surfaces.append(
        {
            "id": "surface-b",
            "candidateId": "candidate-b",
            "disposition": "rejected",
            "label": "Second candidate ruled out",
            "receiptRefs": [],
        }
    )
    publish()
    rejected_event = feed("--after-cursor", "2")["updates"]
    assert [(u["kind"], u["findingId"]) for u in rejected_event] == [("withdrawn", second_id)]
    surfaces.pop()
    findings["findings"] = [retired]
    publish()
    assert [u["kind"] for u in feed("--after-cursor", "3")["updates"]] == ["reviewed"]
    findings["findings"] = []
    publish()
    assert feed("--after-cursor", "4")["updates"] == []
    finding["remediation"] = "Changed remediation"
    findings["findings"] = [finding]
    publish()
    changed = feed("--after-cursor", "4")["updates"]
    assert len(changed) == 1 and changed[0]["changedFields"] == ["remediation"]
    assert changed[0]["kind"] == "updated" and changed[0]["findingId"] == first_id

    finding["provenance"]["candidateId"] = "new-source-reference"
    publish()
    provenance = feed("--after-cursor", "5")["updates"]
    assert [(u["kind"], u["changedFields"]) for u in provenance] == [("updated", ["provenance"])]

    documents["manifest"]["scan"]["complete"] = True
    publish()
    scan_command(state, "complete-scan", scan_id)
    terminal = feed("--after-cursor", "6")
    assert terminal["status"] == "complete"
    poll = scan_command(state, "get-scan", scan_id, "--progress-only", "--after-cursor", "6")
    assert poll["findingUpdates"] == terminal
    assert poll["scan"]["progress"]["status"] == "complete"
    assert [(u["kind"], u["findingId"]) for u in terminal["updates"]][-2:] == [
        ("finalized", first_id),
        ("withdrawn", second_id),
    ]
    sealed = json.loads((scan_dir / "findings.json").read_text())
    assert [f["findingId"] for f in sealed["findings"]] == [first_id]
    assert feed("--after-cursor", str(terminal["nextCursor"]))["updates"] == []


def test_combined_poll_preserves_snapshot_and_reports_feed_errors(
    tmp_path, workbench_api, monkeypatch
):
    state, _, scan_id, _ = empty_target_scan(tmp_path)
    database = state / "workbench.sqlite3"
    read = workbench_api["get_scan"]
    progress_module = workbench_api["progress"]
    original = progress_module.scan_progress_result
    args = Namespace(scan_id=scan_id, progress_only=True, after_cursor=0)
    with closing(sqlite3.connect(database)) as reader, closing(sqlite3.connect(database)) as writer:
        reader.row_factory = sqlite3.Row
        reader.execute("PRAGMA query_only = ON")
        assert reader.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

        # Commit a reviewed update after the progress SELECT and before the feed SELECT.
        def publish_after_progress(connection, scan):
            result = original(connection, scan)
            with writer:
                writer.execute(
                    "INSERT INTO scan_finding_updates"
                    "(scan_id, cursor, finding_id, kind, preview_json, fields_json) "
                    "VALUES (?, 1, 'fixture', 'reviewed', '{}', '{}')",
                    (scan_id,),
                )
            return result

        with monkeypatch.context() as patch:
            patch.setattr(progress_module, "scan_progress_result", publish_after_progress)
            assert read(reader, args)["findingUpdates"]["updates"] == []
        poll = read(reader, args)
        assert [entry["findingId"] for entry in poll["findingUpdates"]["updates"]] == ["fixture"]
        with writer:
            writer.execute(
                "UPDATE scan_finding_updates SET preview_json = 'bad json' WHERE scan_id = ?",
                (scan_id,),
            )
        damaged = read(reader, args)
        assert damaged["scan"] == poll["scan"]
        assert "findingUpdates" not in damaged and damaged["findingUpdatesError"]
        assert not reader.in_transaction


def test_direct_files_and_historical_index_are_replayed(tmp_path):
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    assert not scan_command(state, "list-finding-updates", scan_id)["updates"]
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute("""CREATE TRIGGER fail_feed_append BEFORE INSERT ON scan_finding_updates
                      BEGIN SELECT RAISE(ABORT, 'feed unavailable'); END""")
    scan_command(state, "complete-scan", scan_id)
    page = scan_command(state, "list-finding-updates", scan_id)
    [final] = page["updates"]
    assert final["kind"] == "finalized"

    # Old completed scans had no feed, and the oldest indexed rows had no details_json.
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        assert (
            "feed unavailable"
            in db.execute(
                "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
        )
        db.execute("UPDATE scans SET completion_warnings_json = '[]' WHERE id = ?", (scan_id,))
        db.execute(
            "UPDATE finding_occurrences SET details_json = '{}' WHERE scan_id = ?", (scan_id,)
        )
    old = scan_command(state, "list-finding-updates", scan_id)
    assert old["updates"] == [{**final, "validation": ""}]
    assert not scan_command(state, "list-finding-updates", scan_id, "--after-cursor", "1")[
        "updates"
    ]

    # Scans completed before migration 8 have valid seals without a pinned digest.
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute("UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan_id,))
    assert scan_command(state, "list-finding-updates", scan_id) == old
    (scan_dir / "findings.json").write_text("{}")
    assert scan_command(state, "list-finding-updates", scan_id)["updates"] == []


def test_completed_custom_pending_source_discovery_cannot_replay_as_reviewed(tmp_path):
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["scope"]["validationMode"] = "custom_pending"
    manifest_path.write_text(json.dumps(manifest))
    scan_command(state, "complete-scan", scan_id)
    page = scan_command(state, "list-finding-updates", scan_id)
    assert page["status"] == "complete"
    assert page["updates"] == []
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute("UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan_id,))
    assert scan_command(state, "list-finding-updates", scan_id) == page


def test_feed_append_failure_preserves_completion_and_replays_its_terminal_changes(tmp_path):
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    documents = read_draft_documents(scan_dir)
    findings = documents["findings"]["findings"]
    removed = copy.deepcopy(findings[0])
    removed["identity"]["instance"] = "removed"
    findings.append(removed)
    (scan_dir / "drafts").mkdir(exist_ok=True)
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", str(staged))
    before = scan_command(state, "list-finding-updates", scan_id)
    kept_id, removed_id = [entry["findingId"] for entry in before["updates"]]
    # A direct-file final handoff revises a finding and drops its sibling.
    # Reject the *second* journal insert to exercise rollback of the first.
    final_file = scan_dir / "findings.json"
    final = json.loads(final_file.read_text())
    final["findings"].pop()
    final["findings"][0]["severity"]["level"] = "low"
    final_file.write_text(json.dumps(final))
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        db.execute("""CREATE TRIGGER fail_feed_append BEFORE INSERT ON scan_finding_updates
                      WHEN NEW.kind = 'finalized' BEGIN SELECT RAISE(ABORT, 'feed unavailable'); END""")

    scan_command(state, "complete-scan", scan_id)
    with sqlite3.connect(state / "workbench.sqlite3") as db:
        status, warnings = db.execute(
            "SELECT status, completion_warnings_json FROM scans WHERE id=?", (scan_id,)
        ).fetchone()
        assert status == "complete"
        assert "feed unavailable" in warnings
        assert (
            db.execute(
                "SELECT count(*) FROM scan_finding_updates WHERE scan_id=?", (scan_id,)
            ).fetchone()[0]
            == 2
        )

    cursor = before["nextCursor"]
    replay = []

    def read_page(after):
        return scan_command(
            state, "list-finding-updates", scan_id, "--after-cursor", str(after), "--limit", "1"
        )

    for _ in range(3):
        page = read_page(cursor)
        assert page["status"] == "complete" and page == read_page(cursor)
        replay.extend(page["updates"])
        cursor = page["nextCursor"]
    assert [u["cursor"] for u in replay] == [3, 4, 5]
    assert [(u["kind"], u["findingId"]) for u in replay] == [
        ("updated", kept_id),
        ("finalized", kept_id),
        ("withdrawn", removed_id),
    ]
    assert "severity" in replay[0]["changedFields"] and replay[1]["severity"] == "low"
    assert (
        scan_command(state, "list-finding-updates", scan_id, "--after-cursor", str(cursor))[
            "updates"
        ]
        == []
    )
