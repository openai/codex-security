from __future__ import annotations

import json
import sqlite3
from argparse import Namespace
from contextlib import closing
from itertools import combinations
from pathlib import Path

import pytest

# These queries moved out of the bundled SDK tests; keep exercising native SQLite on all three OSes.
pytestmark = pytest.mark.cross_platform

NOW = "2026-01-01T00:00:00Z"


def add_scan(db, scan_id, repository: Path, *, target_id=None, started_at=NOW):
    if target_id is not None:
        db.execute(
            "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
            (target_id, str(repository), repository.name, NOW, NOW),
        )
    db.execute(
        "INSERT INTO workspaces (id, target_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (scan_id, target_id, NOW, NOW),
    )
    db.execute(
        "INSERT INTO scans (id, workspace_id, target_id, target_path, target_revision, scope, "
        "mode, scan_dir, status, phase, started_at, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 'unversioned', '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?)",
        (
            scan_id,
            scan_id,
            target_id,
            str(repository),
            str(repository / scan_id),
            started_at,
            NOW,
            NOW,
        ),
    )


def add_occurrence(db, scan_id, occurrence_id, *, finding_id=None, severity="high", path=None):
    finding_id = finding_id or occurrence_id
    db.execute(
        "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
        "VALUES (?, ?, 'synthetic-control', ?, ?, ?) ON CONFLICT (id) DO NOTHING",
        (finding_id, finding_id, finding_id, NOW, NOW),
    )
    db.execute(
        "INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, "
        "confidence, remediation, details_json, created_at) VALUES (?, ?, ?, ?, 'summary', ?, "
        "'high', 'fix', '{}', ?)",
        (occurrence_id, finding_id, scan_id, occurrence_id, severity, NOW),
    )
    if path is not None:
        db.execute(
            "INSERT INTO finding_locations (occurrence_id, relative_path, start_line, end_line, role, "
            "sort_order) VALUES (?, ?, 1, 1, 'root_control', 0)",
            (occurrence_id, path),
        )


def cache_comparison(db, before, after, payload=None):
    db.execute(
        "INSERT INTO scan_comparisons (before_scan_id, after_scan_id, result_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (before_scan_id, after_scan_id) DO NOTHING",
        (before, after, '{"matches":[],"uncertain":[]}', NOW, NOW),
    )
    if payload is not None:
        db.execute(
            "UPDATE scan_comparisons SET result_json = ? WHERE before_scan_id = ? AND after_scan_id = ?",
            (json.dumps(payload), before, after),
        )


def link(db, previous, current, reason="Confirmed link."):
    before, after = [
        db.execute(
            "SELECT scan_id FROM finding_occurrences WHERE id = ?", (occurrence,)
        ).fetchone()[0]
        for occurrence in (previous, current)
    ]
    cache_comparison(db, before, after)
    db.execute(
        "INSERT INTO scan_comparison_matches "
        "(before_scan_id, after_scan_id, before_occurrence_id, after_occurrence_id, reason) "
        "VALUES (?, ?, ?, ?, ?)",
        (before, after, previous, current, reason),
    )


def test_legacy_repository_matching_excludes_confirmed_links_from_another_checkout(
    workbench_api, workbench_db, tmp_path
):
    for index, (scan, repository) in enumerate(
        [
            ("foreign-before", "other"),
            ("foreign-after", "other"),
            ("selected-before", "selected"),
            ("selected-after", "selected"),
        ]
    ):
        # Historical scans lack a target ID; their checkout paths decide repository identity.
        add_scan(
            workbench_db, scan, tmp_path / repository, started_at=f"2026-08-01T00:00:0{index}Z"
        )
    add_occurrence(workbench_db, "foreign-before", "foreign-a")
    add_occurrence(workbench_db, "foreign-after", "foreign-b")
    link(workbench_db, "foreign-a", "foreign-b")
    comparison = workbench_api["scan_history"].compare_scans(
        workbench_db,
        Namespace(before_scan_id="selected-before", after_scan_id="selected-after"),
        require_scan=workbench_api["require_scan"],
        read_coverage=lambda _: {},
        include_matching_inputs=True,
    )
    assert comparison["matchingInputs"] == {"before": [], "after": []}


def test_comparison_index_migration_preserves_saved_history_and_indexes_both_directions(
    workbench_api, tmp_path
):
    # Start before the comparison indexes and run the current migrations twice over saved history.
    migrations = workbench_api["MIGRATIONS"]
    with closing(sqlite3.connect(":memory:")) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        workbench_api["apply_schema_migrations"](
            db, tuple(step for step in migrations if step[0] < 31), lambda: NOW, lambda _: None
        )
        scans = [f"scan-{i:03}" for i in range(200)]
        for scan in scans:
            add_scan(db, scan, tmp_path, target_id="target")
        db.executemany(
            "INSERT INTO scan_comparisons (before_scan_id, after_scan_id, result_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (
                (before, after, '{"matches":[],"uncertain":[]}', NOW, NOW)
                for before, after in combinations(scans, 2)
            ),
        )

        def rows():
            return db.execute(
                "SELECT * FROM scan_comparisons ORDER BY before_scan_id, after_scan_id"
            ).fetchall()

        original = rows()
        assert len(original) == 19_900
        for _ in range(2):
            workbench_api["apply_migrations"](db)
        assert rows() == original
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []

        statements = []
        db.set_trace_callback(statements.append)
        workbench_api["scan_history"].finding_relations(db, "scan-100", ["missing"])
        db.set_trace_callback(None)
        (select,) = [query for query in statements if "FROM scan_comparisons" in query]
        searches = [row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + select)]
        assert any("before_scan_id=?" in step for step in searches), searches
        assert any("after_scan_id=?" in step for step in searches), searches
        assert not any(step.startswith("SCAN scan_comparisons") for step in searches), searches

        for index, columns in [
            ("scan_comparisons_by_after_scan", ["after_scan_id", "before_scan_id"]),
            ("finding_occurrences_by_finding", ["finding_id", "id"]),
        ]:
            assert [row["name"] for row in db.execute(f"PRAGMA index_info({index})")] == columns
        id_plan = db.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM finding_occurrences WHERE finding_id = ?",
            ("synthetic-finding",),
        )
        assert any("finding_occurrences_by_finding" in row["detail"] for row in id_plan)


def test_invalid_comparison_preserves_saved_groups_and_related_pairs(
    workbench_db, workbench_api, tmp_path
):
    db = workbench_db
    for scan, occurrences in [
        ("scan-before", ("a1", "a2", "b", "c")),
        ("scan-after", ("x1", "x2", "y", "z")),
    ]:
        add_scan(db, scan, tmp_path, target_id="target")
        for occurrence in occurrences:
            add_occurrence(db, scan, occurrence, path="src/covered.py")
    db.commit()

    def pair(before, after):
        return {
            "beforeOccurrenceId": before,
            "afterOccurrenceId": after,
            "reason": "Separate controls.",
        }

    def group(before, after):
        return {
            "beforeOccurrenceIds": before,
            "afterOccurrenceIds": after,
            "confidence": "high",
            "reason": "Same control.",
        }

    def save(payload):
        return workbench_api["scan_history"].save_scan_comparison(
            db,
            Namespace(
                before_scan_id="scan-before",
                after_scan_id="scan-after",
                matches_json=json.dumps(payload),
            ),
            now=lambda: NOW,
            require_scan=workbench_api["require_scan"],
            read_coverage=lambda _: {
                "includePaths": ["src"],
                "excludePaths": [],
                "explicitExclusions": [],
            },
        )

    def snapshot():
        return (
            db.execute("SELECT result_json FROM scan_comparisons").fetchone()[0],
            db.execute(
                "SELECT * FROM scan_comparison_matches ORDER BY before_occurrence_id, after_occurrence_id"
            ).fetchall(),
        )

    matches = [group(["a1", "a2"], ["x1", "x2"]), group(["b"], ["y"])]
    payload = {"matches": matches, "uncertain": [], "related": [pair("a2", "y"), pair("c", "z")]}
    saved = save(payload)
    assert saved["summary"] == {
        "new": 1,
        "persisting": 2,
        "not_observed": 1,
        "reopened": 0,
        "resolved": 0,
        "unknown": 0,
    }
    assert [(p["beforeOccurrenceId"], p["afterOccurrenceId"]) for p in saved["related"]] == [
        ("a2", "y"),
        ("c", "z"),
    ]
    original = snapshot()
    assert json.loads(original[0]) == payload
    assert [(r["before_occurrence_id"], r["after_occurrence_id"]) for r in original[1]] == [
        ("a1", "x1"),
        ("a1", "x2"),
        ("a2", "x1"),
        ("a2", "x2"),
        ("b", "y"),
    ]
    for field, values, error in [
        ("related", [pair("a2", "x2")], "Related"),
        ("related", [pair("b", "y")], "Related"),
        ("related", [pair("a2", "y"), pair("a2", "y")], "Related"),
        ("related", [pair("outside", "z")], "Related"),
        ("uncertain", [pair("c", "z")], "Related"),
        ("uncertain", [pair("a1", "z")], "Uncertain"),
        ("uncertain", [pair("c", "y")], "Uncertain"),
        ("matches", [matches[0], group(["b", "a1"], ["y"])], "distinct scan findings"),
    ]:
        with pytest.raises(SystemExit, match=error):
            save({**payload, field: values})
        assert snapshot() == original, (field, values)


def test_cached_group_status_follows_coverage_uncertainty_and_confirmed_links(
    workbench_db, workbench_api, tmp_path
):
    db = workbench_db
    for scan, occurrences in [
        ("scan-before", ("a1", "a2")),
        ("scan-after", ("b1", "b2")),
        ("scan-later", ("c1", "c2")),
        ("scan-latest", ("d1",)),
    ]:
        add_scan(db, scan, tmp_path, target_id="target")
        for occurrence in occurrences:
            add_occurrence(
                db,
                scan,
                occurrence,
                severity="low" if occurrence.endswith("1") else "high",
                path="src/excluded.py" if occurrence == "a1" else "src/covered.py",
            )
    for before, after in [("a1", "c1"), ("a2", "c1"), ("b1", "c2"), ("b2", "c2")]:
        link(db, before, after)
    payload = {
        "matches": [],
        "uncertain": [
            {"beforeOccurrenceId": "a1", "afterOccurrenceId": "b1", "reason": "Uncertain."}
        ],
        "related": [{"beforeOccurrenceId": "a2", "afterOccurrenceId": "b2", "reason": "Separate."}],
    }
    coverage = {
        "includePaths": ["src"],
        "excludePaths": ["src/excluded.py"],
        "explicitExclusions": [],
    }

    def compare():
        return workbench_api["scan_history"].compare_scans(
            db,
            Namespace(before_scan_id="scan-before", after_scan_id="scan-after"),
            require_scan=workbench_api["require_scan"],
            read_coverage=lambda _: coverage,
            require_matches=True,
        )

    def counts(comparison):
        return {status: n for status, n in comparison["summary"].items() if n}

    cache_comparison(db, "scan-before", "scan-after", payload)
    uncertain = compare()
    assert counts(uncertain) == {"unknown": 2}
    previous, current = uncertain["findings"]
    assert previous["beforeOccurrenceIds"] == ["a1", "a2"]
    assert current["afterOccurrenceIds"] == ["b1", "b2"]
    assert (previous["findingId"], previous["severity"], current["findingId"]) == (
        "a2",
        "high",
        "b2",
    )
    assert all(
        f["status"] == "unknown" and f["reason"] == "Uncertain." for f in (previous, current)
    )

    payload["uncertain"] = []
    cache_comparison(db, "scan-before", "scan-after", payload)
    assert counts(compare()) == {"new": 1, "unknown": 1}
    coverage["excludePaths"] = []
    unlinked = compare()
    assert counts(unlinked) == {"new": 1, "not_observed": 1}

    db.execute(
        "INSERT INTO finding_triage (occurrence_id, status, close_reason, updated_at) VALUES ('a1', 'closed', 'already_fixed', ?)",
        (NOW,),
    )
    link(db, "c1", "d1")
    link(db, "c2", "d1")
    linked = compare()
    assert counts(linked) == {"reopened": 1}
    (reopened,) = linked["findings"]
    assert reopened["status"] == "reopened"
    assert isinstance(reopened["matchReason"], str) and reopened["matchReason"]
    assert reopened["beforeOccurrenceIds"] == ["a1", "a2"]
    assert reopened["afterOccurrenceIds"] == ["b1", "b2"]
    assert "related" not in linked
    stored = db.execute(
        "SELECT result_json FROM scan_comparisons WHERE before_scan_id='scan-before' AND after_scan_id='scan-after'"
    ).fetchone()[0]
    assert json.loads(stored) == payload

    db.execute("DELETE FROM scan_comparison_matches WHERE after_scan_id='scan-latest'")
    assert compare() == unlinked


def test_matching_reads_each_scan_once_and_skips_cached_links(
    workbench_api, workbench_db, tmp_path
):
    history = workbench_api["scan_history"]
    db = workbench_db
    repository = tmp_path / "repository"
    for index in range(3):
        scan = f"scan-{index}"
        add_scan(db, scan, repository, started_at=f"2026-01-01T00:00:0{index}Z")
        add_occurrence(db, scan, scan)
    queries = []
    backfilled = []
    db.set_trace_callback(queries.append)

    def pending(*, force=False, coverage=lambda _: {}):
        return history.list_unmatched_scan_pairs(
            db,
            Namespace(repository=str(repository), force=force),
            backfill_finding_details=lambda _, scan: backfilled.append(scan["id"]),
            read_coverage=coverage,
        )

    def batches(result):
        return [
            (batch["afterScanId"], [scan["scanId"] for scan in batch["beforeScans"]])
            for batch in result["batches"]
        ]

    result = pending()
    assert result["scanCount"] == 3
    assert batches(result) == [("scan-1", ["scan-0"]), ("scan-2", ["scan-0", "scan-1"])]
    for batch in result["batches"]:
        assert [row["occurrenceId"] for row in batch["afterFindings"]] == [batch["afterScanId"]]
        for before in batch["beforeScans"]:
            assert [row["occurrenceId"] for row in before["findings"]] == [before["scanId"]]
    assert sorted(backfilled) == ["scan-0", "scan-1", "scan-2"]
    assert sum("from finding_occurrences " in sql.lower() for sql in queries) <= 3

    for before, after in [("scan-0", "scan-1"), ("scan-0", "scan-2"), ("scan-1", "scan-2")]:
        cache_comparison(db, before, after)
    queries.clear()
    cached = pending()
    assert (cached["batches"], cached["skippedPairs"]) == ([], 3)
    assert not any("FROM scan_comparison_matches" in sql for sql in queries)

    for scan in ("foreign-a", "foreign-b"):
        add_scan(db, scan, tmp_path / "other")
        add_occurrence(db, scan, scan)
    link(db, "scan-0", "scan-1")
    link(db, "foreign-a", "foreign-b")
    queries.clear()
    scoped = history._saved_finding_links(db, {"scan-0", "scan-1"})
    assert [(row["before_finding_id"], row["after_finding_id"]) for row in scoped] == [
        ("scan-0", "scan-1")
    ]
    (sql,) = queries
    # A query over all saved links could return the same rows after filtering in Python.
    assert any(
        "before_scan_id=?" in row["detail"] for row in db.execute("EXPLAIN QUERY PLAN " + sql)
    )

    for index in (3, 4):
        scan = f"scan-{index}"
        add_scan(db, scan, repository, started_at=f"2026-01-01T00:00:0{index}Z")
        add_occurrence(db, scan, scan, finding_id=f"scan-{index - 3}")

    def coverage(scan):
        if scan["id"] in {"scan-0", "scan-1", "scan-2"}:
            raise SystemExit("Unavailable artifacts")
        return {}

    unavailable = pending(coverage=coverage)
    assert (unavailable["scanCount"], unavailable["unavailableScans"]) == (5, 3)
    assert batches(unavailable) == [("scan-4", ["scan-3"])]
    assert unavailable["batches"][0]["knownFindingGroups"] == [["scan-0", "scan-1"]]
    forced = pending(force=True, coverage=coverage)
    assert batches(forced) == [("scan-4", ["scan-3"])]
    assert "knownFindingGroups" not in forced["batches"][0]

    for before, after in [
        ("scan-1", "scan-2"),
        ("scan-2", "scan-0"),
        ("scan-0", "foreign-a"),
        ("foreign-a", "scan-1"),
    ]:
        link(db, before, after)
    if hasattr(db, "setlimit"):
        db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 2)
    queries.clear()
    selected = history._saved_finding_links(db, {"scan-0", "scan-1", "scan-2"})
    assert [(row["before_scan_id"], row["after_scan_id"]) for row in selected] == [
        ("scan-0", "scan-1"),
        ("scan-1", "scan-2"),
        ("scan-2", "scan-0"),
    ]
    assert len(queries) <= 1
    queries.clear()
    assert history._saved_finding_links(db, set()) == []
    assert queries == []


def test_relations_follow_confirmed_identities_and_read_a_page_in_bulk(
    workbench_api, workbench_db, tmp_path
):
    history = workbench_api["scan_history"]
    db = workbench_db
    for scan, target in [
        ("one", "target"),
        ("two", "target"),
        ("three", "clone"),
        ("four", "clone"),
        ("foreign-one", "unrelated"),
        ("foreign-two", "unrelated"),
    ]:
        add_scan(db, scan, tmp_path / target, target_id=target)
    # Exceed SQLite's historical 999-bind limit, even if setlimit is unavailable.
    left_ids = [f"left-{i}" for i in range(1001)]
    pairs = []
    for i, left in enumerate(left_ids):
        right = f"right-{i}"
        add_occurrence(db, "one", left, finding_id=f"left-identity-{i}")
        add_occurrence(db, "two", right, finding_id=f"right-identity-{i}")
        pairs.append(
            {"beforeOccurrenceId": left, "afterOccurrenceId": right, "reason": "Separate controls."}
        )
    cache_comparison(db, "one", "two", {"matches": [], "uncertain": [], "related": pairs})

    def saved():
        return db.execute(
            "SELECT result_json FROM scan_comparisons WHERE before_scan_id = 'one' AND after_scan_id = 'two'"
        ).fetchone()[0]

    payload = saved()
    queries = []
    db.set_trace_callback(queries.append)
    scoped = history.finding_relations(db, "one", ["left-0"])
    assert set(scoped) == {"left-0"}
    (relation,) = scoped["left-0"]
    assert (relation["occurrenceId"], relation["scanId"]) == ("right-0", "two")
    assert len(queries) <= 3
    queries.clear()
    assert history.finding_relations(db, "one", []) == {}
    assert queries == []

    add_occurrence(db, "four", "recurring-left", finding_id="left-identity-0")
    add_occurrence(db, "three", "bridge", finding_id="bridge-identity")
    add_occurrence(db, "foreign-one", "foreign-a")
    add_occurrence(db, "foreign-two", "foreign-b")
    link(db, "recurring-left", "bridge")
    link(db, "right-0", "bridge")
    link(db, "foreign-a", "foreign-b")
    assert set(history._confirmed_finding_aliases(db, ["left-0"])) == {
        "left-identity-0",
        "right-identity-0",
        "bridge-identity",
    }
    assert history.finding_relations(db, "one", ["left-0"]) == {}
    assert history.finding_relations(db, "two", ["right-0"]) == {}
    assert set(history.finding_relations(db, "one", ["left-1"])) == {"left-1"}
    assert saved() == payload
    db.execute("DELETE FROM scan_comparison_matches WHERE before_occurrence_id = 'right-0'")
    assert history.finding_relations(db, "one", ["left-0"]) == scoped

    if hasattr(db, "setlimit"):
        db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 8)
    queries.clear()
    page = history.finding_relations(db, "one", left_ids[1:11])
    assert {
        left: [relation["occurrenceId"] for relation in rows] for left, rows in page.items()
    } == {f"left-{i}": [f"right-{i}"] for i in range(1, 11)}
    assert len(queries) <= 3
    queries.clear()
    rows = history._rows_for_ids(
        db,
        "SELECT id FROM finding_occurrences WHERE id IN (SELECT value FROM json_each(?))",
        iter(left_ids),
    )
    assert {row["id"] for row in rows} == set(left_ids)
    assert len(queries) <= 1


def test_confirmed_history_follows_recurring_ids_and_reverts_after_unlink(
    workbench_api, workbench_db, tmp_path
):
    from finalize_scan_contract import _populate_unsealed_finding_identities

    history = workbench_api["scan_history"]
    db = workbench_db
    scans = [
        ("a", "a", "primary"),
        ("b", "b", "primary"),
        ("c", "c", "primary"),
        ("a-repeat", "a", "primary"),
        ("c-repeat", "c", "primary"),
        ("unlinked", "a", "other"),
    ]
    started = {}
    occurrences = {}
    for index, (scan, anchor, target) in enumerate(scans):
        started[scan] = f"2026-08-01T00:00:0{index}Z"
        add_scan(db, scan, tmp_path / target, target_id=target, started_at=started[scan])
        finding = {"ruleId": "synthetic-control", "identity": {"anchor": anchor}}
        _populate_unsealed_finding_identities(
            {"scan": {"id": scan, "target": {"targetId": target}}},
            {"scanId": scan, "findings": [finding]},
        )
        occurrences[scan] = finding["occurrenceId"]
        add_occurrence(db, scan, finding["occurrenceId"], finding_id=finding["findingId"])
    link(db, occurrences["a"], occurrences["b"], reason="First confirmed link.")
    link(db, occurrences["b"], occurrences["c"], reason="Second confirmed link.")

    def assert_history(group):
        # The group is in scan-start order; matches are sorted by scan ID.
        for scan in group:
            matches, first, bounds = history.finding_matches(
                db, occurrences[scan], scan, started[scan]
            )
            assert [(match["scanId"], match["occurrenceId"]) for match in matches] == [
                (other, occurrences[other]) for other in sorted(set(group) - {scan})
            ]
            assert first == started[group[0]]
            assert bounds == (group if len(group) == 1 else [group[0], group[-1]])
            assert all(match["reason"] for match in matches)
            if scan == "a" and "b" in group:
                assert (
                    next(match["reason"] for match in matches if match["scanId"] == "b")
                    == "First confirmed link."
                )

    assert_history(["a", "b", "c", "a-repeat", "c-repeat"])
    assert_history(["unlinked"])
    db.execute("DELETE FROM scan_comparison_matches")
    for group in (["a", "a-repeat"], ["b"], ["c", "c-repeat"], ["unlinked"]):
        assert_history(group)
