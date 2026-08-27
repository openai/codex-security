#!/usr/bin/env python3
"""Validate and compare evidence-classified remediation snapshots; no network or writes."""

import argparse
import collections
import datetime
import json
import sys
import unittest
from urllib.parse import urlsplit

FLAGS = {"no_pickup", "routing_gap", "stalled", "new_awaiting_pickup"}
CLASSES = FLAGS | {"active", "pending_validation", "dispositioned", "unverified"}
REQUIRED = ("inventory", "details", "comments", "remediation")
ISSUE_CHECKS = ("details", "comments", "remediation")
TERMINAL = {"completed", "canceled"}
NONTERMINAL = {"backlog", "unstarted", "started", "triage"}
PENDING_STEPS = {"patch_review", "merge", "patch_verification", "deployment",
                 "mitigation_execution", "deployed_retest"}


def timestamp(value, field):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO timestamp with a timezone")
    try:
        at = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO timestamp with a timezone") from exc
    if at.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return at


def nonblank(value):
    return isinstance(value, str) and bool(value.strip())


def validate_scope(scope):
    if not isinstance(scope, dict) or not nonblank(scope.get("key")):
        raise ValueError("scope needs a nonempty key")
    if type(scope.get("assigned_only")) is not bool or type(scope.get("include_archived")) is not bool:
        raise ValueError("scope needs boolean assigned_only and include_archived")
    priorities = scope.get("priorities")
    if not isinstance(priorities, list) or not priorities:
        raise ValueError("scope.priorities must be a nonempty list of exact integers 0..4")
    if any(type(p) is not int or not 0 <= p <= 4 for p in priorities):
        raise ValueError("scope.priorities must contain only exact integers 0..4")
    if len(priorities) != len(set(priorities)):
        raise ValueError("scope.priorities must not contain duplicates")


def inventory_state(issue, scope):
    """Return selected, unfinished, assigned as True/False/unknown plus warnings.

    A missing field is never normalized to a negative observation. Callers must
    normalize duplicates to a documented terminal type using source evidence.
    Human status names, labels, and title prefixes do not determine eligibility.
    """
    key = issue["id"]
    priority = issue.get("priority")
    if isinstance(priority, dict):
        priority = priority.get("value")
    if type(priority) is not int or not 0 <= priority <= 4:
        return None, None, None, [f"{key}: missing or invalid numeric priority"]
    if priority not in scope["priorities"]:
        return False, False, None, []
    if "archived_at" not in issue:
        return None, None, None, [f"{key}: archive state is unknown; archived_at is required"]
    archived_at = issue["archived_at"]
    if archived_at is not None:
        try:
            timestamp(archived_at, f"{key}.archived_at")
        except ValueError:
            return None, None, None, [f"{key}: invalid archived_at; archive state is unknown"]
        if not scope["include_archived"]:
            return False, False, None, []
    status_type = issue.get("status_type")
    if not isinstance(status_type, str) or status_type.casefold() not in TERMINAL | NONTERMINAL:
        return True, None, None, [f"{key}: missing or unknown status_type; unfinished state is unknown"]
    if status_type.casefold() in TERMINAL:
        return True, False, None, []
    if "assignee" not in issue:
        return True, True, None, [f"{key}: assignment is unknown; assignee is required"]
    assignee = issue["assignee"]
    if assignee is None:
        return True, True, False, []
    if not nonblank(assignee):
        return True, True, None, [f"{key}: invalid assignee; use an exact stable ID or explicit null"]
    return True, True, True, []


def source_link(value):
    """Check link shape only; never fetch a URL or read a referenced file."""
    if not nonblank(value) or any(c.isspace() or ord(c) < 32 for c in value):
        return False
    try:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            return False
        if parsed.scheme in {"http", "https"}:
            # Accessing port also rejects malformed numeric port declarations.
            return bool(parsed.hostname) and (parsed.port is None or parsed.port > 0)
        return (parsed.scheme == "file" and parsed.netloc in {"", "localhost"}
                and parsed.path.startswith("/") and len(parsed.path) > 1)
    except ValueError:
        return False


def evidence_complete(row, checked_at):
    checks = row.get("checks")
    evidence = row.get("evidence")
    if not (isinstance(checks, dict)
            and all(checks.get(k) == "complete" for k in ISSUE_CHECKS)
            and nonblank(row.get("reason"))
            and isinstance(evidence, list) and bool(evidence)):
        return False
    try:
        for entry in evidence:
            if (not isinstance(entry, dict) or not source_link(entry.get("url"))
                    or not nonblank(entry.get("summary"))):
                return False
            observed_at = timestamp(entry.get("at"), "evidence.at")
            if observed_at > checked_at:
                return False
            if entry.get("event_at") is not None:
                if timestamp(entry["event_at"], "evidence.event_at") > observed_at:
                    return False
        activity = row.get("last_substantive_activity_at")
        if activity is not None and timestamp(activity, "last_substantive_activity_at") > checked_at:
            return False
    except ValueError:
        return False
    if row.get("classification") == "pending_validation":
        step = row.get("pending_step")
        if not isinstance(step, str) or step not in PENDING_STEPS:
            return False
    return True


def inspect(snapshot):
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be an object")
    if type(snapshot.get("schema_version")) is not int or snapshot["schema_version"] != 3:
        raise ValueError("unsupported or missing schema_version; expected 3; recheck evidence before migrating older snapshots")
    checked_at = timestamp(snapshot.get("checked_at"), "checked_at")
    scope = snapshot.get("scope")
    validate_scope(scope)
    issues = snapshot.get("issues")
    if not isinstance(issues, list) or any(not isinstance(i, dict) for i in issues):
        raise ValueError("issues must be a list of objects")
    ids = [i.get("id") for i in issues]
    if any(not nonblank(key) for key in ids):
        raise ValueError("every issue needs an exact nonempty canonical string ID")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate canonical issue IDs")
    coverage = snapshot.get("coverage", {})
    if not isinstance(coverage, dict):
        raise ValueError("coverage must be an object")

    rows, warnings, unresolved_ids = {}, [], []
    totals = collections.Counter()
    for issue in issues:
        selected, unfinished, assigned, field_warnings = inventory_state(issue, scope)
        warnings.extend(field_warnings)
        if field_warnings:
            unresolved_ids.append(issue["id"])
        if selected is not True:
            continue
        totals["inventory_selected"] += 1
        if unfinished is not True:
            continue
        totals["unfinished"] += 1
        if assigned is True:
            totals["assigned_unfinished"] += 1
        elif assigned is False:
            totals["unassigned_unfinished"] += 1
        else:
            totals["assignment_unknown_unfinished"] += 1
        if scope["assigned_only"] and assigned is not True:
            continue

        row = dict(issue)
        classification = row.get("classification")
        if assigned is None:
            row["classification"] = "unverified"
        elif classification not in CLASSES:
            raise ValueError(f'{row["id"]}: unsupported or missing classification')
        if (type(row.get("routing_gap")) is not bool
                or (assigned is False and row["routing_gap"] is not True)
                or (classification == "routing_gap" and row["routing_gap"] is not True)):
            row["classification"] = "unverified"
            warnings.append(f'{row["id"]}: missing or contradictory routing_gap; keep routing separate from engagement')
        if not evidence_complete(row, checked_at):
            row["classification"] = "unverified"
            warnings.append(f'{row["id"]}: classification lacks complete checks/reason/dated evidence or a required pending_step')
        rows[row["id"]] = row

    coverage_complete = all(coverage.get(k) == "complete" for k in REQUIRED)
    counts = collections.Counter(r["classification"] for r in rows.values())
    if not coverage_complete:
        warnings.append("incomplete source coverage; do not advance baseline")
    routing_gap_ids = {k for k, v in rows.items()
                       if v["classification"] != "unverified" and v["routing_gap"] is True}
    follow_up_ids = routing_gap_ids | {k for k, v in rows.items() if v["classification"] in FLAGS}
    report = {
        "schema_version": 3,
        "checked_at": snapshot["checked_at"], "scope": scope,
        "baseline_eligible": coverage_complete and not warnings and counts["unverified"] == 0,
        "counts": {k: totals[k] for k in (
            "inventory_selected", "unfinished", "assigned_unfinished",
            "unassigned_unfinished", "assignment_unknown_unfinished")},
        "follow_up_ids": sorted(follow_up_ids),
        "routing_gap_ids": sorted(routing_gap_ids),
        "unresolved_issue_ids": sorted(unresolved_ids),
        "warnings": warnings,
    }
    report["counts"].update({
        "eligible": len(rows), "follow_up": len(follow_up_ids),
        "routing_gap": len(routing_gap_ids),
        "by_classification": dict(sorted(counts.items())),
    })
    return report, rows


def compare(current, previous=None):
    report, now = inspect(current)
    if previous is None:
        return report
    old_report, old = inspect(previous)
    if current["scope"] != previous["scope"]:
        raise ValueError("scope changed; snapshots are not directly comparable")
    if not old_report["baseline_eligible"]:
        raise ValueError("previous snapshot does not meet the complete baseline contract")
    current_at = timestamp(current["checked_at"], "checked_at")
    previous_at = timestamp(previous["checked_at"], "checked_at")
    if current_at < previous_at:
        raise ValueError("current snapshot is older than the previous baseline")

    observed_ids = {i["id"] for i in current["issues"]}
    unresolved_ids = set(report["unresolved_issue_ids"])
    inventory_complete = current.get("coverage", {}).get("inventory") == "complete"
    missing_now = old.keys() - now.keys()
    uncertain_exits = {key for key in missing_now
                       if key in unresolved_ids or (key not in observed_ids and not inventory_complete)}
    unverified_now = {key for key in old.keys() & now.keys() if now[key]["classification"] == "unverified"}
    uncertain = uncertain_exits | unverified_now
    before_flags = set(old_report["follow_up_ids"])
    now_flags = set(report["follow_up_ids"])
    report["delta_is_complete"] = report["baseline_eligible"]
    report["delta"] = {
        "entered_scope": sorted(now.keys() - old.keys()),
        "left_scope": sorted(missing_now - uncertain_exits),
        "newly_flagged": sorted(now_flags - before_flags),
        "left_follow_up": [{"id": key, "now": now[key]["classification"] if key in now else "out_of_scope"}
                           for key in sorted(before_flags - now_flags - uncertain)],
        "unverified_since_baseline": sorted(uncertain),
        "assignee_changes": [{"id": key, "before": old[key]["assignee"], "now": now[key]["assignee"]}
                             for key in sorted(old.keys() & now.keys())
                             if "assignee" in now[key]
                             and (now[key]["assignee"] is None or nonblank(now[key]["assignee"]))
                             and old[key]["assignee"] != now[key]["assignee"]],
        "routing_gap_changes": [{"id": key, "before": old[key]["routing_gap"], "now": now[key]["routing_gap"]}
                                for key in sorted(old.keys() & now.keys())
                                if now[key]["classification"] != "unverified"
                                and old[key]["routing_gap"] != now[key]["routing_gap"]],
        "classification_changes": [{"id": key, "before": old[key]["classification"], "now": now[key]["classification"]}
                                   for key in sorted(old.keys() & now.keys())
                                   if old[key]["classification"] != now[key]["classification"]],
    }
    return report


def self_test():
    def scope(**changes):
        return {"key": "test", "priorities": [1], "assigned_only": False,
                "include_archived": False, **changes}

    def issue(key, classification="no_pickup", **changes):
        return {"id": key, "priority": 1, "archived_at": None,
                "status": "Backlog", "status_type": "backlog", "assignee": "user-owner",
                "classification": classification, "reason": "checked",
                "routing_gap": classification == "routing_gap" or changes.get("assignee", "user-owner") is None,
                **({"pending_step": "patch_verification"} if classification == "pending_validation" else {}),
                "checks": {k: "complete" for k in ISSUE_CHECKS},
                "evidence": [{"url": "https://example.test/issues/fixture",
                              "at": "2026-08-17T18:00:00Z",
                              "summary": "Fictional observation supporting the declared review."}], **changes}

    def snap(rows, **changes):
        return {"schema_version": 3, "checked_at": "2026-08-18T19:30:00Z", "scope": scope(),
                "coverage": {k: "complete" for k in REQUIRED}, "issues": rows, **changes}

    class Tests(unittest.TestCase):
        def test_scope_and_counts(self):
            r = compare(snap([issue("A"), issue("B", assignee=None),
                              issue("C", status_type="completed"), issue("D", priority=2)]))
            self.assertEqual((r["counts"]["inventory_selected"], r["counts"]["eligible"],
                              r["counts"]["unassigned_unfinished"]), (3, 2, 1))

        def test_partial_is_not_negative_evidence(self):
            r = compare(snap([issue("A", checks={})]))
            self.assertEqual(r["follow_up_ids"], [])
            self.assertFalse(r["baseline_eligible"])

        def test_pickup_and_owner_change(self):
            r = compare(snap([issue("A", "active", assignee="user-responder"), issue("B")]), snap([issue("A")]))
            self.assertEqual(r["delta"]["newly_flagged"], ["B"])
            self.assertEqual(r["delta"]["left_follow_up"], [{"id": "A", "now": "active"}])
            self.assertEqual(r["delta"]["assignee_changes"][0]["now"], "user-responder")

        def test_incomplete_baseline_rejected(self):
            with self.assertRaises(ValueError):
                compare(snap([]), snap([], coverage={}))

        def test_duplicate_ids_rejected(self):
            with self.assertRaises(ValueError):
                compare(snap([issue("A"), issue("A")]))

        def test_scope_change_rejected(self):
            with self.assertRaises(ValueError):
                compare(snap([], scope=scope(key="other", assigned_only=True)), snap([]))

        def test_assigned_only(self):
            r = compare(snap([issue("A"), issue("B", assignee=None)], scope=scope(assigned_only=True)))
            self.assertEqual(r["follow_up_ids"], ["A"])
            self.assertEqual(r["counts"]["unassigned_unfinished"], 1)

        def test_older_snapshot_rejected(self):
            with self.assertRaises(ValueError):
                compare(snap([], checked_at="2026-08-17T19:30:00Z"), snap([]))

        # Additional boundary coverage for false-confidence and contract gaps.
        def test_scope_priority_list_is_required_and_exact(self):
            for priorities in (None, [], [True], [False], [1.0], ["1"], [-1], [5], [1, 1]):
                with self.subTest(priorities=priorities), self.assertRaises(ValueError):
                    compare(snap([], scope=scope(priorities=priorities)))

        def test_multiple_priorities_include_unset_without_label_inference(self):
            r = compare(snap([issue("A", priority=0), issue("B", priority={"value": 2}),
                              issue("C", priority=1, title="P0", labels=["P0"])],
                             scope=scope(priorities=[0, 2])))
            self.assertEqual(r["follow_up_ids"], ["A", "B"])
            self.assertEqual(r["counts"]["inventory_selected"], 2)

        def test_unknown_and_noninteger_priorities_are_unresolved(self):
            for priority in (None, True, False, 1.0, "1", {}, {"value": True}, 5):
                with self.subTest(priority=priority):
                    r = compare(snap([issue("A", priority=priority)]))
                    self.assertEqual(r["unresolved_issue_ids"], ["A"])
                    self.assertEqual(r["counts"]["inventory_selected"], 0)
                    self.assertFalse(r["baseline_eligible"])

        def test_missing_archive_state_is_not_known_unarchived(self):
            row = issue("A")
            del row["archived_at"]
            r = compare(snap([row]))
            self.assertEqual(r["unresolved_issue_ids"], ["A"])
            self.assertEqual(r["counts"]["inventory_selected"], 0)
            self.assertFalse(r["baseline_eligible"])

        def test_invalid_archive_state_is_unresolved(self):
            for archived_at in (False, "", "unknown", "2026-08-18T18:00:00"):
                with self.subTest(archived_at=archived_at):
                    r = compare(snap([issue("A", archived_at=archived_at)]))
                    self.assertEqual(r["unresolved_issue_ids"], ["A"])
                    self.assertFalse(r["baseline_eligible"])

        def test_explicit_archived_scope_is_honored(self):
            row = issue("A", archived_at="2026-08-18T18:00:00Z")
            self.assertEqual(compare(snap([row]))["counts"]["eligible"], 0)
            included = compare(snap([row], scope=scope(include_archived=True)))
            self.assertEqual(included["follow_up_ids"], ["A"])
            self.assertTrue(included["baseline_eligible"])
            with self.assertRaises(ValueError):
                compare(snap([], scope=scope(include_archived=1)))

        def test_missing_state_never_counts_as_unfinished(self):
            row = issue("A")
            del row["status_type"]
            r = compare(snap([row]))
            self.assertEqual(r["counts"]["inventory_selected"], 1)
            self.assertEqual(r["counts"]["unfinished"], 0)
            self.assertEqual(r["unresolved_issue_ids"], ["A"])
            self.assertFalse(r["baseline_eligible"])

        def test_state_names_do_not_override_typed_state(self):
            r = compare(snap([issue("A", status="Done", status_type="started"),
                              issue("B", status="Backlog", status_type="canceled")]))
            self.assertEqual(r["follow_up_ids"], ["A"])
            for unknown in (None, "", "done", "duplicate", "cancelled", "custom"):
                with self.subTest(status_type=unknown):
                    r = compare(snap([issue("A", status_type=unknown)]))
                    self.assertEqual(r["counts"]["unfinished"], 0)
                    self.assertFalse(r["baseline_eligible"])

        def test_missing_assignment_is_not_unassigned(self):
            row = issue("A")
            del row["assignee"]
            r = compare(snap([row, issue("B", assignee=None)]))
            self.assertEqual(r["counts"]["unfinished"], 2)
            self.assertEqual(r["counts"]["unassigned_unfinished"], 1)
            self.assertEqual(r["counts"]["assignment_unknown_unfinished"], 1)
            self.assertEqual(r["counts"]["by_classification"], {"no_pickup": 1, "unverified": 1})
            self.assertFalse(r["baseline_eligible"])
            r = compare(snap([row], scope=scope(assigned_only=True)))
            self.assertEqual(r["counts"]["eligible"], 0)
            self.assertEqual(r["unresolved_issue_ids"], ["A"])
            self.assertFalse(r["baseline_eligible"])

        def test_invalid_assignment_is_not_a_person_or_unassigned(self):
            for assignee in ("", " ", False, 0, {}, []):
                with self.subTest(assignee=assignee):
                    r = compare(snap([issue("A", assignee=assignee)]))
                    self.assertEqual(r["counts"]["assigned_unfinished"], 0)
                    self.assertEqual(r["counts"]["unassigned_unfinished"], 0)
                    self.assertFalse(r["baseline_eligible"])

        def test_every_classification_needs_checks_reason_and_evidence(self):
            for classification in sorted(CLASSES - {"unverified"}):
                for change in ({"checks": {}}, {"checks": []}, {"reason": " "},
                               {"reason": 1}, {"evidence": []}, {"evidence": [{}]},
                               {"evidence": [{"url": " "}]}, {"evidence": "checked"}):
                    with self.subTest(classification=classification, change=change):
                        r = compare(snap([issue("A", classification, **change)]))
                        self.assertEqual(r["counts"]["by_classification"], {"unverified": 1})
                        self.assertEqual(r["follow_up_ids"], [])
                        self.assertFalse(r["baseline_eligible"])

        def test_explicit_unverified_never_forms_a_baseline(self):
            incomplete = snap([issue("A", "unverified")])
            self.assertFalse(compare(incomplete)["baseline_eligible"])
            with self.assertRaises(ValueError):
                compare(snap([]), incomplete)

        def test_known_out_of_scope_rows_need_no_engagement_evidence(self):
            rows = [{"id": "A", "priority": 2},
                    {"id": "B", "priority": 1, "archived_at": None, "status_type": "completed"},
                    {"id": "C", "priority": 1, "archived_at": "2026-08-18T18:00:00Z"}]
            r = compare(snap(rows))
            self.assertEqual(r["counts"]["inventory_selected"], 1)
            self.assertEqual(r["counts"]["eligible"], 0)
            self.assertTrue(r["baseline_eligible"])

        def test_full_source_filter_scope_is_compared(self):
            old = snap([], scope=scope(source_url="https://example.test/view", filters={"labels": ["a"]}))
            new = snap([], scope=scope(source_url="https://example.test/view", filters={"labels": ["b"]}))
            with self.assertRaises(ValueError):
                compare(new, old)
            self.assertEqual(compare(old)["scope"], old["scope"])

        def test_partial_inventory_absence_is_not_an_exit(self):
            r = compare(snap([], coverage={"inventory": "partial"}), snap([issue("A")]))
            self.assertFalse(r["delta_is_complete"])
            self.assertEqual(r["delta"]["left_scope"], [])
            self.assertEqual(r["delta"]["left_follow_up"], [])
            self.assertEqual(r["delta"]["unverified_since_baseline"], ["A"])

        def test_observed_terminal_exit_is_not_called_a_verified_fix(self):
            r = compare(snap([issue("A", status_type="completed")], coverage={"inventory": "partial"}),
                        snap([issue("A")]))
            self.assertEqual(r["delta"]["left_scope"], ["A"])
            self.assertEqual(r["delta"]["left_follow_up"], [{"id": "A", "now": "out_of_scope"}])
            self.assertNotIn("fixed", r["counts"])
            self.assertNotIn("fixed", r["delta"])
            self.assertFalse(r["delta_is_complete"])

        def test_unknown_state_is_not_an_exit(self):
            r = compare(snap([issue("A", status_type=None)]), snap([issue("A")]))
            self.assertEqual(r["delta"]["left_scope"], [])
            self.assertEqual(r["delta"]["left_follow_up"], [])
            self.assertEqual(r["delta"]["unverified_since_baseline"], ["A"])

        def test_incomplete_positive_evidence_does_not_show_pickup(self):
            r = compare(snap([issue("A", "active", evidence=[])]), snap([issue("A")]))
            self.assertEqual(r["delta"]["left_follow_up"], [])
            self.assertEqual(r["delta"]["unverified_since_baseline"], ["A"])
            self.assertEqual(r["delta"]["classification_changes"][0]["now"], "unverified")

        def test_missing_assignment_does_not_show_owner_removal(self):
            row = issue("A")
            del row["assignee"]
            r = compare(snap([row]), snap([issue("A")]))
            self.assertEqual(r["delta"]["assignee_changes"], [])
            self.assertEqual(r["delta"]["unverified_since_baseline"], ["A"])

        def test_complete_inventory_absence_can_show_scope_exit(self):
            r = compare(snap([]), snap([issue("A")]))
            self.assertEqual(r["delta"]["left_scope"], ["A"])
            self.assertEqual(r["delta"]["unverified_since_baseline"], [])
            self.assertTrue(r["delta_is_complete"])

        def test_schema_and_ids_are_not_coerced(self):
            for version in (1, 2, True, 3.0, "3", None):
                with self.subTest(version=version), self.assertRaises(ValueError):
                    compare(snap([], schema_version=version))
            for key in (None, True, 1, "", " ", []):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    compare(snap([issue(key)]))
            r = compare(snap([issue("001"), issue("a"), issue("A")]))
            self.assertEqual(r["follow_up_ids"], ["001", "A", "a"])

        def test_inputs_are_not_mutated(self):
            current, previous = snap([issue("A", checks={})]), snap([issue("A")])
            before = json.dumps([current, previous], sort_keys=True)
            compare(current, previous)
            self.assertEqual(json.dumps([current, previous], sort_keys=True), before)

        def test_active_work_does_not_hide_routing_gap(self):
            for assignee in (None, "user-owner"):
                with self.subTest(assignee=assignee):
                    current = snap([issue("A", "active", assignee=assignee, routing_gap=True)])
                    r = compare(current, snap([issue("A")]))
                    self.assertEqual(r["follow_up_ids"], ["A"])
                    self.assertEqual(r["routing_gap_ids"], ["A"])
                    self.assertEqual(r["counts"]["follow_up"], 1)
                    self.assertEqual(r["counts"]["by_classification"], {"active": 1})
                    self.assertEqual(r["delta"]["left_follow_up"], [])
                    self.assertTrue(r["baseline_eligible"])

        def test_cleared_routing_gap_can_leave_follow_up_without_new_engagement(self):
            r = compare(snap([issue("A", "active", routing_gap=False)]),
                        snap([issue("A", "active", routing_gap=True)]))
            self.assertEqual(r["routing_gap_ids"], [])
            self.assertEqual(r["delta"]["left_follow_up"], [{"id": "A", "now": "active"}])
            self.assertEqual(r["delta"]["classification_changes"], [])
            self.assertEqual(r["delta"]["routing_gap_changes"], [{"id": "A", "before": True, "now": False}])

        def test_routing_contract_is_explicit_and_consistent(self):
            rows = [issue("A", "active", routing_gap=value) for value in (None, "true", 1)]
            rows += [issue("A", "active", assignee=None, routing_gap=False),
                     issue("A", "routing_gap", routing_gap=False)]
            missing = issue("A", "active")
            del missing["routing_gap"]
            for row in rows + [missing]:
                with self.subTest(row=row):
                    r = compare(snap([row]), snap([issue("A")]))
                    self.assertFalse(r["baseline_eligible"])
                    self.assertEqual(r["delta"]["left_follow_up"], [])
                    self.assertEqual(r["delta"]["unverified_since_baseline"], ["A"])

        def test_incomplete_evidence_cannot_support_routing_follow_up(self):
            for gap in (True, False):
                with self.subTest(routing_gap=gap):
                    r = compare(snap([issue("A", "active", routing_gap=gap, evidence=[])]),
                                snap([issue("A", "active", routing_gap=True)]))
                    self.assertEqual(r["routing_gap_ids"], [])
                    self.assertEqual(r["follow_up_ids"], [])
                    self.assertEqual(r["delta"]["routing_gap_changes"], [])
                    self.assertEqual(r["delta"]["left_follow_up"], [])
                    self.assertFalse(r["baseline_eligible"])

        def test_evidence_needs_source_observation_time_and_supporting_fact(self):
            base = issue("A")["evidence"][0]
            for field in ("url", "at", "summary"):
                for value in (None, "", " "):
                    with self.subTest(field=field, value=value):
                        r = compare(snap([issue("A", "active", evidence=[{**base, field: value}])]),
                                    snap([issue("A")]))
                        self.assertFalse(r["baseline_eligible"])
                        self.assertEqual(r["delta"]["left_follow_up"], [])

        def test_source_link_shape_is_checked_without_access(self):
            for url in ("not-a-url", "https://", "https://example.test:bad/path",
                        "https://user:secret@example.test/path", "https://example.test/has space"):
                with self.subTest(url=url):
                    row = issue("A")
                    row["evidence"][0]["url"] = url
                    self.assertFalse(compare(snap([row]))["baseline_eligible"])
            for url in ("https://example.test/issues/fixture", "file:///synthetic/review.json"):
                with self.subTest(url=url):
                    row = issue("A")
                    row["evidence"][0]["url"] = url
                    self.assertTrue(compare(snap([row]))["baseline_eligible"])

        def test_invalid_or_future_evidence_times_are_unverified(self):
            valid = issue("A", last_substantive_activity_at="2026-08-17T19:00:00+02:00")
            valid["evidence"][0].update(at="2026-08-17T20:00:00+02:00", event_at="2026-08-17T17:00:00Z")
            self.assertTrue(compare(snap([valid]))["baseline_eligible"])
            for field, value in (("at", "not-a-date"), ("at", "2026-08-17T18:00:00"),
                                 ("at", "2026-08-19T00:00:00Z"),
                                 ("event_at", "not-a-date"), ("event_at", "2026-08-18T00:00:00Z")):
                with self.subTest(field=field, value=value):
                    row = issue("A", "active")
                    row["evidence"][0][field] = value
                    r = compare(snap([row]), snap([issue("A")]))
                    self.assertFalse(r["baseline_eligible"])
                    self.assertEqual(r["delta"]["left_follow_up"], [])
            for activity in ("not-a-date", "2026-08-17T18:00:00", "2026-08-19T00:00:00Z"):
                with self.subTest(activity=activity):
                    self.assertFalse(compare(snap([issue("A", last_substantive_activity_at=activity)]))["baseline_eligible"])

        def test_pending_validation_names_the_remaining_step(self):
            for step in PENDING_STEPS:
                with self.subTest(step=step):
                    self.assertTrue(compare(snap([issue("A", "pending_validation", pending_step=step)]))["baseline_eligible"])
            for step in (None, "", "done", [], 1):
                with self.subTest(step=step):
                    r = compare(snap([issue("A", "pending_validation", pending_step=step)]), snap([issue("A")]))
                    self.assertFalse(r["baseline_eligible"])
                    self.assertEqual(r["delta"]["left_follow_up"], [])

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current", nargs="?")
    parser.add_argument("--previous")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.current:
        parser.error("current snapshot is required")
    try:
        with open(args.current, encoding="utf-8") as f:
            current = json.load(f)
        previous = None
        if args.previous:
            with open(args.previous, encoding="utf-8") as f:
                previous = json.load(f)
        print(json.dumps(compare(current, previous), indent=2, ensure_ascii=False))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"Invalid snapshot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
