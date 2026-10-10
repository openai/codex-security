from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from test_workbench_db import budget_scan_fixture, complete_budget_scan
from workbench_test_support import BUDGET_COST, SCRIPT, run_workbench, write_completed_contract


@pytest.mark.parametrize("variant", ["deduplicated", "distinct", "invalid"])
def test_budget_completion_retains_each_confirmed_candidate_identity(
    tmp_path: Path, workbench_api: dict[str, Any], variant: str
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    first_candidate = json.loads(ledger.read_text())
    second_candidate = {**first_candidate, "candidate_id": "candidate-two"}
    ledger.write_text(
        "\n".join(json.dumps(row) for row in [first_candidate, second_candidate]) + "\n"
    )
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    first = findings["findings"][0]
    first["provenance"]["candidateId"] = first_candidate["candidate_id"]
    second = json.loads(json.dumps(first))
    second["provenance"]["candidateId"] = second_candidate["candidate_id"]
    second["severity"]["level"] = "low"
    if variant == "distinct":
        second["identity"]["instance"] = "second-instance"
    elif variant == "invalid":
        second.pop("ruleId")
    findings["findings"] = [first, second]
    findings_path.write_text(json.dumps(findings))

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    workbench_api["budget_exhausted_draft"](
        scan, scan_dir, [first_candidate, second_candidate], "Synthetic budget stop."
    )
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert {row["candidateId"] for row in coverage["deferred"] if row.get("candidateId")} == (
        {second_candidate["candidate_id"]} if variant == "invalid" else set()
    )


@pytest.mark.parametrize(
    ("reopened", "decision", "expected_disposition"),
    [
        (True, "deferred", "needs_follow_up"),
        (False, "deferred", "reported"),
        (True, "suppressed", "rejected"),
        (True, "not_applicable", "not_applicable"),
    ],
)
def test_budget_completion_uses_current_candidate_state_after_finding_reopens(
    tmp_path: Path, reopened: bool, decision: str, expected_disposition: str
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": decision}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"][0]["provenance"].update(
        candidateId=candidate["candidate_id"], candidateReopened=reopened
    )
    findings_path.write_text(json.dumps(findings))
    surface = {
        "id": "candidate-review",
        "candidateId": candidate["candidate_id"],
        "label": "Current candidate review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    pending = {
        "id": "candidate-proof-gap",
        "candidateId": candidate["candidate_id"],
        "candidate": candidate,
        "reason": "Current proof gap still needs validation.",
        "surfaceIds": [surface["id"]],
    }
    other_surface = {**surface, "id": "other-owner-review", "sourceWorkerId": "worker-other"}
    other_pending = {
        **pending,
        "id": "other-owner-proof-gap",
        "sourceWorkerId": "worker-other",
        "reason": "Independent proof gap for another worker.",
        "surfaceIds": [other_surface["id"]],
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(
        completeness="partial",
        surfaces=[surface, other_surface],
        deferred=[pending, other_pending],
    )
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    saved = json.loads(coverage_path.read_text())
    still_pending = expected_disposition == "needs_follow_up"
    assert (pending in saved["deferred"]) is still_pending
    retained = next(row for row in saved["surfaces"] if row["id"] == surface["id"])
    assert retained["disposition"] == expected_disposition
    assert other_pending in saved["deferred"]
    assert other_surface in saved["surfaces"]
    assert completed["progress"]["status"] == "complete"
    assert completed["progress"]["candidates"]["unresolved"] == 1 + int(still_pending)


@pytest.mark.parametrize(
    "decision",
    [
        "reported",
        "suppressed",
        "not_applicable",
        "ignore",
        "deferred",
        "other-owner",
        "existing-terminal",
    ],
)
def test_budget_exhaustion_reconciles_saved_candidate_rows_without_losing_other_work(
    tmp_path: Path, decision: str
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    previous = {**candidate, "context": "Saved source context."}
    if decision == "ignore":
        candidate["attack_path"] = {"decision": "ignore"}
    else:
        candidate["validation"] = {
            "disposition": "reportable"
            if decision in {"reported", "other-owner", "existing-terminal"}
            else decision
        }
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    if decision in {"reported", "other-owner"}:
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        findings["findings"][0]["provenance"]["candidateId"] = candidate["candidate_id"]
        if decision == "other-owner":
            findings["findings"][0]["provenance"]["sourceWorkerId"] = "worker-other"
        findings_path.write_text(json.dumps(findings))
    surface = {
        "id": "candidate-candidate-1",
        "candidateId": candidate["candidate_id"],
        "label": "Authored candidate review",
        "disposition": "needs_follow_up",
        "notes": "Saved authored evidence.",
        "receiptRefs": [],
        "reviewContext": "Keep this annotation.",
    }
    if decision == "existing-terminal":
        surface["disposition"] = "rejected"
    shared = {**surface, "id": "shared-review", "sourceWorkerId": " "}
    other_owner = {
        **surface,
        "id": "other-owner-review",
        "sourceWorkerId": "worker-other",
        "disposition": "needs_follow_up",
    }
    generic = {
        "id": "general-review",
        "reason": "Independent unfinished review.",
        "surfaceIds": [shared["id"]],
    }
    independent = {
        "id": "other-owner-candidate",
        "candidateId": candidate["candidate_id"],
        "sourceWorkerId": "worker-other",
        "reason": "A different worker's unfinished review.",
        "surfaceIds": [other_owner["id"]],
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"] = [surface, shared, other_owner]
    coverage["deferred"] = [
        {
            "id": "candidate-1",
            "candidateId": candidate["candidate_id"],
            "candidate": previous,
            "reason": "Authored unresolved evidence.",
            "surfaceIds": [surface["id"]],
        },
        generic,
        independent,
    ]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    preserved = json.loads(coverage_path.read_text())
    assert generic in preserved["deferred"]
    assert independent in preserved["deferred"]
    assert shared in preserved["surfaces"]
    assert other_owner in preserved["surfaces"]
    expected_disposition = {
        "reported": "reported",
        "suppressed": "rejected",
        "not_applicable": "not_applicable",
        "ignore": "rejected",
        "deferred": "needs_follow_up",
        "other-owner": "needs_follow_up",
        "existing-terminal": "rejected",
    }[decision]
    retained = next(row for row in preserved["surfaces"] if row["id"] == surface["id"])
    assert retained["disposition"] == expected_disposition
    assert retained["notes"] == surface["notes"]
    assert retained["reviewContext"] == surface["reviewContext"]
    pending = [
        row
        for row in preserved["deferred"]
        if row.get("candidateId") == candidate["candidate_id"] and not row.get("sourceWorkerId")
    ]
    assert bool(pending) is (decision in {"deferred", "other-owner"})
    assert completed["progress"]["candidates"]["unresolved"] == (2 if decision == "deferred" else 1)
    if decision in {"deferred", "other-owner"}:
        assert pending[0] == coverage["deferred"][0]
    else:
        assert retained["candidate"] == {**previous, **candidate}


@pytest.mark.parametrize("decision", ["reported", "suppressed", "not_applicable"])
@pytest.mark.parametrize("saved_payload", ["finding", "previousFindings"])
@pytest.mark.parametrize("newer_phase", [False, True])
def test_budget_exhaustion_retains_original_deferred_finding_evidence(
    tmp_path: Path, decision: str, saved_payload: str, newer_phase: bool
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "reportable" if decision == "reported" else decision}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    original = dict(findings["findings"][0])
    original["summary"] = "Original detailed finding evidence from the deferred review."
    original["evidence"] = {"context": "Additional synthetic source review evidence."}
    if decision == "reported":
        findings["findings"][0]["provenance"]["candidateId"] = candidate["candidate_id"]
    else:
        findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [
        {
            "id": "pending-candidate",
            "candidateId": candidate["candidate_id"],
            "candidate": candidate,
            saved_payload: [original] if saved_payload == "previousFindings" else original,
            "reason": "Authored review gap.",
        }
    ]
    coverage_path.write_text(json.dumps(coverage))

    if newer_phase:
        candidate["validation"]["counterevidence_or_proof_gap"] = "Later review resolved the gap."
        ledger.write_text(json.dumps(candidate) + "\n")
    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    still_pending = decision != "reported" and not newer_phase
    assert completed["progress"]["candidates"]["unresolved"] == int(still_pending)
    preserved = json.loads(coverage_path.read_text())
    pending = [
        row for row in preserved["deferred"] if row.get("candidateId") == candidate["candidate_id"]
    ]
    assert bool(pending) is still_pending
    if still_pending:
        assert pending[0] == coverage["deferred"][0]
    else:
        surface = next(
            row
            for row in preserved["surfaces"]
            if row.get("candidateId") == candidate["candidate_id"]
        )
        assert original in surface["previousFindings"]


@pytest.mark.parametrize("decision", ["suppressed", "deferred"])
def test_budget_exhaustion_preserves_shared_reported_surface(tmp_path: Path, decision: str) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": decision}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    shared = {
        "id": "shared-reported",
        "candidateId": candidate["candidate_id"],
        "label": "Shared reviewed surface",
        "disposition": "reported",
        "notes": "This surface includes a confirmed finding and another candidate.",
        "receiptRefs": [],
    }
    coverage.update(surfaces=[shared], deferred=[])
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["findingCount"] == 1
    preserved = json.loads(coverage_path.read_text())
    assert shared in preserved["surfaces"]
    candidate_surfaces = [
        row
        for row in preserved["surfaces"]
        if row["id"] != shared["id"] and row.get("candidateId") == candidate["candidate_id"]
    ]
    assert len(candidate_surfaces) == 1
    assert candidate_surfaces[0]["disposition"] == (
        "rejected" if decision == "suppressed" else "needs_follow_up"
    )
    assert completed["progress"]["candidates"]["unresolved"] == int(decision == "deferred")


@pytest.mark.parametrize("malformed", [{"surfaceIds": None}, {"id": {}}])
def test_budget_exhaustion_keeps_failure_recovery_for_malformed_coverage(
    tmp_path: Path, malformed: dict[str, Any]
) -> None:
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    invalid = {"id": "malformed-review", "reason": "Unrelated saved review.", **malformed}
    coverage["deferred"] = [invalid]
    coverage_path.write_text(json.dumps(coverage))

    result = complete_budget_scan(state_dir, scan_id, check=False)

    assert result["returncode"] != 0
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["findingCount"] == 1
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    assert invalid not in json.loads(coverage_path.read_text())["deferred"]


@pytest.mark.parametrize("disposition", [{}, []])
def test_budget_exhaustion_preserves_structured_exclusion_extensions(
    tmp_path: Path, disposition: Any
) -> None:
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, candidates=[])
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    exclusion = {
        "pattern": "synthetic-exclusion/**",
        "reason": "Unrelated scope exclusion.",
        "disposition": disposition,
    }
    coverage["explicitExclusions"] = [exclusion]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert exclusion in json.loads(coverage_path.read_text())["explicitExclusions"]
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]


def test_budget_exhaustion_retains_ledger_candidate_when_recovering_nonobject_surface(
    tmp_path: Path,
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"].append(None)
    generic = {
        "id": "general-review",
        "reason": "Unrelated review remains pending.",
        "surfaceIds": [coverage["surfaces"][0]["id"]],
    }
    coverage["deferred"] = [generic]
    coverage_path.write_text(json.dumps(coverage))

    result = complete_budget_scan(state_dir, scan_id, check=False)

    assert result["returncode"] != 0
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["findingCount"] == 1
    assert scan["progress"]["candidates"]["unresolved"] == 1
    recovered = json.loads(coverage_path.read_text())
    assert generic in recovered["deferred"]
    pending = next(row for row in recovered["deferred"] if row.get("candidateId"))
    assert pending["candidate"] == candidate
    assert None not in recovered["surfaces"]
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]


def test_budget_candidate_projection_preserves_owner_references_and_unique_ids_at_scale(
    workbench_api,
) -> None:
    candidates = [
        {
            "candidate_id": f"synthetic-{index}",
            "summary": "Synthetic candidate review.",
            "evidence": "Synthetic source context.",
            "locations": [{"path": "app.py"}],
        }
        for index in range(1000)
    ]
    shared = {
        "id": "shared-surface",
        "candidateId": candidates[0]["candidate_id"],
        "disposition": "needs_follow_up",
        "notes": "Keep shared evidence.",
    }
    worker = {**shared, "sourceWorkerId": "worker-other"}
    generic = {"id": "generic-review", "surfaceIds": [shared["id"]]}
    collision = {"id": "candidate-synthetic-1", "notes": "Unrelated coverage."}
    coverage = {
        "surfaces": [shared, worker, collision],
        "deferred": [generic, {"id": "synthetic-1", "reason": "Unrelated review."}],
        "explicitExclusions": [],
    }

    workbench_api["saved_results"].preserve_budget_candidates(coverage, [], candidates)

    assert shared in coverage["surfaces"]
    assert worker in coverage["surfaces"]
    assert collision in coverage["surfaces"]
    assert "candidate" not in shared
    assert "candidate" not in worker
    assert generic in coverage["deferred"]
    pending = [row for row in coverage["deferred"] if row.get("candidateId")]
    assert len(pending) == len(candidates)
    assert {row["candidateId"] for row in pending} == {
        candidate["candidate_id"] for candidate in candidates
    }
    for field in ("surfaces", "deferred"):
        keys = {(row.get("sourceWorkerId"), row["id"]) for row in coverage[field]}
        assert len(keys) == len(coverage[field])
    surface_ids = {row["id"] for row in coverage["surfaces"]}
    assert all(set(row["surfaceIds"]) <= surface_ids for row in pending)


@pytest.mark.parametrize("saved_id", [{}, {"id": None}, {"id": {}}, {"id": " "}])
def test_budget_exhaustion_retains_candidate_when_saved_surface_has_no_usable_id(
    tmp_path: Path, saved_id: dict[str, Any]
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"] = [
        {
            "candidateId": candidate["candidate_id"],
            "label": "Unfinished candidate surface",
            "disposition": "needs_follow_up",
            "notes": "Saved source context.",
            "receiptRefs": [],
            **saved_id,
        }
    ]
    coverage["deferred"] = []
    coverage_path.write_text(json.dumps(coverage))

    result = complete_budget_scan(state_dir, scan_id, check=False)

    assert result["returncode"] != 0
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["findingCount"] == 1
    assert scan["progress"]["candidates"]["unresolved"] == 1
    recovered = json.loads(coverage_path.read_text())
    pending = next(row for row in recovered["deferred"] if row.get("candidateId"))
    assert pending["candidate"] == candidate
    assert pending["surfaceIds"]
    assert set(pending["surfaceIds"]) <= {row["id"] for row in recovered["surfaces"]}
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]


@pytest.mark.parametrize("missing_rule_id", [True, False])
def test_budget_exhaustion_resolves_candidates_only_with_recoverable_findings(
    tmp_path: Path, missing_rule_id: bool
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"]["candidateId"] = candidate["candidate_id"]
    if missing_rule_id:
        finding.pop("ruleId")
    else:
        finding["ruleId"] = "Synthetic Candidate Review"
    findings_path.write_text(json.dumps(findings))
    pending = {
        "id": "saved-candidate-review",
        "candidateId": candidate["candidate_id"],
        "candidate": candidate,
        "reason": "Saved validation gap.",
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [pending]
    coverage_path.write_text(json.dumps(coverage))

    result = complete_budget_scan(state_dir, scan_id, check=False)

    assert result["returncode"] != 0
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["findingCount"] == int(not missing_rule_id)
    assert scan["progress"]["candidates"]["unresolved"] == int(missing_rule_id)
    recovered = json.loads(coverage_path.read_text())
    if missing_rule_id:
        assert pending in recovered["deferred"]
    else:
        assert not any(
            row.get("candidateId") == candidate["candidate_id"] for row in recovered["deferred"]
        )
        assert (
            json.loads(findings_path.read_text())["findings"][0]["ruleId"]
            == "synthetic-candidate-review"
        )
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]


@pytest.mark.parametrize(
    ("saved_kind", "saved_disposition", "ledger_disposition"),
    [
        ("surface", "not_applicable", "suppressed"),
        ("surface", "rejected", "not_applicable"),
        ("exclusion", "not_applicable", "suppressed"),
        ("mixed", "not_applicable", "suppressed"),
        ("other-owner", "not_applicable", "suppressed"),
        ("finding", "not_applicable", "suppressed"),
    ],
)
def test_budget_exhaustion_preserves_authored_terminal_decisions(
    tmp_path: Path, saved_kind: str, saved_disposition: str, ledger_disposition: str
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": ledger_disposition}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    if saved_kind == "finding":
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        findings["findings"][0]["provenance"]["candidateId"] = candidate["candidate_id"]
        findings_path.write_text(json.dumps(findings))
    pending_surface = {
        "id": "pending-review",
        "candidateId": candidate["candidate_id"],
        "label": "Candidate review",
        "disposition": "needs_follow_up",
        "notes": "Review details awaiting reconciliation.",
        "receiptRefs": [],
    }
    authored = {
        **pending_surface,
        "id": "authored-review",
        "disposition": saved_disposition,
        "notes": f"Authored rationale for {saved_disposition}.",
        "reviewContext": "Preserve this annotation.",
    }
    if saved_kind == "other-owner":
        authored["sourceWorkerId"] = "worker-other"
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"] = [pending_surface]
    if saved_kind == "exclusion":
        authored = {
            "pattern": "app.py",
            "candidateId": candidate["candidate_id"],
            "disposition": saved_disposition,
            "reason": authored["notes"],
        }
        coverage["explicitExclusions"] = [authored]
    else:
        coverage["surfaces"].append(authored)
    if saved_kind == "mixed":
        coverage["surfaces"].append(
            {
                **authored,
                "id": "second-review",
                "disposition": "rejected",
                "notes": "Other rationale.",
            }
        )
    original_surfaces = list(coverage["surfaces"])
    coverage["deferred"] = [
        {
            "id": "pending-candidate",
            "candidateId": candidate["candidate_id"],
            "reason": "Unfinished validation.",
            "surfaceIds": [pending_surface["id"]],
        }
    ]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["progress"]["candidates"]["unresolved"] == 0
    assert completed["findingCount"] == 1
    preserved = json.loads(coverage_path.read_text())
    assert not any(
        row.get("candidateId") == candidate["candidate_id"] for row in preserved["deferred"]
    )
    if saved_kind == "exclusion":
        assert preserved["explicitExclusions"] == [authored]
    for original in original_surfaces:
        retained = next(row for row in preserved["surfaces"] if row["id"] == original["id"])
        for field in ("label", "notes", "reviewContext", "sourceWorkerId"):
            assert retained.get(field) == original.get(field)
        if saved_kind == "finding":
            assert retained["disposition"] == "reported"
        elif original["disposition"] != "needs_follow_up":
            assert retained["disposition"] == original["disposition"]
        elif saved_kind == "other-owner":
            assert retained["disposition"] == "rejected"
        elif saved_kind == "mixed":
            assert retained["disposition"] in {"rejected", "not_applicable"}
        else:
            assert retained["disposition"] == saved_disposition


@pytest.mark.parametrize("decision", ["deferred", "reportable", "not_applicable"])
@pytest.mark.parametrize("saved_pending", [False, True])
@pytest.mark.parametrize("started_pending", [False, True])
def test_budget_exhaustion_refreshes_generated_terminal_draft_after_resume(
    tmp_path: Path,
    workbench_api: dict[str, Any],
    decision: str,
    saved_pending: bool,
    started_pending: bool,
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    original = json.loads(ledger.read_text())
    original["validation"] = {"disposition": "deferred" if started_pending else "suppressed"}
    original["context"] = "Retained discovery context."
    run_workbench(state_dir, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "sdk-thread")
    # Leave the real budget writer's output unsealed, as when completion is interrupted.
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        workbench_api["budget_exhausted_draft"](scan, scan_dir, [original], "Cost limit reached.")
        if started_pending:
            assert (
                run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"][
                    "candidates"
                ]["unresolved"]
                == 1
            )
            assert (
                run_workbench(state_dir, "get-cli-scan-resume", "--scan-id", scan_id)["scanId"]
                == scan_id
            )
            original = {
                **original,
                "summary": "Updated terminal review",
                "evidence": "Updated terminal evidence.",
                "validation": {"disposition": "suppressed"},
            }
            workbench_api["budget_exhausted_draft"](
                scan, scan_dir, [original], "Cost limit reached."
            )
            assert (
                run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"][
                    "candidates"
                ]["unresolved"]
                == 0
            )
    resumed = run_workbench(state_dir, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["scanId"] == scan_id
    assert "sealedProducerVersion" not in resumed

    candidate = {
        **original,
        "summary": "Updated candidate review",
        "evidence": "Current review evidence.",
        "validation": {"disposition": decision},
    }
    candidate.pop("context")
    if decision == "reportable":
        candidate["attack_path"] = {"decision": "reportable"}
    ledger.write_text(json.dumps(candidate) + "\n")
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    surface = coverage["surfaces"][0]
    surface["reviewContext"] = "Keep this independent annotation."
    other_owner = {**surface, "id": "other-owner-review", "sourceWorkerId": "worker-other"}
    coverage["surfaces"].append(other_owner)
    generic = {
        "id": "shared-review",
        "reason": "Independent unfinished work on the same surface.",
        "surfaceIds": [surface["id"]],
    }
    coverage["deferred"].append(generic)
    if saved_pending:
        coverage["deferred"].append(
            {
                "id": "pending-candidate",
                "candidateId": candidate["candidate_id"],
                "candidate": candidate,
                "reason": "Saved review gap.",
                "surfaceIds": [surface["id"]],
            }
        )
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 0
    still_pending = saved_pending or decision != "not_applicable"
    assert completed["progress"]["candidates"]["unresolved"] == int(still_pending)
    preserved = json.loads(coverage_path.read_text())
    assert generic in preserved["deferred"]
    assert other_owner in preserved["surfaces"]
    refreshed = next(row for row in preserved["surfaces"] if row["id"] == surface["id"])
    assert refreshed["disposition"] == ("needs_follow_up" if still_pending else "not_applicable")
    assert refreshed["label"] == candidate["summary"]
    assert refreshed["notes"] == candidate["evidence"]
    assert refreshed["reviewContext"] == surface["reviewContext"]
    assert refreshed["candidate"] == {**candidate, "context": original["context"]}
    pending = [
        row for row in preserved["deferred"] if row.get("candidateId") == candidate["candidate_id"]
    ]
    assert bool(pending) is still_pending


@pytest.mark.parametrize("edited_field", [None, "reason", "paths", "surfaceIds", "candidate"])
def test_budget_exhaustion_refreshes_generated_pending_evidence_after_resume(
    tmp_path: Path, workbench_api: dict[str, Any], edited_field: str | None
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(
        tmp_path,
        extra_files={
            "authored.py": "# authored review location\n",
            "updated.py": "# current candidate location\n",
        },
    )
    original = {
        **json.loads(ledger.read_text()),
        "context": "Retained discovery context.",
        "validation": {"disposition": "deferred"},
    }
    run_workbench(state_dir, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "sdk-thread")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        workbench_api["budget_exhausted_draft"](scan, scan_dir, [original], "Cost limit reached.")
    assert (
        run_workbench(state_dir, "get-cli-scan-resume", "--scan-id", scan_id)["scanId"] == scan_id
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    pending = coverage["deferred"][0]
    original_id = pending["id"]
    independent = {
        **pending,
        "id": "independent-worker-review",
        "sourceWorkerId": "worker-other",
    }
    generic = {
        "id": "shared-review",
        "reason": "Independent review remains on the shared surface.",
        "surfaceIds": list(pending["surfaceIds"]),
    }
    coverage["deferred"].extend([independent, generic])
    coverage["surfaces"].append(
        {
            "id": "authored-surface",
            "label": "Authored review",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
    )
    if edited_field is not None:
        pending[edited_field] = {
            "reason": "Authored follow-up reason.",
            "paths": ["authored.py"],
            "surfaceIds": ["authored-surface"],
            "candidate": {**original, "evidence": "Authored evidence."},
        }[edited_field]
    saved_pending = json.loads(json.dumps(pending))
    coverage_path.write_text(json.dumps(coverage))
    current = {
        **original,
        "summary": "Current candidate review",
        "evidence": "Current candidate evidence.",
        "locations": [{"path": "updated.py", "start_line": 1, "end_line": 1, "role": "sink"}],
        "validation": {"disposition": "reportable"},
        "attack_path": {
            "decision": "deferred",
            "proof_gap": "Current reachability remains unknown.",
        },
    }
    current.pop("context")
    ledger.write_text(json.dumps(current) + "\n")

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    preserved = json.loads(coverage_path.read_text())
    assert independent in preserved["deferred"]
    assert generic in preserved["deferred"]
    refreshed = next(row for row in preserved["deferred"] if row["id"] == original_id)
    if edited_field is not None:
        assert refreshed == saved_pending
    else:
        assert refreshed["candidate"] == {**current, "context": original["context"]}
        assert refreshed["paths"] == ["updated.py"]
        assert refreshed["surfaceIds"] == saved_pending["surfaceIds"]
        assert "Current candidate review" in refreshed["reason"]
        assert "Current candidate evidence." in refreshed["reason"]
        report = (scan_dir / "report.md").read_text()
        assert "Current candidate review" in report
        assert "Current candidate evidence." in report


@pytest.mark.parametrize("field", ["label", "notes"])
@pytest.mark.parametrize("started_pending", [False, True])
def test_budget_exhaustion_preserves_authored_changes_to_generated_decisions(
    workbench_api: dict[str, Any], field: str, started_pending: bool
) -> None:
    preserve = workbench_api["saved_results"].preserve_budget_candidates
    candidate = {
        "candidate_id": "candidate-1",
        "summary": "Synthetic candidate",
        "evidence": "Saved review evidence.",
        "locations": [{"path": "app.py"}],
        "validation": {"disposition": "deferred" if started_pending else "not_applicable"},
    }
    coverage = {"surfaces": [], "explicitExclusions": [], "deferred": []}
    preserve(coverage, [], [candidate])
    surface = coverage["surfaces"][0]
    surface[field] = "Authored decision detail."
    if started_pending:
        candidate = {**candidate, "validation": {"disposition": "not_applicable"}}
        preserve(coverage, [], [candidate])

    preserve(coverage, [], [{**candidate, "validation": {"disposition": "deferred"}}])

    assert surface["disposition"] == "not_applicable"
    assert surface[field] == "Authored decision detail."
    assert coverage["deferred"] == []


@pytest.mark.parametrize("original_decision", ["deferred", "suppressed"])
@pytest.mark.parametrize("decision", ["deferred", "suppressed", "not_applicable"])
@pytest.mark.parametrize("edited_field", [None, "label", "notes"])
def test_legacy_budget_surface_reconciles_generated_identity(
    workbench_api: dict[str, Any], original_decision: str, decision: str, edited_field: str | None
) -> None:
    preserve_budget_candidates = workbench_api["saved_results"].preserve_budget_candidates

    candidate = {
        "candidate_id": "legacy-review",
        "summary": "Saved synthetic candidate review",
        "evidence": "Saved synthetic source evidence.",
        "locations": [{"path": "app.py", "startLine": 1}],
        "validation": {"disposition": original_decision},
    }
    # The previous budget writer emitted this ID, label and evidence without a payload.
    surface = {
        "id": "candidate-legacy-review",
        "label": candidate["summary"],
        "disposition": "needs_follow_up" if original_decision == "deferred" else "rejected",
        "notes": candidate["evidence"],
        "receiptRefs": [],
        "annotation": "Retain this saved annotation.",
    }
    if edited_field is not None:
        surface[edited_field] = "Authored review detail remains authoritative."
    original = dict(surface)
    deferred = []
    if original_decision == "deferred":
        deferred.append(
            {
                "id": candidate["candidate_id"],
                "candidateId": candidate["candidate_id"],
                "reason": "Validation was deferred because the scan reached its cost limit: "
                f"{candidate['summary']}. Evidence: {candidate['evidence']}",
                "paths": ["app.py"],
                "surfaceIds": [surface["id"]],
            }
        )
    coverage = {"surfaces": [surface], "explicitExclusions": [], "deferred": deferred}
    updated = {**candidate, "validation": {"disposition": decision}}
    preserve_budget_candidates(coverage, [], [updated])
    retained = next(row for row in coverage["surfaces"] if row["id"] == original["id"])
    if edited_field is not None:
        assert retained == original
        return
    assert len(coverage["surfaces"]) == 1
    assert retained["candidateId"] == candidate["candidate_id"]
    assert retained["disposition"] == (
        "needs_follow_up"
        if decision == "deferred"
        else "not_applicable"
        if decision == "not_applicable"
        else "rejected"
    )
    assert retained["annotation"] == original["annotation"]
    assert retained["candidate"] == updated


@pytest.mark.parametrize("snapshot", ["authored-partial", "generated-complete"])
def test_budget_completion_preserves_authored_partial_candidate_snapshot(
    tmp_path: Path, workbench_api: dict[str, Any], snapshot: str
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    original = json.loads(ledger.read_text())
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        workbench_api["budget_exhausted_draft"](scan, scan_dir, [original], "Cost limit reached.")
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    partial = {field: original[field] for field in ("candidate_id", "summary", "evidence")}
    if snapshot == "authored-partial":
        for field in ("surfaces", "deferred"):
            coverage[field][0]["candidate"] = partial
        coverage["deferred"][0]["reason"] = "Keep the authored proof gap."
        coverage_path.write_text(json.dumps(coverage))
    current = {**original, "summary": "Updated review", "evidence": "Updated source evidence."}
    ledger.write_text(json.dumps(current) + "\n")

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["progress"]["candidates"]["unresolved"] == 1
    restored = json.loads(coverage_path.read_text())
    pending = next(
        row for row in restored["deferred"] if row.get("candidateId") == original["candidate_id"]
    )
    surface = next(
        row for row in restored["surfaces"] if row.get("candidateId") == original["candidate_id"]
    )
    if snapshot == "authored-partial":
        assert pending["candidate"] == partial
        assert pending["reason"] == "Keep the authored proof gap."
        assert surface["candidate"] == partial
        assert surface["label"] == original["summary"]
        assert surface["notes"] == original["evidence"]
    else:
        assert pending["candidate"] == current
        assert surface["candidate"] == current
        assert surface["label"] == current["summary"]
        assert surface["notes"] == current["evidence"]
        assert pending["paths"] == ["app.py"]


@pytest.mark.parametrize("receipt", ["valid", "missing", "unsafe", "blank-label"])
def test_budget_receipts_are_recovered_before_shared_surface_decisions(
    tmp_path: Path, receipt: str
) -> None:
    state, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "deferred"}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    receipt_file = scan_dir / "artifacts/review/receipt.txt"
    receipt_file.parent.mkdir(parents=True, exist_ok=True)
    if receipt == "valid":
        receipt_file.write_text("Synthetic verified review.\n")
    surface = {
        "id": "shared-source-review",
        "candidateId": candidate["candidate_id"],
        "label": "Authored candidate decision",
        "disposition": "rejected",
        "receiptRefs": [
            "../outside.txt" if receipt == "unsafe" else "artifacts/review/receipt.txt"
        ],
    }
    if receipt == "blank-label":
        surface.update(label="", receiptRefs=[])
    pending = {
        "id": "authored-candidate-gap",
        "candidateId": candidate["candidate_id"],
        "reason": "Original source evidence still needs validation.",
        "candidate": {**candidate, "annotation": "Original saved annotation."},
        "surfaceIds": [surface["id"]],
    }
    generic = {
        "id": "generic-review",
        "reason": "Independent review remains.",
        "surfaceIds": [surface["id"]],
    }
    coverage.update(surfaces=[surface], deferred=[pending, generic])
    coverage_path.write_text(json.dumps(coverage))
    completion = complete_budget_scan(state, scan_id, check=False)
    if completion["returncode"]:
        run_workbench(
            state,
            "fail-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Synthetic budget recovery failure.",
        )
    completed = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    saved = json.loads(coverage_path.read_text())
    assert generic in saved["deferred"]
    rows = [row for row in saved["deferred"] if row.get("candidateId") == candidate["candidate_id"]]
    assert bool(rows) is (receipt != "valid")
    assert completed["progress"]["candidates"]["unresolved"] == int(receipt != "valid")
    if rows:
        assert pending in rows
        assert not any(
            row.get("candidateId") == candidate["candidate_id"]
            and row.get("disposition") in {"rejected", "not_applicable"}
            for row in saved["surfaces"]
        )
    else:
        assert any(row["receiptRefs"] == surface["receiptRefs"] for row in saved["surfaces"])


@pytest.mark.parametrize("edited_field", [None, "reason", "paths", "surfaceIds", "candidate"])
def test_budget_generated_dedicated_surface_refresh_keeps_saved_reference_context(
    tmp_path: Path, workbench_api: dict[str, Any], edited_field: str | None
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(
        tmp_path,
        extra_files={"updated.py": "# updated review\n", "authored.py": "# authored review\n"},
    )
    original = {**json.loads(ledger.read_text()), "validation": {"disposition": "suppressed"}}
    run_workbench(state_dir, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "sdk-thread")
    coverage_path = scan_dir / "coverage.json"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        workbench_api["budget_exhausted_draft"](scan, scan_dir, [original], "Cost limit reached.")
        coverage = json.loads(coverage_path.read_text())
        generic = {
            "id": "independent-review",
            "reason": "Keep independent unfinished work.",
            "surfaceIds": [coverage["surfaces"][0]["id"]],
        }
        coverage["deferred"].append(generic)
        coverage_path.write_text(json.dumps(coverage))
        reopened = {**original, "validation": {"disposition": "deferred"}}
        workbench_api["budget_exhausted_draft"](scan, scan_dir, [reopened], "Cost limit reached.")
    coverage = json.loads(coverage_path.read_text())
    pending = next(
        row for row in coverage["deferred"] if row.get("candidateId") == original["candidate_id"]
    )
    generated_ids = [
        row["id"]
        for row in coverage["surfaces"]
        if row.get("candidateId") == original["candidate_id"]
    ]
    assert len(generated_ids) == 2
    assert len(pending["surfaceIds"]) == 1
    coverage["surfaces"].append(
        {
            "id": "authored-review",
            "label": "Independent authored surface",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
    )
    if edited_field is not None:
        pending[edited_field] = {
            "reason": "Authored proof gap.",
            "paths": ["authored.py"],
            "surfaceIds": ["authored-review"],
            "candidate": {**reopened, "evidence": "Authored source evidence."},
        }[edited_field]
    saved = json.loads(json.dumps(pending))
    coverage_path.write_text(json.dumps(coverage))
    current = {
        **reopened,
        "summary": "Current reopened review",
        "evidence": "Current reopened source evidence.",
        "locations": [{"path": "updated.py", "start_line": 1, "end_line": 1, "role": "sink"}],
    }
    ledger.write_text(json.dumps(current) + "\n")
    complete_budget_scan(state_dir, scan_id)
    published = json.loads(coverage_path.read_text())
    assert generic in published["deferred"]
    actual = next(row for row in published["deferred"] if row.get("id") == saved["id"])
    if edited_field is not None:
        assert actual == saved
    else:
        assert actual["candidate"] == current
        assert actual["surfaceIds"] == saved["surfaceIds"]
        assert actual["paths"] == ["updated.py"]
        assert current["evidence"] in actual["reason"]
        assert current["evidence"] in (scan_dir / "report.md").read_text()


@pytest.mark.parametrize("edited_field", [None, "label", "notes"])
@pytest.mark.parametrize("decision", ["suppressed", "not_applicable"])
def test_budget_legacy_saved_pending_surface_refresh_uses_original_evidence(
    tmp_path: Path, edited_field: str | None, decision: str
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    original = {**json.loads(ledger.read_text()), "validation": {"disposition": "deferred"}}
    # This is the canonical row emitted by the previous budget writer.
    surface = {
        "id": f"candidate-{original['candidate_id']}",
        "label": original["summary"],
        "disposition": "needs_follow_up",
        "notes": original["evidence"],
        "receiptRefs": [],
        "annotation": "Keep this original annotation.",
    }
    if edited_field is not None:
        surface[edited_field] = "Authored review detail remains authoritative."
    saved_surface = dict(surface)
    pending = {
        "id": original["candidate_id"],
        "candidateId": original["candidate_id"],
        "reason": f"Validation was deferred because the scan reached its cost limit: {original['summary']}. Evidence: {original['evidence']}",
        "paths": [row["path"] for row in original["locations"]],
        "surfaceIds": [surface["id"]],
    }
    current = {
        **original,
        "summary": "Updated legacy review",
        "evidence": "Updated legacy source evidence.",
        "validation": {"disposition": decision},
    }
    ledger.write_text(json.dumps(current) + "\n")
    target = tmp_path / "target"
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"].pop("sealedAt", None)
    manifest["scan"].pop("artifacts", None)
    manifest_path.write_text(json.dumps(manifest))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(completeness="partial", surfaces=[surface], deferred=[pending])
    coverage_path.write_text(json.dumps(coverage))
    complete_budget_scan(state_dir, scan_id)
    published = json.loads(coverage_path.read_text())
    retained = next(row for row in published["surfaces"] if row["id"] == surface["id"])
    if edited_field is not None:
        assert retained == saved_surface
    else:
        assert retained["disposition"] == (
            "rejected" if decision == "suppressed" else "not_applicable"
        )
        assert retained["label"] == current["summary"]
        assert retained["notes"] == current["evidence"]
        assert retained["annotation"] == saved_surface["annotation"]
        assert len(published["surfaces"]) == 1


@pytest.mark.parametrize("decision", ["suppressed", "not_applicable", "deferred"])
@pytest.mark.parametrize("authored", [False, True, "string", "array", "null"])
def test_budget_terminal_refresh_archives_previous_candidate_snapshot(
    tmp_path: Path, workbench_api, decision: str, authored: bool | str
) -> None:
    state_dir, _, scan_dir, scan_id, ledger = budget_scan_fixture(
        tmp_path, extra_files={"updated.py": "# updated evidence\n"}
    )
    original = {**json.loads(ledger.read_text()), "validation": {"disposition": "suppressed"}}
    run_workbench(state_dir, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "sdk-thread")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        workbench_api["budget_exhausted_draft"](scan, scan_dir, [original], "Cost limit reached.")
    current = {
        **original,
        "summary": "Current review",
        "evidence": "Current source evidence.",
        "locations": [{"path": "updated.py", "start_line": 1, "end_line": 1, "role": "sink"}],
        "validation": {"disposition": decision},
    }
    if authored:
        path = scan_dir / "coverage.json"
        coverage = json.loads(path.read_text())
        surface = next(
            row
            for row in coverage["surfaces"]
            if row.get("candidateId") == original["candidate_id"]
        )
        surface.update(label="Authored review", notes="Retained authored annotation.")
        if authored is not True:
            original = {
                "string": "Retained authored candidate annotation.",
                "array": ["Retained authored annotation."],
                "null": None,
            }[authored]
            surface["candidate"] = original
        path.write_text(json.dumps(coverage))
    ledger.write_text(json.dumps(current) + "\n")
    complete_budget_scan(state_dir, scan_id)
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    surface = next(
        row for row in coverage["surfaces"] if row.get("candidateId") == current["candidate_id"]
    )
    assert surface["candidate"] == current
    assert original in surface["originalCandidates"]


@pytest.mark.parametrize("edited_field", [None, "reason", "paths"])
def test_legacy_budget_pending_refresh_keeps_authored_fields(
    tmp_path: Path, edited_field: str | None
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(
        tmp_path, extra_files={"updated.py": "# updated source\n"}
    )
    original = {**json.loads(ledger.read_text()), "validation": {"disposition": "deferred"}}
    surface = {
        "id": f"candidate-{original['candidate_id']}",
        "label": original["summary"],
        "disposition": "needs_follow_up",
        "notes": original["evidence"],
        "receiptRefs": [],
    }
    pending = {
        "id": original["candidate_id"],
        "candidateId": original["candidate_id"],
        "reason": f"Validation was deferred because the scan reached its cost limit: {original['summary']}. Evidence: {original['evidence']}",
        "paths": [row["path"] for row in original["locations"]],
        "surfaceIds": [surface["id"]],
    }
    if edited_field is not None:
        pending[edited_field] = (
            "Authored reason." if edited_field == "reason" else ["app.py", "authored.py"]
        )
    saved_pending = copy.deepcopy(pending)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(completeness="partial", surfaces=[surface], deferred=[pending])
    coverage_path.write_text(json.dumps(coverage))
    current = {
        **original,
        "summary": "Current unresolved review",
        "evidence": "Current unresolved evidence.",
        "locations": [{"path": "updated.py", "start_line": 1, "end_line": 1, "role": "sink"}],
    }
    ledger.write_text(json.dumps(current) + "\n")
    complete_budget_scan(state_dir, scan_id)
    coverage = json.loads(coverage_path.read_text())
    actual = next(
        row for row in coverage["deferred"] if row.get("candidateId") == current["candidate_id"]
    )
    if edited_field is None:
        assert actual["paths"] == ["app.py", "updated.py"]
        assert current["evidence"] in actual["reason"]
        assert actual["candidate"] == current
    elif edited_field == "paths":
        assert actual["paths"] == [*saved_pending["paths"], "updated.py"]
        assert current["evidence"] in actual["reason"]
    else:
        assert actual[edited_field] == saved_pending[edited_field]


@pytest.mark.parametrize("collision", [False, True])
def test_budget_candidate_allocation_preserves_generic_closure(
    tmp_path: Path, collision: bool
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    closure = {
        "id": candidate["candidate_id"] if collision else "general-review",
        "reason": "Independent generic review finished.",
    }
    coverage.update(surfaces=[], explicitExclusions=[], deferred=[], resolvedDeferred=[closure])
    coverage_path.write_text(json.dumps(coverage))
    complete_budget_scan(state_dir, scan_id)
    saved = json.loads(coverage_path.read_text())
    assert saved["resolvedDeferred"] == [closure]
    pending = [
        row for row in saved["deferred"] if row.get("candidateId") == candidate["candidate_id"]
    ]
    assert len(pending) == 1
    assert pending[0]["id"] != closure["id"]


@pytest.mark.parametrize("modern", [False, True])
@pytest.mark.parametrize("decision", ["suppressed", "not_applicable"])
@pytest.mark.parametrize("receipt", ["missing", "valid", "replacement", "reported"])
def test_public_budget_completion_keeps_receipt_reopened_work(
    tmp_path: Path, modern: bool, decision: str, receipt: str
) -> None:
    state, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": decision,
        "counterevidence_or_proof_gap": "Saved terminal decision.",
    }
    ledger.write_text(json.dumps(candidate) + "\n")
    original_ledger = ledger.read_bytes()
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    if receipt == "reported":
        findings["findings"][0]["provenance"]["candidateId"] = candidate["candidate_id"]
    else:
        findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    path = scan_dir / "artifacts/proof/decision.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Synthetic original decision evidence.\n")
    refs = ["artifacts/proof/decision.txt"]
    if receipt != "valid":
        path.unlink()
    if receipt == "replacement":
        path = path.with_name("replacement.txt")
        path.write_text("Synthetic independently replaced decision evidence.\n")
        refs = ["artifacts/proof/replacement.txt"]
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(
        completeness="complete",
        surfaces=[
            {
                "id": "candidate-review",
                "candidateId": candidate["candidate_id"],
                "label": "Saved candidate decision",
                "disposition": "rejected" if decision == "suppressed" else "not_applicable",
                "receiptRefs": refs,
            }
        ],
        deferred=[],
    )
    coverage_path.write_text(json.dumps(coverage))
    if modern:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET manifest_path = ? WHERE scan_id = ?",
                (str(scan_dir / "scan-manifest.json"), scan_id),
            )
    completed = complete_budget_scan(state, scan_id)["scan"]
    saved = json.loads(coverage_path.read_text())
    active = json.loads(findings_path.read_text())["findings"]
    assert len(active) == int(receipt == "reported")
    assert completed["progress"]["candidates"]["unresolved"] == int(receipt == "missing")
    if receipt == "missing":
        assert any(row.get("candidateId") == candidate["candidate_id"] for row in saved["deferred"])
        assert saved["surfaces"][0]["disposition"] == "needs_follow_up"
        assert saved["surfaces"][0]["receiptRefs"] == []
        assert saved["completeness"] == "partial"
    elif receipt != "reported":
        assert saved["surfaces"][0]["disposition"] == (
            "rejected" if decision == "suppressed" else "not_applicable"
        )
        assert path.read_text().startswith("Synthetic")
    assert ledger.read_bytes() == original_ledger


@pytest.mark.parametrize("modern", [False, True])
@pytest.mark.parametrize("decision", ["suppressed", "not_applicable"])
@pytest.mark.parametrize("newer_phase", [False, True])
def test_public_budget_dismissal_archives_reopened_findings(
    tmp_path: Path, modern: bool, decision: str, newer_phase: bool
) -> None:
    state, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": decision,
        "counterevidence_or_proof_gap": "Saved ledger decision.",
    }
    previous = copy.deepcopy(candidate)
    if newer_phase:
        candidate["validation"]["counterevidence_or_proof_gap"] = (
            "New independent terminal evidence."
        )
    ledger.write_text(json.dumps(candidate) + "\n")
    original_ledger = ledger.read_bytes()
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    old = findings["findings"][0]
    old["provenance"].update(candidateId=candidate["candidate_id"], candidateReopened=True)
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(
        completeness="partial",
        surfaces=[
            {
                "id": "candidate-review",
                "candidateId": candidate["candidate_id"],
                "label": "Current proof gap",
                "disposition": "needs_follow_up",
                "receiptRefs": [],
            }
        ],
        deferred=[
            {
                "id": "candidate-gap",
                "candidateId": candidate["candidate_id"],
                "candidate": previous,
                "reason": "Reopened proof gap.",
                "surfaceIds": ["candidate-review"],
            }
        ],
    )
    coverage_path.write_text(json.dumps(coverage))
    if modern:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET manifest_path = ? WHERE scan_id = ?",
                (str(scan_dir / "scan-manifest.json"), scan_id),
            )
    completed = complete_budget_scan(state, scan_id)["scan"]
    saved = json.loads(coverage_path.read_text())
    active = json.loads(findings_path.read_text())["findings"]
    assert len(active) == int(modern)
    assert completed["progress"]["candidates"]["unresolved"] == int(modern)
    if modern:
        assert saved["surfaces"][0]["disposition"] == "needs_follow_up"
    else:
        terminal = next(
            row for row in saved["surfaces"] if row.get("candidateId") == candidate["candidate_id"]
        )
        assert terminal["disposition"] == (
            "rejected" if decision == "suppressed" else "not_applicable"
        )
        history = terminal.get("previousFindings", [])
        assert any(
            row.get("summary") == old["summary"]
            and row.get("locations") == old["locations"]
            and row.get("provenance", {}).get("candidateId") == candidate["candidate_id"]
            for row in history
        )
    assert ledger.read_bytes() == original_ledger


@pytest.mark.parametrize("decision", ["suppressed", "not_applicable"])
@pytest.mark.parametrize("retry_evidence", ["unchanged", "new-phase", "receipt", "finding"])
def test_public_budget_retry_retains_receipt_reopening(
    tmp_path: Path, decision: str, retry_evidence: str
) -> None:
    state, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": decision,
        "counterevidence_or_proof_gap": "Saved terminal decision.",
    }
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"]["candidateId"] = candidate["candidate_id"]
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    disposition = "rejected" if decision == "suppressed" else "not_applicable"
    coverage.update(
        completeness="complete",
        surfaces=[
            {
                "id": "candidate-review",
                "candidateId": candidate["candidate_id"],
                "label": "Saved candidate decision",
                "disposition": disposition,
                "receiptRefs": ["artifacts/proof/missing.txt"],
            }
        ],
        deferred=[],
    )
    coverage_path.write_text(json.dumps(coverage))
    # Interrupt the public command after its real draft writes, before sealing.
    wrapper = (
        "import os, runpy, sys\n"
        "script = sys.argv[1]; sys.argv = sys.argv[1:]\n"
        "def interrupt(frame, event, arg):\n"
        "    if event == 'call' and frame.f_code.co_name == 'complete_scan_locked':\n"
        "        os._exit(75)\n"
        "    return interrupt\n"
        "sys.settrace(interrupt)\n"
        "runpy.run_path(script, run_name='__main__')\n"
    )
    args = [
        str(SCRIPT),
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(BUDGET_COST),
        "--message",
        "Synthetic budget stop.",
    ]
    for _ in range(2):
        interrupted = subprocess.run(
            [sys.executable, "-B", "-c", wrapper, *args],
            env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
            capture_output=True,
            text=True,
            check=False,
        )
        assert interrupted.returncode == 75, interrupted.stderr
        pending = json.loads(coverage_path.read_text())
        assert pending["surfaces"][0]["disposition"] == "needs_follow_up"
        assert any(
            row.get("candidateId") == candidate["candidate_id"] for row in pending["deferred"]
        )
    if retry_evidence == "new-phase":
        candidate["validation"]["counterevidence_or_proof_gap"] = "New terminal evidence."
        ledger.write_text(json.dumps(candidate) + "\n")
    elif retry_evidence == "receipt":
        path = scan_dir / "artifacts/proof/replacement.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Synthetic replacement receipt.\n")
        pending["surfaces"][0].update(
            disposition=disposition, receiptRefs=["artifacts/proof/replacement.txt"]
        )
        coverage_path.write_text(json.dumps(pending))
    elif retry_evidence == "finding":
        findings["findings"] = [finding]
        findings_path.write_text(json.dumps(findings))
    original_ledger = ledger.read_bytes()
    completed = complete_budget_scan(state, scan_id)["scan"]
    saved = json.loads(coverage_path.read_text())
    assert completed["progress"]["candidates"]["unresolved"] == int(retry_evidence == "unchanged")
    assert completed["findingCount"] == int(retry_evidence == "finding")
    assert bool(
        [row for row in saved["deferred"] if row.get("candidateId") == candidate["candidate_id"]]
    ) is (retry_evidence == "unchanged")
    assert ledger.read_bytes() == original_ledger
