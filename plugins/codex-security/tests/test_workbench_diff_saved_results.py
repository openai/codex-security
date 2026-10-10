from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    initialize_git_repository,
    run_workbench,
    start_delivered_scan,
    write_checkpoint,
    write_completed_contract,
)


def saved_diff_candidate(
    tmp_path: Path, *, pending: bool = True, complete: bool = False
) -> tuple[Path, Path, str, Path, dict]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    started = start_delivered_scan(
        state_dir, "--workspace-id", workspace_id, "--scan-root", str(tmp_path / "scans")
    )["results"]
    scan_id, scan_dir = started["scanId"], Path(started["scanDir"])
    candidate = {
        "candidate_id": "candidate-synthetic",
        "summary": "Synthetic candidate requiring review.",
        "evidence": "Synthetic source review evidence.",
        "cwe_ids": [],
        "locations": [{"path": "README.md", "start_line": 1, "end_line": 1, "role": "evidence"}],
    }
    ledger = scan_dir / "artifacts/02_discovery/candidate_ledger.jsonl"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(json.dumps(candidate) + "\n")
    # This is the checkpoint emitted when the Diff draft writer automatically retains
    # a ledger candidate omitted from the submitted draft.
    checkpoint = {
        "scanId": scan_id,
        "complete": complete,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [
                {
                    "candidateId": candidate["candidate_id"],
                    "label": candidate["summary"],
                    "disposition": "needs_follow_up",
                    "notes": "Candidate review is incomplete.",
                }
            ],
            "explicitExclusions": [],
            "deferred": [
                {
                    "candidateId": candidate["candidate_id"],
                    "candidate": candidate,
                    "reason": "Candidate review is incomplete.",
                },
                {"id": "other-review", "reason": "Independent review remains pending."},
            ],
        },
    }
    if not pending:
        checkpoint["coverage"]["surfaces"] = []
        checkpoint["coverage"]["deferred"].pop(0)
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.parent.mkdir()
    coverage = copy.deepcopy(checkpoint["coverage"])
    coverage["inventoryStrategy"] = "diff"
    for field in ("surfaces", "deferred"):
        for item in coverage[field]:
            item.setdefault("id", item.get("candidateId"))
            if field == "surfaces":
                item["receiptRefs"] = []
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": complete}},
                "findings": {"findings": []},
                "coverage": coverage,
            }
        )
    )
    run_workbench(state_dir, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unresolved"] == int(pending)
    return state_dir, scan_dir, scan_id, ledger, checkpoint


def saved_candidate_finding(tmp_path: Path, scan_id: str, candidate_id: str) -> dict:
    template = tmp_path / "finding-template"
    template.mkdir()
    write_completed_contract(template, scan_id, tmp_path / "target", relative_path="README.md")
    finding = json.loads((template / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = candidate_id
    return finding


@pytest.mark.parametrize(
    ("validation", "attack_path", "disposition"),
    [
        ("suppressed", None, "rejected"),
        ("not_applicable", None, "not_applicable"),
        ("not_applicable", "ignore", "not_applicable"),
        ("reportable", "ignore", "rejected"),
        ("suppressed", "deferred", None),
        ("not_applicable", "deferred", None),
        ("deferred", "ignore", None),
        ("reportable", "reportable", None),
    ],
)
def test_diff_candidate_decision_precedence(
    workbench_api, validation: str, attack_path: str | None, disposition: str | None
) -> None:
    candidate = {
        "candidate_id": "candidate-one",
        "summary": "Saved candidate review",
        "validation": {
            "disposition": validation,
            "counterevidence_or_proof_gap": "Validation evidence.",
        },
    }
    if attack_path:
        candidate["attack_path"] = {
            "decision": attack_path,
            "counterevidence": "Path counterevidence.",
            "severity_rationale": "Path severity rationale.",
        }

    decision = workbench_api["saved_results"]._diff_candidate_decision(candidate)

    if disposition is None:
        assert decision is None
    else:
        assert decision["disposition"] == disposition
        assert decision["candidate"] == candidate
        assert decision["notes"] == (
            "Path counterevidence."
            if disposition == "rejected" and attack_path == "ignore"
            else "Validation evidence."
        )


@pytest.mark.parametrize("authored", [False, True])
def test_stopped_diff_reopens_legacy_terminal_rationale(
    tmp_path: Path, workbench_api, authored: bool
) -> None:
    state_dir, scan_dir, scan_id, ledger, _checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": "not_applicable",
        "counterevidence_or_proof_gap": "Validation evidence.",
    }
    candidate["attack_path"] = {
        "decision": "ignore",
        "counterevidence": "Earlier attack-path evidence.",
    }
    surface = workbench_api["saved_results"]._diff_candidate_decision(candidate)
    surface.update(
        id="legacy-terminal",
        receiptRefs=[],
        notes="Independent authored evidence."
        if authored
        else candidate["attack_path"]["counterevidence"],
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[surface], deferred=[])
    coverage_path.write_text(json.dumps(coverage))
    candidate["validation"] = {"disposition": "deferred"}
    ledger.write_text(json.dumps(candidate) + "\n")

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    recovered = json.loads(coverage_path.read_text())
    pending = [
        row for row in recovered["deferred"] if row.get("candidateId") == candidate["candidate_id"]
    ]
    assert len(pending) == (0 if authored else 1)
    saved_surface = next(
        row for row in recovered["surfaces"] if row.get("candidateId") == candidate["candidate_id"]
    )
    assert saved_surface["disposition"] == ("not_applicable" if authored else "needs_follow_up")
    if authored:
        assert saved_surface["notes"] == surface["notes"]


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize(
    ("validation", "attack_path", "expected_count", "expected_disposition"),
    [
        ("suppressed", None, 0, "rejected"),
        ("not_applicable", None, 0, "not_applicable"),
        ("reportable", "ignore", 0, "rejected"),
        ("reportable", "reportable", 1, "needs_follow_up"),
    ],
)
def test_stopped_diff_reconciles_and_freezes_saved_candidate_decisions(
    tmp_path: Path,
    termination: str,
    validation: str,
    attack_path: str | None,
    expected_count: int,
    expected_disposition: str,
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": validation,
        "counterevidence_or_proof_gap": "Synthetic validation decision.",
    }
    if attack_path:
        candidate["attack_path"] = {
            "decision": attack_path,
            "proof_gap": "Synthetic path decision.",
        }
    ledger.write_text(json.dumps(candidate) + "\n")
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_retained() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == expected_count
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        candidate_surfaces = [
            item
            for item in coverage["surfaces"]
            if item.get("candidateId") == "candidate-synthetic"
        ]
        assert {item["disposition"] for item in candidate_surfaces} == {expected_disposition}
        assert any(item.get("id") == "other-review" for item in coverage["deferred"])
        assert any(item.get("id") == "scan-stopped" for item in coverage["deferred"])

    assert_retained()
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    snapshots = [
        json.loads((scan_dir / path).read_text())
        for path in manifest["scan"]["preservedSources"]
        if json.loads((scan_dir / path).read_text())
        .get("coverage", {})
        .get("stoppedDiffCandidateDecisions")
    ]
    assert len(snapshots) == 1
    assert len(snapshots[0]["coverage"]["surfaces"]) == (0 if expected_count else 1)
    if expected_count:
        candidate["validation"]["disposition"] = "suppressed"
        candidate.pop("attack_path", None)
        ledger.write_text(json.dumps(candidate) + "\n")
    else:
        ledger.unlink()
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_retained()
    if termination == "fail-scan":
        # Force an actual replay, admitting a new ordinary checkpoint while the
        # ledger has changed. The original decision snapshot remains authoritative.
        late = copy.deepcopy(checkpoint)
        late["coverage"]["deferred"].append({"id": "late-review", "reason": "Late saved review."})
        write_checkpoint(scan_dir / "checkpoints", late)
        run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
        assert_retained()
        assert any(
            item.get("id") == "late-review"
            for item in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
        )


@pytest.mark.parametrize(
    ("resolution", "owner", "ledger_disposition"),
    [
        ("finding", None, "suppressed"),
        ("rejected", None, "not_applicable"),
        ("not_applicable", None, "suppressed"),
        ("finding", "other-worker", "suppressed"),
        ("rejected", None, "deferred"),
    ],
)
def test_stopped_diff_keeps_current_resolutions_over_historical_ledger_decisions(
    tmp_path: Path, resolution: str, owner: str | None, ledger_disposition: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate_id = candidate["candidate_id"]
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(
        deferred=[],
        surfaces=[
            {
                "id": "current-decision",
                "candidateId": candidate_id,
                **({"sourceWorkerId": owner} if owner else {}),
                "label": "Current authored decision",
                "disposition": "reported" if resolution == "finding" else resolution,
                "notes": "Keep the current saved review conclusion.",
                "receiptRefs": [],
            }
        ],
    )
    coverage_path.write_text(json.dumps(coverage))
    if resolution == "finding":
        finding = saved_candidate_finding(tmp_path, scan_id, candidate_id)
        if owner:
            finding["provenance"]["sourceWorkerId"] = owner
        (scan_dir / "findings.json").write_text(
            json.dumps({"scanId": scan_id, "findings": [finding]})
        )
    candidate["validation"] = {
        "disposition": ledger_disposition,
        "counterevidence_or_proof_gap": "An older ledger decision.",
    }
    ledger.write_text(json.dumps(candidate) + "\n")
    run_workbench(
        state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after saving."
    )

    def assert_current_resolution() -> None:
        result = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert result["findingCount"] == int(resolution == "finding")
        assert result["progress"]["candidates"]["unresolved"] == 0
        recovered = json.loads(coverage_path.read_text())
        decisions = [
            item for item in recovered["surfaces"] if item.get("candidateId") == candidate_id
        ]
        current = next(item for item in decisions if item["id"] == "current-decision")
        expected = coverage["surfaces"][0]
        assert {key: current[key] for key in expected} == expected
        assert set(current) - set(expected) <= {"originalCandidates", "previousFindings"}
        generated = [item for item in decisions if "candidate" in item]
        assert len(generated) == int(owner is not None)
        if generated:
            # A different worker's finding cannot resolve this unscoped Diff candidate.
            assert generated[0].get("sourceWorkerId") is None
            assert generated[0]["disposition"] == "rejected"
        assert "- Candidate review is incomplete." not in (scan_dir / "report.md").read_text()

    assert_current_resolution()
    ledger.unlink()
    late = copy.deepcopy(checkpoint)
    late["coverage"].update(
        surfaces=[], deferred=[{"id": "late-review", "reason": "Later saved work."}]
    )
    write_checkpoint(scan_dir / "checkpoints", late)
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_current_resolution()


@pytest.mark.parametrize(
    ("transition", "termination"),
    [
        ("historical-generated-decision", "fail-scan"),
        ("historical-authored-decision", "fail-scan"),
        ("current-generated-decision", "fail-scan"),
        ("current-generated-decision", "cancel-scan"),
        ("historical-finding", "fail-scan"),
    ],
)
def test_stopped_diff_freezes_current_candidate_state_over_history(
    tmp_path: Path, workbench_api, transition: str, termination: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate_id = candidate["candidate_id"]
    old_candidate = {
        **candidate,
        "validation": {
            "disposition": "suppressed",
            "counterevidence_or_proof_gap": "Earlier generated decision.",
        },
    }
    if transition == "current-generated-decision":
        old_candidate.update(
            attack_path={"decision": "ignore", "counterevidence": "Earlier path decision."},
            reviewAnnotation="Retain this authored annotation.",
        )
    old_decision = workbench_api["saved_results"]._diff_candidate_decision(old_candidate)
    if transition == "historical-authored-decision":
        old_decision.pop("candidate")
        old_decision["notes"] = "Earlier authored decision superseded by a reopened draft."
    terminal_checkpoint = copy.deepcopy(checkpoint)
    terminal_checkpoint["coverage"].update(surfaces=[old_decision], deferred=[])
    write_checkpoint(scan_dir / "checkpoints", terminal_checkpoint)
    coverage_path = scan_dir / "coverage.json"
    current = json.loads(coverage_path.read_text())
    if transition == "current-generated-decision":
        current.update(
            surfaces=[{**old_decision, "id": candidate_id, "receiptRefs": []}], deferred=[]
        )
    historical_finding = None
    if transition == "historical-finding":
        historical_finding = saved_candidate_finding(tmp_path, scan_id, candidate_id)
        finding_checkpoint = copy.deepcopy(checkpoint)
        finding_checkpoint["findings"] = [historical_finding]
        finding_checkpoint["coverage"].update(surfaces=[], deferred=[])
        write_checkpoint(scan_dir / "checkpoints", finding_checkpoint)
        current["deferred"][0]["finding"] = historical_finding
    # The same candidate ID from an independent owner must keep its authored decision.
    other_owner = {
        "id": "other-owner-decision",
        "candidateId": candidate_id,
        "sourceWorkerId": "independent-worker",
        "label": "Independent worker decision",
        "disposition": "not_applicable",
        "notes": "Keep this separately owned review.",
        "receiptRefs": [],
    }
    current["surfaces"].append(other_owner)
    coverage_path.write_text(json.dumps(current))
    candidate["validation"] = {
        "disposition": "suppressed" if historical_finding else "deferred",
        "counterevidence_or_proof_gap": "Current saved review evidence.",
    }
    ledger.write_text(json.dumps(candidate) + "\n")
    original_sources = {
        path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")
    }
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_current_state() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 0
        assert scan["progress"]["candidates"]["unresolved"] == int(historical_finding is None)
        coverage = json.loads(coverage_path.read_text())
        assert other_owner in coverage["surfaces"]
        root_surfaces = [
            item
            for item in coverage["surfaces"]
            if item.get("candidateId") == candidate_id and item.get("sourceWorkerId") is None
        ]
        assert {item["disposition"] for item in root_surfaces} == {
            "rejected" if historical_finding else "needs_follow_up"
        }
        if historical_finding:
            assert any(
                historical_finding in item.get("previousFindings", []) for item in root_surfaces
            )
        else:
            pending = next(
                item for item in coverage["deferred"] if item.get("candidateId") == candidate_id
            )
            assert pending["candidate"] == {
                **candidate,
                **(
                    {"reviewAnnotation": "Retain this authored annotation."}
                    if transition == "current-generated-decision"
                    else {}
                ),
            }
            assert "## Unresolved candidates" in (scan_dir / "report.md").read_text()
        assert all(path.read_bytes() == content for path, content in original_sources.items())

    assert_current_state()
    # Replay admits unrelated work but must use the frozen state even if the live
    # ledger changes again and the earlier terminal/finding checkpoints remain.
    ledger.write_text("{later incomplete ledger")
    frozen_sources = {
        scan_dir / relative: (scan_dir / relative).read_bytes()
        for relative in json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
            "preservedSources"
        ]
    }
    if termination == "fail-scan":
        late = copy.deepcopy(checkpoint)
        late["coverage"].update(
            surfaces=[], deferred=[{"id": "late-review", "reason": "Later work."}]
        )
        write_checkpoint(scan_dir / "checkpoints", late)
        run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    else:
        run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_current_state()
    assert all(path.read_bytes() == content for path, content in frozen_sources.items())


def test_stopped_diff_does_not_infer_reopening_from_unordered_history(
    tmp_path: Path, workbench_api
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    terminal = copy.deepcopy(checkpoint)
    terminal["coverage"].update(
        surfaces=[workbench_api["saved_results"]._diff_candidate_decision(candidate)], deferred=[]
    )
    write_checkpoint(scan_dir / "checkpoints", terminal)
    # Neither the current empty draft nor a missing ledger establishes which of
    # these historical candidate checkpoints was saved most recently.
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[], deferred=[])
    coverage_path.write_text(json.dumps(coverage))
    ledger.unlink()
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == 0
    assert scan["progress"]["candidates"]["unresolved"] == 0
    assert any(
        item.get("disposition") == "rejected"
        for item in json.loads(coverage_path.read_text())["surfaces"]
    )


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("ledger_state", ["deferred", "terminal"])
@pytest.mark.parametrize("finding_source", ["canonical", "checkpoint"])
def test_stopped_diff_retains_every_reopened_sibling_finding(
    tmp_path: Path, workbench_api, termination: str, ledger_state: str, finding_source: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    phases = {"validation": {"disposition": "suppressed"}}
    first = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    first["provenance"]["diffCandidateDecision"] = phases
    sibling = copy.deepcopy(first)
    sibling["identity"]["instance"] = "second-synthetic-instance"
    sibling["title"] = "Second retained sibling finding."
    sibling["summary"] = "Independent evidence from the second finding."
    siblings = workbench_api["saved_results"].recoverable_findings(
        scan_dir,
        scan_id,
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["target"],
        [first, sibling],
    )
    assert len({finding["findingId"] for finding in siblings}) == 2
    coverage_path = scan_dir / "coverage.json"
    if finding_source == "canonical":
        (scan_dir / "findings.json").write_text(
            json.dumps({"scanId": scan_id, "findings": siblings})
        )
        coverage = json.loads(coverage_path.read_text())
        coverage.update(surfaces=[], deferred=[])
        coverage_path.write_text(json.dumps(coverage))
    else:
        override = copy.deepcopy(checkpoint)
        override["findings"] = siblings
        override["coverage"].update(surfaces=[], deferred=[])
        write_checkpoint(scan_dir / "checkpoints", override)
    candidate["validation"] = {
        "disposition": "deferred" if ledger_state == "deferred" else "suppressed",
        "counterevidence_or_proof_gap": "Newer phase review.",
    }
    ledger.write_text(json.dumps(candidate) + "\n")
    originals = {path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")}
    arguments = ["--message", "Synthetic stop."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_retained() -> None:
        coverage = json.loads(coverage_path.read_text())
        if ledger_state == "deferred":
            row = next(item for item in coverage["deferred"] if item.get("candidateId"))
            retained = list(workbench_api["saved_results"]._retained_findings(row["finding"]))
        else:
            row = next(item for item in coverage["surfaces"] if item.get("candidateId"))
            retained = row["previousFindings"]
        assert {finding["findingId"] for finding in retained} == {
            finding["findingId"] for finding in siblings
        }
        assert {finding["summary"] for finding in retained} == {
            finding["summary"] for finding in siblings
        }
        assert all(path.read_bytes() == content for path, content in originals.items())

    assert_retained()
    ledger.write_text("{later incomplete ledger")
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_retained()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("resolved", [False, True])
def test_stopped_diff_retains_distinct_saved_proof_gaps(
    tmp_path: Path, termination: str, resolved: bool
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    first = copy.deepcopy(checkpoint["coverage"]["deferred"][0])
    first.update(id="first-gap", reason="First independent proof gap.", paths=["README.md"])
    second = copy.deepcopy(first)
    second.update(id="second-gap", reason="Second independent proof gap.", paths=["second.py"])
    second["candidate"]["evidence"] = "Second saved evidence."
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [first, second]
    coverage_path.write_text(json.dumps(coverage))
    checkpoint["coverage"]["deferred"] = [first, second]
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    if resolved:
        candidate = json.loads(ledger.read_text())
        candidate["validation"] = {"disposition": "suppressed"}
        ledger.write_text(json.dumps(candidate) + "\n")
    arguments = ["--message", "Synthetic stop."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_gaps() -> None:
        coverage = json.loads(coverage_path.read_text())
        pending = [row for row in coverage["deferred"] if row.get("candidateId")]
        current_gaps = [row for row in pending if row["id"] in {"first-gap", "second-gap"}]
        assert {row["id"] for row in current_gaps} == (
            set() if resolved else {"first-gap", "second-gap"}
        )
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == int(not resolved)
        if resolved:
            assert pending == []
        else:
            assert {row["reason"] for row in current_gaps} == {first["reason"], second["reason"]}
            assert {tuple(row["paths"]) for row in current_gaps} == {("README.md",), ("second.py",)}
            assert any(
                row["candidate"]["evidence"] == "Second saved evidence." for row in current_gaps
            )

    assert_gaps()
    ledger.write_text("{later incomplete ledger")
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_gaps()


@pytest.mark.parametrize("finding_source", ["canonical", "checkpoint"])
@pytest.mark.parametrize(
    "ledger_state", ["unchanged", "terminal", "deferred", "missing", "malformed"]
)
def test_stopped_diff_orders_marked_finding_override_by_saved_phase_snapshot(
    tmp_path: Path, ledger_state: str, finding_source: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    phases = {
        "validation": {
            "disposition": "suppressed",
            "counterevidence_or_proof_gap": "Earlier ledger review.",
        },
        "attack_path": {"decision": "reportable", "severity_rationale": "Earlier path review."},
    }
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    finding["provenance"]["diffCandidateDecision"] = copy.deepcopy(phases)
    coverage_path = scan_dir / "coverage.json"
    if finding_source == "canonical":
        (scan_dir / "findings.json").write_text(
            json.dumps({"scanId": scan_id, "findings": [finding]})
        )
        coverage = json.loads(coverage_path.read_text())
        coverage.update(surfaces=[], deferred=[])
        coverage_path.write_text(json.dumps(coverage))
    else:
        # The finding checkpoint was saved, but publication left the older
        # unresolved canonical draft in place.
        override = copy.deepcopy(checkpoint)
        override["findings"] = [finding]
        override["coverage"].update(surfaces=[], deferred=[])
        write_checkpoint(scan_dir / "checkpoints", override)
    # Object key order does not change a phase snapshot's meaning.
    candidate.update({key: dict(reversed(list(value.items()))) for key, value in phases.items()})
    if ledger_state in {"terminal", "deferred"}:
        candidate["validation"]["counterevidence_or_proof_gap"] = "Newer saved review."
        if ledger_state == "deferred":
            candidate["validation"]["disposition"] = "deferred"
    if ledger_state == "missing":
        ledger.unlink()
    elif ledger_state == "malformed":
        candidate["validation"] = "Incomplete phase record"
        ledger.write_text(json.dumps(candidate) + "\n")
    else:
        ledger.write_text(json.dumps(candidate) + "\n")
    run_workbench(
        state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after review."
    )

    def assert_override_state() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == int(ledger_state in {"unchanged", "missing", "malformed"})
        assert scan["progress"]["candidates"]["unresolved"] == int(ledger_state == "deferred")
        findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
        recovered = json.loads(coverage_path.read_text())
        if findings:
            assert findings[0]["provenance"]["diffCandidateDecision"] == phases
        elif ledger_state == "deferred":
            pending = next(item for item in recovered["deferred"] if item.get("candidateId"))
            assert pending["candidate"] == candidate
            assert pending["finding"] == finding
        else:
            decision = next(item for item in recovered["surfaces"] if item.get("candidateId"))
            assert decision["disposition"] == "rejected"
            assert finding in decision["previousFindings"]

    assert_override_state()
    frozen = {
        scan_dir / relative: (scan_dir / relative).read_bytes()
        for relative in json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
            "preservedSources"
        ]
    }
    ledger.write_text("{later incomplete ledger")
    late = copy.deepcopy(checkpoint)
    late["coverage"].update(surfaces=[], deferred=[{"id": "later-work", "reason": "Later work."}])
    write_checkpoint(scan_dir / "checkpoints", late)
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_override_state()
    assert all(path.read_bytes() == content for path, content in frozen.items())


@pytest.mark.parametrize("resolution", ["authored-terminal", "other-owner-finding"])
def test_stopped_diff_scopes_checkpoint_override_and_preserves_current_authored_decision(
    tmp_path: Path, resolution: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    finding["provenance"]["diffCandidateDecision"] = {"validation": candidate["validation"]}
    if resolution == "other-owner-finding":
        finding["provenance"]["sourceWorkerId"] = "other-worker"
    override = copy.deepcopy(checkpoint)
    override["findings"] = [finding]
    override["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", override)
    original = saved.read_bytes()
    coverage_path = scan_dir / "coverage.json"
    if resolution == "authored-terminal":
        coverage = json.loads(coverage_path.read_text())
        authored = {
            "id": "authored-decision",
            "candidateId": candidate["candidate_id"],
            "label": "Current authored review",
            "disposition": "not_applicable",
            "notes": "Current authored decision supersedes the historical finding.",
            "receiptRefs": [],
        }
        coverage.update(surfaces=[authored], deferred=[])
        coverage_path.write_text(json.dumps(coverage))

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == int(resolution == "other-owner-finding")
    assert scan["progress"]["candidates"]["unresolved"] == 0
    recovered = json.loads(coverage_path.read_text())
    if resolution == "authored-terminal":
        retained = next(row for row in recovered["surfaces"] if row["id"] == authored["id"])
        assert {key: retained[key] for key in authored} == authored
        assert finding in retained["previousFindings"]
    else:
        assert any(
            row.get("candidateId") == candidate["candidate_id"]
            and row.get("sourceWorkerId") is None
            and row["disposition"] == "rejected"
            for row in recovered["surfaces"]
        )
    assert saved.read_bytes() == original


@pytest.mark.parametrize("null_history", [False, True])
def test_stopped_diff_uses_current_checkpoint_override_over_older_marked_parent(
    tmp_path: Path, null_history: bool
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": "suppressed",
        "counterevidence_or_proof_gap": "Current ledger review.",
    }
    ledger.write_text(json.dumps(candidate) + "\n")
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    finding["provenance"]["diffCandidateDecision"] = {"validation": candidate["validation"]}
    if null_history:
        finding["provenance"]["previousFindings"] = None
    older = copy.deepcopy(finding)
    older["summary"] = "Earlier saved finding evidence."
    older["provenance"]["diffCandidateDecision"]["validation"]["counterevidence_or_proof_gap"] = (
        "Earlier ledger review."
    )
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": [older]}))
    checkpoint["findings"] = [finding]
    checkpoint["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    original = saved.read_bytes()

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    def assert_current_override() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 1
        assert scan["progress"]["candidates"]["unresolved"] == 0
        recovered = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
        assert recovered["summary"] == finding["summary"]
        assert (
            recovered["provenance"]["diffCandidateDecision"]
            == finding["provenance"]["diffCandidateDecision"]
        )
        assert older in recovered["provenance"]["previousFindings"]

    assert_current_override()
    ledger.write_text("{later incomplete ledger")
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_current_override()
    assert saved.read_bytes() == original


@pytest.mark.parametrize(
    "ledger_state", ["missing", "malformed", "matching-checkpoint", "current-decision"]
)
@pytest.mark.parametrize("current_phase", ["same", "newer"])
def test_stopped_diff_keeps_saved_terminal_snapshot_over_stale_checkpoint(
    tmp_path: Path, workbench_api, ledger_state: str, current_phase: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": "suppressed",
        "counterevidence_or_proof_gap": "Earlier ledger review.",
    }
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    finding["provenance"]["diffCandidateDecision"] = {
        "validation": copy.deepcopy(candidate["validation"])
    }
    checkpoint["findings"] = [finding]
    checkpoint["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    original = saved.read_bytes()
    current = copy.deepcopy(candidate)
    if current_phase == "newer":
        current["validation"]["counterevidence_or_proof_gap"] = "Newer saved terminal review."
    decision = workbench_api["saved_results"]._diff_candidate_decision(current)
    decision.update(id="current-terminal", receiptRefs=[])
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[decision], deferred=[])
    coverage_path.write_text(json.dumps(coverage))
    if ledger_state == "missing":
        ledger.unlink()
    elif ledger_state == "malformed":
        ledger.write_text("{incomplete ledger")
    else:
        ledger.write_text(
            json.dumps(candidate if ledger_state == "matching-checkpoint" else current) + "\n"
        )
    reported = current_phase == "same" or ledger_state == "matching-checkpoint"

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    def assert_saved_decision() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == int(reported)
        assert scan["progress"]["candidates"]["unresolved"] == 0
        recovered = json.loads(coverage_path.read_text())
        terminal = [
            row
            for row in recovered["surfaces"]
            if row.get("candidateId") == candidate["candidate_id"]
            and row["disposition"] == "rejected"
        ]
        if reported:
            assert terminal == []
        else:
            assert len(terminal) == 1
            assert terminal[0]["candidate"] == current
            assert finding in terminal[0]["previousFindings"]

    assert_saved_decision()
    ledger.write_text(json.dumps(candidate) + "\n")
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_saved_decision()
    assert saved.read_bytes() == original


@pytest.mark.parametrize("ledger_state", ["missing", "malformed"])
@pytest.mark.parametrize("history_field", [None, "previousFindings", "sourceFindings"])
def test_stopped_diff_preserves_reopened_candidate_over_historical_finding_checkpoint(
    tmp_path: Path, ledger_state: str, history_field: str | None
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    finding["provenance"]["diffCandidateDecision"] = {
        "validation": copy.deepcopy(candidate["validation"])
    }
    checkpoint["findings"] = [finding]
    checkpoint["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    originals = {saved: saved.read_bytes()}
    if history_field is not None:
        previous = copy.deepcopy(finding)
        finding["summary"] = "Revised finding with additional review context."
        finding["provenance"][history_field] = [
            {"finding": previous} if history_field == "sourceFindings" else previous
        ]
        saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
        originals[saved] = saved.read_bytes()
    candidate["validation"] = {
        "disposition": "deferred",
        "counterevidence_or_proof_gap": "New evidence requires further review.",
    }
    reopened = {
        "id": "reopened-candidate",
        "candidateId": candidate["candidate_id"],
        "candidate": candidate,
        "finding": finding,
        "reason": "Reopened after newer review.",
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[], deferred=[reopened])
    coverage_path.write_text(json.dumps(coverage))
    if ledger_state == "missing":
        ledger.unlink()
    else:
        ledger.write_text("{incomplete ledger")

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    def assert_reopened() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 0
        assert scan["progress"]["candidates"]["unresolved"] == 1
        pending = next(
            item
            for item in json.loads(coverage_path.read_text())["deferred"]
            if item.get("candidateId") == candidate["candidate_id"]
        )
        assert pending["candidate"] == candidate
        assert pending["finding"] == finding
        assert pending["reason"] == reopened["reason"]

    assert_reopened()
    ledger.write_text(json.dumps({**candidate, "validation": {"disposition": "suppressed"}}))
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_reopened()
    assert all(path.read_bytes() == original for path, original in originals.items())


@pytest.mark.cross_platform
@pytest.mark.parametrize("outcome", ["pending", "active", "accepted", "rejected"])
@pytest.mark.parametrize("marked_checkpoint", [False, True])
def test_stopped_diff_preserves_canonical_reopened_candidate_state(
    tmp_path: Path, outcome: str, marked_checkpoint: bool
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate_id = checkpoint["coverage"]["deferred"][0]["candidateId"]
    finding = saved_candidate_finding(tmp_path, scan_id, candidate_id)
    finding["provenance"]["candidateReopened"] = outcome != "active"
    if marked_checkpoint:
        finding["provenance"]["diffCandidateDecision"] = {"validation": {"disposition": "deferred"}}
        checkpoint["findings"] = [finding]
        write_checkpoint(scan_dir / "checkpoints", checkpoint)
    ledger.unlink()
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    coverage.update(surfaces=[], deferred=[coverage["deferred"][0]])
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"

    def write_draft(findings: list[dict]) -> None:
        staged.write_text(
            json.dumps(
                {
                    "manifest": {"scan": {"complete": False}},
                    "findings": {"findings": findings},
                    "coverage": coverage,
                }
            )
        )
        run_workbench(
            state_dir, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged)
        )

    write_draft([finding])
    if outcome == "accepted":
        finding = copy.deepcopy(finding)
        finding["provenance"].pop("candidateReopened")
        write_draft([finding])
    elif outcome == "rejected":
        coverage.update(
            deferred=[],
            surfaces=[
                {
                    "id": "current-decision",
                    "candidateId": candidate_id,
                    "label": "Current review decision",
                    "disposition": "rejected",
                    "notes": "Later review dismissed the candidate.",
                    "receiptRefs": [],
                }
            ],
        )
        write_draft([])
    originals = {path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")}
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    def assert_saved_state() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == int(outcome == "pending")
        saved_coverage = json.loads((scan_dir / "coverage.json").read_text())
        saved_findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
        if outcome == "pending":
            pending = next(
                row for row in saved_coverage["deferred"] if row.get("candidateId") == candidate_id
            )
            assert pending["candidate"] == checkpoint["coverage"]["deferred"][0]["candidate"]
            assert pending["finding"]["title"] == finding["title"]
            assert pending["finding"]["provenance"]["candidateReopened"] is True
        elif outcome == "rejected":
            terminal = next(
                row for row in saved_coverage["surfaces"] if row.get("candidateId") == candidate_id
            )
            assert terminal["disposition"] == "rejected"
            assert any(
                previous["title"] == finding["title"] for previous in terminal["previousFindings"]
            )
        else:
            assert len(saved_findings) == 1
            assert saved_findings[0]["title"] == finding["title"]
            assert saved_findings[0]["provenance"].get("candidateReopened") is not True
        assert all(path.read_bytes() == original for path, original in originals.items())

    assert_saved_state()
    # Changes after the stop must not replace the frozen candidate decision.
    ledger.write_text(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "summary": "Later review",
                "validation": {"disposition": "suppressed"},
            }
        )
        + "\n"
    )
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_saved_state()


@pytest.mark.cross_platform
@pytest.mark.parametrize("ledger_state", ["missing", "matching"])
@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("revision", ["unchanged", "with-history", "file-authored"])
def test_stopped_diff_ignores_old_checkpoint_for_canonical_reopening(
    tmp_path: Path, ledger_state: str, termination: str, revision: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate_id = checkpoint["coverage"]["deferred"][0]["candidateId"]
    original = saved_candidate_finding(tmp_path, scan_id, candidate_id)
    original["provenance"]["diffCandidateDecision"] = {"validation": {"disposition": "deferred"}}
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[], deferred=[])
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"

    def publish(finding: dict) -> None:
        staged.write_text(
            json.dumps(
                {
                    "manifest": {"scan": {"complete": False}},
                    "findings": {"findings": [finding]},
                    "coverage": coverage,
                }
            )
        )
        run_workbench(
            state_dir, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged)
        )

    publish(original)
    reopened = copy.deepcopy(original)
    reopened["provenance"]["candidateReopened"] = True
    if revision != "unchanged":
        reopened["summary"] = "Revised evidence needs further validation."
    if revision == "with-history":
        reopened["provenance"]["previousFindings"] = [original]
    coverage.update(
        completeness="partial",
        deferred=[
            {
                "id": "candidate-review",
                "candidateId": candidate_id,
                "reason": "Current review requires further validation.",
            }
        ],
    )
    if revision == "file-authored":
        findings_path = scan_dir / "findings.json"
        document = json.loads(findings_path.read_text())
        document["findings"] = [reopened]
        findings_path.write_text(json.dumps(document))
        coverage_path.write_text(json.dumps(coverage))
    else:
        publish(reopened)
    if ledger_state == "missing":
        ledger.unlink()
    else:
        candidate = json.loads(ledger.read_text())
        candidate["validation"] = {"disposition": "deferred"}
        ledger.write_text(json.dumps(candidate) + "\n")
    originals = {path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")}
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"][
            "candidates"
        ]["unresolved"]
        == 1
    )
    arguments = ["--message", "Stopped."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_reopened() -> dict:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == 1
        pending = next(
            row
            for row in json.loads(coverage_path.read_text())["deferred"]
            if row.get("candidateId") == candidate_id
        )
        assert pending["finding"]["summary"] == reopened["summary"]
        assert pending["finding"]["provenance"]["candidateReopened"] is True
        if revision == "with-history":
            assert original in pending["finding"]["provenance"]["previousFindings"]
        assert all(path.read_bytes() == value for path, value in originals.items())
        return pending

    pending = assert_reopened()
    if termination == "fail-scan":
        ledger.write_text(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "summary": "Later review",
                    "validation": {"disposition": "suppressed"},
                }
            )
            + "\n"
        )
        run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
        assert assert_reopened() == pending


@pytest.mark.parametrize("ledger_state", ["missing", "malformed", "matching"])
@pytest.mark.parametrize(
    "evidence_location",
    ["finding", "candidate", "second-row", "surface", "other-owner", "row-history"],
)
def test_stopped_diff_checks_all_current_demotion_evidence_before_checkpoint_admission(
    tmp_path: Path, workbench_api, ledger_state: str, evidence_location: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    finding["provenance"]["diffCandidateDecision"] = {
        "validation": copy.deepcopy(candidate["validation"])
    }
    checkpoint["findings"] = [finding]
    checkpoint["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    original = saved.read_bytes()
    current = {
        **candidate,
        "validation": {"disposition": "deferred"},
    }
    pending = {
        "id": "current-review",
        "candidateId": candidate["candidate_id"],
        "candidate": current,
        "reason": "Current review remains unresolved.",
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[], deferred=[pending])
    if evidence_location == "surface":
        # The writer carries pending.finding onto the terminal surface when a
        # reopened candidate closes, even when phase values return to the original.
        surface = workbench_api["saved_results"]._diff_candidate_decision(candidate)
        surface.update(id="closed-review", receiptRefs=[], finding=finding)
        coverage.update(surfaces=[surface], deferred=[])
    elif evidence_location == "row-history":
        pending["finding"] = {"title": "Compact saved finding annotation."}
        pending["previousFindings"] = [finding]
    elif evidence_location == "candidate":
        # Custom validation stores the demoted finding in this supported field.
        pending["candidate"] = finding
    elif evidence_location in {"second-row", "other-owner"}:
        coverage["deferred"].append(
            {
                **pending,
                "id": "retained-finding-review",
                "finding": finding,
                **(
                    {"sourceWorkerId": "worker-other"} if evidence_location == "other-owner" else {}
                ),
            }
        )
    else:
        pending["finding"] = finding
    coverage_path.write_text(json.dumps(coverage))
    if ledger_state == "missing":
        ledger.unlink()
    elif ledger_state == "malformed":
        ledger.write_text("{incomplete ledger")
    else:
        ledger.write_text(json.dumps(candidate) + "\n")

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    def assert_current_state() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == int(evidence_location == "other-owner")
        assert scan["progress"]["candidates"]["unresolved"] == int(
            evidence_location == "other-owner"
            or (evidence_location != "surface" and ledger_state != "matching")
        )
        recovered = json.loads(coverage_path.read_text())
        if evidence_location != "other-owner" and (
            evidence_location == "surface" or ledger_state == "matching"
        ):
            terminal = next(
                row
                for row in recovered["surfaces"]
                if row.get("candidateId") == candidate["candidate_id"]
                and row["disposition"] == "rejected"
            )
            assert {key: terminal["candidate"][key] for key in candidate} == candidate
        assert saved.read_bytes() == original

    assert_current_state()
    ledger.write_text(json.dumps(current) + "\n")
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert_current_state()


def test_stopped_diff_freezes_blank_owner_pending_candidate_without_ledger(
    tmp_path: Path, workbench_api
) -> None:
    coverage = {
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [
            {
                "candidateId": "synthetic-candidate",
                "sourceWorkerId": " ",
                "reason": "Saved review gap.",
            }
        ],
    }
    draft = workbench_api["saved_results"]._stopped_diff_candidate_decisions(
        tmp_path,
        "synthetic-scan",
        [{"coverage": coverage}],
        [],
        current_coverage=coverage,
        current_findings=[],
        checkpoint_findings=[],
        receipt_reopened=set(),
    )
    assert draft["coverage"]["deferred"] == coverage["deferred"]


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("reopened", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
def test_stopped_diff_freezes_the_accepted_parent_head(
    tmp_path: Path, termination: str, reopened: bool, interrupted: bool
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    original = json.loads(coverage_path.read_text())
    terminal = {
        "id": "authored-decision",
        "candidateId": "candidate-synthetic",
        "label": "Authored review",
        "disposition": "rejected",
        "notes": "The accepted review rejected this candidate.",
        "receiptRefs": [],
    }
    rejected = {**original, "surfaces": [terminal], "deferred": []}
    previous, current = (rejected, original) if reopened else (original, rejected)
    coverage_path.write_text(json.dumps(previous))
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": False}},
                "findings": {"findings": []},
                "coverage": current,
            }
        )
    )
    arguments = ["write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged)]
    if interrupted:
        scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
        wrapper = tmp_path / "interrupt_accepted_publication.py"
        wrapper.write_text(
            f"import sys\nsys.path.insert(0, {str(scripts_dir)!r})\n"
            "import workbench_db\nimport workbench_saved_results\n"
            "original = workbench_saved_results.write_scan_local_bytes\n"
            "def interrupt(scan_dir, relative, payload, **kwargs):\n"
            "    if relative == 'coverage.json':\n"
            "        raise OSError('synthetic interrupted canonical publication')\n"
            "    return original(scan_dir, relative, payload, **kwargs)\n"
            "workbench_saved_results.write_scan_local_bytes = interrupt\n"
            "raise SystemExit(workbench_db.main())\n"
        )
        publication = subprocess.run(
            [sys.executable, str(wrapper), *arguments],
            capture_output=True,
            text=True,
            env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
        )
        assert publication.returncode != 0
        assert "synthetic interrupted canonical publication" in publication.stderr
        assert json.loads(coverage_path.read_text()) == previous
    else:
        run_workbench(state_dir, *arguments)
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    accepted = scan_dir / "checkpoints" / head["checkpoint"]
    accepted_bytes = accepted.read_bytes()
    assert json.loads(accepted_bytes)["coverage"]["deferred"] == current["deferred"]
    ledger.unlink()
    extra = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *extra)

    def assert_accepted() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == int(reopened)
        coverage = json.loads(coverage_path.read_text())
        matching = [row for row in coverage["surfaces"] if row.get("id") == terminal["id"]]
        assert bool(matching) is (not reopened)
        if matching:
            assert len(matching) == 1
            assert {key: matching[0][key] for key in terminal} == terminal
            assert set(matching[0]) - set(terminal) <= {"originalCandidates", "previousFindings"}
        assert accepted.read_bytes() == accepted_bytes

    assert_accepted()
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_accepted()


@pytest.mark.parametrize("publication_failure", ["before_freeze", "after_freeze"])
def test_stopped_diff_retries_saved_decisions_after_publication_failure(
    tmp_path: Path, publication_failure: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_publication.py"
    injected = (
        "original = workbench_saved_results.merge_saved_results\n"
        "def fail_publication(*args, **kwargs):\n"
        "    original(*args, **kwargs)\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_publication\n"
        if publication_failure == "before_freeze"
        else "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n"
    )
    wrapper.write_text(
        f"import sys\nsys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\nimport workbench_saved_results\n"
        + injected
        + "raise SystemExit(workbench_db.main())\n"
    )
    failed = subprocess.run(
        [sys.executable, str(wrapper), "fail-scan", "--scan-id", scan_id, "--message", "Stopped."],
        capture_output=True,
        text=True,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
    )
    assert failed.returncode == 0, failed.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        frozen = connection.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    assert (frozen is None) is (publication_failure == "before_freeze")
    ledger.unlink()
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unresolved"] == 0
    assert not any("publication needs follow-up" in warning for warning in scan["warnings"])


def test_stopped_diff_keeps_decision_evidence_when_parent_supersedes_checkpoints(
    tmp_path: Path,
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path, complete=True)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert not any(item.get("candidateId") for item in coverage["deferred"])
    assert {item["disposition"] for item in coverage["surfaces"]} == {"rejected"}


@pytest.mark.parametrize(
    "invalid", ["phase", "summary", "json", "NaN", "Infinity", "-Infinity", "1e400", "1e300"]
)
@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
def test_stopped_diff_preserves_pending_evidence_when_ledger_is_unusable(
    tmp_path: Path, invalid: str, termination: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    if invalid == "phase":
        candidate["validation"] = "incomplete phase output"
    elif invalid == "summary":
        del candidate["summary"]
    payload = json.dumps(candidate)
    if invalid in {"NaN", "Infinity", "-Infinity", "1e400", "1e300"}:
        payload = payload[:-1] + ', "metadata": {"estimate": ' + invalid + "}}"
    ledger.write_text("{incomplete" if invalid == "json" else payload + "\n")
    arguments = ["--message", "Stopped."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unresolved"] == 1
    assert any(
        "Could not reconcile the saved Diff candidates" in warning for warning in scan["warnings"]
    )
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
def test_stopped_diff_keeps_finite_ledger_metadata(tmp_path: Path, termination: str) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    candidate["metadata"] = {"estimate": 1.25}
    ledger.write_text(json.dumps(candidate) + "\n")
    arguments = ["--message", "Stopped."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unresolved"] == 0
    assert not any("Diff candidates" in warning for warning in scan["warnings"])
    assert (scan_dir / "report.md").is_file()


def test_stopped_diff_without_saved_candidates_does_not_consult_ledger(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path, pending=False)
    ledger.write_text("{unrelated incomplete ledger")
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unresolved"] == 0
    assert not any("Diff candidates" in warning for warning in scan["warnings"])
    assert not any(
        json.loads(path.read_text())["coverage"].get("stoppedDiffCandidateDecisions")
        for path in (scan_dir / "checkpoints").glob("*.json")
    )


@pytest.mark.parametrize("metadata", [["worker-one"], {"worker": "worker-one"}])
def test_stopped_diff_retains_imported_surface_owner_when_dismissing_candidate(
    tmp_path: Path, metadata: object
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    imported_surface = {
        "id": "imported-follow-up",
        "candidateId": "imported-candidate",
        "sourceWorkerId": metadata,
        "label": "Imported synthetic coverage",
        "disposition": "needs_follow_up",
        "notes": "Retain the imported ownership metadata.",
        "receiptRefs": [],
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"].append(imported_surface)
    coverage_path.write_text(json.dumps(coverage))
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")

    run_workbench(
        state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after review."
    )

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["progress"]["candidates"]["unresolved"] == 0
    sources = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"]
    assert any(
        imported_surface
        in json.loads((scan_dir / path).read_text()).get("coverage", {}).get("surfaces", [])
        for path in sources
    )
    assert imported_surface in json.loads(coverage_path.read_text())["surfaces"]
    assert not any(
        "Skipped malformed coverage surface" in warning for warning in stopped["warnings"]
    )
    assert not any("publication needs follow-up" in warning for warning in stopped["warnings"])
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("source", ["parent", "checkpoint"])
@pytest.mark.parametrize(
    "scenario",
    [
        "shared",
        "direct-only",
        "all-resolved",
        "linked-only",
        "linked-all-resolved",
        "other-owner",
        "direct-pending-owner",
        "cross-owner-reference",
    ],
)
def test_stopped_diff_preserves_shared_follow_up_evidence(
    tmp_path: Path, termination: str, source: str, scenario: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    first = json.loads(ledger.read_text())
    second = {**first, "candidate_id": "candidate-pending", "summary": "Second synthetic review."}
    receipt_path = scan_dir / "artifacts/shared-evidence.txt"
    receipt_path.write_text("Synthetic shared route evidence.\n")
    shared = {
        "id": "shared-follow-up",
        "candidateId": first["candidate_id"],
        "label": "Shared synthetic route",
        "disposition": "needs_follow_up",
        "notes": "Both candidates depend on this saved route evidence.",
        "receiptRefs": ["artifacts/shared-evidence.txt"],
    }
    if scenario in {"linked-only", "linked-all-resolved"}:
        shared.pop("candidateId")
    elif scenario == "other-owner":
        shared["sourceWorkerId"] = "different-worker"
    elif scenario == "direct-pending-owner":
        shared["candidateId"] = second["candidate_id"]
    deferred = [
        {
            "id": candidate["candidate_id"],
            "candidateId": candidate["candidate_id"],
            "candidate": candidate,
            "reason": "Synthetic validation remains unfinished.",
            "surfaceIds": [shared["id"]],
        }
        for candidate in (first, second)
    ]
    if scenario in {"direct-only", "other-owner", "direct-pending-owner"}:
        deferred[1]["surfaceIds"] = []
    if scenario == "cross-owner-reference":
        deferred[1]["sourceWorkerId"] = "different-worker"
    checkpoint["coverage"].update(surfaces=[shared], deferred=deferred)
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": False}},
                "findings": {"findings": []},
                "coverage": {**checkpoint["coverage"], "inventoryStrategy": "diff"},
            }
        )
    )
    run_workbench(state_dir, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    checkpoint_path = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    checkpoint_bytes = checkpoint_path.read_bytes()
    if source == "checkpoint":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan_dir / name).unlink()
    first["validation"] = {"disposition": "suppressed"}
    second["validation"] = {
        "disposition": "suppressed"
        if scenario in {"all-resolved", "linked-all-resolved"}
        else "deferred"
    }
    ledger.write_text("\n".join(json.dumps(candidate) for candidate in (first, second)) + "\n")
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_retained() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == int(
            scenario not in {"all-resolved", "linked-all-resolved"}
        )
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        pending = [row for row in coverage["deferred"] if row.get("candidateId")]
        assert [row["candidateId"] for row in pending] == (
            [] if scenario in {"all-resolved", "linked-all-resolved"} else [second["candidate_id"]]
        )
        retained = [row for row in coverage["surfaces"] if row["id"] == shared["id"]]
        if scenario in {
            "shared",
            "linked-only",
            "other-owner",
            "direct-pending-owner",
            "cross-owner-reference",
        }:
            assert retained == [shared]
        else:
            assert retained == []
        for item in pending:
            for surface_id in item["surfaceIds"]:
                assert any(row["id"] == surface_id for row in coverage["surfaces"])
        assert checkpoint_path.read_bytes() == checkpoint_bytes
        assert receipt_path.read_text() == "Synthetic shared route evidence.\n"

    assert_retained()
    first.pop("validation")
    second["validation"] = {"disposition": "suppressed"}
    ledger.write_text("\n".join(json.dumps(candidate) for candidate in (first, second)) + "\n")
    if termination == "fail-scan":
        # Admit new saved work to force replay of the original frozen decision and
        # surface checkpoints after the live ledger has changed.
        late = copy.deepcopy(checkpoint)
        late["coverage"].update(
            surfaces=[], deferred=[{"id": "late-review", "reason": "Additional saved work."}]
        )
        write_checkpoint(scan_dir / "checkpoints", late)
        run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
        assert any(
            row.get("id") == "late-review"
            for row in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
        )
    else:
        run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_retained()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize(
    "disposition", [{"status": "synthetic-review"}, ["synthetic-review"], "rejected"]
)
def test_stopped_diff_retains_generic_exclusion_extensions(
    tmp_path: Path, termination: str, disposition: object
) -> None:
    state_dir, scan_dir, scan_id, _, _ = saved_diff_candidate(tmp_path)
    exclusion = {
        "pattern": "vendor/**",
        "reason": "Synthetic imported scope exclusion.",
        "disposition": disposition,
        "annotation": "Keep the authored extension unchanged.",
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["explicitExclusions"].append(exclusion)
    coverage_path.write_text(json.dumps(coverage))
    arguments = ["--message", "Synthetic stop."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)
    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["progress"]["status"] == ("failed" if termination == "fail-scan" else "canceled")
    assert stopped["progress"]["candidates"]["unresolved"] == 1
    assert exclusion in json.loads(coverage_path.read_text())["explicitExclusions"]
    assert (scan_dir / "report.md").is_file()
    assert not any("publication needs follow-up" in warning for warning in stopped["warnings"])


@pytest.mark.parametrize("decision", ["deferred", "rejected", "not_applicable"])
@pytest.mark.parametrize("saved_shape", ["null", "scalar", "canonical"])
def test_stopped_diff_recovers_nullable_authored_finding_history(
    tmp_path: Path, decision: str, saved_shape: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    checkpoint["findings"] = [finding]
    checkpoint["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    original = saved.read_bytes()
    value = None if saved_shape == "null" else "Legacy annotation."
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(surfaces=[], explicitExclusions=[], deferred=[])
    if decision == "deferred":
        coverage["deferred"] = [
            {
                "id": "authored-gap",
                "candidateId": candidate["candidate_id"],
                "reason": "Authored proof gap remains open.",
                "finding": finding if saved_shape == "canonical" else value,
            }
        ]
    else:
        coverage["surfaces"] = [
            {
                "id": "authored-terminal",
                "candidateId": candidate["candidate_id"],
                "label": "Authored terminal review",
                "disposition": decision,
                "receiptRefs": [],
                "notes": "Authored terminal rationale.",
                "previousFindings": [finding] if saved_shape == "canonical" else value,
            }
        ]
    coverage_path.write_text(json.dumps(coverage))
    ledger.unlink()

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    for attempt in range(2):
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 0
        assert scan["progress"]["candidates"]["unresolved"] == int(decision == "deferred")
        restored = json.loads(coverage_path.read_text())
        rows = restored["deferred" if decision == "deferred" else "surfaces"]
        row = next(item for item in rows if item.get("candidateId") == candidate["candidate_id"])
        if decision == "deferred":
            assert row["finding"] == finding
            assert row["reason"] == "Authored proof gap remains open."
        else:
            assert row["previousFindings"] == [finding]
            assert row["disposition"] == decision
            assert row["notes"] == "Authored terminal rationale."
        if attempt == 0:
            run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert saved.read_bytes() == original


@pytest.mark.parametrize("shared", [False, True])
def test_stopped_diff_dismissal_resolves_unique_cross_owner_linked_surface(
    tmp_path: Path, shared: bool
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    candidate = json.loads(ledger.read_text())
    linked = {
        "id": "cross-owner-proof",
        "sourceWorkerId": "surface-worker",
        "label": "Linked proof",
        "disposition": "needs_follow_up",
        "notes": "Review the saved proof.",
        "receiptRefs": [],
    }
    coverage["surfaces"].append(linked)
    coverage["deferred"][0]["surfaceIds"] = [linked["id"]]
    if shared:
        coverage["deferred"][1]["surfaceIds"] = [linked["id"]]
    coverage_path.write_text(json.dumps(coverage))
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    run_workbench(
        state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after review."
    )
    saved = json.loads(coverage_path.read_text())
    assert (
        any(row.get("candidateId") == candidate["candidate_id"] for row in saved["deferred"])
        is False
    )
    assert any(row.get("id") == linked["id"] for row in saved["surfaces"]) is shared
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("surfaces", [None, 1, {"legacy": "annotation"}, []])
@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
def test_stopped_diff_dismissal_recovers_nonarray_saved_surfaces(
    tmp_path: Path, surfaces, termination: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"] = surfaces
    coverage["deferred"][0]["surfaceIds"] = ["saved-proof"]
    coverage_path.write_text(json.dumps(coverage))
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    arguments = ["--message", "Stopped after review."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)
    for attempt in range(2):
        saved = json.loads(coverage_path.read_text())
        assert not any(
            row.get("candidateId") == candidate["candidate_id"] for row in saved["deferred"]
        )
        assert any(row.get("id") == "other-review" for row in saved["deferred"])
        assert (scan_dir / "report.md").is_file()
        if attempt == 0 and termination == "fail-scan":
            run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)


@pytest.mark.parametrize("provenance", [None, "Saved annotation", {}, "absent"])
def test_stopped_diff_retains_opaque_embedded_finding_provenance(
    tmp_path: Path, provenance
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    checkpoint["findings"] = [finding]
    checkpoint["coverage"].update(surfaces=[], deferred=[])
    saved = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    original_checkpoint = saved.read_bytes()
    embedded = {"title": "Earlier authored evidence"}
    if provenance != "absent":
        embedded["provenance"] = provenance
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(
        surfaces=[],
        explicitExclusions=[],
        deferred=[
            {
                "id": "authored-gap",
                "candidateId": candidate["candidate_id"],
                "reason": "Authored proof gap remains open.",
                "finding": embedded,
            }
        ],
    )
    coverage_path.write_text(json.dumps(coverage))
    ledger.unlink()
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    for attempt in range(2):
        restored = json.loads(coverage_path.read_text())
        row = next(
            item
            for item in restored["deferred"]
            if item.get("candidateId") == candidate["candidate_id"]
        )
        if isinstance(provenance, dict):
            assert row["finding"]["title"] == embedded["title"]
            assert row["finding"]["provenance"]["previousFindings"] == [finding]
        else:
            assert row["finding"] == embedded
            assert row["previousFindings"] == [finding]
        assert row["reason"] == "Authored proof gap remains open."
        assert (scan_dir / "report.md").is_file()
        if attempt == 0:
            run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    assert saved.read_bytes() == original_checkpoint


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("same_candidate", [False, True])
@pytest.mark.parametrize(
    "disposition", [{"status": "synthetic-review"}, ["synthetic-review"], "unreviewed"]
)
def test_stopped_diff_retains_historical_exclusion_extensions(
    tmp_path: Path, termination: str, same_candidate: bool, disposition: object
) -> None:
    state_dir, scan_dir, scan_id, _, checkpoint = saved_diff_candidate(tmp_path)
    exclusion = {
        "id": "historical-exclusion",
        "pattern": "vendor/**",
        "reason": "Earlier imported scope exclusion.",
        "candidateId": "candidate-synthetic" if same_candidate else "independent-candidate",
        "disposition": disposition,
        "annotation": "Keep the authored historical extension unchanged.",
    }
    historical = copy.deepcopy(checkpoint)
    historical["coverage"].update(surfaces=[], deferred=[], explicitExclusions=[exclusion])
    saved = write_checkpoint(scan_dir / "checkpoints", historical)
    original = saved.read_bytes()
    coverage_path = scan_dir / "coverage.json"
    current = coverage_path.read_bytes()
    coverage_path.write_bytes(current)
    observed = coverage_path.stat().st_mtime_ns
    os.utime(saved, ns=(observed - 1_000_000_000, observed - 1_000_000_000))
    arguments = ["--message", "Synthetic stop."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_retained() -> None:
        stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert stopped["progress"]["status"] == (
            "failed" if termination == "fail-scan" else "canceled"
        )
        assert stopped["progress"]["candidates"]["unresolved"] == 1
        assert exclusion in json.loads(coverage_path.read_text())["explicitExclusions"]
        assert (scan_dir / "report.md").is_file()
        assert not any("publication needs follow-up" in warning for warning in stopped["warnings"])
        assert saved.read_bytes() == original

    assert_retained()
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_retained()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("malformed_receipts", [False, True])
def test_stopped_diff_recovers_receipts_before_freezing_authored_gap(
    tmp_path: Path, termination: str, malformed_receipts: bool
) -> None:
    state, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    pending = next(row for row in coverage["deferred"] if row.get("candidateId"))
    pending.update(
        reason="Original authored proof gap and diagnostic text.",
        candidate={**candidate, "annotation": "Original candidate annotation."},
        finding={"title": "Original compact finding annotation."},
    )
    original_pending = copy.deepcopy(pending)
    surface = next(row for row in coverage["surfaces"] if row.get("candidateId"))
    surface.update(disposition="rejected", receiptRefs=None if malformed_receipts else [])
    coverage_path.write_text(json.dumps(coverage))
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state, termination, "--scan-id", scan_id, *arguments)
    saved = json.loads(coverage_path.read_text())
    rows = [row for row in saved["deferred"] if row.get("candidateId") == candidate["candidate_id"]]
    assert bool(rows) is malformed_receipts
    assert run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["progress"]["candidates"][
        "unresolved"
    ] == int(malformed_receipts)
    if rows:
        assert any(
            {key: row.get(key) for key in original_pending} == original_pending for row in rows
        )
    assert any(row.get("id") == "other-review" for row in saved["deferred"])


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("decision", ["suppressed", "deferred"])
def test_stopped_diff_archives_every_deferred_payload_before_resolution(
    tmp_path: Path, termination: str, decision: str
) -> None:
    state, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    history = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    original = next(row for row in coverage["deferred"] if row.get("candidateId"))
    rows = []
    for index in range(2):
        row = copy.deepcopy(original)
        row.update(
            id=f"history-gap-{index}",
            reason=f"Original authored proof gap {index}.",
            candidate={**candidate, "savedEvidence": f"Candidate annotation {index}."},
            finding={"title": f"Original compact finding annotation {index}."},
            previousFindings=[{**history, "summary": f"Original saved finding history {index}."}],
        )
        rows.append(row)
    coverage["deferred"] = [*rows, {"id": "other-review", "reason": "Independent review."}]
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": False}},
                "findings": {"findings": []},
                "coverage": coverage,
            }
        )
    )
    run_workbench(state, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    candidate["validation"] = {"disposition": decision}
    ledger.write_text(json.dumps(candidate) + "\n")
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state, termination, "--scan-id", scan_id, *arguments)

    def contains(value: object, expected: object) -> bool:
        if isinstance(value, list):
            return any(contains(child, expected) for child in value)
        if isinstance(value, dict):
            if isinstance(expected, dict) and all(
                key in value and value[key] == item for key, item in expected.items()
            ):
                return True
            return any(contains(child, expected) for child in value.values())
        return value == expected

    def assert_retained() -> None:
        saved = json.loads(coverage_path.read_text())
        for row in rows:
            assert contains(saved, {"savedEvidence": row["candidate"]["savedEvidence"]})
            assert contains(saved, row["finding"])
            assert contains(saved, row["previousFindings"][0])
        pending = [
            row for row in saved["deferred"] if row.get("candidateId") == candidate["candidate_id"]
        ]
        assert bool(pending) is (decision == "deferred")
        assert any(row.get("id") == "other-review" for row in saved["deferred"])

    assert_retained()
    frozen = {
        scan_dir / relative: (scan_dir / relative).read_bytes()
        for relative in json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
            "preservedSources"
        ]
    }
    ledger.unlink()
    if termination == "fail-scan":
        run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
    else:
        refused = run_workbench(state, "recover-scan-results", "--scan-id", scan_id, check=False)
        assert refused["returncode"] != 0
        assert "Canceled scans cannot recover terminal results." in refused["stderr"]
        run_workbench(state, "get-scan", "--scan-id", scan_id)
    assert_retained()
    assert all(path.read_bytes() == content for path, content in frozen.items())


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("outcome", ["finding", "rejected"])
def test_stopped_diff_archives_deferred_evidence_on_authored_resolution(
    tmp_path: Path, termination: str, outcome: str
) -> None:
    state, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    original = next(row for row in coverage["deferred"] if row.get("candidateId"))
    payloads = []
    for index in range(2):
        row = copy.deepcopy(original)
        row.update(
            id=f"authored-history-{index}",
            candidate={**candidate, "annotation": f"Saved deferred evidence {index}."},
            finding={"title": f"Saved compact finding {index}."},
            previousFindings=[{**finding, "summary": f"Saved full history {index}."}],
        )
        payloads.append(row)
    coverage["deferred"] = [*payloads, {"id": "other-review", "reason": "Independent review."}]
    if outcome == "rejected":
        coverage["surfaces"] = [
            {
                "id": "authored-terminal",
                "candidateId": candidate["candidate_id"],
                "label": "Authored terminal review",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ]
    else:
        coverage["surfaces"] = []
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": False}},
                "findings": {"findings": [finding] if outcome == "finding" else []},
                "coverage": coverage,
            }
        )
    )
    run_workbench(state, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state, termination, "--scan-id", scan_id, *arguments)

    def contains(value: object, expected: object) -> bool:
        if value == expected:
            return True
        if isinstance(value, list):
            return any(contains(item, expected) for item in value)
        return isinstance(value, dict) and any(contains(item, expected) for item in value.values())

    def assert_retained() -> None:
        saved = json.loads(coverage_path.read_text())
        values = [saved, json.loads((scan_dir / "findings.json").read_text())]
        for row in payloads:
            for expected in [row["candidate"], row["finding"], *row["previousFindings"]]:
                assert contains(values, expected)
        assert not any(
            row.get("candidateId") == candidate["candidate_id"] for row in saved["deferred"]
        )
        assert any(row.get("id") == "other-review" for row in saved["deferred"])

    assert_retained()
    ledger.unlink()
    if termination == "fail-scan":
        run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
    else:
        run_workbench(state, "get-scan", "--scan-id", scan_id)
    assert_retained()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("field", ["surfaces", "explicitExclusions"])
def test_stopped_diff_replacement_archives_prior_terminal_payload(
    tmp_path: Path, termination: str, field: str
) -> None:
    state, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    finding = saved_candidate_finding(tmp_path, scan_id, candidate["candidate_id"])
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    historical = {
        "id": "historical-terminal",
        "candidateId": candidate["candidate_id"],
        "label": "Historical candidate review",
        "disposition": "rejected",
        "receiptRefs": [],
        "notes": "Previous authored decision.",
        "candidate": {**candidate, "annotation": "Original terminal candidate evidence."},
        "finding": {"title": "Original compact terminal finding."},
        "previousFindings": [{**finding, "summary": "Original full terminal finding."}],
    }
    if field == "explicitExclusions":
        historical.update(pattern="README.md", reason="Authored exclusion review.")
    coverage["surfaces"] = []
    coverage["explicitExclusions"] = []
    coverage["deferred"] = [{"id": "independent-gap", "reason": "Independent review remains."}]
    coverage[field] = [historical]
    for old in (True, False):
        submitted = copy.deepcopy(coverage)
        if not old:
            submitted[field] = [
                {
                    key: value
                    for key, value in historical.items()
                    if key not in ("candidate", "finding", "previousFindings")
                }
            ]
            submitted[field][0].update(id="current-terminal", notes="Current authored decision.")
        staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
        staged.write_text(
            json.dumps(
                {
                    "manifest": {"scan": {"complete": False}},
                    "findings": {"findings": []},
                    "coverage": submitted,
                }
            )
        )
        run_workbench(state, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    ledger.unlink()
    checkpoints = {path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")}
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state, termination, "--scan-id", scan_id, *arguments)

    def contains(value: object, expected: object) -> bool:
        if value == expected:
            return True
        if isinstance(value, list):
            return any(contains(item, expected) for item in value)
        return isinstance(value, dict) and any(contains(item, expected) for item in value.values())

    def assert_retained() -> None:
        saved = json.loads(coverage_path.read_text())
        for payload in [
            historical["candidate"],
            historical["finding"],
            *historical["previousFindings"],
        ]:
            assert contains(saved, payload)
        rows = saved[field]
        assert any(row.get("notes") == "Current authored decision." for row in rows)
        assert not any(row.get("notes") == "Previous authored decision." for row in rows)
        assert any(row.get("id") == "independent-gap" for row in saved["deferred"])
        assert all(path.read_bytes() == original for path, original in checkpoints.items())

    assert_retained()
    if termination == "fail-scan":
        run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
    else:
        run_workbench(state, "get-scan", "--scan-id", scan_id)
    assert_retained()


@pytest.mark.parametrize(
    "payload,archive", [("candidate", "originalCandidates"), ("finding", "previousFindings")]
)
@pytest.mark.parametrize("comparison", ["destination", "archive"])
def test_stopped_diff_preserves_type_distinct_opaque_candidate_history(
    tmp_path: Path, payload: str, archive: str, comparison: str
) -> None:
    state, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    pending = next(row for row in coverage["deferred"] if row.get("candidateId"))
    boolean = {"opaque": [True, {"value": False}]}
    numeric = {"opaque": [1, {"value": 0}]}
    pending[payload] = numeric if comparison == "destination" else boolean
    pending[archive] = [numeric, copy.deepcopy(numeric)] if comparison == "archive" else []
    surface = next(row for row in coverage["surfaces"] if row.get("candidateId"))
    surface.update(disposition="rejected", receiptRefs=[])
    if comparison == "destination":
        surface[payload] = boolean
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": False}},
                "findings": {"findings": []},
                "coverage": coverage,
            }
        )
    )
    run_workbench(state, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    ledger.unlink()
    checkpoints = {path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")}
    run_workbench(state, "fail-scan", "--scan-id", scan_id, "--message", "Synthetic stop.")

    def assert_retained() -> None:
        saved = json.loads(coverage_path.read_text())
        terminal = next(row for row in saved["surfaces"] if row.get("candidateId"))
        values = ([terminal[payload]] if payload in terminal else []) + terminal.get(archive, [])
        encoded = [json.dumps(value, sort_keys=True) for value in values]
        assert json.dumps(boolean, sort_keys=True) in encoded
        assert json.dumps(numeric, sort_keys=True) in encoded
        assert encoded.count(json.dumps(numeric, sort_keys=True)) == 1
        assert not any(row.get("candidateId") for row in saved["deferred"])
        assert all(path.read_bytes() == contents for path, contents in checkpoints.items())

    assert_retained()
    run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
    assert_retained()
