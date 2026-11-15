import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    empty_target_scan,
    get_scan,
    scan_command,
    write_completed_contract,
)

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "standard_validation.py"


def test_standard_cannot_publish_a_shortlist(tmp_path):
    state, target, scan_id, scan = empty_target_scan(tmp_path)
    write_completed_contract(scan, scan_id, target)
    queue = scan / "artifacts/01_context/standard-queue.json"
    queue.parent.mkdir(parents=True, exist_ok=True)
    returned = "artifacts/02_discovery/worker.json"
    (scan / returned).parent.mkdir(parents=True, exist_ok=True)
    (scan / returned).write_text(
        json.dumps(
            {
                "reviewed_files": ["src/extract.py"],
                "findings": [{"title": f"claim {i}"} for i in range(6)],
                "resolved_questions": ["The path has a partial guard."],
            }
        )
    )
    queue.write_text(
        json.dumps(
            {
                "reviewed": ["src/extract.py"],
                "batches": [["src/extract.py"]],
                "returns": [{"file": returned, "count": 6}],
            }
        )
    )

    def page(after=0):
        return json.loads(
            subprocess.check_output([sys.executable, SCRIPT, "pending", scan, str(after)])
        )

    first = page()
    assert [row["cursor"] for row in first] == list(range(1, 6))
    assert first[0]["counterevidence"] == ["The path has a partial guard."]
    assert [row["cursor"] for row in page(5)] == [6]

    documents = {
        key: json.loads((scan / filename).read_text())
        for key, filename in (
            ("manifest", "scan-manifest.json"),
            ("reviewState", "coverage.json"),
            ("findings", "findings.json"),
        )
    }
    manifest = documents["manifest"]["scan"]
    manifest.pop("coverageRef")
    manifest["mode"] = "repository"
    manifest["reviewState"] = {
        key: documents["reviewState"][key] for key in ("surfaces", "deferred", "explicitExclusions")
    }
    (scan / "scan-manifest.json").write_text(json.dumps(documents["manifest"]))
    (scan / "coverage.json").unlink()
    stage = scan / "drafts" / f"{uuid.uuid4()}.json"
    stage.parent.mkdir(exist_ok=True)
    stage.write_text(json.dumps(documents))
    for cmd in [("write-scan-draft", "--draft-path", str(stage)), ("complete-scan",)]:
        rejected = scan_command(state, cmd[0], scan_id, *cmd[1:], check=False)
        assert "standard-1 has no decision" in rejected["stderr"]

    assert get_scan(state, scan_id)["scan"]["progress"]["status"] == "running"
    decisions = [
        {
            "candidateId": f"standard-{i}",
            "parts": [{"disposition": disposition, "reason": "Reviewed src/extract.py:41."}],
        }
        for i, disposition in enumerate(
            ["reportable", "duplicate", "rejected", "not_applicable", "deferred", "reportable"], 1
        )
    ]
    decisions[0]["parts"].append(
        {"disposition": "reportable", "reason": "Independent control in src/extract.py:44."}
    )
    decisions[1]["parts"][0]["duplicateOf"] = "standard-1.1"

    def record(batch, check=True):
        return subprocess.run(
            [sys.executable, SCRIPT, "record", scan],
            input=json.dumps(batch),
            text=True,
            capture_output=True,
            check=check,
        )

    record(decisions[:5])
    record(decisions[5:])
    assert page() == []
    recorded_deferred = decisions[4]
    record([recorded_deferred])
    rewritten = {
        **recorded_deferred,
        "parts": [{"disposition": "duplicate", "duplicateOf": "standard-1.1", "reason": "Same."}],
    }
    assert "already has a different decision" in record([rewritten], check=False).stderr
    finding = documents["findings"]["findings"][0]
    finding["provenance"].update(candidateId="standard-1.1", duplicateCandidateIds=["standard-6.1"])
    review = documents["reviewState"]
    for index, disposition in [(3, "rejected"), (4, "not_applicable")]:
        review["surfaces"].append(
            {
                "id": f"review-{index}",
                "candidateId": f"standard-{index}.1",
                "label": "Reviewed claim",
                "disposition": disposition,
                "notes": "Read the guard at line 41.",
                "receiptRefs": [],
            }
        )
    review["deferred"].append(
        {
            "id": "standard-5.1",
            "candidateId": "standard-5.1",
            "reason": "The configured backend is unknown.",
            "paths": ["src/extract.py"],
        }
    )
    stage.write_text(json.dumps(documents))
    rejected = scan_command(
        state, "write-scan-draft", scan_id, "--draft-path", str(stage), check=False
    )
    assert "standard-1.2 is reportable" in rejected["stderr"]
    sibling = {
        **finding,
        "identity": {"anchor": "independent-control"},
        "provenance": {"source": "local_plugin", "candidateId": "standard-1.2"},
    }
    documents["findings"]["findings"].append(sibling)
    # The rejection surface alone must not authorize also publishing the rejected claim.
    sibling["provenance"]["candidateId"] = "standard-3.1"
    stage.write_text(json.dumps(documents))
    rejected = scan_command(
        state, "write-scan-draft", scan_id, "--draft-path", str(stage), check=False
    )
    assert "standard-3.1 is rejected and cannot be a finding" in rejected["stderr"]
    sibling["provenance"]["candidateId"] = "standard-1.2"
    finding["provenance"]["duplicateCandidateIds"].append("standard-5.1")
    stage.write_text(json.dumps(documents))
    rejected = scan_command(
        state, "write-scan-draft", scan_id, "--draft-path", str(stage), check=False
    )
    assert "standard-5.1 is deferred" in rejected["stderr"]
    finding["provenance"]["duplicateCandidateIds"].pop()
    stage.write_text(json.dumps(documents))
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", str(stage))
    # Both publication paths must reject a candidate ID without a per-claim decision.
    extra = {
        **sibling,
        "identity": {"anchor": "additional-finding"},
        "provenance": {"source": "local_plugin", "candidateId": "standard-3"},
    }
    documents["findings"]["findings"].append(extra)
    stage.write_text(json.dumps(documents))
    (scan / "findings.json").write_text(json.dumps(documents["findings"]))
    draft = scan_command(
        state, "write-scan-draft", scan_id, "--draft-path", str(stage), check=False
    )
    final = scan_command(state, "complete-scan", scan_id, check=False)
    for result in (draft, final):
        assert "standard-3 has no recorded claim decision" in result["stderr"]

    # A separate finding can use its own ID. Any Standard aliases still need a claim decision.
    extra["provenance"]["candidateId"] = "independent-review"
    extra["provenance"]["duplicateCandidateIds"] = ["standard-1.3"]
    stage.write_text(json.dumps(documents))
    rejected = scan_command(
        state, "write-scan-draft", scan_id, "--draft-path", str(stage), check=False
    )
    assert "standard-1.3 has no recorded claim decision" in rejected["stderr"]
    del extra["provenance"]["duplicateCandidateIds"]
    stage.write_text(json.dumps(documents))
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", str(stage))
    completed = scan_command(state, "complete-scan", scan_id)
    assert completed["scan"]["findingCount"] == 3


def test_registered_deadline_reports_unread_paths_and_pending_candidates(tmp_path):
    from test_workbench_completion_binding import register_cli_scan
    from workbench_test_support import read_review_state

    state, target, scan = (tmp_path / name for name in ("state", "target", "scan"))
    target.mkdir()
    receipt = register_cli_scan(state, target, scan, recipe_fields={"maxTimeMinutes": 1})
    scan_id = receipt["scanId"]
    assert receipt["canSaveTimeBudgetStart"]
    write_completed_contract(scan, scan_id, target)
    manifest_path = scan / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    findings = json.loads((scan / "findings.json").read_text())
    coverage = json.loads((scan / "coverage.json").read_text())
    finding = findings["findings"][0]
    finding["provenance"]["candidateId"] = "standard-1.1"
    pending = {"title": "Unverified boundary", "source": "src/read.py:2"}
    source = {
        "reviewed_files": ["src/read.py"],
        "findings": [{"title": finding["title"]}, pending],
        "resolved_questions": ["A guard is active on the first route."],
    }
    returned = "artifacts/02_discovery/worker.json"
    (scan / returned).parent.mkdir(parents=True, exist_ok=True)
    (scan / returned).write_text(json.dumps(source))
    queue = scan / "artifacts/01_context/standard-queue.json"
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.write_text(
        json.dumps(
            {
                "batches": [["src/read.py", "src/z.py", "src/b.py", "src/a.py"]],
                "reviewed": ["src/read.py"],
                "returns": [{"file": returned, "count": 2}],
            }
        )
    )
    subprocess.run(
        [sys.executable, SCRIPT, "record", scan],
        input=json.dumps(
            [
                {
                    "candidateId": "standard-1",
                    "parts": [
                        {
                            "disposition": "reportable",
                            "reason": "The entry point reaches the operation.",
                        }
                    ],
                }
            ]
        ),
        text=True,
        check=True,
    )
    manifest["scan"].pop("coverageRef")
    manifest["scan"]["mode"] = "repository"
    (scan / "coverage.json").unlink()
    stage = scan / "drafts" / f"{uuid.uuid4()}.json"
    stage.parent.mkdir(exist_ok=True)
    unread = {
        "id": "unread",
        "paths": ["src/z.py", "src/a.py"],
        "reason": "Time expired before reading these files.",
    }
    coverage["deferred"] = [unread]

    def publish(*, check=True):
        manifest["scan"]["reviewState"] = {
            k: coverage[k] for k in ("surfaces", "explicitExclusions", "deferred")
        }
        manifest_path.write_text(json.dumps(manifest))
        (scan / "findings.json").write_text(json.dumps(findings))
        stage.write_text(
            json.dumps({"manifest": manifest, "reviewState": coverage, "findings": findings})
        )
        return scan_command(
            state, "write-scan-draft", scan_id, "--draft-path", str(stage), check=check
        )

    # An allowance without its registered start cannot waive unfinished files.
    assert "3 Standard target files still need review" in publish(check=False)["stderr"]
    assert (
        "still need review" in scan_command(state, "complete-scan", scan_id, check=False)["stderr"]
    )
    scan_command(
        state,
        "set-scan-thread",
        scan_id,
        "--thread-id",
        "fixture",
        "--time-budget-started-at",
        "2000-01-01T00:00:00Z",
    )
    assert "Name every unread" in publish(check=False)["stderr"]
    coverage["deferred"].append(
        {"id": "another", "paths": ["src/b.py"], "reason": "Unopened batch."}
    )
    assert "standard-2 has no decision" in publish(check=False)["stderr"]
    proof_gap = {
        "id": "caller-proof-gap",
        "candidateId": "standard-2",
        "reason": "The second route still needs a reachability check.",
        "paths": ["src/read.py"],
    }
    coverage["deferred"].append(proof_gap)
    finding["provenance"]["duplicateCandidateIds"] = ["standard-2"]
    assert "standard-2 has no recorded claim decision" in publish(check=False)["stderr"]
    assert (
        "standard-2 has no recorded claim decision"
        in scan_command(state, "complete-scan", scan_id, check=False)["stderr"]
    )
    del finding["provenance"]["duplicateCandidateIds"]
    publish()
    result = scan_command(state, "complete-scan", scan_id)
    assert result["scan"]["findingCount"] == 1
    assert json.loads(queue.read_text())["reviewed"] == ["src/read.py"]
    deferred = read_review_state(state, scan)["deferred"]
    saved = next(row for row in deferred if row.get("candidateId") == "standard-2")
    assert saved["candidate"] == pending
    assert saved["counterevidence"] == source["resolved_questions"]
    assert saved["reviewed_files"] == source["reviewed_files"]
    assert unread in deferred
    report = (scan / "report.md").read_text()
    assert "## Deferred Requested Work" in report
    for label in ("src/a.py", "src/b.py", "src/z.py", proof_gap["reason"], finding["title"]):
        assert label in report
    assert [
        f["provenance"]["candidateId"]
        for f in json.loads((scan / "findings.json").read_text())["findings"]
    ] == ["standard-1.1"]
    queue.write_text(json.dumps({"batches": [["src/changed.py"]], "reviewed": [], "returns": []}))
    scan_command(state, "complete-scan", scan_id)
    assert (scan / "report.md").read_text() == report


@pytest.mark.parametrize("use_queue", [True, False], ids=["local-queue", "in-context"])
def test_deadline_file_handoff_waits_for_custom_validation(tmp_path, use_queue):
    from workbench_test_support import run_workbench

    state, target, scan = (tmp_path / name for name in ("state", "target", "scan"))
    target.mkdir()
    scan.mkdir(mode=0o700)
    recipe = {
        "mode": "standard",
        "config": {},
        "repository": str(target),
        "target": {"kind": "repository", "paths": []},
        "maxTimeMinutes": 1,
        "validationMode": "custom",
    }
    scan_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(scan),
        "--registration-json-stdin",
        input_text=json.dumps({"recipe": recipe, "surface": "sdk", "hosted": not use_queue}),
    )["scanId"]
    scan_command(
        state,
        "set-scan-thread",
        scan_id,
        "--thread-id",
        "fixture",
        "--time-budget-started-at",
        "2000-01-01T00:00:00Z",
    )
    write_completed_contract(scan, scan_id, target)
    queue = scan / "artifacts/01_context/standard-queue.json"
    queue.parent.mkdir(parents=True, exist_ok=True)
    if use_queue:
        queue.write_text(
            json.dumps({"batches": [["src/unread.py"]], "reviewed": [], "returns": []})
        )
    manifest_path = scan / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    coverage = json.loads((scan / "coverage.json").read_text())
    coverage["deferred"] = [
        {
            "id": "unread",
            "paths": ["src/unread.py"],
            "reason": "The investigation allowance elapsed before opening the file.",
        }
    ]
    manifest["scan"].pop("coverageRef")
    manifest["scan"]["mode"] = "repository"
    manifest["scan"]["reviewState"] = {
        k: coverage[k] for k in ("surfaces", "explicitExclusions", "deferred")
    }
    (scan / "coverage.json").unlink()
    for mode in [None, "custom_pending", "unknown"]:
        if mode is not None:
            manifest["scan"]["scope"]["validationMode"] = mode
        manifest_path.write_text(json.dumps(manifest))
        if mode == "custom_pending" and use_queue:
            # The bound discovery handoff can be accepted before separate SDK validation.
            stage = scan / "drafts" / f"{uuid.uuid4()}.json"
            stage.parent.mkdir(exist_ok=True)
            stage.write_text(
                json.dumps(
                    {
                        "manifest": manifest,
                        "reviewState": coverage,
                        "findings": json.loads((scan / "findings.json").read_text()),
                    }
                )
            )
            assert (
                scan_command(state, "write-scan-draft", scan_id, "--draft-path", str(stage))[
                    "status"
                ]
                == "draft_written"
            )
        assert (
            "awaiting custom validation"
            in scan_command(state, "complete-scan", scan_id, check=False)["stderr"]
        )
    assert get_scan(state, scan_id)["scan"]["progress"]["status"] == "running"
    # The SDK now owns the separate validation turn; simulate its accepted file handoff.
    manifest["scan"]["scope"]["validationMode"] = "custom"
    manifest_path.write_text(json.dumps(manifest))
    assert scan_command(state, "complete-scan", scan_id)["scan"]["findingCount"] == 1
    assert "src/unread.py" in (scan / "report.md").read_text()
    assert (
        json.loads(manifest_path.read_text())["scan"]["reviewState"]["deferred"]
        == coverage["deferred"]
    )


def test_deadline_checks_require_original_elapsed_allowance():
    from workbench_test_support import load_script

    elapsed = load_script("standard_validation").investigation_deadline_elapsed
    past = "2000-01-01T00:00:00Z"
    assert elapsed({"timeBudgetStartedAt": past, "maxTimeMinutes": 0.5})
    for recipe in [
        {},
        {"timeBudgetStartedAt": past},
        {"maxTimeMinutes": 0.5},
        {"timeBudgetStartedAt": "2999-01-01T00:00:00Z", "maxTimeMinutes": 0.5},
        {"timeBudgetStartedAt": "2000-01-01", "maxTimeMinutes": 0.5},
        {"timeBudgetStartedAt": past, "maxTimeMinutes": True},
        {"timeBudgetStartedAt": past, "maxTimeMinutes": -1},
    ]:
        assert not elapsed(recipe)


def test_elapsed_deadline_keeps_recorded_proof_gap_after_queue_finishes(tmp_path):
    from test_workbench_completion_binding import register_cli_scan

    state, target, scan = (tmp_path / name for name in ("state", "target", "scan"))
    target.mkdir()
    scan_id = register_cli_scan(state, target, scan, recipe_fields={"maxTimeMinutes": 1})["scanId"]
    scan_command(
        state,
        "set-scan-thread",
        scan_id,
        "--thread-id",
        "fixture",
        "--time-budget-started-at",
        "2000-01-01T00:00:00Z",
    )
    write_completed_contract(scan, scan_id, target)
    queue = scan / "artifacts/01_context/standard-queue.json"
    queue.parent.mkdir(parents=True, exist_ok=True)
    returned = "artifacts/02_discovery/worker.json"
    (scan / returned).parent.mkdir(parents=True, exist_ok=True)
    (scan / returned).write_text(
        json.dumps(
            {
                "findings": [{"title": "Potential bypass"}],
                "reviewed_files": ["src/read.py"],
                "resolved_questions": [],
            }
        )
    )
    queue.write_text(
        json.dumps(
            {
                "batches": [["src/read.py"]],
                "reviewed": ["src/read.py"],
                "returns": [{"file": returned, "count": 1}],
            }
        )
    )
    reason = "The backend configuration needed to verify the route was unavailable."
    subprocess.run(
        [sys.executable, SCRIPT, "record", scan],
        input=json.dumps(
            [
                {
                    "candidateId": "standard-1",
                    "parts": [{"disposition": "deferred", "reason": reason}],
                }
            ]
        ),
        text=True,
        check=True,
    )
    manifest_path = scan / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    coverage = json.loads((scan / "coverage.json").read_text())
    coverage["deferred"] = [
        {
            "id": "proof-gap",
            "candidateId": "standard-1.1",
            "reason": reason,
            "paths": ["src/read.py"],
        }
    ]
    manifest["scan"].pop("coverageRef")
    manifest["scan"]["mode"] = "repository"
    manifest["scan"]["reviewState"] = {
        k: coverage[k] for k in ("surfaces", "explicitExclusions", "deferred")
    }
    (scan / "coverage.json").unlink()
    manifest_path.write_text(json.dumps(manifest))
    assert scan_command(state, "complete-scan", scan_id)["scan"]["findingCount"] == 1
    assert reason in (scan / "report.md").read_text()
    assert (
        json.loads(manifest_path.read_text())["scan"]["reviewState"]["deferred"]
        == coverage["deferred"]
    )
