import json
import subprocess
import sys
import uuid
from pathlib import Path

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
    for batch in [decisions[:5], decisions[5:]]:
        subprocess.run(
            [sys.executable, SCRIPT, "record", scan], input=json.dumps(batch), text=True, check=True
        )
    assert page() == []
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
    stage.write_text(json.dumps(documents))
    scan_command(state, "write-scan-draft", scan_id, "--draft-path", str(stage))
    completed = scan_command(state, "complete-scan", scan_id)
    assert completed["scan"]["findingCount"] == 2
