from __future__ import annotations

import copy
import hashlib
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_db import BUDGET_COST


def host_checkpoint(directory, source):
    # The draft tool names pretty-printed snapshots by their compact JSON.
    name = hashlib.sha256(json.dumps(source, separators=(",", ":")).encode()).hexdigest()
    path = directory / f"{name}.json"
    path.write_text(json.dumps(source, indent=2) + "\n")
    return path


@pytest.fixture
def legacy_budget(workbench_db, publication_scan):
    def create(*, named=True, duplicate=True, receipt_owner=None, scoped_checkpoint=False):
        scan = publication_scan(scope="subdir/extract.py" if scoped_checkpoint else ".")
        worker_id = add_worker(workbench_db, scan).parent.name
        result = (
            scan.scan_dir / "artifacts/deep_discovery/workers/discovery-0001/output/result.json"
        )
        result.parent.mkdir(parents=True)
        receipt = result.parent / "artifacts/review.md"
        receipt.parent.mkdir()
        receipt.write_text("Synthetic accepted review evidence.\n")
        surfaces = [
            {
                "label": "Filesystem boundary",
                "disposition": "needs_follow_up",
                "notes": "The race remains untested.",
                "reason": "The caller policy is unknown.",
                "receiptRefs": ["artifacts/review.md"],
                "provenance": {"source": "independent-review"},
            },
            {
                "label": "Configuration boundary",
                "disposition": "rejected",
                "reason": "Only trusted configuration reaches this path.",
                "receiptRefs": ["artifacts/review.md"],
                "provenance": {"source": "independent-review"},
            },
        ]
        if receipt_owner is not None:
            shared = scan.scan_dir / "artifacts/review.md"
            shared.write_text("Different evidence recorded at the scan root.\n")
            for surface in surfaces:
                surface["provenance"]["scanReceiptRefs"] = surface["receiptRefs"]
            if receipt_owner == "scan":
                receipt = shared
        if named:
            for index, surface in enumerate(surfaces):
                surface["id"] = f"source-{index}"
        source = {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": scan.findings,
            "coverage": {**scan.coverage, "completeness": "partial", "surfaces": surfaces},
        }
        contents = (json.dumps(source, indent=2) + "\n").encode()
        digest = hashlib.sha256(contents).hexdigest()
        checkpoints = result.parent / "checkpoints"
        checkpoints.mkdir()
        if receipt_owner == "scan" and not scoped_checkpoint:
            accepted = host_checkpoint(checkpoints, source)
        else:
            accepted = checkpoints / f"{digest}.json"
            accepted.write_bytes(contents)
        if scoped_checkpoint:
            full = copy.deepcopy(source)
            outside = copy.deepcopy(scan.findings[0])
            outside["locations"][0]["path"] = "unrelated.py"
            full["findings"].append(outside)
            if receipt_owner == "worker":
                full["coverage"]["surfaces"][0]["provenance"]["scanReceiptRefs"] = []
                (checkpoints / ("0" * 64 + ".json")).write_text("unfinished checkpoint")
            host_checkpoint(checkpoints, full)
        result.write_text("Later unaccepted output must not replace the accepted checkpoint.")
        provenance = {"workerId": worker_id, "attempt": 1}
        prefix = f"{worker_id}-attempt-1"
        # This is the persisted old-writer shape at its draft commit: one copy
        # lacks descriptive provenance; an interrupted projection adds another.
        projected = []
        for index, surface in enumerate(surfaces):
            item = copy.deepcopy(surface)
            item["id"] = f"{prefix}-surface-{index + 1}"
            item["receiptRefs"] = [receipt.relative_to(scan.scan_dir).as_posix()]
            item["provenance"] = {
                **provenance,
                **({"sourceId": surface["id"]} if named else {}),
                **({"scanReceiptRefs": surface["receiptRefs"]} if receipt_owner else {}),
            }
            projected.append(item)
        coverage = {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": projected,
            "reviews": [{**provenance, "completeness": "partial"}],
            "deferred": [
                {
                    "id": f"{prefix}-unmerged",
                    "provenance": provenance,
                    "reason": "This accepted discovery was not merged before the scan reached its cost limit.",
                },
                {
                    "id": "scan-cost-limit",
                    "reason": "Validation was deferred because the scan reached its cost limit.",
                },
            ],
        }
        if duplicate:
            for item in copy.deepcopy(projected):
                item["provenance"]["source"] = "independent-review"
                projected.append(item)
        (scan.scan_dir / "coverage.json").write_text(json.dumps(coverage))
        (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
        selection = {
            "version": 1,
            "resultPath": None,
            "resultSha256": None,
            "terminalReason": "capped",
            "omittedWorkerIds": [worker_id],
            "selectedAt": scan.timestamp,
        }
        with workbench_db:
            recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
            recipe["maxCostUsd"] = 0.005
            workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
            workbench_db.execute(
                "UPDATE deep_scan_workers SET merge_state = 'buffered', artifact_dir = ?, "
                "result_manifest_path = ? WHERE id = ?",
                (str(result.parent), str(result), worker_id),
            )
            workbench_db.execute(
                "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
                "completed_at, accepted_result_path, accepted_result_sha256) "
                "VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
                (scan.scan_id, worker_id, scan.timestamp, scan.timestamp, str(accepted), digest),
            )
            workbench_db.execute(
                "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
                "terminal_reason = 'capped', finalization_input_json = ?",
                (json.dumps(selection),),
            )
        scan.accepted, scan.contents, scan.source = accepted, contents, source
        scan.receipt, scan.selection, scan.projected = receipt, selection, projected
        return scan

    return create


def snapshot(connection, scan):
    return list(connection.iterdump()), {
        str(path.relative_to(scan.scan_dir)): path.read_bytes()
        for path in scan.scan_dir.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("named", [False, True])
@pytest.mark.parametrize("duplicate", [False, True])
def test_reader_completes_old_unsealed_budget_and_replays(
    workbench_api, workbench_db, legacy_budget, named, duplicate
):
    scan = legacy_budget(named=named, duplicate=duplicate)
    run = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    attempts = list(workbench_db.execute("SELECT * FROM deep_scan_attempts"))
    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None),
    )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()) == run
    assert list(workbench_db.execute("SELECT * FROM deep_scan_attempts")) == attempts
    coverage = json.loads((scan.scan_dir / "coverage.json").read_bytes())
    assert "completeness" not in coverage
    assert len(coverage["surfaces"]) == 2
    for actual, source in zip(
        coverage["surfaces"], scan.source["coverage"]["surfaces"], strict=True
    ):
        assert actual["disposition"] == source["disposition"]
        assert actual["reason"] == source["reason"]
        assert actual["provenance"]["source"] == "independent-review"
        assert actual["receiptRefs"] == [scan.receipt.relative_to(scan.scan_dir).as_posix()]
        assert source["reason"] in (scan.scan_dir / "report.md").read_text()
    assert json.loads((scan.scan_dir / "findings.json").read_bytes())["findings"] == []
    assert scan.accepted.read_bytes() == scan.contents
    before = snapshot(workbench_db, scan)
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert snapshot(workbench_db, scan) == before


@pytest.mark.parametrize("receipt_owner", ["worker", "scan"])
@pytest.mark.parametrize("scoped_checkpoint", [False, True])
def test_reader_seals_evidence_from_the_accepted_receipt_owner(
    workbench_api, workbench_db, legacy_budget, receipt_owner, scoped_checkpoint
):
    scan = legacy_budget(
        duplicate=False, receipt_owner=receipt_owner, scoped_checkpoint=scoped_checkpoint
    )
    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None),
    )
    expected = scan.receipt.relative_to(scan.scan_dir).as_posix()
    coverage = json.loads((scan.scan_dir / "coverage.json").read_bytes())
    assert [surface["receiptRefs"] for surface in coverage["surfaces"]] == [[expected], [expected]]
    artifacts = json.loads((scan.scan_dir / "scan-manifest.json").read_bytes())["scan"]["artifacts"]
    assert (
        next(row["sha256"] for row in artifacts if row["path"] == expected)
        == hashlib.sha256(scan.receipt.read_bytes()).hexdigest()
    )


def test_reader_rejects_buffered_work_outside_the_legacy_selection(
    workbench_api, workbench_db, legacy_budget
):
    scan = legacy_budget()
    extra = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET merge_state = 'buffered' WHERE id = ?",
            (extra.parent.name,),
        )
    before = snapshot(workbench_db, scan)
    with pytest.raises(SystemExit, match="discovery output remains buffered"):
        workbench_api["complete_scan"](
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=json.dumps(BUDGET_COST)),
        )
    assert snapshot(workbench_db, scan) == before


@pytest.mark.parametrize(
    "damage",
    [
        "accepted-bytes",
        "accepted-null-digest",
        "newer-rejection",
        "changed-obligation",
        "unknown-duplicate",
        "null-digest",
    ],
)
def test_reader_rejects_damaged_old_budget_before_writes(
    workbench_api, workbench_db, legacy_budget, damage
):
    scan = legacy_budget()
    if damage == "accepted-bytes":
        scan.accepted.write_bytes(scan.contents + b" ")
    elif damage == "accepted-null-digest":
        with workbench_db:
            workbench_db.execute("UPDATE deep_scan_attempts SET accepted_result_sha256 = NULL")
    elif damage == "newer-rejection":
        newer = copy.deepcopy(scan.source)
        newer["coverage"]["surfaces"][0]["disposition"] = "rejected"
        contents = json.dumps(newer).encode()
        name = hashlib.sha256(contents).hexdigest() + ".json"
        (scan.accepted.parent / name).write_bytes(contents)
        (scan.accepted.parent.parent / "checkpoint-head.json").write_text(
            json.dumps({"checkpoint": name})
        )
    elif damage == "null-digest":
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_runs SET finalization_input_json = ?",
                (json.dumps({**scan.selection, "publicationSha256": None}),),
            )
    else:
        path = scan.scan_dir / "coverage.json"
        coverage = json.loads(path.read_bytes())
        if damage == "changed-obligation":
            coverage["surfaces"][0]["reason"] = "A different obligation remains unresolved."
        else:
            coverage["surfaces"].extend(
                [{"id": "other", "label": "Other", "disposition": "needs_follow_up"}] * 2
            )
        path.write_text(json.dumps(coverage))
    before = snapshot(workbench_db, scan)
    statements = []
    workbench_db.set_trace_callback(statements.append)
    with pytest.raises(SystemExit):
        workbench_api["complete_budget_exhausted_scan"](
            workbench_db,
            Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None),
        )
    workbench_db.set_trace_callback(None)
    assert snapshot(workbench_db, scan) == before
    assert not any(
        statement.lstrip().split()[0].upper() in {"UPDATE", "DELETE", "INSERT", "REPLACE"}
        for statement in statements
    )
