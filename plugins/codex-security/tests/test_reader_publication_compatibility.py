"""A reader preserves publication identity recorded by a newer writer."""

from __future__ import annotations

import copy
import hashlib
import json
from argparse import Namespace

import pytest
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import publication_scan as publication_scan


def selected_publication(api, connection, scan):
    result = scan.scan_dir / "accepted.json"
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "sourceCoverage": scan.coverage,
            }
        )
    )
    row = api["require_scan"](connection, scan.scan_id)
    prepared = api["_prepare_scan_finalization"](
        scan.scan_dir,
        expected_coverage_mode=api["expected_coverage_mode"](row),
        completion_binding=api["workbench_completion_binding"](row, api["now"]()),
    )
    manifest = copy.deepcopy(prepared[2])
    for key in ("completedAt", "sealedAt"):
        manifest["scan"].pop(key, None)
    encoded = json.dumps(
        [manifest, prepared[3], prepared[4]], sort_keys=True, separators=(",", ":")
    ).encode()
    selection = {
        "version": 1,
        "resultPath": result.name,
        "resultSha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        "publicationSha256": hashlib.sha256(encoded).hexdigest(),
        "terminalReason": "saturated",
        "omittedWorkerIds": [],
        "selectedAt": scan.timestamp,
    }
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "coordinator_generation = 2, finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan.scan_id),
        )
    return result


@pytest.mark.parametrize("damage", [None, "findings", "coverage", "selected"])
def test_reader_completion_validates_saved_publication(
    workbench_api, workbench_db, publication_scan, damage
):
    scan = publication_scan()
    selected = selected_publication(workbench_api, workbench_db, scan)
    if damage == "selected":
        selected.write_bytes(selected.read_bytes() + b"\n")
    elif damage is not None:
        path = scan.scan_dir / f"{damage}.json"
        document = json.loads(path.read_bytes())
        if damage == "findings":
            document["findings"][0]["remediation"] = "Substituted repair."
        else:
            document["completeness"] = "partial"
            document["deferred"] = [
                {"id": "changed-coverage", "reason": "Substituted unresolved review."}
            ]
        path.write_text(json.dumps(document))
    before = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
    state = "\n".join(workbench_db.iterdump())
    args = Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    if damage is None:
        workbench_api["complete_scan"](workbench_db, args)
        sealed = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
        workbench_api["complete_scan"](workbench_db, args)
        assert {p: p.read_bytes() for p in sealed} == sealed
    else:
        with pytest.raises(SystemExit, match="publication|changed after acceptance"):
            workbench_api["complete_scan"](workbench_db, args)
        assert "\n".join(workbench_db.iterdump()) == state
        assert {p: p.read_bytes() for p in before} == before


@pytest.mark.parametrize("damage", ["draft", "selected"])
def test_reader_republication_checks_identity_before_writing_checkpoints(
    workbench_api, workbench_db, publication_scan, damage
):
    scan = publication_scan()
    result = selected_publication(workbench_api, workbench_db, scan)
    staged = stage_publication(
        scan,
        generation=2,
        result_path=result,
        title="Substituted aggregate" if damage == "draft" else scan.findings[0]["title"],
    )
    if damage == "selected":
        result.write_bytes(result.read_bytes() + b"\n")
    before = {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")}
    state = "\n".join(workbench_db.iterdump())
    with pytest.raises(
        workbench_api["ContractError"], match="publication|changed after acceptance"
    ):
        workbench_api["write_scan_draft"](workbench_db, staged)
    assert {p: p.read_bytes() for p in scan.scan_dir.rglob("*.json")} == before
    assert "\n".join(workbench_db.iterdump()) == state


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "findings",
        "coverage",
        "selected",
        "target",
        "displayName",
        "id",
        "includePaths",
        "excludePaths",
        "null-digest",
        "bad-digest",
        "claim",
        "protocol",
    ],
)
@pytest.mark.parametrize("omitted_scope", [False, True])
def test_reader_budget_validates_publication_before_changing_the_projection(
    workbench_api, workbench_db, publication_scan, damage, omitted_scope
):
    from test_workbench_db import BUDGET_COST, BUDGET_WARNING

    scan = publication_scan()
    scan.coverage["completeness"] = "partial"
    scan.coverage["deferred"] = [{"id": "remaining", "reason": "A review remains unresolved."}]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    if omitted_scope:
        path = scan.scan_dir / "scan-manifest.json"
        manifest = json.loads(path.read_bytes())
        manifest["scan"]["scope"].pop("includePaths")
        manifest["scan"]["scope"].pop("excludePaths")
        path.write_text(json.dumps(manifest))
    selected = selected_publication(workbench_api, workbench_db, scan)
    recipe = json.loads(workbench_api["require_scan"](workbench_db, scan.scan_id)["recipe_json"])
    recipe["maxCostUsd"] = 0.005
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET recipe_json = ? WHERE id = ?", (json.dumps(recipe), scan.scan_id)
        )
    if damage == "selected":
        selected.write_bytes(selected.read_bytes() + b"\n")
    elif damage in {
        "findings",
        "coverage",
        "target",
        "displayName",
        "id",
        "includePaths",
        "excludePaths",
    }:
        name = damage if damage in {"findings", "coverage"} else "scan-manifest"
        path = scan.scan_dir / f"{name}.json"
        document = json.loads(path.read_bytes())
        if damage == "findings":
            document["findings"][0]["remediation"] = "Substituted repair."
        elif damage == "coverage":
            document["deferred"][0]["reason"] = "Substituted unresolved review."
        elif damage in {"includePaths", "excludePaths"}:
            document["scan"]["scope"][damage] = ["another-path"]
        elif damage == "id":
            document["scan"]["id"] = "95a98220-0653-47cb-b6b8-b5f125a5b4e7"
        else:
            document["scan"]["target"]["targetId" if damage == "target" else damage] = (
                "another-target"
            )
        path.write_text(json.dumps(document))
    elif damage in {"null-digest", "bad-digest"}:
        selection = json.loads(
            workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
        )
        selection["publicationSha256"] = None if damage == "null-digest" else "0" * 64
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_runs SET finalization_input_json = ?", (json.dumps(selection),)
            )
    elif damage == "claim":
        with workbench_db:
            workbench_db.execute(
                "UPDATE scans SET handoff_claim_token = '407e80b8-a8a0-412a-8ec7-d4954afba06a'"
            )
    elif damage == "protocol":
        with workbench_db:
            workbench_db.execute("UPDATE deep_scan_runs SET workflow_version = 'future/v9'")

    def snapshot():
        return list(workbench_db.iterdump()), {
            p.relative_to(scan.scan_dir): p.read_bytes()
            for p in scan.scan_dir.rglob("*")
            if p.is_file()
        }

    before = snapshot()
    run_before = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    args = Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=BUDGET_WARNING
    )
    if damage is not None:
        with pytest.raises(SystemExit):
            workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert snapshot() == before
        return

    result = workbench_api["complete_budget_exhausted_scan"](workbench_db, args)["scan"]
    assert result["progress"]["status"] == "complete"
    run_after = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    selection_before = json.loads(run_before.pop("finalization_input_json"))
    selection_after = json.loads(run_after.pop("finalization_input_json"))
    assert run_after == run_before
    assert selection_after.pop("publicationSha256") != selection_before.pop("publicationSha256")
    assert selection_after == selection_before
    coverage = json.loads((scan.scan_dir / "coverage.json").read_bytes())
    assert coverage["completeness"] == "partial"
    assert scan.coverage["deferred"][0] in coverage["deferred"]
    assert any(item["id"] == "scan-cost-limit" for item in coverage["deferred"])
    assert [f["remediation"] for f in result["findings"]] == [
        f["remediation"] for f in scan.findings
    ]
    sealed = snapshot()
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert snapshot() == sealed
    with pytest.raises(SystemExit, match="Only a running CLI Deep Scan"):
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
    assert snapshot() == sealed
