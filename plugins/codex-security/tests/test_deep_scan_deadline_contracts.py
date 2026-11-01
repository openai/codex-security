from __future__ import annotations

import copy
import json
import os

import pytest
from test_deep_scan_deadline_recovery import worker_finding
from test_deep_scan_stop_conditions import canceled_discovery_output, finish
from test_deep_scan_stop_conditions import deadline_scan as deadline_scan
from test_deep_scan_stop_conditions import publication_scan as publication_scan
from test_deep_scan_stop_conditions import saturated_scan as saturated_scan
from workbench_test_support import (
    read_review_state,
    saved_draft,
    select_checkpoint,
    write_checkpoint,
)


@pytest.mark.parametrize("source", ["result", "checkpoint", "archived-checkpoint"])
@pytest.mark.parametrize(
    "marker",
    [
        pytest.param("false", id="string-false"),
        pytest.param(None, id="null"),
        pytest.param(0, id="zero"),
        pytest.param(1, id="one"),
        pytest.param(False, id="incomplete"),
        pytest.param(True, id="complete"),
        pytest.param("omitted", id="omitted"),
    ],
)
def test_deadline_requires_boolean_completion_before_superseding_worker_history(
    workbench_api, workbench_db, deadline_scan, source, marker
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan, attempt=2)
    if source == "archived-checkpoint":
        output = output.parent / "attempts" / "attempt-1"
    earlier = worker_finding(scan, "earlier-worker-finding")
    rejected = worker_finding(scan, "rejected-worker-finding")
    rejected["provenance"]["candidateId"] = "rejected-worker-finding"
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[earlier, rejected],
            deferred=[{"id": "review", "reason": "Review remains."}],
        ),
        mtime_ns=100,
    )
    sibling = worker_finding(scan, "latest-valid-sibling")
    latest = saved_draft(
        scan.scan_id,
        complete=marker,
        findings=[sibling],
        surfaces=[
            {
                "id": "rejected-outcome",
                "candidateId": "rejected-worker-finding",
                "label": "Rejected after review",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ],
        closures=[{"id": "review", "reason": "Review completed."}],
    )
    if marker == "omitted":
        latest.pop("complete")
    if source == "result":
        result = output / "result.json"
        result.write_text(json.dumps(latest))
    else:
        result = write_checkpoint(output / "checkpoints", latest)
        select_checkpoint(output, result, mtime_ns=300)
    os.utime(result, ns=(200, 200))
    original = {path: path.read_bytes() for path in (checkpoint, result)}

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    terminal = marker is True or marker == "omitted"
    invalid = not isinstance(marker, bool) and marker != "omitted"
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    titles = {finding["title"] for finding in findings}
    assert sibling["title"] in titles
    assert rejected["title"] not in titles
    if not terminal or source == "result":
        assert (earlier["title"] in titles) == (not terminal)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert any(row["reason"] == "Review remains." for row in coverage["deferred"]) == (not terminal)
    assert (
        any(
            "Invalid complete marker" in warning and result.name in warning
            for warning in completed["warnings"]
        )
        == invalid
    )
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    for path, contents in original.items():
        assert path.read_bytes() == contents
        assert manifest["preservedSources"][path.relative_to(scan.scan_dir).as_posix()] == (
            workbench_api["saved_results"]._digest(json.loads(contents))
        )


# Each source feeds the same per-finding validator. Exercise each rejection in isolation.
@pytest.mark.parametrize(
    ("source", "invalid"),
    [
        ("result", "rationale"),
        ("checkpoint", "code_evidence"),
        ("archived-result", "sourceFindingIds"),
    ],
)
def test_deadline_validates_each_recovered_finding_against_the_completed_contract(
    workbench_api, workbench_db, deadline_scan, source, invalid
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan, attempt=2)
    if source == "archived-result":
        output = output.parent / "attempts" / "attempt-1"
    earlier = worker_finding(scan, "earlier-worker-finding")
    rejected = worker_finding(scan, "rejected-worker-finding")
    rejected["provenance"]["candidateId"] = "rejected-worker-finding"
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[earlier, rejected],
            deferred=[
                {"id": "review", "reason": "Review remains."},
                {"id": "finished", "reason": "Separate review remains."},
            ],
        ),
        mtime_ns=100,
    )
    sibling = worker_finding(scan, "valid-worker-sibling")
    malformed = worker_finding(scan, "malformed-worker-finding")
    malformed["provenance"]["candidateId"] = "malformed-worker-finding"
    if invalid == "rationale":
        malformed["severity"]["rationale"] = " \t "
    elif invalid == "code_evidence":
        malformed["code_evidence"] = []
    else:
        malformed["provenance"]["sourceFindingIds"] = ["source-finding", "source-finding"]
    latest = saved_draft(
        scan.scan_id,
        complete=True,
        findings=[malformed, sibling],
        surfaces=[
            {
                "id": "reported-outcome",
                "candidateId": "malformed-worker-finding",
                "label": "Unverified finding",
                "disposition": "reported",
                "receiptRefs": [],
            },
            {
                "id": "rejected-outcome",
                "candidateId": "rejected-worker-finding",
                "label": "Rejected after review",
                "disposition": "rejected",
                "receiptRefs": [],
            },
        ],
        closures=[{"id": "finished", "reason": "Separate review completed."}],
    )
    if source == "checkpoint":
        result = write_checkpoint(output / "checkpoints", latest)
        select_checkpoint(output, result, mtime_ns=300)
    else:
        result = output / "result.json"
        result.write_text(json.dumps(latest))
    os.utime(result, ns=(200, 200))
    original = {path: path.read_bytes() for path in (checkpoint, result)}
    if source == "archived-result":
        selected = write_checkpoint(output / "checkpoints", latest, mtime_ns=200)
        select_checkpoint(output, selected, mtime_ns=300)
        original[selected] = selected.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert {finding["title"] for finding in findings} == {
        scan.findings[0]["title"],
        earlier["title"],
        sibling["title"],
    }
    retained = next(finding for finding in findings if finding["title"] == sibling["title"])
    assert retained["provenance"]["workerId"] == worker_id
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert any(row["reason"] == "Review remains." for row in coverage["deferred"])
    assert not any(row["reason"] == "Separate review remains." for row in coverage["deferred"])
    surfaces = {row["label"]: row for row in coverage["surfaces"]}
    assert surfaces["Unverified finding"]["disposition"] == "needs_follow_up"
    assert surfaces["Rejected after review"]["disposition"] == "rejected"
    assert any(invalid in warning and result.name in warning for warning in completed["warnings"])
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    for path, contents in original.items():
        assert path.read_bytes() == contents
        assert manifest["preservedSources"][path.relative_to(scan.scan_dir).as_posix()] == (
            workbench_api["saved_results"]._digest(json.loads(contents))
        )


@pytest.mark.parametrize(
    "model",
    [
        {"assets": []},
        {"summary": "Invalid " + chr(0xD800)},
        {"summary": "Reviewed boundaries."},
        {"format": "markdown", "content": "# Reviewed boundaries"},
    ],
)
def test_deadline_recovers_optional_worker_model_without_losing_findings(
    workbench_api, workbench_db, deadline_scan, model
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    finding = worker_finding(scan, "worker-model-finding")
    draft = {**saved_draft(scan.scan_id, findings=[finding]), "threatModel": model}
    checkpoint = write_checkpoint(output / "checkpoints", draft)
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 2
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    invalid = "assets" in model or chr(0xD800) in model.get("summary", "")
    if invalid:
        assert "threatModel" not in manifest
        assert any(
            "threat model" in warning and checkpoint.name in warning
            for warning in completed["warnings"]
        )
    else:
        assert manifest["threatModel"] == {**model, "origin": "recovered"}
    assert checkpoint.read_bytes() == original


def test_deadline_still_rejects_malformed_canonical_model(
    workbench_api, workbench_db, deadline_scan
):
    from finalize_scan_contract import ContractError

    scan = deadline_scan
    manifest_file = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_file.read_text())
    manifest["scan"]["threatModel"] = {"assets": []}
    manifest_file.write_text(json.dumps(manifest))
    _, output = canceled_discovery_output(workbench_db, scan)
    write_checkpoint(output / "checkpoints", saved_draft(scan.scan_id))
    with pytest.raises(ContractError, match="threatModel"):
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")


def test_deadline_still_rejects_canonical_findings_outside_the_completed_contract(
    workbench_api, workbench_db, deadline_scan
):
    from finalize_scan_contract import ContractError

    scan = deadline_scan
    finding = worker_finding(scan, "valid-worker-finding")
    scan.findings[0]["severity"]["rationale"] = " \t "
    findings_path = scan.scan_dir / "findings.json"
    findings_path.write_text(json.dumps({"findings": scan.findings}))
    original = findings_path.read_bytes()
    _, output = canceled_discovery_output(workbench_db, scan)
    write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, findings=[finding]),
    )

    with pytest.raises(ContractError, match="rationale"):
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert findings_path.read_bytes() == original


@pytest.mark.parametrize("label", [" \t ", "  Reviewed Résumé 😀  "])
def test_deadline_applies_existing_nonblank_surface_label_contract(
    workbench_api, workbench_db, deadline_scan, label
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[worker_finding(scan, "worker-label-finding")],
            surfaces=[
                {"id": "entry", "label": label, "disposition": "reported", "receiptRefs": []}
            ],
        ),
    )
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 2
    coverage = read_review_state(workbench_db, scan.scan_dir)
    surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert len(surfaces) == bool(label.strip())
    if surfaces:
        assert surfaces[0]["label"] == label
    else:
        assert any(
            "label: expected a non-empty string" in warning and checkpoint.name in warning
            for warning in completed["warnings"]
        )
    assert checkpoint.read_bytes() == original


@pytest.mark.parametrize(
    "field",
    ["finding", "surfaces", "explicitExclusions", "deferred", "openQuestions", "resolvedDeferred"],
)
@pytest.mark.parametrize("malformed", [False, True], ids=["valid-unicode", "lone-surrogate"])
def test_deadline_applies_existing_unicode_contract_per_worker_record(
    workbench_api, workbench_db, deadline_scan, field, malformed
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    text = "Review " + (chr(0xD800) if malformed else "Résumé 😀")
    finding = worker_finding(scan, "unicode-worker-finding")
    draft = saved_draft(scan.scan_id, findings=[finding])
    if field == "finding":
        finding["summary"] = text
    elif field == "surfaces":
        draft["coverage"][field] = [
            {"id": "entry", "label": text, "disposition": "reported", "receiptRefs": []}
        ]
    elif field == "openQuestions":
        draft["coverage"][field] = [text]
    elif field == "explicitExclusions":
        draft["coverage"][field] = [{"pattern": "vendor/", "reason": text}]
    else:
        draft["coverage"][field] = [{"id": "review", "reason": text}]
    if field == "resolvedDeferred":
        draft["complete"] = True
        write_checkpoint(
            output / "checkpoints",
            saved_draft(scan.scan_id, deferred=[{"id": "review", "reason": "Review pending."}]),
            mtime_ns=100,
        )
    checkpoint = write_checkpoint(output / "checkpoints", draft, mtime_ns=200)
    if field == "resolvedDeferred":
        select_checkpoint(output, checkpoint)
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == (1 if malformed and field == "finding" else 2)
    assert any("well-formed Unicode" in warning for warning in completed["warnings"]) == malformed
    if field == "resolvedDeferred":
        coverage = read_review_state(workbench_db, scan.scan_dir)
        assert any(row["reason"] == "Review pending." for row in coverage["deferred"]) == malformed
    elif not malformed:
        document = (
            findings if field == "finding" else read_review_state(workbench_db, scan.scan_dir)
        )
        assert text in json.dumps(document, ensure_ascii=False)
    assert checkpoint.read_bytes() == original


@pytest.mark.parametrize(
    "reason",
    [pytest.param("\u0085", id="historical-nel"), pytest.param("Review completed.", id="valid")],
)
def test_deadline_recovers_historical_closure_text_without_losing_a_valid_sibling(
    workbench_api, workbench_db, deadline_scan, reason
):
    scan = deadline_scan
    _, output = canceled_discovery_output(workbench_db, scan)
    previous = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            deferred=[
                {"id": "review", "reason": "First review pending."},
                {"id": "sibling", "reason": "Valid sibling review pending."},
            ],
        ),
        mtime_ns=100,
    )
    draft = saved_draft(
        scan.scan_id,
        complete=True,
        closures=[
            {"id": "review", "reason": reason},
            {"id": "sibling", "reason": "Valid sibling review completed."},
        ],
    )
    checkpoint = write_checkpoint(output / "checkpoints", draft)
    result = output / "result.json"
    result.write_text(json.dumps(draft))
    head = select_checkpoint(output, checkpoint)
    for path in (checkpoint, result, head):
        os.utime(path, ns=(200, 200))
    original = {path: path.read_bytes() for path in (previous, checkpoint, result)}

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    invalid = not reason.strip()
    assert completed["progress"]["status"] == "complete"
    coverage = read_review_state(workbench_db, scan.scan_dir)
    pending = {row["reason"] for row in coverage["deferred"]}
    assert ("First review pending." in pending) == invalid
    assert "Valid sibling review pending." not in pending
    report = (scan.scan_dir / "report.md").read_text()
    assert "First review pending." not in report
    assert "Valid sibling review pending." not in report
    assert any("expected a non-empty string" in warning for warning in completed["warnings"]) == (
        invalid
    )
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["sealedAt"]
    for path, contents in original.items():
        assert path.read_bytes() == contents
        assert manifest["preservedSources"][path.relative_to(scan.scan_dir).as_posix()] == (
            workbench_api["saved_results"]._digest(json.loads(contents))
        )


@pytest.mark.parametrize(
    ("terminal_findings", "malformed", "selected_head"),
    [
        (False, None, False),
        (True, None, False),
        (False, "surface", False),
        (True, "surface", False),
        (False, "closure", False),
        (True, "closure", False),
        (True, "surface", True),
        (False, "missing-receipt", False),
        (True, "missing-receipt", False),
        (False, "disposition", False),
        (True, "disposition", False),
        (False, "receipt-array", False),
        (True, "receipt-array", False),
    ],
    ids=[
        "valid-coverage-empty-findings",
        "valid-coverage-retained-finding",
        "malformed-surface-empty-findings",
        "malformed-surface-retained-finding",
        "malformed-closure-empty-findings",
        "malformed-closure-retained-finding",
        "malformed-selected-head",
        "missing-receipt-empty-findings",
        "missing-receipt-retained-finding",
        "disposition-empty-findings",
        "disposition-retained-finding",
        "receipt-array-empty-findings",
        "receipt-array-retained-finding",
    ],
)
def test_malformed_terminal_coverage_preserves_only_earlier_coverage(
    workbench_api, workbench_db, deadline_scan, terminal_findings, malformed, selected_head
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    finding = worker_finding(scan, "earlier-worker-finding")
    rejected = worker_finding(scan, "rejected-sibling")
    rejected["provenance"]["candidateId"] = "rejected-sibling"
    surface = {
        "id": "entry",
        "label": "Unfinished review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            findings=[finding, rejected],
            surfaces=[surface],
            deferred=[
                {"id": "review", "reason": "Review remains.", "surfaceIds": ["entry"]},
                {"id": "finished", "reason": "Separate review remains."},
            ],
        ),
        mtime_ns=100,
    )
    invalid_surface = copy.deepcopy(surface)
    if malformed == "surface":
        invalid_surface.pop("label")
    else:
        invalid_surface.update(id="latest", label="Latest review", disposition="no_issue_found")
        if malformed == "missing-receipt":
            invalid_surface["receiptRefs"] = ["artifacts/missing.txt"]
        elif malformed == "disposition":
            invalid_surface["disposition"] = "unknown"
        elif malformed == "receipt-array":
            invalid_surface["receiptRefs"] = "invalid"
    closures = [{"id": "finished", "reason": "Separate review completed."}]
    if malformed == "closure":
        closures.append({"id": "review", "reason": "Invalid " + chr(0xD800)})
    terminal = saved_draft(
        scan.scan_id,
        complete=True,
        findings=[finding] if terminal_findings else [],
        surfaces=[
            {
                "id": "sibling-outcome",
                "candidateId": "rejected-sibling",
                "label": "Sibling reviewed",
                "disposition": "rejected",
                "receiptRefs": [],
            },
            *([invalid_surface] if malformed not in (None, "closure") else []),
        ],
        closures=closures,
    )
    if selected_head:
        result = write_checkpoint(output / "checkpoints", terminal)
        select_checkpoint(output, result)
    else:
        result = output / "result.json"
        result.write_text(json.dumps(terminal))
    os.utime(result, ns=(200, 200))
    original = {path: path.read_bytes() for path in (checkpoint, result)}

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    scan.complete()

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert any(row["title"] == finding["title"] for row in findings) == terminal_findings
    assert all(row["title"] != rejected["title"] for row in findings)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert any(
        row.get("workerId") == worker_id and row["label"] == surface["label"]
        for row in coverage["surfaces"]
    ) == bool(malformed)
    assert any(row["reason"] == "Review remains." for row in coverage["deferred"]) == bool(
        malformed
    )
    assert not any(row["reason"] == "Separate review remains." for row in coverage["deferred"])
    assert (
        next(row for row in coverage["surfaces"] if row["label"] == "Sibling reviewed")[
            "disposition"
        ]
        == "rejected"
    )
    if malformed in {"missing-receipt", "disposition", "receipt-array"}:
        latest = next(row for row in coverage["surfaces"] if row["label"] == "Latest review")
        assert latest["disposition"] == "needs_follow_up"
        assert latest["receiptRefs"] == []
    assert {path: path.read_bytes() for path in original} == original


@pytest.mark.parametrize("canceled_worker", [False, True])
def test_optional_export_failure_does_not_block_deadline(
    workbench_api, workbench_db, deadline_scan, tmp_path, capsys, canceled_worker
):
    scan = deadline_scan
    sentinel = tmp_path / "untouched.sarif"
    sentinel.write_text("Preserve this file.\n")
    export = scan.scan_dir / "exports" / "results.sarif"
    export.parent.mkdir()
    export.symlink_to(sentinel)
    if canceled_worker:
        _, output = canceled_discovery_output(workbench_db, scan)
        write_checkpoint(
            output / "checkpoints",
            saved_draft(scan.scan_id, findings=[worker_finding(scan, "saved-worker-finding")]),
        )

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    completed = scan.complete()

    assert completed["progress"]["status"] == "complete"
    assert "automatic SARIF export failed" in capsys.readouterr().err
    assert export.is_symlink()
    assert sentinel.read_text() == "Preserve this file.\n"


def test_standard_parent_closure_preserves_unrelated_task_without_id(
    workbench_db, publication_scan
):
    scan = publication_scan(mode="standard")
    scan.coverage["resolvedDeferred"] = [{"id": "finished", "reason": "Review completed."}]
    scan.coverage["deferred"] = [{"reason": "Unrelated pending review."}]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))

    scan.complete()

    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert len(coverage["deferred"]) == 1
    assert coverage["deferred"][0]["id"]
    assert coverage["deferred"][0]["reason"] == "Unrelated pending review."
