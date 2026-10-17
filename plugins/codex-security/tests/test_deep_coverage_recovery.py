from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import write_saved_parent
from workbench_test_support import (
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finalize_scan_contract as finalizer
import workbench_saved_results as saved


def worker(root: Path, name: str, draft: dict):
    output = root / "artifacts" / "deep_discovery" / "workers" / name / "output"
    (output / "artifacts").mkdir(parents=True)
    (output / "artifacts/review.md").write_text(f"{name} source review\n")
    result = output / "result.json"
    result.write_text(json.dumps(draft))
    os.utime(result, ns=(100, 100))
    return saved_discovery_worker(output, name, 1)


def recover(root, workers, *, project=False, frozen=None):
    warnings = []
    result = saved.merge_saved_results(
        root,
        "coverage-scan",
        saved_binding("deep_repository", repository="synthetic"),
        workers,
        warnings,
        stopped=True,
        reason="Source review stopped.",
        project_worker_coverage=project,
        frozen_source_digests=frozen,
    )
    assert result is not None
    finalizer._normalize_unsealed_open_questions(result[2])
    finalizer._recover_unsealed_coverage(
        result[2], Path(saved.__file__).resolve().parent.parent / "schemas", root, warnings, []
    )
    assert not warnings
    return result


@pytest.mark.parametrize("identical_labels", [False, True])
def test_worker_projection_retains_independent_links_receipts_and_frozen_replay(
    tmp_path, identical_labels
):
    workers = []
    for name in ("first", "second"):
        draft = saved_draft(
            "coverage-scan",
            complete=False,
            surfaces=[
                {
                    "id": "api",
                    "label": "API" if identical_labels else name,
                    "disposition": "no_issue_found",
                    "receiptRefs": ["artifacts/review.md"],
                }
            ],
            deferred=[{"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}],
        )
        workers.append(worker(tmp_path, name, draft))
    originals = {p: p.read_bytes() for p in tmp_path.rglob("result.json")}
    first = recover(tmp_path, workers, project=True)
    replay = recover(tmp_path, workers, project=True, frozen=first[0]["scan"]["preservedSources"])
    assert replay[2] == first[2]
    for coverage in (first[2], replay[2]):
        assert {row["id"] for row in coverage["surfaces"]} == {"first/api", "second/api"}
        for name in ("first", "second"):
            surface = next(row for row in coverage["surfaces"] if row["workerId"] == name)
            task = next(row for row in coverage["deferred"] if row.get("workerId") == name)
            assert task["surfaceIds"] == [surface["id"]]
            assert surface["disposition"] == "no_issue_found"
            assert (tmp_path / surface["receiptRefs"][0]).read_text() == f"{name} source review\n"
    assert all(p.read_bytes() == contents for p, contents in originals.items())


def test_aggregate_copies_reconcile_once_and_later_worker_closure_removes_pending_work(tmp_path):
    surface = {"id": "api", "label": "API", "disposition": "needs_follow_up"}
    task = {"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}
    draft = saved_draft("coverage-scan", complete=True, surfaces=[surface], deferred=[task])
    source = worker(tmp_path, "first", draft)
    parent = copy.deepcopy(draft)
    parent["coverage"]["surfaces"] = [{**surface, "id": "first/api", "workerId": "first"}]
    parent["coverage"]["deferred"] = [
        {**task, "id": "first/review", "surfaceIds": ["first/api"], "workerId": "first"}
    ]
    write_saved_parent(tmp_path, parent, 200)
    initial = recover(tmp_path, [source])[2]
    assert [row["id"] for row in initial["surfaces"]] == ["first/api"]
    assert [row["id"] for row in initial["deferred"]] == ["first/review", "scan-stopped"]
    output = Path(source["artifact_dir"])
    closed = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[{**surface, "disposition": "no_issue_found"}],
        closures=[{"id": "review", "reason": "Review completed."}],
    )
    checkpoint = write_checkpoint(output / "checkpoints", closed)
    os.utime(checkpoint, ns=(300, 300))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(400, 400))
    result = recover(tmp_path, [source])[2]
    assert [row["id"] for row in result["deferred"]] == ["scan-stopped"]
    assert result["surfaces"] == [
        {
            **surface,
            "id": "first/api",
            "workerId": "first",
            "disposition": "no_issue_found",
            "receiptRefs": [],
        }
    ]


@pytest.mark.parametrize("earlier_identity", [None, "restored"])
@pytest.mark.parametrize("colliding_candidate", [False, True])
def test_parent_only_task_keeps_link_to_recovered_anonymous_surface(
    tmp_path, earlier_identity, colliding_candidate
):
    surface = {"label": "API", "disposition": "needs_follow_up"}
    surfaces = [surface]
    published_id = "first/0"
    if colliding_candidate:
        surface["candidateId"] = "api"
        surfaces.insert(0, {"id": "api", "label": "Other", "disposition": "needs_follow_up"})
        published_id = "first/1"
    draft = saved_draft("coverage-scan", complete=True, surfaces=surfaces)
    source = worker(tmp_path, "first", draft)
    if earlier_identity is not None:
        older = copy.deepcopy(draft)
        older["coverage"]["surfaces"][-1]["id"] = earlier_identity
        checkpoint = write_checkpoint(Path(source["artifact_dir"]) / "checkpoints", older)
        os.utime(checkpoint, ns=(50, 50))
    parent = copy.deepcopy(draft)
    parent["coverage"]["surfaces"][-1].update(id=published_id, workerId="first")
    if colliding_candidate:
        parent["coverage"]["surfaces"][0].update(id="first/api", workerId="first")
    parent["coverage"]["deferred"] = [
        {"id": "parent-review", "reason": "Review remains.", "surfaceIds": [published_id]}
    ]
    write_saved_parent(tmp_path, parent, 200)
    originals = {p: p.read_bytes() for p in tmp_path.rglob("result.json")}
    result = recover(tmp_path, [source])
    replay = recover(tmp_path, [source], frozen=result[0]["scan"]["preservedSources"])
    assert replay[2] == result[2]
    for coverage in (result[2], replay[2]):
        assert len(coverage["surfaces"]) == len(surfaces)
        recovered_surface = next(row for row in coverage["surfaces"] if row["label"] == "API")
        task = next(row for row in coverage["deferred"] if row["id"] == "parent-review")
        assert task["surfaceIds"] == [recovered_surface["id"]]
        assert recovered_surface["workerId"] == "first"
        if earlier_identity is not None:
            assert recovered_surface["id"] == f"first/{earlier_identity}"
        if colliding_candidate:
            other = next(row for row in coverage["surfaces"] if row["label"] == "Other")
            assert task["surfaceIds"] != [other["id"]]
    assert all(p.read_bytes() == contents for p, contents in originals.items())


def test_parent_only_task_remaps_anonymous_surface_links_once(tmp_path):
    draft = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[
            {"candidateId": "1", "label": "API", "disposition": "needs_follow_up"},
            {"label": "Other", "disposition": "needs_follow_up"},
        ],
    )
    source = worker(tmp_path, "first", draft)
    parent = copy.deepcopy(draft)
    parent["coverage"]["surfaces"][0].update(id="first/0", workerId="first")
    parent["coverage"]["surfaces"][1].update(id="first/1", workerId="first")
    parent["coverage"]["deferred"] = [
        {"id": "parent-review", "reason": "Review remains.", "surfaceIds": ["first/0", "first/1"]}
    ]
    write_saved_parent(tmp_path, parent, 200)
    result = recover(tmp_path, [source])
    replay = recover(tmp_path, [source], frozen=result[0]["scan"]["preservedSources"])
    assert replay[2] == result[2]
    for coverage in (result[2], replay[2]):
        surfaces = {row["label"]: row["id"] for row in coverage["surfaces"]}
        task = next(row for row in coverage["deferred"] if row["id"] == "parent-review")
        assert task["surfaceIds"] == [surfaces["API"], surfaces["Other"]]
        assert surfaces["API"] != surfaces["Other"]


def test_parent_only_task_links_to_surface_with_retained_finding_history(tmp_path):
    template = tmp_path / "template"
    template.mkdir()
    write_completed_contract(template, "coverage-scan", tmp_path, target_kind="git_revision")
    finding = json.loads((template / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(workerId="first", candidateId="review")
    draft = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[{"candidateId": "review", "label": "API", "disposition": "rejected"}],
    )
    source = worker(tmp_path, "first", draft)
    parent = copy.deepcopy(draft)
    parent["findings"] = [finding]
    parent["coverage"]["surfaces"][0].update(id="first/0", workerId="first")
    parent["coverage"]["deferred"] = [
        {"id": "parent-review", "reason": "Review remains.", "surfaceIds": ["first/0"]}
    ]
    write_saved_parent(tmp_path, parent, 200)
    manifest = tmp_path / "scan-manifest.json"
    parent_manifest = json.loads((template / "scan-manifest.json").read_text())
    parent_manifest["scan"].update(
        complete=True, sealedAt="2026-01-01T00:00:00Z", status="interrupted"
    )
    manifest.write_text(json.dumps(parent_manifest))
    result = recover(tmp_path, [source])
    surface = result[2]["surfaces"][0]
    task = next(row for row in result[2]["deferred"] if row["id"] == "parent-review")
    assert len(surface["previousFindings"]) == 1
    assert task["surfaceIds"] == [surface["id"]]


@pytest.mark.parametrize("worker_metadata", ["first", ["first"], {"hint": "first"}])
def test_parent_evidence_is_retained_without_matching_saved_worker_source(
    tmp_path, worker_metadata
):
    parent = saved_draft(
        "coverage-scan",
        deferred=[{"id": "first/review", "workerId": worker_metadata, "reason": "Review remains."}],
    )
    write_saved_parent(tmp_path, parent, 100)
    result = recover(tmp_path, [])[2]
    assert result["deferred"][0] == parent["coverage"]["deferred"][0]


@pytest.mark.parametrize("project", [False, True])
@pytest.mark.parametrize(
    "question",
    [
        " Which deployments enable the handler? ",
        {
            "question": "Which deployments enable the handler?",
            "id": "question-1",
            "surfaceIds": ["extension-surface"],
            "receiptRefs": ["extension-receipt"],
        },
    ],
)
def test_question_only_aggregate_reconciles_once_without_rewriting_extensions(
    tmp_path, project, question
):
    draft = saved_draft("coverage-scan", complete=True)
    draft["coverage"]["openQuestions"] = [copy.deepcopy(question)]
    source = worker(tmp_path, "first", draft)
    parent = copy.deepcopy(draft)
    expected = {
        **({"question": question} if isinstance(question, str) else question),
        "workerId": "first",
    }
    parent["coverage"]["openQuestions"] = [copy.deepcopy(expected)]
    write_saved_parent(tmp_path, parent, 200)
    result = recover(tmp_path, [source], project=project)
    expected["question"] = expected["question"].strip()
    assert result[2]["openQuestions"] == [expected]
    replay = recover(
        tmp_path, [source], project=project, frozen=result[0]["scan"]["preservedSources"]
    )
    assert replay[2]["openQuestions"] == [expected]


def test_distinct_anonymous_checkpoint_tasks_survive_reconciliation_before_projection(tmp_path):
    output = tmp_path / "artifacts/deep_discovery/workers/first/output"
    output.mkdir(parents=True)
    for index, reason in enumerate(["Review authentication.", "Review authorization."], 1):
        checkpoint = write_checkpoint(
            output / "checkpoints",
            saved_draft("coverage-scan", deferred=[{"reason": reason}], complete=False),
        )
        os.utime(checkpoint, ns=(index * 100, index * 100))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(250, 250))
    source = saved_discovery_worker(output, "first", 1)
    result = recover(tmp_path, [source], project=True)
    replay = recover(tmp_path, [source], project=True, frozen=result[0]["scan"]["preservedSources"])
    for documents in [result, replay]:
        tasks = [row for row in documents[2]["deferred"] if row.get("workerId") == "first"]
        assert {row["reason"] for row in tasks} == {
            "Review authentication.",
            "Review authorization.",
        }
        assert len({row["id"] for row in tasks}) == 2
        assert all(row["id"].startswith("first/saved-") for row in tasks)
    assert replay[2] == result[2]


def test_legacy_duplicate_tasks_match_the_accepted_aggregate_and_keep_distinct_output_ids(tmp_path):
    tasks = [
        {"id": "review", "reason": "Review authentication."},
        {"id": "review", "reason": "Review authorization."},
        {"id": "review-2", "reason": "Review routing."},
    ]
    draft = saved_draft("coverage-scan", deferred=tasks, complete=True)
    source = worker(tmp_path, "first", draft)
    parent = copy.deepcopy(draft)
    parent["coverage"]["deferred"] = [
        {**row, "workerId": "first", "id": identity}
        for row, identity in zip(
            tasks, ["first/review", "first/review-3", "first/review-2"], strict=True
        )
    ]
    write_saved_parent(tmp_path, parent, 200)
    result = recover(tmp_path, [source])
    replay = recover(tmp_path, [source], frozen=result[0]["scan"]["preservedSources"])
    for documents in [result, replay]:
        retained = [row for row in documents[2]["deferred"] if row.get("workerId") == "first"]
        assert retained == parent["coverage"]["deferred"]
    assert replay[2] == result[2]


@pytest.mark.parametrize(
    "receipt", ["artifacts/review.md", "artifacts/./review.md", "artifacts//review.md"]
)
@pytest.mark.parametrize("exclusion_id", [{}, {"id": None}, {"id": 7}, {"id": "external"}])
def test_projection_normalizes_surface_receipts_without_rewriting_extension_metadata(
    tmp_path, receipt, exclusion_id
):
    draft = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[
            {"id": "api", "label": "API", "disposition": "no_issue_found", "receiptRefs": [receipt]}
        ],
        deferred=[
            {
                "id": "review",
                "reason": "Review another route.",
                "surfaceIds": ["api"],
                "receiptRefs": {"external": "opaque metadata"},
            }
        ],
    )
    draft["coverage"]["explicitExclusions"] = [
        {
            **exclusion_id,
            "pattern": "vendor/**",
            "reason": "External code.",
            "receiptRefs": ["opaque/missing.md"],
            "surfaceIds": ["opaque-id"],
        }
    ]
    source = worker(tmp_path, "first", draft)
    parent = copy.deepcopy(draft)
    for field in ("surfaces", "explicitExclusions", "deferred"):
        for index, row in enumerate(parent["coverage"][field]):
            row["workerId"] = "first"
            identity = row["id"] if isinstance(row.get("id"), str) else str(index)
            row["id"] = f"first/{identity}"
    parent["coverage"]["surfaces"][0]["receiptRefs"] = [
        "artifacts/deep_discovery/workers/first/output/artifacts/review.md"
    ]
    parent["coverage"]["deferred"][0]["surfaceIds"] = ["first/api"]
    write_saved_parent(tmp_path, parent, 200)
    coverage = recover(tmp_path, [source])[2]
    assert len(coverage["surfaces"]) == 1
    assert (
        coverage["surfaces"][0]["receiptRefs"] == parent["coverage"]["surfaces"][0]["receiptRefs"]
    )
    assert len(coverage["explicitExclusions"]) == 1
    exclusion = coverage["explicitExclusions"][0]
    expected = parent["coverage"]["explicitExclusions"][0]
    if isinstance(exclusion_id.get("id"), str):
        assert exclusion == expected
    else:
        assert {key: value for key, value in exclusion.items() if key != "id"} == {
            key: value for key, value in expected.items() if key != "id"
        }
    task = next(row for row in coverage["deferred"] if row["id"] == "first/review")
    assert task["receiptRefs"] == {"external": "opaque metadata"}
    assert task["surfaceIds"] == ["first/api"]
    assert json.loads((Path(source["artifact_dir"]) / "result.json").read_text()) == draft


@pytest.mark.parametrize("reverse_sources", [False, True])
@pytest.mark.parametrize("reverse_surfaces", [False, True])
def test_current_receipt_spelling_precedes_historical_receipts(
    tmp_path, reverse_sources, reverse_surfaces
):
    prefix = "artifacts/deep_discovery/workers/first/output/artifacts/"
    directory = tmp_path / prefix
    directory.mkdir(parents=True)
    for name in ("review.md", "Review.md", "new-review.md"):
        (directory / name).write_text(f"Evidence from {name}.\n")
    originals = {path: path.read_bytes() for path in directory.iterdir()}

    def surface(identity, disposition, receipt):
        return {
            "id": identity,
            "label": identity,
            "disposition": disposition,
            "receiptRefs": [prefix + receipt],
        }

    old = {
        "coverage": {
            "surfaces": [
                surface("reader", "needs_follow_up", "review.md"),
                surface("writer", "needs_follow_up", "Review.md"),
            ]
        }
    }
    current = {
        "coverage": {
            "surfaces": [
                surface("reader", "no_issue_found", "new-review.md"),
                surface("writer", "no_issue_found", "Review.md"),
            ]
        }
    }
    if reverse_surfaces:
        for draft in (old, current):
            draft["coverage"]["surfaces"].reverse()
    sources = [("old", old, "first"), ("current", current, "first")]
    if reverse_sources:
        sources.reverse()
    task = {"id": "review", "reason": "Review remains.", "surfaceIds": ["reader", "writer"]}
    schema = json.loads(
        (Path(saved.__file__).resolve().parent.parent / "schemas/coverage.schema.json").read_text()
    )["properties"]["surfaces"]["items"]
    warnings = []
    _, updates = saved._generic_surface_updates(
        sources,
        {"old": (0, 0), "current": (1, 0)},
        {("first", "review"): ((1, 0), {"id": "review", "reason": "Review completed."}, "current")},
        {},
        {},
        set(),
        schema,
        {"old": [task], "current": []},
        set(),
        surface_is_retained=lambda _relative, _owner, _row: True,
        receipt_root=tmp_path,
        receipt_warnings=warnings,
    )
    receipts = {row["id"]: row["receiptRefs"] for _, row in updates}
    assert receipts == {"reader": [prefix + "new-review.md"], "writer": [prefix + "Review.md"]}
    assert any("duplicate artifact path" in warning for warning in warnings)
    scan = {
        "completedAt": "synthetic-time",
        "sealedAt": "synthetic-time",
        "artifacts": [
            {"path": ref, "sha256": hashlib.sha256((tmp_path / ref).read_bytes()).hexdigest()}
            for refs in receipts.values()
            for ref in refs
        ],
    }
    finalizer._validate_existing_seal(tmp_path, scan)
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("split_surfaces", [False, True])
def test_stopped_publication_recovers_unrepaired_failed_worker_receipt_collisions(
    tmp_path, split_surfaces
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("synthetic_handler()\n")
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, "coverage-scan", target, coverage_mode="deep_repository")
    fixture_manifest = json.loads((contract / "scan-manifest.json").read_text())
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    binding = {
        "scanId": "coverage-scan",
        "startedAt": fixture_manifest["scan"]["startedAt"],
        "completedAt": fixture_manifest["scan"]["completedAt"],
        "producer": fixture_manifest["scan"]["producer"],
        "status": "interrupted",
        "allowedTargetKinds": [fixture_manifest["scan"]["target"]["kind"]],
        "target": fixture_manifest["scan"]["target"],
        "scope": fixture_manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    root = tmp_path / "scan"
    root.mkdir(mode=0o700)
    good = saved_draft(
        "coverage-scan",
        complete=True,
        findings=[finding],
        surfaces=[
            {
                "id": "reviewed",
                "label": "Reviewed surface",
                "disposition": "reported",
                "receiptRefs": [],
            }
        ],
    )
    accepted = worker(root, "accepted", good)
    accepted["status"] = "succeeded"
    failed_rows = [
        {
            "id": "reader",
            "label": "Reader",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/review.md"],
        },
        {
            "id": "writer",
            "label": "Writer",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/Review.md"],
        },
    ]
    if not split_surfaces:
        failed_rows[0]["receiptRefs"].extend(failed_rows.pop()["receiptRefs"])
    failed = worker(
        root, "failed", saved_draft("coverage-scan", complete=False, surfaces=failed_rows)
    )
    failed["status"] = "failed"
    (Path(failed["artifact_dir"]) / "artifacts/Review.md").write_text(
        "Other saved source review.\n"
    )
    parent = copy.deepcopy(good)
    parent["coverage"]["surfaces"][0].update(id="accepted/reviewed", workerId="accepted")
    write_saved_parent(root, parent, 300)
    originals = {p: p.read_bytes() for p in (root / "artifacts").rglob("*") if p.is_file()}
    warnings = []
    recovered = saved.merge_saved_results(
        root,
        "coverage-scan",
        binding,
        [accepted, failed],
        warnings,
        stopped=True,
        reason="Review stopped.",
    )
    assert recovered is not None
    prepared = finalizer._prepare_scan_finalization(
        root,
        completion_binding=binding,
        recover_unsealed=True,
        expected_coverage_mode="deep_repository",
        draft_documents=recovered,
    )
    _, published_findings, published_coverage = finalizer._write_prepared_scan_finalization(
        prepared
    )
    assert len(published_findings["findings"]) == 1
    assert published_findings["findings"][0]["title"] == finding["title"]
    assert "completeness" not in published_coverage
    failed_surfaces = [
        row for row in published_coverage["surfaces"] if row.get("workerId") == "failed"
    ]
    assert any(row["disposition"] == "needs_follow_up" for row in failed_surfaces)
    assert any("duplicate artifact path" in warning for warning in prepared.warnings)
    assert (root / "report.md").is_file()
    manifest = json.loads((root / "scan-manifest.json").read_text())
    assert manifest["scan"]["status"] == "interrupted"
    assert isinstance(manifest["scan"]["sealedAt"], str)
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("reverse", [False, True])
def test_missing_historical_receipt_does_not_hide_valid_case_variant(tmp_path, reverse):
    refs = ["artifacts/review.md", "artifacts/Review.md"]
    if reverse:
        refs.reverse()
    surface = {"id": "api", "label": "API", "disposition": "no_issue_found"}
    old = saved_draft("coverage-scan", complete=True, surfaces=[{**surface, "receiptRefs": refs}])
    source = worker(tmp_path, "first", old)
    output = Path(source["artifact_dir"])
    (output / "artifacts/review.md").unlink()
    (output / "artifacts/Review.md").write_text("Retained historical evidence.\n")
    if (output / "artifacts/review.md").exists():
        pytest.skip("This regression requires case-sensitive receipt paths.")
    (output / "artifacts/replacement.md").write_text("Current review evidence.\n")
    prefix = output.relative_to(tmp_path).as_posix() + "/"
    parent = copy.deepcopy(old)
    parent["coverage"]["surfaces"] = [
        {
            **surface,
            "id": "first/api",
            "workerId": "first",
            "receiptRefs": [prefix + ref for ref in refs],
        }
    ]
    write_saved_parent(tmp_path, parent, 200)
    current = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[{**surface, "receiptRefs": ["artifacts/replacement.md"]}],
    )
    checkpoint = write_checkpoint(output / "checkpoints", current)
    os.utime(checkpoint, ns=(300, 300))
    warnings = []
    documents = saved.merge_saved_results(
        tmp_path,
        "coverage-scan",
        saved_binding("deep_repository", repository="synthetic"),
        [source],
        warnings,
        stopped=True,
        reason="Interrupted retry before checkpoint-head publication.",
    )
    assert documents is not None
    retained = documents[2]["surfaces"][0]["receiptRefs"]
    assert set(retained) == {prefix + "artifacts/Review.md", prefix + "artifacts/replacement.md"}
    assert any("Replaced invalid saved coverage receipt" in warning for warning in warnings)
    scan = {
        "completedAt": "synthetic-time",
        "sealedAt": "synthetic-time",
        "artifacts": [
            {"path": ref, "sha256": hashlib.sha256((tmp_path / ref).read_bytes()).hexdigest()}
            for ref in retained
        ],
    }
    finalizer._validate_existing_seal(tmp_path, scan)


@pytest.mark.parametrize("projected_parent", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_superseded_surface_cannot_reserve_historical_receipt(tmp_path, projected_parent, reverse):
    reader = {
        "id": "reader",
        "label": "Reader",
        "disposition": "needs_follow_up",
        "receiptRefs": ["artifacts/review.md"],
    }
    writer = {
        "id": "writer",
        "label": "Writer",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/Review.md"],
    }
    task = {"id": "review-reader", "reason": "Review reader.", "surfaceIds": ["reader"]}
    surfaces = [writer, reader] if reverse else [reader, writer]
    old = saved_draft("coverage-scan", complete=True, surfaces=surfaces, deferred=[task])
    source = worker(tmp_path, "first", old)
    output = Path(source["artifact_dir"])
    if (output / "artifacts/Review.md").exists():
        pytest.skip("This regression requires case-sensitive receipt paths.")
    (output / "artifacts/Review.md").write_text("Superseded writer evidence.\n")
    archive = output.parent / "attempts/attempt-01"
    archive.parent.mkdir()
    output.rename(archive)
    (output / "artifacts").mkdir(parents=True)
    (output / "artifacts/replacement.md").write_text("Completed reader evidence.\n")
    current = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[
            {**reader, "disposition": "no_issue_found", "receiptRefs": ["artifacts/replacement.md"]}
        ],
        closures=[{"id": "review-reader", "reason": "Reader review complete."}],
    )
    (output / "result.json").write_text(json.dumps(current))
    os.utime(output / "result.json", ns=(300, 300))
    prefix = archive.relative_to(tmp_path).as_posix() + "/"
    if projected_parent:
        parent = copy.deepcopy(old)
        parent["coverage"]["surfaces"] = [
            {
                **row,
                "id": "first/" + row["id"],
                "workerId": "first",
                "receiptRefs": [prefix + ref for ref in row["receiptRefs"]],
            }
            for row in surfaces
        ]
        parent["coverage"]["deferred"] = [
            {
                **task,
                "id": "first/review-reader",
                "workerId": "first",
                "surfaceIds": ["first/reader"],
            }
        ]
        write_saved_parent(tmp_path, parent, 200)
    originals = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    warnings = []
    documents = saved.merge_saved_results(
        tmp_path,
        "coverage-scan",
        saved_binding("deep_repository", repository="synthetic"),
        [source],
        warnings,
        stopped=True,
        reason="Source review stopped.",
        project_worker_coverage=not projected_parent,
    )
    assert documents is not None
    retained = documents[2]["surfaces"]
    assert [row["id"] for row in retained] == ["first/reader"]
    assert set(retained[0]["receiptRefs"]) == {
        prefix + "artifacts/review.md",
        output.relative_to(tmp_path).as_posix() + "/artifacts/replacement.md",
    }
    assert prefix + "artifacts/review.md" in finalizer._supplementary_artifact_refs(
        documents[0]["scan"], documents[2]
    )
    assert not warnings
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("scenario", ["superseded-omitted", "unselected-metadata"])
@pytest.mark.parametrize("missing", [False, True])
def test_receipt_repair_preserves_selected_surface_metadata(tmp_path, scenario, missing):
    source = worker(tmp_path, "first", saved_draft("coverage-scan", complete=True))
    output = Path(source["artifact_dir"])
    (output / "artifacts/accepted.md").write_text("Accepted completed review.\n")
    (output / "artifacts/unselected.md").write_text("Unselected interrupted observation.\n")
    surface = {
        "id": "api",
        "label": "Archived label",
        "notes": "Archived notes",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/missing.md"],
    }
    if scenario == "superseded-omitted":
        for modified, row in [
            (100, surface),
            (
                200,
                {
                    **surface,
                    "label": "Intermediate label",
                    "receiptRefs": ["artifacts/accepted.md"],
                },
            ),
        ]:
            checkpoint = write_checkpoint(
                output / "checkpoints", saved_draft("coverage-scan", surfaces=[row])
            )
            os.utime(checkpoint, ns=(modified, modified))
        missing_path = output / "artifacts/missing.md"
    else:
        archive = output.parent / "attempts/attempt-01"
        (archive / "artifacts").mkdir(parents=True)
        (archive / "result.json").write_text(
            json.dumps(saved_draft("coverage-scan", complete=True, surfaces=[surface]))
        )
        os.utime(archive / "result.json", ns=(100, 100))
        missing_path = archive / "artifacts/missing.md"
        accepted = saved_draft(
            "coverage-scan",
            complete=True,
            surfaces=[
                {
                    **surface,
                    "label": "Accepted label",
                    "notes": "Accepted notes",
                    "receiptRefs": ["artifacts/accepted.md"],
                }
            ],
        )
        checkpoint = write_checkpoint(output / "checkpoints", accepted)
        os.utime(checkpoint, ns=(200, 200))
        (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(output / "checkpoint-head.json", ns=(250, 250))
        (output / "result.json").write_text(json.dumps(accepted))
        pending = saved_draft(
            "coverage-scan",
            surfaces=[
                {
                    **surface,
                    "label": "Unselected label",
                    "notes": "Unselected notes",
                    "receiptRefs": ["artifacts/unselected.md"],
                }
            ],
        )
        checkpoint = write_checkpoint(output / "checkpoints", pending)
        os.utime(checkpoint, ns=(400, 400))
        source["attempt"] = 2
    os.utime(output / "result.json", ns=(300, 300))
    if not missing:
        missing_path.write_text("Existing historical receipt.\n")
    originals = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    documents = saved.merge_saved_results(
        tmp_path,
        "coverage-scan",
        saved_binding("deep_repository", repository="synthetic"),
        [source],
        [],
        stopped=True,
        reason="Source review stopped.",
        project_worker_coverage=True,
    )
    assert documents is not None
    surfaces = documents[2]["surfaces"]
    if scenario == "superseded-omitted":
        assert surfaces == []
    else:
        assert len(surfaces) == 1
        assert surfaces[0]["label"] == "Accepted label"
        assert surfaces[0]["notes"] == "Accepted notes"
        assert (
            output.relative_to(tmp_path).as_posix() + "/artifacts/accepted.md"
            in surfaces[0]["receiptRefs"]
        )
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("checkpoint", ["absent", "same", "conflicting", "distinct"])
def test_unselected_receipt_spelling_cannot_replace_accepted_evidence(
    tmp_path, reverse, checkpoint
):
    accepted_name, unselected_name = (
        ("Review.md", "review.md") if reverse else ("review.md", "Review.md")
    )
    surface = {
        "id": "api",
        "label": "Accepted review",
        "disposition": "no_issue_found",
        "receiptRefs": [f"artifacts/{accepted_name}"],
    }
    accepted = saved_draft("coverage-scan", complete=True, surfaces=[surface])
    source = worker(tmp_path, "first", accepted)
    output = Path(source["artifact_dir"])
    for name, text in (
        (accepted_name, "Accepted receipt bytes."),
        (unselected_name, "Unselected receipt bytes."),
        ("distinct.md", "Independent receipt bytes."),
    ):
        (output / "artifacts" / name).write_text(text)
    selected = write_checkpoint(output / "checkpoints", accepted)
    os.utime(selected, ns=(200, 200))
    (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(output / "checkpoint-head.json", ns=(250, 250))
    os.utime(output / "result.json", ns=(300, 300))
    if checkpoint != "absent":
        name = {
            "same": accepted_name,
            "conflicting": unselected_name,
            "distinct": "distinct.md",
        }[checkpoint]
        pending = write_checkpoint(
            output / "checkpoints",
            saved_draft(
                "coverage-scan",
                surfaces=[{**surface, "receiptRefs": [f"artifacts/{name}"]}],
            ),
        )
        os.utime(pending, ns=(400, 400))
    originals = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    documents = recover(tmp_path, [source], project=True)
    replay = recover(
        tmp_path, [source], project=True, frozen=documents[0]["scan"]["preservedSources"]
    )
    for recovered in (documents, replay):
        assert recovered[2]["surfaces"] == [
            {
                **surface,
                "id": "first/api",
                "workerId": "first",
                "receiptRefs": [
                    f"{output.relative_to(tmp_path).as_posix()}/artifacts/{accepted_name}"
                ],
            }
        ]
    assert all(path.read_bytes() == content for path, content in originals.items())


@pytest.mark.parametrize("unselected", [False, True])
def test_non_emitted_repair_cannot_reserve_another_surfaces_receipt(tmp_path, unselected):
    def surface(identity, names):
        return {
            "id": identity,
            "label": identity,
            "disposition": "no_issue_found",
            "receiptRefs": [f"artifacts/{name}" for name in names],
        }

    accepted = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[surface("reader", ["reader.md"]), surface("writer", ["writer.md"])],
    )
    source = worker(tmp_path, "first", accepted)
    output = Path(source["artifact_dir"])
    for name in ["reader.md", "writer.md", "review.md", "Review.md"]:
        (output / "artifacts" / name).write_text(f"Evidence from {name}.")
    history = saved_draft(
        "coverage-scan", complete=True, surfaces=[surface("writer", ["Review.md", "missing.md"])]
    )
    for modified, draft in [(100, history), (200, accepted)]:
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(output / "checkpoint-head.json", ns=(250, 250))
    os.utime(output / "result.json", ns=(300, 300))
    if unselected:
        checkpoint = write_checkpoint(
            output / "checkpoints",
            saved_draft("coverage-scan", surfaces=[surface("reader", ["review.md"])]),
        )
        os.utime(checkpoint, ns=(400, 400))
    originals = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    warnings = []
    documents = saved.merge_saved_results(
        tmp_path,
        "coverage-scan",
        saved_binding("deep_repository", repository="synthetic"),
        [source],
        warnings,
        stopped=True,
        reason="Source review stopped.",
        project_worker_coverage=True,
    )
    assert documents is not None
    surfaces = {row["id"]: row for row in documents[2]["surfaces"]}
    prefix = output.relative_to(tmp_path).as_posix() + "/artifacts/"
    assert surfaces["first/reader"]["receiptRefs"] == [prefix + "reader.md"]
    assert set(surfaces["first/writer"]["receiptRefs"]) == {
        prefix + "writer.md",
        prefix + "Review.md",
    }
    assert all("missing.md" in warning for warning in warnings)
    assert all(path.read_bytes() == content for path, content in originals.items())


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    "metadata", ["valid", "missing-label", "invalid-label", "disposition", "receipt", "empty-id"]
)
def test_only_recoverable_surface_metadata_reserves_receipt_spelling(tmp_path, reverse, metadata):
    current_name, historical_name = (
        ("review.md", "Review.md") if reverse else ("Review.md", "review.md")
    )
    selected = {
        "id": "selected",
        "label": "Current selected review",
        "disposition": "no_issue_found",
        "receiptRefs": [f"artifacts/{current_name}"],
    }
    if metadata == "empty-id":
        selected["id"] = ""
    elif metadata == "missing-label":
        selected.pop("label")
    elif metadata == "invalid-label":
        selected["label"] = 7
    elif metadata == "disposition":
        selected["disposition"] = "unverified"
    elif metadata == "receipt":
        selected["receiptRefs"].append(7)
    writer = {
        "id": "writer",
        "label": "Retained review",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/replacement.md"],
    }
    accepted = saved_draft("coverage-scan", complete=True, surfaces=[selected, writer])
    source = worker(tmp_path, "first", accepted)
    output = Path(source["artifact_dir"])
    for name in [current_name, historical_name, "replacement.md"]:
        (output / "artifacts" / name).write_text(f"Evidence from {name}.\n")
    history = saved_draft(
        "coverage-scan",
        complete=True,
        surfaces=[
            {**writer, "receiptRefs": [f"artifacts/{historical_name}", "artifacts/missing.md"]}
        ],
    )
    for modified, draft in [(100, history), (200, accepted)]:
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(output / "checkpoint-head.json", ns=(250, 250))
    os.utime(output / "result.json", ns=(300, 300))
    originals = {p: p.read_bytes() for p in output.rglob("*") if p.is_file()}
    warnings = []
    documents = saved.merge_saved_results(
        tmp_path,
        "coverage-scan",
        saved_binding("deep_repository", repository="synthetic"),
        [source],
        warnings,
        stopped=True,
        reason="Source review stopped.",
        project_worker_coverage=True,
    )
    assert documents is not None
    finalizer._recover_unsealed_coverage(
        documents[2],
        Path(saved.__file__).resolve().parent.parent / "schemas",
        tmp_path,
        warnings,
        [],
    )
    rows = {row["id"]: row for row in documents[2]["surfaces"]}
    prefix = output.relative_to(tmp_path).as_posix() + "/artifacts/"
    expected = {prefix + "replacement.md"}
    if metadata in {"missing-label", "invalid-label"}:
        expected.add(prefix + historical_name)
        assert "first/selected" not in rows
        assert any("Skipped malformed coverage surface" in warning for warning in warnings)
    else:
        assert rows[f"first/{selected['id']}"]["receiptRefs"] == [prefix + current_name]
    assert set(rows["first/writer"]["receiptRefs"]) == expected
    assert all(path.read_bytes() == content for path, content in originals.items())
