from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    deep_scan_fixture,
    standard_finding,
)
from workbench_test_support import (
    cancel_scan,
    fail_deep_scan,
    get_scan,
    preserve_scan_results,
    read_review_state,
    saved_draft,
    select_checkpoint,
    upsert_deep_worker,
    worker_paths,
    write_checkpoint,
    write_result_draft,
)


def coverage_worker(
    state_dir: Path, codex_home: Path, scan_dir: Path, scan_id: str, name: str, accepted: bool
) -> tuple[str, Path]:
    if accepted:
        return accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id, name=name)
    worker_id = str(uuid.uuid4())
    prompt, artifacts, result = worker_paths(scan_dir, name)
    upsert_deep_worker(
        state_dir,
        scan_id,
        worker_id,
        "discovery",
        "running",
        str(prompt),
        str(artifacts),
        "--attempt",
        "1",
        environment={"CODEX_HOME": str(codex_home)},
    )
    return worker_id, result


@pytest.mark.parametrize("accepted", [False, True], ids=["running", "accepted"])
@pytest.mark.parametrize("termination", ["failed", "interrupted", "canceled"])
def test_stopped_deep_scan_projects_worker_coverage_without_parent_aggregate(
    tmp_path: Path, termination: str, accepted: bool
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    environment = {"CODEX_HOME": str(codex_home)}
    finding = standard_finding(tmp_path, scan_id, target)
    workers = {}
    originals = {}
    for name in ("first", "second"):
        worker_id, result = coverage_worker(
            state_dir, codex_home, scan_dir, scan_id, name, accepted
        )
        receipt = result.parent / "artifacts/review.md"
        receipt.parent.mkdir()
        receipt.write_text(f"Synthetic {name} review.\n")
        result.write_text(
            json.dumps(
                saved_draft(
                    scan_id,
                    complete=accepted,
                    findings=[finding] if name == "first" else [],
                    surfaces=[
                        {
                            "id": "api",
                            "label": name,
                            "disposition": "no_issue_found",
                            "receiptRefs": ["artifacts/review.md"],
                        }
                    ],
                    deferred=[
                        {
                            "id": "review",
                            "reason": f"Review {name} remains.",
                            "surfaceIds": ["api"],
                        }
                    ],
                )
            )
        )
        workers[name] = (worker_id, receipt)
        originals.update({path: path.read_bytes() for path in (result, receipt)})
    assert not (scan_dir / "coverage.json").exists()
    assert not (scan_dir / "checkpoints").exists()

    if termination == "canceled":
        cancel_scan(state_dir, scan_id, "standard-worker-thread", environment=environment)
    else:
        fail_deep_scan(state_dir, codex_home, scan_id, deep_status=termination)
    stopped = get_scan(state_dir, scan_id)["scan"]
    assert stopped["findingCount"] == 1
    assert not any("coverage receipt" in warning for warning in stopped["warnings"])
    coverage = read_review_state(state_dir, scan_dir)
    assert "completeness" not in coverage
    assert {row["id"] for row in coverage["surfaces"]} == {
        f"{worker_id}-attempt-1-surface-1" if accepted else f"{worker_id}/api"
        for worker_id, _ in workers.values()
    }
    for name, (worker_id, receipt) in workers.items():
        surface = next(row for row in coverage["surfaces"] if row["label"] == name)
        task = next(
            row for row in coverage["deferred"] if row["reason"] == f"Review {name} remains."
        )
        if accepted:
            assert surface["provenance"] == {
                "workerId": worker_id,
                "attempt": 1,
                "sourceId": "api",
            }
            assert task["provenance"] == {
                "workerId": worker_id,
                "attempt": 1,
                "sourceId": "review",
            }
        else:
            assert surface["workerId"] == task["workerId"] == worker_id
        assert surface["disposition"] == "no_issue_found"
        assert surface["receiptRefs"] == [receipt.relative_to(scan_dir).as_posix()]
        assert task["id"] == (
            f"{worker_id}-attempt-1-deferred-1" if accepted else f"{worker_id}/review"
        )
        assert task["surfaceIds"] == [surface["id"]]
        assert (scan_dir / surface["receiptRefs"][0]).read_text() == f"Synthetic {name} review.\n"
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["status"] == termination
    assert isinstance(manifest["scan"]["sealedAt"], str)
    sealed = {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
        if (scan_dir / name).is_file()
    }
    replay = preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment=environment
    )["scan"]
    assert replay["findingCount"] == 1
    assert all((scan_dir / name).read_bytes() == content for name, content in sealed.items())
    assert all(path.read_bytes() == content for path, content in originals.items())


@pytest.mark.parametrize("accepted", [False, True], ids=["running", "accepted"])
def test_stopped_worker_rejects_receipts_outside_its_artifacts_directory(
    tmp_path: Path, accepted: bool
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result = coverage_worker(
        state_dir, codex_home, scan_dir, scan_id, "standard-worker", accepted
    )
    result.write_text(
        json.dumps(
            saved_draft(
                scan_id,
                complete=accepted,
                surfaces=[
                    {
                        "id": "api",
                        "label": "API",
                        "disposition": "no_issue_found",
                        "receiptRefs": ["result.json"],
                    }
                ],
            )
        )
    )
    original = result.read_bytes()

    fail_deep_scan(state_dir, codex_home, scan_id)

    surface = read_review_state(state_dir, scan_dir)["surfaces"][0]
    assert surface["id"] == (f"{worker_id}-attempt-1-surface-1" if accepted else f"{worker_id}/api")
    if accepted:
        assert surface["provenance"] == {"workerId": worker_id, "attempt": 1, "sourceId": "api"}
    else:
        assert surface["workerId"] == worker_id
    assert surface["disposition"] == "needs_follow_up"
    assert surface["receiptRefs"] == []
    assert any(
        "under artifacts/" in warning
        for warning in get_scan(state_dir, scan_id)["scan"]["warnings"]
    )
    sealed = (scan_dir / "scan-manifest.json").read_bytes()
    preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == sealed
    assert result.read_bytes() == original


@pytest.mark.parametrize("anonymous_first", [True, False])
def test_stopped_worker_links_follow_explicit_surface_identity_through_collisions(
    tmp_path: Path, anonymous_first: bool
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    anonymous = {"candidateId": "api", "label": "Anonymous", "disposition": "needs_follow_up"}
    explicit = {"id": "api", "label": "Explicit", "disposition": "needs_follow_up"}
    result.write_text(
        json.dumps(
            saved_draft(
                scan_id,
                complete=True,
                surfaces=[anonymous, explicit] if anonymous_first else [explicit, anonymous],
                deferred=[{"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}],
            )
        )
    )
    original = result.read_bytes()

    fail_deep_scan(state_dir, codex_home, scan_id)

    coverage = read_review_state(state_dir, scan_dir)
    surfaces = {row["label"]: row for row in coverage["surfaces"]}
    assert len(surfaces) == 2
    assert surfaces["Explicit"]["id"] != surfaces["Anonymous"]["id"]
    assert coverage["deferred"][0]["surfaceIds"] == [surfaces["Explicit"]["id"]]
    sealed = (scan_dir / "scan-manifest.json").read_bytes()
    preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == sealed
    assert result.read_bytes() == original


def test_pending_worker_surface_receipt_precedes_historical_receipt_repair(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    output = result.parent
    artifacts = output / "artifacts"
    artifacts.mkdir()
    current_receipt = artifacts / "Review.md"
    current_receipt.write_text("Current API review.\n")
    historical_receipt = artifacts / "review.md"
    if historical_receipt.exists():
        pytest.skip("This regression requires case-sensitive receipt paths.")
    historical_receipt.write_text("Historical writer review.\n")
    other_receipt = artifacts / "other.md"
    other_receipt.write_text("Current writer review.\n")
    surface = {
        "id": "api",
        "label": "API",
        "disposition": "no_issue_found",
        "receiptRefs": ["artifacts/Review.md"],
    }
    writer = {
        **surface,
        "id": "writer",
        "label": "Writer",
        "receiptRefs": ["artifacts/other.md"],
    }
    task = {"id": "review-api", "reason": "Review remains.", "surfaceIds": ["api"]}
    write_result_draft(
        result,
        saved_draft(scan_id, complete=True, surfaces=[surface, writer], deferred=[task]),
        mtime_ns=100,
    )
    historical = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan_id,
            complete=True,
            surfaces=[
                {
                    **writer,
                    "receiptRefs": ["artifacts/review.md", "artifacts/missing.md"],
                }
            ],
        ),
        mtime_ns=50,
    )
    selected = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan_id, complete=True, surfaces=[writer]),
        mtime_ns=300,
    )
    head = select_checkpoint(output, selected, mtime_ns=400)
    originals = {
        path: path.read_bytes()
        for path in (result, historical, selected, head, current_receipt, historical_receipt)
    }
    assert not (scan_dir / "coverage.json").exists()

    fail_deep_scan(state_dir, codex_home, scan_id)

    coverage = read_review_state(state_dir, scan_dir)
    surfaces = {row["label"]: row for row in coverage["surfaces"]}
    retained = surfaces["API"]
    assert retained["disposition"] == "no_issue_found"
    assert retained["receiptRefs"] == [current_receipt.relative_to(scan_dir).as_posix()]
    assert surfaces["Writer"]["receiptRefs"] == [other_receipt.relative_to(scan_dir).as_posix()]
    retained_task = next(
        row
        for row in coverage["deferred"]
        if row.get("provenance") == {"workerId": worker_id, "attempt": 1, "sourceId": "review-api"}
    )
    assert retained_task["surfaceIds"] == [retained["id"]]
    assert not any(
        "Skipped malformed coverage receipt" in warning
        for warning in get_scan(state_dir, scan_id)["scan"]["warnings"]
    )
    sealed = (scan_dir / "scan-manifest.json").read_bytes()
    preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == sealed
    assert all(path.read_bytes() == content for path, content in originals.items())
