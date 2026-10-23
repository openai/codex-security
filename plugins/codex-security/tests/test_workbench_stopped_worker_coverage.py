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
    saved_draft,
    upsert_deep_worker,
    worker_paths,
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
    coverage = json.loads((scan_dir / "coverage.json").read_text())
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

    coverage_path = scan_dir / "coverage.json"
    surface = json.loads(coverage_path.read_text())["surfaces"][0]
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
    sealed = coverage_path.read_bytes()
    preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )
    assert coverage_path.read_bytes() == sealed
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

    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    surfaces = {row["label"]: row for row in coverage["surfaces"]}
    assert len(surfaces) == 2
    assert surfaces["Explicit"]["id"] != surfaces["Anonymous"]["id"]
    assert coverage["deferred"][0]["surfaceIds"] == [surfaces["Explicit"]["id"]]
    sealed = coverage_path.read_bytes()
    preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )
    assert coverage_path.read_bytes() == sealed
    assert result.read_bytes() == original
