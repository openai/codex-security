from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import register, run_workbench, saved_draft, write_checkpoint


@pytest.mark.parametrize("unreadable", ["missing", "malformed"])
@pytest.mark.parametrize("publication_failure", [False, True])
def test_failed_child_reread_retains_frozen_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unreadable: str, publication_failure: bool
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    task = {"id": "review-task", "reason": "Synthetic review remains."}
    draft = saved_draft(
        child["scanId"],
        complete=True,
        surfaces=[
            {
                "id": "review-surface",
                "label": "Synthetic surface",
                "disposition": "no_issue_found",
                "receiptRefs": [],
            }
        ],
        deferred=[task],
    )
    draft["coverage"]["inventoryStrategy"] = "repository"
    draft["coverage"]["explicitExclusions"] = [
        {"id": "excluded-path", "reason": "Synthetic exclusion", "pattern": "docs/**"}
    ]
    draft["coverage"]["openQuestions"] = [
        {"id": "open-question", "question": "Synthetic question?"}
    ]
    original = write_checkpoint(child_dir / "checkpoints", draft)
    (child_dir / "checkpoint-head.json").write_text(json.dumps({"checkpoint": original.name}))
    run_workbench(
        state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic child stop"
    )
    for field in ("surfaces", "deferred", "explicitExclusions", "openQuestions"):
        assert (
            draft["coverage"][field][0]
            in json.loads((child_dir / "coverage.json").read_text())[field]
        )
    child_bytes = {path: path.read_bytes() for path in child_dir.rglob("*") if path.is_file()}

    def interrupt_publication(*args, **kwargs):
        raise OSError("Synthetic first parent publication failure")

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        if publication_failure:
            patch.setattr(results, "_write_prepared_scan_finalization", interrupt_publication)
        results.fail_scan(
            db._WORKBENCH_DB_CONTEXT,
            connection,
            SimpleNamespace(
                scan_id=parent["scanId"],
                claim_token=None,
                cost_json=None,
                message="Synthetic parent stop",
            ),
        )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        seal, frozen = connection.execute(
            "SELECT seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
            (parent["scanId"],),
        ).fetchone()
    assert (seal is None) is publication_failure
    assert frozen is not None
    history = {path: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    assert history
    coverage_path = child_dir / "coverage.json"
    if unreadable == "missing":
        coverage_path.unlink()
    else:
        coverage_path.write_text("{")
    recovery = ("recover-scan-results", "--scan-id", parent["scanId"])
    for _ in range(2):
        recovered = run_workbench(state, *recovery)["scan"]
        assert recovered["resultsRecoveryNeeded"] is True
        assert any(
            "Independent scan recovery failed:" in warning for warning in recovered["warnings"]
        )
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        for field in ("surfaces", "deferred", "explicitExclusions", "openQuestions"):
            for row in draft["coverage"][field]:
                assert any(
                    item.get("id") == f"{child['scanId']}/{row['id']}"
                    and all(item.get(key) == value for key, value in row.items() if key != "id")
                    for item in coverage[field]
                )
        for path, contents in history.items():
            assert path.read_bytes() == contents
    coverage_path.write_bytes(child_bytes[coverage_path])
    published = None
    for _ in range(3):
        recovered = run_workbench(state, *recovery)["scan"]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        coverage = (parent_dir / "coverage.json").read_bytes()
        if published is not None:
            assert coverage == published
        published = coverage
        for path, contents in {**history, **child_bytes}.items():
            assert path.read_bytes() == contents


def test_legacy_child_coverage_retires_only_after_successful_empty_observation(
    tmp_path: Path,
) -> None:
    from workbench_test_support import write_completed_contract

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target)
    for filename, field in (("findings.json", "findings"), ("coverage.json", "surfaces")):
        path = child_dir / filename
        document = json.loads(path.read_text())
        document[field] = []
        path.write_text(json.dumps(document))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    original = {path: path.read_bytes() for path in child_dir.rglob("*") if path.is_file()}
    prefix = child["scanId"] + "/"
    older = saved_draft(
        parent["scanId"],
        surfaces=[
            {
                "id": prefix + "surface",
                "label": "Earlier child observation",
                "disposition": "no_issue_found",
            }
        ],
        deferred=[{"id": prefix + "task", "reason": "Earlier child work."}],
    )
    older["coverage"]["explicitExclusions"] = [
        {"id": prefix + "exclusion", "pattern": "docs/**", "reason": "Earlier exclusion."}
    ]
    older["coverage"]["openQuestions"] = [
        {"id": prefix + "question", "question": "Earlier question?"}
    ]
    older["coverage"]["deferred"].append(
        {"id": "unmerged-" + child["scanId"], "reason": "Earlier unmerged child observation."}
    )
    history = write_checkpoint(parent_dir / "checkpoints", older)
    immutable = history.read_bytes()
    coverage_path = child_dir / "coverage.json"
    coverage_path.unlink()
    run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic parent stop"
    )
    # An older failure note has no machine-readable successful observation.
    for _ in range(2):
        run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        for field in ("surfaces", "deferred", "explicitExclusions", "openQuestions"):
            assert any(row["id"].startswith(prefix) for row in coverage[field])
        assert history.read_bytes() == immutable
    coverage_path.write_bytes(original[coverage_path])
    published = None
    for _ in range(3):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        contents = (parent_dir / "coverage.json").read_bytes()
        coverage = json.loads(contents)
        for field in ("surfaces", "deferred", "explicitExclusions", "openQuestions"):
            assert not any(row["id"].startswith(prefix) for row in coverage[field])
        if published is not None:
            assert contents == published
        published = contents
        assert history.read_bytes() == immutable
        for path, contents in original.items():
            assert path.read_bytes() == contents
