from __future__ import annotations

import copy
import json
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_workbench_recovery_edges import select_checkpoint
from workbench_test_support import (
    checkpoint,
    register,
    run_workbench,
    saved_draft,
    write_checkpoint,
)


def test_legacy_anonymous_child_questions_preserve_shared_parent_and_sibling_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    question = {"question": "Synthetic shared unresolved question."}
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        draft = saved_draft(child["scanId"], complete=True)
        draft["coverage"]["inventoryStrategy"] = "repository"
        draft["coverage"]["openQuestions"] = [copy.deepcopy(question)]
        original = write_checkpoint(directory / "checkpoints", draft)
        select_checkpoint(directory, original)
        run_workbench(
            state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic interruption"
        )
        children.append((child, directory, draft))
    saved = checkpoint(state, parent)
    saved["aggregate"] = saved_draft(parent["scanId"])
    saved["aggregate"]["coverage"]["openQuestions"] = [copy.deepcopy(question)]
    (parent_dir / "artifacts/deep-scan/checkpoint.json").write_text(json.dumps(saved))
    project_child = results._stopped_child_draft

    def legacy_project_child(*args, **kwargs):
        draft = project_child(*args, **kwargs)
        for row in draft["coverage"].get("openQuestions", []):
            row.pop("id", None)
        return draft

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "_stopped_child_draft", legacy_project_child)
        results.fail_scan(
            db._WORKBENCH_DB_CONTEXT,
            connection,
            SimpleNamespace(
                scan_id=parent["scanId"],
                claim_token=None,
                cost_json=None,
                message="Synthetic interruption",
            ),
        )
    # The old writer coalesced identical anonymous rows and saved no row owner.
    assert json.loads((parent_dir / "coverage.json").read_text())["openQuestions"] == [question]
    child, directory, draft = children[0]
    draft["coverage"]["openQuestions"] = []
    latest = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, latest)
    run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
    unchanged = {
        path: path.read_bytes()
        for _, child_dir, _ in children
        for path in child_dir.rglob("*")
        if path.is_file()
    }
    previous = None
    for _ in range(3):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        coverage = (parent_dir / "coverage.json").read_bytes()
        questions = json.loads(coverage)["openQuestions"]
        # A matching historical child source cannot establish exclusive ownership.
        assert question in questions
        owned = [row for row in questions if "id" in row]
        assert len(owned) == 1
        assert owned[0]["id"].startswith(f"{children[1][0]['scanId']}/")
        assert {key: value for key, value in owned[0].items() if key != "id"} == question
        if previous is not None:
            assert coverage == previous
        previous = coverage
        for path, contents in unchanged.items():
            assert path.read_bytes() == contents
