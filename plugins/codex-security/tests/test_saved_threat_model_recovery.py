from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from test_deep_coverage_recovery import worker
from workbench_test_support import saved_binding, saved_draft

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finalize_scan_contract as finalizer
import workbench_saved_results as saved


@pytest.mark.parametrize(
    "invalid_model",
    [
        {},
        {"summary": ""},
        {"summary": "Review", "assets": [42]},
        pytest.param({"summary": "\ud800"}, id="lone-surrogate"),
    ],
)
@pytest.mark.parametrize("with_fallback", [False, True])
def test_invalid_optional_context_does_not_block_findings_or_frozen_replay(
    tmp_path, invalid_model, with_fallback
):
    scan_id = "00000000-0000-4000-8000-000000000001"
    finding = {
        "ruleId": "synthetic.input",
        "identity": {"anchor": "fixture"},
        "title": "Synthetic finding",
        "summary": "A synthetic source-backed result.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic fixture evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "fixture.py", "startLine": 1}],
        "remediation": "Apply the synthetic correction.",
        "provenance": {"source": "local_plugin"},
    }
    draft = saved_draft(scan_id, findings=[finding])
    draft["threatModel"] = copy.deepcopy(invalid_model)
    sources = [worker(tmp_path, "invalid-context", draft)]
    fallback = {"summary": "A valid saved worker context.", "assets": ["Synthetic records"]}
    if with_fallback:
        valid = saved_draft(scan_id)
        valid["threatModel"] = fallback
        sources.append(worker(tmp_path, "valid-context", valid))
    originals = {path: path.read_bytes() for path in tmp_path.rglob("result.json")}
    binding = {
        **saved_binding("deep_repository", repository="synthetic", status="completed"),
        "scanId": scan_id,
        "startedAt": "2026-01-01T00:00:00Z",
        "completedAt": "2026-01-01T00:01:00Z",
        "producer": {"name": "codex-security", "version": "0.0.0"},
    }
    binding["target"].update(
        revision="a" * 40, targetId="synthetic", displayName="Synthetic fixture"
    )
    frozen = None
    invalid_source = "artifacts/deep_discovery/workers/invalid-context/output/result.json"
    for replay in (False, True):
        warnings = []
        selected = [invalid_source] if replay else []
        documents = saved.merge_saved_results(
            tmp_path,
            scan_id,
            binding,
            sources,
            warnings,
            stopped=True,
            reason="Time limit.",
            project_worker_coverage=True,
            frozen_source_digests=frozen,
            frozen_model_source=invalid_source if replay else None,
            selected_model_source=selected,
        )
        assert documents is not None
        frozen = documents[0]["scan"]["preservedSources"]
        documents[0]["scan"].pop("complete", None)
        prepared = finalizer._prepare_scan_finalization(
            tmp_path,
            expected_coverage_mode="deep_repository",
            completion_binding=binding,
            recover_unsealed=True,
            draft_documents=documents,
        )
        assert len(prepared.findings["findings"]) == 1
        assert prepared.findings["findings"][0]["provenance"]["workerId"] == "invalid-context"
        assert any("Skipped malformed saved threat model" in warning for warning in warnings)
        if with_fallback:
            assert prepared.manifest["scan"]["threatModel"] == {**fallback, "origin": "recovered"}
            assert selected == ["artifacts/deep_discovery/workers/valid-context/output/result.json"]
        else:
            assert "threatModel" not in prepared.manifest["scan"]
            assert selected == []
    assert all(path.read_bytes() == contents for path, contents in originals.items())
