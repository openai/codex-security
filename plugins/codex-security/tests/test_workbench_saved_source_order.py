from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import drafts, select
from workbench_test_support import saved_binding, write_checkpoint

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_db
import workbench_saved_results as saved


def call_workbench(monkeypatch, state, codex_home, *args):
    with open(os.devnull) as stdin, monkeypatch.context() as patch:
        patch.setenv("CODEX_HOME", str(codex_home))
        patch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
        patch.setattr(sys, "stdin", stdin)
        patch.setattr(sys, "argv", ["workbench_db", *args])
        workbench_db.main()


@pytest.mark.parametrize("latest_pending", [True, False])
@pytest.mark.parametrize("rewritten", ["accepted", "pending"])
def test_frozen_times_survive_identical_committed_and_pending_rewrites(
    tmp_path: Path, latest_pending: bool, rewritten: str
) -> None:
    scan_id = "source-order"
    pending, closed = drafts(scan_id)
    accepted, incoming = (closed, pending) if latest_pending else (pending, closed)
    committed = write_checkpoint(tmp_path / "checkpoints", accepted)
    os.utime(committed, ns=(100, 100))
    select(tmp_path, committed, 100)
    checkpoint = write_checkpoint(tmp_path / "checkpoints", incoming)
    os.utime(checkpoint, ns=(200, 200))
    marker = tmp_path / "checkpoints/pending" / checkpoint.name
    marker.parent.mkdir()
    marker.write_bytes(checkpoint.read_bytes())
    os.utime(marker, ns=(200, 200))
    binding = saved_binding(repository="synthetic")

    def merge(frozen=None):
        return saved.merge_saved_results(
            tmp_path,
            scan_id,
            binding,
            [],
            stopped=True,
            reason="interrupted",
            frozen_source_digests=frozen,
        )

    first = merge()
    frozen = first[0]["scan"]["preservedSources"]
    assert any(row["id"] == "review" for row in first[2]["deferred"]) is latest_pending
    path, observed = (committed, 300) if rewritten == "accepted" else (checkpoint, 50)
    path.write_bytes(path.read_bytes())
    os.utime(path, ns=(observed, observed))
    assert merge(frozen)[2] == first[2]
    record_path = next(path for path in frozen if path.startswith("source-order/"))
    record = json.loads((tmp_path / record_path).read_text())
    record["sources"][checkpoint.relative_to(tmp_path).as_posix()]["observedAtNs"] = "400"
    (tmp_path / record_path).write_text(json.dumps(record))
    with pytest.raises(saved.ContractError, match="source ordering changed"):
        merge(frozen)


def test_order_metadata_is_not_new_evidence(tmp_path: Path) -> None:
    orphan = tmp_path / "source-order" / ("0" * 64 + ".json")
    orphan.parent.mkdir()
    orphan.write_text(json.dumps({"scanId": "scan", "sources": {}}))
    assert saved._saved_result_paths(tmp_path, "scan") == []
