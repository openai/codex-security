from __future__ import annotations

import importlib
from pathlib import Path


def test_archived_publication_matches_its_snapshot(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    deep = importlib.import_module("deep_scan_workbench")
    source = tmp_path / "snapshot.jsonl"
    publication = tmp_path / "publication.jsonl"
    source.write_bytes(b'{"finding":"synthetic"}\n')

    publication.write_bytes(source.read_bytes())
    assert publication.read_bytes() == source.read_bytes()
    assert not publication.samefile(source)
    assert deep.publication_matches_snapshot(publication, source)
    publication.write_bytes(b'{"finding":"different"}\n')
    assert not deep.publication_matches_snapshot(publication, source)
    publication.unlink()
    assert not deep.publication_matches_snapshot(publication, source)
