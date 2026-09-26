from __future__ import annotations

import errno
import importlib
from pathlib import Path


def test_publication_copy_survives_unavailable_hardlinks(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    deep = importlib.import_module("deep_scan_workbench")
    source = tmp_path / "snapshot.jsonl"
    publication = tmp_path / "publication.jsonl"
    source.write_bytes(b'{"finding":"synthetic"}\n')

    def reject_hardlink(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "hardlinks are unavailable")

    monkeypatch.setattr(deep.os, "link", reject_hardlink)
    deep.create_publication_copy(source, publication)
    assert publication.read_bytes() == source.read_bytes()
    assert not publication.samefile(source)
    assert deep.publication_matches_snapshot(publication, source)
    publication.write_bytes(b'{"finding":"different"}\n')
    assert not deep.publication_matches_snapshot(publication, source)
    publication.unlink()
    assert not deep.publication_matches_snapshot(publication, source)
