from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath

import pytest


def test_measures_selected_markdown_and_compiled_deep_roles(tmp_path: Path, workbench_api) -> None:
    from workbench_instruction_digest import bundled_instruction_digest

    skills = tmp_path / "skills" / "scan"
    roles = tmp_path / "references" / "deep-scan"
    roles.mkdir(parents=True)
    skills.mkdir(parents=True)
    entries = {
        "references/deep-scan/dedup.md": b"dedup",
        "references/deep-scan/discovery.md": b"discovery",
        "skills/scan/SKILL.md": b"first\r\nsecond",
    }
    for relative, content in reversed(entries.items()):
        (tmp_path / relative).write_bytes(content)
    (skills / "config.json").write_text("{}")
    sha = hashlib.sha256
    compiled = {
        name: sha((roles / f"{name}.md").read_bytes()).hexdigest()
        for name in ("dedup", "discovery")
    }
    framed = b"".join(
        path.encode() + b"\0" + sha(content).digest() for path, content in entries.items()
    )
    expected = "sha256:" + sha(framed).hexdigest()
    assert (
        bundled_instruction_digest(tmp_path)
        == bundled_instruction_digest(tmp_path, compiled)
        == expected
    )

    (skills / "SKILL.md").write_bytes(entries["skills/scan/SKILL.md"] + b"\n")
    changed = bundled_instruction_digest(tmp_path)
    assert changed and changed != expected
    assert bundled_instruction_digest(tmp_path, compiled) == changed

    (roles / "dedup.md").write_bytes(b"dedup\n")
    assert bundled_instruction_digest(tmp_path) != changed
    assert bundled_instruction_digest(tmp_path, compiled) == changed


def test_opaque_or_unbound_installation_has_no_digest(tmp_path: Path, workbench_api) -> None:
    from workbench_instruction_digest import bundled_instruction_digest

    assert bundled_instruction_digest(None) is None
    assert bundled_instruction_digest(tmp_path) is None
    skills = tmp_path / "skills"
    skills.mkdir()
    (skills / "SKILL.md").write_text("read the reference")
    references = tmp_path / "references"
    references.mkdir()
    try:
        (references / "external.md").symlink_to(Path(__file__))
    except OSError:
        pytest.skip("symlinks unavailable")
    assert bundled_instruction_digest(tmp_path) is None


@pytest.mark.skipif(os.name != "posix", reason="These are POSIX filenames")
def test_digest_includes_native_markdown_names(tmp_path: Path, workbench_api) -> None:
    from workbench_instruction_digest import bundled_instruction_digest

    (tmp_path / "skills").mkdir()
    (tmp_path / "references").mkdir()
    paths = (
        b"references/aux.md",
        rb"references/audit\linux.md",
        b"references/control\x01.md",
        b"references/audit:linux.md",
    )
    for path in paths:
        (tmp_path / os.fsdecode(path)).write_bytes(b"instruction")
    expected = hashlib.sha256()
    for path in sorted(paths):
        expected.update(path + b"\0" + hashlib.sha256(b"instruction").digest())
    assert bundled_instruction_digest(tmp_path) == "sha256:" + expected.hexdigest()


@pytest.mark.skipif(os.name != "posix", reason="Exercises the POSIX instruction opener")
def test_native_instruction_opener_confines_reads(tmp_path: Path, workbench_api) -> None:
    from workbench_instruction_digest import _open_instruction_file

    root = tmp_path / "plugin"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "external.md").write_bytes(b"external instruction")
    (root / "directory").symlink_to(outside, target_is_directory=True)
    (root / "leaf.md").symlink_to(outside / "external.md")
    for path in ("../outside/external.md", "directory/external.md", "leaf.md"):
        with pytest.raises((ValueError, OSError)):
            os.close(_open_instruction_file(root, PurePosixPath(path)))


def test_instruction_directory_link_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workbench_api
) -> None:
    from workbench_instruction_digest import bundled_instruction_digest

    root = tmp_path / "plugin"
    (root / "skills").mkdir(parents=True)
    references = root / "references"
    try:
        references.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    original = os.stat

    def probe(path, *args, **kwargs):
        if path in (references, str(references)) and kwargs.get("follow_symlinks", True):
            pytest.fail("followed the instruction directory link")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", probe)
    assert bundled_instruction_digest(root) is None


def test_replacing_the_installation_during_measurement_yields_no_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workbench_api
) -> None:
    import workbench_instruction_digest as instructions

    selected, replacement = tmp_path / "selected", tmp_path / "replacement"
    for root in (selected, replacement):
        for directory in ("skills", "references"):
            (root / directory).mkdir(parents=True)
            (root / directory / "instructions.md").write_text(root.name)
    original_open = instructions._open_instruction_file
    opened = 0

    def open_during_update(*args, **kwargs):
        nonlocal opened
        opened += 1
        if opened == 2:
            selected.rename(tmp_path / "old")
            replacement.rename(selected)
        return original_open(*args, **kwargs)

    monkeypatch.setattr(instructions, "_open_instruction_file", open_during_update)
    assert instructions.bundled_instruction_digest(selected) is None
    assert opened == 2


@pytest.mark.parametrize(
    "update",
    [
        "replace-subtree",
        "add-markdown",
        pytest.param(
            "restore-after-open",
            marks=pytest.mark.skipif(
                os.name != "posix", reason="Moves a directory with an open file"
            ),
        ),
    ],
)
def test_changing_instructions_inside_the_installation_yields_no_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workbench_api, update: str
) -> None:
    import workbench_instruction_digest as instructions

    selected = tmp_path / "selected"
    (selected / "skills").mkdir(parents=True)
    references = selected / "references"
    replacement = tmp_path / "replacement"
    for directory in (references, replacement):
        directory.mkdir()
        for name in ("first.md", "second.md"):
            (directory / name).write_text(f"{directory.name}: {name}")
    installation = selected.stat()
    before = instructions.bundled_instruction_digest(selected)
    open_file = instructions._open_instruction_file
    opened = 0

    def update_after_first_read(*args, **kwargs):
        nonlocal opened
        opened += 1
        if opened == 2:
            # The first file has been hashed and closed. The parent installation stays in place.
            if update in ("replace-subtree", "restore-after-open"):
                references.rename(tmp_path / "old")
                replacement.rename(references)
                if update == "restore-after-open":
                    descriptor = open_file(*args, **kwargs)
                    references.rename(replacement)
                    (tmp_path / "old").rename(references)
                    return descriptor
            else:
                (references / "added.md").write_text("additional instruction")
        return open_file(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(instructions, "_open_instruction_file", update_after_first_read)
        measured = instructions.bundled_instruction_digest(selected)
    after = instructions.bundled_instruction_digest(selected)
    assert opened >= 2 and os.path.samestat(installation, selected.stat())
    assert before and after
    assert (before == after) == (update == "restore-after-open")
    assert measured is None, f"measured {measured}, stable digests were {before} and {after}"
