from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import scan_command, start_saved_scan, write_completed_contract


@pytest.mark.parametrize("location", ["findings", "finding", "poc", "descendant", "cycle"])
@pytest.mark.parametrize(
    "link_kind",
    [
        pytest.param("symlink", marks=pytest.mark.cross_platform),
        pytest.param("emulated-junction", marks=pytest.mark.cross_platform),
        pytest.param(
            "junction",
            marks=[
                pytest.mark.native_windows,
                pytest.mark.skipif(os.name != "nt", reason="requires native Windows junctions"),
            ],
        ),
    ],
)
def test_finding_details_do_not_walk_linked_artifact_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    workbench_api,
    location: str,
    link_kind: str,
) -> None:
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_id, scan_dir = start_saved_scan(state, target, tmp_path / "scans")
    write_completed_contract(scan_dir, scan_id, target)
    slug = "synthetic-finding"
    report_path = f"findings/{slug}/{slug}.md"
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"][0]["writeup"] = {"reportPath": report_path}
    findings_path.write_text(json.dumps(findings))
    report = scan_dir / report_path
    poc = report.parent / "poc"
    fixtures = poc / "fixtures"
    fixtures.mkdir(parents=True)
    report.write_text("# Synthetic finding\n")
    (poc / "reproduce.py").write_text("print('synthetic')\n")
    (fixtures / "payload.txt").write_text("synthetic input\n")
    expected = [
        report_path,
        f"findings/{slug}/poc/reproduce.py",
        f"findings/{slug}/poc/fixtures/payload.txt",
    ]
    completed = scan_command(state, "complete-scan", scan_id)["scan"]["findings"][0]
    assert completed["artifactPaths"] == expected

    link = {
        "findings": scan_dir / "findings",
        "finding": report.parent,
        "poc": poc,
        "descendant": poc / "linked",
        "cycle": fixtures / "cycle",
    }[location]
    outside = tmp_path / "outside"
    if link_kind == "emulated-junction":
        link.mkdir(exist_ok=True)
    elif link.exists():
        link.rename(outside)
    elif location != "cycle":
        outside.mkdir()
        (outside / "unrelated.txt").write_text("outside artifact tree\n")
    destination = poc if location == "cycle" else outside
    if link_kind == "junction":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(destination)],
            check=True,
            capture_output=True,
        )
    elif link_kind == "symlink":
        try:
            link.symlink_to(destination, target_is_directory=True)
        except OSError as exc:
            if os.name != "nt":
                raise
            pytest.skip(f"creating a Windows directory symlink requires host support: {exc}")

    real_lstat = Path.lstat
    real_scandir = os.scandir
    visited = []

    def metadata(path: Path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        if link_kind == "emulated-junction" and path == link:
            fields = {name: getattr(result, name) for name in dir(result) if name.startswith("st_")}
            fields["st_file_attributes"] = stat.FILE_ATTRIBUTE_REPARSE_POINT
            fields["st_reparse_tag"] = 0xA0000003
            return SimpleNamespace(**fields)
        return result

    def scandir(path):
        if not isinstance(path, int):
            selected = Path(path)
            visited.append(selected)
            assert not selected.is_relative_to(link), "finding details traversed a linked directory"
        return real_scandir(path)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(Path, "lstat", metadata)
            patch.setattr(os, "scandir", scandir)
            patch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
            patch.setattr(
                sys,
                "argv",
                ["workbench_db.py", "get-finding", "--occurrence-id", completed["occurrenceId"]],
            )
            with io.TextIOWrapper(io.BytesIO()) as stdin:
                patch.setattr(sys, "stdin", stdin)
                workbench_api["main"]()
        finding = json.loads(capsys.readouterr().out)["scan"]["findings"][0]
        if location in {"findings", "finding"}:
            expected = [report_path] if link_kind == "emulated-junction" else []
        elif location == "poc":
            expected = [report_path]
        assert finding["artifactPaths"] == expected
        assert not any(path.is_relative_to(link) for path in visited)
    finally:
        if link_kind == "junction":
            link.rmdir()
        elif link_kind == "symlink":
            link.unlink()
