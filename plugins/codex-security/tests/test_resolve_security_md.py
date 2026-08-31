from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "resolve_security_md.py"


def run_resolver(
    root: Path,
    scope: str | Path,
    *,
    out: str | Path = "-",
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(root),
            "--scope",
            str(scope),
            "--out",
            str(out),
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def run_inventory(root: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", str(root), "--list"],
        check=check,
        capture_output=True,
        text=True,
    )


def test_lists_sorted_hidden_and_linked_policies_without_git_metadata(tmp_path: Path) -> None:
    root = tmp_path / "project"
    hidden = root / ".hidden"
    nested = root / "services" / "api"
    git_metadata = root / ".git" / "objects"
    for directory in (hidden, nested, git_metadata):
        directory.mkdir(parents=True)
    (root / "SECURITY.md").write_text("root policy\n", encoding="utf-8")
    (hidden / "SECURITY.md").write_text("hidden policy\n", encoding="utf-8")
    shared = root / "shared-policy.md"
    shared.write_text("shared policy\n", encoding="utf-8")
    (nested / "SECURITY.md").symlink_to(shared)
    (git_metadata / "SECURITY.md").write_text("not a policy\n", encoding="utf-8")

    result = run_inventory(root)

    assert json.loads(result.stdout) == [
        ".hidden/SECURITY.md",
        "SECURITY.md",
        "services/api/SECURITY.md",
    ]
    assert result.stderr == ""


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not allow control characters in paths"
)
def test_inventory_json_escapes_newline_and_terminal_control_paths(tmp_path: Path) -> None:
    root = tmp_path / "project"
    unusual = root / "service\n\x1b[31mname"
    unusual.mkdir(parents=True)
    (unusual / "SECURITY.md").write_text("component policy\n", encoding="utf-8")

    result = run_inventory(root)

    assert json.loads(result.stdout) == ["service\n\x1b[31mname/SECURITY.md"]
    assert "\\n" in result.stdout
    assert "\\u001b" in result.stdout
    assert "\x1b" not in result.stdout
    assert result.stdout.count("\n") == 1


def test_inventory_does_not_follow_directory_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SECURITY.md").write_text("outside policy\n", encoding="utf-8")
    (root / "outside-link").symlink_to(outside, target_is_directory=True)

    result = run_inventory(root)

    assert json.loads(result.stdout) == []


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-specific")
def test_inventory_does_not_follow_windows_directory_junctions(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SECURITY.md").write_text("outside policy\n", encoding="utf-8")
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(root / "junction"), str(outside)],
        check=True,
        capture_output=True,
    )

    result = run_inventory(root)

    assert json.loads(result.stdout) == []


def test_inventory_rejects_missing_scan_root(tmp_path: Path) -> None:
    result = run_inventory(tmp_path / "missing", check=False)

    assert result.returncode == 2
    assert "scan root does not exist" in result.stderr
    assert result.stdout == ""


def test_inventory_rejects_scope_option(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(root),
            "--list",
            "--scope",
            ".",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "--list cannot be combined with --scope" in result.stderr
    assert result.stdout == ""


def test_concatenates_plain_folder_guidance_root_to_leaf(tmp_path: Path) -> None:
    root = tmp_path / "project"
    nested = root / "services" / "api"
    nested.mkdir(parents=True)
    (root / "SECURITY.md").write_text("root policy\n", encoding="utf-8")
    (root / "services" / "SECURITY.md").write_text("service policy\n", encoding="utf-8")
    (nested / "SECURITY.md").write_text("api policy\n", encoding="utf-8")
    target = nested / "handler.py"
    target.write_text("pass\n", encoding="utf-8")

    result = run_resolver(root, target)

    expected_sources = [
        '## SECURITY.md source: "SECURITY.md"',
        '## SECURITY.md source: "services/SECURITY.md"',
        '## SECURITY.md source: "services/api/SECURITY.md"',
    ]
    assert all(source in result.stdout for source in expected_sources)
    assert [result.stdout.index(source) for source in expected_sources] == sorted(
        result.stdout.index(source) for source in expected_sources
    )
    assert "root policy\n" in result.stdout
    assert "service policy\n" in result.stdout
    assert "api policy\n" in result.stdout


def test_uses_file_parent_and_skips_empty_guidance(tmp_path: Path) -> None:
    root = tmp_path / "project"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / "SECURITY.md").write_text("root policy\n", encoding="utf-8")
    (nested / "SECURITY.md").write_text(" \n\t", encoding="utf-8")
    target = nested / "app.py"
    target.write_text("pass\n", encoding="utf-8")

    result = run_resolver(root, "src/app.py")

    assert result.stdout.count("## SECURITY.md source:") == 1
    assert '## SECURITY.md source: "SECURITY.md"' in result.stdout


def test_writes_empty_output_when_no_guidance_exists(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    output = tmp_path / "artifacts" / "security_guidance.md"

    run_resolver(root, ".", out=output)

    assert output.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("scope", ["missing", "../outside"])
def test_rejects_invalid_scope(tmp_path: Path, scope: str) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (tmp_path / "outside").mkdir()

    result = run_resolver(root, scope, check=False)

    assert result.returncode == 2
    assert "error:" in result.stderr


def test_rejects_non_utf8_guidance(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "SECURITY.md").write_bytes(b"\xff")

    result = run_resolver(root, ".", check=False)

    assert result.returncode == 2
    assert "not valid UTF-8" in result.stderr


def test_resolves_repository_local_symlinked_guidance(tmp_path: Path) -> None:
    root = tmp_path / "project"
    policies = root / "policies"
    policies.mkdir(parents=True)
    target = policies / "shared.md"
    target.write_text("shared policy\n", encoding="utf-8")
    (root / "SECURITY.md").symlink_to(target.relative_to(root))

    result = run_resolver(root, ".")

    assert '## SECURITY.md source: "SECURITY.md"' in result.stdout
    assert "shared policy\n" in result.stdout


def test_rejects_guidance_symlink_outside_repository(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("outside policy\n", encoding="utf-8")
    (root / "SECURITY.md").symlink_to(outside)

    result = run_resolver(root, ".", check=False)

    assert result.returncode == 2
    assert "SECURITY.md is outside the scan root" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("symlinked", [False, True])
def test_rejects_oversized_regular_or_symlinked_guidance(
    tmp_path: Path, *, symlinked: bool
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    policy = root / "SECURITY.md"
    target = root / "large-policy.md" if symlinked else policy
    target.write_bytes(b"a" * (1024 * 1024 + 1))
    if symlinked:
        policy.symlink_to(target.name)

    result = run_resolver(root, ".", check=False)

    assert result.returncode == 2
    assert "SECURITY.md exceeds 1 MiB" in result.stderr
    assert result.stdout == ""


def test_accepts_guidance_at_size_limit(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    content = "a" * (1024 * 1024)
    (root / "SECURITY.md").write_text(content, encoding="utf-8")

    result = run_resolver(root, ".")

    assert result.stdout.endswith(content + "\n")


def test_stdout_preserves_utf8_under_legacy_console_encoding(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    content = "Unicode policy: 🔐 東京\n"
    (root / "SECURITY.md").write_text(content, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(root),
            "--scope",
            ".",
            "--out",
            "-",
        ],
        check=True,
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "cp1252"},
    )

    assert content in result.stdout.decode("utf-8")
    assert result.stderr == b""
