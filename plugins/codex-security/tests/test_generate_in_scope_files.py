from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_in_scope_files.py"


def write_file(repository: Path, name: str, content: bytes = b"example\n") -> Path:
    path = repository / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def make_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "-q"],
        cwd=repository,
        capture_output=True,
        check=True,
    )
    for name in (
        "app/routes.py",
        "app/name with spaces.py",
        "app/résumé.py",
        "app/évidence.py",
        "tests/demo.py",
        "fixtures/example.py",
        ".hidden.py",
        ".hidden-directory/handler.py",
    ):
        write_file(repository, name)
    write_file(repository, "app/binary.dat", b"\x00\xff\x01")
    write_file(repository, ".gitignore", b"ignored/\n*.skip\n")
    write_file(repository, "ignored/secret.py")
    write_file(repository, "app/ignored.skip")
    return repository


def run_inventory(
    repository: Path,
    scope: str,
    output: Path,
    *,
    env: dict[str, str] | None = None,
    arguments: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repository),
            "--scope",
            scope,
            "--out",
            str(output),
            *(arguments or []),
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def standard_inventory(repository: Path, scope: str) -> bytes:
    files = subprocess.run(
        ["rg", "--files", "--hidden", "--glob", "!.git/**", "--path-separator=/", "--", scope],
        cwd=repository,
        capture_output=True,
        check=False,
    )
    assert files.returncode in (0, 1), files.stderr.decode("utf-8", errors="replace")
    return b"".join(sorted(files.stdout.splitlines(keepends=True)))


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.mark.parametrize("scope", [".", "app", "./app", "app/routes.py"])
def test_inventory_matches_the_existing_standard_command(tmp_path: Path, scope: str) -> None:
    repository = make_repository(tmp_path)
    output = tmp_path / "artifacts" / "02_discovery" / "in_scope_files.txt"
    output.parent.mkdir(parents=True)
    output.write_text("previous.py\n", encoding="utf-8")

    result = run_inventory(repository, scope, output)

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == standard_inventory(repository, scope)
    assert list(output.parent.glob(f".{output.name}.*.tmp")) == []
    if scope == ".":
        rows = set(output.read_text(encoding="utf-8").splitlines())
        assert {
            "./.hidden.py",
            "./.hidden-directory/handler.py",
            "./tests/demo.py",
            "./fixtures/example.py",
            "./app/binary.dat",
            "./app/name with spaces.py",
            "./app/résumé.py",
            "./app/évidence.py",
        } <= rows
        assert {"./ignored/secret.py", "./app/ignored.skip"}.isdisjoint(rows)


def test_absolute_scope_still_produces_repository_relative_paths(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    output = tmp_path / "in_scope_files.txt"

    result = run_inventory(repository, str(repository / "app"), output)

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == standard_inventory(repository, "app")
    assert all(not Path(line).is_absolute() for line in output.read_text().splitlines())


def test_inventory_keeps_ignored_tracked_files_without_ignored_untracked_files(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    write_file(repository, "ignored/tracked.py")
    git(repository, "add", "--force", "--", "ignored/tracked.py")
    output = tmp_path / "in_scope_files.txt"

    result = run_inventory(repository, ".", output)

    assert result.returncode == 0, result.stderr
    paths = set(output.read_text(encoding="utf-8").splitlines())
    assert "./ignored/tracked.py" in paths
    assert "./ignored/secret.py" not in paths
    assert "./app/ignored.skip" not in paths


def test_diff_inventory_includes_power_shell_files(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "-q"],
        cwd=repository,
        capture_output=True,
        check=True,
    )
    git(repository, "commit", "--allow-empty", "-qm", "base")
    base = git(repository, "rev-parse", "HEAD")

    write_file(repository, "config.json", b'{"enabled": true}\n')
    write_file(repository, "build.ps1", b'Write-Output "build"\n')
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "add diff files")
    head = git(repository, "rev-parse", "HEAD")

    output = tmp_path / "in_scope_files.txt"
    result = run_inventory(
        repository,
        ".",
        output,
        arguments=["--diff-base", base, "--diff-head", head],
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == [
        "build.ps1",
        "config.json",
    ]


def test_inventory_uses_forward_slashes_when_ripgrep_defaults_to_backslashes(
    tmp_path: Path,
) -> None:
    repository = make_repository(tmp_path)
    output = tmp_path / "in_scope_files.txt"
    config = tmp_path / "ripgrep.conf"
    config.write_text("--path-separator=\\\n", encoding="utf-8")

    result = run_inventory(
        repository,
        ".",
        output,
        env={**os.environ, "RIPGREP_CONFIG_PATH": str(config)},
    )

    assert result.returncode == 0, result.stderr
    paths = output.read_text(encoding="utf-8").splitlines()
    assert "./app/routes.py" in paths
    assert all("\\" not in path for path in paths)


def test_empty_inventory_is_a_success_and_replaces_the_previous_output(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    output = tmp_path / "in_scope_files.txt"
    output.write_text("old.py\n", encoding="utf-8")

    result = run_inventory(repository, ".", output)

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == b""
    assert "0 in-scope files" in result.stdout


@pytest.mark.parametrize(
    ("scope", "message"),
    [
        ("missing", "--scope: path does not exist"),
        ("../outside", "--scope: path must remain inside --repo"),
    ],
)
def test_invalid_scope_preserves_the_previous_inventory(
    tmp_path: Path,
    scope: str,
    message: str,
) -> None:
    repository = make_repository(tmp_path)
    (tmp_path / "outside").mkdir()
    output = tmp_path / "in_scope_files.txt"
    output.write_text("previous.py\n", encoding="utf-8")

    result = run_inventory(repository, scope, output)

    assert result.returncode == 2
    assert message in result.stderr
    assert output.read_text(encoding="utf-8") == "previous.py\n"


def test_scope_cannot_follow_a_symlink_outside_the_repository(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    write_file(outside, "external.py")
    try:
        (repository / "external-link").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"creating a symbolic link requires host support: {error}")
    output = tmp_path / "in_scope_files.txt"
    output.write_text("previous.py\n", encoding="utf-8")

    result = run_inventory(repository, "external-link", output)

    assert result.returncode == 2
    assert "--scope: path must remain inside --repo" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous.py\n"


def test_inventory_refuses_to_replace_an_output_symlink(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    original = tmp_path / "original.txt"
    original.write_text("previous.py\n", encoding="utf-8")
    output = tmp_path / "linked-inventory.txt"
    try:
        output.symlink_to(original)
    except OSError as error:
        pytest.skip(f"creating a symbolic link requires host support: {error}")

    result = run_inventory(repository, ".", output)

    assert result.returncode == 2
    assert "--out: refusing to replace a symbolic link" in result.stderr
    assert output.is_symlink()
    assert original.read_text(encoding="utf-8") == "previous.py\n"


def test_missing_ripgrep_preserves_the_previous_inventory(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    output = tmp_path / "in_scope_files.txt"
    output.write_text("previous.py\n", encoding="utf-8")
    missing_programs = tmp_path / "missing-programs"

    result = run_inventory(
        repository,
        ".",
        output,
        env={**os.environ, "PATH": str(missing_programs)},
    )

    assert result.returncode == 2
    assert "could not run ripgrep" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous.py\n"


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot launch executable script shims")
def test_ripgrep_failure_preserves_the_previous_inventory(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    tools = tmp_path / "tools"
    tools.mkdir()
    ripgrep = tools / "rg"
    ripgrep.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'simulated ripgrep failure' >&2\nexit 2\n",
        encoding="utf-8",
    )
    ripgrep.chmod(0o755)
    output = tmp_path / "in_scope_files.txt"
    output.write_text("previous.py\n", encoding="utf-8")

    result = run_inventory(repository, ".", output, env={**os.environ, "PATH": str(tools)})

    assert result.returncode == 2
    assert "ripgrep exited with status 2: simulated ripgrep failure" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous.py\n"


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot launch executable script shims")
def test_large_inventory_is_not_limited_by_a_subprocess_output_buffer(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    tools = tmp_path / "tools"
    tools.mkdir()
    ripgrep = tools / "rg"
    ripgrep.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "for index in range(12000, 0, -1):\n"
        "    sys.stdout.write(f\"./{'x' * 100}-{index:05d}.py\\n\")\n",
        encoding="utf-8",
    )
    ripgrep.chmod(0o755)
    output = tmp_path / "in_scope_files.txt"

    result = run_inventory(repository, ".", output, env={**os.environ, "PATH": str(tools)})

    assert result.returncode == 0, result.stderr
    assert output.stat().st_size > 1024 * 1024
    rows = output.read_bytes().splitlines()
    assert len(rows) == 12_000
    assert rows == sorted(rows)


def test_diff_inventory_keeps_changed_and_deleted_source_files(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "base")
    base = git(repository, "rev-parse", "HEAD")

    write_file(repository, "app/routes.py", b"changed = True\n")
    write_file(repository, "app/new handler.py", b"handler = True\n")
    write_file(repository, "app/binary.py", b"\x00\xff\x01")
    write_file(repository, "tests/demo.py", b"excluded = True\n")
    (repository / "app/évidence.py").unlink()
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "change")
    head = git(repository, "rev-parse", "HEAD")
    output = tmp_path / "in_scope_files.txt"

    result = run_inventory(
        repository,
        ".",
        output,
        arguments=["--diff-base", base, "--diff-head", head],
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == [
        "app/new handler.py",
        "app/routes.py",
        "app/évidence.py",
    ]


def test_diff_inventory_combines_staged_and_unstaged_changes(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "base")

    write_file(repository, "app/routes.py", b"unstaged = True\n")
    write_file(repository, "app/staged.py", b"staged = True\n")
    git(repository, "add", "app/staged.py")
    write_file(repository, "app/untracked.py", b"untracked = True\n")
    write_file(repository, "app/untracked-binary.py", b"\x00\xff\x01")
    index_only = write_file(repository, "app/index-only.py", b"index_only = True\n")
    git(repository, "add", "app/index-only.py")
    index_only.unlink()
    output = tmp_path / "in_scope_files.txt"

    result = run_inventory(
        repository,
        ".",
        output,
        arguments=["--diff-base", "HEAD", "--diff-mode", "local-patch"],
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == [
        "app/routes.py",
        "app/staged.py",
        "app/untracked.py",
    ]


def test_revision_inventory_checks_the_selected_revision_not_the_worktree(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "base")
    base = git(repository, "rev-parse", "HEAD")

    write_file(repository, "app/routes.py", b"selected = True\n")
    write_file(repository, "app/name with spaces.py", b"\x00\xff\x01")
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "selected revision")
    selected = git(repository, "rev-parse", "HEAD")

    write_file(repository, "app/routes.py", b"\x00\xff\x01")
    write_file(repository, "app/name with spaces.py", b"current = True\n")
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "current revision")
    output = tmp_path / "in_scope_files.txt"

    result = run_inventory(
        repository,
        ".",
        output,
        arguments=["--diff-base", base, "--diff-head", selected],
    )

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == ["app/routes.py"]


def test_invalid_diff_revision_preserves_previous_inventory(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    output = tmp_path / "in_scope_files.txt"
    output.write_text("previous.py\n", encoding="utf-8")

    result = run_inventory(repository, ".", output, arguments=["--diff-base", "missing"])

    assert result.returncode == 2
    assert "could not resolve the selected Git changes" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous.py\n"


def test_diff_inventory_rejects_a_narrower_scope(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    output = tmp_path / "in_scope_files.txt"
    output.write_text("previous.py\n", encoding="utf-8")

    result = run_inventory(repository, "app", output, arguments=["--diff-base", "HEAD"])

    assert result.returncode == 2
    assert "diff scans must use the repository root" in result.stderr
    assert output.read_text(encoding="utf-8") == "previous.py\n"
