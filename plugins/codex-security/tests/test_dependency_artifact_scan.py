from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
RANK_SCRIPT = PLUGIN_ROOT / "scripts" / "generate_rank_input.py"
INVENTORY_SCRIPT = PLUGIN_ROOT / "scripts" / "generate_in_scope_files.py"
ARTIFACT_ENVIRONMENT = "CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN"


def write_file(repository: Path, name: str, contents: bytes) -> None:
    path = repository / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)


def run_helper(script: Path, *args: str, artifact: bool) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    if artifact:
        environment[ARTIFACT_ENVIRONMENT] = "1"
    else:
        environment.pop(ARTIFACT_ENVIRONMENT, None)
    return subprocess.run(
        [sys.executable, str(script), *args],
        env=environment,
        capture_output=True,
        check=True,
        text=True,
    )


def rank_paths(output: Path) -> set[str]:
    return {json.loads(line)["path"] for line in output.read_text(encoding="utf-8").splitlines()}


def distributed_files(repository: Path) -> set[str]:
    text_files = {
        "src/runtime.py": b"print('runtime')\n",
        "dist/runtime.min.js": b"function run(){send(process.env.TOKEN)}\n",
        "dist/runtime.js.map": b'{"version":3,"sources":["payload.ts"]}\n',
        "generated/payload.py": b"send(os.environ['TOKEN'])\n",
        "build/install.cjs": b"require('./payload')\n",
        "vendor/loader.py": b"import payload\n",
        "third_party/helper.js": b"module.exports = run\n",
        "tests/install.py": b"install()\n",
        "package.json": b'{"scripts":{"postinstall":"node install.cjs"}}\n',
        "package-lock.json": b'{"packages":{}}\n',
        "pnpm-lock.yaml": b"lockfileVersion: '9.0'\n",
        "yarn.lock": b"__metadata:\n  version: 8\n",
        "python-startup.pth": b"import payload\n",
        "package.dist-info/entry_points.txt": b"[console_scripts]\nrun=payload:run\n",
        "Dockerfile": b"RUN python -m payload\n",
        "entrypoint": b"#!/bin/sh\nnode payload.js\n",
    }
    for name, contents in text_files.items():
        write_file(repository, name, contents)
    write_file(repository, "dist/native.so", b"\x7fELF\x00native")
    write_file(repository, "vendor/binary.py", b"python\x00binary")
    write_file(repository, "dist/native", b"\x7fELF\x00native")
    return set(text_files)


def test_artifact_repo_ranking_includes_distributed_sources_without_binaries(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "package"
    repository.mkdir()
    expected_paths = distributed_files(repository)
    write_file(repository, ".git/config", b"[core]\nrepositoryformatversion = 0\n")
    write_file(repository, "vendor/.git/config", b"[remote]\nurl = secret\n")
    artifact_output = tmp_path / "artifact-rank.jsonl"
    standard_output = tmp_path / "standard-rank.jsonl"

    for output, artifact in ((artifact_output, True), (standard_output, False)):
        run_helper(
            RANK_SCRIPT,
            "make-repo-rank-input",
            "--repo",
            str(repository),
            "--scope",
            ".",
            "--out",
            str(output),
            artifact=artifact,
        )

    artifact_paths = rank_paths(artifact_output)
    standard_paths = rank_paths(standard_output)

    assert expected_paths <= artifact_paths
    assert artifact_paths.isdisjoint({"dist/native.so", "dist/native", "vendor/binary.py"})
    assert all(".git" not in Path(path).parts for path in artifact_paths)
    assert standard_paths == {"package.json", "src/runtime.py"}


def test_artifact_diff_ranking_includes_package_metadata_and_distributed_sources(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "package"
    repository.mkdir()
    git = ["git", "-C", str(repository)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "config", "user.name", "Codex Security Tests"], check=True)
    subprocess.run([*git, "config", "user.email", "codex-security-tests@example.com"], check=True)
    subprocess.run([*git, "commit", "--allow-empty", "-qm", "baseline"], check=True)
    expected_paths = distributed_files(repository)
    subprocess.run([*git, "add", "--all"], check=True)
    subprocess.run([*git, "commit", "-qm", "publish dependency"], check=True)
    artifact_output = tmp_path / "artifact-diff-rank.jsonl"
    standard_output = tmp_path / "standard-diff-rank.jsonl"

    for output, artifact in ((artifact_output, True), (standard_output, False)):
        run_helper(
            RANK_SCRIPT,
            "make-diff-rank-input",
            "--repo",
            str(repository),
            "--base",
            "HEAD~1",
            "--head",
            "HEAD",
            "--out",
            str(output),
            artifact=artifact,
        )

    artifact_paths = rank_paths(artifact_output)
    standard_paths = rank_paths(standard_output)

    assert expected_paths <= artifact_paths
    assert artifact_paths.isdisjoint({"dist/native.so", "dist/native", "vendor/binary.py"})
    assert standard_paths == {"package.json", "src/runtime.py"}


def test_artifact_inventory_ignores_package_ignore_rules_but_not_git_or_binaries(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "package"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    expected_paths = distributed_files(repository)
    write_file(
        repository,
        ".gitignore",
        b"dist/\ngenerated/\nbuild/\nvendor/\nthird_party/\n*.pth\nentrypoint\n",
    )
    artifact_output = tmp_path / "artifact-inventory.txt"
    standard_output = tmp_path / "standard-inventory.txt"

    for output, artifact in ((artifact_output, True), (standard_output, False)):
        run_helper(
            INVENTORY_SCRIPT,
            "--repo",
            str(repository),
            "--scope",
            ".",
            "--out",
            str(output),
            artifact=artifact,
        )

    artifact_paths = {
        path.removeprefix("./") for path in artifact_output.read_text(encoding="utf-8").splitlines()
    }
    standard_paths = {
        path.removeprefix("./") for path in standard_output.read_text(encoding="utf-8").splitlines()
    }

    assert expected_paths <= artifact_paths
    assert artifact_paths.isdisjoint({"dist/native.so", "dist/native", "vendor/binary.py"})
    assert all(".git" not in Path(path).parts for path in artifact_paths)
    assert "dist/runtime.min.js" not in standard_paths
    assert "generated/payload.py" not in standard_paths
    assert "python-startup.pth" not in standard_paths
    assert "entrypoint" not in standard_paths
