"""Target inspection and content-integrity helpers for the security workbench."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_constants import GIT_REPOSITORY_ENVIRONMENT


def git_output(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str | None:
    completed = git_command(target, *args, text=True, git_dir=git_dir, work_tree=work_tree)
    output = completed.stdout.strip()
    return output if completed.returncode == 0 and output else None


def git_bytes(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> bytes | None:
    completed = git_command(target, *args, text=False, git_dir=git_dir, work_tree=work_tree)
    return completed.stdout if completed.returncode == 0 else None


def git_command(
    target: Path,
    *args: str,
    text: bool,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    if (git_dir is None) != (work_tree is None):
        raise ValueError("git_dir and work_tree must be provided together")
    environment = os.environ.copy()
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    # Repository-local config is untrusted; fsmonitor may name an executable hook.
    command = ["git", "-c", "core.fsmonitor=false", "-C", str(target)]
    if git_dir is not None and work_tree is not None:
        command.extend(["--git-dir", str(git_dir), "--work-tree", str(work_tree)])
    full_command = [*command, *args]
    try:
        return subprocess.run(
            full_command,
            check=False,
            capture_output=True,
            env=environment,
            text=text,
        )
    except FileNotFoundError:
        # Git is optional for Codebase scans. Treat an unavailable executable like
        # any other failed Git probe so the target falls back to a directory snapshot.
        empty_output = "" if text else b""
        return subprocess.CompletedProcess(full_command, 127, empty_output, empty_output)


def update_digest_field(digest: Any, label: bytes, value: bytes) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def worktree_content_digest(target: Path) -> str:
    require_clean_submodule_worktrees(target)
    repository, pathspec = git_worktree_context(target)
    return worktree_content_digest_for_context(repository, pathspec)


def worktree_content_digest_for_context(
    repository: Path,
    pathspec: str,
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str:
    tracked = git_bytes(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "HEAD",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    untracked = git_bytes(
        repository,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    if tracked is None or untracked is None:
        raise SystemExit("Could not snapshot the selected working-tree changes.")
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", tracked)
    for raw_path in sorted(path for path in untracked.split(b"\0") if path):
        relative_path = os.fsdecode(raw_path)
        path = (work_tree or repository) / relative_path
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
        update_digest_field(digest, b"untracked-path", raw_path)
        update_digest_field(
            digest,
            b"untracked-mode",
            str(stat.S_IMODE(metadata.st_mode)).encode(),
        )
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"untracked-kind", b"symlink")
            update_digest_field(
                digest,
                b"untracked-content",
                os.fsencode(os.readlink(path)),
            )
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
            update_digest_field(digest, b"untracked-kind", b"file")
            update_digest_field(
                digest,
                b"untracked-size",
                str(content_size).encode(),
            )
            update_digest_field(
                digest,
                b"untracked-content-sha256",
                content_digest.digest(),
            )
        else:
            raise SystemExit(f"Unsupported untracked file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_worktree_context(target: Path) -> tuple[Path, str]:
    root = git_output(target, "rev-parse", "--show-toplevel")
    if root is None:
        raise SystemExit("Could not inspect the selected Git working tree.")
    repository = Path(root).resolve()
    try:
        relative = target.resolve().relative_to(repository)
    except ValueError as exc:
        raise SystemExit("Scan target must stay inside its Git working tree.") from exc
    return repository, relative.as_posix() or "."


def git_submodule_entries(target: Path) -> tuple[tuple[Path, str], ...]:
    repository, pathspec = git_worktree_context(target)
    staged = git_bytes(repository, "ls-files", "--stage", "-z", "--", pathspec)
    if staged is None:
        raise SystemExit("Could not inspect Git submodules in the selected working tree.")
    entries = []
    for record in (item for item in staged.split(b"\0") if item):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, _ = metadata.split(b" ", 2)
        except ValueError as exc:
            raise SystemExit(
                "Could not inspect Git submodules in the selected working tree."
            ) from exc
        if mode != b"160000":
            continue
        entries.append((repository / os.fsdecode(raw_path), object_id.decode("ascii")))
    return tuple(entries)


def git_submodule_paths(target: Path) -> tuple[Path, ...]:
    return tuple(path for path, _ in git_submodule_entries(target))


def require_clean_submodule_worktrees(target: Path) -> None:
    for submodule, expected_revision in git_submodule_entries(target):
        relative_path = str(submodule.relative_to(target))
        if not submodule.exists():
            continue
        try:
            (submodule / ".git").lstat()
        except FileNotFoundError:
            continue
        root = git_output(submodule, "rev-parse", "--show-toplevel")
        try:
            is_initialized = root is not None and Path(root).resolve() == submodule.resolve()
        except OSError:
            is_initialized = False
        if not is_initialized:
            raise SystemExit(
                f"Could not inspect initialized Git submodule contents: {relative_path}"
            )
        if git_output(submodule, "rev-parse", "HEAD") != expected_revision:
            raise SystemExit(
                "Initialized Git submodules must be checked out at the revision recorded "
                f"by the parent repository: {relative_path}"
            )
        status = git_bytes(
            submodule,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        if status is None:
            raise SystemExit(f"Could not inspect Git submodule contents: {relative_path}")
        if status:
            raise SystemExit(
                f"Dirty Git submodules are not supported for remediation integrity checks: {relative_path}"
            )
        require_clean_submodule_worktrees(submodule)


def clean_worktree_content_digest() -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", b"")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_directory_snapshot_paths(target: Path) -> list[Path] | None:
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None:
        return None
    repository, pathspec = git_worktree_context(target)
    listed = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    paths: list[Path] = []
    for raw_path in (raw_path for raw_path in listed.split(b"\0") if raw_path):
        path = repository / os.fsdecode(raw_path)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            # The index can retain a path that was staged and then deleted.
            continue
        paths.append(path)
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        nested_repository_root = git_output(path, "rev-parse", "--show-toplevel")
        if (
            nested_repository_root is not None
            and Path(nested_repository_root).resolve() == path.resolve()
        ):
            nested_paths = git_directory_snapshot_paths(path)
            if nested_paths is not None:
                paths.extend(nested_paths)
                continue
        paths.extend(
            nested_path
            for nested_path in path.rglob("*")
            if ".git" not in nested_path.relative_to(path).parts
        )
    return sorted(set(paths))


def directory_content_digest(target: Path, *, excluded: tuple[Path, ...] = ()) -> str:
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(target))
        except ValueError:
            continue
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = sorted(target.rglob("*"))
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-directory/v1")
    for path in paths:
        relative_path = path.relative_to(target)
        if any(
            relative_path == excluded_path or excluded_path in relative_path.parents
            for excluded_path in excluded_relative
        ):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read local file: {relative_path}") from exc
        raw_path = os.fsencode(relative_path.as_posix())
        update_digest_field(digest, b"path", raw_path)
        update_digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode())
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"kind", b"symlink")
            update_digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read local file: {relative_path}") from exc
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(content_size).encode())
            update_digest_field(digest, b"content-sha256", content_digest.digest())
        else:
            raise SystemExit(f"Unsupported local file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def copy_directory_excluding(source: Path, destination: Path, excluded: tuple[Path, ...]) -> None:
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(source))
        except ValueError:
            continue

    def ignored(directory: str, names: list[str]) -> list[str]:
        relative = Path(directory).relative_to(source)
        return [
            path.name
            for path in excluded_relative
            if path.parent == relative and path.name in names
        ]

    shutil.copytree(source, destination, symlinks=True, ignore=ignored)


def copy_git_worktree_files(source: Path, destination: Path, excluded: tuple[Path, ...]) -> Path:
    repository, pathspec = git_worktree_context(source)
    listed = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.relative_to(repository))
        except ValueError:
            continue
    destination.mkdir()
    for raw_path in sorted(path for path in listed.split(b"\0") if path):
        relative = Path(os.fsdecode(raw_path))
        if any(
            relative == excluded_path or excluded_path in relative.parents
            for excluded_path in excluded_relative
        ):
            continue
        source_path = repository / relative
        try:
            metadata = source_path.lstat()
        except FileNotFoundError:
            continue
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(metadata.st_mode):
            destination_path.symlink_to(os.readlink(source_path))
        elif stat.S_ISREG(metadata.st_mode):
            shutil.copy2(source_path, destination_path, follow_symlinks=False)
        elif not stat.S_ISDIR(metadata.st_mode):
            raise SystemExit(f"Unsupported Git working-tree file type: {relative}")
    copied_target = destination if pathspec == "." else destination / pathspec
    copied_target.mkdir(parents=True, exist_ok=True)
    return copied_target


def git_revision(target: Path) -> str:
    return git_output(target, "rev-parse", "HEAD") or "unversioned"


def git_target_metadata(target: Path) -> dict[str, Any]:
    is_git = git_output(target, "rev-parse", "--git-dir") is not None
    is_worktree = git_output(target, "rev-parse", "--is-inside-work-tree") == "true"
    revision = git_output(target, "rev-parse", "--verify", "HEAD")
    repository_root = git_output(target, "rev-parse", "--show-toplevel") if is_worktree else None
    supported = (
        is_git
        and is_worktree
        and revision is not None
        and repository_root is not None
        and Path(repository_root).resolve() == target
    )
    metadata: dict[str, Any] = {
        "hasHead": revision is not None,
        "isGit": is_git,
        "isWorktree": is_worktree,
        "reviewChangesSupported": supported,
    }
    if not is_git:
        return metadata
    branch = git_output(target, "symbolic-ref", "--quiet", "--short", "HEAD")
    metadata.update({"branch": branch, "detachedHead": revision is not None and branch is None})
    if revision is not None:
        metadata.update(
            {
                "commitSubject": git_output(target, "show", "-s", "--format=%s", "HEAD"),
                "revision": revision,
                "shortRevision": revision[:7],
            }
        )
    return metadata


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
