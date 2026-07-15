from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias

from .errors import InvalidTargetError

PathInput: TypeAlias = str | os.PathLike[str]
ScanMode: TypeAlias = Literal["standard", "deep"]


@dataclass(frozen=True, slots=True)
class DiffTarget:
    """A committed-ref or working-tree Git diff target."""

    kind: Literal["refs", "working_tree"]
    base: str
    head: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("refs", "working_tree"):
            raise InvalidTargetError(f"Unsupported diff target kind: {self.kind}")
        if not isinstance(self.base, str) or not self.base:
            raise InvalidTargetError("The diff base ref must be non-empty.")
        if self.kind == "refs" and (not isinstance(self.head, str) or not self.head):
            raise InvalidTargetError("Git diff refs must include a non-empty head ref.")
        if self.kind == "working_tree" and self.head is not None:
            raise InvalidTargetError("Working-tree targets cannot specify a head ref.")

    @classmethod
    def refs(cls, *, base: str, head: str = "HEAD") -> DiffTarget:
        if not base or not head:
            raise InvalidTargetError("Git diff refs must be non-empty.")
        return cls(kind="refs", base=base, head=head)

    @classmethod
    def working_tree(
        cls,
        *,
        base: str = "HEAD",
    ) -> DiffTarget:
        if not base:
            raise InvalidTargetError("The working-tree base ref must be non-empty.")
        return cls(kind="working_tree", base=base)


ScanTarget: TypeAlias = Literal["repository"] | DiffTarget | Sequence[PathInput]


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    kind: Literal["repository", "paths", "refs", "working_tree"]
    paths: tuple[str, ...] = ()
    base: str | None = None
    head: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None


def normalize_repository(repository: PathInput) -> Path:
    path = Path(repository).expanduser().resolve()
    if not path.is_dir():
        raise InvalidTargetError(f"Repository is not a directory: {path}")
    return path


def normalize_target(repository: Path, target: ScanTarget) -> NormalizedTarget:
    repository = normalize_repository(repository)
    if target == "repository":
        return NormalizedTarget(kind="repository")

    if isinstance(target, DiffTarget):
        _require_git_repository(repository)
        base = _resolve_git_ref(repository, target.base)
        if target.kind == "refs":
            if target.head is None:  # Defensive for dynamically typed callers.
                raise InvalidTargetError("Git diff refs must include a non-empty head ref.")
            head = _resolve_git_ref(repository, target.head)
            return NormalizedTarget(
                kind="refs",
                base=base,
                head=head,
                base_ref=target.base,
                head_ref=target.head,
            )
        if target.kind == "working_tree":
            head = _resolve_git_ref(repository, "HEAD")
            return NormalizedTarget(
                kind="working_tree",
                base=base,
                head=head,
                base_ref=target.base,
                head_ref="HEAD",
            )
        raise InvalidTargetError(f"Unsupported diff target kind: {target.kind}")

    if isinstance(target, str) or not isinstance(target, Sequence):
        raise InvalidTargetError(
            "Scan target must be 'repository', a DiffTarget, or a sequence of paths."
        )
    if not target:
        raise InvalidTargetError("A path scan target must contain at least one path.")

    paths: list[str] = []
    for value in target:
        if not isinstance(value, (str, os.PathLike)):
            raise InvalidTargetError(
                "Path scan targets must contain only strings or path-like values."
            )
        if os.fspath(value) == "":
            raise InvalidTargetError("Path scan targets must not contain an empty path.")
        path = Path(value).expanduser()
        absolute = path.resolve() if path.is_absolute() else (repository / path).resolve()
        try:
            relative = absolute.relative_to(repository)
        except ValueError as exc:
            raise InvalidTargetError(f"Path target is outside the repository: {value}") from exc
        if not absolute.exists():
            raise InvalidTargetError(f"Path target does not exist: {value}")
        normalized = relative.as_posix()
        if normalized not in paths:
            paths.append(normalized)
    return NormalizedTarget(kind="paths", paths=tuple(paths))


def _require_git_repository(repository: Path) -> None:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise InvalidTargetError(f"Diff targets require a Git repository: {repository}")
    root = Path(result.stdout.strip()).resolve()
    if root != repository:
        raise InvalidTargetError(f"Diff target repository must be the Git worktree root: {root}")


def _resolve_git_ref(repository: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise InvalidTargetError(f"unknown Git ref: {ref}")
    return result.stdout.strip()


def repository_revision(repository: Path) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None
