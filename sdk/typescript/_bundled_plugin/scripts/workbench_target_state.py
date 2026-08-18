"""Persist stable Codex Security target identities."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import platform
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import (
    serialize_filesystem_identity,
    stored_filesystem_identity_matches,
)
from workbench_target import git_bytes, git_output


def stable_target_id(target: Path) -> str:
    digest = hashlib.sha256(f"local-workspace\0{target}".encode()).hexdigest()
    return f"target_sha256_{digest}"


def repository_relative_path(target: Path) -> str | None:
    """Return the target's normalized location within its own Git worktree."""
    worktree = _repository_worktree(target)
    return worktree[1] if worktree is not None else None


def _repository_worktree(target: Path) -> tuple[Path, str] | None:
    worktree_root = _git_path(target, "rev-parse", "--show-toplevel")
    if worktree_root is None:
        return None
    try:
        canonical_root = Path(os.path.realpath(worktree_root))
        relative = Path(os.path.realpath(target)).relative_to(canonical_root)
    except (OSError, ValueError):
        return None
    return canonical_root, relative.as_posix()


def _path_from_git_bytes(
    value: bytes, relative_to: Path, *, strip_line_feed: bool = True
) -> Path | None:
    if strip_line_feed and value.endswith(b"\n"):
        value = value[:-1]
    if not value or b"\0" in value:
        return None
    path = Path(os.fsdecode(value))
    return Path(os.path.realpath(path if path.is_absolute() else relative_to / path))


def _git_path(target: Path, *args: str) -> Path | None:
    value = git_bytes(target, *args)
    return _path_from_git_bytes(value, target) if value is not None else None


def _registered_worktree(target: Path, root: Path, common: Path) -> bool:
    registered = git_bytes(target, "worktree", "list", "--porcelain", "-z")
    if registered is not None:
        return any(
            os.path.realpath(os.fsdecode(record[len(b"worktree "):])) == str(root)
            for record in registered.split(b"\0")
            if record.startswith(b"worktree ")
        )
    # Git before 2.36 emits unquoted newline-delimited paths. Repository-side
    # ownership records are unambiguous even when a checkout path has newlines.
    gitdir = _git_path(target, "rev-parse", "--absolute-git-dir")
    dotgit = root / ".git"
    try:
        mode = dotgit.lstat().st_mode
        if stat.S_ISDIR(mode):
            return gitdir == common == Path(os.path.realpath(dotgit))
        if not stat.S_ISREG(mode) or gitdir is None or not gitdir.is_dir():
            return False
        forward = dotgit.read_bytes()
        if (
            not forward.startswith(b"gitdir: ")
            or _path_from_git_bytes(forward[len(b"gitdir: "):], root) != gitdir
        ):
            return False
        if gitdir == common:
            configured = git_bytes(
                target, "config", "--null", "--show-scope", "--no-includes",
                "--get", "core.worktree",
            )
            fields = configured.split(b"\0") if configured is not None else []
            if (
                len(fields) != 3 or fields[0] not in (b"local", b"worktree")
                or not fields[1] or fields[2]
            ):
                return False
            configured_root = _path_from_git_bytes(
                fields[1], gitdir, strip_line_feed=False
            )
            return configured_root is not None and str(configured_root) == str(root)
        return (
            gitdir.parent == common / "worktrees"
            and _path_from_git_bytes((gitdir / "gitdir").read_bytes(), gitdir)
            == Path(os.path.realpath(dotgit))
        )
    except (OSError, ValueError):
        return False


class _LinuxStatxTimestamp(ctypes.Structure):
    _fields_ = (
        ("seconds", ctypes.c_int64),
        ("nanoseconds", ctypes.c_uint32),
        ("_reserved", ctypes.c_int32),
    )


class _LinuxStatx(ctypes.Structure):
    # Linux's statx UAPI keeps birth time at offset 0x50 in a 0x100-byte buffer.
    _fields_ = (
        ("mask", ctypes.c_uint32),
        ("_before_birth_time", ctypes.c_ubyte * 76),
        ("birth_time", _LinuxStatxTimestamp),
        ("_after_birth_time", ctypes.c_ubyte * 160),
    )


def _linux_repository_birth_time_ns(path: str) -> int | None:
    if ctypes.sizeof(_LinuxStatx) != 256 or _LinuxStatx.birth_time.offset != 80:
        return None
    metadata = _LinuxStatx()
    birth_time_mask = 0x800
    arguments = (-100, os.fsencode(path), 0, birth_time_mask, ctypes.byref(metadata))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            statx = libc.statx
        except AttributeError:
            # Older musl has the syscall but no statx wrapper. Only use known LP64 ABIs.
            if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8:
                return None
            number = {"x86_64": 332, "aarch64": 291}.get(platform.machine())
            if number is None:
                return None
            statx = libc.syscall
            statx.argtypes = (
                ctypes.c_long, ctypes.c_long, ctypes.c_char_p, ctypes.c_long,
                ctypes.c_ulong, ctypes.POINTER(_LinuxStatx),
            )
            statx.restype = ctypes.c_long
            status = statx(number, *arguments)
        else:
            statx.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint,
                ctypes.POINTER(_LinuxStatx),
            )
            statx.restype = ctypes.c_int
            status = statx(*arguments)
    except (AttributeError, OSError):
        return None
    birth_time = metadata.birth_time
    if (
        status != 0 or not metadata.mask & birth_time_mask
        or not 0 <= birth_time.nanoseconds < 1_000_000_000
    ):
        return None
    birth_time_ns = birth_time.seconds * 1_000_000_000 + birth_time.nanoseconds
    return birth_time_ns if birth_time_ns > 0 else None


def _repository_birth_time_ns(path: str, metadata: os.stat_result) -> int | None:
    birth_time_ns = getattr(metadata, "st_birthtime_ns", None)
    if birth_time_ns is not None:
        return birth_time_ns if birth_time_ns > 0 else None
    if os.name == "nt":
        return metadata.st_ctime_ns if metadata.st_ctime_ns > 0 else None
    birth_time = getattr(metadata, "st_birthtime", None)
    if birth_time is not None:
        return int(birth_time * 1_000_000_000) if birth_time > 0 else None
    if not sys.platform.startswith("linux"):
        return None
    birth_time_ns = _linux_repository_birth_time_ns(path)
    if birth_time_ns is not None:
        return birth_time_ns
    try:
        result = subprocess.run(
            ["stat", "--format=%.9W", "--", path],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
    except OSError:
        return None
    seconds, separator, nanoseconds = result.stdout.strip().partition(".")
    if (
        result.returncode != 0
        or separator != "."
        or not seconds.isdecimal()
        or len(nanoseconds) != 9
        or not nanoseconds.isdecimal()
    ):
        return None
    birth_time_ns = int(seconds) * 1_000_000_000 + int(nanoseconds)
    return birth_time_ns if birth_time_ns > 0 else None


@dataclass(frozen=True)
class GitRepositoryIdentity:
    value: str
    relative_path: str
    common_directory: str
    device: int | str
    inode: int | str
    birth_time_ns: int

    @property
    def legacy_value(self) -> str:
        return _identity_digest(
            f"git-common-dir\0{self.common_directory}\0{self.device}\0{self.inode}\0"
            f"{self.birth_time_ns}\0{self.relative_path}"
        )


def _identity_digest(material: str) -> str:
    return f"repository_sha256_{hashlib.sha256(material.encode(errors='surrogateescape')).hexdigest()}"


def _repository_identity_details(target: Path | str) -> GitRepositoryIdentity | None:
    target = Path(target)
    common_directory = _git_path(
        target, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    if common_directory is None:
        return None
    worktree = _repository_worktree(target)
    if worktree is None:
        return None
    worktree_root, relative = worktree
    if not _registered_worktree(target, worktree_root, common_directory):
        return None
    object_directory = _git_path(
        target, "rev-parse", "--path-format=absolute", "--git-path", "objects"
    )
    if object_directory is None:
        return None
    canonical_directory = str(common_directory)
    try:
        metadata = common_directory.stat()
        object_metadata = object_directory.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(metadata.st_mode) or not stat.S_ISDIR(object_metadata.st_mode):
        return None
    birth_time_ns = _repository_birth_time_ns(canonical_directory, metadata)
    object_birth_time_ns = _repository_birth_time_ns(str(object_directory), object_metadata)
    if birth_time_ns is None or object_birth_time_ns is None:
        return None
    device = serialize_filesystem_identity(metadata.st_dev)
    inode = serialize_filesystem_identity(metadata.st_ino)
    material = (
        f"git-generation-v2\0{canonical_directory}\0{device}\0{inode}\0"
        f"{birth_time_ns}\0{object_directory}\0"
        f"{serialize_filesystem_identity(object_metadata.st_dev)}\0"
        f"{serialize_filesystem_identity(object_metadata.st_ino)}\0"
        f"{object_birth_time_ns}\0{relative}"
    )
    return GitRepositoryIdentity(
        _identity_digest(material), relative, canonical_directory, device, inode, birth_time_ns
    )


def repository_identity(target: Path | str) -> str | None:
    """Identify matching Git worktree targets without storing remote credentials."""
    identity = _repository_identity_details(target)
    return identity.value if identity is not None else None


def repository_origin(target: Path) -> tuple[str, str] | None:
    remote = git_output(target, "remote", "get-url", "origin")
    if remote is None:
        return None
    if "://" in remote:
        try:
            parsed = urlsplit(remote)
            port = parsed.port
        except ValueError:
            return None
        if parsed.scheme not in {"https", "ssh"} or parsed.hostname is None:
            return None
        if parsed.query or parsed.fragment:
            return None
        host = parsed.hostname
        if port is not None and port != {"https": 443, "ssh": 22}[parsed.scheme]:
            host = f"{host}:{port}"
        path = parsed.path
    else:
        authority, separator, path = remote.partition(":")
        if not separator or "?" in path or "#" in path:
            return None
        host = authority.rsplit("@", 1)[-1]
    path = path.strip("/").removesuffix(".git")
    return (host.lower(), path) if host and path else None


def supports_repository_identity(connection: sqlite3.Connection) -> bool:
    return any(
        row["name"] == "repository_identity"
        for row in connection.execute("PRAGMA table_info(security_targets)")
    )


@dataclass(frozen=True)
class RepositoryTargetState:
    target_id: str
    target_path: str
    stored_identity: str | None
    resolved_path: str | None = None
    metadata: os.stat_result | None = None
    repository: GitRepositoryIdentity | None = None
    ownership_matches: bool = False
    strict_owner_matches: bool = False
    generation_predates_history: bool = False
    has_historical_scans: bool = False
    missing: bool = False

    @property
    def live_identity(self) -> str | None:
        return self.repository.value if self.repository is not None else None

    @property
    def verified_identity(self) -> str | None:
        if not self.ownership_matches or self.repository is None:
            return None
        if self.stored_identity is None:
            # Checkout ownership and repository age cannot identify an older Git generation.
            return (
                self.live_identity
                if self.strict_owner_matches
                and self.generation_predates_history
                and not self.has_historical_scans
                else None
            )
        return self.live_identity if self.live_identity == self.stored_identity else None

    def require_owner(self) -> None:
        if not self.ownership_matches:
            raise SystemExit(
                f"The repository checkout at {self.target_path} no longer matches its recorded "
                "security scan history; refusing to reuse its target."
            )


def _inspect_repository_target(
    connection: sqlite3.Connection,
    target_id: str,
    target_path: str,
    stored_identity: str | None,
    *,
    scan_columns: set[str] | None = None,
) -> RepositoryTargetState:
    target = Path(target_path)
    try:
        resolved_path = str(target.resolve())
    except (OSError, RuntimeError):
        return RepositoryTargetState(target_id, target_path, stored_identity)
    try:
        metadata = target.stat()
    except (FileNotFoundError, NotADirectoryError):
        return RepositoryTargetState(
            target_id, target_path, stored_identity,
            resolved_path=resolved_path, ownership_matches=True, missing=True,
        )
    except OSError:
        return RepositoryTargetState(
            target_id, target_path, stored_identity, resolved_path=resolved_path
        )
    repository = _repository_identity_details(target)
    if scan_columns is None:
        scan_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)")
        }
    historical_scan = False
    recorded_owner = False
    malformed_owner = False
    mismatch = False
    strict_owner_matches = False
    generation_predates_history = False
    ownership_matches = True
    if {"target_id", "target_path"} <= scan_columns:
        recorded_generations = {
            row[0] for row in connection.execute(
                "SELECT DISTINCT repository_generation FROM scans "
                "WHERE (target_id = ? OR target_path = ?) AND repository_generation IS NOT NULL",
                (target_id, target_path),
            )
        } if "repository_generation" in scan_columns else set()
        generation_conflict = bool(recorded_generations) and (
            repository is None or recorded_generations != {repository.value}
        )
        if not {"target_device", "target_inode"} <= scan_columns:
            historical_scan = connection.execute(
                "SELECT 1 FROM scans WHERE target_id = ? OR target_path = ? LIMIT 1",
                (target_id, target_path),
            ).fetchone() is not None
            strict_owner_matches = not historical_scan
            generation_predates_history = repository is not None and not historical_scan
        else:
            strict_owner_matches = True
            timestamps = ", started_at, created_at" if {
                "started_at", "created_at"
            } <= scan_columns else ""
            scans = connection.execute(
                f"""
                SELECT target_device, target_inode{timestamps} FROM scans
                WHERE target_id = ? OR target_path = ?
                """,
                (target_id, target_path),
            ).fetchall()
            generation_predates_history = (
                repository is not None and _repository_predates_history(repository, scans)
            )
            for scan in scans:
                historical_scan = True
                device, inode = scan["target_device"], scan["target_inode"]
                if device is None and inode is None:
                    strict_owner_matches = False
                    continue
                if device is None or inode is None:
                    malformed_owner = True
                    strict_owner_matches = False
                    continue
                recorded_owner = True
                if not stored_filesystem_identity_matches(
                    device, metadata.st_dev
                ) or not stored_filesystem_identity_matches(inode, metadata.st_ino):
                    mismatch = True
                    strict_owner_matches = False
            stored_matches = (
                repository is not None
                and stored_identity in {repository.value, repository.legacy_value}
            )
            verified_repository = (
                repository is not None
                and (stored_matches or recorded_generations == {repository.value})
            )
            ownership_matches = not (
                malformed_owner
                or mismatch
                and (
                    not verified_repository
                    or repository is None
                    or repository.relative_path == "."
                )
                or stored_identity is not None
                and (
                    not stored_matches or historical_scan and not recorded_owner
                )
                or stored_identity is None
                and repository is not None
                and historical_scan
                and not generation_predates_history
            )
        ownership_matches = ownership_matches and not generation_conflict
    return RepositoryTargetState(
        target_id, target_path, stored_identity, resolved_path, metadata, repository,
        ownership_matches, strict_owner_matches, generation_predates_history, historical_scan,
    )


def verified_repository_identity(
    connection: sqlite3.Connection,
    target_id: str,
    target_path: str,
    *,
    stored_identity: str | None = None,
) -> str | None:
    return _inspect_repository_target(
        connection, target_id, target_path, stored_identity
    ).verified_identity


def scan_repository_generation(scan: sqlite3.Row | dict) -> str | None:
    return scan["repository_generation"] if "repository_generation" in scan.keys() else None


def scan_repository_group(scan: sqlite3.Row | dict) -> tuple[str, str]:
    generation = scan_repository_generation(scan)
    return (
        ("repository", generation) if generation is not None else ("target", scan["target_id"])
    )


@dataclass(frozen=True)
class RepositoryScanScope:
    """A verified generation and, separately, its exact target's legacy scans."""

    generation: str | None = None
    target_id: str | None = None
    exact_target: bool = False
    available: bool = True

    def sql(
        self, alias: str = "scans", *, supports_generation: bool = True
    ) -> tuple[str, tuple[str, ...]]:
        if not self.available:
            return "0", ()
        if self.exact_target:
            return (f"{alias}.target_id = ?", (self.target_id,)) if self.target_id else ("0", ())
        clauses, values = [], []
        if self.generation is not None and supports_generation:
            clauses.append(f"{alias}.repository_generation = ?")
            values.append(self.generation)
        if self.target_id:
            legacy = f"{alias}.repository_generation IS NULL AND " if supports_generation else ""
            clauses.append(f"({legacy}{alias}.target_id = ?)")
            values.append(self.target_id)
        return (f"({' OR '.join(clauses)})", tuple(values)) if clauses else ("0", ())

    def contains(self, scan: sqlite3.Row | dict) -> bool:
        if not self.available:
            return False
        if self.exact_target:
            return bool(self.target_id) and scan["target_id"] == self.target_id
        generation = scan_repository_generation(scan)
        if generation is not None:
            return generation == self.generation
        return bool(self.target_id) and scan["target_id"] == self.target_id


class RepositoryIdentityCache:
    """One request's saved identities and verified live aliases."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.supports_identity = supports_repository_identity(connection)
        self.scan_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(scans)")
        }
        self.supports_generation = "repository_generation" in self.scan_columns
        identity_column = "repository_identity" if self.supports_identity else "NULL"
        self.targets = {
            row["target_id"]: row
            for row in connection.execute(
                "SELECT id AS target_id, current_path AS target_path, "
                f"{identity_column} AS repository_identity FROM security_targets"
            )
        }
        self.targets_by_path = {
            row["target_path"]: row for row in self.targets.values()
        }
        self._states: dict[tuple[str, str, str | None], RepositoryTargetState] = {}
        self._origins: dict[str, tuple[str, str] | None] = {}

    def for_row(self, row: sqlite3.Row | dict) -> RepositoryTargetState:
        target = self.targets.get(row["target_id"])
        stored = (
            row["repository_identity"] if "repository_identity" in row.keys()
            else target["repository_identity"] if target is not None else None
        )
        key = (
            row["target_id"] or "",
            row["target_path"],
            stored,
        )
        if key not in self._states:
            self._states[key] = _inspect_repository_target(
                self.connection, *key, scan_columns=self.scan_columns
            )
        return self._states[key]

    def for_path(self, target_path: str) -> RepositoryTargetState:
        row = self.targets_by_path.get(target_path)
        return self.for_row(
            row if row is not None else {
                "target_id": "", "target_path": target_path, "repository_identity": None,
            }
        )

    def scope(self, target_id: str) -> RepositoryScanScope:
        target = self.targets.get(target_id)
        return (
            self._scope_for_state(self.for_row(target)) if target is not None
            else RepositoryScanScope(target_id=target_id)
        )

    def scope_for_path(self, target_path: str) -> RepositoryScanScope:
        return self._scope_for_state(self.for_path(target_path))

    def scope_for_scan(self, scan: sqlite3.Row | dict) -> RepositoryScanScope:
        requested = self.for_row(scan)
        generation = scan_repository_generation(scan)
        if not requested.ownership_matches or (
            generation is not None and generation != requested.live_identity
        ):
            return RepositoryScanScope(available=False)
        return RepositoryScanScope(generation, requested.target_id)

    def _scope_for_state(self, requested: RepositoryTargetState) -> RepositoryScanScope:
        if not requested.ownership_matches:
            return RepositoryScanScope(available=False)
        return RepositoryScanScope(
            requested.live_identity if not requested.missing else None,
            requested.target_id or None,
            exact_target=requested.missing,
        )

    def target_ids(self, target_id: str) -> set[str]:
        return self._target_ids_for_scope(self.scope(target_id))

    def target_ids_for_path(self, target_path: str) -> set[str]:
        return self._target_ids_for_scope(self.scope_for_path(target_path))

    def _target_ids_for_scope(self, scope: RepositoryScanScope) -> set[str]:
        clause, values = scope.sql(supports_generation=self.supports_generation)
        result = {
            row[0] for row in self.connection.execute(
                f"SELECT DISTINCT target_id FROM scans WHERE {clause}", values
            ) if row[0] is not None
        }
        if scope.available and scope.target_id:
            result.add(scope.target_id)
        return result

    def origin(self, state: RepositoryTargetState) -> tuple[str, str] | None:
        if state.target_path not in self._origins:
            self._origins[state.target_path] = repository_origin(Path(state.target_path))
        return self._origins[state.target_path]


def require_scan_checkout_owner(
    connection: sqlite3.Connection, scan: sqlite3.Row | dict
) -> None:
    identities = RepositoryIdentityCache(connection)
    owner = identities.for_row(scan)
    owner.require_owner()
    if owner.missing or not identities.scope_for_scan(scan).contains(scan):
        raise SystemExit(
            "The saved scan no longer matches the selected repository checkout."
        )


def _pre_release_repository_identities(identity: GitRepositoryIdentity) -> set[str]:
    directory = os.path.normcase(identity.common_directory)
    relative = os.path.normcase(os.fspath(Path(identity.relative_path))).replace(os.sep, "/")
    prefix = f"git-common-dir\0{directory}\0{identity.device}\0{identity.inode}\0"
    identities = {_identity_digest(f"{prefix}{relative}")}
    try:
        generation = (Path(identity.common_directory) / "description").lstat()
    except OSError:
        return identities
    if stat.S_ISREG(generation.st_mode):
        identities.add(_identity_digest(
            f"{prefix}git-description\0"
            f"{serialize_filesystem_identity(generation.st_dev)}\0"
            f"{serialize_filesystem_identity(generation.st_ino)}\0"
            f"{generation.st_ctime_ns}\0{relative}"
        ))
    return identities


def _timestamp_ns(value: str) -> int | None:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if timestamp.tzinfo is None:
        return None
    delta = timestamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _repository_predates_history(
    identity: GitRepositoryIdentity,
    scans: list[sqlite3.Row],
    *,
    empty_timestamp: str | None = None,
) -> bool:
    if not scans and empty_timestamp is None:
        return True
    if any(not {"started_at", "created_at"} <= set(scan.keys()) for scan in scans):
        return False
    timestamps = (
        [_timestamp_ns(scan[column]) for scan in scans for column in ("started_at", "created_at")]
        if scans else [_timestamp_ns(empty_timestamp)]
    )
    return (
        all(value is not None for value in timestamps)
        and identity.birth_time_ns <= min(timestamps)
    )


def normalize_pre_release_repository_identities(connection: sqlite3.Connection) -> None:
    """Retain only individually established pre-release identity bindings."""
    if not supports_repository_identity(connection):
        return
    identities = RepositoryIdentityCache(connection)
    targets = connection.execute(
        "SELECT id AS target_id, current_path AS target_path, created_at, repository_identity "
        "FROM security_targets WHERE repository_identity IS NOT NULL"
    ).fetchall()
    states = {target["target_id"]: identities.for_row(target) for target in targets}
    anchors = {
        state.stored_identity: state.repository
        for state in states.values()
        if state.repository is not None
        and state.ownership_matches
        and state.stored_identity in {state.repository.value, state.repository.legacy_value}
    }
    for target in targets:
        stored = target["repository_identity"]
        state = states[target["target_id"]]
        scans = connection.execute(
            "SELECT started_at, created_at FROM scans WHERE target_id = ? OR target_path = ?",
            (target["target_id"], target["target_path"]),
        ).fetchall()
        anchor = anchors.get(stored)
        identity = state.repository
        replacement = None
        if anchor is not None:
            if _repository_predates_history(
                anchor, scans, empty_timestamp=target["created_at"]
            ):
                replacement = stored
        elif (
            identity is not None
            and state.strict_owner_matches
            and stored in _pre_release_repository_identities(identity)
            and _repository_predates_history(
                identity, scans, empty_timestamp=target["created_at"]
            )
        ):
            replacement = identity.legacy_value
        if replacement != stored:
            connection.execute(
                "UPDATE security_targets SET repository_identity = ? "
                "WHERE id = ? AND repository_identity = ?",
                (replacement, target["target_id"], stored),
            )


def _bind_unscanned_repository_identity(
    connection: sqlite3.Connection, target_id: str, target_path: str, identity: str
) -> bool:
    return connection.execute(
        """
        UPDATE security_targets
        SET repository_identity = ?
        WHERE id = ? AND current_path = ? AND repository_identity IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM scans
                WHERE scans.target_id = security_targets.id
                    OR scans.target_path = security_targets.current_path
            )
        """,
        (identity, target_id, target_path),
    ).rowcount == 1


def backfill_repository_identities(connection: sqlite3.Connection) -> None:
    if not supports_repository_identity(connection):
        return
    targets = connection.execute(
        """
        SELECT targets.id, targets.current_path
        FROM security_targets AS targets
        WHERE targets.repository_identity IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM scans
                WHERE scans.target_id = targets.id OR scans.target_path = targets.current_path
            )
        """
    ).fetchall()
    for target in targets:
        identity = verified_repository_identity(
            connection, str(target["id"]), target["current_path"]
        )
        if identity is not None:
            _bind_unscanned_repository_identity(
                connection, str(target["id"]), target["current_path"], identity
            )


def backfill_security_targets(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT target_path FROM workspaces WHERE target_path IS NOT NULL
        UNION
        SELECT target_path FROM scans
        """
    ).fetchall()
    for row in rows:
        target_path = row["target_path"]
        target_id = ensure_security_target(connection, target_path, verify_ownership=False)
        connection.execute(
            "UPDATE workspaces SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
            (target_id, target_path),
        )
        connection.execute(
            "UPDATE scans SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
            (target_id, target_path),
        )
    backfill_repository_identities(connection)


@dataclass(frozen=True)
class RegisteredRepositoryTarget:
    target_id: str
    repository_generation: str | None


def register_security_target(
    connection: sqlite3.Connection, target_path: str, *, verify_ownership: bool = True
) -> RegisteredRepositoryTarget:
    supports_identity = supports_repository_identity(connection)
    target_query = (
        "SELECT id, repository_identity FROM security_targets WHERE current_path = ?"
        if supports_identity
        else "SELECT id FROM security_targets WHERE current_path = ?"
    )
    existing = connection.execute(target_query, (target_path,)).fetchone()
    if existing is None:
        target_id = stable_target_id(Path(target_path))
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        # Leave repository_identity NULL until the guarded binding below succeeds.
        connection.execute(
            """
            INSERT OR IGNORE INTO security_targets (
                id, current_path, display_name, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (target_id, target_path, Path(target_path).name, timestamp, timestamp),
        )
        existing = connection.execute(target_query, (target_path,)).fetchone()
        if existing is None:
            raise SystemExit("The repository target changed while it was being registered.")
    target_id = str(existing["id"])
    if not supports_identity:
        return RegisteredRepositoryTarget(target_id, None)
    state = _inspect_repository_target(
        connection, target_id, target_path, existing["repository_identity"]
    )
    if verify_ownership:
        state.require_owner()
    if existing["repository_identity"] is None:
        identity = state.verified_identity
        if identity is not None and not _bind_unscanned_repository_identity(
            connection, target_id, target_path, identity
        ):
            # A writer may have registered history or bound this target after inspection.
            existing = connection.execute(target_query, (target_path,)).fetchone()
            if existing is None:
                raise SystemExit("The repository target changed while it was being registered.")
            target_id = str(existing["id"])
            state = _inspect_repository_target(
                connection, target_id, target_path, existing["repository_identity"]
            )
            if verify_ownership:
                state.require_owner()
    return RegisteredRepositoryTarget(
        target_id, state.live_identity if state.ownership_matches and not state.missing else None
    )


def ensure_security_target(
    connection: sqlite3.Connection, target_path: str, *, verify_ownership: bool = True
) -> str:
    return register_security_target(
        connection, target_path, verify_ownership=verify_ownership
    ).target_id


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
