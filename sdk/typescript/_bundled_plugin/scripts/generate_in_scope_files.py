#!/usr/bin/env python3
"""Generate the shared, deterministically ordered security-scan file inventory."""

from __future__ import annotations

import argparse
import codecs
import fnmatch
import io
import mmap
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

IGNORE_FILE_NAMES = (".gitignore", ".ignore", ".rgignore")


class InventoryError(ValueError):
    """Raised when the repository, scope, or inventory cannot be used safely."""


def symbolic_metadata(metadata: os.stat_result) -> bool:
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_point
    )


def filesystem_name_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).upper().casefold().rstrip(". ")


def split_index_backing(index: Path, hash_size: int) -> str | None:
    with index.open("rb") as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            return None
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as contents:
            if len(contents) < 12 + hash_size or contents[:4] != b"DIRC":
                return None
            version = int.from_bytes(contents[4:8], "big")
            if version not in (2, 3, 4):
                return None
            count = int.from_bytes(contents[8:12], "big")
            position = 12
            limit = len(contents) - hash_size
            for _ in range(count):
                entry = position
                position += 40 + hash_size
                if position + 2 > limit:
                    return None
                flags = int.from_bytes(contents[position : position + 2], "big")
                position += 2 + (2 if flags & 0x4000 else 0)
                if version == 4:
                    while position < limit:
                        byte = contents[position]
                        position += 1
                        if not byte & 0x80:
                            break
                    else:
                        return None
                end = contents.find(b"\0", position, limit)
                if end < 0:
                    return None
                position = end + 1 if version == 4 else entry + ((end - entry + 8) & ~7)
            backing = None
            while position + 8 <= limit:
                signature = contents[position : position + 4]
                length = int.from_bytes(contents[position + 4 : position + 8], "big")
                position += 8
                if position + length > limit:
                    return None
                if signature == b"link":
                    if length < hash_size:
                        return None
                    backing = contents[position : position + hash_size].hex()
                position += length
            return backing
    return None


def git_metadata_path(parent: Path, name: str) -> bool:
    if name == ".git":
        return True
    if filesystem_name_key(name) != ".git":
        return False
    try:
        candidate = (parent / name).stat(follow_symlinks=False)
        if symbolic_metadata(candidate):
            raise InventoryError("symbolic Git metadata paths are not supported")
        metadata = (parent / ".git").stat(follow_symlinks=False)
        if symbolic_metadata(metadata):
            raise InventoryError("symbolic Git metadata paths are not supported")
        return (candidate.st_dev, candidate.st_ino) == (metadata.st_dev, metadata.st_ino)
    except OSError:
        return False


def resolve_repository(value: str) -> Path:
    """Resolve the repository once so every scope is bound to its real root."""
    try:
        repository = Path(value).expanduser().resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--repo: cannot resolve repository: {value}") from error
    if not repository.is_dir():
        raise InventoryError(f"--repo: expected a directory: {repository}")
    return repository


def resolve_scope(repository: Path, value: str) -> str:
    """Preserve ripgrep's relative path spelling while rejecting escaped scopes."""
    if not value or "\0" in value:
        raise InventoryError("--scope: expected a non-empty file or directory")

    requested = Path(value).expanduser()
    scope = requested if requested.is_absolute() else repository / requested
    try:
        resolved = scope.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--scope: path does not exist: {value}") from error

    repository_metadata = repository.stat(follow_symlinks=False)
    repository_identity = (repository_metadata.st_dev, repository_metadata.st_ino)
    try:
        relative = resolved.relative_to(repository)
    except ValueError as error:
        ancestor = resolved
        while True:
            metadata = ancestor.stat(follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) == repository_identity:
                relative = Path(*resolved.parts[len(ancestor.parts) :])
                break
            if ancestor == ancestor.parent:
                raise InventoryError(
                    f"--scope: path must remain inside --repo: {value}"
                ) from error
            ancestor = ancestor.parent
    parent = repository
    for component in relative.parts:
        if git_metadata_path(parent, component):
            raise InventoryError("--scope: Git metadata paths are not supported")
        parent /= component

    current = scope
    while True:
        metadata = current.stat(follow_symlinks=False)
        if symbolic_metadata(metadata):
            raise InventoryError("--scope: symbolic links are not supported")
        if (metadata.st_dev, metadata.st_ino) == repository_identity:
            break
        if current == current.parent:
            raise InventoryError("--scope: symbolic links are not supported")
        current = current.parent

    if not resolved.is_dir() and not resolved.is_file():
        raise InventoryError(f"--scope: expected a file or directory: {value}")

    canonical = relative.as_posix() if relative.parts else "."
    return f"./{canonical}" if value.startswith("./") and canonical != "." else canonical


def resolve_output(value: str) -> Path:
    """Reject direct symlink outputs without constraining the artifact root."""
    if not value or "\0" in value:
        raise InventoryError("--out: expected an inventory file path")
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise InventoryError("--out: refusing to replace a symbolic link")
    try:
        output = requested.resolve(strict=False)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--out: cannot resolve inventory path: {value}") from error
    if output.exists() and not output.is_file():
        raise InventoryError(f"--out: expected a regular file path: {output}")
    return output


def generate_in_scope_files(repository: Path, scope: str, output: Path) -> int:
    """Atomically inventory visible files and ignored files tracked by Git."""
    selected = (repository / scope).resolve(strict=True)
    selected_directory = selected if selected.is_dir() else selected.parent
    ancestors: list[Path] = []
    current = selected_directory
    while True:
        ancestors.append(current)
        if current == repository:
            break
        current = current.parent
    ancestors.reverse()
    def reject_symbolic_ignore(directory: Path) -> None:
        for name in IGNORE_FILE_NAMES:
            try:
                metadata = (directory / name).stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not symbolic_metadata(metadata) and (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
            ):
                continue
            if symbolic_metadata(metadata):
                raise InventoryError("symbolic ignore files are not supported")
            raise InventoryError("non-regular ignore files are not supported")

    def directory_identity(path: Path) -> tuple[int, int]:
        metadata = path.stat()
        return metadata.st_dev, metadata.st_ino

    def same_filesystem_path(first: Path, second: Path) -> bool:
        try:
            return directory_identity(first) == directory_identity(second) and directory_identity(
                first.parent
            ) == directory_identity(second.parent)
        except FileNotFoundError:
            return False

    def nonsymbolic_directory(path: Path) -> bool:
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISDIR(metadata.st_mode) and not symbolic_metadata(metadata)

    repository_identity = directory_identity(repository)
    gitdir_owners: dict[tuple[int, int], tuple[int, int]] = {}
    ignore_case_roots: dict[tuple[int, int], bool] = {}
    validated_metadata_roots: set[tuple[int, int]] = set()
    validated_object_stores: set[tuple[int, int]] = set()
    validated_metadata_files: set[tuple[int, int]] = set()
    validated_reference_directories: set[tuple[int, int, bool]] = set()

    def config_value(value: str | None) -> str | None:
        if value is None:
            return None
        quoted = False
        escaped = False
        for index, character in enumerate(value):
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = not quoted
            elif character in "#;" and not quoted:
                return value[:index].rstrip(" \t\r")
        return value.rstrip(" \t\r")

    def join_config_lines(contents: bytes) -> bytes:
        joined = bytearray()
        quoted = False
        comment = False
        escaped = False
        position = 0
        while position < len(contents):
            character = contents[position]
            if character == ord("\n"):
                quoted = False
                comment = False
                escaped = False
            elif not comment and not escaped and character == ord("\\"):
                if contents[position + 1 : position + 2] == b"\n":
                    position += 2
                    continue
                if contents[position + 1 : position + 3] == b"\r\n":
                    position += 3
                    continue
                escaped = True
            elif escaped:
                escaped = False
            elif not comment and character == ord('"'):
                quoted = not quoted
            elif not quoted and character in (ord("#"), ord(";")):
                comment = True
            joined.append(character)
            position += 1
        return bytes(joined)

    def decode_config_value(value: str) -> tuple[bytes, bytes]:
        decoded = bytearray()
        normalized = bytearray()
        quoted = False
        escaped = False
        replacements = {ord("n"): ord("\n"), ord("t"): ord("\t"), ord("b"): ord("\b")}
        for character in os.fsencode(value):
            if escaped:
                if character not in (*replacements, ord('"'), ord("\\")):
                    raise InventoryError("invalid Git worktree path")
                replacement = replacements.get(character, character)
                decoded.append(replacement)
                normalized.append(replacement)
                escaped = False
            elif character == ord("\\"):
                escaped = True
            elif character == ord('"'):
                quoted = not quoted
            else:
                decoded.append(character)
                normalized.append(
                    ord(" ")
                    if character in (ord("\t"), ord("\r")) and not quoted
                    else character
                )
        if quoted or escaped:
            raise InventoryError("invalid Git worktree path")
        return bytes(decoded), bytes(normalized)

    def has_git_marker(directory: Path) -> bool:
        marker = directory / ".git"

        def inspect_metadata(
            path: Path, *, directory: bool | None = None
        ) -> os.stat_result | None:
            if (
                os.name == "nt"
                and path.anchor.startswith("\\\\")
                and os.path.normcase(path.anchor) != os.path.normcase(repository.anchor)
            ):
                raise InventoryError("network Git metadata paths are not supported")
            try:
                metadata = path.stat(follow_symlinks=False)
            except FileNotFoundError:
                return None
            except (OSError, ValueError) as error:
                raise InventoryError(f"could not inspect Git metadata: {directory}") from error
            if symbolic_metadata(metadata):
                raise InventoryError("symbolic Git metadata paths are not supported")
            if directory is True and not stat.S_ISDIR(metadata.st_mode):
                raise InventoryError("non-directory Git metadata paths are not supported")
            if directory is False and not stat.S_ISREG(metadata.st_mode):
                raise InventoryError("non-regular Git metadata files are not supported")
            if stat.S_ISREG(metadata.st_mode):
                validated_metadata_files.add((metadata.st_dev, metadata.st_ino))
            return metadata

        def inspect_metadata_path(path: Path, *, directory_path: bool | None) -> Path | None:
            current = Path(path.anchor)
            if inspect_metadata(current, directory=True) is None:
                return None
            components = path.parts[1:]
            for index, component in enumerate(components):
                if component == "..":
                    current = current.parent
                    continue
                current /= component
                if (
                    inspect_metadata(
                        current,
                        directory=directory_path if index + 1 == len(components) else True,
                    )
                    is None
                ):
                    return None
            return current

        def aliases_canonical_path(path: Path, canonical: str) -> bool:
            try:
                actual = path.stat(follow_symlinks=False)
                expected = (path.parent / canonical).stat(follow_symlinks=False)
            except FileNotFoundError:
                return False
            return (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)

        def inspect_object_store(objects: Path) -> None:
            try:
                identity = directory_identity(objects)
                if identity in validated_object_stores:
                    return
                entries = objects.iterdir()
                for entry in entries:
                    canonical = filesystem_name_key(entry.name)
                    if canonical not in ("info", "pack") and not re.fullmatch(
                        r"[0-9a-f]{2}", canonical
                    ):
                        continue
                    if entry.name != canonical and not aliases_canonical_path(entry, canonical):
                        continue
                    inspect_metadata(entry, directory=True)
                    if canonical != "info":
                        for member in entry.iterdir():
                            member_canonical = filesystem_name_key(member.name)
                            if canonical == "pack":
                                if member_canonical == "multi-pack-index.d":
                                    if member.name != member_canonical and not aliases_canonical_path(
                                        member, member_canonical
                                    ):
                                        continue
                                    inspect_metadata(member, directory=True)
                                    for layer in member.iterdir():
                                        layer_canonical = filesystem_name_key(layer.name)
                                        if layer_canonical != "multi-pack-index-chain" and not re.fullmatch(
                                            r"multi-pack-index-[0-9a-f]{40}(?:[0-9a-f]{24})?\.(?:midx|bitmap|rev)",
                                            layer_canonical,
                                        ):
                                            continue
                                        if layer.name != layer_canonical and not aliases_canonical_path(
                                            layer, layer_canonical
                                        ):
                                            continue
                                        inspect_metadata(layer, directory=False)
                                    continue
                                if member_canonical == "multi-pack-index":
                                    expected = member_canonical
                                elif not member_canonical.endswith(
                                    (".pack", ".idx", ".rev", ".bitmap", ".keep", ".promisor", ".mtimes")
                                ):
                                    continue
                                else:
                                    stem, _, suffix = member.name.rpartition(".")
                                    expected = f"{stem}.{filesystem_name_key(suffix)}"
                            else:
                                if not re.fullmatch(
                                    r"(?:[0-9a-f]{38}|[0-9a-f]{62})", member_canonical
                                ):
                                    continue
                                expected = member_canonical
                            if member.name != expected and not aliases_canonical_path(member, expected):
                                continue
                            inspect_metadata(member, directory=False)
                validated_object_stores.add(identity)
            except OSError as error:
                raise InventoryError(f"could not inspect Git metadata: {directory}") from error

        try:
            metadata = marker.stat(follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as error:
            raise InventoryError(f"could not inspect Git metadata: {directory}") from error
        if symbolic_metadata(metadata):
            raise InventoryError("symbolic Git metadata paths are not supported")
        gitfile = stat.S_ISREG(metadata.st_mode)
        gitfile_identity = (metadata.st_dev, metadata.st_ino) if gitfile else None
        backpointer_owned = False
        if stat.S_ISDIR(metadata.st_mode):
            gitdir = marker
        elif gitfile:
            try:
                contents = marker.read_bytes()
            except OSError as error:
                raise InventoryError(f"could not inspect Git metadata: {directory}") from error
            if not contents.startswith(b"gitdir: "):
                return True
            gitdir = Path(os.fsdecode(contents.removeprefix(b"gitdir: ").rstrip(b"\r\n")))
            if not gitdir.is_absolute():
                gitdir = directory / gitdir
            inspected_gitdir = inspect_metadata_path(gitdir, directory_path=True)
            if inspected_gitdir is None:
                raise InventoryError("Git metadata directory does not own selected worktree")
            gitdir = inspected_gitdir
            internally_owned = len(gitdir.parts) >= len(repository.parts)
            if internally_owned:
                ancestor = gitdir
                for _ in range(len(gitdir.parts) - len(repository.parts)):
                    ancestor = ancestor.parent
                internally_owned = directory_identity(ancestor) == directory_identity(repository)
            backpointer = gitdir / "gitdir"
            if inspect_metadata(backpointer, directory=False) is not None:
                backpointer_owned = True
                try:
                    target = Path(os.fsdecode(backpointer.read_bytes().rstrip(b"\r\n")))
                except (OSError, ValueError) as error:
                    raise InventoryError(f"could not inspect Git metadata: {directory}") from error
                if not target.is_absolute():
                    target = gitdir / target
                inspected_target = inspect_metadata_path(target, directory_path=None)
                if inspected_target is None or not same_filesystem_path(inspected_target, marker):
                    raise InventoryError("Git metadata directory does not own selected worktree")
            elif not internally_owned:
                raise InventoryError("Git metadata directory does not own selected worktree")
        else:
            return False

        identity = directory_identity(gitdir)
        owner = directory_identity(directory)
        if identity in gitdir_owners:
            if gitdir_owners[identity] != owner:
                raise InventoryError("Git metadata directory does not own selected worktree")
            return True
        gitdir_owners[identity] = owner

        roots = [gitdir]
        common_marker = gitdir / "commondir"
        common_metadata = inspect_metadata(common_marker, directory=False)
        if common_metadata is not None:
            try:
                common = Path(os.fsdecode(common_marker.read_bytes().rstrip(b"\r\n")))
            except (OSError, ValueError) as error:
                raise InventoryError(f"could not inspect Git metadata: {directory}") from error
            if not common.is_absolute():
                common = gitdir / common
            inspected_common = inspect_metadata_path(common, directory_path=True)
            if inspected_common is None:
                raise InventoryError("Git common directory does not own selected worktree")
            common = inspected_common
            if not same_filesystem_path(common, gitdir):
                owner = inspect_metadata_path(
                    common / "worktrees" / gitdir.name,
                    directory_path=True,
                )
                if owner is None or not same_filesystem_path(owner, gitdir):
                    raise InventoryError("Git common directory does not own selected worktree")
                roots.append(common)

        def config_enabled(value: str | None) -> bool:
            if value is None:
                return True
            normalized = os.fsdecode(decode_config_value(value)[0]).strip(" \t\r").casefold()
            return normalized not in ("", "false", "no", "off") and re.fullmatch(
                r"[+-]?(?:0+|0x0+)[kmg]?", normalized
            ) is None

        options: dict[tuple[str, str], str | None] = {}
        config_path = roots[-1] / "config"
        worktree_config_enabled = False
        config_includes = False
        if inspect_metadata(config_path, directory=False) is not None:
            try:
                for candidate in (config_path, gitdir / "config.worktree"):
                    if candidate != config_path:
                        worktree_config_enabled = config_enabled(
                            options.get(("extensions", "worktreeconfig"), "false")
                        )
                        if not worktree_config_enabled:
                            continue
                        if inspect_metadata(candidate, directory=False) is None:
                            continue
                    contents = candidate.read_bytes().removeprefix(codecs.BOM_UTF8)
                    contents = join_config_lines(contents)
                    section = None
                    for raw in os.fsdecode(contents).split("\n"):
                        line = raw.lstrip(" \t\r").rstrip("\r")
                        if not line or line.startswith(("#", ";")):
                            continue
                        while line.startswith("["):
                            match = re.match(
                                r'\[[ \t]*([a-z0-9-]*)'
                                r'(?:([.][^\]\r\n]*)|[ \t\r]+("(?:[^"\\]|\\.)*"))?'
                                r'[ \t]*\]',
                                line,
                                re.IGNORECASE,
                            )
                            section = None
                            if match is None:
                                break
                            name = match.group(1).casefold()
                            if (
                                name in ("core", "extensions", "include", "includeif")
                                and match.group(2) is None
                                and (match.group(3) is not None) == (name == "includeif")
                            ):
                                section = name
                            line = line[match.end() :].lstrip(" \t\r")
                        if section is None or not line or line.startswith(("#", ";")):
                            continue
                        assignment = re.match(
                            r"([a-z][a-z0-9-]*)(?:([ \t]*=)[ \t\r]*(.*))?",
                            line,
                            re.IGNORECASE,
                        )
                        if assignment is None:
                            continue
                        if assignment.group(2) is None:
                            remainder = line[assignment.end() :].lstrip(" \t")
                            if remainder and not remainder.startswith(("#", ";")):
                                continue
                        key = assignment.group(1).casefold()
                        if section in ("include", "includeif") and key == "path":
                            config_includes = True
                        if (section, key) in (
                            ("core", "worktree"),
                            ("core", "sparsecheckout"),
                            ("core", "ignorecase"),
                            ("extensions", "objectformat"),
                            ("extensions", "worktreeconfig"),
                        ):
                            if (section, key) == ("extensions", "objectformat") and candidate != config_path:
                                continue
                            options[(section, key)] = (
                                None
                                if assignment.group(2) is None
                                else config_value(assignment.group(3))
                            )
            except (OSError, UnicodeError, ValueError) as error:
                raise InventoryError(f"could not inspect Git metadata: {directory}") from error
        if config_includes:
            raise InventoryError("Git config includes are not supported")
        ignore_case_roots[directory_identity(directory)] = config_enabled(
            options.get(("core", "ignorecase"), "false")
        )
        sparse_checkout_enabled = config_enabled(
            options.get(("core", "sparsecheckout"), "false")
        )

        configured_worktree = options.get(("core", "worktree"))
        if gitfile:
            if configured_worktree is None:
                if not backpointer_owned:
                    raise InventoryError("Git metadata directory does not own selected worktree")
            else:
                decoded, normalized = decode_config_value(configured_worktree)
                configured_worktree = os.fsdecode(decoded)
                target = Path(configured_worktree)
                if not target.is_absolute():
                    target = gitdir / target
                inspected_target = inspect_metadata_path(target, directory_path=True)
                if inspected_target is None:
                    raise InventoryError("Git metadata directory does not own selected worktree")
                if decoded != normalized:
                    normalized_target = Path(os.fsdecode(normalized))
                    if not normalized_target.is_absolute():
                        normalized_target = gitdir / normalized_target
                    inspected_normalized = inspect_metadata_path(
                        normalized_target,
                        directory_path=True,
                    )
                    if inspected_normalized is None:
                        raise InventoryError(
                            "Git metadata directory does not own selected worktree"
                        )
                    if directory_identity(inspected_normalized) != directory_identity(directory):
                        raise InventoryError(
                            "Git metadata directory does not own selected worktree"
                        )
                if not same_filesystem_path(inspected_target, directory):
                    raise InventoryError("Git metadata directory does not own selected worktree")

        configured_format = options.get(("extensions", "objectformat"), "sha1")
        object_format = (
            "sha1"
            if configured_format is None
            else os.fsdecode(decode_config_value(configured_format)[0]).strip(" \t\r").casefold()
        )
        reference_hash_width = 64 if object_format == "sha256" else 40

        def inspect_reference_tree(reference_root: Path, *, common: bool) -> None:
            def valid_reference_component(name: str) -> bool:
                return bool(name) and not (
                    name.startswith(".")
                    or name.endswith((".lock", "."))
                    or ".." in name
                    or "@{" in name
                    or any(
                        ord(character) < 32
                        or ord(character) == 127
                        or character in " ~^:?*[\\"
                        for character in name
                    )
                )

            pending_references = [reference_root]
            while pending_references:
                references = pending_references.pop()
                reference_identity = (
                    *directory_identity(references),
                    not common or gitdir == roots[-1],
                )
                if reference_identity in validated_reference_directories:
                    continue
                validated_reference_directories.add(reference_identity)
                for reference in references.iterdir():
                    name = reference.name
                    if not valid_reference_component(name):
                        continue
                    details = reference.stat(follow_symlinks=False)
                    if common and references == reference_root:
                        canonical = filesystem_name_key(name)
                        reserved = canonical == "replace" or (
                            gitdir != roots[-1]
                            and canonical in ("bisect", "worktree", "rewritten")
                        )
                        if (
                            reserved
                            and (name == canonical or aliases_canonical_path(reference, canonical))
                            and not stat.S_ISREG(details.st_mode)
                        ):
                            continue
                    if symbolic_metadata(details):
                        raise InventoryError(
                            "symbolic Git metadata paths are not supported"
                        )
                    if stat.S_ISDIR(details.st_mode):
                        pending_references.append(reference)
                    elif stat.S_ISREG(details.st_mode):
                        try:
                            with reference.open("rb") as handle:
                                contents = handle.readline()
                                if re.match(
                                    rb"[0-9a-fA-F]{%d}(?=[\x00\x09\x0a\x0d\x20]|$)"
                                    % reference_hash_width,
                                    contents,
                                ):
                                    valid = True
                                elif contents.startswith(b"ref:"):
                                    symbolic, separator, _trailing = contents.partition(
                                        b"\0"
                                    )
                                    target = os.fsdecode(
                                        symbolic.removeprefix(b"ref:").strip(b" \t\r\n")
                                    )
                                    valid = target.startswith("refs/") and all(
                                        valid_reference_component(component)
                                        for component in target.split("/")
                                    )
                                    if valid and not separator:
                                        while chunk := handle.read(io.DEFAULT_BUFFER_SIZE):
                                            if chunk.strip(b" \t\r\n"):
                                                valid = False
                                                break
                                else:
                                    valid = False
                        except OSError:
                            continue
                        if valid:
                            validated_metadata_files.add(
                                (details.st_dev, details.st_ino)
                            )

        for root in roots:
            for relative in (
                "HEAD",
                "index",
                "packed-refs",
                "refs",
                "refs/heads",
                "refs/tags",
                "config",
                "config.worktree",
                "info",
                "info/exclude",
                "info/sparse-checkout",
                "objects",
                "objects/info",
                "objects/info/alternates",
            ):
                effective_root = (
                    gitdir
                    if relative in ("HEAD", "index", "config.worktree", "info/sparse-checkout")
                    else roots[-1]
                )
                if (
                    root != effective_root
                    or relative == "config.worktree" and not worktree_config_enabled
                    or relative == "info/sparse-checkout" and not sparse_checkout_enabled
                ):
                    continue
                if relative == "info/sparse-checkout" and root != roots[-1]:
                    inspect_metadata(root / "info", directory=True)
                path = root / relative
                metadata = inspect_metadata(
                    path,
                    directory=relative in (
                        "refs",
                        "refs/heads",
                        "refs/tags",
                        "info",
                        "objects",
                        "objects/info",
                    ),
                )
                if metadata is not None and relative == "refs":
                    inspect_reference_tree(path, common=True)
                if metadata is not None and relative == "objects":
                    inspect_object_store(path)
                if metadata is not None and relative == "objects/info/alternates":
                    try:
                        contents = path.read_bytes()
                    except OSError as error:
                        raise InventoryError(f"could not inspect Git metadata: {directory}") from error
                    pending = [(root / "objects", contents)]
                    inspected = {directory_identity(root / "objects")}
                    while pending:
                        object_root, records = pending.pop()
                        lines = records.split(b"\n")
                        for index, record in enumerate(lines):
                            terminated = index + 1 < len(lines)
                            if not record or (terminated and record == b"\r"):
                                continue
                            if record.startswith(b'"'):
                                variants = (record.removesuffix(b"\r"),)
                            elif terminated and record.endswith(b"\r"):
                                variants = (record.removesuffix(b"\r"),)
                                if os.name != "nt":
                                    variants += (record,)
                            else:
                                variants = (record,)
                            validated = False
                            for line in variants:
                                if line.startswith(b'"'):
                                    if not line.endswith(b'"'):
                                        raise InventoryError("invalid Git object alternate paths")
                                    quoted = line[1:-1]
                                    if not re.fullmatch(
                                        rb'(?:[^"\\]|\\(?:["\\abfnrtv]|[0-3][0-7]{2}))*', quoted
                                    ):
                                        raise InventoryError("invalid Git object alternate paths")
                                    try:
                                        line = codecs.escape_decode(quoted)[0]
                                    except (ValueError, UnicodeError) as error:
                                        raise InventoryError(
                                            "invalid Git object alternate paths"
                                        ) from error
                                alternate = Path(os.fsdecode(line))
                                if not alternate.is_absolute():
                                    alternate = object_root / alternate
                                owner = None
                                anchor = alternate
                                for candidate in (repository, *roots):
                                    if len(alternate.parts) < len(candidate.parts):
                                        continue
                                    candidate_anchor = inspect_metadata_path(
                                        Path(*alternate.parts[: len(candidate.parts)]),
                                        directory_path=True,
                                    )
                                    if candidate_anchor is None:
                                        continue
                                    if directory_identity(candidate_anchor) != directory_identity(candidate):
                                        continue
                                    owner = candidate
                                    anchor = candidate_anchor
                                    break
                                if owner is None:
                                    raise InventoryError(
                                        "external Git object alternates are not supported"
                                    )
                                current = anchor
                                depth = 0
                                for component in alternate.parts[len(anchor.parts) :]:
                                    if component == "..":
                                        if depth == 0:
                                            raise InventoryError(
                                                "external Git object alternates are not supported"
                                            )
                                        current = current.parent
                                        depth -= 1
                                        continue
                                    current /= component
                                    if inspect_metadata(current, directory=True) is None:
                                        break
                                    depth += 1
                                else:
                                    validated = True
                                    alternate = current
                                    identity = directory_identity(alternate)
                                    if identity in inspected:
                                        continue
                                    inspected.add(identity)
                                    inspect_object_store(alternate)
                                    info = alternate / "info"
                                    if inspect_metadata(info, directory=True) is None:
                                        continue
                                    nested_alternates = info / "alternates"
                                    details = inspect_metadata(
                                        nested_alternates, directory=False
                                    )
                                    if details is None:
                                        continue
                                    try:
                                        records = nested_alternates.read_bytes()
                                    except OSError as error:
                                        raise InventoryError(
                                            f"could not inspect Git metadata: {directory}"
                                        ) from error
                                    pending.append((alternate, records))
                            if not validated:
                                raise InventoryError(
                                    "missing Git object alternates are not supported"
                                )
            if root != gitdir:
                continue
            try:
                backing = split_index_backing(root / "index", 32 if object_format == "sha256" else 20)
                if backing is not None:
                    inspect_metadata(root / f"sharedindex.{backing}", directory=False)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise InventoryError(f"could not inspect Git metadata: {directory}") from error
        if gitdir != roots[-1]:
            private_references = gitdir / "refs"
            if inspect_metadata(private_references, directory=True) is not None:
                for namespace in ("bisect", "worktree", "rewritten"):
                    reference_root = private_references / namespace
                    try:
                        details = reference_root.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if symbolic_metadata(details):
                        raise InventoryError(
                            "symbolic Git metadata paths are not supported"
                        )
                    if stat.S_ISDIR(details.st_mode):
                        inspect_reference_tree(reference_root, common=False)
        validated_metadata_roots.update(
            directory_identity(root)
            for root in roots
            if directory_identity(root)
            not in (repository_identity, directory_identity(directory))
        )
        if gitfile_identity is not None:
            validated_metadata_files.add(gitfile_identity)
        return True

    discovered_roots: dict[tuple[int, int], Path] = {}
    metadata_aliases: set[tuple[str, ...]] = set()
    unowned_metadata_candidates: set[tuple[int, int]] = set()

    def validated_metadata_directory(path: Path) -> bool:
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            return False
        identity = metadata.st_dev, metadata.st_ino
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or symbolic_metadata(metadata)
            or identity == repository_identity
        ):
            return False
        if identity in validated_metadata_roots:
            return True
        if identity in validated_object_stores:
            try:
                marker = (path / ".git").stat(follow_symlinks=False)
            except OSError:
                return True
            if symbolic_metadata(marker) or not (
                stat.S_ISREG(marker.st_mode) or stat.S_ISDIR(marker.st_mode)
            ):
                return True
            if not selected.is_relative_to(path):
                relative = path.relative_to(repository).as_posix()
                visible = visible_to_outer_ignores(
                    path, [path], directories_only=True
                )
                if normalized(os.fsencode(relative)) not in visible:
                    tracked = run_git(
                        ["ls-files", "--stage", "-z", "--", relative]
                    )
                    expected = normalized(os.fsencode(relative))
                    indexed = (
                        record.partition(b"\t")
                        for record in tracked.stdout.split(b"\0")
                        if record
                    )
                    if tracked.returncode or not any(
                        (header.split(maxsplit=1)[0] == b"160000" and path == expected)
                        or path.startswith(expected + b"/")
                        for header, _separator, path in indexed
                    ):
                        return True
            if not has_git_marker(path):
                return True
            candidate = run_git(["rev-parse", "--absolute-git-dir"], directory=path)
            if candidate.returncode:
                return True
            try:
                gitdir = resolve_git_root(candidate.stdout)
                return gitdir_owners.get(directory_identity(gitdir)) != identity
            except (OSError, ValueError):
                return True
        if identity in unowned_metadata_candidates:
            return False
        try:
            head = (path / "HEAD").stat(follow_symlinks=False)
        except OSError:
            return False
        if not stat.S_ISREG(head.st_mode) and not symbolic_metadata(head):
            return False

        def regular_member(name: str) -> bytes | None:
            member = path / name
            try:
                details = member.stat(follow_symlinks=False)
                if not stat.S_ISREG(details.st_mode) or symbolic_metadata(details):
                    return None
                return member.read_bytes()
            except OSError:
                return None

        def repository_directory(value: bytes, base: Path) -> Path | None:
            try:
                candidate = Path(os.fsdecode(value))
                if not candidate.is_absolute():
                    candidate = base / candidate
                if len(candidate.parts) < len(repository.parts) or os.path.normcase(
                    candidate.anchor
                ) != os.path.normcase(repository.anchor):
                    return None
                supplied = Path(candidate.anchor)
                trusted = Path(repository.anchor)
                for actual, expected in zip(
                    candidate.parts[1 : len(repository.parts)], repository.parts[1:]
                ):
                    if actual in (".", ".."):
                        return None
                    supplied /= actual
                    trusted /= expected
                    actual_metadata = supplied.stat(follow_symlinks=False)
                    expected_metadata = trusted.stat(follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(actual_metadata.st_mode)
                        or symbolic_metadata(actual_metadata)
                        or (actual_metadata.st_dev, actual_metadata.st_ino)
                        != (expected_metadata.st_dev, expected_metadata.st_ino)
                    ):
                        return None
                components = candidate.parts[len(repository.parts) :]
            except (OSError, UnicodeError, ValueError):
                return None
            current = repository
            for component in components:
                if component == ".":
                    continue
                if component == "..":
                    if current == repository:
                        return None
                    current = current.parent
                    continue
                current /= component
                try:
                    details = current.stat(follow_symlinks=False)
                except OSError:
                    return None
                if not stat.S_ISDIR(details.st_mode) or symbolic_metadata(details):
                    return None
            return current

        owners: list[Path] = []
        backpointer = regular_member("gitdir")
        if backpointer is not None:
            try:
                marker = Path(os.fsdecode(backpointer.rstrip(b"\r\n")))
                if not marker.is_absolute():
                    marker = path / marker
                if marker.name == ".git":
                    owner = repository_directory(os.fsencode(marker.parent), repository)
                    if owner is not None:
                        owners.append(owner)
            except (OSError, UnicodeError, ValueError):
                pass

        for config in (regular_member("config"), regular_member("config.worktree")):
            if config is None:
                continue
            section = False
            configured = None
            contents = join_config_lines(config.removeprefix(codecs.BOM_UTF8))
            for raw in contents.split(b"\n"):
                line = raw.lstrip(b" \t\r").rstrip(b"\r")
                if line.startswith(b"["):
                    header = re.match(rb"\[[ \t]*core[ \t]*\]", line, re.IGNORECASE)
                    section = header is not None
                    line = line[header.end() :].lstrip(b" \t\r") if header else b""
                if not section:
                    continue
                assignment = re.match(
                    rb"worktree[ \t]*=[ \t\r]*(.*)", line, re.IGNORECASE
                )
                if assignment is not None:
                    configured = assignment.group(1).strip(b" \t\r")
            if configured:
                try:
                    value = config_value(os.fsdecode(configured))
                    if value is None:
                        continue
                    decoded, _normalized = decode_config_value(value)
                except (InventoryError, OSError, UnicodeError, ValueError):
                    continue
                owner = repository_directory(decoded, path)
                if owner is not None:
                    owners.append(owner)

        for owner in owners:
            if directory_identity(owner) == identity:
                continue
            marker = owner / ".git"
            try:
                details = marker.stat(follow_symlinks=False)
                if not stat.S_ISREG(details.st_mode) or symbolic_metadata(details):
                    continue
                contents = marker.read_bytes()
            except OSError:
                continue
            if not contents.startswith(b"gitdir: "):
                continue
            target = repository_directory(
                contents.removeprefix(b"gitdir: ").rstrip(b"\r\n"), owner
            )
            if target is not None and same_filesystem_path(target, path):
                if not symbolic_metadata(head):
                    contents = regular_member("HEAD")
                    if contents is None:
                        continue
                    if contents.startswith(b"ref:"):
                        reference = contents.removeprefix(b"ref:").lstrip(b" \t\r\n")
                        if not reference.startswith(b"refs/"):
                            continue
                    elif re.match(rb"[0-9a-fA-F]{40}", contents) is None:
                        continue
                common = path
                pointer = regular_member("commondir")
                if pointer is not None:
                    common = repository_directory(pointer.rstrip(b"\r\n"), path)
                    if common is None:
                        continue
                try:
                    members = [
                        (common / name).stat(follow_symlinks=False)
                        for name in ("objects", "refs")
                    ]
                except OSError:
                    continue
                if any(
                    not stat.S_ISDIR(member.st_mode) and not symbolic_metadata(member)
                    for member in members
                ):
                    continue
                validated_metadata_roots.add(identity)
                return True
        unowned_metadata_candidates.add(identity)
        return False

    global_ignore: Path | None = None

    command = [
        "rg",
        "--no-config",
        "--files",
        "--null",
        "--hidden",
        "--path-separator",
        "/",
        "--no-require-git",
        "--no-ignore-parent",
        "--no-ignore-global",
        "--glob",
        "!.git",
        "--glob",
        "!.git/**",
    ]

    def ripgrep_inventory(
        directory: Path,
        requested_scope: str,
        *,
        directory_guard: bool = False,
        ignore_case: bool | None = None,
    ) -> set[bytes]:
        arguments = command.copy()
        if ignore_case is not None:
            arguments = [
                argument
                for argument in arguments
                if argument != "--ignore-file-case-insensitive"
            ]
            if ignore_case:
                insertion = (
                    arguments.index("--ignore-file")
                    if "--ignore-file" in arguments
                    else len(arguments)
                )
                arguments.insert(insertion, "--ignore-file-case-insensitive")
        directory_parts = directory.relative_to(repository).parts
        ignored_aliases = []
        for alias in sorted(metadata_aliases):
            if alias[: len(directory_parts)] != directory_parts:
                continue
            relative_alias = "/".join(re.escape(part) for part in alias[len(directory_parts) :])
            if relative_alias and "\n" not in relative_alias and "\r" not in relative_alias:
                ignored_aliases.append(relative_alias)
        if directory_guard:
            relative_scope = requested_scope.removeprefix("./")
            arguments.extend(["--quiet", "--glob", f"/{re.escape(relative_scope)}/**"])
        for alias in ignored_aliases:
            arguments.extend(["--glob", f"!/{alias}", "--glob", f"!/{alias}/**"])
        arguments.extend(["--", "." if directory_guard else requested_scope])
        with tempfile.TemporaryFile(mode="w+b") as inventory:
            try:
                result = run_ripgrep(
                    arguments,
                    cwd=directory,
                    stdout=inventory,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            except OSError as error:
                raise InventoryError(f"could not run ripgrep: {error}") from error

            if result.returncode not in (0, 1):
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                message = f"ripgrep exited with status {result.returncode}"
                if detail:
                    message = f"{message}: {detail}"
                raise InventoryError(message)

            if directory_guard:
                return {b""} if result.returncode == 0 else set()
            inventory.seek(0)
            rows = set()

            def inventory_paths() -> Iterator[bytes]:
                remainder = b""
                while chunk := inventory.read(io.DEFAULT_BUFFER_SIZE):
                    paths = chunk.split(b"\0")
                    paths[0] = remainder + paths[0]
                    remainder = paths.pop()
                    yield from paths
                if remainder:
                    raise InventoryError("ripgrep returned an unterminated inventory path")

            for path in inventory_paths():
                if not path:
                    continue
                if b"\n" in path or b"\r" in path:
                    raise InventoryError("line separators are not supported in inventory paths")
                row = path + b"\n"
                if not metadata_aliases:
                    rows.add(row)
                    continue
                parts = (
                    *directory_parts,
                    *Path(os.fsdecode(row.removesuffix(b"\n"))).parts,
                )
                if not any(parts[: len(alias)] == alias for alias in metadata_aliases):
                    rows.add(row)
            return rows

    def normalized(path: bytes) -> bytes:
        return path.replace(b"\\", b"/") if os.name == "nt" else path

    def visible_to_outer_ignores(
        root: Path,
        candidates: list[Path],
        *,
        directories_only: bool = False,
        exempt_gitignores: tuple[tuple[Path, Path], ...] = (),
        preserve_gitignore_descendants: bool = False,
        configured_excludes_only: bool = False,
        include_global_excludes: bool = True,
        default_excluded: bool = False,
    ) -> set[bytes]:
        requested = {
            normalized(os.fsencode(candidate.relative_to(repository).as_posix()))
            for candidate in candidates
        }
        if directories_only and any(b"\n" in path or b"\r" in path for path in requested):
            raise InventoryError("line separators are not supported in inventory paths")
        directories: list[Path] = []
        current = root if default_excluded else root.parent
        while True:
            directories.append(current)
            if current == repository:
                break
            current = current.parent
        for directory in directories:
            reject_symbolic_ignore(directory)
        ignore_files = [] if configured_excludes_only else [
            directory / name
            for directory in directories
            for name in IGNORE_FILE_NAMES
            if name != ".gitignore"
            or preserve_gitignore_descendants
            or not any(
                directory.is_relative_to(owner)
                and gitlink.is_relative_to(directory)
                and directory != gitlink
                for owner, gitlink in exempt_gitignores
            )
            if (directory / name).is_file()
        ]
        configured_excludes: dict[Path, bytes] = {}
        for directory in directories:
            if not has_git_marker(directory):
                continue
            location = run_git(
                ["rev-parse", "--path-format=absolute", "--git-path", "info/exclude"],
                directory=directory,
            )
            if location.returncode == 0:
                exclude = Path(os.fsdecode(location.stdout.rstrip(b"\r\n")))
                if exclude.is_file():
                    contents = exclude.read_bytes()
                    if any(
                        line.strip() and not line.startswith(b"#")
                        for line in contents.splitlines()
                    ):
                        configured_excludes[directory] = contents
        if not default_excluded and not ignore_files and not configured_excludes and (
            global_ignore is None or not include_global_excludes
        ):
            return requested

        def ignore_component_matches(actual: bytes, pattern: bytes) -> bool:
            prefix = bytearray()
            for character in pattern:
                if character in b"*?[{\\":
                    break
                prefix.append(character)
            if prefix and not actual.startswith(bytes(prefix)):
                return False
            single_class = re.fullmatch(
                rb"([^*?{\[\\/]*)(\[(?:[!^])?[^\]/]+\])", pattern
            )
            if single_class is not None and len(actual) != len(single_class.group(1)) + 1:
                return False

            classes: list[tuple[int, tuple[int, ...]]] = []
            brace_ends: dict[int, int] = {}
            braces: list[int] = []
            index = 0
            while index < len(pattern):
                character = pattern[index]
                if character == ord("\\"):
                    index += 2
                    continue
                if character == ord("{"):
                    braces.append(index)
                    index += 1
                    continue
                if character == ord("}") and braces:
                    brace_ends[braces.pop()] = index
                    index += 1
                    continue
                if character != ord("["):
                    index += 1
                    continue
                index += 1
                if index < len(pattern) and pattern[index] in (ord("!"), ord("^")):
                    index += 1
                if index < len(pattern) and pattern[index] == ord("]"):
                    index += 1
                while index < len(pattern) and pattern[index] != ord("]"):
                    index += 1
                if index == len(pattern):
                    return True
                index += 1
                classes.append((index, tuple(braces)))

            globs = [b"/" + pattern + b"/**"]
            for end, openings in classes:
                position = end
                pending = list(openings)
                while position < len(pattern):
                    character = pattern[position]
                    if character == ord("}") and pending:
                        pending.pop()
                        position += 1
                    elif character == ord(",") and pending:
                        closing = brace_ends.get(pending.pop())
                        if closing is None:
                            return True
                        position = closing + 1
                    else:
                        if character != ord("/"):
                            globs.append(
                                b"/" + pattern[:end] + b"}" * len(openings) + b"*"
                            )
                        break
            try:
                with tempfile.TemporaryDirectory() as temporary_directory:
                    probe = Path(temporary_directory)
                    component = probe / os.fsdecode(actual)
                    component.mkdir()
                    (component / "source").touch()
                    arguments = [*command]
                    for glob in globs:
                        arguments.extend(["--glob", os.fsdecode(glob)])
                    arguments.extend(["--", "."])
                    result = subprocess.run(
                        arguments,
                        cwd=probe,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
            except (OSError, ValueError):
                return True
            return result.returncode != 1 or bool(result.stderr)

        def without_ignore_bom(contents: bytes) -> bytes:
            return re.sub(rb"\A(?:\xef\xbb\xbf)+", b"", contents)

        def reopens_scope_descendant(ignore: Path) -> bool:
            try:
                scope = tuple(
                    os.fsencode(part)
                    for part in selected.relative_to(ignore.parent).parts
                )
            except ValueError:
                return True
            for line in without_ignore_bom(ignore.read_bytes()).split(b"\n"):
                line = line.rstrip(b"\r")
                if not line.startswith(b"!"):
                    continue
                pattern = line[1:]
                if not pattern.endswith(b"\\ "):
                    pattern = pattern.rstrip(b" \t")
                if not pattern.endswith(b"/"):
                    continue
                anchored = pattern.startswith(b"/")
                pattern = pattern.rstrip(b"/").lstrip(b"/")
                if any(
                    value in pattern for value in (b"*", b"?", b"[", b"{", b"\\")
                ):
                    return True
                parts = tuple(pattern.split(b"/"))
                if (
                    len(parts) == 1
                    and not anchored
                    and (not scope or parts[0] != scope[-1])
                ) or (
                    len(parts) > len(scope) and parts[: len(scope)] == scope
                ):
                    return True
            return False

        reopened_scope_descendants = bool(exempt_gitignores) and any(
            reopens_scope_descendant(ignore) for ignore in ignore_files
        )

        def ignore_pattern_matches(components: tuple[bytes, ...], pattern: bytes) -> bool:
            if not components:
                return True

            def prefix_matches(actual: bytes, candidate: bytes) -> bool:
                pending = [(0, candidate)]
                seen: set[tuple[int, bytes]] = set()
                while pending:
                    offset, remaining = pending.pop()
                    state = (offset, remaining)
                    if state in seen:
                        continue
                    seen.add(state)
                    for index, character in enumerate(remaining):
                        if character in b"*?[\\/":
                            return True
                        if character == ord("{"):
                            depth = 1
                            separators: list[int] = []
                            escaped = False
                            character_class = False
                            first_class_character = False
                            for end in range(index + 1, len(remaining)):
                                current = remaining[end]
                                if character_class:
                                    if current == ord("]"):
                                        if first_class_character:
                                            first_class_character = False
                                        else:
                                            character_class = False
                                        continue
                                    if current == ord("/"):
                                        return True
                                    if first_class_character and current in (
                                        ord("!"),
                                        ord("^"),
                                    ):
                                        continue
                                    first_class_character = False
                                elif escaped:
                                    escaped = False
                                elif current == ord("\\"):
                                    escaped = True
                                elif current == ord("["):
                                    character_class = True
                                    first_class_character = True
                                elif current == ord("/"):
                                    return True
                                elif current == ord("{"):
                                    depth += 1
                                elif current == ord("}"):
                                    depth -= 1
                                    if depth:
                                        continue
                                    beginning = index + 1
                                    for separator in (*separators, end):
                                        pending.append(
                                            (
                                                offset,
                                                remaining[beginning:separator]
                                                + remaining[end + 1 :],
                                            )
                                        )
                                        beginning = separator + 1
                                    break
                                elif current == ord(",") and depth == 1:
                                    separators.append(end)
                            else:
                                return True
                            break
                        if offset == len(actual) or actual[offset] != character:
                            break
                        offset += 1
                    else:
                        return True
                return False

            def component_matches(actual: bytes, expected: bytes) -> bool:
                if any(value in expected for value in (b"\\", b"{", b"}", b"[")):
                    return ignore_component_matches(actual, expected)
                return fnmatch.fnmatchcase(actual, expected)

            pending = [(0, pattern)]
            seen: set[tuple[int, bytes]] = set()
            while pending:
                component_index, candidate = pending.pop()
                state = (component_index, candidate)
                if state in seen:
                    continue
                seen.add(state)
                if not prefix_matches(components[component_index], candidate):
                    continue
                braces: list[tuple[int, list[int], bool]] = []
                escaped = False
                character_class = False
                first_class_character = False
                for index, character in enumerate(candidate):
                    if character_class:
                        if character == ord("]"):
                            if first_class_character:
                                first_class_character = False
                            else:
                                character_class = False
                            continue
                        if character == ord("/"):
                            if not braces:
                                return True
                            opening, separators, _ = braces[-1]
                            braces[-1] = (opening, separators, True)
                        if first_class_character and character in (ord("!"), ord("^")):
                            continue
                        first_class_character = False
                    elif escaped:
                        escaped = False
                    elif character == ord("\\"):
                        escaped = True
                    elif character == ord("["):
                        character_class = True
                        first_class_character = True
                    elif character == ord("{"):
                        braces.append((index, [], False))
                    elif character == ord(",") and braces:
                        braces[-1][1].append(index)
                    elif character == ord("/") and braces:
                        opening, separators, _ = braces[-1]
                        braces[-1] = (opening, separators, True)
                    elif character == ord("/"):
                        if component_index == len(components):
                            return True
                        expected = candidate[:index]
                        if expected == b"**":
                            suffix = candidate[index + 1 :]
                            pending.append((component_index, suffix))
                            if component_index + 1 < len(components):
                                pending.append((component_index + 1, candidate))
                            else:
                                if reopened_scope_descendants:
                                    return True
                                while suffix.startswith(b"**/"):
                                    suffix = suffix[3:]
                                if b"/" not in suffix or any(
                                    value in suffix for value in (b"{", b"[", b"\\")
                                ):
                                    return True
                            break
                        if not component_matches(components[component_index], expected):
                            break
                        component_index += 1
                        if component_index == len(components):
                            return True
                        pending.append((component_index, candidate[index + 1 :]))
                        break
                    elif character == ord("}") and braces:
                        opening, separators, crosses_components = braces.pop()
                        if not crosses_components:
                            continue
                        if braces:
                            outer_opening, outer_separators, _ = braces[-1]
                            braces[-1] = (outer_opening, outer_separators, True)
                            continue
                        same_component = []
                        start = opening + 1
                        for separator in (*separators, index):
                            alternative = candidate[start:separator]
                            if b"/" in alternative:
                                pending.append(
                                    (
                                        component_index,
                                        candidate[:opening]
                                        + alternative
                                        + candidate[index + 1 :],
                                    )
                                )
                            elif prefix_matches(
                                components[component_index],
                                candidate[:opening] + alternative,
                            ):
                                same_component.append(alternative)
                            start = separator + 1
                        if same_component:
                            grouped = (
                                same_component[0]
                                if len(same_component) == 1
                                else b"{" + b",".join(same_component) + b"}"
                            )
                            pending.append(
                                (
                                    component_index,
                                    candidate[:opening] + grouped + candidate[index + 1 :],
                                )
                            )
                        break
                else:
                    if escaped or character_class or any(
                        crosses for _, _, crosses in braces
                    ):
                        return True
                    for actual, expected in zip(
                        components[component_index:],
                        candidate.split(b"/"),
                    ):
                        if expected == b"**":
                            return True
                        if not component_matches(actual, expected):
                            break
                    else:
                        return True
            return False

        recursive_scope_matches: dict[tuple[str, bytes], bool] = {}

        def recursive_ignore_matches(scope: str, pattern: bytes) -> bool:
            pattern = pattern.lstrip(b"/")
            key = scope, pattern
            if key in recursive_scope_matches:
                return recursive_scope_matches[key]
            try:
                with tempfile.TemporaryDirectory() as temporary_directory:
                    probe = Path(temporary_directory)
                    scoped = probe / scope
                    scoped.mkdir(parents=True)
                    (scoped / "source").touch()
                    result = subprocess.run(
                        [
                            *command,
                            "--glob",
                            os.fsdecode(b"/" + pattern + b"/**"),
                            "--",
                            ".",
                        ],
                        cwd=probe,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
            except (OSError, ValueError):
                return False
            matched = result.returncode == 0 and not result.stderr
            recursive_scope_matches[key] = matched
            return matched

        def scope_is_allowlisted(ignore: Path, allowlisted: bool) -> bool:
            try:
                components = tuple(
                    os.fsencode(part)
                    for part in selected.relative_to(ignore.parent).parts
                )
            except ValueError:
                return True
            scope = os.fsdecode(b"/".join(components))
            for line in without_ignore_bom(ignore.read_bytes()).split(b"\n"):
                line = line.rstrip(b"\r")
                if not line.startswith(b"!"):
                    if allowlisted:
                        deny = re.fullmatch(
                            rb"(/?[^!#\r\n][^\r\n]*?)/(?:\*\*/)*\*{1,2}[ \t]*",
                            line,
                        )
                        if deny is not None and recursive_ignore_matches(
                            scope, deny.group(1)
                        ):
                            allowlisted = False
                    continue
                raw_pattern = line[1:]
                if not raw_pattern.endswith(b"\\ "):
                    raw_pattern = raw_pattern.rstrip(b" \t")
                if raw_pattern.endswith(b"/"):
                    continue
                anchored = raw_pattern.startswith(b"/")
                pattern = re.sub(
                    rb"(\\+)/",
                    lambda escaped: (
                        escaped.group(1)[:-1] + b"/"
                        if len(escaped.group(1)) % 2
                        else escaped.group(0)
                    ),
                    raw_pattern,
                ).rstrip(b"/")
                if anchored:
                    pattern = pattern.lstrip(b"/")
                if not anchored and b"/" not in pattern:
                    # Basename rules can allowlist missing or untracked descendants.
                    allowlisted = True
                elif ignore_pattern_matches(components, pattern):
                    allowlisted = True
            return allowlisted

        preserve_allowlisted_scope = False
        if exempt_gitignores:
            for ignore in sorted(
                ignore_files,
                key=lambda path: (
                    IGNORE_FILE_NAMES.index(path.name),
                    len(path.parent.relative_to(repository).parts),
                ),
            ):
                preserve_allowlisted_scope = scope_is_allowlisted(
                    ignore, preserve_allowlisted_scope
                )

        batches: list[tuple[dict[str, str], set[bytes]]] = []

        for relative in requested:
            parts = PurePosixPath(os.fsdecode(relative)).parts
            prefixes = {
                filesystem_name_key("/".join(parts[: index + 1])): "/".join(parts[: index + 1])
                for index in range(len(parts))
            }
            for names, batch in batches:
                if all(names.get(folded, spelling) == spelling for folded, spelling in prefixes.items()):
                    names.update(prefixes)
                    batch.add(relative)
                    break
            else:
                batches.append((prefixes, {relative}))

        visible: set[bytes] = set()
        for _, batch in batches:
            with tempfile.TemporaryDirectory() as temporary_directory:
                temporary_root = Path(temporary_directory)
                probe = temporary_root / "inventory"
                probe.mkdir()
                external_ignores: list[tuple[int, int, int, Path]] = []

                def collides_with_candidates(relative: tuple[str, ...]) -> bool:
                    for candidate in batch:
                        pairs = tuple(
                            zip(PurePosixPath(os.fsdecode(candidate)).parts, relative)
                        )
                        if all(
                            filesystem_name_key(actual) == filesystem_name_key(synthetic)
                            for actual, synthetic in pairs
                        ) and any(actual != synthetic for actual, synthetic in pairs):
                            return True
                    return False

                isolate_ignores = any(
                    collides_with_candidates(
                        (*ignore.parent.relative_to(repository).parts, ignore.name)
                    )
                    for ignore in ignore_files
                ) or any(
                    collides_with_candidates(
                        (*directory.relative_to(repository).parts, name)
                    )
                    for directory in configured_excludes
                    for name in (".gitignore", ".ignore")
                )

                def install_ignore(
                    directory: Path,
                    name: str,
                    contents: bytes,
                    *,
                    prepend: bool = False,
                ) -> None:
                    relative = (*directory.relative_to(repository).parts, name)
                    if isolate_ignores:
                        if directory != repository:
                            prefix = os.fsencode(
                                "/".join(
                                    re.escape(part)
                                    for part in directory.relative_to(repository).parts
                                )
                            )
                            rebased = []
                            lines = without_ignore_bom(contents).split(b"\n")
                            for index, line in enumerate(lines):
                                terminated = index < len(lines) - 1
                                if terminated:
                                    line = line.removesuffix(b"\r")
                                if not line or line.startswith(b"#"):
                                    continue
                                negated = line.startswith(b"!")
                                pattern = line[1:] if negated else line
                                if not pattern.rstrip(b" ").strip(b"/"):
                                    continue
                                if pattern.startswith(b"/"):
                                    pattern = pattern[1:]
                                elif b"/" not in pattern.rstrip(b"/"):
                                    pattern = b"**/" + pattern
                                rebased.append(
                                    (b"!" if negated else b"")
                                    + b"/"
                                    + prefix
                                    + b"/"
                                    + pattern
                                    + (b"\n" if terminated else b"")
                                )
                            contents = b"".join(rebased)
                        position = len(external_ignores)
                        destination = temporary_root / f"ignore-{position}"
                        destination.write_bytes(contents)
                        priority = -1 if prepend else IGNORE_FILE_NAMES.index(name)
                        depth = len(directory.relative_to(repository).parts)
                        external_ignores.append((priority, depth, position, destination))
                        return

                    destination = probe.joinpath(*relative)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if prepend and destination.exists():
                        existing = without_ignore_bom(destination.read_bytes())
                        separator = b"" if not contents or contents.endswith(b"\n") else b"\n"
                        contents += separator + existing
                    destination.write_bytes(contents)

                def admit_gitlink_directories(
                    directory: Path,
                    contents: bytes,
                    *,
                    scope_only: bool = False,
                    reopen_scope: bool = False,
                ) -> bytes:
                    if not preserve_gitignore_descendants and not scope_only:
                        return contents
                    for owner, selected_root in exempt_gitignores:
                        if scope_only and selected_root != selected:
                            continue
                        if not (
                            directory.is_relative_to(owner)
                            and selected_root.is_relative_to(directory)
                            and directory != selected_root
                        ):
                            continue
                        parts = selected_root.relative_to(directory).parts
                        for index in range(len(parts)):
                            if contents and not contents.endswith(b"\n"):
                                contents += b"\n"
                            admitted = "/".join(re.escape(part) for part in parts[: index + 1])
                            if (
                                (scope_only or (reopen_scope and selected_root == selected))
                                and not preserve_allowlisted_scope
                            ):
                                scope = "/".join(parts[: index + 1])

                                def reopen_recursive(match: re.Match[bytes]) -> bytes:
                                    original = os.fsdecode(match.group(2)).lstrip("/")
                                    decoded = re.sub(
                                        r"\\(.)",
                                        lambda escaped: (
                                            f"[{escaped.group(1)}]"
                                            if escaped.group(1) in "*?["
                                            else escaped.group(1)
                                        ),
                                        original,
                                    )
                                    if not (
                                        any(
                                            fnmatch.fnmatchcase(scope, pattern)
                                            or fnmatch.fnmatchcase(
                                                scope, pattern.removeprefix("**/")
                                            )
                                            or pattern == admitted
                                            for pattern in (original, decoded)
                                        )
                                        or (
                                            b"{" in match.group(2)
                                            and recursive_ignore_matches(
                                                scope, match.group(2)
                                            )
                                        )
                                    ):
                                        return match.group(0)
                                    return (match.group(1) or b"") + match.group(2) + b"/"

                                contents = re.sub(
                                    rb"(?m)^(\A(?:\xef\xbb\xbf)+)?(/?[^!#\r\n][^\r\n]*?)/"
                                    rb"(?:\*\*/)*\*{1,2}[ \t]*(?=\r*$)",
                                    reopen_recursive,
                                    contents,
                                )
                            contents += os.fsencode(f"!/{admitted}/\n")
                    return contents

                for ignore in ignore_files:
                    contents = ignore.read_bytes()
                    if ignore.name == ".gitignore":
                        contents = admit_gitlink_directories(
                            ignore.parent, contents, reopen_scope=True
                        )
                    else:
                        contents = admit_gitlink_directories(
                            ignore.parent, contents, scope_only=True
                        )
                    install_ignore(ignore.parent, ignore.name, contents)
                for directory, contents in configured_excludes.items():
                    contents = admit_gitlink_directories(directory, contents)
                    install_ignore(directory, ".gitignore", contents, prepend=True)
                if default_excluded:
                    defaults = b"".join(
                        b"/" + re.escape(relative) + b"\n"
                        for relative in batch
                    )
                    install_ignore(repository, ".gitignore", defaults, prepend=True)
                for relative in batch:
                    destination = probe / os.fsdecode(relative)
                    if directories_only:
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.touch()
                result = run_ripgrep(
                    [
                        *(
                            command
                            if include_global_excludes or global_ignore is None
                            else command[:-2]
                        ),
                        *(
                            argument
                            for _, _, _, ignore in sorted(external_ignores)
                            for argument in ("--ignore-file", str(ignore))
                        ),
                        *(["--debug"] if directories_only else []),
                        "--",
                        ".",
                    ],
                    cwd=probe,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if result.returncode not in (0, 1):
                    detail = result.stderr.decode("utf-8", errors="replace").strip()
                    raise InventoryError(f"could not evaluate outer ignore rules: {detail}")
                if directories_only:
                    ignored = {
                        normalized(match.group(1)).removeprefix(b"./")
                        for line in result.stderr.splitlines()
                        if (match := re.search(rb": ignoring (.+): Ignore\(", line)) is not None
                    }
                    visible.update(
                        relative
                        for relative in batch
                        if not any(
                            relative == excluded or relative.startswith(excluded + b"/")
                            for excluded in ignored
                        )
                    )
                else:
                    visible.update(
                        normalized(relative).removeprefix(b"./")
                        for relative in result.stdout.split(b"\0")
                        if normalized(relative).removeprefix(b"./") in batch
                    )
        return visible

    environment = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_INDEX_FILE",
        "GIT_ICASE_PATHSPECS",
        "GIT_GLOB_PATHSPECS",
        "GIT_NAMESPACE",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["LC_ALL"] = "C"
    git = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.excludesFile={os.devnull}",
        "--literal-pathspecs",
    ]

    def run_git(
        arguments: list[str], *, directory: Path = repository, literal: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        command = git if literal else git[:-1]
        git_environment = environment if literal else environment.copy()
        if not literal:
            git_environment.pop("GIT_LITERAL_PATHSPECS", None)
        try:
            return subprocess.run(
                [*command, f"--work-tree={directory}", *arguments],
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=git_environment,
                check=False,
            )
        except OSError as error:
            raise InventoryError(f"could not run Git: {error}") from error

    ripgrep_global_directory: tempfile.TemporaryDirectory[str] | None = None

    def run_ripgrep(
        arguments: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal ripgrep_global_directory
        include_trusted_global = (
            global_ignore is not None
            and "--ignore-file-case-insensitive" in arguments
            and any(
                argument == "--ignore-file"
                and index + 1 < len(arguments)
                and arguments[index + 1] == str(global_ignore)
                for index, argument in enumerate(arguments)
            )
        )
        if include_trusted_global:
            if ripgrep_global_directory is None:
                ripgrep_global_directory = tempfile.TemporaryDirectory()
                root = Path(ripgrep_global_directory.name)
                defaults = root / "git"
                defaults.mkdir()
                (defaults / "ignore").write_bytes(global_ignore.read_bytes())
                (root / "gitconfig").write_bytes(b"")
            controlled_environment = environment.copy()
            controlled_environment["XDG_CONFIG_HOME"] = ripgrep_global_directory.name
            controlled_environment["GIT_CONFIG_GLOBAL"] = str(
                Path(ripgrep_global_directory.name) / "gitconfig"
            )
            controlled_environment["GIT_CONFIG_NOSYSTEM"] = "1"
            arguments = arguments.copy()
            arguments[arguments.index("--no-ignore-global")] = "--ignore-global"
            kwargs["env"] = controlled_environment
        return subprocess.run(arguments, **kwargs)

    def resolve_git_root(value: bytes) -> Path:
        root_path = value.removesuffix(b"\n")
        if os.name == "nt":
            root_path = root_path.removesuffix(b"\r")
        return Path(os.fsdecode(root_path)).resolve(strict=True)

    for ancestor in ancestors:
        if ancestor != repository and validated_metadata_directory(ancestor):
            raise InventoryError("--scope: Git metadata paths are not supported")
        reject_symbolic_ignore(ancestor)
        has_git_marker(ancestor)
    if selected.is_file():
        metadata = selected.stat(follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) in validated_metadata_files:
            raise InventoryError("--scope: Git metadata paths are not supported")

    def owns_git_root(value: bytes, expected: Path) -> bool:
        actual = resolve_git_root(value)
        return directory_identity(actual) == directory_identity(expected) and (
            actual.relative_to(repository).parts == expected.relative_to(repository).parts
        )

    worktree = (
        run_git(["rev-parse", "--show-toplevel"])
        if has_git_marker(repository)
        else None
    )
    if worktree is not None and worktree.returncode:
        detail = worktree.stderr.decode("utf-8", errors="replace").strip()
        if any(
            reason in detail.lower()
            for reason in (
                "not a git repository",
                "gitfile does not point to a valid repository",
                "invalid gitfile format",
            )
        ):
            worktree = None
        else:
            message = f"git rev-parse exited with status {worktree.returncode}"
            if detail:
                message = f"{message}: {detail}"
            raise InventoryError(message)

    if worktree is not None:
        try:
            valid_worktree = owns_git_root(worktree.stdout, repository)
        except (OSError, ValueError) as error:
            raise InventoryError(f"could not resolve Git worktree root: {error}") from error
        if not valid_worktree:
            worktree = None

    configuration_scopes = ["--global"]
    skip_system = environment.get("GIT_CONFIG_NOSYSTEM", "").strip().casefold()
    if skip_system in ("", "0", "false", "no", "off"):
        configuration_scopes.append("--system")
    configured_global_ignore: subprocess.CompletedProcess[bytes] | None = None
    for configuration_scope in configuration_scopes:
        try:
            configured_global_ignore = subprocess.run(
                [
                    "git",
                    "config",
                    configuration_scope,
                    "--includes",
                    "--path",
                    "--null",
                    "--get",
                    "core.excludesFile",
                ],
                cwd=repository if worktree is not None else Path(repository.anchor),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except FileNotFoundError as error:
            if worktree is not None:
                raise InventoryError(
                    f"could not inspect global Git exclusions: {error}"
                ) from error
            break
        except OSError as error:
            raise InventoryError(
                f"could not inspect global Git exclusions: {error}"
            ) from error
        if configured_global_ignore.returncode not in (0, 1):
            detail = configured_global_ignore.stderr.decode(
                "utf-8", errors="replace"
            ).strip()
            raise InventoryError(f"could not inspect global Git exclusions: {detail}")
        if configured_global_ignore.returncode == 0:
            break
    if configured_global_ignore is not None and configured_global_ignore.returncode == 0:
        global_ignore = Path(
            os.fsdecode(configured_global_ignore.stdout.removesuffix(b"\0"))
            or os.devnull
        )
        if not global_ignore.is_absolute():
            global_ignore = repository / global_ignore
            try:
                components = global_ignore.relative_to(repository).parts
            except ValueError:
                components = ()
            current = repository
            for component in components:
                if component == "..":
                    current = current.parent
                    continue
                current /= component
                try:
                    metadata = current.stat(follow_symlinks=False)
                except FileNotFoundError:
                    break
                if not current.is_relative_to(repository):
                    if (
                        not symbolic_metadata(metadata)
                        and stat.S_ISDIR(metadata.st_mode)
                        and (metadata.st_dev, metadata.st_ino) == repository_identity
                    ):
                        current = repository
                    continue
                if symbolic_metadata(metadata):
                    raise InventoryError("symbolic ignore files are not supported")
    else:
        configured_home = environment.get("XDG_CONFIG_HOME")
        config_home = Path(configured_home) if configured_home else Path.home() / ".config"
        global_ignore = config_home / "git" / "ignore"
    selected_git_root = next(
        (
            ancestor
            for ancestor in reversed(ancestors)
            if directory_identity(ancestor) in ignore_case_roots
        ),
        None,
    )
    if (
        selected_git_root is not None
        and ignore_case_roots[directory_identity(selected_git_root)]
    ):
        command.append("--ignore-file-case-insensitive")
    try:
        ignore_metadata = global_ignore.stat()
    except FileNotFoundError:
        global_ignore = None
    except OSError as error:
        raise InventoryError(f"could not inspect global Git exclusions: {error}") from error
    else:
        if not stat.S_ISREG(ignore_metadata.st_mode):
            try:
                null_ignore = global_ignore.samefile(os.devnull)
            except OSError:
                null_ignore = False
            if not null_ignore:
                raise InventoryError(
                    f"global Git exclusions must be a regular file: {global_ignore}"
                )
            global_ignore = None
        else:
            try:
                with global_ignore.open("rb"):
                    pass
            except OSError as error:
                raise InventoryError(
                    f"could not read global Git exclusions: {error}"
                ) from error
            command.extend(["--ignore-file", str(global_ignore)])

    scoped_files: dict[Path, list[Path]] = {}
    inspected_directories: set[tuple[int, int]] = set()
    if selected.is_dir():
        pending = [selected]
        while pending:
            visibility_groups: dict[tuple[tuple[str, ...], ...], list[Path]] = {}
            for directory in pending:
                if validated_metadata_directory(directory):
                    metadata_aliases.add(directory.relative_to(repository).parts)
                    continue
                identity = directory_identity(directory)
                if identity in inspected_directories:
                    continue
                inspected_directories.add(identity)
                reject_symbolic_ignore(directory)
                entries = list(directory.iterdir())
                metadata_aliases.update(
                    entry.relative_to(repository).parts
                    for entry in entries
                    if (
                        entry.name != ".git" and git_metadata_path(directory, entry.name)
                    )
                    or validated_metadata_directory(entry)
                )
                children = [
                    entry
                    for entry in entries
                    if nonsymbolic_directory(entry)
                    and not git_metadata_path(directory, entry.name)
                    and not validated_metadata_directory(entry)
                ]
                if scope not in (".", "./"):
                    scoped_files[directory] = [
                        entry
                        for entry in entries
                        if not git_metadata_path(directory, entry.name)
                        and not entry.is_symlink()
                        and entry.is_file()
                    ]
                if children:
                    context: list[tuple[str, ...]] = []
                    current = directory
                    while True:
                        relative = current.relative_to(repository).parts
                        context.extend(
                            (*relative, name)
                            for name in IGNORE_FILE_NAMES
                            if (current / name).is_file()
                        )
                        if has_git_marker(current):
                            context.append((*relative, ".git"))
                        if current == repository:
                            break
                        current = current.parent
                    visibility_groups.setdefault(tuple(context), []).extend(children)
            pending = []
            for children in visibility_groups.values():
                visible = visible_to_outer_ignores(children[0], children, directories_only=True)
                for entry in children:
                    if normalized(os.fsencode(entry.relative_to(repository).as_posix())) not in visible:
                        continue
                    if has_git_marker(entry):
                        candidate = run_git(["rev-parse", "--show-toplevel"], directory=entry)
                        if candidate.returncode == 0:
                            try:
                                if owns_git_root(candidate.stdout, entry):
                                    discovered_roots[directory_identity(entry)] = entry
                            except (OSError, ValueError):
                                pass
                    pending.append(entry)

    def reconciled_nested_rows(
        root: Path,
        nested_scope: str,
        previous: set[bytes],
        rendered_prefix: bytes,
    ) -> set[bytes]:
        nested_rows = ripgrep_inventory(
            root,
            nested_scope,
            ignore_case=ignore_case_roots[directory_identity(root)],
        )
        candidates = [
            root / os.fsdecode(row.removesuffix(b"\n")) for row in nested_rows
        ]
        visible = visible_to_outer_ignores(
            root, candidates, include_global_excludes=False
        )
        root_prefix = os.fsencode(root.relative_to(repository).as_posix()) + b"/"
        result = {
            rendered_prefix + row.removeprefix(b"./")
            for row in nested_rows
            if normalized(
                root_prefix + row.removeprefix(b"./").removesuffix(b"\n")
            ) in visible
        }
        omitted = [
            repository / os.fsdecode(row.removesuffix(b"\n"))
            for row in previous
            if row not in result
        ]
        if omitted:
            overrides = visible_to_outer_ignores(
                root,
                omitted,
                include_global_excludes=False,
                default_excluded=True,
            )
            result.update(
                row
                for row in previous
                if normalized(row.removeprefix(b"./").removesuffix(b"\n"))
                in overrides
            )
        return result

    rows = ripgrep_inventory(repository, scope)
    if selected == repository:
        roots = sorted(
            discovered_roots.values(),
            key=lambda path: len(path.relative_to(repository).parts),
        )
        for nested in roots:
            nested_ignore_case = ignore_case_roots.get(
                directory_identity(nested), False
            )
            parent = next(
                (
                    root
                    for root in reversed(roots)
                    if root != nested and nested.is_relative_to(root)
                ),
                repository,
            )
            parent_ignore_case = ignore_case_roots.get(
                directory_identity(parent), False
            )
            if nested_ignore_case == parent_ignore_case and global_ignore is None:
                continue
            relative = nested.relative_to(repository).as_posix()
            prefix = os.fsencode(f"./{relative}/")
            previous = {row for row in rows if row.startswith(prefix)}
            rows.difference_update(previous)
            rows.update(reconciled_nested_rows(nested, ".", previous, prefix))
    visible_directories = set(ancestors)
    for row in rows:
        current = (repository / os.fsdecode(row.removesuffix(b"\n"))).parent
        while current != repository:
            visible_directories.add(current)
            current = current.parent
    for directory in sorted(visible_directories):
        reject_symbolic_ignore(directory)
        if directory != repository and has_git_marker(directory):
            discovered_roots[directory_identity(directory)] = directory
    if selected.is_dir() and scope not in (".", "./") and not ripgrep_inventory(
        repository, scope, directory_guard=True
    ):
        rows.clear()
    elif scope not in (".", "./"):
        prefix = b"./" if scope.startswith("./") else b""
        for candidates in scoped_files.values():
            if not candidates:
                continue
            visible = visible_to_outer_ignores(candidates[0], candidates)
            for candidate in candidates:
                relative = normalized(os.fsencode(candidate.relative_to(repository).as_posix()))
                if b"\n" in relative or b"\r" in relative:
                    raise InventoryError("line separators are not supported in inventory paths")
                row = prefix + relative + b"\n"
                if relative in visible:
                    rows.add(row)
                else:
                    rows.discard(row)

    if (
        selected.is_dir()
        and selected != repository
        and selected_git_root is not None
        and selected_git_root != repository
        and global_ignore is not None
    ):
        nested_scope = selected.relative_to(selected_git_root).as_posix() or "."
        nested_prefix = os.fsencode(
            selected_git_root.relative_to(repository).as_posix()
        ) + b"/"
        rendered_prefix = (b"./" if scope.startswith("./") else b"") + nested_prefix
        rows = reconciled_nested_rows(
            selected_git_root, nested_scope, rows, rendered_prefix
        )

    if worktree is not None or discovered_roots:
        prefix = b"./" if scope == "." or scope.startswith("./") else b""
        listed: list[list[bytes]] = [[], []]
        cached_by_root: dict[tuple[int, int], tuple[Path, list[bytes]]] = {}

        def validated_git_path(relative: bytes, root: Path = repository) -> bytes:
            portable = normalized(relative)
            components = portable.removesuffix(b"/").split(b"/")
            path = Path(os.fsdecode(portable))
            if (
                path.is_absolute()
                or path.drive
                or not (root / path).is_relative_to(root)
                or any(component in (b"", b".", b"..") for component in components)
            ):
                raise InventoryError("out-of-scope Git inventory paths are not supported")
            current = root
            for component in path.parts[:-1]:
                current /= component
                try:
                    metadata = current.stat(follow_symlinks=False)
                except OSError:
                    break
                if symbolic_metadata(metadata):
                    raise InventoryError("symbolic Git inventory paths are not supported")
                if not stat.S_ISDIR(metadata.st_mode):
                    break
            return relative

        def listed_paths(index: int) -> Iterator[bytes]:
            for chunk in listed[index]:
                for relative in chunk.split(b"\0"):
                    if not relative:
                        continue
                    if b"\n" in relative or b"\r" in relative:
                        raise InventoryError("line separators are not supported in inventory paths")
                    yield validated_git_path(relative)

        if worktree is not None:
            for index, arguments in enumerate(
                (["--cached"], ["--others", "--exclude-standard"])
            ):
                result = run_git(["ls-files", "--sparse", *arguments, "-z", "--", scope])
                if result.returncode:
                    detail = result.stderr.decode("utf-8", errors="replace").strip()
                    message = f"git ls-files exited with status {result.returncode}"
                    if detail:
                        message = f"{message}: {detail}"
                    raise InventoryError(message)
                listed[index].append(result.stdout)
                if index == 0:
                    cached_by_root[directory_identity(repository)] = (
                        repository,
                        [relative for relative in result.stdout.split(b"\0") if relative],
                    )

        def visible_nested_root(root: Path) -> bool:
            selected_parts = selected.relative_to(repository).parts
            root_parts = root.relative_to(repository).parts
            shared_depth = min(len(selected_parts), len(root_parts))
            if selected_parts[:shared_depth] != root_parts[:shared_depth]:
                return False
            selected_ancestor = (
                selected
                if len(selected_parts) == shared_depth
                else selected.parents[len(selected_parts) - shared_depth - 1]
            )
            root_ancestor = (
                root
                if len(root_parts) == shared_depth
                else root.parents[len(root_parts) - shared_depth - 1]
            )
            return directory_identity(selected_ancestor) == directory_identity(root_ancestor)

        nested_roots = {
            identity: root
            for identity, root in discovered_roots.items()
            if visible_nested_root(root)
        }
        current = selected if selected.is_dir() else selected.parent
        while current != repository:
            if has_git_marker(current):
                nested_roots[directory_identity(current)] = current
            current = current.parent
        for index in range(len(listed)):
            for relative in listed_paths(index):
                candidate = repository / os.fsdecode(relative)
                current = candidate if nonsymbolic_directory(candidate) else candidate.parent
                while current != repository:
                    if index != 0 and directory_identity(current) not in inspected_directories:
                        current = current.parent
                        continue
                    if nonsymbolic_directory(current) and has_git_marker(current):
                        try:
                            discovered = current.resolve(strict=True)
                            discovered.relative_to(repository)
                        except (OSError, ValueError):
                            break
                        if index == 0 or visible_nested_root(discovered):
                            nested_roots[directory_identity(discovered)] = discovered
                    current = current.parent

        pending_roots = sorted(nested_roots.values())
        inspected_roots: dict[tuple[int, int], Path] = {}
        while pending_roots:
            nested = pending_roots.pop(0)
            nested_identity = directory_identity(nested)
            if nested_identity in inspected_roots:
                continue
            nested_worktree = run_git(
                ["rev-parse", "--show-toplevel"], directory=nested
            )
            if nested_worktree.returncode:
                detail = nested_worktree.stderr.decode("utf-8", errors="replace").strip()
                if any(
                    reason in detail.lower()
                    for reason in (
                        "not a git repository",
                        "gitfile does not point to a valid repository",
                        "invalid gitfile format",
                    )
                ):
                    continue
                raise InventoryError(
                    f"nested git rev-parse exited with status {nested_worktree.returncode}: {detail}"
                )
            try:
                if not owns_git_root(nested_worktree.stdout, nested):
                    continue
            except (OSError, ValueError):
                continue
            inspected_roots[nested_identity] = nested
            try:
                nested_scope = selected.relative_to(nested).as_posix() or "."
            except ValueError:
                nested_scope = "."
            nested_prefix = os.fsencode(nested.relative_to(repository).as_posix()) + b"/"
            for index, arguments in enumerate(
                (["--cached"], ["--others", "--exclude-standard"])
            ):
                result = run_git(
                    ["ls-files", "--sparse", *arguments, "-z", "--", nested_scope],
                    directory=nested,
                )
                if result.returncode:
                    detail = result.stderr.decode("utf-8", errors="replace").strip()
                    raise InventoryError(
                        f"nested git ls-files exited with status {result.returncode}: {detail}"
                    )
                listed[index].append(
                    b"".join(
                        nested_prefix + relative + b"\0"
                        for relative in result.stdout.split(b"\0")
                        if relative
                    )
                )
                if index == 0:
                    cached_by_root[nested_identity] = (
                        nested,
                        [relative for relative in result.stdout.split(b"\0") if relative],
                    )
                for relative in result.stdout.split(b"\0"):
                    if not relative:
                        continue
                    validated_git_path(relative, nested)
                    candidate = nested / os.fsdecode(relative)
                    if not nonsymbolic_directory(candidate):
                        continue
                    if not has_git_marker(candidate):
                        continue
                    try:
                        discovered = candidate.resolve(strict=True)
                        discovered.relative_to(repository)
                    except (OSError, ValueError):
                        continue
                    if directory_identity(discovered) not in inspected_roots:
                        pending_roots.append(discovered)

        if scope not in (".", "./"):
            for identity, (root, _) in list(cached_by_root.items()):
                tracked = run_git(["ls-files", "--sparse", "--cached", "-z"], directory=root)
                if tracked.returncode:
                    detail = tracked.stderr.decode("utf-8", errors="replace").strip()
                    raise InventoryError(
                        f"git ls-files exited with status {tracked.returncode}: {detail}"
                    )
                cached_by_root[identity] = (
                    root,
                    [relative for relative in tracked.stdout.split(b"\0") if relative],
                )
        recorded = {normalized(row.removesuffix(b"\n")) for row in rows}
        directory_entries: dict[tuple[int, int], dict[bytes, list[Path]]] = {}

        def indexed_name_key(value: str) -> bytes:
            return os.fsencode(filesystem_name_key(value))

        selected_parts = tuple(
            os.fsencode(part) for part in selected.relative_to(repository).parts
        )
        selected_is_directory = selected.is_dir()

        def exact_descendant(candidate: Path, parent: Path) -> bool:
            candidate_parts = candidate.relative_to(repository).parts
            parent_parts = parent.relative_to(repository).parts
            return candidate_parts[: len(parent_parts)] == parent_parts

        def tracked_gitlink(owner: Path, nested: Path, indexed_paths: set[bytes]) -> bool:
            relative = nested.relative_to(owner)
            if os.fsencode(relative.as_posix()) in indexed_paths:
                return True
            for indexed in indexed_paths:
                components = PurePosixPath(os.fsdecode(indexed)).parts
                if len(components) != len(relative.parts):
                    continue
                parent = owner
                for indexed_name, materialized in zip(components, relative.parts):
                    if indexed_name != materialized:
                        try:
                            expected = (parent / indexed_name).stat(follow_symlinks=False)
                            actual = (parent / materialized).stat(follow_symlinks=False)
                        except OSError:
                            break
                        if symbolic_metadata(expected) or symbolic_metadata(actual) or (
                            expected.st_dev,
                            expected.st_ino,
                        ) != (actual.st_dev, actual.st_ino):
                            break
                    parent /= materialized
                else:
                    return True
            return False

        tracked_gitlinks = []
        for owner, _tracked_paths in cached_by_root.values():
            staged = run_git(["ls-files", "--sparse", "--stage", "-z"], directory=owner)
            if staged.returncode:
                detail = staged.stderr.decode("utf-8", errors="replace").strip()
                raise InventoryError(f"git ls-files --stage exited with status {staged.returncode}: {detail}")
            indexed_paths = {
                path
                for record in staged.stdout.split(b"\0")
                if record
                and (parts := record.partition(b"\t"))[1]
                and (header := parts[0].split())
                and len(header) == 3
                and header[0] == b"160000"
                and header[2] in (b"0", b"1", b"2", b"3")
                for path in (parts[2],)
            }
            tracked_gitlinks.extend(
                (owner, nested)
                for nested in inspected_roots.values()
                if nested != owner
                and exact_descendant(nested, owner)
                and tracked_gitlink(owner, nested, indexed_paths)
            )
        def tracked_variants(root: Path, relative: bytes) -> Iterator[Path]:
            components = PurePosixPath(os.fsdecode(relative)).parts
            if not components or any(part in (".", "..") for part in components):
                return
            root_parts = tuple(os.fsencode(part) for part in root.relative_to(repository).parts)
            indexed_parts = root_parts + tuple(os.fsencode(part) for part in components)
            if (not selected_is_directory and len(indexed_parts) != len(selected_parts)) or (
                selected_is_directory and len(indexed_parts) <= len(selected_parts)
            ):
                return
            for index, requested in enumerate(selected_parts):
                indexed = indexed_parts[index]
                if indexed == requested:
                    continue
                if index < len(root_parts):
                    return

            def descend(parent: Path, index: int) -> list[Path]:
                try:
                    parent_identity = directory_identity(parent)
                except OSError:
                    return []
                if parent_identity not in directory_entries:
                    grouped: dict[bytes, list[Path]] = {}
                    try:
                        with os.scandir(parent) as entries:
                            for entry in entries:
                                if not git_metadata_path(
                                    parent, entry.name
                                ) and not validated_metadata_directory(parent / entry.name):
                                    grouped.setdefault(indexed_name_key(entry.name), []).append(
                                        parent / entry.name
                                    )
                    except OSError:
                        return []
                    directory_entries[parent_identity] = grouped
                component = components[index]
                variants = directory_entries[parent_identity].get(
                    indexed_name_key(component), []
                )
                if not variants:
                    try:
                        expected = (parent / component).stat(follow_symlinks=False)
                    except OSError:
                        return []
                    if symbolic_metadata(expected):
                        return []
                    try:
                        addressed = (parent / component).resolve(strict=True)
                    except OSError:
                        return []
                    variants = [
                        candidate
                        for candidate in directory_entries[parent_identity].get(
                            indexed_name_key(addressed.name), []
                        )
                        if candidate.name == addressed.name
                    ]
                selected_index = len(root_parts) + index
                if selected_index < len(selected_parts):
                    requested = os.fsdecode(selected_parts[selected_index])
                    variants = [candidate for candidate in variants if candidate.name == requested]
                exact = [candidate for candidate in variants if candidate.name == component]
                alternatives = [
                    candidate
                    for candidate in variants
                    if candidate.name != component
                ]
                for group in (exact, alternatives):
                    matches: list[Path] = []
                    for candidate in group:
                        try:
                            metadata = candidate.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if symbolic_metadata(metadata):
                            continue
                        if candidate.name != component:
                            try:
                                expected = (parent / component).stat(follow_symlinks=False)
                            except OSError:
                                continue
                            if symbolic_metadata(expected) or (
                                metadata.st_dev,
                                metadata.st_ino,
                            ) != (expected.st_dev, expected.st_ino):
                                continue
                        if index + 1 < len(components):
                            if not stat.S_ISDIR(metadata.st_mode):
                                continue
                            matches.extend(descend(candidate, index + 1))
                        elif stat.S_ISREG(metadata.st_mode):
                            matches.append(candidate)
                    if matches:
                        return matches
                return []

            for candidate in descend(root, 0):
                try:
                    resolved = candidate.resolve(strict=True)
                    resolved.relative_to(repository)
                except (OSError, ValueError):
                    continue
                candidate_parts = tuple(
                    os.fsencode(part) for part in candidate.relative_to(repository).parts
                )
                if selected_is_directory:
                    if candidate_parts[: len(selected_parts)] != selected_parts:
                        continue
                elif candidate_parts != selected_parts:
                    continue
                yield candidate

        for root, tracked_paths in cached_by_root.values():
            candidates = [
                candidate
                for relative in tracked_paths
                for candidate in tracked_variants(root, relative)
            ]
            outer_visible = (
                visible_to_outer_ignores(
                    root, candidates, include_global_excludes=False
                )
                if root != repository and selected_is_directory
                else None
            )
            gitlink_groups: dict[tuple[tuple[Path, Path], ...], list[Path]] = {}
            scope_exemptions: tuple[tuple[Path, Path], ...] = ()
            if outer_visible is not None:
                if selected != repository and (
                    selected == root or exact_descendant(selected, root)
                ):
                    selected_path = normalized(
                        os.fsencode(selected.relative_to(repository).as_posix())
                    )
                    selected_visible = visible_to_outer_ignores(
                        selected, [selected], directories_only=True
                    )
                    candidate_exemption = ((repository, selected),)
                    if (
                        (
                            selected_path not in selected_visible
                            or any(
                                normalized(
                                    os.fsencode(candidate.relative_to(repository).as_posix())
                                )
                                not in outer_visible
                                for candidate in candidates
                            )
                        )
                        and selected_path in visible_to_outer_ignores(
                            selected,
                            [selected],
                            directories_only=True,
                            exempt_gitignores=candidate_exemption,
                        )
                        and selected_path in visible_to_outer_ignores(
                            selected,
                            [selected],
                            directories_only=True,
                            configured_excludes_only=True,
                        )
                    ):
                        scope_exemptions = candidate_exemption
                for candidate in candidates:
                    exemptions = tuple(
                        (owner, gitlink)
                        for owner, gitlink in tracked_gitlinks
                        if exact_descendant(candidate, gitlink)
                    )
                    exemptions += scope_exemptions
                    if exemptions:
                        gitlink_groups.setdefault(exemptions, []).append(candidate)
            gitlink_visible = {
                relative
                for exemptions, linked_candidates in gitlink_groups.items()
                for relative in visible_to_outer_ignores(
                    root,
                    linked_candidates,
                    exempt_gitignores=exemptions,
                    preserve_gitignore_descendants=True,
                    include_global_excludes=False,
                )
            }
            for candidate in candidates:
                relative = os.fsencode(candidate.relative_to(repository).as_posix())
                if (
                    outer_visible is not None
                    and normalized(relative) not in outer_visible
                    and normalized(relative) not in gitlink_visible
                ):
                    continue
                relative_path = prefix + relative
                key = normalized(relative_path)
                if key not in recorded:
                    rows.add(relative_path + b"\n")
                    recorded.add(key)

    metadata_inventory_directories: dict[Path, bool] = {}

    def metadata_inventory_row(row: bytes) -> bool:
        relative = Path(os.fsdecode(row.removesuffix(b"\n")))
        if any(relative.parts[: len(alias)] == alias for alias in metadata_aliases):
            return True
        try:
            metadata = (repository / relative).stat(follow_symlinks=False)
        except OSError:
            return False
        if (metadata.st_dev, metadata.st_ino) in validated_metadata_files:
            return True
        current = (repository / relative).parent
        inspected: list[Path] = []
        while current != repository:
            if current in metadata_inventory_directories:
                excluded = metadata_inventory_directories[current]
                break
            inspected.append(current)
            if validated_metadata_directory(current):
                excluded = True
                break
            current = current.parent
        else:
            excluded = False
        for directory in inspected:
            metadata_inventory_directories[directory] = excluded
        return excluded

    rows = sorted(row for row in rows if not metadata_inventory_row(row))

    return write_inventory(output, rows)


def generate_diff_in_scope_files(
    repository: Path,
    base: str,
    head: str,
    mode: str,
    output: Path,
) -> int:
    """Reuse the existing diff selection without generating previews or duplicate worklists."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from generate_rank_input import git_changed_paths, path_is_excluded
    from rank_preview import (
        DEFAULT_PREVIEW_BYTES,
        TEXT_CODE_EXTENSIONS,
        is_binary_sample,
        preview_for,
    )
    from workbench_target import git_blob_bytes

    rows: list[bytes] = []
    try:
        changed = git_changed_paths(repository, base, head, mode)
        eligible = [
            (path, status)
            for path, status in changed
            if not path_is_excluded(path.relative_to(repository))
            and path.suffix.lower() in TEXT_CODE_EXTENSIONS
        ]
        revision_paths = [
            path.relative_to(repository)
            for path, status in eligible
            if mode == "revisions" and status != "D"
        ]
        revision_blobs = dict(
            zip(
                revision_paths,
                git_blob_bytes(
                    repository,
                    [f"{head}:{path.as_posix()}" for path in revision_paths],
                ),
            )
        )

        for path, status in eligible:
            relative = path.relative_to(repository)
            if status != "D":
                if mode == "revisions":
                    contents = revision_blobs[relative]
                    if contents is None:
                        raise InventoryError(
                            f"could not read committed diff blob: {head}:{relative.as_posix()}"
                        )
                    if is_binary_sample(contents):
                        continue
                elif (
                    path.is_symlink()
                    or not path.is_file()
                    or preview_for(path, DEFAULT_PREVIEW_BYTES)[1]
                ):
                    continue
            relative_path = relative.as_posix()
            if "\n" in relative_path or "\r" in relative_path:
                raise InventoryError(
                    "Git changes contain a path that cannot fit in the file inventory"
                )
            rows.append(f"{relative_path}\n".encode())
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None)
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        message = detail.strip() if isinstance(detail, str) and detail.strip() else str(error)
        raise InventoryError(f"could not resolve the selected Git changes: {message}") from error

    return write_inventory(output, sorted(set(rows)))


def write_inventory(output: Path, rows: list[bytes]) -> int:
    """Replace a complete inventory atomically, keeping failures from corrupting the old one."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.writelines(rows)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--scope", required=True, help="File or directory within the repository.")
    parser.add_argument("--out", required=True, help="Destination for the file inventory.")
    parser.add_argument("--diff-base", help="Authoritative Git base for a changed-file inventory.")
    parser.add_argument("--diff-head", default="HEAD", help="Authoritative Git head revision.")
    parser.add_argument(
        "--diff-mode",
        choices=("revisions", "local-patch"),
        default="revisions",
        help="Use committed revisions or the current staged and unstaged patch.",
    )
    args = parser.parse_args()

    try:
        repository = resolve_repository(args.repo)
        scope = resolve_scope(repository, args.scope)
        output = resolve_output(args.out)
        if args.diff_base is None:
            count = generate_in_scope_files(repository, scope, output)
        elif scope not in (".", "./"):
            raise InventoryError("--scope: diff scans must use the repository root")
        else:
            count = generate_diff_in_scope_files(
                repository,
                args.diff_base,
                args.diff_head,
                args.diff_mode,
                output,
            )
    except (OSError, ValueError) as error:
        print(f"generate_in_scope_files: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(f"Recorded {count} in-scope files.")


if __name__ == "__main__":
    main()
