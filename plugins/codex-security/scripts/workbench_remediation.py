"""Durable remediation state transitions for the Codex Security workbench."""

from __future__ import annotations

import argparse
import codecs
import hashlib
import io
import os
import re
import sqlite3
import sys
from collections.abc import Callable
from contextlib import ExitStack, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    MissingScanLocalFileError,
    _open_scan_local_directory,
    _open_verified_scan_directory,
    _read_scan_local_json_bytes,
    _read_sealed_scan,
    scan_local_file_version,
    scan_root_identity,
    stage_scan_local_bytes,
)
from posix_scan_local_files import managed_fd
from workbench_constants import CLAIM_LEASE_SECONDS, DELIVERED_ACTION_LEASE_SECONDS
from workbench_target import git_command, git_output
from workbench_validation import optional_text, require_occurrence, require_uuid

COMMANDS = {
    "request-finding-remediation",
    "request-finding-remediation-action",
    "claim-finding-remediation-resend",
    "mark-finding-remediation-delivered",
    "release-finding-remediation-claim",
    "cancel-finding-remediation-request",
    "set-finding-remediation",
}
SCAN_STATUS_ERROR = "Remediation is available only for successfully completed scans."


def require_available(connection: sqlite3.Connection, args: Any, require_scan: Any) -> None:
    if args.command not in COMMANDS:
        return
    occurrence = require_occurrence(connection, args.occurrence_id)
    if require_scan(connection, occurrence["scan_id"])["status"] != "complete":
        raise SystemExit(SCAN_STATUS_ERROR)


def require_request(
    connection: sqlite3.Connection, request_id: str, occurrence: sqlite3.Row
) -> sqlite3.Row:
    current = connection.execute(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if current is None or current["occurrence_id"] != occurrence["id"]:
        raise SystemExit("Codex Security finding remediation request not found.")
    return current


_HUNK_HEADER = re.compile(rb"@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@")
_QUOTED_GIT_PATH = rb'"((?:[^"\\]|\\(?:[abfnrtv"\\]|[0-3][0-7]{2}))*)"'
_SUBMODULE_SUMMARY_END = re.compile(
    rb" (?:contains (?:modified|untracked) content|"
    rb"[0-9a-f]+\.{2,3}[0-9a-f]+(?: \([a-z ]+\):?|:))$"
)
_SUBMODULE_ERROR = (
    "A remediation patch cannot update Git submodules. Regenerate without gitlink changes."
)


def _git_path(field: bytes) -> bytes:
    if quoted := re.match(_QUOTED_GIT_PATH + rb"(?:\t|$)", field):
        return codecs.escape_decode(quoted[1])[0]
    return field.partition(b"\t")[0]


def _matches_git_paths(header: bytes, old_field: bytes, new_field: bytes) -> bool:
    old, new = _git_path(old_field), _git_path(new_field)
    # Git strips one component from each path. Unquoted paths can contain
    # spaces, so use the known preimage to locate the separator.
    if quoted := re.match(_QUOTED_GIT_PATH + rb"(?= )", header):
        split = quoted.end()
    elif quoted := re.search(rb" " + _QUOTED_GIT_PATH + rb"$", header):
        split = quoted.start()
    elif old == b"/dev/null" and header.endswith(b" " + new):
        split = len(header) - len(new) - 1
    elif header.count(b" ") == 1:
        split = header.index(b" ")
    else:
        # On a creation Git repeats the destination on the left of the header.
        expected = new if old == b"/dev/null" else old
        prefix, slash, suffix = expected.partition(b"/")
        split = header.find(b"/") + 1 + len(suffix) if slash else len(prefix)
    if split < 0 or header[split : split + 1] != b" ":
        return False
    for path, field in ((header[:split], old), (header[split + 1 :], new)):
        if field != b"/dev/null" and _git_path(path).split(b"/", 1)[-1] != field.split(b"/", 1)[-1]:
            return False
    return True


def _patch_file_sections(patch: bytes, incomplete: str) -> tuple[bytes, int]:
    mail = re.match(rb"From (?:[0-9a-f]{40}|[0-9a-f]{64}) Mon Sep 17 00:00:00 2001\r?\n", patch)
    if mail:
        first = re.search(rb"(?m)^diff --git [^\n]+\n", patch)
        if first:
            start = first.start()
            # A commit message can quote a Git header. Look for format-patch's
            # diffstat before the first hunk, where a deleted "--" can also
            # look like the separator. Each run of indented lines is scanned once.
            hunk = re.compile(rb"(?m)^@@ -").search(patch, start)
            diffstat = re.compile(
                rb"(?m)^---\r?\n(?: [^\n]*\n)+\r?\n(?=diff --git |Submodule )"
            ).search(patch, 0, hunk.start() if hunk else len(patch))
            if diffstat:
                start = diffstat.end()
            else:
                # With --no-stat Git can retain a quoted header as the preimage of
                # the first change. Ignore it only for the same in-place file edit.
                file = re.compile(
                    rb"(?m)^diff --git [^\n]+\n(?=index |--- |@@ |old mode|new mode|new file|deleted file"
                    rb"|(?:dis)?similarity index|(?:rename|copy) |GIT binary patch|Binary files |Files |Only in )"
                ).search(patch, start)
                if (
                    file
                    and file[0] == first[0]
                    and patch.endswith((b"\n\n", b"\n\r\n"), 0, file.start())
                    and re.compile(
                        rb"(?:index [0-9a-f]+\.\.[0-9a-f]+ 100(?:644|755)|"
                        rb"old mode 100(?:644|755)\r?\nnew mode 100(?:644|755)\r?\n"
                        rb"index [0-9a-f]+\.\.[0-9a-f]+)\r?\n(?:--- |GIT binary patch)"
                    ).match(patch, file.end())
                ):
                    start = file.start()
                elif not patch.endswith((b"\n\n", b"\n\r\n"), 0, start):
                    # A leading submodule summary runs directly into the next file header.
                    summary = re.compile(rb"(?m)^Submodule ").search(patch, 0, start)
                    if summary:
                        start = summary.start()
            patch = patch[start:]

    sections = old_lines = new_lines = 0
    git_paths = b""
    pending_paths = None
    submodule_summary = False
    expect_hunk = False
    stream = io.BytesIO(patch)
    for raw_line in stream:
        line = raw_line.removesuffix(b"\n").removesuffix(b"\r")
        if old_lines or new_lines:
            if line.startswith(b"\\ "):  # No newline at end of file
                continue
            prefix = line[:1]
            if prefix in (b"", b" ", b"-"):
                old_lines -= 1
            if prefix in (b"", b" ", b"+"):
                new_lines -= 1
            if prefix not in (b"", b" ", b"+", b"-") or old_lines < 0 or new_lines < 0:
                raise SystemExit(incomplete)
            expect_hunk = True
            continue
        if expect_hunk and line.startswith(b"\\ "):  # No newline at end of file
            continue
        hunk = _HUNK_HEADER.match(line)
        if expect_hunk and not hunk and re.match(rb"@@ -(?:[0-9]|$)", line):
            raise SystemExit(incomplete)
        expect_hunk = bool(sections) and line.startswith(b"+++ ")
        if mail and sections and line == b"-- ":
            patch = patch[: stream.tell() - len(raw_line)]
            break
        # Git writes the raw submodule name (possibly including newlines) before the
        # status or object range. Neither log nor inline-diff headers can be replayed.
        if line.startswith(b"Submodule "):
            submodule_summary = True
        if submodule_summary and _SUBMODULE_SUMMARY_END.search(line):
            raise SystemExit(_SUBMODULE_ERROR)
        if pending_paths:
            if line.startswith(b"+++ ") and not _matches_git_paths(*pending_paths, line[4:]):
                sections += 1
            pending_paths = None
        if line.startswith(b"diff --git "):
            sections += 1
            submodule_summary = False
            git_paths = line.removeprefix(b"diff --git ")
            continue
        if line.startswith(b"--- "):
            submodule_summary = False
            # A Git header can introduce the same unified path pair. An
            # unrelated pair starts a separate file even if Git ignores one.
            if git_paths:
                pending_paths = (git_paths, line[4:])
            else:
                sections += 1
            git_paths = b""
            continue
        if git_paths:
            if line.startswith(
                (b"index ", b"old mode ", b"new mode ", b"new file mode ", b"deleted file mode ")
            ):
                if re.search(rb" 0*16[0-7]{4}(?:\s|$)", line):
                    raise SystemExit(_SUBMODULE_ERROR)
                if not line.startswith(b"index ") and not re.fullmatch(rb".* [0-7]{6}[ \t]*", line):
                    raise SystemExit(incomplete)
                continue
            if line.startswith(
                (
                    b"similarity index ",
                    b"dissimilarity index ",
                    b"rename from ",
                    b"rename to ",
                    b"copy from ",
                    b"copy to ",
                )
            ):
                continue
            git_paths = b""
        if hunk:
            old_lines = int(hunk[1] or b"1")
            new_lines = int(hunk[2] or b"1")
        elif (
            line.startswith((b"Binary files ", b"Files "))
            and line.endswith(b" differ")
            and b" and " in line
        ):
            raise SystemExit(incomplete)
        elif line.startswith(b"Only in ") and b": " in line:
            raise SystemExit(incomplete)
    if old_lines or new_lines:
        raise SystemExit(incomplete)
    return patch, sections


def require_valid_patch(target: Path, patch: bytes) -> None:
    """Reject incomplete patches before recording the submitted bytes."""
    incomplete = (
        "The remediation patch omits file content. Generate a complete binary diff "
        "with Git's --binary option."
    )
    # Git's numstat skips target-relative paths when run below the repository root.
    root = git_output(target, "rev-parse", "--show-toplevel", offline=True)
    directory = ("-C", root) if root else ()

    def git(data: bytes, *arguments: str):
        result = git_command(
            target,
            *directory,
            *arguments,
            text=False,
            input_data=data,
            pathspec_environment={"LC_ALL": "C"},
            offline=True,
        )
        if result.returncode == 127:
            raise SystemExit(
                "Validating a new remediation patch requires a trusted Git executable."
            )
        # Git may report a corrupt trailing binary block but return zero for an earlier file.
        if result.returncode or re.search(rb"(?m)^error: ", result.stderr):
            reason = result.stderr.decode(errors="replace").strip()
            raise SystemExit(f"Could not parse the remediation patch: {reason}")
        return result.stdout

    # Parse every header and hunk, then skip checkout reads and repository clean filters.
    apply = ("apply", "--no-index", "--whitespace=nowarn")
    body, sections = _patch_file_sections(patch, incomplete)
    git(patch, *apply, "--check", "--exclude=*", "-")
    # Git silently ignores some incomplete sections when another file is valid.
    # NUL termination gives one record per file, even for unusual pathnames.
    if git(patch, *apply, "--numstat", "-z", "-").count(b"\0") != sections:
        raise SystemExit(incomplete)

    binary_oid_width = None
    for header in re.finditer(
        rb"(?m)^diff --git [^\n]+\n((?:(?!diff )[a-z][^\n]*(?:\n|\Z))*)",
        body,
    ):
        metadata = header.group(1)
        index = re.search(rb"(?m)^index ([^\s.]+)\.\.([^\s.]+)(?: [0-7]+[ \t]*)?\r?$", metadata)
        binary = body.startswith((b"GIT binary patch\n", b"GIT binary patch\r\n"), header.end())
        if not binary:
            if index is None or re.compile(rb"(?:--- [^\n]*\n\+\+\+ [^\n]*\n)?@@ ").match(
                body, header.end()
            ):
                continue
            old, new = index.groups()
            if metadata.startswith(b"deleted file mode ") and not new.strip(b"0"):
                content_id = old
            elif metadata.startswith(b"new file mode ") and not old.strip(b"0"):
                content_id = new
            else:
                # Mode changes and renames can omit hunks only if
                # their advertised blob contents are unchanged.
                old, new = old.lower(), new.lower()
                if not old.startswith(new) and not new.startswith(old):
                    raise SystemExit(incomplete)
                continue
            # Only an empty file can be added or deleted without a hunk.
            empty_blobs = (
                hashlib.sha1(b"blob 0\0", usedforsecurity=False).hexdigest().encode(),
                hashlib.sha256(b"blob 0\0").hexdigest().encode(),
            )
            if not any(digest.startswith(content_id.lower()) for digest in empty_blobs):
                raise SystemExit(incomplete)
            continue
        if index is None:
            raise SystemExit("A binary patch requires an index line with full object IDs.")
        old, new = index.groups()
        if binary_oid_width is None:
            binary_oid_width = len(git(b"", "hash-object", "--no-filters", "--stdin").strip())
        if (
            len(old) != binary_oid_width
            or len(new) != binary_oid_width
            or not re.fullmatch(rb"[0-9a-fA-F]+", old + new)
        ):
            raise SystemExit(
                "A binary patch requires full object IDs in the selected target's Git object format."
            )


def patch_metadata(
    current: sqlite3.Row,
    args: argparse.Namespace,
    patch: bytes | None,
    resolve_path: Callable[[str], str],
) -> tuple[str | None, str | None]:
    path = args.patch_path
    digest = args.patch_digest
    if patch is not None:
        if args.state != "generated" or path is not None or digest is not None:
            raise SystemExit("Supply patch only for generation, without a patch path or digest.")
        path = current["patch_path"] or (
            f"artifacts/remediation/{current['occurrence_id']}/{current['request_id']}/"
            f"{current['pending_action_claim_token']}.patch"
        )
        digest = f"sha256:{hashlib.sha256(patch).hexdigest()}"
    else:
        if path is not None:
            path = resolve_path(path)
        if digest is not None:
            digest = optional_text(digest, maximum=71)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
                raise SystemExit("patch-digest must use sha256:<64 lowercase hex characters>.")
    if path is not None and current["patch_path"] not in (None, path):
        raise SystemExit("A remediation attempt cannot replace its reviewed patch path.")
    if digest is not None and current["patch_digest"] not in (None, digest):
        raise SystemExit("A remediation attempt cannot replace its reviewed patch digest.")
    return path or current["patch_path"], digest or current["patch_digest"]


def same_file_version(
    original: tuple[os.stat_result, int], current: tuple[os.stat_result, int]
) -> bool:
    before, before_change = original
    after, after_change = current
    return (
        os.path.samestat(before, after)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before_change == after_change
    )


def file_digest_and_version(source: BinaryIO, label: str) -> tuple[str, tuple[os.stat_result, int]]:
    before = scan_local_file_version(source.fileno())
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    after = scan_local_file_version(source.fileno())
    if not same_file_version(before, after):
        raise SystemExit(f"The {label} changed while it was being verified.")
    return f"sha256:{digest.hexdigest()}", after


def matching_patch_metadata(source: BinaryIO, expected_digest: str) -> tuple[os.stat_result, int]:
    digest, version = file_digest_and_version(source, "scan-local patch")
    if digest != expected_digest:
        raise SystemExit("Patch digest does not match the scan-local patch file.")
    return version


def patch_manifest_version(
    db: Any, scan: sqlite3.Row, scan_dir: Path
) -> tuple[str, tuple[os.stat_result, int]]:
    manifest_path = db.ARTIFACTS["manifest"]
    expected = scan["seal_manifest_digest"]
    if expected is None:
        # Historical manifests can have different JSON formatting. Bind their original bytes.
        saved, raw = _read_scan_local_json_bytes(scan_dir, manifest_path, manifest_path)
        manifest, _, _, _ = _read_sealed_scan(scan_dir, None, "remediation")
        if saved != manifest:
            raise SystemExit("The sealed scan manifest changed during validation.")
        db.verify_manifest_binding(scan, manifest)
        expected = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    with db.open_scan_local_file(scan_dir, manifest_path) as source:
        digest, version = file_digest_and_version(source, "sealed scan manifest")
    if digest != expected:
        raise SystemExit("The sealed scan manifest changed after completion.")
    return digest, version


def save_patch(
    db: Any,
    connection: sqlite3.Connection,
    scan_id: str,
    current: sqlite3.Row,
    path: str,
    digest: str,
    patch: bytes,
    record_update: Callable[[], None],
) -> None:
    def admit() -> Path:
        record_update()
        latest = db.require_scan(connection, scan_id)
        directory = db.require_canonical_scan_directory(Path(latest["scan_dir"]))
        if scan_root_identity(directory)[1] != identity:
            raise SystemExit("The scan directory changed after seal validation.")
        with db.open_scan_local_file(directory, db.ARTIFACTS["manifest"]) as named:
            current_version = scan_local_file_version(named.fileno())
        if latest["seal_manifest_digest"] not in (None, manifest_digest) or not same_file_version(
            manifest_version, current_version
        ):
            raise SystemExit("The sealed scan manifest changed after completion.")
        return directory

    def prepare_saved_patch(directory: Path) -> tuple[os.stat_result, int]:
        with db.open_scan_local_file(directory, path) as named:
            version = matching_patch_metadata(named, digest)
            if os.name == "posix":
                # Persist the file and every directory entry before SQLite commits its path.
                os.fsync(named.fileno())
                with (
                    managed_fd(_open_verified_scan_directory(directory, identity)) as root,
                    managed_fd(
                        _open_scan_local_directory(
                            root, Path(path).parts[:-1], create=False, sync_parents=True
                        )
                    ) as parent,
                ):
                    os.fsync(parent)
        return version

    def verify_name(directory: Path, expected: tuple[os.stat_result, int]) -> None:
        with db.open_scan_local_file(directory, path) as named:
            if not same_file_version(expected, scan_local_file_version(named.fileno())):
                raise SystemExit("The scan-local patch changed during generation.")
        if scan_root_identity(directory)[1] != identity:
            raise SystemExit("The scan directory changed while saving the patch.")

    existing = current["patch_path"] is not None
    retried_directory = None
    identity = None
    while True:
        scan = db.require_scan(connection, scan_id)
        root_changed_during_validation = False
        with ExitStack() as staging:
            try:
                scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
                if identity is None:
                    scan_dir, root_identity = scan_root_identity(scan_dir)
                    manifest_digest, manifest_version = patch_manifest_version(db, scan, scan_dir)
                    root_changed_during_validation = (
                        scan_root_identity(scan_dir)[1] != root_identity
                    )
                    if root_changed_during_validation:
                        raise ContractError("The scan directory changed during seal validation.")
                    identity = root_identity
                publish = None
                if not existing:
                    with suppress(FileExistsError):
                        publish = staging.enter_context(
                            stage_scan_local_bytes(
                                scan_dir,
                                path,
                                patch,
                                expected_root_identity=identity,
                                owner_read_write=True,
                            )
                        )
                if publish is None:
                    metadata = prepare_saved_patch(scan_dir)
            except (ContractError, OSError, SystemExit) as exc:
                # Archiving moves the directory before committing its new location.
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    directory = db.require_scan(connection, scan_id)["scan_dir"]
                if directory == scan["scan_dir"]:
                    if directory == retried_directory:
                        raise
                    # Rollback can restore a missing file or the verified staging root.
                    cause: BaseException | None = exc
                    while cause and not isinstance(
                        cause, (FileNotFoundError, MissingScanLocalFileError)
                    ):
                        cause = cause.__cause__
                    if (
                        cause is None
                        and not root_changed_during_validation
                        and not (
                            isinstance(exc, ContractError)
                            and identity is not None
                            and scan_root_identity(Path(directory))[1] == identity
                        )
                    ):
                        raise
                    retried_directory = directory
                continue
            directory = admit()
            if publish is not None:
                with suppress(FileExistsError):
                    publish(directory)
                # Keep the token's file, including a competing winner, if cancellation
                # or interruption wins before final admission. Verify it outside SQLite.
                connection.rollback()
                existing = True
                continue
        verify_name(directory, metadata)
        return


def remediation_claim_is_active(remediation: sqlite3.Row) -> bool:
    if remediation["pending_action_claim_token"] is None:
        return False
    delivered_at = remediation["pending_action_delivered_at"]
    claimed_at = delivered_at or remediation["pending_action_claimed_at"]
    if not isinstance(claimed_at, str):
        return True
    try:
        if claimed_at.endswith(("Z", "z")):
            claimed_at = claimed_at[:-1] + "+00:00"
        parsed = datetime.fromisoformat(claimed_at)
        if parsed.tzinfo is None:
            return True
    except ValueError:
        return True
    lease_seconds = DELIVERED_ACTION_LEASE_SECONDS if delivered_at else CLAIM_LEASE_SECONDS
    return parsed > datetime.now(timezone.utc) - timedelta(seconds=lease_seconds)


def require_transition(current: str, requested: str) -> None:
    allowed = {
        "requested": {"requested", "generated", "failed"},
        "generated": {"generated", "applied", "failed"},
        "applied": {"applied", "verifying", "failed"},
        "verifying": {"verifying", "verified", "failed"},
        "verified": {"verifying", "verified"},
        "failed": {"generated", "applied", "verifying", "verified", "failed"},
    }
    if requested not in allowed.get(current, set()):
        raise SystemExit(f"Finding remediation cannot move from {current} to {requested}.")


def require_pending_action(current: sqlite3.Row, requested: str) -> None:
    pending_action = current["pending_action"]
    if pending_action is not None:
        allowed = {
            "generate": {"generated", "failed"},
            "apply": {"applied", "failed"},
            "verify": {"verifying", "verified", "failed"},
        }
        if requested not in allowed[pending_action]:
            raise SystemExit(
                f"Pending remediation action {pending_action} cannot record state {requested}."
            )
        return
    required_action = {
        ("requested", "generated"): "generate",
        ("generated", "applied"): "apply",
        ("applied", "verifying"): "verify",
    }.get((current["state"], requested))
    if required_action is not None:
        raise SystemExit(
            f"Request {required_action} before recording remediation state {requested}."
        )


def cancel_finding_remediation_request(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> str:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        occurrence = require_occurrence(connection, args.occurrence_id)
        current = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current is None:
            return str(occurrence["scan_id"])
        if current["occurrence_id"] != occurrence["id"]:
            raise SystemExit("This remediation request belongs to a different finding.")
        if current["pending_action"] is None:
            return str(occurrence["scan_id"])
        if current["state"] == "failed" and current["pending_action_claim_token"] is None:
            return str(occurrence["scan_id"])
        if current["pending_action_claim_token"] != action_token:
            raise SystemExit("This remediation host request is owned by a different action token.")
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if current["state"] == "failed":
            connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
                    pending_action_delivered_at = NULL, updated_at = ?
                WHERE request_id = ? AND pending_action_claim_token = ?
                """,
                (timestamp, request_id, action_token),
            )
        elif current["pending_action"] == "generate":
            _cancel_generation(
                connection, occurrence["id"], request_id, timestamp, current["state"]
            )
            connection.execute(
                "UPDATE scans SET updated_at = ? WHERE id = ?",
                (timestamp, occurrence["scan_id"]),
            )
        else:
            connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET state = CASE
                        WHEN pending_action = 'verify' AND state = 'verifying' THEN 'applied'
                        ELSE state
                    END,
                    pending_action = NULL, pending_action_claimed_at = NULL,
                    pending_action_claim_token = NULL, pending_action_delivered_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE request_id = ? AND pending_action_claim_token = ?
                """,
                (timestamp, request_id, action_token),
            )
    return str(occurrence["scan_id"])


def _cancel_generation(
    connection: sqlite3.Connection,
    occurrence_id: str,
    request_id: str,
    timestamp: str,
    state: str,
) -> None:
    if state != "requested":
        raise SystemExit("Only a requested patch generation can be canceled.")
    connection.execute(
        "DELETE FROM finding_remediation_attempts WHERE request_id = ?", (request_id,)
    )
    previous = connection.execute(
        """
        SELECT * FROM finding_remediation_attempts
        WHERE occurrence_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1
        """,
        (occurrence_id,),
    ).fetchone()
    if previous is None or previous["state"] != "superseded":
        return
    restored_state = "applied" if previous["applied_content_digest"] is not None else "generated"
    connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET state = ?, version = version + 1, updated_at = ?
        WHERE request_id = ? AND state = 'superseded'
        """,
        (restored_state, timestamp, previous["request_id"]),
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
