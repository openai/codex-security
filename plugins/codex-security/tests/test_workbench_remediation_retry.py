from __future__ import annotations

import argparse
import errno
import io
import os
import secrets
import sqlite3
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    cancel_remediation_request,
    claim_remediation_resend,
    empty_target_paths,
    initialize_git_repository,
    mark_remediation_delivered,
    request_remediation,
    request_remediation_action,
    scan_command,
    set_remediation,
    set_triage,
    start_saved_scan,
    write_completed_contract,
    write_remediation_patch,
)


def update_remediation(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    expected_version: int,
    state: str,
    *extra: str,
) -> dict[str, Any]:
    result = set_remediation(
        state_dir, occurrence_id, request_id, action_token, str(expected_version), state, *extra
    )
    return result["scan"]["findings"][0]["remediationState"]


@pytest.mark.cross_platform
def test_generated_patch_does_not_fetch_missing_git_objects(tmp_path, workbench_api, monkeypatch):
    from workbench_source_scopes import offline_git_bytes

    repo = tmp_path / "repo"
    revision = initialize_git_repository(repo)
    missing = "e" * len(revision)
    marker = tmp_path / "remote-called"
    monkeypatch.setenv("TEST_REMOTE_MARKER", marker.as_posix())
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "file")
    monkeypatch.delenv("GIT_NO_LAZY_FETCH", raising=False)
    for key, value in {
        "attr.tree": missing,
        "core.repositoryformatversion": "1",
        "extensions.partialclone": "origin",
        "remote.origin.promisor": "true",
        "remote.origin.partialclonefilter": "blob:none",
        "remote.origin.url": repo.as_uri(),
        "remote.origin.uploadpack": 'echo invoked > "$TEST_REMOTE_MARKER"; exit 1;',
    }.items():
        subprocess.run(["git", "config", key, value], cwd=repo, check=True)

    patch = b"--- /dev/null\n+++ b/added\n@@ -0,0 +1 @@\n+new\n"
    workbench_api["remediation_state"].require_valid_patch(repo, patch)
    assert offline_git_bytes(repo, "cat-file", "blob", missing) is None
    assert not marker.exists()
    # An explicit transport can reach the same helper through the caller's environment.
    assert subprocess.run(["git", "ls-remote", "origin"], cwd=repo).returncode != 0
    assert marker.exists()


@pytest.mark.cross_platform
def test_generated_patch_requires_binary_contents(
    tmp_path: Path, workbench_api, monkeypatch
) -> None:
    repository = tmp_path / "repo"
    initialize_git_repository(repository)
    target = repository / "nested" / "scan" / "target"
    target.mkdir(parents=True)
    asset = target / "asset.bin"
    asset.write_bytes(b"\0before")
    subprocess.run(["git", "add", "asset.bin"], cwd=target, check=True)
    diff = ["git", "diff", "--relative"]
    added = subprocess.check_output([*diff, "--cached", "--binary"], cwd=target)
    subprocess.run(["git", "commit", "-qm", "Add asset"], cwd=target, check=True)
    asset.write_bytes(b"\0after")
    summary = subprocess.check_output(diff, cwd=target)
    binary = subprocess.check_output([*diff, "--binary"], cwd=target)
    notice = summary.splitlines(keepends=True)[-1]
    prose = (
        notice.decode()
        + "Only in target: new-file\nindex 1234567..89abcde 100644\nGIT binary patch"
    )
    subprocess.run(["git", "commit", "-qam", "Update asset", "-m", prose], cwd=target, check=True)
    email = ["git", "format-patch", "-1", "--stdout", "--relative", "--signature", prose]
    mail = subprocess.check_output(email, cwd=target)
    mail_summary = subprocess.check_output([*email, "--no-binary"], cwd=target)
    asset.write_bytes(b"\0before")

    validate = workbench_api["remediation_state"].require_valid_patch
    hunk = b"--- a/note\n+++ b/note\n@@ -1 +1 @@\n-old\n+Binary files a/a and b/a differ\n"
    with pytest.raises(SystemExit, match="Could not parse the remediation patch"):
        validate(target, summary.removesuffix(notice))
    for incomplete in (
        summary,
        summary.rstrip(b"\n"),
        hunk + summary,
        mail_summary,
        notice + hunk,
        hunk + notice,
        hunk + b"Only in tree: new-file\n",
    ):
        with pytest.raises(SystemExit, match="--binary option"):
            validate(target, incomplete)

    data_line = binary.split(b"GIT binary patch\n", 1)[1].splitlines()[1]
    corrupt = binary.replace(data_line, b"!", 1)
    monkeypatch.setenv("GIT_TRACE", "1")
    with pytest.raises(SystemExit, match="error: corrupt binary patch"):
        validate(target, hunk + corrupt)
    validate(target, hunk + binary)
    padded = binary.replace(b" 100644\nGIT binary patch", b" 100644 \t\nGIT binary patch")
    assert padded != binary
    validate(target, padded)
    validate(target, mail)
    near_miss = b"---\n" + b" 1 file changed\n" * 10000 + b"end of message\n"
    validate(target, mail.replace(b"\n---\n", b"\n" + near_miss + b"---\n", 1))
    # --no-stat with diff.suppressBlankEmpty can look like a diffstat between two files.
    deleted_dash = b"diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,3 +1,2 @@\n---\n stays\n\n"
    validate(target, mail.partition(b"\n---\n")[0] + b"\n\n" + deleted_dash + binary)
    validate(target, mail + b"diff --git a/signature b/signature\n")
    message, signature = mail.rsplit(b"\n-- \n", 1)
    with pytest.raises(SystemExit, match="omits file content"):
        validate(target, message + b"\ndiff --git a/test b/test\n-- \n" + signature)
    validate(target, b"Files changed: note\n" + hunk)
    validate(target, added.partition(b"\n\n")[0] + b"\n\n")
    index_line = next(
        line for line in added.splitlines(keepends=True) if line.startswith(b"index ")
    )
    with pytest.raises(SystemExit, match="full object IDs"):
        validate(target, added.replace(index_line, b""))
    assert asset.read_bytes() == b"\0before"


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    "old,new,make_executable",
    [
        (b"old\n", b"new\n", False),
        (b"\0old", b"\0new", False),
        (b"", None, False),
        (b"old\n", b"new\n", True),
    ],
)
def test_generated_patch_with_quoted_no_stat_header(
    tmp_path: Path, workbench_api, old: bytes, new: bytes | None, make_executable: bool
) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=repo)

    path = repo / "file"
    path.write_bytes(old)
    git("add", "file")
    git("commit", "-qm", "Baseline")
    if new is None:
        path.unlink()
    else:
        path.write_bytes(new)
    git("add", "-A", "--", "file")
    if make_executable:
        git("update-index", "--chmod=+x", "file")
    git("commit", "-qm", "Change", "-m", "diff --git a/file b/file\nThis header is an example.")
    mail = git("format-patch", "--no-stat", "--binary", "-1", "--stdout")
    target = tmp_path / "target"
    target.mkdir()
    restored = target / "file"
    restored.write_bytes(old)
    validate = workbench_api["remediation_state"].require_valid_patch
    if new is None:
        # Git retains a preimage for this empty deletion and cannot reverse it.
        with pytest.raises(SystemExit, match="omits file content"):
            validate(target, mail)
        return
    validate(target, mail)
    for flags, expected in (([], new), (["--reverse"], old)):
        subprocess.run(
            ["git", "apply", "--no-index", *flags, "-"], cwd=target, input=mail, check=True
        )
        assert restored.read_bytes() == expected
        if make_executable and os.name != "nt":
            assert bool(restored.stat().st_mode & 0o100) == (not flags)


@pytest.mark.cross_platform
def test_generated_patch_compares_decoded_git_paths(tmp_path: Path, workbench_api) -> None:
    (tmp_path / "source file").write_bytes(b"old\n")
    raw = (b"a/source file", b"b/source file")
    quoted = (b'"a/source file"', rb'"b/\163ource\040file"')
    mixed = (rb'"original/\163ource\040file"', b"updated/source file")
    for git_paths, (old, new) in ((raw, quoted), (quoted, raw), (raw, mixed), (quoted, mixed)):
        patch = b"diff --git %s %s\n--- %s\n+++ %s\n@@ -1 +1 @@\n-old\n+new\n" % (
            *git_paths,
            old,
            new,
        )
        subprocess.run(
            ["git", "apply", "--no-index", "--check", "-"], input=patch, cwd=tmp_path, check=True
        )
        workbench_api["remediation_state"].require_valid_patch(tmp_path, patch)

    # Git uses the unified paths even if the Git header names another file.
    # A suffix following a space in a directory name is still a different target.
    for header in (b"a/other b/source file", b"a/source file b/other dir/source file"):
        unrelated = patch.replace(patch.splitlines()[0], b"diff --git " + header)
        assert subprocess.check_output(
            ["git", "apply", "--numstat", "-z", "-"], input=unrelated, cwd=tmp_path
        ).endswith(b"\tsource file\0")
        with pytest.raises(SystemExit, match="omits file content"):
            workbench_api["remediation_state"].require_valid_patch(tmp_path, unrelated)


@pytest.mark.cross_platform
def test_generated_patch_rejects_truncated_hunk_header(tmp_path: Path, workbench_api) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    path = repo / "source"
    path.write_bytes(b"before first\n" + b"context\n" * 12 + b"before last\n")
    subprocess.run(["git", "add", "source"], cwd=repo, check=True)
    path.write_bytes(path.read_bytes().replace(b"before", b"after"))
    patch = subprocess.check_output(["git", "diff", "--", "source"], cwd=repo)
    first, last = patch.rsplit(b"\n@@ -", 1)
    assert b"@@ -" in first and b"after last" in last
    validate = workbench_api["remediation_state"].require_valid_patch
    validate(repo, patch)
    truncated = first + b"\n@@ -"
    assert (
        subprocess.check_output(["git", "apply", "--numstat", "-z", "-"], input=truncated, cwd=repo)
        == b"1\t1\tsource\0"
    )
    for tail in (b"", b"12,2 +", b"12,2 +12,2 @\n"):
        with pytest.raises(SystemExit, match="omits file content"):
            validate(repo, truncated + tail)
    validate(repo, b"@@ - a quoted header\n" + patch + b"\nPostscript\n@@ -")
    no_newline = b"--- a/one\n+++ b/one\n@@ -1 +1 @@\n-@@ -\n+@@ -\n\\ No newline at end of file\n"
    validate(repo, no_newline)
    with pytest.raises(SystemExit, match="omits file content"):
        validate(repo, no_newline + b"@@ -")


@pytest.mark.cross_platform
def test_generated_patch_requires_complete_file_sections(tmp_path: Path, workbench_api) -> None:
    validate = workbench_api["remediation_state"].require_valid_patch
    hunk = b"--- a/one\n+++ b/one\n@@ -1 +1 @@\n-old\n+new\n"
    validate(tmp_path, b"Binary files " + b"path and " * 10000 + b"other text\n" + hunk)
    added = (
        b"diff --git a/added b/added\nnew file mode 100644 \t\n"
        b"--- /dev/null\n+++ b/added\n@@ -0,0 +1 @@\n+contents\n"
    )
    validate(tmp_path, added)
    with pytest.raises(SystemExit, match="omits file content"):
        validate(tmp_path, added.replace(b"100644", b"10064"))
    third = hunk.replace(b"one", b"three")
    for header in (
        b"diff --git a/two b/two",
        b"diff --git a/two b/two\nnew file m",
        b"diff --git a/two b/two\nnew file mode 100",
        b"--- a/two",
        b"--- a/two\n+++ b/two",
    ):
        for ending in (
            b"",
            b"\n",
            b"\r\n\n",
            b"\n" + third,
            b"\ndiff --git a/three b/three\n" + third,
        ):
            with pytest.raises(SystemExit, match="omits file content|Could not parse"):
                validate(tmp_path, hunk + header + ending)
    validate(tmp_path, hunk + b"--- a/two\n+++ b/two\n@@ -1 +1 @@\n--- a/three\n+++ b/three\n")
    validate(tmp_path, b"--- a/one\n+++ b/one\n@@ -1 +0,0 @@\n--- a/two\n")

    for section in (
        b"diff --git a/two b/two\nold mode 100644\nnew mode 100755\n",
        b"diff --git a/two b/three\nsimilarity index 100%\nrename from two\nrename to three\n",
    ):
        validate(tmp_path, hunk + section)
        validate(tmp_path, hunk + section + b"index 1234567..1234567\n")
        with pytest.raises(SystemExit, match="omits file content"):
            validate(tmp_path, hunk + section + b"index 1234567..7654321\n")

    copy = b"diff --git a/two b/three\nsimilarity index 100%\ncopy from two\ncopy to three\n"
    validate(tmp_path, hunk + copy)
    (tmp_path / "one").write_bytes(b"old\n")
    (tmp_path / "two").write_bytes(b"original\n")
    subprocess.run(["git", "apply", "--no-index", "-"], cwd=tmp_path, input=hunk + copy, check=True)
    assert (tmp_path / "three").read_bytes() == (tmp_path / "two").read_bytes() == b"original\n"


@pytest.mark.cross_platform
def test_generated_patch_rejects_gitlink_changes(tmp_path: Path, workbench_api) -> None:
    target = tmp_path / "repo"
    before = initialize_git_repository(target)

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=target)

    git("update-index", "--add", "--cacheinfo", f"160000,{before},dependency")
    added = git("diff", "--cached")
    git("commit", "-qm", "Add gitlink")
    after = git("rev-parse", "HEAD").decode().strip()
    git("update-index", "--cacheinfo", f"160000,{after},dependency")
    modified = git("diff", "--cached")
    git("update-index", "--force-remove", "dependency")
    deleted = git("diff", "--cached")
    for patch in (added, modified, deleted, modified.replace(b" 160000\n", b" 0160000 \n")):
        with pytest.raises(SystemExit, match="cannot update Git submodules"):
            workbench_api["remediation_state"].require_valid_patch(target, patch)


@pytest.mark.cross_platform
@pytest.mark.parametrize("style", ["log", "diff"])
def test_generated_patch_rejects_submodule_summaries(
    tmp_path: Path, workbench_api, style: str
) -> None:
    root = tmp_path / "repo"
    initialize_git_repository(root)
    target = root / "nested"
    target.mkdir()
    dep = target / "a dependency"
    initialize_git_repository(dep)

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=target)

    validate = workbench_api["remediation_state"].require_valid_patch
    note = target / "note"
    prose = "Submodule dep 1234567..89abcde (rewind):"
    note.write_bytes(prose.encode() + b"\n")
    git("add", "note")
    git("commit", "-qm", "Add note", "-m", prose)
    # A commit message, signature and changed file can all quote a real summary.
    email = ("format-patch", "-1", "--stdout", "--relative", "--signature", prose)
    validate(target, git(*email))
    validate(target, git(*email, "--no-stat"))

    git("config", "diff.submodule", style)
    note.write_bytes(b"updated\n")
    git("add", "note", "a dependency")
    added = git("diff", "--cached", "--relative")
    assert b"(new submodule)" in added
    git("commit", "-qm", "Add dependency")
    mail = git(*email, f"--submodule={style}")
    mail_no_stat = git(*email, f"--submodule={style}", "--no-stat")
    assert mail.index(b"Submodule nested/a dependency") < mail.index(b"diff --git ")

    (dep / "README.md").write_bytes(b"new version\n")
    git("-C", str(dep), "commit", "-qam", "Update dependency")
    note.write_bytes(b"another update\n")
    moved = git("diff", "--relative")
    if style == "diff":
        assert b"diff --git a/nested/a dependency/README.md" in moved
    git("add", "a dependency")
    (dep / "README.md").write_bytes(b"worktree change\n")
    dirty = git("diff", "--relative")
    assert b"contains modified content" in dirty
    for patch in (added, mail, mail_no_stat, moved, dirty):
        with pytest.raises(SystemExit, match="cannot update Git submodules"):
            validate(target, patch)


@pytest.mark.cross_platform
@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_generated_patch_preserves_deletions_and_uses_target_binary_ids(
    tmp_path: Path, workbench_api, object_format: str
) -> None:
    repo = tmp_path / object_format
    other_format = "sha256" if object_format == "sha1" else "sha1"
    other = tmp_path / other_format
    for directory in (repo, other):
        subprocess.run(
            ["git", "init", "-q", f"--object-format={directory.name}", directory], check=True
        )

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=repo)

    (repo / "text").write_bytes(b"old\n")
    (repo / "empty").touch()
    (repo / "asset").write_bytes(b"\0old")
    git("add", ".")
    added = git("diff", "--cached", "--", "text")
    added_empty = git("diff", "--cached", "--abbrev=4", "--", "empty")
    (repo / "text").unlink()
    (repo / "empty").unlink()
    (repo / "asset").write_bytes(b"\0new")
    validate = workbench_api["remediation_state"].require_valid_patch
    for marker in (b"--- /dev/null", b"+++ b/text", b"@@ "):
        with pytest.raises(SystemExit, match="omits file content"):
            validate(repo, added.partition(marker)[0])
    with pytest.raises(SystemExit, match="omits file content"):
        validate(repo, git("diff", "--irreversible-delete", "--", "text"))
    text = git("diff", "--full-index", "--", "text")
    empty = git("diff", "--abbrev=4", "--", "empty")
    for target in (repo, other, tmp_path):
        validate(target, text)
        validate(target, empty)
        validate(target, added)
        validate(target, added_empty)

    binary = git("diff", "--binary", "--", "asset")
    forward_only = binary.partition(b"\n\n")[0] + b"\n\n"
    validate(repo, forward_only)
    (repo / "asset").write_bytes(b"\0old")
    subprocess.run(["git", "apply", "--no-index", "-"], cwd=repo, input=forward_only, check=True)
    assert (repo / "asset").read_bytes() == b"\0new"
    index = next(line for line in binary.splitlines() if line.startswith(b"index "))
    with pytest.raises(SystemExit, match="full object IDs"):
        validate(repo, binary.replace(index, b"index 1234567..89abcde 100644"))
    with pytest.raises(SystemExit, match="Git object format"):
        validate(other, binary)
    if object_format == "sha1":
        validate(tmp_path, binary)
    else:
        with pytest.raises(SystemExit, match="Git object format"):
            validate(tmp_path, binary)


@pytest.fixture
def pending_generation(tmp_path, monkeypatch):
    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("before\n")
    scan_id, scan_dir = start_saved_scan(state, target, tmp_path / "scans")
    write_completed_contract(scan_dir, scan_id, target, relative_path="source.txt")
    completed = scan_command(state, "complete-scan", scan_id)["scan"]
    occurrence = completed["findings"][0]["occurrenceId"]
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    request_remediation(state, occurrence, request, token)
    database = state / "workbench.sqlite3"
    patch = b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-before\n+after\n"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(patch)))
    args = argparse.Namespace(
        occurrence_id=occurrence,
        request_id=request,
        action_token=token,
        expected_version=1,
        state="generated",
        patch_stdin=True,
        patch_path=None,
        patch_digest=None,
        base_revision=None,
        summary=None,
        verification_summary=None,
    )
    return database, scan_dir, scan_id, args, patch


@pytest.mark.cross_platform
@pytest.mark.parametrize("change_manifest", [False, True])
def test_generate_legacy_patch_validates_seal_before_taking_writer_lock(
    pending_generation, workbench_api, monkeypatch, change_manifest: bool
) -> None:
    database, scan_dir, scan_id, args, patch = pending_generation
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan_id,))

    manifest = scan_dir / "scan-manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    remediation = workbench_api["remediation_state"]
    read_seal = remediation._read_sealed_scan
    validated = []

    def read_without_writer_lock(*args):
        with sqlite3.connect(database, timeout=0) as writer:
            writer.execute("BEGIN IMMEDIATE")
            result = read_seal(*args)
        validated.append(args[0])
        if change_manifest:
            manifest.write_bytes(manifest.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(remediation, "_read_sealed_scan", read_without_writer_lock)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if change_manifest:
            with pytest.raises(SystemExit, match="sealed scan manifest changed"):
                workbench_api["set_finding_remediation"](connection, args)
            row = connection.execute(
                "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
                (args.request_id,),
            ).fetchone()
            assert tuple(row) == ("requested", 1, None)
            assert not list(scan_dir.rglob("*.patch"))
        else:
            result = workbench_api["set_finding_remediation"](connection, args)
            relative = result["scan"]["findings"][0]["remediationState"]["patchPath"]
            assert (scan_dir / relative).read_bytes() == patch
    assert validated == [scan_dir]


@pytest.mark.cross_platform
@pytest.mark.parametrize("scenario", ["new", "existing", "canceled", "canceled-after-publication"])
def test_generate_keeps_the_database_writer_available_during_patch_io(
    pending_generation, workbench_api, monkeypatch, scenario
):
    database, scan_dir, _, args, patch = pending_generation
    destination = (
        scan_dir
        / f"artifacts/remediation/{args.occurrence_id}/{args.request_id}/{args.action_token}.patch"
    )
    remediation = workbench_api["remediation_state"]
    acquired = []
    if scenario == "existing":
        destination.parent.mkdir(parents=True)
        destination.write_bytes(patch)
    if scenario in {"existing", "canceled-after-publication"}:
        verify = remediation.matching_patch_metadata

        def verify_with_writer(*verify_args):
            with sqlite3.connect(database, timeout=0) as other:
                other.row_factory = sqlite3.Row
                other.execute("BEGIN IMMEDIATE")
                acquired.append(scenario)
                result = verify(*verify_args)
                other.commit()
                if scenario == "canceled-after-publication":
                    remediation.cancel_finding_remediation_request(other, args)
                return result

        monkeypatch.setattr(remediation, "matching_patch_metadata", verify_with_writer)
    else:
        stage = remediation.stage_scan_local_bytes

        @contextmanager
        def stage_with_writer(*stage_args, **options):
            with sqlite3.connect(database, timeout=0) as other:
                other.row_factory = sqlite3.Row
                other.execute("BEGIN IMMEDIATE")
                with stage(*stage_args, **options) as publish:
                    acquired.append(scenario)
                    other.commit()
                    if scenario == "canceled":
                        remediation.cancel_finding_remediation_request(other, args)
                    yield publish

        monkeypatch.setattr(remediation, "stage_scan_local_bytes", stage_with_writer)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if scenario.startswith("canceled"):
            with pytest.raises(SystemExit, match="remediation request changed"):
                workbench_api["set_finding_remediation"](connection, args)
            if scenario == "canceled":
                assert not destination.exists()
            else:
                assert destination.read_bytes() == patch
            assert not list(destination.parent.glob("*.tmp"))
            assert (
                connection.execute(
                    "SELECT 1 FROM finding_remediation_attempts WHERE request_id = ?",
                    (args.request_id,),
                ).fetchone()
                is None
            )
        else:
            result = workbench_api["set_finding_remediation"](connection, args)
            assert result["scan"]["findings"][0]["remediationState"]["state"] == "generated"
            assert destination.read_bytes() == patch
    assert acquired == [scenario]


@pytest.mark.cross_platform
@pytest.mark.parametrize("matching", [False, True], ids=["different-patch", "identical-patch"])
def test_generate_preserves_patch_published_by_another_writer(
    pending_generation, workbench_api, monkeypatch, matching
):
    database, scan_dir, _, args, patch = pending_generation
    destination = (
        scan_dir
        / f"artifacts/remediation/{args.occurrence_id}/{args.request_id}/{args.action_token}.patch"
    )
    winner = patch if matching else patch.replace(b"+after", b"+another")
    token_hex = secrets.token_hex
    created = []

    def publish_before_temp_file(size):
        # Both backends allocate the temp name after checking the destination.
        with destination.open("xb") as output:
            output.write(winner)
        created.append(destination.stat())
        return token_hex(size)

    monkeypatch.setattr(secrets, "token_hex", publish_before_temp_file)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if matching:
            result = workbench_api["set_finding_remediation"](connection, args)
            assert result["scan"]["findings"][0]["remediationState"]["state"] == "generated"
        else:
            with pytest.raises(SystemExit, match="Patch digest does not match"):
                workbench_api["set_finding_remediation"](connection, args)
            row = connection.execute(
                "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
                (args.request_id,),
            ).fetchone()
            assert tuple(row) == ("requested", 1, None)
    assert len(created) == 1 and os.path.samestat(created[0], destination.stat())
    assert destination.read_bytes() == winner
    assert list(destination.parent.iterdir()) == [destination]


@pytest.mark.native_macos
@pytest.mark.skipif(os.name != "posix", reason="requires POSIX hard-link publication")
def test_generate_rejects_changed_patch_bytes_even_with_the_original_mtime(
    pending_generation, workbench_api, monkeypatch
):
    database, scan_dir, _, args, patch = pending_generation
    destination = (
        scan_dir
        / f"artifacts/remediation/{args.occurrence_id}/{args.request_id}/{args.action_token}.patch"
    )
    changed = patch.replace(b"+after", b"+other")
    link = os.link

    def overwrite_after_link(*args, **kwargs):
        link(*args, **kwargs)
        published = destination.stat()
        destination.write_bytes(changed)
        os.utime(destination, ns=(published.st_atime_ns, published.st_mtime_ns))

    monkeypatch.setattr(os, "link", overwrite_after_link)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(SystemExit, match="Patch digest does not match"):
            workbench_api["set_finding_remediation"](connection, args)
        row = connection.execute(
            "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
            (args.request_id,),
        ).fetchone()
        assert tuple(row) == ("requested", 1, None)
    assert destination.read_bytes() == changed


@pytest.mark.native_macos
@pytest.mark.skipif(os.name != "posix", reason="POSIX directory fsync")
def test_generate_retries_syncing_patch_and_new_directories_before_commit(
    pending_generation, workbench_api, monkeypatch
):
    database, scan_dir, _, args, patch = pending_generation
    parent = scan_dir / "artifacts" / "remediation" / args.occurrence_id / args.request_id
    destination = parent / f"{args.action_token}.patch"
    fsync = os.fsync
    synced = []

    def fail_directory_sync(fd):
        metadata = os.fstat(fd)
        if destination.exists() and os.path.samestat(metadata, parent.stat()):
            raise OSError(errno.ENOSPC, "patch directory sync failed")
        fsync(fd)

    def record_sync(fd):
        fsync(fd)
        synced.append(os.fstat(fd))

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        monkeypatch.setattr(os, "fsync", fail_directory_sync)
        with pytest.raises(SystemExit, match="patch directory sync failed"):
            workbench_api["set_finding_remediation"](connection, args)
        row = connection.execute(
            "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
            (args.request_id,),
        ).fetchone()
        assert tuple(row) == ("requested", 1, None)
        assert destination.read_bytes() == patch

        monkeypatch.setattr(os, "fsync", record_sync)
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(patch)))
        result = workbench_api["set_finding_remediation"](connection, args)
        assert result["scan"]["findings"][0]["remediationState"]["state"] == "generated"
        entry = destination
        while entry != scan_dir.parent:
            assert any(os.path.samestat(entry.stat(), info) for info in synced), entry
            entry = entry.parent


@pytest.mark.cross_platform
def test_generate_requires_the_published_patch_at_its_recorded_path(
    pending_generation, workbench_api, monkeypatch
):
    database, scan_dir, _, args, patch = pending_generation
    remediation = workbench_api["remediation_state"]
    stage = remediation.stage_scan_local_bytes
    request_dir = scan_dir / "artifacts" / "remediation" / args.occurrence_id / args.request_id
    moved = request_dir.with_name("moved-request")

    @contextmanager
    def move_published_patch(*args, **kwargs):
        with stage(*args, **kwargs) as publish:
            yield publish
        request_dir.rename(moved)

    monkeypatch.setattr(remediation, "stage_scan_local_bytes", move_published_patch)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(SystemExit, match="scan-local regular file"):
            workbench_api["set_finding_remediation"](connection, args)
        row = connection.execute(
            "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
            (args.request_id,),
        ).fetchone()
        assert tuple(row) == ("requested", 1, None)
    assert not request_dir.exists()
    assert (moved / f"{args.action_token}.patch").read_bytes() == patch


@pytest.mark.parametrize("wrote_patch", [False, True], ids=["before-apply", "after-apply"])
def test_failed_remediation_steps_can_retry_or_regenerate(
    tmp_path: Path, wrote_patch: bool
) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    source = target / "source.txt"
    source.write_text("vulnerable\n")
    scan_id, scan_dir = start_saved_scan(state_dir, target, tmp_path / "scans")
    write_completed_contract(scan_dir, scan_id, target, relative_path=source.name)
    completed = scan_command(state_dir, "complete-scan", scan_id)["scan"]
    occurrence_id = str(completed["findings"][0]["occurrenceId"])

    request_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())
    request_remediation(state_dir, occurrence_id, request_id, action_token)
    mark_remediation_delivered(state_dir, occurrence_id, request_id, action_token)
    destination = (
        scan_dir / f"artifacts/remediation/{occurrence_id}/{request_id}/{action_token}.patch"
    )
    generation = (state_dir, occurrence_id, request_id, action_token, "1", "generated")
    proposed_patch = "--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-vulnerable\n+updated\n"
    for invalid_patch in ("", " \t\n", "Updated the source.\n", proposed_patch.removesuffix("\n")):
        rejected = set_remediation(
            *generation, "--patch-stdin", input_text=invalid_patch, check=False
        )
        assert rejected["returncode"] != 0
        assert "Could not parse the remediation patch" in rejected["stderr"]
        assert not destination.exists()

    destination.parent.mkdir(parents=True, exist_ok=True)
    write_remediation_patch(destination)
    existing_patch = destination.read_bytes()
    rejected = set_remediation(*generation, "--patch-stdin", input_text=proposed_patch, check=False)
    assert rejected["returncode"] != 0
    save_error = rejected["stderr"].strip()
    assert "Could not save the remediation patch" in save_error
    assert destination.read_bytes() == existing_patch
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        action_token,
        1,
        "failed",
        "--summary",
        save_error,
    )
    assert failed["summary"] == save_error
    assert failed["pendingAction"] == "generate"
    assert failed["actionClaimToken"] is None
    assert failed["actionDeliveredAt"] is None

    closed = set_triage(
        state_dir,
        occurrence_id,
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Closing is allowed after the remediation worker has failed.",
    )["scan"]
    assert closed["findings"][0]["triage"]["status"] == "closed"
    set_triage(state_dir, occurrence_id, "open")

    resend_token = str(uuid.uuid4())
    resent = claim_remediation_resend(state_dir, occurrence_id, request_id, resend_token)["scan"]
    assert resent["findings"][0]["remediationState"]["actionClaimToken"] == resend_token
    delivered = mark_remediation_delivered(state_dir, occurrence_id, request_id, resend_token)[
        "scan"
    ]
    assert delivered["findings"][0]["remediationState"]["actionDeliveredAt"]
    canceled = cancel_remediation_request(state_dir, occurrence_id, request_id, resend_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert canceled["state"] == "failed"
    assert canceled["pendingAction"] == "generate"
    assert canceled["actionClaimToken"] is None
    replayed = cancel_remediation_request(state_dir, occurrence_id, request_id, resend_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert replayed == canceled

    resend_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, resend_token)

    failed_request_id = request_id
    request_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())
    blocked = request_remediation(state_dir, occurrence_id, request_id, action_token, check=False)
    assert blocked["returncode"] != 0
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?
            WHERE request_id = ?
            """,
            ("2000-01-01T00:00:00Z", failed_request_id),
        )
    regenerated = request_remediation(state_dir, occurrence_id, request_id, action_token)["scan"][
        "findings"
    ][0]["remediationState"]
    assert regenerated["state"] == "requested"

    no_newline_patch = proposed_patch + r"\ No newline at end of file"
    generated = set_remediation(
        state_dir,
        occurrence_id,
        request_id,
        action_token,
        "1",
        "generated",
        "--patch-stdin",
        input_text=no_newline_patch,
    )["scan"]["findings"][0]["remediationState"]
    patch_path = scan_dir / generated["patchPath"]
    assert patch_path.read_text(encoding="utf-8") == no_newline_patch

    apply_token = str(uuid.uuid4())
    request_remediation_action(state_dir, occurrence_id, request_id, "2", "apply", apply_token)
    apply_command = ["git", "apply", "--no-index", str(patch_path)]
    if wrote_patch:
        subprocess.run(apply_command, cwd=target, check=True)
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_token,
        3,
        "failed",
        "--summary",
        "The Apply worker was interrupted.",
    )
    assert failed["pendingAction"] == "apply"
    apply_retry_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, apply_retry_token)
    if not wrote_patch:
        assert source.read_text() == "vulnerable\n"
        subprocess.run(apply_command, cwd=target, check=True)
    applied = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_retry_token,
        4,
        "applied",
        "--base-revision",
        "unversioned",
    )
    assert applied["state"] == "applied"
    assert applied["summary"] is None

    verify_token = str(uuid.uuid4())
    request_remediation_action(state_dir, occurrence_id, request_id, "5", "verify", verify_token)
    mark_remediation_delivered(state_dir, occurrence_id, request_id, verify_token)
    update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        6,
        "verifying",
        "--base-revision",
        "unversioned",
    )
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        7,
        "failed",
        "--summary",
        "Verification could not reach the dependency registry from the sandbox.",
    )
    assert failed["pendingAction"] == "verify"
    assert failed["actionClaimToken"] is None
    assert failed["actionDeliveredAt"] is None
    canceled = cancel_remediation_request(state_dir, occurrence_id, request_id, verify_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert canceled == failed
    verify_retry_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, verify_retry_token)
    delivered = mark_remediation_delivered(
        state_dir, occurrence_id, request_id, verify_retry_token
    )["scan"]["findings"][0]["remediationState"]
    assert delivered["actionDeliveredAt"]
    canceled = cancel_remediation_request(state_dir, occurrence_id, request_id, verify_retry_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert canceled["state"] == "failed"
    assert canceled["pendingAction"] == "verify"
    assert canceled["summary"] == failed["summary"]
    assert canceled["version"] == failed["version"]
    assert canceled["actionClaimToken"] is None
    assert canceled["actionClaimedAt"] is None
    assert canceled["actionDeliveredAt"] is None
    verify_retry_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, verify_retry_token)
    verified = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_retry_token,
        8,
        "verified",
        "--base-revision",
        "unversioned",
        "--verification-summary",
        "Focused regression tests passed after permission was granted.",
    )
    assert verified["state"] == "verified"
    assert verified["summary"] is None
