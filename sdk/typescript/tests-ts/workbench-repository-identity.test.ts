import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryRoots: string[] = [];
const remote =
  "https://fixture-user:SYNTHETIC_PASSWORD@example.test/acme/project.git";

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      ...args,
    ],
    { cwd: repository, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
}

function fixture(): {
  root: string;
  repository: string;
  worktree: string;
  clone: string;
} {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-repository-identity-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  const worktree = join(root, "linked-worktree");
  const clone = join(root, "same-origin-clone");
  mkdirSync(repository);
  git(repository, "init", "-q");
  for (const service of ["service-a", "service-b", "MixedCase"]) {
    mkdirSync(join(repository, service));
    writeFileSync(join(repository, service, "service.py"), "value = 1\n");
  }
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "fixture");
  git(repository, "remote", "add", "origin", remote);
  git(repository, "worktree", "add", "--detach", "-q", worktree, "HEAD");
  execFileSync("git", ["clone", "-q", repository, clone], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  git(clone, "remote", "set-url", "origin", remote);
  return { root, repository, worktree, clone };
}

const probe = String.raw`
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, sys.argv[1])

import workbench_scan_history as history
from filesystem_identity import serialize_filesystem_identity
from workbench_native_indexes import repository_target_ids
from workbench_schema import MIGRATIONS, apply_migrations
from workbench_target_state import (
    _repository_birth_time_ns,
    _repository_identity_details,
    backfill_repository_identities,
    backfill_security_targets,
    ensure_security_target,
    register_security_target,
    repository_identity,
    repository_relative_path,
    stable_target_id,
)

scenario = sys.argv[2]
root, repository, worktree, clone = map(Path, sys.argv[3:7])
timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill_security_targets)


def git(target, *args):
    return subprocess.run(
        [
            "git",
            "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.test",
            "-C", str(target),
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def add_scan(scan_id, target, ownership="current", verify_ownership=True):
    target = Path(target)
    registration = register_security_target(
        connection, str(target), verify_ownership=verify_ownership
    )
    target_id = registration.target_id
    metadata = target.stat()
    device = serialize_filesystem_identity(metadata.st_dev)
    inode = serialize_filesystem_identity(metadata.st_ino)
    if ownership == "missing":
        device, inode = None, None
    elif ownership == "malformed":
        inode = None
    elif ownership == "mismatch":
        inode = serialize_filesystem_identity(metadata.st_ino + 1)

    workspace_id = f"workspace-{scan_id}"
    connection.execute(
        "INSERT INTO workspaces (id, target_path, target_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (workspace_id, str(target), target_id, timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO scans (id, workspace_id, target_path, target_id, repository_generation, target_device, "
        "target_inode, target_revision, scope, mode, scan_dir, status, phase, "
        "started_at, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id, workspace_id, str(target), target_id, registration.repository_generation, device, inode,
            "synthetic-revision", ".", "standard", str(root / "scans" / scan_id),
            "complete", "reporting", timestamp, timestamp, timestamp,
        ),
    )
    connection.execute(
        "INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
        (scan_id, timestamp),
    )
    return target_id


def listed(target):
    arguments = argparse.Namespace(
        repository=str(target),
        scan_root=None,
        target_id=None,
        mode=None,
        status=None,
        query=None,
        limit=None,
        offset=0,
    )
    return sorted(scan["scanId"] for scan in history.list_scans(connection, arguments)["scans"])


def forged_worktree():
    forged = root / "forged-git-pointer"
    forged.mkdir()
    common = git(repository, "rev-parse", "--path-format=absolute", "--git-common-dir")
    (forged / ".git").write_text(f"gitdir: {common}\n")
    return forged


if scenario == "identity":
    targets = {
        "repository": repository,
        "worktree": worktree,
        "serviceA": repository / "service-a",
        "worktreeServiceA": worktree / "service-a",
        "serviceB": repository / "service-b",
        "mixedCase": repository / "MixedCase",
        "worktreeMixedCase": worktree / "MixedCase",
        "clone": clone,
    }
    target_ids = {
        name: ensure_security_target(connection, str(target))
        for name, target in targets.items()
    }
    identities = {
        name: repository_identity(target)
        for name, target in targets.items()
    }
    common = os.path.realpath(git(
        repository, "rev-parse", "--path-format=absolute", "--git-common-dir"
    ))
    forged_identity = repository_identity(forged_worktree())
    (repository / "service-a" / "service.py").write_text("value = 2\n")
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "ordinary update")
    commit_independent = repository_identity(repository) == identities["repository"]
    additional_worktree = root / "additional-worktree"
    git(repository, "worktree", "add", "--detach", "-q", str(additional_worktree), "HEAD")
    worktree_independent = repository_identity(repository) == identities["repository"]
    git(repository, "worktree", "remove", "--force", str(additional_worktree))
    git(
        repository,
        "remote", "set-url", "origin",
        "https://different-user:DIFFERENT_SYNTHETIC_PASSWORD@example.test/other/repo.git",
    )
    remote_independent = repository_identity(repository) == identities["repository"]
    description = Path(common) / "description"
    description.write_text("An ordinary user-edited Git description.\n")
    description_edit_independent = repository_identity(repository) == identities["repository"]
    os.chmod(description, 0o400)
    description_mode_independent = repository_identity(repository) == identities["repository"]
    os.chmod(description, 0o600)
    description.unlink()
    description_absence_independent = repository_identity(repository) == identities["repository"]
    custom_template = root / "custom-template"
    custom_template.mkdir()
    git(custom_template, "init", "-q", "--template=")
    markerless_repository_identity = repository_identity(custom_template)
    with patch("workbench_target_state._repository_birth_time_ns", side_effect=(41, 100, 42, 100)):
        recycled_inode_distinguished = (
            repository_identity(repository) != repository_identity(repository)
        )
    original_normcase = os.path.normcase
    os.path.normcase = lambda path: os.fspath(path).lower()
    try:
        case_preserved = (
            repository_relative_path(repository / "MixedCase") == "MixedCase"
            and repository_identity(repository / "MixedCase") == identities["mixedCase"]
        )
    finally:
        os.path.normcase = original_normcase

    legacy_metadata = SimpleNamespace(st_ctime_ns=41)
    modern_metadata = SimpleNamespace(st_birthtime_ns=43, st_ctime_ns=41)
    with patch.object(os, "name", "nt"):
        windows_legacy_birth_time = _repository_birth_time_ns(common, legacy_metadata)
        windows_modern_birth_time = _repository_birth_time_ns(common, modern_metadata)
    linux_birth_times = {}
    with patch.object(sys, "platform", "linux"), patch.object(os, "name", "posix"), \
         patch("workbench_target_state._linux_repository_birth_time_ns", return_value=None):
        for label, output, status in (
            ("valid", "42.000000123\n", 0),
            ("unavailable", "0.000000000\n", 0),
            ("malformed", "42.123\n", 0),
            ("failed", "42.000000123\n", 1),
        ):
            with patch("workbench_target_state.subprocess.run") as stat_command:
                stat_command.return_value = SimpleNamespace(stdout=output, returncode=status)
                linux_birth_times[label] = _repository_birth_time_ns(common, legacy_metadata)
                if label == "valid":
                    linux_locale = stat_command.call_args.kwargs["env"]["LC_ALL"]
        with patch("workbench_target_state.subprocess.run", side_effect=OSError("missing stat")):
            linux_birth_times["missing"] = _repository_birth_time_ns(common, legacy_metadata)
    print(json.dumps({
        "identities": identities,
        "forgedIdentity": forged_identity,
        "commitIndependent": commit_independent,
        "worktreeIndependent": worktree_independent,
        "remoteIndependent": remote_independent,
        "descriptionEditIndependent": description_edit_independent,
        "descriptionModeIndependent": description_mode_independent,
        "descriptionAbsenceIndependent": description_absence_independent,
        "markerlessRepositoryIdentity": markerless_repository_identity,
        "recycledInodeDistinguished": recycled_inode_distinguished,
        "casePreserved": case_preserved,
        "windowsLegacyBirthTime": windows_legacy_birth_time,
        "windowsModernBirthTime": windows_modern_birth_time,
        "linuxBirthTimes": linux_birth_times,
        "linuxLocale": linux_locale,
        "targetIdsPreserved": all(
            target_ids[name] == stable_target_id(target)
            for name, target in targets.items()
        ),
        "stored": {
            row["current_path"]: row["repository_identity"]
            for row in connection.execute(
                "SELECT current_path, repository_identity FROM security_targets"
            )
        },
    }))

elif scenario == "history":
    add_scan("canonical-root", repository)
    add_scan("linked-root", worktree)
    add_scan("spoof-root", clone)
    add_scan("canonical-a", repository / "service-a")
    add_scan("linked-a", worktree / "service-a")
    add_scan("canonical-b", repository / "service-b")
    add_scan("spoof-a", clone / "service-a")
    add_scan("forged-root", forged_worktree())
    before = {
        "root": listed(repository),
        "serviceA": listed(repository / "service-a"),
        "serviceB": listed(repository / "service-b"),
    }
    git(repository, "worktree", "remove", "--force", str(worktree))
    after = {
        "root": listed(repository),
        "serviceA": listed(repository / "service-a"),
    }
    arguments = argparse.Namespace(repository=str(repository), force=False)
    matched = history.list_unmatched_scan_pairs(
        connection,
        arguments,
        backfill_finding_details=lambda _connection, _scan: None,
        read_coverage=lambda _scan: {},
    )

    def unavailable(scan):
        if scan["id"] == "linked-root":
            raise SystemExit("Saved scan artifacts are unavailable.")
        return {}

    unavailable_matches = history.list_unmatched_scan_pairs(
        connection,
        arguments,
        backfill_finding_details=lambda _connection, _scan: None,
        read_coverage=unavailable,
    )

    def require_scan(database, scan_id):
        return database.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    comparison_args = argparse.Namespace(
        before_scan_id="canonical-root",
        after_scan_id="linked-root",
        matches_json=json.dumps({"matches": [], "uncertain": []}),
    )
    compared = history.compare_scans(
        connection,
        comparison_args,
        require_scan=require_scan,
        read_coverage=lambda _scan: {"completeness": "complete"},
    )
    connection.commit()
    saved = history.save_scan_comparison(
        connection,
        comparison_args,
        now=lambda: timestamp,
        require_scan=require_scan,
        read_coverage=lambda _scan: {"completeness": "complete"},
    )
    explicit_clone = history.compare_scans(
        connection,
        argparse.Namespace(before_scan_id="canonical-root", after_scan_id="spoof-root"),
        require_scan=require_scan,
        read_coverage=lambda _scan: {"completeness": "complete"},
    )

    print(json.dumps({
        "before": before,
        "after": after,
        "matchedScanCount": matched["scanCount"],
        "matchingBatches": len(matched["batches"]),
        "unavailableScans": unavailable_matches["unavailableScans"],
        "compared": compared["beforeScanId"] == "canonical-root"
            and compared["afterScanId"] == "linked-root",
        "saved": saved["beforeScanId"] == "canonical-root"
            and saved["afterScanId"] == "linked-root",
        "explicitCloneCompared": explicit_clone["afterScanId"] == "spoof-root",
    }))

elif scenario == "backfill":
    add_scan("valid", repository)
    add_scan("reused", clone, "mismatch")
    add_scan("mixed-current", repository / "service-a")
    add_scan("mixed-previous", repository / "service-a", "mismatch")
    add_scan("malformed", repository / "service-b", "malformed")
    add_scan("missing", worktree)
    missing_path = str(worktree)
    git(repository, "worktree", "remove", "--force", missing_path)
    connection.execute("UPDATE security_targets SET repository_identity = NULL")
    before_ids = {
        row["current_path"]: row["id"]
        for row in connection.execute("SELECT id, current_path FROM security_targets")
    }
    backfill_repository_identities(connection)
    rows = {
        row["current_path"]: {"id": row["id"], "identity": row["repository_identity"]}
        for row in connection.execute(
            "SELECT id, current_path, repository_identity FROM security_targets"
        )
    }
    print(json.dumps({
        "valid": rows[str(repository)]["identity"],
        "reused": rows[str(clone)]["identity"],
        "mixed": rows[str(repository / "service-a")]["identity"],
        "malformed": rows[str(repository / "service-b")]["identity"],
        "missing": rows[missing_path]["identity"],
        "idsPreserved": all(rows[path]["id"] == target_id for path, target_id in before_ids.items()),
    }))

elif scenario == "replacement":
    add_scan("previous-owner", worktree)
    add_scan("trusted-alias", repository)
    git(repository, "worktree", "remove", "--force", str(worktree))
    worktree.mkdir()
    git(worktree, "init", "-q")
    (worktree / "replacement.py").write_text("value = 2\n")
    git(worktree, "add", ".")
    git(worktree, "commit", "-qm", "replacement")
    git(worktree, "remote", "add", "origin", sys.argv[7])
    before = listed(worktree)
    try:
        add_scan("replacement-owner", worktree)
    except SystemExit as error:
        registration_error = str(error)
    else:
        registration_error = None
    try:
        history.list_unmatched_scan_pairs(
            connection,
            argparse.Namespace(repository=str(worktree), force=False),
            backfill_finding_details=lambda _connection, _scan: None,
            read_coverage=lambda _scan: {},
        )
    except SystemExit as error:
        matching_error = str(error)
    else:
        matching_error = None
    after = listed(worktree)

    empty_target = clone / "service-a"
    ensure_security_target(connection, str(empty_target))
    connection.execute(
        "UPDATE security_targets SET repository_identity = ? WHERE current_path = ?",
        (repository_identity(repository), str(empty_target)),
    )
    try:
        ensure_security_target(connection, str(empty_target))
    except SystemExit as error:
        empty_target_error = str(error)
    else:
        empty_target_error = None

    explicit_clone_id = add_scan("explicit-clone", clone)
    connection.execute(
        "UPDATE security_targets SET repository_identity = ? WHERE id = ?",
        (repository_identity(repository), explicit_clone_id),
    )
    try:
        ensure_security_target(connection, str(clone))
    except SystemExit as error:
        explicit_clone_error = str(error)
    else:
        explicit_clone_error = None

    unverified_target = clone / "service-b"
    add_scan("unverified-owner", unverified_target, "missing")
    try:
        ensure_security_target(connection, str(unverified_target))
    except SystemExit as error:
        unverified_owner_error = str(error)
    else:
        unverified_owner_error = None
    print(json.dumps({
        "before": before,
        "after": after,
        "registrationError": registration_error,
        "matchingError": matching_error,
        "emptyTargetError": empty_target_error,
        "explicitCloneError": explicit_clone_error,
        "unverifiedOwnerError": unverified_owner_error,
        "replacementScanCreated": connection.execute(
            "SELECT 1 FROM scans WHERE id = 'replacement-owner'"
        ).fetchone() is not None,
    }))

elif scenario == "recreated-directory":
    target = repository / "service-a"
    linked = worktree / "service-a"
    target_id = add_scan("before-recreation", target)
    linked_id = add_scan("linked-scope", linked)
    original_metadata = target.stat()
    original_identity = repository_identity(target)
    original_scan = connection.execute(
        "SELECT target_device, target_inode FROM scans WHERE id = 'before-recreation'"
    ).fetchone()

    shutil.rmtree(target)
    (root / "retired-directory-inode").mkdir()
    target.mkdir()
    (target / "service.py").write_text("value = 2\n")
    recreated_metadata = target.stat()
    before_rescan = listed(target)
    before_aliases = repository_target_ids(connection, target_id)
    recreated_id = add_scan("after-recreation", target)
    repeated_id = add_scan("repeated-rescan", target)
    after_rescan = listed(target)
    after_aliases = repository_target_ids(connection, target_id)

    malformed_target = repository / "service-b"
    add_scan("malformed-owner", malformed_target, "malformed")
    try:
        ensure_security_target(connection, str(malformed_target))
    except SystemExit as error:
        malformed_owner_error = str(error)
    else:
        malformed_owner_error = None

    plain = root / "recreated-nongit"
    plain.mkdir()
    add_scan("plain-before-recreation", plain)
    shutil.rmtree(plain)
    (root / "retired-nongit-inode").mkdir()
    plain.mkdir()
    try:
        ensure_security_target(connection, str(plain))
    except SystemExit as error:
        nongit_owner_error = str(error)
    else:
        nongit_owner_error = None

    root_target_id = add_scan("linked-root-before", worktree)
    add_scan("canonical-root-alias", repository)
    root_identity = repository_identity(worktree)
    root_metadata = worktree.stat()
    git_pointer = (worktree / ".git").read_text()
    shutil.rmtree(worktree)
    (root / "retired-worktree-root-inode").mkdir()
    worktree.mkdir()
    (worktree / ".git").write_text(git_pointer)
    try:
        ensure_security_target(connection, str(worktree))
    except SystemExit as error:
        recreated_root_error = str(error)
    else:
        recreated_root_error = None

    preserved_scan = connection.execute(
        "SELECT target_device, target_inode FROM scans WHERE id = 'before-recreation'"
    ).fetchone()
    print(json.dumps({
        "ownerChanged": (
            original_metadata.st_dev != recreated_metadata.st_dev
            or original_metadata.st_ino != recreated_metadata.st_ino
        ),
        "identityPreserved": repository_identity(target) == original_identity,
        "targetIdPreserved": recreated_id == target_id and repeated_id == target_id,
        "historicalOwnerPreserved": (
            preserved_scan["target_device"] == original_scan["target_device"]
            and preserved_scan["target_inode"] == original_scan["target_inode"]
        ),
        "beforeRescan": before_rescan,
        "afterRescan": after_rescan,
        "beforeAliases": sorted(before_aliases),
        "afterAliases": sorted(after_aliases),
        "expectedAliases": sorted((target_id, linked_id)),
        "malformedOwnerError": malformed_owner_error,
        "nongitOwnerError": nongit_owner_error,
        "rootOwnerChanged": root_metadata.st_ino != worktree.stat().st_ino,
        "rootIdentityPreserved": repository_identity(worktree) == root_identity,
        "recreatedRootError": recreated_root_error,
        "recreatedRootScans": listed(worktree),
        "recreatedRootAliases": sorted(repository_target_ids(connection, root_target_id)),
    }))

elif scenario == "candidate-generation":
    add_scan("requested-scan", repository)
    legacy_id = add_scan("trusted-alias", worktree)
    candidate_id = add_scan("previous-generation", clone)
    requested_identity = repository_identity(repository)
    candidate_identity = repository_identity(clone)

    def live_identity(target):
        details = _repository_identity_details(target)
        return replace(details, value=requested_identity) if Path(target) == clone else details

    def automatic_history():
        matching = history.list_unmatched_scan_pairs(
            connection,
            argparse.Namespace(repository=str(repository), force=False),
            backfill_finding_details=lambda _connection, _scan: None,
            read_coverage=lambda _scan: {},
        )
        matching_ids = {
            batch["afterScanId"] for batch in matching["batches"]
        } | {
            scan["scanId"]
            for batch in matching["batches"]
            for scan in batch["beforeScans"]
        }
        return {
            "scans": listed(repository),
            "matchingScanCount": matching["scanCount"],
            "matchingScanIds": sorted(matching_ids),
        }

    with patch("workbench_target_state._repository_identity_details", side_effect=live_identity):
        persisted = automatic_history()
        connection.execute(
            "UPDATE security_targets SET repository_identity = NULL WHERE id = ?",
            (legacy_id,),
        )
        connection.execute(
            "UPDATE scans SET repository_generation = NULL WHERE id = ?", ("trusted-alias",)
        )
        verified_legacy = automatic_history()
        connection.execute(
            "UPDATE scans SET target_device = NULL, target_inode = NULL WHERE id = ?",
            ("trusted-alias",),
        )
        unverified_legacy = automatic_history()

    print(json.dumps({
        "persisted": persisted,
        "verifiedLegacy": verified_legacy,
        "unverifiedLegacy": unverified_legacy,
        "candidateIdentityPreserved": connection.execute(
            "SELECT repository_identity FROM security_targets WHERE id = ?",
            (candidate_id,),
        ).fetchone()[0] == candidate_identity,
    }))

elif scenario == "git-replacement":
    add_scan("original-repository", repository)
    add_scan("original-alias", worktree)
    original_identity = repository_identity(repository)
    original_metadata = repository.stat()

    def remove_read_only(operation, path, _error):
        os.chmod(path, 0o700)
        operation(path)

    shutil.rmtree(repository / ".git", onerror=remove_read_only)
    git(repository, "init", "-q")
    git(repository, "add", ".")
    git(repository, "commit", "-qm", "replacement")
    replacement_identity = repository_identity(repository)
    try:
        ensure_security_target(connection, str(repository))
    except SystemExit as error:
        registration_error = str(error)
    else:
        registration_error = None
    replacement_metadata = repository.stat()
    print(json.dumps({
        "originalIdentity": original_identity,
        "replacementIdentity": replacement_identity,
        "checkoutOwnerUnchanged": (
            original_metadata.st_dev == replacement_metadata.st_dev
            and original_metadata.st_ino == replacement_metadata.st_ino
        ),
        "visibleScans": listed(repository),
        "registrationError": registration_error,
    }))

elif scenario == "unverified-owner":
    ensure_security_target(connection, str(repository))
    add_scan("trusted-alias", worktree)
    git(repository, "worktree", "remove", "--force", str(worktree))
    before = listed(repository)
    add_scan("unverified-owner", repository, "missing")
    after = listed(repository)
    print(json.dumps({
        "before": before,
        "after": after,
    }))

elif scenario == "nongit":
    first = root / "plain-a"
    second = root / "plain-b"
    first.mkdir()
    second.mkdir()
    add_scan("plain-a", first)
    add_scan("legacy-a", first, "missing")
    add_scan("malformed-a", first, "malformed", verify_ownership=False)
    add_scan("mismatched-a", first, "mismatch", verify_ownership=False)
    add_scan("plain-b", second)
    before = connection.execute(
        "SELECT NULL AS target_id, ? AS target_path", (str(first),)
    ).fetchone()
    after = connection.execute(
        "SELECT NULL AS target_id, ? AS target_path", (str(second),)
    ).fetchone()
    same = connection.execute(
        "SELECT NULL AS target_id, ? AS target_path", (str(first),)
    ).fetchone()
    print(json.dumps({
        "firstIdentity": repository_identity(first),
        "secondIdentity": repository_identity(second),
        "differentNullIdsMatch": history._same_repository(connection, before, after),
        "sameNullPathMatches": history._same_repository(connection, before, same),
        "firstScans": listed(first),
        "secondScans": listed(second),
    }))
`;

function runProbe(
  scenario: string,
  repositories: ReturnType<typeof fixture>,
): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");
  const execution = spawnSync(
    python,
    [
      "-I",
      "-B",
      "-c",
      probe,
      join(PLUGIN_ROOT, "scripts"),
      scenario,
      repositories.root,
      repositories.repository,
      repositories.worktree,
      repositories.clone,
      remote,
    ],
    { encoding: "utf8", timeout: 20_000 },
  );
  expect(execution.status, execution.stderr).toBe(0);
  expect(execution.stderr).toBe("");
  return JSON.parse(execution.stdout) as Record<string, unknown>;
}

describe("durable workbench repository identities", () => {
  test("hashes Git common directories and repository-relative target scopes", () => {
    const repositories = fixture();
    const result = runProbe("identity", repositories);
    const identities = result["identities"] as Record<string, string>;

    expect(identities["repository"]).toMatch(
      /^repository_sha256_[a-f0-9]{64}$/,
    );
    expect(identities["worktree"]).toBe(identities["repository"]);
    expect(identities["worktreeServiceA"]).toBe(identities["serviceA"]);
    expect(identities["worktreeMixedCase"]).toBe(identities["mixedCase"]);
    expect(identities["serviceA"]).not.toBe(identities["repository"]);
    expect(identities["serviceA"]).not.toBe(identities["serviceB"]);
    expect(identities["clone"]).not.toBe(identities["repository"]);
    expect(result["forgedIdentity"]).toBeNull();
    expect(result["commitIndependent"]).toBe(true);
    expect(result["worktreeIndependent"]).toBe(true);
    expect(result["remoteIndependent"]).toBe(true);
    expect(result["descriptionEditIndependent"]).toBe(true);
    expect(result["descriptionModeIndependent"]).toBe(true);
    expect(result["descriptionAbsenceIndependent"]).toBe(true);
    expect(result["markerlessRepositoryIdentity"]).toMatch(
      /^repository_sha256_[a-f0-9]{64}$/,
    );
    expect(result["recycledInodeDistinguished"]).toBe(true);
    expect(result["casePreserved"]).toBe(true);
    expect(result["windowsLegacyBirthTime"]).toBe(41);
    expect(result["windowsModernBirthTime"]).toBe(43);
    expect(result["linuxBirthTimes"]).toEqual({
      valid: 42_000_000_123,
      unavailable: null,
      malformed: null,
      failed: null,
      missing: null,
    });
    expect(result["linuxLocale"]).toBe("C");
    expect(result["targetIdsPreserved"]).toBe(true);
    expect(JSON.stringify(result["stored"])).not.toContain(
      "SYNTHETIC_PASSWORD",
    );
  }, 30_000);

  test("retains removed worktrees while excluding spoofed origins and unrelated scopes", () => {
    const result = runProbe("history", fixture());
    const before = result["before"] as Record<string, string[]>;
    const after = result["after"] as Record<string, string[]>;

    expect(before["root"]).toEqual(["canonical-root", "linked-root"]);
    expect(before["serviceA"]).toEqual(["canonical-a", "linked-a"]);
    expect(before["serviceB"]).toEqual(["canonical-b"]);
    expect(after["root"]).toEqual(["canonical-root", "linked-root"]);
    expect(after["serviceA"]).toEqual(["canonical-a", "linked-a"]);
    expect(result["matchedScanCount"]).toBe(2);
    expect(result["matchingBatches"]).toBe(1);
    expect(result["unavailableScans"]).toBe(1);
    expect(result["compared"]).toBe(true);
    expect(result["saved"]).toBe(true);
    expect(result["explicitCloneCompared"]).toBe(true);
  }, 30_000);

  test("leaves unproved historical identities unbound and preserves every target ID", () => {
    const result = runProbe("backfill", fixture());

    expect(result["valid"]).toBeNull();
    expect(result["reused"]).toBeNull();
    expect(result["mixed"]).toBeNull();
    expect(result["malformed"]).toBeNull();
    expect(result["missing"]).toBeNull();
    expect(result["idsPreserved"]).toBe(true);
  }, 30_000);

  test("does not expose a previous checkout owner or its trusted aliases", () => {
    const result = runProbe("replacement", fixture());

    expect(result["before"]).toEqual([]);
    expect(result["after"]).toEqual([]);
    expect(result["registrationError"]).toContain(
      "refusing to reuse its target",
    );
    expect(result["matchingError"]).toContain("refusing to reuse its target");
    expect(result["emptyTargetError"]).toContain(
      "refusing to reuse its target",
    );
    expect(result["replacementScanCreated"]).toBe(false);
    expect(result["explicitCloneError"]).toContain(
      "refusing to reuse its target",
    );
    expect(result["unverifiedOwnerError"]).toContain(
      "refusing to reuse its target",
    );
  }, 30_000);

  test("rejects an in-place Git directory replacement under the same checkout", () => {
    const result = runProbe("git-replacement", fixture());

    expect(result["checkoutOwnerUnchanged"]).toBe(true);
    expect(result["replacementIdentity"]).not.toBe(result["originalIdentity"]);
    expect(result["visibleScans"]).toEqual([]);
    expect(result["registrationError"]).toContain(
      "refusing to reuse its target",
    );
  }, 30_000);

  test("does not discover historical targets through a conflicting live generation", () => {
    const result = runProbe("candidate-generation", fixture());
    const verified = {
      scans: ["requested-scan", "trusted-alias"],
      matchingScanCount: 2,
      matchingScanIds: ["requested-scan", "trusted-alias"],
    };

    expect(result["persisted"]).toEqual(verified);
    const isolated = {
      scans: ["requested-scan"],
      matchingScanCount: 1,
      matchingScanIds: [],
    };
    expect(result["verifiedLegacy"]).toEqual(isolated);
    expect(result["unverifiedLegacy"]).toEqual(isolated);
    expect(result["candidateIdentityPreserved"]).toBe(true);
  }, 30_000);

  test("rescans recreated directories when their Git repository and scope are unchanged", () => {
    const result = runProbe("recreated-directory", fixture());

    expect(result["ownerChanged"]).toBe(true);
    expect(result["identityPreserved"]).toBe(true);
    expect(result["targetIdPreserved"]).toBe(true);
    expect(result["historicalOwnerPreserved"]).toBe(true);
    expect(result["beforeRescan"]).toEqual([
      "before-recreation",
      "linked-scope",
    ]);
    expect(result["afterRescan"]).toEqual([
      "after-recreation",
      "before-recreation",
      "linked-scope",
      "repeated-rescan",
    ]);
    expect(result["beforeAliases"]).toEqual(result["expectedAliases"]);
    expect(result["afterAliases"]).toEqual(result["expectedAliases"]);
    expect(result["malformedOwnerError"]).toContain(
      "refusing to reuse its target",
    );
    expect(result["nongitOwnerError"]).toContain(
      "refusing to reuse its target",
    );
    expect(result["rootOwnerChanged"]).toBe(true);
    expect(result["rootIdentityPreserved"]).toBe(true);
    expect(result["recreatedRootError"]).toContain(
      "refusing to reuse its target",
    );
    expect(result["recreatedRootScans"]).toEqual([]);
    expect(result["recreatedRootAliases"]).toEqual([]);
  }, 30_000);

  test("does not expand trusted aliases when historical checkout ownership is unverified", () => {
    const result = runProbe("unverified-owner", fixture());

    expect(result["before"]).toEqual(["trusted-alias"]);
    expect(result["after"]).toEqual([]);
  }, 30_000);

  test("keeps non-Git paths isolated and never equates unrelated null target IDs", () => {
    const result = runProbe("nongit", fixture());

    expect(result["firstIdentity"]).toBeNull();
    expect(result["secondIdentity"]).toBeNull();
    expect(result["differentNullIdsMatch"]).toBe(false);
    expect(result["sameNullPathMatches"]).toBe(false);
    expect(result["firstScans"]).toEqual([]);
    expect(result["secondScans"]).toEqual(["plain-b"]);
  }, 30_000);
});
