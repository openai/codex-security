import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const probe = String.raw`
import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
from collections import Counter
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
import workbench_native_indexes as indexes
import workbench_target_state as state
import workbench_feedback as feedback_module
import workbench_db as workbench
import workbench_scan_start as scan_start
import deep_scan_workbench as deep_workbench
from workbench_feedback import get_scan_feedback
from workbench_schema import MIGRATIONS, apply_migrations

scenario = sys.argv[2]
timestamp = "2026-08-01T00:00:00Z"
root = Path.cwd() / "synthetic-identity-fixture"
connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
legacy_identity_migration = (
    30, "persist repository identities",
    "ALTER TABLE security_targets ADD COLUMN repository_identity TEXT;\n"
    "CREATE INDEX security_targets_by_repository_identity ON security_targets(repository_identity);\n",
)
recorded_identity31 = scenario == "migration-recorded31"
initial = (
    (*tuple(item for item in MIGRATIONS if item[0] <= 28), legacy_identity_migration)
    if scenario in ("migration", "v30-current", "completion-order") else
    tuple(item for item in MIGRATIONS if item[0] <= 30)
    if scenario == "null-history" or recorded_identity31 else MIGRATIONS
)
apply_migrations(connection, initial, lambda: timestamp, lambda database: None)
if recorded_identity31:
    connection.executescript(legacy_identity_migration[2])
    connection.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, ?)",
        (31, legacy_identity_migration[1], timestamp),
    )
paths = {}
details = {}
metadata = {}
missing = set()
resolution_errors = {}
probes = Counter()
origins = Counter()
real_identity_details = state._repository_identity_details
description = SimpleNamespace(
    st_mode=stat.S_IFREG, st_dev=44, st_ino=55, st_ctime_ns=66
)


def add_target(name, stored, live=None, relative=".", birth=1_000_000_000):
    path = str(root / name)
    paths[name] = path
    metadata[path] = SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=7, st_ino=100 + len(paths))
    details[path] = state.GitRepositoryIdentity(
        live or stored or "repository-current", relative, str(root / "common"), 11, 22, birth
    )
    if state.supports_repository_identity(connection):
        connection.execute(
            "INSERT INTO security_targets "
            "(id, current_path, display_name, created_at, updated_at, repository_identity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, path, name, timestamp, timestamp, stored),
        )
    else:
        connection.execute(
            "INSERT INTO security_targets "
            "(id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (name, path, name, timestamp, timestamp),
        )
    return details[path]


current_generation = object()


def add_scan(scan_id, target, owner="current", started=timestamp, created=timestamp,
             generation=current_generation, status="complete"):
    path = paths[target]
    device, inode = metadata[path].st_dev, metadata[path].st_ino
    if owner == "missing":
        device, inode = None, None
    elif owner == "mismatch":
        inode += 1
    connection.execute(
        "INSERT INTO workspaces (id, target_path, target_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("workspace-" + scan_id, path, target, timestamp, timestamp),
    )
    supports_generation = any(
        row["name"] == "repository_generation"
        for row in connection.execute("PRAGMA table_info(scans)")
    )
    if generation is current_generation:
        generation = connection.execute(
            "SELECT repository_identity FROM security_targets WHERE id = ?", (target,)
        ).fetchone()[0] if state.supports_repository_identity(connection) else None
    include_generation = supports_generation and generation is not None
    generation_column = ", repository_generation" if include_generation else ""
    generation_placeholder = ", ?" if include_generation else ""
    connection.execute(
        "INSERT INTO scans (id, workspace_id, target_path, target_id, target_device, "
        "target_inode, target_revision, scope, mode, scan_dir, status, phase, "
        f"started_at, completed_at, created_at, updated_at{generation_column}) "
        f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?{generation_placeholder})",
        (scan_id, "workspace-" + scan_id, path, target, device, inode, "synthetic",
         ".", "standard", str(root / "scans" / scan_id), status, "reporting",
         started, created if status == "complete" else None, created, created,
         *((generation,) if include_generation else ())),
    )
    connection.execute(
        "INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
        (scan_id, timestamp),
    )


def add_finding(scan_id, finding_id, closed=False):
    occurrence = scan_id + ":" + finding_id
    connection.execute(
        "INSERT OR IGNORE INTO findings "
        "(id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (finding_id, "fingerprint-" + finding_id, "synthetic-rule", finding_id, timestamp, timestamp),
    )
    connection.execute(
        "INSERT INTO finding_occurrences "
        "(id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (occurrence, finding_id, scan_id, finding_id, "Synthetic summary", "high",
         "high", "Synthetic remediation", timestamp),
    )
    connection.execute(
        "INSERT INTO finding_locations "
        "(occurrence_id, relative_path, start_line, end_line, role, sort_order) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (occurrence, "src/example.py", 1, 1, "root_control", 0),
    )
    if closed:
        connection.execute(
            "INSERT INTO finding_triage VALUES (?, ?, ?, ?, ?)",
            (occurrence, "closed", "false_positive", "Synthetic review", timestamp),
        )
    return occurrence


original_resolve, original_stat, original_lstat = Path.resolve, Path.stat, Path.lstat


def resolve_path(path, *args, **kwargs):
    value = str(path)
    if value in resolution_errors:
        raise resolution_errors[value]("Synthetic path resolution failure")
    return path if value in metadata else original_resolve(path, *args, **kwargs)


def stat_path(path, *args, **kwargs):
    value = str(path)
    if value in missing:
        raise FileNotFoundError(errno.ENOENT, "Synthetic missing path", value)
    return metadata[value] if value in metadata else original_stat(path, *args, **kwargs)


def lstat_path(path, *args, **kwargs):
    if path.name == "description" and path.parent == root / "common":
        return description
    return original_lstat(path, *args, **kwargs)


def identity_details(path):
    value = str(path)
    probes[value] += 1
    return details.get(value)


def origin(path):
    value = str(path)
    origins[value] += 1
    identity = details.get(value)
    return ("example.test", identity.value) if identity is not None else None


def listed(target):
    args = argparse.Namespace(
        repository=paths[target], scan_root=None, target_id=None, mode=None,
        status=None, query=None, limit=None, offset=0,
    )
    return sorted(row["scanId"] for row in history.list_scans(connection, args)["scans"])


def findings(target):
    return indexes.list_global_findings(
        connection,
        argparse.Namespace(target_id=target, limit=50, offset=0, query=None, severity=None, status=None),
    )["findings"]


def legacy_hash(identity, with_description=False):
    directory = os.path.normcase(identity.common_directory)
    relative = os.path.normcase(os.fspath(Path(identity.relative_path))).replace(os.sep, "/")
    material = f"git-common-dir\0{directory}\0{identity.device}\0{identity.inode}\0"
    if with_description:
        material += f"git-description\0{description.st_dev}\0{description.st_ino}\0{description.st_ctime_ns}\0"
    return "repository_sha256_" + hashlib.sha256((material + relative).encode()).hexdigest()


with ExitStack() as stack:
    stack.enter_context(patch.object(Path, "resolve", resolve_path))
    stack.enter_context(patch.object(Path, "stat", stat_path))
    stack.enter_context(patch.object(Path, "lstat", lstat_path))
    stack.enter_context(patch.object(state, "_repository_identity_details", identity_details))
    stack.enter_context(patch.object(state, "repository_origin", origin))
    if scenario == "generation-metadata":
        main = root / "main\ncheckout"
        linked = root / "linked\ncheckout"
        common = main / ".git"
        admin = common / "worktrees" / "linked"
        objects = common / "objects"
        active = {"root": main, "gitdir": common, "nul": False, "config": None}
        config_command = ("config", "--null", "--show-scope", "--no-includes", "--get", "core.worktree")
        commands = []
        directory = lambda inode, birth: SimpleNamespace(
            st_mode=stat.S_IFDIR, st_dev=7, st_ino=inode, st_birthtime_ns=birth
        )
        records = {
            str(common): directory(20, 100), str(objects): directory(21, 200),
            str(admin): directory(22, 300),
            str(linked / ".git"): SimpleNamespace(st_mode=stat.S_IFREG),
        }
        files = {
            str(linked / ".git"): b"gitdir: " + os.fsencode(admin) + b"\n",
            str(admin / "gitdir"): os.fsencode(linked / ".git") + b"\n",
        }
        def git_bytes(target, *arguments):
            commands.append(arguments)
            if arguments == ("worktree", "list", "--porcelain", "-z"):
                return b"worktree " + os.fsencode(active["root"]) + b"\0\0" if active["nul"] else None
            if arguments == config_command:
                return active["config"]
            paths_by_command = {
                ("rev-parse", "--show-toplevel"): active["root"],
                ("rev-parse", "--path-format=absolute", "--git-common-dir"): common,
                ("rev-parse", "--absolute-git-dir"): active["gitdir"],
                ("rev-parse", "--path-format=absolute", "--git-path", "objects"): objects,
            }
            value = paths_by_command.get(arguments)
            return os.fsencode(value) + b"\n" if value is not None else None
        primary = root / "primary-checkout"
        def file_primary(configuration, selected_root=primary, forward=common):
            active.update(root=selected_root, gitdir=common, nul=False, config=configuration)
            records[str(selected_root / ".git")] = SimpleNamespace(st_mode=stat.S_IFREG)
            files[str(selected_root / ".git")] = b"gitdir: " + os.fsencode(forward) + b"\n"
            return real_identity_details(selected_root) is not None
        def configured(value, scope=b"local"):
            return scope + b"\0" + os.fsencode(value) + b"\0"
        # Keep directory checks inside the metadata fixture on every supported Python.
        with patch.object(state, "git_bytes", git_bytes), \
             patch.object(os.path, "realpath", side_effect=os.path.abspath), \
             patch.object(Path, "stat", lambda path, *a, **k: records[str(path)]), \
             patch.object(Path, "lstat", lambda path, *a, **k: records[str(path)]), \
             patch.object(Path, "is_dir", lambda path, *a, **k: stat.S_ISDIR(records[str(path)].st_mode)), \
             patch.object(Path, "read_bytes", lambda path: files[str(path)]), \
             patch.object(state, "_repository_birth_time_ns", side_effect=lambda path, value: value.st_birthtime_ns):
            first = real_identity_details(main)
            same = real_identity_details(main)
            active.update(root=linked, gitdir=admin)
            old_linked = real_identity_details(linked)
            files[str(admin / "gitdir")] = os.fsencode(main / ".git") + b"\n"
            wrong_backlink = real_identity_details(linked)
            files[str(admin / "gitdir")] = os.fsencode(linked / ".git") + b"\n"
            active["nul"] = True
            nul_linked = real_identity_details(linked)
            records[str(objects)] = directory(23, 400)
            changed = real_identity_details(linked)
            literal_tilde = common / "~literal" / "checkout"
            trailing_lf = root / "primary-checkout\n"
            trailing_space = root / "primary-checkout "
            primary_results = {
                "localAbsolute": file_primary(configured(primary)),
                "worktreeRelative": file_primary(configured(os.path.relpath(primary, common), b"worktree")),
                "literalLeadingTilde": file_primary(configured(Path("~literal") / "checkout"), literal_tilde),
                "trailingLineFeed": file_primary(configured(trailing_lf), trailing_lf),
                "trailingWhitespace": file_primary(configured(trailing_space), trailing_space),
                "missing": file_primary(None),
                "wrongScopes": all(not file_primary(configured(primary, scope)) for scope in (
                    b"global", b"system", b"command", b"unknown",
                )),
                "malformed": all(not file_primary(value) for value in (
                    b"local\0", b"local\0\0", configured(primary)[:-1],
                    configured(primary) + b"extra\0",
                )),
                "wrongRoot": file_primary(configured(main)),
                "foreignForward": file_primary(configured(primary), forward=root / "other-common"),
            }
        print(json.dumps({
            "oldMain": first is not None,
            "oldLinkedMatches": old_linked.value == first.value,
            "nulMatches": nul_linked.value == first.value,
            "wrongBacklink": wrong_backlink,
            "unchanged": same.value == first.value,
            "objectInstanceChangesGeneration": changed.value != first.value,
            "legacyMaterialUnchanged": changed.legacy_value == first.legacy_value,
            "domainSeparated": first.value != first.legacy_value,
            "actualObjectLookup": ("rev-parse", "--path-format=absolute", "--git-path", "objects") in commands,
            "oldPrimary": primary_results,
            "rawConfigLookup": any(command == config_command for command in commands)
                and all(command == config_command for command in commands if command[0] == "config"),
        }))
    elif scenario == "scan-generation":
        for name, value in (("requested", "generation-current"), ("alias", "generation-current"),
                            ("clone", "generation-clone")):
            add_target(name, value)
        add_scan("requested-new", "requested")
        add_scan("alias-proved", "alias")
        add_scan("alias-old-client", "alias", generation=None)
        add_scan("requested-legacy", "requested", generation=None)
        add_scan("clone-scan", "clone")
        proved = add_finding("alias-proved", "proved-review", closed=True)
        ignored = add_finding("alias-old-client", "unproved-review", closed=True)
        current = add_finding("requested-new", "current-open")
        add_finding("requested-legacy", "local-review", closed=True)
        connection.execute("INSERT INTO scan_comparisons VALUES (?, ?, ?, ?, ?)",
                           ("alias-old-client", "requested-new", "{}", timestamp, timestamp))
        connection.execute("INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)",
                           ("alias-old-client", "requested-new", ignored, current, "Synthetic match"))
        cache = state.RepositoryIdentityCache(connection)
        scope = cache.scope("requested")
        clause, values = scope.sql()
        selected = sorted(row[0] for row in connection.execute(f"SELECT id FROM scans WHERE {clause}", values))
        feedback = get_scan_feedback(connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-new'").fetchone())
        indexed = findings("requested")
        with patch.object(state, "repository_origin", return_value=("example.test", "same-repository")):
            rows = {row["id"]: row for row in connection.execute("SELECT * FROM scans")}
            explicit_clones = history._same_repository(connection, rows["requested-new"], rows["clone-scan"])
            explicit_legacy = history._same_repository(connection, rows["alias-old-client"], rows["clone-scan"])
            contradictory = dict(rows["clone-scan"], repository_generation="different-snapshot")
            own_contradiction = history._same_repository(connection, rows["requested-new"], contradictory)
        legacy = add_target("weak", None, "generation-strong")
        connection.execute("UPDATE security_targets SET repository_identity = ? WHERE id = 'weak'", (legacy.legacy_value,))
        add_scan("weak-history", "weak", generation=None)
        registration = state.register_security_target(connection, paths["weak"])
        add_finding("requested-new", "shared-decision", closed=True)
        add_finding("alias-proved", "shared-decision")
        missing.add(paths["alias"])
        absent_findings = sum(row["status"] == "open" for row in findings("alias"))
        absent_repository = next(row for row in indexes.list_repositories(connection)["repositories"] if row["targetId"] == "alias")
        print(json.dumps({
            "selected": selected,
            "predicate": {"binds": len(values), "ors": clause.count(" OR ")},
            "feedback": sorted(row["findingId"] for row in feedback["falsePositives"]),
            "findings": sorted((row["findingId"], row["occurrenceCount"], row["status"]) for row in indexed),
            "oldClientGeneration": rows["alias-old-client"]["repository_generation"],
            "explicitClones": explicit_clones, "explicitLegacy": explicit_legacy,
            "ownContradiction": own_contradiction,
            "weakRegistration": registration.repository_generation,
            "weakHistory": connection.execute("SELECT repository_generation FROM scans WHERE id = 'weak-history'").fetchone()[0],
            "weakBindingPreserved": connection.execute("SELECT repository_identity FROM security_targets WHERE id = 'weak'").fetchone()[0] == legacy.legacy_value,
            "absentExactCounts": [absent_findings, absent_repository["openFindingsCount"]],
        }))
    elif scenario == "repository-counts":
        for name, stored, live in (
            ("first", "shared-generation", None),
            ("second", "shared-generation", None),
            ("absent", "shared-generation", None),
            ("independent", "other-generation", None),
            ("refused", "previous-generation", "current-generation"),
        ):
            add_target(name, stored, live)
            add_scan(name + "-scan", name)
        add_scan("first-legacy", "first", generation=None)
        add_scan("second-legacy", "second", generation=None)
        add_finding("first-scan", "shared-open")
        add_finding("second-scan", "shared-open")
        add_finding("first-legacy", "first-local")
        add_finding("second-legacy", "second-local")
        reviewed = add_finding("first-scan", "reviewed-original", closed=True)
        renamed = add_finding("absent-scan", "reviewed-renamed")
        add_finding("independent-scan", "independent-open")
        add_finding("refused-scan", "refused-open")
        connection.execute("INSERT INTO scan_comparisons VALUES (?, ?, ?, ?, ?)",
                           ("first-scan", "absent-scan", "{}", timestamp, timestamp))
        connection.execute("INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)",
                           ("first-scan", "absent-scan", reviewed, renamed, "Synthetic match"))
        missing.add(paths["absent"])
        real_index = indexes._indexed_findings
        real_inspect = state._inspect_repository_target
        def repository_counts(**options):
            args = argparse.Namespace(query=None, target_id=None, status=None, limit=None, offset=0)
            vars(args).update(options)
            calls, inspections = [], []
            def indexed(database, **kwargs):
                scope = kwargs.get("scan_scope")
                calls.append(None if scope is None else scope.target_id)
                return real_index(database, **kwargs)
            def inspected(database, target_id, *args, **kwargs):
                inspections.append(target_id)
                return real_inspect(database, target_id, *args, **kwargs)
            with patch.object(indexes, "_indexed_findings", side_effect=indexed), \
                 patch.object(state, "_inspect_repository_target", side_effect=inspected):
                result = indexes.list_repositories(connection, args)
            return {
                "counts": {row["targetId"]: row["openFindingsCount"] for row in result["repositories"]},
                "ids": [row["targetId"] for row in result["repositories"]],
                "calls": calls, "inspections": sorted(inspections),
                "nextOffset": result.get("nextOffset"),
            }
        all_repositories = repository_counts()
        direct_counts = {
            name: sum(row["status"] == "open" for row in findings(name)) for name in paths
        }
        open_repositories = repository_counts(status="open_findings")
        page = repository_counts(status="open_findings", limit=2, offset=1)
        print(json.dumps({
            "all": all_repositories,
            "directCounts": direct_counts,
            "absentOnly": repository_counts(target_id="absent"),
            "queryOnly": repository_counts(query="INDEPENDENT"),
            "refusedOnly": repository_counts(target_id="refused"),
            "notScanned": repository_counts(status="not_scanned"),
            "openIds": open_repositories["ids"],
            "pagePreserved": page["ids"] == open_repositories["ids"][1:3] and page["nextOffset"] == 3,
        }))
    elif scenario == "scan-writers":
        add_target("writer", "generation-writer")
        target = Path(paths["writer"])
        connection.execute("INSERT INTO workspaces (id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                           ("current-workspace", "writer", str(target), timestamp, timestamp))
        connection.commit()
        checks = []
        def register(database, path):
            checks.append(database.in_transaction)
            return state.register_security_target(database, path)
        connection.execute("BEGIN IMMEDIATE")
        registration = register(connection, str(target))
        scan_start.insert_running_scan(
            connection, scan_id="current-writer", workspace=connection.execute("SELECT * FROM workspaces WHERE id = 'current-workspace'").fetchone(),
            target=target, scope=".", diff_target=None,
            target_identity=("synthetic", None, 7, metadata[str(target)].st_ino),
            repository_generation=registration.repository_generation,
            target_root=root / "artifacts", target_summary=None, scope_file_count=0,
            timestamp=timestamp, scan_dir=root / "artifacts" / "current",
        )
        connection.commit()
        add_scan("old-writer", "writer", generation=None)
        connection.commit()
        with ExitStack() as mocks:
            for name, value in {
                "require_target": target, "require_remediation_target": target,
                "require_scope": ".", "existing_deep_scan_for_target": None,
                "terminal_deep_scan_for_target_snapshot": None, "git_revision": "synthetic",
                "worktree_content_digest": "snapshot", "directory_snapshot_regular_file_count": 0,
                "effective_deep_scan_config": {}, "now": timestamp,
                "compact_timestamp": "synthetic", "state_dir": root,
            }.items():
                mocks.enter_context(patch.object(deep_workbench, name, return_value=value))
            mocks.enter_context(patch.object(deep_workbench, "require_scannable_target"))
            mocks.enter_context(patch.object(deep_workbench, "safe_segment", side_effect=lambda value: value))
            mocks.enter_context(patch.object(deep_workbench, "register_security_target", side_effect=register))
            mocks.enter_context(patch.object(deep_workbench, "require_scan", side_effect=lambda database, scan_id: database.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()))
            mocks.enter_context(patch.object(deep_workbench, "ensure_deep_scan_run"))
            mocks.enter_context(patch.object(deep_workbench, "deep_scan_result", side_effect=lambda database, scan_id, **kwargs: {"scanId": scan_id}))
            mocks.enter_context(patch.object(Path, "mkdir"))
            mocks.enter_context(patch.object(Path, "resolve", lambda path, *a, **k: path))
            mocks.enter_context(patch.object(deep_workbench.tempfile, "mkdtemp", return_value=str(root / "artifacts" / "deep")))
            deep = deep_workbench.begin_deep_scan_for_target(connection, argparse.Namespace(
                target_path=str(target), scope=".", workflow_version="synthetic", scan_root=str(root / "artifacts"),
                user_context=None, model=None, reasoning_effort=None,
            ), "synthetic-thread")
        print(json.dumps({
            "generations": {row["id"]: row["repository_generation"] for row in connection.execute("SELECT id, repository_generation FROM scans")},
            "deepId": deep["scanId"], "registeredInsideTransaction": checks,
            "generationIndex": connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'scans_by_repository_generation'").fetchone() is not None,
        }))
    elif scenario == "scan-reuse":
        for name, stored, live, generation in (
            ("current", "generation-current", None, "generation-current"),
            ("legacy", None, "generation-legacy", None),
            ("refused", "generation-before", "generation-after", "generation-before"),
            ("contradictory", "generation-current", None, "generation-other"),
            ("missing", "generation-missing", None, "generation-missing"),
        ):
            add_target(name, stored, live)
            add_scan(name + "-scan", name, generation=generation, status="running")
        missing.add(paths["missing"])
        connection.commit()
        scan = lambda name: connection.execute(
            "SELECT * FROM scans WHERE id = ?", (name + "-scan",)
        ).fetchone()
        accepted = {}
        for name in paths:
            try:
                state.require_scan_checkout_owner(connection, scan(name))
            except SystemExit:
                accepted[name] = False
            else:
                accepted[name] = True

        def reuse(name, kind):
            target = Path(paths[name])
            scan_id = name + "-scan"
            workspace_id = "workspace-" + scan_id
            mode = "deep" if kind.startswith("deep-") else "standard"
            headless = kind == "headless"
            connection.execute(
                "UPDATE workspaces SET thread_id = 'synthetic-thread', active_scan_id = ?, "
                "default_scope = '.', default_mode = ?, submitted = 1 WHERE id = ?",
                (scan_id, mode, workspace_id),
            )
            connection.execute(
                "UPDATE scans SET mode = ?, handoff_status = 'delivered', "
                "handoff_claim_token = ?, continuation_thread_id = ? WHERE id = ?",
                (mode, "synthetic-token" if headless else None,
                 "synthetic-thread" if headless else None, scan_id),
            )
            connection.commit()
            row = scan(name)
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchone()
            ensure_run = Mock()
            with ExitStack() as mocks:
                for module in (workbench, deep_workbench):
                    mocks.enter_context(patch.object(module, "require_uuid", side_effect=lambda value, label: value))
                    mocks.enter_context(patch.object(module, "require_remediation_target", return_value=target))
                    mocks.enter_context(patch.object(module, "directory_snapshot_regular_file_count", return_value=0))
                mocks.enter_context(patch.object(workbench, "workspace_state", return_value={}))
                mocks.enter_context(patch.object(workbench, "scan_context", return_value={}))
                mocks.enter_context(patch.object(workbench, "inspect_setup_values", return_value={
                    "target": {"targetPath": str(target)}, "scope": ".", "diffTarget": None,
                }))
                mocks.enter_context(patch.object(workbench, "scan_target_identity", return_value=(
                    "synthetic", None, 7, metadata[str(target)].st_ino,
                )))
                mocks.enter_context(patch.object(workbench, "scan_target_root", return_value=root / "artifacts"))
                for function, value in {
                    "require_target": target, "require_scope": ".",
                    "require_scan": row, "require_workspace": workspace,
                    "require_owned_scan": (row, workspace), "git_revision": "synthetic",
                    "worktree_content_digest": "snapshot", "effective_deep_scan_config": {},
                    "now": timestamp, "deep_scan_result": {},
                }.items():
                    mocks.enter_context(patch.object(deep_workbench, function, return_value=value))
                mocks.enter_context(patch.object(deep_workbench, "require_scannable_target"))
                mocks.enter_context(patch.object(deep_workbench, "require_current_continuation"))
                mocks.enter_context(patch.object(deep_workbench, "ensure_deep_scan_run", ensure_run))
                existing = [row] if kind == "deep-direct" else [None, row] if kind == "deep-transaction" else [None, None]
                mocks.enter_context(patch.object(deep_workbench, "existing_deep_scan_for_target", side_effect=existing))
                mocks.enter_context(patch.object(deep_workbench, "terminal_deep_scan_for_target_snapshot", return_value=row))
                args = argparse.Namespace(
                    workspace_id=workspace_id, target_path=str(target), scope=".", mode="standard",
                    thread_id="synthetic-thread", diff_target_kind=None, diff_base_revision=None,
                    diff_head_revision=None, diff_content_digest=None, user_context=None,
                    target_summary=None, scan_root=None, model=None, reasoning_effort=None,
                    claim_token=None, workflow_version="synthetic",
                )
                try:
                    if kind == "workspace":
                        workbench.start_scan(connection, args)
                    elif kind in ("prompt", "headless"):
                        workbench._start_prompt_driven_scan(connection, args, headless_standard=headless)
                    else:
                        deep_workbench.begin_deep_scan_for_target(connection, args, "synthetic-thread")
                except SystemExit:
                    return {"accepted": False, "createdRun": ensure_run.call_count != 0}
                return {"accepted": True, "createdRun": ensure_run.call_count != 0}

        kinds = ("workspace", "prompt", "headless", "deep-direct", "deep-transaction", "deep-terminal")
        print(json.dumps({
            "owners": accepted,
            "reuse": {name: {kind: reuse(name, kind) for kind in kinds}
                      for name in ("current", "refused")},
            "legacyGeneration": scan("legacy")["repository_generation"],
        }))
    elif scenario == "birth-time":
        path = "/synthetic repository/.git"
        real_sizeof = ctypes.sizeof

        def native_result(*, wrapper=True, machine="x86_64", mask=0x800,
                          seconds=42, nanoseconds=123, status=0,
                          pointer_size=8, long_size=8):
            calls = []

            def invoke(*arguments):
                number = None
                if not wrapper:
                    number, *arguments = arguments
                directory, encoded, flags, requested_mask, output = arguments
                assert (directory, encoded, flags, requested_mask) == (
                    -100, os.fsencode(path), 0, 0x800
                )
                value = ctypes.cast(output, ctypes.POINTER(state._LinuxStatx)).contents
                assert not value.mask and not value.birth_time.seconds
                value.mask = mask
                value.birth_time.seconds = seconds
                value.birth_time.nanoseconds = nanoseconds
                calls.append(number)
                return status

            function = Mock(side_effect=invoke)
            libc = SimpleNamespace(**{"statx" if wrapper else "syscall": function})

            def sizeof(kind):
                if kind is ctypes.c_void_p:
                    return pointer_size
                if kind is ctypes.c_long:
                    return long_size
                return real_sizeof(kind)

            with patch.object(state.ctypes, "CDLL", return_value=libc), \
                 patch.object(state.ctypes, "sizeof", side_effect=sizeof), \
                 patch.object(state.platform, "machine", return_value=machine):
                result = state._linux_repository_birth_time_ns(path)
            expected_arguments = (
                (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint,
                 ctypes.POINTER(state._LinuxStatx)) if wrapper else
                (ctypes.c_long, ctypes.c_long, ctypes.c_char_p, ctypes.c_long,
                 ctypes.c_ulong, ctypes.POINTER(state._LinuxStatx))
            )
            return {
                "value": result, "calls": calls,
                "typed": not calls or function.argtypes == expected_arguments
                    and function.restype is (ctypes.c_int if wrapper else ctypes.c_long),
            }

        cases = {
            "wrapper": native_result(),
            "x86_64": native_result(wrapper=False),
            "aarch64": native_result(wrapper=False, machine="aarch64"),
            "unknown-abi": native_result(wrapper=False, machine="unknown"),
            "pointer32": native_result(wrapper=False, pointer_size=4),
            "long32": native_result(wrapper=False, long_size=4),
            "missing-mask": native_result(mask=0),
            "invalid-nanoseconds": native_result(nanoseconds=1_000_000_000),
            "zero": native_result(seconds=0, nanoseconds=0),
            "negative": native_result(seconds=-1, nanoseconds=999_999_999),
            "failed": native_result(status=-1),
        }
        with patch.object(state.ctypes, "CDLL", return_value=SimpleNamespace()), \
             patch.object(state.platform, "machine", return_value="x86_64"):
            cases["missing-symbols"] = state._linux_repository_birth_time_ns(path)
        with patch.object(state.ctypes, "CDLL", side_effect=OSError("unavailable")):
            cases["missing-libc"] = state._linux_repository_birth_time_ns(path)
        with patch.object(state.ctypes, "sizeof", return_value=255), \
             patch.object(state.ctypes, "CDLL") as library:
            cases["invalid-layout"] = state._linux_repository_birth_time_ns(path)
            assert not library.called
        with patch.object(sys, "platform", "linux"), patch.object(os, "name", "posix"), \
             patch.object(state, "_linux_repository_birth_time_ns", return_value=42_000_000_123), \
             patch.object(state.subprocess, "run") as command:
            native = state._repository_birth_time_ns(path, SimpleNamespace(st_ctime_ns=41))
            assert not command.called
        with patch.object(sys, "platform", "linux"), patch.object(os, "name", "posix"), \
             patch.object(state, "_linux_repository_birth_time_ns", return_value=None), \
             patch.object(state.subprocess, "run", return_value=SimpleNamespace(
                 stdout="42.000000123\n", returncode=0
             )) as command:
            fallback = state._repository_birth_time_ns(path, SimpleNamespace(st_ctime_ns=41))
            assert command.call_args.args[0] == ["stat", "--format=%.9W", "--", path]
            assert command.call_args.kwargs["env"]["LC_ALL"] == "C"
        print(json.dumps({
            "cases": cases, "native": native, "fallback": fallback,
            "layout": [real_sizeof(state._LinuxStatxTimestamp),
                       state._LinuxStatx.birth_time.offset, real_sizeof(state._LinuxStatx)],
        }))
    elif scenario == "cache":
        for name, stored, live in [
            ("requested", "repository-current", None),
            ("persisted", "repository-current", None),
            ("legacy", None, "repository-current"),
            ("unverified", None, "repository-current"),
            ("unrelated", "repository-other", None),
            ("unresolvable-runtime", None, "repository-current"),
            ("unresolvable-os", None, "repository-current"),
            ("removed", "repository-current", None),
            ("changed", "repository-previous", "repository-current"),
        ]:
            add_target(name, stored, live)
        state.ensure_security_target(connection, paths["legacy"])
        for name in paths:
            add_scan(name + "-scan", name, "missing" if name == "unverified" else "current")
        for number in range(5):
            add_scan("unrelated-extra-" + str(number), "unrelated")
        add_scan("legacy-second", "legacy")
        missing.add(paths["removed"])
        resolution_errors[paths["unresolvable-runtime"]] = RuntimeError
        resolution_errors[paths["unresolvable-os"]] = OSError
        before = add_finding("persisted-scan", "before-review")
        after = add_finding("legacy-scan", "after-review", closed=True)
        add_finding("legacy-second", "legacy-open")
        add_finding("unrelated-scan", "unrelated-finding", closed=True)
        connection.execute(
            "INSERT INTO scan_comparisons VALUES (?, ?, ?, ?, ?)",
            ("persisted-scan", "legacy-scan", "{}", timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)",
            ("persisted-scan", "legacy-scan", before, after, "Synthetic match"),
        )
        scans = listed("requested")
        listing_probes = dict(probes)
        probes.clear()
        origins.clear()
        matching = history.list_unmatched_scan_pairs(
            connection, argparse.Namespace(repository=paths["requested"], force=False),
            backfill_finding_details=lambda database, scan: None,
            read_coverage=lambda scan: {},
        )
        matching_probes = dict(probes)
        matching_origins = dict(origins)
        probes.clear()
        indexed = findings("requested")
        indexing_probes = dict(probes)
        probes.clear()
        feedback_scope = []
        feedback_queries = []
        def scoped_index(database, **kwargs):
            clause, values = kwargs["scan_scope"].sql()
            feedback_scope.extend(sorted(row[0] for row in database.execute(
                f"SELECT DISTINCT target_id FROM scans WHERE {clause}", values
            )))
            return indexes._indexed_findings(database, **kwargs)
        connection.set_trace_callback(feedback_queries.append)
        with patch.object(feedback_module, "_indexed_findings", side_effect=scoped_index):
            feedback = get_scan_feedback(
                connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-scan'").fetchone()
            )
        connection.set_trace_callback(None)
        index_queries = [query for query in feedback_queries if any(marker in query for marker in (
            "SELECT before_scans.target_id AS before_target_id",
            "SELECT scans.target_id, scans.id",
            "occurrences.id AS occurrence_id",
        ))]
        feedback_probes = dict(probes)
        print(json.dumps({
            "scans": scans,
            "removedExact": listed("removed"),
            "matchingCount": matching["scanCount"],
            "findings": indexed,
            "feedback": [row["findingId"] for row in feedback["falsePositives"]],
            "feedbackScope": feedback_scope,
            "feedbackIndexQueriesScoped": len(index_queries) == 3 and all(
                "repository_generation = " in query for query in index_queries
            ),
            "listingRequestedProbes": listing_probes.get(paths["requested"], 0),
            "matchingRequestedProbes": matching_probes.get(paths["requested"], 0),
            "matchingUnrelatedProbes": matching_probes.get(paths["unrelated"], 0),
            "matchingUnrelatedOrigins": matching_origins.get(paths["unrelated"], 0),
            "indexingMaxProbes": max(indexing_probes.values(), default=0),
            "feedbackMaxProbes": max(feedback_probes.values(), default=0),
            "legacyStored": connection.execute(
                "SELECT repository_identity FROM security_targets WHERE id = 'legacy'"
            ).fetchone()[0],
            "changedStored": connection.execute(
                "SELECT repository_identity FROM security_targets WHERE id = 'changed'"
            ).fetchone()[0],
        }))
    elif scenario == "selected-latest":
        add_target("requested", "repository-current")
        add_target("linked", "repository-current")
        add_target("unrelated", "repository-other")
        add_scan("legacy", "requested", generation=None)
        add_finding("legacy", "legacy-only")
        add_finding("legacy", "same-key", closed=True)
        add_scan("bound", "linked")
        add_finding("bound", "bound-only")
        add_finding("bound", "same-key")
        add_scan("other", "unrelated")
        add_finding("other", "other-only")
        selected = findings("requested")
        unscoped = list(indexes._indexed_findings(connection))
        print(json.dumps({
            "selected": {row["occurrenceId"]: [row["confirmedInLatestScan"], row["status"], row["occurrenceCount"]] for row in selected},
            "unscoped": {row["occurrence_id"]: row["confirmed_in_latest_scan"] for row in unscoped},
        }))
    elif scenario == "archive-recovery":
        database = sqlite3.connect(":memory:")
        database.row_factory = sqlite3.Row
        database.execute("CREATE TABLE scans(id TEXT PRIMARY KEY, scan_dir TEXT UNIQUE)")
        scan_dir = root / "outputs" / "scan"
        archive = scan_dir.with_name(scan_dir.name + ".previous-synthetic")

        def recover(*, expected="previous", owner="previous", archived_owner=None,
                    original_exists=True, nonempty=False, invalid_sibling=False,
                    invalid_directory=False, rename_fails=False):
            selected_archive = archive if not invalid_sibling else scan_dir.with_name("unrelated")
            database.execute("DELETE FROM scans")
            if owner is not None:
                database.execute("INSERT INTO scans VALUES (?, ?)", (owner, str(scan_dir)))
            if archived_owner is not None:
                database.execute("INSERT INTO scans VALUES (?, ?)", (archived_owner, str(selected_archive)))
            database.commit()
            present = {selected_archive, *((scan_dir,) if original_exists else ())}
            operations = []
            lock_checks = []

            def canonical(path):
                lock_checks.append(database.in_transaction)
                if path not in present or invalid_directory:
                    raise SystemExit("Synthetic invalid scan directory")
                return path

            def lstat(path):
                if path not in present:
                    raise FileNotFoundError(errno.ENOENT, "Synthetic missing path", str(path))
                return SimpleNamespace(st_mode=stat.S_IFDIR)

            def rmdir(path):
                lock_checks.append(database.in_transaction)
                if nonempty:
                    raise OSError(errno.ENOTEMPTY, "Synthetic nonempty output")
                present.remove(path)
                operations.append("rmdir")

            def rename(path, destination):
                lock_checks.append(database.in_transaction)
                if rename_fails:
                    raise OSError("Synthetic rename failure")
                assert destination not in present
                present.remove(path)
                present.add(destination)
                operations.append("rename")

            with patch.object(Path, "resolve", lambda path, *a, **k: path), \
                 patch.object(Path, "lstat", lstat), \
                 patch.object(Path, "rmdir", rmdir), \
                 patch.object(Path, "rename", rename):
                try:
                    result = scan_start.restore_cli_scan_archive(database, argparse.Namespace(
                        scan_dir=str(scan_dir), archived_scan_dir=str(selected_archive),
                        previous_scan_id=expected, previous_scan_absent=expected is None,
                    ), canonical)["disposition"]
                except (SystemExit, OSError):
                    result = "error"
            return {
                "disposition": result, "operations": operations,
                "originalPresent": scan_dir in present, "archivePresent": selected_archive in present,
                "locked": all(lock_checks), "transactionClosed": not database.in_transaction,
                "owners": dict(database.execute("SELECT scan_dir, id FROM scans")),
            }

        base = ["workbench", "restore-cli-scan-archive", "--scan-dir", str(scan_dir), "--archived-scan-dir", str(archive)]
        parser_accepts = []
        for flags in (["--previous-scan-id", "previous"], ["--previous-scan-absent"], [], ["--previous-scan-id", "previous", "--previous-scan-absent"]):
            with patch.object(sys, "argv", [*base, *flags]), redirect_stderr(io.StringIO()):
                try:
                    workbench.parse_args("Synthetic archive recovery")
                except SystemExit:
                    parser_accepts.append(False)
                else:
                    parser_accepts.append(True)
        cases = {
            "recorded": recover(),
            "unrecorded": recover(expected=None, owner=None),
            "missingOriginal": recover(original_exists=False),
            "committed": recover(owner="new", archived_owner="previous"),
            "changedOwner": recover(owner="other"),
            "unexpectedOwner": recover(expected=None),
            "nonempty": recover(nonempty=True),
            "invalidSibling": recover(invalid_sibling=True),
            "invalidDirectory": recover(invalid_directory=True),
            "renameFailure": recover(rename_fails=True),
        }
        print(json.dumps({"cases": cases, "parserAccepts": parser_accepts, "scanDir": str(scan_dir), "archiveDir": str(archive)}))
    elif scenario == "archive-registration":
        target = root / "requested"
        scan_dir = root / "outputs" / "scan"
        cases = {}
        class ReadyToInsert(Exception):
            pass
        for case in ("valid", "owner-refused", "parent-refused", "nonempty", "noncanonical"):
            events = []
            def canonical(path):
                events.append(["canonical", connection.in_transaction])
                if case == "noncanonical" and connection.in_transaction:
                    raise SystemExit("Synthetic changed output")
                return path
            def entries(path):
                assert path == scan_dir
                events.append(["empty", connection.in_transaction])
                return iter(["retained-artifact"] if case == "nonempty" and connection.in_transaction else [])
            def register(database, path):
                events.append(["owner", database.in_transaction])
                if case == "owner-refused":
                    raise SystemExit("Synthetic refused owner")
                return state.RegisteredRepositoryTarget("requested", "current")
            def parent(database, scan_id):
                events.append(["parent", database.in_transaction])
                return {"target_id": "requested", "repository_generation": "other" if case == "parent-refused" else "current"}
            def archive_scan(database, *args):
                events.append(["archive", database.in_transaction])
                raise ReadyToInsert()
            with ExitStack() as mocks:
                for name, value in {
                    "require_target": target,
                    "parse_scan_recipe": {"target": {"kind": "repository", "paths": []}, "mode": "standard"},
                    "scan_target_identity": ("synthetic", None, 7, 8),
                    "directory_snapshot_regular_file_count": 0,
                }.items():
                    mocks.enter_context(patch.object(workbench, name, return_value=value))
                mocks.enter_context(patch.object(workbench, "require_scannable_target"))
                mocks.enter_context(patch.object(workbench, "require_uuid", side_effect=lambda value, label: value))
                mocks.enter_context(patch.object(workbench, "require_canonical_scan_directory", side_effect=canonical))
                mocks.enter_context(patch.object(workbench, "register_security_target", side_effect=register))
                mocks.enter_context(patch.object(workbench, "require_scan", side_effect=parent))
                mocks.enter_context(patch.object(workbench, "archive_scan", side_effect=archive_scan))
                mocks.enter_context(patch.object(Path, "iterdir", entries))
                try:
                    workbench.register_cli_scan(connection, argparse.Namespace(
                        repository=str(target), scan_dir=str(scan_dir), recipe_json="{}", parent_scan_id="parent", registration_json_stdin=False, recipe_json_stdin=False,
                    ))
                except ReadyToInsert:
                    accepted = True
                except SystemExit:
                    accepted = False
            cases[case] = {"accepted": accepted, "events": events, "transactionClosed": not connection.in_transaction}
        print(json.dumps(cases))
    elif scenario == "completion-order":
        add_target("first", "repository-current")
        add_target("second", "repository-current")
        add_scan("legacy-b", "second", started="2026-07-31T01:00:00Z", created="2026-07-31T05:00:00+01:00")
        add_scan("legacy-a", "first", started="2026-07-31T02:00:00Z", created="2026-07-31T04:00:00Z")
        add_scan("legacy-missing", "first", started="2026-07-31T03:00:00Z")
        connection.execute("UPDATE scans SET completed_at = NULL WHERE id = 'legacy-missing'")
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        add_scan("visible-last", "first", started="2026-08-01T01:00:00Z", status="running")
        add_scan("visible-first", "second", started="2026-08-01T02:00:00Z", status="running")
        def sequences():
            return {row["id"]: row["completion_sequence"] for row in connection.execute(
                "SELECT id, completion_sequence FROM scans ORDER BY completion_sequence, id"
            )}
        def predecessors(scan_id):
            plan = history.list_unmatched_scan_pairs(
                connection,
                argparse.Namespace(repository=paths["first"], force=False, after_scan_id=scan_id),
                backfill_finding_details=lambda *_: None, read_coverage=lambda _: {},
            )
            return [scan["scanId"] for batch in plan["batches"] for scan in batch["beforeScans"]]
        legacy = sequences()
        connection.execute(
            "UPDATE scans SET status = 'complete', completed_at = '2026-08-01T04:00:00Z' "
            "WHERE id = 'visible-first'"
        )
        connection.commit()
        first_predecessors = predecessors("visible-first")
        connection.execute(
            "UPDATE scans SET status = 'complete', completed_at = '2026-08-01T03:00:00Z' "
            "WHERE id = 'visible-last'"
        )
        connection.commit()
        add_finding("visible-first", "first-finding")
        add_finding("visible-last", "last-finding")
        confirmed = {row["findingId"]: row["confirmedInLatestScan"] for row in findings("first")}
        last_predecessors = predecessors("visible-last")
        reciprocal_predecessors = predecessors("visible-first")
        connection.execute("UPDATE scans SET status = 'complete' WHERE id = 'visible-last'")
        connection.execute("UPDATE scans SET status = 'failed' WHERE id = 'visible-last'")
        add_scan("inserted-complete", "second", created="2026-07-01T00:00:00Z")
        before_repair = sequences()
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        print(json.dumps({
            "legacy": legacy,
            "legacyGenerationsNull": all(row[0] is None for row in connection.execute(
                "SELECT repository_generation FROM scans WHERE id LIKE 'legacy-%'"
            )),
            "firstPredecessors": first_predecessors,
            "lastPredecessors": last_predecessors,
            "reciprocalPredecessors": reciprocal_predecessors,
            "confirmed": confirmed,
            "sequences": sequences(),
            "idempotent": sequences() == before_repair,
            "sequenceOutranksFallback": history._scan_completion_order({
                "id": "fallback", "started_at": "2999-01-01T00:00:00Z"
            }) < history._scan_completion_order({
                "id": "sequenced", "completion_sequence": 1
            }),
            "sealedTimes": {row["id"]: row["completed_at"] for row in connection.execute(
                "SELECT id, completed_at FROM scans WHERE id IN ('visible-first', 'visible-last')"
            )},
        }))
    elif scenario == "persisted-alias":
        for name, stored, live in [
            ("requested", "repository-current", None),
            ("reused", "repository-current", "repository-other"),
            ("legacy", None, "repository-current"),
            ("unverified", None, "repository-current"),
            ("unrelated", "repository-other", None),
        ]:
            add_target(name, stored, live)
            if name == "legacy":
                state.ensure_security_target(connection, paths[name])
            add_scan(name + "-scan", name, "missing" if name == "unverified" else "current")
        for name, identity in [("fresh", "repository-current"), ("empty", "repository-empty")]:
            add_target(name, identity)
            connection.execute("DELETE FROM security_targets WHERE id = ?", (name,))
        metadata[paths["reused"]].st_ino += 1000
        add_finding("requested-scan", "current-finding")
        add_finding("reused-scan", "historical-finding", closed=True)
        scans = listed("requested")
        reused_listing_probes = probes[paths["reused"]]
        matching = history.list_unmatched_scan_pairs(
            connection, argparse.Namespace(repository=paths["requested"], force=False),
            backfill_finding_details=lambda *_: None, read_coverage=lambda _: {},
        )
        feedback = get_scan_feedback(
            connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-scan'").fetchone()
        )
        def findings_page(name=None, target_id=None):
            return indexes.list_global_findings(
                connection,
                argparse.Namespace(repository=paths[name] if name else None,
                                   target_id=target_id, limit=50, offset=0,
                                   query=None, severity=None, status=None),
            )
        target_count = connection.execute("SELECT COUNT(*) FROM security_targets").fetchone()[0]
        fresh_findings = findings_page("fresh")
        empty_findings = findings_page("empty")
        replacement_findings = findings_page("reused")
        with patch.object(sys, "argv", [
            "workbench", "list-global-findings", "--repository", paths["fresh"],
            "--target-id", "reused",
        ]), redirect_stderr(io.StringIO()):
            try:
                workbench.parse_args("Synthetic selector test")
            except SystemExit as error:
                rejects_both_selectors = error.code == 2
            else:
                rejects_both_selectors = False
        print(json.dumps({
            "scans": scans,
            "replacementRequest": listed("reused"),
            "findings": sorted(row["findingId"] for row in findings("requested")),
            "freshFindings": sorted(row["findingId"] for row in fresh_findings["findings"]),
            "emptyFindings": empty_findings["findings"],
            "replacementFindings": replacement_findings["findings"],
            "projectionAvailable": {
                "fresh": fresh_findings["projectionAvailable"],
                "empty": empty_findings["projectionAvailable"],
                "replacementPath": replacement_findings["projectionAvailable"],
                "replacementId": findings_page(target_id="reused")["projectionAvailable"],
                "unknownId": findings_page(target_id="not-registered")["projectionAvailable"],
            },
            "rejectsBothSelectors": rejects_both_selectors,
            "readOnly": target_count == connection.execute("SELECT COUNT(*) FROM security_targets").fetchone()[0]
                and connection.execute("SELECT 1 FROM security_targets WHERE id = 'fresh'").fetchone() is None,
            "feedback": [row["findingId"] for row in feedback["falsePositives"]],
            "matchingCount": matching["scanCount"],
            "reusedListingProbes": reused_listing_probes,
            "stored": connection.execute(
                "SELECT repository_identity FROM security_targets WHERE id = 'reused'"
            ).fetchone()[0],
        }))
    elif scenario == "saved-start":
        original_identity = add_target("requested", "repository-current")
        other_identity = add_target("other", "repository-other")
        add_scan("historical", "requested")
        target = Path(paths["requested"])
        target_root = root / "scan-output"
        original_mkdir = Path.mkdir
        stack.enter_context(patch.object(Path, "mkdir", lambda path, *args, **kwargs: None if path == target_root else original_mkdir(path, *args, **kwargs)))
        stack.enter_context(patch.object(workbench, "require_uuid", side_effect=lambda value, label: value))
        stack.enter_context(patch.object(workbench, "require_target", return_value=target))
        stack.enter_context(patch.object(workbench, "require_remediation_target", return_value=target))
        stack.enter_context(patch.object(workbench, "require_scannable_target"))
        stack.enter_context(patch.object(workbench, "require_scope", return_value="."))
        stack.enter_context(patch.object(workbench, "directory_snapshot_regular_file_count", return_value=0))
        stack.enter_context(patch.object(workbench, "scan_target_identity", return_value=("synthetic", None, 7, metadata[str(target)].st_ino)))
        stack.enter_context(patch.object(workbench, "scan_target_root", return_value=target_root))
        checks = []
        original_register = workbench.register_security_target
        def register(database, target_path):
            checks.append({"transaction": database.in_transaction, "path": target_path})
            return original_register(database, target_path)
        stack.enter_context(patch.object(workbench, "register_security_target", side_effect=register))
        class StartAccepted(Exception):
            pass
        stack.enter_context(patch.object(workbench, "insert_running_scan", side_effect=StartAccepted))
        accepted = {}
        for name, saved_target, live in [
            ("valid", "requested", original_identity),
            ("changed-generation", "requested", other_identity),
            ("changed-saved-id", "other", original_identity),
        ]:
            details[str(target)] = live
            connection.execute(
                "INSERT INTO workspaces (id, target_id, target_path, submitted, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?)",
                (name, saved_target, str(target), timestamp, timestamp),
            )
            connection.commit()
            try:
                workbench.start_scan(
                    connection, argparse.Namespace(workspace_id=name, scan_root=None, model=None, reasoning_effort=None)
                )
            except StartAccepted:
                accepted[name] = True
            except SystemExit:
                accepted[name] = False
        print(json.dumps({
            "accepted": accepted,
            "verifiedInsideTransaction": len(checks) == 3 and all(
                item == {"transaction": True, "path": str(target)} for item in checks
            ),
            "scanCount": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "stored": connection.execute("SELECT repository_identity FROM security_targets WHERE id = 'requested'").fetchone()[0],
        }))
    elif scenario == "v30-current":
        generation_birth = state._timestamp_ns("2026-08-02T00:00:00Z")
        later = "2026-08-03T00:00:00Z"
        for name in ("current-owner", "old-owner", "removed-old", "removed-valid", "invalid-time"):
            add_target(name, "current-generation", birth=generation_birth)
            recorded = later if name in ("current-owner", "removed-valid") else timestamp
            add_scan(name + "-scan", name, started="invalid" if name == "invalid-time" else recorded, created=recorded)
        add_target("unverified-anchor", "unverified-current")
        add_scan("unverified-anchor-scan", "unverified-anchor", owner="missing")
        add_target("opaque-missing", "opaque-current")
        add_scan("opaque-missing-scan", "opaque-missing")
        add_target("valid-scope", "scope-current", relative="service")
        add_scan("valid-scope-scan", "valid-scope")
        missing.update(paths[name] for name in ("removed-old", "removed-valid", "opaque-missing"))
        for name in ("current-owner", "old-owner", "removed-old", "removed-valid"):
            add_finding(name + "-scan", name + "-finding", closed=name != "current-owner")
            connection.execute(
                "INSERT INTO scan_artifacts VALUES (?, ?, ?, ?)",
                (name + "-scan", "findings", str(root / name / "findings.json"), timestamp),
            )
        tables = ("scans", "findings", "finding_occurrences", "finding_triage", "scan_artifacts")
        columns = {
            table: ", ".join(row["name"] for row in connection.execute("PRAGMA table_info(" + table + ")"))
            for table in tables
        }
        def retained_records():
            return {table: [tuple(row) for row in connection.execute(
                "SELECT " + columns[table] + " FROM " + table
            )] for table in tables}
        retained = retained_records()
        target_ids = sorted(paths)
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        state.backfill_repository_identities(connection)
        try:
            state.ensure_security_target(connection, paths["old-owner"])
        except SystemExit:
            old_registration_rejected = True
        else:
            old_registration_rejected = False
        print(json.dumps({
            "stored": {row["id"]: row["repository_identity"] for row in connection.execute(
                "SELECT id, repository_identity FROM security_targets"
            )},
            "recordsPreserved": retained == retained_records(),
            "targetIdsPreserved": target_ids == sorted(row["id"] for row in connection.execute("SELECT id FROM security_targets")),
            "removedExact": listed("removed-old"),
            "visibleFindings": sorted(row["findingId"] for row in findings("current-owner")),
            "oldRegistrationRejected": old_registration_rejected,
        }))
    elif scenario == "lineage":
        for name, stored, live in [
            ("requested", "repository-current", None),
            ("removed", "repository-current", None),
            ("legacy", None, "repository-current"),
            ("unverified", None, "repository-current"),
            ("clone", "repository-other", None),
            ("scope", "repository-current-scope", None),
            ("changed", "repository-previous", "repository-current"),
        ]:
            add_target(name, stored, live, relative="service" if name == "scope" else ".")
            add_scan(name + "-scan", name, "missing" if name == "unverified" else "current")
        missing.add(paths["removed"])
        scan_dir = root / "scan-output"
        original_iterdir = Path.iterdir
        stack.enter_context(patch.object(Path, "iterdir", lambda path: iter(()) if path == scan_dir else original_iterdir(path)))
        stack.enter_context(patch.object(workbench, "require_target", return_value=Path(paths["requested"])))
        stack.enter_context(patch.object(workbench, "require_scannable_target"))
        stack.enter_context(patch.object(workbench, "require_canonical_scan_directory", return_value=scan_dir))
        stack.enter_context(patch.object(workbench, "directory_snapshot_regular_file_count", return_value=0))
        stack.enter_context(patch.object(workbench, "scan_target_identity", return_value={}))
        stack.enter_context(patch.object(workbench, "require_uuid", side_effect=lambda value, label: value))
        stack.enter_context(patch.object(workbench, "archive_scan"))
        class LineageAccepted(Exception):
            pass
        stack.enter_context(patch.object(workbench, "insert_running_scan", side_effect=LineageAccepted))
        connection.commit()
        accepted = {}
        for name in paths:
            args = argparse.Namespace(
                repository=paths["requested"], scan_dir=str(scan_dir), parent_scan_id=name + "-scan",
                recipe_json=json.dumps({"repository": paths["requested"], "mode": "standard", "config": {}, "target": {"kind": "repository", "paths": []}}),
                registration_json_stdin=False, recipe_json_stdin=False,
            )
            try:
                workbench.register_cli_scan(connection, args)
            except LineageAccepted:
                accepted[name] = True
            except SystemExit:
                accepted[name] = False
        print(json.dumps({"accepted": accepted, "scanCount": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]}))
    elif scenario == "null-history":
        newer_birth = state._timestamp_ns("2026-08-02T00:00:00Z")
        for name, birth in [
            ("unchanged", 1_000_000_000), ("newer", newer_birth),
            ("invalid-time", 1_000_000_000), ("no-history", newer_birth),
        ]:
            add_target(name, None, "current-" + name, birth=birth)
            if name != "no-history":
                add_scan(name + "-scan", name, started="invalid" if name == "invalid-time" else timestamp)
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
        add_target("replacement-alias", "current-newer", birth=newer_birth)
        add_scan("replacement-alias-scan", "replacement-alias", started="2026-08-03T00:00:00Z")
        errors = {}
        for name in ("unchanged", "newer", "invalid-time", "no-history"):
            try:
                state.ensure_security_target(connection, paths[name])
            except SystemExit as error:
                errors[name] = str(error)
        print(json.dumps({
            "stored": {row["id"]: row["repository_identity"] for row in connection.execute(
                "SELECT id, repository_identity FROM security_targets"
            )},
            "registrationErrors": sorted(errors),
            "scans": listed("replacement-alias"),
            "sameCheckoutMetadata": connection.execute(
                "SELECT target_inode FROM scans WHERE id = 'newer-scan'"
            ).fetchone()[0] == metadata[paths["newer"]].st_ino,
        }))
    elif scenario == "late-null":
        add_target("requested", "repository-current")
        add_scan("requested-scan", "requested")
        add_target("unscanned", None, "repository-current")
        add_target("unselected", None, "repository-current")
        details.pop(paths["unselected"])
        add_target("historical", None, "repository-current")
        add_scan("historical-scan", "historical")
        add_finding("historical-scan", "historical-finding", closed=True)
        probes.clear()
        backfill = Mock(wraps=state.backfill_security_targets)
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)
        apply_migrations(connection, MIGRATIONS, lambda: timestamp, backfill)
        maintenance_probes = dict(probes)
        probes.clear()
        with patch.object(state, "_bind_unscanned_repository_identity", wraps=state._bind_unscanned_repository_identity) as guarded_bind:
            selected_id = state.ensure_security_target(connection, paths["unscanned"])
            selected_guard = guarded_bind.call_count == 1 and guarded_bind.call_args.args[1:] == (
                "unscanned", paths["unscanned"], "repository-current",
            )
        selected_probes = dict(probes)
        historical_id = state.ensure_security_target(connection, paths["historical"])
        add_scan("established-scan", "unscanned")
        missing.update((paths["unscanned"], paths["historical"]))
        print(json.dumps({
            "stored": {row["id"]: row["repository_identity"] for row in connection.execute(
                "SELECT id, repository_identity FROM security_targets"
            )},
            "fullBackfillCalls": backfill.call_count,
            "maintenanceProbes": {name: maintenance_probes.get(path, 0) for name, path in paths.items()},
            "selectedProbes": {name: selected_probes.get(path, 0) for name, path in paths.items()},
            "selectedRegistrationId": selected_id,
            "selectedGuarded": selected_guard,
            "historicalRegistrationId": historical_id,
            "scans": listed("requested"),
            "historicalExact": listed("historical"),
            "feedback": get_scan_feedback(
                connection, connection.execute("SELECT * FROM scans WHERE id = 'requested-scan'").fetchone()
            )["falsePositives"],
        }))
    elif scenario == "binding":
        for name, stored in (
            ("eligible", None), ("id-history", None), ("path-history", None),
            ("donor", None), ("bound", "repository-bound"),
        ):
            add_target(name, stored, "repository-current")
        add_scan("id-history-scan", "id-history")
        connection.execute("UPDATE scans SET target_path = ? WHERE id = 'id-history-scan'", (paths["donor"],))
        add_scan("path-history-scan", "donor")
        connection.execute("UPDATE scans SET target_path = ? WHERE id = 'path-history-scan'", (paths["path-history"],))
        def bind(name, path=None):
            return state._bind_unscanned_repository_identity(
                connection, name, path or paths[name], "repository-current"
            )
        guarded = {
            "idHistory": bind("id-history"),
            "pathHistory": bind("path-history"),
            "wrongPath": bind("eligible", paths["donor"]),
            "alreadyBound": bind("bound"),
            "eligible": bind("eligible"),
            "repeat": bind("eligible"),
        }
        path = paths["eligible"]
        def inspected(target_id, stored=None, *, historical=False, owner=True):
            return state.RepositoryTargetState(
                target_id, path, stored, resolved_path=path, repository=details[path],
                ownership_matches=owner, strict_owner_matches=True,
                generation_predates_history=True, has_historical_scans=historical,
            )
        def cursor(row):
            return SimpleNamespace(fetchone=lambda: row)
        ignored = Mock()
        ignored.execute.side_effect = [cursor(None), None, cursor({
            "id": "actual-target", "repository_identity": None,
        })]
        with patch.object(state, "supports_repository_identity", return_value=True), \
             patch.object(state, "stable_target_id", return_value="proposed-target"), \
             patch.object(state, "_inspect_repository_target", return_value=inspected("actual-target", historical=True)) as inspect, \
             patch.object(state, "_bind_unscanned_repository_identity") as guarded_bind:
            ignored_id = state.ensure_security_target(ignored, path)
            ignored_reselected = inspect.call_args.args[1:] == ("actual-target", path, None)
            ignored_unbound = guarded_bind.call_count == 0
        insert = ignored.execute.call_args_list[1].args
        def lost_binding(stored, owner):
            database = Mock()
            database.execute.side_effect = [
                cursor({"id": "actual-target", "repository_identity": None}),
                cursor({"id": "actual-target", "repository_identity": stored}),
            ]
            with patch.object(state, "supports_repository_identity", return_value=True), \
                 patch.object(state, "_inspect_repository_target", side_effect=[
                     inspected("actual-target"),
                     inspected("actual-target", stored, historical=True, owner=owner),
                 ]) as inspect, \
                 patch.object(state, "_bind_unscanned_repository_identity", return_value=False) as guarded_bind:
                try:
                    accepted = state.ensure_security_target(database, path) == "actual-target"
                except SystemExit:
                    accepted = False
                return {
                    "accepted": accepted,
                    "rechecked": inspect.call_count == 2 and inspect.call_args.args[1:] == ("actual-target", path, stored),
                    "guarded": guarded_bind.call_args.args[1:] == ("actual-target", path, "repository-current"),
                }
        print(json.dumps({
            "guarded": guarded,
            "stored": {row["id"]: row["repository_identity"] for row in connection.execute(
                "SELECT id, repository_identity FROM security_targets"
            )},
            "ignoredInsert": {
                "id": ignored_id, "reselected": ignored_reselected, "unbound": ignored_unbound,
                "insertsNull": "INSERT OR IGNORE" in insert[0] and "repository_identity" not in insert[0] and len(insert[1]) == 5,
            },
            "lostToHistory": lost_binding(None, True),
            "lostToConflictingIdentity": lost_binding("repository-other", False),
        }))
    elif scenario == "sealed-comparison":
        for name, stored in (("legacy", None), ("first", "repository-saved"), ("second", "repository-saved")):
            add_target(name, stored)
        for scan_id, target in (("legacy-before", "legacy"), ("legacy-after", "legacy"), ("first-scan", "first"), ("second-scan", "second")):
            add_scan(scan_id, target)
        resolution_errors.update({paths["legacy"]: RuntimeError, paths["first"]: OSError, paths["second"]: RuntimeError})
        connection.commit()
        require_scan = lambda database, scan_id: database.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        coverage = lambda scan: {"completeness": "complete"}
        accepted = []
        with patch.object(state, "_inspect_repository_target", side_effect=AssertionError("Sealed comparison inspected the live target")):
            for before, after in (("legacy-before", "legacy-after"), ("first-scan", "second-scan")):
                args = argparse.Namespace(before_scan_id=before, after_scan_id=after, matches_json='{"matches":[],"uncertain":[]}', matches_json_stdin=False)
                compared = history.compare_scans(connection, args, require_scan=require_scan, read_coverage=coverage)
                saved = history.save_scan_comparison(connection, args, now=lambda: timestamp, require_scan=require_scan, read_coverage=coverage)
                accepted.append(compared["afterScanId"] == after and saved["beforeScanId"] == before)
        conflicting = history._same_repository(
            connection,
            {"target_id": "same-target", "repository_generation": "repository-first"},
            {"target_id": "same-target", "repository_generation": "repository-second"},
            identities=Mock(),
        )
        targetless = {"target_id": None, "target_path": paths["legacy"]}
        healthy = state.RepositoryTargetState(
            "", paths["legacy"], None, resolved_path=paths["legacy"], ownership_matches=True
        )
        refused_targetless = state.RepositoryTargetState(
            "", paths["legacy"], None, resolved_path=paths["legacy"]
        )
        healthy_path = history._same_repository(
            connection, targetless, targetless,
            identities=Mock(for_row=Mock(return_value=healthy)),
        )
        refused_path = history._same_repository(
            connection, targetless, targetless,
            identities=Mock(for_row=Mock(return_value=refused_targetless)),
        )
        add_target("unregistered", None)
        connection.execute("DELETE FROM security_targets WHERE id = 'unregistered'")
        refused = state.RepositoryTargetState("", paths["unregistered"], None)
        cache = Mock(supports_identity=True)
        cache.for_path.return_value = refused
        with patch.object(history, "RepositoryIdentityCache", return_value=cache):
            try:
                history.list_unmatched_scan_pairs(
                    connection, argparse.Namespace(repository=paths["unregistered"], force=False),
                    backfill_finding_details=lambda *_: None, read_coverage=coverage,
                )
            except SystemExit:
                automatic_rejected = True
            else:
                automatic_rejected = False
        print(json.dumps({
            "accepted": accepted, "conflictingIdentitiesAccepted": conflicting,
            "healthyTargetless": healthy_path, "refusedTargetless": refused_path,
            "savedCount": connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone()[0],
            "unregisteredAutomaticRequesterRejected": automatic_rejected,
        }))
    else:
        stack.enter_context(patch.object(os.path, "normcase", lambda value: os.fspath(value).lower()))
        originals = {}
        expected = {}
        for name in [
            "old-basic", "old-description", "current", "unknown", "newer-generation",
            "unverified", "changed-owner", "unavailable", "invalid-time", "no-scans",
            "scope-upper", "scope-lower",
        ]:
            relative = "Service" if name == "scope-upper" else "service" if name == "scope-lower" else "."
            birth = state._timestamp_ns("2026-08-02T00:00:00Z") if name == "newer-generation" else 1_000_000_000
            identity = add_target(name, None, "current-" + name, relative, birth)
            stored = (
                identity.value if name == "current" else
                "unknown-identity" if name == "unknown" else
                legacy_hash(identity, name == "old-description")
            )
            originals[name] = stored
            connection.execute(
                "UPDATE security_targets SET repository_identity = ? WHERE id = ?", (stored, name)
            )
            if name != "no-scans":
                owner = "missing" if name == "unverified" else "mismatch" if name == "changed-owner" else "current"
                add_scan(name + "-scan", name, owner, "invalid" if name == "invalid-time" else timestamp)
            if name == "unavailable":
                missing.add(paths[name])
            expected[name] = (
                identity.value if name == "current" else identity.legacy_value if name in {
                    "old-basic", "old-description", "no-scans", "scope-upper", "scope-lower"
                } else None
            )
        add_finding("old-basic-scan", "historical-finding", closed=True)
        connection.execute(
            "INSERT INTO scan_artifacts VALUES (?, ?, ?, ?)",
            ("old-basic-scan", "findings", str(root / "historical-findings.json"), timestamp),
        )
        tables = ("scans", "findings", "finding_occurrences", "finding_triage", "scan_artifacts")
        columns = {
            table: ", ".join(row["name"] for row in connection.execute("PRAGMA table_info(" + table + ")"))
            for table in tables
        }
        def retained_records():
            return {table: [tuple(row) for row in connection.execute(
                "SELECT " + columns[table] + " FROM " + table
            )] for table in tables}
        retained = retained_records()
        starting_version = connection.execute(
            "SELECT version FROM schema_migrations WHERE name = ?",
            ("persist repository identities",),
        ).fetchone()[0]
        real_normalize = state.normalize_pre_release_repository_identities
        normalization_transactions = []
        def normalize(database):
            normalization_transactions.append(database.in_transaction)
            return real_normalize(database)
        with patch.object(state, "normalize_pre_release_repository_identities", side_effect=normalize) as normalizer:
            apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
            first = {
                row["id"]: row["repository_identity"]
                for row in connection.execute("SELECT id, repository_identity FROM security_targets")
            }
            probes.clear()
            apply_migrations(connection, MIGRATIONS, lambda: timestamp, state.backfill_security_targets)
            current_open_probes = sum(probes.values())
            normalization_count = normalizer.call_count
        second = {
            row["id"]: row["repository_identity"]
            for row in connection.execute("SELECT id, repository_identity FROM security_targets")
        }
        print(json.dumps({
            "identities": first,
            "expected": expected,
            "startingVersion": starting_version,
            "normalizationCount": normalization_count,
            "normalizationTransactions": normalization_transactions,
            "currentOpenProbes": current_open_probes,
            "recordsPreserved": retained == retained_records(),
            "scanGenerationsUnbound": all(row[0] is None for row in connection.execute("SELECT repository_generation FROM scans")),
            "idempotent": first == second,
            "foldedLegacyScopesEqual": originals["scope-upper"] == originals["scope-lower"],
            "currentScopesDistinct": first["scope-upper"] != first["scope-lower"],
            "targetCount": len(first),
            "migrations": [row["version"] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")],
        }))
`;

function run(scenario: string): Record<string, unknown> {
  const python = (Bun.which("python3") ?? Bun.which("python"))!;
  // Keep the Python fixture off the Windows command line.
  const execution = spawnSync(
    python,
    ["-I", "-B", "-", join(PLUGIN_ROOT, "scripts"), scenario],
    { input: probe, encoding: "utf8", timeout: 10_000 },
  );
  expect(execution.status, execution.error?.message ?? execution.stderr).toBe(
    0,
  );
  return JSON.parse(execution.stdout) as Record<string, unknown>;
}

test("uses registered old-Git paths and stable object-directory generation evidence", () => {
  expect(run("generation-metadata")).toEqual({
    oldMain: true,
    oldLinkedMatches: true,
    nulMatches: true,
    wrongBacklink: null,
    unchanged: true,
    objectInstanceChangesGeneration: true,
    legacyMaterialUnchanged: true,
    domainSeparated: true,
    actualObjectLookup: true,
    oldPrimary: {
      localAbsolute: true,
      worktreeRelative: true,
      literalLeadingTilde: true,
      trailingLineFeed: true,
      trailingWhitespace: true,
      missing: false,
      wrongScopes: true,
      malformed: true,
      wrongRoot: false,
      foreignForward: false,
    },
    rawConfigLookup: true,
  });
});

test("keeps automatic history bounded by saved scan generation", () => {
  const result = run("scan-generation");
  expect(result["selected"]).toEqual([
    "alias-proved",
    "requested-legacy",
    "requested-new",
  ]);
  expect(result["predicate"]).toEqual({ binds: 2, ors: 1 });
  expect(result["feedback"]).toEqual(["local-review", "proved-review"]);
  expect(result["findings"]).toEqual([
    ["current-open", 1, "open"],
    ["local-review", 1, "closed"],
    ["proved-review", 1, "closed"],
  ]);
  expect(result["oldClientGeneration"]).toBeNull();
  expect(result["explicitClones"]).toBe(true);
  expect(result["explicitLegacy"]).toBe(true);
  expect(result["ownContradiction"]).toBe(false);
  expect(result["weakRegistration"]).toBe("generation-strong");
  expect(result["weakHistory"]).toBeNull();
  expect(result["weakBindingPreserved"]).toBe(true);
  expect(result["absentExactCounts"]).toEqual([1, 1]);
});

test("counts repository groups once while preserving absent exact-target decisions", () => {
  const result = run("repository-counts");
  const all = result["all"] as {
    counts: Record<string, number>;
    calls: Array<string | null>;
    inspections: string[];
  };

  expect(all.counts).toEqual({
    first: 2,
    second: 2,
    absent: 1,
    independent: 1,
    refused: 0,
  });
  expect(result["directCounts"]).toEqual(all.counts);
  expect(all.calls).toEqual([null, "absent"]);
  expect(all.inspections).toEqual([
    "absent",
    "first",
    "independent",
    "refused",
    "second",
  ]);
  expect(result["absentOnly"]).toEqual({
    counts: { absent: 1 },
    ids: ["absent"],
    calls: ["absent"],
    inspections: ["absent"],
    nextOffset: null,
  });
  expect(result["queryOnly"]).toEqual({
    counts: { independent: 1 },
    ids: ["independent"],
    calls: [null],
    inspections: ["independent"],
    nextOffset: null,
  });
  expect(result["refusedOnly"]).toEqual({
    counts: { refused: 0 },
    ids: ["refused"],
    calls: [],
    inspections: ["refused"],
    nextOffset: null,
  });
  expect(result["notScanned"]).toEqual({
    counts: {},
    ids: [],
    calls: [],
    inspections: [],
    nextOffset: null,
  });
  expect((result["openIds"] as string[]).sort()).toEqual([
    "absent",
    "first",
    "independent",
    "second",
  ]);
  expect(result["pagePreserved"]).toBe(true);
});

test("records generation explicitly in both transactional parent scan writers", () => {
  const result = run("scan-writers");
  expect(result["generations"]).toEqual({
    "current-writer": "generation-writer",
    "old-writer": null,
    [result["deepId"] as string]: "generation-writer",
  });
  expect(result["registeredInsideTransaction"]).toEqual([true, true]);
  expect(result["generationIndex"]).toBe(true);
});

test("reads precise Linux birth time through supported native interfaces", () => {
  const result = run("birth-time");
  const cases = result["cases"] as Record<string, unknown>;

  expect(result["layout"]).toEqual([16, 80, 256]);
  expect(result["native"]).toBe(42_000_000_123);
  expect(result["fallback"]).toBe(result["native"]);
  expect(cases["wrapper"]).toEqual({
    value: 42_000_000_123,
    calls: [null],
    typed: true,
  });
  for (const [architecture, number] of [
    ["x86_64", 332],
    ["aarch64", 291],
  ] as const) {
    expect(cases[architecture]).toEqual({
      value: 42_000_000_123,
      calls: [number],
      typed: true,
    });
  }
  for (const name of ["unknown-abi", "pointer32", "long32"]) {
    expect(cases[name]).toEqual({ value: null, calls: [], typed: true });
  }
  for (const name of [
    "missing-mask",
    "invalid-nanoseconds",
    "zero",
    "negative",
    "failed",
  ]) {
    expect(cases[name]).toEqual({ value: null, calls: [null], typed: true });
  }
  for (const name of ["missing-symbols", "missing-libc", "invalid-layout"]) {
    expect(cases[name]).toBeNull();
  }
});

test("reuses established aliases and probes each saved target once per request", () => {
  const result = run("cache");

  expect(result["scans"]).toEqual([
    "legacy-scan",
    "legacy-second",
    "persisted-scan",
    "removed-scan",
    "requested-scan",
  ]);
  expect(result["removedExact"]).toEqual(["removed-scan"]);
  expect(result["matchingCount"]).toBe(5);
  const findings = result["findings"] as Array<Record<string, unknown>>;
  expect(
    findings.find((finding) => finding["status"] === "closed"),
  ).toMatchObject({
    occurrenceCount: 2,
    matchedFindingIds: ["after-review", "before-review"],
  });
  expect(
    findings.find((finding) => finding["findingId"] === "legacy-open"),
  ).toBeDefined();
  expect(result["feedback"]).toEqual(["after-review"]);
  expect(result["feedbackScope"]).toEqual([
    "legacy",
    "persisted",
    "removed",
    "requested",
  ]);
  expect(result["feedbackIndexQueriesScoped"]).toBe(true);
  expect(result["listingRequestedProbes"]).toBe(1);
  expect(result["matchingRequestedProbes"]).toBe(1);
  expect(result["matchingUnrelatedProbes"]).toBe(0);
  expect(result["matchingUnrelatedOrigins"]).toBe(0);
  expect(result["indexingMaxProbes"]).toBe(1);
  expect(result["feedbackMaxProbes"]).toBe(1);
  expect(result["legacyStored"]).toBe("repository-current");
  expect(result["changedStored"]).toBe("repository-previous");
});

test("orders completed history by database visibility across legacy and current writers", () => {
  const result = run("completion-order");

  expect(result["legacy"]).toEqual({
    "visible-first": null,
    "visible-last": null,
    "legacy-missing": 1,
    "legacy-a": 2,
    "legacy-b": 3,
  });
  expect(result["legacyGenerationsNull"]).toBe(true);
  expect(result["firstPredecessors"]).not.toContain("visible-last");
  expect(result["lastPredecessors"]).toContain("visible-first");
  expect(result["reciprocalPredecessors"]).not.toContain("visible-last");
  expect(result["confirmed"]).toEqual({
    "first-finding": false,
    "last-finding": true,
  });
  expect(result["sequences"]).toEqual({
    "legacy-missing": 1,
    "legacy-a": 2,
    "legacy-b": 3,
    "visible-first": 4,
    "visible-last": 5,
    "inserted-complete": 6,
  });
  expect(result["idempotent"]).toBe(true);
  expect(result["sequenceOutranksFallback"]).toBe(true);
  expect(result["sealedTimes"]).toEqual({
    "visible-first": "2026-08-01T04:00:00Z",
    "visible-last": "2026-08-01T03:00:00Z",
  });
});

test("confirms findings against the latest selected scan without merging legacy groups", () => {
  expect(run("selected-latest")).toEqual({
    selected: {
      "legacy:legacy-only": [false, "open", 1],
      "legacy:same-key": [false, "closed", 1],
      "bound:bound-only": [true, "open", 1],
      "bound:same-key": [true, "open", 1],
    },
    unscoped: {
      "legacy:legacy-only": true,
      "legacy:same-key": true,
      "bound:bound-only": true,
      "bound:same-key": true,
      "other:other-only": true,
    },
  });
});

test("restores only an unclaimed empty scan output under the workbench writer lock", () => {
  const result = run("archive-recovery");
  const cases = result["cases"] as Record<string, Record<string, unknown>>;
  expect(result["parserAccepts"]).toEqual([true, true, false, false]);
  for (const name of ["recorded", "unrecorded", "missingOriginal"]) {
    expect(cases[name]).toMatchObject({
      disposition: "restored",
      operations: name === "missingOriginal" ? ["rename"] : ["rmdir", "rename"],
      originalPresent: true,
      archivePresent: false,
    });
  }
  expect(cases["committed"]).toMatchObject({
    disposition: "already-recorded",
    operations: [],
    owners: {
      [String(result["scanDir"])]: "new",
      [String(result["archiveDir"])]: "previous",
    },
  });
  for (const name of ["changedOwner", "unexpectedOwner"]) {
    expect(cases[name]).toMatchObject({
      disposition: "ownership-changed",
      operations: [],
      originalPresent: true,
      archivePresent: true,
    });
  }
  for (const name of ["nonempty", "invalidSibling", "invalidDirectory"]) {
    expect(cases[name]).toMatchObject({
      disposition: "error",
      operations: [],
      originalPresent: true,
      archivePresent: true,
    });
  }
  expect(cases["renameFailure"]).toMatchObject({
    disposition: "error",
    operations: ["rmdir"],
    archivePresent: true,
  });
  for (const value of Object.values(cases)) {
    expect(value).toMatchObject({ locked: true, transactionClosed: true });
  }
});

test("rechecks scan output inside registration after owner and parent validation", () => {
  const result = run("archive-registration") as Record<
    string,
    {
      accepted: boolean;
      events: Array<[string, boolean]>;
      transactionClosed: boolean;
    }
  >;
  expect(result["valid"]).toEqual({
    accepted: true,
    events: [
      ["canonical", false],
      ["empty", false],
      ["owner", true],
      ["parent", true],
      ["canonical", true],
      ["empty", true],
      ["archive", true],
    ],
    transactionClosed: true,
  });
  for (const name of [
    "owner-refused",
    "parent-refused",
    "nonempty",
    "noncanonical",
  ]) {
    expect(result[name]?.accepted).toBe(false);
    expect(result[name]?.events.some(([event]) => event === "archive")).toBe(
      false,
    );
    expect(result[name]?.transactionClosed).toBe(true);
  }
});

test("keeps authenticated historical aliases visible without trusting a replacement checkout", () => {
  const result = run("persisted-alias");

  expect(result["scans"]).toEqual([
    "legacy-scan",
    "requested-scan",
    "reused-scan",
  ]);
  expect(result["replacementRequest"]).toEqual([]);
  expect(result["findings"]).toEqual(["current-finding", "historical-finding"]);
  expect(result["freshFindings"]).toEqual([
    "current-finding",
    "historical-finding",
  ]);
  expect(result["replacementFindings"]).toEqual([]);
  expect(result["emptyFindings"]).toEqual([]);
  expect(result["projectionAvailable"]).toEqual({
    fresh: true,
    empty: true,
    replacementPath: false,
    replacementId: false,
    unknownId: true,
  });
  expect(result["rejectsBothSelectors"]).toBe(true);
  expect(result["readOnly"]).toBe(true);
  expect(result["feedback"]).toEqual(["historical-finding"]);
  expect(result["matchingCount"]).toBe(3);
  expect(result["reusedListingProbes"]).toBe(0);
  expect(result["stored"]).toBe("repository-current");
});

test.each(["migration", "migration-recorded31"])(
  "upgrades only independently verified pre-release repository hashes (%s)",
  (scenario) => {
    const result = run(scenario);

    expect(result["identities"]).toEqual(result["expected"]);
    expect(result["startingVersion"]).toBe(
      scenario === "migration-recorded31" ? 31 : 30,
    );
    expect(result["normalizationCount"]).toBe(1);
    expect(result["normalizationTransactions"]).toEqual([true]);
    expect(result["currentOpenProbes"]).toBe(0);
    expect(result["recordsPreserved"]).toBe(true);
    expect(result["scanGenerationsUnbound"]).toBe(true);
    expect(result["idempotent"]).toBe(true);
    expect(result["foldedLegacyScopesEqual"]).toBe(true);
    expect(result["currentScopesDistinct"]).toBe(true);
    expect(result["targetCount"]).toBe(12);
    expect(result["migrations"]).toEqual(
      Array.from({ length: 40 }, (_, index) => index + 1),
    );
  },
);

test("keeps unproved legacy history unbound and rejects newer or indeterminate owners", () => {
  const result = run("null-history");

  expect(result["sameCheckoutMetadata"]).toBe(true);
  expect(result["stored"]).toEqual({
    unchanged: null,
    newer: null,
    "invalid-time": null,
    "no-history": "current-no-history",
    "replacement-alias": "current-newer",
  });
  expect(result["registrationErrors"]).toEqual(["invalid-time", "newer"]);
  expect(result["scans"]).toEqual(["replacement-alias-scan"]);
});

test("binds late NULL identities only when the selected target is registered", () => {
  const result = run("late-null");

  expect(result["stored"]).toEqual({
    requested: "repository-current",
    unscanned: "repository-current",
    unselected: null,
    historical: null,
  });
  expect(result["fullBackfillCalls"]).toBe(0);
  expect(result["maintenanceProbes"]).toEqual({
    requested: 0,
    unscanned: 0,
    unselected: 0,
    historical: 0,
  });
  expect(result["selectedProbes"]).toEqual({
    requested: 0,
    unscanned: 1,
    unselected: 0,
    historical: 0,
  });
  expect(result["selectedRegistrationId"]).toBe("unscanned");
  expect(result["selectedGuarded"]).toBe(true);
  expect(result["historicalRegistrationId"]).toBe("historical");
  expect(result["scans"]).toEqual(["established-scan", "requested-scan"]);
  expect(result["historicalExact"]).toEqual(["historical-scan"]);
  expect(result["feedback"]).toEqual([]);
});

test("guards identity binding at the database write and rechecks lost bindings", () => {
  const result = run("binding");

  expect(result["guarded"]).toEqual({
    idHistory: false,
    pathHistory: false,
    wrongPath: false,
    alreadyBound: false,
    eligible: true,
    repeat: false,
  });
  expect(result["stored"]).toEqual({
    eligible: "repository-current",
    "id-history": null,
    "path-history": null,
    donor: null,
    bound: "repository-bound",
  });
  expect(result["ignoredInsert"]).toEqual({
    id: "actual-target",
    reselected: true,
    unbound: true,
    insertsNull: true,
  });
  expect(result["lostToHistory"]).toEqual({
    accepted: true,
    rechecked: true,
    guarded: true,
  });
  expect(result["lostToConflictingIdentity"]).toEqual({
    accepted: false,
    rechecked: true,
    guarded: true,
  });
});

test("compares sealed history from persisted evidence without weakening automatic requesters", () => {
  const result = run("sealed-comparison");

  expect(result["accepted"]).toEqual([true, true]);
  expect(result["conflictingIdentitiesAccepted"]).toBe(false);
  expect(result["healthyTargetless"]).toBe(true);
  expect(result["refusedTargetless"]).toBe(false);
  expect(result["savedCount"]).toBe(2);
  expect(result["unregisteredAutomaticRequesterRejected"]).toBe(true);
});

test("admits rerun lineage only through the verified repository and exact scope", () => {
  const result = run("lineage");

  expect(result["accepted"]).toEqual({
    requested: true,
    removed: true,
    legacy: false,
    unverified: false,
    clone: false,
    scope: false,
    changed: false,
  });
  expect(result["scanCount"]).toBe(7);
});

test("revalidates saved workspace identity inside the scan-start transaction", () => {
  const result = run("saved-start");

  expect(result["accepted"]).toEqual({
    valid: true,
    "changed-generation": false,
    "changed-saved-id": false,
  });
  expect(result["verifiedInsideTransaction"]).toBe(true);
  expect(result["scanCount"]).toBe(1);
  expect(result["stored"]).toBe("repository-current");
});

test("checks current ownership before rejoining saved scan tasks", () => {
  const result = run("scan-reuse");

  expect(result["owners"]).toEqual({
    current: true,
    legacy: true,
    refused: false,
    contradictory: false,
    missing: false,
  });
  expect(result["reuse"]).toEqual({
    current: {
      workspace: { accepted: true, createdRun: false },
      prompt: { accepted: true, createdRun: false },
      headless: { accepted: true, createdRun: false },
      "deep-direct": { accepted: true, createdRun: true },
      "deep-transaction": { accepted: true, createdRun: true },
      "deep-terminal": { accepted: true, createdRun: false },
    },
    refused: Object.fromEntries(
      [
        "workspace",
        "prompt",
        "headless",
        "deep-direct",
        "deep-transaction",
        "deep-terminal",
      ].map((kind) => [kind, { accepted: false, createdRun: false }]),
    ),
  });
  expect(result["legacyGeneration"]).toBeNull();
});

test("quarantines unproved public-v30 bindings without discarding historical records", () => {
  const result = run("v30-current");

  expect(result["stored"]).toEqual({
    "current-owner": "current-generation",
    "old-owner": null,
    "removed-old": null,
    "removed-valid": "current-generation",
    "invalid-time": null,
    "unverified-anchor": null,
    "opaque-missing": null,
    "valid-scope": "scope-current",
  });
  expect(result["recordsPreserved"]).toBe(true);
  expect(result["targetIdsPreserved"]).toBe(true);
  expect(result["removedExact"]).toEqual(["removed-old-scan"]);
  expect(result["visibleFindings"]).toEqual(["current-owner-finding"]);
  expect(result["oldRegistrationRejected"]).toBe(true);
});
