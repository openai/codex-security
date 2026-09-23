from __future__ import annotations

import json
import runpy
import sqlite3
import uuid
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import (
    SCRIPT,
    create_saved_workspace,
    initialize_git_repository,
    run_workbench,
    start_delivered_scan,
    write_completed_contract,
)


def dependency_entry(package: str, version: str) -> dict[str, object]:
    return {
        "ecosystem": "npm",
        "registry": "https://registry.npmjs.org",
        "package": package,
        "oldVersion": None,
        "newVersion": version,
    }


def dependency_artifacts(scan_dir: Path) -> tuple[Path, Path]:
    artifact_dir = scan_dir / "artifacts" / "02_discovery" / "dependency-update-scan"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    direct = dependency_entry("direct-package", "1.0.0")
    transitive = dependency_entry("transitive-package", "2.0.0")
    discovery = {
        "mode": "repository",
        "dependencies": [
            {**direct, "dependencyTypes": ["runtime"]},
            {**transitive, "dependencyTypes": ["runtime"]},
        ],
    }
    impacts = {
        "dependencies": [
            {
                **direct,
                "affectedProjects": ["services/api"],
                "dependencyChains": [["services/api", "direct-package"]],
            },
            {
                **transitive,
                "affectedProjects": ["services/api"],
                "dependencyChains": [["services/api", "direct-package", "transitive-package"]],
            },
        ]
    }
    discovery_path = artifact_dir / "dependency-discovery.json"
    impacts_path = artifact_dir / "dependency-impacts.json"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    impacts_path.write_text(json.dumps(impacts), encoding="utf-8")
    return discovery_path, impacts_path


def running_dependency_scan(
    tmp_path: Path,
) -> tuple[Path, Path, str, Path]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target, mode="full_dependency")
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan = started["results"]
    return state_dir, target, str(scan["scanId"]), Path(str(scan["scanDir"]))


def test_dependency_depth_migration_preserves_unlimited_legacy_scans() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    previous_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] <= 42
    )
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": previous_migrations}):
        apply_migrations(connection)

    timestamp = "2026-07-01T00:00:00Z"
    connection.execute(
        "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
        ("legacy-workspace", timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
            status, phase, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy-scan",
            "legacy-workspace",
            "/legacy/target",
            "legacy-revision",
            ".",
            "full_dependency",
            "/legacy/scan",
            "running",
            "discovery",
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    connection.commit()

    apply_migrations(connection)

    assert (
        connection.execute(
            "SELECT dependency_depth FROM workspaces WHERE id = ?", ("legacy-workspace",)
        ).fetchone()["dependency_depth"]
        is None
    )
    assert (
        connection.execute(
            "SELECT dependency_depth FROM scans WHERE id = ?", ("legacy-scan",)
        ).fetchone()["dependency_depth"]
        is None
    )


def test_dependency_scan_target_migration_preserves_comprehensive_legacy_scans() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    previous_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] < 44
    )
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": previous_migrations}):
        apply_migrations(connection)

    timestamp = "2026-07-01T00:00:00Z"
    connection.execute(
        "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
        ("legacy-workspace", timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
            status, phase, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy-scan",
            "legacy-workspace",
            "/legacy/target",
            "legacy-revision",
            ".",
            "full_dependency",
            "/legacy/scan",
            "running",
            "discovery",
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    connection.commit()

    apply_migrations(connection)

    assert (
        connection.execute(
            "SELECT dependency_scan_target FROM workspaces WHERE id = ?", ("legacy-workspace",)
        ).fetchone()["dependency_scan_target"]
        == "malware-and-vulnerabilities"
    )
    assert (
        connection.execute(
            "SELECT dependency_scan_target FROM scans WHERE id = ?", ("legacy-scan",)
        ).fetchone()["dependency_scan_target"]
        == "malware-and-vulnerabilities"
    )


@pytest.mark.parametrize(("argument", "depth"), (("1", 1), ("3", 3), ("all", None)))
def test_dependency_depth_round_trips_through_workspace_scan_and_context(
    tmp_path: Path, argument: str, depth: int | None
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())

    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "full_dependency",
        "--dependency-depth",
        argument,
    )
    assert created["dependencyDepth"] == depth

    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "full_dependency",
        "--dependency-depth",
        argument,
    )
    assert saved["dependencyDepth"] == depth

    started = start_delivered_scan(state_dir, "--workspace-id", workspace_id)
    scan_id = str(started["results"]["scanId"])
    assert started["dependencyDepth"] == depth
    assert started["results"]["dependencyDepth"] == depth

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert context["scan"]["dependencyDepth"] == depth
    assert context["workspace"]["dependencyDepth"] == depth

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT dependency_depth FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone() == (depth,)
        assert connection.execute(
            "SELECT dependency_depth FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (depth,)


@pytest.mark.parametrize("scan_target", ("malware", "malware-and-vulnerabilities"))
def test_dependency_scan_target_round_trips_through_workspace_scan_and_context(
    tmp_path: Path, scan_target: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())

    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "full_dependency",
        "--dependency-scan-target",
        scan_target,
    )
    assert created["dependencyScanTarget"] == scan_target

    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "full_dependency",
        "--dependency-scan-target",
        scan_target,
    )
    assert saved["dependencyScanTarget"] == scan_target

    started = start_delivered_scan(state_dir, "--workspace-id", workspace_id)
    scan_id = str(started["results"]["scanId"])
    assert started["dependencyScanTarget"] == scan_target
    assert started["results"]["dependencyScanTarget"] == scan_target

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert context["scan"]["dependencyScanTarget"] == scan_target
    assert context["workspace"]["dependencyScanTarget"] == scan_target

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT dependency_scan_target FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone() == (scan_target,)
        assert connection.execute(
            "SELECT dependency_scan_target FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (scan_target,)


def test_new_dependency_workspaces_default_to_direct_dependencies(tmp_path: Path) -> None:
    state_dir, _, scan_id, _ = running_dependency_scan(tmp_path)

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert context["scan"]["dependencyDepth"] == 1
    assert context["workspace"]["dependencyDepth"] == 1
    assert context["scan"]["dependencyScanTarget"] == "malware-and-vulnerabilities"
    assert context["workspace"]["dependencyScanTarget"] == "malware-and-vulnerabilities"


@pytest.mark.parametrize("mode", ("standard", "full_dependency"))
def test_dependency_scans_preserve_a_selected_folder_scope(tmp_path: Path, mode: str) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    folder = target / "services" / "api"
    folder.mkdir(parents=True)
    (folder / "handler.py").write_text("handler = True\n", encoding="utf-8")
    workspace_id = str(uuid.uuid4())
    dependency_arguments = ["--scan-dependencies"] if mode == "standard" else []

    created = run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        "services/api",
        "--mode",
        mode,
        *dependency_arguments,
    )
    assert created["scope"] == "services/api"

    saved = run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        "services/api",
        "--mode",
        mode,
        *dependency_arguments,
    )
    assert saved["scope"] == "services/api"

    started = start_delivered_scan(state_dir, "--workspace-id", workspace_id)
    scan = started["results"]
    assert scan["scope"] == "services/api"
    assert scan["scanDependencies"] is True
    assert scan["contract"]["scope"]["requestedPath"] == "services/api"
    assert scan["progress"]["coverage"]["filesTotal"] == 1


@pytest.mark.parametrize(("argument", "depth"), ((None, 1), ("3", 3), ("all", None)))
def test_registered_cli_scans_persist_dependency_depth(
    tmp_path: Path, argument: str | None, depth: int | None
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(target),
        "target": {"kind": "repository", "paths": []},
    }

    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--recipe-json",
        json.dumps(recipe),
        "--dependency-mode",
        "full_dependency",
        *(["--dependency-depth", argument] if argument is not None else []),
    )
    scan_id = str(registered["scanId"])
    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert context["scan"]["dependencyDepth"] == depth
    assert context["workspace"]["dependencyDepth"] == depth
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT dependency_depth FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (depth,)


@pytest.mark.parametrize("mode", ("standard", "full_dependency"))
@pytest.mark.parametrize("git_backed", (True, False), ids=("git", "directory"))
@pytest.mark.parametrize(
    ("paths", "argument", "depth"),
    (
        (["services/api"], "3", 3),
        (["services/api", "tools/worker"], "all", None),
    ),
    ids=("single-path-finite-depth", "multiple-paths-all-depths"),
)
def test_registered_dependency_scans_preserve_the_exact_selected_paths(
    tmp_path: Path, mode: str, git_backed: bool, paths: list[str], argument: str, depth: int | None
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    if git_backed:
        initialize_git_repository(target)
    else:
        target.mkdir()
    for path in ("services/api", "tools/worker", "unrelated"):
        project = target / path
        project.mkdir(parents=True)
        (project / "package.json").write_text("{}\n", encoding="utf-8")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(target),
        "target": {"kind": "paths", "paths": paths},
    }
    dependency_arguments = (
        ["--dependency-mode", mode] if mode == "full_dependency" else ["--scan-dependencies"]
    )

    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--recipe-json",
        json.dumps(recipe),
        "--dependency-depth",
        argument,
        *dependency_arguments,
    )
    scan_id = str(registered["scanId"])
    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    scan = context["scan"]

    expected_scope = paths[0] if len(paths) == 1 else "."
    assert scan["scope"] == expected_scope
    assert scan["mode"] == mode
    assert scan["scanDependencies"] is True
    assert scan["dependencyDepth"] == depth
    assert context["workspace"]["dependencyDepth"] == depth
    assert registered["scopeFileCount"] == (0 if mode == "full_dependency" else len(paths))
    assert scan["contract"] == registered["contract"]
    assert scan["contract"]["scope"] == {
        "requestedPath": expected_scope,
        "requiredIncludePaths": paths,
        "requiredExcludePaths": [],
    }
    assert scan["contract"]["target"]["allowedKinds"] == [
        "git_worktree" if git_backed else "directory_snapshot"
    ]
    if not git_backed:
        assert scan["targetRevision"] == "unversioned"
        assert scan["contract"]["target"]["requiredSnapshotDigest"].startswith(
            "codex-security-snapshot/v1:sha256:"
        )
    assert context["recipe"]["target"] == recipe["target"]
    saved_recipe = run_workbench(state_dir, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    assert saved_recipe["target"] == recipe["target"]


@pytest.mark.parametrize(
    ("argument", "scan_target"),
    ((None, "malware-and-vulnerabilities"), ("malware", "malware")),
)
def test_registered_cli_scans_persist_dependency_scan_target(
    tmp_path: Path, argument: str | None, scan_target: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    recipe = {
        "config": {},
        "mode": "standard",
        "repository": str(target),
        "target": {"kind": "repository", "paths": []},
    }

    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--recipe-json",
        json.dumps(recipe),
        "--dependency-mode",
        "full_dependency",
        *(["--dependency-scan-target", argument] if argument is not None else []),
    )
    scan_id = str(registered["scanId"])
    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert context["scan"]["dependencyScanTarget"] == scan_target
    assert context["workspace"]["dependencyScanTarget"] == scan_target
    assert context["recipe"]["target"] == recipe["target"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT dependency_scan_target FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (scan_target,)


def test_prompt_only_dependency_scan_defaults_to_direct_dependencies(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()

    started = run_workbench(
        state_dir,
        "start-prompt-only-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "full_dependency",
        "--scan-root",
        str(tmp_path / "scans"),
    )

    assert started["scan"]["dependencyDepth"] == 1
    assert started["workspace"]["dependencyDepth"] == 1
    assert started["scan"]["dependencyScanTarget"] == "malware-and-vulnerabilities"
    assert started["workspace"]["dependencyScanTarget"] == "malware-and-vulnerabilities"


def test_prompt_only_dependency_scan_joins_only_matching_dependency_depth(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()

    def launch(depth: str) -> dict[str, object]:
        return run_workbench(
            state_dir,
            "start-prompt-only-scan",
            "--thread-id",
            "fixture-thread",
            "--target-path",
            str(target),
            "--scope",
            ".",
            "--mode",
            "full_dependency",
            "--dependency-depth",
            depth,
            "--scan-root",
            str(tmp_path / "scans"),
        )

    direct = launch("1")
    unlimited = launch("all")
    joined = launch("all")

    assert direct["startDisposition"] == "created"
    assert direct["scan"]["dependencyDepth"] == 1
    assert unlimited["startDisposition"] == "created"
    assert unlimited["scan"]["dependencyDepth"] is None
    assert unlimited["scan"]["scanId"] != direct["scan"]["scanId"]
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["scanId"] == unlimited["scan"]["scanId"]
    assert joined["scan"]["dependencyDepth"] is None


def test_prompt_only_dependency_scan_joins_only_matching_dependency_scan_target(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()

    def launch(scan_target: str) -> dict[str, object]:
        return run_workbench(
            state_dir,
            "start-prompt-only-scan",
            "--thread-id",
            "fixture-thread",
            "--target-path",
            str(target),
            "--scope",
            ".",
            "--mode",
            "full_dependency",
            "--dependency-scan-target",
            scan_target,
            "--scan-root",
            str(tmp_path / "scans"),
        )

    comprehensive = launch("malware-and-vulnerabilities")
    malware = launch("malware")
    joined = launch("malware")

    assert comprehensive["startDisposition"] == "created"
    assert comprehensive["scan"]["dependencyScanTarget"] == "malware-and-vulnerabilities"
    assert malware["startDisposition"] == "created"
    assert malware["scan"]["dependencyScanTarget"] == "malware"
    assert malware["scan"]["scanId"] != comprehensive["scan"]["scanId"]
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["scanId"] == malware["scan"]["scanId"]
    assert joined["scan"]["dependencyScanTarget"] == "malware"


def test_running_dependency_scan_projects_real_provisional_graph(tmp_path: Path) -> None:
    state_dir, _, scan_id, scan_dir = running_dependency_scan(tmp_path)
    dependency_artifacts(scan_dir)

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    graph = context["scan"]["dependencies"]
    nodes = {node["id"]: node for node in graph["nodes"]}
    names = {node["name"]: node for node in nodes.values()}

    assert set(names) == {"services/api", "direct-package", "transitive-package"}
    assert names["services/api"]["kind"] == "project"
    assert names["direct-package"]["status"] == "not_scanned"
    assert names["transitive-package"]["status"] == "not_scanned"
    assert {
        (nodes[edge["from"]]["name"], nodes[edge["to"]]["name"]) for edge in graph["edges"]
    } == {
        ("services/api", "direct-package"),
        ("direct-package", "transitive-package"),
    }
    assert context["workspace"]["results"]["dependencies"] == graph


def test_provisional_graph_never_guesses_between_duplicate_package_versions(
    tmp_path: Path,
) -> None:
    state_dir, _, scan_id, scan_dir = running_dependency_scan(tmp_path)
    discovery_path, impacts_path = dependency_artifacts(scan_dir)
    entries_and_chains = (
        (
            dependency_entry("shared-package", "1.0.0"),
            ["services/api", "shared-package"],
        ),
        (
            dependency_entry("shared-package", "2.0.0"),
            ["services/api", "shared-package"],
        ),
        (
            dependency_entry("first-leaf", "3.0.0"),
            ["services/api", "shared-package", "first-leaf"],
        ),
        (
            dependency_entry("second-leaf", "4.0.0"),
            ["services/api", "shared-package", "second-leaf"],
        ),
    )
    discovery_path.write_text(
        json.dumps(
            {
                "mode": "repository",
                "dependencies": [entry for entry, _ in entries_and_chains],
            }
        ),
        encoding="utf-8",
    )
    impacts_path.write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        **entry,
                        "affectedProjects": ["services/api"],
                        "dependencyChains": [chain],
                    }
                    for entry, chain in entries_and_chains
                ]
            }
        ),
        encoding="utf-8",
    )

    graph = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["dependencies"]
    nodes = {node["id"]: node for node in graph["nodes"]}

    assert {
        (node["name"], node.get("newVersion"))
        for node in nodes.values()
        if node["kind"] == "dependency"
    } == {
        ("shared-package", "1.0.0"),
        ("shared-package", "2.0.0"),
        ("first-leaf", "3.0.0"),
        ("second-leaf", "4.0.0"),
    }
    assert {
        (
            nodes[edge["from"]]["name"],
            nodes[edge["to"]]["name"],
            nodes[edge["to"]].get("newVersion"),
        )
        for edge in graph["edges"]
    } == {
        ("services/api", "shared-package", "1.0.0"),
        ("services/api", "shared-package", "2.0.0"),
    }


def test_combined_code_and_dependency_scan_projects_provisional_graph(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--mode",
        "standard",
        "--scan-dependencies",
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
        "--scan-dependencies",
    )
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan = started["results"]
    scan_id = str(scan["scanId"])
    dependency_artifacts(Path(str(scan["scanDir"])))

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert context["scan"]["mode"] == "standard"
    assert context["scan"]["scanDependencies"] is True
    assert {node["name"] for node in context["scan"]["dependencies"]["nodes"]} == {
        "services/api",
        "direct-package",
        "transitive-package",
    }


@pytest.mark.parametrize(
    "invalid_artifact",
    (
        "missing_discovery",
        "missing_impacts",
        "symlinked_discovery",
        "symlinked_impacts",
        "malformed_json",
        "missing_chains",
        "invalid_chain",
        "mismatched_chain_destination",
    ),
)
def test_running_dependency_scan_never_invents_provisional_edges(
    tmp_path: Path, invalid_artifact: str
) -> None:
    state_dir, _, scan_id, scan_dir = running_dependency_scan(tmp_path)
    discovery_path, impacts_path = dependency_artifacts(scan_dir)

    if invalid_artifact == "missing_discovery":
        discovery_path.unlink()
    elif invalid_artifact == "missing_impacts":
        impacts_path.unlink()
    elif invalid_artifact in {"symlinked_discovery", "symlinked_impacts"}:
        selected = discovery_path if invalid_artifact == "symlinked_discovery" else impacts_path
        external = tmp_path / f"external-{selected.name}"
        external.write_text(selected.read_text(encoding="utf-8"), encoding="utf-8")
        selected.unlink()
        selected.symlink_to(external)
    elif invalid_artifact == "malformed_json":
        impacts_path.write_text("{not valid json", encoding="utf-8")
    else:
        impacts = json.loads(impacts_path.read_text(encoding="utf-8"))
        if invalid_artifact == "missing_chains":
            chains = []
        elif invalid_artifact == "invalid_chain":
            chains = [["services/api"]]
        else:
            chains = [["services/api", "direct-package", "different-package"]]
        impacts["dependencies"][1]["dependencyChains"] = chains
        impacts_path.write_text(json.dumps(impacts), encoding="utf-8")

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert "dependencies" not in context["scan"]
    assert "dependencies" not in context["workspace"]["results"]


def test_failed_dependency_scan_does_not_project_provisional_graph(tmp_path: Path) -> None:
    state_dir, _, scan_id, scan_dir = running_dependency_scan(tmp_path)
    dependency_artifacts(scan_dir)
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Fixture failure")

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert context["scan"]["progress"]["status"] == "failed"
    assert "dependencies" not in context["scan"]


def test_source_only_scan_does_not_project_dependency_artifacts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target, mode="standard")
    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan = started["results"]
    scan_id = str(scan["scanId"])
    dependency_artifacts(Path(str(scan["scanDir"])))

    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert context["scan"]["scanDependencies"] is False
    assert "dependencies" not in context["scan"]


def test_completed_coverage_graph_takes_precedence_over_provisional_graph(
    tmp_path: Path,
) -> None:
    state_dir, target, scan_id, scan_dir = running_dependency_scan(tmp_path)
    dependency_artifacts(scan_dir)
    write_completed_contract(scan_dir, scan_id, target)
    authoritative_graph = {
        "nodes": [
            {
                "id": "npm:final-package@9.0.0",
                "kind": "dependency",
                "name": "final-package",
                "package": "final-package",
                "ecosystem": "npm",
                "registry": "https://registry.npmjs.org",
                "oldVersion": None,
                "newVersion": "9.0.0",
                "status": "completed",
                "changed": False,
                "findingCount": 0,
            }
        ],
        "edges": [],
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage["dependencies"] = authoritative_graph
    coverage_path.write_text(json.dumps(coverage), encoding="utf-8")

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    context = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)

    assert completed["scan"]["dependencies"] == authoritative_graph
    assert context["scan"]["dependencies"] == authoritative_graph
    assert context["workspace"]["results"]["dependencies"] == authoritative_graph
