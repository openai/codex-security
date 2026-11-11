"""Bind final manifests to the registered target, scope, and completion contract."""

import json
import sqlite3
from pathlib import Path, PurePosixPath
from typing import Any

import workbench_scan_history as scan_history
from finalize_scan_contract import PRODUCER_NAME
from workbench_scan_start import loaded_plugin_version, stored_diff_target
from workbench_source_scopes import expected_target_kinds, requested_scan_paths
from workbench_target import clean_worktree_content_digest, diff_snapshot_digest
from workbench_validation import path_within_scope, reject_non_finite_json


def requested_scan_file_paths(scan: sqlite3.Row) -> list[str]:
    # Older scans did not record path kinds. Retain their lexical scope semantics
    # rather than infer the original target from a possibly changed checkout.
    if scan["recipe_json"] is None:
        return []
    recipe = json.loads(scan["recipe_json"], parse_constant=reject_non_finite_json)
    return recipe.get("scopeFilePaths", [])


def requested_finding_scope(scan: sqlite3.Row) -> list[tuple[str, bool]]:
    """Return requested paths paired with whether the stored recipe identified each one as a file."""
    files = {PurePosixPath(path) for path in requested_scan_file_paths(scan)}
    return [(path, PurePosixPath(path) in files) for path in requested_scan_paths(scan)]


def scan_contract(scan: sqlite3.Row) -> dict[str, Any]:
    """Return the target identity, scope requirements, and diff target recorded for this scan."""
    target = Path(scan["target_path"])
    target_contract = {
        "allowedKinds": expected_target_kinds(scan),
        "displayName": target.name,
        "targetId": scan["target_id"],
    }
    if (
        scan["mode"] != "diff"
        and scan["target_snapshot_digest"]
        and (
            scan["target_revision"] == "unversioned"
            or scan["target_snapshot_digest"] != clean_worktree_content_digest()
        )
    ):
        target_contract["requiredSnapshotDigest"] = scan["target_snapshot_digest"]
    return {
        "diffTarget": stored_diff_target(scan),
        "scope": {
            "requiredExcludePaths": [],
            "requestedPath": scan["scope"],
            "filePaths": requested_scan_file_paths(scan),
            **(
                {"requiredIncludePaths": requested_scan_paths(scan)}
                if scan["mode"] != "diff"
                else {}
            ),
        },
        "target": target_contract,
    }


def expected_coverage_mode(scan: sqlite3.Row) -> str:
    """Return the coverage mode implied by the recorded scope, scan mode, and diff target kind."""
    if scan["mode"] == "diff":
        mode = {
            "commit": "commit",
            "range": "branch_diff",
            "working_tree": "working_tree",
        }.get(scan["diff_target_kind"])
        if mode is None:
            raise SystemExit("This migrated diff scan does not have a validated change set.")
        return mode
    if scan["scope"] != "." or (
        "recipe_json" in scan.keys()
        and scan["recipe_json"] is not None
        and json.loads(scan["recipe_json"])["target"]["kind"] == "paths"
    ):
        return "scoped_path"
    return "deep_repository" if scan["mode"] == "deep" else "repository"


def workbench_completion_binding(
    scan: sqlite3.Row, completed_at: str, manifest: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build the scan ID, timestamps, producer, target, and scope used to bind output artifacts at completion."""
    contract = scan_contract(scan)
    target_contract = contract["target"]
    plugin_version = loaded_plugin_version()
    target: dict[str, Any] = {
        "targetId": target_contract["targetId"],
        "displayName": target_contract["displayName"],
    }
    if scan["mode"] == "diff":
        target["baseRevision"] = scan["diff_base_revision"]
        target["headRevision"] = scan["diff_head_revision"]
        if snapshot_digest := diff_snapshot_digest(scan, manifest):
            target["snapshotDigest"] = snapshot_digest
    else:
        if scan["target_revision"] != "unversioned":
            target["revision"] = scan["target_revision"]
        if "requiredSnapshotDigest" in target_contract:
            target["snapshotDigest"] = target_contract["requiredSnapshotDigest"]

    scope: dict[str, Any] = {
        "includePaths": requested_scan_paths(scan),
        "excludePaths": contract["scope"]["requiredExcludePaths"],
    }

    binding: dict[str, Any] = {
        "scanId": scan["id"],
        "startedAt": scan["started_at"],
        "completedAt": completed_at,
        "producer": {"name": PRODUCER_NAME, "version": plugin_version},
        "target": target,
        "allowedTargetKinds": target_contract["allowedKinds"],
        "scope": scope,
        "coverageMode": expected_coverage_mode(scan),
    }
    return scan_history.preserve_sealed_completion(binding, manifest)


def verify_manifest_binding(scan: sqlite3.Row, manifest: dict[str, Any]) -> None:
    """Raise SystemExit if the supplied manifest does not match the registered scan, target, or scope."""
    manifest_scan = manifest.get("scan")
    if not isinstance(manifest_scan, dict):
        raise SystemExit("scan-manifest.json scan must be an object.")
    if manifest_scan.get("id") != scan["id"]:
        raise SystemExit("scan-manifest.json scan.id must match the workbench scan ID.")
    target = manifest_scan.get("target")
    if not isinstance(target, dict):
        raise SystemExit("scan-manifest.json scan.target must be an object.")
    expected_contract = scan_contract(scan)
    expected_target = expected_contract["target"]
    if target.get("targetId") != expected_target["targetId"]:
        raise SystemExit("scan-manifest.json targetId must match the workbench target.")
    if target.get("displayName") != expected_target["displayName"]:
        raise SystemExit("scan-manifest.json target displayName must match the workbench target.")
    if target.get("kind") not in expected_target["allowedKinds"]:
        raise SystemExit("scan-manifest.json target kind must match the workbench target.")
    if (
        scan["target_revision"] != "unversioned"
        and target.get("kind") in {"git_worktree", "git_revision"}
        and target.get("revision") != scan["target_revision"]
    ):
        raise SystemExit("scan-manifest.json target revision must match the workbench target.")
    if (
        scan["mode"] != "diff"
        and scan["target_snapshot_digest"] is not None
        and target.get("kind") in {"directory_snapshot", "git_worktree"}
        and target.get("snapshotDigest") != scan["target_snapshot_digest"]
    ):
        raise SystemExit(
            "scan-manifest.json target snapshotDigest must match the workbench target snapshot."
        )
    if scan["mode"] == "diff":
        if not scan["diff_target_kind"]:
            raise SystemExit("This migrated diff scan does not have a validated change set.")
        if target.get("baseRevision") != scan["diff_base_revision"]:
            raise SystemExit(
                "scan-manifest.json target baseRevision must match the workbench diff target."
            )
        if target.get("headRevision") != scan["diff_head_revision"]:
            raise SystemExit(
                "scan-manifest.json target headRevision must match the workbench diff target."
            )
        if (
            scan["diff_target_kind"] == "working_tree"
            and target.get("snapshotDigest") != scan["diff_content_digest"]
        ):
            raise SystemExit(
                "scan-manifest.json target snapshotDigest must match the selected "
                "working-tree contents."
            )
    scope = manifest_scan.get("scope")
    if not isinstance(scope, dict):
        raise SystemExit("scan-manifest.json scan.scope must be an object.")
    include_paths = scope.get("includePaths")
    if not isinstance(include_paths, list):
        raise SystemExit("scan-manifest.json scope includePaths must be an array.")
    if scope.get("excludePaths") != []:
        raise SystemExit(
            "scan-manifest.json scope excludePaths must match the workbench scan scope."
        )
    requested_scope = scan["scope"]
    if scan["mode"] != "diff" and include_paths != requested_scan_paths(scan):
        raise SystemExit("scan-manifest.json scope must match the workbench scan scope.")
    for include_path in include_paths:
        if not isinstance(include_path, str) or not path_within_scope(
            include_path, requested_scope
        ):
            raise SystemExit("scan-manifest.json scope must stay inside the workbench scan scope.")
