from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

DEPTH_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dependency_scan_depth.py"


def dependency(
    package: str,
    version: str,
    *,
    ecosystem: str = "npm",
    registry: str = "https://registry.npmjs.org",
    previous: str | None = None,
    types: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "ecosystem": ecosystem,
        "registry": registry,
        "package": package,
        "oldVersion": previous,
        "newVersion": version,
        "anchorPath": "packages/example/package-lock.json",
        "anchorStartLine": 12,
        "dependencyTypes": types or [],
    }


def impact(entry: dict[str, Any], *chains: list[str]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in {
            **entry,
            "affectedProjects": ["packages/example"],
            "dependencyChains": list(chains),
        }.items()
        if key != "dependencyTypes"
    }


def run_depth_selection(
    tmp_path: Path,
    dependencies: list[dict[str, Any]],
    impacts: list[dict[str, Any]],
    depth: int | None,
    *,
    limitations: list[dict[str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    discovery_path = tmp_path / "dependency-discovery.json"
    impacts_path = tmp_path / "dependency-impacts.json"
    discovery = {
        "dependencies": dependencies,
        "coverageLimitations": deepcopy(limitations or []),
    }
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    impacts_path.write_text(json.dumps({"dependencies": impacts}), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(DEPTH_SCRIPT),
            "--discovery",
            str(discovery_path),
            "--impacts",
            str(impacts_path),
            "--dependency-depth",
            "all" if depth is None else str(depth),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout), json.loads(discovery_path.read_text(encoding="utf-8"))


def test_direct_selection_uses_actual_chain_rather_than_dependency_type(tmp_path: Path) -> None:
    direct = dependency("direct-package", "1.0.0", types=["development"])
    transitive = dependency("nested-package", "2.0.0", types=["direct"])

    result, _ = run_depth_selection(
        tmp_path,
        [direct, transitive],
        [
            impact(direct, ["packages/example", "direct-package"]),
            impact(transitive, ["packages/example", "direct-package", "nested-package"]),
        ],
        1,
    )

    assert result["depthCounts"] == [1, 1]
    assert result["dependencies"] == [
        {
            "ecosystem": "npm",
            "registry": "https://registry.npmjs.org",
            "package": "direct-package",
            "oldVersion": None,
            "newVersion": "1.0.0",
        }
    ]


def test_shared_dependency_uses_shortest_actual_chain_across_projects(tmp_path: Path) -> None:
    direct = dependency("direct-package", "1.0.0")
    shared = dependency("shared-package", "2.0.0")
    distant = dependency("distant-package", "3.0.0")

    result, _ = run_depth_selection(
        tmp_path,
        [direct, shared, distant],
        [
            impact(direct, ["packages/example", "direct-package"]),
            impact(
                shared,
                ["packages/example", "direct-package", "bridge", "shared-package"],
                ["packages/other", "other-direct", "shared-package"],
            ),
            impact(
                distant,
                ["packages/example", "direct-package", "bridge", "third", "distant-package"],
            ),
        ],
        2,
    )

    assert result["depthCounts"] == [1, 1, 0, 1]
    assert [entry["package"] for entry in result["dependencies"]] == [
        "direct-package",
        "shared-package",
    ]


def test_same_package_versions_and_registries_keep_distinct_actual_depths(tmp_path: Path) -> None:
    direct_version = dependency("shared-name", "1.0.0")
    nested_version = dependency("shared-name", "2.0.0", previous="1.9.0")
    other_registry = dependency("shared-name", "2.0.0", registry="https://example.public.registry")
    other_ecosystem = dependency(
        "shared-name", "2.0.0", ecosystem="pypi", registry="https://pypi.org"
    )

    result, _ = run_depth_selection(
        tmp_path,
        [direct_version, nested_version, other_registry, other_ecosystem],
        [
            impact(direct_version, ["packages/example", "shared-name"]),
            impact(nested_version, ["packages/example", "parent", "shared-name"]),
            impact(other_registry, ["packages/example", "registry-parent", "shared-name"]),
            impact(other_ecosystem, ["packages/example", "shared-name"]),
        ],
        1,
    )

    assert result["depthCounts"] == [2, 2]
    assert [
        (entry["ecosystem"], entry["registry"], entry["newVersion"])
        for entry in result["dependencies"]
    ] == [
        ("npm", "https://registry.npmjs.org", "1.0.0"),
        ("pypi", "https://pypi.org", "2.0.0"),
    ]


def test_identity_normalizes_ecosystem_registry_and_deduplicates(tmp_path: Path) -> None:
    first = dependency(
        "shared-package", "1.0.0", ecosystem="NPM", registry="HTTPS://Registry.Npmjs.Org/"
    )
    duplicate = dependency("shared-package", "1.0.0")
    normalized_impact = impact(duplicate, ["packages/example", "shared-package"])

    result, _ = run_depth_selection(tmp_path, [first, duplicate], [normalized_impact], 1)

    assert result["depthCounts"] == [1]
    assert result["dependencies"] == [
        {
            "ecosystem": "npm",
            "registry": "https://registry.npmjs.org",
            "package": "shared-package",
            "oldVersion": None,
            "newVersion": "1.0.0",
        }
    ]


def test_unknown_finite_depth_preserves_existing_coverage_limitation_shape(tmp_path: Path) -> None:
    direct = dependency("known-direct", "1.0.0")
    unknown = dependency("unknown-depth", "2.0.0")
    existing = {
        "path": "packages/example/package-lock.json",
        "package": "private-package",
        "reason": "Private registry package.",
    }

    result, discovery = run_depth_selection(
        tmp_path,
        [direct, unknown],
        [impact(direct, ["packages/example", "known-direct"]), impact(unknown)],
        1,
        limitations=[existing],
    )

    assert result["depthCounts"] == [1]
    assert [entry["package"] for entry in result["dependencies"]] == ["known-direct"]
    assert discovery["coverageLimitations"][0] == existing
    assert discovery["coverageLimitations"][1]["package"] == "unknown-depth"
    assert discovery["coverageLimitations"][1]["path"] == unknown["anchorPath"]
    assert "chain" in discovery["coverageLimitations"][1]["reason"].lower()
    assert set(discovery["coverageLimitations"][1]) == {"path", "package", "reason"}


def test_all_preserves_every_identity_and_does_not_require_dependency_chains(
    tmp_path: Path,
) -> None:
    direct = dependency("known-direct", "1.0.0")
    unknown = dependency("unknown-depth", "2.0.0")
    existing = {"path": "lock.json", "package": "prior", "reason": "Existing limitation."}

    result, discovery = run_depth_selection(
        tmp_path,
        [direct, unknown],
        [impact(direct, ["packages/example", "known-direct"])],
        None,
        limitations=[existing],
    )

    assert result["depthCounts"] == [1]
    assert [entry["package"] for entry in result["dependencies"]] == [
        "known-direct",
        "unknown-depth",
    ]
    assert discovery["coverageLimitations"] == [existing]


def test_wrong_chain_endpoint_does_not_fabricate_direct_relationship(tmp_path: Path) -> None:
    package = dependency("real-package", "1.0.0")

    result, discovery = run_depth_selection(
        tmp_path,
        [package],
        [impact(package, ["packages/example", "different-package"])],
        1,
    )

    assert result == {"depthCounts": [], "dependencies": []}
    assert discovery["coverageLimitations"][0]["package"] == "real-package"


def test_direct_selection_can_leave_changed_transitive_only_graph_without_cloud_work(
    tmp_path: Path,
) -> None:
    changed_transitive = dependency("changed-transitive", "2.0.0", previous="1.0.0")

    result, discovery = run_depth_selection(
        tmp_path,
        [changed_transitive],
        [
            impact(
                changed_transitive,
                ["packages/example", "unchanged-direct", "changed-transitive"],
            )
        ],
        1,
    )

    assert result == {"depthCounts": [0, 1], "dependencies": []}
    assert discovery["coverageLimitations"] == []


def test_graph_depth_has_no_artificial_upper_bound(tmp_path: Path) -> None:
    package = dependency("distant-package", "1.0.0")
    intermediate = [f"bridge-{index}" for index in range(41)]

    result, _ = run_depth_selection(
        tmp_path,
        [package],
        [impact(package, ["packages/example", *intermediate, "distant-package"])],
        42,
    )

    assert result["depthCounts"] == [0] * 41 + [1]
    assert [entry["package"] for entry in result["dependencies"]] == ["distant-package"]


def test_empty_dependency_graph_is_an_exact_empty_selection(tmp_path: Path) -> None:
    result, discovery = run_depth_selection(tmp_path, [], [], 1)

    assert result == {"depthCounts": [], "dependencies": []}
    assert discovery["coverageLimitations"] == []
