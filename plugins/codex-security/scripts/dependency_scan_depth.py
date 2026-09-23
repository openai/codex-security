#!/usr/bin/env python3
"""Select public dependency artifacts using their actual first-party graph depth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from runpy import run_path
from typing import Any

DependencyIdentity = tuple[str, str, str, str | None, str]

_REPORTING = run_path(str(Path(__file__).with_name("dependency_scan_reporting.py")))
dependency_identity = _REPORTING["dependency_identity"]
read_object = _REPORTING["read_object"]
require_entries = _REPORTING["require_entries"]


def _discovered_dependencies(
    discovery: dict[str, Any],
) -> dict[DependencyIdentity, dict[str, Any]]:
    dependencies: dict[DependencyIdentity, dict[str, Any]] = {}
    for entry in require_entries(discovery, "dependencies", "Local dependency discovery"):
        dependencies.setdefault(dependency_identity(entry), entry)
    return dependencies


def _actual_dependency_depths(
    discovery: dict[str, Any], impacts: dict[str, Any]
) -> dict[DependencyIdentity, int]:
    discovered = _discovered_dependencies(discovery)
    depths: dict[DependencyIdentity, int] = {}
    for impact in require_entries(impacts, "dependencies", "Local dependency impacts"):
        identity = dependency_identity(impact)
        if identity not in discovered:
            continue
        chains = impact.get("dependencyChains", [])
        if not isinstance(chains, list):
            continue
        for chain in chains:
            if (
                not isinstance(chain, list)
                or len(chain) < 2
                or not all(isinstance(segment, str) and segment.strip() for segment in chain)
                or chain[-1] != impact["package"]
            ):
                continue
            depth = len(chain) - 1
            previous = depths.get(identity)
            if previous is None or depth < previous:
                depths[identity] = depth
    return depths


def dependency_depth_counts(discovery: dict[str, Any], impacts: dict[str, Any]) -> list[int]:
    depths = _actual_dependency_depths(discovery, impacts)
    if not depths:
        return []
    counts = [0] * max(depths.values())
    for depth in depths.values():
        counts[depth - 1] += 1
    return counts


def select_dependencies_by_depth(
    discovery: dict[str, Any],
    impacts: dict[str, Any],
    dependency_depth: int | None,
) -> list[dict[str, Any]]:
    discovered = _discovered_dependencies(discovery)
    depths = _actual_dependency_depths(discovery, impacts) if dependency_depth is not None else {}
    selected: list[dict[str, Any]] = []
    for identity in discovered:
        actual_depth = depths.get(identity)
        if dependency_depth is not None and (
            actual_depth is None or actual_depth > dependency_depth
        ):
            continue
        ecosystem, registry, package, previous, version = identity
        selected.append(
            {
                "ecosystem": ecosystem,
                "registry": registry,
                "package": package,
                "oldVersion": previous,
                "newVersion": version,
            }
        )
    return selected


def _record_unknown_depth_limitations(discovery: dict[str, Any], impacts: dict[str, Any]) -> bool:
    discovered = _discovered_dependencies(discovery)
    depths = _actual_dependency_depths(discovery, impacts)
    unknown = [entry for identity, entry in discovered.items() if identity not in depths]
    if not unknown:
        return False

    limitations = discovery.setdefault("coverageLimitations", [])
    if not isinstance(limitations, list):
        return False

    recorded = False
    for entry in unknown:
        anchor_path = entry.get("anchorPath")
        path = anchor_path if isinstance(anchor_path, str) and anchor_path else "."
        package = entry["package"]
        version = entry["newVersion"]
        registry = entry["registry"]
        limitation = {
            "path": path,
            "package": package,
            "reason": (
                f"No verified dependency chain establishes the graph depth of "
                f"{package}@{version} from {registry}; its published artifact was not scanned."
            ),
        }
        if limitation not in limitations:
            limitations.append(limitation)
            recorded = True
    return recorded


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select public dependency artifacts by actual graph depth."
    )
    parser.add_argument("--discovery", required=True, help="Local dependency-discovery JSON.")
    parser.add_argument("--impacts", required=True, help="Local dependency-impacts JSON.")
    parser.add_argument("--dependency-depth", required=True, help="A selected graph depth, or all.")
    args = parser.parse_args()

    discovery_path = Path(args.discovery)
    discovery = read_object(discovery_path, "Local dependency discovery")
    impacts = read_object(Path(args.impacts), "Local dependency impacts")
    dependency_depth = None if args.dependency_depth == "all" else int(args.dependency_depth)

    selected = select_dependencies_by_depth(discovery, impacts, dependency_depth)
    if dependency_depth is not None and _record_unknown_depth_limitations(discovery, impacts):
        discovery_path.write_text(
            json.dumps(discovery, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    print(
        json.dumps(
            {
                "depthCounts": dependency_depth_counts(discovery, impacts),
                "dependencies": selected,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
