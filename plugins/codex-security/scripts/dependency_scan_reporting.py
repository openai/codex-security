#!/usr/bin/env python3
"""Merge upstream package findings into an unsealed Codex Security findings document."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge published dependency findings into canonical scan findings."
    )
    parser.add_argument("--findings", required=True, help="Unsealed canonical findings.json.")
    parser.add_argument("--results", required=True, help="Cloud dependency-scan results JSON.")
    parser.add_argument(
        "--impacts", required=True, help="Local first-party dependency impacts JSON."
    )
    parser.add_argument(
        "--discovery", help="Local dependency-discovery JSON for canonical inventory."
    )
    parser.add_argument("--coverage", help="Unsealed canonical coverage.json to enrich.")
    arguments = parser.parse_args()
    if (arguments.discovery is None) != (arguments.coverage is None):
        parser.error("--discovery and --coverage must be supplied together")
    return arguments


def read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label}: invalid JSON object at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label}: expected a JSON object")
    return payload


def dependency_identity(entry: dict[str, Any]) -> tuple[str, str, str, str | None, str]:
    required = ("ecosystem", "registry", "package", "newVersion")
    for field in required:
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            raise ValueError(f"Dependency {field} must be a nonempty string.")
    previous = entry.get("oldVersion")
    if previous is not None and (not isinstance(previous, str) or not previous.strip()):
        raise ValueError("Dependency oldVersion must be a nonempty string or null.")
    return (
        entry["ecosystem"].lower(),
        entry["registry"].rstrip("/").lower(),
        entry["package"],
        previous,
        entry["newVersion"],
    )


def safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise ValueError("Dependency finding anchor must be a safe repository-relative POSIX path.")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() == ".":
        raise ValueError("Dependency finding anchor must be a safe repository-relative POSIX path.")
    return path.as_posix()


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string.")
    return value


def application_impact(impact: dict[str, Any], upstream_id: str) -> dict[str, Any]:
    """Keep each upstream issue separate from its evidenced first-party impact."""
    assessments = impact.get("findingAssessments", [])
    if not isinstance(assessments, list):
        raise ValueError("Dependency findingAssessments must be an array.")
    selected = None
    seen: set[str] = set()
    for assessment in assessments:
        if not isinstance(assessment, dict):
            raise ValueError("Dependency finding assessments must be objects.")
        finding_id = require_string(
            assessment.get("upstreamFindingId"), "Assessment upstreamFindingId"
        )
        if finding_id in seen:
            raise ValueError(
                "Dependency finding assessments must have unique upstreamFindingId values."
            )
        seen.add(finding_id)
        if finding_id == upstream_id:
            selected = assessment
    if selected is None:
        return {
            "status": "inconclusive",
            "summary": "Application impact has not been established for this package finding.",
            "evidence": [],
            "limitations": ["No per-finding assessment of first-party usage was recorded."],
        }

    status = selected.get("status")
    if status not in {"affected", "not_affected", "inconclusive"}:
        raise ValueError(
            "Application impact status must be affected, not_affected, or inconclusive."
        )
    summary = require_string(selected.get("summary"), "Application impact summary")
    raw_evidence = selected.get("evidence", [])
    if not isinstance(raw_evidence, list):
        raise ValueError("Application impact evidence must be an array.")
    evidence = []
    for item in raw_evidence:
        if not isinstance(item, dict):
            raise ValueError("Application impact evidence must be an object.")
        line = item.get("startLine")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValueError("Application impact evidence startLine must be a positive integer.")
        evidence.append(
            {
                "path": safe_relative_path(item.get("path")),
                "startLine": line,
                "code": require_string(item.get("code"), "Application impact evidence code"),
                "explanation": require_string(
                    item.get("explanation"), "Application impact evidence explanation"
                ),
            }
        )
    limitations = selected.get("limitations", [])
    if not isinstance(limitations, list):
        raise ValueError("Application impact limitations must be an array.")
    limitations = [require_string(item, "Application impact limitation") for item in limitations]
    if status != "inconclusive" and not evidence:
        status = "inconclusive"
        summary = "Application impact could not be established without first-party evidence."
        limitations.append(
            "The recorded assessment did not provide first-party code or configuration evidence."
        )
    return {"status": status, "summary": summary, "evidence": evidence, "limitations": limitations}


def local_finding(
    package: dict[str, Any],
    upstream: dict[str, Any],
    impact: dict[str, Any],
) -> dict[str, Any]:
    package_name = require_string(package.get("package"), "Package name")
    new_version = require_string(package.get("newVersion"), "Package newVersion")
    upstream_id = require_string(upstream.get("upstreamFindingId"), "Upstream finding identity")
    anchor_path = safe_relative_path(impact.get("anchorPath"))
    anchor_line = impact.get("anchorStartLine", 1)
    if not isinstance(anchor_line, int) or isinstance(anchor_line, bool) or anchor_line < 1:
        raise ValueError("Dependency finding anchorStartLine must be a positive integer.")

    stable_anchor = hashlib.sha256(upstream_id.encode("utf-8")).hexdigest()[:24]
    instance_material = "\0".join(
        (
            anchor_path,
            json.dumps(impact.get("affectedProjects", []), sort_keys=True),
            json.dumps([package.get("oldVersion"), new_version], separators=(",", ":")),
        )
    )
    stable_instance = hashlib.sha256(instance_material.encode("utf-8")).hexdigest()[:16]
    evidence = upstream.get("codeEvidence", [])
    if not isinstance(evidence, list):
        raise ValueError("Upstream finding codeEvidence must be an array.")

    title = require_string(upstream.get("title"), "Upstream finding title")
    if package_name not in title or new_version not in title:
        old_version = package.get("oldVersion")
        version_label = f"{old_version} → {new_version}" if old_version else new_version
        title = f"{title}: {package_name} {version_label}"

    dependency_extension = {
        "ecosystem": package["ecosystem"],
        "registry": package["registry"],
        "package": package_name,
        "oldVersion": package.get("oldVersion"),
        "newVersion": new_version,
        "upstreamFindingId": upstream_id,
        "lifecycle": upstream.get("lifecycle", "new"),
        "artifactDigests": upstream.get("artifactDigests", []),
        "affectedProjects": impact.get("affectedProjects", []),
        "dependencyChains": impact.get("dependencyChains", []),
        "usageContext": impact.get("usageContext", ""),
        "scannerSeverity": upstream.get("severity", {"level": "medium"}),
        "applicationImpact": application_impact(impact, upstream_id),
    }
    introduced = upstream.get("introducedIn")
    if introduced is not None:
        if not isinstance(introduced, dict):
            raise ValueError("Upstream finding introducedIn must be an object.")
        introduction: dict[str, Any] = {
            "version": require_string(
                introduced.get("version"), "Upstream finding introduction version"
            ),
            "artifactDigest": require_string(
                introduced.get("artifactDigest"), "Upstream finding introduction artifactDigest"
            ),
        }
        if "confidence" in introduced:
            confidence = introduced["confidence"]
            if not isinstance(confidence, (str, dict)):
                raise ValueError(
                    "Upstream finding introduction confidence must be text or an object."
                )
            introduction["confidence"] = confidence
        if "evidence" in introduced:
            evidence_items = introduced["evidence"]
            if not isinstance(evidence_items, list):
                raise ValueError("Upstream finding introduction evidence must be an array.")
            introduction["evidence"] = evidence_items
        dependency_extension["introducedIn"] = introduction

    finding: dict[str, Any] = {
        "ruleId": require_string(upstream.get("ruleId"), "Upstream finding ruleId"),
        "identity": {"anchor": f"dependency-{stable_anchor}", "instance": stable_instance},
        "title": title,
        "summary": require_string(upstream.get("summary"), "Upstream finding summary"),
        "severity": upstream.get("severity", {"level": "medium"}),
        "confidence": upstream.get(
            "confidence",
            {"level": "medium", "rationale": "Published dependency artifact analysis."},
        ),
        "taxonomy": upstream.get("taxonomy", {"category": "supply-chain", "cwe": []}),
        "locations": [{"path": anchor_path, "startLine": anchor_line, "role": "root_control"}],
        "remediation": require_string(
            upstream.get("remediation", "Upgrade to a verified unaffected dependency version."),
            "Upstream finding remediation",
        ),
        "provenance": {"source": "dependency_update_scan"},
        "extensions": {"dependency": dependency_extension},
    }
    if evidence:
        finding["codeEvidence"] = evidence
        finding["rootCause"] = {
            "summary": finding["summary"],
            "evidenceRefs": [
                item["id"]
                for item in evidence
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ],
        }
    return finding


def merge_dependency_findings(
    findings: dict[str, Any],
    results: dict[str, Any],
    impacts: dict[str, Any],
    coverage: dict[str, Any] | None = None,
) -> tuple[int, int]:
    existing = findings.get("findings")
    if not isinstance(existing, list):
        raise ValueError("Canonical findings document must contain a findings array.")
    packages = results.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("Cloud scan results must contain a packages array when present.")
    impact_entries = impacts.get("dependencies")
    if not isinstance(impact_entries, list):
        raise ValueError("Local dependency impacts must contain a dependencies array.")

    by_dependency: dict[tuple[str, str, str, str | None, str], list[dict[str, Any]]] = {}
    for impact in impact_entries:
        if not isinstance(impact, dict):
            raise ValueError("Local dependency impacts must be objects.")
        by_dependency.setdefault(dependency_identity(impact), []).append(impact)

    seen: set[tuple[str, str]] = set()
    for finding in existing:
        if isinstance(finding, dict) and isinstance(finding.get("identity"), dict):
            identity = finding["identity"]
            if isinstance(identity.get("anchor"), str):
                seen.add((identity["anchor"], str(identity.get("instance", ""))))

    merged = 0
    unmapped = 0
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("Cloud dependency packages must be objects.")
        upstream_findings = package.get("findings", [])
        if not isinstance(upstream_findings, list):
            raise ValueError("Cloud dependency findings must be an array.")
        if not upstream_findings:
            continue
        matches = by_dependency.get(dependency_identity(package), [])
        if not matches:
            if coverage is None:
                raise ValueError("Unmapped dependency findings require discovery and coverage.")
            deferred = require_entries(coverage, "deferred", "Canonical coverage")
            existing_ids = {entry.get("id") for entry in deferred}
            for upstream in upstream_findings:
                finding_id = require_string(
                    upstream.get("upstreamFindingId"), "Upstream finding identity"
                )
                identity = json.dumps(
                    [*dependency_identity(package), finding_id], separators=(",", ":")
                )
                deferred_id = (
                    "dependency-unmapped-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
                )
                if deferred_id not in existing_ids:
                    deferred.append(
                        {
                            "id": deferred_id,
                            "reason": f"Finding {finding_id} in {package['package']} {package['newVersion']} has no verified local dependency location; application impact remains unknown.",
                        }
                    )
                    existing_ids.add(deferred_id)
            coverage["completeness"] = "partial"
            unmapped += len(upstream_findings)
            continue
        for upstream in upstream_findings:
            if not isinstance(upstream, dict):
                raise ValueError("Cloud dependency findings must be objects.")
            for impact in matches:
                candidate = local_finding(package, upstream, impact)
                identity = candidate["identity"]
                key = (identity["anchor"], identity["instance"])
                if key in seen:
                    continue
                existing.append(candidate)
                seen.add(key)
                merged += 1
    return merged, unmapped


def require_entries(document: dict[str, Any], field: str, label: str) -> list[dict[str, Any]]:
    entries = document.get(field)
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise ValueError(f"{label} must contain an array of objects named {field}.")
    return entries


def package_node_id(ecosystem: str, registry: str, package: str, version: str | None) -> str:
    identity = f"{ecosystem}:{registry}:{package}"
    return f"{identity}@{version}" if version is not None else identity


def project_node_id(project: str) -> str:
    return f"project:{project}"


def project_for_chain(root: str, projects: list[str]) -> str:
    if root in projects:
        return root
    matches = [project for project in projects if project.endswith(f"/{root}")]
    return matches[0] if len(matches) == 1 else root


def dependency_inventory(
    discovery: dict[str, Any],
    impacts: dict[str, Any],
    results: dict[str, Any],
) -> dict[str, Any]:
    full_repository = discovery.get("mode") == "repository"
    discoveries = require_entries(discovery, "dependencies", "Local dependency discovery")
    impact_entries = require_entries(impacts, "dependencies", "Local dependency impacts")
    result_entries = require_entries(results, "packages", "Cloud dependency results")

    discovered_by_identity = {dependency_identity(entry): entry for entry in discoveries}
    results_by_identity = {dependency_identity(entry): entry for entry in result_entries}
    if set(results_by_identity) - set(discovered_by_identity):
        raise ValueError("Cloud dependency results contain an identity outside local discovery.")
    selected = None
    if "selectedDependencies" in discovery:
        selected = {
            dependency_identity(entry)
            for entry in require_entries(discovery, "selectedDependencies", "Dependency selection")
        }
        if not selected or not selected.issubset(discovered_by_identity):
            raise ValueError(
                "Selected dependencies must identify resolved packages in this discovery."
            )
        if not set(results_by_identity).issubset(selected):
            raise ValueError(
                "Cloud dependency results contain packages outside the requested selection."
            )
    impacts_by_identity: dict[tuple[str, str, str, str | None, str], list[dict[str, Any]]] = {}
    for impact in impact_entries:
        impacts_by_identity.setdefault(dependency_identity(impact), []).append(impact)

    identities = set(discovered_by_identity) | set(results_by_identity) | set(impacts_by_identity)
    nodes: dict[str, dict[str, Any]] = {}
    changed_nodes: dict[tuple[str, str, str, str | None, str], dict[str, Any]] = {}
    nodes_by_package: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    affected_by_node: dict[str, set[str]] = {}

    for identity in sorted(
        identities,
        key=lambda item: (item[0], item[1], item[2], item[3] or "", item[4]),
    ):
        ecosystem, registry, package, old_version, new_version = identity
        discovered = discovered_by_identity.get(identity, {})
        result = results_by_identity.get(identity)
        status = result.get("status", "not_scanned") if result is not None else "not_scanned"
        if status not in {"completed", "partial", "failed", "not_scanned"}:
            raise ValueError(f"Dependency {package} has an unsupported scan status: {status}.")

        node_id = f"{package_node_id(ecosystem, registry, package, old_version)}->{new_version}"
        node: dict[str, Any] = {
            "id": node_id,
            "kind": "dependency",
            "name": package,
            "package": package,
            "ecosystem": ecosystem,
            "registry": registry,
            "oldVersion": old_version,
            "newVersion": new_version,
            "status": status,
            "changed": not full_repository,
        }
        if selected is not None:
            node["selected"] = identity in selected
        dependency_types = discovered.get("dependencyTypes", [])
        if not isinstance(dependency_types, list) or any(
            not isinstance(value, str) or not value.strip() for value in dependency_types
        ):
            raise ValueError(f"Dependency {package} types must be nonempty strings.")
        if dependency_types:
            node["dependencyTypes"] = list(dict.fromkeys(dependency_types))

        if result is not None:
            findings = result.get("findings", [])
            artifacts = result.get("artifacts", [])
            if not isinstance(findings, list) or not isinstance(artifacts, list):
                raise ValueError(f"Dependency {package} findings and artifacts must be arrays.")
            node["findingCount"] = len(findings)
            if artifacts and all(
                isinstance(artifact, dict) and isinstance(artifact.get("cacheHit"), bool)
                for artifact in artifacts
            ):
                node["cacheHit"] = all(artifact["cacheHit"] for artifact in artifacts)

        projects: set[str] = set()
        for impact in impacts_by_identity.get(identity, []):
            affected = impact.get("affectedProjects", [])
            if not isinstance(affected, list) or any(
                not isinstance(project, str) or not project.strip() for project in affected
            ):
                raise ValueError(f"Dependency {package} affectedProjects must be nonempty strings.")
            projects.update(affected)
        affected_by_node[node_id] = projects
        nodes[node_id] = node
        changed_nodes[identity] = node
        nodes_by_package.setdefault((ecosystem, registry, package), []).append(node)

    edges: set[tuple[str, str]] = set()
    for identity in sorted(
        impacts_by_identity,
        key=lambda item: (item[0], item[1], item[2], item[3] or "", item[4]),
    ):
        ecosystem, registry, _, _, _ = identity
        destination = changed_nodes[identity]
        for impact in sorted(
            impacts_by_identity[identity],
            key=lambda entry: json.dumps(entry, ensure_ascii=False, sort_keys=True),
        ):
            projects = sorted(affected_by_node[destination["id"]])
            chains = impact.get("dependencyChains", [])
            if not isinstance(chains, list):
                raise ValueError("Local dependency chains must be an array.")
            valid_chains = [
                chain
                for chain in chains
                if isinstance(chain, list)
                and len(chain) > 1
                and all(isinstance(segment, str) and segment.strip() for segment in chain)
            ]
            if not valid_chains:
                valid_chains = [[project, destination["name"]] for project in projects]

            for chain in sorted(valid_chains, key=lambda item: tuple(item)):
                project = project_for_chain(chain[0], projects)
                root_id = project_node_id(project)
                nodes.setdefault(
                    root_id,
                    {
                        "id": root_id,
                        "kind": "project",
                        "name": project,
                        "status": "project",
                        "changed": False,
                    },
                )
                previous_id = root_id
                for index, package in enumerate(chain[1:], start=1):
                    if index == len(chain) - 1:
                        node = destination
                    else:
                        candidates = nodes_by_package.get((ecosystem, registry, package), [])
                        node = (
                            min(
                                candidates,
                                key=lambda candidate: (
                                    project not in affected_by_node.get(candidate["id"], set()),
                                    candidate["id"],
                                ),
                            )
                            if candidates
                            else None
                        )
                        if node is None:
                            bridge_id = package_node_id(ecosystem, registry, package, None)
                            node = nodes.setdefault(
                                bridge_id,
                                {
                                    "id": bridge_id,
                                    "kind": "dependency",
                                    "name": package,
                                    "package": package,
                                    "ecosystem": ecosystem,
                                    "registry": registry,
                                    "status": "unchanged",
                                    "changed": False,
                                },
                            )
                    affected_by_node.setdefault(node["id"], set()).update(projects or [project])
                    edges.add((previous_id, node["id"]))
                    previous_id = node["id"]

    for node_id, projects in affected_by_node.items():
        if projects:
            nodes[node_id]["affectedProjects"] = sorted(projects)

    return {
        "nodes": sorted(
            nodes.values(),
            key=lambda node: (
                node["kind"] != "project",
                node.get("ecosystem", ""),
                node["name"],
                node.get("newVersion", ""),
                node["id"],
            ),
        ),
        "edges": [{"from": parent, "to": child} for parent, child in sorted(edges)],
    }


def defer_missing_selected_results(
    coverage: dict[str, Any], discovery: dict[str, Any], results: dict[str, Any]
) -> None:
    """Keep requested packages without a result visible as incomplete work."""
    if "selectedDependencies" not in discovery:
        return
    received = {
        dependency_identity(entry)
        for entry in require_entries(results, "packages", "Cloud dependency results")
    }
    missing = [
        entry
        for entry in require_entries(discovery, "selectedDependencies", "Dependency selection")
        if dependency_identity(entry) not in received
    ]
    if not missing:
        return
    deferred = require_entries(coverage, "deferred", "Canonical coverage")
    existing_ids = {entry.get("id") for entry in deferred}
    for dependency in missing:
        identity = json.dumps(dependency_identity(dependency), separators=(",", ":"))
        review_id = "dependency-missing-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
        if review_id not in existing_ids:
            deferred.append(
                {
                    "id": review_id,
                    "reason": (
                        f"Selected dependency {dependency['package']} {dependency['newVersion']} "
                        "has no published-artifact result."
                    ),
                }
            )
            existing_ids.add(review_id)
    coverage["completeness"] = "partial"


def defer_unknown_prior_findings(
    coverage: dict[str, Any],
    results: dict[str, Any],
    impacts: dict[str, Any],
) -> None:
    unknown: dict[tuple[str, str, str, str | None, str, str], set[str]] = {}
    for package in require_entries(results, "packages", "Cloud dependency results"):
        assessments = package.get("priorFindingAssessments", [])
        if not isinstance(assessments, list) or any(
            not isinstance(assessment, dict) for assessment in assessments
        ):
            raise ValueError("Cloud prior finding assessments must be an array of objects.")
        for assessment in assessments:
            if assessment.get("status") != "unknown":
                continue
            finding_id = require_string(
                assessment.get("upstreamFindingId"), "Prior finding assessment identity"
            )
            reason = require_string(assessment.get("reason"), "Prior finding assessment reason")
            identity = (*dependency_identity(package), finding_id)
            unknown.setdefault(identity, set()).add(reason)

    if not unknown:
        return

    deferred = coverage.get("deferred")
    if not isinstance(deferred, list) or any(not isinstance(item, dict) for item in deferred):
        raise ValueError("Canonical coverage must contain an array of deferred review objects.")
    existing_ids = {require_string(item.get("id"), "Deferred review identity") for item in deferred}

    affected_dependencies = {identity[:5] for identity in unknown}
    paths_by_dependency: dict[tuple[str, str, str, str | None, str], set[str]] = {}
    for impact in require_entries(impacts, "dependencies", "Local dependency impacts"):
        dependency = dependency_identity(impact)
        if dependency not in affected_dependencies:
            continue
        anchor = impact.get("anchorPath")
        if anchor is not None:
            paths_by_dependency.setdefault(dependency, set()).add(safe_relative_path(anchor))

    for identity, reasons in sorted(
        unknown.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
            item[0][2],
            item[0][3] or "",
            item[0][4],
            item[0][5],
        ),
    ):
        ecosystem, registry, package, old_version, new_version, finding_id = identity
        stable_identity = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
        review_id = (
            "dependency-prior-" + hashlib.sha256(stable_identity.encode("utf-8")).hexdigest()[:24]
        )
        if review_id in existing_ids:
            continue

        version_label = f"{old_version} → {new_version}" if old_version else new_version
        review: dict[str, Any] = {
            "id": review_id,
            "reason": (
                f"Prior vulnerability {finding_id} in {package} {version_label}: "
                "status is unknown; could not determine whether it remains present or was fixed. "
                + " ".join(sorted(reasons))
            ),
        }
        paths = paths_by_dependency.get((ecosystem, registry, package, old_version, new_version))
        if paths:
            review["paths"] = sorted(paths)
        deferred.append(review)
        existing_ids.add(review_id)

    coverage["completeness"] = "partial"


def main() -> None:
    arguments = parse_args()
    findings_path = Path(arguments.findings)
    try:
        findings = read_object(findings_path, "Canonical findings")
        results = read_object(Path(arguments.results), "Cloud dependency results")
        impacts = read_object(Path(arguments.impacts), "Local dependency impacts")
        coverage = None
        if arguments.coverage is not None:
            discovery = read_object(Path(arguments.discovery), "Local dependency discovery")
            coverage = read_object(Path(arguments.coverage), "Canonical coverage")
            coverage["dependencies"] = dependency_inventory(discovery, impacts, results)
            defer_missing_selected_results(coverage, discovery, results)
            defer_unknown_prior_findings(coverage, results, impacts)
        merged, unmapped = merge_dependency_findings(findings, results, impacts, coverage)
        findings_path.write_text(
            json.dumps(findings, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if coverage is not None:
            Path(arguments.coverage).write_text(
                json.dumps(coverage, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Dependency finding merge failed: {exc}") from exc
    print(json.dumps({"merged": merged, "unmapped": unmapped}))


if __name__ == "__main__":
    main()
