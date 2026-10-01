"""Normalize supported Endor, Snyk Open Source, and Socket reports.

Vendor evidence and remediation suggestions remain unverified input. These
adapters do not infer reachability or treat scanner severity as a verdict.
"""

from __future__ import annotations

import csv
import io
import json
from copy import deepcopy

MAX_SOURCE_FINDINGS = 10000
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_BYTES = 16 * 1024
MAX_NORMALIZED_BYTES = 16 * 1024 * 1024

_ECOSYSTEMS = {
    "pip": "pypi",
    "pipenv": "pypi",
    "poetry": "pypi",
    "gradle": "maven",
    "yarn": "npm",
    "pnpm": "npm",
    "golang": "go",
    "mvn": "maven",
}

_ENDOR_CSV_HEADERS = {
    "UUID",
    "Title",
    "Severity Level",
    "Finding Categories",
}


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a JSON object")
    return dict(value)


def _objects(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a JSON array")
    return [_object(item, label) for item in value]


def _optional_object(value: object) -> dict[str, object]:
    return _object(value, "metadata") if isinstance(value, dict) else {}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _selected(record: dict[str, object], *keys: str) -> dict[str, object]:
    return {key: deepcopy(record[key]) for key in keys if key in record}


def _check_record_count(lists: list[object]) -> None:
    count = 0
    for records in lists:
        if not isinstance(records, list):
            raise ValueError("Source findings must be JSON arrays")
        count += len(records)
    if count > MAX_SOURCE_FINDINGS:
        raise ValueError(f"Import at most {MAX_SOURCE_FINDINGS} source findings per report")


def _context(record: dict[str, object], *keys: str) -> dict[str, object]:
    context = {key: record[key] for key in keys if key in record}
    if len(json.dumps(context).encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ValueError("Shared package or project context exceeds the 16 KiB limit")
    return deepcopy(context)


def _package(ecosystem: object, name: object, version: object) -> dict[str, str]:
    result = {}
    eco = _text(ecosystem)
    if eco and eco != "ECOSYSTEM_UNSPECIFIED":
        eco = eco.removeprefix("ECOSYSTEM_").lower()
        result["ecosystem"] = _ECOSYSTEMS.get(eco, eco)
    for key, value in (("name", name), ("version", version)):
        text = _text(value)
        if text:
            result[key] = text
    return result


def _locations(paths: list[str]) -> list[dict[str, str]]:
    return [{"path": path} for path in dict.fromkeys(paths)]


def _finding(
    record: dict[str, object],
    *,
    source_id: object,
    title: object,
    kind: str,
    package: dict[str, str],
    advisory_ids: list[str],
    severity: object,
    paths: list[list[str]],
    locations: list[dict[str, str]],
    fix: dict[str, object],
    evidence: dict[str, object],
) -> dict[str, object]:
    return {
        "sourceId": _text(source_id),
        "title": _text(title) or _text(source_id) or "Imported dependency finding",
        "kind": kind,
        "package": package,
        "advisoryIds": list(dict.fromkeys(advisory_ids)),
        "originalSeverity": _text(severity),
        "dependencyPaths": paths,
        "locations": locations,
        "fix": fix,
        "evidence": evidence,
        "original": deepcopy(record),
    }


def _snyk(payload: object) -> tuple[list[dict[str, object]], int, int]:
    reports = _objects(payload if isinstance(payload, list) else [payload], "Snyk report")
    _check_record_count([report.get("vulnerabilities") for report in reports])
    findings = []
    licenses = 0
    others = 0
    for report in reports:
        if "vulnerabilities" not in report or not _text(report.get("packageManager")):
            raise ValueError(
                "Expected Snyk Open Source CLI JSON with packageManager and vulnerabilities"
            )
        context = _context(
            report, "projectName", "path", "targetFile", "displayTargetFile", "packageManager"
        )
        for record in _objects(report["vulnerabilities"], "Snyk vulnerabilities"):
            if record.get("type") == "license":
                licenses += 1
                continue
            if record.get("type") not in (None, "vuln"):
                others += 1
                continue
            identifiers = _optional_object(record.get("identifiers"))
            advisory_ids = _strings([record.get("id")])
            for key in ("CVE", "GHSA", "OSV", "ALTERNATIVE"):
                advisory_ids.extend(_strings(identifiers.get(key)))
            source_paths = record.get("from")
            if isinstance(source_paths, list) and all(
                isinstance(chain, list) for chain in source_paths
            ):
                paths = [_strings(chain) for chain in source_paths]
            else:
                paths = [_strings(source_paths)]
            locations = _strings(
                [
                    report.get("displayTargetFile") or report.get("targetFile"),
                    record.get("__filename"),
                ]
            )
            evidence = _selected(record, "reachability", "functions", "functions_new", "references")
            evidence["project"] = deepcopy(context)
            findings.append(
                _finding(
                    record,
                    source_id=record.get("id"),
                    title=record.get("title"),
                    kind="malware" if record.get("malicious") is True else "vulnerability",
                    package=_package(
                        record.get("packageManager") or report.get("packageManager"),
                        record.get("packageName") or record.get("name"),
                        record.get("version"),
                    ),
                    advisory_ids=advisory_ids,
                    severity=record.get("severity"),
                    paths=[chain for chain in paths if chain],
                    locations=_locations(locations),
                    fix=_selected(
                        record,
                        "fixedIn",
                        "upgradePath",
                        "isUpgradable",
                        "isPatchable",
                        "isPinnable",
                        "patches",
                    ),
                    evidence=evidence,
                )
            )
    return findings, licenses, others


def _endor(payload: object) -> tuple[list[dict[str, object]], int, int]:
    if isinstance(payload, str):
        return _endor_csv(payload)
    report = _object(payload, "Endor report")
    if "list" in report:
        records = _objects(_object(report["list"], "Endor list").get("objects"), "Endor findings")
    elif "meta" in report and "spec" in report:
        records = [report]
    else:
        raise ValueError("Expected Endor Finding or ListFindingsResponse JSON")
    _check_record_count([records])
    findings = []
    licenses = 0
    others = 0
    for record in records:
        meta = _object(record.get("meta"), "Endor finding meta")
        spec = _object(record.get("spec"), "Endor finding spec")
        metadata = _optional_object(spec.get("finding_metadata"))
        categories = _strings(spec.get("finding_categories"))
        tags = _strings(spec.get("finding_tags"))
        malware = _optional_object(metadata.get("malware"))
        vulnerability = _optional_object(metadata.get("vulnerability"))
        malware_kind = (
            bool(malware)
            or "FINDING_TAGS_MALWARE" in tags
            or "FINDING_CATEGORY_MALWARE" in categories
        )
        if (
            not malware_kind
            and not vulnerability
            and "FINDING_CATEGORY_VULNERABILITY" not in categories
        ):
            if "FINDING_CATEGORY_LICENSE_RISK" in categories:
                licenses += 1
            else:
                others += 1
            continue
        advisory_ids = []
        for advisory in (vulnerability, malware):
            advisory_ids.extend(_strings([_optional_object(advisory.get("meta")).get("name")]))
            advisory_ids.extend(_strings(_optional_object(advisory.get("spec")).get("aliases")))
        evidence = _selected(
            spec,
            "finding_tags",
            "reachable_paths",
            "call_graph_analysis_type",
            "relationship",
            "finding_metadata",
            "location_urls",
        )
        findings.append(
            _finding(
                record,
                source_id=record.get("uuid"),
                title=meta.get("description") or spec.get("summary") or meta.get("name"),
                kind="malware" if malware_kind else "vulnerability",
                package=_package(
                    spec.get("ecosystem"),
                    spec.get("target_dependency_name"),
                    spec.get("target_dependency_version"),
                ),
                advisory_ids=advisory_ids,
                severity=spec.get("level"),
                paths=[],
                locations=_locations(_strings(spec.get("dependency_file_paths"))),
                fix=_selected(
                    spec,
                    "proposed_version",
                    "remediation",
                    "remediation_action",
                    "fixing_upgrades",
                    "fixing_patch",
                ),
                evidence=evidence,
            )
        )
    return findings, licenses, others


def _csv_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _endor_csv_package(value: str) -> dict[str, str]:
    ecosystem, separator, identifier = value.partition("://")
    if not separator:
        return {}
    name, separator, version = identifier.rpartition("@")
    if not separator or not name:
        name, version = identifier, ""
    return _package(ecosystem, name, version)


def _endor_csv(payload: str) -> tuple[list[dict[str, object]], int, int]:
    reader = csv.reader(io.StringIO(payload.removeprefix("\ufeff"), newline=""), strict=True)
    findings: list[dict[str, object]] = []
    licenses = 0
    others = 0
    previous_field_limit = csv.field_size_limit(MAX_REPORT_BYTES)
    try:
        headers = next(reader, [])
        if (
            not _ENDOR_CSV_HEADERS.issubset(headers)
            or any(not header.strip() for header in headers)
            or len(set(headers)) != len(headers)
        ):
            raise ValueError("Expected Endor CSV export headers without blank or duplicate columns")
        for position, values in enumerate(reader, start=1):
            if position > MAX_SOURCE_FINDINGS:
                raise ValueError(f"Import at most {MAX_SOURCE_FINDINGS} source findings per report")
            if len(values) != len(headers):
                raise ValueError(f"Endor CSV row {position} does not match the header columns")
            row = dict(zip(headers, values, strict=True))
            record: dict[str, object] = dict(row)
            categories = _csv_values(row["Finding Categories"])
            attributes = _csv_values(row.get("Attributes", ""))
            malware = (
                "FINDING_CATEGORY_MALWARE" in categories or "FINDING_TAGS_MALWARE" in attributes
            )
            if not malware and "FINDING_CATEGORY_VULNERABILITY" not in categories:
                if "FINDING_CATEGORY_LICENSE_RISK" in categories:
                    licenses += 1
                else:
                    others += 1
                continue
            advisory_ids = [
                value
                for column in ("CVE", "Vulnerability ID", "Aliases")
                for value in _csv_values(row.get(column, ""))
            ]
            location = row.get("Location", "")
            # The export does not escape commas within this already quoted cell.
            # Preserve ambiguous locations as evidence instead of inventing paths.
            locations = _locations([location]) if location and "," not in location else []
            finding = _finding(
                record,
                source_id=row["UUID"],
                title=row["Title"],
                kind="malware" if malware else "vulnerability",
                package=_endor_csv_package(row.get("Dependency Name", "")),
                advisory_ids=advisory_ids,
                severity=row["Severity Level"],
                paths=[],
                locations=locations,
                fix={
                    key: row[column]
                    for key, column in (
                        ("proposed_version", "Fix Version"),
                        ("remediation", "Remediation"),
                    )
                    if row.get(column)
                },
                evidence={
                    "finding_tags": attributes,
                    "finding_categories": categories,
                    **_selected(
                        record,
                        "Risk Details",
                        "Explanation",
                        "Package Name",
                        "Project UUID",
                        "Project Name",
                        "Location",
                    ),
                },
            )
            if row.get("Commit SHA"):
                finding["sourceRevision"] = row["Commit SHA"]
            findings.append(finding)
    except csv.Error as error:
        raise ValueError(f"Malformed Endor CSV: {error}") from error
    finally:
        csv.field_size_limit(previous_field_limit)
    return findings, licenses, others


def _socket(payload: object) -> tuple[list[dict[str, object]], int, int]:
    if isinstance(payload, dict):
        report = _object(payload, "Socket report")
        if report.get("ok") is not True:
            raise ValueError("Expected Socket JSON with ok=true and a data array")
        payload = report.get("data")
    artifacts = _objects(payload, "Socket artifacts")
    _check_record_count(
        [artifact.get("alerts") for artifact in artifacts if artifact.get("_type") != "scores"]
    )
    findings = []
    licenses = 0
    others = 0
    for artifact in artifacts:
        if artifact.get("_type") == "scores":
            continue
        if not _text(artifact.get("type")):
            raise ValueError("Expected Socket package artifacts with type and alerts")
        context = _context(
            artifact,
            "id",
            "type",
            "namespace",
            "name",
            "version",
            "direct",
            "dev",
            "manifestFiles",
            "dependencies",
            "topLevelAncestors",
        )
        name = _text(artifact.get("name"))
        namespace = _text(artifact.get("namespace"))
        if namespace and name:
            name = (
                f"{namespace}:{name}" if artifact.get("type") == "maven" else f"{namespace}/{name}"
            )
        package = _package(artifact.get("type"), name, artifact.get("version"))
        for record in _objects(artifact.get("alerts"), "Socket alerts"):
            alert_type = _text(record.get("type"))
            if not alert_type:
                raise ValueError("Socket alerts must contain a type")
            if alert_type not in ("cve", "criticalCVE", "malware", "gptMalware"):
                if record.get("category") == "license":
                    licenses += 1
                else:
                    others += 1
                continue
            props = _optional_object(record.get("props"))
            paths = _strings([record.get("file")])
            manifests = artifact.get("manifestFiles")
            if manifests is not None:
                paths.extend(
                    _strings(
                        [item.get("file") for item in _objects(manifests, "Socket manifestFiles")]
                    )
                )
            evidence = _selected(record, "props", "reachability", "file", "start", "end")
            evidence["package"] = deepcopy(context)
            reachability = _optional_object(artifact.get("alertKeysToReachabilitySummaries"))
            key = _text(record.get("key"))
            if key and key in reachability:
                evidence["reachabilitySummary"] = _context(reachability, key)[key]
            fix = _selected(props, "firstPatchedVersionIdentifier", "vulnerableVersionRange")
            fix.update(_selected(record, "fix", "patch"))
            findings.append(
                _finding(
                    record,
                    source_id=record.get("key"),
                    title=props.get("title") or f"{alert_type}: {name or 'unknown package'}",
                    kind="malware" if alert_type in ("malware", "gptMalware") else "vulnerability",
                    package=dict(package),
                    advisory_ids=_strings([props.get("cveId"), props.get("ghsaId")]),
                    severity=record.get("severity"),
                    paths=[],
                    locations=_locations(paths),
                    fix=fix,
                    evidence=evidence,
                )
            )
    return findings, licenses, others


def parse_report(payload: object, vendor: str) -> dict[str, object]:
    """Parse vendor JSON or Endor CSV, preserving individual source records.

    Return findings, warnings, and excludedCount. Raise ValueError for unsupported
    vendors or report structures. Locations retain the vendor's path scope;
    package file paths are not necessarily paths in the consuming repository.
    """
    parsers = {"endor": _endor, "snyk": _snyk, "socket": _socket}
    if vendor not in parsers:
        raise ValueError("Supported vendors are endor, snyk, and socket")
    findings, licenses, others = parsers[vendor](payload)
    if len(json.dumps(findings).encode("utf-8")) > MAX_NORMALIZED_BYTES:
        raise ValueError("Normalized findings exceed the 16 MiB size limit")
    warnings = []
    if licenses:
        warnings.append(f"Excluded {licenses} license-only finding(s).")
    if others:
        warnings.append(f"Excluded {others} finding(s) outside vulnerability and malware scope.")
    incomplete = sum(len(_optional_object(item.get("package"))) < 3 for item in findings)
    if incomplete:
        warnings.append(
            f"{incomplete} finding(s) lack a complete package ecosystem, name, or version."
        )
    ambiguous_locations = sum(
        "," in (_text(_optional_object(item.get("original")).get("Location")) or "")
        for item in findings
    )
    if vendor == "endor" and isinstance(payload, str) and ambiguous_locations:
        warnings.append(
            f"{ambiguous_locations} finding(s) have comma-containing locations retained "
            "as vendor evidence; individual repository paths are unresolved."
        )
    if vendor == "endor" and isinstance(payload, str):
        missing_locations = sum(
            not _text(_optional_object(item.get("original")).get("Location")) for item in findings
        )
        if missing_locations:
            warnings.append(
                f"{missing_locations} finding(s) lack a repository location; "
                "application evidence must be supplied during assessment."
            )
    return {"findings": findings, "warnings": warnings, "excludedCount": licenses + others}
