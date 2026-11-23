"""Compare an image package upgrade using two Syft JSON SBOMs and their Grype reports."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


def required_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing {field}")
    return value


def image_identity(source):
    digest = source["manifestDigest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Expected a full image manifest digest")
    platform = [required_text(source[k], k) for k in ("os", "architecture")]
    if source.get("architectureVariant"):
        platform.append(source["architectureVariant"])
    return digest, "/".join(platform)


def package_identity(artifact):
    purl = required_text(artifact["purl"], "package URL")
    path = purl.partition("?")[0]
    name, _, version = path.rpartition("@")
    if not version or not name.startswith("pkg:"):
        raise ValueError("Expected a versioned package URL")
    return name


def package_distros(artifacts):
    distros = set()
    for artifact in artifacts:
        query = parse_qsl(urlsplit(artifact["purl"]).query, keep_blank_values=True)
        values = {value for key, value in query if key.lower() == "distro"}
        distros.update(values or {None})
    return distros


def image_snapshot(sbom, scan, advisory, package, package_type, identity_key=None):
    if sbom["source"]["type"] != "image" or scan["source"]["type"] != "image":
        raise ValueError("Expected image reports")
    identity = image_identity(sbom["source"]["metadata"])
    if identity != image_identity(scan["source"]["target"]):
        raise ValueError("SBOM and scanner report identify different images")
    if sbom["descriptor"]["configuration"]["search"]["scope"] != "squashed":
        raise ValueError("Use a squashed SBOM covering the final image filesystem")

    def selected_package(artifact):
        return (
            artifact["name"] == package
            and artifact["type"] == package_type
            and (identity_key is None or package_identity(artifact) == identity_key)
        )

    def selected(match):
        return (
            match["vulnerability"]["id"] == advisory
            or any(v["id"] == advisory for v in match.get("relatedVulnerabilities", []))
        ) and selected_package(match["artifact"])

    matches = scan["matches"]
    active = [m for m in matches if selected(m)]
    if identity_key is None:
        keys = {package_identity(m["artifact"]) for m in active}
        if len(keys) != 1:
            raise ValueError("Select one baseline advisory and package identity")
        identity_key = keys.pop()
    installed = [a for a in sbom["artifacts"] if selected_package(a)]
    versions = sorted({required_text(a["version"], "installed version") for a in installed})
    distros = package_distros(installed) | package_distros(m["artifact"] for m in active)
    summary = {
        "manifest_digest": identity[0],
        "platform": identity[1],
        "package_identity": identity_key,
        "installed_versions": versions,
        "selected_matches": len(active),
        "selected_ignored_matches": sum(selected(m) for m in scan.get("ignoredMatches", [])),
        "total_matches": len(matches),
        "distinct_advisories": len({m["vulnerability"]["id"] for m in matches}),
    }
    return summary, active, distros


def database_identity(scan):
    db = scan["descriptor"]["db"]
    status = db["status"]
    if status["valid"] is not True:
        raise ValueError("Invalid Grype database")
    return {
        "built": required_text(status["built"], "Grype DB built"),
        "schemaVersion": required_text(status["schemaVersion"], "Grype DB schemaVersion"),
        "from": status.get("from"),
        "providers": db["providers"],
    }


def reported_fixes(match):
    fix = match["vulnerability"].get("fix") or {}
    versions = fix.get("versions") if fix.get("state") == "fixed" else []
    if not isinstance(versions, list):
        raise ValueError("Expected a list of reported fixed versions")
    return {required_text(v, "fixed version") for v in versions}


def comparable_versions(versions, package_type):
    if package_type == "rpm":
        return {version.removeprefix("0:") for version in versions}
    return set(versions)


def compare(before_sbom, before_scan, after_sbom, after_scan, advisory, package, package_type):
    for before, after, tool in [
        (before_sbom, after_sbom, "syft"),
        (before_scan, after_scan, "grype"),
    ]:
        for key in ("name", "version", "configuration"):
            value = before["descriptor"][key]
            if value != after["descriptor"][key] or (key == "name" and value != tool):
                raise ValueError(f"Incomparable {tool} {key}")
    database = database_identity(before_scan)
    if database != database_identity(after_scan):
        raise ValueError("Incomparable Grype databases")

    before, active, before_distros = image_snapshot(
        before_sbom, before_scan, advisory, package, package_type
    )
    after, _, after_distros = image_snapshot(
        after_sbom, after_scan, advisory, package, package_type, before["package_identity"]
    )
    if before["platform"] != after["platform"]:
        raise ValueError("Image platforms differ")
    if any(m["artifact"]["version"] not in before["installed_versions"] for m in active):
        raise ValueError("Selected match must be present in the baseline report and inventory")
    fixes = set.intersection(*(reported_fixes(match) for match in active))
    installed = comparable_versions(after["installed_versions"], package_type)
    if after["selected_matches"]:
        outcome = "still_reported"
    elif (
        installed
        and len(before_distros | after_distros) <= 1
        and installed <= comparable_versions(fixes, package_type)
        and comparable_versions(before["installed_versions"], package_type) != installed
        and before["manifest_digest"] != after["manifest_digest"]
        and not after["selected_ignored_matches"]
    ):
        outcome = "reported_fix_present"
    else:
        outcome = "inconclusive"
    return {
        "advisory": advisory,
        "package": package,
        "package_type": package_type,
        "scanner_evidence": outcome,
        "reported_fixed_versions": sorted(fixes),
        "database_built": database["built"],
        "before": before,
        "after": after,
        "deployment": "unverified",
    }


def scan_sbom(path):
    contents = path.read_bytes()
    sbom = json.loads(contents)
    scan = subprocess.run(
        ["grype", "--file", "", "-o", "json"], input=contents, stdout=subprocess.PIPE, check=False
    )
    # Grype exits with 2 when completed findings exceed the configured severity threshold.
    if scan.returncode not in (0, 2):
        scan.check_returncode()
    return (sbom, json.loads(scan.stdout)), hashlib.sha256(contents).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("before-sbom", "after-sbom"):
        parser.add_argument(f"--{key}", required=True, type=Path)
    for key in ("advisory", "package", "package-type"):
        parser.add_argument(f"--{key}", required=True)
    args = parser.parse_args()
    try:
        before, before_hash = scan_sbom(args.before_sbom)
        after, after_hash = scan_sbom(args.after_sbom)
        result = compare(*before, *after, args.advisory, args.package, args.package_type)
        result["before"]["sbom_sha256"] = before_hash
        result["after"]["sbom_sha256"] = after_hash
        print(json.dumps(result, indent=2))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.CalledProcessError,
    ) as error:
        parser.exit(2, f"Could not compare image evidence: {error}\n")


if __name__ == "__main__":
    main()
