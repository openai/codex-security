"""Compare an image package upgrade using two Syft JSON SBOMs and their Grype reports."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


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
    name, version_separator, _ = path.rpartition("@")
    if not version_separator or not name.startswith("pkg:"):
        raise ValueError("Expected a versioned package URL")
    return name


def image_snapshot(sbom, scan, advisory, package, package_type, identity_key=None):
    if sbom["source"]["type"] != "image" or scan["source"]["type"] != "image":
        raise ValueError("Expected image reports")
    identity = image_identity(sbom["source"]["metadata"])
    if identity != image_identity(scan["source"]["target"]):
        raise ValueError("SBOM and scanner report identify different images")
    if sbom["descriptor"]["configuration"]["search"]["scope"] != "squashed":
        raise ValueError("Use a squashed SBOM covering the final image filesystem")

    def selected(match):
        artifact = match["artifact"]
        ids = [
            match["vulnerability"]["id"],
            *(v["id"] for v in match.get("relatedVulnerabilities", [])),
        ]
        return advisory in ids and artifact["name"] == package and artifact["type"] == package_type

    matches = scan["matches"]
    active = [m for m in matches if selected(m)]
    if identity_key is None:
        keys = {package_identity(m["artifact"]) for m in active}
        if len(keys) != 1:
            raise ValueError("Select one baseline advisory and package identity")
        identity_key = keys.pop()
    active = [m for m in active if package_identity(m["artifact"]) == identity_key]
    ignored = [
        m
        for m in scan.get("ignoredMatches", [])
        if selected(m) and package_identity(m["artifact"]) == identity_key
    ]
    versions = sorted(
        {
            required_text(a["version"], "installed version")
            for a in sbom["artifacts"]
            if a["name"] == package
            and a["type"] == package_type
            and package_identity(a) == identity_key
        }
    )
    summary = {
        "manifest_digest": identity[0],
        "platform": identity[1],
        "package_identity": identity_key,
        "installed_versions": versions,
        "selected_matches": len(active),
        "selected_ignored_matches": len(ignored),
        "total_matches": len(matches),
        "distinct_advisories": len({m["vulnerability"]["id"] for m in matches}),
    }
    return summary, active


def compare(before_sbom, before_scan, after_sbom, after_scan, advisory, package, package_type):
    for before, after, tool in [
        (before_sbom, after_sbom, "syft"),
        (before_scan, after_scan, "grype"),
    ]:
        for key in ("name", "version", "configuration"):
            value = before["descriptor"][key]
            if value != after["descriptor"][key] or (key == "name" and value != tool):
                raise ValueError(f"Incomparable {tool} {key}")
    db = before_scan["descriptor"]["db"]
    status = db["status"]
    for key in ("built", "schemaVersion"):
        required_text(status[key], f"Grype DB {key}")
    other_db = after_scan["descriptor"]["db"]
    if (
        any(status[k] != other_db["status"][k] for k in ("built", "schemaVersion", "from"))
        or db["providers"] != other_db["providers"]
        or any(d["status"]["valid"] is not True for d in (db, other_db))
    ):
        raise ValueError("Incomparable Grype databases")

    before, active = image_snapshot(before_sbom, before_scan, advisory, package, package_type)
    after, _ = image_snapshot(
        after_sbom, after_scan, advisory, package, package_type, before["package_identity"]
    )
    if before["platform"] != after["platform"]:
        raise ValueError("Image platforms differ")
    if not active or any(
        m["artifact"]["version"] not in before["installed_versions"] for m in active
    ):
        raise ValueError("Selected match must be present in the baseline report and inventory")
    fixes = None
    for match in active:
        fix = match["vulnerability"].get("fix") or {}
        versions = fix.get("versions") if fix.get("state") == "fixed" else []
        if not isinstance(versions, list):
            raise ValueError("Expected a list of reported fixed versions")
        reported = {required_text(v, "fixed version") for v in versions}
        fixes = reported if fixes is None else fixes & reported
    if after["selected_matches"]:
        outcome = "still_reported"
    elif (
        after["installed_versions"]
        and set(after["installed_versions"]) <= fixes
        and before["installed_versions"] != after["installed_versions"]
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
        "database_built": status["built"],
        "before": before,
        "after": after,
        "deployment": "unverified",
    }


def scan_sbom(path):
    contents = path.read_bytes()
    sbom = json.loads(contents)
    scan = subprocess.run(
        ["grype", "--file", "", "-o", "json"], input=contents, stdout=subprocess.PIPE, check=True
    )
    return sbom, json.loads(scan.stdout), hashlib.sha256(contents).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("before-sbom", "after-sbom"):
        parser.add_argument(f"--{key}", required=True, type=Path)
    for key in ("advisory", "package", "package-type"):
        parser.add_argument(f"--{key}", required=True)
    args = parser.parse_args()
    try:
        before_sbom, before_scan, before_hash = scan_sbom(args.before_sbom)
        after_sbom, after_scan, after_hash = scan_sbom(args.after_sbom)
        result = compare(
            before_sbom,
            before_scan,
            after_sbom,
            after_scan,
            args.advisory,
            args.package,
            args.package_type,
        )
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
