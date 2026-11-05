#!/usr/bin/env python3
"""Add the verified scanner payload to apko's single-platform SPDX document."""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
from urllib.parse import quote


def enrich(sbom, components):
    """Add installed npm packages, bundled tokenizer libraries, and native files to an SPDX document.

    Args:
        sbom (dict): apko's single-image SPDX document, updated in place.
        components (dict): public-components.json inventory produced for the same image.

    Returns:
        dict: The input document with containment relationships and a new document namespace.

    Raises:
        ValueError: The image manifest in the inventory differs from the one in the SBOM.
    """
    packages = sbom["packages"]
    image, = (p for p in packages if p["SPDXID"] in sbom["documentDescribes"])
    if image["name"] != components["image_manifest"]:
        raise ValueError("apko SBOM and payload inventory describe different images")
    apk, = (p for p in packages if p["name"] == "codex-security")
    install = PurePosixPath("/usr/lib/codex-security")

    def add(parent_id, package):
        packages.append(package)
        sbom["relationships"].append({"spdxElementId": parent_id, "relationshipType": "CONTAINS",
                                      "relatedSpdxElement": package["SPDXID"]})

    # Use the manifest name for npm aliases, but keep each installed path distinct.
    npm_ids = {}
    for i, item in enumerate(components["installed_npm"]):
        path = PurePosixPath(item["path"])
        npm_ids[path] = f"SPDXRef-npm-{i}"
        name, version = item["name"], item["version"]
        purl = f"pkg:npm/{quote(name)}@{quote(version, safe='')}"
        checksum = base64.b64decode(item["integrity"].removeprefix("sha512-"), validate=True).hex()
        add(apk["SPDXID"], {
            "SPDXID": npm_ids[path], "name": name, "versionInfo": version,
            "downloadLocation": item["source"], "licenseDeclared": item["license"],
            "filesAnalyzed": False, "sourceInfo": f"Installed at {install / path}; SHA512 identifies the source archive.",
            "checksums": [{"algorithm": "SHA512", "checksumValue": checksum}],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": purl}],
        })

    for i, item in enumerate(components.get("bundled_tokenizer", [])):
        add(npm_ids[PurePosixPath("node_modules/@openai/codex-security")], {
            "SPDXID": f"SPDXRef-tokenizer-{i}", "name": item["name"], "versionInfo": item["version"],
            "downloadLocation": "NOASSERTION", "licenseDeclared": item["licenses"][0]["license"]["id"],
            "filesAnalyzed": False, "sourceInfo": "Bundled in the SDK embedding tokenizer.",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": item["purl"]}],
        })

    for i, item in enumerate(components["bundled_native"]):
        path = PurePosixPath(item["path"])
        owner = next(npm_ids[p] for p in path.parents if p in npm_ids)
        add(owner, {
            "SPDXID": f"SPDXRef-native-{i}", "name": path.name, "primaryPackagePurpose": "FILE",
            "packageFileName": str(install / path), "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False, "sourceInfo": item["source"],
            "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}],
        })

    # A changed SPDX document needs its own namespace, distinct from apko's original.
    sbom["creationInfo"]["creators"].append("Tool: codex-security/release-sbom.py")
    digest = hashlib.sha256(json.dumps(sbom, sort_keys=True).encode()).hexdigest()
    sbom["documentNamespace"] = f"https://github.com/openai/codex-security/spdx/wolfi-{digest}"
    return sbom


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path)
    parser.add_argument("components", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    result = enrich(json.loads(args.sbom.read_bytes()), json.loads(args.components.read_bytes()))
    args.destination.write_text(json.dumps(result, indent=2) + "\n")
