#!/usr/bin/env python3
"""Copy a verified single-platform apko archive into a new OCI image layout.

Verify the build's signed SHA256SUMS before using its image.tar and verification.json.
The layout names its single image 'wolfi'. The OCI manifest, config and compressed
layer bytes remain identical. No registry access is needed.
"""
import argparse
import hashlib
import json
import re
import tarfile
import tempfile
from pathlib import Path


def convert(archive, verification, destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Destination already exists: {destination}")
    expected = json.loads(verification.read_bytes())
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp, tarfile.open(archive, "r:") as tar:
        layout = Path(tmp) / "layout"
        blobs = layout / "blobs" / "sha256"
        blobs.mkdir(parents=True)
        members = tar.getmembers()
        entries = {m.name: m for m in members}
        if len(entries) != len(members):
            raise ValueError("Archive contains duplicate member names")

        def member(name):
            m = entries[name]
            if not m.isfile():
                raise ValueError(f"Expected a regular archive member: {name}")
            return m

        def copy_blob(name, desc):
            digest = desc["digest"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError(f"Invalid blob digest: {digest}")
            m = member(name)
            if type(desc["size"]) is not int or m.size != desc["size"]:
                raise ValueError(f"Size mismatch: {name}")
            path = blobs / digest.split(":")[1]
            h = hashlib.sha256()
            total = 0
            with tar.extractfile(m) as source, path.open("wb") as dest:
                for chunk in iter(lambda: source.read(1 << 20), b""):
                    dest.write(chunk)
                    total += len(chunk)
                    h.update(chunk)
            if total != desc["size"] or "sha256:" + h.hexdigest() != digest:
                raise ValueError(f"Blob does not match its descriptor: {name}")
            return path

        with tar.extractfile(member("index.json")) as f:
            index = json.load(f)
        descriptor, = index["manifests"]
        if (index["schemaVersion"] != 2 or index["mediaType"] != "application/vnd.oci.image.index.v1+json"
                or descriptor["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
                or descriptor["digest"] != expected["oci_manifest"]):
            raise ValueError("OCI manifest does not match verification.json")
        platform = descriptor["platform"]
        if f"{platform['os']}/{platform['architecture']}" != expected["platform"]:
            raise ValueError("OCI platform does not match verification.json")
        manifest = json.loads(copy_blob(descriptor["digest"], descriptor).read_bytes())
        if (manifest["schemaVersion"] != 2 or manifest["mediaType"] != descriptor["mediaType"]
                or manifest["config"]["digest"] != expected["config_digest"]):
            raise ValueError("Unexpected OCI manifest or configuration digest")
        with tar.extractfile(member("manifest.json")) as f:
            docker, = json.load(f)
        config = json.loads(copy_blob(docker["Config"], manifest["config"]).read_bytes())
        if any(config[k] != platform[k] for k in ("os", "architecture")):
            raise ValueError("OCI config and platform descriptor disagree")
        if len(docker["Layers"]) != len(manifest["layers"]):
            raise ValueError("Docker and OCI layer counts disagree")
        for name, desc in zip(docker["Layers"], manifest["layers"]):
            copy_blob(name, desc)
        (layout / "oci-layout").write_bytes(b'{"imageLayoutVersion":"1.0.0"}\n')
        descriptor.setdefault("annotations", {})["org.opencontainers.image.ref.name"] = "wolfi"
        (layout / "index.json").write_text(json.dumps(index, separators=(",", ":")) + "\n")
        layout.rename(destination)
    return descriptor["digest"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Verified apko image.tar")
    parser.add_argument("verification", type=Path, help="Build's verification.json")
    parser.add_argument("destination", type=Path, help="New layout directory (parent must exist)")
    args = parser.parse_args()
    try:
        print(convert(args.archive, args.verification, args.destination))
    except (KeyError, OSError, ValueError, tarfile.TarError) as exc:
        parser.exit(1, f"Failed to convert archive: {exc}\n")
