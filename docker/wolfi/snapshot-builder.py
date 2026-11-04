#!/usr/bin/env python3
"""Stage the APKs from a verified apko builder lock for an offline Melange build."""
import argparse
import base64
import hashlib
import json
import re
import tempfile
from pathlib import Path
from urllib.request import HTTPRedirectHandler, build_opener

ARCH = "x86_64"
REPO = "https://packages.wolfi.dev/os/" + ARCH


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None  # Only fetch the exact URLs in the lock.


def stage_package(pkg, directory, fetch):
    name, version = pkg["name"], pkg["version"]
    filename = f"{name}-{version}.apk"
    if not all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+_~-]*", s) for s in (name, version)):
        raise ValueError(f"Invalid package name or version: {filename}")
    if pkg["architecture"] != ARCH or pkg["url"] != f"{REPO}/{filename}":
        raise ValueError(f"Unexpected package source or architecture: {filename}")

    with (directory / filename).open("xb") as dest, fetch(pkg["url"], timeout=60) as source:
        offset = 0
        for part, algorithm in (("signature", "sha1"), ("control", "sha1"), ("data", "sha256")):
            record = pkg[part]
            if part == "signature" and record == {"range": "", "checksum": ""}:
                continue
            match = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", record["range"])
            if not match or int(match[1]) != offset or int(match[2]) < offset:
                raise ValueError(f"{filename}: invalid {part} range {record['range']!r}")
            length = int(match[2]) + 1 - offset
            block = source.read(length)
            digest = base64.b64encode(hashlib.new(algorithm, block).digest()).decode("ascii")
            if len(block) != length or f"{algorithm}-{digest}" != record["checksum"]:
                raise ValueError(f"{filename}: {part} differs from builder lock")
            dest.write(block)
            offset += length
        if source.read(1):
            raise ValueError(f"{filename}: bytes beyond locked ranges")


def snapshot(lock, output, fetch):
    if lock["version"] != "v1" or not lock["contents"]["packages"]:
        raise ValueError("Expected a nonempty apko v1 builder lock")
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or any(output.iterdir()):
        raise ValueError("Builder repository must be a new or empty directory")
    with tempfile.TemporaryDirectory(dir=output) as staging:
        packages = Path(staging) / ARCH
        packages.mkdir()
        for pkg in lock["contents"]["packages"]:
            stage_package(pkg, packages, fetch)
        packages.rename(output / ARCH)  # Publish only after the entire lock verifies.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("repository", type=Path)
    args = parser.parse_args()
    try:
        snapshot(json.loads(args.lock.read_bytes()), args.repository, build_opener(NoRedirect()).open)
    except (KeyError, ValueError, OSError) as exc:
        parser.exit(1, f"Could not stage builder repository: {exc}\n")
