"""Cache verified public archives and materialize one eval checkout offline."""

import argparse
import base64
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
ASSETS = json.loads((ROOT / "assets.json").read_text())
ARTIFACTS = json.loads((ROOT / "fixtures/mime-receiver/artifacts.json").read_text())[
    "artifacts"
]
PACKAGES = {f"{a['name'].split('/')[-1]}-{a['version']}": a for a in ARTIFACTS}


def sha256(path):
    with path.open("rb") as fp:
        return hashlib.file_digest(fp, "sha256").hexdigest()


def cached(cache, name):
    entry = ASSETS[name]
    path = cache / entry["sha256"]
    if not path.is_file() or sha256(path) != entry["sha256"]:
        raise ValueError(
            f"Cache is missing verified public source {name}. Run assets.py fetch first."
        )
    return path


def fetch(cache):
    cache.mkdir(parents=True, exist_ok=True)
    for name, entry in ASSETS.items():
        path = cache / entry["sha256"]
        if not path.exists():
            with tempfile.TemporaryDirectory(dir=cache) as tmp:
                downloaded = Path(tmp) / "download"
                with (
                    urlopen(entry["url"], timeout=120) as src,
                    downloaded.open("xb") as dest,
                ):
                    shutil.copyfileobj(src, dest)
                if sha256(downloaded) != entry["sha256"]:
                    raise ValueError(f"Unexpected bytes for {name}")
                downloaded.replace(path)
        cached(cache, name)
        print(name, flush=True)


def materialize(cache, destination, case):
    source = cached(cache, f"{case['repository']}@{case['revision']}")
    destination.mkdir()
    # tarfile's data filter rejects archive traversal, escaping links and devices.
    with tarfile.open(source, "r:gz") as archive:
        archive.extractall(destination, filter="data")
    (checkout,) = destination.iterdir()
    if checkout.is_symlink() or not checkout.is_dir():
        raise ValueError("Expected one upstream source directory")
    new_directories = set()
    with ExitStack() as handles:
        packages = {}
        for file in case["stage"]:
            path = PurePosixPath(file["destination"])
            if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
                raise ValueError(f"Unsafe staged path: {path}")
            top = path.parts[0]
            if top not in new_directories:
                # A checked-out symlink cannot redirect a staged file.
                (checkout / top).mkdir()
                new_directories.add(top)
            dest = checkout / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            kind = file["kind"]
            if kind == "json":
                content = (
                    json.dumps(file["value"], ensure_ascii=False, indent=2) + "\n"
                ).encode()
            elif kind == "git":
                content = cached(
                    cache, f"{file['repository']}@{file['revision']}:{file['source']}"
                ).read_bytes()
            elif kind == "fixture":
                content = (ROOT / file["source"]).read_bytes()
            elif kind == "npm":
                info = PACKAGES[file["archive"]]
                key = f"{info['name']}@{info['version']}"
                if key not in packages:
                    pinned = cached(cache, key)
                    if pinned.name != info["archiveSha256"]:
                        raise ValueError(
                            f"Archive pin differs from public lock for {key}"
                        )
                    with pinned.open("rb") as fp:
                        integrity = base64.b64encode(
                            hashlib.file_digest(fp, "sha512").digest()
                        ).decode()
                    if "sha512-" + integrity != info["integrity"]:
                        raise ValueError(f"Public npm integrity mismatch for {key}")
                    packages[key] = handles.enter_context(tarfile.open(pinned, "r:gz"))
                member = file["member"]
                archive = packages[key]
                entry = archive.getmember("package/" + member)
                if not entry.isfile():
                    raise ValueError(f"Expected a regular file at {entry.name}")
                with archive.extractfile(entry) as src:
                    content = src.read()
                digest = next(f["sha256"] for f in info["files"] if f["path"] == member)
                if hashlib.sha256(content).hexdigest() != digest:
                    raise ValueError(f"Unexpected contents for {key}/{member}")
            else:
                raise ValueError(f"Unknown snapshot source: {kind}")
            with dest.open("xb") as fp:
                fp.write(content)
    print(checkout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch").add_argument("cache", type=Path)
    stage = sub.add_parser("materialize")
    stage.add_argument("cache", type=Path)
    stage.add_argument("destination", type=Path)
    options = parser.parse_args()
    if options.command == "fetch":
        fetch(options.cache)
    else:
        materialize(options.cache, options.destination, json.load(sys.stdin))
