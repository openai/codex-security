#!/usr/bin/env python3
"""Verify the local apko image and write verification.json and public-components.json."""
import argparse
import gzip
import hashlib
import json
import re
import tarfile
from pathlib import Path

WOLFI = "https://packages.wolfi.dev/os"
REGISTRY = "https://registry.npmjs.org/"
APP = "usr/lib/codex-security/"
ENTRYPOINT = "/usr/local/bin/codex-security-entrypoint"
SOURCES = "usr/share/licenses/codex-security/SOURCES.json"
APK_DATABASES = {"lib/apk/db/installed", "usr/lib/apk/db/installed"}
# A package can contain other package.json files (for example, in examples/).
NPM_MANIFEST = re.compile(r"(?:node_modules/(?:@[^/]+/)?[^/]+/)+package\.json")
LICENSES = set("""MIT Apache-2.0 BSD-1-Clause BSD-2-Clause BSD-3-Clause BSD-4-Clause-UC
ISC CC0-1.0 MPL-2.0 PSF-2.0 OLDAP-2.8 Artistic-1.0-Perl GPL-1.0-only GPL-1.0-or-later
GPL-2.0-only GPL-2.0-or-later GPL-3.0-or-later LGPL-2.0-or-later LGPL-2.1 LGPL-2.1-only
LGPL-2.1-or-later LGPL-3.0-or-later GCC-exception-3.1 libselinux-1.0 blessing CC-PDDC AND OR WITH""".split())

def check(ok, message):
    if not ok:
        raise SystemExit(message)

def check_license(name, expression):
    terms = set(re.findall(r"[\w.+-]+", expression or ""))
    check(terms and not (terms - LICENSES), f"Unreviewed license for {name}: {expression}")

class HashingReader:
    """Hash what the gzip and tar readers consume, including trailing tar padding."""

    def __init__(self, stream):
        self.stream = stream
        self.hash = hashlib.sha256()

    def read(self, size):
        chunk = self.stream.read(size)
        self.hash.update(chunk)
        return chunk

    @property
    def digest(self):
        return "sha256:" + self.hash.hexdigest()


def read_blob(tar, descriptor):
    data = tar.extractfile(descriptor["digest"]).read()
    check(len(data) == descriptor["size"] and "sha256:" + hashlib.sha256(data).hexdigest() == descriptor["digest"],
          f"OCI blob does not match descriptor: {descriptor['digest']}")
    return json.loads(data)


def inspect_layer(fs):
    raw, manifests, keys, native = {}, {}, {}, {}
    executable = False
    for ent in fs:
        path = ent.name.removeprefix("./")
        check(path.rsplit("/", 1)[-1] != "melange.rsa", f"Signing private key in the image: {path}")
        if path == ENTRYPOINT.lstrip("/"):
            bit = 0o100 if ent.uid == 10001 else 0o010 if ent.gid == 10001 else 0o001
            executable = ent.isfile() and bool(ent.mode & bit)
        elif path.startswith("etc/apk/keys/"):
            check(ent.isfile(), f"Unexpected public key format: {path}")
            keys[path.removeprefix("etc/apk/keys/")] = fs.extractfile(ent).read()
        elif ent.isfile():
            if path in APK_DATABASES or path in {"etc/apk/repositories", APP + "package-lock.json", SOURCES}:
                raw[path] = fs.extractfile(ent).read()
            elif path.startswith(APP) and NPM_MANIFEST.fullmatch(path[len(APP):]):
                manifests[path[len(APP):-len("/package.json")]] = json.load(fs.extractfile(ent))
            elif ("/@openai/codex-linux-x64/vendor/" in path and ent.mode & 0o111) or (path.startswith(APP) and path.endswith(".node")):
                h = hashlib.sha256()
                stream = fs.extractfile(ent)
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
                native[path] = h.hexdigest()
    check(executable, "Expected a regular entrypoint executable by UID/GID 10001")
    return raw, manifests, keys, native


def inventory_apks(database, packages):
    apks = []
    lock = {p["name"]:p for p in packages}
    for record in database.decode().strip().split("\n\n"):
        fields = dict(line.split(":",1) for line in record.splitlines() if line[:2] in {"P:","V:","L:","o:"})
        name, version, license = fields["P"],fields["V"],fields["L"]
        check_license(name, license)
        item = lock.pop(name)
        check(item["version"] == version, "Lock version mismatch: "+name)
        url = f"{WOLFI}/x86_64/{name}-{version}.apk"
        if name == "codex-security":
            url = f"./packages/x86_64/{name}-{version}.apk"
        check(item["url"] == url, "Unexpected package source: "+item["url"])
        apks.append({"name":name, "version":version, "origin":fields["o"], "license":license, "source":url})
    check(not lock, "Missing locked APKs")
    return sorted(apks, key=lambda p: p["name"])


def inventory_npm(manifests, packages, sources):
    paths = {p["path"] for p in sources}
    check(len(paths) == len(sources) and paths == manifests.keys(),
          "Installed npm package paths differ from SOURCES.json")
    npm = []
    for item in sources:
        path = item["path"]
        pkg = packages[path]
        meta = manifests[path]
        check(pkg["resolved"].startswith(REGISTRY) and pkg["integrity"].startswith("sha512-"), "Unexpected npm source: "+path)
        # npm aliases have a different package name from their installed path.
        identity = (pkg.get("name", path.rsplit("node_modules/", 1)[-1]), pkg["version"], pkg["license"])
        check(identity == (meta["name"], meta["version"], meta["license"]) == (item["name"], item["version"], item["license"]),
              "npm metadata mismatch: "+path)
        check((pkg["resolved"], pkg["integrity"]) == (item["input_archive"], item["integrity"]), "npm source mismatch: "+path)
        check_license(path, meta["license"])
        repository = meta.get("repository")
        npm.append({"path":path, "name":meta["name"], "version":meta["version"], "license":meta["license"],
                    "source":pkg["resolved"], "integrity":pkg["integrity"],
                    "source_repository":repository.get("url") if isinstance(repository,dict) else repository})
    return npm


def verify(archive, lock):
    with tarfile.open(archive) as tar:
        manifest, = json.load(tar.extractfile("manifest.json"))
        index, = json.load(tar.extractfile("index.json"))["manifests"]
        platform = {"architecture": "amd64", "os": "linux"}
        check(index["platform"] == platform, "Expected Linux amd64")
        oci = read_blob(tar, index)
        check(manifest["Config"] == oci["config"]["digest"], "Docker and OCI configuration disagree")
        config = read_blob(tar, oci["config"])
        check(all(config[k] == v for k, v in platform.items()), "Unexpected image platform")
        c = config["config"]
        check((c["Entrypoint"], c["Cmd"], c["User"]) == ([ENTRYPOINT], ["--help"], "10001:10001"),
              "Unexpected entrypoint, default command or user")
        layer, = manifest["Layers"]
        descriptor, = oci["layers"]
        check(tar.getmember(layer).size == descriptor["size"], "OCI layer size mismatch")
        with tar.extractfile(layer) as stream:
            compressed = HashingReader(stream)
            with gzip.GzipFile(fileobj=compressed, mode="rb") as gz:
                uncompressed = HashingReader(gz)
                with tarfile.open(fileobj=uncompressed, mode="r|", bufsize=1024*1024) as fs:
                    raw, manifests, keys, native = inspect_layer(fs)
                while uncompressed.read(1024*1024):  # gzip trailer and any remaining tar padding
                    pass
        check(compressed.digest == descriptor["digest"], "Compressed layer checksum mismatch")
        check(config["rootfs"]["diff_ids"] == [uncompressed.digest], "Uncompressed layer checksum mismatch")
    repos = raw["etc/apk/repositories"].decode().splitlines()
    check(repos == [WOLFI], "Unexpected runtime repository")
    expected = {Path(k["name"]).name: k["content"].encode() for k in lock["keyring"]}
    check(set(expected) == {"wolfi-signing.rsa.pub", "melange.rsa.pub"} and keys == expected, "Incorrect runtime APK trust keys")
    key_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(keys.items())}
    databases = {raw[p] for p in APK_DATABASES if p in raw}
    check(len(databases) == 1, "Missing or conflicting installed APK database")
    apks = inventory_apks(databases.pop(), lock["packages"])
    local = sum(p["name"] == "codex-security" for p in apks)
    check(local == 1, "Expected one local scanner APK")
    src = json.loads(raw[SOURCES])
    npm = inventory_npm(manifests, json.loads(raw[APP+"package-lock.json"])["packages"], src["npm"])
    records = src["native_executables_and_addons"]
    check(len(records) == 6 and all(p["source"].startswith("https://github.com/") for p in records),
          "Unknown native runtime source")
    check({APP+p["path"]:p["sha256"] for p in records} == native, "Native files differ from source inventory")
    components = {"image_manifest":index["digest"], "platform":"linux/amd64", "apk_repository":WOLFI,
        "apk_trust_sha256":key_hashes, "apk_count":len(apks), "installed_apks":apks,
        "npm_package_count":len(npm), "installed_npm":npm, "bundled_native":records,
        "scope":"Installed package sources and declared licenses. The model service is external to the image."
    }
    verification = {"platform":"linux/amd64", "tag":manifest["RepoTags"][0], "config_digest":manifest["Config"],
        "oci_manifest":index["digest"], "runtime_repositories":repos, "entrypoint":ENTRYPOINT, "user":c["User"],
        "public_upstream_packages":len(apks)-local, "local_scanner_packages":local,
        "keyring_sha256":{k:"sha256:"+v for k,v in key_hashes.items()},
        "signed_build_manifest":"SHA256SUMS", "manifest_signature":"SHA256SUMS.sig"}
    return {"verification.json": verification, "public-components.json": components}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    reports = verify(args.archive, json.loads(args.lock.read_bytes())["contents"])
    for name, report in reports.items():
        Path(name).write_text(json.dumps(report, indent=2) + "\n")

if __name__ == "__main__":
    main()
