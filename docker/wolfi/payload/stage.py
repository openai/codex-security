#!/usr/bin/env python3
"""Stage the open-source scanner payload for offline Linux/amd64 melange builds.

Usage: python3 payload/stage.py PATH_TO_MELANGE_SOURCE_DIR
Requires Python 3.9+, Node and npm 11 on a POSIX host. No target code is run.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
DOCKER = HERE.parent.parent
REPO = DOCKER.parent
INSTALL = Path("usr/lib/codex-security")
SDK = "node_modules/@openai/codex-security"
VENDOR = "node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl"
TARGET = {"os": "linux", "cpu": "x64", "libc": "glibc"}
LICENSE_DIR = Path("usr/share/licenses/codex-security")
REVIEWED_NPM_LICENSES = {"Apache-2.0", "BSD-3-Clause", "ISC", "MIT", "(MIT OR CC0-1.0)"}
CODEX_SOURCE = "https://github.com/openai/codex/tree/6aaac694803004a63c6f393d153c96d22521a6b9"
SCANNER_SOURCE = "https://github.com/openai/codex-security/tree/f05a0b096cc881242ddf34a4d6b3ce0f322f3cf9"
OFF_TARGET_PLUGIN_TARGETS = {
    "darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-arm64-musl",
    "linux-x64-musl", "win32-arm64", "win32-x64",
}

# Reuse this repository's Docker scripts at their released hashes. The root
# LICENSE is byte-identical to the LICENSE in the pinned native Codex release.
EXTRAS = {
    DOCKER / "entrypoint.sh": ("usr/local/bin/codex-security-entrypoint", "5bcce4a6b0f6a57d938f3e9def0aea93660d41356fdf0ddad1d343a067fc6610"),
    DOCKER / "git-credential.sh": ("usr/local/bin/codex-security-git-credential", "0b792c2304abcd60366aed3040287ecee4d8e336c121516d8112f577fc2af360"),
    REPO / "LICENSE": ("usr/share/licenses/codex-security/CODEX-LICENSE", "d17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc"),
    HERE / "CODEX-NOTICE": ("usr/share/licenses/codex-security/CODEX-NOTICE", "9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915"),
}


def read_json(path):
    return json.loads(path.read_text())


def matches_target(package):
    for key, target in TARGET.items():
        values = package.get(key, [])
        allowed = [v for v in values if not v.startswith("!")]
        if "!" + target in values or (allowed and target not in allowed):
            return False
    return True


def source_url(pkg):
    repo = pkg.get("repository")
    raw = repo.get("url") if isinstance(repo, dict) else repo
    # npm accepts both GitHub shorthand and conventional git URLs. Do not
    # silently accept missing metadata, new repository hosts or unknown terms.
    match = re.fullmatch(r"(?:(?:git\+https://|https://|git://|git@)github\.com[:/]|github:)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", raw or "")
    if not match:
        raise ValueError(f"Review repository for {pkg['name']}: {raw}")
    return "https://github.com/" + match[1].removesuffix(".git")


def select_scanner_payload(app):
    # Voice belongs to the interactive client, not repository scanning. The
    # MCP server uses Node's target (Linux x64 glibc), while the Codex executable
    # itself is the upstream static musl build.
    shutil.rmtree(app / VENDOR / "codex-resources/voice")
    native = app / SDK / "_bundled_plugin/mcp/native"
    if {p.name for p in native.iterdir() if p.is_dir()} != OFF_TARGET_PLUGIN_TARGETS | {"licenses", "linux-x64-gnu"}:
        raise ValueError("Review changed native MCP targets")
    for target in OFF_TARGET_PLUGIN_TARGETS:
        shutil.rmtree(native / target)
    known = {
        "bin/codex", "bin/codex-code-mode-host", "codex-resources/bwrap",
        "codex-path/rg", "codex-package.json",
    }
    vendor = app / VENDOR
    if {p.relative_to(vendor).as_posix() for p in vendor.rglob("*") if p.is_file()} != known:
        raise ValueError("Review changed Codex release files")


def write_attributions(root, app, wanted):
    license_dir = root / LICENSE_DIR
    notices = read_json(HERE / "notices/sources.json")
    for name, item in notices.items():
        source = HERE / "notices" / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"Changed upstream notice: {name}")
        shutil.copyfile(source, license_dir / name)
    shutil.copyfile(HERE / "notices/sources.json", license_dir / "NOTICE-SOURCES.json")
    npm = []
    for key, lock_record in sorted(wanted.items()):
        pkg = read_json(app / key / "package.json")
        if pkg.get("license") != lock_record.get("license") or pkg.get("license") not in REVIEWED_NPM_LICENSES:
            raise ValueError(f"Review license for {key}: {pkg.get('license')}")
        npm.append({"path": key, "name": pkg["name"], "version": pkg["version"], "license": pkg["license"],
                    "repository": source_url(pkg), "input_archive": lock_record["resolved"], "integrity": lock_record["integrity"]})
    codex_native = {
        VENDOR + "/bin/codex": CODEX_SOURCE + "/codex-rs/cli",
        VENDOR + "/bin/codex-code-mode-host": CODEX_SOURCE + "/codex-rs/code-mode-host",
        VENDOR + "/codex-resources/bwrap": CODEX_SOURCE + "/codex-rs/vendor/bubblewrap",
        VENDOR + "/codex-path/rg": "https://github.com/BurntSushi/ripgrep/tree/e89fff89ac9af12e8d4ce9d5fd07beb408ca730f",
        SDK + "/_bundled_plugin/mcp/native/linux-x64-gnu/unix.node": SCANNER_SOURCE + "/plugins/codex-security/native",
        "node_modules/@napi-rs/canvas-linux-x64-gnu/skia.linux-x64-gnu.node": "https://github.com/Brooooooklyn/canvas/tree/00a115d9903647f116daf86eccd2c6ba36128371",
    }
    native_records = []
    for file, source in codex_native.items():
        hasher = hashlib.sha256()
        with (app / file).open("rb") as f:
            while chunk := f.read(1 << 20):
                hasher.update(chunk)
        native_records.append({"path": file, "source": source, "sha256": hasher.hexdigest()})
    manifest = {"scanner_source": SCANNER_SOURCE, "codex_source": CODEX_SOURCE, "npm": npm,
                "native_executables_and_addons": native_records,
                "omitted": [VENDOR + "/codex-resources/voice"] +
                           [SDK + "/_bundled_plugin/mcp/native/" + target for target in sorted(OFF_TARGET_PLUGIN_TARGETS)]}
    (license_dir / "SOURCES.json").write_text(json.dumps(manifest, indent=2) + "\n")


def stage_root(root):
    app = root / INSTALL
    app.mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(HERE / name, app / name)
    lock = read_json(app / "package-lock.json")
    packages = {k: v for k, v in lock["packages"].items() if k}
    # An unexpected package manager script or nonregistry artifact requires review.
    for name, pkg in packages.items():
        if (not pkg["resolved"].startswith("https://registry.npmjs.org/")
                or not pkg["integrity"].startswith("sha512-") or pkg.get("hasInstallScript")):
            raise ValueError(f"Unexpected source, integrity, or lifecycle script: {name}")
    global_config = root.parent / "empty-npmrc"
    global_config.touch()
    subprocess.run([
        "npm", "ci", "--os=linux", "--cpu=x64", "--libc=glibc", "--omit=dev",
        "--include=optional", "--ignore-scripts", "--no-audit", "--no-fund",
        "--userconfig=/dev/null", f"--globalconfig={global_config}", "--registry=https://registry.npmjs.org",
    ], cwd=app, check=True)
    # npm treats failed optional installs as success. Check the full target graph,
    # including platform packages, before accepting the install.
    installed = read_json(app / "node_modules/.package-lock.json")["packages"]
    wanted = {k: v for k, v in packages.items() if matches_target(v)}
    if installed.keys() != wanted.keys():
        raise ValueError(f"Installed graph differs from lock: {sorted(installed.keys() ^ wanted.keys())}")
    for key, pkg in wanted.items():
        if installed[key]["integrity"] != pkg["integrity"] or read_json(app / key / "package.json")["version"] != pkg["version"]:
            raise ValueError(f"Installed version/integrity differs for {key}")
    # Keep the original lock usable by npm ci. SOURCES.json records the subset
    # installed for this platform.
    (app / "node_modules/.package-lock.json").unlink()  # transient local npm cache
    select_scanner_payload(app)
    for name in ("bin/codex", "bin/codex-code-mode-host", "codex-resources/bwrap", "codex-path/rg"):
        binary = app / VENDOR / name
        with binary.open("rb") as f:
            header = f.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00" or not os.access(binary, os.X_OK):
            raise ValueError(f"Missing executable ELF64 x86-64 {name}")
    for name in (".codex-plugin/plugin.json", "scripts/launch_codex_security_mcp", "mcp/native/linux-x64-gnu/unix.node", "mcp/server.mjs", "mcp/native/THIRD_PARTY_NOTICES.txt"):
        if not (app / SDK / "_bundled_plugin" / name).is_file():
            raise ValueError(f"Incomplete bundled plugin: {name}")
    bindir = root / "usr/bin"
    bindir.mkdir()
    for name in ("cs", "codex-security"):
        (bindir / name).symlink_to("../lib/codex-security/" + SDK + "/bin/codex-security.mjs")
    for source, (dest, sha) in EXTRAS.items():
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError(f"Release file differs from pin: {source.name}")
        path = root / dest
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if source.suffix == ".sh" else 0o644)
    write_attributions(root, app, wanted)
    return len(wanted)


def normalize(entry):
    if not (entry.isdir() or entry.isreg() or entry.issym()):
        raise ValueError(f"Unexpected file type: {entry.name}")
    entry.uid = entry.gid = entry.mtime = 0
    entry.uname = entry.gname = "root"
    entry.mode = (0o777 if entry.issym() else 0o755 if entry.isdir() or entry.mode & 0o111 else 0o644)
    return entry


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("stage", type=Path, help="melange --source-dir (only payload.tar.gz will be written)")
    output = args.parse_args().stage.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="codex-security-payload-") as work:
        root = Path(work) / "root"
        count = stage_root(root)
        # The recipe pins the uncompressed tar hash, independent of gzip/zlib.
        # Normalize sort order, mtime, owners and permissions across build hosts.
        with tempfile.NamedTemporaryFile(dir=output, prefix="payload-", delete=False) as temp:
            temporary = Path(temp.name)
        try:
            with temporary.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=3, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w|", format=tarfile.GNU_FORMAT) as archive:
                    archive.add(root / "usr", arcname="usr", filter=normalize)
            digest = hashlib.sha256()
            with gzip.open(temporary, "rb") as gz:
                while chunk := gz.read(1024 * 1024):
                    digest.update(chunk)
            temporary.chmod(0o644)
            temporary.replace(output / "payload.tar.gz")
            print(f"{count} locked production packages; uncompressed tar SHA-256: {digest.hexdigest()}")
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
