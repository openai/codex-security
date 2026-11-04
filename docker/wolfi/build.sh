#!/usr/bin/env bash
# Build and verify a local linux/amd64 image from the public Wolfi repository.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./build.sh [NEW_OUTPUT_DIR]   (default: ./build next to this script)
Requires Linux with an x86_64-capable melange/bubblewrap runner, melange 0.61.1,
apko 1.4.13, Python 3.9+, OpenSSL, and npm 11 for payload staging.
APKO and MELANGE optionally name the installed tool executables.
STAGED_PAYLOAD optionally names an absolute path to an already staged payload
matching the payload_sha256 in build-inputs.json. All OS packages come from packages.wolfi.dev.
Each run generates a new local signing key and removes the private key at exit.
EOF
}
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ ${1:-} != -h && ${1:-} != --help ]] || { usage; exit 0; }
[[ $# -le 1 && ${1:-} != -* ]] || { usage >&2; exit 2; }
root=$(cd "$(dirname "$0")" && pwd -P)
out=${1:-"$root/build"}
apko=${APKO:-apko}; melange=${MELANGE:-melange}
"$apko" version | grep -Eq '^GitVersion:[[:space:]]+v1\.4\.13$' || die 'Expected apko 1.4.13'
"$melange" version | grep -Eq '^GitVersion:[[:space:]]+v0\.61\.1$' || die 'Expected melange 0.61.1'
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else "Python 3.9+ required")'
if [[ -n ${STAGED_PAYLOAD:-} ]]; then
  [[ $STAGED_PAYLOAD == /* && -f $STAGED_PAYLOAD ]] || die 'STAGED_PAYLOAD must be an existing absolute file path'
else
  [[ $(npm --version) == 11.* ]] || die 'Expected npm 11'
fi
mkdir -p "$(dirname "$out")"
(umask go-w; mkdir "$out") || die 'Use a new output directory for each build'
cd "$out"; out=$(pwd -P)
scratch=$(mktemp -d /tmp/codex-security-build.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM
unset HTTP_AUTH SOURCE_DATE_EPOCH
mkdir -p src packages sbom
cp "$root"/{wolfi-signing.rsa.pub,builder.yaml,apko.yaml,melange.yaml,build-inputs.json} .
(cd "$scratch"; "$melange" keygen melange.rsa)
cp "$scratch/melange.rsa.pub" .
stamp=2026-10-26T11:30:14Z
if [[ -n ${SCANNER_TARBALL:-} ]]; then
  : "${SCANNER_SHA:?}" "${SCANNER_VERSION:?}" "${SCANNER_RUNTIME_LOCK:?}"
  if [[ -n ${STAGED_PAYLOAD:-} ]]; then
    [[ ${BASE_PAYLOAD_SHA:-} =~ ^[0-9a-f]{64}$ ]] || die 'OS updates require the original scanner payload hash'
  fi
  [[ $SCANNER_SHA =~ ^[0-9a-f]{40}$ && $SCANNER_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Invalid scanner release'
  stamp=$(git -C "$root" show -s --format=%cI "$SCANNER_SHA")
fi
# Authenticate the upstream indexes with the reviewed Wolfi key.
python3 -c 'import hashlib, json, pathlib, sys
actual = hashlib.sha256(pathlib.Path("wolfi-signing.rsa.pub").read_bytes()).hexdigest()
if actual != json.load(open("build-inputs.json"))["wolfi_key_sha256"]: sys.exit("Unexpected Wolfi signing key")'

# Verify the lock's origin, architecture, control/data checksums and exact keyring.
check_lock() {
  python3 - "$1" "$2" <<'PY'
import hashlib, json, sys
from pathlib import Path
m=json.loads(Path("build-inputs.json").read_text()); which=sys.argv[1]; snap=m["snapshots"][which]
c=json.loads(Path(sys.argv[2]).read_text())["contents"]; local_spec=m["local_package"]
rows=[]; local=[]
for p in c["packages"]:
    n=p["name"]; v=p["version"]; filename=f"{n}-{v}.apk"
    if p["architecture"]!="x86_64": raise ValueError(f"Unexpected architecture: {n}")
    if p["url"]=="./packages/x86_64/"+filename: local.append(n+"="+v)
    else:
        if p["url"]!=m["repository"]+"/x86_64/"+filename: raise ValueError(f"Unexpected package URL: {n}")
        rows.append({k:v for k,v in p.items() if k!="url"})
rows.sort(key=lambda r:r["name"])
digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()
if digest!=snap["lock_identity_sha256"] or local!=([] if which=="builder" else [local_spec]):
    raise ValueError(f"{which}: package identities differ from the public snapshot")
keys={(Path(k["name"]).name,k["content"]) for k in c["keyring"]}
expected={"wolfi-signing.rsa.pub":Path("wolfi-signing.rsa.pub").read_text()}
if which=="runtime": expected["melange.rsa.pub"]=Path("melange.rsa.pub").read_text()
if keys!=set(expected.items()): raise ValueError(f"{which}: unrecognized or missing APK signing keys")
PY
}
"$apko" lock builder.yaml --arch x86_64 --output builder.lock.json --cache-dir "$scratch/cache"
check_lock builder builder.lock.json
# Sign an index over exactly the APK bytes authenticated by the builder lock.
snapshot=$scratch/builder-repo
python3 "$root/snapshot-builder.py" builder.lock.json "$snapshot"
"$melange" index --arch x86_64 --signing-key "$scratch/melange.rsa" \
  --output "$snapshot/x86_64/APKINDEX.tar.gz" "$snapshot"/x86_64/*.apk
if [[ -n ${STAGED_PAYLOAD:-} ]]; then
  cp "$STAGED_PAYLOAD" src/payload.tar.gz
else
  python3 "$root/payload/stage.py" "$out/src"
fi
# Render only the scanner-specific fields. The reviewed OS locks stay fixed.
python3 - "$root" <<'RECIPE'
import gzip, hashlib, json, os, subprocess, sys
from pathlib import Path
inputs_path = Path("build-inputs.json")
inputs = json.loads(inputs_path.read_text())
if os.environ.get("SCANNER_TARBALL"):
    version = os.environ["SCANNER_VERSION"]
    epoch = inputs["local_package"].rsplit("-r", 1)[1]
    inputs["local_package"] = f"codex-security={version}-r{epoch}"
    if os.environ.get("STAGED_PAYLOAD"):
        inputs["payload_sha256"] = os.environ["BASE_PAYLOAD_SHA"]
    else:
        digest = hashlib.sha256()
        with gzip.open("src/payload.tar.gz", "rb") as data:
            for chunk in iter(lambda: data.read(1024 * 1024), b""):
                digest.update(chunk)
        inputs["payload_sha256"] = digest.hexdigest()
    inputs_path.write_text(json.dumps(inputs, indent=2) + "\n")
    revision = subprocess.check_output(["git", "-C", sys.argv[1], "rev-parse", "HEAD"], text=True).strip()
    tag = os.environ.get("SCANNER_RELEASE_TAG", f"{version}-wolfi-amd64")
    recipe = f'org.opencontainers.image.revision: "{revision}"\n  io.openai.codex-security.release-tag: "{tag}"'
else:
    version = inputs["local_package"].split("=")[1].split("-r")[0]
    recipe = ""
for path in (Path("melange.yaml"), Path("apko.yaml")):
    path.write_text(path.read_text().replace("@SCANNER_VERSION@", version)
                   .replace("@LOCAL_PACKAGE@", inputs["local_package"])
                   .replace("@PAYLOAD_SHA256@", inputs["payload_sha256"])
                   .replace("# @RECIPE_REVISION@", recipe))
RECIPE
pins=$(python3 -c 'import json; print(",".join(p["name"]+"="+p["version"] for p in json.load(open("builder.lock.json"))["contents"]["packages"]))')
"$melange" build melange.yaml --source-dir "$out/src" --arch x86_64 --runner bubblewrap \
  --signing-key "$scratch/melange.rsa" --generate-index --out-dir "$out/packages" \
  --repository-append "$snapshot" --keyring-append "$out/melange.rsa.pub" --package-append "$pins" \
  --build-date "$stamp" --apk-cache-dir "$scratch/guest-apk-cache" --cache-dir "$scratch/melange-cache"
"$apko" lock apko.yaml --arch x86_64 --output image.lock.json --cache-dir "$scratch/cache"
check_lock runtime image.lock.json
tag=codex-security:wolfi
"$apko" build apko.yaml "$tag" .image.unverified.tar --arch x86_64 --lockfile image.lock.json \
  --cache-dir "$scratch/cache" --vcs=false --sbom-path ./sbom --build-date "$stamp"

python3 "$root/verify-public.py" .image.unverified.tar image.lock.json
mv .image.unverified.tar image.tar
# This single detached signature covers the image, locks, SBOMs and signed local APK evidence.
sha256sum build-inputs.json builder.yaml builder.lock.json apko.yaml image.lock.json melange.yaml \
  melange.rsa.pub wolfi-signing.rsa.pub verification.json public-components.json image.tar sbom/*.spdx.json \
  packages/x86_64/APKINDEX.tar.gz packages/x86_64/*.apk > SHA256SUMS
openssl dgst -sha256 -sign "$scratch/melange.rsa" -out SHA256SUMS.sig SHA256SUMS
openssl dgst -sha256 -verify melange.rsa.pub -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
loaded_tag=$(python3 -c 'import json; print(json.load(open("verification.json"))["tag"])')
printf 'Built %s: %s/image.tar\n' "$loaded_tag" "$out"
