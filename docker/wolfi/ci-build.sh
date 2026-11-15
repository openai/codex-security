#!/usr/bin/env bash
# Build and smoke-test one archive on a fresh GitHub-hosted ubuntu-24.04 VM.
# The workflow supplies Node 24.15.0 (npm 11) and an absolute, new output directory.
set -euo pipefail
die() { echo "$*" >&2; exit 1; }
[[ $# == 1 && $1 == /* && ! -e $1 ]] || die 'Usage: ci-build.sh NEW_ABSOLUTE_OUTPUT_DIRECTORY'
[[ ${RUNNER_ENVIRONMENT:-} == github-hosted && $(uname -s -m) == 'Linux x86_64' ]] ||
  die 'Use a disposable GitHub-hosted Ubuntu 24.04 amd64 VM'
[[ $(id -u) != 0 && $(npm --version) == 11.* ]] || die 'Run as the runner user with npm 11 on PATH'

recipe=$(cd "$(dirname "$0")" && pwd -P)
out=$1
tools=$(mktemp -d "${RUNNER_TEMP:?}/wolfi-tools.XXXXXXXX")
profile=$recipe/../codex-security.apparmor
added_profile=false
cleanup() {
  if "$added_profile"; then sudo -n apparmor_parser --skip-cache --remove "$profile"; fi
  rm -rf -- "$tools"
}
trap cleanup EXIT

# Reuse the repository's Ubuntu Bubblewrap setup. Its packaged AppArmor profile
# grants user namespaces to bwrap without changing any host security sysctl.
bash "$recipe/../../github-action/scripts/setup-ubuntu-sandbox.sh"
bwrap --unshare-user --unshare-net --uid 1000 --gid 1000 --ro-bind / / --dev /dev --proc /proc -- /usr/bin/true

# SHA-256 pins from each tagged upstream release's checksums.txt. Extract only
# the binary after verification; no installer or downloaded source is executed.
install_tool() {
  local name=$1 version=$2 sha=$3 base
  base="${name}_${version}_linux_amd64"
  curl --proto '=https' --proto-redir '=https' --fail --location --silent --show-error --retry 3 \
    "https://github.com/chainguard-dev/$name/releases/download/v$version/$base.tar.gz" \
    --output "$tools/$base.tar.gz"
  printf '%s  %s\n' "$sha" "$tools/$base.tar.gz" | sha256sum --check --strict
  tar -xOzf "$tools/$base.tar.gz" "$base/$name" > "$tools/$name"
  chmod 0755 "$tools/$name"
}
install_tool apko 1.4.13 2377cd4a2efed58905da580f835fbdf2a6ed4ad0f10ff541827153a42d491cee
install_tool melange 0.61.1 4f2d104f1149e4bcf63c7f7a71deeae385d453c3bdf0f987c9c2d16a2efdd7da

# Stage and resolve the public inputs normally. For the guest build alone,
# unshare needs CAP_SYS_ADMIN: create its network namespace, then drop back
# to the runner UID before starting melange. The APK snapshot is its only source.
export REAL_MELANGE="$tools/melange"
cat > "$tools/offline-melange" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == build ]]; then
  exec sudo -n /usr/bin/unshare --net -- /usr/bin/setpriv \
    --reuid "$(id -u)" --regid "$(id -g)" --clear-groups --reset-env -- "$REAL_MELANGE" "$@"
fi
exec "$REAL_MELANGE" "$@"
EOF
chmod 0755 "$tools/offline-melange"
APKO="$tools/apko" MELANGE="$tools/offline-melange" "$recipe/build.sh" "$out"

# build.sh has verified the package locks, original archive and signed checksums.
# Bind the smoke test to the verified config, including its rootfs diff IDs.
tag=$(jq -er .tag "$out/verification.json")
config_digest=$(jq -er .config_digest "$out/verification.json")
if docker image inspect "$tag" >/dev/null 2>&1; then die "Test image tag already exists: $tag"; fi
docker load --input "$out/image.tar"
image_id=$(docker image inspect --format '{{.Id}}' "$tag")
if [[ $image_id != "$config_digest" ]]; then
  # The containerd image store returns a manifest digest as the ID; the
  # classic store returns the config digest itself. Inspect the same local ID.
  loaded_config=$(skopeo inspect --raw "docker-daemon:$image_id" | jq -er .config.digest)
  [[ $loaded_config == "$config_digest" ]] || die "Docker's loaded config differs from the verified archive"
fi

# Fail if AppArmor cannot enforce the repository's profile. The smoke script
# also applies the committed seccomp policy and disables container networking.
sudo -n apparmor_parser --skip-cache --add "$profile"
added_profile=true
sudo -n grep -Fxq 'codex-security-container (enforce)' /sys/kernel/security/apparmor/profiles
"$recipe/tests/smoke.sh" "$image_id"
