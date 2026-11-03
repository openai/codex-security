#!/usr/bin/env bash
# Native Linux/amd64. Load the repository's Docker AppArmor profile first.
# The offline fixture creates its own repository and output in disposable tmpfs.
set -euo pipefail
if (( $# != 1 )); then
  echo 'usage: tests/smoke.sh LOCAL_IMAGE' >&2
  exit 2
fi
test_dir=$(cd -- "$(dirname -- "$0")" && pwd)
docker_dir=$(cd -- "$test_dir/../.." && pwd)
case "$(docker info --format '{{.OSType}}/{{.Architecture}}')" in
  linux/x86_64|linux/amd64) ;;
  *) echo 'Run on native Linux/amd64 so the nested sandbox can be tested.' >&2; exit 2 ;;
esac
image=$(docker image inspect "$1" --format '{{.Id}}')
[[ $(docker image inspect "$image" --format '{{.Os}}/{{.Architecture}} {{join .Config.Entrypoint " "}}') == 'linux/amd64 /usr/local/bin/codex-security-entrypoint' ]]
echo "Image: $image"
flags=(--rm --pull=never --network=none --read-only --cap-drop=ALL
  --security-opt=no-new-privileges --security-opt=apparmor=codex-security-container
  --security-opt="seccomp=$docker_dir/codex-security-seccomp.json"
  --tmpfs /tmp:rw,nodev,nosuid,mode=1777
  --tmpfs /input:rw,nodev,nosuid,uid=10001,gid=10001,mode=0755
  --tmpfs /output:rw,nodev,nosuid,uid=10001,gid=10001
  --tmpfs /state:rw,nodev,nosuid,uid=10001,gid=10001)

# Exercise the image's configured entrypoint & CMD before using Node as a harness.
help=$(docker run "${flags[@]}" "$image")
[[ $help == *'Usage: codex-security'* ]]
version=$(docker run "${flags[@]}" "$image" --version)
expected=${SCANNER_VERSION:-$(docker run "${flags[@]}" --entrypoint /usr/bin/node "$image" \
  -p 'require("/usr/lib/codex-security/node_modules/@openai/codex-security/package.json").version')}
[[ $version == "$expected" ]]
status=0
reason=$(docker run "${flags[@]}" "$image" bulk-scan 2>&1) || status=$?
[[ $status == 2 && $reason == *'bulk-scan requires a repository CSV'* ]]
echo "PASS default help, version $version, and noninteractive bulk-scan guard"
docker run "${flags[@]}" -i --entrypoint /usr/bin/node "$image" --input-type=module - < "$test_dir/runtime.mjs"
