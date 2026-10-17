#!/usr/bin/env bash

set -euo pipefail

image=${1:?Usage: verify-container-sandbox.sh IMAGE}
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
apparmor_options=()

if docker info --format '{{json .SecurityOptions}}' | grep -Fq '"name=apparmor"'; then
  sudo install -m 0644 "$repository_root/docker/codex-security.apparmor" \
    /etc/apparmor.d/codex-security-container
  sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
  sudo grep -Fxq 'codex-security-container (enforce)' \
    /sys/kernel/security/apparmor/profiles
  apparmor_options=(--security-opt apparmor=codex-security-container)
  printf '%s\n' 'COMPOSE_FILE=compose.yaml:compose.apparmor.yaml' >> "$GITHUB_ENV"
fi

docker run --rm \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt "seccomp=$repository_root/docker/codex-security-seccomp.json" \
  "${apparmor_options[@]}" \
  --entrypoint node \
  "$image" \
  /usr/local/lib/node_modules/@openai/codex-security/node_modules/@openai/codex/bin/codex.js \
  sandbox /usr/bin/true
