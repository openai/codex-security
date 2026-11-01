#!/usr/bin/env bash
# Exercise the release index with BuildKit's OCI layout and attestation manifests.
set -euo pipefail

prepare=$(realpath "$(dirname "$0")/prepare-container-index.sh")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir context
printf 'FROM scratch\nCOPY platform /platform\n' > context/Dockerfile
for arch in amd64 arm64; do
  echo "$arch" > context/platform
  docker buildx build --platform "linux/$arch" --provenance=mode=max \
    --output "type=oci,dest=$arch.tar,name=ghcr.io/openai/codex-security:1.2.3" context
  skopeo inspect --raw "oci-archive:$arch.tar" > "$arch.json"
done

export IMAGE_METADATA='{"labels":{"org.opencontainers.image.version":"1.2.3"}}'
digest=$(bash "$prepare" amd64.tar arm64.tar release)
skopeo copy --all --preserve-digests --digestfile copied.digest oci:release:scanner oci:copied:scanner
[[ $(cat copied.digest) == "$digest" ]]
skopeo inspect --raw oci:copied:scanner > copied.json
jq -es --argjson metadata "$IMAGE_METADATA" '
  .[2].annotations == $metadata.labels and
  .[2].manifests == (.[0].manifests + .[1].manifests)
' amd64.json arm64.json copied.json > /dev/null
for arch in amd64 arm64; do
  platform=$(jq -er --arg arch "$arch" '.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch).digest' "$arch.json")
  attachment=$(jq -er --arg platform "$platform" '.manifests[] | select(.annotations["vnd.docker.reference.digest"] == $platform).digest' "$arch.json")
  statement=$(jq -er '.layers[] | select(.annotations["in-toto.io/predicate-type"] | startswith("https://slsa.dev/provenance/")).digest' \
    "copied/blobs/sha256/${attachment#sha256:}")
  jq -e --arg digest "${platform#sha256:}" --arg name "pkg:docker/ghcr.io/openai/codex-security@1.2.3?platform=linux%2F$arch" \
    'any(.subject[]; .digest.sha256 == $digest and .name == $name)' "copied/blobs/sha256/${statement#sha256:}" > /dev/null
done

if bash "$prepare" amd64.tar amd64.tar duplicate; then
  echo 'Two amd64 archives must not form a release index.' >&2
  exit 1
fi
