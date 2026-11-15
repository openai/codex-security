#!/usr/bin/env bash
# Combine the tested BuildKit archives into a release index without rewriting
# their runnable manifests, attestation manifests, or layers.
set -euo pipefail

amd64=$1 arm64=$2 layout=$3
mkdir "$layout"
indexes=()
for arch in amd64 arm64; do
  archive=$amd64
  if [[ $arch == arm64 ]]; then archive=$arm64; fi
  tar -xf "$archive" -C "$layout" blobs oci-layout index.json
  # BuildKit's layout index points to its build result. That inner index contains
  # both the native manifest and its SBOM/provenance attestation descriptor.
  digest=$(jq -er '.manifests | select(length == 1) | .[0].digest' "$layout/index.json")
  [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]
  index="$layout/blobs/sha256/${digest#sha256:}"
  jq -e --arg arch "$arch" '
    [.manifests[] | select(.platform.os == "linux") | .platform.architecture] == [$arch]
  ' "$index" > /dev/null
  indexes+=("$index")
done

index="$layout/release-index.json"
jq -cs --argjson metadata "$IMAGE_METADATA" '
  .[0] + {manifests: map(.manifests[]), annotations: $metadata.labels}
' "${indexes[@]}" > "$index"
digest=$(sha256sum "$index" | cut -d' ' -f1)
size=$(wc -c < "$index")
mv "$index" "$layout/blobs/sha256/$digest"
jq -n --arg digest "sha256:$digest" --argjson size "$size" '{
  schemaVersion: 2,
  manifests: [{
    mediaType: "application/vnd.oci.image.index.v1+json", digest: $digest, size: $size,
    annotations: {"org.opencontainers.image.ref.name": "scanner"}
  }]
}' > "$layout/index.json"
printf 'sha256:%s\n' "$digest"
