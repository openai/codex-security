#!/usr/bin/env bash
# Resolve the scanner bytes and the immutable tag before building a new Wolfi image.
set -euo pipefail
image=ghcr.io/openai/codex-security
version=$RELEASE_VERSION
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
sha=$(git rev-parse --verify "refs/tags/npm-v$version^{commit}")
recipe=$(git rev-parse HEAD)
dir=$RUNNER_TEMP/scanner
mkdir -p "$dir"
lock=$dir/package-lock.json
base=$version-wolfi-amd64
tag=$base
if [[ $OS_UPDATE == true ]]; then
  revision=$(jq -er '.image_revision | numbers | select(. > 0 and . == floor)' docker/wolfi/build-inputs.json)
  tag=$base-r$revision
else
  [[ $sha == "$RELEASE_SHA" && -n $RELEASE_INTEGRITY ]]
fi
printf 'tag=%s\n' "$tag" >> "$GITHUB_OUTPUT"

# Work by immutable digest, including when obtaining the frozen runtime lock of an older release.
read_public_image() {
  local release_tag=$1 prefix=$2 ref container predicate signed_tag commit revision
  digest=sha256:$(skopeo inspect --no-creds --raw "docker://$image:$release_tag" | tee "$dir/$prefix-manifest.json" | sha256sum | cut -d' ' -f1)
  ref=$image@$digest
  for predicate in https://slsa.dev/provenance/v1 https://spdx.dev/Document/v2.3; do
    gh attestation verify "oci://$ref" --repo "$GITHUB_REPOSITORY" --predicate-type "$predicate" \
      --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish-wolfi.yml" --source-ref refs/heads/main \
      --format json > "$dir/$prefix-${predicate##*/}.json"
  done
  signed_tag=$(jq -r '.annotations["io.openai.codex-security.release-tag"] // empty' "$dir/$prefix-manifest.json")
  if [[ -z $signed_tag ]]; then
    # The original publisher tagged the scanner version with the revision in its signed main commit.
    commit=$(image_recipe "$prefix")
    revision=$(git show "$commit:docker/wolfi/build-inputs.json" | jq -er '.image_revision | numbers | select(. >= 0 and . == floor)')
    signed_tag=$base
    if [[ $revision != 0 ]]; then signed_tag+=-r$revision; fi
  fi
  if [[ $signed_tag != "$release_tag" ]]; then
    echo "::error::$release_tag resolves to an image built for $signed_tag."
    exit 1
  fi
  docker pull "$ref"
  container=$(docker create "$ref")
  docker cp "$container:/usr/lib/codex-security/package-lock.json" "$dir/$prefix-lock.json"
  docker cp "$container:/usr/share/licenses/codex-security/SOURCES.json" "$dir/$prefix-sources.json"
  docker rm "$container" >/dev/null
  jq -e --arg sha "$sha" '.scanner_source == ("https://github.com/openai/codex-security/tree/" + $sha)' \
    "$dir/$prefix-sources.json" >/dev/null
}

image_recipe() {
  local prefix=$1 commit
  commit=$(jq -r '.annotations["org.opencontainers.image.revision"] // empty' "$dir/$prefix-manifest.json")
  if [[ -z $commit ]]; then
    # The original standalone publisher signed the protected-main recipe but did not annotate it.
    commit=$(jq -er --arg uri "git+https://github.com/$GITHUB_REPOSITORY@refs/heads/main" \
      '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[] | select(.uri == $uri) | .digest.gitCommit' "$dir/$prefix-v1.json")
  fi
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || return 1
  printf '%s\n' "$commit"
}

image_payload_sha() {
  local prefix=$1 commit=$2 hash
  hash=$(jq -r '.annotations["io.openai.codex-security.payload-sha256"] // empty' "$dir/$prefix-manifest.json")
  if [[ -z $hash ]]; then
    # Unannotated releases pinned the payload directly in their signed recipe.
    hash=$(git show "$commit:docker/wolfi/melange.yaml" | sed -nE 's/^[[:space:]]+expected=([0-9a-f]{64})$/\1/p')
  fi
  [[ $hash =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$hash"
}

if [[ $OS_UPDATE == true ]]; then
  read_public_image "$base" base
  cp "$dir/base-lock.json" "$lock"
  npm pack --ignore-scripts --pack-destination "$dir" --registry=https://registry.npmjs.org \
    "@openai/codex-security@$version"
  base_recipe=$(image_recipe base)
  git merge-base --is-ancestor "$base_recipe" "$recipe"
  mkdir "$dir/base-recipe"
  git archive "$base_recipe" LICENSE docker | tar -x -C "$dir/base-recipe"
  base_payload=$(image_payload_sha base "$base_recipe")
fi
archives=("$dir"/*.tgz)
[[ ${#archives[@]} == 1 && -f ${archives[0]} ]]
archive=${archives[0]}
integrity=$(jq -er --arg version "$version" '.packages["node_modules/@openai/codex-security"] | select(.version == $version) | .integrity' "$lock")
[[ $integrity == "sha512-$(openssl dgst -sha512 -binary "$archive" | openssl base64 -A)" ]]
if [[ $OS_UPDATE == true ]]; then
  bash docker/wolfi/verify-npm-release.sh "$lock" "$version" "$sha" "$archive"
else
  [[ $integrity == "$RELEASE_INTEGRITY" ]]
fi

# A new melange key changes the digest. Reuse an already attested matching release on recovery.
skopeo list-tags --no-creds "docker://$image" > "$dir/tags.json"
if jq -e --arg tag "$tag" '.Tags | index($tag) != null' "$dir/tags.json" >/dev/null; then
  read_public_image "$tag" published
  cmp "$lock" "$dir/published-lock.json"
  if [[ $OS_UPDATE == true ]]; then
    # The scanner payload is frozen at the base tag. Compare what builds the OS around it.
    published_recipe=$(image_recipe published)
    git merge-base --is-ancestor "$published_recipe" "$recipe"
    published_payload=$(image_payload_sha published "$published_recipe")
    inputs=docker/wolfi/build-inputs.json
    git show "$published_recipe:$inputs" > "$dir/published-inputs.json"
    # The release tag supplies the scanner version and payload hash. Only the APK epoch carries over.
    if [[ $published_payload != "$base_payload" ]] ||
      ! jq -es 'map(del(.payload_sha256) | .local_package |= (split("-r") | last)) | .[0] == .[1]' \
        "$dir/published-inputs.json" "$inputs" >/dev/null ||
      ! git diff --quiet "$published_recipe" "$recipe" -- \
      docker/wolfi/{apko.yaml,builder.yaml,melange.yaml,wolfi-signing.rsa.pub} \
      docker/wolfi/{build.sh,ci-build.sh,snapshot-builder.py}; then
      echo "::error::$tag already exists with different Wolfi build inputs. Increment image_revision."
      exit 1
    fi
  fi
  printf 'existing=true\ndigest=%s\n' "$digest" >> "$GITHUB_OUTPUT"
  printf 'Verified previously published %s:%s at %s.\n' "$image" "$tag" "$digest" >> "$GITHUB_STEP_SUMMARY" || true
  exit 0
fi

if [[ $OS_UPDATE == true ]]; then
  # Use the original entrypoint, notices and scanner staging code; only the OS recipe advances.
  SCANNER_TARBALL="$archive" SCANNER_RUNTIME_LOCK="$lock" SCANNER_VERSION="$version" SCANNER_SHA="$sha" \
    python3 "$dir/base-recipe/docker/wolfi/payload/stage.py" "$dir/base-payload"
  printf 'BASE_PAYLOAD_SHA=%s\nSTAGED_PAYLOAD=%s\n' "$base_payload" "$dir/base-payload/payload.tar.gz" >> "$GITHUB_ENV"
fi
printf 'SCANNER_RELEASE_TAG=%s\nSCANNER_VERSION=%s\nSCANNER_SHA=%s\nSCANNER_RECIPE_SHA=%s\nSCANNER_TARBALL=%s\nSCANNER_RUNTIME_LOCK=%s\nSCANNER_INTEGRITY=%s\n' \
  "$tag" "$version" "$sha" "$recipe" "$archive" "$lock" "$integrity" >> "$GITHUB_ENV"
printf 'existing=false\n' >> "$GITHUB_OUTPUT"
