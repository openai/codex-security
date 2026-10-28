#!/usr/bin/env bash
# Run from the repo root with the verified image inventory, scanner version and tagged commit.
set -euo pipefail
inventory=$1 version=$2 release_sha=$3
verifier=$PWD/sdk/typescript/scripts/release-automation.mjs
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export npm_config_registry=https://registry.npmjs.org/

# npm ci checked this lock integrity while staging the image. Verify the very
# same archive against the signed provenance of the upstream scanner release.
integrity=$(jq -er --arg version "$version" '.installed_npm[] |
  select(.path == "node_modules/@openai/codex-security" and .version == $version) | .integrity' "$inventory")
cp docker/wolfi/payload/{package.json,package-lock.json} "$work/"
cd "$work"
npm ci --omit=optional --ignore-scripts --no-audit --no-fund
archive=$(npm pack --ignore-scripts --json "@openai/codex-security@$version" |
  jq -er --arg integrity "$integrity" '.[0] | if .integrity == $integrity then .filename
    else error("npm archive SHA-512 differs from the verified image inventory") end')
npm audit signatures --json --include-attestations |
  node "$verifier" verify-recovered-provenance "$archive" "$version" "$release_sha" openai/codex-security
