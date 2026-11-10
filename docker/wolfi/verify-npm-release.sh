#!/usr/bin/env bash
# Verify the release lock's scanner archive against the signed npm provenance.
set -euo pipefail
lock=$1 version=$2 release_sha=$3 archive=${4:-}
verifier=$PWD/sdk/typescript/scripts/release-automation.mjs
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export npm_config_registry=https://registry.npmjs.org/
integrity=$(jq -er --arg version "$version" '.packages["node_modules/@openai/codex-security"] | select(.version == $version) | .integrity' "$lock")
cp "$lock" "$work/package-lock.json"
jq '.packages[""]' "$lock" > "$work/package.json"
if [[ -n $archive && $archive != /* ]]; then archive=$PWD/$archive; fi
cd "$work"
npm ci --omit=optional --ignore-scripts --no-audit --no-fund
if [[ -z $archive ]]; then
  archive=$(npm pack --ignore-scripts --json "@openai/codex-security@$version" |
    jq -er --arg integrity "$integrity" '.[0] | select(.integrity == $integrity) | .filename')
fi
npm audit signatures --json --include-attestations |
  node "$verifier" verify-recovered-provenance "$archive" "$version" "$release_sha" openai/codex-security
