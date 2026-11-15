#!/usr/bin/env bash
# Exercise the npm archive under a released arm64 Node that enforces library validation.
set -euo pipefail

archive=${1:?expected a packed npm release}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"

# Pin the host as well as the package under test. Only the Node executable is needed.
curl --fail --location --retry 3 --output "$work/desktop.zip" \
  https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-arm64-26.1029.61003.zip
(cd "$work" && echo '43def98099e94837f07b976be98138251859ae58831d057d5483e8b20906a9a4  desktop.zip' | shasum -a 256 --check)
unzip -p "$work/desktop.zip" 'ChatGPT.app/Contents/Resources/cua_node/bin/node' > "$work/node"
chmod +x "$work/node"

CODEX_MCP_NODE_PATH="$work/node" "$work/node" \
  sdk/typescript/scripts/fixtures/package-review-items.mjs "$work/package"

# The arm64 host exercises its own slice. Check the other shipped addon has
# the same Developer ID signature before publishing the universal package.
team=$(codesign -dv --verbose=4 "$work/node" 2>&1 | sed -n 's/^TeamIdentifier=//p')
for arch in arm64 x64; do
  codesign --verify --strict -R="anchor apple generic and certificate leaf[subject.OU] = \"$team\"" \
    "$work/package/_bundled_plugin/mcp/native/darwin-$arch/unix.node"
done
