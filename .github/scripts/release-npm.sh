#!/usr/bin/env bash
release_npm_version=11.12.1
release_npm_prefix="$RUNNER_TEMP/codex-security-provenance-npm"
release_npm_bin="$release_npm_prefix/node_modules/.bin"

verify_release_npm() {
  if [[ "$1" != "$release_npm_bin/npm" || "$("$1" --version)" != "$release_npm_version" ]]; then
    echo "Expected npm $release_npm_version at $release_npm_bin/npm for provenance verification." >&2
    return 1
  fi
}

install_release_npm() {
  npm install --prefix "$release_npm_prefix" --ignore-scripts --no-audit --no-fund \
    --registry=https://openai.firewall.socket.dev/npm/ "npm@$release_npm_version"
  verify_release_npm "$release_npm_bin/npm"
}
