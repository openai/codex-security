#!/bin/sh

set -eu

# Install the development dependencies for the Node.js and Python workflows.
# Shared by .devcontainer/devcontainer.json and .ona/automations.yml so editors
# and Ona environments install the same toolchain.

cd "$(dirname "$0")/.."

# Install the pnpm release pinned by packageManager in package.json. Node ships
# a corepack shim for pnpm, so installing it with npm collides with that shim.
COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_ENABLE_DOWNLOAD_PROMPT
corepack install

# Keep bun aligned with the version pinned in .github/workflows/node-ci.yml.
npm install --global bun@1.3.14 --no-audit --no-fund

if ! command -v rg >/dev/null 2>&1; then
    # Refresh only the Ubuntu sources. Dev container features add APT sources of
    # their own, and apt-get update exits 100 when any configured source fails
    # validation, which would stop this script before ripgrep installs.
    sudo apt-get update \
        -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources \
        -o Dir::Etc::sourceparts=-
    sudo apt-get install --yes ripgrep
fi

pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
python -m pip install --disable-pip-version-check --no-input -e 'plugins/codex-security[test]'
