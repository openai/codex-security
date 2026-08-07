#!/bin/sh

set -eu

if [ "${1:-}" != get ]; then
    exit 0
fi

# Refuse to hand out credentials when Git is operating inside a submodule.
# Git sets GIT_DIR to a path under the parent repository's .git/modules/
# directory during submodule operations, which distinguishes a submodule
# fetch from a top-level clone. Without this guard a malicious .gitmodules
# inside a scanned repository could point to another repo on the same host
# and receive the scan credential token.
case "${GIT_DIR:-}" in
    */.git/modules/*|*.git/modules/*)
        exit 0
        ;;
esac

protocol=
host=

while IFS= read -r line; do
    case "$line" in
        protocol=*) protocol=${line#protocol=} ;;
        host=*) host=${line#host=} ;;
        "") break ;;
    esac
done

if [ "$protocol" != https ] \
    || [ "$host" != "${CODEX_SECURITY_GIT_HOST:-github.com}" ]; then
    exit 0
fi

token=${GH_TOKEN:-${GITHUB_TOKEN:-}}

if [ -z "$token" ]; then
    exit 0
fi

printf '%s\n' 'username=x-access-token' "password=$token"
