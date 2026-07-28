#!/bin/sh

set -eu

if [ "${1:-}" != get ]; then
    exit 0
fi

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
