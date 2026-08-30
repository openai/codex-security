#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: verify-container-release-source.sh VERSION COMMIT' >&2
    exit 2
fi

version=$1
expected_commit=$2
release_tag="npm-v$version"

if ! release_commit="$(git rev-parse --verify "refs/tags/$release_tag^{commit}")"; then
    printf '%s\n' "::error::Create the npm release $release_tag before publishing its container." >&2
    exit 1
fi

if [ "$release_commit" != "$expected_commit" ]; then
    printf '%s\n' "::error::Container version $version must use the same commit as $release_tag. Create container-v$version at that release commit if main has advanced." >&2
    exit 1
fi
