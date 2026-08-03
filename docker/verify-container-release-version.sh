#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: verify-container-release-version.sh PACKAGE_ENDPOINT VERSION' >&2
    exit 2
fi

endpoint=$1
version=$2

if ! versions="$(gh api --paginate "$endpoint/versions?per_page=100")"; then
    printf '%s\n' "::error::Unable to verify whether container version $version already exists; refusing to publish." >&2
    exit 1
fi

if ! already_published="$(
    printf '%s\n' "$versions" |
        jq --slurp --arg version "$version" '
            if length == 0 or any(.[]; type != "array") then
                error("Container package versions must contain at least one JSON array.")
            else
                any(.[]; any(.[]; any(.metadata.container.tags[]?; . == $version)))
            end
        '
)"; then
    printf '%s\n' "::error::Unable to validate existing container versions for $version; refusing to publish." >&2
    exit 1
fi

case "$already_published" in
    false)
        exit 0
        ;;
    true)
        printf '%s\n' "::error::Container version $version already exists; stable version tags cannot be overwritten." >&2
        exit 1
        ;;
    *)
        printf '%s\n' "::error::Invalid container version lookup result for $version; refusing to publish." >&2
        exit 1
        ;;
esac
