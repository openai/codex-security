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

if ! version_status="$(
    printf '%s\n' "$versions" |
        jq --raw-output --slurp --arg version "$version" '
            def stable_version:
                select(test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) |
                split(".") | map(tonumber);
            if length == 0 or any(.[]; type != "array") then
                error("Container package versions must contain at least one JSON array.")
            elif any(.[]; any(.[]; any(.metadata.container.tags[]?; . == $version))) then
                "published"
            elif any(.[]; any(.[]; any(.metadata.container.tags[]?;
                stable_version > ($version | stable_version)))) then
                "backfill"
            else
                "latest"
            end
        '
)"; then
    printf '%s\n' "::error::Unable to validate existing container versions for $version; refusing to publish." >&2
    exit 1
fi

case "$version_status" in
    latest|backfill)
        if [ -n "${GITHUB_OUTPUT:-}" ]; then
            publish_latest=false
            if [ "$version_status" = latest ]; then
                publish_latest=true
            fi
            printf 'publish_latest=%s\n' "$publish_latest" >> "$GITHUB_OUTPUT"
        fi
        exit 0
        ;;
    published)
        printf '%s\n' "::error::Container version $version already exists; stable version tags cannot be overwritten." >&2
        exit 1
        ;;
    *)
        printf '%s\n' "::error::Invalid container version lookup result for $version; refusing to publish." >&2
        exit 1
        ;;
esac
