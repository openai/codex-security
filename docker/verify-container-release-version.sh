#!/bin/sh

set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf '%s\n' 'Usage: verify-container-release-version.sh PACKAGE_ENDPOINT VERSION [VERIFIED_DIGEST]' >&2
    exit 2
fi

endpoint=$1
version=$2
verified_digest=${3:-}
stable='^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$'

if ! versions="$(gh api --paginate "$endpoint/versions?per_page=100")"; then
    printf '%s\n' "::error::Unable to verify whether container version $version already exists; refusing to publish." >&2
    exit 1
fi

if ! version_status="$(
    printf '%s\n' "$versions" |
        jq --raw-output --slurp --arg version "$version" --arg digest "$verified_digest" --arg sha "${RELEASE_SHA:-}" --arg stable "$stable" '
            def stable_version:
                select(test($stable)) |
                split(".") | map(tonumber);
            if length == 0 or any(.[]; type != "array") then
                error("Container package versions must contain at least one JSON array.")
            else
                [.[][] | select(any(.metadata.container.tags[]?; . == $version))] as $existing |
                [.[][] | select(any(.metadata.container.tags[]?; . == ("sha-" + $sha)))] as $source |
                any(.[][]; any(.metadata.container.tags[]?;
                    stable_version > ($version | stable_version))) as $backfill |
                if (($existing + $source) | length) > 0 and (
                    ($digest | test("^sha256:[a-fA-F0-9]{64}$") | not) or
                    any(($existing + $source)[]; .name != $digest)
                ) then "published"
                elif $backfill then "backfill"
                else
                    # An index can lose its numeric alias while it still owns latest.
                    [.[][] | .metadata.container.tags as $tags |
                        select(.name != $digest and any($tags[]?; . == "latest") and
                            (any($tags[]?; stable_version) | not))] |
                    if length == 0 then "latest" else .[].name end
                end
            end
        '
)"; then
    printf '%s\n' "::error::Unable to validate existing container versions for $version; refusing to publish." >&2
    exit 1
fi

case "$version_status" in
    sha256:*)
        if ! manifest="$(docker buildx imagetools inspect "$IMAGE@$version_status" --raw)" ||
            ! version_status="$(printf '%s\n' "$manifest" | jq -er --arg version "$version" --arg stable "$stable" '
                .annotations["org.opencontainers.image.version"] | select(test($stable)) |
                (split(".") | map(tonumber)) as $latest | ($version | split(".") | map(tonumber)) as $target |
                if $latest > $target then "backfill" elif $latest < $target then "latest" else "published" end
            ')"; then
            printf '%s\n' "::error::Unable to verify the current latest image version; refusing to promote." >&2
            exit 1
        fi
        ;;
esac

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
        printf '%s\n' "::error::Container version $version or its source tag already exists; retries require a matching verified digest." >&2
        exit 1
        ;;
    *)
        printf '%s\n' "::error::Invalid container version lookup result for $version; refusing to publish." >&2
        exit 1
        ;;
esac
