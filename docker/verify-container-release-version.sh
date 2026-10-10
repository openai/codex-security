#!/bin/sh

set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf '%s\n' 'Usage: verify-container-release-version.sh PACKAGE_ENDPOINT VERSION [VERIFIED_DIGEST]' >&2
    exit 2
fi

endpoint=$1
version=$2
verified_digest=${3:-}

if ! versions="$(gh api --paginate "$endpoint/versions?per_page=100")"; then
    printf '%s\n' "::error::Unable to verify whether container version $version already exists; refusing to publish." >&2
    exit 1
fi

if ! version_status="$(
    printf '%s\n' "$versions" |
        jq --raw-output --slurp --arg version "$version" --arg digest "$verified_digest" '
            def stable_version:
                select(test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) |
                split(".") | map(tonumber);
            if length == 0 or any(.[]; type != "array") then
                error("Container package versions must contain at least one JSON array.")
            else
                [.[][] | select(any(.metadata.container.tags[]?; . == $version))] as $existing |
                [.[][] | select(any(.metadata.container.tags[]?; . == "latest"))] as $latest |
                any(.[][]; any(.metadata.container.tags[]?;
                    stable_version > ($version | stable_version))) as $backfill |
                if ($existing | length) > 0 and (
                    ($digest | test("^sha256:[a-fA-F0-9]{64}$") | not) or
                    any($existing[]; .name != $digest) or
                    ($backfill | not) and (
                        ($latest | length) == 0 or any($latest[]; .name != $digest)
                    )
                ) then "published"
                elif $backfill then "backfill"
                else "latest"
                end
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
        printf '%s\n' "::error::Container version $version already exists; retries require a matching verified digest and, unless a newer stable version exists, a matching latest tag." >&2
        exit 1
        ;;
    *)
        printf '%s\n' "::error::Invalid container version lookup result for $version; refusing to publish." >&2
        exit 1
        ;;
esac
