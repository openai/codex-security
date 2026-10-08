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

if ! already_published="$(
    printf '%s\n' "$versions" |
        jq --slurp --arg version "$version" --arg digest "$verified_digest" '
            if length == 0 or any(.[]; type != "array") then
                error("Container package versions must contain at least one JSON array.")
            else
                [.[][] | select(any(.metadata.container.tags[]?; . == $version))] as $existing |
                if ($existing | length) == 0 then false
                elif ($digest | test("^sha256:[a-fA-F0-9]{64}$")) then
                    [.[][] | select(any(.metadata.container.tags[]?; . == "latest"))] as $latest |
                    any($existing[]; .name != $digest) or
                    ($latest | length) == 0 or any($latest[]; .name != $digest)
                else true
                end
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
        printf '%s\n' "::error::Container version $version already exists; retries require both that version and latest to match the verified digest." >&2
        exit 1
        ;;
    *)
        printf '%s\n' "::error::Invalid container version lookup result for $version; refusing to publish." >&2
        exit 1
        ;;
esac
