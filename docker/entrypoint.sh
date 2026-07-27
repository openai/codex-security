#!/bin/sh

set -eu

has_bulk_scan_input() {
    shift

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --help|-h|--schema|--llms|--llms-full)
                return 0
                ;;
            --workers|--max-attempts|--mode|--model|--output-dir|--plugin-path|--python|--codex|--format|--filter-output|--token-limit|--token-offset)
                if [ "$#" -lt 2 ]; then
                    return 1
                fi
                shift 2
                ;;
            --)
                shift
                if [ "$#" -gt 0 ]; then
                    return 0
                fi
                return 1
                ;;
            --*=*|--full-output|--token-count|-*)
                shift
                ;;
            *)
                return 0
                ;;
        esac
    done

    return 1
}

if [ "${1:-}" = bulk-scan ]; then
    if ! has_bulk_scan_input "$@"; then
        printf '%s\n' 'codex-security: bulk-scan requires a repository CSV; interactive discovery is not supported in this image.' >&2
        exit 2
    fi

    set -- "$@" --codex features.use_legacy_landlock=true
fi

if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    git_host=${CODEX_SECURITY_GIT_HOST:-github.com}

    case "$git_host" in
        ""|.*|*..*|*.|*[!A-Za-z0-9.-]*)
            printf '%s\n' 'codex-security: CODEX_SECURITY_GIT_HOST must be a valid hostname.' >&2
            exit 2
            ;;
    esac

    git_config_count=${GIT_CONFIG_COUNT:-0}

    case "$git_config_count" in
        0|[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])
            ;;
        *)
            printf '%s\n' 'codex-security: GIT_CONFIG_COUNT must be an integer from 0 to 128.' >&2
            exit 2
            ;;
    esac

    export "GIT_CONFIG_KEY_${git_config_count}=credential.https://${git_host}.helper"
    export "GIT_CONFIG_VALUE_${git_config_count}=/usr/local/bin/codex-security-git-credential"
    git_config_count=$((git_config_count + 1))
    export "GIT_CONFIG_KEY_${git_config_count}=url.https://${git_host}/.insteadOf"
    export "GIT_CONFIG_VALUE_${git_config_count}=git@${git_host}:"
    export GIT_CONFIG_COUNT=$((git_config_count + 1))
fi

exec codex-security "$@"
