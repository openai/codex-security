#!/bin/sh

set -eu

is_bulk_scan() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            bulk-scan)
                return 0
                ;;
            --format|--filter-output|--token-limit|--token-offset|--model)
                if [ "$#" -lt 2 ]; then
                    return 1
                fi
                shift 2
                ;;
            --*=*|--full-output|--token-count|-*)
                shift
                ;;
            *)
                return 1
                ;;
        esac
    done

    return 1
}

has_bulk_scan_input() {
    while [ "${1:-}" != bulk-scan ]; do
        case "${1:-}" in
            --format|--filter-output|--token-limit|--token-offset|--model)
                shift 2
                ;;
            --*=*|--full-output|--token-count|-*)
                shift
                ;;
            *)
                return 1
                ;;
        esac
    done

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

if is_bulk_scan "$@"; then
    if ! has_bulk_scan_input "$@"; then
        printf '%s\n' 'codex-security: bulk-scan requires a repository CSV; interactive discovery is not supported in this image.' >&2
        exit 2
    fi

    remaining=$#
    inserted_override=0
    while [ "$remaining" -gt 0 ]; do
        argument=$1
        shift
        remaining=$((remaining - 1))

        if [ "$argument" = -- ]; then
            set -- "$@" --codex features.use_legacy_landlock=true --
            while [ "$remaining" -gt 0 ]; do
                argument=$1
                shift
                set -- "$@" "$argument"
                remaining=$((remaining - 1))
            done
            inserted_override=1
            break
        fi

        set -- "$@" "$argument"
    done

    if [ "$inserted_override" -eq 0 ]; then
        set -- "$@" --codex features.use_legacy_landlock=true
    fi
fi

if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    git_host=${CODEX_SECURITY_GIT_HOST:-github.com}
    git_hostname=$git_host

    case "$git_host" in
        *:*:*)
            printf '%s\n' 'codex-security: CODEX_SECURITY_GIT_HOST must be a valid hostname.' >&2
            exit 2
            ;;
        *:*)
            git_hostname=${git_host%:*}
            git_port=${git_host##*:}
            case "$git_port" in
                ""|*[!0-9]*)
                    printf '%s\n' 'codex-security: CODEX_SECURITY_GIT_HOST must be a valid hostname.' >&2
                    exit 2
                    ;;
            esac
            if [ "${#git_port}" -gt 5 ] || [ "$git_port" -lt 1 ] || [ "$git_port" -gt 65535 ]; then
                printf '%s\n' 'codex-security: CODEX_SECURITY_GIT_HOST must be a valid hostname.' >&2
                exit 2
            fi
            ;;
    esac

    case "$git_hostname" in
        ""|.*|*..*|*.|*[!A-Za-z0-9.-]*)
            printf '%s\n' 'codex-security: CODEX_SECURITY_GIT_HOST must be a valid hostname.' >&2
            exit 2
            ;;
    esac

    git_hostname=$(printf '%s' "$git_hostname" | LC_ALL=C tr '[:upper:]' '[:lower:]')
    if [ "$git_host" != "$git_hostname" ]; then
        case "$git_host" in
            *:*) git_host="${git_hostname}:${git_port}" ;;
            *) git_host=$git_hostname ;;
        esac
    fi

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
    export "GIT_CONFIG_VALUE_${git_config_count}=git@${git_hostname}:"
    export GIT_CONFIG_COUNT=$((git_config_count + 1))
fi

exec codex-security "$@"
