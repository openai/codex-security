#!/bin/sh

set -eu

# Fail closed instead of silently degrading: docker/codex-security-seccomp.json
# allows mount/pivot_root/unshare/setns/clone unconditionally, on the assumption
# (previously only a comment) that the caller runs this image with
# --cap-drop ALL --security-opt no-new-privileges (as compose.yaml does). If
# someone runs the raw image without that contract, refuse to start rather than
# let the seccomp profile's namespace/mount allowlist apply with capabilities
# or new-privilege escalation still available.
caps=$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)
if [ "$caps" != "0000000000000000" ]; then
    printf '%s\n' "codex-security: refusing to start without --cap-drop ALL (effective capabilities are not empty: ${caps:-unknown})." >&2
    exit 3
fi
nnp=$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status 2>/dev/null || true)
if [ "$nnp" != "1" ]; then
    printf '%s\n' "codex-security: refusing to start without --security-opt no-new-privileges." >&2
    exit 3
fi

if [ "${1:-}" = bulk-scan ]; then
    case "${2:-}" in
        --help|-h)
            ;;
        ""|-*)
            printf '%s\n' 'codex-security: bulk-scan requires a repository CSV; interactive discovery is not supported in this image.' >&2
            exit 2
            ;;
        *)
            if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
                restricted_user_namespaces=
                IFS= read -r restricted_user_namespaces < /proc/sys/kernel/apparmor_restrict_unprivileged_userns ||
                    true
                if [ "$restricted_user_namespaces" = 1 ]; then
                    apparmor_profile=
                    if [ -r /proc/self/attr/current ]; then
                        IFS= read -r apparmor_profile < /proc/self/attr/current || true
                    fi
                    if [ "$apparmor_profile" != 'codex-security-container (enforce)' ]; then
                        landlock_override=
                        expects_codex_override=
                        for argument do
                            if [ "$expects_codex_override" = yes ]; then
                                case "$argument" in
                                    features.use_legacy_landlock=true)
                                        landlock_override=enabled
                                        ;;
                                    features.use_legacy_landlock=*)
                                        printf '%s\n' 'codex-security: restricted Ubuntu hosts require --codex features.use_legacy_landlock=true.' >&2
                                        exit 2
                                        ;;
                                esac
                                expects_codex_override=
                            elif [ "$argument" = --codex ]; then
                                expects_codex_override=yes
                            else
                                case "$argument" in
                                    --codex=features.use_legacy_landlock=true)
                                        landlock_override=enabled
                                        ;;
                                    --codex=features.use_legacy_landlock=*)
                                        printf '%s\n' 'codex-security: restricted Ubuntu hosts require --codex features.use_legacy_landlock=true.' >&2
                                        exit 2
                                        ;;
                                esac
                            fi
                        done

                        if [ "$landlock_override" != enabled ]; then
                            set -- "$@" --codex features.use_legacy_landlock=true
                        fi
                    fi
                fi
            fi
            ;;
    esac
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
