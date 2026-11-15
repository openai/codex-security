#!/bin/sh
set -eu

command_directory=$(mktemp -d)
trap 'rm -rf "$command_directory"' EXIT
printf '%s\n' '#!/bin/sh' 'printf "%s\0" "$@"' > "$command_directory/codex-security"
chmod 755 "$command_directory/codex-security"

set -- bulk-scan /input/repositories.csv --output-dir /output
PATH="$command_directory:$PATH" /usr/local/bin/codex-security-entrypoint "$@" > "$command_directory/actual"
printf '%s\0' "$@" | cmp - "$command_directory/actual"
