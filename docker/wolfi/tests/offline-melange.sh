#!/usr/bin/env bash
# Use as MELANGE for a build: the guest must install from the local snapshot
# even when melange itself has no route to the upstream repository.
set -euo pipefail
if [[ $1 == build ]]; then
  exec unshare --net -- "${REAL_MELANGE:-melange}" "$@"
fi
exec "${REAL_MELANGE:-melange}" "$@"
