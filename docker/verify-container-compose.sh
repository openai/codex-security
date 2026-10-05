#!/usr/bin/env bash

set -euo pipefail
mkdir -p results state
chmod 700 results state
printf 'id,repository,revision\n' > repositories.csv
CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_USER
docker compose config --quiet
docker compose run --rm codex-security --version
if output="$(docker compose run --rm codex-security 2>&1)"; then
  echo 'An empty repository CSV must not start a security scan.' >&2
  exit 1
else
  status=$?
fi
if [[ "$status" -ne 2 ]] || ! grep -Fq 'Multiscan CSV must contain at least one repository.' <<< "$output"; then
  printf 'Unexpected empty-repository scan behavior:\n%s\n' "$output" >&2
  exit 1
fi
