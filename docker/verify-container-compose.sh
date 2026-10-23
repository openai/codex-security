#!/usr/bin/env bash

set -euo pipefail

# Resolve the environment on the host; these checks need no running container.
for compose_file in compose.yaml compose.runner.yaml; do
  endpoint="https://embeddings.example.com/custom/v1/embeddings?api-version=synthetic"
  CODEX_SECURITY_EMBEDDINGS_URL="$endpoint" \
    docker compose --env-file /dev/null -f "$compose_file" config --format json |
    jq --exit-status --arg endpoint "$endpoint" \
      '.services["codex-security"].environment.CODEX_SECURITY_EMBEDDINGS_URL == $endpoint' > /dev/null

  env -u CODEX_SECURITY_EMBEDDINGS_URL \
    docker compose --env-file /dev/null -f "$compose_file" config --format json |
    jq --exit-status \
      '.services["codex-security"].environment.CODEX_SECURITY_EMBEDDINGS_URL == null' > /dev/null

  CODEX_SECURITY_EMBEDDINGS_URL="" \
    docker compose --env-file /dev/null -f "$compose_file" config --format json |
    jq --exit-status \
      '.services["codex-security"].environment.CODEX_SECURITY_EMBEDDINGS_URL == ""' > /dev/null
done

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
