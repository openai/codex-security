# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS package

WORKDIR /build/sdk/typescript

COPY sdk/typescript/package.json sdk/typescript/pnpm-lock.yaml ./

RUN corepack enable \
    && corepack prepare "$(node --print 'require("./package.json").packageManager')" --activate \
    && pnpm install --frozen-lockfile

COPY sdk/typescript/ ./

RUN pnpm run types \
    && pnpm run build \
    && pnpm pack --pack-destination /build/package \
    && node scripts/check-package.mjs /build/package/*.tgz

FROM node:22-bookworm-slim

LABEL org.opencontainers.image.title="Codex Security" \
      org.opencontainers.image.description="Noninteractive, resumable Codex Security CSV repository scans" \
      org.opencontainers.image.source="https://github.com/openai/codex-security"

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        git \
        openssh-client \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=package /build/package/ /tmp/codex-security-package/

RUN npm install --global --include=optional --no-audit --no-fund \
        /tmp/codex-security-package/*.tgz \
    && codex-security --version \
    && codex-security bulk-scan --help \
    && rm -rf /tmp/codex-security-package \
    && npm cache clean --force

COPY --chmod=0555 docker/entrypoint.sh /usr/local/bin/codex-security-entrypoint
COPY --chmod=0555 docker/git-credential.sh /usr/local/bin/codex-security-git-credential

RUN groupadd --gid 10001 codex-security \
    && useradd --uid 10001 --gid 10001 --no-create-home codex-security \
    && mkdir -p /input /output /state \
    && chown 10001:10001 /output /state

ENV CODEX_HOME=/state \
    CODEX_SECURITY_STATE_DIR=/output/.codex-security-state \
    GIT_TERMINAL_PROMPT=0 \
    HOME=/state \
    PYTHON=/usr/bin/python3

USER 10001:10001
WORKDIR /state

ENTRYPOINT ["/usr/local/bin/codex-security-entrypoint"]
CMD ["--help"]
