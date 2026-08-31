# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS package

RUN apt-get update \
    && apt-get install --no-install-recommends --yes python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/sdk/typescript

COPY package.json /build/package.json
COPY sdk/typescript/package.json sdk/typescript/pnpm-lock.yaml sdk/typescript/pnpm-workspace.yaml ./
COPY plugins/codex-security/mcp-app/package.json plugins/codex-security/mcp-app/pnpm-lock.yaml plugins/codex-security/mcp-app/pnpm-workspace.yaml /build/plugins/codex-security/mcp-app/

RUN corepack enable \
    && corepack prepare "$(node --print 'require("/build/package.json").packageManager')" --activate \
    && pnpm install --frozen-lockfile \
    && pnpm --dir /build/plugins/codex-security/mcp-app install --frozen-lockfile

COPY sdk/typescript/ ./
COPY plugins/codex-security/ /build/plugins/codex-security/

RUN pnpm run types \
    && pnpm pack --pack-destination /build/package \
    && node scripts/check-package.mjs /build/package/*.tgz

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS scanner

LABEL org.opencontainers.image.title="Codex Security" \
      org.opencontainers.image.description="Codex Security scanner and findings API" \
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
