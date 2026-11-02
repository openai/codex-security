# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM node:26.12.1-bookworm-slim@sha256:28147155d47dc31abe0a46e0d12b59b2fb3d0a2dcc5dc65fce76a074180b16fe AS package

RUN apt-get update \
    && apt-get install --no-install-recommends --yes git python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/sdk/typescript

COPY package.json /build/package.json
COPY sdk/typescript/package.json sdk/typescript/pnpm-lock.yaml sdk/typescript/pnpm-workspace.yaml ./
COPY sdk/typescript/patches/ ./patches/
COPY plugins/codex-security/mcp-app/package.json plugins/codex-security/mcp-app/pnpm-lock.yaml plugins/codex-security/mcp-app/pnpm-workspace.yaml /build/plugins/codex-security/mcp-app/

RUN npm install --global --no-audit --no-fund corepack@0.36.0 \
    && corepack enable \
    && corepack prepare "$(node --print 'require("/build/package.json").packageManager')" --activate \
    && pnpm install --frozen-lockfile \
    && pnpm --dir /build/plugins/codex-security/mcp-app install --frozen-lockfile

COPY sdk/typescript/ ./
COPY plugins/codex-security/ /build/plugins/codex-security/

RUN pnpm run types \
    && pnpm pack --pack-destination /build/package \
    && node scripts/check-package.mjs /build/package/*.tgz

FROM node:26.12.1-bookworm-slim@sha256:28147155d47dc31abe0a46e0d12b59b2fb3d0a2dcc5dc65fce76a074180b16fe AS runtime

LABEL org.opencontainers.image.title="Codex Security" \
      org.opencontainers.image.description="Codex Security scanner" \
      org.opencontainers.image.source="https://github.com/openai/codex-security"

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        git \
        openssh-client \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0555 docker/entrypoint.sh /usr/local/bin/codex-security-entrypoint
COPY --chmod=0555 docker/git-credential.sh /usr/local/bin/codex-security-git-credential

RUN groupadd --gid 10001 codex-security \
    && useradd --uid 10001 --gid 10001 --no-create-home codex-security \
    && mkdir -p /input /output /state \
    && chown 10001:10001 /output /state

ENV CODEX_SECURITY_STATE_DIR=/output/.codex-security-state \
    GIT_TERMINAL_PROMPT=0 \
    PYTHON=/usr/bin/python3

WORKDIR /state

ENTRYPOINT ["/usr/local/bin/codex-security-entrypoint"]
CMD ["--help"]

# Release builds supply a verified npm tarball and a frozen runtime lock.
FROM runtime AS scanner-release
RUN --mount=type=bind,from=release-inputs,target=/tmp/scanner,rw \
    cd /tmp/scanner \
    && npm ci --ignore-scripts --include=optional --no-audit --no-fund \
    && node node_modules/@openai/codex/bin/codex.js --version \
    && mkdir /opt/codex-security \
    && mv node_modules /opt/codex-security/ \
    && ln -s /opt/codex-security/node_modules/.bin/codex-security /usr/local/bin/codex-security \
    && ln -s /opt/codex-security/node_modules/.bin/cs /usr/local/bin/cs \
    && npm cache clean --force
ENV HOME=/state CODEX_HOME=/state
USER 10001:10001

# Local and pull request builds package the current checkout.
FROM runtime AS scanner
COPY --from=package /build/package/ /tmp/codex-security-package/

RUN npm install --global --include=optional --no-audit --no-fund \
        /tmp/codex-security-package/*.tgz \
    && node /usr/local/lib/node_modules/@openai/codex-security/node_modules/@openai/codex/bin/codex.js --version \
    && codex-security --version \
    && codex-security bulk-scan --help \
    && rm -rf /tmp/codex-security-package \
    && npm cache clean --force
ENV HOME=/state CODEX_HOME=/state
USER 10001:10001
