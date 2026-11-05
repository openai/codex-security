FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-boto3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/mail
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY index.js ./
COPY lib/ ./lib/
COPY archive/ ./archive/
COPY preview/ ./preview/
