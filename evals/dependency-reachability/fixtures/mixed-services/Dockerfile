FROM node:22-alpine
WORKDIR /app
ARG SERVICE
COPY ${SERVICE}/package*.json ./
RUN npm ci --omit=dev
COPY server.mjs .
USER node
CMD ["node", "server.mjs"]
