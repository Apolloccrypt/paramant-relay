# Pinned by digest. Tag node:24-alpine3.24 resolved 2026-09-02 (Node 24.20.0,
# Alpine 3.24.1). Node 24 is the newest LTS line; this was node:25-alpine3.21,
# and Node 25 is end-of-life. Kept in lockstep with relay/Dockerfile.
FROM node:24-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf

# See relay/Dockerfile: default matches admin/package.json, CI overrides it per
# build, and tests/version-consistency.test.mjs holds the two together.
ARG IMAGE_VERSION=3.1.0

LABEL org.opencontainers.image.title="paramant-admin" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.description="PARAMANT admin panel" \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app
# Copy the lockfile too and use `npm ci` so the build installs the exact
# versions in package-lock.json instead of re-resolving the ^ ranges on every
# rebuild (reproducible, supply-chain-pinned image).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --quiet && npm cache clean --force
COPY server.js .
COPY lib/ lib/
COPY public/ public/

# Non-root user — admin server never needs root
RUN addgroup -S admin && adduser -S admin -G admin

USER admin

EXPOSE 4200

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-4200}/api/auth/check || exit 1

CMD ["node", "server.js"]
