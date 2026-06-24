# Pinned by digest — tag node:22-alpine3.21 resolved 2026-04-24
FROM node:25-alpine3.21@sha256:32509199057d74a987fdd88cde00fdfd48ef52469adbd6bd11969fc701477761

LABEL org.opencontainers.image.title="paramant-admin" \
      org.opencontainers.image.version="1.0.0" \
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
