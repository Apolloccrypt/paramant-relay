# ── Stage 1: build ──────────────────────────────────────────────────────────
# Build tools (python3, make, g++) are required only to compile argon2 native
# bindings. They are NOT present in the final runtime image.
FROM node:22-alpine3.21 AS build

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
# Lean image: no build tools, no npm, no compilers — only the relay and its deps.
FROM node:22-alpine3.21

LABEL org.opencontainers.image.title="paramant-relay" \
      org.opencontainers.image.version="2.4.5" \
      org.opencontainers.image.description="Post-quantum encrypted file relay — RAM-only, burn-on-read" \
      org.opencontainers.image.source="https://github.com/Apolloccrypt/paramant-relay" \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app

# Copy only compiled node_modules from build stage — no build tools follow
COPY --from=build /app/node_modules ./node_modules
COPY relay.js ./

# Non-root user — relay never needs root after install
RUN addgroup -S relay && adduser -S relay -G relay \
    && mkdir -p /data && chown relay:relay /data

USER relay

# All relay containers listen on 3000 internally; host port mapping is set per-service in docker-compose.yml
EXPOSE 3000

# wget is built into alpine; curl is not
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-3000}/health || exit 1

CMD ["node", "relay.js"]
