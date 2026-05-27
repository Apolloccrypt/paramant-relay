# ── Stage 1: build ──────────────────────────────────────────────────────────
# Build tools (python3, make, g++) are required only to compile argon2 native
# bindings. They are NOT present in the final runtime image.
# Pinned by digest — tag node:22-alpine3.21 resolved 2026-04-24
# -- @paramant/core binding builder ------------------------------------------
# Compiles the paramant-core-node napi binding for musl, so it loads inside the
# node:22-alpine runtime (a glibc build would not). Pinned to a paramant-core
# commit for reproducibility; bump PARAMANT_CORE_COMMIT when upgrading.
FROM rust:1.95-alpine AS paramant-core-binding

RUN apk add --no-cache musl-dev gcc g++ make cmake ninja clang clang-dev llvm-dev perl nasm git bash
ENV LIBCLANG_PATH=/usr/lib
# musl defaults to static linking, which cannot produce a cdylib; link
# dynamically against musl libc so the .node addon builds and loads in the
# (also-musl) node:22-alpine runtime.
ENV RUSTFLAGS="-C target-feature=-crt-static"

ARG PARAMANT_CORE_COMMIT=dc454d47880ab54e6f1483433580abab894b854e
WORKDIR /build
RUN git clone https://github.com/Apolloccrypt/paramant-core.git \
 && cd paramant-core && git checkout "${PARAMANT_CORE_COMMIT}" \
 && cargo build --release -p paramant-core-node \
 && mkdir -p /pkg \
 && cp target/release/libparamant_core_node.so /pkg/paramant-core.node \
 && printf '{\n  "name": "@paramant/core",\n  "version": "0.5.0-alpha.1",\n  "main": "paramant-core.node",\n  "files": ["paramant-core.node"]\n}\n' > /pkg/package.json

FROM node:22-alpine3.21@sha256:af8023ec879993821f6d5b21382ed915622a1b0f1cc03dbeb6804afaf01f8885 AS build

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json ./
# Strip the @paramant/core dev file-link (resolvable only in a sibling checkout);
# the binding is installed from the paramant-core-binding stage in the runtime.
RUN node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json'));if(p.dependencies)delete p.dependencies['@paramant/core'];fs.writeFileSync('package.json',JSON.stringify(p,null,2))" \
 && npm install --omit=dev && npm cache clean --force

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
# Lean image: no build tools, no npm, no compilers — only the relay and its deps.
FROM node:22-alpine3.21@sha256:af8023ec879993821f6d5b21382ed915622a1b0f1cc03dbeb6804afaf01f8885

LABEL org.opencontainers.image.title="paramant-relay" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.description="Post-quantum encrypted file relay — RAM-only, burn-on-read" \
      org.opencontainers.image.source="https://github.com/Apolloccrypt/paramant-relay" \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app

# Copy only compiled node_modules from build stage — no build tools follow
COPY --from=build /app/node_modules ./node_modules
COPY relay.js ./
COPY lib/ ./lib/
COPY crypto/ ./crypto/

# Optional static frontend serving (SERVE_FRONTEND=true, default off).
# frontend/ lives at the repo root, outside this image's build context (./relay),
# so it is provided at runtime as a read-only bind mount in docker-compose.yml
# (./frontend -> /app/frontend:ro), not COPY'd here. This ENV is only the default
# root the relay reads; production keeps SERVE_FRONTEND=false and uses nginx.
ENV FRONTEND_ROOT=/app/frontend

# Non-root user — relay never needs root after install
# Install @paramant/core (the napi binding built for musl in the builder stage)
# by placing it directly in node_modules -- real files, no npm symlink.
COPY --from=paramant-core-binding /pkg /app/node_modules/@paramant/core

RUN addgroup -S relay && adduser -S relay -G relay \
    && mkdir -p /data && chown relay:relay /data

USER relay

# All relay containers listen on 3000 internally; host port mapping is set per-service in docker-compose.yml
EXPOSE 3000

# wget is built into alpine; curl is not
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT:-3000}/health || exit 1

CMD ["node", "relay.js"]
