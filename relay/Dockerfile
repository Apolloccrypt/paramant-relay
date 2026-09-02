# ── Stage 1: build ──────────────────────────────────────────────────────────
# Build tools (python3, make, g++) are required only to compile argon2 native
# bindings. They are NOT present in the final runtime image.
# Pinned by digest. Tag node:24-alpine3.24 resolved 2026-09-02 (Node 24.20.0,
# Alpine 3.24.1). Node 24 is the newest LTS line; the digest previously pinned
# here was node:25-alpine3.21, and Node 25 went end-of-life, so the image that
# production would get on its next deploy ran an unsupported runtime. Alpine
# 3.24 also matches the rust:1.98-alpine builder stage below, so the musl the
# .node binding is compiled against is the musl it is loaded on.
# -- @paramant/core binding builder ------------------------------------------
# Compiles the paramant-core-node napi binding for musl, so it loads inside the
# node:24-alpine runtime (a glibc build would not). Pinned to a paramant-core
# commit for reproducibility; bump PARAMANT_CORE_COMMIT when upgrading.
#
# rust:1.98-alpine (Alpine 3.24, libclang 22). Earlier bumps past 1.95 (#222,
# #313) failed here with E0609 "no field `alg_version`/… on `OQS_SIG`": bindgen
# 0.71 turns the forward-declared OQS_SIG into an opaque struct under libclang
# 22. paramant-core now builds oqs-sys with bindgen 0.72 (oqs 0.11.0, liboqs
# 0.13.0), which resolves it. NOTE: CI's crypto suite builds on ubuntu/glibc,
# not via this musl Dockerfile; paramant-core's `musl-node-binding` job pins
# the same digest, and any base bump must still be verified by an image build.
FROM rust:1.98-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS paramant-core-binding

RUN apk add --no-cache musl-dev gcc g++ make cmake ninja clang clang-dev llvm-dev perl nasm git bash
ENV LIBCLANG_PATH=/usr/lib
# musl defaults to static linking, which cannot produce a cdylib; link
# dynamically against musl libc so the .node addon builds and loads in the
# (also-musl) node:24-alpine runtime.
ENV RUSTFLAGS="-C target-feature=-crt-static"

ARG PARAMANT_CORE_COMMIT=b90b3c52af5c3c30053766bfa108924aff4f9eec
WORKDIR /build
RUN git clone https://github.com/Apolloccrypt/paramant-core.git \
 && cd paramant-core && git checkout "${PARAMANT_CORE_COMMIT}" \
 # --locked: build against paramant-core's committed Cargo.lock (oqs 0.11.0 +
 # vendored liboqs 0.13.0) so a transitive bump can't silently drift the crypto
 # build. paramant-core's CI has a musl job pinned to this same base that proves
 # the lockfile builds here; keep the two in lockstep when bumping the base.
 && cargo build --locked --release -p paramant-core-node \
 && mkdir -p /pkg \
 && cp target/release/libparamant_core_node.so /pkg/paramant-core.node \
 && printf '{\n  "name": "@paramant/core",\n  "version": "0.5.0-alpha.1",\n  "main": "paramant-core.node",\n  "files": ["paramant-core.node"]\n}\n' > /pkg/package.json

FROM node:24-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS build

RUN apk add --no-cache python3 make g++

WORKDIR /app
COPY package.json package-lock.json ./
# Strip the @paramant/core dev file-link (resolvable only in a sibling checkout);
# the binding is installed from the paramant-core-binding stage in the runtime.
# Strip it from BOTH package.json and package-lock.json so the two stay in sync
# and `npm ci` (which fails on any drift) accepts the lockfile. Every other
# dependency then installs at its exact lockfile-pinned version (no ^ re-resolve).
RUN node -e "const fs=require('fs');for(const f of ['package.json','package-lock.json']){const j=JSON.parse(fs.readFileSync(f));if(j.dependencies)delete j.dependencies['@paramant/core'];if(j.packages){if(j.packages['']&&j.packages[''].dependencies)delete j.packages[''].dependencies['@paramant/core'];delete j.packages['node_modules/@paramant/core'];delete j.packages['../../paramant-core/crates/paramant-core-node'];}fs.writeFileSync(f,JSON.stringify(j,null,2));}" \
 && npm ci --omit=dev && npm cache clean --force

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
# Lean image: no build tools, no npm, no compilers — only the relay and its deps.
FROM node:24-alpine3.24@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf

# Image version. Default matches relay/package.json; CI passes it explicitly as
# a build-arg so a tagged build labels itself with the tag it was cut from.
# tests/version-consistency.test.mjs fails if this default and package.json drift.
ARG IMAGE_VERSION=3.1.0

LABEL org.opencontainers.image.title="paramant-relay" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.description="Post-quantum encrypted file relay — RAM-only, burn-on-read" \
      org.opencontainers.image.source="https://github.com/Apolloccrypt/paramant-relay" \
      org.opencontainers.image.licenses="BUSL-1.1"

WORKDIR /app

# Copy only compiled node_modules from build stage — no build tools follow
COPY --from=build /app/node_modules ./node_modules
# relay.js reads its VERSION from here, so package.json is part of the runtime
# image, not just the build stage.
COPY package.json ./
COPY relay.js ./
COPY parasign.js ./
COPY envelope.js ./
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
