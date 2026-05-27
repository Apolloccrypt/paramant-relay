# R003. Multi-stage Dockerfile for the @paramant/core binding

Date: 2026-05-27
Status: Accepted

## Context

M5b integrates the `@paramant/core` NAPI binding (Rust) into the relay's Node.js
docker image. Production runs on `node:22-alpine` (musl libc); the binding must be
built for the exact runtime libc. Three strategies were considered:

- A: multi-stage Dockerfile (Rust+Alpine builder stage, then runtime stage).
- B: a prebuilt musl tarball, COPY plus npm install.
- C: switch the runtime to debian-slim (glibc).

## Decision

Multi-stage Dockerfile. paramant-core is git-cloned in a builder stage pinned to a
specific commit via the `PARAMANT_CORE_COMMIT` build-arg, built for musl with
`-C target-feature=-crt-static` (musl defaults to static linking, which cannot
produce the required cdylib), and the resulting `.so` is copied into the runtime
stage as `@paramant/core`.

## Consequences

- Reproducible builds: the same commit always produces the same binding.
- Native libc match: no glibc-vs-musl drift.
- No prebuilt-artifact management.
- Trade-off: the first build is slow (about 5 minutes, compiling liboqs and
  aws-lc-rs); incremental builds are cached via docker layers.

## Alternatives

- B prebuilt tarball: rejected; requires per-version tarball management and
  onboarding overhead.
- C debian-slim runtime: rejected; changes the base OS of all containers for a
  crypto-swap reason. Base-image hardening belongs in a separate decision.
