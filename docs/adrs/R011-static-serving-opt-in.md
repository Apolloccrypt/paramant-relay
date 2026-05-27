# R011. Static frontend serving: opt-in via SERVE_FRONTEND

Date: 2026-05-27

Status: Accepted

Relates to: R005 (plug-and-play onboarding), R010 (plug-and-play package formats)

## Context

Production (paramant.app) runs nginx as a reverse proxy: nginx serves the
static `frontend/` (from a webroot) and proxies `/v2/*` + `/api/*` to the relay
containers. That works well at production scale.

A fresh self-host install has no such nginx config. The relay image
(`relay/Dockerfile`) copies only `relay.js`, `lib/` and `crypto/` -- not
`frontend/` -- and the relay had no static-file handler. So in a clean self-host
install, `GET /setup` (the M11 onboarding wizard delivered in PR #56) returned
nothing useful: the backend endpoints (`/v2/setup/apply`, `/v2/health/deep`)
worked, but the HTML/JS to drive them was unreachable until the operator stood
up their own webserver. That defeats the plug-and-play goal of R005: an operator
should not need to understand nginx to get a working install.

This is the #1 follow-up flagged in the PR #56 report.

## Decision

The relay gains an **opt-in** static-file handler, activated by the
`SERVE_FRONTEND=true` environment variable. Default is `false`, so production is
unchanged (nginx keeps serving the frontend; the relay never intercepts).

- Implementation lives in `relay/lib/static-serve.js` (a small, unit-tested
  module: `createStaticHandler({ serveFrontend, frontendRoot, log })`), wired
  into `relay.js` early in the request handler -- after CORS/security headers and
  the OPTIONS short-circuit, but before the relay-mode gate and the API routes,
  so frontend paths are not rejected by `modeAllows`.
- `install.sh` writes `SERVE_FRONTEND=true` into the generated `.env` for
  plug-and-play installs; an operator running their own webserver sets it back to
  `false`.
- The frontend files are provided to the container as a **read-only bind mount**
  in `docker-compose.yml` (`./frontend -> /app/frontend:ro`), NOT copied into the
  image. Reason: each relay service builds with context `./relay`, and
  `frontend/` lives at the repo root -- outside that build context -- so a
  `COPY frontend/` in `relay/Dockerfile` is not possible without reworking the
  build context and every `COPY` path (high blast radius, affects production
  image builds). The bind mount is read-only, inert when `SERVE_FRONTEND=false`,
  and matches the realistic install path (install.sh clones the repo and runs
  `docker compose up`, so `frontend/` is present on the host).

Path rules (in `static-serve.js`):
- `/v2/*`, `/api/*`, `/ct/*`, `/ct`, `/health`, `/metrics`: never intercepted.
- Only `GET`/`HEAD`; other methods fall through.
- `/` -> `index.html`; `/<path>/` -> `<path>/index.html`;
  `/<name>` (no extension) -> tries `<name>.html` (so `/setup` -> `setup.html`).
- MIME by extension; `.html` is `no-cache`, other assets `max-age=300`;
  `X-Content-Type-Options: nosniff` always.
- Path traversal (`..`) and null bytes -> 400. The resolved path must stay
  within `FRONTEND_ROOT` or it is 403. The handler never writes to disk.

## Consequences

- Plug-and-play installs serve `/setup`, `/dashboard`, etc with no external
  webserver -- single-container works for RasPi / small VPS.
- Production is unchanged: `SERVE_FRONTEND` defaults to `false`; the read-only
  mount is present but unused (the handler returns early).
- The published bare image does not embed `frontend/`; serving requires the
  repo-provided bind mount (i.e. the `docker compose` install path). A future
  change could embed the frontend by moving the relay build context to the repo
  root, if a repo-less `docker run` self-serve path is ever required.
- Multi-container (nginx + relay) remains the recommended production topology for
  scale, caching and TLS.

## Alternatives considered

- **COPY frontend/ into the image** (the original PR #56 follow-up sketch):
  rejected for now -- impossible without changing the `./relay` build context and
  every `COPY` path, which risks the production image build (e.g. `COPY
  package.json` would resolve to the root manifest). Not validatable without a
  full image build.
- **Serve from a separate static-only container**: rejected -- overkill for
  plug-and-play; reintroduces the multi-container requirement R005 wants to avoid.
- **Embed the frontend in the JS bundle at build time**: rejected -- loses fast
  frontend iteration and bloats the relay.
- **External CDN**: rejected per EU-sovereignty (production audit findings
  M-05/M-06: no third-party origins).
