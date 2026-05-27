# R005. Plug-and-play onboarding approach

Date: 2026-05-27

Status: Draft

## Context

Self-hosting paramant-relay today is a developer-flow, not an
appliance-flow. First-time setup requires:

- Generating an ADMIN_TOKEN by hand (openssl rand -hex 32).
- Editing .env: roughly 15 variables are relevant for a first run
  (ADMIN_TOKEN, RELAY_MODE, sector selection, TOTP_SECRET, RESEND_API_KEY,
  USERS_FILE/USERS_JSON, PLK_KEY, TTL/audit limits, port overrides, ...).
- docker compose up.
- Creating the first API key via a CLI helper (scripts/paramant-key-add.sh)
  or an authenticated admin call (POST /api/request-key). There is no
  scripts/paramant-admin.py despite older docs referring to one.
- Enrolling admin TOTP by typing an otpauth:// URI printed by install.sh
  into an authenticator app.

The installers already do a lot: install.sh (458 lines) and
frontend/install-pi.sh (379 lines, Raspberry Pi edition) install Docker +
Compose, install certbot, prompt for an admin token and sectors, generate
a TOTP secret, write a chmod-600 .env, and run certbot for TLS. What is
missing is a single guided surface that takes an operator from "containers
are up" to "first transfer sent" without hand-editing files.

Compare appliance products (Home Assistant, Proxmox, Mailcow): they expose
a first-run web wizard. We want the same experience.

A CLI first-boot TUI already exists (scripts/paramant-setup.sh, tied to
/etc/paramant/.setup-done). That belongs to the appliance / ParamantOS
route, which is explicitly NOT the direction we are taking. install-pi.sh +
install.sh + docker compose remain the install method.

## Decision

Add a first-version onboarding wizard as a web route `/setup`:

1. Frontend: a new page frontend/setup.html with a multi-step wizard
   (sectors, domain + TLS, admin email + TOTP, first user, compliance
   template, review + apply) plus frontend/setup.js as its state machine.
   This PR ships the UX shell only.

2. Backend: new endpoints under /v2/setup/* on the existing relay that
   accept first-time configuration. This PR ships two stubs:
   - GET  /v2/setup/check  -- reports whether the relay is in first-time
     mode (currently: apiKeys.size === 0).
   - POST /v2/setup/apply  -- returns 501 Not Implemented for now; the real
     apply logic is deferred (see Consequences / gap analysis).

3. First-run gate: /setup endpoints are reachable only when the relay has
   no users yet (apiKeys.size === 0), with an optional explicit override
   SETUP_MODE=true in .env for re-runs. After a successful apply the gate
   closes automatically, because the first key then exists and
   apiKeys.size > 0. SETUP_MODE is intentionally NOT added to .env.example
   in the scaffolding change; it is documented here and wired when apply
   is implemented.

4. Under the hood the wizard reuses existing flows rather than inventing
   new crypto: it converges on the same .env format install.sh writes, and
   it calls the admin panel's existing key-issuance endpoints (POST
   /api/request-key, POST /api/sectors/:sector/keys) for the first user.
   Pure UX layer; no new cryptography.

Note on routing: relay/relay.js is a raw http.createServer dispatcher with
a mode-gate (modeAllows, relay.js:1691) that blocks any path not listed in
ALLOWED[RELAY_MODE] for ghost_pipe and iot modes. The /v2/setup prefix is
therefore added to those ALLOWED arrays so the wizard works in every relay
mode (full mode has no gate).

No Linux distro. install-pi.sh + install.sh install Docker + paramant-relay,
then the installer directs the operator to https://<domain>/setup to run
the wizard.

## Consequences

- Self-hosters can go from bare metal to first transfer in under 10
  minutes via the browser, instead of editing .env and running CLI helpers.
- The existing .env route stays fully working (backwards compatible). The
  CLI helpers (paramant-key-add.sh, paramant-setup.sh) remain for
  power-users.
- The admin panel keeps all its current features; /setup is strictly for
  first-time configuration and is unreachable once a user exists.
- install-pi.sh remains the Raspberry Pi entry point.
- No OS to maintain -- only the container + a UI layer.
- The heavy lifting is deferred: POST /v2/setup/apply business logic,
  auto-TLS via certbot from the wizard, admin TOTP-in-browser, backup
  strategy, compliance-template presets, and the "all systems go"
  health-check are tracked in /tmp/plug-and-play-gaps.md and follow in
  separate PRs.

## Alternatives

- ParamantOS Linux distro with a paramant-setup TUI wizard: rejected -- too
  much OS maintenance for the value; the appliance audience is better
  served by a container + web wizard.
- CLI-only setup: stays available for power-users, but is not the default
  route for the appliance audience.
- Web onboarding via a separate dashboard app: rejected -- running /setup on
  the existing relay is simpler than shipping another service.
