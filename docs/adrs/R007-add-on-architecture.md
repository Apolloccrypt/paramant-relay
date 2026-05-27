# R007. Add-on architecture (manifest, lifecycle, security model)

Date: 2026-05-27

Status: Draft (specification only; implementation in later milestones)

## Context

paramant-relay does a small set of things well: post-quantum encrypted
blob transit with burn-on-read. Useful integrations live just beyond
the core: storage mirrors (S3/MinIO ciphertext spiegeling), notification
bridges (Slack/Teams/webhook on delivery), sensor bridges (MQTT for
IoT), identity providers (OIDC/SAML for enterprise SSO), compliance
exporters (SIEM audit-trail export), STH monitors (cross-relay
verification service).

Building these into the relay core violates Apple-simple principle
(BLUEPRINT.md design principle B). Forcing every self-hoster to vendor
their own integrations wastes community effort. An add-on system is
the correct seam.

Reference architectures:

- HomeAssistant: container-based add-ons, manifest-driven,
  capability-permissions, official + community registries
- Proxmox: helper-scripts and templates, less formal
- Nextcloud: app marketplace, server-side PHP plugins (different model)

paramant should adopt the HomeAssistant model: container-isolated
add-ons with manifest-declared capabilities.

## Decision

### Add-on form factor

A paramant add-on is a Docker container with a manifest file. The
container runs alongside the relay (same docker-compose stack or
separate host) and communicates via documented channels.

### Manifest: paramant-addon.json

Single JSON file in the add-on root directory. Schema:

```json
{
  "name": "paramant-addon-storage-mirror",
  "version": "1.0.0",
  "description": "Mirror blob ciphertext to S3 or MinIO",
  "vendor": "Paramant Official",
  "license": "BUSL-1.1",
  "homepage": "https://github.com/Apolloccrypt/paramant-addons-official",
  "compatibility": {
    "paramant-relay": ">=3.0.0"
  },
  "image": "ghcr.io/apolloccrypt/paramant-addon-storage-mirror:1.0.0",
  "capabilities": [
    "read:blob-metadata",
    "subscribe:stream",
    "subscribe:nats"
  ],
  "communication": {
    "channels": ["webhook", "stream", "nats"],
    "webhook_endpoint": "/api/inbound-event"
  },
  "config_schema": {
    "S3_ENDPOINT": { "type": "string", "required": true },
    "S3_BUCKET": { "type": "string", "required": true },
    "S3_ACCESS_KEY": { "type": "string", "required": true, "secret": true },
    "S3_SECRET_KEY": { "type": "string", "required": true, "secret": true }
  }
}
```

### Capabilities (permission model)

Add-ons declare what they need. Admin grants explicitly via add-on
install flow. No add-on gets blanket access.

Defined capabilities:

- `read:blob-metadata` - access blob hashes, sizes, timestamps from
  /v2/audit, /v2/ct/log. NOT plaintext.
- `read:audit-events` - subscribe to or query the full CT-log audit
  stream
- `subscribe:stream` - WebSocket to /v2/stream for real-time
  blob_ready events
- `subscribe:nats` - NATS JetStream subscription to "paramant.>"
  (only if NATS_URL configured on relay)
- `webhook:receive` - relay POSTs delivery events to add-on's declared
  endpoint
- `export:audit-format` - GET /v2/audit/export (CSV/JSON download)
- `manage:users` - call admin API for user-CRUD (HIGH PRIVILEGE;
  requires admin confirmation per call)

Critical exclusions: NO capability gives access to plaintext,
encryption keys, or signing keys. Add-ons work on ciphertext +
metadata only. Zero-knowledge guarantee is structural, not
policy-based.

### Communication channels

An add-on may use one or more of three channels. Each declared in
manifest:

1. **HTTP webhook**: relay POSTs to add-on's declared endpoint.
   Add-on requires `webhook:receive` capability. Body is JSON event
   (blob hash, ts, sector, recipient hash). Signed with HMAC-SHA256
   using add-on's per-install secret.

2. **WebSocket stream**: add-on connects to relay's /v2/stream with
   ws-ticket auth (using add-on's API key). Requires `subscribe:stream`.

3. **NATS JetStream**: add-on subscribes to "paramant.>" subjects on
   the relay's NATS instance (if configured). Requires `subscribe:nats`.

### Lifecycle: docker-compose extension model

```
paramant-relay/
  docker-compose.yml          # core relay containers
  addons/
    storage-mirror/
      paramant-addon.json
      docker-compose.fragment.yml  # add-on container definition
      config/                       # admin-supplied env-vars (gitignored)
    notification-bridge/
      paramant-addon.json
      docker-compose.fragment.yml
      config/
```

Admin scripts:

- `paramant-addon-install <github-url-or-tarball>` - download, validate
  manifest, capability-confirm with admin, write to addons/
- `paramant-addon-enable <name>` - merge docker-compose.fragment.yml
  into runtime, docker compose up -d for the new service
- `paramant-addon-disable <name>` - docker compose stop, remove from runtime
- `paramant-addon-update <name>` - check registry for newer version,
  download, replace, restart
- `paramant-addon-uninstall <name>` - disable + remove directory
- `paramant-addon-list` - show installed + enabled state

Web UI: addons-tab in admin panel mirrors these commands (CLI parity).

### Registry

Three registries:

- **Official**: github.com/Apolloccrypt/paramant-addons-official
  (curated by Paramant team, audited for compliance claims). Eerste
  add-ons gemaakt door Paramant team.
- **Community**: github topic `paramant-addon`. Discovery via GitHub
  search. No curation. Install at own risk.
- **Local**: any tarball or git URL. For private enterprise add-ons.

Mogelijke uitbreiding M13+: paramant.app/addons marketplace met
reviews + ratings.

### Versioning

Add-ons follow SemVer. Manifest declares `compatibility.paramant-relay`
as a semver range. Relay refuses to install add-ons whose compat range
excludes the running relay version.

Major-version-bumps of add-on may require admin re-confirmation of
capabilities if the new manifest requests different capabilities than
the previous version.

## Consequences

- Integration ecosystem can grow without bloating relay core
- Audit surface bounded: each add-on is reviewable independently
- Zero-knowledge claim remains structural - add-ons cannot decrypt
- Self-hosters and enterprise can vendor private add-ons without
  contributing back
- Official add-on registry becomes a Paramant product line
  (potentially paid for enterprise tier)
- Community add-ons grow ecosystem like HomeAssistant

Trade-offs:

- Adds complexity to self-hosting (admin must understand capabilities)
- Container runtime overhead per add-on
- Add-on quality varies in community registry (warned)
- First-party add-on development becomes ongoing maintenance

## Alternatives considered

- **Built-in integrations**: rejected. Bloats core, conflicts with
  Apple-simple principle.
- **Node.js plugin system (require'd modules)**: rejected. Plugins
  would run in relay process, breaking process isolation. Any plugin
  bug crashes the relay.
- **Lua/WASM sandbox**: rejected. Complex runtime, limited library
  ecosystem, doesn't match "Docker is the unit of deployment" pattern
  already used by paramant-relay.
- **Webhook-only (no add-on framework)**: rejected. Each self-hoster
  rebuilds integrations from scratch. No shared community work.

## Implementation roadmap

This ADR is specification only. Implementation in stages:

1. **Foundation** (after M9 audit): paramant-addon CLI scripts,
   manifest validation, capability-grant flow
2. **First-party add-ons** (post-audit): storage-mirror,
   notification-bridge, MQTT-bridge, SIEM-exporter
3. **Admin panel addons-tab** (M11+ during plug-and-play fase)
4. **Community registry guidelines** (M12+)
5. **paramant.app/addons marketplace** (M13+ optional)
