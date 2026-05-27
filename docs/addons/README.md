# Paramant Add-ons

Add-ons extend paramant-relay with integrations: storage mirrors,
notification bridges, identity providers, IoT sensors, SIEM exporters.

See [R007 Add-on architecture](../adrs/R007-add-on-architecture.md)
for the specification.

## Installing an add-on (planned)

```bash
paramant-addon-install https://github.com/Apolloccrypt/paramant-addons-official/storage-mirror
paramant-addon-enable storage-mirror
```

## Status

Add-on framework is specified but not yet implemented. This
documentation is forward-looking. Track implementation progress
via R007 ADR status.

## Manifest schema

See [example-manifest.json](./example-manifest.json) for a
complete annotated example.

## Available capabilities

Add-ons declare what they need in their manifest. The admin reviews
and grants capabilities during install:

| Capability | What it allows | Notes |
|---|---|---|
| read:blob-metadata | Read blob hashes, sizes, timestamps | NOT plaintext |
| read:audit-events | Subscribe or query CT-log entries | Public-ish data |
| subscribe:stream | WebSocket /v2/stream blob-ready events | Real-time |
| subscribe:nats | NATS JetStream subscription | Requires NATS configured |
| webhook:receive | Receive POSTs from relay | HMAC-signed |
| export:audit-format | Read /v2/audit/export | CSV/JSON exports |
| manage:users | User CRUD via admin API | HIGH PRIVILEGE |

Add-ons never get access to plaintext, encryption keys, or signing
keys. The zero-knowledge guarantee is structural.
