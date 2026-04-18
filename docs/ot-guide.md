# Ghost Pipe OT Integration Guide

## Overview

Ghost Pipe is a quantum-safe data conduit for OT environments. It transports sensor data, PLC configurations, and firmware updates across the OT/IT boundary without creating a persistent network connection or storing data at rest.

This guide covers deploying Ghost Pipe as the IEC 62443 conduit between your OT zone (Levels 1–2) and your IT/SCADA zone (Level 3).

---

## Architecture — Purdue Model placement

```
┌─────────────────────────────────────────────────────────────────┐
│  Level 4 — Enterprise network                                   │
│  ERP, business systems, cloud historian                         │
│                              ↑                                  │
│                    paramant-receiver                            │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│  Level 3 — Operations / Site network                            │
│  SCADA, data historian, engineering workstations                │
│                              ↑                                  │
│                    paramant-receiver                            │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│  Level 3.5 — Industrial DMZ (conduit)                           │
│                                                                 │
│         ┌──────────────────────────────────┐                   │
│         │  Ghost Pipe relay (self-hosted)  │  ← runs here      │
│         │  iot.paramant.app (managed)      │                   │
│         └──────────────────────────────────┘                   │
│                                                                 │
│  Data enters encrypted from Level 2.                           │
│  Data exits as ciphertext only. Relay cannot decrypt.           │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│  Level 2 — Control network                                      │
│  DCS, PLC output, HMI                                          │
│                              ↓                                  │
│                    paramant-sender                              │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│  Level 1 — Field devices                                        │
│  Sensors, actuators, PLCs                                       │
└─────────────────────────────────────────────────────────────────┘
```

**Key property:** The relay in the DMZ stores nothing. Data resides in RAM only and is destroyed immediately after the receiver downloads it. There is no persistent connection from Level 2 to Level 3.

---

## Prerequisites

- Python 3.8+ on the sender host (Level 2 / control network edge), or use the ARM64 binary
- Paramant API key — request one at [paramant.app/request-key](https://paramant.app/request-key)
- Receiver key registered with `paramant-setup` on the receiving host (Level 3 / SCADA)
- Self-hosted relay recommended for air-gap deployments (see below)

Install the client tools:

```bash
curl -fsSL https://paramant.app/install-client.sh | bash
```

---

## Quickstart — Raspberry Pi edge node

A Raspberry Pi 3B+ or 4 in the OT DMZ can run the relay. The installer handles everything:

```bash
# On the Pi (as root)
curl -fsSL https://paramant.app/install-pi.sh | sudo bash
```

This installs the relay as a systemd service (`paramant-relay.service`) with the `iot` sector mode. The relay accepts transfers from your OT sender and queues them for the IT receiver.

Verify the relay is running:

```bash
curl http://localhost:3000/health
# {"ok":true,"sector":"iot","version":"2.4.5"}
```

---

## Continuous sensor data — `--interval` flag

For periodic sensor readings, use `--interval` to send continuously without scripting a cron job:

```bash
# Temperature and pressure every 15 seconds, tagged with device ID
echo '{"temp": 72.4, "pressure": 1.013, "unit": "plc-A1"}' | \
  paramant-sender --stdin --interval 15 --device-id plc-factory-01 \
    --relay iot --key pgp_xxx

# Read a file that updates each cycle (e.g. a PLC export)
paramant-sender --file /var/plc/latest-reading.json \
  --interval 30 --device-id dcs-reactor-02 --relay iot --key pgp_xxx

# Stop after 100 transmissions
paramant-sender --stdin --interval 5 --count 100 --relay iot --key pgp_xxx
```

Each transmission is independent and burn-on-read. If the receiver is temporarily offline, the relay holds the blob for the TTL duration (default 5 minutes, configurable with `--ttl`).

---

## Watch mode — directory polling

Watch a directory for new sensor exports and send each file automatically:

```bash
# Send any new file that appears in /var/scada/export/ every 30 seconds
paramant-sender --watch /var/scada/export/ --interval 30 \
  --device-id scada-export --relay iot --key pgp_xxx
```

---

## Firmware distribution — `paramant-firmware`

Push signed firmware to a group of field devices:

```bash
# Vendor side — sign and distribute firmware to all bodycams
paramant-firmware firmware-v2.1.bin \
  --sign \
  --device-group factory-floor-devices.txt \
  --version 2.1

# Device side — receive and verify
paramant-firmware --receive --verify-key vendor.pub
```

`factory-floor-devices.txt` contains one device ID per line. The sender creates one transfer per device. The firmware is ed25519-signed before upload; devices verify the signature before applying the update.

---

## Zone isolation — self-hosted relay in the DMZ

For strict zone control (no outbound internet from Level 3.5), deploy your own relay:

```bash
# On the DMZ relay host
docker run -d \
  --name paramant-relay \
  --restart unless-stopped \
  -p 3000:3000 \
  -e RELAY_MODE=iot \
  -e LICENSE_KEY=plk_xxx \
  mtty001/relay:latest
```

Set the relay URL on both sender and receiver:

```bash
# Sender (Level 2 side)
paramant-sender --file reading.json \
  --relay https://dmz-relay.internal:3000 \
  --key plk_xxx

# Receiver (Level 3 side)
paramant-receiver --hash <hash> \
  --relay https://dmz-relay.internal:3000 \
  --key plk_xxx
```

The self-hosted relay has no dependency on `iot.paramant.app`. All traffic stays within your network perimeter.

---

## Air-gap deployment

For environments with no internet connectivity between zones:

1. Deploy the relay on a host with **one-way reachability** from the OT sender (Level 2 can push to relay; relay cannot initiate connections into Level 2)
2. The relay stores blobs in RAM only — no disk writes, no database
3. The CT log is local to the relay and can be archived to an air-gapped audit server via the RSS feed (`GET /ct/feed.xml`)
4. Time synchronization: the relay uses system time for CT log timestamps. Ensure NTP is configured on the relay host, even in isolated environments

For completely disconnected operations (both sender and relay offline from internet):

```bash
# Self-hosted relay, no external NTP
docker run -d \
  -e RELAY_MODE=iot \
  -e RELAY_ID=relay.internal.factory \
  -e LICENSE_KEY=plk_xxx \
  -p 3000:3000 \
  mtty001/relay:latest
```

The CT log will use local timestamps. Signature verification still works — the relay's ML-DSA-65 key is generated at first boot and does not require internet connectivity.

---

## Device identity enrollment

Register a device identity before sending, so the relay can track which device sent which transfer:

```bash
# Register PLC device identity
curl -X POST https://iot.paramant.app/v2/did/register \
  -H "X-Api-Key: plk_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "plc-factory-01",
    "ecdh_pub": "<base64 ECDH public key>"
  }'

# Response includes the DID and CT log entry index
# {"ok":true,"did":"did:paramant:a3f2...","ct_index":42}
```

See [API reference — Device Identity](api.md#device-identity) for the full enrollment flow.

---

## IEC 62443 compliance mapping

| IEC 62443 Requirement | How Ghost Pipe addresses it |
|---|---|
| SR 4.1 — Information confidentiality | ML-KEM-768 + ECDH P-256 client-side encryption. Relay never holds plaintext. |
| SR 4.2 — Use control | API key per device. `plk_` operator keys for infrastructure, `pgp_` device keys for field units. |
| SR 3.1 — Communication integrity | AES-256-GCM AEAD authentication tag on every payload. ML-DSA-65 signed STH in CT log. |
| SR 1.1 — Device identification | `/v2/did/register` enrollment with ed25519 device key. DID document in public CT log. |
| SR 2.8 — Auditable events | Every transfer appended to tamper-evident Merkle CT log. Public at `iot.paramant.app/ct`. |
| SR 5.2 — Zone boundary protection | Self-hosted relay in DMZ. No persistent connection crosses the OT/IT boundary. |
| IEC 62443-3-2 — Zones and conduits | `iot.paramant.app` is an isolated sector. No cross-sector data sharing with health/legal/finance relays. |
| IEC 62443-2-3 — Patch management | Open source (BUSL-1.1), versioned Docker releases, public security audit (April 2026). |

---

## Latency characteristics

Round-trip latency for the managed relay at `iot.paramant.app` (Hetzner Falkenstein DE):

| Payload | p50 | p95 | p99 |
|---|---|---|---|
| 4 KB (sensor packet) | see benchmark | see benchmark | see benchmark |
| 64 KB (config blob) | see benchmark | see benchmark | see benchmark |
| 1 MB (firmware chunk) | see benchmark | see benchmark | see benchmark |

Run the benchmark with your actual API key to get site-specific numbers:

```bash
python3 scripts/paramant-benchmark.py \
  --relay https://iot.paramant.app \
  --key pgp_xxx \
  --count 50 \
  --size 4096
```

Self-hosted relay on the same LAN segment achieves sub-10 ms p50 for 4 KB payloads.

Ghost Pipe is not designed for hard real-time (< 1 ms) control loops — use it for data collection, configuration push, and firmware distribution where eventual delivery within seconds is acceptable.

---

## Troubleshooting

**"Invalid API key"** — Verify the key format (`pgp_` or `plk_` prefix) and that it was issued for the IoT sector (`iot.paramant.app`).

**"Data te groot"** — Default pad-block is 5 MB. Payload must be under ~5 MB. For firmware larger than 5 MB, split into chunks and send sequentially.

**Relay unreachable from OT network** — Check that the OT host can reach `iot.paramant.app:443` (HTTPS). If using a self-hosted relay, verify the firewall allows one-way outbound from the OT sender to the relay host on port 3000 (or your configured port).

**Receiver gets no blob** — Default TTL is 300 seconds (5 minutes). If the receiver polls after TTL expiry, the blob is gone. Increase `--ttl` for slow receivers, or use `GET /v2/stream-next` to poll the delivery queue.
