# paramant-* CLI tools

Command-line tools for managing and using Paramant relays.

## Install

```bash
curl -fsSL https://paramant.app/install-client.sh | bash
```

On ParamantOS — all tools are pre-installed. Type `paramant-help`.

## Tools by category

### Setup & diagnostics
| Tool | Description |
|------|-------------|
| `paramant-setup` | First-time wizard — relay URL + API key |
| `paramant-status` | Relay health across all 5 sectors |
| `paramant-doctor` | Automated health check with fix instructions |
| `paramant-info` | System info, uptime, relay version, edition |
| `paramant-relay-setup` | Clone + configure + start your own relay |

### File transfer
| Tool | Description |
|------|-------------|
| `paramant-sender.py` | Encrypt and send a file to a relay sector |
| `paramant-receiver.py` | Receive and decrypt from a relay sector |

### Sector tools
| Tool | Standard | Description |
|------|----------|-------------|
| `paramant-referral` | NEN 7510 / HL7 FHIR | Healthcare referral transport |
| `paramant-notary` | eIDAS / KNB | Legal document transport |
| `paramant-legal` | eIDAS | Court document relay |
| `paramant-payslip` | GDPR | HR payslip distribution |
| `paramant-firmware` | IEC 62443 | IoT firmware updates |
| `paramant-cra` | EU CRA 2027 | Software supply chain relay |
| `paramant-ticket` | — | One-time transit ticket |

### CT log & verification
| Tool | Description |
|------|-------------|
| `paramant-verify-sth` | Verify ML-DSA-65 signed tree head against relay |
| `paramant-receipt` | View or verify a delivery receipt |
| `paramant-verify-peers` | Cross-check STH consistency across all peer relays |

### Key management
| Tool | Description |
|------|-------------|
| `paramant-keys` | List all API keys |
| `paramant-key-add` | Add new API key (interactive) |
| `paramant-key-revoke` | Revoke an API key (interactive) |

### Security & network
| Tool | Description |
|------|-------------|
| `security-status` | All security layers at a glance |
| `paramant-ports` | Firewall rules + listening ports |
| `paramant-scan` | LAN relay discovery + registry |
| `paramant-verify` | TOFU fingerprint verification |
| `paramant-crypto-audit` | Scan for quantum-vulnerable algorithms |

### Data & maintenance
| Tool | Description |
|------|-------------|
| `paramant-backup` | Backup keys + CT log |
| `paramant-restore` | Restore from backup |
| `paramant-export` | Export audit log to USB |
| `paramant-logs` | Live log stream |
| `paramant-update` | Check for relay updates |
| `paramant-roadmap` | PQC migration roadmap generator |

---

## Python client scripts

Run on your own machine — not on the relay server.

## Install dependencies
```bash
pip install cryptography
pip install websocket-client    # optional, for WebSocket streaming
pip install kyber-py            # optional, for ML-KEM-768
```

## paramant-sender.py v5.0

Encrypts and sends data to the Ghost Pipe relay.
```bash
# Heartbeat — sends status every N seconds
python3 paramant-sender.py --key pgp_xxx --device mri-001 --heartbeat 15

# Single file
python3 paramant-sender.py --key pgp_xxx --device mri-001 --file scan.dcm

# From stdin
echo "hello" | python3 paramant-sender.py --key pgp_xxx --device mri-001 --stdin
cat data.bin  | python3 paramant-sender.py --key pgp_xxx --device mri-001 --stdin

# HTTP proxy — POST to local port
python3 paramant-sender.py --key pgp_xxx --device mri-001 --listen 8765

# Watch directory — sends new files automatically
python3 paramant-sender.py --key pgp_xxx --device mri-001 --watch /exports/

# Specific relay
python3 paramant-sender.py --key pgp_xxx --device mri-001 --file x.pdf \
  --relay https://health.paramant.app
```

**Options:**
- `--key` (required) API key starting with `pgp_`
- `--device` (required) Device ID, any string
- `--relay` Relay URL (auto-detects from key if omitted)
- `--ttl` Blob TTL in seconds (default: 300)
- `--heartbeat SEC` Heartbeat interval
- `--listen PORT` HTTP proxy port
- `--watch DIR` Directory to watch
- `--file FILE` Single file to send
- `--stdin` Read from stdin

**Sequence state:** stored in `~/.paramant/<device>.seq`

## paramant-receiver.py v5.0

Decrypts and delivers data from the Ghost Pipe relay.

**Start receiver BEFORE sender** — receiver registers pubkeys that sender needs.
```bash
# Save to directory
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --output /pacs/

# Forward to HTTP endpoint
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --forward https://api/ingest

# Print to stdout
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --stdout | jq .

# Force polling (no WebSocket)
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --output /tmp/ --no-ws

# Custom poll interval
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --output /tmp/ --interval 5
```

**Options:**
- `--key` (required) API key
- `--device` (required) Device ID (must match sender)
- `--relay` Relay URL (auto-detects if omitted)
- `--output DIR` Save received files here
- `--forward URL` POST received data to this URL
- `--stdout` Write to stdout
- `--interval SEC` Poll interval (default: 3)
- `--no-ws` Skip WebSocket, use polling only

**File type detection:**
- `.dcm` — DICOM files (magic bytes or offset 128)
- `.json` — JSON data
- `.pdf` — PDF files
- `.bin` — everything else

**Keypair:** stored in `~/.paramant/<device>.keypair.json`, rotated every 24h

## E2E test
```bash
mkdir -p /tmp/recv-test

# Terminal 1
python3 paramant-receiver.py \
  --key pgp_xxx_redacted \
  --device e2e-test \
  --output /tmp/recv-test \
  --no-ws

# Terminal 2 (after "Pubkeys geregistreerd" in terminal 1)
echo "PARAMANT e2e $(date)" | python3 paramant-sender.py \
  --key pgp_xxx_redacted \
  --device e2e-test \
  --stdin

# Verify
cat /tmp/recv-test/recv_000001.json
```

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `No receiver pubkeys` | Receiver not running | Start receiver before sender |
| `Decrypt error` | Keypair mismatch | Delete `~/.paramant/<device>.keypair.json`, restart receiver |
| `HTTP 401` | Invalid API key | Check key starts with `pgp_`, check plan |
| `HTTP 403` | Cloudflare block | User-Agent is set correctly in v5.0 |
| `Relay unreachable` | Network issue | Try `--relay https://health.paramant.app` explicitly |
| `base64 decode error` | Old receiver v4.x | Upgrade to v5.0 |
| WebSocket connects but no data | Polling fallback active | Normal — polling picks up what WS misses |
