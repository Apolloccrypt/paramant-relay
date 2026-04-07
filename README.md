# PARAMANT Ghost Pipe

Post-quantum encrypted file transfer. ML-KEM-768 + ECDH P-256 + AES-256-GCM. Burn-on-read. RAM-only. EU/DE.

## What changed (April 2026)

- **ParaShare**: Full ML-KEM-768 E2E with fingerprint verification — relay never sees the key
- **Drop feature**: BIP39 12-word mnemonic one-time transfers with TTL + max-views policy
- **Argon2id**: Password-based transfers now use Argon2id instead of PBKDF2
- **Key zeroization**: All keys wiped from memory after use (ctypes.memset / zeroBuffer)
- **Variable padding**: 4KB / 64KB / 512KB / 5MB block sizes
- **Access policies**: TTL and max-views configurable per upload
- **Cloudflare removed**: Direct to Hetzner Frankfurt — no US intermediary
- **Let's Encrypt**: Direct TLS on all subdomains

## Architecture

```
Sender browser → ML-KEM-768 encapsulate(receiver_pub)
               → ECDH P-256 hybrid
               → HKDF-SHA256 → AES-256-GCM
               → 5MB padded blob → health relay (RAM only)
               → burn-on-read after first download
```

## Relays

| Sector  | URL                     | Port |
|---------|-------------------------|------|
| Health  | health.paramant.app     | 3005 |
| Legal   | legal.paramant.app      | 3002 |
| Finance | finance.paramant.app    | 3003 |
| IoT     | iot.paramant.app        | 3004 |

## Quick start

```bash
pip install paramant-sdk

from paramant_sdk import GhostPipe
gp = GhostPipe(api_key="pgp_...", device="device-001")

# Send
hash_ = gp.send(b"secret data")

# Receive
data = gp.receive(hash_)

# Drop (BIP39 mnemonic, no API key needed for receiver)
mnemonic = gp.drop(b"sensitive file")
data = gp.pickup("word1 word2 ... word12")

# With access policies
hash_ = gp.send(data, ttl=3600, max_views=3, pad_block=65536)
```

## ParaShare

Browser-based E2E file transfer at paramant.app/parashare

1. Sender enters API key + selects file → creates session
2. Receiver opens link → browser generates ML-KEM-768 keypair
3. Both verify fingerprint (relay cannot spoof)
4. File encrypted with receiver's public key → uploaded
5. Receiver decrypts locally → burn-on-read

## Relay API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v2/inbound` | POST | Upload encrypted blob (max_views, ttl_ms, password) |
| `/v2/outbound/:hash` | GET | Burn-on-read download (X-Blob-Password if protected) |
| `/v2/drop/create` | POST | Mnemonic drop with Argon2id password |
| `/v2/drop/pickup` | POST | Retrieve drop via BIP39 mnemonic |
| `/v2/drop/status` | POST | Check drop availability |
| `/v2/pubkey` | POST | Register ML-KEM-768 + ECDH pubkeys |
| `/v2/status/:hash` | GET | Check blob status |
| `/health` | GET | Relay health |

## Security model

- **Trusted**: sender, receiver
- **Untrusted**: relay, network, infrastructure provider
- **Relay sees**: encrypted blobs only — never plaintext or keys
- **RAM-only**: no disk writes, swap disabled
- **Burn-on-read**: deleted from RAM immediately after retrieval
- **Key zeroization**: derived keys zeroed after use (randomFill + fill(0))
- **Argon2id**: 19MB memory, 2 iterations (OWASP compliant)

## License

BUSL-1.1 — see LICENSE. Change Date: 2029-01-01 → Apache 2.0.
