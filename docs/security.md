# PARAMANT Ghost Pipe — Security Model

**Version:** 2.4.1  
**Last updated:** 2026-04-11

---

## Overview

Ghost Pipe is a zero-plaintext, burn-on-read file transport. The relay is an _untrusted intermediary_: it stores only encrypted ciphertext and has no access to keys or plaintext. This document explains the four-layer key verification system that protects transfers even when the relay is fully compromised.

---

## Threat model

| Actor | Can do | Cannot do |
|-------|--------|-----------|
| Network attacker (passive) | Observe encrypted blobs | Decrypt (quantum-safe keys) |
| Network attacker (active) | Intercept relay traffic | Forge valid ciphertext |
| Compromised relay | Serve wrong pubkey (MITM) | Decrypt if PSS or fingerprint verification is used |
| Malicious relay operator | Log metadata, delay delivery | Read plaintext; break PSS-protected transfers |
| Quantum computer | Break classical crypto | Break ML-KEM-768 or ML-DSA-65 (NIST FIPS 203/204) |

**What the relay knows:**
- Existence of a transfer (metadata)
- Transfer time and approximate size (padded to 5 MB fixed blocks)
- Device IDs of sender and receiver (if API key is used)

**What the relay never knows:**
- Plaintext content
- Private keys (generated in browser/SDK, never uploaded)
- Pre-shared secret (PSS)
- Identity of parties (in anonymous drop mode)

---

## Layer 1 — TOFU (Trust On First Use)

**What it is:** Like SSH `known_hosts`. The first time you fetch a device's pubkey, its fingerprint is stored locally. Every subsequent fetch verifies the stored fingerprint matches.

**Fingerprint format:**
```
SHA-256(kyber_pub_bytes || ecdh_pub_bytes) → first 10 bytes → 5 groups of 4 hex chars
Example: A3F2-19BE-C441-8D07-F2A0
```

The fingerprint is computed independently by both parties. The relay also computes and returns it, but clients re-derive it locally to prevent relay forgery.

**Storage:**
- **SDK Python/JS:** `~/.paramant/known_keys` (SSH-style, `device_id fingerprint registered_at`)
- **ParaShare:** localStorage in browser
- **ParamantOS CLI:** `/home/paramant/.paramant/known_keys`

**What it protects against:**  
A compromised relay that swaps pubkeys between registrations. After first contact, any key change triggers a `FingerprintMismatchError` and blocks the transfer.

**What it does NOT protect against:**  
A relay that swaps the pubkey on the very _first_ fetch (before any fingerprint is stored). This is why out-of-band verification (Layer 2) or PSS (Layer 3) is recommended for high-security transfers.

**API:**
```python
# Python SDK
gp.fingerprint('mri-scanner-001')   # Show fingerprint for verification
gp.trust('mri-scanner-001')          # Manually mark as trusted
gp.untrust('mri-scanner-001')        # Remove from known_keys
gp.known_devices()                   # List all trusted devices
```

```bash
# ParamantOS CLI
paramant-verify mri-scanner-001     # Interactive TOFU verification
paramant-verify --list              # List trusted devices
paramant-verify --clear mri-001     # Remove device
```

---

## Layer 2 — Out-of-band fingerprint verification

**What it is:** Both sender and receiver independently compute the same fingerprint and compare it via a separate, trusted channel (phone call, Signal, in-person).

**Three methods:**

### 2a. Verbal comparison (phone/Signal)
1. Receiver opens `ontvang.html` — fingerprint is displayed prominently
2. Sender polls for receiver's pubkey — fingerprint appears in ParaShare UI
3. Sender calls/messages receiver: _"Your fingerprint?"_
4. Receiver reads: `A3F2-19BE-C441-8D07-F2A0`
5. Sender confirms they see the same value → clicks **Verified — encrypt & send**

### 2b. QR code scan
1. ParaShare shows a QR code of the fingerprint
2. Receiver scans it with their phone camera and compares visually
3. Requires proximity — effective for in-person or video-call scenarios

### 2c. SDK fingerprint method
```python
# Sender checks receiver's fingerprint before sending
fp = gp.fingerprint('dicom-storage-001')
# → Device:      dicom-storage-001
# → Fingerprint: A3F2-19BE-C441-8D07-F2A0
# → Registered:  2026-04-10T09:23:11Z
# → CT log index: 42
# Compare with receiver out-of-band, then:
gp.trust('dicom-storage-001')
```

**What it protects against:**  
A compromised relay performing a MITM by swapping public keys. The relay cannot forge a fingerprint because neither party trusts the relay's fingerprint claim — both compute it independently from the raw key bytes.

---

## Layer 3 — Pre-Shared Secret (PSS)

**What it is:** An optional password agreed out-of-band. The PSS is added to the HKDF key derivation input. Even if the relay serves a completely wrong pubkey, the receiver cannot decrypt without the PSS.

**Key derivation with PSS:**
```
ikm = ecdh_shared_secret || kem_shared_secret || SHA3-256(pss)
K   = HKDF-SHA256(salt=kct[:32], info="aes-key", ikm=ikm) → AES-256-GCM key
```

Without PSS, `ikm = ecdh_ss || kem_ss` (unchanged — backward compatible).

**API:**
```python
# Sender
h = gp.send(data, recipient='dicom-storage-001', pre_shared_secret='correct-horse-battery-staple')

# Receiver
data = gp.receive(h, pre_shared_secret='correct-horse-battery-staple')
```

**What it protects against:**  
- Relay MITM on first contact (before any fingerprint is stored)
- Relay-side key injection attacks at any time
- Even a fully compromised relay cannot decrypt PSS-protected transfers

**What it does NOT protect against:**  
An attacker who knows the PSS. PSS is only as strong as its secrecy and entropy.

**When to use PSS:**
- Healthcare (DICOM) transfers between known systems → agree PSS during device commissioning
- Legal document transfer between law firms → PSS distributed via encrypted email
- Any scenario where relay compromise is a realistic threat model

---

## Layer 4 — ML-DSA-65 signature + CT log

**What it is:** When a device registers its pubkey with the relay, it can sign the registration with an ML-DSA-65 keypair (NIST FIPS 204, post-quantum). The relay stores the signature alongside the pubkey. The CT (Certificate Transparency) log records all registrations with a Merkle hash chain.

**CT log entry:**
```json
{
  "index": 42,
  "leaf_hash": "sha3-256(device_hash || pubkey_first_32_bytes || timestamp)",
  "tree_hash": "merkle_root_after_appending_this_leaf",
  "device_hash": "sha3-256(device_id + api_key[:8])",
  "ts": "2026-04-10T09:23:11.000Z",
  "proof": [{ "hash": "...", "position": "right" }]
}
```

**What it protects against:**
- Retroactive key injection (CT log proves _when_ a key was registered)
- Key substitution attacks (ML-DSA-65 signature links pubkey to identity)
- Suspicious timing: a pubkey registered <60s ago for a device active for months warrants investigation

**CT log endpoints:**
```bash
GET /v2/ct?from=0&limit=50       # Paginated CT log entries
GET /v2/ct/:index                # Single entry with inclusion proof
```

**Suspicious patterns to check:**
```python
import urllib.request, json
r = urllib.request.urlopen('https://relay.paramant.app/v2/ct')
entries = json.loads(r.read())['entries']
# Check: was this device's key registered very recently?
for e in entries:
    if 'my-device' in e.get('device_hash', ''):
        print(e['ts'], e['index'])
```

---

## Relay API — key distribution endpoints

### GET /v2/pubkey/:device

Returns pubkey + fingerprint + CT metadata for a device.

```json
{
  "ok": true,
  "ecdh_pub": "3059...",
  "kyber_pub": "...",
  "dsa_pub": "...",
  "fingerprint": "A3F2-19BE-C441-8D07-F2A0",
  "registered_at": "2026-04-10T09:23:11.000Z",
  "ct_index": 42,
  "ts": "2026-04-10T09:23:11.000Z"
}
```

### GET /v2/fingerprint/:device

Returns just the fingerprint (lightweight, for out-of-band verification tools).

```json
{
  "ok": true,
  "device_id": "mri-scanner-001",
  "fingerprint": "A3F2-19BE-C441-8D07-F2A0",
  "registered_at": "2026-04-10T09:23:11.000Z",
  "ct_index": 42
}
```

### POST /v2/pubkey/verify

Verify a fingerprint against the stored pubkey.

**Request:**
```json
{ "device_id": "mri-scanner-001", "fingerprint": "A3F2-19BE-C441-8D07-F2A0" }
```

**Response (match):** HTTP 200 `{ "ok": true, "match": true, "stored": "A3F2-..." }`  
**Response (mismatch):** HTTP 409 `{ "ok": false, "match": false, "stored": "...", "provided": "..." }`

### POST /v2/pubkey (updated)

Registration now returns fingerprint + CT info:

```json
{
  "ok": true,
  "fingerprint": "A3F2-19BE-C441-8D07-F2A0",
  "ct_index": 42,
  "ct_tree_hash": "...",
  "dsa_supported": true
}
```

---

## Example: Healthcare workflow (DICOM)

```python
from paramant_sdk import GhostPipe

# === Device commissioning (one-time, in person) ===
# Hospital IT agrees PSS with radiology department: "flu-vaccine-2026"
# PACS system registers its pubkey:
gp = GhostPipe(api_key='pgp_xxx', device='pacs-001')
gp.receive_setup()
fp = gp.fingerprint()
# IT prints fingerprint on paper, MRI operator compares visually → trusted

# === Daily transfer ===
gp_mri = GhostPipe(api_key='pgp_xxx', device='mri-scanner-001')
h = gp_mri.send(
    dicom_data,
    recipient='pacs-001',
    pre_shared_secret='flu-vaccine-2026'   # PSS: relay MITM impossible
)
print(f'Transfer hash (give to PACS): {h}')

# === PACS receives ===
gp_pacs = GhostPipe(api_key='pgp_xxx', device='pacs-001')
data = gp_pacs.receive(h, pre_shared_secret='flu-vaccine-2026')
# Decrypt succeeds only if PSS matches + keys match
```

**Security guarantees:**
1. Relay never sees DICOM plaintext
2. PSS ensures relay MITM is impossible even on first transfer
3. TOFU detects any future key changes
4. CT log provides audit trail of all key registrations

---

## Example: Legal document workflow (law firm)

```python
# Sender (law firm A) verifies receiver fingerprint before sending
gp = GhostPipe(api_key='pgp_legal_xxx', device='lawfirm-a-001')
fp = gp.fingerprint('lawfirm-b-001')
# → A3F2-19BE-C441-8D07-F2A0
# Call partner at law firm B: "Your fingerprint?"  → they confirm same value

gp.trust('lawfirm-b-001')   # Store in known_keys
h = gp.send(contract_pdf, recipient='lawfirm-b-001')
```

Or with ParaShare (browser):
1. Law firm A shares session link via email
2. Law firm B opens link → their browser shows fingerprint `A3F2-19BE-C441-8D07-F2A0`
3. Law firm B calls law firm A, reads fingerprint aloud
4. Law firm A sees QR code in ParaShare, scans it, or reads the matching value
5. Law firm A clicks **Verified** → file is encrypted and sent

---

## Choosing the right security level

| Scenario | Minimum | Recommended | Maximum |
|----------|---------|-------------|---------|
| Internal transfer, trusted network | TOFU | TOFU + verbal fingerprint | PSS |
| Cross-organization, untrusted relay | Verbal fingerprint | PSS | PSS + fingerprint |
| Healthcare (DICOM, PHI) | PSS | PSS + TOFU | PSS + TOFU + CT audit |
| Legal documents, contracts | Verbal fingerprint | PSS | PSS + ML-DSA-65 |
| Whistleblower, anonymous | Drop mode (BIP39) | Drop mode | Drop mode + PSS |
| IoT sensor data | TOFU | TOFU | PSS |

---

## Known limitations

1. **Browser fingerprints use SHA-256** — SubtleCrypto (browser) does not support SHA3-256 natively. The Python/JS SDK and relay use the same SHA-256 formula for consistency.
2. **PSS is not replay-protected** — The same PSS used repeatedly reduces security. Rotate PSS periodically for high-volume transfers.
3. **CT log is relay-hosted** — The relay cannot forge the Merkle chain retroactively, but a relay that never appends entries could suppress CT log growth. Cross-check CT indices when auditing.
4. **Burn-on-read is single-relay** — The relay stores ciphertext in RAM (no disk). A relay restart burns all blobs.

---

## Audit

Pentest by Ryan Williams · Smart Cyber Solutions Pty Ltd (AU) · April 2026  
Report: [pentest-report-2026-04-08.txt](../pentest-report-2026-04-08.txt)  
Full writeup: [security-audit-2026-04.md](./security-audit-2026-04.md)

All critical/high/medium findings addressed in v2.4.1.
