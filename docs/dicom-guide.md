# Sending DICOM files securely with Paramant

> **Compliance baseline:** NEN 7510 · AVG/GDPR · EU jurisdiction · burn-on-read

---

## The problem

DICOM files contain some of the most sensitive personal data that exists: patient imaging, metadata with birth dates, BSN numbers, referring physician names, and diagnosis codes. Every transfer is subject to:

| Requirement | Regulation |
|---|---|
| Encrypted transport (end-to-end) | GDPR Art. 32 · NEN 7510-2 |
| No persistent storage of patient data | GDPR Art. 5(1)(e) · NEN 7510-1 |
| Tamper-evident audit trail | NEN 7510-1 §9.4 · WGBO |
| EU jurisdiction — no US CLOUD Act exposure | GDPR Art. 46 |
| Post-quantum encryption (2030 readiness) | NCSC PQC migration guideline |

Legacy solutions fail at least one of these. Email fails all of them. Even SFTP has no audit trail, no burn-on-read, and no PQC.

---

## Architecture

```
[PACS / radiology workstation]
  │
  ▼  encrypt client-side (ML-KEM-768 + AES-256-GCM)
paramant-sender.py
  │
  ▼  Ghost Pipe relay — RAM only, no disk write
health.paramant.app  (Hetzner Frankfurt DE)
  │
  ▼  decrypt client-side
paramant-receiver.py
  │
  ▼
[Destination PACS / archive / reading station]
```

Key properties:
- **Client-side encryption only** — the relay sees only opaque ciphertext
- **Burn-on-read** — first authorised download destroys the ciphertext
- **5 MB fixed padding** — all transfers look identical; file size is not leaked
- **CT log** — every transfer gets a Merkle leaf hash; delivery is provable without knowing the content

---

## Step by step

### 1. Install the paramant client

```bash
# Debian / Ubuntu (including Raspberry Pi)
curl -fsSL https://paramant.app/install-client.sh | bash

# Or manual .deb install
wget https://github.com/Apolloccrypt/paramant-relay/releases/latest/download/paramant-client_amd64.deb
sudo dpkg -i paramant-client_amd64.deb
```

Verify:
```bash
paramant-sender.py --version
# paramant-client 2.4.5
```

### 2. Configure

Interactive setup:
```bash
paramant-setup
# Relay:  health.paramant.app
# Key:    pgp_xxxxxxxxxxxxxxxx   (request via privacy@paramant.app)
# Device: mri-001
```

Or write the config directly:
```bash
cat > ~/.paramant/config.json <<EOF
{
  "relay": "https://health.paramant.app",
  "key": "pgp_xxxxxxxxxxxxxxxx",
  "device": "mri-001",
  "sector": "health"
}
EOF
```

### 3. Send a DICOM file

Single file:
```bash
paramant-sender.py --key pgp_xxx --device mri-001 --sector health scan.dcm
# → Uploaded: https://health.paramant.app/v2/blob/abc123
# → CT leaf:  3fa7b2...
# → Expires:  burn-on-read (no TTL)
```

Watch a folder — auto-send when new files arrive:
```bash
paramant-sender.py \
  --watch /dicom/outbox/ \
  --device mri-001 \
  --sector health \
  --key pgp_xxx
```

Systemd unit for persistent watching:
```ini
# /etc/systemd/system/paramant-dicom.service
[Unit]
Description=Paramant DICOM sender
After=network.target

[Service]
ExecStart=/usr/local/bin/paramant-sender.py \
  --watch /dicom/outbox/ \
  --device mri-001 \
  --sector health \
  --key pgp_xxx
Restart=always
RestartSec=10
User=paramant

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now paramant-dicom
```

### 4. Receive and forward to destination PACS

```bash
paramant-receiver.py \
  --key pgp_xxx \
  --sector health \
  --forward http://pacs.hospital.nl:11112/api/dicom
```

The receiver:
1. Polls the relay for new blobs addressed to your key
2. Decrypts locally
3. POSTs the raw DICOM bytes to `--forward` URL (STOW-RS compatible)
4. File is burned on the relay side after download

For DICOM DIMSE instead of STOW-RS:
```bash
paramant-receiver.py \
  --key pgp_xxx \
  --sector health \
  --forward-dcm pacs.hospital.nl:11112 \
  --forward-aet DESTINATION_AET
```

### 5. Verify in the CT log

Every transfer creates an immutable Merkle log entry:
```bash
curl https://health.paramant.app/v2/ct/log?limit=5 \
  -H "X-Api-Key: pgp_xxx" \
  | python3 -m json.tool
```

Example output:
```json
{
  "ok": true,
  "root": "3fa7b2c4...",
  "entries": [
    {
      "index": 47,
      "leaf_hash": "3fa7b2c4d8e1...",
      "tree_hash": "9b4c1a2e...",
      "device_hash": "a1b2c3...",
      "ts": 1744649123
    }
  ]
}
```

The `leaf_hash` proves the transfer happened at `ts` without storing any patient data.

---

## Compliance summary

| Aspect | Implementation | Standard |
|---|---|---|
| Encryption algorithm | ML-KEM-768 (FIPS 203) + AES-256-GCM | NCSC PQC roadmap |
| Key exchange | Client-side, relay has zero plaintext access | NEN 7510-2 A.10.1 |
| Storage | 0 bytes on relay — RAM only, destroyed after read | AVG Art. 5(1)(e) |
| Jurisdiction | Hetzner Falkenstein, Germany — EU only | AVG Art. 46 |
| Audit trail | Merkle CT log, SHA-256 leaf hashes | NEN 7510-1 §9.4 |
| Identity | ML-DSA-65 relay identity certificate | FIPS 204 |
| Agreement | Verwerkersovereenkomst (GDPR Art. 28) | AVG Art. 28 |

**Verwerkersovereenkomst** — Required under GDPR Art. 28 when patient data is processed by a third party. Available on request: privacy@paramant.app

---

## Frequently asked questions

**Q: Does the relay store the DICOM file?**  
No. Ciphertext is held in RAM only. It is destroyed immediately after the first authorised download. No disk I/O occurs.

**Q: Can we run paramant entirely on-premise?**  
Yes. The relay is open source (BUSL-1.1). Run it in your own Kubernetes cluster or on a VPS. The receiver and sender still apply client-side encryption — the operator of the relay never has access to plaintext.

**Q: What about DICOM files > 5 MB?**  
The relay currently pads all transfers to 5 MB and has a hard limit. For large CT/MRI series, split by series UID or use the streaming WebSocket mode (available in Enterprise tier).

**Q: Is there a DICOM WADO-RS / STOW-RS adapter?**  
Yes, in Enterprise. The DICOM gateway at `/dicom/` proxies STOW-RS-compatible uploads directly into the Ghost Pipe relay. Contact privacy@paramant.app.

---

## Get started

| | |
|---|---|
| Request a key | privacy@paramant.app |
| Live relay | https://health.paramant.app |
| Source code | https://github.com/Apolloccrypt/paramant-relay |
| Verwerkersovereenkomst | privacy@paramant.app — subject: Verwerkersovereenkomst |
