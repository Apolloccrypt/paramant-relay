# PARAMANT Sender & Receiver v5.0

Command-line tools voor het versturen en ontvangen van bestanden via Ghost Pipe.

## Installatie
```bash
pip install cryptography
pip install websocket-client   # optioneel, voor WebSocket streaming
pip install kyber-py           # optioneel, voor ML-KEM-768
```

## Receiver — altijd eerst starten

De receiver moet draaien voordat de sender iets kan sturen. Bij opstart registreert de receiver zijn publieke sleutels bij de relay — de sender heeft die nodig om te versleutelen.

```bash
# Opslaan in map
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --output /pacs/incoming/

# Doorsturen naar HTTP endpoint
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --forward https://mijn-api.nl/ingest

# Naar stdout
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --stdout | jq .

# Zonder WebSocket
python3 paramant-receiver.py --key pgp_xxx --device mri-001 --output /tmp/ --no-ws
```

### Opties receiver

| Optie | Beschrijving |
|-------|-------------|
| `--key` | API key (verplicht) |
| `--device` | Device ID (verplicht, moet matchen met sender) |
| `--relay` | Relay URL (auto-detect als leeg) |
| `--output` | Map om ontvangen bestanden op te slaan |
| `--forward` | HTTP URL om data naar door te sturen |
| `--stdout` | Schrijf naar stdout |
| `--interval` | Poll interval in seconden (standaard: 3) |
| `--no-ws` | Sla WebSocket over, gebruik alleen polling |

## Sender — na receiver starten

```bash
# Enkel bestand
python3 paramant-sender.py --key pgp_xxx --device mri-001 --file scan.dcm

# Stdin
echo "hello" | python3 paramant-sender.py --key pgp_xxx --device mri-001 --stdin

# Heartbeat
python3 paramant-sender.py --key pgp_xxx --device plc-001 --relay https://iot.paramant.app --heartbeat 30

# Map bewaken
python3 paramant-sender.py --key pgp_xxx --device mri-001 --watch /exports/dicom/

# HTTP proxy
python3 paramant-sender.py --key pgp_xxx --device mri-001 --listen 8765
# Dan: curl -X POST http://127.0.0.1:8765 --data-binary @file.pdf
```

### Opties sender

| Optie | Beschrijving |
|-------|-------------|
| `--key` | API key (verplicht) |
| `--device` | Device ID (verplicht) |
| `--relay` | Relay URL (auto-detect als leeg) |
| `--ttl` | Blob TTL in seconden (standaard: 300) |
| `--file` | Enkel bestand versturen |
| `--stdin` | Lees van stdin |
| `--heartbeat SEC` | Heartbeat elke N seconden |
| `--listen PORT` | HTTP proxy op lokale poort |
| `--watch DIR` | Map bewaken op nieuwe bestanden |

## End-to-end test
```bash
mkdir -p /tmp/recv-test

# Terminal 1
python3 paramant-receiver.py \
  --key pgp_xxx_redacted \
  --device e2e-test \
  --output /tmp/recv-test \
  --no-ws

# Terminal 2 — wacht op "Pubkeys geregistreerd" in terminal 1
echo "test $(date)" | python3 paramant-sender.py \
  --key pgp_xxx_redacted \
  --device e2e-test \
  --stdin

cat /tmp/recv-test/recv_000001.json
```

## Bestandstype detectie

| Extensie | Detectie |
|----------|---------|
| `.dcm` | DICOM magic bytes |
| `.json` | Begint met `{` |
| `.pdf` | Begint met `%PDF-` |
| `.bin` | Alles overige |

## Troubleshooting

| Probleem | Oorzaak | Oplossing |
|----------|---------|-----------|
| `Geen receiver pubkeys` | Receiver niet actief | Start receiver vóór sender |
| `Decrypt fout` | Keypair mismatch | Verwijder `~/.paramant/<device>.keypair.json`, herstart receiver |
| `HTTP 401` | Ongeldige API key | Controleer key begint met `pgp_` |
| `Relay niet bereikbaar` | Netwerk | Probeer `--relay https://paramant-ghost-pipe.fly.dev` |
