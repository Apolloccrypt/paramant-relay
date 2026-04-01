# PARAMANT — Tooling

Client tools voor het Ghost Pipe protocol. Draaien op jouw machine — niet op de relay server.

## Overzicht

```
tooling/
├── sdk-python/         Python SDK — pip install paramant-sdk
├── sdk-javascript/     JavaScript SDK — npm install @paramant/connect
├── sender-receiver/    Command-line sender + receiver + wrapper
└── admin-cli/          Admin CLI voor key beheer
```

## Snelstart

### Python SDK
```bash
pip install paramant-sdk
```
```python
from paramant_sdk import GhostPipe

gp = GhostPipe("pgp_xxx", "device-001", relay="https://health.paramant.app")
gp.receive_setup()
hash = gp.send(open("file.pdf", "rb").read())
data = gp.receive(hash)
```

### JavaScript SDK
```bash
npm install @paramant/connect
```
```javascript
import { GhostPipe } from '@paramant/connect';

const gp = new GhostPipe('pgp_xxx', 'device-001', { relay: 'https://health.paramant.app' });
const hash = await gp.send(buffer);
const data = await gp.receive(hash);
```

### Command-line (sender/receiver)
```bash
pip install cryptography

# Terminal 1 — start receiver eerst
python3 sender-receiver/paramant-receiver.py \
  --key pgp_xxx \
  --device my-device \
  --output /tmp/received/

# Terminal 2 — na "Pubkeys geregistreerd" in terminal 1
python3 sender-receiver/paramant-sender.py \
  --key pgp_xxx \
  --device my-device \
  --file document.pdf
```

### Admin CLI
```bash
python3 admin-cli/paramant-admin.py add --label klant --plan pro --email klant@example.com
python3 admin-cli/paramant-admin.py list
python3 admin-cli/paramant-admin.py sync
```

## Relays per sector

| Sector | URL | Gebruik |
|--------|-----|---------|
| Healthcare | https://health.paramant.app | DICOM, HL7 FHIR, vitals |
| Legal | https://legal.paramant.app | Contracten, notarieel |
| Finance | https://finance.paramant.app | Banking, compliance |
| IoT | https://iot.paramant.app | SCADA, sensors, PLC |
| Anycast | https://paramant-ghost-pipe.fly.dev | Globale fallback |
