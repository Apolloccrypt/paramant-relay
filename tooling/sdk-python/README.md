# paramant-sdk — Python
```bash
pip install paramant-sdk
```

## Vereisten
- Python 3.8+
- `pip install cryptography`
- Optioneel: `pip install kyber-py` voor ML-KEM-768

## Klassen

### GhostPipe — enkele relay
```python
from paramant_sdk import GhostPipe

gp = GhostPipe(
    api_key  = "pgp_xxx",
    device   = "device-001",
    relay    = "https://health.paramant.app"  # auto-detect als leeg
)

# Receiver setup (verplicht voor ontvangen)
gp.receive_setup()

# Sturen
hash = gp.send(b"hello world")
hash = gp.send(open("scan.dcm", "rb").read())

# Ontvangen
data = gp.receive(hash)

# Continu luisteren (blocking)
gp.listen(callback=lambda data: print("ontvangen:", len(data), "bytes"))

# Webhook registreren
gp.register_webhook("https://mijn-server.nl/webhook")
```

### GhostPipeCluster — automatische failover
```python
from paramant_sdk import GhostPipeCluster

cluster = GhostPipeCluster(
    api_key = "pgp_xxx",
    device  = "device-001",
    relays  = [
        "https://health.paramant.app",
        "https://paramant-ghost-pipe.fly.dev",
    ]
)

hash = cluster.send(data)
data = cluster.receive(hash)
```

## Sectoren kiezen
```python
# Healthcare — DICOM, NEN 7510
gp = GhostPipe("pgp_xxx", "mri-001", relay="https://health.paramant.app")

# Legal — contracten, notarieel
gp = GhostPipe("pgp_xxx", "kantoor-001", relay="https://legal.paramant.app")

# Finance — geen US CLOUD Act
gp = GhostPipe("pgp_xxx", "bank-001", relay="https://finance.paramant.app")

# IoT — SCADA, sensoren
gp = GhostPipe("pgp_xxx", "plc-factory-01", relay="https://iot.paramant.app")
```

## Publiceren (PyPI)
```bash
pip install build twine
python3 -m build
twine upload dist/*
```

Package: [pypi.org/project/paramant-sdk](https://pypi.org/project/paramant-sdk)
