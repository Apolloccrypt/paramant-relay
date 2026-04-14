# paramant-sdk — Python

Python SDK for the PARAMANT post-quantum encrypted relay.

## Install

```bash
pip install paramant-sdk
```

## Quick start

```python
from paramant import Client

client = Client(api_key="pgp_your_key", relay="https://relay.paramant.app")

# Send a file
blob_hash = client.send("file.pdf", device="sender-001")

# Receive a file
client.receive("receiver-001", output="received.pdf")
```

## Sector routing

```python
# Healthcare
client = Client(api_key="pgp_xxx", relay="https://health.paramant.app")

# Legal
client = Client(api_key="pgp_xxx", relay="https://legal.paramant.app")
```

## Version

Current: 2.4.5 — matches relay v2.4.5

[Full API docs](https://paramant.app/docs) · [GitHub](https://github.com/Apolloccrypt/paramant-relay)
