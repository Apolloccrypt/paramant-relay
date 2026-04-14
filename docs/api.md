# API Reference — PARAMANT v2.4.5

## Base URLs

| Sector | URL | Compliance |
|--------|-----|------------|
| General | https://relay.paramant.app | — |
| Healthcare | https://health.paramant.app | NEN 7510, DICOM |
| Legal | https://legal.paramant.app | eIDAS, KNB |
| Finance | https://finance.paramant.app | NIS2, DORA |
| IoT | https://iot.paramant.app | IEC 62443 |

## Authentication

All endpoints require: `X-Api-Key: your_key`

- `pgp_` prefix = end user key (10 uploads/day free)
- `plk_` prefix = operator license key

## Endpoints

### POST /v2/inbound — Send a file

```bash
curl -X POST https://relay.paramant.app/v2/inbound \
  -H "X-Api-Key: pgp_your_key" \
  -H "X-Device-Id: sender-001" \
  --data-binary @file.pdf

# Response
{"blob_hash":"sha256...","ttl":3600,"size":5242880}
```

### GET /v2/outbound — Receive a file (burn-on-read)

```bash
curl https://relay.paramant.app/v2/outbound \
  -H "X-Api-Key: pgp_your_key" \
  -H "X-Device-Id: receiver-001" \
  --output received.pdf

# File destroyed immediately after this request
```

### GET /v2/stream-next — Poll for next blob

```bash
curl https://relay.paramant.app/v2/stream-next \
  -H "X-Api-Key: pgp_your_key" \
  -H "X-Device-Id: receiver-001"

# Response: {"blob_hash":"sha256...","queued_at":"2026-04-14T..."}
# No content (204) if no pending blobs
```

### GET /health — Relay status (public)

```bash
curl https://relay.paramant.app/health
# {"ok":true,"version":"2.4.5","sector":"relay","edition":"community"}
```

### GET /v2/ct — CT log (authenticated)

```bash
curl https://health.paramant.app/v2/ct \
  -H "X-Api-Key: pgp_your_key"
# {"size":58,"root":"deed04dd...","entries":[...]}
```

### GET /v2/relays — Relay registry (public)

```bash
curl https://relay.paramant.app/v2/relays
# {"total":5,"relays":[{"url":"...","version":"2.4.5",...}]}
```

## Rate limits

| Tier | Uploads/day | Retention |
|------|-------------|-----------|
| Free (pgp_) | 10 | 1 hour |
| Community (plk_) | unlimited | 1 hour |
| Professional | unlimited | 24 hours |
| Enterprise | unlimited | configurable |

## Error codes

| Code | Meaning |
|------|---------|
| 401 | Invalid API key |
| 404 | No pending blob for this device |
| 429 | Rate limit exceeded |
| 500 | Relay error |
