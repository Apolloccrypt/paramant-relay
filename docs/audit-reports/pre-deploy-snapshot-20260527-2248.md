# Pre-deploy production snapshot - 2026-05-27T22:48:19+02:00

Rollback reference captured immediately before the v3.0.0 deploy.
Method: read-only HTTPS to paramant.app + sector subdomains. No SSH, no auth.
Repo main at capture: 5519d24 (Merge pull request #59).

## TL;DR rollback baseline

The currently-live production is the **pre-3.0.0** build. If a v3.0.0 deploy must
be rolled back, this is the state to return to:

- All five relays report **version 2.5.0**, edition **licensed**, license to
  `paramant.app`, expiry `2027-01-01`.
- `/v2/capabilities` advertises **3 KEM + 18 SIG** (all 21 loaded) -- i.e. the
  pre-R006 "load everything" behaviour (R006 core-mode is NOT live yet).
- `/setup` and `/all-systems-go` return **404** -- the M11 wizard (PR #56) and
  static serving (PR #59) are NOT deployed yet.
- Signed tree head (STH) tree_size = **86** at capture.
- All frontend assets Last-Modified **Mon, 27 Apr 2026 14:44:05 GMT** (deploy date).
- TLS cert: Let's Encrypt E8, valid **2026-05-16 .. 2026-08-14**.

A successful v3.0.0 deploy should flip: version -> 3.0.0, capabilities -> core
(ML-KEM-768 + ML-DSA-65 only) unless CRYPTO_MODE=extended, /setup + /all-systems-go
-> 200, asset Last-Modified -> the new deploy time.

## Relay health (per sector)

| Host | version | sector | edition | license_expires |
|------|---------|--------|---------|-----------------|
| paramant.app | 2.5.0 | relay | licensed | 2027-01-01 |
| health.paramant.app | 2.5.0 | health | licensed | 2027-01-01 |
| finance.paramant.app | 2.5.0 | finance | licensed | 2027-01-01 |
| legal.paramant.app | 2.5.0 | legal | licensed | 2027-01-01 |
| iot.paramant.app | 2.5.0 | iot | licensed | 2027-01-01 |

Raw (paramant.app/health):
```
{"ok":true,"version":"2.5.0","sector":"relay","edition":"licensed","max_keys":null,"license_expires":"2027-01-01T00:00:00.000Z","license_issued_to":"paramant.app"}
```

## Crypto capabilities (/v2/capabilities)

- wire_version: 1
- KEM (3): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- SIG (18): none, ML-DSA-44, ML-DSA-65, ML-DSA-87, Falcon-512, Falcon-1024,
  SLH-DSA-SHA2-{128s,128f,192s,192f,256s,256f}, SLH-DSA-SHAKE-{128s,128f,192s,192f,256s,256f}
- All entries loaded=true (pre-R006 behaviour).

## Signed tree head (/v2/sth)

```
{"tree_size":86,"version":1,"relay_id":"https://relay.paramant.app","sig":true}
```

## Public endpoint status

| Endpoint | Status | Size |
|----------|--------|------|
| /v2/status | 401 | 55B (correctly rejects unauth) |
| /v2/pubkey | 200 | 2726B |
| /v2/relays | 200 | 55B (empty registry: relays:[], total:0) |
| /v2/ct/log | 200 | 19544B |
| /ct-log | 200 | 36953B |
| /robots.txt | 200 | 141B |
| /sitemap.xml | 200 | 7438B |
| /.well-known/security.txt | 200 | 788B |
| /.well-known/openpgp-key.asc | 200 | 344B (still the PLACEHOLDER key) |

## Frontend assets (rollback fingerprints)

ETag + Content-Length + Last-Modified per page. Post-deploy these change for any
updated page; /setup + /all-systems-go currently 404 (served the SPA 404 body).

```
/                200  etag="69ef7635-92c8" len=37576   lm=Mon, 27 Apr 2026 14:44:05 GMT
/docs            200  etag="69ef7635-10c21" len=68641   lm=Mon, 27 Apr 2026 14:44:05 GMT
/pricing         200  etag="69ef7635-6c9e" len=27806   lm=Mon, 27 Apr 2026 14:44:05 GMT
/dashboard       200  etag="69ef6484-967c" len=38524   lm=Mon, 27 Apr 2026 13:28:36 GMT
/send            200  etag="69ef7635-9284" len=37508   lm=Mon, 27 Apr 2026 14:44:05 GMT
/parashare       200  etag="69ef65e7-f95b" len=63835   lm=Mon, 27 Apr 2026 13:34:31 GMT
/drop            200  etag="69ef7635-b4e0" len=46304   lm=Mon, 27 Apr 2026 14:44:05 GMT
/setup           404  (SPA 404 body, len=12699)
/all-systems-go  404  (SPA 404 body, len=12699)
/security        200  etag="69ef7635-7cb2" len=31922   lm=Mon, 27 Apr 2026 14:44:05 GMT
/status          200  etag="69ef7635-5911" len=22801   lm=Mon, 27 Apr 2026 14:44:05 GMT
```

## Security headers (paramant.app/)

```
HTTP/2 200
server: nginx
via: 1.1 Caddy
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: no-referrer
permissions-policy: geolocation=(), microphone=(), camera=(self)
content-security-policy: default-src 'self'; connect-src 'self' https://relay.paramant.app wss://relay.paramant.app https://health.paramant.app wss://health.paramant.app https://legal.paramant.app wss://legal.paramant.app https://finance.paramant.app wss://finance.paramant.app https://iot.paramant.app wss://iot.paramant.app; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://cdn.jsdelivr.net https://server.arcgisonline.com
```

## TLS certificate (paramant.app:443)

```
issuer=C=US, O=Let's Encrypt, CN=E8
subject=CN=paramant.app
notBefore=May 16 08:10:30 2026 GMT
notAfter=Aug 14 08:10:29 2026 GMT
```

## Notes / known open items at capture time (cross-ref production audit PR #52)

- security.txt still advertises a PLACEHOLDER PGP key (openpgp-key.asc 344B).
- /v2/relays registry empty despite 5 live relays.
- Google Fonts + jsDelivr origins still allowed in CSP (admin.html / parashare).
- These are pre-existing and unrelated to the v3.0.0 deploy; recorded so the
  post-deploy diff is unambiguous.

## Verification commands (re-run post-deploy to confirm the flip)

```
curl -s https://paramant.app/health | jq .version          # expect 3.0.0 after deploy
curl -s https://paramant.app/v2/capabilities | jq '.kem|length, .sig|length'
curl -s -o /dev/null -w '%{http_code}\n' https://paramant.app/setup   # expect 200 after deploy
```
