# Incident: ParaSign backend deploy crash-loop + rollback - 2026-05-28

## Summary

Attempted to deploy the ParaSign backend (PR #73, already merged to main) to
production. The `docker compose build` succeeded but **every relay sector
crash-looped on boot**, taking the relay tier down (502 / `/health`
unreachable on all 5 sectors). Detected immediately, **rolled back to the
pre-deploy images**, and **production was restored to 3.0.0** within ~1 minute.
ParaSign is NOT live; root cause found and fixed in this PR.

## Timeline

1. Tagged current (working 3.0.0) relay+admin images for rollback; wrote a
   manifest (`/home/paramant/backups/rollback-parasign-<ts>.txt`).
2. `git pull` on `/opt/paramant-relay` (-> main with #73), `docker compose build`
   -> **BUILD_OK**.
3. Rolling restart per sector. Each relay sector came up then immediately went
   `Restarting (1)`. All 5 sectors down; admin + redis unaffected.
4. Live check: `paramant.app/health` and all sectors UNREACHABLE; `/v2/sign`,
   `/v2/verify` -> 502.
5. **Rollback**: retagged the saved pre-deploy images back to the compose image
   names and `docker compose up -d --no-deps --force-recreate` (no rebuild).
6. All sectors `Up (healthy)`; external `/health` = 3.0.0 on all five; site,
   /dashboard, /admin all 200. Restored.

## Root cause

`relay/relay.js` (line 83) does:

```
const parasign = require('./parasign');
```

but `relay/Dockerfile` copies only `relay.js`, `lib/`, `crypto/` -- it never
copies the new top-level `relay/parasign.js`:

```
COPY relay.js ./
COPY lib/ ./lib/
COPY crypto/ ./crypto/
```

So in the built image, `require('./parasign')` throws `MODULE_NOT_FOUND` at
startup and the relay process exits, repeatedly (crash-loop). The unit tests
(`relay/crypto/parasign.test.js`) import the module directly on the host, so CI
passed and never exercised the Docker image's file set -- the gap was invisible
to CI.

## Fix (this PR)

Add the missing copy to `relay/Dockerfile`:

```
COPY relay.js ./
COPY parasign.js ./
COPY lib/ ./lib/
COPY crypto/ ./crypto/
```

## Current state

- Production: healthy, 3.0.0, all sectors + admin up. Unchanged from before the
  attempt (rolled back to identical images).
- ParaSign endpoints `/v2/sign` + `/v2/verify`: still NOT live (relay running the
  pre-#73 image).
- **State mismatch to be aware of**: `/opt/paramant-relay` git checkout is at
  current main (includes #73) while the *running images* are the pre-#73 ones.
  Do NOT run `docker compose build`/`up --build` on the server until this fix is
  merged + pulled, or it will rebuild the same broken image. The rollback
  manifest + tagged images remain available.

## Safe retry plan (after this PR merges)

1. Merge this PR (Dockerfile fix) to main.
2. On `/opt/paramant-relay`: `git pull`, `docker compose build`, rolling restart
   per sector with health checks (same procedure, now with parasign.js present).
3. Verify `/v2/sign` -> 401 (needs `X-Api-Key`) and `/v2/verify` -> 400 (needs
   body) = endpoints live.
4. End-to-end smoke: client-side ML-DSA-65 sign of SHA3-256(doc) -> POST
   `/v2/sign` with `{document_hash, signature, signer_public_key}` + a
   disposable `X-Api-Key` -> `/v2/verify`.

## Frontend note (still pending, separate from this fix)

The ParaSign web UI is still unbuilt. The previously-proposed client design was
insecure/incorrect (it POSTed the signer's private key + the full document to
the relay). The correct design, per `relay/parasign.js` (notary model) and the
`paramant-sign` CLI, is:

- Sign **client-side**: `signature = ml_dsa65.sign(secretKey,
  sha3_256(document))`; send only `{document_hash (hex), signature (b64),
  signer_public_key (b64), signer_label}` plus `X-Api-Key`
  (`localStorage['paramant_api_key']`, prompt if absent). `/v2/verify` is public.
- Vendor the browser ML-DSA-65 bundle (no runtime US CDN, per M-06); the site
  already vendors ML-KEM the same way.

Build the UI only after the backend is verified live.
