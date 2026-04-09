# Security Audit — April 2026

**Auditor:** Ryan Williams · Director, [Smart Cyber Solutions Pty Ltd](https://www.linkedin.com/in/ryan-williams-4068351b8/) (Victoria, AU)
**Scope:** Full codebase review — relay, frontend, SDKs, admin panel, nginx, Docker stack
**Method:** Independent, uncompensated voluntary review. No prior access to internals.
**Raw report:** [pentest-report-2026-04-08.txt](../pentest-report-2026-04-08.txt)
**Summary:** 4 critical · 5 high · 6 medium · 5 low

> All findings are being addressed publicly. This page is updated as patches ship.

---

## Status legend

| Symbol | Meaning |
|--------|---------|
| ✓ | Patched and deployed |
| ⚙ | Fix in progress |
| ○ | Acknowledged — documented, accepted risk, or design tradeoff |
| ● | Open |

---

## Critical

| # | Finding | Status | Notes |
|---|---------|--------|-------|
| 1 | **API key leaked in receiver URL** — sender's `pgp_` key embedded in `/ontvang?k=pgp_xxx` share link | ⚙ | Fix: scope to a session token derived from the PSS/inv_ mechanism. Relay already logs `key_in_querystring` warning. |
| 2 | **`await` in non-async `ws.onmessage`** — fingerprint path silently broken in parashare.html | ⚙ | HTTP polling fallback masks it in practice. Async handler fix pending. |
| 3 | **Python SDK — no key zeroization** — `sdk-py/paramant_sdk/__init__.py` (pip package) has no `_zero()` calls unlike `scripts/paramant_sdk.py` | ⚙ | Zeroization will be added to the pip package to match the scripts version. |
| 4 | **Plaintext filename in relay metadata** — `files[0].name` stored in cleartext in `pubkeys` Map and `downloadTokens` Map on relay | ⚙ | Filename should be encrypted client-side before being passed through the token metadata channel. |

---

## High

| # | Finding | Status | Notes |
|---|---------|--------|-------|
| 5 | **Metadata size leakage** — `total_chunks` visible to relay, allowing order-of-magnitude file size inference despite 5 MB block padding | ○ | Accepted tradeoff. Padding blocks exact size; chunk count unavoidable for streaming assembly. Documented in threat model. |
| 6 | **`_zero()` CPython-only** — `ctypes.memset` approach fails silently on PyPy / GraalPy / future CPython without warning | ⚙ | Add runtime warning when zeroization is not available. |
| 7 | **HKDF salt inconsistency** — browser uses `cipherText.slice(0,32)` as salt (correct); Python SDK uses static string `paramant-gp-v1` as salt (weakens domain separation on CLI-to-CLI path) | ⚙ | Python SDK HKDF salt will be derived from KEM ciphertext to match browser behavior. |
| 8 | **No GCM AAD** — version byte and chunk metadata not integrity-bound to ciphertext in browser or Python SDK | ⚙ | AAD will be added: version byte + chunk index bound to each GCM seal. |
| 9 | **stream-next hash uses full API key as HMAC secret** — sequence hashes are precomputable from any key holder | ⚙ | Noted as `// FIX` comment in relay. Session-scoped nonce will be introduced. |

---

## Medium

| # | Finding | Status | Notes |
|---|---------|--------|-------|
| 10 | **Admin operations write to disk** — `POST /v2/admin/keys` and `/revoke` call `fs.writeFileSync` | ○ | Intentional and documented. RAM-only applies to blob (payload) storage. API key config and CT log hashes are explicitly persisted. See [privacy policy](../frontend/privacy.html) and [self-hosting guide](self-hosting.md). |
| 11 | **CORS origin fallback** — non-allowlisted origins receive `Access-Control-Allow-Origin: https://paramant.app` | ○ | Not exploitable. Real auth is the API key. Noted. |
| 12 | **No rate limiting on `/v2/outbound`** — valid key holder can burn other users' blobs via download token if intercepted | ⚙ | Rate limit on outbound per-key will be added. Download token path intentionally keyless for link sharing. |
| 13 | **WebSocket API key in query string** — upgrade requests carry `?k=pgp_xxx` in URL, visible in access logs | ⚙ | Will move to a pre-upgrade HTTP handshake or short-lived ticket. |
| 14 | **CT log Merkle tree non-standard** — odd-leaf duplication differs from RFC standard; tree rebuilt from scratch on each append; "proofs" are just last 8 leaf hashes | ⚙ | Incremental tree and proper inclusion proofs are planned. |
| 15 | **DID auth uses raw hex as SPKI** — `crypto.verify` receives raw key bytes where DER-SPKI is expected; DID auth likely non-functional | ⚙ | DID auth path to be fixed or disabled pending rewrite. |

---

## Low

| # | Finding | Status | Notes |
|---|---------|--------|-------|
| 16 | **Duplicate route handlers** — `/v2/ct/log` and `/v2/ct/proof/:index` defined twice (pre-auth and post-auth); post-auth versions are dead code | ⚙ | Dead code will be removed. |
| 17 | **Google Fonts CDN in drop.html** — external CDN call leaks user IP to Google in a privacy-first product | ⚙ | Fonts will be self-hosted or removed. |
| 18 | **CSP allows `unsafe-inline`** — weakens XSS protection; structurally required by inline `<script>` blocks | ⚙ | Nonces will be introduced to replace blanket `unsafe-inline`. |
| 19 | **Nginx dead Cloudflare config** — `set_real_ip_from 127.0.0.1` with `real_ip_header CF-Connecting-IP` is a Cloudflare remnant | ○ | Harmless (header unset without Cloudflare). Will be cleaned up in next nginx pass. |
| 20 | **Python SDK private keys serialized to disk** — `~/.paramant/*.keypair.json` stored as hex; `_zero()` only works on in-memory bytes, not persisted JSON | ⚙ | Key files will use encrypted storage or documented secure-deletion guidance. |

---

## Disclosure timeline

| Date | Event |
|------|-------|
| 2026-04-08 | Ryan Williams submits full report |
| 2026-04-09 | Report reviewed, findings triaged, this tracking page published |
| TBD | Critical patches shipped (findings #1–4) |

---

## Acknowledgement

Ryan Williams performed this review independently and without compensation. His work directly improves the security of everyone who uses PARAMANT. We are grateful.

If you find a security issue, see [SECURITY.md](../SECURITY.md) for responsible disclosure.
