# R013. License-server protocol

Date: 2026-05-27

Status: Draft (specification only; implementation in later milestones)

Deciders: Mick (project owner)

Relates to: R006 (crypto-mode / ML-DSA-65), R007 (add-on architecture),
R010 (package formats). Enables future R014 (management plane) and R015
(release channels) to reference a common license model.

## Context

Today a relay's commercial entitlement is an *offline, Ed25519-signed
license* carried in the `PLK_KEY` environment variable. Its format is
`plk_<base64url(payload_json + ed25519_signature)>`, where the last 64
bytes are an Ed25519 signature over a small JSON payload
(`{ max_keys, expires_at, issued_to, issued_at }`). The relay verifies the
signature against a hardcoded Paramant public key, checks `expires_at`, and
either runs as `licensed` (with `max_keys`) or falls back to Community
Edition. The Community cap is a fixed 5 keys and is never env-overridable
(BUSL-1.1 section 4).

This is enough for early self-hosters but insufficient for selling Paramant
as an appliance-style product, because the offline license:

- carries only a user-count and an expiry -- there is no general
  capability-set (blob size, retention, add-ons, branding, support tier);
- cannot be revoked once issued -- a refunded or non-paying customer keeps
  their entitlement until `expires_at`;
- cannot be updated without re-issuing a key the operator must paste into
  `.env` by hand;
- gives Paramant no consented visibility into license usage for support and
  billing.

To productise, Paramant needs to:

- issue per-customer licenses with different tiers (Community / Pro /
  Enterprise);
- enforce tier capabilities beyond user-count;
- revoke licenses on payment failure without operator cooperation;
- push an updated capability-set without forcing a `.env` edit;
- observe (only with explicit consent) aggregate license usage.

This ADR defines the *wire protocol* by which a customer relay obtains its
capability-set from Paramant's central license-server. It is a pure
specification; no relay or server code is changed by this document.

## Decision

### Architecture

- **License-server**: an HTTPS endpoint on Paramant's root server
  (`license.paramant.app`) that issues signed capability-sets keyed by
  license-key.
- **Customer relay**: at startup and every 6 hours, POSTs its license-key
  to the license-server, receives a signed capability-set, and caches it
  locally.
- **Offline grace period**: 7 days. After 7 days without a successful
  check-in, the relay degrades to Community caps (5 users, no add-ons).

The online protocol below is *additive* to the existing offline Ed25519
license (see "Relationship to the existing offline license"). It does not
remove the offline path, which remains the air-gap / bootstrap fallback.

### Wire format -- check-in request

```
POST https://license.paramant.app/v1/license/check
Content-Type: application/json

{
  "license_key": "plk_<64-hex>",
  "relay_id": "<ML-DSA-65 public key hash; identifies the relay instance>",
  "version": "3.0.0",
  "telemetry": {
    "opted_in": false,
    "user_count": null,
    "transfer_count_24h": null
  },
  "nonce": "<random 16 bytes, hex>"
}
```

`telemetry` fields are `null` when the operator has opted out (the default).
Opt-in, configured via `/admin/settings`, sends aggregate counters only
(number of users, number of transfers) -- never content, filenames, keys, or
recipient identities. `nonce` is echoed in the signed response to bind the
response to this request and prevent replay of an older capability-set.

### Wire format -- check-in response

HTTP 200 (license active):

```
{
  "issued_at": "2026-05-28T10:00:00Z",
  "expires_at": "2026-05-28T16:00:00Z",
  "license_key": "plk_<64-hex>",
  "relay_id": "<echoed from request>",
  "nonce": "<echoed from request>",
  "tier": "pro",
  "capabilities": {
    "max_users": 50,
    "max_blob_size_mb": 25,
    "retention_max_seconds": 86400,
    "addons_allowed": ["storage-mirror", "notification-bridge"],
    "ml_dsa_required": false,
    "support_level": "email",
    "custom_branding": false
  },
  "next_check_in_seconds": 21600,
  "signature": "<ML-DSA-65 signature over the canonical JSON of all fields above except signature>"
}
```

Status codes:

- **200** -- license active; capability-set returned and cached.
- **402** -- payment failed, license suspended. Relay degrades to Community
  caps immediately and surfaces a billing notice to the admin.
- **404** -- license-key unknown. Relay refuses to enter licensed mode and
  raises an error to the admin (it still starts in Community Edition).
- **410** -- license revoked. Terminal state; relay degrades to Community
  and stops retrying with this key.
- **503** -- license-server unavailable. Relay keeps serving the cached
  capability-set and runs the grace-period timer (see "Offline grace").

`expires_at` here is the validity window of *this capability-set* (short,
hours), distinct from the commercial license term tracked server-side.

### Signature verification

The customer relay embeds a Paramant licensing public key
(`paramant-licensing-pubkey`, ML-DSA-65). This is the identity key of the
license-server and is deliberately *separate* from both the relay's own
identity key and the existing Ed25519 license-signing key. The relay
verifies the ML-DSA-65 signature on every response and refuses any unsigned
or invalid response (treating it like a 503: serve cache, run grace timer).

ML-DSA-65 is chosen over a classical signature (or JWT RS256/HS256) to keep
the licensing channel post-quantum consistent with the rest of the stack
(R006 / paramant-core). The legacy offline license stays Ed25519 for
backward compatibility; new online capability-sets are ML-DSA-65.

Key rotation:

- The license-server begins advertising the next public-key hash 30 days
  before the current key expires (in a `next_pubkey_hash` response field).
- The relay adopts the new embedded key on its next image upgrade.
- Old keys remain valid for 60 days after rotation so that relays upgrading
  on a normal cadence never see a verification gap.

### Capability enforcement

Capabilities are enforced on the request path, not only at config-load time,
so that a mid-session downgrade (402/410, or grace expiry) takes effect
without a restart. Illustrative pseudocode (not a code change in this ADR):

```
const caps = license.getActiveCapabilities();
if (newUserCount > caps.max_users) {
  return res.status(402).json({ error: "tier_limit_users" });
}
```

The same pattern gates `max_blob_size_mb`, `retention_max_seconds`,
`addons_allowed` (cross-checked against R007 add-on manifests), and
`custom_branding`. If a capability key is unknown to the relay it is ignored
(forward compatibility); removing a capability key is a breaking change that
requires a major version bump.

### Offline grace

The last successful, signed check-in is cached at
`/data/license-cache.json`. The cache stores the full signed response, so
the relay re-verifies the ML-DSA-65 signature on read; a tampered cache
fails verification and the relay degrades to Community. When the
license-server is unreachable:

- **within 7 days** of the last good check-in: serve the cached
  capability-set unchanged, logging a warning on each failed attempt;
- **after 7 days**: degrade to Community caps (5 users, no add-ons);
- **on recovery**: re-check at the next interval and restore full caps
  immediately on a valid 200.

### Threat model

In scope (addressed by this protocol):

- *Operator edits `.env` to claim a higher tier*: rejected -- there is no
  validly signed capability-set for the claimed tier.
- *Operator tampers with a check-in response in transit*: caught by the
  ML-DSA-65 signature check (TLS plus signature; signature is authoritative).
- *Operator runs offline forever to dodge revocation*: bounded to 7 days by
  the grace period.
- *Operator copies one license-key across many deployments*: the
  license-server records `relay_id` per key and can refuse or flag a second
  relay presenting the same key.
- *Replay of a stale, more-generous capability-set*: bound by the echoed
  `nonce` and the short `expires_at`.

Out of scope:

- *License-server compromise*: handled by Paramant's own root-server
  hardening, not by this protocol.
- *Local binary patching of the capability check*: an operator with root on
  their own host can modify the relay; this is a BUSL-1.1 license-violation
  matter, not a protocol control.
- *Timing/side-channel analysis of the capability check*: out of scope.

## Consequences

- The license-server becomes critical infrastructure on Paramant's root
  server, with its own availability and key-management requirements.
- The relay gains a small license-client module (request, verify, cache,
  grace timer) plus capability-check middleware on premium routes.
- Self-hosters with no license-key are unaffected: the relay starts in
  Community Edition exactly as today.
- Existing offline `PLK_KEY` (Ed25519) holders remain backward compatible;
  the offline license is treated as a baseline entitlement that the online
  protocol can extend.
- Air-gapped deployments cannot reach `license.paramant.app`; they rely on
  the offline license and an explicit offline-license bundle (deferred to a
  future ADR/extension).
- Capability-set evolution is forward compatible (unknown keys ignored);
  removing a capability is a major-version change.

## Alternatives considered

- **Keep only the static/offline license (status quo)**: rejected. Cannot
  enforce payment-failure revocation without operator cooperation and cannot
  carry a general capability-set.
- **JWT-based licenses (RS256/HS256)**: rejected. Classical crypto; using
  ML-DSA-65 keeps the licensing channel post-quantum consistent with the
  rest of the stack.
- **Hardware-bound licenses**: rejected. Self-hosters move hosts routinely;
  `relay_id`-based binding is sufficient deterrence.
- **Always-online check, no grace period**: rejected. A network outage would
  take down paying customers' relays; a 7-day grace is the industry norm.
- **Per-request license-server check**: rejected. Excess load on the
  license-server; a cached capability-set refreshed every 6 hours is enough.

## Implementation order

1. License-server MVP (this ADR is its specification).
2. Relay-side license-client module (request, verify, cache).
3. Capability-check middleware on premium routes.
4. Admin panel: license-status display plus manual refresh.
5. Offline grace plus cache-signature verification.
6. Telemetry opt-in flow (separate UI; separate ADR).

Rough effort: 2-3 weeks of engineering for the license-server plus the
relay-side client.
