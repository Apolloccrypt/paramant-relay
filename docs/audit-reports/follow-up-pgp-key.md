# Follow-up: PGP key for privacy@paramant.app

Date: 2026-05-27
Status: Placeholder removed; honest notice now served at the key URL.
Source findings: docs/audit-reports/production-site-2026-05-27.md (M-03 + /careers LOW)

## What is live now

`/.well-known/openpgp-key.asc` no longer contains a fake PGP block with
`[PLACEHOLDER -- GENERATE REAL KEY AND REPLACE]`. It now serves a plain-text
notice stating that no public key is published at this URL and that researchers
can email privacy@paramant.app to request an out-of-band key exchange. No fake
key, no false assurance.

Both copies of security.txt (frontend/security.txt and
frontend/.well-known/security.txt) had the `Hiring: https://paramant.app/careers`
line removed because /careers returns 404. The `Encryption:` line is kept: the
URL it points at now returns 200 with useful instructions instead of a
placeholder.

## What still needs to happen (Mick action)

When Mick (or a designated security contact) wants a real PGP key published:

1. Generate a key pair locally (do not let tooling do this -- see below):
   `gpg --full-generate-key`  (ed25519 + cv25519, or rsa4096)
2. Export the public block:
   `gpg --armor --export privacy@paramant.app > openpgp-key.asc`
3. Replace frontend/.well-known/openpgp-key.asc with the real block.
4. Optionally add fingerprint pinning context near the `Encryption:` line in
   both security.txt copies.
5. Optionally publish to keys.openpgp.org (and keyserver.ubuntu.com).
6. Update or delete this follow-up doc once the real key is live.

## Why the CLI did not do this itself

A PGP key asserts the cryptographic identity of the security contact. An
autonomous CLI does not hold and must not claim that identity. Generating a key
under privacy@paramant.app without the owner holding the private key would be a
false claim of identity -- the opposite of what this fix is meant to remove.
