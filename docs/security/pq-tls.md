# Next-level HTTPS: post-quantum (hybrid) TLS at the relay edge

PARAMANT already encrypts every payload with ML-KEM-768 + AES-256-GCM, so the
file contents are post-quantum safe end to end. The one classical link that
remains is the **TLS handshake** that carries those payloads between the client
and the relay's nginx edge: by default it negotiates the session key with
classical X25519 (ECDHE).

That matters because of **harvest-now-decrypt-later (HNDL)**: an adversary can
record encrypted traffic today and store it until a cryptographically-relevant
quantum computer (CRQC) exists, then break the recorded X25519 handshake and
recover the TLS session key. The application-layer ML-KEM ciphertext inside is
still safe, but TLS metadata — request paths, timing, headers, sizes, and
anything not separately encrypted — is exposed.

Making the **TLS handshake itself post-quantum** is the next level of HTTPS for
the relay. This guide shows how.

---

## What we use: X25519MLKEM768

The hybrid key-exchange group **`X25519MLKEM768`** combines:

- **X25519** — the battle-tested classical elliptic-curve exchange, and
- **ML-KEM-768** — the NIST FIPS 203 post-quantum KEM (the same primitive
  PARAMANT uses for payloads).

The TLS session secret is derived from **both**. It stays secret unless an
attacker breaks *both* X25519 *and* ML-KEM-768 — so you lose nothing relative to
today's security and gain quantum resistance. This is the IETF-standardised
hybrid named in RFC 9794 and is the default PQ group shipped by Chrome, Firefox,
Cloudflare, and OpenSSL 3.5.

> Hybrid (not pure ML-KEM) is deliberate: if a flaw is ever found in the
> still-young lattice KEM, the classical half keeps the handshake secure.

---

## Requirements

PQ-hybrid TLS is negotiated by the TLS library, not by nginx itself. You need a
build of nginx linked against a PQ-capable TLS stack:

| TLS stack | X25519MLKEM768 support |
|-----------|------------------------|
| **OpenSSL 3.5+** | Built in and **enabled by default** — nothing to configure. |
| **OpenSSL 3.2 – 3.4 + [oqs-provider](https://github.com/open-quantum-safe/oqs-provider)** | Supported once the provider is loaded. |
| OpenSSL ≤ 3.1, LibreSSL | Not supported — falls back to classical X25519. |

Check what your nginx is linked against:

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep -i ssl     # built-with version
openssl version                                # runtime version
openssl list -groups 2>/dev/null | grep -i mlkem   # is the group available?
```

On Ubuntu 24.10+/Debian 13+ the system OpenSSL is already 3.5+. On older
distros, run nginx from a container image built on OpenSSL 3.5 (for example a
recent `nginx` Docker tag) or compile OpenSSL 3.5 and point nginx at it.

---

## Enabling it

### The zero-config path (OpenSSL 3.5+)

If your edge already runs OpenSSL 3.5+, **you are done** — nginx offers
`X25519MLKEM768` automatically as its top-preference group, and any PQ-capable
client (Chrome 131+, Firefox 132+, recent curl/OpenSSL) will use it. The
shipped [`nginx-selfhost.conf`](../../nginx-selfhost.conf) does **not** pin
`ssl_ecdh_curve`, precisely so it never *disables* the PQ default.

### Pinning the preference order (optional)

To make the configuration explicit — PQ hybrid first, classical fallback —
uncomment this line in the `server { ... }` TLS block of
[`nginx-selfhost.conf`](../../nginx-selfhost.conf):

```nginx
ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
```

> **Only uncomment this on OpenSSL 3.5+ (or 3.2+ with oqs-provider).** Naming a
> group the TLS library does not recognise makes `nginx -t` fail and nginx
> refuses to start. That is why the line ships commented.

Reload after editing:

```bash
nginx -t && nginx -s reload
```

---

## Verifying

### With OpenSSL 3.5+

```bash
# Force the hybrid group; a successful handshake proves the edge supports it.
openssl s_client -connect relay.example.com:443 -groups X25519MLKEM768 </dev/null 2>/dev/null \
  | grep -E 'Negotiated|Server Temp Key'
# Expect: Negotiated TLS1.3 ... Server Temp Key: X25519MLKEM768
```

### With a browser

Open the site in Chrome 131+ → DevTools → **Security** panel → the connection
should list the key exchange as `X25519MLKEM768` (or `X25519Kyber768` on older
builds).

### With testssl.sh

```bash
testssl.sh --pq relay.example.com
```

---

## What the shipped config already gives you (A+ baseline)

Even before PQ, [`nginx-selfhost.conf`](../../nginx-selfhost.conf) is hardened
to an SSL Labs **A+** baseline:

- **TLS 1.2 + 1.3 only** — no SSLv3/TLS 1.0/1.1.
- **AEAD-only cipher suites** — ECDHE + AES-GCM / ChaCha20-Poly1305; the legacy
  `HIGH:!aNULL:!MD5` catch-all is gone.
- **Forward secrecy everywhere** — ECDHE key exchange, `ssl_session_tickets off`.
- **OCSP stapling** — `ssl_stapling on` + `ssl_stapling_verify on`.
- **HSTS preload** — `max-age=63072000; includeSubDomains; preload`.
- **Hardened headers** — `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `X-Permitted-Cross-Domain-Policies`.
- **Slowloris timeouts** + `client_max_body_size` + per-endpoint rate limits.

Adding PQ-hybrid key exchange on top is what takes the edge from "A+ classical"
to "A+ and quantum-resistant".

---

## FAQ

**Does this change the wire format or break old clients?**
No. PQ-hybrid is negotiated during the TLS handshake. Clients that do not
support `X25519MLKEM768` transparently fall back to classical X25519 — the
application protocol is untouched.

**Do I still need application-layer ML-KEM if TLS is post-quantum?**
Yes. The relay is zero-knowledge by design: payloads stay encrypted with
ML-KEM-768 + AES-256-GCM so the relay never sees plaintext. PQ-TLS protects the
*transport metadata*; it does not replace end-to-end payload encryption.

**Is pure ML-KEM (non-hybrid) better?**
No. Hybrid keeps a classical fallback so a future lattice break cannot, on its
own, retroactively expose recorded sessions. Use the hybrid group.
