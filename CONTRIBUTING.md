# Contributing to PARAMANT Ghost Pipe

Thanks for your interest in contributing.

## How it works

1. Fork or branch from `main`
2. Make your changes
3. Open a Pull Request with a clear description
4. I'll review and merge

## Branch naming

- `feature/description` — new functionality
- `fix/description` — bug fixes
- `docs/description` — documentation only

## Areas where help is welcome

- **Thunderbird FileLink integration** — `/outlook-addin/` as reference
- **SDK improvements** — `sdk-js/` and `sdk-py/`
- **Documentation** — API docs, examples, use cases
- **Security review** — relay logic in `relay/`

## Ground rules

- No secrets, tokens, or API keys in commits
- No changes to `relay/ghost-pipe-relay.js` without discussion first — this is production code
- Keep PRs focused — one thing per PR

## Protocol constraints (never compromise)

- ML-KEM-768 — key encapsulation
- AES-256-GCM — symmetric encryption
- Burn-on-read — destroyed after first download
- Zero plaintext — relay never sees content
- RAM-only blobs — encrypted payload data never written to disk (CT log hashes and API keys are persisted)
- EU/DE jurisdiction — Hetzner Frankfurt only

## Questions?

Open an issue or reach out at privacy@paramant.app

## Hall of Fame

Security researchers and contributors who have helped make PARAMANT better:

| Researcher | Handle | Contribution | Date |
|------------|--------|--------------|------|
| Ryan Williams | [@scs-labrat](https://github.com/scs-labrat) | Independent security review — 4 critical · 5 high · 6 medium · 5 low (20 findings total) · [Smart Cyber Solutions](https://www.linkedin.com/in/ryan-williams-4068351b8/) | April 2026 |
| Hendrik Bruinsma | [@readefries](https://github.com/readefries) | Thunderbird FileLink add-on (built & contributed); security review: Argon2 race condition (MEDIUM), `/health` info leak (MEDIUM), `X-Paramant-Views-Left` header leak (MEDIUM), `/v2/ct/proof` routing (LOW), stale CSP domain (LOW); bug reports: QR code display bug, ParaDrop fingerprint mismatch on refresh, receiver stuck at fingerprint verification, preload burn bug | April 2026 |

Want to be on this list? Find something wrong. Report it. We fix it publicly.

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.
