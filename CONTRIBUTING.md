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
- RAM-only — no disk writes
- EU/DE jurisdiction — Hetzner Frankfurt only

## Questions?

Open an issue or reach out at mick@paramant.app
