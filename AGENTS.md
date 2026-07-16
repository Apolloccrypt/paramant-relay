# AGENTS.md

## Commit- en GitHub-stijl (hard, geldt voor elke agent)

Deze repos zijn Micks publieke repos onder zijn merk. Commit-messages, PR-teksten
en GitHub-comments volgen deze regels:

- Alles in Micks naam. Geen co-author-trailer (in welke schrijfwijze dan ook),
  geen generated-with-regel, geen enkele AI-attributie.
- Geen em-dashes (het teken U+2014). Geen emoji.
- Kaal en feitelijk. Herhaal niet wat de diff al toont.
- Nooit secrets, geen placeholders, geen debug-ruis of half-afgemaakte zinnen.
- Nooit echte persoons- of bedrijfsnamen in code, comments, commits, tests of
  branchnamen. Gebruik generieke placeholders: acct_demo, demo@example.com,
  signer Demo, bedrijf Acme. Echte verboden termen staan alleen in de
  gitignored .style-denylist, afgedwongen door de stijl-scan.

De poort is `scripts/check-commit-style.sh`. Die scant de commit-message(s) en de
toegevoegde diff-regels op deze fouten. Een commit die de scan laat FALEN mag niet
gepusht worden; herschrijf de message of de diff en commit opnieuw. De scan draait
op twee plekken:

- `bash tests/static-sanity.sh` (de gate vlak voor commit) draait de scan over de
  laatste commit, naast de bestaande checks.
- De committed pre-push hook `.githooks/pre-push` draait dezelfde scan over het
  push-bereik. Committed hooks activeren niet vanzelf; zet ze eenmalig aan met:

  ```
  git config core.hooksPath .githooks
  ```

## Cursor Cloud specific instructions

PARAMANT is a post-quantum encrypted file relay. The components relevant to local
development are the **relay** (`relay/`, Node.js HTTP server), the **admin panel**
(`admin/`, Express), and the static **frontend** (`frontend/`). Standard
build/run commands live in `README.md`, `CONTRIBUTING.md`, `package.json` scripts,
and `scripts/dev-local.sh` — prefer those. The notes below are the non-obvious
caveats discovered while setting the environment up.

### Running the dev stack
- `bash scripts/dev-local.sh` boots the full local stack on a single origin:
  relay-health on `:3001`, admin on `:4200`, and a single-origin dev proxy on
  `http://localhost:8080`. It prints a passkey setup URL and tails to
  `/tmp/paramant-dev-relay.log` and `/tmp/paramant-dev-admin.log`. Ctrl-C stops all
  three. This is the dev path; `docker compose up` (the README path) is
  production-like and Docker is **not** installed in this environment.
- Redis is required and is installed as a system service. If `redis-cli ping`
  does not return `PONG`, start it with `sudo service redis-server start`.

### The `@paramant/core` native binding (critical gotcha)
- `relay/package.json` declares `@paramant/core` as a file link to a **sibling
  repo that is not in this monorepo**: `file:../../paramant-core/crates/paramant-core-node`.
  The relay loads its ML-KEM-768 / ML-DSA-65 crypto from this binding at startup
  (`relay/crypto/bootstrap.js` requires the impls eagerly), so **the relay crashes
  on boot if the binding is missing** — there is no pure-JS fallback in the current
  code despite README mentions of `@noble`.
- The binding is prebuilt in the VM at `/paramant-core` (cloned sibling) with the
  compiled artifact at `/paramant-core/crates/paramant-core-node/index.node`, which
  the file link resolves to. This persists in the VM image; `npm install` in
  `relay/` just symlinks it.
- To rebuild it from scratch: clone `https://github.com/Apolloccrypt/paramant-core`
  at the commit pinned by `PARAMANT_CORE_COMMIT` in `relay/Dockerfile`, run
  `cargo build --release -p paramant-core-node` (needs `cmake`, `nasm`, `ninja`,
  clang; toolchain auto-fetched via `rust-toolchain.toml`), then copy
  `target/release/libparamant_core_node.so` to
  `crates/paramant-core-node/index.node`.

### Testing
- Lint / static checks: `bash tests/static-sanity.sh` (also wired as the
  `.git/hooks/pre-commit` hook).
- Unit tests: `node --test tests/receive-filename.test.mjs tests/sign-full.test.mjs`.
  `sign-full.test.mjs` drives a real browser; Playwright browsers are **not**
  downloaded here, so run it with the system Chrome:
  `PLAYWRIGHT_CHROMIUM_PATH=/usr/bin/google-chrome node tests/sign-full.test.mjs`.
- `tests/auth-smoke.sh` asserts production semantics (e.g. `/request-key` → 410,
  captcha shape, signup route). Several of its checks fail against the local
  dev stack — that is expected, not a regression.

### Other caveats
- The relay logs `EACCES ... mkdir '/data'` warnings when run by `dev-local.sh`
  (no writable `/data`). Harmless in dev: the relay identity is regenerated each
  restart and nothing is persisted. Set `RELAY_IDENTITY_FILE` / `USERS_FILE` /
  `CT_FILE` to writable paths if you need persistence.
- Account email validation rejects dotless domains, so `dev-local.sh`'s
  `dev@localhost` account auto-create returns a harmless `400`. When creating keys
  via `POST /v2/admin/keys` (header `X-Admin-Token`), use a dotted email
  (e.g. `alice@example.com`).
- The relay stores opaque blobs keyed by a client-supplied SHA-256 hash; it does
  not verify the hash. End-to-end smoke test of the core flow:
  `POST /v2/inbound` then `GET /v2/outbound/<hash>` (burns after one read).
- Browser apps (`frontend/parashare.html`, etc.) hardcode the production relay
  hosts (`health.paramant.app`, …) and discover relays via `/v2/check-key`; they
  do **not** target the local relay without code edits. Exercise the relay API
  directly for end-to-end testing.
