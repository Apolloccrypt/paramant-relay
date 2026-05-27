# Webroot sync (ACTUAL) - 2026-05-27

paramant.app static site re-synced to current main. Backend was already on
3.0.0; the static webroot was only partially synced and is now fully current.

## How the site is actually served (verified, not assumed)

- nginx `paramant-public.conf` proxies `paramant.app/` (and /docs, /setup,
  /dashboard, ...) to an internal nginx server block on `127.0.0.1:8080`.
- That `:8080` block serves static files from **`/home/paramant/app`** with
  `root /home/paramant/app; index index.html;` and a clean-URL fallback
  `location / { try_files $uri $uri.html $uri/ =404; }`.
- `/.well-known/`, `security.txt`, `robots.txt`, install scripts are served
  directly from `/home/paramant/app` by `paramant-public.conf`.
- An edge proxy (`via: 1.1 Caddy`) sits in front; it was NOT serving stale
  content (origin and edge agreed after sync).

## Pre-sync state

- `index.html` was already `build 3.0.0` (an earlier partial sync).
- `docs.html` on the webroot DIFFERED from main (stale) -> the webroot was
  only partially updated.
- `/trust` returned 404 because `trust.html` was absent from the webroot
  (the trust page landed in main via PR #69, after the previous sync).

## Action taken

- Backed up the webroot (`/home/paramant/backups/webroot-20260527-2339.tar.gz`)
  and both nginx confs.
- Shallow-cloned main (`93dd4d3`) and `rsync -a` of `frontend/` ->
  `/home/paramant/app` (no `--delete`, to preserve server-only files such as
  the separate `app-legal` root and `*.bak` files). Ownership normalized to
  `paramant:paramant`.
- No nginx config change required: the existing `$uri.html` clean-URL fallback
  serves `/trust` -> `trust.html` automatically once the file is present.
- No docker compose changes. No `.env` changes.

## Post-sync external verification (https://paramant.app, cache-busted)

| Check | Result |
|-------|--------|
| homepage build label | `build 3.0.0` |
| `/docs` | HTTP 200, "PARAMANT - Documentation", shows `v3.0.0` / `build 3.0.0` |
| `/setup` | HTTP 200 |
| `/trust` | HTTP 200, "Trust & Transparency", mentions **R013 R014 R015 R016** |
| `/dashboard` | cards present (cards-grid / card-header) |
| `/.well-known/openpgp-key.asc` | 0 PLACEHOLDER occurrences (clean) |
| `docs.html` content | byte-identical to `origin/main:frontend/docs.html` |

## Note on the "/docs mentions R013-R016" goal

`docs.html` in main references the older ADRs (R001, R005, R006, R007, R011)
and does NOT enumerate R013-R016. The R013-R016 transparency content lives on
the dedicated **/trust** page (added in PR #69, "feat/trust-page"), which is now
live and reachable, and which the R016 spec designates as the canonical place
for license-check / management-plane / verification disclosures. `/docs` itself
reports 3.0.0. No ADR text was fabricated into the marketing copy.

## Result

paramant.app is visibly on 3.0.0; /setup is 200; /trust (R013-R016) is live;
all PR frontend content (incl. PR #61 and PR #69) is synced to the webroot.
