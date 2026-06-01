# Mail integrations: implementation notes

Branch `feat/extensions-real-crypto`. Scope: the Gmail/Outlook browser extension and the
Outlook add-in.

## The core problem (why this was needed)

All three surfaces (Gmail content script, Outlook-web content script, Outlook add-in) were
built against a **mock** and did not work against the real relay:

- They POSTed **plaintext** base64 to `/v2/inbound` with **no `hash`** field and the wrong
  field names (`metadata` instead of `meta`). The real endpoint requires a SHA-256 `hash`
  and stores opaque, client-encrypted ciphertext.
- They read `response.share_url` and `response.expires_at`, which `/v2/inbound` does not
  return (it returns `{ ok, hash, ttl_ms, download_token, merkle_proof }`).
- They read `email` from `/v2/check-key`, which only returns `{ valid, plan }`.
- The READMEs still described `USE_MOCK` and "stub" files.

So nothing actually encrypted, uploaded, or produced a working link.

## What changed

- New shared core `extensions/shared/paramant-core.js`: AES-256-GCM encryption, PRSH
  framing, fixed 5 MB padded blocks, chunking, SHA-256, `/v2/inbound` upload with
  503/429 backoff and 409 re-encrypt, sector relay discovery, and the `parashare` share
  URL. Byte-compatible with the shipping Thunderbird FileLink receiver, proven by a
  round-trip test that mirrors `parashare.html`'s decrypt.
- New shared `extensions/shared/link-block.js`: one XSS-safe link builder (block / plain)
  used by both surfaces.
- Chromium extension: service worker now streams chunks from the content script and does
  the encrypt+upload (keeps the API key out of the page, handles files larger than a single
  message); real progress UI; fixed `OPEN_POPUP` (was unhandled, so a logged-out click did
  nothing); XSS-safe insertion with an execCommand→Range fallback; an options page (expiry,
  link format, relay, clear history); recent-transfers in the popup; wired `chrome.i18n`
  with complete en/nl/de locales; minimal permissions; valid manifest.
- Outlook add-in: same real core; plan display; per-chunk progress; valid manifest GUID;
  fixed a broken logo reference.
- 16 vitest tests, eslint config, both webpack builds green.

## Decisions to confirm

1. **Extension covers Gmail and Outlook web; the add-in covers native Outlook.** Both are
   wired and working. If you would rather the extension be Gmail-only (so an OWA user with
   both installed never sees two buttons), remove the Outlook block from
   `chromium/manifest.json` `content_scripts` and the `content/outlook` webpack entry. I did
   not remove it because both paths now work and removing is your call.
2. **Upload requires an API key.** TOTP login is kept but dormant (the relay capability is
   off). A TOTP-only upload path would need a same-origin `paramant.app/api/relay` proxy I
   could not verify exists. The popup/taskpane only show TOTP when the relay advertises it.
3. **Product name** is now "Paramant: Encrypted Attachments" (colon, no em-dash).
4. **Version** set to 1.0.0 in `chromium/manifest.json` and both `package.json`s.

## Findings (acted on / for you)

- **FIXED — Thunderbird FileLink base64 corruption** (`thunderbird-filelink/background.js`).
  `toBase64()` encoded the 5 MB blob in 8192-byte windows; 8192 is not a multiple of 3, so
  every window emitted a trailing `=` and the relay's `Buffer.from(payload,'base64')`
  stopped at the first interior `=`, truncating **every** upload to ~8 KB (so every
  Thunderbird transfer was undecryptable). Replaced with build-binary-then-single-`btoa`.
  Please verify and ship this fix; it affects the live Thunderbird integration.
- **Recommend — relay does not verify `hash == sha256(payload)`** in `/v2/inbound`. A
  client bug (like the one above) silently stores a corrupted blob. Verifying server-side
  would have caught it. Out of scope here; flagging it.
- **Minor — `parashare.html` receiver double-decodes the filename**
  (`decodeURIComponent(sp.get('n'))`). For filenames containing a literal `%` the second
  decode can throw. Our sender encodes like the shipping path, so normal names are fine; the
  true filename is also inside the encrypted blob. A one-line receiver fix would close it.

## Deliberately not done (for you to decide)

- **Dead stub files** left in place (not deleted): `chromium/src/shared/api.js`,
  `chromium/src/shared/crypto.js`, `chromium/src/content/shared/file-handler.js`. They are
  unused and not bundled. Recommend deleting; left for your call.
- **Store screenshots / promo art**: cannot be generated headless. Listing copy is in
  `STORE_LISTING.md`; privacy text in `PRIVACY.md` (host it and set the policy URL).
- **The website help pages** (`frontend/help/*-extension.html`) now match the
  implementation but were not edited (that is the website, not the extension).
