# Paramant: Encrypted Attachments (Chromium extension)

Adds a **Paramant** button next to the attach button in Gmail and Outlook on the web. Pick a
file and it is encrypted in your browser, uploaded to Paramant's relay, and replaced in your
email with a burn-on-read link. The recipient downloads it once, then it is gone.

This extension covers webmail (Gmail and Outlook on the web). Native desktop Outlook is
served by the separate Office.js add-in in `../outlook-addin`.

## How it works

1. The content script reads the chosen file in 4.9 MB plaintext chunks (sliced lazily from
   disk, so the whole file is never held in memory at once) and streams each chunk to the
   service worker. The page never sees your API key.
2. The service worker encrypts each chunk with a fresh **AES-256-GCM** key, frames it, and
   pads it to a fixed **5 MB** block (so the stored size leaks nothing), then uploads it to
   `POST /v2/inbound` on the relay sector your key belongs to.
3. The symmetric key never reaches the relay. It travels in the link's URL fragment
   (`#k=…`), which browsers never send to servers. The relay stores only opaque ciphertext
   and never sees the filename.
4. The resulting link points at `paramant.app/parashare`, the same receiver the Thunderbird
   FileLink integration uses, so links are decrypted with no server change. Large files are
   split across multiple chunks/links transparently.

"Post-quantum relay" refers to the relay's own transport and storage crypto; the per-file
content key is AES-256-GCM held only by sender and recipient.

## Build and load (unpacked)

A build step is required (the content scripts and service worker import shared modules that
webpack bundles into self-contained scripts).

```sh
npm install
npm run build        # → dist/
```

Then in Chrome: `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
select the **`dist/`** directory.

```sh
npm run package      # → paramant-extension.zip (for the Chrome Web Store / Edge Add-ons)
npm run lint         # eslint
npm test             # vitest — core crypto + upload, incl. a round-trip decrypt that mirrors
                     # the parashare receiver (proves links we mint are decryptable)
```

## Sign in

Use your **API key** from the Paramant dashboard. The extension auto-detects which relay
sector the key belongs to. Email + authenticator (TOTP) sign-in is gated behind a server
capability flag and only appears once the relay advertises it.

## Settings (options page)

- **Default expiry**: 1 hour to 7 days (the relay caps this to your plan's ceiling).
- **Link format**: a formatted block or a plain single-line link.
- **Relay**: blank to auto-detect, or a self-hosted relay URL.
- **Transfer history**: a local list (name, size, time). It never leaves the browser and
  never contains keys or links.

## File structure

```
extensions/
├── shared/                       # shared across the Chromium extension and the Outlook add-in
│   ├── paramant-core.js          # encrypt + chunk + upload + share-URL (the heart; fully tested)
│   └── link-block.js             # XSS-safe link builder (block / plain)
└── chromium/
    ├── manifest.json             # MV3, Gmail + Outlook web, options page
    ├── eslint.config.js
    └── src/
        ├── background/
        │   ├── service-worker.js # message router + per-chunk transfer orchestration
        │   └── auth-client.js    # API-key auth, relay discovery, session
        ├── content/
        │   ├── gmail.js          # Gmail host adapter (selectors + editor)
        │   ├── outlook.js        # Outlook-web host adapter
        │   ├── compose-inject.js # shared inject + upload flow + robust insertion
        │   └── shared/
        │       ├── banner.js     # injected progress + error UI
        │       ├── banner.css
        │       └── link-replace.js  # re-exports shared/link-block.js
        ├── popup/                # sign-in + recent transfers + settings link
        ├── options/              # settings page
        └── shared/settings.js    # preferences + local history
```

## Security notes

- Filenames and URLs are escaped before insertion; the link href is restricted to the
  https paramant.app origins we mint.
- The relay receives only the encrypted blob plus minimal routing metadata (a random file
  id for quota dedup). No filename, no plaintext, no key.
- Permissions are minimal: `storage` plus host access to `*.paramant.app` (for relay
  uploads) and the mail compose pages (for the button).

## Known limitations

- Uploads run in the service worker; a very large multi-chunk transfer interrupted by the
  browser evicting the worker will need to be retried. Most transfers complete in one go.
- Burn-on-read means a chunk download cannot be retried; the recipient should download in a
  single pass (the parashare receiver does this automatically).
