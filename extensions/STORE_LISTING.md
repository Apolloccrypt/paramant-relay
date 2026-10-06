# Store listing — Paramant: Encrypted Attachments

Copy for the Chrome Web Store and Microsoft Edge Add-ons submissions of the Chromium
extension (`extensions/chromium`). The Outlook add-in is submitted separately through
Microsoft AppSource using `extensions/outlook-addin/manifest.xml`.

## Name

Paramant: Encrypted Attachments

## Summary (132 chars max)

Send Gmail and Outlook attachments as encrypted, burn-on-read links. The key stays in your
browser; the relay never sees your files.

## Category

Productivity / Communication

## Detailed description

Paramant replaces email attachments with encrypted, single-download links.

Click the Paramant button next to "Attach files" in Gmail or Outlook on the web, pick a
file, and Paramant encrypts it in your browser with AES-256-GCM before it ever leaves your
machine. The encrypted file is uploaded to Paramant's post-quantum relay and a link is
dropped into your email. Your recipient opens the link, the file is decrypted in their
browser, and it is deleted after that first download.

What makes it private:
- End-to-end encryption. The decryption key travels in the link fragment, which browsers
  never send to a server. The relay stores only ciphertext and never sees your filename.
- Burn-on-read. Each link is good for one download, then the file is gone.
- Expiry you control. From 1 hour to 7 days.
- Large files. Files are split and encrypted in chunks, so size is not a wall.
- Local-only history. A record of what you sent stays in your browser, with no keys or
  links in it.

Sign in with your Paramant API key, or with your e-mail address and authenticator code.
Running your own Paramant relay? Set it in the options; the receiver then opens the link on
your relay. Works in Chrome and Chromium 120+ on Gmail and Outlook on the web. Native desktop Outlook is supported by the separate Paramant Outlook add-in.

Paramant is source-available: https://github.com/Apolloccrypt/paramant-relay

## Permissions justification (for store review)

- `storage`: stores your sign-in session, preferences (expiry, link format), and the local
  transfer history. Nothing is synced or sent off-device.
- Host access to `https://*.paramant.app/*`: uploads the encrypted file to the Paramant
  relay and checks your API key.
- Host access to `https://mail.google.com/*` and the Outlook web hosts: injects the
  Paramant button into the compose toolbar and inserts the resulting link.

No remote code is loaded. No analytics. No ad or tracking SDKs.

## Privacy practices

- Does the item collect or use personal data? Only the user's own API key and a local list
  of their own transfers, both stored on-device. File contents are end-to-end encrypted and
  not readable by Paramant.
- Data is not sold or transferred to third parties.
- Privacy policy URL: https://github.com/Apolloccrypt/paramant-relay/blob/main/extensions/PRIVACY.md
  (paramant.app has no separate page for the integrations; this file is the policy).

## Assets

All in `extensions/store/`:

- `screenshots/01-gmail-link.png` .. `05-taskpane.png`: 1280x800, made from the real build
  against a local stack (Gmail and Outlook web are stand-ins, the extension, relay and
  receiving page are real).
- `screenshots/promo-440x280.png`: small promo tile.
- Store icon 128x128: `chromium/icons/icon-128.png`.

## Packages

`bash scripts/build-store-packages.sh` builds and checks everything below into
`extensions/store/out/` (gitignored), with a `SHA256SUMS`. The build is reproducible: the
same commit gives the same hashes. It refuses a package with a missing file, remote code,
a description over 132 characters, a taskpane that loads its script twice or makes
/parashare links, or a manifest asking less than Mailbox 1.8.

| File | For |
|---|---|
| `paramant-chromium-<version>.zip` | Chrome Web Store and Edge Add-ons |
| `manifest.xml` | AppSource (Partner Center) and Microsoft 365 admin center |
| `paramant-outlook-addin-<version>.tar.gz` | addin.paramant.app (`deploy/addin-uitrol.sh`) |

## Submitting (only Mick: needs the developer accounts)

Chrome Web Store, https://chrome.google.com/webstore/devconsole:
1. New item, upload `paramant-chromium-<version>.zip`.
2. Store listing: name, summary and description from this file; category Productivity;
   language English, with the Dutch and German texts from `_locales` in the package.
3. Graphics: the five screenshots and the promo tile above, icon from the package.
4. Privacy: the permission justifications and privacy practices from this file, single
   purpose "encrypt mail attachments into one-time links", privacy policy URL above.
5. Distribution: public. Submit for review.

Edge Add-ons, https://partner.microsoft.com/dashboard/microsoftedge: the same zip and the
same texts and images.

Outlook add-in, AppSource via Partner Center (Office Store): new offer "Office add-in",
upload `manifest.xml`, same texts, the screenshot `05-taskpane.png`, privacy URL above,
support URL https://paramant.app/help/outlook-extension, and test notes with a test API
key. Without AppSource an organisation can already roll it out today through Microsoft 365
admin center > Settings > Integrated apps > Upload custom apps, manifest URL
https://addin.paramant.app/manifest.xml.

Roll out the add-in (`deploy/addin-uitrol.sh`) before submitting: the reviewer loads the
taskpane from addin.paramant.app.

After approval: replace the "not in the Chrome Web Store / AppSource yet" paragraphs on
`frontend/help/gmail-extension.html`, `frontend/help/outlook-extension.html` and their
`/en` versions with the store link; `tests/extension-fase2.test.mjs` (EXT-26-A) pins the
current wording and changes with them.
