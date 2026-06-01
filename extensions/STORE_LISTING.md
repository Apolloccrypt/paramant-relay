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

Sign in with your Paramant API key. Works in Chrome and Chromium 120+ on Gmail and Outlook
on the web. Native desktop Outlook is supported by the separate Paramant Outlook add-in.

Paramant is open source: https://github.com/Apolloccrypt/paramant-relay

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
- Privacy policy URL: https://paramant.app/extension-privacy (host the contents of
  `extensions/PRIVACY.md`).

## Assets needed before submission (not generated here)

- Screenshots (1280x800 or 640x400): the compose button, the upload progress, the inserted
  link, the popup, the options page.
- Small promo tile 440x280; optional marquee 1400x560.
- Store icon 128x128 (already in `chromium/icons/icon-128.png`).
