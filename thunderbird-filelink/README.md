# ParaShare FileLink — Thunderbird Extension

Thunderbird FileLink provider that uploads attachments to the PARAMANT Ghost Pipe relay and replaces them with a burn-on-read download link.

## How it works

1. You attach a file in Thunderbird's compose window
2. Thunderbird prompts to upload via ParaShare (once the file exceeds the configured size threshold)
3. The extension POSTs the file to `/v2/inbound` on your relay
4. The relay returns a one-time download token
5. Thunderbird replaces the attachment with the link `https://relay.paramant.app/v2/dl/<token>`
6. The recipient clicks the link — the file is served and immediately destroyed

## Install (development / local)

1. Open Thunderbird → **Add-ons and Themes** (☰ menu or `Ctrl+Shift+A`)
2. Gear icon → **Install Add-on From File…**
3. Select the `thunderbird-filelink/` directory (Thunderbird accepts a directory for temporary installs, or zip the directory into a `.xpi` file)

To package as `.xpi`:
```bash
cd thunderbird-filelink
zip -r ../parashare-filelink.xpi . -x "*.DS_Store" -x "__MACOSX/*"
```
Then install the `.xpi` via **Install Add-on From File…**

## Configuration

After installing, go to **Thunderbird Settings → Composition → Attachments** and you will see "ParaShare" listed as a FileLink provider. Click **Add Account** (or the settings link) and enter your PARAMANT API key (`pgp_...`).

You can also optionally set a custom relay URL (defaults to `https://relay.paramant.app`).

## Notes

- **No E2E encryption in this path.** Files are uploaded as-is; the relay is trusted but not end-to-end encrypted via ML-KEM for FileLink uploads. The link is burn-on-read and destroyed after one download.
- **TTL** is determined by your plan (Dev: 1 hr, Pro: 24 hr, Enterprise: 7 days).
- **Max file size:** 5 MB (relay default). Configure `MAX_BLOB` on your relay to raise this.
- **Icons:** Add `icons/icon-48.png` and `icons/icon-96.png` to enable icons in the Add-on Manager. Without them the extension still works.
