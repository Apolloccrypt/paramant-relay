# Paramant Chromium Extension — Track B

Browser extension that injects a "Send via Paramant" button into Gmail and Outlook compose windows.

## Local install (unpacked, no build step)

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extensions/chromium/` directory (this folder)
5. The Paramant lock icon appears in the toolbar

No build step is required for development — the source files are loaded directly.

## Mock auth (current state)

`USE_MOCK = true` in `src/background/auth-client.js`:

- Any email + any 6-digit code → signs in successfully
- Upload returns a fake `https://paramant.app/get/{id}#mockkey` URL after a 600 ms delay
- Session expires 8 hours from sign-in

**To switch to real auth**: set `USE_MOCK = false`. Requires Track A PR 5 (ML-KEM session tokens) to be live at `paramant.app`.

## Build (for distribution)

```sh
npm install
npm run build      # → dist/
npm run package    # → paramant-extension.zip
```

The built `dist/` directory is also loadable via "Load unpacked".

## File structure

```
extensions/chromium/
├── manifest.json
├── src/
│   ├── background/
│   │   ├── service-worker.js   # message router
│   │   └── auth-client.js      # login / session / upload (USE_MOCK flag here)
│   ├── content/
│   │   ├── gmail.js            # injects button into Gmail compose
│   │   ├── outlook.js          # injects button into Outlook compose
│   │   └── shared/
│   │       ├── banner.js       # window.ParamantBanner global UI helper
│   │       ├── banner.css
│   │       ├── file-handler.js # (stub — Week 2)
│   │       └── link-replace.js # (stub — Week 2)
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   └── shared/
│       ├── api.js              # (stub — Week 2)
│       └── crypto.js           # (stub — Week 5, ML-KEM client-side)
├── icons/
│   └── icon.svg
└── _locales/
    ├── en/messages.json
    ├── nl/messages.json
    └── de/messages.json
```

## Roadmap

| Week | Track A dependency | Extension work |
|------|-------------------|----------------|
| 1    | —                 | Scaffold (this PR) |
| 2    | —                 | File picker, upload progress UI |
| 3    | Session token API | Swap USE_MOCK → real auth |
| 5    | ML-KEM PR 5       | Client-side encryption in crypto.js |
