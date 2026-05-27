# Vendored dependencies

These assets are committed to the repo and served from the admin container
itself. They are NOT loaded from a public CDN at runtime: per the site audit
finding M-06 (EU data sovereignty), the admin panel must not make runtime calls
to US-based CDNs.

## xterm.js (MIT license)

- Source: https://github.com/xtermjs/xterm.js
- Files: `xterm.js`, `xterm.css`
- Used by: `/admin/cli` (web debug terminal)

### Verifying integrity

    sha256sum admin/public/vendor/xterm.*

Recorded hashes at vendor time:

    f0aea0f75f48559013ae6643c2479dd737d26da42d5524e6d2b70915ae6523c7  xterm.js
    832f3f2c603b43ad4351ff04970150cc7a873014276db126a6065c6dd81e4872  xterm.css

### Update procedure

    scripts/paramant-update-vendor.sh

Re-run after bumping the pinned version, then re-record the hashes above and
commit the changed files.
