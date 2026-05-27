#!/usr/bin/env bash
# paramant-update-vendor -- refresh vendored front-end assets for the admin panel.
# Downloads pinned dependencies into admin/public/vendor/ so the admin UI never
# makes a runtime CDN call (EU-sovereignty, audit finding M-06). ASCII-only.
set -euo pipefail

XTERM_VERSION="${XTERM_VERSION:-5}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="${ROOT}/admin/public/vendor"

mkdir -p "$VENDOR"

echo "Vendoring xterm.js @ ${XTERM_VERSION} -> ${VENDOR}"
curl -fL "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VERSION}/lib/xterm.js"  -o "${VENDOR}/xterm.js"
curl -fL "https://cdn.jsdelivr.net/npm/xterm@${XTERM_VERSION}/css/xterm.css" -o "${VENDOR}/xterm.css"

echo "--------------------------------------"
ls -la "${VENDOR}/xterm."*
echo "--------------------------------------"
echo "sha256:"
sha256sum "${VENDOR}/xterm.js" "${VENDOR}/xterm.css"
echo
echo "Update the recorded hashes in ${VENDOR}/README.md and commit the changes."
