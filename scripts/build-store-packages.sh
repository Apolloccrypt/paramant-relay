#!/usr/bin/env bash
# Builds and checks what goes to the stores and to addin.paramant.app.
#
#   extensions/store/out/paramant-chromium-<version>.zip
#       Chrome Web Store and Edge Add-ons: one zip, manifest.json at the root.
#   extensions/store/out/paramant-outlook-addin-<version>.tar.gz
#       The add-in build for addin.paramant.app (contents of dist/).
#   extensions/store/out/manifest.xml
#       The add-in manifest for AppSource (Partner Center) and for
#       Microsoft 365 admin center > Integrated apps.
#   extensions/store/out/SHA256SUMS
#
# Every package is checked before it is written; a failed check stops the
# script with a reason and leaves no package behind. Needs npm ci in
# extensions/chromium and extensions/outlook-addin.
#
# Run: bash scripts/build-store-packages.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/extensions/store/out"
CH="$ROOT/extensions/chromium"
AD="$ROOT/extensions/outlook-addin"
fail() { echo "FAIL: $*" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT"

# ── Chromium extension ──────────────────────────────────────────────────────────
( cd "$CH" && npx webpack --mode production >/dev/null ) || fail "chromium build"
VER=$(node -p "require('$CH/manifest.json').version")
node - "$CH/dist" <<'EOF' || fail "chromium package check"
const fs = require('fs'), path = require('path');
const dist = process.argv[2];
const m = JSON.parse(fs.readFileSync(path.join(dist, 'manifest.json'), 'utf8'));
const problems = [];
if (m.manifest_version !== 3) problems.push('manifest_version is not 3');
if (!/^\d+\.\d+\.\d+$/.test(m.version)) problems.push('version is not x.y.z');
for (const f of [m.background.service_worker, m.action.default_popup, m.options_ui.page,
  ...Object.values(m.icons), ...m.content_scripts.flatMap((c) => [...c.js, ...(c.css || [])])]) {
  if (!fs.existsSync(path.join(dist, f))) problems.push('missing ' + f);
}
// Store rule: no remotely hosted code. No script from another origin, no eval.
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
for (const f of walk(dist)) {
  const s = fs.readFileSync(f, 'utf8');
  if (/\.html$/.test(f) && /<script[^>]+src="(https?:)?\/\//i.test(s)) problems.push('remote script in ' + f);
  if (/\.js$/.test(f) && /\beval\(|new Function\(/.test(s)) problems.push('eval in ' + f);
}
if (JSON.stringify(m.permissions) !== '["storage"]') problems.push('permissions changed: ' + JSON.stringify(m.permissions));
for (const l of ['en', 'nl', 'de']) {
  const msgs = JSON.parse(fs.readFileSync(path.join(dist, '_locales', l, 'messages.json'), 'utf8'));
  if (!msgs.extName || !msgs.extDesc) problems.push(l + ': extName/extDesc missing');
  if (msgs.extDesc && msgs.extDesc.message.length > 132) problems.push(l + ': extDesc over 132 characters');
}
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
EOF
ZIP="$OUT/paramant-chromium-$VER.zip"
# Fixed timestamps and order, so the same source gives the same zip.
find "$CH/dist" -exec touch -h -d '2026-01-01T00:00:00Z' {} +
( cd "$CH/dist" && find . -type f | LC_ALL=C sort | zip -X -q "$ZIP" -@ ) || fail "zip"
unzip -l "$ZIP" | grep -q ' manifest.json$' || fail "manifest.json not at the zip root"

# ── Outlook add-in ──────────────────────────────────────────────────────────────
( cd "$AD" && npx webpack --mode production >/dev/null ) || fail "add-in build"
AVER=$(sed -n 's#.*<Version>\(.*\)</Version>.*#\1#p' "$AD/manifest.xml" | head -1)
( cd "$AD" && npx office-addin-manifest validate manifest.xml >"$OUT/manifest-validate.txt" 2>&1 ) \
  || { cat "$OUT/manifest-validate.txt" >&2; fail "office-addin-manifest validate"; }
grep -q 'The manifest is valid' "$OUT/manifest-validate.txt" || fail "manifest validate gave no verdict"
node - "$AD" <<'EOF' || fail "add-in package check"
const fs = require('fs'), path = require('path');
const ad = process.argv[2], dist = path.join(ad, 'dist');
const problems = [];
const html = fs.readFileSync(path.join(dist, 'taskpane.html'), 'utf8');
const own = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map((x) => x[1]).filter((s) => !/^https:/.test(s));
if (own.length !== 1 || !/^taskpane\.[0-9a-f]{8}\.js$/.test(own[0])) problems.push('taskpane.html must load one hashed taskpane.js, got ' + JSON.stringify(own));
for (const s of own) if (!fs.existsSync(path.join(dist, s))) problems.push('missing ' + s);
const js = own.map((s) => fs.readFileSync(path.join(dist, s), 'utf8')).join('\n');
if (/parashare\?t=/.test(js)) problems.push('the build still makes /parashare links');
if (!/paramant\.app\/get/.test(js)) problems.push('the build makes no /get links');
const m = fs.readFileSync(path.join(ad, 'manifest.xml'), 'utf8');
const src = fs.readFileSync(path.join(ad, 'src/shared/office-helpers.js'), 'utf8');
if (/getAttachmentsAsync|getAttachmentContentAsync/.test(src) && !/<Set Name="Mailbox" MinVersion="1\.8"\/>/.test(m)) problems.push('manifest asks less than Mailbox 1.8');
for (const u of m.matchAll(/https:\/\/addin\.paramant\.app\/([^"]+)/g)) {
  if (!fs.existsSync(path.join(dist, u[1]))) problems.push('manifest points at missing ' + u[1]);
}
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
EOF
find "$AD/dist" -exec touch -h -d '2026-01-01T00:00:00Z' {} +
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='2026-01-01 00:00Z' \
  -C "$AD/dist" -czf "$OUT/paramant-outlook-addin-$AVER.tar.gz" . || fail "tar"
cp "$AD/manifest.xml" "$OUT/manifest.xml"

( cd "$OUT" && sha256sum paramant-chromium-*.zip paramant-outlook-addin-*.tar.gz manifest.xml > SHA256SUMS )
echo "chromium $VER, outlook add-in $AVER:"
sed 's/^/  /' "$OUT/SHA256SUMS"
