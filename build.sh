#!/usr/bin/env bash
set -euo pipefail

DIST=frontend/dist
mkdir -p "$DIST"

TERSER=node_modules/.bin/terser
OBFUSCATOR=node_modules/.bin/javascript-obfuscator

if [ ! -x "$TERSER" ] || [ ! -x "$OBFUSCATOR" ]; then
  echo "Run 'npm install' first." >&2
  exit 1
fi

for src in frontend/*.js; do
  name=$(basename "$src")
  minified="$DIST/${name%.js}.min.js"
  obfuscated="$DIST/$name"

  "$TERSER" "$src" \
    --compress --mangle \
    --output "$minified"

  "$OBFUSCATOR" "$minified" \
    --output "$obfuscated" \
    --compact true \
    --control-flow-flattening true \
    --string-array true \
    --string-array-encoding base64 \
    --self-defending true \
    --dead-code-injection false

  rm "$minified"
  echo "built: $obfuscated"
done

echo "Done. Output in $DIST/"
