#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --target web --out-dir ../frontend/pkg --release
echo "WASM built → frontend/pkg/"
