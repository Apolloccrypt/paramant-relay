#!/usr/bin/env bash
# Cache-bust guard (CACHE-01). The nginx static-asset block serves /*.css /*.js
# with `Cache-Control: immutable, max-age=1y` — the browser never revalidates.
# That is only safe when every reference carries a ?v=N cache-bust, so a content
# change ships under a NEW url. This guard fails the build when that invariant
# breaks, so stale-after-deploy assets can't silently creep back in.
#
# Two checks over frontend/**/*.html, for LOCAL .css/.js/.mjs only (external
# https:// and protocol-relative // links are ignored — they aren't ours to bust):
#   1. MISSING  — a local asset link with no ?v=N at all.
#   2. SPLIT    — the same asset referenced with >1 distinct ?v= value
#                 (two cache keys for one file; the "double-key" bug).
#
# Run: scripts/check-cache-bust.sh   (exit 0 = clean, 1 = violations)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/frontend"
fail=0

# All local .css/.js/.mjs references (value starts with "/" or "./", never "//"
# or a scheme). Emits: "<file>:<line>\t<asset-path>\t<version-or-NONE>".
refs="$(grep -rnoE '(href|src)="(\.?/[^"/][^"]*)\.(css|js|mjs)(\?v=[0-9]+)?"' "$DIR" --include='*.html' \
  | sed -E 's#^([^:]+:[0-9]+):.*"(\.?/[^"]+\.(css|js|mjs))(\?v=([0-9]+))?"#\1\t\2\t\5#' || true)"

# ── Check 1: MISSING ?v= ──────────────────────────────────────────────────────
missing="$(printf '%s\n' "$refs" | awk -F'\t' 'NF>=3 && $3=="" {print "  "$1"  ->  "$2}')"
if [ -n "$missing" ]; then
  echo "FAIL: local asset links WITHOUT a ?v= cache-bust (immutable-cached => stale after deploy):"
  printf '%s\n' "$missing"
  fail=1
fi

# ── Check 2: SPLIT version (same asset, >1 distinct ?v=) ──────────────────────
split="$(printf '%s\n' "$refs" | awk -F'\t' '$3!="" {seen[$2 SUBSEP $3]=1} END{for(k in seen){split(k,a,SUBSEP); c[a[1]]++; vs[a[1]]=vs[a[1]]" v"a[2]} for(p in c) if(c[p]>1) print "  "p"  ->" vs[p]}')"
if [ -n "$split" ]; then
  echo "FAIL: assets referenced with more than one ?v= version (one file, two cache keys — unify them):"
  printf '%s\n' "$split"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  n="$(printf '%s\n' "$refs" | grep -c . || true)"
  echo "cache-bust guard: OK — $n local css/js/mjs link(s), all carry a single consistent ?v="
fi
exit "$fail"
