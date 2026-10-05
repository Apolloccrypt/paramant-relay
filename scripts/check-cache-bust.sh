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
#   3. STALE    - the asset's content differs from the base ref, but its ?v= is
#                 not higher than the ?v= the base ref serves. A merge that
#                 resolves a conflict back to the old number lands here: the new
#                 file would ship under the old, immutable-cached url.
#                 Base ref: $CACHE_BUST_BASE, default origin/main (what prod
#                 runs). Without that ref (shallow clone) check 3 is skipped
#                 with a notice, never silently passed.
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

# ── Check 3: STALE version (content changed against base, ?v= not bumped) ──
BASE="${CACHE_BUST_BASE:-origin/main}"
if git -C "$ROOT" rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
  # Highest ?v= per asset path as the base ref has it, over all its html.
  basevers="$(git -C "$ROOT" grep -hoE '(href|src)="(\.?/[^"/][^"]*)\.(css|js|mjs)\?v=[0-9]+"' "$BASE" -- 'frontend/*.html' 2>/dev/null \
    | sed -E 's#^(href|src)="([^"?]+)\?v=([0-9]+)"$#\2\t\3#' \
    | awk -F'\t' '{if(!($1 in m) || $2+0>m[$1]+0) m[$1]=$2} END{for(k in m) print k"\t"m[k]}' || true)"
  stale=""
  while IFS=$'\t' read -r loc asset ver; do
    [ -n "$ver" ] || continue
    bv="$(printf '%s\n' "$basevers" | awk -F'\t' -v a="$asset" '$1==a{print $2; exit}')"
    [ -n "$bv" ] || continue
    html="${loc%:*}"
    case "$asset" in
      /*) file="$DIR$asset" ;;
      *)  file="$(dirname "$html")/${asset#./}" ;;
    esac
    [ -f "$file" ] || continue
    rel="${file#"$ROOT"/}"
    git -C "$ROOT" cat-file -e "$BASE:$rel" 2>/dev/null || continue
    if ! git -C "$ROOT" diff --quiet "$BASE" -- "$rel" && [ "$ver" -le "$bv" ]; then
      stale="$stale  $loc  ->  $asset  v$ver (base $BASE has v$bv, content changed)"$'\n'
    fi
  done <<< "$refs"
  if [ -n "$stale" ]; then
    echo "FAIL: assets whose content changed against $BASE but whose ?v= was not raised (old immutable url, new code):"
    printf '%s' "$stale"
    fail=1
  fi
else
  echo "cache-bust guard: NOTICE - base ref $BASE not available, STALE check (3) skipped"
fi

if [ "$fail" -eq 0 ]; then
  n="$(printf '%s\n' "$refs" | grep -c . || true)"
  echo "cache-bust guard: OK — $n local css/js/mjs link(s), all carry a single consistent ?v="
fi
exit "$fail"
