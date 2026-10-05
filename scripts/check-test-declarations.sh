#!/usr/bin/env bash
# Test-scope guard (SCOPE-01). Every suite in this repo is a flat top-level
# script: tests/*.mjs and relay/test/*.js declare their fixtures with a bare
# `const` at column 0 and read them all the way down the file. That shape is
# fine on its own and it is what makes the suites readable, but it turns the
# file into ONE shared namespace that every open pull request writes into.
#
# On 2026-09-02 five pull requests each appended a block to that namespace and
# each was green on its own. #333, #334, #336, #339 and #354 landed within the
# hour and main went red on the merge of the last one: `const tiers` twice in
# relay/test/pricing-page.test.js, `const pricingVisible` twice in
# tests/ui-truthfulness.test.mjs. Two files that no longer parse means the unit
# suite and the eslint gate both fall over, so nothing else in either file runs.
# No single pull request was wrong; the collision only exists in the merge.
#
# Two checks, and they catch different halves of the problem:
#
#   1. PARSE: node --check on every suite. A duplicate top-level const/let/
#      class is an early SyntaxError, so this reports the file and the line
#      before a single assertion runs. Locally that is the whole answer; in CI
#      it is what turns "the eslint job is red" into "this file, this line".
#
#   2. SHADOW: duplicate top-level `var` and `function` names. These are LEGAL
#      JavaScript: the second declaration silently replaces the first, the file
#      parses, the suite runs, and every assertion above the collision is now
#      measured against the helper from the block below it. Nothing goes red.
#      That is the same merge collision as above, only quiet, and it is the one
#      no parser and no lint rule will ever report.
#
# The SHADOW scan reads column-0 declarations only. That is a deliberate
# heuristic and not a parser: these suites put every top-level declaration at
# column 0 and indent everything nested, so nesting is visible without one.
# Destructuring (`const { default: tiers } = ...`) is left to check 1, which
# handles it exactly.
#
# Run: scripts/check-test-declarations.sh   (exit 0 = clean, 1 = violations)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0
files=()
for pattern in tests/*.mjs tests/*.js relay/test/*.js relay/crypto/*.test.js admin/test/*.js; do
  for f in $pattern; do
    [ -f "$f" ] && files+=("$f")
  done
done

if [ "${#files[@]}" -eq 0 ]; then
  echo "FAIL: no suites matched; the globs in this script are stale."
  exit 1
fi

# ── 1. PARSE ──────────────────────────────────────────────────────────────────
for f in "${files[@]}"; do
  if ! out="$(node --check "$f" 2>&1)"; then
    echo "FAIL: $f does not parse."
    printf '%s\n' "$out" | sed 's/^/    /'
    if printf '%s' "$out" | grep -q 'has already been declared'; then
      echo "    Two top-level blocks in this file declare the same name. This is what a"
      echo "    merge collision looks like: each pull request was green alone. Reuse the"
      echo "    first declaration or give the second block its own name."
    fi
    # GitHub Actions annotation, so the job summary names the file, not just eslint's tail.
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      line="$(printf '%s' "$out" | sed -nE "s#^.*${f//./\\.}:([0-9]+).*\$#\1#p" | head -1)"
      echo "::error file=${f}${line:+,line=$line}::${f} does not parse (see the test-scope guard)"
    fi
    fail=$((fail + 1))
  fi
done

# ── 2. SHADOW ─────────────────────────────────────────────────────────────────
for f in "${files[@]}"; do
  dupes="$(awk '
    /^\/\*/ { inblock = 1 }
    inblock { if (/\*\//) inblock = 0; next }
    /^(async[ \t]+)?function[ \t]+[A-Za-z_$][A-Za-z0-9_$]*/ {
      name = $0; sub(/^(async[ \t]+)?function[ \t]+/, "", name); sub(/[^A-Za-z0-9_$].*$/, "", name)
      seen[name] = seen[name] " " NR; kind[name] = "function"
    }
    /^var[ \t]+[A-Za-z_$][A-Za-z0-9_$]*/ {
      name = $0; sub(/^var[ \t]+/, "", name); sub(/[^A-Za-z0-9_$].*$/, "", name)
      seen[name] = seen[name] " " NR; kind[name] = "var"
    }
    END {
      for (n in seen) {
        c = split(seen[n], at, " ")
        if (c > 1) printf "%s %s lines%s\n", kind[n], n, seen[n]
      }
    }
  ' "$f")"
  if [ -n "$dupes" ]; then
    echo "FAIL: $f declares a top-level name more than once:"
    printf '%s\n' "$dupes" | sed 's/^/    /'
    echo "    A second top-level var/function of the same name is legal and silent: it"
    echo "    replaces the first, and every assertion above it now runs against the"
    echo "    definition below it. Rename one, or give each block its own scope."
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::error file=${f}::${f} declares a top-level name more than once"
    fi
    fail=$((fail + 1))
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "OK: ${#files[@]} suites parse and declare each top-level name once."
  exit 0
fi
echo "FAIL: $fail suite(s) with a scope problem."
exit 1
