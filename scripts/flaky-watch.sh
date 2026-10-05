#!/usr/bin/env bash
# Run the suites that boot and restart a real relay, more than once, in the same
# parallel shape the build straat uses.
#
# WHY. A test that fails one run in twenty passes a pull request nineteen times
# out of twenty, and the twentieth is read as "CI being CI". Measured on
# 2026-09-05: route-ct-persistence "a relay that lost its tree refuses to sign a
# head contradicting one it already signed" failed 0 times in 100 runs on an
# idle machine and 3 times in 60 with the other route suites alongside it on
# four cores. One pass of the suite says nothing about that. Four passes catch
# it about one time in five, which is enough for it to be a REPORTED flake with
# a name instead of a red tick on somebody's unrelated branch.
#
# This is not a retry. A failure here is a failure of the run: the point is to
# widen the window in which a wobble shows up, and then to say which suite
# wobbled and in which repeat, so it can be fixed or put on the dated register
# (tests/known-flaky.tsv) rather than absorbed.
#
# Run from the repo root or from relay/:
#   scripts/flaky-watch.sh                 # 3 repeats over the route suites
#   FLAKY_WATCH_REPEATS=10 scripts/flaky-watch.sh
#   scripts/flaky-watch.sh test/route-ct-persistence.test.js   # explicit suites
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/relay" || { echo "FAIL: no relay/ directory under $ROOT"; exit 1; }

REPEATS="${FLAKY_WATCH_REPEATS:-3}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

# The suites, in the same single invocation CI uses, because running them one at
# a time removes the very load the flake needs. Default matches the route step
# in .github/workflows/test.yml; a caller may name its own.
if [ "$#" -gt 0 ]; then
  SUITES=("$@")
else
  SUITES=()
  for f in test/route-*.test.js test/parasign-signs-quota.test.js test/parasign-party-index.test.js; do
    [ -f "$f" ] && SUITES+=("$f")
  done
fi
if [ "${#SUITES[@]}" -eq 0 ]; then
  echo "FAIL: no suites selected. The glob in this script is stale, and an empty"
  echo "      run would report green over nothing."
  exit 1
fi

# Which of them restart a relay or read what one wrote after stopping it. These
# are the ones a shutdown or a boot race can reach, and they are named here so a
# reader knows what this job is actually watching. Selected by what the file
# does, not by a hand-kept list, so a new suite joins on the run after it lands.
echo "════════ FLAKY WATCH ════════"
echo "repeats: $REPEATS   suites: ${#SUITES[@]}"
SENSITIVE=()
for f in "${SUITES[@]}"; do
  grep -qE '\.stop\(\)|\.restart\(' "$f" && SENSITIVE+=("$(basename "$f")")
done
echo "restart-sensitive among them (${#SENSITIVE[@]}):"
printf '      %s\n' "${SENSITIVE[@]:-(none)}"
echo ""

red_runs=0
declare -A failed_in
for i in $(seq 1 "$REPEATS"); do
  log="$OUT/repeat-$i.tap"
  if node --test --test-reporter=tap "${SUITES[@]}" > "$log" 2>&1; then
    echo "repeat $i/$REPEATS: green"
  else
    red_runs=$((red_runs + 1))
    echo "repeat $i/$REPEATS: RED"
    # TAP names the subtest on the "not ok" line; the file it lives in comes
    # from the location line underneath it.
    while IFS= read -r line; do
      echo "      $line"
      failed_in["$line"]="${failed_in["$line"]:-} $i"
    done < <(grep -E '^not ok [0-9]+ - ' "$log" | sed 's/^not ok [0-9]* - //' | sort -u)
  fi
done

echo ""
if [ "$red_runs" -eq 0 ]; then
  echo "PASS: $REPEATS repeats, none red"
  exit 0
fi

echo "════════ RESULT ════════"
echo "FAIL: $red_runs of $REPEATS repeats went red."
for name in "${!failed_in[@]}"; do
  # shellcheck disable=SC2086
  set -- ${failed_in["$name"]}
  if [ "$#" -eq "$REPEATS" ]; then
    echo "  ALWAYS  $name"
  else
    echo "  FLAKY   $name (repeats:$(printf ' %s' "$@") of $REPEATS)"
  fi
done
echo ""
echo "A suite marked FLAKY passed and failed the same code in the same job. Do not"
echo "re-run it. Either fix the cause, or add a dated row to tests/known-flaky.tsv,"
echo "which expires (scripts/check-flaky-register.sh)."
exit 1
