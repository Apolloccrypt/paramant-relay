#!/usr/bin/env bash
#
# The gate on the gate.
#
# scripts/security/posture.sh is the thing that will be believed when it says
# green, so something has to prove it can also say red. On 2026-09-02 the old
# heartbeat reported four green steps while two of them had run nothing at all,
# and the reason nobody caught it was that no test ever drove the monitor into
# failure. This drives every measurement both ways.
#
# It replaces curl, openssl, dig and npm with stubs from
# tests/security-posture-stubs/ and runs the scanner three times:
#
#   green    every external answer correct        -> exit 0, no red rows
#   red      every external answer wrong          -> exit 1, no green rows
#   missing  services silent or unparseable       -> exit 1, the preconditions red
#
# The green and red runs must produce the SAME set of measurement names. A
# measurement that only exists in one of them is a measurement that cannot
# change its mind, which is the failure mode this file exists to catch.
#
# Run: tests/security-posture-dryrun.sh   (exit 0 = clean, 1 = the scanner lies)
# No network. No secrets. Seconds.
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STUBS="$ROOT/tests/security-posture-stubs"
SCANNER="$ROOT/scripts/security/posture.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }
ok() { printf 'ok   %s\n' "$1"; }

[ -x "$SCANNER" ] || { bad "scripts/security/posture.sh is missing or not executable"; exit 1; }
for stub in curl openssl dig npm; do
  [ -x "$STUBS/$stub" ] || { bad "stub $stub is missing or not executable"; exit 1; }
done

# run MODE -> writes $WORK/MODE.json and $WORK/MODE.log, echoes the exit code
run() {
  local mode=$1
  POSTURE_STUB_MODE="$mode" \
  POSTURE_CURL="$STUBS/curl" \
  POSTURE_OPENSSL="$STUBS/openssl" \
  POSTURE_DIG="$STUBS/dig" \
  POSTURE_NPM="$STUBS/npm" \
    "$SCANNER" --json "$WORK/$mode.json" --report "$WORK/$mode.md" \
    >"$WORK/$mode.log" 2>&1
  echo $?
}

# names STATUS FILE -> the measurement names with that status, one per line
names() {
  node -e '
    const j = JSON.parse(require("fs").readFileSync(process.argv[2], "utf8"));
    for (const c of j.checks) if (c.status === process.argv[1]) console.log(c.group + " | " + c.name);
  ' "$1" "$2" | sort
}

printf '== green: every answer correct ==\n'
green_code=$(run green)
[ "$green_code" = 0 ] && ok "exit 0" || bad "green run exited $green_code, expected 0"
green_red=$(names red "$WORK/green.json")
if [ -n "$green_red" ]; then
  bad "green run reported red rows:"
  printf '%s\n' "$green_red" >&2
else
  ok "no red rows"
fi
green_ok=$(names green "$WORK/green.json")
green_n=$(printf '%s\n' "$green_ok" | grep -c .)
[ "$green_n" -gt 40 ] && ok "$green_n measurements ran" || bad "only $green_n measurements ran; the scanner is not measuring what it claims"

printf '\n== red: every answer wrong ==\n'
red_code=$(run red)
[ "$red_code" = 1 ] && ok "exit 1" || bad "red run exited $red_code, expected 1"
red_green=$(names green "$WORK/red.json")
if [ -n "$red_green" ]; then
  bad "red run still reported these green, so they cannot fail:"
  printf '%s\n' "$red_green" >&2
else
  ok "no green rows"
fi

# The heart of it: the same measurements in both directions.
red_red=$(names red "$WORK/red.json")
if [ "$green_ok" = "$red_red" ]; then
  ok "every one of the $green_n measurements went green once and red once"
else
  bad "the green and red runs measured different things:"
  diff <(printf '%s\n' "$green_ok") <(printf '%s\n' "$red_red") >&2 || true
fi

# One ::error line per red measurement, which is what makes a run readable
# at the top of the Actions page instead of somewhere in the log.
errors=$(grep -c '^::error title=' "$WORK/red.log")
red_n=$(printf '%s\n' "$red_red" | grep -c .)
[ "$errors" = "$red_n" ] && ok "$errors ::error lines, one per red measurement" \
  || bad "$errors ::error lines for $red_n red measurements"

printf '\n== missing: the services say nothing ==\n'
missing_code=$(run missing)
[ "$missing_code" = 1 ] && ok "exit 1" || bad "missing run exited $missing_code, expected 1"
missing_green=$(names green "$WORK/missing.json")
if [ -n "$missing_green" ]; then
  bad "a silent service was still reported green, which is the escape hatch this scanner must not have:"
  printf '%s\n' "$missing_green" >&2
else
  ok "nothing green when nothing answered"
fi
# Silence must be named, not shrugged at.
for want in "no certificate returned" "no response from" "no v=spf1" "no _dmarc" \
            "no CAA record" "unsigned" "expected 404" "no parseable" "not served"; do
  if grep -qF "$want" "$WORK/missing.md"; then
    ok "silence reported as: $want"
  else
    bad "the missing run never reported: $want"
  fi
done

# The report is the artifact a human reads. It has to say which way it went.
grep -q '^\*\*Uitslag: GROEN\*\*' "$WORK/green.md" && ok "green report says GROEN" || bad "green report does not say GROEN"
grep -q '^\*\*Uitslag: ROOD\*\*' "$WORK/red.md" && ok "red report says ROOD" || bad "red report does not say ROOD"
grep -q '^## Rood' "$WORK/red.md" && ok "red report leads with the red table" || bad "red report has no red table"

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf 'PASS: the scanner reports green when things are right and red when they are not.\n'
else
  printf 'FAIL: the scanner cannot be trusted in at least one direction.\n'
fi
exit "$fail"
