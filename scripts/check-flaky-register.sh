#!/usr/bin/env bash
# The known-flaky register, and its expiry.
#
# WHY. A test that fails one run in twenty is not a smaller problem than one
# that always fails; it is a bigger one, because the answer people reach for is
# "run it again" and after two weeks nobody reads it at all. That is how a guard
# ends up green over nothing.
#
# So a flaky test may be on the record, and the record has a date on it. This
# script fails the build when a row in tests/known-flaky.tsv is older than
# KNOWN_FLAKY_MAX_DAYS. The row buys two weeks of not being surprised; it does
# not buy silence.
#
# Run: scripts/check-flaky-register.sh   (exit 0 = clean, 1 = an entry is stale)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REG="$ROOT/tests/known-flaky.tsv"
MAX_DAYS="${KNOWN_FLAKY_MAX_DAYS:-14}"
TODAY_EPOCH="$(date -u +%s)"
fail=0
rows=0

if [ ! -f "$REG" ]; then
  echo "FAIL: tests/known-flaky.tsv is gone. The register is the gate; deleting it"
  echo "      does not make a flaky test go away, it makes it unrecorded."
  exit 1
fi

# shellcheck disable=SC2034  # "source" is column 4 of the row; read needs a name for it
while IFS=$'\t' read -r suite name seen source why; do
  case "${suite:-}" in ''|'#'*) continue ;; esac
  rows=$((rows + 1))
  if [ -z "${seen:-}" ] || ! printf '%s' "$seen" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    echo "FAIL: $suite / $name has no usable date in column 3 (got '${seen:-}')."
    echo "      A row without a date never expires, which is the whole failure mode."
    fail=$((fail + 1))
    continue
  fi
  if ! seen_epoch="$(date -u -d "$seen" +%s 2>/dev/null)"; then
    echo "FAIL: $suite / $name carries an unreadable date '$seen'."
    fail=$((fail + 1))
    continue
  fi
  age=$(( (TODAY_EPOCH - seen_epoch) / 86400 ))
  if [ "$age" -lt 0 ]; then
    echo "FAIL: $suite / $name is dated $seen, which is in the future."
    fail=$((fail + 1))
    continue
  fi
  if [ "$age" -gt "$MAX_DAYS" ]; then
    echo "FAIL: $suite / $name has been known-flaky since $seen ($age days, limit $MAX_DAYS)."
    echo "      ${why:-no reason given}"
    echo "      Fix the cause and delete the row, or say in the row why it is still"
    echo "      open and re-date it deliberately. Re-dating is a decision someone"
    echo "      signs; letting it rot is not."
    fail=$((fail + 1))
  else
    echo "   known-flaky: $suite / $name (since $seen, $age of $MAX_DAYS days)"
  fi
done < "$REG"

if [ "$fail" -eq 0 ]; then
  if [ "$rows" -eq 0 ]; then
    echo "   OK  the known-flaky register is empty"
  else
    echo "   OK  $rows known-flaky entr(y|ies), none past $MAX_DAYS days"
  fi
fi
exit "$fail"
