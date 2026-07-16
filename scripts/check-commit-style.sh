#!/usr/bin/env bash
# Commit- en GitHub-stijl-poort. Blokkeert wat niet in Micks publieke repos hoort:
#   1. em-dash (U+2014) in een commit-message of in een toegevoegde diff-regel
#   2. emoji (gangbare emoji-unicodeblokken)
#   3. AI-attributie-markers (zie ATTRIB hieronder)
# Scant de commit-message(s) EN de toegevoegde ('+') regels van de commits.
#
# Gebruik:
#   scripts/check-commit-style.sh [git-range]     # standalone, default de laatste commit
#   scripts/check-commit-style.sh --pre-push      # leest het git pre-push protocol op stdin
#
# Exit 0 = schoon. Exit 1 = stijlfout gevonden (commit/push geblokkeerd).

set -euo pipefail

# grep -P met \x{...} vereist een UTF-8 locale om multibyte-tekens te matchen.
export LC_ALL="${LC_ALL:-C.UTF-8}"

ZERO="0000000000000000000000000000000000000000"
FAIL=0

# em-dash: uitsluitend U+2014. Een gewone hyphen/minus (U+002D) valt hier NOOIT onder.
EMDASH='\x{2014}'
# emoji: de gangbare emoji-blokken. Accenten (U+00E9, U+00FC), hyphen en gewone
# leestekens liggen ver onder U+2600 en vallen hier dus nooit onder.
EMOJI='[\x{1F000}-\x{1FAFF}\x{2600}-\x{26FF}\x{FE0F}]'
# AI-attributie-markers, case-insensitive. Opgebouwd uit stukken zodat deze regels
# de scan niet op zichzelf laten falen. Runtime-waarde: de drie verboden markers.
_a1="Generated"; _a2="with"; _a3="Co"; _a4="authored"
ATTRIB="${_a1} ${_a2}|${_a3}-${_a4}"

# Scant een tekstblok op alle drie de categorieen. $1 = plek-omschrijving.
check_text() {
  local where="$1"
  local text="$2"
  local hit

  if hit=$(printf '%s\n' "$text" | grep -nP "$EMDASH" 2>/dev/null); then
    echo "FOUT [$where]: em-dash (U+2014) gevonden. Gebruik gewone interpunctie:"
    printf '%s\n' "$hit" | sed 's/^/    /'
    FAIL=$((FAIL + 1))
  fi

  if hit=$(printf '%s\n' "$text" | grep -nP "$EMOJI" 2>/dev/null); then
    echo "FOUT [$where]: emoji gevonden. Geen emoji in commit/PR/comments:"
    printf '%s\n' "$hit" | sed 's/^/    /'
    FAIL=$((FAIL + 1))
  fi

  if hit=$(printf '%s\n' "$text" | grep -niE "$ATTRIB" 2>/dev/null); then
    echo "FOUT [$where]: AI-attributie gevonden. Commit in Micks naam, geen co-author/generated-with-regel:"
    printf '%s\n' "$hit" | sed 's/^/    /'
    FAIL=$((FAIL + 1))
  fi
}

# Scant elke commit in een rev-list-revspec: message + toegevoegde diff-regels.
scan_revspec() {
  local revspec="$1"
  local commits c msg added
  commits=$(git rev-list $revspec 2>/dev/null || true)
  [ -z "$commits" ] && return 0
  for c in $commits; do
    msg=$(git log -1 --format=%B "$c")
    check_text "commit-message ${c:0:12}" "$msg"
    added=$(git show "$c" --no-color --format= --unified=0 2>/dev/null \
      | grep '^+' | grep -v '^+++' || true)
    [ -n "$added" ] && check_text "toegevoegde regels ${c:0:12}" "$added"
  done
}

# ── Modusbepaling ─────────────────────────────────────────────────────────────
if [ "${1:-}" = "--pre-push" ] || [ "${1:-}" = "--stdin" ]; then
  # git pre-push protocol op stdin: <local ref> <local sha> <remote ref> <remote sha>
  while read -r local_ref local_sha remote_ref remote_sha; do
    [ -z "${local_sha:-}" ] && continue
    if [ "$local_sha" = "$ZERO" ]; then
      continue  # branch wordt verwijderd, niets te scannen
    fi
    if [ "$remote_sha" = "$ZERO" ]; then
      # nieuwe branch op de remote: alleen commits die nog nergens op een remote staan
      scan_revspec "$local_sha --not --remotes"
    else
      scan_revspec "$remote_sha..$local_sha"
    fi
  done
else
  # standalone: $1 = git-range, default de laatste commit
  if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then
    scan_revspec "$1"
  else
    scan_revspec "-n 1 HEAD"
  fi
fi

if [ "$FAIL" -eq 0 ]; then
  echo "OK: commit-message(s) en toegevoegde regels voldoen aan de stijlregels"
  exit 0
else
  echo "GEBLOKKEERD: $FAIL stijlfout(en) gevonden. Herschrijf en commit opnieuw, niet pushen."
  exit 1
fi
