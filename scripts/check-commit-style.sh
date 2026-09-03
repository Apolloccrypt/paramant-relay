#!/usr/bin/env bash
# Commit- en GitHub-stijl-poort. Blokkeert wat niet in Micks publieke repos hoort:
#   1. em-dash (U+2014) in een commit-message of in een toegevoegde diff-regel
#   2. emoji (gangbare emoji-unicodeblokken)
#   3. AI-attributie-markers (zie ATTRIB hieronder)
# Scant de commit-message(s) EN de toegevoegde ('+') regels van de commits.
#
# UITZONDERING op regel 1, en alleen op regel 1. De licentietekst is een
# juridisch document en geen kopij: LICENSE bepaalt wat iemand met deze software
# mag, en die tekst herschrijven om een stijlregel te halen is een besluit van
# de licentiegever, niet van deze wacht. De Additional Use Grant bevat twee
# em-dashes. Vrijgesteld zijn daarom:
#
#   - LICENSE en deploy/LICENSE, op pad, in hun geheel
#   - in frontend/license.html het blok tussen LICENCE-VERBATIM-START en
#     LICENCE-VERBATIM-END, dat LICENSE woord voor woord herhaalt en door
#     blok 23 van tests/site-claims.test.mjs daaraan gelijk wordt gehouden
#
# Emoji en AI-attributie blijven overal verboden, ook daar. De vrijstelling
# geldt uitsluitend voor diff-regels: een commit-message met een em-dash wordt
# geweigerd, ook als hij de licentie aanpast. En zij geldt per regelnummer, dus
# een em-dash die elders op license.html wordt toegevoegd valt gewoon door.
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

# Paden waarvan elke toegevoegde regel van de em-dash-regel is vrijgesteld.
EMDASH_EXEMPT_PATHS='^(LICENSE|deploy/LICENSE)$'
# Bestand met een gemarkeerd letterlijk licentieblok, en de twee markeringen.
VERBATIM_FILE='frontend/license.html'
VERBATIM_START='LICENCE-VERBATIM-START'
VERBATIM_END='LICENCE-VERBATIM-END'

# Regelbereik van het letterlijke licentieblok in een blob ($1 = <commit>:<pad>).
# Print "start eind", of niets als het blok er niet compleet staat.
verbatim_range() {
  git show "$1" 2>/dev/null | awk -v s="$VERBATIM_START" -v e="$VERBATIM_END" '
    index($0, s) && !st { st = NR }
    index($0, e) && st && !en { en = NR }
    END { if (st && en && en > st) print st " " en }'
}

# Denylist: repo-lokale lijst met te-beschermen termen (echte namen). Staat in
# .gitignore en wordt NOOIT gecommit, zo blijven de namen lokaal. Afwezig -> de
# denylist-check wordt simpelweg overgeslagen (geen fout).
DENY_TERMS=()
_deny_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$_deny_root" ] && [ -f "$_deny_root/.style-denylist" ]; then
  while IFS= read -r _dl || [ -n "$_dl" ]; do
    _dl="${_dl#"${_dl%%[![:space:]]*}"}"   # trim leidende spaties
    case "$_dl" in ''|'#'*) continue;; esac  # lege regel of comment overslaan
    _dl="${_dl%"${_dl##*[![:space:]]}"}"     # trim volgspaties
    DENY_TERMS+=("$_dl")
  done < "$_deny_root/.style-denylist"
fi

# Scant een tekstblok op denylist-termen (hoofdletterongevoelig, heel-woord).
# Meldt ALLEEN de plek, nooit de gevonden term: die mag nooit in een log belanden.
check_denylist_text() {
  local where="$1" text="$2" term
  [ "${#DENY_TERMS[@]}" -eq 0 ] && return 0
  for term in "${DENY_TERMS[@]}"; do
    if printf '%s\n' "$text" | grep -Fiwq -- "$term"; then
      echo "FOUT [$where]: verboden term uit .style-denylist aangetroffen. Vervang door een generieke placeholder (bv. acct_demo, demo@example.com, Acme)."
      FAIL=$((FAIL + 1))
    fi
  done
}

# Scant een commit op denylist-termen: de message plus elke toegevoegde regel,
# met bestand:regelnr als plek. Print nooit de regelinhoud.
check_denylist_commit() {
  local c="$1" file="" newno=0 line content term h
  [ "${#DENY_TERMS[@]}" -eq 0 ] && return 0
  check_denylist_text "commit-message ${c:0:12}" "$(git log -1 --format=%B "$c")"
  while IFS= read -r line; do
    case "$line" in
      '+++ '*) file="${line#+++ }"; file="${file#b/}";;
      '@@'*) h="${line#*+}"; h="${h%% *}"; newno="${h%%,*}";;
      '+'*)
        content="${line#+}"
        for term in "${DENY_TERMS[@]}"; do
          if printf '%s\n' "$content" | grep -Fiwq -- "$term"; then
            echo "FOUT [commit ${c:0:12} ${file}:${newno}]: verboden term uit .style-denylist op een toegevoegde regel. Vervang door een generieke placeholder."
            FAIL=$((FAIL + 1))
          fi
        done
        newno=$((newno + 1));;
      '-'*) : ;;
      *) newno=$((newno + 1));;
    esac
  done < <(git show "$c" --no-color --format= --unified=0 2>/dev/null)
}

# Scant een tekstblok op alle drie de categorieen. $1 = plek-omschrijving.
# $3 = "no-emdash" slaat uitsluitend regel 1 over (letterlijke licentietekst).
check_text() {
  local where="$1"
  local text="$2"
  local mode="${3:-all}"
  local hit

  if [ "$mode" != "no-emdash" ] && hit=$(printf '%s\n' "$text" | grep -nP "$EMDASH" 2>/dev/null); then
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

# Verdeelt de toegevoegde regels van een commit over twee bakken: gewoon, en
# vrijgesteld van de em-dash-regel. De verdeling is per bestand, en binnen
# VERBATIM_FILE per regelnummer, dus een em-dash die buiten het gemarkeerde blok
# op diezelfde pagina wordt toegevoegd valt gewoon door de wacht.
scan_added() {
  local c="$1"
  local file="" newno=0 line content h range
  local vstart=0 vend=0 exempt
  local checked="" verbatim=""
  while IFS= read -r line; do
    case "$line" in
      '+++ '*)
        file="${line#+++ }"; file="${file#b/}"
        vstart=0; vend=0
        if [ "$file" = "$VERBATIM_FILE" ]; then
          range="$(verbatim_range "$c:$file" || true)"
          if [ -n "$range" ]; then vstart="${range%% *}"; vend="${range##* }"; fi
        fi
        ;;
      '@@'*) h="${line#*+}"; h="${h%% *}"; newno="${h%%,*}";;
      '+'*)
        content="${line#+}"
        exempt=0
        if printf '%s' "$file" | grep -qE "$EMDASH_EXEMPT_PATHS"; then
          exempt=1
        elif [ "$vend" -gt 0 ] && [ "$newno" -ge "$vstart" ] && [ "$newno" -le "$vend" ]; then
          exempt=1
        fi
        if [ "$exempt" -eq 1 ]; then
          verbatim="${verbatim}${content}"$'\n'
        else
          checked="${checked}${content}"$'\n'
        fi
        newno=$((newno + 1));;
      '-'*) : ;;
      *) newno=$((newno + 1));;
    esac
  done < <(git show "$c" --no-color --format= --unified=0 2>/dev/null)
  [ -n "$checked" ] && check_text "toegevoegde regels ${c:0:12}" "$checked"
  # Emoji en AI-attributie gelden ook in de licentietekst; alleen de em-dash niet.
  [ -n "$verbatim" ] && check_text "letterlijke licentietekst ${c:0:12}" "$verbatim" no-emdash
  return 0
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
    scan_added "$c"
    check_denylist_commit "$c"
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
