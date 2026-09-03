#!/usr/bin/env bash
#
# posture.sh - measure the security posture of Paramant from the outside.
#
# It logs in nowhere and changes nothing. Every check is a black-box measurement
# against the live hostnames, plus npm audit over the three lockfiles and the
# Rust lockfile against the advisory database.
#
# The rule this script is built on, learned the expensive way from the old
# heartbeat: a monitoring step never gets an escape of its own. A missing tool,
# an unreachable host or an unparseable answer is red with the name of what is
# missing, never green with a reason. See docs Bevinding "de heartbeat bewees
# niets" (2026-09-02).
#
# Usage:
#   scripts/security/posture.sh [--report FILE] [--json FILE] [--min-cert-days N]
#
# Exit codes:
#   0  every check green
#   1  at least one check red
#   2  the script itself could not run (bad usage)
#
# Test seam: the external binaries are taken from these variables, so a dry run
# can substitute stubs without touching the network.
#   POSTURE_CURL POSTURE_OPENSSL POSTURE_DIG POSTURE_NPM
#
set -uo pipefail

CURL=${POSTURE_CURL:-curl}
OPENSSL=${POSTURE_OPENSSL:-openssl}
DIG=${POSTURE_DIG:-dig}
NPM=${POSTURE_NPM:-npm}

APEX=paramant.app
HOSTS=(paramant.app relay.paramant.app health.paramant.app legal.paramant.app finance.paramant.app iot.paramant.app)
SECTORS=(relay.paramant.app health.paramant.app legal.paramant.app finance.paramant.app iot.paramant.app)
HEADER_PATHS=(/ /sign /pricing /parasign)
REQUIRED_HEADERS=(strict-transport-security content-security-policy x-frame-options referrer-policy permissions-policy x-content-type-options)
PARAID_ROUTE=/v1/paraid/issue-document
DKIM_SELECTOR=resend
NPM_DIRS=(. relay admin)
CARGO_DIR=crypto-wasm

REPORT=""
JSON=""
MIN_CERT_DAYS=21
CURL_TIMEOUT=${POSTURE_CURL_TIMEOUT:-20}

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

while [ $# -gt 0 ]; do
  case "$1" in
    --report) REPORT=${2:-}; shift 2 ;;
    --json) JSON=${2:-}; shift 2 ;;
    --min-cert-days) MIN_CERT_DAYS=${2:-}; shift 2 ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "posture.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

RED_COUNT=0
GREEN_COUNT=0
ROWS_FILE=$(mktemp)
ERRORS_FILE=$(mktemp)
NOTES_FILE=$(mktemp)
trap 'rm -f "$ROWS_FILE" "$ERRORS_FILE" "$NOTES_FILE"' EXIT

# record GROUP NAME STATUS DETAIL
# STATUS is green or red. There is deliberately no third value: a check that
# cannot be performed is red, named after what stopped it.
record() {
  local group=$1 name=$2 status=$3 detail=$4
  printf '%s\t%s\t%s\t%s\n' "$group" "$name" "$status" "$detail" >>"$ROWS_FILE"
  if [ "$status" = red ]; then
    RED_COUNT=$((RED_COUNT + 1))
    printf '::error title=%s::%s - %s\n' "$group" "$name" "$detail" >>"$ERRORS_FILE"
    printf '  ROOD  %-46s %s\n' "$name" "$detail" >&2
  else
    GREEN_COUNT=$((GREEN_COUNT + 1))
    printf '  groen %-46s %s\n' "$name" "$detail" >&2
  fi
}

# note records an observation that is not a pass/fail gate, so that the report
# carries what was seen even where nothing is asserted about it.
note() { printf '%s\n' "$1" >>"$NOTES_FILE"; }

section() { printf '\n== %s ==\n' "$1" >&2; }

need_tool() {
  local bin=$1 group=$2
  if ! command -v "${bin%% *}" >/dev/null 2>&1; then
    record "$group" "tool $bin" red "not on PATH; the check could not run"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------- TLS

check_tls() {
  section "TLS en certificaten"
  need_tool "$OPENSSL" tls || return
  local now host
  now=$(date +%s)
  for host in "${HOSTS[@]}"; do
    local pem
    pem=$("$OPENSSL" s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null \
      | "$OPENSSL" x509 2>/dev/null)
    if [ -z "$pem" ]; then
      record tls "cert $host" red "no certificate returned on port 443"
      continue
    fi

    local enddate end_epoch days
    enddate=$(printf '%s' "$pem" | "$OPENSSL" x509 -noout -enddate 2>/dev/null | cut -d= -f2-)
    end_epoch=$(date -d "$enddate" +%s 2>/dev/null || echo "")
    if [ -z "$end_epoch" ]; then
      record tls "cert expiry $host" red "notAfter could not be parsed: '$enddate'"
    else
      days=$(( (end_epoch - now) / 86400 ))
      if [ "$days" -lt "$MIN_CERT_DAYS" ]; then
        record tls "cert expiry $host" red "expires in ${days}d (floor ${MIN_CERT_DAYS}d), notAfter $enddate"
      else
        record tls "cert expiry $host" green "${days}d left, notAfter $enddate"
      fi
    fi

    local names
    names=$(printf '%s' "$pem" | "$OPENSSL" x509 -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/.*DNS:\([^ ,]*\).*/\1/p')
    if printf '%s\n' "$names" | grep -qx "$host"; then
      record tls "cert name $host" green "covered by subjectAltName"
    else
      record tls "cert name $host" red "hostname not in subjectAltName ($(printf '%s' "$names" | tr '\n' ' '))"
    fi

    local issuer
    issuer=$(printf '%s' "$pem" | "$OPENSSL" x509 -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    note "TLS $host issuer: $issuer"

    # TLS 1.0 and 1.1 must be refused; 1.2 and 1.3 must be offered.
    local proto
    for proto in tls1 tls1_1; do
      if "$OPENSSL" s_client -connect "$host:443" -servername "$host" "-$proto" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
        record tls "$proto refused on $host" red "deprecated protocol $proto completed a handshake"
      else
        record tls "$proto refused on $host" green "handshake refused"
      fi
    done
    for proto in tls1_2 tls1_3; do
      if "$OPENSSL" s_client -connect "$host:443" -servername "$host" "-$proto" </dev/null 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
        record tls "$proto offered on $host" green "handshake completed"
      else
        record tls "$proto offered on $host" red "modern protocol $proto is not offered"
      fi
    done
  done
}

# ------------------------------------------------------------ headers

# fetch_headers URL -> lowercased header block on stdout, empty on failure
fetch_headers() {
  "$CURL" -sS --max-time "$CURL_TIMEOUT" -o /dev/null -D - "$1" 2>/dev/null | tr '[:upper:]' '[:lower:]'
}

check_one_header_set() {
  local url=$1 label=$2 headers
  headers=$(fetch_headers "$url")
  if [ -z "$headers" ]; then
    record headers "$label" red "no response from $url"
    return
  fi

  local code
  code=$(printf '%s\n' "$headers" | sed -n 's|^http/[0-9.]* \([0-9]\{3\}\).*|\1|p' | tail -1)
  note "headers $label: HTTP $code"

  local h value
  for h in "${REQUIRED_HEADERS[@]}"; do
    value=$(printf '%s\n' "$headers" | grep -i "^$h:" | head -1 | cut -d: -f2- | sed 's/^ *//; s/\r$//')
    if [ -z "$value" ]; then
      record headers "$h on $label" red "header absent (HTTP $code)"
      continue
    fi

    local count
    count=$(printf '%s\n' "$headers" | grep -c -i "^$h:")
    if [ "$count" -gt 1 ]; then
      record headers "$h on $label" red "sent $count times; a duplicate header is ambiguous to clients and hides which layer set it"
      continue
    fi

    case "$h" in
      strict-transport-security)
        local maxage
        maxage=$(printf '%s' "$value" | sed -n 's/.*max-age=\([0-9]*\).*/\1/p')
        if [ -z "$maxage" ] || [ "$maxage" -lt 31536000 ]; then
          record headers "$h on $label" red "max-age '$maxage' below one year: $value"
        elif ! printf '%s' "$value" | grep -q includesubdomains; then
          record headers "$h on $label" red "no includeSubDomains: $value"
        else
          record headers "$h on $label" green "$value"
        fi
        ;;
      content-security-policy)
        # 'wasm-unsafe-eval' is not 'unsafe-eval'. It permits WebAssembly
        # compilation and nothing else, which is exactly what the ML-KEM and
        # ML-DSA modules need, so a naive substring match on unsafe-eval reads
        # the correct policy as a violation. Strip it before looking.
        local csp_bare
        csp_bare=$(printf '%s' "$value" | sed "s/'wasm-unsafe-eval'//g")
        if ! printf '%s' "$value" | grep -q "default-src"; then
          record headers "$h on $label" red "no default-src: $value"
        elif printf '%s' "$csp_bare" | grep -q "unsafe-eval"; then
          record headers "$h on $label" red "allows unsafe-eval: $value"
        elif printf '%s' "$csp_bare" | grep -q "script-src[^;]*unsafe-inline"; then
          record headers "$h on $label" red "script-src allows unsafe-inline: $value"
        elif ! printf '%s' "$value" | grep -q "frame-ancestors"; then
          record headers "$h on $label" red "no frame-ancestors: $value"
        else
          record headers "$h on $label" green "default-src and frame-ancestors set, no unsafe-eval or inline script"
        fi
        ;;
      x-frame-options)
        case "$value" in
          deny|sameorigin) record headers "$h on $label" green "$value" ;;
          *) record headers "$h on $label" red "expected DENY or SAMEORIGIN, got '$value'" ;;
        esac
        ;;
      referrer-policy)
        case "$value" in
          no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)
            record headers "$h on $label" green "$value" ;;
          *) record headers "$h on $label" red "leaky policy '$value'" ;;
        esac
        ;;
      permissions-policy)
        # interest-cohort is not a registered directive. A policy consisting only
        # of it parses to an empty policy, so the header is present but governs
        # nothing. Require at least one registered feature to be restricted.
        if printf '%s' "$value" | grep -qE '(geolocation|microphone|camera|payment|usb|midi|fullscreen|display-capture)='; then
          record headers "$h on $label" green "$value"
        else
          record headers "$h on $label" red "no registered feature restricted, so the policy is empty in practice: '$value'"
        fi
        ;;
      x-content-type-options)
        if [ "$value" = nosniff ]; then
          record headers "$h on $label" green "nosniff"
        else
          record headers "$h on $label" red "expected nosniff, got '$value'"
        fi
        ;;
    esac
  done
}

check_headers() {
  section "Securityheaders"
  need_tool "$CURL" headers || return
  local p host
  for p in "${HEADER_PATHS[@]}"; do
    check_one_header_set "https://$APEX$p" "$APEX$p"
  done
  # The five sector relays are their own origin with their own nginx server
  # block, so the apex result says nothing about them.
  for host in "${SECTORS[@]}"; do
    check_one_header_set "https://$host/" "$host/"
  done
}

# ---------------------------------------------------------------- DNS

txt_records() { "$DIG" +short TXT "$1" 2>/dev/null | tr -d '"'; }

check_dns() {
  section "DNS-hygiene van $APEX"
  need_tool "$DIG" dns || return

  local spf
  spf=$(txt_records "$APEX" | grep -i '^v=spf1' | head -1)
  if [ -z "$spf" ]; then
    record dns "SPF" red "no v=spf1 TXT record on $APEX"
  elif printf '%s' "$spf" | grep -qE '(\+all|[^-~?]all$)'; then
    record dns "SPF" red "record ends in a permissive all: $spf"
  else
    record dns "SPF" green "$spf"
  fi

  local dmarc policy
  dmarc=$(txt_records "_dmarc.$APEX" | grep -i '^v=DMARC1' | head -1)
  if [ -z "$dmarc" ]; then
    record dns "DMARC" red "no _dmarc.$APEX TXT record"
  else
    policy=$(printf '%s' "$dmarc" | sed -n 's/.*[; ]p=\([a-z]*\).*/\1/p')
    if [ "$policy" = none ] || [ -z "$policy" ]; then
      record dns "DMARC" red "policy p=${policy:-absent} enforces nothing: $dmarc"
    else
      record dns "DMARC" green "$dmarc"
    fi
  fi

  local caa
  caa=$("$DIG" +short CAA "$APEX" 2>/dev/null | grep -v '^$')
  if [ -z "$caa" ]; then
    record dns "CAA" red "no CAA record, so any CA in any trust store may issue for $APEX"
  else
    record dns "CAA" green "$(printf '%s' "$caa" | tr '\n' ' ')"
  fi

  local ds ad
  ds=$("$DIG" +short DS "$APEX" 2>/dev/null | grep -v '^$')
  ad=$("$DIG" +dnssec "$APEX" A 2>/dev/null | grep -c 'flags:.* ad')
  if [ -z "$ds" ] && [ "$ad" -eq 0 ]; then
    record dns "DNSSEC" red "no DS record at the parent and no authenticated-data flag; the zone is unsigned"
  else
    record dns "DNSSEC" green "DS present or answer authenticated (ds='$(printf '%s' "$ds" | tr '\n' ' ')' ad=$ad)"
  fi

  local dkim
  dkim=$(txt_records "${DKIM_SELECTOR}._domainkey.$APEX" | grep -i 'p=' | head -1)
  if [ -z "$dkim" ]; then
    record dns "DKIM selector ${DKIM_SELECTOR}" red "no key at ${DKIM_SELECTOR}._domainkey.$APEX while SPF includes amazonses.com (the Resend path)"
  else
    record dns "DKIM selector ${DKIM_SELECTOR}" green "public key present (${#dkim} chars)"
  fi
}

# -------------------------------------------------------------- ParaID

check_paraid_deny() {
  section "ParaID-deny op zes ingangen"
  need_tool "$CURL" paraid || return
  local host code
  for host in "${HOSTS[@]}"; do
    code=$("$CURL" -sS --max-time "$CURL_TIMEOUT" -o /dev/null -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' -d '{}' \
      "https://$host$PARAID_ROUTE" 2>/dev/null)
    if [ "$code" = 404 ]; then
      record paraid "deny on $host" green "POST $PARAID_ROUTE -> 404"
    else
      record paraid "deny on $host" red "POST $PARAID_ROUTE -> ${code:-no answer}, expected 404; the unauthenticated issuing route is reachable again"
    fi
  done
}

# -------------------------------------------------------------- audits

check_npm_audit() {
  section "npm audit"
  need_tool "$NPM" npm || return
  need_tool node npm || return
  local dir label out counts high crit
  for dir in "${NPM_DIRS[@]}"; do
    label=${dir#./}
    [ "$label" = "." ] && label=root
    if [ ! -f "$REPO_ROOT/$dir/package-lock.json" ]; then
      record audit "npm audit $label" red "no package-lock.json in $dir, so nothing was audited"
      continue
    fi
    # Two attempts. npm audit is a network call to the registry and a single
    # hiccup there is not a finding about Paramant; a second failure still ends
    # red, so this shortens the odds without giving the check a way out.
    out=$(cd "$REPO_ROOT/$dir" && "$NPM" audit --json 2>/dev/null)
    if ! printf '%s' "$out" | grep -q '"vulnerabilities"'; then
      out=$(cd "$REPO_ROOT/$dir" && "$NPM" audit --json 2>/dev/null)
    fi
    # Parsed with node, not sed. The report has a "high" key at more than one
    # depth and a regex picks whichever comes first in the byte stream, which is
    # not necessarily the metadata total.
    counts=$(printf '%s' "$out" | node -e '
      let raw = "";
      process.stdin.on("data", d => raw += d);
      process.stdin.on("end", () => {
        try {
          const v = JSON.parse(raw).metadata.vulnerabilities;
          if (typeof v.high !== "number" || typeof v.critical !== "number") throw new Error("no counts");
          process.stdout.write(v.critical + " " + v.high);
        } catch { process.exit(1); }
      });
    ' 2>/dev/null)
    if [ -z "$counts" ]; then
      record audit "npm audit $label" red "npm audit produced no parseable metadata.vulnerabilities"
      continue
    fi
    crit=${counts%% *}
    high=${counts##* }
    if [ "$crit" -gt 0 ] || [ "$high" -gt 0 ]; then
      record audit "npm audit $label" red "$crit critical, $high high"
    else
      record audit "npm audit $label" green "0 critical, 0 high"
    fi
  done
}

check_rust_audit() {
  section "Rust-afhankelijkheden"
  # The Rust NAPI binding lives in the sibling paramant-core repo and is not
  # checked out here. crypto-wasm is the Rust this repo owns and locks, so it is
  # what gets audited; a green line here says nothing about paramant-core.
  local lock="$REPO_ROOT/$CARGO_DIR/Cargo.lock"
  if [ ! -f "$lock" ]; then
    record audit "rust audit $CARGO_DIR" red "no Cargo.lock in $CARGO_DIR"
    return
  fi
  need_tool node audit || return
  need_tool "$CURL" audit || return

  # Why OSV and not `cargo audit --json`: the RustSec advisory record carries a
  # CVSS vector and no severity word, so a gate written against a `severity`
  # field reads undefined for every advisory and passes forever. The severity
  # comes from a source that states one, and is turned into a word by
  # scripts/security/osv-severity.mjs, which that file explains at length.
  local query
  query=$(node -e '
    const fs = require("fs");
    const lock = fs.readFileSync(process.argv[1], "utf8");
    const re = /\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g;
    const queries = [];
    let m;
    while ((m = re.exec(lock)) !== null) {
      queries.push({ package: { name: m[1], ecosystem: "crates.io" }, version: m[2] });
    }
    if (!queries.length) process.exit(1);
    process.stdout.write(JSON.stringify({ queries }));
  ' "$lock" 2>/dev/null)
  if [ -z "$query" ]; then
    record audit "rust audit $CARGO_DIR" red "no [[package]] entries parsed out of Cargo.lock"
    return
  fi

  local crates
  crates=$(printf '%s' "$query" | node -pe 'JSON.parse(require("fs").readFileSync(0,"utf8")).queries.length')

  local batch
  batch=$("$CURL" -sS --max-time 60 -X POST -H 'Content-Type: application/json' \
    -d "$query" https://api.osv.dev/v1/querybatch 2>/dev/null)
  # results must line up one-for-one with the crates asked about. A short or
  # empty array is a truncated answer, and reading "no vulns" out of it would
  # turn an outage into a clean bill of health for 114 crates.
  local ids
  if ! ids=$(printf '%s' "$batch" | node -e '
    let raw = "";
    process.stdin.on("data", d => raw += d);
    process.stdin.on("end", () => {
      try {
        const want = Number(process.argv[1]);
        const r = JSON.parse(raw).results;
        if (!Array.isArray(r)) throw new Error("results is not an array");
        if (r.length !== want) throw new Error("results " + r.length + " for " + want + " crates");
        const out = [];
        for (const entry of r) for (const v of (entry && entry.vulns) || []) out.push(v.id);
        process.stdout.write(out.join(" "));
      } catch (e) { process.stderr.write(e.message); process.exit(1); }
    });
  ' "$crates" 2>"$ROWS_FILE.osverr"); then
    record audit "rust audit $CARGO_DIR" red "the advisory service did not answer for all $crates crates: $(cat "$ROWS_FILE.osverr" 2>/dev/null)"
    rm -f "$ROWS_FILE.osverr"
    return
  fi
  rm -f "$ROWS_FILE.osverr"

  if [ -z "$ids" ]; then
    record audit "rust audit $CARGO_DIR" green "no advisories at all over $crates locked crates"
    return
  fi

  # One detail request per advisory, concatenated as json lines, classified in
  # a single pass.
  local details id detail
  details="$ROWS_FILE.osv"
  : >"$details"
  for id in $ids; do
    detail=$("$CURL" -sS --max-time 30 "https://api.osv.dev/v1/vulns/$id" 2>/dev/null)
    # An empty or multi-line answer must still occupy a line, or the classifier
    # silently sees fewer advisories than were found.
    printf '%s\n' "$(printf '%s' "${detail:-{\}}" | tr -d '\n')" >>"$details"
  done

  local verdicts
  verdicts=$(node "$REPO_ROOT/scripts/security/osv-severity.mjs" <"$details" 2>/dev/null)
  local want got
  want=$(printf '%s\n' "$ids" | tr ' ' '\n' | grep -c .)
  got=$(printf '%s\n' "$verdicts" | grep -c .)
  rm -f "$details"
  if [ -z "$verdicts" ] || [ "$got" -ne "$want" ]; then
    record audit "rust audit $CARGO_DIR" red "classified $got of $want advisories; the rest could not be read"
    return
  fi

  local bad="" seen="" vid band why
  while IFS=$'\t' read -r vid band why; do
    [ -z "$vid" ] && continue
    case "$band" in
      high|critical|unknown) bad="$bad $vid($band: $why)" ;;
      *) seen="$seen $vid($band)" ;;
    esac
  done <<<"$verdicts"

  if [ -n "$bad" ]; then
    record audit "rust audit $CARGO_DIR" red "high, critical or unrated advisories against the locked tree:$bad"
  else
    record audit "rust audit $CARGO_DIR" green "0 high or critical over $crates locked crates"
  fi
  [ -n "$seen" ] && note "rust audit $CARGO_DIR, below the failing threshold:$seen"
}

# ------------------------------------------------- robots and sitemap

check_robots_sitemap() {
  section "robots.txt en sitemap.xml"
  need_tool "$CURL" seo || return

  local robots
  robots=$("$CURL" -sS --max-time "$CURL_TIMEOUT" "https://$APEX/robots.txt" 2>/dev/null)
  if [ -z "$robots" ]; then
    record seo "robots.txt served" red "not served on https://$APEX/robots.txt"
    return
  fi

  if printf '%s\n' "$robots" | grep -qi "^sitemap:.*sitemap.xml"; then
    record seo "robots.txt names the sitemap" green "$(printf '%s\n' "$robots" | grep -i '^sitemap:' | head -1)"
  else
    record seo "robots.txt names the sitemap" red "no Sitemap: line in robots.txt"
  fi

  local sitemap
  sitemap=$("$CURL" -sS --max-time "$CURL_TIMEOUT" "https://$APEX/sitemap.xml" 2>/dev/null)
  if ! printf '%s' "$sitemap" | grep -q "<urlset"; then
    record seo "sitemap.xml served as a urlset" red "not served or not a urlset on https://$APEX/sitemap.xml"
    return
  fi

  local locs
  locs=$(printf '%s' "$sitemap" | sed -n 's|.*<loc>\(.*\)</loc>.*|\1|p')
  local total
  total=$(printf '%s\n' "$locs" | grep -c .)
  # A precondition, not a measurement: it is recorded as a note rather than a
  # green row, because the failing side of it is the "served as a urlset" row
  # above. One measurement, one name, or it can never be seen to change.
  note "sitemap.xml: $total urls"

  local disallows
  disallows=$(printf '%s\n' "$robots" | sed -n 's/^[Dd]isallow: *//p' | grep -v '^$')

  local bad_status="" bad_disallow="" bad_host="" loc code path rule
  while IFS= read -r loc; do
    [ -z "$loc" ] && continue
    # The sitemap is fetched over the network, so its contents are input, not
    # instruction. Anything that is not our own origin does not get requested:
    # a scanner that follows whatever a <loc> says is a scanner that can be
    # aimed at a third party by editing one file on the web server.
    case "$loc" in
      "https://$APEX"|"https://$APEX"/*|https://*.paramant.app|https://*.paramant.app/*) ;;
      *) bad_host="$bad_host $loc"; continue ;;
    esac
    code=$("$CURL" -sS --max-time "$CURL_TIMEOUT" -o /dev/null -w '%{http_code}' "$loc" 2>/dev/null)
    if [ "$code" != 200 ]; then
      bad_status="$bad_status $loc=${code:-none}"
    fi
    path=${loc#"https://$APEX"}
    [ -z "$path" ] && path=/
    while IFS= read -r rule; do
      [ -z "$rule" ] && continue
      case "$path" in
        "$rule"*) bad_disallow="$bad_disallow $loc(via $rule)" ;;
      esac
    done <<<"$disallows"
  done <<<"$locs"

  if [ -n "$bad_status" ]; then
    record seo "every sitemap url answers 200" red "not 200:$bad_status"
  else
    record seo "every sitemap url answers 200" green "$total/$total"
  fi

  if [ -n "$bad_disallow" ]; then
    record seo "no sitemap url is disallowed" red "robots.txt blocks:$bad_disallow"
  else
    record seo "no sitemap url is disallowed" green "checked against $(printf '%s\n' "$disallows" | grep -c .) disallow rules"
  fi

  if [ -n "$bad_host" ]; then
    record seo "every sitemap url is ours" red "off-origin urls, not requested:$bad_host"
  else
    record seo "every sitemap url is ours" green "all $total on paramant.app"
  fi
}

# ---------------------------------------------------------------- run

check_tls
check_headers
check_dns
check_paraid_deny
check_npm_audit
check_rust_audit
check_robots_sitemap

# ------------------------------------------------------------ reports

STAMP=$(date -u '+%Y-%m-%d %H:%M UTC')
VERDICT=GROEN
[ "$RED_COUNT" -gt 0 ] && VERDICT=ROOD

write_report() {
  printf '# Security posture van Paramant\n\n'
  printf 'Gemeten van buitenaf op %s. Nergens ingelogd, niets gewijzigd.\n\n' "$STAMP"
  printf '**Uitslag: %s** - %d groen, %d rood.\n\n' "$VERDICT" "$GREEN_COUNT" "$RED_COUNT"

  if [ "$RED_COUNT" -gt 0 ]; then
    printf '## Rood\n\n| groep | meting | wat er is |\n|---|---|---|\n'
    awk -F'\t' '$3=="red" {printf "| %s | %s | %s |\n", $1, $2, $4}' "$ROWS_FILE"
    printf '\n'
  fi

  printf '## Alle metingen\n\n| groep | meting | uitslag | wat er is |\n|---|---|---|---|\n'
  awk -F'\t' '{printf "| %s | %s | %s | %s |\n", $1, $2, ($3=="red" ? "ROOD" : "groen"), $4}' "$ROWS_FILE"

  if [ -s "$NOTES_FILE" ]; then
    printf '\n## Waargenomen, niet beoordeeld\n\n'
    sed 's/^/- /' "$NOTES_FILE"
  fi

  printf '\n---\n\nEen meting die niet uitgevoerd kon worden telt als rood, met de naam van wat ontbrak.\nEen bewakingsstap heeft geen eigen ontsnapping.\n'
}

if [ -n "$REPORT" ]; then
  write_report >"$REPORT"
  echo "report: $REPORT" >&2
fi

if [ -n "$JSON" ]; then
  {
    printf '{"stamp":"%s","verdict":"%s","green":%d,"red":%d,"checks":[' "$STAMP" "$VERDICT" "$GREEN_COUNT" "$RED_COUNT"
    awk -F'\t' 'BEGIN{first=1}
      {gsub(/\\/,"\\\\",$4); gsub(/"/,"\\\"",$4); gsub(/"/,"\\\"",$2);
       if(!first) printf ","; first=0;
       printf "{\"group\":\"%s\",\"name\":\"%s\",\"status\":\"%s\",\"detail\":\"%s\"}", $1,$2,$3,$4}' "$ROWS_FILE"
    printf ']}\n'
  } >"$JSON"
  echo "json: $JSON" >&2
fi

if [ -s "$ERRORS_FILE" ]; then
  cat "$ERRORS_FILE"
fi

printf '\n%s: %d groen, %d rood\n' "$VERDICT" "$GREEN_COUNT" "$RED_COUNT" >&2

[ "$RED_COUNT" -eq 0 ] || exit 1
exit 0
