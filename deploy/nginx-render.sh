#!/usr/bin/env bash
# nginx-render.sh - the site conf exactly as it goes onto a server.
#
# deploy/nginx-paramant-live.conf is written for production: TLS terminates in
# Caddy (deploy/caddy/Caddyfile), so this conf carries no certificate, no
# server_name of its own and no public listen. What differs per machine is the
# two docroots. This script fills them in and prints the result on stdout,
# byte for byte what deploy-3.1.sh phase 5e places, what
# scripts/check-prod-drift.sh compares the server against, and what
# tests/nginx-volledig-docker.test.mjs boots in a real nginx.
#
#   deploy/nginx-render.sh [conf]          default: deploy/nginx-paramant-live.conf
#
#   PARAMANT_DOCROOT        default /home/paramant/app        (the site)
#   PARAMANT_LEGAL_DOCROOT  default /home/paramant/app-legal  (legal.paramant.app)
#
# With the defaults the output is the file itself, unchanged: production is the
# default, so a render for production can never drift from git.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:-$ROOT/deploy/nginx-paramant-live.conf}"
DOCROOT="${PARAMANT_DOCROOT:-/home/paramant/app}"
LEGAL="${PARAMANT_LEGAL_DOCROOT:-/home/paramant/app-legal}"

[ -r "$SRC" ] || { echo "nginx-render: cannot read $SRC" >&2; exit 2; }

# A value lands inside nginx directives: refuse anything that could end one.
for v in "$DOCROOT" "$LEGAL"; do
  case "$v" in
    /*) ;;
    *) echo "nginx-render: docroot must be an absolute path: $v" >&2; exit 2 ;;
  esac
  if printf '%s' "$v" | grep -q '[[:space:];{}#$"'"'"'\\]'; then
    echo "nginx-render: docroot holds a character nginx would read as syntax: $v" >&2
    exit 2
  fi
done

# Legal first: /home/paramant/app-legal starts with /home/paramant/app, and the
# trailing [/;] keeps the second rule off it either way.
sed -e "s#/home/paramant/app-legal\\([/;]\\)#${LEGAL}\\1#g" \
    -e "s#/home/paramant/app\\([/;]\\)#${DOCROOT}\\1#g" "$SRC"
