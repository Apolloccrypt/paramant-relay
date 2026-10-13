#!/usr/bin/env bash
# Docroot drift guard. The production docroot is /home/paramant/app, NOT the
# repo, and deploys are file copies. So the docroot can differ from the commit
# it is supposed to be running, in both directions:
#
#   behind  a fix was merged but never copied out (July 2026: editor, v3-verify,
#           email, signup and claim all ran older code than main)
#   ahead   a file was hand-edited on the server and exists nowhere in git
#
# Both are silent. This script compares, by checksum, what is on the server with
# what is in a given commit, and reports every difference. It changes nothing.
#
# Run from the NUC, where the prod key lives:
#   scripts/check-prod-drift.sh [ref]        (default: origin/main)
#
# Exit 0 = docroot and site nginx conf match the ref, 1 = drift, 2 = cannot check.
#
# Files the docroot legitimately holds and the repo does not (dist/, the
# investor brief, paramant-mark.svg) are listed in IGNORE below. They are the
# reason a deploy must never use --delete.
#
# The site nginx conf is the second half. deploy-3.1.sh phase 5c only ever
# applied seven edits to it, and on 2026-10-05 the server conf differed from
# deploy/nginx-paramant-live.conf by ~600 lines (/api/user/ on a login brake,
# /parashare?t= losing its token). Phase 5e now places the whole rendered conf;
# this guard reads the live one (read-only, cat over ssh) and diffs it against
# deploy/nginx-render.sh at the ref, plus the security-headers snippet it
# includes. PARAMANT_NGINX_LIVE_COPY=<file> diffs against a local copy instead.
set -euo pipefail

REF="${1:-origin/main}"
KEY="${PARAMANT_PROD_KEY:-$HOME/.ssh/paramant_prod_claude}"
HOST="${PARAMANT_PROD_HOST:-root@116.203.86.81}"
DOCROOT="${PARAMANT_DOCROOT:-/home/paramant/app}"
WORKTREE="$(mktemp -d /tmp/paramant-drift.XXXXXX)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Present on the server by design, absent from the repo.
IGNORE=(--exclude 'dist/***' --exclude 'paramant-mark.svg' --exclude 'developer.js' --exclude 'docs/paramant-investor-brief.html')

cleanup() { git -C "$ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || rm -rf "$WORKTREE"; }
trap cleanup EXIT

[ -r "$KEY" ] || { echo "prod key not readable: $KEY (run this on the NUC)" >&2; exit 2; }

git -C "$ROOT" fetch -q origin
rmdir "$WORKTREE"
git -C "$ROOT" worktree add -q --detach "$WORKTREE" "$REF"
COMMIT="$(git -C "$WORKTREE" rev-parse --short HEAD)"

# -c compares content, not timestamps: a deploy that copied the bytes but not
# the mtime is not drift. -i lists what WOULD change, -n changes nothing.
drift="$(rsync -rinc --no-times "${IGNORE[@]}" \
  -e "ssh -i $KEY -o BatchMode=yes" \
  "$WORKTREE/frontend/" "$HOST:$DOCROOT/" 2>/dev/null | grep -v '^$' || true)"

status=0
if [ -z "$drift" ]; then
  echo "prod drift guard: OK - $DOCROOT matches $REF ($COMMIT)"
else
  status=1
  echo "prod drift guard: DRIFT - $DOCROOT differs from $REF ($COMMIT)"
  echo
  echo "$drift"
  echo
  echo "Lines starting with <f are files the server would receive: prod is behind"
  echo "the ref, or was edited by hand. Investigate before deploying."
fi

# ---- the site nginx conf and its snippet ----
SITES="${PARAMANT_NGINX_SITES:-/etc/nginx/sites-enabled}"
SNIP="${PARAMANT_NGINX_SNIPPET:-/etc/nginx/snippets/paramant-security-headers.conf}"
echo
if [ ! -f "$WORKTREE/deploy/nginx-render.sh" ]; then
  echo "nginx drift guard: SKIP - $REF ($COMMIT) predates deploy/nginx-render.sh"
  exit "$status"
fi
want="$(PARAMANT_DOCROOT="$DOCROOT" bash "$WORKTREE/deploy/nginx-render.sh" "$WORKTREE/deploy/nginx-paramant-live.conf")"
want_snip="$(cat "$WORKTREE/deploy/nginx/snippets/paramant-security-headers.conf")"
if [ -n "${PARAMANT_NGINX_LIVE_COPY:-}" ]; then
  live="$(cat "$PARAMANT_NGINX_LIVE_COPY")"
  live_snip="$want_snip"
  where="$PARAMANT_NGINX_LIVE_COPY (local copy; snippet not compared)"
else
  # Same candidates as deploy-3.1.sh NGINX_LIVE_SLOT: the first one present wins.
  live="$(ssh -i "$KEY" -o BatchMode=yes "$HOST" \
    "for n in paramant-live.conf paramant.conf; do [ -e '$SITES'/\$n ] && { cat \"\$(readlink -f '$SITES'/\$n)\"; exit 0; }; done; exit 3")" \
    || { echo "nginx drift guard: cannot read the live site conf in $SITES" >&2; exit 2; }
  live_snip="$(ssh -i "$KEY" -o BatchMode=yes "$HOST" "cat '$SNIP' 2>/dev/null || true")"
  where="$HOST:$SITES"
fi
ndiff="$(diff -u --label "live" --label "repo $COMMIT, rendered" <(printf '%s\n' "$live") <(printf '%s\n' "$want") || true)"
sdiff="$(diff -u --label "live snippet" --label "repo snippet" <(printf '%s\n' "$live_snip") <(printf '%s\n' "$want_snip") || true)"
if [ -z "$ndiff" ] && [ -z "$sdiff" ]; then
  echo "nginx drift guard: OK - the site conf in $where is the repo conf at $REF ($COMMIT)"
  exit "$status"
fi
echo "nginx drift guard: DRIFT - the site conf in $where differs from $REF ($COMMIT)"
echo "  $(printf '%s\n' "$ndiff" | grep -cE '^[-+][^-+]|^[-+]$' || true) conf line(s), $(printf '%s\n' "$sdiff" | grep -cE '^[-+][^-+]|^[-+]$' || true) snippet line(s)"
echo
[ -n "$ndiff" ] && printf '%s\n' "$ndiff"
[ -n "$sdiff" ] && printf '%s\n' "$sdiff"
echo
echo "'+' lines are in the repo and not on the server. Place the repo conf with"
echo "bash deploy/deploy-3.1.sh --nginx-sync (--dry-run first)."
exit 1
