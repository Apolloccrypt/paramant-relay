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
# Exit 0 = docroot matches the ref, 1 = drift, 2 = cannot check.
#
# Files the docroot legitimately holds and the repo does not (dist/, the
# investor brief, paramant-mark.svg) are listed in IGNORE below. They are the
# reason a deploy must never use --delete.
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

if [ -z "$drift" ]; then
  echo "prod drift guard: OK — $DOCROOT matches $REF ($COMMIT)"
  exit 0
fi

echo "prod drift guard: DRIFT — $DOCROOT differs from $REF ($COMMIT)"
echo
echo "$drift"
echo
echo "Lines starting with <f are files the server would receive: prod is behind"
echo "the ref, or was edited by hand. Investigate before deploying."
exit 1
