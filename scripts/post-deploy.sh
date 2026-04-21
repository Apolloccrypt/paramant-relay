#!/usr/bin/env bash
# post-deploy.sh — run after every deploy to catch auth stack regressions
# Exits non-zero (and blocks the deploy pipeline) on any test failure.
#
# Usage: ./scripts/post-deploy.sh
# Called automatically by deploy/deploy.sh after services restart.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E="${SCRIPT_DIR}/../tests/e2e-auth-flow.sh"

if [ ! -x "$E2E" ]; then
  echo "ERROR: e2e test script not found or not executable: $E2E" >&2
  exit 1
fi

echo "==> Running auth stack regression tests..."
"$E2E"
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo "" >&2
  echo "ERROR: Auth regression tests failed — deploy should be rolled back." >&2
  echo "       Check output above for which tests failed and why." >&2
  exit 1
fi

echo "==> Auth regression tests passed."
