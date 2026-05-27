#!/usr/bin/env bash
# paramant-config-show (web-cli) -- show current env config with secrets masked.
# Non-interactive, read-only. ASCII-only.
# NEVER prints secret values: anything whose name matches the secret pattern is
# shown as "<set>" or "<empty>" only.
set -uo pipefail

echo "Paramant config (secrets masked)"
echo "--------------------------------------"

# Pattern of env var names considered secret.
SECRET_RE='TOKEN|SECRET|PASSWORD|PASSWD|KEY|RESEND|API_KEY|PRIVATE'

# Only surface paramant/relay/admin-relevant variables, never the whole env.
ALLOW_RE='^(PORT|BASE_PATH|NODE_ENV|RELAY_|SECTOR|ADMIN_|PARAMANT_|NATS_|REDIS_|RESEND_)'

printenv | sort | while IFS='=' read -r name value; do
  echo "$name" | grep -qE "$ALLOW_RE" || continue
  if echo "$name" | grep -qE "$SECRET_RE"; then
    if [ -n "$value" ]; then
      echo "  ${name}=<set>"
    else
      echo "  ${name}=<empty>"
    fi
  else
    echo "  ${name}=${value}"
  fi
done
