#!/usr/bin/env bash
# PARAMANT client installer — DEPRECATED
#
# This installer was for the standalone .deb package which is no longer
# maintained. The .deb's GitHub release tag (client-v1.0) was never
# published, so this script returned 404 for everyone.
#
# Use the SDKs instead:
#
#   # Python (recommended for CLI use):
#   pip install paramant-sdk
#
#   # JavaScript (Node-based tooling):
#   npm install paramant-sdk
#
# Both SDKs include CLI helpers and are kept current with the wire
# format spec. See https://paramant.app/docs

cat >&2 <<'NOTICE'

  install-client.sh is deprecated.

  Install the Python SDK:
    pip install paramant-sdk

  Or the JavaScript SDK:
    npm install paramant-sdk

  Documentation: https://paramant.app/docs

NOTICE

exit 1
