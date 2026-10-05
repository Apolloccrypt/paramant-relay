#!/usr/bin/env bash
set -euo pipefail

echo "==> Installing Node dependencies (relay)..."
cd /workspaces/paramant-relay/relay && npm install

echo "==> Installing Node dependencies (fly-relay)..."
cd /workspaces/paramant-relay/fly-relay && npm install

# The SDKs (sdk-js, sdk-py) moved to https://github.com/Apolloccrypt/paramant-sdk.
# Install the Python client from PyPI if you need it in this devcontainer:
#   pip install --user paramant-sdk

echo "==> Installing Python script dependencies..."
pip install --user cryptography

echo "==> Done. Container is ready."
