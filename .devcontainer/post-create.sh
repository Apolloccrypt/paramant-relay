#!/usr/bin/env bash
set -euo pipefail

echo "==> Installing Node dependencies (relay)..."
cd /workspaces/paramant-relay/relay && npm install

echo "==> Installing Node dependencies (fly-relay)..."
cd /workspaces/paramant-relay/fly-relay && npm install

echo "==> Installing Node dependencies (sdk-js)..."
cd /workspaces/paramant-relay/sdk-js && npm install

echo "==> Installing Python SDK..."
cd /workspaces/paramant-relay/sdk-py && pip install --user -e ".[mlkem]"

echo "==> Installing Python script dependencies..."
pip install --user cryptography

echo "==> Done. Container is ready."
