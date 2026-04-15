#!/usr/bin/env bash
# PARAMANT client installer
# Usage: curl -fsSL https://paramant.app/install-client.sh | bash
# Docs:  https://paramant.app/docs
# BUSL-1.1 — free for Community Edition

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; C='\033[0;36m'
W='\033[1;37m'; D='\033[2m'; E='\033[0m'; BOLD='\033[1m'

ok()   { echo -e "${G}✓${E}  $*"; }
err()  { echo -e "${R}✗${E}  $*" >&2; }
warn() { echo -e "${Y}⚠${E}  $*"; }
info() { echo -e "${D}·${E}  $*"; }
step() { echo -e "\n${BOLD}${W}$*${E}"; }

CLIENT_VERSION="1.0"
RELEASE_TAG="client-v${CLIENT_VERSION}"
GITHUB_REPO="Apolloccrypt/paramant-relay"
RELEASES="https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_TAG}"

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "
${C}${BOLD}  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗ █████╗ ███╗  ██╗████████╗${E}
${C}${BOLD}  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔══██╗████╗ ██║╚══██╔══╝${E}
${C}${BOLD}  ██████╔╝███████║██████╔╝███████║██╔████╔██║███████║██╔██╗██║   ██║   ${E}
${C}${BOLD}  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══██║██║╚████║   ██║   ${E}
${C}${BOLD}  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██║ ╚███║   ██║   ${E}
${C}${BOLD}  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝   ${E}

  ${D}PARAMANT Client Installer v${CLIENT_VERSION}${E}
  ${D}ML-KEM-768 · Burn-on-read · EU/DE${E}
"

# ── Platform check ────────────────────────────────────────────────────────────
step "Step 1/3 — Detecting platform"

ARCH=$(uname -m)
OS_ID=""
[[ -f /etc/os-release ]] && . /etc/os-release || true

case "$ARCH" in
  x86_64)  DEB_ARCH="amd64"  ;;
  aarch64) DEB_ARCH="arm64"  ;;
  *)
    err "Unsupported architecture: ${ARCH}"
    err "Supported: x86_64 (amd64), aarch64 (arm64)"
    exit 1
    ;;
esac

case "${ID:-}" in
  ubuntu|debian|raspbian|linuxmint|pop)
    ok "Detected Debian-based OS (${PRETTY_NAME:-Linux})"
    ;;
  *)
    if command -v dpkg &>/dev/null; then
      warn "Non-standard Debian variant — attempting dpkg install"
    else
      err "This installer requires a Debian/Ubuntu-based system with dpkg."
      err "For other platforms, download directly from:"
      err "  https://github.com/${GITHUB_REPO}/releases/tag/${RELEASE_TAG}"
      exit 1
    fi
    ;;
esac

# ── Download ─────────────────────────────────────────────────────────────────
step "Step 2/3 — Downloading paramant-client v${CLIENT_VERSION} (${DEB_ARCH})"

DEB_FILE="paramant-client_${CLIENT_VERSION}_${DEB_ARCH}.deb"
DEB_URL="${RELEASES}/${DEB_FILE}"
TMP_DEB="/tmp/${DEB_FILE}"

info "From: ${DEB_URL}"

if command -v curl &>/dev/null; then
  curl -fsSL --progress-bar -o "${TMP_DEB}" "${DEB_URL}" || {
    err "Download failed. Check your connection or visit:"
    err "  https://github.com/${GITHUB_REPO}/releases/tag/${RELEASE_TAG}"
    exit 1
  }
elif command -v wget &>/dev/null; then
  wget -q --show-progress -O "${TMP_DEB}" "${DEB_URL}" || {
    err "Download failed."
    exit 1
  }
else
  err "curl or wget is required."
  exit 1
fi

ok "Downloaded ${DEB_FILE}"

# ── Install ───────────────────────────────────────────────────────────────────
step "Step 3/3 — Installing"

if [[ $EUID -ne 0 ]]; then
  if command -v sudo &>/dev/null; then
    sudo dpkg -i "${TMP_DEB}" 2>&1 | grep -v "^(Reading\|Selecting\|Preparing\|Unpacking\|Setting up\|Processing)" || true
    sudo apt-get install -f -y -q 2>/dev/null || true
  else
    err "Root access required. Run:"
    echo "  sudo dpkg -i ${TMP_DEB}"
    exit 1
  fi
else
  dpkg -i "${TMP_DEB}" 2>&1 | grep -v "^(Reading\|Selecting\|Preparing\|Unpacking\|Setting up\|Processing)" || true
  apt-get install -f -y -q 2>/dev/null || true
fi

rm -f "${TMP_DEB}"
ok "paramant-client installed"

# ── Done ─────────────────────────────────────────────────────────────────────
echo -e "
${G}${BOLD}  Installation complete.${E}

  ${D}Usage:${E}
    paramant upload --key \$API_KEY file.pdf
    paramant receive \$TOKEN

  ${D}Get a free API key:${E}
    https://paramant.app/request-key

  ${D}Docs:${E}
    https://paramant.app/docs
"
