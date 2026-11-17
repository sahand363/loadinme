#!/usr/bin/env bash
# LoadInMe — quick installer for Ubuntu server.
#
# Downloads the pre-built binary from the latest GitHub release.
# No Go, no clone, no compile on the server.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash
#
# Specific version (a git tag, e.g. v0.1.0):
#   curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash -s -- --version v0.1.0
#   VERSION=v0.1.0 bash install.sh
#
# Env overrides:
#   INSTALL_DIR - where to put the binary, default $HOME/.local/bin
#   VERSION     - release tag to download, default: latest
set -euo pipefail

REPO="sahfar363/loadinme"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-}"

# Parse --version (also accepts --version=v0.1.0).
while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:-}"; shift 2 ;;
    --version=*)
      VERSION="${1#*=}"; shift ;;
    --install-dir)
      INSTALL_DIR="${2:-}"; shift 2 ;;
    --install-dir=*)
      INSTALL_DIR="${1#*=}"; shift ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: install.sh [--version v0.1.0] [--install-dir DIR]" >&2
      exit 1 ;;
  esac
done

echo "==> LoadInMe quick installer (no compile — binary download)"

# --- Architecture ---
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  GO_ARCH=amd64 ;;
  aarch64|arm64) GO_ARCH=arm64 ;;
  *)
    echo "Unsupported architecture: $ARCH (only x86_64/amd64 and aarch64/arm64 releases exist)" >&2
    exit 1 ;;
esac
echo "Architecture: $ARCH ($GO_ARCH)"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required. Install it with: sudo apt update && sudo apt install -y curl" >&2
  exit 1
fi

# --- Download URL ---
if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/loadinme-linux-${GO_ARCH}"
  echo "Release: latest"
else
  # Accept both "0.1.0" and "v0.1.0".
  case "$VERSION" in
    v*) TAG="$VERSION" ;;
    *)  TAG="v$VERSION" ;;
  esac
  URL="https://github.com/${REPO}/releases/download/${TAG}/loadinme-linux-${GO_ARCH}"
  echo "Release: $TAG"
fi
echo "Downloading: $URL"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! curl -fsSL -o "$TMP/loadinme" "$URL"; then
  echo "" >&2
  echo "ERROR: could not download LoadInMe from:" >&2
  echo "  $URL" >&2
  echo "" >&2
  echo "That usually means no release exists yet for this version." >&2
  echo "Create one first (from your laptop, in the repo):" >&2
  echo "  git tag v0.1.0" >&2
  echo "  git push origin v0.1.0" >&2
  echo "Then wait a minute for GitHub Actions to build and publish" >&2
  echo "loadinme-linux-amd64 and loadinme-linux-arm64, and run this installer again." >&2
  echo "This installer does not fall back to compiling — the binary is the point." >&2
  exit 1
fi

chmod +x "$TMP/loadinme"

# --- Verify the binary actually runs before installing it ---
if ! "$TMP/loadinme" --help >/dev/null 2>&1; then
  echo "ERROR: the downloaded file does not run as loadinme. Aborting." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 755 "$TMP/loadinme" "$INSTALL_DIR/loadinme"

echo ""
echo "Installed: $INSTALL_DIR/loadinme"
echo ""
echo "Next steps:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "  loadinme menu        # SSH menu — the web link is on top"
echo ""
echo "Or start the web UI directly:"
echo "  loadinme serve --port 8080"
echo "Then open the printed address in your browser and create your login."
