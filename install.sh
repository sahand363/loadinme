#!/usr/bin/env bash
# LoadInMe — quick installer for Ubuntu server.
#
# Downloads the pre-built binary from the latest GitHub release.
# No Go, no clone, no compile on the server.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash
#
# After installing, the installer starts the web UI (default port 8080)
# and opens the SSH menu — the web UI link is on top of the menu.
# Open the web UI in your browser and create your login on the setup
# page. If there is no terminal (CI, a pipe without a TTY), it starts
# the web UI in the background, prints the address, and exits instead
# of hanging.
#
# Specific version (a git tag, e.g. v0.2.0):
#   curl -fsSL https://raw.githubusercontent.com/sahfar363/loadinme/main/install.sh | bash -s -- --version v0.2.0
#   VERSION=v0.2.0 bash install.sh
#
# Flags: --version TAG | --install-dir DIR | --no-menu | --no-web
#
# Env overrides:
#   INSTALL_DIR - where to put the binary, default $HOME/.local/bin
#   VERSION     - release tag to download, default: latest
#   LOADINME_NO_MENU=1 - do not open the SSH menu after installing
#   LOADINME_NO_WEB=1  - do not start the web UI after installing
#   LOADINME_DATA - data directory, default $HOME/.loadinme
#   LOCAL_BINARY - dev/test only: install this local file instead of downloading
set -euo pipefail

REPO="sahfar363/loadinme"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-}"
DATA_DIR="${LOADINME_DATA:-$HOME/.loadinme}"

# Parse --version (also accepts --version=v0.2.0).
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
    --no-menu)
      LOADINME_NO_MENU=1; shift ;;
    --no-web)
      LOADINME_NO_WEB=1; shift ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: install.sh [--version v0.2.0] [--install-dir DIR] [--no-menu] [--no-web]" >&2
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
  # Accept both "0.2.0" and "v0.2.0".
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

if [ -n "${LOCAL_BINARY:-}" ]; then
  echo "Using local binary: $LOCAL_BINARY"
  cp "$LOCAL_BINARY" "$TMP/loadinme" || { echo "ERROR: could not copy $LOCAL_BINARY" >&2; exit 1; }
elif ! curl -fsSL -o "$TMP/loadinme" "$URL"; then
  echo "" >&2
  echo "ERROR: could not download LoadInMe from:" >&2
  echo "  $URL" >&2
  echo "" >&2
  echo "That usually means no release exists yet for this version." >&2
  echo "Create one first (from your laptop, in the repo):" >&2
  echo "  git tag v0.2.0" >&2
  echo "  git push origin v0.2.0" >&2
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
BIN="$INSTALL_DIR/loadinme"

# --- Start the web UI automatically (default port 8080) ---
# A port already saved in <data-dir>/config.json wins over the default.
PORT=8080
if [ -f "$DATA_DIR/config.json" ]; then
  SAVED="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('port') or 8080)" "$DATA_DIR/config.json" 2>/dev/null || echo 8080)"
  case "$SAVED" in ''|*[!0-9]*) ;; *) PORT="$SAVED" ;; esac
fi
LOG="$DATA_DIR/loadinme.log"
if [ -z "${LOADINME_NO_WEB:-}" ]; then
  if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "Web UI is already running on port $PORT."
  elif "$BIN" start --port "$PORT" --data-dir "$DATA_DIR"; then
    if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
      echo "Web UI started on port $PORT."
    else
      echo "WARNING: the web UI did not answer on port $PORT." >&2
    fi
  else
    echo "WARNING: the web UI did not start on port $PORT — the port may already be in use." >&2
    echo "Check the log: $LOG" >&2
    echo "You can change the port in the SSH menu (option 5) and start it with option 1." >&2
  fi
fi
echo ""
echo "Open the web UI in your browser and create your login on the setup page."
echo "If the server is remote, open http://<your-server-IP>:$PORT — the SSH menu below shows the exact link on top."
echo "No terminal setup needed — everything after this is in the web UI."
echo ""

# --- Open the SSH menu (the web UI link is on top of it) ---
# When run as `curl … | bash`, stdin is the download pipe, not the
# terminal — so the menu is reopened on /dev/tty when one exists.
# With no terminal at all (CI, piped runs), print the address and exit.
if [ -z "${LOADINME_NO_MENU:-}" ]; then
  if [ -t 0 ]; then
    exec "$BIN" menu --data-dir "$DATA_DIR"
  elif [ -e /dev/tty ] && (exec 0</dev/tty) 2>/dev/null; then
    exec "$BIN" menu --data-dir "$DATA_DIR" </dev/tty
  else
    echo "No terminal attached — the web UI is running in the background."
    echo "Run \`loadinme menu\` later to open the SSH menu."
  fi
fi
