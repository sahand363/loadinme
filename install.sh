#!/usr/bin/env bash
# LoadInMe — quick installer for Ubuntu server.
#
# Downloads the pre-built binary from the latest GitHub release.
# No Go, no clone, no compile on the server.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sahand363/loadinme/main/install.sh | bash
#
# After installing, the installer restarts the web UI with the new
# version (default port 8080) and opens the SSH menu — the web UI link
# is on top of the menu. If the UI was already running, the old process
# is stopped first, so the update always applies.
# Open the web UI in your browser and create your login on the setup
# page. If there is no terminal (CI, a pipe without a TTY), it starts
# the web UI in the background, prints the address, and exits instead
# of hanging.
#
# Specific version (a git tag, e.g. v0.4.0):
#   curl -fsSL https://raw.githubusercontent.com/sahand363/loadinme/main/install.sh | bash -s -- --version v0.4.0
#   VERSION=v0.4.0 bash install.sh
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

REPO="sahand363/loadinme"
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
  echo "  git tag v0.4.0" >&2
  echo "  git push origin v0.4.0" >&2
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

# --- Address without port (v0.8.0): port 443/80 permission ---
# When LoadInMe serves https://<domain> on port 443 itself and runs as
# a normal user, its binary carries cap_net_bind_service (setcap).
# Replacing the file drops that, so grant it again BEFORE the web UI
# starts — otherwise the new version could not listen on 443/80.
if [ -f "$DATA_DIR/config.json" ] && grep -q '"setcap"[[:space:]]*:[[:space:]]*true' "$DATA_DIR/config.json" 2>/dev/null; then
  echo "Giving the new binary permission to use ports 443/80 again (setcap)…"
  if [ "$(id -u)" = 0 ]; then
    setcap cap_net_bind_service=+ep "$BIN" || echo "WARNING: setcap failed — run: sudo setcap cap_net_bind_service=+ep $BIN" >&2
  elif command -v sudo >/dev/null 2>&1; then
    sudo setcap cap_net_bind_service=+ep "$BIN" || echo "WARNING: setcap failed — run: sudo setcap cap_net_bind_service=+ep $BIN" >&2
  else
    echo "WARNING: no sudo — run as root: setcap cap_net_bind_service=+ep $BIN" >&2
  fi
fi

# --- Restart the web UI with the new version (default port 8080) ---
# A port already saved in <data-dir>/config.json wins over the default.
# The UI is ALWAYS restarted after an install/update, so the new
# version actually applies: if it is already running, stop the old
# process first, then start the new binary and verify /health. Never
# skip the restart just because the old version is still running.
#
# saved_port prints the port from config.json, or 8080 when the file
# has no valid port. python3 is tried first, but a plain grep/sed
# fallback MUST work when python3 is missing — v0.4.0 used python3
# only, so on a server without it the parse silently failed and the
# update started the UI on 8080, wiping the user's saved port (5234).
saved_port() {
  local cfg="$1" p=""
  if command -v python3 >/dev/null 2>&1; then
    p="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('port') or '')" "$cfg" 2>/dev/null || true)"
  fi
  if [ -z "$p" ]; then
    p="$(grep -o '"port"[[:space:]]*:[[:space:]]*[0-9][0-9]*' "$cfg" 2>/dev/null | head -1 | grep -o '[0-9][0-9]*' || true)"
  fi
  case "$p" in
    ''|*[!0-9]*) echo 8080 ;;
    *) if [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; then echo "$p"; else echo 8080; fi ;;
  esac
}
PORT=8080
if [ -f "$DATA_DIR/config.json" ]; then
  PORT="$(saved_port "$DATA_DIR/config.json")"
fi
LOG="$DATA_DIR/loadinme.log"
# health answers whether the web UI is up on $PORT — over http, or
# over https when SSL is on (self-check of our own server, so -k).
health() {
  curl -fsS --max-time "${1:-2}" "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 ||
    curl -fsSk --max-time "${1:-2}" "https://127.0.0.1:$PORT/health" >/dev/null 2>&1
}
if [ -z "${LOADINME_NO_WEB:-}" ]; then
  OLD_RUNNING=0
  if health 2; then
    OLD_RUNNING=1
    echo "Web UI is running — restarting it with the new version…"
    "$BIN" stop --data-dir "$DATA_DIR" >/dev/null 2>&1 || true
    # Wait until the old process is really gone (up to ~5s).
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      health 1 || break
      sleep 0.5
    done
  fi
  if [ "$OLD_RUNNING" = 1 ] && health 2; then
    echo "WARNING: the old web UI is still running — the update may not have applied." >&2
    echo "Stop it by hand (loadinme stop) and start it again (loadinme start)." >&2
  elif "$BIN" start --port "$PORT" --data-dir "$DATA_DIR"; then
    if health 2; then
      if [ "$OLD_RUNNING" = 1 ]; then
        echo "Web UI restarted on port $PORT ($("$BIN" version))."
      else
        echo "Web UI started on port $PORT ($("$BIN" version))."
      fi
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
if [ -f "$DATA_DIR/setup-code" ]; then
  # A fresh install: the setup page asks for this one-time code, so a
  # stranger who finds the page first cannot claim the server.
  echo "Open the web UI in your browser and create your login on the setup page."
  echo "If the server is remote, open http://<your-server-IP>:$PORT — the SSH menu below shows the exact link on top."
  echo ""
  echo "  Setup code: $(cat "$DATA_DIR/setup-code" 2>/dev/null)   (the setup page asks for it once)"
  echo ""
  echo "No terminal setup needed — everything after this is in the web UI."
else
  echo "Open the web UI in your browser — the SSH menu below shows the exact link on top."
fi
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
