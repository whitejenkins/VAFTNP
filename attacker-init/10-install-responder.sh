#!/usr/bin/with-contenv bash
set -euo pipefail

RESPONDER_DIR="/opt/Responder"

log() {
  echo "[attacker-init] $*"
}

install_from_apt() {
  log "Trying apt package installation..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y responder python3-pip
}

install_from_apk_or_source() {
  log "Trying apk package installation..."
  if apk add --no-cache responder; then
    return 0
  fi

  log "'responder' package is unavailable in apk repositories, falling back to source install..."
  apk add --no-cache git python3 py3-pip py3-netifaces py3-requests py3-six py3-future

  if [ ! -d "$RESPONDER_DIR/.git" ]; then
    git clone https://github.com/lgandx/Responder.git "$RESPONDER_DIR"
  else
    git -C "$RESPONDER_DIR" pull --ff-only
  fi

  ln -sf "$RESPONDER_DIR/Responder.py" /usr/local/bin/responder
  chmod +x "$RESPONDER_DIR/Responder.py"
}
ensure_aioquic() {
  if python3 -c "import aioquic" >/dev/null 2>&1; then
    log "aioquic dependency already present."
    return 0
  fi

  log "Installing missing dependency: aioquic"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3-aioquic || true
  fi

  if ! python3 -c "import aioquic" >/dev/null 2>&1; then
    if ! python3 -m pip --version >/dev/null 2>&1 && command -v apk >/dev/null 2>&1; then
      apk add --no-cache py3-pip
    fi
    python3 -m pip install --no-cache-dir aioquic --break-system-packages
  fi
}


log "Installing responder package..."
if command -v responder >/dev/null 2>&1; then
  log "Responder is already installed, skipping."
elif command -v apt-get >/dev/null 2>&1; then
  install_from_apt
elif command -v apk >/dev/null 2>&1; then
  install_from_apk_or_source
else
  log "No supported package manager found (apt-get/apk)."
  exit 1
fi

ensure_aioquic

if command -v responder >/dev/null 2>&1; then
  log "Responder installation completed successfully."
else
  log "Responder installation failed: binary not found in PATH."
  exit 1
fi
