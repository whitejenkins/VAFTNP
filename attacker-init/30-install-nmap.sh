#!/usr/bin/with-contenv bash
set -euo pipefail

echo "[attacker-init] Installing nmap..."
if command -v nmap >/dev/null 2>&1; then
  echo "[attacker-init] nmap already installed, skipping."
  exit 0
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y nmap
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache nmap
else
  echo "[attacker-init] No supported package manager found (apt-get/apk)." >&2
  exit 1
fi

echo "[attacker-init] nmap installation completed."
