#!/usr/bin/with-contenv bash
set -e

echo "[attacker-init] Installing responder package..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y responder
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache responder
else
  echo "[attacker-init] No supported package manager found (apt-get/apk)." >&2
  exit 1
fi

echo "[attacker-init] responder installation completed."
