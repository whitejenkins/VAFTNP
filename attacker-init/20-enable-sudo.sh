#!/usr/bin/with-contenv bash
set -euo pipefail

echo "[attacker-init] Enabling passwordless sudo for attacker user..."
echo "attacker ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99-attacker
chmod 0440 /etc/sudoers.d/99-attacker
