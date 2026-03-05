#!/bin/bash
#
# Fail2Ban WordPress wp-login - Setup script (config deploy only)
# Use when fail2ban is already installed. Copies config and restarts.
# Must be run as root
#

set -e

INSTALL_DIR="/usr/share/fail2ban"
[ -d "$INSTALL_DIR" ] || INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$INSTALL_DIR"

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Check fail2ban is installed
if ! rpm -q fail2ban-server &>/dev/null; then
   echo "fail2ban is not installed. Run $INSTALL_DIR/install.sh for full installation." >&2
   exit 1
fi
[ -d "$CONFIG_DIR" ] || { echo "Source not found. Run install.sh first." >&2; exit 1; }

echo "=== Fail2Ban WordPress wp-login - Setup (config deploy) ==="
echo

echo "[1/2] Deploying config to /etc/fail2ban/..."
cp -f "$CONFIG_DIR/filter.d/"*.conf /etc/fail2ban/filter.d/
cp -f "$CONFIG_DIR/jail.d/"*.conf /etc/fail2ban/jail.d/
[ -f "$CONFIG_DIR/action.d/csf-domain.conf" ] && cp -f "$CONFIG_DIR/action.d/csf-domain.conf" /etc/fail2ban/action.d/
[ -f "$CONFIG_DIR/fail2ban.d/loglevel-verbose.conf" ] && cp -f "$CONFIG_DIR/fail2ban.d/loglevel-verbose.conf" /etc/fail2ban/fail2ban.d/
mkdir -p /etc/fail2ban/scripts
[ -f "$CONFIG_DIR/scripts/csf-ban.sh" ] && cp -f "$CONFIG_DIR/scripts/csf-ban.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/csf-ban.sh
[ -f "$CONFIG_DIR/scripts/ignore-countries.conf" ] && cp -f "$CONFIG_DIR/scripts/ignore-countries.conf" /etc/fail2ban/scripts/
[ -f "$CONFIG_DIR/scripts/setup-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/setup-ip2location.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/setup-ip2location.sh
[ -f "$CONFIG_DIR/scripts/update-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/update-ip2location.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/update-ip2location.sh
echo "      Config deployed."

echo "[2/2] Restarting fail2ban..."
systemctl restart fail2ban
# Wait for fail2ban socket to be ready (avoid "Failed to access socket" on quick re-runs)
for i in {1..10}; do
    fail2ban-client status &>/dev/null && break
    sleep 1
done
echo "      Done."

echo
fail2ban-client status
echo
echo "=== Setup complete ==="
