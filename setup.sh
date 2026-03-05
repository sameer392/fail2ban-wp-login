#!/bin/bash
#
# Fail2Ban WordPress wp-login - Setup script (config deploy only)
# Use when fail2ban is already installed. Copies config and restarts.
# Must be run as root
#

set -e

CONFIG_DIR="/root/fail2ban-config"

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

# Check fail2ban is installed
if ! rpm -q fail2ban-server &>/dev/null; then
   echo "fail2ban is not installed. Run ./install.sh for full installation." >&2
   exit 1
fi

echo "=== Fail2Ban WordPress wp-login - Setup (config deploy) ==="
echo

echo "[1/2] Deploying config to /etc/fail2ban/..."
cp -f "$CONFIG_DIR/filter.d/wordpress-wp-login.conf" /etc/fail2ban/filter.d/
cp -f "$CONFIG_DIR/jail.d/wordpress-wp-login.conf" /etc/fail2ban/jail.d/
echo "      Config deployed."

echo "[2/2] Restarting fail2ban..."
systemctl restart fail2ban
echo "      Done."

echo
fail2ban-client status wordpress-wp-login
echo
echo "=== Setup complete ==="
