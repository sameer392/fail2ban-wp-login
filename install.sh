#!/bin/bash
#
# Fail2Ban WordPress wp-login - Full installation script
# Installs fail2ban (if needed), deploys config, enables and starts the service
# Must be run as root
#

set -e

CONFIG_DIR="/root/fail2ban-config"
F2B_FILTER="/etc/fail2ban/filter.d/wordpress-wp-login.conf"
F2B_JAIL="/etc/fail2ban/jail.d/wordpress-wp-login.conf"

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

echo "=== Fail2Ban WordPress wp-login - Full Installation ==="
echo

# 1. Install fail2ban if not installed
if ! rpm -q fail2ban-server &>/dev/null; then
   echo "[1/5] Installing fail2ban..."
   if command -v dnf &>/dev/null; then
      dnf install -y fail2ban fail2ban-systemd
   elif command -v yum &>/dev/null; then
      yum install -y fail2ban fail2ban-systemd
   else
      echo "Error: dnf or yum not found. Please install fail2ban manually." >&2
      exit 1
   fi
   echo "      fail2ban installed."
else
   echo "[1/5] fail2ban already installed."
fi

# 2. Deploy config
echo "[2/5] Deploying config to /etc/fail2ban/..."
cp -f "$CONFIG_DIR/filter.d/wordpress-wp-login.conf" /etc/fail2ban/filter.d/
cp -f "$CONFIG_DIR/jail.d/wordpress-wp-login.conf" /etc/fail2ban/jail.d/
echo "      Config deployed."

# 3. Verify domlog path (informational)
echo "[3/5] Verifying domlog path..."
if ls /usr/local/apache/domlogs/*/* &>/dev/null 2>&1; then
   echo "      Domlog path OK: /usr/local/apache/domlogs/*/*"
else
   echo "      WARNING: Domlog path may not exist. Check logpath in jail config."
   echo "      Run: ls /usr/local/apache/domlogs/*/*"
fi

# 4. Enable and start
echo "[4/5] Enabling and starting fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban
systemctl restart fail2ban
echo "      fail2ban enabled and restarted."

# 5. Status
echo "[5/5] Status:"
echo
fail2ban-client status
echo
fail2ban-client status wordpress-wp-login
echo
echo "=== Installation complete ==="
