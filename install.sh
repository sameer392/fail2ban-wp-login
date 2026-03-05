#!/bin/bash
#
# Fail2Ban WordPress wp-login - Full installation script
# Installs fail2ban (if needed), deploys config, enables and starts the service
# Must be run as root
#

set -e

INSTALL_DIR="/usr/share/fail2ban"
SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

echo "=== Fail2Ban WordPress wp-login - Full Installation ==="
echo

# 0. Install source to permanent location (so /root/fail2ban can be removed after)
if [ "$SCRIPT_SRC" != "$INSTALL_DIR" ]; then
   echo "[0/7] Installing to $INSTALL_DIR..."
   mkdir -p "$INSTALL_DIR"
   for d in filter.d jail.d action.d fail2ban.d scripts; do
      [ -d "$SCRIPT_SRC/$d" ] && cp -r "$SCRIPT_SRC/$d" "$INSTALL_DIR/"
   done
   for f in install.sh setup.sh uninstall.sh update-whitelist.sh status.sh whitelist-ips.conf; do
      [ -f "$SCRIPT_SRC/$f" ] && cp -f "$SCRIPT_SRC/$f" "$INSTALL_DIR/"
   done
   echo "      Source installed. You may remove $SCRIPT_SRC after this."
fi
CONFIG_DIR="$INSTALL_DIR"

# 1. Install fail2ban if not installed
if ! rpm -q fail2ban-server &>/dev/null; then
   echo "[1/7] Installing fail2ban..."
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
   echo "[1/7] fail2ban already installed."
fi

# 2. Deploy config
echo "[2/7] Deploying config to /etc/fail2ban/..."
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

# 3. Install libmaxminddb (for IP2Location country lookup via mmdblookup)
echo "[3/7] Installing libmaxminddb (if not installed)..."
if ! command -v mmdblookup &>/dev/null; then
   if command -v dnf &>/dev/null; then
      dnf install -y libmaxminddb libmaxminddb-utils 2>/dev/null || { echo "      Warning: dnf install libmaxminddb failed; run manually if needed."; }
   elif command -v yum &>/dev/null; then
      yum install -y libmaxminddb libmaxminddb-utils 2>/dev/null || { echo "      Warning: yum install libmaxminddb failed; run manually if needed."; }
   else
      echo "      Install manually: dnf install libmaxminddb libmaxminddb-utils"
   fi
   command -v mmdblookup &>/dev/null && echo "      libmaxminddb installed."
else
   echo "      libmaxminddb already installed."
fi

# 4. Setup IP2Location (country lookup for ignore-countries)
echo "[4/7] Setting up IP2Location LITE DB1..."
if [ -f "$CONFIG_DIR/scripts/setup-ip2location.sh" ]; then
   "$CONFIG_DIR/scripts/setup-ip2location.sh" || echo "      IP2Location setup skipped or failed; ip-api.com fallback will be used."
else
   echo "      setup-ip2location.sh not found; run manually if needed."
fi

# 5. Verify domlog path (informational)
echo "[5/7] Verifying domlog path..."
if ls /usr/local/apache/domlogs/*/* &>/dev/null 2>&1; then
   echo "      Domlog path OK: /usr/local/apache/domlogs/*/*"
else
   echo "      WARNING: Domlog path may not exist. Check logpath in jail config."
   echo "      Run: ls /usr/local/apache/domlogs/*/*"
fi

# 6. Enable and start
echo "[6/7] Enabling and starting fail2ban..."
systemctl enable fail2ban
systemctl restart fail2ban
# Wait for socket to be ready (avoids "Failed to access socket" race on fresh start)
sleep 3
echo "      fail2ban enabled and restarted."

# 7. Status
echo "[7/7] Status:"
echo
fail2ban-client status
echo
fail2ban-client status wordpress-wp-login
echo
echo "=== Installation complete ==="
