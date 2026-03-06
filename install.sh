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
copy_if_changed() {
   local src="$1" dst="$2"
   mkdir -p "$(dirname "$dst")"
   if [ ! -f "$dst" ] || ! cmp -s "$src" "$dst" 2>/dev/null; then
      cp -f "$src" "$dst"
      return 0
   fi
   return 1
}
if [ "$SCRIPT_SRC" != "$INSTALL_DIR" ]; then
   echo "[0/7] Installing to $INSTALL_DIR..."
   mkdir -p "$INSTALL_DIR"
   updated=0
   for d in filter.d jail.d action.d fail2ban.d scripts whm-plugin; do
      if [ -d "$SCRIPT_SRC/$d" ]; then
         for f in "$SCRIPT_SRC/$d"/*; do
            [ -f "$f" ] || continue
            bn=$(basename "$f")
            copy_if_changed "$f" "$INSTALL_DIR/$d/$bn" && updated=1
         done
      fi
   done
   for f in install.sh setup.sh uninstall.sh restore-backup.sh update-whitelist.sh status.sh whitelist-ips.conf fail2ban-logrotate; do
      [ -f "$SCRIPT_SRC/$f" ] && copy_if_changed "$SCRIPT_SRC/$f" "$INSTALL_DIR/$f" && updated=1
   done
   [ "$updated" -eq 1 ] && echo "      Source installed/updated." || echo "      Source unchanged (already up to date)."
   echo "      You may remove $SCRIPT_SRC after this."
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
[ -f "$CONFIG_DIR/scripts/blocklist-organizations.conf" ] && cp -f "$CONFIG_DIR/scripts/blocklist-organizations.conf" /etc/fail2ban/scripts/
[ -f "$CONFIG_DIR/scripts/setup-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/setup-ip2location.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/setup-ip2location.sh
[ -f "$CONFIG_DIR/scripts/update-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/update-ip2location.sh" /etc/fail2ban/scripts/
[ -f "$CONFIG_DIR/scripts/setup-ip2location-asn.sh" ] && cp -f "$CONFIG_DIR/scripts/setup-ip2location-asn.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/setup-ip2location-asn.sh && chmod +x /etc/fail2ban/scripts/update-ip2location.sh
[ -f "$CONFIG_DIR/scripts/update-useragent-jails.sh" ] && cp -f "$CONFIG_DIR/scripts/update-useragent-jails.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/update-useragent-jails.sh
[ -f "$CONFIG_DIR/scripts/update-from-github.sh" ] && cp -f "$CONFIG_DIR/scripts/update-from-github.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/update-from-github.sh
[ -f "$CONFIG_DIR/fail2ban-logrotate" ] && cp -f "$CONFIG_DIR/fail2ban-logrotate" /etc/logrotate.d/fail2ban && echo "      Logrotate config installed."
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
echo "[6/8] Enabling and starting fail2ban..."
systemctl enable fail2ban
systemctl restart fail2ban
# Wait for socket to be ready (avoids "Failed to access socket" race on fresh start)
sleep 3
echo "      fail2ban enabled and restarted."

# 7. Install/update WHM plugin (if cPanel present)
echo "[7/8] Installing WHM plugin..."
WHM_PLUGIN_SRC="$CONFIG_DIR/whm-plugin/plugin"
WHM_PLUGIN_DST="/usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager"
if [ -d "$WHM_PLUGIN_SRC" ] && [ -f "$WHM_PLUGIN_SRC/index.php" ]; then
   mkdir -p "$WHM_PLUGIN_DST"
   cp -f "$WHM_PLUGIN_SRC/index.php" "$WHM_PLUGIN_SRC/fail2ban_manager.png" "$WHM_PLUGIN_DST/"
   chmod 755 "$WHM_PLUGIN_DST/index.php"
   [ -f "$WHM_PLUGIN_DST/fail2ban_manager.png" ] && chmod 644 "$WHM_PLUGIN_DST/fail2ban_manager.png"
   [ -d /usr/local/cpanel/whostmgr/docroot/addon_plugins ] && cp -f "$WHM_PLUGIN_SRC/fail2ban_manager.png" /usr/local/cpanel/whostmgr/docroot/addon_plugins/ 2>/dev/null && chmod 644 /usr/local/cpanel/whostmgr/docroot/addon_plugins/fail2ban_manager.png
   if [ -x /usr/local/cpanel/bin/register_appconfig ] && [ -f "$WHM_PLUGIN_SRC/fail2ban_manager.conf" ]; then
      /usr/local/cpanel/bin/register_appconfig "$WHM_PLUGIN_SRC/fail2ban_manager.conf"
   fi
   systemctl restart cpanel 2>/dev/null || [ -x /usr/local/cpanel/scripts/restartsrv_cpsrvd ] && /usr/local/cpanel/scripts/restartsrv_cpsrvd 2>/dev/null || true
   echo "      WHM plugin installed."
else
   echo "      Skipped (WHM plugin source not found)."
fi

# 8. Status
echo "[8/8] Status:"
echo
fail2ban-client status
echo
fail2ban-client status wordpress-wp-login
echo
echo "=== Installation complete ==="
