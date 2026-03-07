#!/bin/bash
#
# Fail2Ban WordPress wp-login - Full installation script
# Installs fail2ban (if needed), deploys config, enables and starts the service
# Must be run as root
#

set -e

INSTALL_DIR="/usr/share/fail2ban"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# When run from scripts/, repo root is parent
[[ "$SCRIPT_DIR" == */scripts ]] && SCRIPT_SRC="$(dirname "$SCRIPT_DIR")" || SCRIPT_SRC="$SCRIPT_DIR"

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
   for d in filter.d jail.d action.d fail2ban.d conf.d logrotate.d scripts whm-plugin; do
      if [ -d "$SCRIPT_SRC/$d" ]; then
         for f in "$SCRIPT_SRC/$d"/*; do
            [ -f "$f" ] || continue
            bn=$(basename "$f")
            copy_if_changed "$f" "$INSTALL_DIR/$d/$bn" && updated=1
         done
         # whm-plugin/plugin/ subdirectory (contains index.php, etc.)
         if [ "$d" = "whm-plugin" ] && [ -d "$SCRIPT_SRC/$d/plugin" ]; then
            mkdir -p "$INSTALL_DIR/$d/plugin"
            for f in "$SCRIPT_SRC/$d/plugin"/*; do
               [ -f "$f" ] || continue
               bn=$(basename "$f")
               copy_if_changed "$f" "$INSTALL_DIR/$d/plugin/$bn" && updated=1
            done
         fi
      fi
   done
   for f in install.sh update.sh uninstall.sh restore-backup.sh update-whitelist.sh status.sh; do
      [ -f "$SCRIPT_SRC/scripts/$f" ] && copy_if_changed "$SCRIPT_SRC/scripts/$f" "$INSTALL_DIR/scripts/$f" && updated=1
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
mkdir -p /etc/fail2ban/conf.d
[ -f "$CONFIG_DIR/conf.d/whitelist-countries.conf" ] && cp -f "$CONFIG_DIR/conf.d/whitelist-countries.conf" /etc/fail2ban/conf.d/
[ -f "$CONFIG_DIR/conf.d/blocklist-organizations.conf" ] && cp -f "$CONFIG_DIR/conf.d/blocklist-organizations.conf" /etc/fail2ban/conf.d/
[ -f "$CONFIG_DIR/scripts/setup-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/setup-ip2location.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/setup-ip2location.sh
[ -f "$CONFIG_DIR/scripts/update-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/update-ip2location.sh" /etc/fail2ban/scripts/
[ -f "$CONFIG_DIR/scripts/setup-ip2location-asn.sh" ] && cp -f "$CONFIG_DIR/scripts/setup-ip2location-asn.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/setup-ip2location-asn.sh && chmod +x /etc/fail2ban/scripts/update-ip2location.sh
[ -f "$CONFIG_DIR/scripts/update-useragent-jails.sh" ] && cp -f "$CONFIG_DIR/scripts/update-useragent-jails.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/update-useragent-jails.sh
[ -f "$CONFIG_DIR/scripts/update-from-github.sh" ] && cp -f "$CONFIG_DIR/scripts/update-from-github.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/update-from-github.sh
[ -f "$CONFIG_DIR/conf.d/whitelist-domains.conf" ] && cp -f "$CONFIG_DIR/conf.d/whitelist-domains.conf" /etc/fail2ban/conf.d/
[ -f "$CONFIG_DIR/conf.d/whitelist-ips.conf" ] && cp -f "$CONFIG_DIR/conf.d/whitelist-ips.conf" /etc/fail2ban/conf.d/
[ -f "$CONFIG_DIR/scripts/generate-logpath.sh" ] && cp -f "$CONFIG_DIR/scripts/generate-logpath.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/generate-logpath.sh
[ -f "$CONFIG_DIR/logrotate.d/fail2ban" ] && cp -f "$CONFIG_DIR/logrotate.d/fail2ban" /etc/logrotate.d/fail2ban && echo "      Logrotate config installed."
[ -x /etc/fail2ban/scripts/generate-logpath.sh ] && /etc/fail2ban/scripts/generate-logpath.sh || true
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

# 4. Setup IP2Location (country lookup for whitelist-countries)
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
# Use SCRIPT_SRC so running install.sh from source deploys plugin via install-whm-plugin.sh (same as update.sh)
WHM_PLUGIN_DIR="$SCRIPT_SRC/whm-plugin"
if [ -x "$WHM_PLUGIN_DIR/install-whm-plugin.sh" ] && [ -f "$WHM_PLUGIN_DIR/plugin/index.php" ]; then
   (cd "$WHM_PLUGIN_DIR" && ./install-whm-plugin.sh) && echo "      WHM plugin installed." || echo "      WHM plugin install failed."
elif [ -d "$CONFIG_DIR/whm-plugin/plugin" ] && [ -f "$CONFIG_DIR/whm-plugin/plugin/index.php" ]; then
   # Fallback: copy from CONFIG_DIR when install script not in script dir
   WHM_PLUGIN_SRC="$CONFIG_DIR/whm-plugin/plugin"
   mkdir -p /usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager
   cp -f "$WHM_PLUGIN_SRC/index.php" "$WHM_PLUGIN_SRC/fail2ban_manager.png" /usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager/ 2>/dev/null || true
   chmod 755 /usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager/index.php
   [ -d /usr/local/cpanel/whostmgr/docroot/addon_plugins ] && cp -f "$WHM_PLUGIN_SRC/fail2ban_manager.png" /usr/local/cpanel/whostmgr/docroot/addon_plugins/ 2>/dev/null && chmod 644 /usr/local/cpanel/whostmgr/docroot/addon_plugins/fail2ban_manager.png
   [ -x /usr/local/cpanel/bin/register_appconfig ] && [ -f "$WHM_PLUGIN_SRC/fail2ban_manager.conf" ] && /usr/local/cpanel/bin/register_appconfig "$WHM_PLUGIN_SRC/fail2ban_manager.conf"
   echo "      WHM plugin installed (no cPanel restart needed)."
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
