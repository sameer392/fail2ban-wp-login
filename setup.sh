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

BACKUP_DIR="/etc/fail2ban/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "[1/4] Backing up current config..."
mkdir -p "$BACKUP_DIR"
BKP="$BACKUP_DIR/$TIMESTAMP"
mkdir -p "$BKP/filter.d" "$BKP/jail.d" "$BKP/fail2ban.d" "$BKP/scripts"
for f in /etc/fail2ban/filter.d/wordpress-wp-login.conf /etc/fail2ban/filter.d/apache-high-volume.conf; do
   [ -f "$f" ] && cp -a "$f" "$BKP/filter.d/"
done
for f in /etc/fail2ban/jail.d/wordpress-wp-login.conf /etc/fail2ban/jail.d/apache-high-volume.conf; do
   [ -f "$f" ] && cp -a "$f" "$BKP/jail.d/"
done
mkdir -p "$BKP/action.d"
[ -f /etc/fail2ban/action.d/csf-domain.conf ] && cp -a /etc/fail2ban/action.d/csf-domain.conf "$BKP/action.d/"
[ -f /etc/fail2ban/fail2ban.d/loglevel-verbose.conf ] && cp -a /etc/fail2ban/fail2ban.d/loglevel-verbose.conf "$BKP/fail2ban.d/"
for f in csf-ban.sh ignore-countries.conf blocklist-organizations.conf setup-ip2location.sh setup-ip2location-asn.sh update-ip2location.sh; do
   [ -f "/etc/fail2ban/scripts/$f" ] && cp -a "/etc/fail2ban/scripts/$f" "$BKP/scripts/"
done
[ -f /etc/logrotate.d/fail2ban ] && cp -a /etc/logrotate.d/fail2ban "$BKP/" 2>/dev/null || true
echo "      Backup: $BKP"
# Keep last 10 backups
ls -dt "$BACKUP_DIR"/[0-9]*-[0-9]* 2>/dev/null | tail -n +11 | xargs -r rm -rf

echo "[2/4] Deploying config to /etc/fail2ban/..."
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
[ -f "$CONFIG_DIR/fail2ban-logrotate" ] && cp -f "$CONFIG_DIR/fail2ban-logrotate" /etc/logrotate.d/fail2ban
echo "      Config deployed."

echo "[3/4] Updating WHM plugin..."
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
   echo "      WHM plugin updated."
else
   echo "      WHM plugin source not found, skipped."
fi

echo "[4/4] Restarting fail2ban..."
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
