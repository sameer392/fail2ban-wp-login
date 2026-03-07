#!/bin/bash
#
# Fail2Ban WordPress wp-login - Update script (config deploy only)
# Use when fail2ban is already installed. Copies config and restarts.
# Must be run as root
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/share/fail2ban"
[ -d "$INSTALL_DIR" ] || INSTALL_DIR="$SCRIPT_DIR"
# When running from repo (e.g. /root/fail2ban), deploy from there so local fixes apply
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ] && [ -f "$SCRIPT_DIR/scripts/setup-ip2location-asn.sh" ]; then
   CONFIG_DIR="$SCRIPT_DIR"
else
   CONFIG_DIR="$INSTALL_DIR"
fi

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

echo "=== Fail2Ban WordPress wp-login - Update (config deploy) ==="
echo

BACKUP_DIR="/etc/fail2ban/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "[1/5] Backing up current config..."
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
for f in csf-ban.sh ignore-countries.conf blocklist-organizations.conf excluded-domains.conf setup-ip2location.sh setup-ip2location-asn.sh update-ip2location.sh; do
   [ -f "/etc/fail2ban/scripts/$f" ] && cp -a "/etc/fail2ban/scripts/$f" "$BKP/scripts/"
done
[ -f /etc/fail2ban/jail.d/99-domlog-logpath.conf ] && cp -a /etc/fail2ban/jail.d/99-domlog-logpath.conf "$BKP/jail.d/" 2>/dev/null || true
[ -f /etc/logrotate.d/fail2ban ] && cp -a /etc/logrotate.d/fail2ban "$BKP/" 2>/dev/null || true
echo "      Backup: $BKP"
# Keep last 10 backups
ls -dt "$BACKUP_DIR"/[0-9]*-[0-9]* 2>/dev/null | tail -n +11 | xargs -r rm -rf

# When running from repo, sync source to /usr/share/fail2ban/ so update-from-github.sh is available
if [ "$CONFIG_DIR" != "$INSTALL_DIR" ] && [ -d "$CONFIG_DIR" ]; then
   mkdir -p "$INSTALL_DIR"
   for d in filter.d jail.d action.d fail2ban.d scripts whm-plugin; do
      [ -d "$CONFIG_DIR/$d" ] || continue
      mkdir -p "$INSTALL_DIR/$d"
      for f in "$CONFIG_DIR/$d"/*; do [ -f "$f" ] && cp -f "$f" "$INSTALL_DIR/$d/"; done
      [ "$d" = "whm-plugin" ] && [ -d "$CONFIG_DIR/whm-plugin/plugin" ] && mkdir -p "$INSTALL_DIR/whm-plugin/plugin" && for f in "$CONFIG_DIR/whm-plugin/plugin"/*; do [ -f "$f" ] && cp -f "$f" "$INSTALL_DIR/whm-plugin/plugin/"; done
   done
   for f in install.sh update.sh uninstall.sh restore-backup.sh update-whitelist.sh status.sh whitelist-ips.conf fail2ban-logrotate; do
      [ -f "$CONFIG_DIR/$f" ] && cp -f "$CONFIG_DIR/$f" "$INSTALL_DIR/"
   done
   chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
   chmod +x "$INSTALL_DIR/scripts"/*.sh 2>/dev/null || true
fi

echo "[2/5] Deploying config to /etc/fail2ban/..."
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
[ -f "$CONFIG_DIR/scripts/excluded-domains.conf" ] && cp -f "$CONFIG_DIR/scripts/excluded-domains.conf" /etc/fail2ban/scripts/
[ -f "$CONFIG_DIR/scripts/generate-logpath.sh" ] && cp -f "$CONFIG_DIR/scripts/generate-logpath.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/generate-logpath.sh
[ -f "$CONFIG_DIR/fail2ban-logrotate" ] && cp -f "$CONFIG_DIR/fail2ban-logrotate" /etc/logrotate.d/fail2ban
echo "      Config deployed."

echo "[3/5] Generating logpath (excluded domains)..."
[ -x /etc/fail2ban/scripts/generate-logpath.sh ] && /etc/fail2ban/scripts/generate-logpath.sh || true

echo "[4/5] Updating WHM plugin..."
# Use SCRIPT_DIR so running ./update.sh from source (e.g. /root/fail2ban) deploys latest plugin files
WHM_PLUGIN_DIR="$SCRIPT_DIR/whm-plugin"
if [ -x "$WHM_PLUGIN_DIR/install-whm-plugin.sh" ] && [ -f "$WHM_PLUGIN_DIR/plugin/index.php" ]; then
   (cd "$WHM_PLUGIN_DIR" && ./install-whm-plugin.sh) || echo "      WHM plugin install failed."
else
   # Fallback: copy from CONFIG_DIR if install script not in script dir
   WHM_PLUGIN_SRC="$CONFIG_DIR/whm-plugin/plugin"
   if [ -d "$WHM_PLUGIN_SRC" ] && [ -f "$WHM_PLUGIN_SRC/index.php" ]; then
      mkdir -p /usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager
      cp -f "$WHM_PLUGIN_SRC/index.php" "$WHM_PLUGIN_SRC/fail2ban_manager.png" /usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager/
      chmod 755 /usr/local/cpanel/whostmgr/docroot/cgi/fail2ban_manager/index.php
      [ -d /usr/local/cpanel/whostmgr/docroot/addon_plugins ] && cp -f "$WHM_PLUGIN_SRC/fail2ban_manager.png" /usr/local/cpanel/whostmgr/docroot/addon_plugins/ 2>/dev/null
      [ -x /usr/local/cpanel/bin/register_appconfig ] && [ -f "$WHM_PLUGIN_SRC/fail2ban_manager.conf" ] && /usr/local/cpanel/bin/register_appconfig "$WHM_PLUGIN_SRC/fail2ban_manager.conf"
      echo "      WHM plugin updated (no cPanel restart needed)."
   else
      echo "      WHM plugin source not found, skipped."
   fi
fi

echo "[5/5] Restarting fail2ban..."
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
echo "=== Update complete ==="
