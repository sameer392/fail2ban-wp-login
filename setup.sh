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

echo "[1/3] Backing up current config..."
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
for f in csf-ban.sh ignore-countries.conf setup-ip2location.sh update-ip2location.sh; do
   [ -f "/etc/fail2ban/scripts/$f" ] && cp -a "/etc/fail2ban/scripts/$f" "$BKP/scripts/"
done
[ -f /etc/logrotate.d/fail2ban ] && cp -a /etc/logrotate.d/fail2ban "$BKP/" 2>/dev/null || true
echo "      Backup: $BKP"
# Keep last 10 backups
ls -dt "$BACKUP_DIR"/[0-9]*-[0-9]* 2>/dev/null | tail -n +11 | xargs -r rm -rf

echo "[2/3] Deploying config to /etc/fail2ban/..."
cp -f "$CONFIG_DIR/filter.d/"*.conf /etc/fail2ban/filter.d/
cp -f "$CONFIG_DIR/jail.d/"*.conf /etc/fail2ban/jail.d/
[ -f "$CONFIG_DIR/action.d/csf-domain.conf" ] && cp -f "$CONFIG_DIR/action.d/csf-domain.conf" /etc/fail2ban/action.d/
[ -f "$CONFIG_DIR/fail2ban.d/loglevel-verbose.conf" ] && cp -f "$CONFIG_DIR/fail2ban.d/loglevel-verbose.conf" /etc/fail2ban/fail2ban.d/
mkdir -p /etc/fail2ban/scripts
[ -f "$CONFIG_DIR/scripts/csf-ban.sh" ] && cp -f "$CONFIG_DIR/scripts/csf-ban.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/csf-ban.sh
[ -f "$CONFIG_DIR/scripts/ignore-countries.conf" ] && cp -f "$CONFIG_DIR/scripts/ignore-countries.conf" /etc/fail2ban/scripts/
[ -f "$CONFIG_DIR/scripts/setup-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/setup-ip2location.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/setup-ip2location.sh
[ -f "$CONFIG_DIR/scripts/update-ip2location.sh" ] && cp -f "$CONFIG_DIR/scripts/update-ip2location.sh" /etc/fail2ban/scripts/ && chmod +x /etc/fail2ban/scripts/update-ip2location.sh
[ -f "$CONFIG_DIR/fail2ban-logrotate" ] && cp -f "$CONFIG_DIR/fail2ban-logrotate" /etc/logrotate.d/fail2ban
echo "      Config deployed."

echo "[3/3] Restarting fail2ban..."
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
