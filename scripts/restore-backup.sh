#!/bin/bash
#
# Restore fail2ban config from a backup
# Usage: restore-backup.sh [BACKUP_DIR]
#   BACKUP_DIR: e.g. /etc/fail2ban/backups/20260305-123456 (default: latest)
# Must be run as root
#
set -e
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

BACKUP_BASE="/etc/fail2ban/backups"
BKP="${1:-$(ls -dt "$BACKUP_BASE"/[0-9]*-[0-9]* 2>/dev/null | head -1)}"

if [ -z "$BKP" ] || [ ! -d "$BKP" ]; then
   echo "No backup found. Usage: $0 [BACKUP_DIR]" >&2
   echo "  Backups: ls $BACKUP_BASE" >&2
   exit 1
fi

echo "=== Restoring from $BKP ==="
[ -d "$BKP/filter.d" ] && cp -f "$BKP/filter.d/"*.conf /etc/fail2ban/filter.d/ 2>/dev/null || true
[ -d "$BKP/jail.d" ] && cp -f "$BKP/jail.d/"*.conf /etc/fail2ban/jail.d/ 2>/dev/null || true
[ -f "$BKP/action.d/csf-domain.conf" ] && cp -f "$BKP/action.d/csf-domain.conf" /etc/fail2ban/action.d/
[ -f "$BKP/fail2ban.d/loglevel-verbose.conf" ] && cp -f "$BKP/fail2ban.d/loglevel-verbose.conf" /etc/fail2ban/fail2ban.d/
[ -d "$BKP/scripts" ] && for f in "$BKP/scripts/"*; do [ -f "$f" ] && cp -f "$f" /etc/fail2ban/scripts/ && chmod +x "/etc/fail2ban/scripts/$(basename "$f")" 2>/dev/null || true; done
[ -f "$BKP/fail2ban" ] && cp -f "$BKP/fail2ban" /etc/logrotate.d/fail2ban 2>/dev/null || true
echo "Config restored. Restarting fail2ban..."
systemctl restart fail2ban
echo "Done."
