#!/bin/bash
#
# Fail2Ban WordPress wp-login - Uninstall script
# Removes deployed config and optionally uninstalls fail2ban
# Must be run as root
#

set -e

# Configs we deploy (must match update.sh)
F2B_FILTERS=(
   /etc/fail2ban/filter.d/wordpress-wp-login.conf
   /etc/fail2ban/filter.d/apache-high-volume.conf
)
F2B_JAILS=(
   /etc/fail2ban/jail.d/wordpress-wp-login.conf
   /etc/fail2ban/jail.d/apache-high-volume.conf
)
F2B_ACTIONS=(
   /etc/fail2ban/action.d/csf-domain.conf
   /etc/fail2ban/scripts/csf-ban.sh
   /etc/fail2ban/conf.d/whitelist-countries.conf
   /etc/fail2ban/conf.d/blocklist-organizations.conf
   /etc/fail2ban/conf.d/whitelist-domains.conf
   /etc/fail2ban/scripts/setup-ip2location.sh
   /etc/fail2ban/scripts/update-ip2location.sh
)
F2B_FAIL2BAN_D=(
   /etc/fail2ban/fail2ban.d/loglevel-verbose.conf
)
PURGE=false

# Parse args
for arg in "$@"; do
   case $arg in
      --purge)
         PURGE=true
         shift
         ;;
   esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" >&2
   exit 1
fi

echo "=== Fail2Ban WordPress wp-login - Uninstall ==="
echo

# 1. Stop fail2ban (needed to remove config cleanly)
echo "[1/4] Stopping fail2ban..."
if systemctl is-active --quiet fail2ban 2>/dev/null; then
   systemctl stop fail2ban
   echo "      fail2ban stopped."
else
   echo "      fail2ban was not running."
fi

# 2. Remove deployed config
echo "[2/4] Removing config..."
removed=0
for f in "${F2B_FILTERS[@]}" "${F2B_JAILS[@]}" "${F2B_ACTIONS[@]}" "${F2B_FAIL2BAN_D[@]}"; do
   if [[ -f "$f" ]]; then
      rm -f "$f"
      echo "      Removed: $f"
      removed=1
   fi
done
if [[ $removed -eq 0 ]]; then
   echo "      No deployed config found."
fi

# 3. Restart or disable fail2ban
if [[ "$PURGE" == true ]]; then
   echo "[3/6] Disabling fail2ban service..."
   systemctl disable fail2ban 2>/dev/null || true
   echo "      fail2ban disabled."
   echo
   echo "[4/6] Uninstalling fail2ban packages..."
   if rpm -q fail2ban-server &>/dev/null; then
      if command -v dnf &>/dev/null; then
         dnf remove -y fail2ban fail2ban-systemd fail2ban-firewalld fail2ban-sendmail 2>/dev/null || true
      elif command -v yum &>/dev/null; then
         yum remove -y fail2ban fail2ban-systemd fail2ban-firewalld fail2ban-sendmail 2>/dev/null || true
      fi
      echo "      fail2ban packages removed."
   else
      echo "      fail2ban was not installed."
   fi
   echo
   echo "[5/6] Uninstalling WHM plugin..."
   UNINSTALL_WHM=""
   [[ -f /usr/share/fail2ban/whm-plugin/uninstall-whm-plugin.sh ]] && UNINSTALL_WHM="/usr/share/fail2ban/whm-plugin/uninstall-whm-plugin.sh"
   [[ -z "$UNINSTALL_WHM" ]] && SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" && CONFIG_DIR="$(dirname "$SCRIPT_DIR")" && [[ -f "$CONFIG_DIR/whm-plugin/uninstall-whm-plugin.sh" ]] && UNINSTALL_WHM="$CONFIG_DIR/whm-plugin/uninstall-whm-plugin.sh"
   if [[ -n "$UNINSTALL_WHM" ]]; then
      (cd "$(dirname "$UNINSTALL_WHM")" && ./uninstall-whm-plugin.sh) || echo "      WHM plugin uninstall skipped or failed."
   else
      echo "      WHM plugin uninstall script not found."
   fi
   echo
   echo "[6/6] Removing /etc/fail2ban/, logrotate config, and /usr/share/fail2ban/ (custom config)..."
   rm -f /etc/logrotate.d/fail2ban 2>/dev/null && echo "      /etc/logrotate.d/fail2ban removed." || true
   if [[ -d /etc/fail2ban ]]; then
      rm -rf /etc/fail2ban
      echo "      /etc/fail2ban/ removed."
   fi
   if [[ -d /usr/share/fail2ban ]]; then
      rm -rf /usr/share/fail2ban
      echo "      /usr/share/fail2ban/ removed."
   fi
else
   echo "[3/4] Restarting fail2ban..."
   if rpm -q fail2ban-server &>/dev/null; then
      systemctl start fail2ban
      sleep 2
      echo "      fail2ban restarted (WordPress jail removed)."
   fi
   echo "[4/4] (Skipped - use --purge to also uninstall fail2ban, WHM plugin, and remove config)"
fi

echo
echo "=== Uninstall complete ==="
