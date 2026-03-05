#!/bin/bash
#
# Fail2Ban WordPress wp-login - Status script
# Shows fail2ban service and jail status
# Must be run as root (or user with fail2ban-client access)
#

echo "=== Fail2Ban Status ==="
echo

# Service status
if systemctl is-active fail2ban &>/dev/null; then
   echo "Service: running"
   systemctl status fail2ban --no-pager -l 2>/dev/null | head -15
else
   echo "Service: not running"
   echo "Run: systemctl start fail2ban"
   exit 1
fi

echo
echo "=== Jail: wordpress-wp-login ==="
fail2ban-client status wordpress-wp-login 2>/dev/null || echo "Jail not found or not active."

echo
echo "=== Quick commands ==="
echo "  fail2ban-client get wordpress-wp-login banip   # List banned IPs"
echo "  fail2ban-client set wordpress-wp-login unbanip <IP>  # Unban IP"
echo "  tail -f /var/log/fail2ban.log                 # Monitor log"
