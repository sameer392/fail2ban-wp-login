#!/bin/bash
# Apply blacklist countries to CSF CC_DENY
# Blocks all traffic from listed countries at the firewall
# Usage: run as root. Called on save from WHM or by update.sh

CONFIG="/etc/fail2ban/scripts/blacklist-countries.conf"
CSF_CONF="/etc/csf/csf.conf"

[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -f "$CSF_CONF" ] || { echo "CSF not found"; exit 1; }

BLACKLIST_COUNTRIES=""
if [ -f "$CONFIG" ] && [ -r "$CONFIG" ]; then
    BLACKLIST_COUNTRIES=$(grep -E '^BLACKLIST_COUNTRIES=' "$CONFIG" | cut -d= -f2- | tr -d '"' | tr -d "'" | xargs)
fi

# Format for csf.conf: CC_DENY = "XX,YY,ZZ" or empty ""
VALUE=""
if [ -n "$BLACKLIST_COUNTRIES" ]; then
    # Sanitize: only allow A-Za-z commas
    VALUE=$(echo "$BLACKLIST_COUNTRIES" | tr ',' '\n' | sed 's/[^A-Za-z]//g' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')
fi

# Update csf.conf - match CC_DENY line (with or without quotes)
if grep -q '^CC_DENY' "$CSF_CONF" 2>/dev/null; then
    if [ -n "$VALUE" ]; then
        sed -i "s|^CC_DENY.*|CC_DENY = \"$VALUE\"|" "$CSF_CONF"
    else
        sed -i "s|^CC_DENY.*|CC_DENY = \"\"|" "$CSF_CONF"
    fi
    csf -r &>/dev/null || true
    echo "CSF CC_DENY updated. Countries blocked: ${VALUE:-none}"
else
    echo "CC_DENY not found in $CSF_CONF"
fi
