#!/bin/bash
# Fail2Ban CSF ban helper - adds IP to csf.deny with jail name and affected domain(s)
# Skips banning IPs from whitelisted countries (see ignore-countries.conf)
# Usage: csf-ban.sh <ip> <jail_name>
# Comment format: Fail2Ban <jail> - <domain1, domain2, ...>

IP="$1"
JAIL="$2"
SCRIPT_DIR="$(dirname "$0")"
CONFIG="${SCRIPT_DIR}/ignore-countries.conf"
DOMLOGS="${DOMLOGS:-/usr/local/apache/domlogs}"

[ -z "$IP" ] || [ -z "$JAIL" ] && exit 1

# Skip private/local IPs
[[ "$IP" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]] && exit 0
[[ "$IP" =~ ^(::1|fc00:|fe80:) ]] && exit 0

# Load ignored countries
WHITELIST_COUNTRIES=""
[ -f "$CONFIG" ] && . "$CONFIG"

# Check country and skip if whitelisted
if [ -n "$WHITELIST_COUNTRIES" ]; then
    COUNTRY=""
    # IP2Location LITE DB1 (country lookup via mmdblookup)
    for db in /etc/fail2ban/GeoIP/IP2LOCATION-LITE-DB1.mmdb; do
        if [ -f "$db" ] && command -v mmdblookup &>/dev/null; then
            COUNTRY=$(mmdblookup -f "$db" -i "$IP" country iso_code 2>/dev/null | awk -F'"' '/iso_code/ {print $2}')
            [ -n "$COUNTRY" ] && break
        fi
    done
    # Fallback: ip-api.com (free, no key, ~45 req/min limit)
    if [ -z "$COUNTRY" ] && command -v curl &>/dev/null; then
        COUNTRY=$(curl -s --connect-timeout 2 --max-time 4 "http://ip-api.com/json/${IP}?fields=countryCode" 2>/dev/null | grep -o '"countryCode":"[A-Z]*"' | cut -d'"' -f4)
    fi
    if [ -n "$COUNTRY" ]; then
        for c in $(echo "$WHITELIST_COUNTRIES" | tr ',' ' '); do
            c=$(echo "$c" | tr -d ' ')
            [ "$COUNTRY" = "$c" ] && exit 0
        done
    else
        # Country lookup failed - skip ban to avoid blocking whitelisted countries
        exit 0
    fi
fi

# Find domains that had traffic from this IP
DOMAINS=""
if [ -d "$DOMLOGS" ]; then
    DOMAINS=$(grep -lE "^${IP} " "$DOMLOGS"/*/* 2>/dev/null | while read -r f; do
        basename "$f" | sed 's/-ssl_log$//'
    done | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')
fi

# Build comment
if [ -n "$DOMAINS" ]; then
    COMMENT="Fail2Ban ${JAIL} - ${DOMAINS}"
else
    COMMENT="Fail2Ban ${JAIL}"
fi

COMMENT=$(echo "$COMMENT" | head -c 200)
/usr/sbin/csf -d "$IP" "$COMMENT"

# Optional: send email alert on ban (SMTP)
EMAIL_CONF="${SCRIPT_DIR}/email-alerts.conf"
if [ -f "$EMAIL_CONF" ] && [ -r "$EMAIL_CONF" ]; then
    . "$EMAIL_CONF"
    if [ "${ENABLED:-0}" = "1" ] && [ -n "$EMAIL_TO" ] && [ -n "$SMTP_HOST" ] && command -v curl &>/dev/null; then
        SUBJ="[Fail2Ban] $IP banned ($JAIL)"
        BODY="IP $IP was banned by Fail2Ban (jail: $JAIL). Domains: ${DOMAINS:--}. $(date)"
        FROM="${EMAIL_FROM:-fail2ban@localhost}"
        MSG="From: $FROM
To: $EMAIL_TO
Subject: $SUBJ

$BODY"
        case "${SMTP_SECURE:-tls}" in
            ssl) PORT="${SMTP_PORT:-465}" ; URL="smtps://${SMTP_HOST}:${PORT}" ; EXTRA="" ;;
            tls) PORT="${SMTP_PORT:-587}" ; URL="smtp://${SMTP_HOST}:${PORT}" ; EXTRA="--ssl-reqd" ;;
            *)   PORT="${SMTP_PORT:-25}"  ; URL="smtp://${SMTP_HOST}:${PORT}" ; EXTRA="" ;;
        esac
        if [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASS" ]; then
            echo "$MSG" | curl -s --connect-timeout 10 --max-time 30 --url "$URL" --mail-from "$FROM" --mail-rcpt "$EMAIL_TO" --user "$SMTP_USER:$SMTP_PASS" $EXTRA -T - 2>/dev/null
        else
            echo "$MSG" | curl -s --connect-timeout 10 --max-time 30 --url "$URL" --mail-from "$FROM" --mail-rcpt "$EMAIL_TO" $EXTRA -T - 2>/dev/null
        fi
    fi
fi
