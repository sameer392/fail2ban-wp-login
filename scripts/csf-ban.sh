#!/bin/bash
# Fail2Ban CSF ban helper - adds IP to csf.deny with jail name and affected domain(s)
# Country whitelist (whitelist-countries.conf) applies ONLY to apache-high-volume.
# All other jails (wordpress-wp-login, apache-ua-*, etc.) always ban regardless of country.
# Exceptions for apache-high-volume: blocked orgs, multi-domain abuse override whitelist.
# Usage: csf-ban.sh <ip> <jail_name>
# Comment format: Fail2Ban <jail> - <domain1, domain2, ...>

IP="$1"
JAIL="$2"
SCRIPT_DIR="$(dirname "$0")"
CONFIG="/etc/fail2ban/conf.d/whitelist-countries.conf"
BLOCKLIST_CONFIG="/etc/fail2ban/conf.d/blocklist-organizations.conf"
DOMLOGS="${DOMLOGS:-/usr/local/apache/domlogs}"

[ -z "$IP" ] || [ -z "$JAIL" ] && exit 1

# Skip private/local IPs
[[ "$IP" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]] && exit 0
[[ "$IP" =~ ^(::1|fc00:|fe80:) ]] && exit 0

# Country whitelist applies ONLY to apache-high-volume; all other jails always ban
[[ "$JAIL" == apache-high-volume ]] && SKIP_WHITELIST=0 || SKIP_WHITELIST=1

# Find domains that had traffic from this IP (needed for comment and multi-domain check)
DOMAINS=""
DOMAIN_COUNT=0
if [ -d "$DOMLOGS" ]; then
    DOMAINS=$(grep -lE "^${IP} " "$DOMLOGS"/*/* 2>/dev/null | while read -r f; do
        basename "$f" | sed 's/-ssl_log$//'
    done | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')
    [ -n "$DOMAINS" ] && DOMAIN_COUNT=$(echo "$DOMAINS" | tr ',' '\n' | wc -l)
fi

# Load ignored countries
WHITELIST_COUNTRIES=""
[ -f "$CONFIG" ] && . "$CONFIG"

# Load blocklist and multi-domain threshold
BLOCKED_ORGANIZATIONS=""
MULTI_DOMAIN_ABUSE_THRESHOLD=0
[ -f "$BLOCKLIST_CONFIG" ] && . "$BLOCKLIST_CONFIG"

# Check country and skip if whitelisted (with exceptions) - skip for apache-ua-* jails
SKIP_BAN=0
if [ "$SKIP_WHITELIST" != "1" ] && [ -n "$WHITELIST_COUNTRIES" ]; then
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
        IS_WHITELISTED=0
        for c in $(echo "$WHITELIST_COUNTRIES" | tr ',' ' '); do
            c=$(echo "$c" | tr -d ' ')
            [ "$COUNTRY" = "$c" ] && { IS_WHITELISTED=1; break; }
        done
        if [ "$IS_WHITELISTED" = "1" ]; then
            SKIP_BAN=1
            # Exception 1: Multi-domain abuse - whitelisted country but hitting many domains
            if [ -n "$MULTI_DOMAIN_ABUSE_THRESHOLD" ] && [ "$MULTI_DOMAIN_ABUSE_THRESHOLD" -gt 0 ] 2>/dev/null; then
                if [ "$DOMAIN_COUNT" -ge "$MULTI_DOMAIN_ABUSE_THRESHOLD" ] 2>/dev/null; then
                    SKIP_BAN=0
                fi
            fi
            # Exception 2: Blocked organization - ban Microsoft, DigitalOcean, etc.
            if [ "$SKIP_BAN" = "1" ] && [ -n "$BLOCKED_ORGANIZATIONS" ]; then
                ORG=""
                # Prefer local mmdb (IP2Location LITE ASN)
                ASN_MMDB="/etc/fail2ban/GeoIP/IP2LOCATION-LITE-ASN.mmdb"
                if [ -f "$ASN_MMDB" ] && command -v mmdblookup &>/dev/null; then
                    for path in "as" "autonomous_system_organization" "organization"; do
                        ORG=$(mmdblookup -f "$ASN_MMDB" -i "$IP" "$path" 2>/dev/null | grep -m1 'utf8_string' | sed 's/.*"\([^"]*\)".*/\1/')
                        [ -n "$ORG" ] && [ "$ORG" != "-" ] && break
                    done
                fi
                # Fallback: local whois
                if [ -z "$ORG" ] && command -v whois &>/dev/null; then
                    ORG_RAW=$(whois "$IP" 2>/dev/null)
                    ORG=$(echo "$ORG_RAW" | grep -m1 -E '^OrgName:|^Organization:' | sed 's/^[^:]*:[ \t]*//' | sed 's/ ([A-Z0-9]*)$//' | tr -d '\n')
                fi
                # Fallback: ip-api.com
                if [ -z "$ORG" ] && command -v curl &>/dev/null; then
                    ORG_RAW=$(curl -s --connect-timeout 2 --max-time 4 "http://ip-api.com/json/${IP}?fields=org,isp" 2>/dev/null)
                    ORG=$(echo "$ORG_RAW" | grep -oE '"(org|isp)":"[^"]*"' | cut -d'"' -f4 | tr '\n' ' ')
                fi
                for bl in $(echo "$BLOCKED_ORGANIZATIONS" | tr ',' ' '); do
                    bl=$(echo "$bl" | tr -d ' ')
                    [ -z "$bl" ] && continue
                    if echo "$ORG" | grep -qiF "$bl"; then
                        SKIP_BAN=0
                        break
                    fi
                done
            fi
            [ "$SKIP_BAN" = "1" ] && exit 0
        fi
    else
        # Country lookup failed - skip ban to avoid blocking whitelisted countries
        exit 0
    fi
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
