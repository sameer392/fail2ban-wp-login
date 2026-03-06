#!/bin/bash
# IP2Location LITE ASN (Organization) setup for fail2ban
# Provides local org/AS lookup via mmdb. Requires IP2Location LITE account token.
# Run as root. Optional - org display works without it (whois/ip-api.com fallback).

set -e
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

GEOIP_DIR="/etc/fail2ban/GeoIP"
DB_DIR="${IP2LOCATION_DB_DIR:-$GEOIP_DIR}"
[ -f "$GEOIP_DIR/ip2location.conf" ] && . "$GEOIP_DIR/ip2location.conf" 2>/dev/null
TOKEN="${IP2LOCATION_TOKEN:-}"
[ -z "$TOKEN" ] && { echo "Set IP2LOCATION_TOKEN in $GEOIP_DIR/ip2location.conf (from lite.ip2location.com)"; exit 1; }

echo "=== IP2Location LITE ASN Setup for fail2ban ==="
mkdir -p "$GEOIP_DIR"

ZIP="/tmp/IP2LOCATION-LITE-ASN.MMDB.ZIP"
is_valid_zip() {
    [ -s "$1" ] && [ "$(head -c 2 "$1" | od -An -tx1 | tr -d ' \n')" = "504b" ]
}

DOWNLOADED=0
for FILE_CODE in ASNLITEMMDB ASNLITE.MMDB ASNLITE ASNMMDB DBASNLITE; do
    rm -f "$ZIP"
    if curl -sLf -o "$ZIP" "https://www.ip2location.com/download?token=${TOKEN}&file=${FILE_CODE}" 2>/dev/null && is_valid_zip "$ZIP"; then
        DOWNLOADED=1
        break
    fi
done

if [ "$DOWNLOADED" -eq 0 ]; then
    if [ -s "$ZIP" ]; then
        RESP=$(head -c 500 "$ZIP" 2>/dev/null)
        if echo "$RESP" | grep -qi "ONLY BE DOWNLOADED"; then
            echo "Rate limit: 5 downloads per 24h per IP. Wait and try again."
        elif echo "$RESP" | grep -qi "invalid\|unauthorized\|token"; then
            echo "Invalid token. Get a free token from lite.ip2location.com and save it in Settings."
        elif echo "$RESP" | grep -qi "not found\|404"; then
            echo "ASN database not available with this token. LITE ASN may require manual download from lite.ip2location.com."
        else
            echo "Download failed. Response: $(echo "$RESP" | head -c 120)..."
        fi
    else
        echo "Download failed. Check network and token (lite.ip2location.com)."
    fi
    rm -f "$ZIP"
    exit 1
fi

TMPDIR=$(mktemp -d)
unzip -q -o "$ZIP" -d "$TMPDIR"
rm -f "$ZIP"

MMDB=$(find "$TMPDIR" -iname "*.mmdb" -type f | head -1)
if [ -n "$MMDB" ]; then
    install -m 644 "$MMDB" "$DB_DIR/IP2LOCATION-LITE-ASN.mmdb"
    echo "Installed to $DB_DIR/IP2LOCATION-LITE-ASN.mmdb"
else
    echo "No .mmdb file in archive"
    rm -rf "$TMPDIR"
    exit 1
fi
rm -rf "$TMPDIR"

echo "Setup complete. Organization lookup will use local mmdb."
