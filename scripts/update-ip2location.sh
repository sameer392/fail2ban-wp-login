#!/bin/bash
# IP2Location LITE DB1 auto-updater (for cron)
# Loads token from /etc/fail2ban/GeoIP/ip2location.conf

CONFIG="/etc/fail2ban/GeoIP/ip2location.conf"
[ -f "$CONFIG" ] && . "$CONFIG"

TOKEN="${IP2LOCATION_TOKEN:-}"
DB_DIR="${IP2LOCATION_DB_DIR:-/etc/fail2ban/GeoIP}"
ZIP="/tmp/IP2LOCATION-LITE-DB1.MMDB.ZIP"
MMDB_DEST="$DB_DIR/IP2LOCATION-LITE-DB1.mmdb"

# Try token-based download (if token set)
DOWNLOADED=0
if [ -n "$TOKEN" ]; then
for FILE_CODE in DB1LITEMMDB DB1LITE.MMDB; do
    if curl -sLf -o "$ZIP" "https://www.ip2location.com/download?token=${TOKEN}&file=${FILE_CODE}" 2>/dev/null && [ -s "$ZIP" ]; then
        if file "$ZIP" | grep -qi zip; then
            DOWNLOADED=1
            break
        fi
    fi
    rm -f "$ZIP"
done
fi

# Fallback: direct LITE mirror (no token required)
if [ "$DOWNLOADED" -eq 0 ]; then
    curl -sLf -o "$ZIP" "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.MMDB.ZIP" 2>/dev/null && [ -s "$ZIP" ] && DOWNLOADED=1
fi

[ "$DOWNLOADED" -eq 0 ] && { rm -f "$ZIP"; exit 1; }

TMPDIR=$(mktemp -d)
unzip -q -o "$ZIP" -d "$TMPDIR"
rm -f "$ZIP"

MMDB=$(find "$TMPDIR" -name "*.mmdb" -type f | head -1)
if [ -n "$MMDB" ]; then
    mkdir -p "$DB_DIR"
    install -m 644 "$MMDB" "$MMDB_DEST"
fi
rm -rf "$TMPDIR"
