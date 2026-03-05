#!/bin/bash
# IP2Location LITE DB1 (Country) setup for fail2ban
# Run as root. Uses token for automated downloads; fallback to direct LITE URL.
# LITE database updates monthly (first day). Add cron for weekly updates.

set -e
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

TOKEN="${IP2LOCATION_TOKEN:-j4lX5sxtvlmBvdki8ITEPt9zmJUraz7xHkFx64piNGMyH6ubyA1EdhAubhBtfrH3}"
GEOIP_DIR="/etc/fail2ban/GeoIP"
DB_DIR="${IP2LOCATION_DB_DIR:-$GEOIP_DIR}"
SCRIPT_DIR="$(dirname "$0")"

echo "=== IP2Location LITE DB1 Setup for fail2ban ==="

# Install libmaxminddb and mmdblookup
if ! command -v mmdblookup &>/dev/null; then
    echo "Installing libmaxminddb..."
    dnf install -y libmaxminddb libmaxminddb-utils 2>/dev/null || yum install -y libmaxminddb libmaxminddb-utils 2>/dev/null || {
        echo "Install manually: dnf install libmaxminddb libmaxminddb-utils"
        exit 1
    }
fi

mkdir -p "$GEOIP_DIR"

# Store token for update cron (avoid hardcoding in cron script)
if [ ! -f "$GEOIP_DIR/ip2location.conf" ]; then
    echo "IP2LOCATION_TOKEN=$TOKEN" > "$GEOIP_DIR/ip2location.conf"
    echo "IP2LOCATION_DB_DIR=$DB_DIR" >> "$GEOIP_DIR/ip2location.conf"
    chmod 600 "$GEOIP_DIR/ip2location.conf"
fi

echo "Downloading IP2Location LITE DB1 (MMDB)..."

# Try token-based download first (DB1 LITE MMDB)
ZIP="/tmp/IP2LOCATION-LITE-DB1.MMDB.ZIP"
DOWNLOADED=0

for FILE_CODE in DB1LITEMMDB DB1LITE.MMDB; do
    if curl -sL -f -o "$ZIP" "https://www.ip2location.com/download?token=${TOKEN}&file=${FILE_CODE}" 2>/dev/null && [ -s "$ZIP" ]; then
        if file "$ZIP" | grep -qi zip; then
            DOWNLOADED=1
            break
        fi
    fi
    rm -f "$ZIP"
done

# Fallback: direct LITE mirror (no token, free)
if [ "$DOWNLOADED" -eq 0 ]; then
    echo "Token download failed, trying direct LITE mirror..."
    if curl -sLf -o "$ZIP" "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.MMDB.ZIP" 2>/dev/null && [ -s "$ZIP" ]; then
        DOWNLOADED=1
    fi
fi

if [ "$DOWNLOADED" -eq 0 ]; then
    echo "Failed to download database. Check token or network."
    exit 1
fi

# Extract and install
TMPDIR=$(mktemp -d)
unzip -q -o "$ZIP" -d "$TMPDIR"
rm -f "$ZIP"

MMDB=$(find "$TMPDIR" -name "*.mmdb" -type f | head -1)
if [ -n "$MMDB" ]; then
    install -m 644 "$MMDB" "$DB_DIR/IP2LOCATION-LITE-DB1.mmdb"
    echo "Installed to $DB_DIR/IP2LOCATION-LITE-DB1.mmdb"
else
    echo "No .mmdb file found in archive"
    rm -rf "$TMPDIR"
    exit 1
fi
rm -rf "$TMPDIR"

echo ""
echo "Setup complete. csf-ban.sh will use IP2Location for country lookup."
echo "Add weekly cron for auto-updates:"
echo "  0 3 * * 3 root [ -f /etc/fail2ban/GeoIP/ip2location.conf ] && . /etc/fail2ban/GeoIP/ip2location.conf && /etc/fail2ban/scripts/update-ip2location.sh"
