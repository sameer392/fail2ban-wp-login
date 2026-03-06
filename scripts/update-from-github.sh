#!/bin/bash
# Update fail2ban-whm from GitHub release
# Usage: ./update-from-github.sh <tag>
#   e.g. ./update-from-github.sh fail2ban-whm-v1.0.0
# Run as root.

set -e
TAG="${1:?Usage: $0 <tag>}"
INSTALL_DIR="/usr/share/fail2ban"
REPO_URL="https://github.com/sameer392/fail2ban-whm"
ZIP_URL="$REPO_URL/archive/refs/tags/$TAG.zip"
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -d "$INSTALL_DIR" ] || { echo "$INSTALL_DIR not found. Run install.sh first."; exit 1; }

echo "Downloading $TAG from GitHub..."
if command -v curl &>/dev/null; then
    curl -sL -o "$TMP_DIR/release.zip" "$ZIP_URL"
elif command -v wget &>/dev/null; then
    wget -q -O "$TMP_DIR/release.zip" "$ZIP_URL"
else
    echo "curl or wget required"; exit 1
fi

[ -s "$TMP_DIR/release.zip" ] || { echo "Download failed or empty"; exit 1; }

echo "Extracting..."
cd "$TMP_DIR"
unzip -q release.zip
SRC=$(ls -1d */ 2>/dev/null | head -1 | tr -d '/')
[ -d "$SRC" ] || { echo "Unexpected archive structure"; exit 1; }

echo "Backing up user configs..."
BACKUP="$TMP_DIR/backup"
mkdir -p "$BACKUP"
[ -f "$INSTALL_DIR/whitelist-ips.conf" ] && cp -a "$INSTALL_DIR/whitelist-ips.conf" "$BACKUP/"
[ -f /etc/fail2ban/scripts/ignore-countries.conf ] && cp -a /etc/fail2ban/scripts/ignore-countries.conf "$BACKUP/"
[ -f /etc/fail2ban/scripts/blocklist-organizations.conf ] && cp -a /etc/fail2ban/scripts/blocklist-organizations.conf "$BACKUP/" 2>/dev/null || true
[ -f /etc/fail2ban/scripts/email-alerts.conf ] && cp -a /etc/fail2ban/scripts/email-alerts.conf "$BACKUP/" 2>/dev/null || true

echo "Installing files..."
rsync -a --exclude='.git' --exclude='whitelist-ips.conf' "$SRC/" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true
chmod +x "$INSTALL_DIR/scripts"/*.sh 2>/dev/null || true
[ -f "$BACKUP/whitelist-ips.conf" ] && cp -a "$BACKUP/whitelist-ips.conf" "$INSTALL_DIR/"

echo "Running setup..."
(cd "$INSTALL_DIR" && ./setup.sh)

echo "Restoring user configs..."
[ -f "$BACKUP/ignore-countries.conf" ] && cp -a "$BACKUP/ignore-countries.conf" /etc/fail2ban/scripts/
[ -f "$BACKUP/blocklist-organizations.conf" ] && cp -a "$BACKUP/blocklist-organizations.conf" /etc/fail2ban/scripts/ 2>/dev/null || true
[ -f "$BACKUP/email-alerts.conf" ] && cp -a "$BACKUP/email-alerts.conf" /etc/fail2ban/scripts/ 2>/dev/null || true

echo "Installing WHM plugin..."
[ -x "$INSTALL_DIR/whm-plugin/install-whm-plugin.sh" ] && (cd "$INSTALL_DIR/whm-plugin" && ./install-whm-plugin.sh) || true

echo "Update complete: $TAG"
