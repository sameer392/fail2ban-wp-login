#!/bin/bash
# Update fail2ban-whm from GitHub release
# Usage: ./update-from-github.sh <tag>
#   e.g. ./update-from-github.sh v1.0.1
# Uses GitHub's auto-generated source archive (archive/refs/tags/<tag>.zip).
# Run as root.

set -e
TAG="${1:?Usage: $0 <tag>}"
INSTALL_DIR="/usr/share/fail2ban"
REPO_URL="https://github.com/sameer392/fail2ban-whm"
ZIP_URL="$REPO_URL/archive/refs/tags/$TAG.zip"
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

[ "$EUID" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -d "$INSTALL_DIR" ] || { echo "$INSTALL_DIR not found. Run scripts/install.sh first."; exit 1; }

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
# New layout (conf.d)
[ -f "$INSTALL_DIR/conf.d/whitelist-ips.conf" ] && cp -a "$INSTALL_DIR/conf.d/whitelist-ips.conf" "$BACKUP/"
[ -d /etc/fail2ban/conf.d ] && for f in /etc/fail2ban/conf.d/*.conf; do [ -f "$f" ] && cp -a "$f" "$BACKUP/" 2>/dev/null || true; done
# Old layout (scripts/configurations, root whitelist-ips.conf)
[ -f "$INSTALL_DIR/scripts/configurations/whitelist-ips.conf" ] && [ ! -f "$BACKUP/whitelist-ips.conf" ] && cp -a "$INSTALL_DIR/scripts/configurations/whitelist-ips.conf" "$BACKUP/"
[ -f "$INSTALL_DIR/whitelist-ips.conf" ] && [ ! -f "$BACKUP/whitelist-ips.conf" ] && cp -a "$INSTALL_DIR/whitelist-ips.conf" "$BACKUP/"
[ -d /etc/fail2ban/scripts/configurations ] && for f in /etc/fail2ban/scripts/configurations/*.conf; do
   [ -f "$f" ] || continue
   bn=$(basename "$f")
   [ "$bn" = "ignore-countries.conf" ] && bn="whitelist-countries.conf"
   [ "$bn" = "excluded-domains.conf" ] && bn="whitelist-domains.conf"
   [ ! -f "$BACKUP/$bn" ] && cp -a "$f" "$BACKUP/$bn" 2>/dev/null || true
done

echo "Installing files..."
rsync -a --exclude='.git' "$SRC/" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/scripts"/*.sh 2>/dev/null || true
[ -f "$BACKUP/whitelist-ips.conf" ] && mkdir -p "$INSTALL_DIR/conf.d" && cp -a "$BACKUP/whitelist-ips.conf" "$INSTALL_DIR/conf.d/"

echo "Running setup..."
(cd "$INSTALL_DIR" && ./scripts/update.sh)

echo "Restoring user configs..."
mkdir -p /etc/fail2ban/conf.d
for f in "$BACKUP"/*.conf; do [ -f "$f" ] && cp -a "$f" /etc/fail2ban/conf.d/ 2>/dev/null || true; done

echo "Installing WHM plugin..."
[ -x "$INSTALL_DIR/whm-plugin/install-whm-plugin.sh" ] && (cd "$INSTALL_DIR/whm-plugin" && ./install-whm-plugin.sh) || true

echo "Update complete: $TAG"
