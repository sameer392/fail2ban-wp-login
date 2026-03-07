#!/bin/bash
#
# Fail2Ban Manager for cPanel/WHM - Bootstrap installer
# Usage:
#   # From latest release (attach this file as release asset):
#   curl -sSL https://github.com/sameer392/fail2ban-whm/releases/latest/download/install.sh | bash
#
#   # From main branch (no release needed):
#   curl -sSL https://raw.githubusercontent.com/sameer392/fail2ban-whm/main/install.sh | bash
#
#   # With wget:
#   wget -qO- https://raw.githubusercontent.com/sameer392/fail2ban-whm/main/install.sh | bash
#
# Optional: specify a tag for a specific version
#   curl -sSL .../install.sh | bash -s v1.0.0
#

set -e

REPO="https://github.com/sameer392/fail2ban-whm"
TAG="${1:-}"

echo "=== Fail2Ban Manager for cPanel/WHM - Installer ==="
echo

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Use: sudo bash -c \"\$(curl -sSL $REPO/releases/latest/download/install.sh)\"" >&2
   exit 1
fi

# Check cPanel/WHM
if [[ ! -d /usr/local/cpanel ]] || { [[ ! -x /usr/local/cpanel/cpanel ]] && [[ ! -f /usr/local/cpanel/version ]]; }; then
   echo "ERROR: cPanel/WHM is not installed on this server." >&2
   echo "" >&2
   echo "Fail2Ban Manager for cPanel/WHM requires:" >&2
   echo "  - cPanel/WHM server" >&2
   echo "  - CSF firewall" >&2
   echo "" >&2
   echo "Installation aborted." >&2
   exit 1
fi

# Check CSF
if [[ ! -x /usr/sbin/csf ]] || [[ ! -f /etc/csf/csf.conf ]]; then
   echo "ERROR: CSF firewall is not installed or not properly configured." >&2
   echo "" >&2
   echo "Fail2Ban Manager for cPanel/WHM requires:" >&2
   echo "  - cPanel/WHM server" >&2
   echo "  - CSF firewall (/usr/sbin/csf and /etc/csf/csf.conf)" >&2
   echo "" >&2
   echo "Install CSF first: https://www.configserver.com/cp/csf.html" >&2
   echo "Installation aborted." >&2
   exit 1
fi

# Resolve latest tag if not specified
if [[ -z "$TAG" ]]; then
   echo "Fetching latest release..."
   if command -v curl &>/dev/null; then
      TAG=$(curl -sL "https://api.github.com/repos/sameer392/fail2ban-whm/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || true)
   fi
   if [[ -z "$TAG" ]]; then
      echo "Could not fetch latest tag. Falling back to main branch."
      TAG="main"
   fi
fi

if [[ "$TAG" == "main" ]]; then
   ZIP_URL="$REPO/archive/refs/heads/main.zip"
else
   ZIP_URL="$REPO/archive/refs/tags/$TAG.zip"
fi

echo "Downloading $TAG..."
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

if command -v curl &>/dev/null; then
   curl -sL -o "$TMP/release.zip" "$ZIP_URL"
elif command -v wget &>/dev/null; then
   wget -q -O "$TMP/release.zip" "$ZIP_URL"
else
   echo "curl or wget required." >&2
   exit 1
fi

if [[ ! -s "$TMP/release.zip" ]]; then
   echo "Download failed or empty. Check tag: $TAG" >&2
   exit 1
fi

echo "Extracting..."
cd "$TMP"
unzip -q release.zip
SRC=$(ls -1d */ 2>/dev/null | head -1 | tr -d '/')
if [[ ! -d "$SRC" ]] || [[ ! -f "$SRC/scripts/install.sh" ]]; then
   echo "Unexpected archive structure. Install failed." >&2
   exit 1
fi

# GitHub zip archives don't preserve execute bits; fix before running
chmod +x "$SRC/scripts/"*.sh 2>/dev/null || true

echo
exec "$SRC/scripts/install.sh"
