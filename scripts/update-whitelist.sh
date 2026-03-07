#!/bin/bash
#
# update-whitelist.sh - Regenerate filter ignoreregex from whitelist-ips.conf
# Run after editing whitelist-ips.conf, then run ./update.sh to deploy
# Must be run as root (writes to filter.d/)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/share/fail2ban"
[[ "$SCRIPT_DIR" == */scripts ]] && CONFIG_DIR="$(dirname "$SCRIPT_DIR")" || CONFIG_DIR="$SCRIPT_DIR"
[ -d "$INSTALL_DIR" ] || INSTALL_DIR="$CONFIG_DIR"
WHITELIST="$CONFIG_DIR/whitelist-ips.conf"
FILTER="$CONFIG_DIR/filter.d/apache-high-volume.conf"

# Built-in crawler exclusions (same as find_suspicious_ips.sh)
CRAWLER_REGEX='^66\.249\.|^2a03:2880|^173\.208\.207\.|^40\.77\.|^207\.46\.|googlebot|bingbot|meta-webindexer|facebookexternalhit'

cidr_to_regex() {
    local entry="$1"
    if [[ "$entry" == */* ]]; then
        local ip="${entry%%/*}"
        local cidr="${entry##*/}"
        local a b c d
        IFS='.' read -r a b c d <<< "$ip"
        case "$cidr" in
            32) echo "^${a}\\.${b}\\.${c}\\.${d}" ;;
            24) echo "^${a}\\.${b}\\.${c}\\." ;;
            29)
                local base=$((d & 248))
                local end=$((base + 7))
                local regex=""
                for ((i=base; i<=end; i++)); do
                    [ -n "$regex" ] && regex+="|"
                    regex+="$i"
                done
                echo "^${a}\\.${b}\\.${c}\\.(${regex})"
                ;;
            28)
                local base=$((d & 240))
                local end=$((base + 15))
                local regex=""
                for ((i=base; i<=end; i++)); do
                    [ -n "$regex" ] && regex+="|"
                    regex+="$i"
                done
                echo "^${a}\\.${b}\\.${c}\\.(${regex})"
                ;;
            *)
                echo "# Unsupported CIDR /$cidr - add regex manually" >&2
                echo "^${a}\\.${b}\\.${c}\\.${d}"
                ;;
        esac
    else
        # Single IP
        local a b c d
        IFS='.' read -r a b c d <<< "$entry"
        echo "^${a}\\.${b}\\.${c}\\.${d}"
    fi
}

[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }
[ ! -f "$WHITELIST" ] && { echo "whitelist-ips.conf not found"; exit 1; }

WL_REGEX=""
while IFS= read -r line; do
    line="${line%%#*}"
    line="${line// /}"
    [ -z "$line" ] && continue
    re=$(cidr_to_regex "$line")
    [[ "$re" == ^#* ]] && continue
    [ -n "$WL_REGEX" ] && WL_REGEX+="|"
    WL_REGEX+="$re"
done < "$WHITELIST"

if [ -z "$WL_REGEX" ]; then
    IGNOREREGEX_HV="$CRAWLER_REGEX"
    IGNOREREGEX_WP=""
else
    IGNOREREGEX_HV="${CRAWLER_REGEX}|${WL_REGEX}"
    IGNOREREGEX_WP="$WL_REGEX"
fi

tmp=$(mktemp)
trap "rm -f $tmp" EXIT

# Escape backslashes for awk (avoids "escape sequence treated as plain" warning)
IGN_HV="${IGNOREREGEX_HV//\\/\\\\}"
IGN_WP="${IGNOREREGEX_WP//\\/\\\\}"

# Update apache-high-volume filter
awk -v ign="$IGN_HV" '
    /^ignoreregex =/ { print "ignoreregex = " ign; next }
    { print }
' "$CONFIG_DIR/filter.d/apache-high-volume.conf" > "$tmp"
mv "$tmp" "$CONFIG_DIR/filter.d/apache-high-volume.conf"

# Update wordpress-wp-login filter (whitelist only)
awk -v ign="$IGN_WP" '
    /^ignoreregex =/ { print "ignoreregex = " ign; next }
    { print }
' "$CONFIG_DIR/filter.d/wordpress-wp-login.conf" > "$tmp"
mv "$tmp" "$CONFIG_DIR/filter.d/wordpress-wp-login.conf"

echo "Whitelist updated. Run $INSTALL_DIR/scripts/update.sh to deploy."
