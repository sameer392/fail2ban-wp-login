# Fail2Ban Protection for cPanel/WHM

A complete fail2ban configuration for cPanel/WHM servers that blocks WordPress brute-force attacks and high-volume traffic abuse. Includes a WHM plugin for management via the web interface.

---

## Features

| Feature | Description |
|---------|-------------|
| **wordpress-wp-login** | Blocks wp-login.php brute force (5+ requests in 5 min) |
| **apache-high-volume** | Blocks high-volume traffic (100+ requests in 10 min, excludes crawlers) |
| **CSF integration** | Bans via CSF with jail name and affected domain(s) in comment |
| **Country whitelist** | Skip banning IPs from specified countries (e.g. India, US) |
| **IP whitelist** | Exclude trusted IPs/CIDRs from bans |
| **WHM plugin** | Manage jails, banned IPs, whitelists, and settings from WHM UI |
| **Auto-unban** | Bans expire after bantime (default 1 hr); IPs removed from CSF automatically |
| **Log rotation** | Prevents unbounded log growth (rotate at 50MB or weekly) |

---

## Target Environment

| Component | Requirement |
|-----------|-------------|
| **Server** | cPanel/WHM + CloudLinux + LiteSpeed |
| **Firewall** | CSF (primary), works alongside BitNinja |
| **Scope** | All WordPress sites (primary + addon domains) |
| **Access** | Root or full reseller ACL for WHM plugin |

---

## Quick Start

### Full Installation (fail2ban not yet installed)

```bash
cd /root/fail2ban
./install.sh
```

**What it does:**
- Copies source to `/usr/share/fail2ban/` (permanent location)
- Installs fail2ban packages (dnf/yum)
- Deploys config to `/etc/fail2ban/`
- Installs libmaxminddb for GeoIP
- Sets up IP2Location LITE DB1 for country lookup
- Installs logrotate config for fail2ban.log
- Enables and starts fail2ban
- **Installs WHM plugin** if cPanel is detected
- You may remove `/root/fail2ban` after install

### Config Deploy Only (fail2ban already installed)

```bash
/usr/share/fail2ban/setup.sh
```

Copies filters, jails, actions, scripts, and logrotate config from `/usr/share/fail2ban/` to `/etc/fail2ban/` and restarts fail2ban.

### Uninstall

```bash
# Remove only custom config (keep fail2ban service)
/usr/share/fail2ban/uninstall.sh

# Full removal: config, packages, WHM plugin, /usr/share/fail2ban/
/usr/share/fail2ban/uninstall.sh --purge
```

---

## Directory Structure

```
/root/fail2ban/
├── install.sh              # Full install (packages, config, WHM plugin)
├── uninstall.sh            # Remove config; --purge for full removal
├── setup.sh                # Deploy config only
├── status.sh               # Show fail2ban and jail status
├── update-whitelist.sh     # Regenerate filter ignoreregex from whitelist-ips.conf
├── whitelist-ips.conf      # IP/CIDR whitelist (never banned)
├── fail2ban-logrotate      # Logrotate config → /etc/logrotate.d/fail2ban
├── README.md
│
├── filter.d/               # Fail2ban filters
│   ├── wordpress-wp-login.conf    # Match wp-login.php requests
│   └── apache-high-volume.conf   # Match all requests, exclude crawlers
│
├── jail.d/                 # Jail definitions
│   ├── wordpress-wp-login.conf   # 5 hits / 5 min → 1 hr ban
│   └── apache-high-volume.conf  # 100 hits / 10 min → 1 hr ban
│
├── action.d/
│   └── csf-domain.conf     # Ban via CSF with domain comment
│
├── fail2ban.d/
│   └── loglevel-verbose.conf     # Loglevel override (INFO/WARNING)
│
├── scripts/
│   ├── csf-ban.sh          # CSF ban helper (country-aware)
│   ├── ignore-countries.conf     # Countries to never ban (e.g. IN)
│   ├── setup-ip2location.sh      # One-time IP2Location setup
│   └── update-ip2location.sh     # Cron: weekly DB update
│
└── whm-plugin/
    ├── install-whm-plugin.sh
    ├── uninstall-whm-plugin.sh
    ├── README.md
    └── plugin/
        ├── index.php       # WHM plugin UI
        ├── fail2ban_manager.conf
        └── fail2ban_manager.png
```

---

## How It Works

### Blocking Flow

```
Attacker → Internet → Server
                         → iptables (fail2ban) / CSF → DROP (blocked)
                         → LiteSpeed (never reached if banned)
                         → WordPress
```

### End-to-End Flow

1. **Monitor** – Fail2ban watches `/usr/local/apache/domlogs/*/*` (all cPanel domain logs)
2. **Filter** – Matches wp-login.php requests or high-volume (excludes crawlers)
3. **Trigger** – 5+ wp-login in 5 min OR 100+ requests in 10 min
4. **Ban** – `scripts/csf-ban.sh` adds IP to CSF; skips whitelisted countries
5. **Unban** – After bantime (1 hr), fail2ban runs `csf -dr <ip>` to remove from CSF

---

## Jails and Configuration

### Jail Settings (editable via WHM UI)

| Jail | maxretry | findtime | bantime | Purpose |
|------|----------|----------|---------|---------|
| wordpress-wp-login | 5 | 300 sec (5 min) | 3600 sec (1 hr) | wp-login brute force |
| apache-high-volume | 100 | 600 sec (10 min) | 3600 sec (1 hr) | High-volume abuse |

### Files Deployed

| File | Purpose |
|------|---------|
| filter.d/wordpress-wp-login.conf | Match POST to wp-login.php (login attempts only; GET ignored) |
| filter.d/apache-high-volume.conf | Match all requests; ignoreregex excludes crawlers (Google, Bing, Facebook) + whitelist IPs |
| jail.d/*.conf | Jail definitions (backend=polling, logpath, banaction) |
| action.d/csf-domain.conf | Custom action: actionban → csf-ban.sh, actionunban → csf -dr |
| scripts/csf-ban.sh | Adds IP to csf.deny; skips whitelisted countries; resolves affected domains |
| scripts/ignore-countries.conf | `WHITELIST_COUNTRIES=IN,US` (ISO codes) |
| fail2ban.d/loglevel-verbose.conf | Loglevel override (INFO or WARNING) |
| fail2ban-logrotate | → /etc/logrotate.d/fail2ban |

---

## Whitelisting

### IP Whitelist (whitelist-ips.conf)

IPs/CIDRs in this file are excluded from bans. Supported: single IP, /24, /28, /29, /32.

1. Edit `whitelist-ips.conf` (in `/usr/share/fail2ban/` or package root)
2. Run `update-whitelist.sh` – regenerates filter ignoreregex
3. Run `setup.sh` – deploy and restart

### Country Whitelist (ignore-countries.conf)

IPs from specified countries are not banned (checked in csf-ban.sh via GeoIP).

```ini
# scripts/ignore-countries.conf
WHITELIST_COUNTRIES=IN,US,GB
```

- **IN** = India, **US** = United States, **GB** = United Kingdom
- Country lookup: IP2Location LITE DB1 → ip-api.com fallback
- Setup: Run `scripts/setup-ip2location.sh` during install or manually

### Organization Lookup (for WHM display and blocked-orgs)

Organization (Microsoft, DigitalOcean, etc.) is shown in the Banned IPs table. Lookup order:
1. SQLite cache (local)
2. IP2Location LITE ASN mmdb (local file)
3. whois (system tool)
4. ip-api.com (fallback)

For local mmdb, run `scripts/setup-ip2location-asn.sh` (requires IP2LOCATION_TOKEN in `/etc/fail2ban/GeoIP/ip2location.conf`). Without it, whois/ip-api.com are used. All results are cached in SQLite.

---

## CSF Integration

- **Comment format:** `Fail2Ban <jail> - <domain1, domain2, ...>`
- **Example:** `Fail2Ban wordpress-wp-login - example.com` or `Fail2Ban apache-high-volume - site1.com, site2.com`
- Domains are resolved from domlogs when the ban is triggered
- Auto-unban: When bantime expires, fail2ban runs `csf -dr <ip>`

---

## WHM Plugin

### Install (included in install.sh when cPanel present)

```bash
/usr/share/fail2ban/whm-plugin/install-whm-plugin.sh
systemctl restart cpanel
```

### Uninstall (included in uninstall.sh --purge)

```bash
/usr/share/fail2ban/whm-plugin/uninstall-whm-plugin.sh
```

### Features

| Feature | Description |
|---------|-------------|
| **Status** | fail2ban service and per-jail stats |
| **Jail settings** | Edit maxretry, findtime, bantime per jail; Save & Deploy |
| **Banned IPs** | Table with IP, country (GeoIP), banned time, Unban button; reload icon for AJAX refresh |
| **Unban** | Per-IP or "Unban all from whitelisted countries" |
| **Ignore Countries** | Edit ISO codes; saves to ignore-countries.conf |
| **Whitelist IPs** | Edit whitelist-ips.conf; Save & Deploy runs update-whitelist + setup |
| **Deploy** | Runs setup.sh to deploy config and restart fail2ban |
| **Update IP2Location** | Refreshes GeoIP database |

**Access:** WHM → Plugins → Fail2Ban Manager, or search "Fail2Ban Manager". Requires root or full reseller ACL.

---

## Management Commands

```bash
# Service status
fail2ban-client status

# Per-jail status
fail2ban-client status wordpress-wp-login
fail2ban-client status apache-high-volume

# List banned IPs
fail2ban-client get wordpress-wp-login banip

# Unban an IP
fail2ban-client set wordpress-wp-login unbanip <IP_ADDRESS>

# Monitor log
tail -f /var/log/fail2ban.log

# Verify domlog path
ls /usr/local/apache/domlogs/*/* | head -5

# Status script
/usr/share/fail2ban/status.sh
```

---

## Logging and Rotation

| Item | Details |
|------|---------|
| **Log file** | `/var/log/fail2ban.log` |
| **Logrotate** | `/etc/logrotate.d/fail2ban` – rotate at 50MB or weekly, keep 4 compressed archives |
| **Flush** | Uses `fail2ban-client flushlogs` so no restart needed |
| **Immediate rotate** | `logrotate --force /etc/logrotate.d/fail2ban` |
| **Loglevel** | `fail2ban.d/loglevel-verbose.conf` – set INFO for more detail, WARNING for less. Remove file to use fail2ban default. |

### Backup & Restore

`setup.sh` creates a timestamped backup in `/etc/fail2ban/backups/YYYYMMDD-HHMMSS/` before each deploy (keeps last 10). To restore: `restore-backup.sh` (latest) or `restore-backup.sh /etc/fail2ban/backups/YYYYMMDD-HHMMSS`.

---

## Shell Scripts Reference

| Script | Purpose |
|--------|---------|
| install.sh | Full install: copy to /usr/share/fail2ban, deploy, IP2Location, logrotate, enable, WHM plugin |
| setup.sh | Deploy config to /etc/fail2ban (backs up first), restart fail2ban |
| restore-backup.sh | Restore from backup (default: latest). Usage: `restore-backup.sh [BACKUP_DIR]` |
| uninstall.sh | Remove config; --purge = also packages, WHM plugin, /etc and /usr/share |
| status.sh | Show fail2ban service and jail status |
| update-whitelist.sh | Regenerate filter ignoreregex from whitelist-ips.conf |

All scripts must be run as root.

---

## Troubleshooting

### Domlog path differs

Edit jail config: `logpath = /path/to/your/logs/*` then run `setup.sh` or `systemctl restart fail2ban`.

### No `fail2ban` binary

Use `fail2ban-client` for management. There is no standalone `fail2ban` command.

### Ban action (firewalld vs iptables)

- EL9 installs fail2ban-firewalld; fail2ban auto-selects backend
- On cPanel with CSF, firewalld is usually disabled; fail2ban uses iptables
- CSF bans are separate from iptables; csf-ban.sh adds to csf.deny

### IP not being banned

- **Country whitelist:** Check ignore-countries.conf; IPs from listed countries are skipped
- **IP whitelist:** Check whitelist-ips.conf and run update-whitelist.sh + setup.sh
- **Time window:** findtime is a sliding window; requests must exceed maxretry within that window
- **Test filter:** `fail2ban-regex /path/to/log /etc/fail2ban/filter.d/wordpress-wp-login.conf`

### High-volume jail caution

The apache-high-volume jail may affect legitimate high-traffic users (API clients, CDNs, mobile apps). To disable: set `enabled = false` in `jail.d/apache-high-volume.conf` and run setup.sh.

---

## Applicability

This configuration protects **all** sites on the server. The log path `/usr/local/apache/domlogs/*/*` covers all cPanel domain logs (primary and addon domains).
