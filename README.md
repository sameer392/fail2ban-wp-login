# Fail2Ban Protection for cPanel/WHM

Generic fail2ban configuration for cPanel/WHM servers. Includes:

1. **wordpress-wp-login** – Block wp-login.php brute force (5+ requests in 5 min)
2. **apache-high-volume** – Block high-volume traffic (100+ requests in 10 min, excluding crawlers)

## Target Environment

- **Server:** cPanel/WHM + CloudLinux + LiteSpeed
- **Firewall:** CSF, BitNinja (works alongside both)
- **Scope:** All WordPress sites (primary and addon domains)

---

## Quick Start

### Option 1: Full installation (fail2ban not yet installed)

```bash
cd /root/fail2ban   # or wherever you extracted the package
./install.sh
```

- Copies source to `/usr/share/fail2ban/` (permanent location)
- Installs fail2ban, deploys config to `/etc/fail2ban/`, enables the service
- **You may remove** `/root/fail2ban` after install

### Option 2: Deploy config only (fail2ban already installed)

```bash
/usr/share/fail2ban/setup.sh
```

Copies filter and jail from `/usr/share/fail2ban/` to `/etc/fail2ban/` and restarts fail2ban.

### Uninstall

```bash
# Remove only the custom jail config (keep fail2ban)
/usr/share/fail2ban/uninstall.sh

# Remove config, uninstall fail2ban packages, and /usr/share/fail2ban/
/usr/share/fail2ban/uninstall.sh --purge
```

### Option 3: Manual installation

Extract the package, run `./install.sh` once. It installs to `/usr/share/fail2ban/` and deploys to `/etc/fail2ban/`. Or manually:

```bash
dnf install fail2ban fail2ban-systemd -y
# Copy from /usr/share/fail2ban/ (after running install.sh) or from extracted package
```

---

## How It Works

1. **Monitoring:** Fail2ban watches access logs at `/usr/local/apache/domlogs/*/*` (all cPanel domain logs)
2. **Filter:** Matches any request to `wp-login.php` (GET or POST, root or subdirectory)
3. **Ban trigger:** 5+ requests within 5 minutes from the same IP
4. **Ban action:** IP is blocked at the firewall (iptables) for 1 hour
5. **Blocking layer:** Network/firewall level – traffic never reaches LiteSpeed or WordPress

### Blocking Flow

```
Attacker → Internet → Server
                         → iptables (fail2ban rules) → DROP (blocked)
                         → CSF
                         → LiteSpeed (never reached if banned)
                         → WordPress
```

---

## Configuration

| Setting   | Value | Description                          |
|-----------|-------|--------------------------------------|
| maxretry  | 5     | Requests to wp-login before ban      |
| findtime  | 300   | Time window in seconds (5 min)       |
| bantime   | 3600  | Ban duration in seconds (1 hour)     |
| logpath   | `/usr/local/apache/domlogs/*/*` | All cPanel domain logs |

### Jails and Filters

| Jail | Filter | Purpose |
|------|--------|---------|
| wordpress-wp-login | wordpress-wp-login.conf | 5+ wp-login requests in 5 min |
| apache-high-volume | apache-high-volume.conf | 100+ requests in 10 min (excludes crawlers) |

### Files

| File | Purpose |
|------|---------|
| filter.d/wordpress-wp-login.conf | Match wp-login.php requests |
| filter.d/apache-high-volume.conf | Match all requests, exclude crawlers (same logic as find_suspicious_ips.sh) |
| jail.d/wordpress-wp-login.conf | wp-login ban rules |
| jail.d/apache-high-volume.conf | High-volume ban rules (100/10min, 1hr ban) |
| action.d/csf-domain.conf | Custom CSF action (jail + domain in comment) |
| scripts/csf-ban.sh | Helper: adds IP to csf.deny; skips whitelisted countries (India, etc.) |
| scripts/ignore-countries.conf | Countries to exclude from bans (e.g. IN=India) |
| scripts/setup-ip2location.sh | One-time setup: download IP2Location LITE DB1, install libmaxminddb |
| scripts/update-ip2location.sh | Cron script: weekly DB update (add 0 3 * * 3) |
| whm-plugin/ | WHM plugin: manage from WHM UI (install via install-whm-plugin.sh) |
| fail2ban.d/loglevel-verbose.conf | Optional: DEBUG loglevel for IP monitoring (failures, bans) in /var/log/fail2ban.log |
| whitelist-ips.conf | Whitelisted IPs (excluded from bans) – edit and run update-whitelist.sh |

### Whitelist IPs

To exclude trusted IPs from bans (wp-login and high-volume jails):

1. Edit `whitelist-ips.conf` – add one IP or CIDR per line:
   ```
   173.208.157.34/29
   204.12.247.42/29
   192.168.1.100
   10.0.0.0/24
   ```
2. Run `update-whitelist.sh` – regenerates filter ignoreregex (from `/usr/share/fail2ban/`)
3. Run `setup.sh` – deploy and restart fail2ban

Supported: single IPs, /24, /28, /29, /32. Other CIDRs fall back to single-IP match.

---

### Ignore countries (e.g. India)

IPs from certain countries are not banned. Edit `scripts/ignore-countries.conf`:

```ini
WHITELIST_COUNTRIES=IN
```

- **IN** = India. Add more: `IN,US,GB` (comma-separated ISO codes).
- **Country lookup:** IP2Location LITE DB1 (recommended) or ip-api.com (fallback, ~45 req/min).
- **Setup IP2Location:** Run during install; or manually: `/usr/share/fail2ban/scripts/setup-ip2location.sh`

---

### CSF integration (default)

Bans are added to CSF's deny list with this comment format:
- **Format:** `Fail2Ban <jail> - <domain1, domain2, ...>`
- **Example:** `Fail2Ban wordpress-wp-login - example.com` or `Fail2Ban apache-high-volume - site1.com, site2.com`
- No "do not delete" prefix; domains indicate which site(s) were affected.

Uses custom action `csf-domain` and `scripts/csf-ban.sh` to resolve affected domains from domlogs.

---

## Management Commands

```bash
# Check all jails
fail2ban-client status

# Check specific jail
fail2ban-client status wordpress-wp-login
fail2ban-client status apache-high-volume

# List banned IPs
fail2ban-client get wordpress-wp-login banip
fail2ban-client get apache-high-volume banip

# Unban an IP
fail2ban-client set wordpress-wp-login unbanip <IP_ADDRESS>

# Monitor fail2ban log (with loglevel-verbose.conf shows IP failures, bans)
tail -f /var/log/fail2ban.log

# Verify domlog path exists
ls /usr/local/apache/domlogs/*/* | head -5
```

With `loglevel = DEBUG` (from `fail2ban.d/loglevel-verbose.conf`), you'll see:
- `Found <ip>` – each failure counted for an IP
- `Ban <ip>` – IP banned
- `Unban <ip>` – IP unbanned
To reduce log volume, remove `/etc/fail2ban/fail2ban.d/loglevel-verbose.conf` and restart fail2ban.

---

## Shell Scripts

| Script        | Purpose                                                        |
|---------------|----------------------------------------------------------------|
| `install.sh`  | Full install: copies to /usr/share/fail2ban, deploys to /etc/fail2ban, IP2Location, enable |
| `setup.sh`    | Deploy config from /usr/share/fail2ban to /etc/fail2ban, restart fail2ban |
| `status.sh`         | Show fail2ban and jail status                                  |
| `update-whitelist.sh` | Regenerate filters from whitelist-ips.conf after adding IPs   |
| `uninstall.sh`      | Remove config; use `--purge` to also uninstall fail2ban packages |

All scripts must be run as root.

### WHM Plugin

Manage fail2ban from the WHM interface: status, unban IPs, edit whitelists, deploy config.

```bash
/usr/share/fail2ban/whm-plugin/install-whm-plugin.sh
systemctl restart cpanel
```

After install, **Fail2Ban Manager** appears in WHM's plugin list. Requires root or full reseller ACL.

---

## Troubleshooting

### Domlog path differs

If logs are elsewhere (e.g. `/home/*/logs/*`):

1. Edit the jail: `nano /etc/fail2ban/jail.d/wordpress-wp-login.conf`
2. Update the `logpath =` line
3. Restart: `systemctl restart fail2ban`

### No `fail2ban` binary

Use `fail2ban-client` for management. There is no standalone `fail2ban` command.

### Ban action (firewalld vs iptables)

- EL9 installs `fail2ban-firewalld`; fail2ban auto-selects the backend
- On cPanel with CSF, firewalld is often disabled; fail2ban uses iptables
- Both work at the firewall layer before traffic reaches the web server

---

## Applicability

This configuration works for **all** sites on the server. The log path covers all cPanel domain logs.

### High-volume jail caution

The `apache-high-volume` jail bans IPs with 100+ requests per 10 minutes (excluding Google, Bing, Facebook bots). This may affect:
- Legitimate users browsing many pages
- API clients or CDN origins
- Mobile apps with high request rates

To disable: edit `/etc/fail2ban/jail.d/apache-high-volume.conf` and set `enabled = false`, then `systemctl restart fail2ban`.
