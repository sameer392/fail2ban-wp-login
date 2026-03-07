# Configuration

## Jails and Settings

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
3. Run `update.sh` – deploy and restart

### Country Whitelist (ignore-countries.conf)

**Applies only to `apache-high-volume` jail.** IPs from whitelisted countries are not banned by apache-high-volume (high-traffic abuse). **All other jails (wordpress-wp-login, apache-ua-*, etc.) always ban regardless of country**—wp-login brute force and User-Agent abuse are blocked even from whitelisted countries.

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
