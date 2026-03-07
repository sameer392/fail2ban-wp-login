# WHM Plugin

## Install (included in install.sh when cPanel present)

```bash
/usr/share/fail2ban/whm-plugin/install-whm-plugin.sh
```
No cPanel restart needed. Refresh WHM if the plugin does not appear.

## Uninstall (included in uninstall.sh --purge)

```bash
/usr/share/fail2ban/whm-plugin/uninstall-whm-plugin.sh
```

## Features

| Feature | Description |
|---------|-------------|
| **Status** | fail2ban service and per-jail stats |
| **Jail settings** | Edit maxretry, findtime, bantime per jail; Save & Deploy |
| **Banned IPs** | Table with IP, country (GeoIP), banned time; **CSF** button (runs `csf -g` in modal); click IP for log entries (up to 100); Unban; reload icon; **auto-refresh every 60s** when tab is active |
| **Unban** | Per-IP or "Unban all from whitelisted countries" |
| **Ignore Countries** | Edit ISO codes; saves to ignore-countries.conf |
| **Whitelist IPs** | Edit whitelist-ips.conf; Save & Deploy runs update-whitelist + update |
| **Deploy** | Runs update.sh to deploy config and restart fail2ban |
| **Update** | Check for updates from GitHub; install by tag (e.g. v1.0.1); Force re-deploy runs update.sh without downloading |
| **Update IP2Location** | Refreshes GeoIP database |

**Access:** WHM → Plugins → Fail2Ban Manager, or search "Fail2Ban Manager". Requires root or full reseller ACL.
