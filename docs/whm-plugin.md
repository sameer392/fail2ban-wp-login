# WHM Plugin

## Install (included in install.sh when cPanel present)

```bash
/usr/share/fail2ban/whm-plugin/install-whm-plugin.sh
systemctl restart cpanel
```

## Uninstall (included in uninstall.sh --purge)

```bash
/usr/share/fail2ban/whm-plugin/uninstall-whm-plugin.sh
```

## Features

| Feature | Description |
|---------|-------------|
| **Status** | fail2ban service and per-jail stats |
| **Jail settings** | Edit maxretry, findtime, bantime per jail; Save & Deploy |
| **Banned IPs** | Table with IP, country (GeoIP), banned time, **CSF** button (runs `csf -g` in modal), Unban button; reload icon for AJAX refresh |
| **Unban** | Per-IP or "Unban all from whitelisted countries" |
| **Ignore Countries** | Edit ISO codes; saves to ignore-countries.conf |
| **Whitelist IPs** | Edit whitelist-ips.conf; Save & Deploy runs update-whitelist + update |
| **Deploy** | Runs update.sh to deploy config and restart fail2ban |
| **Update IP2Location** | Refreshes GeoIP database |

**Access:** WHM → Plugins → Fail2Ban Manager, or search "Fail2Ban Manager". Requires root or full reseller ACL.
