# Fail2Ban Manager - WHM Plugin

Manage fail2ban jails, banned IPs, and whitelists from the WHM interface.

## Requirements

- cPanel/WHM server
- Fail2Ban (installed via `/usr/share/fail2ban/install.sh`)
- Root or full reseller privileges

## Install

```bash
cd /root/fail2ban/whm-plugin
./install-whm-plugin.sh
systemctl restart cpanel
```

## Uninstall

```bash
cd /root/fail2ban/whm-plugin
./uninstall-whm-plugin.sh
```

## Features

- **Status** – View fail2ban service and jail status
- **Unban** – Unban an IP from a jail
- **Ignore Countries** – Edit whitelisted countries (e.g. IN, US)
- **Whitelist IPs** – Edit IP/CIDR whitelist, save and deploy
- **Deploy** – Deploy config and restart fail2ban
- **Update IP2Location** – Refresh GeoIP database

## Location in WHM

After install and cPanel restart, the plugin appears as **Fail2Ban Manager**:
- In WHM **Plugins** section (left nav)
- Via WHM search (top right)
- Direct URL: `https://yourserver:2087/cpsessXXX/cgi/fail2ban_manager/index.php`

If it doesn't appear, re-run the install script and restart cPanel again.
