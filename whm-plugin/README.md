# Fail2Ban Manager - WHM Plugin

Manage fail2ban jails, banned IPs, whitelists, and jail settings from the WHM web interface.

## Requirements

- cPanel/WHM server
- Fail2Ban (installed via `/usr/share/fail2ban/install.sh`)
- Root or full reseller privileges

## Install

**Automatic:** The plugin is installed by `install.sh` when cPanel is detected.

**Manual:**
```bash
cd /root/fail2ban/whm-plugin
./install-whm-plugin.sh
```
(No cPanel restart needed.)

## Uninstall

**Automatic:** The plugin is uninstalled by `uninstall.sh --purge`.

**Manual:**
```bash
cd /root/fail2ban/whm-plugin
./uninstall-whm-plugin.sh
```

## Features

| Feature | Description |
|---------|-------------|
| **Status** | View fail2ban service and per-jail stats |
| **Jail settings** | Edit maxretry, findtime, bantime; Save & Deploy |
| **Banned IPs** | Table with IP, country, banned time; CSF button; click IP for log entries; per-IP Unban; AJAX refresh; auto-refresh every 60s |
| **Unban all whitelisted** | Bulk unban IPs from whitelisted countries |
| **Ignore Countries** | Edit whitelisted country codes (e.g. IN, US) |
| **Whitelist IPs** | Edit IP/CIDR whitelist, save and deploy |
| **Update** | Check for updates from GitHub; install by tag; Force re-deploy |
| **Deploy** | Deploy config and restart fail2ban |
| **Update IP2Location** | Refresh GeoIP database |

## Location in WHM

After install, the plugin appears as **Fail2Ban Manager**:
- In WHM **Plugins** section (left nav)
- Via WHM search (top right)
- Direct URL: `https://yourserver:2087/cpsessXXX/cgi/fail2ban_manager/index.php`

If it doesn't appear, refresh WHM or re-run the install script.
