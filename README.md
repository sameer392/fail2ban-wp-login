# Fail2Ban Protection for cPanel/WHM

A complete fail2ban configuration for cPanel/WHM servers that blocks WordPress brute-force attacks and high-volume traffic abuse. Includes a WHM plugin for management via the web interface.

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

## Requirements

- **Server:** cPanel/WHM + CloudLinux + LiteSpeed
- **Firewall:** CSF (primary)
- **Scope:** All WordPress sites (primary + addon domains)

## Quick Start

### One-liner install (latest release)

```bash
curl -sSL https://github.com/sameer392/fail2ban-whm/releases/latest/download/install.sh | bash
```

### One-liner install (main branch)

Works without creating a release.

```bash
curl -sSL https://raw.githubusercontent.com/sameer392/fail2ban-whm/main/install.sh | bash
```

### Install a specific version

```bash
curl -sSL https://github.com/sameer392/fail2ban-whm/releases/latest/download/install.sh | bash -s v1.0.0
```

### From local clone

```bash
cd /root/fail2ban
./scripts/install.sh
```

### Config deploy only (fail2ban already installed)

```bash
/usr/share/fail2ban/scripts/update.sh
```

### Update from GitHub

```bash
/usr/share/fail2ban/scripts/update-from-github.sh v1.0.1
```

## Documentation

Detailed documentation is in the [`docs/`](docs/) folder:

| Document | Description |
|----------|-------------|
| [docs/installation.md](docs/installation.md) | Install, update, uninstall |
| [docs/directory-structure.md](docs/directory-structure.md) | Project layout |
| [docs/how-it-works.md](docs/how-it-works.md) | Blocking flow |
| [docs/configuration.md](docs/configuration.md) | Jails, whitelisting, CSF |
| [docs/whm-plugin.md](docs/whm-plugin.md) | WHM plugin |
| [docs/operations.md](docs/operations.md) | Commands, scripts, logging |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues |
| [docs/IMPROVEMENTS.md](docs/IMPROVEMENTS.md) | Roadmap & ideas |
