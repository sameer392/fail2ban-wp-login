# Directory Structure

```
/root/fail2ban/
├── logrotate.d/            # Logrotate configs
│   └── fail2ban            # → /etc/logrotate.d/fail2ban
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
│   ├── install.sh          # Full install (packages, config, WHM plugin)
│   ├── update.sh           # Deploy config only
│   ├── uninstall.sh        # Remove config; --purge for full removal
│   ├── restore-backup.sh   # Restore from backup
│   ├── status.sh           # Show fail2ban and jail status
│   ├── update-whitelist.sh # Regenerate filter ignoreregex from whitelist-ips.conf
│   ├── csf-ban.sh          # CSF ban helper (country-aware)
│   ├── generate-logpath.sh       # Builds logpath excluding domains/users (reads conf.d/whitelist-domains.conf)
│   ├── setup-ip2location.sh      # One-time IP2Location setup
│   ├── update-ip2location.sh     # Cron: weekly DB update
│   └── update-from-github.sh     # Update from GitHub by tag (e.g. v1.0.1)
│
├── conf.d/                 # Config files
│   ├── whitelist-countries.conf     # Countries to never ban (e.g. IN)
│   ├── whitelist-domains.conf       # Domains/users excluded from monitoring
│   ├── blocklist-organizations.conf
│   ├── blacklist-countries.conf
│   └── whitelist-ips.conf           # IP/CIDR whitelist (never banned)
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
