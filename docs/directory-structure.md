# Directory Structure

```
/root/fail2ban/
├── install.sh              # Full install (packages, config, WHM plugin)
├── uninstall.sh            # Remove config; --purge for full removal
├── update.sh               # Deploy config only
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
│   ├── excluded-domains.conf     # Domains/users excluded from monitoring
│   ├── generate-logpath.sh       # Builds logpath excluding domains/users
│   ├── setup-ip2location.sh      # One-time IP2Location setup
│   ├── update-ip2location.sh     # Cron: weekly DB update
│   └── update-from-github.sh     # Update from GitHub by tag (e.g. v1.0.1)
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
