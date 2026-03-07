# Troubleshooting

## Domlog path differs

Edit jail config: `logpath = /path/to/your/logs/*` then run `update.sh` or `systemctl restart fail2ban`.

## No `fail2ban` binary

Use `fail2ban-client` for management. There is no standalone `fail2ban` command.

## Ban action (firewalld vs iptables)

- EL9 installs fail2ban-firewalld; fail2ban auto-selects backend
- On cPanel with CSF, firewalld is usually disabled; fail2ban uses iptables
- CSF bans are separate from iptables; csf-ban.sh adds to csf.deny

## IP not being banned

- **Country whitelist:** Check conf.d/whitelist-countries.conf; IPs from listed countries are skipped
- **IP whitelist:** Check whitelist-ips.conf and run update-whitelist.sh + update.sh
- **Time window:** findtime is a sliding window; requests must exceed maxretry within that window
- **Test filter:** `fail2ban-regex /path/to/log /etc/fail2ban/filter.d/wordpress-wp-login.conf`

## High-volume jail caution

The apache-high-volume jail may affect legitimate high-traffic users (API clients, CDNs, mobile apps). To disable: set `enabled = false` in `jail.d/apache-high-volume.conf` and run update.sh.
