# Fail2Ban WordPress wp-login Protection

Generic fail2ban configuration to block brute force attacks on `wp-login.php` across all WordPress sites on a cPanel/WHM server.

## Target Environment

- **Server:** cPanel/WHM + CloudLinux + LiteSpeed
- **Firewall:** CSF, BitNinja (works alongside both)
- **Scope:** All WordPress sites (primary and addon domains)

---

## Quick Start

### Option 1: Full installation (fail2ban not yet installed)

```bash
cd /root/fail2ban-config
./install.sh
```

Installs fail2ban, deploys config to `/etc/fail2ban/`, enables and starts the service.

### Option 2: Deploy config only (fail2ban already installed)

```bash
cd /root/fail2ban-config
./setup.sh
```

Copies filter and jail to `/etc/fail2ban/` and restarts fail2ban.

### Option 3: Manual installation

```bash
# Install fail2ban (CloudLinux / RHEL / CentOS)
dnf install fail2ban fail2ban-systemd -y

# Copy config
cp /root/fail2ban-config/filter.d/wordpress-wp-login.conf /etc/fail2ban/filter.d/
cp /root/fail2ban-config/jail.d/wordpress-wp-login.conf /etc/fail2ban/jail.d/

# Enable and start
systemctl enable fail2ban
systemctl start fail2ban
systemctl restart fail2ban

# Verify
fail2ban-client status wordpress-wp-login
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

### Files

| File | Location | Purpose |
|------|----------|---------|
| Filter | `filter.d/wordpress-wp-login.conf` | Regex to match wp-login requests |
| Jail   | `jail.d/wordpress-wp-login.conf`   | Ban rules and log path             |

### Optional: CSF integration

To add banned IPs to CSF's deny list, edit the jail:

```bash
nano /etc/fail2ban/jail.d/wordpress-wp-login.conf
```

Add under `[wordpress-wp-login]`:

```ini
banaction = csf-repeater
banaction_allports = csf-repeater
```

Then restart: `systemctl restart fail2ban`

---

## Management Commands

```bash
# Check all jails
fail2ban-client status

# Check WordPress jail
fail2ban-client status wordpress-wp-login

# List banned IPs
fail2ban-client get wordpress-wp-login banip

# Unban an IP
fail2ban-client set wordpress-wp-login unbanip <IP_ADDRESS>

# Monitor fail2ban log
tail -f /var/log/fail2ban.log

# Verify domlog path exists
ls /usr/local/apache/domlogs/*/* | head -5
```

---

## Shell Scripts

| Script       | Purpose                                              |
|--------------|------------------------------------------------------|
| `install.sh` | Full install: install package + deploy config + enable |
| `setup.sh`   | Deploy config only, restart fail2ban                 |
| `status.sh`  | Show fail2ban and jail status                        |

All scripts must be run as root.

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

This configuration works for **all** WordPress sites because every WordPress installation uses `wp-login.php`. The log path covers all cPanel domain logs, so every WordPress site on the server is protected.
