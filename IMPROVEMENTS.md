# Suggested Improvements for Fail2Ban cPanel/WHM

Recommendations for enhancing usability, reliability, and functionality.

---

## 1. Usability & UX ✅ (Completed)

### 1.1 WHM Plugin – Add helper text for time fields ✅
**Current:** `findtime` and `bantime` show raw seconds (e.g. 300, 3600).  
**Done:** Added preset dropdowns: findtime (1 min, 5 min, 10 min, 1 hr), bantime (5 min, 1 hr, 24 hr, 1 week).

### 1.2 WHM Plugin – Show affected domains per ban ✅
**Current:** Banned IPs table shows IP, country, banned time.  
**Done:** Added "Affected Domains" column from csf.deny comment or domlog lookup.

### 1.3 WHM Plugin – Bulk unban from table ✅
**Current:** Must unban IPs one by one.  
**Done:** Added row checkboxes, "Select all", and "Unban selected" button.

### 1.4 WHM Plugin – Dark/light theme consistency ✅
**Current:** UI uses WHM styles; may not match all themes.  
**Done:** Added .fail2ban-manager wrapper and theme-aware CSS with var() fallbacks.

---

## 2. Reliability & Safety

### 2.1 Backup before deploy
**Current:** `setup.sh` overwrites configs in `/etc/fail2ban/` directly.  
**Improvement:** Before overwriting, create a timestamped backup (e.g. `/etc/fail2ban/backups/YYYYMMDD-HHMMSS/`) and add a restore option.

### 2.2 Validation of jail settings in UI
**Current:** UI accepts arbitrary values; validation is done in PHP.  
**Improvement:** Add client-side validation and clearer error messages (e.g. min/max and allowed ranges).

### 2.3 Idempotent install
**Current:** Re-running `install.sh` may show repeated messages.  
**Improvement:** Make steps more idempotent and only perform changes when needed (e.g. skip copy if files match).

### 2.4 Graceful handling of missing GeoIP
**Current:** If IP2Location is missing, country lookups may fail or fall back to ip-api.com.  
**Improvement:** Surface a clear notice in the WHM plugin when GeoIP setup is incomplete and link to setup instructions.

---

## 3. Monitoring & Observability

### 3.1 Dashboard stats
**Current:** WHM plugin shows per-jail counts (failed, banned).  
**Improvement:** Add simple charts (e.g. bans over time) and a "Last 24h bans" summary using fail2ban.log or SQLite.

### 3.2 Email alerts for bans
**Current:** No built-in email notification.  
**Improvement:** Optional config to send email (or use `fail2ban-sendmail`) when high-value IPs are banned or when a threshold is reached.

### 3.3 Log level toggle in UI
**Current:** Loglevel is set in `loglevel-verbose.conf` and requires manual edit + restart.  
**Improvement:** Add a dropdown in the WHM plugin (INFO/WARNING/ERROR) and apply changes via config update + restart.

---

## 4. Functionality

### 4.1 Additional jails (XML-RPC, exploit probes)
**Current:** Only wp-login and high-volume.  
**Improvement:** Add jails for:
- **xmlrpc** – 10+ xmlrpc.php requests (similar to find_suspicious_ips)
- **exploit-probe** – Common exploit paths (_ignition, path traversal, etc.)

### 4.2 Per-domain or per-jail enable/disable
**Current:** Jails are global.  
**Improvement:** Allow enabling/disabling jails per domain or per user (via config or UI). Higher complexity; may need filter changes.

### 4.3 Whitelist "never ban" for specific IPs even from whitelisted countries
**Current:** Country whitelist applies to all IPs from that country.  
**Improvement:** Support an "always ban" list (e.g. known bad IPs) that overrides country whitelist.

### 4.4 Import/export banned IPs
**Current:** No bulk export/import.  
**Improvement:** Export banned IPs to CSV and import from a list (e.g. for migration or bulk ban).

---

## 5. Security & Performance

### 5.1 Rate limit WHM plugin actions
**Current:** No explicit rate limiting on deploy/unban.  
**Improvement:** Add simple rate limiting or confirmation dialogs for destructive actions (e.g. "Deploy config & restart", "Unban all whitelisted").

### 5.2 Harden csf-ban.sh
**Current:** Script uses external calls (mmdblookup, curl).  
**Improvement:** Validate and sanitize IP input more strictly; add a timeout for country lookup to avoid hanging.

### 5.3 Optional database for ban history
**Current:** Ban history comes from fail2ban SQLite and log parsing.  
**Improvement:** Optionally store ban events in a dedicated table for reporting and analytics.

---

## 6. Documentation & Ops

### 6.1 Changelog
**Current:** No CHANGELOG.  
**Improvement:** Maintain `CHANGELOG.md` with version, date, and notable changes.

### 6.2 Health check script
**Current:** `status.sh` shows status.  
**Improvement:** Add `healthcheck.sh` that verifies: fail2ban running, jails enabled, log path exists, GeoIP present, and returns exit code for monitoring.

### 6.3 Upgrade path
**Current:** Updates are done by re-running setup or reinstalling.  
**Improvement:** Document upgrade steps (e.g. backup → pull/copy new files → setup.sh) and any config migrations.

### 6.4 Integration with find_suspicious_ips.sh
**Current:** find_suspicious_ips is separate.  
**Improvement:** Document how it relates to fail2ban, or add a "Suggested blocks" section in the WHM plugin that runs a similar scan and suggests IPs to ban.

---

## 7. Low-Effort Wins

| Improvement | Effort | Impact |
|-------------|--------|--------|
| Add findtime/bantime presets (5m, 1h, 24h) in UI | Low | Medium |
| Show "Affected domains" in banned IPs table | Medium | High |
| Backup before setup.sh deploy | Low | High |
| Add CHANGELOG.md | Low | Medium |
| Health check script | Low | Medium |
| Log level toggle in WHM UI | Low | Low |

---

## Priority Summary

**High priority:** Backup before deploy, validation in UI, clearer GeoIP setup status.  
**Medium priority:** Time presets, affected domains column, health check, XML-RPC jail.  
**Lower priority:** Ban history DB, per-domain enable/disable, email alerts.
