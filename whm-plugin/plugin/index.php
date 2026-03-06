<?php
#WHMADDON:fail2ban_manager:Fail2Ban Manager:fail2ban_manager.png
#ACLS:all
/**
 * Fail2Ban Manager - WHM Plugin
 * Manage fail2ban jails, banned IPs, whitelists from WHM
 */
require_once('/usr/local/cpanel/php/WHM.php');

function checkacl($acl) {
    $user = $_ENV['REMOTE_USER'] ?? '';
    if ($user === 'root') return true;
    if (!file_exists('/var/cpanel/resellers')) return false;
    $content = file_get_contents('/var/cpanel/resellers');
    foreach (explode("\n", $content) as $line) {
        if (preg_match("/^$user:/", $line)) {
            $line = preg_replace("/^$user:/", "", $line);
            foreach (explode(",", $line) as $perm) {
                if (trim($perm) === 'all' || trim($perm) === $acl) return true;
            }
        }
    }
    return false;
}

function get_ip_country_cache_db() {
    static $pdo = null;
    if ($pdo !== null) return $pdo;
    $dir = '/etc/fail2ban/GeoIP';
    $db_path = $dir . '/ip_country_cache.db';
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    try {
        $pdo = new PDO('sqlite:' . $db_path);
        $pdo->exec("CREATE TABLE IF NOT EXISTS ip_country (ip TEXT PRIMARY KEY, country TEXT NOT NULL, updated_at INTEGER)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS ip_org (ip TEXT PRIMARY KEY, org TEXT NOT NULL, updated_at INTEGER)");
    } catch (Exception $e) {
        return null;
    }
    return $pdo;
}

function get_ip_org($ip, &$cache = []) {
    if (isset($cache[$ip])) return $cache[$ip];
    if (preg_match('/^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fc00:|fe80:)/', $ip)) {
        return $cache[$ip] = '-';
    }
    $org = '';
    $pdo = get_ip_country_cache_db();
    // 1. Check SQLite cache first (local, instant)
    if ($pdo) {
        $stmt = $pdo->prepare("SELECT org FROM ip_org WHERE ip = ?");
        if ($stmt && $stmt->execute([$ip])) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) return $cache[$ip] = $row['org'];
        }
    }
    // 2. Try local mmdb (IP2Location LITE ASN - org/AS name)
    $asn_mmdb = '/etc/fail2ban/GeoIP/IP2LOCATION-LITE-ASN.mmdb';
    if ($org === '' && file_exists($asn_mmdb) && is_readable($asn_mmdb) && function_exists('exec')) {
        $out = [];
        foreach (['as', 'autonomous_system_organization', 'organization'] as $path) {
            @exec("mmdblookup -f " . escapeshellarg($asn_mmdb) . " -i " . escapeshellarg($ip) . " " . escapeshellarg($path) . " 2>/dev/null", $out, $ret);
            if ($ret === 0 && !empty($out)) {
                $text = implode(' ', $out);
                if (preg_match('/"([^"]+)"/', $text, $m) && trim($m[1]) !== '' && trim($m[1]) !== '-') {
                    $org = trim($m[1]);
                    break;
                }
            }
            $out = [];
        }
    }
    // 3. Try local whois (system tool, queries RIRs - no third-party API) - 2s timeout
    if (function_exists('exec')) {
        $out = [];
        @exec("timeout 2 whois " . escapeshellarg($ip) . " 2>/dev/null", $out, $ret);
        $text = implode("\n", $out);
        if (preg_match('/^OrgName:\s*(.+)$/m', $text, $m)) $org = trim($m[1]);
        elseif (preg_match('/^Organization:\s*([^(]+)/m', $text, $m)) $org = trim($m[1]);
        elseif (preg_match('/^netname:\s*(.+)$/mi', $text, $m)) $org = trim($m[1]);
        elseif (preg_match('/^descr:\s*(.+)$/mi', $text, $m)) $org = trim($m[1]);
    }
    // 4. Fallback: remote API (ip-api.com) only when whois fails
    if ($org === '' && (function_exists('file_get_contents') && ini_get('allow_url_fopen') || function_exists('curl_init'))) {
        if (function_exists('file_get_contents') && ini_get('allow_url_fopen')) {
            $json = @file_get_contents("http://ip-api.com/json/" . urlencode($ip) . "?fields=org,isp", false, stream_context_create(['http' => ['timeout' => 2]]));
        } else {
            $ch = curl_init("http://ip-api.com/json/" . urlencode($ip) . "?fields=org,isp");
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
            $json = @curl_exec($ch);
            curl_close($ch);
        }
        if (!empty($json)) {
            if (preg_match('/"org":"([^"]*)"/', $json, $m) && trim($m[1]) !== '') $org = trim($m[1]);
            elseif (preg_match('/"isp":"([^"]*)"/', $json, $m) && trim($m[1]) !== '') $org = trim($m[1]);
        }
    }
    $org = $org ?: '-';
    // 5. Store in SQLite for future lookups (all sources cached)
    if ($pdo) {
        $stmt = $pdo->prepare("INSERT OR REPLACE INTO ip_org (ip, org, updated_at) VALUES (?, ?, ?)");
        if ($stmt) @$stmt->execute([$ip, $org, time()]);
    }
    return $cache[$ip] = $org;
}

function get_ip_country($ip, &$cache = []) {
    if (isset($cache[$ip])) return $cache[$ip];
    if (preg_match('/^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fc00:|fe80:)/', $ip)) {
        return $cache[$ip] = '-';
    }
    $country = '';
    $pdo = get_ip_country_cache_db();
    if ($pdo) {
        $stmt = $pdo->prepare("SELECT country FROM ip_country WHERE ip = ?");
        if ($stmt && $stmt->execute([$ip])) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) return $cache[$ip] = $row['country'];
        }
    }
    $mmdb = '/etc/fail2ban/GeoIP/IP2LOCATION-LITE-DB1.mmdb';
    if (file_exists($mmdb)) {
        foreach (['country iso_code', 'country_code'] as $path) {
            $out = [];
            exec("mmdblookup -f " . escapeshellarg($mmdb) . " -i " . escapeshellarg($ip) . " " . escapeshellarg($path) . " 2>/dev/null", $out, $ret);
            if ($ret === 0 && preg_match('/"([A-Z]{2})"/', implode(' ', $out), $m)) {
                $country = $m[1];
                break;
            }
        }
    }
    if ($country === '') {
        if (function_exists('file_get_contents') && ini_get('allow_url_fopen')) {
            $json = @file_get_contents("http://ip-api.com/json/" . urlencode($ip) . "?fields=countryCode", false, stream_context_create(['http' => ['timeout' => 2]]));
            if ($json && preg_match('/"countryCode":"([A-Z]{2})"/', $json, $m)) $country = $m[1];
        } elseif (function_exists('curl_init')) {
            $ch = curl_init("http://ip-api.com/json/" . urlencode($ip) . "?fields=countryCode");
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
            $json = @curl_exec($ch);
            curl_close($ch);
            if ($json && preg_match('/"countryCode":"([A-Z]{2})"/', $json, $m)) $country = $m[1];
        }
    }
    $country = $country ?: '-';
    if ($pdo) {
        $stmt = $pdo->prepare("INSERT OR REPLACE INTO ip_country (ip, country, updated_at) VALUES (?, ?, ?)");
        if ($stmt) $stmt->execute([$ip, $country, time()]);
    }
    return $cache[$ip] = $country;
}

function get_affected_domains($ip, $jail, &$cache = []) {
    $key = $ip . ':' . $jail;
    if (isset($cache[$key])) return $cache[$key];
    $domains = '';
    $csf_deny = '/etc/csf/csf.deny';
    if (is_readable($csf_deny)) {
        $content = file_get_contents($csf_deny);
        $ip_esc = preg_quote($ip, '/');
        if (preg_match('/^' . $ip_esc . '\s+#\s*Fail2Ban\s+' . preg_quote($jail, '/') . '\s+-\s*(.+)$/m', $content, $m)) {
            $domains = trim(preg_replace('/\s+/', ' ', $m[1]));
        }
    }
    if ($domains === '' && is_dir('/usr/local/apache/domlogs')) {
        $files = [];
        @exec("timeout 2 grep -lE '^" . preg_quote($ip, '/') . " ' /usr/local/apache/domlogs/*/* 2>/dev/null", $files);
        $doms = [];
        foreach ($files as $f) {
            $doms[] = preg_replace('/-ssl_log$/', '', basename($f));
        }
        $doms = array_unique($doms);
        $domains = implode(', ', array_slice($doms, 0, 8));
        if (count($doms) > 8) $domains .= '...';
    }
    $cache[$key] = $domains ?: '-';
    return $cache[$key];
}

/** Format remaining ban seconds as "1h 23m 45s" or "23m 43s" */
function format_remaining_ban($seconds) {
    $s = max(0, (int)$seconds);
    if ($s <= 0) return 'expired';
    $parts = [];
    if ($s >= 3600) {
        $parts[] = (int)($s / 3600) . 'h';
        $s %= 3600;
    }
    if ($s >= 60 || !empty($parts)) {
        $parts[] = (int)($s / 60) . 'm';
        $s %= 60;
    }
    $parts[] = $s . 's';
    return implode(' ', $parts);
}

function get_ban_times($jail) {
    $times = [];
    $db = '/var/lib/fail2ban/fail2ban.sqlite3';
    if (!file_exists($db) || !is_readable($db)) return $times;
    $jail_esc = preg_replace('/[^a-zA-Z0-9_-]/', '', $jail);
    $out = [];
    exec("sqlite3 -separator '|' " . escapeshellarg($db) . " \"SELECT ip, datetime(timeofban, 'unixepoch', 'localtime') FROM bips WHERE jail='" . $jail_esc . "'\" 2>/dev/null", $out, $ret);
    if ($ret !== 0) return $times;
    foreach ($out as $line) {
        $p = explode('|', $line, 2);
        if (count($p) === 2) $times[trim($p[0])] = trim($p[1]);
    }
    return $times;
}

function get_ban_epochs($jail) {
    $epochs = [];
    $db = '/var/lib/fail2ban/fail2ban.sqlite3';
    if (!file_exists($db) || !is_readable($db)) return $epochs;
    $jail_esc = preg_replace('/[^a-zA-Z0-9_-]/', '', $jail);
    $out = [];
    exec("sqlite3 -separator '|' " . escapeshellarg($db) . " \"SELECT ip, timeofban FROM bips WHERE jail='" . $jail_esc . "'\" 2>/dev/null", $out, $ret);
    if ($ret !== 0) return $epochs;
    foreach ($out as $line) {
        $p = explode('|', $line, 2);
        if (count($p) === 2) $epochs[trim($p[0])] = (int)trim($p[1]);
    }
    return $epochs;
}

function get_banned_ips_paginated($jail, $page, $per_page, $search, &$total_out) {
    $db = '/var/lib/fail2ban/fail2ban.sqlite3';
    $jail_esc = preg_replace('/[^a-zA-Z0-9_-]/', '', $jail);
    $search = trim(preg_replace('/[^0-9a-fA-F.:]/', '', $search));
    $offset = max(0, ($page - 1) * $per_page);
    $limit = max(1, min(50, (int)$per_page));
    $rows = [];

    if (file_exists($db) && is_readable($db)) {
        $active_sql = " AND (timeofban + bantime) > cast(strftime('%s','now') as integer)";
        $search_sql = ($search !== '') ? " AND ip LIKE '%" . str_replace("'", "''", $search) . "%'" : '';
        $where = "jail='" . $jail_esc . "'" . $active_sql . $search_sql;
        exec("sqlite3 -separator '|' " . escapeshellarg($db) . " \"SELECT COUNT(*) FROM bips WHERE " . $where . "\" 2>/dev/null", $cnt_out, $cnt_ret);
        $total_out = ($cnt_ret === 0 && isset($cnt_out[0])) ? (int)$cnt_out[0] : 0;
        if ($total_out > 0) {
            $out = [];
            exec("sqlite3 -separator '|' " . escapeshellarg($db) . " \"SELECT ip, datetime(timeofban, 'unixepoch', 'localtime'), timeofban, bantime FROM bips WHERE " . $where . " ORDER BY timeofban DESC LIMIT " . (int)$limit . " OFFSET " . (int)$offset . "\" 2>/dev/null", $out, $ret);
            if ($ret === 0) {
                $now = time();
                foreach ($out as $line) {
                    $p = explode('|', $line, 4);
                    if (count($p) >= 4) {
                        $timeofban = (int)trim($p[2]);
                        $bantime = (int)trim($p[3]);
                        $expiry = $timeofban + $bantime;
                        $remaining = max(0, $expiry - $now);
                        $rows[] = ['ip' => trim($p[0]), 'banned_at' => trim($p[1]), 'remaining' => $remaining, 'expiry' => $expiry];
                    }
                }
                return $rows;
            }
        }
    }

    $total_out = 0;
    $d = parse_jail_status($jail);
    $ips = $d['banned_ips'] ?? [];
    if (empty($ips)) return [];
    if ($search !== '') {
        $ips = array_values(array_filter($ips, function($ip) use ($search) { return stripos($ip, $search) !== false; }));
    }
    $total_out = count($ips);
    $epochs = get_ban_epochs($jail);
    $jail_settings = get_jail_settings($jail);
    $bantime = (int)($jail_settings['bantime'] ?? 3600);
    usort($ips, function($a, $b) use ($epochs) {
        $ea = $epochs[$a] ?? 0;
        $eb = $epochs[$b] ?? 0;
        return $eb - $ea;
    });
    $ips = array_slice($ips, $offset, $limit);
    $now = time();
    foreach ($ips as $ip) {
        $banned_at = '-';
        $timeofban = $epochs[$ip] ?? 0;
        if ($timeofban > 0) {
            $banned_at = date('Y-m-d H:i:s', $timeofban);
        }
        $expiry = $timeofban + $bantime;
        $remaining = max(0, $expiry - $now);
        $rows[] = ['ip' => $ip, 'banned_at' => $banned_at, 'remaining' => $remaining, 'expiry' => $expiry];
    }
    return $rows;
}

function cleanup_expired_bips(&$deleted) {
    $db = '/var/lib/fail2ban/fail2ban.sqlite3';
    $deleted = 0;
    if (!file_exists($db) || !is_writable($db)) return false;
    $out = [];
    exec("sqlite3 " . escapeshellarg($db) . " \"DELETE FROM bips WHERE (timeofban + bantime) <= cast(strftime('%s','now') as integer); SELECT changes();\" 2>/dev/null", $out, $ret);
    if ($ret === 0 && isset($out[0]) && is_numeric($out[0])) $deleted = (int)$out[0];
    return true;
}

function get_bans_last_24h() {
    $db = '/var/lib/fail2ban/fail2ban.sqlite3';
    $result = [];
    if (!file_exists($db) || !is_readable($db)) return $result;
    $out = [];
    exec("sqlite3 -separator '|' " . escapeshellarg($db) . " \"SELECT jail, count(*) FROM bans WHERE timeofban > strftime('%s','now') - 86400 GROUP BY jail\" 2>/dev/null", $out, $ret);
    if ($ret !== 0) return $result;
    foreach ($out as $line) {
        $p = explode('|', $line, 2);
        if (count($p) === 2) $result[trim($p[0])] = (int)trim($p[1]);
    }
    return $result;
}

function get_current_loglevel() {
    $path = '/etc/fail2ban/fail2ban.d/loglevel-verbose.conf';
    if (!is_readable($path)) return 'WARNING';
    $c = file_get_contents($path);
    if (preg_match('/loglevel\s*=\s*(\w+)/', $c, $m)) return strtoupper(trim($m[1]));
    return 'WARNING';
}

function save_loglevel($level) {
    $level = strtoupper(preg_replace('/[^A-Za-z]/', '', $level));
    if (!in_array($level, ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], true)) return false;
    $content = "# Log level override - set via WHM plugin\n[DEFAULT]\nloglevel = $level\n";
    $paths = ['/etc/fail2ban/fail2ban.d/loglevel-verbose.conf'];
    if (is_dir('/usr/share/fail2ban/fail2ban.d')) $paths[] = '/usr/share/fail2ban/fail2ban.d/loglevel-verbose.conf';
    foreach ($paths as $p) {
        $dir = dirname($p);
        if (is_dir($dir) && is_writable($dir)) file_put_contents($p, $content);
    }
    return true;
}

function get_jail_settings($jail) {
    $jail = preg_replace('/[^a-zA-Z0-9_-]/', '', $jail);
    $paths = ['/usr/share/fail2ban/jail.d/' . $jail . '.conf', '/etc/fail2ban/jail.d/' . $jail . '.conf'];
    foreach ($paths as $p) {
        if (!is_readable($p)) continue;
        $text = file_get_contents($p);
        if (preg_match('/maxretry\s*=\s*(\d+)/', $text, $m1) && preg_match('/findtime\s*=\s*(\d+)/', $text, $m2) && preg_match('/bantime\s*=\s*(\d+)/', $text, $m3)) {
            return ['maxretry' => (int)$m1[1], 'findtime' => (int)$m2[1], 'bantime' => (int)$m3[1]];
        }
    }
    return ['maxretry' => 5, 'findtime' => 300, 'bantime' => 3600];
}

function save_jail_settings($jail, $maxretry, $findtime, $bantime) {
    $jail = preg_replace('/[^a-zA-Z0-9_-]/', '', $jail);
    $maxretry = max(1, min(10000, (int)$maxretry));
    $findtime = max(60, min(86400 * 30, (int)$findtime));
    $bantime = max(60, min(86400 * 365, (int)$bantime));
    $path = '/usr/share/fail2ban/jail.d/' . $jail . '.conf';
    if (!file_exists($path) || !is_writable($path)) {
        $path = '/etc/fail2ban/jail.d/' . $jail . '.conf';
    }
    if (!is_readable($path) || !is_writable($path)) return false;
    $content = file_get_contents($path);
    $content = preg_replace('/^maxretry\s*=\s*\d+/m', 'maxretry = ' . $maxretry, $content);
    $content = preg_replace('/^findtime\s*=\s*\d+/m', 'findtime = ' . $findtime, $content);
    $content = preg_replace('/^bantime\s*=\s*\d+/m', 'bantime = ' . $bantime, $content);
    return file_put_contents($path, $content) !== false;
}

function get_useragent_keywords() {
    $conf = '/etc/fail2ban/scripts/useragent-keywords.conf';
    $rows = [];
    if (!file_exists($conf) || !is_readable($conf)) return $rows;
    foreach (file($conf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $parts = array_map('trim', explode('|', $line, 4));
        if (empty($parts[0])) continue;
        $rows[] = [
            'keyword' => $parts[0],
            'maxretry' => max(1, (int)($parts[1] ?? 1)),
            'findtime' => max(60, (int)($parts[2] ?? 60)),
            'bantime' => max(60, (int)($parts[3] ?? 3600))
        ];
    }
    return $rows;
}

function parse_jail_status($jail) {
    $data = ['active' => false, 'currently_failed' => '-', 'total_failed' => '-', 'currently_banned' => '-', 'total_banned' => '-', 'banned_ips' => []];
    exec("fail2ban-client status " . escapeshellarg($jail) . " 2>/dev/null", $out, $ret);
    if ($ret !== 0) return $data;
    $text = implode("\n", $out);
    $data['active'] = true;
    if (preg_match('/Currently failed:\s*(\d+)/', $text, $m)) $data['currently_failed'] = (int)$m[1];
    if (preg_match('/Total failed:\s*(\d+)/', $text, $m)) $data['total_failed'] = (int)$m[1];
    if (preg_match('/Currently banned:\s*(\d+)/', $text, $m)) $data['currently_banned'] = (int)$m[1];
    if (preg_match('/Total banned:\s*(\d+)/', $text, $m)) $data['total_banned'] = (int)$m[1];
    if (preg_match('/Banned IP list:\s*(.+?)(?:\n|$)/s', $text, $m)) {
        $ips = preg_split('/\s+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY);
        $data['banned_ips'] = array_slice($ips, 0, 100);
    }
    if (empty($data['banned_ips']) && $data['currently_banned'] > 0) {
        exec("fail2ban-client get " . escapeshellarg($jail) . " banip 2>/dev/null", $ipout, $ipret);
        if ($ipret === 0 && !empty($ipout[0])) {
            $data['banned_ips'] = array_slice(preg_split('/\s+/', $ipout[0], -1, PREG_SPLIT_NO_EMPTY), 0, 100);
        }
    }
    return $data;
}

if (!checkacl('all')) {
    WHM::header('Fail2Ban Manager - Access Denied', 0, 0);
    echo '<p class="alert alert-danger">Access denied. Root or full reseller privileges required.</p>';
    WHM::footer();
    exit;
}

$msg = '';
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$current_tab = $_GET['tab'] ?? $_POST['tab'] ?? 'dashboard';
$valid_tabs = ['dashboard' => 'Dashboard', 'banned' => 'Banned IPs', 'whitelists' => 'Whitelists', 'notifications' => 'Notifications', 'settings' => 'Settings'];
if (!isset($valid_tabs[$current_tab])) $current_tab = 'dashboard';
$tab_from_action = ['save_ignore_countries' => 'whitelists', 'save_whitelist_ips' => 'whitelists', 'save_blocklist_organizations' => 'whitelists', 'save_email_alerts' => 'notifications', 'save_loglevel' => 'settings', 'deploy' => 'settings', 'update_ip2location' => 'settings', 'save_ip2location_token' => 'settings', 'setup_ip2location_asn' => 'settings', 'unban' => 'banned', 'unban_bulk' => 'banned', 'unban_whitelisted' => 'banned', 'save_jail_settings' => 'settings'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action) {
    if ($action === 'save_ignore_countries') {
        $val = trim($_POST['whitelist_countries'] ?? '');
        $conf = '/etc/fail2ban/scripts/ignore-countries.conf';
        if (file_exists($conf) && is_writable($conf)) {
            $content = "# Countries to exclude from bans (ISO 3166-1 alpha-2 codes, comma-separated)\n# Example: IN = India, US = United States\n# Leave empty to ban all countries\nWHITELIST_COUNTRIES=" . preg_replace('/[^A-Za-z,]/', '', $val) . "\n";
            file_put_contents($conf, $content);
            $msg = 'Ignore countries saved.';
        } else {
            $msg = 'Could not write ignore-countries.conf';
        }
    } elseif ($action === 'save_whitelist_ips') {
        $val = $_POST['whitelist_ips'] ?? '';
        $conf = '/usr/share/fail2ban/whitelist-ips.conf';
        $dir = dirname($conf);
        if (is_dir($dir) || @mkdir($dir, 0755, true)) {
            if (file_put_contents($conf, $val) !== false) {
                if (file_exists('/usr/share/fail2ban/update-whitelist.sh')) {
                    exec('/usr/share/fail2ban/update-whitelist.sh 2>&1', $out, $ret);
                    exec('/usr/share/fail2ban/setup.sh 2>&1', $out2, $ret2);
                }
                $msg = 'Whitelist IPs saved' . (file_exists('/usr/share/fail2ban/setup.sh') ? ' and deployed.' : '.');
            } else {
                $msg = 'Could not write whitelist-ips.conf';
            }
        } else {
            $msg = 'Could not create /usr/share/fail2ban (run install.sh first)';
        }
    } elseif ($action === 'save_blocklist_organizations') {
        $conf = '/etc/fail2ban/scripts/blocklist-organizations.conf';
        $orgs = trim(preg_replace('/[\r\n]+/', ',', $_POST['blocked_organizations'] ?? ''));
        $threshold = max(0, min(20, (int)($_POST['multi_domain_threshold'] ?? 0)));
        $content = "# Blocked organizations - IPs from these orgs/ISPs are ALWAYS banned\n";
        $content .= "# Comma-separated, case-insensitive. Examples: Microsoft, DigitalOcean, Amazon\nBLOCKED_ORGANIZATIONS=" . preg_replace('/[^a-zA-Z0-9,\s.&-]/', '', $orgs) . "\n\n";
        $content .= "# Multi-domain abuse: if IP from whitelisted country hits this many domains, ban anyway\nMULTI_DOMAIN_ABUSE_THRESHOLD=" . $threshold . "\n";
        $dir = dirname($conf);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        if ((file_exists($conf) && is_writable($conf)) || (!file_exists($conf) && is_dir($dir) && is_writable($dir))) {
            if (file_put_contents($conf, $content) !== false) {
                $msg = 'Blocklist and multi-domain threshold saved.';
            } else {
                $msg = 'Could not write blocklist-organizations.conf';
            }
        } else {
            $msg = 'Could not write to /etc/fail2ban/scripts/';
        }
    } elseif ($action === 'save_useragent_keywords') {
        $conf = '/etc/fail2ban/scripts/useragent-keywords.conf';
        $dir = dirname($conf);
        $lines = [];
        $raw = $_POST['useragent_keywords'] ?? '';
        foreach (array_filter(preg_split('/\r?\n/', $raw)) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            $parts = array_map('trim', explode('|', $line, 4));
            if (empty($parts[0])) continue;
            $kw = preg_replace('/[^a-zA-Z0-9\s\-_]/', '', $parts[0]);
            if ($kw === '') continue;
            $maxretry = max(1, min(100, (int)($parts[1] ?? 1)));
            $findtime = max(60, min(86400 * 7, (int)($parts[2] ?? 60)));
            $bantime = max(60, min(86400 * 365, (int)($parts[3] ?? 3600)));
            $lines[] = $kw . '|' . $maxretry . '|' . $findtime . '|' . $bantime;
        }
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        $content = "# User-Agent keyword blocking (keyword|maxretry|findtime|bantime)\n# Examples: python|1|60|3600  headless|2|300|86400\n" . implode("\n", $lines) . "\n";
        if (file_put_contents($conf, $content) !== false) {
            exec('/etc/fail2ban/scripts/update-useragent-jails.sh 2>&1', $out, $ret);
            $msg = $ret === 0 ? 'User-Agent keywords saved and fail2ban reloaded.' : 'Saved but reload failed: ' . implode(' ', $out);
        } else {
            $msg = 'Could not write useragent-keywords.conf';
        }
    } elseif ($action === 'deploy') {
        exec('/usr/share/fail2ban/setup.sh 2>&1', $out, $ret);
        $msg = $ret === 0 ? 'Config deployed and fail2ban restarted.' : 'Deploy failed: ' . implode("\n", $out);
    } elseif ($action === 'unban') {
        $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $_POST['ip'] ?? '');
        $jail = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['jail'] ?? 'wordpress-wp-login');
        if ($ip && $jail) {
            exec("fail2ban-client set $jail unbanip $ip 2>&1", $out, $ret);
            $msg = $ret === 0 ? "Unbanned $ip from $jail" : implode("\n", $out);
        }
    } elseif ($action === 'unban_bulk') {
        $jail = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['jail'] ?? '');
        $ips = is_array($_POST['unban_ips'] ?? null) ? $_POST['unban_ips'] : [];
        $unbanned = 0;
        if ($jail && in_array($jail, $jails) && !empty($ips)) {
            foreach ($ips as $ip) {
                $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $ip);
                if ($ip) {
                    exec("fail2ban-client set $jail unbanip $ip 2>&1", $out, $ret);
                    if ($ret === 0) $unbanned++;
                }
            }
            $msg = $unbanned > 0 ? "Unbanned $unbanned IP(s) from $jail." : "No IPs unbanned.";
        } else {
            $msg = "No IPs selected.";
        }
    } elseif ($action === 'update_ip2location') {
        exec('/etc/fail2ban/scripts/update-ip2location.sh 2>&1', $out, $ret);
        $msg = $ret === 0 ? 'IP2Location database updated.' : 'Update failed: ' . implode("\n", $out);
    } elseif ($action === 'save_ip2location_token') {
        $dir = '/etc/fail2ban/GeoIP';
        $conf = $dir . '/ip2location.conf';
        $token = trim($_POST['ip2location_token'] ?? '');
        $db_dir = '/etc/fail2ban/GeoIP';
        $old_token = '';
        if (file_exists($conf)) {
            $ic = file_get_contents($conf);
            if (preg_match('/IP2LOCATION_DB_DIR=(.+)$/m', $ic, $m)) $db_dir = trim($m[1]);
            if (preg_match('/IP2LOCATION_TOKEN=(.+)$/m', $ic, $m)) $old_token = trim($m[1]);
        }
        if ($token === '' && $old_token !== '') $token = $old_token;
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        if ((file_exists($conf) && is_writable($conf)) || (!file_exists($conf) && is_writable($dir))) {
            $content = "IP2LOCATION_TOKEN=" . preg_replace('/[\r\n]/', '', $token) . "\nIP2LOCATION_DB_DIR=" . preg_replace('/[\r\n]/', '', $db_dir) . "\n";
            if (file_put_contents($conf, $content) !== false) {
                chmod($conf, 0600);
                $msg = 'IP2Location token saved.';
            } else {
                $msg = 'Could not write ip2location.conf';
            }
        } else {
            $msg = 'Could not write to /etc/fail2ban/GeoIP/';
        }
    } elseif ($action === 'setup_ip2location_asn') {
        $script = '/etc/fail2ban/scripts/setup-ip2location-asn.sh';
        if (file_exists($script) && is_executable($script)) {
            exec($script . ' 2>&1', $out, $ret);
            $msg = $ret === 0 ? 'IP2Location ASN database installed.' : 'Setup failed: ' . implode("\n", $out);
        } else {
            $msg = 'setup-ip2location-asn.sh not found. Run setup.sh to deploy.';
        }
    } elseif ($action === 'unban_whitelisted') {
        $unbanned = 0;
        $wl = array_map('trim', array_filter(explode(',', $_POST['whitelist_countries'] ?? 'IN')));
        if (!empty($wl)) {
            foreach (['wordpress-wp-login', 'apache-high-volume'] as $jail) {
                $d = parse_jail_status($jail);
                $country_cache = [];
                foreach ($d['banned_ips'] ?? [] as $ip) {
                    $c = get_ip_country($ip, $country_cache);
                    if (in_array($c, $wl)) {
                        exec("fail2ban-client set " . escapeshellarg($jail) . " unbanip " . escapeshellarg($ip) . " 2>&1", $out, $ret);
                        if ($ret === 0) $unbanned++;
                    }
                }
            }
        }
        $msg = $unbanned > 0 ? "Unbanned $unbanned IP(s) from whitelisted countries." : "No banned IPs found from whitelisted countries.";
    } elseif ($action === 'save_jail_settings') {
        $jail = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['jail'] ?? '');
        if (in_array($jail, ['wordpress-wp-login', 'apache-high-volume'])) {
            $maxretry = (int)($_POST['maxretry'] ?? 5);
            $findtime = (int)($_POST['findtime'] ?? 300);
            $bantime = (int)($_POST['bantime'] ?? 3600);
            if (save_jail_settings($jail, $maxretry, $findtime, $bantime)) {
                exec('/usr/share/fail2ban/setup.sh 2>&1', $out, $ret);
                $msg = $ret === 0 ? "Jail settings saved and fail2ban restarted." : "Settings saved; deploy failed: " . implode("\n", $out);
            } else {
                $msg = "Could not write jail config.";
            }
        } else {
            $msg = "Invalid jail.";
        }
    } elseif ($action === 'save_loglevel') {
        $level = $_POST['loglevel'] ?? 'WARNING';
        if (save_loglevel($level)) {
            exec('/usr/share/fail2ban/setup.sh 2>&1', $out, $ret);
            $msg = $ret === 0 ? "Log level set to $level and fail2ban restarted." : "Log level saved; restart failed: " . implode("\n", $out);
        } else {
            $msg = "Invalid log level.";
        }
    } elseif ($action === 'save_email_alerts') {
        $conf = '/etc/fail2ban/scripts/email-alerts.conf';
        $scripts_dir = '/etc/fail2ban/scripts';
        if (!is_dir($scripts_dir)) @mkdir($scripts_dir, 0755, true);
        $enabled = trim($_POST['email_alerts_enabled'] ?? '') === '1';
        $smtp_host = trim($_POST['smtp_host'] ?? '');
        $smtp_port = (int)($_POST['smtp_port'] ?? 587);
        $smtp_user = trim($_POST['smtp_user'] ?? '');
        $smtp_pass = $_POST['smtp_pass'] ?? '';
        $smtp_secure = in_array($_POST['smtp_secure'] ?? '', ['tls', 'ssl', 'none']) ? $_POST['smtp_secure'] : 'tls';
        $email_from = trim($_POST['email_from'] ?? '');
        $email_to = trim($_POST['email_alerts_to'] ?? '');
        $old_pass = '';
        if (file_exists($conf) && is_readable($conf)) {
            $ec = file_get_contents($conf);
            if (preg_match('/SMTP_PASS=(.+)$/m', $ec, $m)) $old_pass = trim($m[1], " \t\n\r\0\x0B'\"");
        }
        $content = "# Email alerts - configured via WHM (SMTP)\n# Set ENABLED=1 and fill SMTP/EMAIL fields to enable\nENABLED=" . ($enabled ? '1' : '0') . "\n";
        $content .= "SMTP_HOST=" . preg_replace('/[\r\n]/', '', $smtp_host) . "\n";
        $content .= "SMTP_PORT=" . max(1, min(65535, $smtp_port)) . "\n";
        $content .= "SMTP_USER=" . preg_replace('/[\r\n]/', '', $smtp_user) . "\n";
        $pass_val = $smtp_pass !== '' ? $smtp_pass : $old_pass;
        $content .= "SMTP_PASS='" . str_replace("'", "'\"'\"'", $pass_val) . "'\n";
        $content .= "SMTP_SECURE=" . $smtp_secure . "\n";
        $content .= "EMAIL_FROM=" . preg_replace('/[\r\n]/', '', $email_from) . "\n";
        $content .= "EMAIL_TO=" . preg_replace('/[\r\n]/', '', $email_to) . "\n";
        if (file_put_contents($conf, $content) !== false) {
            chmod($conf, 0600);
            $msg = $enabled && $email_to ? "Email alerts (SMTP) saved. Alerts will be sent to $email_to." : ($enabled ? "SMTP config saved. Add recipient email and enable." : "Email alerts disabled.");
        } else {
            $msg = "Could not write email-alerts.conf.";
        }
    }
    if (isset($tab_from_action[$action])) $current_tab = $tab_from_action[$action];
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json; charset=utf-8');
        $err = preg_match('/\b(failed|error|could not|invalid)\b/i', $msg);
        $refresh = in_array($action, ['unban', 'unban_bulk', 'unban_whitelisted']);
        echo json_encode(['ok' => !$err, 'msg' => $msg, 'tab' => $current_tab, 'refresh_banned' => $refresh]);
        exit;
    }
}

$ignore_conf = '/etc/fail2ban/scripts/ignore-countries.conf';
$whitelist_conf = '/usr/share/fail2ban/whitelist-ips.conf';
$ignore_countries = '';
$whitelist_countries_arr = [];
$whitelist_ips = '';
if (file_exists($ignore_conf)) {
    $c = file_get_contents($ignore_conf);
    if (preg_match('/WHITELIST_COUNTRIES=(.*)$/m', $c, $m)) {
        $ignore_countries = trim($m[1]);
        $whitelist_countries_arr = array_map('trim', array_filter(explode(',', $ignore_countries)));
    }
}
if (file_exists($whitelist_conf)) {
    $whitelist_ips = file_get_contents($whitelist_conf);
}
$ip2location_conf = '/etc/fail2ban/GeoIP/ip2location.conf';
$ip2location_token = '';
if (file_exists($ip2location_conf) && is_readable($ip2location_conf)) {
    $ic = file_get_contents($ip2location_conf);
    if (preg_match('/IP2LOCATION_TOKEN=(.+)$/m', $ic, $m)) $ip2location_token = trim($m[1]);
}
$blocklist_conf = '/etc/fail2ban/scripts/blocklist-organizations.conf';
$blocked_organizations = '';
$multi_domain_threshold = 3;
if (file_exists($blocklist_conf) && is_readable($blocklist_conf)) {
    $bc = file_get_contents($blocklist_conf);
    if (preg_match('/BLOCKED_ORGANIZATIONS=(.*)$/m', $bc, $m)) $blocked_organizations = trim($m[1]);
    if (preg_match('/MULTI_DOMAIN_ABUSE_THRESHOLD=\s*(\d+)/', $bc, $m)) $multi_domain_threshold = max(0, min(20, (int)$m[1]));
}

function is_geoip_ready() {
    $mmdb = '/etc/fail2ban/GeoIP/IP2LOCATION-LITE-DB1.mmdb';
    if (!file_exists($mmdb) || !is_readable($mmdb)) return false;
    $out = [];
    exec('mmdblookup -f ' . escapeshellarg($mmdb) . ' -i 8.8.8.8 country iso_code 2>/dev/null', $out, $ret);
    return $ret === 0 && !empty($out);
}

$geoip_ready = is_geoip_ready();
$bans_24h = get_bans_last_24h();
$current_loglevel = get_current_loglevel();
$email_conf = '/etc/fail2ban/scripts/email-alerts.conf';
$email_alerts_enabled = false;
$email_alerts_to = '';
$smtp_host = $smtp_port = $smtp_user = $smtp_secure = $email_from = '';
$smtp_port = 587;
$smtp_secure = 'tls';
if (file_exists($email_conf) && is_readable($email_conf)) {
    $ec = file_get_contents($email_conf);
    $email_alerts_enabled = (bool)preg_match('/ENABLED\s*=\s*1/', $ec);
    if (preg_match('/EMAIL_TO\s*=\s*(.+)$/m', $ec, $m)) $email_alerts_to = trim($m[1]);
    if (preg_match('/SMTP_HOST\s*=\s*(.+)$/m', $ec, $m)) $smtp_host = trim($m[1]);
    if (preg_match('/SMTP_PORT\s*=\s*(\d+)/', $ec, $m)) $smtp_port = max(1, min(65535, (int)$m[1]));
    if (preg_match('/SMTP_USER\s*=\s*(.+)$/m', $ec, $m)) $smtp_user = trim($m[1]);
    if (preg_match('/SMTP_SECURE\s*=\s*(\w+)/', $ec, $m)) $smtp_secure = in_array(strtolower($m[1]), ['tls', 'ssl', 'none']) ? strtolower($m[1]) : 'tls';
    if (preg_match('/EMAIL_FROM\s*=\s*(.+)$/m', $ec, $m)) $email_from = trim($m[1]);
}
$jails = ['wordpress-wp-login', 'apache-high-volume'];
$jail_labels = [
    'wordpress-wp-login' => ['failed' => 'Failed logins', 'failed_total' => 'Total failed logins', 'maxretry' => 'Max failed attempts'],
    'apache-high-volume' => ['failed' => 'Requests in window', 'failed_total' => 'Total requests', 'maxretry' => 'Max requests per IP']
];
foreach (get_useragent_keywords() as $ua) {
    $jid = 'apache-ua-' . trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($ua['keyword'])), '-');
    $jid = $jid !== 'apache-ua-' ? $jid : 'apache-ua-kw';
    $jails[] = $jid;
    $jail_labels[$jid] = ['failed' => 'UA matches', 'failed_total' => 'UA matches', 'maxretry' => 'Max (keyword: ' . $ua['keyword'] . ')'];
}
$jail_data = [];
$jail_settings = [];
foreach ($jails as $j) {
    $jail_data[$j] = parse_jail_status($j);
    $jail_settings[$j] = get_jail_settings($j);
}

// AJAX: get log details for banned IP from bips.data
if (isset($_GET['ajax']) && $_GET['ajax'] === 'ip_log_details' && isset($_GET['ip']) && isset($_GET['jail'])) {
    header('Content-Type: application/json; charset=utf-8');
    $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $_GET['ip']);
    $ajail = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['jail']);
    $matches = [];
    $failures = 0;
    if ($ip && $ajail && in_array($ajail, $jails)) {
        $db = '/var/lib/fail2ban/fail2ban.sqlite3';
        if (file_exists($db) && is_readable($db)) {
            $out = [];
            $ip_esc = str_replace("'", "''", $ip);
            exec("sqlite3 " . escapeshellarg($db) . " \"SELECT data FROM bips WHERE jail='" . $ajail . "' AND ip='" . $ip_esc . "' LIMIT 1\" 2>/dev/null", $out, $ret);
            if ($ret === 0 && !empty($out[0])) {
                $data = @json_decode($out[0], true);
                if (is_array($data)) {
                    $matches = $data['matches'] ?? [];
                    $failures = (int)($data['failures'] ?? 0);
                }
            }
        }
    }
    echo json_encode(['ok' => true, 'ip' => $ip, 'jail' => $ajail, 'matches' => $matches, 'failures' => $failures]);
    exit;
}

// AJAX: cleanup expired bips from DB
if (isset($_GET['ajax']) && $_GET['ajax'] === 'clean_expired_bips') {
    header('Content-Type: application/json; charset=utf-8');
    $deleted = 0;
    $ok = function_exists('checkacl') && checkacl('all') && cleanup_expired_bips($deleted);
    echo json_encode(['ok' => $ok, 'msg' => $ok ? "Removed $deleted expired ban(s) from database." : 'Cleanup failed.', 'deleted' => $deleted]);
    exit;
}

// AJAX handler must run BEFORE WHM::header() so we don't output the full page wrapper
if (isset($_GET['ajax']) && $_GET['ajax'] === 'banned_ips' && isset($_GET['jail'])) {
    $ajail = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['jail']);
    $fs = isset($_GET['fs']) ? '-' . preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['fs']) : '';
    $retab = ($fs === '-tab') ? 'banned' : 'dashboard';
    $page = max(1, (int)($_GET['page'] ?? 1));
    $per_page = max(1, min(50, (int)($_GET['per_page'] ?? 10)));
    $search = trim($_GET['search'] ?? '');
    if (in_array($ajail, $jails)) {
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        $total = 0;
        $ips = get_banned_ips_paginated($ajail, $page, $per_page, $search, $total);
        $country_cache = [];
        $domain_cache = [];
        $org_cache = [];
        $form_id = 'bulk-unban-' . $ajail . $fs;
        $total_pages = $total > 0 ? (int)ceil($total / $per_page) : 0;
        $container_id = 'banned-ips-' . $ajail . $fs;
        echo '<div class="banned-ips-ajax" data-jail="' . htmlspecialchars($ajail) . '" data-container="' . htmlspecialchars($container_id) . '">';
        echo '<form class="form-inline banned-ip-search" style="margin-bottom:10px;"><input type="text" class="form-control input-sm banned-ip-search-input" placeholder="Search IP (type to filter)..." value="' . htmlspecialchars($search) . '" style="width:200px;" data-jail="' . htmlspecialchars($ajail) . '"><button type="submit" class="btn btn-default btn-sm" style="margin-left:6px;">Search</button></form>';
        if (!empty($ips)) {
            echo '<table class="table table-bordered table-striped table-condensed banned-ips-table"><thead><tr><th><input type="checkbox" class="select-all-banned" data-jail="' . htmlspecialchars($ajail) . '" data-container="' . htmlspecialchars($container_id) . '" title="Select all"></th><th>#</th><th>IP Address</th><th>Country</th><th>Organization</th><th>Affected Domains</th><th>Banned At</th><th>Time Left</th><th>Action</th></tr></thead><tbody>';
            foreach ($ips as $i => $row) {
                $ip = $row['ip'];
                $banned_at = $row['banned_at'] ?? '-';
                $remaining = isset($row['remaining']) ? format_remaining_ban($row['remaining']) : '-';
                $expiry = isset($row['expiry']) ? (int)$row['expiry'] : 0;
                $country = get_ip_country($ip, $country_cache);
                $org = get_ip_org($ip, $org_cache);
                $affected = get_affected_domains($ip, $ajail, $domain_cache);
                $is_whitelisted = in_array($country, $whitelist_countries_arr);
                $rowClass = $is_whitelisted ? ' class="warning" style="background:var(--accent-01,#fff3cd)"' : '';
                $wlLabel = $is_whitelisted ? ' <span class="label label-warning">whitelisted</span>' : '';
                $rowNum = ($page - 1) * $per_page + $i + 1;
                $timeLeftAttr = $expiry > 0 ? ' data-expiry="' . $expiry . '" data-remaining="' . (int)($row['remaining'] ?? 0) . '"' : '';
                echo '<tr' . $rowClass . '><td><input type="checkbox" class="banned-ip-cb" name="unban_ips[]" value="' . htmlspecialchars($ip) . '" form="' . htmlspecialchars($form_id) . '"></td><td>' . $rowNum . '</td><td><a href="#" class="ip-log-detail" data-ip="' . htmlspecialchars($ip) . '" data-jail="' . htmlspecialchars($ajail) . '" title="Click to view log details">' . htmlspecialchars($ip) . '</a></td><td>' . htmlspecialchars($country) . $wlLabel . '</td><td style="max-width:150px;font-size:11px;" title="' . htmlspecialchars($org) . '">' . htmlspecialchars($org) . '</td><td style="max-width:200px;font-size:11px;" title="' . htmlspecialchars($affected) . '">' . htmlspecialchars($affected) . '</td><td>' . htmlspecialchars($banned_at) . '</td><td class="ban-time-left"' . $timeLeftAttr . '>' . htmlspecialchars($remaining) . '</td><td><form method="post" style="display:inline;margin:0;"><input type="hidden" name="action" value="unban"><input type="hidden" name="tab" value="' . htmlspecialchars($retab) . '"><input type="hidden" name="jail" value="' . htmlspecialchars($ajail) . '"><input type="hidden" name="ip" value="' . htmlspecialchars($ip) . '"><button type="submit" class="btn btn-default btn-xs">Unban</button></form></td></tr>';
            }
            echo '</tbody></table><form id="' . htmlspecialchars($form_id) . '" method="post" style="margin-top:6px;"><input type="hidden" name="action" value="unban_bulk"><input type="hidden" name="tab" value="' . htmlspecialchars($retab) . '"><input type="hidden" name="jail" value="' . htmlspecialchars($ajail) . '"><button type="submit" class="btn btn-warning btn-sm bulk-unban-btn" disabled>Unban selected</button></form>';
            if ($total_pages > 1) {
                echo '<nav style="margin-top:10px;"><ul class="pagination pagination-sm banned-pagination">';
                echo '<li' . ($page <= 1 ? ' class="disabled"' : '') . '><a href="#" class="banned-page-link" data-page="' . max(1, $page - 1) . '">&laquo;</a></li>';
                $start = max(1, $page - 2);
                $end = min($total_pages, $page + 2);
                for ($p = $start; $p <= $end; $p++) {
                    echo '<li' . ($p === $page ? ' class="active"' : '') . '><a href="#" class="banned-page-link" data-page="' . $p . '">' . $p . '</a></li>';
                }
                echo '<li' . ($page >= $total_pages ? ' class="disabled"' : '') . '><a href="#" class="banned-page-link" data-page="' . min($total_pages, $page + 1) . '">&raquo;</a></li>';
                echo '</ul><span class="text-muted" style="margin-left:10px;">Page ' . $page . ' of ' . $total_pages . ' (' . $total . ' total)</span></nav>';
            }
        } else {
            echo '<p class="text-muted">' . ($search !== '' ? 'No matching IPs.' : 'No banned IPs.') . '</p>';
        }
        echo '</div>';
        exit;
    }
}

WHM::header('Fail2Ban Manager', 0, 0);

exec('fail2ban-client status 2>/dev/null', $gen_out, $gen_ret);
$general_status = $gen_ret === 0 ? implode("\n", array_slice($gen_out, 0, 15)) : 'fail2ban not running';

?>
<link rel="icon" type="image/png" href="fail2ban_manager.png">

<?php
$script_path = $_SERVER['SCRIPT_NAME'] ?? '/cgi/fail2ban_manager/index.php';
$home_url = dirname(dirname($script_path)) . '/';
if ($home_url === '//' || $home_url === './') $home_url = '../../';
?>
<ol class="breadcrumb">
  <li><a href="<?php echo htmlspecialchars($home_url); ?>">Home</a></li>
  <li><a href="<?php echo htmlspecialchars($home_url); ?>">Plugins</a></li>
  <li class="active">Fail2Ban Manager</li>
</ol>

<div id="fail2ban-msg" class="alert alert-info" style="display:<?php echo $msg ? 'block' : 'none'; ?>;"><?php echo $msg ? htmlspecialchars($msg) : ''; ?></div>
<div id="fail2ban-loading" class="fail2ban-loading-overlay" style="display:none;"><span class="fail2ban-spinner"></span><span>Processing...</span></div>
<div id="ip-log-modal-backdrop" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:2147483646;"></div>
<div id="ip-log-modal" tabindex="-1" role="dialog" style="display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:90%;max-width:900px;max-height:80vh;background:#fff;border-radius:4px;box-shadow:0 4px 20px rgba(0,0,0,0.5);z-index:2147483647;overflow:hidden;border:1px solid #ccc;"><div style="padding:15px;border-bottom:1px solid #ddd;display:flex;justify-content:space-between;align-items:center;"><h4 style="margin:0;">Log entries for <code id="ip-log-modal-ip"></code> (<span id="ip-log-modal-jail"></span>)</h4><button type="button" class="btn btn-default btn-sm ip-log-modal-close">&times;</button></div><div style="padding:15px;overflow:auto;max-height:400px;"><p class="text-muted" id="ip-log-modal-loading">Loading...</p><pre id="ip-log-modal-body" style="display:none;font-size:11px;white-space:pre-wrap;word-break:break-all;"></pre><p class="text-muted" id="ip-log-modal-empty" style="display:none;">No log entries in database for this IP.</p></div><div style="padding:15px;border-top:1px solid #ddd;"><button type="button" class="btn btn-default btn-sm ip-log-modal-close">Close</button></div></div>
<?php if (!$geoip_ready): ?>
<p class="alert alert-warning">
  <strong>GeoIP not configured.</strong> Country lookup uses ip-api.com (rate-limited). For better reliability, run <code>/etc/fail2ban/scripts/setup-ip2location.sh</code> as root. Use "Update IP2Location DB" in the Settings tab to refresh after setup.
</p>
<?php endif; ?>

<div class="fail2ban-manager">
<ul class="nav nav-tabs" role="tablist" style="margin-bottom:15px;">
  <?php foreach ($valid_tabs as $tid => $tlabel): ?>
  <li role="presentation" class="<?php echo $current_tab === $tid ? 'active' : ''; ?>">
    <a href="?tab=<?php echo urlencode($tid); ?>" aria-controls="tab-<?php echo htmlspecialchars($tid); ?>" role="tab"><?php echo htmlspecialchars($tlabel); ?></a>
  </li>
  <?php endforeach; ?>
</ul>

<div class="tab-content">
<!-- Tab: Dashboard (overview only - no duplication) -->
<div role="tabpanel" class="tab-pane <?php echo $current_tab === 'dashboard' ? 'active' : ''; ?>" id="tab-dashboard">
<div class="panel panel-default">
  <div class="panel-heading">Status</div>
  <div class="panel-body">
    <?php $total_24h = array_sum($bans_24h); if ($total_24h > 0): $parts = []; foreach ($jails as $j) { $c = $bans_24h[$j] ?? 0; if ($c > 0) $parts[] = htmlspecialchars($j) . ': ' . $c; } ?>
    <p class="text-muted"><strong>Last 24h bans:</strong> <?php echo implode(', ', $parts); ?> — total <?php echo $total_24h; ?></p>
    <?php endif; ?>
    <pre style="background:var(--base-02,#f5f5f5);padding:10px;font-size:12px;margin:0;"><?php echo htmlspecialchars($general_status); ?></pre>
  </div>
</div>
<div class="panel panel-default">
  <div class="panel-heading">Jail Summary</div>
  <div class="panel-body">
    <table class="table table-bordered table-striped table-condensed" style="max-width:500px;">
      <thead><tr><th>Jail</th><th>Currently Banned</th><th>Total Banned</th></tr></thead>
      <tbody>
      <?php foreach ($jails as $j): $d = $jail_data[$j]; ?>
        <tr>
          <td><?php echo htmlspecialchars($j); ?></td>
          <td><?php echo htmlspecialchars($d['currently_banned']); ?></td>
          <td><?php echo htmlspecialchars($d['total_banned']); ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <p style="margin-top:12px;"><a href="?tab=banned" class="btn btn-primary btn-sm">Manage Banned IPs</a></p>
  </div>
</div>
</div>

<!-- Tab: Banned IPs -->
<div role="tabpanel" class="tab-pane <?php echo $current_tab === 'banned' ? 'active' : ''; ?>" id="tab-banned">
<?php if (!empty($whitelist_countries_arr)): ?>
<div class="panel panel-warning" style="margin-bottom:15px;">
  <div class="panel-heading">Whitelisted countries: <?php echo htmlspecialchars($ignore_countries); ?></div>
  <div class="panel-body">
    <p class="text-muted">IPs from these countries may appear if banned before the whitelist was added.</p>
    <form method="post">
      <input type="hidden" name="action" value="unban_whitelisted">
      <input type="hidden" name="tab" value="banned">
      <input type="hidden" name="whitelist_countries" value="<?php echo htmlspecialchars($ignore_countries); ?>">
      <button type="submit" class="btn btn-warning">Unban all from whitelisted countries</button>
    </form>
  </div>
</div>
<?php endif; ?>
<div class="panel panel-default" style="margin-bottom:15px;">
  <div class="panel-body">
    <button type="button" class="btn btn-default btn-sm clean-expired-bips" title="Remove expired ban records from fail2ban database">
      <span class="glyphicon glyphicon-trash"></span> Clean expired from database
    </button>
    <span class="text-muted" style="margin-left:8px;font-size:12px;">Removes IPs whose ban period has ended.</span>
  </div>
</div>
<?php foreach ($jails as $j): ?>
<div class="panel panel-default">
  <div class="panel-heading"><?php echo htmlspecialchars($j); ?> — Banned IPs</div>
  <div class="panel-body">
    <p><strong>Banned IPs:</strong>
      <button type="button" class="btn btn-link reload-banned-ips" data-jail="<?php echo htmlspecialchars($j); ?>" title="Refresh"><span class="glyphicon glyphicon-refresh"></span></button>
    </p>
    <div id="banned-ips-<?php echo htmlspecialchars($j); ?>-tab" class="banned-ips-container">
      <p class="text-muted">Loading...</p>
    </div>
    <form method="post" class="form-inline" style="margin-top:8px;">
      <input type="hidden" name="action" value="unban">
      <input type="hidden" name="tab" value="banned">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <input type="text" name="ip" placeholder="IP to unban" class="form-control input-sm" style="width:150px;">
      <button type="submit" class="btn btn-default btn-sm">Unban</button>
    </form>
  </div>
</div>
<?php endforeach; ?>
</div>

<!-- Tab: Whitelists -->
<div role="tabpanel" class="tab-pane <?php echo $current_tab === 'whitelists' ? 'active' : ''; ?>" id="tab-whitelists">
<div class="row">
  <div class="col-md-6">
    <div class="panel panel-default">
      <div class="panel-heading">Ignore Countries</div>
      <div class="panel-body">
        <p class="text-muted">ISO codes (e.g. IN,US,GB). IPs from these countries are never banned.</p>
        <form method="post">
          <input type="hidden" name="action" value="save_ignore_countries">
          <input type="hidden" name="tab" value="whitelists">
          <input type="text" name="whitelist_countries" value="<?php echo htmlspecialchars($ignore_countries); ?>" class="form-control" placeholder="IN,US,GB">
          <button type="submit" class="btn btn-primary btn-sm" style="margin-top:8px;">Save</button>
        </form>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="panel panel-default">
      <div class="panel-heading">Whitelist IPs</div>
      <div class="panel-body">
        <p class="text-muted">IPs/CIDRs excluded from bans. One per line.</p>
        <form method="post">
          <input type="hidden" name="action" value="save_whitelist_ips">
          <input type="hidden" name="tab" value="whitelists">
          <textarea name="whitelist_ips" class="form-control" rows="8" style="font-family:monospace;font-size:12px;"><?php echo htmlspecialchars($whitelist_ips); ?></textarea>
          <button type="submit" class="btn btn-primary btn-sm" style="margin-top:8px;">Save &amp; Deploy</button>
        </form>
      </div>
    </div>
  </div>
</div>
<div class="row" style="margin-top:15px;">
  <div class="col-md-12">
    <div class="panel panel-default">
      <div class="panel-heading">Blocked Organizations &amp; Multi-Domain Abuse</div>
      <div class="panel-body">
        <p class="text-muted">IPs from blocked orgs (e.g. Microsoft, DigitalOcean) are always banned, even from whitelisted countries. If an IP from a whitelisted country hits many domains in short time, it is also banned.</p>
        <form method="post">
          <input type="hidden" name="action" value="save_blocklist_organizations">
          <input type="hidden" name="tab" value="whitelists">
          <div class="form-group">
            <label>Blocked organizations (comma-separated)</label>
            <input type="text" name="blocked_organizations" value="<?php echo htmlspecialchars($blocked_organizations); ?>" class="form-control" placeholder="Microsoft, DigitalOcean, Amazon" style="max-width:500px;">
          </div>
          <div class="form-group">
            <label>Multi-domain abuse threshold</label>
            <input type="number" name="multi_domain_threshold" value="<?php echo (int)$multi_domain_threshold; ?>" min="0" max="20" class="form-control" style="width:80px;" title="Ban whitelisted-country IPs that hit this many domains">
            <span class="text-muted" style="margin-left:8px;">(0 = disabled)</span>
          </div>
          <button type="submit" class="btn btn-primary btn-sm">Save</button>
        </form>
      </div>
    </div>
  </div>
</div>
</div>

<!-- Tab: Notifications -->
<div role="tabpanel" class="tab-pane <?php echo $current_tab === 'notifications' ? 'active' : ''; ?>" id="tab-notifications">
<div class="panel panel-default" style="max-width:500px;">
  <div class="panel-heading">Email Alerts</div>
  <div class="panel-body">
    <p class="text-muted">Receive email when an IP is banned. Uses SMTP.</p>
    <form method="post">
      <input type="hidden" name="action" value="save_email_alerts">
      <input type="hidden" name="tab" value="notifications">
      <div class="form-group">
        <label class="checkbox-inline"><input type="checkbox" name="email_alerts_enabled" value="1"<?php echo $email_alerts_enabled ? ' checked' : ''; ?>> Enable</label>
      </div>
      <div class="form-group">
        <label>SMTP Host</label>
        <input type="text" name="smtp_host" value="<?php echo htmlspecialchars($smtp_host); ?>" class="form-control" placeholder="smtp.example.com">
      </div>
      <div class="form-group form-inline">
        <label>Port</label>
        <input type="number" name="smtp_port" value="<?php echo (int)$smtp_port; ?>" min="1" max="65535" class="form-control" style="width:80px;"> 
        <select name="smtp_secure" class="form-control" style="width:90px;margin-left:8px;">
          <option value="none"<?php echo $smtp_secure === 'none' ? ' selected' : ''; ?>>None</option>
          <option value="tls"<?php echo $smtp_secure === 'tls' ? ' selected' : ''; ?>>TLS</option>
          <option value="ssl"<?php echo $smtp_secure === 'ssl' ? ' selected' : ''; ?>>SSL</option>
        </select>
      </div>
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="smtp_user" value="<?php echo htmlspecialchars($smtp_user); ?>" class="form-control" placeholder="user@example.com">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="smtp_pass" value="" class="form-control" placeholder="Leave blank to keep current" autocomplete="new-password">
      </div>
      <div class="form-group">
        <label>From address</label>
        <input type="email" name="email_from" value="<?php echo htmlspecialchars($email_from); ?>" class="form-control" placeholder="noreply@example.com">
      </div>
      <div class="form-group">
        <label>Recipient (To)</label>
        <input type="email" name="email_alerts_to" value="<?php echo htmlspecialchars($email_alerts_to); ?>" class="form-control" placeholder="admin@example.com">
      </div>
      <button type="submit" class="btn btn-primary">Save</button>
    </form>
  </div>
</div>
</div>

<!-- Tab: Settings (all configuration - single place) -->
<div role="tabpanel" class="tab-pane <?php echo $current_tab === 'settings' ? 'active' : ''; ?>" id="tab-settings">
<div class="panel panel-default">
  <div class="panel-heading">User-Agent Keyword Blocking</div>
  <div class="panel-body">
    <p class="text-muted">Block IPs when their User-Agent contains these keywords (e.g. python, headless, curl). Each keyword has its own max requests, time window, and ban duration. Format: <code>keyword|maxretry|findtime|bantime</code> (one per line).</p>
    <form method="post">
      <input type="hidden" name="action" value="save_useragent_keywords">
      <input type="hidden" name="tab" value="settings">
      <textarea name="useragent_keywords" class="form-control" rows="8" style="font-family:monospace;font-size:12px;" placeholder="python|1|60|3600"><?php
$ua_lines = [];
foreach (get_useragent_keywords() as $u) {
    $ua_lines[] = $u['keyword'] . '|' . $u['maxretry'] . '|' . $u['findtime'] . '|' . $u['bantime'];
}
echo htmlspecialchars(implode("\n", $ua_lines));
      ?></textarea>
      <p class="text-muted" style="margin-top:6px;font-size:12px;">Example: <code>python|1|60|3600</code> = ban after 1 match in 60 sec, for 1 hour. <code>headless|2|300|86400</code> = 2 matches in 5 min, ban 24h.</p>
      <button type="submit" class="btn btn-primary btn-sm" style="margin-top:6px;">Save &amp; Apply</button>
    </form>
  </div>
</div>
<?php foreach ($jails as $j):
$js = $jail_settings[$j] ?? ['maxretry' => 5, 'findtime' => 300, 'bantime' => 3600];
if (strpos($j, 'apache-ua-') === 0) continue;
?>
<div class="panel panel-default">
  <div class="panel-heading">Jail: <?php echo htmlspecialchars($j); ?></div>
  <div class="panel-body">
    <form method="post" class="form-inline jail-settings-form" data-maxretry-min="1" data-maxretry-max="10000" data-findtime-min="60" data-findtime-max="2592000" data-bantime-min="60" data-bantime-max="31536000">
      <input type="hidden" name="action" value="save_jail_settings">
      <input type="hidden" name="tab" value="settings">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <label><?php echo htmlspecialchars(($jail_labels[$j]['maxretry'] ?? 'maxretry')); ?></label>
      <input type="number" name="maxretry" value="<?php echo (int)$js['maxretry']; ?>" min="1" max="10000" class="form-control input-sm" style="width:70px;margin:0 8px 0 4px;" title="Internal: maxretry" required>
      <label style="margin-left:8px;">findtime</label>
      <input type="number" name="findtime" value="<?php echo (int)$js['findtime']; ?>" min="60" max="2592000" class="form-control input-sm" style="width:80px;" required>
      <select class="form-control input-sm findtime-preset" style="width:auto;margin-left:4px;"><option value="">preset</option><option value="60">1m</option><option value="300">5m</option><option value="600">10m</option><option value="3600">1h</option></select>
      <label style="margin-left:8px;">bantime</label>
      <input type="number" name="bantime" value="<?php echo (int)$js['bantime']; ?>" min="60" max="31536000" class="form-control input-sm" style="width:80px;" required>
      <select class="form-control input-sm bantime-preset" style="width:auto;margin-left:4px;"><option value="">preset</option><option value="300">5m</option><option value="3600">1h</option><option value="86400">24h</option><option value="604800">1w</option></select>
      <button type="submit" class="btn btn-primary btn-sm" style="margin-left:8px;">Save &amp; Deploy</button>
      <span class="jail-settings-err text-danger" style="margin-left:8px;display:none;"></span>
    </form>
  </div>
</div>
<?php endforeach; ?>
<div class="row">
  <div class="col-md-6">
    <div class="panel panel-default">
      <div class="panel-heading">Log Level</div>
      <div class="panel-body">
        <form method="post" class="form-inline">
          <input type="hidden" name="action" value="save_loglevel">
          <input type="hidden" name="tab" value="settings">
          <select name="loglevel" class="form-control">
            <option value="DEBUG"<?php echo $current_loglevel === 'DEBUG' ? ' selected' : ''; ?>>DEBUG</option>
            <option value="INFO"<?php echo $current_loglevel === 'INFO' ? ' selected' : ''; ?>>INFO</option>
            <option value="WARNING"<?php echo $current_loglevel === 'WARNING' ? ' selected' : ''; ?>>WARNING</option>
            <option value="ERROR"<?php echo $current_loglevel === 'ERROR' ? ' selected' : ''; ?>>ERROR</option>
            <option value="CRITICAL"<?php echo $current_loglevel === 'CRITICAL' ? ' selected' : ''; ?>>CRITICAL</option>
          </select>
          <button type="submit" class="btn btn-primary" style="margin-left:8px;">Apply</button>
        </form>
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="panel panel-default">
      <div class="panel-heading">Actions</div>
      <div class="panel-body">
        <form method="post" style="margin-bottom:8px;">
          <input type="hidden" name="action" value="deploy">
          <input type="hidden" name="tab" value="settings">
          <button type="submit" class="btn btn-primary btn-block">Deploy config &amp; restart</button>
        </form>
        <form method="post" style="margin-bottom:8px;">
          <input type="hidden" name="action" value="update_ip2location">
          <input type="hidden" name="tab" value="settings">
          <button type="submit" class="btn btn-default btn-block">Update IP2Location DB (country)</button>
        </form>
        <form method="post">
          <input type="hidden" name="action" value="setup_ip2location_asn">
          <input type="hidden" name="tab" value="settings">
          <button type="submit" class="btn btn-default btn-block">Run IP2Location ASN setup</button>
        </form>
      </div>
    </div>
  </div>
</div>
<div class="row" style="margin-top:15px;">
  <div class="col-md-12">
    <div class="panel panel-default">
      <div class="panel-heading">IP2Location Token</div>
      <div class="panel-body">
        <p class="text-muted">Token for IP2Location LITE downloads (country + ASN). Get a free token at <a href="https://lite.ip2location.com" target="_blank" rel="noopener">lite.ip2location.com</a>.</p>
        <form method="post">
          <input type="hidden" name="action" value="save_ip2location_token">
          <input type="hidden" name="tab" value="settings">
          <div class="form-group">
            <label>IP2Location token</label>
            <input type="text" name="ip2location_token" value="<?php echo htmlspecialchars($ip2location_token); ?>" class="form-control" placeholder="Your token" style="max-width:400px;">
          </div>
          <button type="submit" class="btn btn-primary btn-sm">Save token</button>
        </form>
      </div>
    </div>
  </div>
</div>
<?php if (!$geoip_ready): ?>
<div class="panel panel-warning" style="margin-top:15px;">
  <div class="panel-heading">GeoIP Setup</div>
  <div class="panel-body">
    <p>Country lookup uses ip-api.com (rate-limited). For better reliability, run:</p>
    <pre style="margin:0;">/etc/fail2ban/scripts/setup-ip2location.sh</pre>
    <p class="text-muted" style="margin-top:8px;">Use "Update IP2Location DB" above to refresh after setup.</p>
  </div>
</div>
<?php endif; ?>
</div>

</div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
  var base = (window.location.href || '').split('?')[0];
  var jails = <?php echo json_encode($jails); ?>;

  (function() {
    var modal = document.getElementById('ip-log-modal');
    var backdrop = document.getElementById('ip-log-modal-backdrop');
    if (modal && backdrop && document.body) {
      document.body.appendChild(backdrop);
      document.body.appendChild(modal);
    }
  })();

  function closeIpLogModal() {
    var m = document.getElementById('ip-log-modal');
    var b = document.getElementById('ip-log-modal-backdrop');
    if (m) m.style.display = 'none';
    if (b) b.style.display = 'none';
  }
  document.addEventListener('click', function(e) {
    if (e.target.closest('.ip-log-modal-close') || e.target.id === 'ip-log-modal-backdrop') {
      closeIpLogModal();
    }
  });

  function showMsg(msg, isErr) {
    var el = document.getElementById('fail2ban-msg');
    if (!el) return;
    el.textContent = msg;
    el.className = 'alert alert-' + (isErr ? 'danger' : 'info');
    el.style.display = 'block';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    setTimeout(function() { el.style.display = 'none'; }, 5000);
  }

  var bannedPageState = {};
  jails.forEach(function(j) { bannedPageState[j] = { page: 1, search: '' }; });

  function loadBannedIps(jail, page, search, onDone) {
    var container = document.getElementById('banned-ips-' + jail + '-tab');
    if (!container) return;
    page = page || 1;
    search = (search !== undefined && search !== null) ? String(search) : '';
    if (bannedPageState[jail]) bannedPageState[jail] = { page: page, search: search };
    var url = base + '?ajax=banned_ips&jail=' + encodeURIComponent(jail) + '&fs=tab&page=' + page + '&per_page=10';
    if (search) url += '&search=' + encodeURIComponent(search);
    container.innerHTML = '<p class="text-muted">Loading...</p>';
    fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(function(r) { return r.text(); })
      .then(function(html) {
        if (html && html.length < 100000 && html.indexOf('</html>') === -1) {
          container.innerHTML = html;
          if (typeof updateBanTimeLeft === 'function') updateBanTimeLeft();
        }
      })
      .catch(function() { container.innerHTML = '<p class="text-danger">Failed to load.</p>'; })
      .finally(function() { if (typeof onDone === 'function') onDone(); });
  }

  function refreshBannedIps() {
    jails.forEach(function(jail) { loadBannedIps(jail, bannedPageState[jail] ? bannedPageState[jail].page : 1, bannedPageState[jail] ? bannedPageState[jail].search : ''); });
  }

  function formatRemainingBan(sec) {
    sec = Math.max(0, Math.floor(sec));
    if (sec <= 0) return 'expired';
    var parts = [];
    if (sec >= 3600) { parts.push(Math.floor(sec / 3600) + 'h'); sec %= 3600; }
    if (sec >= 60 || parts.length) { parts.push(Math.floor(sec / 60) + 'm'); sec %= 60; }
    parts.push(sec + 's');
    return parts.join(' ');
  }
  function updateBanTimeLeft() {
    var now = Math.floor(Date.now() / 1000);
    document.querySelectorAll('.ban-time-left[data-expiry]').forEach(function(el) {
      var expiry = parseInt(el.getAttribute('data-expiry'), 10);
      if (isNaN(expiry)) return;
      var remaining = expiry - now;
      el.textContent = formatRemainingBan(remaining);
      if (remaining <= 0) el.removeAttribute('data-expiry');
    });
  }
  setInterval(updateBanTimeLeft, 1000);
  updateBanTimeLeft();

  function ensureBannedLoaded() {
    var pane = document.getElementById('tab-banned');
    if (pane && pane.classList.contains('active')) {
      jails.forEach(function(jail) {
        var c = document.getElementById('banned-ips-' + jail + '-tab');
        if (c && c.textContent.indexOf('Loading...') >= 0) loadBannedIps(jail, 1, '');
      });
    }
  }

  document.addEventListener('click', function(e) {
    var ipLink = e.target.closest('.ip-log-detail');
    if (ipLink) {
      e.preventDefault();
      var ip = ipLink.getAttribute('data-ip');
      var jail = ipLink.getAttribute('data-jail');
      if (!ip || !jail) return;
      var modal = document.getElementById('ip-log-modal');
      var backdrop = document.getElementById('ip-log-modal-backdrop');
      var loadingEl = document.getElementById('ip-log-modal-loading');
      var bodyEl = document.getElementById('ip-log-modal-body');
      var emptyEl = document.getElementById('ip-log-modal-empty');
      var ipEl = document.getElementById('ip-log-modal-ip');
      var jailEl = document.getElementById('ip-log-modal-jail');
      if (modal && ipEl && jailEl) {
        ipEl.textContent = ip;
        jailEl.textContent = jail;
        loadingEl.style.display = 'block';
        bodyEl.style.display = 'none';
        emptyEl.style.display = 'none';
        modal.style.display = 'block';
        if (backdrop) backdrop.style.display = 'block';
        fetch(base + '?ajax=ip_log_details&ip=' + encodeURIComponent(ip) + '&jail=' + encodeURIComponent(jail), { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            loadingEl.style.display = 'none';
            var matches = data.matches || [];
            var failures = data.failures || 0;
            if (matches.length > 0) {
              bodyEl.textContent = (failures ? 'Failures: ' + failures + '\n\n' : '') + matches.join('\n');
              bodyEl.style.display = 'block';
            } else {
              emptyEl.style.display = 'block';
            }
          })
          .catch(function() {
            loadingEl.style.display = 'none';
            emptyEl.textContent = 'Failed to load log details.';
            emptyEl.style.display = 'block';
          });
      }
      return;
    }
    var pg = e.target.closest('.banned-page-link');
    if (pg && !pg.closest('li.disabled')) {
      e.preventDefault();
      var page = parseInt(pg.getAttribute('data-page'), 10);
      var wrap = e.target.closest('.banned-ips-ajax');
      if (wrap) {
        var jail = wrap.getAttribute('data-jail');
        var inp = wrap.querySelector('.banned-ip-search-input');
        loadBannedIps(jail, page, inp ? inp.value : '');
      }
    }
  });

  var searchDebounce = {};
  document.addEventListener('input', function(e) {
    if (e.target.classList && e.target.classList.contains('banned-ip-search-input')) {
      var inp = e.target;
      var jail = inp.closest('.banned-ips-ajax') ? inp.closest('.banned-ips-ajax').getAttribute('data-jail') : inp.getAttribute('data-jail');
      if (!jail) return;
      clearTimeout(searchDebounce[jail]);
      searchDebounce[jail] = setTimeout(function() {
        loadBannedIps(jail, 1, inp.value);
      }, 350);
    }
  });

  document.addEventListener('submit', function(e) {
    if (e.target.classList && e.target.classList.contains('banned-ip-search')) {
      e.preventDefault();
      e.stopImmediatePropagation();
      var inp = e.target.querySelector('.banned-ip-search-input');
      var wrap = e.target.closest('.banned-ips-ajax');
      if (wrap && inp) loadBannedIps(wrap.getAttribute('data-jail'), 1, inp.value);
    }
  }, true);

  // Tab switching without reload (nav tabs + in-page links like "Manage Banned IPs")
  document.querySelectorAll('.fail2ban-manager a[href^="?tab="]').forEach(function(a) {
    a.addEventListener('click', function(e) {
      e.preventDefault();
      var m = this.getAttribute('href').match(/tab=(\w+)/);
      if (!m) return;
      var tid = m[1];
      document.querySelectorAll('.fail2ban-manager .nav-tabs li').forEach(function(li) { li.classList.remove('active'); });
      document.querySelectorAll('.fail2ban-manager .tab-pane').forEach(function(p) { p.classList.remove('active'); });
      var activeTab = document.querySelector('.fail2ban-manager .nav-tabs a[href="?tab=' + tid + '"]');
      if (activeTab) activeTab.parentElement.classList.add('active');
      var pane = document.getElementById('tab-' + tid);
      if (pane) pane.classList.add('active');
      history.pushState(null, '', base + '?tab=' + tid);
      if (tid === 'banned') ensureBannedLoaded();
    });
  });

  window.addEventListener('popstate', function() {
    var m = (window.location.search || '').match(/[?&]tab=(\w+)/);
    if (m) {
      var tid = m[1];
      document.querySelectorAll('.fail2ban-manager .nav-tabs li').forEach(function(li) { li.classList.remove('active'); });
      document.querySelectorAll('.fail2ban-manager .tab-pane').forEach(function(p) { p.classList.remove('active'); });
      var at = document.querySelector('.fail2ban-manager .nav-tabs a[href="?tab=' + tid + '"]');
      if (at) at.parentElement.classList.add('active');
      var pane = document.getElementById('tab-' + tid);
      if (pane) pane.classList.add('active');
    }
  });

  // AJAX form submission (event delegation so dynamically loaded forms work)
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (form.tagName !== 'FORM' || !form.closest || !form.closest('.fail2ban-manager')) return;
    e.preventDefault();
    var btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;
    var loadingEl = document.getElementById('fail2ban-loading');
    if (loadingEl) loadingEl.style.display = 'flex';
    var fd = new FormData(form);
    var url = (form.getAttribute && form.getAttribute('action')) || window.location.href;
    fetch(url, { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(function(r) { return r.json().catch(function() { return { ok: false, msg: 'Invalid response' }; }); })
      .then(function(data) {
        showMsg(data.msg || 'Done.', !data.ok);
        if (data.refresh_banned) refreshBannedIps();
      })
      .catch(function() {
        showMsg('Request failed. Please try again.', true);
      })
      .finally(function() {
        if (btn) btn.disabled = false;
        var le = document.getElementById('fail2ban-loading');
        if (le) le.style.display = 'none';
      });
  });

  // Time preset dropdowns
  document.querySelectorAll('.findtime-preset').forEach(function(sel) {
    sel.addEventListener('change', function() {
      var val = this.value;
      if (val) {
        var form = this.closest('form');
        var inp = form.querySelector('input[name="findtime"]');
        if (inp) inp.value = val;
        this.selectedIndex = 0;
      }
    });
  });
  document.querySelectorAll('.bantime-preset').forEach(function(sel) {
    sel.addEventListener('change', function() {
      var val = this.value;
      if (val) {
        var form = this.closest('form');
        var inp = form.querySelector('input[name="bantime"]');
        if (inp) inp.value = val;
        this.selectedIndex = 0;
      }
    });
  });
  // Jail settings form validation
  document.querySelectorAll('.jail-settings-form').forEach(function(form) {
    form.addEventListener('submit', function(e) {
      var errEl = form.querySelector('.jail-settings-err');
      if (errEl) errEl.style.display = 'none';
      var maxretry = parseInt(form.querySelector('input[name="maxretry"]').value, 10);
      var findtime = parseInt(form.querySelector('input[name="findtime"]').value, 10);
      var bantime = parseInt(form.querySelector('input[name="bantime"]').value, 10);
      var msg = '';
      if (isNaN(maxretry) || maxretry < 1 || maxretry > 10000) msg = 'maxretry: 1–10000';
      else if (isNaN(findtime) || findtime < 60 || findtime > 2592000) msg = 'findtime: 60–2592000 sec (30 days)';
      else if (isNaN(bantime) || bantime < 60 || bantime > 31536000) msg = 'bantime: 60–31536000 sec (1 year)';
      if (msg && errEl) {
        errEl.textContent = msg;
        errEl.style.display = 'inline';
        e.preventDefault();
      }
    });
  });
  // Bulk unban: select-all and enable button (event delegation for AJAX content)
  document.addEventListener('change', function(e) {
    if (e.target.classList.contains('select-all-banned')) {
      var jail = e.target.getAttribute('data-jail');
      var cid = e.target.getAttribute('data-container') || ('banned-ips-' + jail);
      var container = document.getElementById(cid);
      if (!container) return;
      var checked = e.target.checked;
      container.querySelectorAll('.banned-ip-cb').forEach(function(cb) { cb.checked = checked; });
      var btn = container.querySelector('.bulk-unban-btn');
      if (btn) btn.disabled = !checked;
    } else if (e.target.classList.contains('banned-ip-cb')) {
      var form = document.getElementById(e.target.getAttribute('form'));
      if (form) {
        var any = form.querySelectorAll('.banned-ip-cb:checked').length > 0;
        var btn = form.querySelector('.bulk-unban-btn');
        if (btn) btn.disabled = !any;
      }
    }
  });
  document.addEventListener('click', function(e) {
    var cleanBtn = e.target.closest('.clean-expired-bips');
    if (cleanBtn) {
      e.preventDefault();
      cleanBtn.disabled = true;
      fetch(base + '?ajax=clean_expired_bips', { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          showMsg(data.msg || 'Done.', !data.ok);
          if (data.ok && data.deleted > 0) refreshBannedIps(true);
        })
        .catch(function() { showMsg('Request failed.', true); })
        .finally(function() { cleanBtn.disabled = false; });
      return;
    }
    var btn = e.target.closest('.reload-banned-ips');
    if (btn) {
      e.preventDefault();
      e.stopPropagation();
      var jail = btn.getAttribute('data-jail');
      if (!jail) return;
      var container = document.getElementById('banned-ips-' + jail + '-tab');
      if (!container) return;
      var icon = btn.querySelector('.glyphicon-refresh');
      if (icon) icon.classList.add('glyphicon-refresh-animate');
      var wrap = container.querySelector('.banned-ips-ajax');
      var page = 1, search = '';
      if (wrap) {
        var inp = wrap.querySelector('.banned-ip-search-input');
        if (inp) search = inp.value || '';
        var act = wrap.querySelector('.pagination li.active .banned-page-link');
        if (act) page = parseInt(act.getAttribute('data-page'), 10) || 1;
      }
      loadBannedIps(jail, page, search, function() {
        if (icon) icon.classList.remove('glyphicon-refresh-animate');
      });
    }
  });

  if (document.getElementById('tab-banned') && document.getElementById('tab-banned').classList.contains('active')) {
    ensureBannedLoaded();
  }
});
</script>
<style>
/* Fail2Ban Manager - theme-aware styles */
.fail2ban-manager .panel-body { background: var(--base-01, #fff); }
.fail2ban-manager .banned-ips-container { background: var(--base-01, transparent); }
.fail2ban-manager .table { background: var(--base-01, #fff); color: inherit; }
.fail2ban-manager .table-striped > tbody > tr:nth-of-type(odd) { background: var(--base-02, #f9f9f9); }
.fail2ban-manager .panel-default > .panel-heading { background: var(--base-02, #f5f5f5); color: inherit; border-color: var(--border-01, #ddd); }
.glyphicon-refresh-animate { animation: spin 0.8s linear infinite; }
.ip-log-detail { cursor: pointer; text-decoration: underline; color: var(--accent-05, #337ab7); }
.ip-log-detail:hover { color: var(--accent-06, #23527c); }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
.fail2ban-loading-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.35); z-index: 9999; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 10px; color: var(--base-01, #fff); font-size: 14px; }
.fail2ban-spinner { width: 36px; height: 36px; border: 4px solid rgba(255,255,255,0.3); border-top-color: #fff; border-radius: 50%; animation: spin 0.8s linear infinite; }
</style>

<?php WHM::footer(); ?>
