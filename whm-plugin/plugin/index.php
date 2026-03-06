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
    if ($pdo) {
        $stmt = $pdo->prepare("SELECT org FROM ip_org WHERE ip = ?");
        if ($stmt && $stmt->execute([$ip])) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) return $cache[$ip] = $row['org'];
        }
    }
    if (function_exists('file_get_contents') && ini_get('allow_url_fopen')) {
        $json = @file_get_contents("http://ip-api.com/json/" . urlencode($ip) . "?fields=org,isp", false, stream_context_create(['http' => ['timeout' => 2]]));
        if ($json) {
            if (preg_match('/"org":"([^"]*)"/', $json, $m) && trim($m[1]) !== '') $org = trim($m[1]);
            elseif (preg_match('/"isp":"([^"]*)"/', $json, $m) && trim($m[1]) !== '') $org = trim($m[1]);
        }
    } elseif (function_exists('curl_init')) {
        $ch = curl_init("http://ip-api.com/json/" . urlencode($ip) . "?fields=org,isp");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
        $json = @curl_exec($ch);
        curl_close($ch);
        if ($json) {
            if (preg_match('/"org":"([^"]*)"/', $json, $m) && trim($m[1]) !== '') $org = trim($m[1]);
            elseif (preg_match('/"isp":"([^"]*)"/', $json, $m) && trim($m[1]) !== '') $org = trim($m[1]);
        }
    }
    $org = $org ?: '-';
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
        exec("grep -lE '^" . preg_quote($ip, '/') . " ' /usr/local/apache/domlogs/*/* 2>/dev/null", $files);
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
$tab_from_action = ['save_ignore_countries' => 'whitelists', 'save_whitelist_ips' => 'whitelists', 'save_email_alerts' => 'notifications', 'save_loglevel' => 'settings', 'deploy' => 'settings', 'update_ip2location' => 'settings', 'unban' => 'banned', 'unban_bulk' => 'banned', 'unban_whitelisted' => 'banned', 'save_jail_settings' => 'settings'];

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
        if ($jail && in_array($jail, ['wordpress-wp-login', 'apache-high-volume']) && !empty($ips)) {
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
$jail_data = [];
$jail_settings = [];
foreach ($jails as $j) {
    $jail_data[$j] = parse_jail_status($j);
    $jail_settings[$j] = get_jail_settings($j);
}

// AJAX handler must run BEFORE WHM::header() so we don't output the full page wrapper
if (isset($_GET['ajax']) && $_GET['ajax'] === 'banned_ips' && isset($_GET['jail'])) {
    $ajail = preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['jail']);
    $fs = isset($_GET['fs']) ? '-' . preg_replace('/[^a-zA-Z0-9_-]/', '', $_GET['fs']) : '';
    $retab = ($fs === '-tab') ? 'banned' : 'dashboard';
    if (in_array($ajail, $jails)) {
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        $d = parse_jail_status($ajail);
        $country_cache = [];
        $form_id = 'bulk-unban-' . $ajail . $fs;
        if (!empty($d['banned_ips'])) {
            $ban_times = get_ban_times($ajail);
            $domain_cache = [];
            $org_cache = [];
            echo '<table class="table table-bordered table-striped table-condensed banned-ips-table"><thead><tr><th><input type="checkbox" class="select-all-banned" data-jail="' . htmlspecialchars($ajail) . '" data-container="banned-ips-' . htmlspecialchars($ajail) . $fs . '" title="Select all"></th><th>#</th><th>IP Address</th><th>Country</th><th>Organization</th><th>Affected Domains</th><th>Banned At</th><th>Action</th></tr></thead><tbody>';
            foreach (array_values($d['banned_ips']) as $i => $ip) {
                $country = get_ip_country($ip, $country_cache);
                $org = get_ip_org($ip, $org_cache);
                $affected = get_affected_domains($ip, $ajail, $domain_cache);
                $banned_at = $ban_times[$ip] ?? '-';
                $is_whitelisted = in_array($country, $whitelist_countries_arr);
                $rowClass = $is_whitelisted ? ' class="warning" style="background:var(--accent-01,#fff3cd)"' : '';
                $wlLabel = $is_whitelisted ? ' <span class="label label-warning">whitelisted</span>' : '';
                echo '<tr' . $rowClass . '><td><input type="checkbox" class="banned-ip-cb" name="unban_ips[]" value="' . htmlspecialchars($ip) . '" form="' . htmlspecialchars($form_id) . '"></td><td>' . ($i + 1) . '</td><td><code>' . htmlspecialchars($ip) . '</code></td><td>' . htmlspecialchars($country) . $wlLabel . '</td><td style="max-width:150px;font-size:11px;" title="' . htmlspecialchars($org) . '">' . htmlspecialchars($org) . '</td><td style="max-width:200px;font-size:11px;" title="' . htmlspecialchars($affected) . '">' . htmlspecialchars($affected) . '</td><td>' . htmlspecialchars($banned_at) . '</td><td><form method="post" style="display:inline;margin:0;"><input type="hidden" name="action" value="unban"><input type="hidden" name="tab" value="' . htmlspecialchars($retab) . '"><input type="hidden" name="jail" value="' . htmlspecialchars($ajail) . '"><input type="hidden" name="ip" value="' . htmlspecialchars($ip) . '"><button type="submit" class="btn btn-default btn-xs">Unban</button></form></td></tr>';
            }
            echo '</tbody></table><form id="' . htmlspecialchars($form_id) . '" method="post" style="margin-top:6px;"><input type="hidden" name="action" value="unban_bulk"><input type="hidden" name="tab" value="' . htmlspecialchars($retab) . '"><input type="hidden" name="jail" value="' . htmlspecialchars($ajail) . '"><button type="submit" class="btn btn-warning btn-sm bulk-unban-btn" disabled>Unban selected</button></form>';
        } else {
            echo '<p class="text-muted">No banned IPs.</p>';
        }
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
<?php foreach ($jails as $j):
$d = $jail_data[$j];
?>
<div class="panel panel-default">
  <div class="panel-heading"><?php echo htmlspecialchars($j); ?> — Banned IPs</div>
  <div class="panel-body">
    <p><strong>Banned IPs:</strong>
      <button type="button" class="btn btn-link reload-banned-ips" data-jail="<?php echo htmlspecialchars($j); ?>" title="Refresh"><span class="glyphicon glyphicon-refresh"></span></button>
    </p>
    <div id="banned-ips-<?php echo htmlspecialchars($j); ?>-tab" class="banned-ips-container">
    <?php if (!empty($d['banned_ips'])): $ban_times = get_ban_times($j); $domain_cache = []; ?>
    <table class="table table-bordered table-striped table-condensed banned-ips-table">
      <thead><tr><th><input type="checkbox" class="select-all-banned" data-jail="<?php echo htmlspecialchars($j); ?>" data-container="banned-ips-<?php echo htmlspecialchars($j); ?>-tab" title="Select all"></th><th>#</th><th>IP Address</th><th>Country</th><th>Organization</th><th>Affected Domains</th><th>Banned At</th><th>Action</th></tr></thead>
      <tbody>
      <?php $country_cache = []; $org_cache = []; foreach (array_values($d['banned_ips']) as $i => $ip): $country = get_ip_country($ip, $country_cache); $org = get_ip_org($ip, $org_cache); $affected = get_affected_domains($ip, $j, $domain_cache); $banned_at = $ban_times[$ip] ?? '-'; $is_whitelisted = in_array($country, $whitelist_countries_arr); ?>
        <tr<?php echo $is_whitelisted ? ' class="warning"' : ''; ?>>
          <td><input type="checkbox" class="banned-ip-cb" name="unban_ips[]" value="<?php echo htmlspecialchars($ip); ?>" form="bulk-unban-<?php echo htmlspecialchars($j); ?>-tab"></td>
          <td><?php echo $i + 1; ?></td>
          <td><code><?php echo htmlspecialchars($ip); ?></code></td>
          <td><?php echo htmlspecialchars($country); ?><?php if ($is_whitelisted): ?> <span class="label label-warning">whitelisted</span><?php endif; ?></td>
          <td style="max-width:150px;font-size:11px;" title="<?php echo htmlspecialchars($org); ?>"><?php echo htmlspecialchars($org); ?></td>
          <td style="max-width:200px;font-size:11px;" title="<?php echo htmlspecialchars($affected); ?>"><?php echo htmlspecialchars($affected); ?></td>
          <td><?php echo htmlspecialchars($banned_at); ?></td>
          <td>
            <form method="post" style="display:inline;margin:0;">
              <input type="hidden" name="action" value="unban">
              <input type="hidden" name="tab" value="banned">
              <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
              <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
              <button type="submit" class="btn btn-default btn-xs">Unban</button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <form id="bulk-unban-<?php echo htmlspecialchars($j); ?>-tab" method="post" style="margin-top:6px;">
      <input type="hidden" name="action" value="unban_bulk">
      <input type="hidden" name="tab" value="banned">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <button type="submit" class="btn btn-warning btn-sm bulk-unban-btn" disabled>Unban selected</button>
    </form>
    <?php else: ?>
    <p class="text-muted">No banned IPs.</p>
    <?php endif; ?>
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
<?php foreach ($jails as $j):
$js = $jail_settings[$j] ?? ['maxretry' => 5, 'findtime' => 300, 'bantime' => 3600];
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
        <form method="post">
          <input type="hidden" name="action" value="update_ip2location">
          <input type="hidden" name="tab" value="settings">
          <button type="submit" class="btn btn-default btn-block">Update IP2Location DB</button>
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
  var jails = ['wordpress-wp-login', 'apache-high-volume'];

  function showMsg(msg, isErr) {
    var el = document.getElementById('fail2ban-msg');
    if (!el) return;
    el.textContent = msg;
    el.className = 'alert alert-' + (isErr ? 'danger' : 'info');
    el.style.display = 'block';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    setTimeout(function() { el.style.display = 'none'; }, 5000);
  }

  function refreshBannedIps() {
    jails.forEach(function(jail) {
      var container = document.getElementById('banned-ips-' + jail + '-tab');
      if (!container) return;
      fetch(base + '?ajax=banned_ips&jail=' + encodeURIComponent(jail) + '&fs=tab', { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function(r) { return r.text(); })
        .then(function(html) {
          if (html && html.length < 50000 && html.indexOf('</html>') === -1) container.innerHTML = html;
        });
    });
  }

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
  document.querySelectorAll('.reload-banned-ips').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      var jail = this.getAttribute('data-jail');
      var container = document.getElementById('banned-ips-' + jail + '-tab');
      if (!container) return false;
      var icon = this.querySelector('.glyphicon-refresh');
      if (icon) icon.classList.add('glyphicon-refresh-animate');
      var base = (window.location.href || '').split('?')[0];
      var url = base + '?ajax=banned_ips&jail=' + encodeURIComponent(jail) + '&fs=tab';
      fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(function(r) { return r.text(); })
        .then(function(html) {
          if (html && html.length < 50000 && html.indexOf('</html>') === -1 && html.indexOf('<!DOCTYPE') === -1) {
            container.innerHTML = html;
          } else {
            container.innerHTML = '<p class="text-danger">Got full page response; try refreshing the page.</p>';
          }
        })
        .catch(function() {
          container.innerHTML = '<p class="text-danger">Failed to refresh.</p>';
        })
        .finally(function() {
          if (icon) icon.classList.remove('glyphicon-refresh-animate');
        });
      return false;
    });
  });
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
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
.fail2ban-loading-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.35); z-index: 9999; display: flex; align-items: center; justify-content: center; flex-direction: column; gap: 10px; color: var(--base-01, #fff); font-size: 14px; }
.fail2ban-spinner { width: 36px; height: 36px; border: 4px solid rgba(255,255,255,0.3); border-top-color: #fff; border-radius: 50%; animation: spin 0.8s linear infinite; }
</style>

<?php WHM::footer(); ?>
