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
    } catch (Exception $e) {
        return null;
    }
    return $pdo;
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

function is_geoip_ready() {
    $mmdb = '/etc/fail2ban/GeoIP/IP2LOCATION-LITE-DB1.mmdb';
    if (!file_exists($mmdb) || !is_readable($mmdb)) return false;
    $out = [];
    exec('mmdblookup -f ' . escapeshellarg($mmdb) . ' -i 8.8.8.8 country iso_code 2>/dev/null', $out, $ret);
    return $ret === 0 && !empty($out);
}

$geoip_ready = is_geoip_ready();
$jails = ['wordpress-wp-login', 'apache-high-volume'];
$jail_labels = [
    'wordpress-wp-login' => ['failed' => 'Failed logins', 'failed_total' => 'Total failed logins'],
    'apache-high-volume' => ['failed' => 'Requests in window', 'failed_total' => 'Total requests']
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
    if (in_array($ajail, $jails)) {
        header('Content-Type: text/html; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        $d = parse_jail_status($ajail);
        $country_cache = [];
        if (!empty($d['banned_ips'])) {
            $ban_times = get_ban_times($ajail);
            $domain_cache = [];
            echo '<table class="table table-bordered table-striped table-condensed banned-ips-table"><thead><tr><th><input type="checkbox" class="select-all-banned" data-jail="' . htmlspecialchars($ajail) . '" title="Select all"></th><th>#</th><th>IP Address</th><th>Country</th><th>Affected Domains</th><th>Banned At</th><th>Action</th></tr></thead><tbody>';
            foreach (array_values($d['banned_ips']) as $i => $ip) {
                $country = get_ip_country($ip, $country_cache);
                $affected = get_affected_domains($ip, $ajail, $domain_cache);
                $banned_at = $ban_times[$ip] ?? '-';
                $is_whitelisted = in_array($country, $whitelist_countries_arr);
                $rowClass = $is_whitelisted ? ' class="warning" style="background:var(--accent-01,#fff3cd)"' : '';
                $wlLabel = $is_whitelisted ? ' <span class="label label-warning">whitelisted</span>' : '';
                echo '<tr' . $rowClass . '><td><input type="checkbox" class="banned-ip-cb" name="unban_ips[]" value="' . htmlspecialchars($ip) . '" form="bulk-unban-' . htmlspecialchars($ajail) . '"></td><td>' . ($i + 1) . '</td><td><code>' . htmlspecialchars($ip) . '</code></td><td>' . htmlspecialchars($country) . $wlLabel . '</td><td style="max-width:200px;font-size:11px;" title="' . htmlspecialchars($affected) . '">' . htmlspecialchars($affected) . '</td><td>' . htmlspecialchars($banned_at) . '</td><td><form method="post" style="display:inline;margin:0;"><input type="hidden" name="action" value="unban"><input type="hidden" name="jail" value="' . htmlspecialchars($ajail) . '"><input type="hidden" name="ip" value="' . htmlspecialchars($ip) . '"><button type="submit" class="btn btn-default btn-xs">Unban</button></form></td></tr>';
            }
            echo '</tbody></table><form id="bulk-unban-' . htmlspecialchars($ajail) . '" method="post" style="margin-top:6px;"><input type="hidden" name="action" value="unban_bulk"><input type="hidden" name="jail" value="' . htmlspecialchars($ajail) . '"><button type="submit" class="btn btn-warning btn-sm bulk-unban-btn" disabled>Unban selected</button></form>';
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

<?php if ($msg): ?><p class="alert alert-info"><?php echo htmlspecialchars($msg); ?></p><?php endif; ?>

<?php if (!$geoip_ready): ?>
<p class="alert alert-warning">
  <strong>GeoIP not configured.</strong> Country lookup uses ip-api.com (rate-limited). For better reliability, run <code>/etc/fail2ban/scripts/setup-ip2location.sh</code> as root. Use "Update IP2Location DB" below to refresh after setup.
</p>
<?php endif; ?>

<?php if (!empty($whitelist_countries_arr)): ?>
<p class="alert alert-warning">
  <strong>Note:</strong> IPs from whitelisted countries (<?php echo htmlspecialchars($ignore_countries); ?>) may appear if they were banned <em>before</em> the whitelist was added. Use "Unban all from whitelisted countries" below to remove them.
</p>
<?php endif; ?>

<div class="fail2ban-manager">
<div class="row">
<div class="col-md-8">

<h3>Status</h3>
<pre style="background:#f5f5f5;padding:10px;font-size:12px;"><?php echo htmlspecialchars($general_status); ?></pre>

<h3>Jails</h3>
<?php foreach ($jails as $j):
$d = $jail_data[$j];
$js = $jail_settings[$j] ?? ['maxretry' => 5, 'findtime' => 300, 'bantime' => 3600];
?>
<div class="panel panel-default">
  <div class="panel-heading"><?php echo htmlspecialchars($j); ?></div>
  <div class="panel-body">
    <table class="table table-bordered table-striped table-condensed">
      <thead>
        <tr><th>Metric</th><th>Value</th></tr>
      </thead>
      <tbody>
        <?php $lbl = $jail_labels[$j] ?? ['failed' => 'Currently failed', 'failed_total' => 'Total failed']; ?>
        <tr><td><?php echo htmlspecialchars($lbl['failed']); ?></td><td><?php echo htmlspecialchars($d['currently_failed']); ?></td></tr>
        <tr><td><?php echo htmlspecialchars($lbl['failed_total']); ?></td><td><?php echo htmlspecialchars($d['total_failed']); ?></td></tr>
        <tr><td>Currently banned</td><td><?php echo htmlspecialchars($d['currently_banned']); ?></td></tr>
        <tr><td>Total banned</td><td><?php echo htmlspecialchars($d['total_banned']); ?></td></tr>
      </tbody>
    </table>
    <form method="post" class="form-inline jail-settings-form" style="margin-bottom:12px;padding:8px;background:var(--base-01,#f9f9f9);border-radius:4px;" data-maxretry-min="1" data-maxretry-max="10000" data-findtime-min="60" data-findtime-max="2592000" data-bantime-min="60" data-bantime-max="31536000">
      <input type="hidden" name="action" value="save_jail_settings">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <label>maxretry</label>
      <input type="number" name="maxretry" value="<?php echo (int)$js['maxretry']; ?>" min="1" max="10000" class="form-control input-sm" style="width:70px;margin:0 8px 0 4px;" title="Max attempts before ban (1-10000)" required>
      <label style="margin-left:8px;">findtime</label>
      <input type="number" name="findtime" value="<?php echo (int)$js['findtime']; ?>" min="60" max="2592000" class="form-control input-sm" style="width:80px;margin:0 4px 0 4px;" title="Window in seconds, 60-2592000 (30 days)" data-preset-field="findtime" required>
      <span class="text-muted" style="font-size:11px;">sec</span>
      <select class="form-control input-sm findtime-preset" style="width:auto;margin-left:4px;display:inline-block;" title="Quick presets: 300=5min, 600=10min">
        <option value="">preset</option>
        <option value="60">1 min</option>
        <option value="300">5 min</option>
        <option value="600">10 min</option>
        <option value="3600">1 hr</option>
      </select>
      <label style="margin-left:8px;">bantime</label>
      <input type="number" name="bantime" value="<?php echo (int)$js['bantime']; ?>" min="60" max="31536000" class="form-control input-sm" style="width:80px;margin:0 4px 0 4px;" title="Ban duration in seconds, 60-31536000 (1 year)" data-preset-field="bantime" required>
      <span class="text-muted" style="font-size:11px;">sec</span>
      <select class="form-control input-sm bantime-preset" style="width:auto;margin-left:4px;display:inline-block;" title="Quick presets: 3600=1hr, 86400=24hr">
        <option value="">preset</option>
        <option value="300">5 min</option>
        <option value="3600">1 hr</option>
        <option value="86400">24 hr</option>
        <option value="604800">1 week</option>
      </select>
      <button type="submit" class="btn btn-primary btn-sm" style="margin-left:8px;">Save &amp; Deploy</button>
      <span class="jail-settings-err text-danger" style="margin-left:8px;display:none;"></span>
    </form>
    <p><strong>Banned IPs:</strong>
      <button type="button" class="btn btn-link reload-banned-ips" data-jail="<?php echo htmlspecialchars($j); ?>" title="Refresh table" style="margin-left:6px;padding:0 4px;vertical-align:middle;"><span class="glyphicon glyphicon-refresh"></span></button>
    </p>
    <div id="banned-ips-<?php echo htmlspecialchars($j); ?>" class="banned-ips-container">
    <?php if (!empty($d['banned_ips'])): $ban_times = get_ban_times($j); $domain_cache = []; ?>
    <table class="table table-bordered table-striped table-condensed banned-ips-table">
      <thead><tr><th><input type="checkbox" class="select-all-banned" data-jail="<?php echo htmlspecialchars($j); ?>" title="Select all"></th><th>#</th><th>IP Address</th><th>Country</th><th>Affected Domains</th><th>Banned At</th><th>Action</th></tr></thead>
      <tbody>
      <?php $country_cache = []; foreach (array_values($d['banned_ips']) as $i => $ip): $country = get_ip_country($ip, $country_cache); $affected = get_affected_domains($ip, $j, $domain_cache); $banned_at = $ban_times[$ip] ?? '-'; $is_whitelisted = in_array($country, $whitelist_countries_arr); ?>
        <tr<?php echo $is_whitelisted ? ' class="warning" style="background:var(--accent-01,#fff3cd)"' : ''; ?>>
          <td><input type="checkbox" class="banned-ip-cb" name="unban_ips[]" value="<?php echo htmlspecialchars($ip); ?>" form="bulk-unban-<?php echo htmlspecialchars($j); ?>"></td>
          <td><?php echo $i + 1; ?></td>
          <td><code><?php echo htmlspecialchars($ip); ?></code></td>
          <td><?php echo htmlspecialchars($country); ?><?php if ($is_whitelisted): ?> <span class="label label-warning">whitelisted</span><?php endif; ?></td>
          <td style="max-width:200px;font-size:11px;" title="<?php echo htmlspecialchars($affected); ?>"><?php echo htmlspecialchars($affected); ?></td>
          <td><?php echo htmlspecialchars($banned_at); ?></td>
          <td>
            <form method="post" style="display:inline;margin:0;">
              <input type="hidden" name="action" value="unban">
              <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
              <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
              <button type="submit" class="btn btn-default btn-xs">Unban</button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    <form id="bulk-unban-<?php echo htmlspecialchars($j); ?>" method="post" style="margin-top:6px;">
      <input type="hidden" name="action" value="unban_bulk">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <button type="submit" class="btn btn-warning btn-sm bulk-unban-btn" disabled>Unban selected</button>
    </form>
    <?php else: ?>
    <p class="text-muted">No banned IPs.</p>
    <?php endif; ?>
    </div>
    <form method="post" class="form-inline" style="margin-top:8px;">
      <input type="hidden" name="action" value="unban">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <input type="text" name="ip" placeholder="IP to unban" class="form-control input-sm" style="width:150px;">
      <button type="submit" class="btn btn-default btn-sm">Unban</button>
    </form>
  </div>
</div>
<?php endforeach; ?>

<?php if (!empty($whitelist_countries_arr)): ?>
<div class="panel panel-warning" style="margin-top:15px;">
  <div class="panel-heading">Whitelisted countries: <?php echo htmlspecialchars($ignore_countries); ?></div>
  <div class="panel-body">
    <p class="text-muted">IPs from these countries appearing above were likely banned before the whitelist was added.</p>
    <form method="post">
      <input type="hidden" name="action" value="unban_whitelisted">
      <input type="hidden" name="whitelist_countries" value="<?php echo htmlspecialchars($ignore_countries); ?>">
      <button type="submit" class="btn btn-warning">Unban all from whitelisted countries</button>
    </form>
  </div>
</div>
<?php endif; ?>

</div>
<div class="col-md-4">

<h3>Ignore Countries</h3>
<p class="text-muted">ISO codes (e.g. IN,US,GB). IPs from these countries are not banned.</p>
<form method="post">
  <input type="hidden" name="action" value="save_ignore_countries">
  <input type="text" name="whitelist_countries" value="<?php echo htmlspecialchars($ignore_countries); ?>" class="form-control" placeholder="IN,US,GB">
  <button type="submit" class="btn btn-primary btn-sm" style="margin-top:5px;">Save</button>
</form>

<h3 style="margin-top:20px;">Whitelist IPs</h3>
<p class="text-muted">IPs/CIDRs excluded from bans. One per line.</p>
<form method="post">
  <input type="hidden" name="action" value="save_whitelist_ips">
  <textarea name="whitelist_ips" class="form-control" rows="8" style="font-family:monospace;font-size:12px;"><?php echo htmlspecialchars($whitelist_ips); ?></textarea>
  <button type="submit" class="btn btn-primary btn-sm" style="margin-top:5px;">Save &amp; Deploy</button>
</form>

<h3 style="margin-top:20px;">Actions</h3>
<form method="post" style="display:inline;">
  <input type="hidden" name="action" value="deploy">
  <button type="submit" class="btn btn-default btn-sm">Deploy config &amp; restart</button>
</form>
<form method="post" style="display:inline;margin-left:5px;">
  <input type="hidden" name="action" value="update_ip2location">
  <button type="submit" class="btn btn-default btn-sm">Update IP2Location DB</button>
</form>

</div>
</div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
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
      var container = document.getElementById('banned-ips-' + jail);
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
      var container = document.getElementById('banned-ips-' + jail);
      if (!container) return false;
      var icon = this.querySelector('.glyphicon-refresh');
      if (icon) icon.classList.add('glyphicon-refresh-animate');
      var base = (window.location.href || '').split('?')[0];
      var url = base + '?ajax=banned_ips&jail=' + encodeURIComponent(jail);
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
</style>

<?php WHM::footer(); ?>
