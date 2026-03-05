<?php
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
    } elseif ($action === 'update_ip2location') {
        exec('/etc/fail2ban/scripts/update-ip2location.sh 2>&1', $out, $ret);
        $msg = $ret === 0 ? 'IP2Location database updated.' : 'Update failed: ' . implode("\n", $out);
    }
}

WHM::header('Fail2Ban Manager', 0, 0);

$ignore_conf = '/etc/fail2ban/scripts/ignore-countries.conf';
$whitelist_conf = '/usr/share/fail2ban/whitelist-ips.conf';
$ignore_countries = '';
$whitelist_ips = '';
if (file_exists($ignore_conf)) {
    $c = file_get_contents($ignore_conf);
    if (preg_match('/WHITELIST_COUNTRIES=(.*)$/m', $c, $m)) $ignore_countries = trim($m[1]);
}
if (file_exists($whitelist_conf)) {
    $whitelist_ips = file_get_contents($whitelist_conf);
}

// Get fail2ban status
$status = [];
$jails = ['wordpress-wp-login', 'apache-high-volume'];
foreach ($jails as $j) {
    exec("fail2ban-client status $j 2>/dev/null", $out, $ret);
    $status[$j] = $ret === 0 ? implode("\n", $out) : 'Not active';
}
exec('fail2ban-client status 2>/dev/null', $gen_out, $gen_ret);
$general_status = $gen_ret === 0 ? implode("\n", $gen_out) : 'fail2ban not running';
?>

<?php if ($msg): ?><p class="alert alert-info"><?php echo htmlspecialchars($msg); ?></p><?php endif; ?>

<div class="row">
<div class="col-md-8">

<h3>Status</h3>
<pre style="background:#f5f5f5;padding:10px;font-size:12px;"><?php echo htmlspecialchars($general_status); ?></pre>

<h3>Jails</h3>
<?php foreach ($jails as $j): ?>
<div class="panel panel-default">
  <div class="panel-heading"><?php echo htmlspecialchars($j); ?></div>
  <div class="panel-body">
    <pre style="font-size:12px;"><?php echo htmlspecialchars($status[$j]); ?></pre>
    <form method="post" class="form-inline" style="margin-top:8px;">
      <input type="hidden" name="action" value="unban">
      <input type="hidden" name="jail" value="<?php echo htmlspecialchars($j); ?>">
      <input type="text" name="ip" placeholder="IP to unban" class="form-control input-sm" style="width:150px;">
      <button type="submit" class="btn btn-default btn-sm">Unban</button>
    </form>
  </div>
</div>
<?php endforeach; ?>

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

<?php WHM::footer(); ?>
