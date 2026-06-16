<?php

if(version_compare(PHP_VERSION,'7.4.0','<')){http_response_code(500);exit('PHP 7.4+ required (current: '.PHP_VERSION.')');}
foreach(['curl','mbstring','json'] as $_ext){if(!extension_loaded($_ext)){http_response_code(500);exit('Missing required PHP extension: '.$_ext);}}
unset($_ext);

if (!function_exists('str_starts_with')) { function str_starts_with($h,$n){return(string)$n!==''&&strncmp($h,$n,strlen($n))===0;} }
if (!function_exists('str_ends_with'))   { function str_ends_with($h,$n){return $n!==''&&substr($h,-strlen($n))===(string)$n;} }
function isAssoc($a){if(!is_array($a)||empty($a))return false;return array_keys($a)!==range(0,count($a)-1);}

// ─── Security Headers ───────────────────────────────────────────────────────
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");

// ─── Configuration ──────────────────────────────────────────────────────────
define('ADMIN_USER','admin');
$_aPassFile=__DIR__.'/.admin_pass';
$_aPass=file_exists($_aPassFile)?trim(file_get_contents($_aPassFile)):(getenv('REBEL_ADMIN_PASS')?:'admin');
define('ADMIN_PASS',$_aPass);
define('BOTS_DIR',__DIR__.'/bots/');
define('MASTER_FILE',__DIR__.'/rebel_bots.json');
define('TG_BASE','https://api.telegram.org/bot');
define('TG_TO',20);
define('RATE_LIMIT_FILE',__DIR__.'/.rate_limits.json');
define('CSRF_TOKEN_NAME','_csrf');
if(!is_dir(BOTS_DIR))@mkdir(BOTS_DIR,0755,true);

// ─── Login Rate Limiting (brute-force protection) ───────────────────────────
function getRateLimits(){
    if(!file_exists(RATE_LIMIT_FILE))return[];
    $d=json_decode(file_get_contents(RATE_LIMIT_FILE),true);
    return is_array($d)?$d:[];
}
function saveRateLimits($d){file_put_contents(RATE_LIMIT_FILE,json_encode($d),LOCK_EX);}
function isLoginRateLimited($ip){
    $rl=getRateLimits();$now=time();$k='login_'.$ip;
    $e=$rl[$k]??['count'=>0,'until'=>0,'last'=>0];
    return ($e['until']>$now);
}
function recordLoginFail($ip){
    $rl=getRateLimits();$now=time();$k='login_'.$ip;
    $e=$rl[$k]??['count'=>0,'until'=>0,'last'=>$now];
    $e['count']++;$e['last']=$now;
    if($e['count']>=5)$e['until']=$now+300; // 5 min ban after 5 fails
    $rl[$k]=$e;saveRateLimits($rl);
}
function clearLoginFails($ip){$rl=getRateLimits();unset($rl['login_'.$ip]);saveRateLimits($rl);}
function getLoginLockedSecs($ip){
    $rl=getRateLimits();$now=time();$e=$rl['login_'.$ip]??['until'=>0];
    return max(0,$e['until']-$now);
}

// ─── Password verification ──────────────────────────────────────────────────
function verifyAdminPassword($pass){
    return $pass === ADMIN_PASS;
}

// ─── CSRF helpers ───────────────────────────────────────────────────────────
function csrfToken(){
    if(empty($_SESSION[CSRF_TOKEN_NAME])){
        $_SESSION[CSRF_TOKEN_NAME]=bin2hex(random_bytes(32));
    }
    return $_SESSION[CSRF_TOKEN_NAME];
}
function verifyCsrf(){
    $tok=$_POST[CSRF_TOKEN_NAME]??($_SERVER['HTTP_X_CSRF_TOKEN']??'');
    return isset($_SESSION[CSRF_TOKEN_NAME])&&hash_equals($_SESSION[CSRF_TOKEN_NAME],$tok);
}

function loadBots(){return file_exists(MASTER_FILE)?(json_decode(file_get_contents(MASTER_FILE),true)?:[]):[];}
function saveBots($b){file_put_contents(MASTER_FILE,json_encode($b,JSON_PRETTY_PRINT),LOCK_EX);}
function getBotDir($id){$d=BOTS_DIR.preg_replace('/[^a-zA-Z0-9_]/','_',$id).'/';if(!is_dir($d)){@mkdir($d,0755,true);@mkdir($d.'uploads/',0755,true);}return $d;}
function loadDB($id){
    $f=getBotDir($id).'data.json';
    $def=['users'=>[],'ukeys'=>[],'lkeys'=>[],'stats'=>['searches'=>0,'cmds'=>0],
        'pages'=>[],
        'settings'=>['adminId'=>'','global_vars'=>"ADMINS=123456\nVIP=-100123",'api_keys'=>[],'bot_vars'=>'',
            'free_text'=>['enabled'=>false,'chat_mode'=>'both','mention_only'=>false,
                'text'=>'👋 Hi {tg_name}! Use /start to begin.','media'=>'','access_control'=>''],
            'force_join'=>['enabled'=>false,'channels'=>[],'message'=>'⚠️ <b>Please join our channel(s) first!</b>\n\nThen come back and try again 😊','media'=>'','buttons'=>[]],
            'apk_renamer'=>['enabled'=>false,'new_name'=>'RebelApp','caption'=>'✅ {new_name} ready hai!\n\n📁 Original: {original_name}','admin_only'=>false]],
        'dyn_vars'=>[]];
    if(!file_exists($f)){file_put_contents($f,json_encode($def,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);return $def;}
    $d=json_decode(file_get_contents($f),true);
    if(!is_array($d))return $def;
    if(!isset($d['settings']['free_text']))$d['settings']['free_text']=$def['settings']['free_text'];
    else{$dft=$def['settings']['free_text'];foreach($dft as $mk=>$mv){if(!isset($d['settings']['free_text'][$mk]))$d['settings']['free_text'][$mk]=$mv;}}
    if(!isset($d['settings']['force_join']))$d['settings']['force_join']=$def['settings']['force_join'];
    else{$dfj=$def['settings']['force_join'];foreach($dfj as $mk=>$mv){if(!isset($d['settings']['force_join'][$mk]))$d['settings']['force_join'][$mk]=$mv;}}

    $defWm=['enabled'=>false,'text'=>'👋 Welcome {tg_mention} to the group!
Glad to have you here 🎉','media'=>'','buttons'=>[]];
    if(!isset($d['settings']['welcome_message']))$d['settings']['welcome_message']=$defWm;
    else{foreach($defWm as $mk=>$mv){if(!array_key_exists($mk,$d['settings']['welcome_message']))$d['settings']['welcome_message'][$mk]=$mv;}}

    $defUt=['enabled'=>false,'trigger'=>'@all','message'=>'📢 Tagging everyone:','batch_size'=>5,'delay'=>1];
    if(!isset($d['settings']['user_tagger']))$d['settings']['user_tagger']=$defUt;
    else{foreach($defUt as $mk=>$mv){if(!array_key_exists($mk,$d['settings']['user_tagger']))$d['settings']['user_tagger'][$mk]=$mv;}}

    $defRose=[
        'enabled'=>false,
        'warn_limit'=>3,
        'warn_action'=>'kick', // kick / ban / mute
        'warn_mute_duration'=>60, // minutes (if action=mute)
        'rules'=>'',
        'filters'=>[], // [{keyword, reply, media, is_regex}]
        'notes'=>[], // [{name, text, media}]
        'locks'=>['url'=>false,'photo'=>false,'video'=>false,'sticker'=>false,'gif'=>false,'voice'=>false,'audio'=>false,'document'=>false,'forward'=>false,'game'=>false,'location'=>false,'contact'=>false,'poll'=>false,'nsfw'=>false],
        'flood'=>['enabled'=>false,'limit'=>5,'window'=>10,'action'=>'mute','mute_duration'=>5],
        'blacklist'=>[], // [word,...]
        'blacklist_action'=>'delete', // delete / warn / ban
        'greeting'=>['enabled'=>false,'text'=>'👋 Welcome {tg_mention}!','media'=>'','mute_new'=>false,'mute_duration'=>0,'captcha'=>false],
        'goodbye'=>['enabled'=>false,'text'=>'👋 {tg_name} left the group.'],
        'report'=>['enabled'=>true,'reply'=>'🚨 <b>Report sent!</b>\nAdmins will review shortly.'],
        'anti_spam'=>['enabled'=>false,'action'=>'ban'],
        'log_channel'=>'',
        'cleanservice'=>false, // delete join/leave messages
        'cleancommands'=>false, // delete commands after reply
        // Custom reply message templates
        'reply_msgs'=>[
            'warn'        => '⚠️ <b>{mention} has been warned!</b> [{count}/{limit}]' . "\n" . 'Reason: {reason}',
            'warn_limit'  => '🚨 {mention} has hit the warn limit! Action: <b>{action}</b>',
            'ban'         => '🚫 <b>User Banned!</b>' . "\n" . '👤 {mention}' . "\n" . '📝 Reason: {reason}',
            'kick'        => '👢 <b>User Kicked!</b>' . "\n" . '👤 {mention}' . "\n" . '📝 Reason: {reason}',
            'mute'        => '🔇 <b>User Muted!</b>' . "\n" . '👤 {mention}' . "\n" . '⏱ Duration: {duration}' . "\n" . '📝 Reason: {reason}',
            'tban'        => '⏳ <b>User Temp Banned!</b>' . "\n" . '👤 {mention}' . "\n" . '⏱ Duration: {duration}' . "\n" . '📝 Reason: {reason}',
            'unmute'      => '🔊 <b>User Unmuted!</b>' . "\n" . '👤 {mention}',
            'unban'       => '✅ <b>User Unbanned!</b>' . "\n" . '👤 {mention}',
            'flood'       => '⚠️ <b>Flood Detected!</b> Slow down!',
            'blacklist'   => '⚠️ That word is not allowed here.',
            'locked'      => '🔒 <b>{locktype} are locked</b> in this group.',
            'promoted'    => '⬆️ <b>Promoted!</b>' . "\n" . '👤 {mention}',
            'demoted'     => '⬇️ <b>Demoted!</b>' . "\n" . '👤 {mention}',
            'pinned'      => '📌 Message pinned.',
            'unpinned'    => '📌 Message unpinned.',
            'purged'      => '🗑 Purged {count} messages.',
        ],
    ];
    if(!isset($d['settings']['rose']))$d['settings']['rose']=$defRose;
    else{foreach($defRose as $mk=>$mv){if(!array_key_exists($mk,$d['settings']['rose']))$d['settings']['rose'][$mk]=$mv;}}

    if(!isset($d['rose_warns']))$d['rose_warns']=[];

    if(!isset($d['rose_flood']))$d['rose_flood']=[];

    if(!isset($d['group_members']))$d['group_members']=[];
    if(!isset($d['settings']['api_keys']))$d['settings']['api_keys']=[];
    if(!isset($d['settings']['bot_vars']))$d['settings']['bot_vars']='';
    if(!isset($d['dyn_vars']))$d['dyn_vars']=[];

    $defLinkAuto=['enabled'=>false,'rules'=>[]];
    if(!isset($d['settings']['link_automation']))$d['settings']['link_automation']=$defLinkAuto;
    else{foreach($defLinkAuto as $mk=>$mv){if(!array_key_exists($mk,$d['settings']['link_automation']))$d['settings']['link_automation'][$mk]=$mv;}}
    if(!isset($d['settings']['la_bot_id']))$d['settings']['la_bot_id']='';
    if(!isset($d['la_fc_sessions']))$d['la_fc_sessions']=[];

    if(!isset($d['pages']))$d['pages']=is_array($d['settings']['pages']??null)?$d['settings']['pages']:[];
    if(!is_array($d['pages']))$d['pages']=[];
    if(isset($d['settings']['pages']))unset($d['settings']['pages']);

    $d['users']=loadUsersRaw($id,$d['users']??null);

    return $d;
}
function saveDB($id,$d){
    if(isset($d['users'])){
        saveUsersRaw($id,$d['users']);
        unset($d['users']);
    }
    file_put_contents(getBotDir($id).'data.json',json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);
}
function usersDataFile($id){return getBotDir($id).'users.json';}
function usersIndexFile($id){return getBotDir($id).'users_index.json';}
function normalizeUsers($users){
    if(!is_array($users))return [];
    if(isset($users['users'])&&is_array($users['users']))$users=$users['users'];
    if(empty($users))return [];
    $keys=array_keys($users);
    $isList=!empty($keys)&&$keys===range(0,count($users)-1);
    $map=[];
    if($isList){
        foreach($users as $u){
            if(!is_array($u))continue;
            $uid=(string)($u['id']??'');
            if($uid==='')continue;
            $u['id']=$uid;
            $map[$uid]=$u;
        }
    }else{
        foreach($users as $k=>$u){
            if(!is_array($u))continue;
            $uid=(string)($u['id']??$k);
            $u['id']=$uid;
            $map[$uid]=$u;
        }
    }
    return $map;
}
function usersFromDataJson($id){
    $f=getBotDir($id).'data.json';
    if(!file_exists($f))return [];
    $d=json_decode(file_get_contents($f),true);
    if(!is_array($d))return [];
    return normalizeUsers($d['users']??[]);
}
function usersStripFromDataJson($id){
    $f=getBotDir($id).'data.json';
    if(!file_exists($f))return;
    $d=json_decode(file_get_contents($f),true);
    if(!is_array($d)||!array_key_exists('users',$d))return;
    unset($d['users']);
    file_put_contents($f,json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);
}
function userListRow($u,$fallbackId=''){
    return ['id'=>(string)($u['id']??$fallbackId),'name'=>$u['name']??'','username'=>$u['username']??'','searchesLeft'=>$u['searchesLeft']??0,'key'=>$u['key']??'','banned'=>!empty($u['banned']),'joined'=>$u['joined']??''];
}
function saveUsersRaw($id,$users){
    $users=normalizeUsers($users);
    file_put_contents(usersDataFile($id),json_encode($users,JSON_UNESCAPED_UNICODE),LOCK_EX);
    @unlink(usersIndexFile($id));
}
function loadUsersRaw($id,$fromDbUsers=null){
    $fromData=usersFromDataJson($id);
    if($fromDbUsers!==null)$fromData=normalizeUsers($fromDbUsers)?:$fromData;
    $uf=usersDataFile($id);
    $fromFile=[];
    if(file_exists($uf)){
        $raw=@file_get_contents($uf);
        if($raw!==false&&trim($raw)!==''&&trim($raw)!=='[]'&&trim($raw)!=='{}'){
            $u=json_decode($raw,true);
            if(is_array($u))$fromFile=normalizeUsers($u);
        }
    }
    if(empty($fromFile)&&!empty($fromData)){
        saveUsersRaw($id,$fromData);
        usersStripFromDataJson($id);
        return $fromData;
    }
    if(!empty($fromFile)){
        if(!empty($fromData))usersStripFromDataJson($id);
        return $fromFile;
    }
    return $fromData;
}
function usersRowsFromMap($users){
    $rows=[];
    foreach(normalizeUsers($users) as $uid=>$u){
        $rows[]=userListRow($u,(string)$uid);
    }
    return $rows;
}
function usersFilterRows($rows,$search=''){
    if($search==='')return $rows;
    $uq=strtolower($search);
    return array_values(array_filter($rows,static function($u)use($uq){
        return str_contains(strtolower($u['name']??''),$uq)||str_contains(strtolower($u['username']??''),$uq)||str_contains((string)($u['id']??''),$uq)||str_contains(strtolower($u['key']??''),$uq);
    }));
}
function rebuildUsersIndex($id){
    $users=loadUsersRaw($id);
    $rows=usersRowsFromMap($users);
    if(count($rows)>1)usort($rows,fn($a,$b)=>strcmp($b['joined']??'',$a['joined']??''));
    $idx=['total'=>count($rows),'updated'=>time(),'items'=>$rows];
    @file_put_contents(usersIndexFile($id),json_encode($idx,JSON_UNESCAPED_UNICODE),LOCK_EX);
    return $idx;
}
function loadUsersIndex($id){
    $uf=usersDataFile($id);$if=usersIndexFile($id);
    if(file_exists($if)&&file_exists($uf)&&filemtime($if)>=filemtime($uf)){
        $idx=json_decode(@file_get_contents($if),true);
        if(is_array($idx)&&isset($idx['items'],$idx['total'])&&is_array($idx['items']))return $idx;
    }
    return rebuildUsersIndex($id);
}
function getUsersPageDirect($id,$page,$limit,$search=''){
    $users=loadUsersRaw($id);
    $rows=usersFilterRows(usersRowsFromMap($users),$search);
    if($search===''&&count($rows)>1&&count($rows)<=5000)usort($rows,fn($a,$b)=>strcmp($b['joined']??'',$a['joined']??''));
    $total=count($rows);
    $pages=max(1,(int)ceil($total/max(1,$limit)));
    if($page>$pages)$page=$pages;
    return ['data'=>array_slice($rows,($page-1)*$limit,$limit),'total'=>$total,'page'=>$page,'pages'=>$pages,'limit'=>$limit];
}
function getUsersPage($id,$page,$limit,$search=''){
    try{
        $idx=loadUsersIndex($id);
        if(!empty($idx['items'])||($idx['total']??0)===0){
            $rows=usersFilterRows($idx['items'],$search);
            $total=count($rows);
            $pages=max(1,(int)ceil($total/max(1,$limit)));
            if($page>$pages)$page=$pages;
            return ['data'=>array_slice($rows,($page-1)*$limit,$limit),'total'=>$total,'page'=>$page,'pages'=>$pages,'limit'=>$limit];
        }
    }catch(Throwable $e){}
    return getUsersPageDirect($id,$page,$limit,$search);
}
function loadLogs($id){$f=getBotDir($id).'logs.json';return file_exists($f)?(json_decode(file_get_contents($f),true)?:[]):[];}
function addLog($id,$txt,$type='info'){$l=loadLogs($id);array_unshift($l,['time'=>date('c'),'text'=>$txt,'type'=>$type]);if(count($l)>500)$l=array_slice($l,0,500);file_put_contents(getBotDir($id).'logs.json',json_encode($l),LOCK_EX);}
function setCache($id,$k,$v){$f=getBotDir($id).'cache.json';$c=file_exists($f)?json_decode(file_get_contents($f),true):[];if(!is_array($c))$c=[];$c[$k]=['t'=>time(),'v'=>$v];foreach($c as $ck=>$cv)if(time()-$cv['t']>3600)unset($c[$ck]);file_put_contents($f,json_encode($c),LOCK_EX);}
function getCache($id,$k){$f=getBotDir($id).'cache.json';$c=file_exists($f)?json_decode(file_get_contents($f),true):[];return $c[$k]['v']??null;}

function dynVarSet(&$db,$key,$value,$op='set'){
    $key=preg_replace('/[^a-zA-Z0-9_]/','_',$key);
    if($op==='append_unique'||$op==='append'){
        $cur=$db['dyn_vars'][$key]??'';
        $parts=$cur!==''?explode(',',$cur):[];
        if($op==='append_unique'){if(!in_array($value,$parts))$parts[]=$value;}
        else{$parts[]=$value;}
        $db['dyn_vars'][$key]=implode(',',$parts);
    }else{$db['dyn_vars'][$key]=$value;}
}
function dynVarGet(&$db,$key){
    $key=preg_replace('/[^a-zA-Z0-9_]/','_',$key);
    return $db['dyn_vars'][$key]??'';
}

function tg($method,$params=[],$token=''){
    if(!$token)return['ok'=>false];
    $ch=curl_init();
    $o=[CURLOPT_URL=>TG_BASE.$token.'/'.$method,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>TG_TO,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2];
    if($params){$o[CURLOPT_POST]=true;$o[CURLOPT_POSTFIELDS]=json_encode($params);$o[CURLOPT_HTTPHEADER]=['Content-Type: application/json'];}
    curl_setopt_array($ch,$o);$r=curl_exec($ch);curl_close($ch);return json_decode($r,true)?:[];
}

function sendDocument($chatId,$docUrl,$caption,$kb,$token){
    $p=['chat_id'=>$chatId,'document'=>$docUrl,'parse_mode'=>'HTML'];
    if($caption)$p['caption']=$caption;
    if($kb)$p['reply_markup']=$kb;
    return tg('sendDocument',$p,$token);
}

// ═══════════════════════════════════════════════════════════════════════════
// ██████╗ ██████╗     ██████╗ ███████╗██████╗  ██████╗ ███████╗██╗████████╗
// ██╔══██╗██╔══██╗    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔════╝██║╚══██╔══╝
// ██████╔╝██████╔╝    ██║  ██║█████╗  ██████╔╝██║   ██║███████╗██║   ██║
// ██╔══██╗██╔══██╗    ██║  ██║██╔══╝  ██╔═══╝ ██║   ██║╚════██║██║   ██║
// ██║  ██║██████╔╝    ██████╔╝███████╗██║     ╚██████╔╝███████║██║   ██║
//  ╚═╝  ╚═╝╚═════╝     ╚═════╝ ╚══════╝╚═╝      ╚═════╝ ╚══════╝╚═╝   ╚═╝
// RockyBook Deposit Bot — Integrated Module
// ═══════════════════════════════════════════════════════════════════════════
define('RBD_VERSION',     '1.0');
define('RBD_CONFIG_FILE', __DIR__ . '/rbd_config.json');
define('RBD_LOG_FILE',    __DIR__ . '/rbd_logs.json');
define('RBD_STATE_FILE',  __DIR__ . '/rbd_states.json');
define('RBD_COOKIE_DIR',  __DIR__ . '/rbd_cookies/');
define('RBD_QR_DIR',      __DIR__ . '/rbd_qr/');
define('RBD_RATE_FILE',   __DIR__ . '/rbd_ratelimit.json');
define('RBD_LEDGER_FILE', __DIR__ . '/rbd_ledger.json');
define('RB_API_BASE',     'https://rockybook.vip/api');
define('RBD_MIN_DEPOSIT', 500);
define('RBD_BLOCK_MINUTES', 30);
define('RBD_MAX_INCOMPLETE', 2);
define('RBD_DEPOSIT_CLIENT', 'Ujjwal0999');
define('RBD_WITHDRAWAL_CONTACT', '@Rebel_babyyy');
if(!is_dir(RBD_COOKIE_DIR))@mkdir(RBD_COOKIE_DIR,0755,true);
if(!is_dir(RBD_QR_DIR))@mkdir(RBD_QR_DIR,0755,true);

$_rbdDefaultConfig=[
    'admin_pass'     => 'rebel@2026',
    'bot_token'      => '',
    'admin_chat_id'  => '',
    'rb_phone'       => '',
    'rb_password'    => '',
    'rb_branch'      => 'RBVIP1D',
    'rb_bank_id'     => '',
    'min_deposit'    => 500,
    'max_deposit'    => 100000,
    'welcome_msg'    => "🎯 <b>Rebel B2W</b>\n\nWelcome! Use /Deposit to make a deposit.\n\n💰 /Deposit — Deposit\n💸 /Withdrawal — Withdraw\n💳 /Balance — Balance\n❓ /Help — Help",
    'deposit_thanks' => "✅ <b>Transaction Submitted!</b>\n\nAdmin will verify shortly.",
];
function rbdLoadConfig(){
    global $_rbdDefaultConfig;
    if(!file_exists(RBD_CONFIG_FILE))return$_rbdDefaultConfig;
    $l=json_decode(file_get_contents(RBD_CONFIG_FILE),true);
    return is_array($l)?array_merge($_rbdDefaultConfig,$l):$_rbdDefaultConfig;
}
function rbdSaveConfig($cfg){file_put_contents(RBD_CONFIG_FILE,json_encode($cfg,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);}

function rbdGetStates(){if(!file_exists(RBD_STATE_FILE))return[];return json_decode(file_get_contents(RBD_STATE_FILE),true)?:[];}
function rbdSetState($cid,$state,$data=[]){$s=rbdGetStates();$s[(string)$cid]=['state'=>$state,'data'=>$data,'ts'=>time()];file_put_contents(RBD_STATE_FILE,json_encode($s,JSON_UNESCAPED_UNICODE),LOCK_EX);}
function rbdGetState($cid){$s=rbdGetStates();$e=$s[(string)$cid]??null;if($e&&(time()-($e['ts']??0))>1800){rbdClearState($cid);return null;}return $e;}
function rbdClearState($cid){$s=rbdGetStates();unset($s[(string)$cid]);file_put_contents(RBD_STATE_FILE,json_encode($s,JSON_UNESCAPED_UNICODE),LOCK_EX);}

function rbdRlLoad(){if(!file_exists(RBD_RATE_FILE))return[];return json_decode(file_get_contents(RBD_RATE_FILE),true)?:[];}
function rbdRlSave($d){file_put_contents(RBD_RATE_FILE,json_encode($d,JSON_UNESCAPED_UNICODE),LOCK_EX);}
function rbdRlIsBlocked($cid){$rl=rbdRlLoad();$rec=$rl[(string)$cid]??null;if(!$rec)return false;if(!empty($rec['blocked_until'])&&time()<$rec['blocked_until'])return $rec['blocked_until'];return false;}
function rbdRlStart($cid){$rl=rbdRlLoad();$k=(string)$cid;if(!isset($rl[$k]))$rl[$k]=['incomplete'=>0,'blocked_until'=>0,'last_start'=>0];$rl[$k]['incomplete']++;$rl[$k]['last_start']=time();if($rl[$k]['incomplete']>=RBD_MAX_INCOMPLETE){$rl[$k]['blocked_until']=time()+(RBD_BLOCK_MINUTES*60);$rl[$k]['incomplete']=0;rbdRlSave($rl);return false;}rbdRlSave($rl);return true;}
function rbdRlCompleted($cid){$rl=rbdRlLoad();$k=(string)$cid;if(isset($rl[$k])){$rl[$k]['incomplete']=0;$rl[$k]['blocked_until']=0;}rbdRlSave($rl);}
function rbdRlRemaining($until){$s=max(0,$until-time());return ceil($s/60).' minute'.(ceil($s/60)==1?'':'s');}

function rbdLdLoad(){if(!file_exists(RBD_LEDGER_FILE))return[];return json_decode(file_get_contents(RBD_LEDGER_FILE),true)?:[];}
function rbdLdSave($d){file_put_contents(RBD_LEDGER_FILE,json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);}
function rbdLdGetUser($cid){$ld=rbdLdLoad();return $ld[(string)$cid]??['chat_id'=>$cid,'balance'=>0,'deposits'=>[],'withdrawals'=>[]];}
function rbdLdAddDeposit($cid,$amount,$utr,$txnId=null){$ld=rbdLdLoad();$k=(string)$cid;if(!isset($ld[$k]))$ld[$k]=['chat_id'=>$cid,'balance'=>0,'deposits'=>[],'withdrawals'=>[]];$ld[$k]['balance']+=(float)$amount;$ld[$k]['deposits'][]=['amount'=>(float)$amount,'utr'=>$utr,'txn_id'=>$txnId,'time'=>date('c'),'status'=>'approved'];rbdLdSave($ld);}
function rbdLdAddWithdrawal($cid,$amount){$ld=rbdLdLoad();$k=(string)$cid;if(!isset($ld[$k]))$ld[$k]=['chat_id'=>$cid,'balance'=>0,'deposits'=>[],'withdrawals'=>[]];$ld[$k]['withdrawals'][]=['amount'=>(float)$amount,'time'=>date('c'),'status'=>'pending'];rbdLdSave($ld);}

function rbdLog($text,$type='info'){$l=file_exists(RBD_LOG_FILE)?(json_decode(file_get_contents(RBD_LOG_FILE),true)?:[]):[];array_unshift($l,['time'=>date('c'),'text'=>$text,'type'=>$type]);if(count($l)>500)$l=array_slice($l,0,500);file_put_contents(RBD_LOG_FILE,json_encode($l,JSON_UNESCAPED_UNICODE),LOCK_EX);}

function rbdTgSend($token,$cid,$text,$kb=null){$p=['chat_id'=>$cid,'text'=>$text,'parse_mode'=>'HTML','disable_web_page_preview'=>true];if($kb)$p['reply_markup']=json_encode($kb);return tg('sendMessage',$p,$token);}
function rbdTgSendPhoto($token,$cid,$photoPath,$caption='',$kb=null){$ch=curl_init();$f=['chat_id'=>$cid,'caption'=>$caption,'parse_mode'=>'HTML','photo'=>new CURLFile($photoPath,'image/png','qr.png')];if($kb)$f['reply_markup']=json_encode($kb);curl_setopt_array($ch,[CURLOPT_URL=>'https://api.telegram.org/bot'.$token.'/sendPhoto',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_TIMEOUT=>40,CURLOPT_POSTFIELDS=>$f]);$r=json_decode(curl_exec($ch),true);curl_close($ch);return $r;}

function rbdApi($endpoint,$method='GET',$data=null,$cookieFile=null){
    $url=RB_API_BASE.$endpoint;$cf=$cookieFile?:(RBD_COOKIE_DIR.'admin.txt');
    $headers=['Content-Type: application/json','Accept: application/json','User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36','Origin: https://rockybook.vip','Referer: https://rockybook.vip/'];
    $ch=curl_init();$opts=[CURLOPT_URL=>$url,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>30,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_HTTPHEADER=>$headers,CURLOPT_COOKIEJAR=>$cf,CURLOPT_COOKIEFILE=>$cf];
    $m=strtoupper($method);if($m==='POST'){$opts[CURLOPT_POST]=true;$opts[CURLOPT_POSTFIELDS]=$data!==null?json_encode($data):'{}';}elseif(in_array($m,['PUT','PATCH','DELETE'])){$opts[CURLOPT_CUSTOMREQUEST]=$m;if($data!==null)$opts[CURLOPT_POSTFIELDS]=json_encode($data);}
    curl_setopt_array($ch,$opts);$raw=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);$err=curl_error($ch);curl_close($ch);
    return['code'=>$code,'raw'=>$raw?:'','data'=>json_decode($raw,true),'error'=>$err,'ok'=>$code>=200&&$code<300];
}

function rbdAdminLogin($cfg){
    $cf=RBD_COOKIE_DIR.'admin.txt';
    $check=rbdApi('/auth/fetchUserByToken','GET',null,$cf);
    if($check['ok']&&isset($check['data']['user']))return $check['data']['user'];
    $phone=trim($cfg['rb_phone']??'');$pass=trim($cfg['rb_password']??'');
    if(!$phone||!$pass)return false;
    $res=rbdApi('/auth/login','POST',['loginType'=>$phone,'password'=>$pass],$cf);
    if(!$res['ok']||empty($res['data']))return false;
    $d=$res['data'];return $d['user']??$d['data']??((!empty($d['success']))?$d:false);
}

function rbdGetAdminUser($cfg){
    $cf=RBD_COOKIE_DIR.'admin_user.json';
    if(file_exists($cf)&&(time()-filemtime($cf))<3600){$c=json_decode(file_get_contents($cf),true);if($c&&isset($c['_id']))return $c;}
    $u=rbdAdminLogin($cfg);if($u&&is_array($u))file_put_contents($cf,json_encode($u,JSON_UNESCAPED_UNICODE),LOCK_EX);return $u;
}

function rbdGetDepositUserId($cfg){
    $cf=RBD_COOKIE_DIR.'deposit_user.json';
    if(file_exists($cf)&&(time()-filemtime($cf))<86400){$c=json_decode(file_get_contents($cf),true);if(!empty($c['_id']))return $c;}
    $cn=RBD_DEPOSIT_CLIENT;$res=rbdApi('/user/getUsers?page=1&limit=100000');
    if($res['ok']){$users=$res['data']['users']??$res['data']['data']??[];if(is_array($users)){foreach($users as $u){if(strtolower($u['clientName']??'')===strtolower($cn)){$found=['_id'=>$u['_id']??$u['id'],'clientName'=>$u['clientName']];file_put_contents($cf,json_encode($found,JSON_UNESCAPED_UNICODE),LOCK_EX);return $found;}}}}
    rbdLog("Deposit user '{$cn}' not found — using admin as fallback",'error');return rbdGetAdminUser($cfg);
}

function rbdNormalizeBank($b){
    if(!is_array($b)||empty($b))return null;
    $n=['upiId'=>$b['upiId']??$b['upi']??$b['vpa']??null,'accNo'=>$b['accNo']??$b['accountNo']??$b['accountNumber']??$b['account_no']??null,'ifscCode'=>$b['ifscCode']??$b['ifsc']??$b['IFSC']??null,'bankName'=>$b['bankName']??$b['bank']??$b['bank_name']??null,'accHolderName'=>$b['accHolderName']??$b['holderName']??$b['accountHolder']??$b['name']??null,'isActive'=>$b['isActive']??true];
    if($n['upiId']||$n['accNo']||$n['ifscCode'])return $n;return null;
}

function rbdGetBankDetails($cfg,$amount=500){
    $branch=trim($cfg['rb_branch']??'RBVIP1D');
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>'https://www.powerdreams.co/api/online/request/fetchAvailablePeer',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_HTTPHEADER=>['Content-Type: application/json','Accept: application/json','Origin: https://www.powerdreams.co','Referer: https://www.powerdreams.co/online/pay/'.$branch.'/test','User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36'],CURLOPT_POSTFIELDS=>json_encode(['transactionType'=>'Deposit','branchUserName'=>$branch,'amount'=>(int)$amount])]);
    $raw=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);curl_close($ch);
    $data=json_decode($raw,true);rbdLog("fetchAvailablePeer HTTP={$code} branch={$branch} amount={$amount}",'info');
    if(empty($data['success'])||empty($data['bankDetails'])){rbdLog("fetchAvailablePeer failed: ".($data['message']??'no bankDetails'),'error');return null;}
    return rbdNormalizeBank($data['bankDetails']);
}

function rbdCreateDeposit($cfg,$userId,$amount,$mode='PowerPay'){
    $branch=trim($cfg['rb_branch']??'RBVIP1D');
    $payload=['userId'=>$userId,'amount'=>(float)$amount,'transactionType'=>'Deposit','role'=>'User','mode'=>$mode,'branchUserName'=>$branch];
    $res=rbdApi('/transaction/createTransaction','POST',$payload);if(!$res['ok'])return null;
    $d=$res['data'];if(!empty($d['success'])&&isset($d['data']))return $d['data'];return $d;
}

function rbdFetchImage($url,$timeout=25){
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>$url,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>$timeout,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_USERAGENT=>'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36']);
    $data=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);curl_close($ch);
    if($code===200&&$data&&strlen($data)>500)return $data;return null;
}

function rbdScreenshotUrl($url,$outputFile,$timeout=35){
    $enc=urlencode($url);
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>"https://api.microlink.io/?url={$enc}&screenshot=true&meta=false&embed=screenshot.url&timeout=20000",CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>$timeout,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_USERAGENT=>'Mozilla/5.0']);
    $ml=json_decode(curl_exec($ch),true);curl_close($ch);
    $ssUrl=$ml['data']['screenshot']['url']??$ml['data']['screenshot']??null;
    if($ssUrl&&strncmp($ssUrl,'http',4)===0){$d=rbdFetchImage($ssUrl,20);if($d&&strlen($d)>500){file_put_contents($outputFile,$d);return 'microlink';}}
    $d2=rbdFetchImage("https://image.thum.io/get/width/800/crop/1200/png/{$enc}",20);
    if($d2&&strlen($d2)>500){file_put_contents($outputFile,$d2);return 'thum.io';}
    return null;
}

function rbdFetchRealQR($txnId,$branch,$outputFile,$timeout=35){
    $res=rbdApi("/transaction/fetch_powerPay_transaction_screenshot/{$txnId}");
    if($res['ok']&&!empty($res['data'])){$d=$res['data'];$imgData=$d['screenshot']??$d['image']??$d['data']??$d['url']??$d['screenshotUrl']??null;if($imgData){if(strncmp($imgData,'data:image',10)===0){$bytes=base64_decode(preg_replace('/^data:image\/\w+;base64,/','',$imgData));if($bytes&&strlen($bytes)>500){file_put_contents($outputFile,$bytes);return 'rockybook-api';}}elseif(strncmp($imgData,'http',4)===0){$bytes=rbdFetchImage($imgData,20);if($bytes&&strlen($bytes)>500){file_put_contents($outputFile,$bytes);return 'rockybook-api-url';}}}}
    $payUrl="https://www.powerdreams.co/online/pay/{$branch}/{$txnId}";$src=rbdScreenshotUrl($payUrl,$outputFile,$timeout);if($src)return "payment-page-{$src}";return null;
}

function rbdHandleDeposit($token,$cid,$userName,$cfg){
    $blocked=rbdRlIsBlocked($cid);
    if($blocked){rbdTgSend($token,$cid,"🚫 <b>Temporarily Restricted</b>\n\nYou started a deposit without completing it.\n⏳ Please wait <b>".rbdRlRemaining($blocked)."</b> before trying again.");return;}
    $minDep=(int)($cfg['min_deposit']??RBD_MIN_DEPOSIT);$maxDep=(int)($cfg['max_deposit']??100000);
    rbdTgSend($token,$cid,"💰 <b>Deposit Amount</b>\n\nMinimum: <b>₹".number_format($minDep)."</b>\nMaximum: <b>₹".number_format($maxDep)."</b>\n\n<i>Enter amount (e.g. 1000)</i>",['inline_keyboard'=>[[['text'=>'₹500','callback_data'=>'rbdamt_500'],['text'=>'₹1000','callback_data'=>'rbdamt_1000'],['text'=>'₹2000','callback_data'=>'rbdamt_2000']],[['text'=>'₹5000','callback_data'=>'rbdamt_5000'],['text'=>'₹10000','callback_data'=>'rbdamt_10000'],['text'=>'₹25000','callback_data'=>'rbdamt_25000']]]]);
    rbdSetState($cid,'awaiting_amount',[]);
}

function rbdProcessAmount($token,$cid,$amount,$cfg){
    $minDep=(int)($cfg['min_deposit']??RBD_MIN_DEPOSIT);$maxDep=(int)($cfg['max_deposit']??100000);
    if($amount<$minDep){rbdTgSend($token,$cid,"❌ Minimum deposit is <b>₹".number_format($minDep)."</b>.");return false;}
    if($amount>$maxDep){rbdTgSend($token,$cid,"❌ Maximum deposit is <b>₹".number_format($maxDep)."</b>.");return false;}
    rbdTgSend($token,$cid,"⏳ <b>Processing...</b>\n\nCreating deposit request...");
    $adminUser=rbdGetAdminUser($cfg);if(!$adminUser){rbdTgSend($token,$cid,"❌ Server error. Please contact admin.");rbdLog("Deposit failed: RB login failed chat={$cid}",'error');return false;}
    $depositUser=rbdGetDepositUserId($cfg);$rbUserId=$depositUser['_id']??$depositUser['id']??($adminUser['_id']??null);$branch=trim($cfg['rb_branch']??'RBVIP1D');
    $txn=rbdCreateDeposit($cfg,$rbUserId,$amount);$txnId=$txn['_id']??$txn['id']??$txn['transactionId']??null;$mode=$txn['mode']??'PowerPay';
    if(!$txnId){rbdTgSend($token,$cid,"❌ Transaction could not be created. Please try again later.");rbdLog("Deposit failed: no txnId chat={$cid} amount={$amount}",'error');return false;}
    $bank=rbdGetBankDetails($cfg,$amount);$upiId=$bank['upiId']??null;$accNo=$bank['accNo']??null;$ifsc=$bank['ifscCode']??null;$bankNm=$bank['bankName']??null;$accName=$bank['accHolderName']??null;
    $payPageUrl="https://www.powerdreams.co/online/pay/{$branch}/{$txnId}";
    $kb=['inline_keyboard'=>[[['text'=>'✅ Payment Done — Submit UTR','callback_data'=>'rbdsubmitutr_'.$txnId]]]];
    $bankMsg="🎯 <b>Rebel B2W Deposit Details</b>\n\n💰 Amount: <b>₹".number_format($amount)."</b>\n🔖 Txn ID: <code>{$txnId}</code>\n";
    if($upiId||$accNo){$bankMsg.="\n<b>💳 Bank / UPI Details:</b>\n".($upiId?"📱 UPI ID: <code>{$upiId}</code>\n":'').($accName?"👤 Name: <b>{$accName}</b>\n":'').($accNo?"🔢 Acc No: <code>{$accNo}</code>\n":'').($ifsc?"🏛 IFSC: <code>{$ifsc}</code>\n":'').($bankNm?"🏦 Bank: {$bankNm}\n":'');}
    else{$bankMsg.="\n🌐 <b>Payment Page:</b>\n<code>{$payPageUrl}</code>\n\n<i>Open the link above to scan QR and pay</i>\n";}
    $bankMsg.="\n⚠️ <b>Send exact amount ₹".number_format($amount)." only</b>\n\nAfter payment, send your UTR or screenshot 👇";
    rbdTgSend($token,$cid,"⏳ Fetching payment QR...");
    $qrFile=RBD_QR_DIR.'qr_'.$cid.'_'.time().'.png';sleep(3);
    $qrSource=rbdFetchRealQR($txnId,$branch,$qrFile);
    if($qrSource&&file_exists($qrFile)&&filesize($qrFile)>500){$cap="📸 <b>Payment QR</b>\n\n💰 Amount: <b>₹".number_format($amount)."</b>\n".($upiId?"📱 UPI: <code>{$upiId}</code>\n":'')."🔖 Txn: <code>{$txnId}</code>";$r=rbdTgSendPhoto($token,$cid,$qrFile,$cap,null);@unlink($qrFile);if(!empty($r['ok'])){rbdTgSend($token,$cid,$bankMsg,$kb);goto rbd_save_state;}}
    if($upiId){$upiStr="upi://pay?pa={$upiId}&am={$amount}&cu=INR&tn=RebelB2W";$qrApis=["https://api.qrserver.com/v1/create-qr-code/?size=512x512&data=".urlencode($upiStr),"https://quickchart.io/qr?size=512&text=".urlencode($upiStr),"https://chart.googleapis.com/chart?cht=qr&chs=512x512&chl=".urlencode($upiStr)];$uqf=RBD_QR_DIR.'upi_'.$cid.'_'.time().'.png';$sent=false;foreach($qrApis as $qa){$bytes=rbdFetchImage($qa,12);if($bytes&&strlen($bytes)>500){file_put_contents($uqf,$bytes);$cap="📱 <b>UPI QR Code</b>\n\n💰 Amount: <b>₹".number_format($amount)."</b>\n📱 UPI ID: <code>{$upiId}</code>\n🔖 Txn ID: <code>{$txnId}</code>";$r=rbdTgSendPhoto($token,$cid,$uqf,$cap,null);@unlink($uqf);if(!empty($r['ok'])){$sent=true;rbdTgSend($token,$cid,$bankMsg,$kb);break;}}}if(!$sent)rbdTgSend($token,$cid,$bankMsg."\n\n🔗 UPI Pay: <code>{$upiStr}</code>",$kb);}
    else{rbdTgSend($token,$cid,$bankMsg."\n\n🌐 Open this link to pay:\n".$payPageUrl,$kb);}
    rbd_save_state:
    rbdSetState($cid,'awaiting_utr',['amount'=>$amount,'txn_id'=>$txnId,'upi_id'=>$upiId,'pay_url'=>$payPageUrl]);
    rbdRlStart($cid);
    $acid=trim($cfg['admin_chat_id']??'');if($acid)rbdTgSend($token,$acid,"🆕 <b>New Deposit</b>\n\n📊 TG: <code>{$cid}</code>\n💰 Amount: ₹".number_format($amount)."\n🔖 Txn: <code>{$txnId}</code>\n".($upiId?"📱 UPI: <code>{$upiId}</code>\n":'')."🌐 Mode: {$mode}\n🕐 ".date('d/m/Y H:i:s'));
    return true;
}

function rbdTgDownload($token,$fileId){$r=tg('getFile',['file_id'=>$fileId],$token);$fp=$r['result']['file_path']??null;if(!$fp)return null;$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>"https://api.telegram.org/file/bot{$token}/{$fp}",CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>30,CURLOPT_SSL_VERIFYPEER=>true]);$b=curl_exec($ch);curl_close($ch);return($b&&strlen($b)>100)?$b:null;}

function rbdPdOcr($bytes,$mime='image/jpeg'){$tmp=sys_get_temp_dir().'/rbd_ss_'.uniqid().'.jpg';file_put_contents($tmp,$bytes);$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>'https://www.powerdreams.co/api/online/ocr/extract-utr',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_HTTPHEADER=>['Origin: https://www.powerdreams.co','Referer: https://www.powerdreams.co/online/pay/','User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)'],CURLOPT_POSTFIELDS=>['image'=>new CURLFile($tmp,$mime,'screenshot.jpg')]]);$raw=curl_exec($ch);curl_close($ch);@unlink($tmp);$data=json_decode($raw,true);if(!empty($data['success'])&&!empty($data['utr']))return trim($data['utr']);return null;}

function rbdHandleScreenshotUtr($token,$cid,$msg,$state,$cfg){
    $data=$state['data']??[];$amount=$data['amount']??0;$txnId=$data['txn_id']??null;$savedUtr=trim($data['utr']??'');
    $photo=$msg['photo']??null;$doc=$msg['document']??null;
    $fileId=null;$mime='image/jpeg';
    if($photo){$largest=end($photo);$fileId=$largest['file_id'];}elseif($doc){$fileId=$doc['file_id'];$mime=$doc['mime_type']??'image/jpeg';}
    if(!$fileId){rbdTgSend($token,$cid,"❌ Could not read the image. Please send a clear screenshot.");return;}
    rbdTgSend($token,$cid,"⏳ Verifying your screenshot...");
    $imageBytes=rbdTgDownload($token,$fileId);if(!$imageBytes){rbdTgSend($token,$cid,"❌ Could not download image. Please try again.");return;}
    $ocrUtr=rbdPdOcr($imageBytes,$mime);
    if($savedUtr&&$ocrUtr){$n1=strtoupper(preg_replace('/\s+/','',$savedUtr));$n2=strtoupper(preg_replace('/\s+/','',$ocrUtr));if($n1!==$n2){rbdTgSend($token,$cid,"❌ <b>UTR Didn't Match!</b>\n\nYou entered: <code>{$savedUtr}</code>\nScreenshot shows: <code>{$ocrUtr}</code>\n\nPlease send correct screenshot or re-enter UTR.");return;}}
    elseif(!$savedUtr&&$ocrUtr){$savedUtr=$ocrUtr;}
    rbdTgSend($token,$cid,"✅ <b>Request Queued!</b>\n\nYour payment has been submitted for verification.\n".($savedUtr?"🔢 UTR: <code>{$savedUtr}</code>\n":'')."Admin will confirm shortly.");
    rbdClearState($cid);rbdRlCompleted($cid);
    $acid=trim($cfg['admin_chat_id']??'');
    if($acid){tg('forwardMessage',['chat_id'=>$acid,'from_chat_id'=>$cid,'message_id'=>$msg['message_id']],$token);rbdTgSend($token,$acid,"✅ <b>Payment Verified</b>\n\n📊 TG: <code>{$cid}</code>\n💰 Amount: ₹".number_format($amount)."\n🔢 UTR: <code>{$savedUtr}</code>\n".($txnId?"🔖 Txn: <code>{$txnId}</code>\n":'')."🕐 ".date('d/m/Y H:i:s'));}
    rbdLog("Payment verified — chat={$cid} utr={$savedUtr} txn={$txnId}",'success');
}

function rbdHandleUpdate($update,$cfg){
    $token=trim($cfg['bot_token']??'');if(!$token)return;
    if(isset($update['callback_query'])){
        $cq=$update['callback_query'];$cid=$cq['message']['chat']['id']??'';$cbdata=$cq['data']??'';$cqId=$cq['id']??'';
        tg('answerCallbackQuery',['callback_query_id'=>$cqId],$token);
        if(str_starts_with($cbdata,'rbdamt_')){$amount=(int)substr($cbdata,7);rbdProcessAmount($token,$cid,$amount,$cfg);return;}
        if(str_starts_with($cbdata,'rbdsubmitutr_')){$state=rbdGetState($cid);if($state){rbdTgSend($token,$cid,"🔢 <b>Step 1: Enter your UTR Number</b>\n\n<i>12-digit transaction reference from your bank app</i>");rbdSetState($cid,'awaiting_utr_text',$state['data']);}}
        return;
    }
    $msg=$update['message']??$update['channel_post']??null;if(!$msg)return;
    $cid=$msg['chat']['id']??'';$text=trim($msg['text']??'');$userName=$msg['from']['username']??$msg['from']['first_name']??'User';$photo=$msg['photo']??null;$doc=$msg['document']??null;if(!$cid)return;
    $state=rbdGetState($cid);
    if($state&&($photo||$doc)){$st=$state['state']??'';if(in_array($st,['awaiting_utr','awaiting_utr_text','awaiting_screenshot'])){rbdHandleScreenshotUtr($token,$cid,$msg,$state,$cfg);return;}if($st==='awaiting_withdrawal_qr'){$data=$state['data']??[];$wAmount=(float)($data['w_amount']??0);$acid=trim($cfg['admin_chat_id']??'');if($acid){tg('forwardMessage',['chat_id'=>$acid,'from_chat_id'=>$cid,'message_id'=>$msg['message_id']],$token);rbdTgSend($token,$acid,"💸 <b>Withdrawal Request</b>\n\n📊 TG: <code>{$cid}</code>\n💰 Amount: ₹".number_format($wAmount,2)."\n🕐 ".date('d/m/Y H:i:s'));}rbdLdAddWithdrawal($cid,$wAmount);rbdClearState($cid);rbdTgSend($token,$cid,"✅ <b>Withdrawal Request Accepted</b>\n\n💰 Amount: <b>₹".number_format($wAmount,2)."</b>\n\nContact ".RBD_WITHDRAWAL_CONTACT." for assistance.");return;}}
    $cmd=strtolower(explode('@',explode(' ',$text)[0])[0]);
    if($cmd==='/start'){$welcome=str_replace('\n',"\n",$cfg['welcome_msg']??"Welcome to Rebel B2W!");rbdTgSend($token,$cid,$welcome,['keyboard'=>[['💰 Deposit','💸 Withdraw'],['💳 Balance','❓ Help']],'resize_keyboard'=>true]);rbdClearState($cid);return;}
    if($cmd==='/deposit'||$text==='💰 Deposit'){rbdHandleDeposit($token,$cid,$userName,$cfg);return;}
    if($cmd==='/balance'||$text==='💳 Balance'){$user=rbdLdGetUser($cid);$bal=(float)($user['balance']??0);$deps=array_slice(array_reverse($user['deposits']??[]),0,5);$dl='';foreach($deps as $d){$t=date('d/m/Y',strtotime($d['time']));$dl.="\n✅ ₹".number_format($d['amount'])." — {$t}".($d['utr']?" (UTR: {$d['utr']})":"");}rbdTgSend($token,$cid,"💳 <b>Your Rebel B2W Balance</b>\n\n💰 Available: <b>₹".number_format($bal,2)."</b>\n\n".($dl?"<b>Recent Deposits:</b>".$dl:"<i>No approved deposits yet.</i>")."\n\n<i>Balance credited after admin approval.</i>");return;}
    if($cmd==='/withdrawal'||$text==='💸 Withdraw'){$user=rbdLdGetUser($cid);$bal=(float)($user['balance']??0);if($bal<=0){rbdTgSend($token,$cid,"❌ <b>Insufficient Balance</b>\n\nYour balance is ₹0. Make a deposit first.");return;}rbdTgSend($token,$cid,"💸 <b>Withdrawal Request</b>\n\n💰 Your Balance: <b>₹".number_format($bal,2)."</b>\n\nEnter the amount to withdraw:");rbdSetState($cid,'awaiting_withdrawal_amount',['balance'=>$bal]);return;}
    if($cmd==='/help'||$text==='❓ Help'){rbdTgSend($token,$cid,"❓ <b>Help</b>\n\n/Deposit — Make deposit\n/Withdrawal — Request withdrawal\n/Balance — Check balance\n/Start — Restart\n\nSupport: ".RBD_WITHDRAWAL_CONTACT);return;}
    if(!$state){rbdTgSend($token,$cid,"👇 Use /Deposit to deposit funds.");return;}
    switch($state['state']){
        case 'awaiting_amount':$amount=(float)preg_replace('/[^0-9.]/','', $text);if($amount<=0){rbdTgSend($token,$cid,"❌ Enter a valid amount. Example: <code>1000</code>");return;}rbdProcessAmount($token,$cid,(int)$amount,$cfg);break;
        case 'awaiting_utr':case 'awaiting_utr_text':$utr=trim(preg_replace('/[^a-zA-Z0-9]/','',$text));if(strlen($utr)<6){rbdTgSend($token,$cid,"❌ Enter a valid UTR / reference number.");return;}$d2=$state['data'];$d2['utr']=$utr;rbdTgSend($token,$cid,"✅ UTR noted: <code>{$utr}</code>\n\n📸 <b>Now send your payment screenshot</b> to confirm.");rbdSetState($cid,'awaiting_screenshot',$d2);break;
        case 'awaiting_screenshot':rbdTgSend($token,$cid,"📸 Please send a <b>screenshot</b> of your payment.");break;
        case 'awaiting_withdrawal_amount':$wAmount=(float)preg_replace('/[^0-9.]/','',$text);$bal2=(float)($state['data']['balance']??0);if($wAmount<=0){rbdTgSend($token,$cid,"❌ Enter a valid amount.");return;}if($wAmount>$bal2){rbdTgSend($token,$cid,"❌ Insufficient balance.\n\nAvailable: <b>₹".number_format($bal2,2)."</b>");return;}rbdTgSend($token,$cid,"📸 <b>Send your UPI QR Code</b>\n\nAmount: <b>₹".number_format($wAmount,2)."</b>\n\nSend a screenshot of your UPI QR code.");rbdSetState($cid,'awaiting_withdrawal_qr',['balance'=>$bal2,'w_amount'=>$wAmount]);break;
        case 'awaiting_withdrawal_qr':rbdTgSend($token,$cid,"📸 Please send your <b>UPI QR code image</b>.");break;
        default:rbdClearState($cid);rbdTgSend($token,$cid,"👇 /Deposit — Make deposit\n/Balance — Check balance");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ██╗     ██╗███╗   ██╗██╗  ██╗    ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
// ██║     ██║████╗  ██║██║ ██╔╝    ██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
// ██║     ██║██╔██╗ ██║█████╔╝     ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
// ██║     ██║██║╚██╗██║██╔═██╗     ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
// ███████╗██║██║ ╚████║██║  ██╗    ██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
//  ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
// Link Runner — Integrated Module
// ═══════════════════════════════════════════════════════════════════════════
define('LR_VERSION',     '1.2');
define('LR_CONFIG_FILE', __DIR__ . '/lr_config.json');
define('LR_LOG_FILE',    __DIR__ . '/lr_logs.json');
define('LR_SS_DIR',      __DIR__ . '/lr_screenshots/');
define('LR_CURL_TO',     30);
define('LR_SESSION_FILE',__DIR__ . '/lr_sessions.json');
if(!is_dir(LR_SS_DIR))@mkdir(LR_SS_DIR,0755,true);

$_lrDefaultConfig=[
    'run_secret'        => 'changeme123',
    'bot_token'         => '',
    'chat_id'           => '',
    'send_prefix'       => '🔗 <b>Link Runner</b>\n\n',
    'links'             => [],
    'webhook_token'     => '',
    'webhook_cmd'       => '/run',
    // ── Python Aadhaar Bot config ──
    'py_bot_token'      => '',
    'py_uidai_proxy'    => '',
    'py_fetch_cmd'      => '/fetch',
    'py_cancel_cmd'     => '/cancel',
    'py_refresh_cmd'    => '/refresh',
    'py_start_msg'      => "👾 <b>Aadhaar Retrieve Bot</b> — Online ✅\n\n📌 <b>Command:</b>\n<code>/fetch &lt;mobile&gt; &lt;fullname&gt;</code>\n\nExample:\n<code>/fetch 9876543210 Ravi Kumar</code>",
    'py_loading_steps'  => "🔐 Secure tunnel initialize ho raha hai...\n🛰️ UIDAI node se connect ho raha hai...\n🧬 Session payload inject ho raha hai...\n🔍 Biometric endpoint resolve ho raha hai...\n⚡ Sandbox bypass ho raha hai...\n🗝️ Identity matrix decrypt ho rahi hai...\n📋 Form fill ho raha hai...\n📸 Captcha capture ho raha hai...",
    'py_otp_steps'      => "🔐 OTP token validate ho raha hai...\n🧬 Biometric hash cross-reference ho raha hai...\n📂 Encrypted Aadhaar file locate ho rahi hai...\n⬇️ Document decrypt aur package ho raha hai...\n✅ Document secured. Bhej raha hoon...",
    'py_captcha_msg'    => "📸 <b>Captcha ready hai!</b>\n\nNeeche captcha image dekho aur <b>text reply karo.</b>\n<i>/refresh = naya captcha | /cancel = band karo</i>",
    'py_otp_msg'        => "📲 <b>OTP bheja gaya!</b>\n📱 <code>{mobile}</code> pe OTP aaya hoga.\n\n🔢 <b>OTP reply karo:</b>\n<i>/cancel = band karo</i>",
    'py_success_msg'    => "✅ <b>Aadhaar document ready!</b>\n🔒 <i>Yeh file sirf aapke liye hai. Safely store karo.</i>",
    'py_cancel_msg'     => "❌ <b>Process cancel kar diya.</b>\nDobara shuru karne ke liye /fetch karo.",
    'py_error_prefix'   => "❌ <b>Error:</b>",
];
function lrLoadConfig(){
    global $_lrDefaultConfig;
    if(!file_exists(LR_CONFIG_FILE))return$_lrDefaultConfig;
    $l=json_decode(file_get_contents(LR_CONFIG_FILE),true);
    return is_array($l)?array_merge($_lrDefaultConfig,$l):$_lrDefaultConfig;
}
function lrSaveConfig($cfg){file_put_contents(LR_CONFIG_FILE,json_encode($cfg,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);}

function lrLog($text,$type='info'){$l=file_exists(LR_LOG_FILE)?(json_decode(file_get_contents(LR_LOG_FILE),true)?:[]):[];array_unshift($l,['time'=>date('c'),'text'=>$text,'type'=>$type]);if(count($l)>300)$l=array_slice($l,0,300);file_put_contents(LR_LOG_FILE,json_encode($l,JSON_UNESCAPED_UNICODE),LOCK_EX);}

function lrTg($method,$params,$token){$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>'https://api.telegram.org/bot'.$token.'/'.$method,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>json_encode($params),CURLOPT_HTTPHEADER=>['Content-Type: application/json']]);$r=curl_exec($ch);curl_close($ch);return json_decode($r,true)?:[];}

function lrSend($token,$chatId,$text){if(!$token||!$chatId||!trim($text))return false;$chunks=lrChunk($text,4000);$ok=true;foreach($chunks as $chunk){$r=lrTg('sendMessage',['chat_id'=>$chatId,'text'=>$chunk,'parse_mode'=>'HTML','disable_web_page_preview'=>true],$token);if(!($r['ok']??false))$ok=false;}return $ok;}
function lrChunk($text,$maxLen=4000){$chunks=[];while(mb_strlen($text)>$maxLen){$pos=mb_strrpos(mb_substr($text,0,$maxLen),"\n");if($pos===false)$pos=$maxLen;$chunks[]=mb_substr($text,0,$pos);$text=mb_substr($text,$pos);}if(trim($text)!=='')$chunks[]=$text;return $chunks?:[''];}

function lrFetch($url,$method='GET',$headers='',$body='',$timeout=30,$sslVerify=true){
    $hdrs=[];if($headers){foreach(explode("\n",$headers) as $h){$h=trim($h);if($h&&strpos($h,':')!==false)$hdrs[]=$h;}}
    if(empty($hdrs))$hdrs=['User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36','Accept: application/json,text/html,*/*'];
    $ch=curl_init();$o=[CURLOPT_URL=>$url,CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>$sslVerify,CURLOPT_SSL_VERIFYHOST=>$sslVerify?2:0,CURLOPT_TIMEOUT=>$timeout,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_HTTPHEADER=>$hdrs];
    $m=strtoupper($method);if($m==='POST'){$o[CURLOPT_POST]=true;$o[CURLOPT_POSTFIELDS]=$body;}elseif($m!=='GET'){$o[CURLOPT_CUSTOMREQUEST]=$m;if($body)$o[CURLOPT_POSTFIELDS]=$body;}
    curl_setopt_array($ch,$o);$res=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);$err=curl_error($ch);curl_close($ch);
    return['code'=>$code,'body'=>$res?:'','error'=>$err];
}

function lrJsonPath($data,$path){if(empty($path))return is_array($data)?json_encode($data,JSON_UNESCAPED_UNICODE):(string)$data;foreach(explode('.',$path) as $k){if(is_array($data)&&isset($data[$k]))$data=$data[$k];elseif(is_array($data)&&is_numeric($k)&&isset($data[(int)$k]))$data=$data[(int)$k];else return null;}return is_array($data)?json_encode($data,JSON_UNESCAPED_UNICODE):(string)$data;}
function lrFlatten($data,$prefix='',$map=[]){if(!is_array($data)){if($prefix!=='')$map[$prefix]=(string)$data;return $map;}foreach($data as $k=>$v){$full=$prefix!==''?$prefix.'.'.$k:(string)$k;if(is_array($v))$map=lrFlatten($v,$full,$map);else{$map[$full]=(string)$v;if(!isset($map[$k]))$map[$k]=(string)$v;}}return $map;}
function lrReplace($text,$vars){foreach($vars as $k=>$v){$text=str_replace('{'.$k.'}',(string)$v,$text);}return $text;}

// ─── Auto-detect form fields from HTML page ──────────────────────────────
function lrDetectFormFields($pageUrl,$timeout=20){
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>$pageUrl,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>$timeout,CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_USERAGENT=>'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',CURLOPT_HTTPHEADER=>['Accept-Language: en-US,en;q=0.9']]);
    $html=curl_exec($ch);curl_close($ch);if(!$html)return[];
    $fields=[];$skip=['hidden','submit','button','reset','image','file','checkbox','radio'];
    preg_match_all('/<input([^>]*)>/i',$html,$inputs);
    foreach($inputs[1] as $attrs){$type='';$name='';$ph='';$label='';if(preg_match('/type\s*=\s*["\']?([a-zA-Z]+)/i',$attrs,$m))$type=strtolower($m[1]);if(in_array($type,$skip))continue;if(preg_match('/name\s*=\s*["\']([^"\']+)/i',$attrs,$m))$name=$m[1];if(preg_match('/placeholder\s*=\s*["\']([^"\']+)/i',$attrs,$m))$ph=$m[1];if(preg_match('/aria-label\s*=\s*["\']([^"\']+)/i',$attrs,$m))$label=$m[1];$display=$ph?:$label?:$name;if($display)$fields[$name?:$display]=$display;}
    preg_match_all('/<textarea([^>]*)>/i',$html,$textareas);
    foreach($textareas[1] as $attrs){$name='';$ph='';$label='';if(preg_match('/name\s*=\s*["\']([^"\']+)/i',$attrs,$m))$name=$m[1];if(preg_match('/placeholder\s*=\s*["\']([^"\']+)/i',$attrs,$m))$ph=$m[1];if(preg_match('/aria-label\s*=\s*["\']([^"\']+)/i',$attrs,$m))$label=$m[1];$display=$ph?:$label?:$name;if($display)$fields[$name?:$display]=$display;}
    preg_match_all('/<select([^>]*)>/i',$html,$selects);
    foreach($selects[1] as $attrs){$name='';$label='';if(preg_match('/name\s*=\s*["\']([^"\']+)/i',$attrs,$m))$name=$m[1];if(preg_match('/aria-label\s*=\s*["\']([^"\']+)/i',$attrs,$m))$label=$m[1];$display=$label?:$name;if($display)$fields[$name?:$display]=$display;}
    preg_match_all('/<label[^>]*for\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)<\/label>/is',$html,$labels);
    foreach($labels[1] as $i=>$forId){$lt=trim(strip_tags($labels[2][$i]));if(!$lt)continue;preg_match_all('/<input[^>]*id\s*=\s*["\']'.preg_quote($forId,'/').'["\'][^>]*name\s*=\s*["\']([^"\']+)/i',$html,$nm);if(!empty($nm[1][0]))$fields[$nm[1][0]]=$lt;}
    return $fields;
}

// ─── Form-fill session helpers ───────────────────────────────────────────
function lrSessionLoad(){if(!file_exists(LR_SESSION_FILE))return[];return json_decode(file_get_contents(LR_SESSION_FILE),true)?:[];}
function lrSessionSave($s){file_put_contents(LR_SESSION_FILE,json_encode($s,JSON_UNESCAPED_UNICODE),LOCK_EX);}
function lrSessionGet($cid){$a=lrSessionLoad();return $a[(string)$cid]??null;}
function lrSessionSet($cid,$data){$a=lrSessionLoad();$a[(string)$cid]=$data;lrSessionSave($a);}
function lrSessionDel($cid){$a=lrSessionLoad();unset($a[(string)$cid]);lrSessionSave($a);}

function lrFetchScreenshotBytes($url,$timeout=30){
    $thumbUrl='https://image.thum.io/get/width/1280/crop/900/png/'.urlencode($url);
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>$thumbUrl,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>$timeout,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_USERAGENT=>'Mozilla/5.0 (compatible; LinkRunner/1.1)']);
    $data=curl_exec($ch);$code=curl_getinfo($ch,CURLINFO_HTTP_CODE);$ct=curl_getinfo($ch,CURLINFO_CONTENT_TYPE);curl_close($ch);
    if($code===200&&$data&&str_contains((string)$ct,'image'))return['bytes'=>$data,'source'=>'thum.io'];
    $ml='https://api.microlink.io/?url='.urlencode($url).'&screenshot=true&meta=false&embed=screenshot.url';
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>$ml,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>$timeout,CURLOPT_CONNECTTIMEOUT=>15,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_MAXREDIRS=>5,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_USERAGENT=>'Mozilla/5.0 (compatible; LinkRunner/1.1)']);
    $mlData=json_decode(curl_exec($ch),true);curl_close($ch);
    $ssUrl=$mlData['data']['screenshot']['url']??($mlData['data']['screenshot']??null);
    if($ssUrl&&str_starts_with($ssUrl,'http')){$ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>$ssUrl,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>20,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_FOLLOWLOCATION=>true]);$imgData=curl_exec($ch);$imgCode=curl_getinfo($ch,CURLINFO_HTTP_CODE);curl_close($ch);if($imgCode===200&&$imgData)return['bytes'=>$imgData,'source'=>'microlink'];}
    return null;
}

function lrTakeScreenshot($url,$token,$chatId,$caption,$timeout=30){
    if(!$token||!$chatId)return false;
    $result=lrFetchScreenshotBytes($url,$timeout);if(!$result)return false;
    $ssFile=LR_SS_DIR.'ss_'.md5($url.microtime()).'.png';file_put_contents($ssFile,$result['bytes']);
    if(!file_exists($ssFile)||filesize($ssFile)<500){@unlink($ssFile);return false;}
    $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>'https://api.telegram.org/bot'.$token.'/sendPhoto',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_TIMEOUT=>40,CURLOPT_POSTFIELDS=>['chat_id'=>$chatId,'caption'=>$caption."\n<i>via ".($result['source']??'API')."</i>",'parse_mode'=>'HTML','photo'=>new CURLFile($ssFile,'image/png','screenshot.png')]]);
    $r=json_decode(curl_exec($ch),true);curl_close($ch);@unlink($ssFile);
    if(empty($r['ok'])){$r2=lrTg('sendPhoto',['chat_id'=>$chatId,'photo'=>'https://image.thum.io/get/width/1280/crop/900/png/'.urlencode($url),'caption'=>$caption,'parse_mode'=>'HTML'],$token);return!empty($r2['ok']);}
    return!empty($r['ok']);
}

function lrRunAll($cfg,$extraVars=[]){
    $results=[];$links=$cfg['links']??[];
    foreach($links as $link){
        if(empty($link['enabled']))continue;
        $id=$link['id']??uniqid('lr_');$name=$link['name']??$id;$url=trim($link['url']??'');if(!$url)continue;
        $vars=array_merge(['ts'=>date('Y-m-d H:i:s'),'date'=>date('Y-m-d'),'time'=>date('H:i:s')],$extraVars);
        $url=lrReplace($url,$vars);$headers=lrReplace($link['headers']??'',$vars);$body2=lrReplace($link['body']??'',$vars);
        $timeout=max(5,min(120,(int)($link['timeout']??30)));$ssl=!isset($link['ssl_verify'])||(bool)$link['ssl_verify'];
        $chatId2=trim($link['chat_id']??'')?:trim($cfg['chat_id']??'');$token2=trim($cfg['bot_token']??'');
        $useScreenshot=!empty($link['screenshot_mode']);
        if($useScreenshot){
            $ssCaption=lrReplace($link['screenshot_caption']??'📸 <b>{name}</b>\n🌐 <code>{url}</code>\n🕐 {ts}',array_merge($vars,['name'=>htmlspecialchars($name,ENT_NOQUOTES,'UTF-8'),'url'=>htmlspecialchars($url,ENT_NOQUOTES,'UTF-8')]));
            $sent=false;if($token2&&$chatId2)$sent=lrTakeScreenshot($url,$token2,$chatId2,$ssCaption,$timeout);
            $results[]=['id'=>$id,'name'=>$name,'url'=>$url,'code'=>0,'failed'=>!$sent,'extracted'=>$sent?'[screenshot sent]':'[screenshot failed]','sent'=>$sent,'msg'=>$ssCaption,'mode'=>'screenshot'];
            lrLog(($sent?"SS OK [{$id}]":"SS FAIL [{$id}]")." → ".$name,$sent?'success':'error');continue;
        }
        $result=lrFetch($url,$link['method']??'GET',$headers,$body2,$timeout,$ssl);$rawBody=$result['body']??'';$code=$result['code']??0;
        $extracted=null;$respPath=trim($link['response_path']??'');$respData=json_decode($rawBody,true);
        if($respPath!==''&&$respData!==null)$extracted=lrJsonPath($respData,$respPath);
        if($extracted===null&&is_array($respData)){foreach(['result','response','text','content','answer','message','output','data','value'] as $fk){if(isset($respData[$fk])&&is_string($respData[$fk])&&trim($respData[$fk])!==''){$extracted=$respData[$fk];break;}}}
        if($extracted===null)$extracted=$rawBody;
        $failed=($code>=400||$extracted===null||$extracted==='');
        $replyTpl=$link['reply_template']??'📌 <b>{name}</b>\n{response}';
        $allVars=array_merge($vars,['name'=>htmlspecialchars($name,ENT_NOQUOTES,'UTF-8'),'url'=>htmlspecialchars($url,ENT_NOQUOTES,'UTF-8'),'http_code'=>$code,'response'=>htmlspecialchars((string)$extracted,ENT_NOQUOTES,'UTF-8'),'result'=>htmlspecialchars((string)$extracted,ENT_NOQUOTES,'UTF-8'),'curl_response'=>htmlspecialchars((string)$extracted,ENT_NOQUOTES,'UTF-8'),'raw'=>htmlspecialchars($rawBody,ENT_NOQUOTES,'UTF-8'),'status'=>$failed?'❌ FAILED':'✅ OK','error'=>htmlspecialchars($result['error']??'',ENT_NOQUOTES,'UTF-8')]);
        if(is_array($respData)){$flat=lrFlatten($respData);uksort($flat,fn($a,$b)=>strlen($b)-strlen($a));foreach($flat as $fk=>$fv)$allVars[$fk]=htmlspecialchars((string)$fv,ENT_NOQUOTES,'UTF-8');}
        $msgText=lrReplace($replyTpl,$allVars);$sent=false;
        if(!$failed&&$token2&&$chatId2){$prefix=str_replace('\n',"\n",$cfg['send_prefix']??'');$sent=lrSend($token2,$chatId2,$prefix.$msgText);}
        elseif($failed&&!empty($link['send_on_error'])&&$token2&&$chatId2){$errTpl=$link['error_message']??'⚠️ <b>{name}</b> failed!\nHTTP: <code>{http_code}</code>';lrSend($token2,$chatId2,lrReplace($errTpl,$allVars));}
        $results[]=['id'=>$id,'name'=>$name,'url'=>$url,'code'=>$code,'failed'=>$failed,'extracted'=>$extracted,'sent'=>$sent,'msg'=>$msgText,'mode'=>'curl'];
        lrLog(($failed?"FAIL [{$id}] HTTP {$code}":"OK [{$id}] HTTP {$code}")." → ".$name,$failed?'error':'success');
    }
    return $results;
}

function sendSticker($chatId,$stickerId,$token){
    return tg('sendSticker',['chat_id'=>$chatId,'sticker'=>$stickerId],$token);
}

function forwardMsg($toChatId,$fromChatId,$messageId,$token){
    return tg('forwardMessage',[
        'chat_id'=>$toChatId,
        'from_chat_id'=>$fromChatId,
        'message_id'=>(int)$messageId,
    ],$token);
}

function loadForwards($botId){
    $f=getBotDir($botId).'forwards.json';
    return file_exists($f)?(json_decode(file_get_contents($f),true)?:[]):[];
}
function saveForwards($botId,$data){
    file_put_contents(getBotDir($botId).'forwards.json',json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);
}
function addForwardToLib($botId,$fromChatId,$messageId,$label='',$type='message'){
    $lib=loadForwards($botId);
    foreach($lib as $f){
        if($f['from_chat_id']===(string)$fromChatId&&$f['message_id']===(string)$messageId)return false;
    }
    $lib[]=[
        'id'=>uniqid('fwd_'),
        'from_chat_id'=>(string)$fromChatId,
        'message_id'=>(string)$messageId,
        'label'=>$label?:('Forward '.(count($lib)+1)),
        'preview_type'=>$type,
        'saved_at'=>date('Y-m-d H:i:s'),
    ];
    saveForwards($botId,$lib);
    return true;
}

function loadStickers($botId){$f=getBotDir($botId).'stickers.json';return file_exists($f)?(json_decode(file_get_contents($f),true)?:[]):[];}
function saveStickers($botId,$data){file_put_contents(getBotDir($botId).'stickers.json',json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);}
function addStickerToLib($botId,$fileId,$isAnimated=false,$isPremium=false,$label=''){
    $lib=loadStickers($botId);
    foreach($lib as $s){if($s['file_id']===$fileId)return false;}
    $lib[]=['id'=>uniqid('stk_'),'file_id'=>$fileId,'label'=>$label?:('Sticker '.(count($lib)+1)),'is_animated'=>$isPremium||$isAnimated,'is_premium'=>$isPremium,'saved_at'=>date('Y-m-d H:i:s')];
    saveStickers($botId,$lib);return true;
}

function loadPremEmojis($botId){
    $f=getBotDir($botId).'prem_emojis.json';
    return file_exists($f)?(json_decode(file_get_contents($f),true)?:[]):[];
}
function savePremEmojis($botId,$data){
    file_put_contents(getBotDir($botId).'prem_emojis.json',json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);
}
function addPremEmojiToLib($botId,$emojiId,$fallback='⭐',$label=''){
    $lib=loadPremEmojis($botId);
    foreach($lib as $e){if($e['emoji_id']===(string)$emojiId)return false;}
    $lib[]=[
        'id'=>uniqid('emj_'),
        'emoji_id'=>(string)$emojiId,
        'fallback'=>$fallback?:'⭐',
        'label'=>$label?:('Emoji '.(count($lib)+1)),
        'saved_at'=>date('Y-m-d H:i:s')
    ];
    savePremEmojis($botId,$lib);
    return true;
}

function syncEmojiDynVars($botId,&$db){
    foreach(array_keys($db['dyn_vars']??[]) as $k){
        if(str_starts_with($k,'emoji_'))unset($db['dyn_vars'][$k]);
    }
    foreach(loadPremEmojis($botId) as $e){
        $key='emoji_'.preg_replace('/[^a-zA-Z0-9_]/','_',strtolower($e['label']));

        $db['dyn_vars'][$key]='<tg-emoji emoji-id="'.$e['emoji_id'].'">'.$e['fallback'].'</tg-emoji>';
    }
}

function extractTgEmojiEntities(string $html): array {
    $entities = [];

    $pattern = '/<tg-emoji\s+emoji-id=["\'](\d+)["\']>(.*?)<\/tg-emoji>/su';
    $clean = '';
    $offset = 0; // UTF-16 offset (Telegram uses UTF-16 code units)
    $lastPos = 0;
    if(preg_match_all($pattern, $html, $matches, PREG_OFFSET_CAPTURE)){
        foreach($matches[0] as $i => $match){
            $matchStart  = $match[1];   // byte offset in original string
            $fullMatch   = $match[0];
            $emojiId     = $matches[1][$i][0];
            $fallback    = $matches[2][$i][0]; // e.g. ⭐

            $before = substr($html, $lastPos, $matchStart - $lastPos);

            $beforeClean = strip_tags($before);
            $clean .= $beforeClean;

            $offset += mb_strlen(mb_convert_encoding($beforeClean,'UTF-16LE','UTF-8'),
                                  '8bit') / 2;

            $fallbackUtf16Len = mb_strlen(mb_convert_encoding($fallback,'UTF-16LE','UTF-8'),
                                           '8bit') / 2;
            $entities[] = [
                'type'            => 'custom_emoji',
                'offset'          => (int)$offset,
                'length'          => (int)$fallbackUtf16Len,
                'custom_emoji_id' => $emojiId,
            ];
            $clean  .= $fallback;
            $offset += $fallbackUtf16Len;
            $lastPos = $matchStart + strlen($fullMatch);
        }
    }

    $rest = substr($html, $lastPos);
    $clean .= strip_tags($rest);

    if(empty($entities)) return ['text' => $html, 'entities' => []];
    return ['text' => $clean, 'entities' => $entities];
}

function htmlToEntities(string $html): array {

    $tagMap = ['b'=>'bold','strong'=>'bold','i'=>'italic','em'=>'italic',
               'u'=>'underline','s'=>'strikethrough','del'=>'strikethrough',
               'code'=>'code','pre'=>'pre'];
    $text   = '';
    $entities = [];
    $stack  = []; // [type, utf16_start]

    $emojiMap = []; // placeholder → [emoji_id, fallback]
    $idx = 0;
    $html = preg_replace_callback(
        '/<tg-emoji\s+emoji-id=["\'](\d+)["\']>(.*?)<\/tg-emoji>/su',
        function($m) use (&$emojiMap, &$idx){
            $ph = "\x01EMOJI{$idx}\x01";
            $emojiMap[$ph] = ['id'=>$m[1],'fb'=>$m[2]];
            $idx++;
            return $ph;
        },
        $html
    );

    $tokens = preg_split('/(<[^>]+>)/s', $html, -1, PREG_SPLIT_DELIM_CAPTURE);
    $utf16pos = 0;
    foreach($tokens as $tok){
        if($tok === '') continue;
        if($tok[0] === '<'){

            if(preg_match('/^<\/(\w+)>$/i', $tok, $m)){
                $tag = strtolower($m[1]);
                if(isset($tagMap[$tag])){

                    for($si=count($stack)-1;$si>=0;$si--){
                        if($stack[$si]['type']===$tagMap[$tag]){
                            $len = $utf16pos - $stack[$si]['start'];
                            if($len>0) $entities[]=['type'=>$tagMap[$tag],'offset'=>$stack[$si]['start'],'length'=>$len];
                            array_splice($stack,$si,1);
                            break;
                        }
                    }
                }
            } elseif(preg_match('/^<(\w+)/i', $tok, $m)){
                $tag = strtolower($m[1]);
                if(isset($tagMap[$tag])) $stack[]=['type'=>$tagMap[$tag],'start'=>$utf16pos];
            }
        } else {

            $remaining = $tok;
            while($remaining !== ''){

                $found = false;
                foreach($emojiMap as $ph=>$info){
                    if(str_starts_with($remaining, $ph)){
                        $fb = $info['fb'];
                        $fbLen = (int)(mb_strlen(mb_convert_encoding($fb,'UTF-16LE','UTF-8'),'8bit')/2);
                        $entities[]=['type'=>'custom_emoji','offset'=>$utf16pos,'length'=>$fbLen,'custom_emoji_id'=>$info['id']];
                        $text .= $fb;
                        $utf16pos += $fbLen;
                        $remaining = substr($remaining, strlen($ph));
                        $found = true;
                        break;
                    }
                }
                if(!$found){

                    $ch = mb_substr($remaining, 0, 1, 'UTF-8');
                    $decoded = html_entity_decode($ch, ENT_QUOTES|ENT_HTML5, 'UTF-8');
                    $text .= $decoded;
                    $chLen = (int)(mb_strlen(mb_convert_encoding($decoded,'UTF-16LE','UTF-8'),'8bit')/2);
                    $utf16pos += $chLen;
                    $remaining = mb_substr($remaining, 1, null, 'UTF-8');
                }
            }
        }
    }
    return ['text'=>$text, 'entities'=>$entities];
}

function sendMsg($chatId,$msgId,$text,$media,$kb,$edit,$token){

    $hasTgEmoji = (strpos((string)$text,'<tg-emoji')!==false);
    if($hasTgEmoji){
        $parsed = htmlToEntities((string)$text);
        $finalText    = $parsed['text'];
        $finalEntities= $parsed['entities'];
    } else {
        $finalText     = $text;
        $finalEntities = [];
    }
    $p = ['chat_id'=>$chatId];
    if($hasTgEmoji && !empty($finalEntities)){

        $p['entities'] = $finalEntities;
    } else {
        $p['parse_mode'] = 'HTML';
    }
    if($kb) $p['reply_markup'] = $kb;
    if(!empty($media)&&(str_starts_with($media,'http')||str_starts_with($media,'https'))){
        $lm=strtolower($media);
        $isAnim=str_ends_with($lm,'.gif')||str_ends_with($lm,'.mp4')||str_ends_with($lm,'.mov')||strpos($lm,'.gif')!==false;
        $captionKey = 'caption';
        $p[$captionKey] = $finalText ?: ' ';

        if($hasTgEmoji && !empty($finalEntities)){
            unset($p['parse_mode']);
            $p['caption_entities'] = $finalEntities;
        } else {
            $p['parse_mode'] = 'HTML';
        }
        if($edit&&$msgId){
            $mo=['type'=>$isAnim?'animation':'photo','media'=>$media,'caption'=>$finalText?:' '];
            if($hasTgEmoji && !empty($finalEntities)) $mo['caption_entities']=$finalEntities;
            else $mo['parse_mode']='HTML';
            $pe=['chat_id'=>$chatId,'message_id'=>$msgId,'media'=>json_encode($mo)];
            if($kb)$pe['reply_markup']=$kb;
            $r=tg('editMessageMedia',$pe,$token);
            if(!$r['ok']){
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msgId],$token);
                $p[$isAnim?'animation':'photo']=$media;
                $r2=tg($isAnim?'sendAnimation':'sendPhoto',$p,$token);
                if(!$r2['ok']){
                    unset($p['caption'],$p['animation'],$p['photo'],$p['caption_entities']);
                    $p['text']=$finalText?:' ';
                    if($hasTgEmoji&&!empty($finalEntities)){unset($p['parse_mode']);$p['entities']=$finalEntities;}
                    else $p['parse_mode']='HTML';
                    return tg('sendMessage',$p,$token);
                }
                return $r2;
            }
            return $r;
        }
        $p[$isAnim?'animation':'photo']=$media;
        $r=tg($isAnim?'sendAnimation':'sendPhoto',$p,$token);
        if(!$r['ok']){
            unset($p['caption'],$p['animation'],$p['photo'],$p['caption_entities']);
            $p['text']=$finalText?:' ';
            if($hasTgEmoji&&!empty($finalEntities)){unset($p['parse_mode']);$p['entities']=$finalEntities;}
            else $p['parse_mode']='HTML';
            return tg('sendMessage',$p,$token);
        }
        return $r;
    }
    $p['text'] = $finalText ?: ' ';
    if($edit&&$msgId){
        $ep = array_merge($p,['message_id'=>$msgId]);
        $r=tg('editMessageText',$ep,$token);
        if(!$r['ok']){tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msgId],$token);return tg('sendMessage',$p,$token);}
        return $r;
    }
    return tg('sendMessage',$p,$token);
}

function injectOwnerEditBtn($kb,$pageId,$chatUid,$ownerUid){
    if((string)$chatUid!==(string)$ownerUid||empty($pageId))return $kb;
    $rows=[];
    if($kb){$dec=json_decode($kb,true);if(!empty($dec['inline_keyboard']))$rows=$dec['inline_keyboard'];}
    $rows[]=[['text'=>'✏️ Edit This Page','callback_data'=>'__owner_edit__|'.$pageId]];
    return json_encode(['inline_keyboard'=>$rows]);
}

function sendLong($botId,$chatId,$msgId,$text,$media,$kb,$edit,$token,$page=0){
    $LIM=3800;
    if(mb_strlen($text)<=$LIM)return sendMsg($chatId,$msgId,$text,$media,$kb,$edit,$token);
    $chunks=[];$rem=$text;
    while(mb_strlen($rem)>0){
        if(mb_strlen($rem)<=$LIM){$chunks[]=$rem;break;}
        $chunk=mb_substr($rem,0,$LIM);$br=mb_strrpos($chunk,"\n");
        if($br!==false&&$br>$LIM*0.5)$chunk=mb_substr($rem,0,$br);
        $chunks[]=$chunk;$rem=mb_substr($rem,mb_strlen($chunk));
    }
    $total=count($chunks);$page=max(0,min($page,$total-1));$cur=$chunks[$page];
    if($total>1)$cur.="\n\n<i>📄 Page ".($page+1)." / $total</i>";
    $nav=[];
    if($page>0)$nav[]=['text'=>'⬅️ Prev','callback_data'=>'lp|'.($page-1)];
    if($page<$total-1)$nav[]=['text'=>'Next ➡️','callback_data'=>'lp|'.($page+1)];
    $rows=[];if($nav)$rows[]=$nav;
    if($kb){$ek=json_decode($kb,true);if(!empty($ek['inline_keyboard']))foreach($ek['inline_keyboard'] as $r)$rows[]=$r;}
    $fkb=$rows?json_encode(['inline_keyboard'=>$rows]):null;
    return sendMsg($chatId,$msgId,$cur,$page===0?$media:'',$fkb,$edit,$token);
}

function doCurl($url,$method,$headersStr,$body,$timeout=120,$sslVerify=true){
    $hdrs=[];
    foreach(explode("\n",$headersStr) as $h){
        $h=trim($h);
        if($h&&strpos($h,':')!==false)$hdrs[]=$h;
    }
    $ch=curl_init();
    $o=[
        CURLOPT_URL=>$url,
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_SSL_VERIFYPEER=>$sslVerify,
        CURLOPT_SSL_VERIFYHOST=>$sslVerify?2:0,
        CURLOPT_TIMEOUT=>$timeout,
        CURLOPT_CONNECTTIMEOUT=>30,
        CURLOPT_FOLLOWLOCATION=>true,
        CURLOPT_MAXREDIRS=>5,
        CURLOPT_HTTPHEADER=>$hdrs,
        CURLOPT_USERAGENT=>'Mozilla/5.0 (compatible; TelegramBot/1.0)',
    ];
    if(strtoupper($method)==='POST'){$o[CURLOPT_POST]=true;$o[CURLOPT_POSTFIELDS]=$body;}
    elseif(strtoupper($method)!=='GET'){$o[CURLOPT_CUSTOMREQUEST]=strtoupper($method);$o[CURLOPT_POSTFIELDS]=$body;}
    curl_setopt_array($ch,$o);
    $res=curl_exec($ch);
    $code=curl_getinfo($ch,CURLINFO_HTTP_CODE);
    $err=curl_error($ch);
    curl_close($ch);
    return['code'=>$code,'body'=>$res?:'','error'=>$err];
}

function jsonPath($data,$path){
    if(empty($path))return is_array($data)?json_encode($data,JSON_UNESCAPED_UNICODE):(string)$data;
    foreach(explode('.',$path) as $k){
        if(is_array($data)&&isset($data[$k]))$data=$data[$k];
        elseif(is_array($data)&&is_numeric($k)&&isset($data[(int)$k]))$data=$data[(int)$k];
        else return null;
    }
    return is_array($data)?json_encode($data,JSON_UNESCAPED_UNICODE):(string)$data;
}

function flattenJson($data,$prefix='',$map=[]){
    if(!is_array($data)){if($prefix!=='')$map[$prefix]=is_string($data)?$data:(string)$data;return $map;}
    foreach($data as $k=>$v){
        $full=$prefix!==''?$prefix.'.'.$k:(string)$k;
        if(is_array($v)){$map=flattenJson($v,$full,$map);}
        else{$map[$full]=is_string($v)?$v:(string)$v;if(!isset($map[$k]))$map[$k]=is_string($v)?$v:(string)$v;}
    }
    return $map;
}

function parseCurl($raw){
    $r=['method'=>'GET','url'=>'','headers_str'=>'','body'=>''];
    if(empty(trim($raw)))return $r;

    $raw=preg_replace('/\\\\\s*\n\s*/u',' ',$raw);

    $raw=preg_replace('/^\s*curl\s+/u','',$raw);

    if(preg_match("/(?:^|\s)'(https?:\/\/[^']+)'/u",$raw,$m))$r['url']=$m[1];

    elseif(preg_match('/(?:^|\s)"(https?:\/\/[^"]+)"/u',$raw,$m))$r['url']=$m[1];

    elseif(preg_match('/(?:^|\s)(https?:\/\/\S+)/u',$raw,$m))$r['url']=rtrim($m[1],"'\"");

    if(preg_match('/-X\s+[\'"]?([A-Z]+)[\'"]?/u',$raw,$m))$r['method']=strtoupper($m[1]);
    elseif(preg_match('/--request\s+[\'"]?([A-Z]+)[\'"]?/u',$raw,$m))$r['method']=strtoupper($m[1]);

    $headers=[];

    preg_match_all('/(?:-H|--header)\s+(?:\'([^\']+)\'|"([^"]+)")/u',$raw,$hm);
    foreach($hm[1] as $i=>$h){
        $hv=!empty($h)?$h:($hm[2][$i]??'');
        if($hv&&strpos($hv,':')!==false)$headers[]=$hv;
    }
    $r['headers_str']=implode("\n",$headers);

    $body='';

    if(preg_match('/(?:--data(?:-raw|-binary|-urlencode)?|-d)\s+\$\'((?:[^\'\\\\]|\\\\.)*)\'(?:\s|$)/su',$raw,$m)){
        $body=$m[1];

        $body=str_replace(['\\n','\\r','\\t',"\\'"],[ "\n",  "\r",  "\t", "'"],  $body);
    }

    elseif(preg_match('/(?:--data(?:-raw|-binary|-urlencode)?|-d)\s+\'((?:[^\'\\\\]|\\\\.)*)\'/su',$raw,$m)){
        $body=$m[1];
    }

    elseif(preg_match('/(?:--data(?:-raw|-binary|-urlencode)?|-d)\s+"((?:[^"\\\\]|\\\\.)*)"/su',$raw,$m)){
        $body=stripslashes($m[1]);
    }

    elseif(preg_match('/(?:--data(?:-raw|-binary)?|-d)\s+(\{[^\r\n]+)/su',$raw,$m)){
        $body=trim($m[1]);
    }

    if(!empty(trim($body))){
        $r['body']=trim($body);
        if($r['method']==='GET')$r['method']='POST';
    }

    if($r['method']==='GET'){
        if(strpos($raw,'--data')!==false||preg_match('/\s-d\s/',$raw))$r['method']='POST';
    }
    return $r;
}

function md2tg($text){
    if(empty($text))return' ';
    $text=preg_replace_callback('/```(\w+)?\n?(.*?)```/su',function($m){return"\n<pre><code>".htmlspecialchars(trim($m[2]),ENT_NOQUOTES,'UTF-8')."</code></pre>\n";},$text);
    $text=preg_replace_callback('/`([^`\n]+)`/',function($m){return'<code>'.htmlspecialchars($m[1],ENT_NOQUOTES,'UTF-8').'</code>';},$text);
    $parts=preg_split('/(<pre>.*?<\/pre>|<code>.*?<\/code>)/su',$text,-1,PREG_SPLIT_DELIM_CAPTURE);
    $out='';foreach($parts as $pt){
        if(str_starts_with($pt,'<pre>')||str_starts_with($pt,'<code>')){$out.=$pt;}
        else{$pt=preg_replace('/&(?!amp;|lt;|gt;|quot;|#\d+;)/','&amp;',$pt);$pt=preg_replace('/<(?![\/]?(b|i|u|s|code|pre|a)[\s>])/','&lt;',$pt);$pt=str_replace('>','&gt;',$pt);$out.=$pt;}
    }
    $text=$out;
    $text=preg_replace('/^#{1,6}\s+(.+)$/mu',"\n<b>\$1</b>",$text);
    $text=preg_replace('/^[-*]{3,}$/mu','─────────────────',$text);
    $text=preg_replace('/\*\*(.+?)\*\*/su','<b>$1</b>',$text);
    $text=preg_replace('/__(.+?)__/su','<b>$1</b>',$text);
    $text=preg_replace('/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/su','<i>$1</i>',$text);
    $text=preg_replace('/(?<!_)_(?!_)(.+?)(?<!_)_(?!_)/su','<i>$1</i>',$text);
    $text=preg_replace('/~~(.+?)~~/su','<s>$1</s>',$text);
    $text=preg_replace('/\[([^\]]+)\]\((https?:\/\/[^\)]+)\)/','<a href="$2">$1</a>',$text);
    $text=preg_replace('/^[\-\*•]\s+(.+)$/mu','  • $1',$text);
    $text=preg_replace('/^>\s*(.+)$/mu','┃ <i>$1</i>',$text);
    $text=preg_replace('/\n{3,}/u',"\n\n",$text);
    return trim($text);
}

function applyVars($text,$str){
    if(empty(trim($str)))return $text;
    foreach(explode("\n",$str) as $l){if(strpos($l,'=')!==false){[$k,$v]=explode('=',$l,2);$k=trim($k);$v=trim($v);if($k)$text=str_replace('{'.$k.'}',$v,$text);}}
    return $text;
}
function findVal($arr,$key){
    if(!is_array($arr))return null;$q=[$arr];
    while($q){$c=array_shift($q);if(is_array($c)){if(array_key_exists($key,$c))return $c[$key];foreach($c as $v)if(is_array($v))$q[]=$v;}}
    return null;
}
function getNestedVal($data,$path){
    foreach(explode('.',$path) as $k){if(is_array($data)&&isset($data[$k]))$data=$data[$k];else return null;}
    return is_array($data)?json_encode($data,JSON_UNESCAPED_UNICODE):$data;
}
function buildVarMap($u,$s,$query){
    $v=['query'=>$query,'QUERY'=>$query,'tg_id'=>$u['id']??'','tg_name'=>$u['name']??'','tg_username'=>$u['username']??'','user_key'=>$u['key']??'None'];
    foreach($s['api_keys']??[] as $ak)if(!empty($ak['name']))$v[strtoupper($ak['name'])]=$ak['value']??'';
    foreach(explode("\n",$s['bot_vars']??'') as $l)if(strpos($l,'=')!==false){[$k,$val]=explode('=',$l,2);$v[trim($k)]=trim($val);}
    return $v;
}
function pv($text,$u,$s,$query='',$cv='',$record=null,$api=null,&$db=null){
    if(!$text)return' ';
    $sl=$u['searchesLeft']??0;
    $role=($u['id']===($s['adminId']??''))?'👑 Owner':'👤 User';
    $text=str_replace(
        ['{tg_name}','{tg_username}','{tg_id}','{user_key}','{query}','{tg_role}','{tg_searches}'],
        [str_replace(['<','>'],['﹤','﹥'],$u['name']??''),htmlspecialchars($u['username']??'',ENT_NOQUOTES,'UTF-8'),
         $u['id']??'',$u['key']??'None',$query,$role,$sl==999999?'Unlimited':$sl],
        $text);
    foreach($s['api_keys']??[] as $ak)if(!empty($ak['name']))$text=str_replace('{'.strtoupper($ak['name']).'}',$ak['value']??'',$text);
    if(!empty($s['bot_vars']))$text=applyVars($text,$s['bot_vars']);
    $text=applyVars($text,$cv);
    $text=applyVars($text,$s['global_vars']??'');
    if($db!==null&&!empty($db['dyn_vars'])){
        foreach($db['dyn_vars'] as $dk=>$dv)$text=str_replace('{'.$dk.'}',$dv,$text);
    }
    if($record!==null||$api!==null){
        preg_match_all('/\{([a-zA-Z0-9_ \.]+)\}/',$text,$mm);
        foreach(array_unique($mm[1]) as $key){
            $val=null;
            if(strpos($key,'.')!==false){
                if($record!==null)$val=getNestedVal($record,$key);
                if($val===null&&$api!==null)$val=getNestedVal($api,$key);
            }else{
                if($record!==null){if(array_key_exists($key,$record))$val=$record[$key];else $val=findVal($record,$key);}
                if($val===null&&$api!==null){if(array_key_exists($key,$api))$val=$api[$key];else $val=findVal($api,$key);}
            }
            $strVal=strtolower(trim((string)$val));
            if($val===null||$val===''||$strVal==='null'||$strVal==='na'||$strVal==='n/a'||(is_array($val)&&empty($val)))
                $text=str_replace('{'.$key.'}','N/A',$text);
            else{$vs=is_array($val)?json_encode($val,JSON_UNESCAPED_UNICODE):(string)$val;$text=str_replace('{'.$key.'}',htmlspecialchars($vs,ENT_NOQUOTES,'UTF-8'),$text);}
        }
    }
    $text=preg_replace('/\{[a-zA-Z0-9_ \.]+\}/','N/A',$text);
    return $text;
}

function pvNoStamp($text,$u,$s,$query='',$cv='',$db=null){
    if(!$text)return' ';
    $sl=$u['searchesLeft']??0;
    $role=($u['id']===($s['adminId']??''))?'👑 Owner':'👤 User';
    $text=str_replace(
        ['{tg_name}','{tg_username}','{tg_id}','{user_key}','{query}','{tg_role}','{tg_searches}'],
        [str_replace(['<','>'],['﹤','﹥'],$u['name']??''),htmlspecialchars($u['username']??'',ENT_NOQUOTES,'UTF-8'),
         $u['id']??'',$u['key']??'None',htmlspecialchars($query,ENT_NOQUOTES,'UTF-8'),$role,$sl==999999?'Unlimited':$sl],
        $text);
    foreach($s['api_keys']??[] as $ak)if(!empty($ak['name']))$text=str_replace('{'.strtoupper($ak['name']).'}',$ak['value']??'',$text);
    if(!empty($s['bot_vars']))$text=applyVars($text,$s['bot_vars']);
    $text=applyVars($text,$cv);
    $text=applyVars($text,$s['global_vars']??'');
    if($db!==null&&!empty($db['dyn_vars'])){
        foreach($db['dyn_vars'] as $dk=>$dv)$text=str_replace('{'.$dk.'}',$dv,$text);
    }

    return trim($text);
}
function checkCond($c,$u,$s,$q,$cv,$r=null,$a=null){
    if(empty(trim($c)))return true;
    $c=pv($c,$u,$s,$q,$cv,$r,$a);
    if(strpos($c,'!=')!==false){[$l,$rv]=explode('!=',$c,2);$l=trim($l);$rv=trim($rv);$ra=array_map('trim',explode(',',$rv));return!in_array($l,$ra)&&$l!==$rv;}
    if(strpos($c,'==')!==false){[$l,$rv]=explode('==',$c,2);$l=trim($l);$rv=trim($rv);$ra=array_map('trim',explode(',',$rv));return in_array($l,$ra)||$l===$rv;}
    return true;
}

function buildKb($buttons,$u,$s,$q,$cv,$r=null,$a=null){
    if(empty($buttons))return null;$rows=[];
    foreach($buttons as $b){
        if(!empty($b['cond'])&&!checkCond($b['cond'],$u,$s,$q,$cv,$r,$a))continue;
        if(empty($b['text']))continue;
        $btnText=pv($b['text'],$u,$s,$q,$cv,$r,$a);
        if(!empty($b['url'])){
            $rows[]=[['text'=>$btnText,'url'=>$b['url']]];
        }elseif(!empty($b['target'])&&$b['target']!=='_NEXT_'&&$b['target']!=='_PREV_'){
            $rows[]=[['text'=>$btnText,'callback_data'=>'go|'.$b['target'].'|'.($b['edit']?'1':'0').'|'.($b['delay']??'0')]];
        }
    }
    return empty($rows)?null:json_encode(['inline_keyboard'=>$rows]);
}
function hasAccess($uid,$chatId,$ac,$gv){
    if(empty(trim($ac)))return true;
    $ac=applyVars($ac,$gv);$al=array_map('trim',explode(',',$ac));
    return in_array((string)$uid,$al)||in_array((string)$chatId,$al);
}

function getBrowserSessFile($botId,$uid,$pgId){
    return getBotDir($botId).'brs_'.preg_replace('/\W/','_',$uid).'_'.preg_replace('/\W/','_',$pgId).'.json';
}
function saveBrowserSession($botId,$uid,$pgId,$d){file_put_contents(getBrowserSessFile($botId,$uid,$pgId),json_encode($d,JSON_UNESCAPED_UNICODE),LOCK_EX);}
function loadBrowserSession($botId,$uid,$pgId){$f=getBrowserSessFile($botId,$uid,$pgId);return file_exists($f)?json_decode(file_get_contents($f),true):null;}
function deleteBrowserSession($botId,$uid,$pgId){$f=getBrowserSessFile($botId,$uid,$pgId);if(file_exists($f))@unlink($f);}
function buildBrowserScript(array $steps,array $vars,string $sessFile,string $resFile,int $from=0):string{
    $stJ=json_encode($steps,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    $vJ =json_encode($vars, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    $sf =addslashes($sessFile);
    $rf =addslashes($resFile);
    return <<<PY
import sys,json,os,base64,time,random,re,tempfile
SF='{$sf}'; RF='{$rf}'
R={'steps':[],'status':'done','vars':{}}
V={$vJ}
FROM={$from}
if os.path.exists(SF):
    try: V.update(json.load(open(SF)).get('vars',{}))
    except: pass
def av(t):
    t=str(t)
    for k,v in V.items(): t=t.replace('{'+k+'}',str(v))
    def rr(m):
        pts=[x.strip() for x in str(V.get(m.group(1),'')).split(',') if x.strip()]
        return random.choice(pts) if pts else ''
    return re.sub(r'\{random:([^}]+)\}',rr,t)
_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_STEALTH_ARGS=['--no-sandbox','--disable-dev-shm-usage','--disable-blink-features=AutomationControlled','--disable-infobars','--window-size=1920,1080','--disable-gpu','--lang=en-IN','--disable-extensions','--no-first-run','--ignore-certificate-errors']
P=None;B=None;PW=False;_p=None;_PW_CTX=None
try:
    from playwright.sync_api import sync_playwright
    _p=sync_playwright().__enter__();PW=True
except: pass
if PW:
    ok=False
    for ch in ['chrome','msedge',None]:
        try:
            _bargs=_STEALTH_ARGS[:]
            _b=_p.chromium.launch(channel=ch,headless=True,args=_bargs) if ch else _p.chromium.launch(headless=True,args=_bargs)
            ok=True;B=_b;break
        except: pass
    if not ok: PW=False
if not PW:
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait,Select
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.chrome.options import Options as CO
        o=CO()
        for a in _STEALTH_ARGS+['--headless=new']: o.add_argument(a)
        o.add_experimental_option('excludeSwitches',['enable-automation'])
        o.add_experimental_option('useAutomationExtension',False)
        o.add_argument(f'--user-agent={_UA}')
        try: B=webdriver.Chrome(options=o)
        except:
            try:
                from selenium.webdriver.chromium.options import ChromiumOptions
                o2=ChromiumOptions()
                for a in ['--headless=new','--no-sandbox','--disable-dev-shm-usage','--disable-blink-features=AutomationControlled','--window-size=1920,1080']: o2.add_argument(a)
                o2.add_argument(f'--user-agent={_UA}')
                B=webdriver.Chrome(options=o2)
            except Exception as e:
                R['status']='error';R['error']='No browser: '+str(e)
                open(RF,'w').write(json.dumps(R));sys.exit(1)
        try: B.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument',{'source':'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'})
        except: pass
    except ImportError as e:
        R['status']='error';R['error']='selenium missing: '+str(e)
        open(RF,'w').write(json.dumps(R));sys.exit(1)
def _pw_goto(url,timeout=45000):
    global P
    try: P.goto(url,wait_until='networkidle',timeout=timeout)
    except:
        try: P.goto(url,wait_until='domcontentloaded',timeout=timeout)
        except: P.goto(url,wait_until='load',timeout=timeout)
if FROM>0 and os.path.exists(SF):
    try:
        ss_d=json.load(open(SF))
        if PW:
            _PW_CTX=B.new_context(storage_state=ss_d.get('storage',{}),user_agent=_UA,viewport={'width':1920,'height':1080},locale='en-IN',timezone_id='Asia/Kolkata')
            _PW_CTX.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
            P=_PW_CTX.new_page()
            if ss_d.get('url'): _pw_goto(ss_d['url'])
        else:
            if ss_d.get('url'): B.get(ss_d['url'])
            for ck in ss_d.get('cookies',[]):
                try: B.add_cookie(ck)
                except: pass
        V.update(ss_d.get('vars',{}))
    except: pass
else:
    if PW:
        _PW_CTX=B.new_context(user_agent=_UA,viewport={'width':1920,'height':1080},locale='en-IN',timezone_id='Asia/Kolkata')
        _PW_CTX.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
        P=_PW_CTX.new_page()
_CTX_FRAME=[None]
def curl(): return P.url if PW else B.current_url
def _act_page(): return _CTX_FRAME[0] if _CTX_FRAME[0] is not None else P
def ss(crop=None):
    f=tempfile.mktemp(suffix='.png')
    if PW:
        pg=_act_page()
        if crop and all(crop): pg.screenshot(path=f,clip={'x':float(crop[0]),'y':float(crop[1]),'width':float(crop[2]),'height':float(crop[3])})
        else: pg.screenshot(path=f,full_page=False)
    else:
        B.save_screenshot(f)
        if crop and all(crop):
            try:
                from PIL import Image
                img=Image.open(f);img=img.crop((float(crop[0]),float(crop[1]),float(crop[0])+float(crop[2]),float(crop[1])+float(crop[3])));img.save(f)
            except: pass
    d=base64.b64encode(open(f,'rb').read()).decode();os.unlink(f);return d
def fel(sel):
    pg=_act_page() if PW else None
    if PW: return pg.locator(sel).first
    try: return B.find_element(By.CSS_SELECTOR,sel)
    except:
        try: return B.find_element(By.XPATH,sel)
        except: raise Exception('Not found: '+sel)
steps={$stJ}
for i,st in enumerate(steps):
    if i<FROM: continue
    t=st.get('type','open')
    try:
        if t=='open':
            _CTX_FRAME[0]=None
            u=av(st.get('value',''))
            if PW: _pw_goto(u)
            else: B.get(u)
        elif t=='wait': time.sleep(float(av(str(st.get('value','2')))))
        elif t=='wait_load':
            state=av(st.get('value','networkidle'));to=int(float(st.get('timeout',15))*1000)
            if PW: P.wait_for_load_state(state,timeout=to)
            else: time.sleep(2)
        elif t=='wait_element':
            s=av(st.get('selector',''));to=float(st.get('timeout',10))
            if PW: _act_page().wait_for_selector(s,timeout=int(to*1000))
            else:
                by=By.XPATH if s.startswith('//') or s.startswith('(//') else By.CSS_SELECTOR
                WebDriverWait(B,to).until(EC.presence_of_element_located((by,s)))
        elif t=='click':
            x=st.get('x','');y=st.get('y','')
            if x and y:
                if PW: P.mouse.click(float(x),float(y))
                else:
                    from selenium.webdriver.common.action_chains import ActionChains
                    ActionChains(B).move_by_offset(float(x),float(y)).click().perform()
            else:
                pg=_act_page()
                s=av(st.get('selector',''))
                if PW: pg.locator(s).first.click()
                else: fel(s).click()
        elif t=='fill':
            s=av(st.get('selector',''));v=av(st.get('value',''))
            if PW: _act_page().fill(s,v)
            else: el=fel(s);el.clear();el.send_keys(v)
        elif t=='scroll':
            v=float(av(str(st.get('value','500'))))
            if PW: P.mouse.wheel(0,v)
            else: B.execute_script(f'window.scrollBy(0,{v})')
        elif t=='reload':
            if PW: P.reload();P.wait_for_load_state('domcontentloaded')
            else: B.refresh()
        elif t=='key':
            v=av(st.get('value',''))
            if PW: P.keyboard.press(v)
            else:
                from selenium.webdriver.common.keys import Keys
                B.find_element(By.TAG_NAME,'body').send_keys(getattr(Keys,v.upper(),v))
        elif t=='select':
            s=av(st.get('selector',''));v=av(st.get('value',''))
            if PW: _act_page().select_option(s,v)
            else: Select(fel(s)).select_by_visible_text(v)
        elif t=='hover':
            s=av(st.get('selector',''))
            if PW: _act_page().hover(s)
            else:
                from selenium.webdriver.common.action_chains import ActionChains
                ActionChains(B).move_to_element(fel(s)).perform()
        elif t=='get_text':
            s=av(st.get('selector',''));vn=st.get('var_name','result')
            txt=_act_page().locator(s).first.inner_text() if PW else fel(s).text
            V[vn]=txt;R['steps'].append({'i':i,'type':t,'status':'ok','value':txt});continue
        elif t=='screenshot':
            crop=[st.get('crop_x'),st.get('crop_y'),st.get('crop_w'),st.get('crop_h')]
            b64=ss(crop)
            R['steps'].append({'i':i,'type':t,'status':'ok','image':b64,'send':bool(st.get('send_ss')),'delete_after':bool(st.get('delete_after')),'caption':av(st.get('caption',''))});continue
        elif t=='ask_captcha':
            crop=[st.get('crop_x'),st.get('crop_y'),st.get('crop_w'),st.get('crop_h')]
            b64=ss(crop)
            sd={'url':curl(),'vars':V,'resume_from':i+1,'captcha_var':st.get('var_name','captcha')}
            if PW: sd['storage']=_PW_CTX.storage_state() if _PW_CTX else {}
            else: sd['cookies']=B.get_cookies()
            open(SF,'w').write(json.dumps(sd))
            R['status']='captcha_needed';R['captcha_image']=b64
            R['resume_from']=i+1;R['captcha_var']=st.get('var_name','captcha')
            R['captcha_prompt']=av(st.get('caption','🔐 Solve captcha & reply:'))
            R['steps'].append({'i':i,'type':t,'status':'paused'});break
        elif t=='set_var': V[st.get('var_name','v')]=av(st.get('value',''))
        elif t=='random_var':
            vn=st.get('var_name','v');src=av(st.get('value',''))
            pts=[x.strip() for x in src.split(',') if x.strip()]
            V[vn]=random.choice(pts) if pts else ''
        elif t=='raw':
            exec(av(st.get('value','')),{'P':P,'PAGE':P,'B':B,'BROWSER':B,'V':V,'av':av,'ss':ss,'R':R,'_FRAME':_CTX_FRAME[0],'_PW_CTX':_PW_CTX,'_act_page':_act_page})
        elif t=='get_attr':
            s=av(st.get('selector',''));attr=av(st.get('attribute','href'));vn=st.get('var_name','result')
            val=_act_page().locator(s).first.get_attribute(attr) if PW else fel(s).get_attribute(attr)
            V[vn]=val or '';R['steps'].append({'i':i,'type':t,'status':'ok','value':val});continue
        elif t=='js_eval':
            code=av(st.get('value',''));vn=st.get('var_name','js_result')
            val=P.evaluate(code) if PW else B.execute_script('return '+code)
            V[vn]=str(val) if val is not None else '';R['steps'].append({'i':i,'type':t,'status':'ok','value':str(val)});continue
        elif t=='assert_text':
            s=av(st.get('selector',''));expected=av(st.get('value',''))
            actual=_act_page().locator(s).first.inner_text() if PW else fel(s).text
            if expected.lower() not in actual.lower(): raise Exception(f'Assert failed: expected "{expected}" in "{actual}"')
        elif t=='upload_file':
            s=av(st.get('selector',''));path=av(st.get('value',''))
            if PW: _act_page().set_input_files(s,path)
            else: fel(s).send_keys(path)
        elif t=='iframe_switch':
            s=av(st.get('selector',''))
            if PW:
                _CTX_FRAME[0]=P.frame_locator(s)
                try: _CTX_FRAME[0].locator('body').wait_for(timeout=8000)
                except: pass
            else:
                iframe=fel(s);B.switch_to.frame(iframe)
        elif t=='iframe_main':
            _CTX_FRAME[0]=None
            if not PW: B.switch_to.default_content()
        elif t=='cookie_set':
            name=av(st.get('name',''));val2=av(st.get('value',''))
            if PW: _PW_CTX.add_cookies([{'name':name,'value':val2,'url':curl()}]) if _PW_CTX else None
            else: B.add_cookie({'name':name,'value':val2})
        elif t=='cookie_get':
            name=av(st.get('name',''));vn=st.get('var_name','cookie_val')
            if PW:
                cks=_PW_CTX.cookies() if _PW_CTX else []
                match=[c['value'] for c in cks if c['name']==name]
                V[vn]=match[0] if match else ''
            else:
                cks=B.get_cookies();match=[c['value'] for c in cks if c['name']==name]
                V[vn]=match[0] if match else ''
            R['steps'].append({'i':i,'type':t,'status':'ok','value':V[vn]});continue
        elif t=='type_slow':
            s=av(st.get('selector',''));txt=av(st.get('value',''));dms=float(st.get('delay_ms',80))
            if PW:
                _act_page().locator(s).first.click()
                _act_page().locator(s).first.fill('')
                _act_page().locator(s).first.type(txt,delay=dms)
            else:
                el=fel(s);el.clear()
                for ch in txt: el.send_keys(ch);time.sleep(dms/1000)
        elif t=='wait_url':
            expected=av(st.get('value',''));timeout=float(st.get('timeout',10))
            if PW: P.wait_for_url(f'**{expected}**',timeout=int(timeout*1000))
            else:
                import time as _t;start=_t.time()
                while expected not in B.current_url:
                    if _t.time()-start>timeout: raise Exception('URL wait timeout: '+expected)
                    _t.sleep(0.5)
        elif t=='clear_field':
            s=av(st.get('selector',''))
            if PW: _act_page().fill(s,'')
            else: el=fel(s);el.clear()
        elif t=='double_click':
            s=av(st.get('selector',''))
            if PW: _act_page().dblclick(s)
            else:
                from selenium.webdriver.common.action_chains import ActionChains
                ActionChains(B).double_click(fel(s)).perform()
        elif t=='right_click':
            s=av(st.get('selector',''))
            if PW: _act_page().click(s,button='right')
            else:
                from selenium.webdriver.common.action_chains import ActionChains
                ActionChains(B).context_click(fel(s)).perform()
        elif t=='drag_drop':
            src=av(st.get('selector',''));tgt=av(st.get('target',''))
            if PW: P.drag_and_drop(src,tgt)
            else:
                from selenium.webdriver.common.action_chains import ActionChains
                ActionChains(B).drag_and_drop(fel(src),fel(tgt)).perform()
        R['steps'].append({'i':i,'type':t,'status':'ok'})
    except Exception as e:
        R['steps'].append({'i':i,'type':t,'status':'error','error':str(e)})
        if st.get('stop_on_error'): R['status']='error';break
R['vars']=V
try:
    if PW:
        if _PW_CTX: _PW_CTX.close()
        B.close();_p.__exit__(None,None,None)
    else: B.quit()
except: pass
open(RF,'w').write(json.dumps(R))
PY;
}
function execBrowser($botId,$chatId,$msgId,$u,&$db,$s,$query,$p,$token,$extraVars=[]){

    $varNames=array_values(array_filter(array_map('trim',explode(',',$p['browser_var_names']??''))));
    $args=array_values(array_filter(explode(' ',trim($query))));
    $vars=['query'=>$query,'tg_name'=>$u['name']??'','tg_id'=>$u['id']??'','tg_username'=>$u['username']??'','user_key'=>$u['key']??'None'];

    foreach($s['api_keys']??[] as $ak)if(!empty($ak['name']))$vars[strtoupper($ak['name'])]=$ak['value']??'';

    foreach(explode("\n",$s['bot_vars']??'') as $l)if(strpos($l,'=')!==false){[$k,$v]=explode('=',$l,2);$vars[trim($k)]=trim($v);}

    foreach($varNames as $i=>$vn)if(isset($args[$i]))$vars[$vn]=$args[$i];

    foreach($args as $i=>$av)$vars['var'.($i+1)]=$av;

    foreach($db['dyn_vars']??[] as $dk=>$dv)$vars[$dk]=$dv;

    $vars=array_merge($vars,$extraVars);
    $uid=$u['id'];
    $pgId=$p['id'];
    $sessFile=getBrowserSessFile($botId,$uid,$pgId);
    $resFile=getBotDir($botId).'brr_'.preg_replace('/\W/','_',$uid).'_'.preg_replace('/\W/','_',$pgId).'.json';
    if(file_exists($resFile))@unlink($resFile);
    $from=0;
    if(!empty($extraVars['__captcha_resume'])){
        $sess=loadBrowserSession($botId,$uid,$pgId)??[];
        $from=(int)($sess['resume_from']??0);
        $cVar=$sess['captcha_var']??'captcha';
        $vars[$cVar]=$extraVars['captcha']??'';
        foreach($sess['vars']??[] as $k=>$v)if(!isset($vars[$k]))$vars[$k]=$v;
    }
    $steps=$p['browser_steps']??[];
    $script=buildBrowserScript($steps,$vars,$sessFile,$resFile,$from);
    $scrFile=getBotDir($botId).'brs_'.preg_replace('/\W/','_',$uid).'_'.preg_replace('/\W/','_',$pgId).'.py';
    file_put_contents($scrFile,$script);

    $lmsg='⏳ <b>Browser running...</b>';
    if(!empty(trim($p['msg_loading']??'')))$lmsg=pvNoStamp($p['msg_loading'],$u,$s,$query,$p['custom_vars']??'',$db);
    $lr=tg('sendMessage',['chat_id'=>$chatId,'text'=>$lmsg,'parse_mode'=>'HTML'],$token);
    $lmid=$lr['result']['message_id']??null;
    $timeout=max(30,(int)($p['api_timeout']??120));
    exec('timeout '.escapeshellarg($timeout).' python3 '.escapeshellarg($scrFile).' 2>/dev/null');
    @unlink($scrFile);
    $res=file_exists($resFile)?json_decode(file_get_contents($resFile),true):null;
    if($lmid)tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$lmid],$token);
    if(!$res){
        tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Browser failed or timed out.','parse_mode'=>'HTML'],$token);
        addLog($botId,"Browser FAIL [{$pgId}]",'error');
        return;
    }

    if(($res['status']??'')==='captcha_needed'){
        $b64=$res['captcha_image']??'';
        $prompt=$res['captcha_prompt']??'🔐 Solve the captcha and reply:';
        saveBrowserSession($botId,$uid,$pgId,['resume_from'=>$res['resume_from'],'captcha_var'=>$res['captcha_var']??'captcha','vars'=>$res['vars']??[]]);
        $db['users'][$uid]['active_page']='__brcap__'.$pgId;
        saveDB($botId,$db);
        if($b64){
            $tmp=tempnam(sys_get_temp_dir(),'cap_').'.png';
            file_put_contents($tmp,base64_decode($b64));
            $ch=curl_init();
            curl_setopt_array($ch,[CURLOPT_URL=>TG_BASE.$token.'/sendPhoto',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_POSTFIELDS=>['chat_id'=>$chatId,'caption'=>$prompt,'parse_mode'=>'HTML','photo'=>new CURLFile($tmp,'image/png','cap.png')]]);
            curl_exec($ch);curl_close($ch);@unlink($tmp);
        }else{
            tg('sendMessage',['chat_id'=>$chatId,'text'=>$prompt,'parse_mode'=>'HTML'],$token);
        }
        addLog($botId,"Browser captcha [{$pgId}]",'info');
        return;
    }

    foreach($res['steps']??[] as $step){
        if(($step['type']??'')==='screenshot'&&!empty($step['send'])&&!empty($step['image'])){
            $tmp=tempnam(sys_get_temp_dir(),'ss_').'.png';
            file_put_contents($tmp,base64_decode($step['image']));
            $cap=htmlspecialchars($step['caption']??'',ENT_NOQUOTES,'UTF-8');
            $ch=curl_init();
            curl_setopt_array($ch,[CURLOPT_URL=>TG_BASE.$token.'/sendPhoto',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_POSTFIELDS=>['chat_id'=>$chatId,'caption'=>$cap,'parse_mode'=>'HTML','photo'=>new CURLFile($tmp,'image/png','ss.png')]]);
            $sr=json_decode(curl_exec($ch),true);curl_close($ch);@unlink($tmp);
            if(!empty($step['delete_after'])&&!empty($sr['result']['message_id'])){
                sleep(5);tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$sr['result']['message_id']],$token);
            }
        }
    }

    $allVars=array_merge($vars,$res['vars']??[]);
    $doneTmpl=trim($p['browser_done_msg']??'✅ Done!');
    if($doneTmpl){
        $doneText=pvNoStamp($doneTmpl,$u,$s,$query,$p['custom_vars']??'',$db);
        foreach($allVars as $k=>$v)$doneText=str_replace('{'.$k.'}',htmlspecialchars((string)$v,ENT_NOQUOTES,'UTF-8'),$doneText);
        $kb=buildKb($p['buttons']??[],$u,$s,$query,$p['custom_vars']??'');
        sendLong($botId,$chatId,null,$doneText,$p['media_main']??'',$kb,false,$token);
    }
    $st=$res['status']??'done';
    addLog($botId,"Browser ".strtoupper($st)." [{$pgId}]: $query",$st==='done'?'success':'warn');
    deleteBrowserSession($botId,$uid,$pgId);
    @unlink($resFile);
}
function checkForceJoin($uid,$fj,$token){
    if(empty($fj['enabled'])||empty($fj['channels']))return true;
    foreach($fj['channels'] as $ch){
        $chId=trim($ch['id']??'');
        if(!$chId)continue;
        $r=tg('getChatMember',['chat_id'=>$chId,'user_id'=>$uid],$token);
        $status=$r['result']['status']??'left';
        if(in_array($status,['left','kicked','restricted']))return false;
    }
    return true;
}
function sendForceJoinMsg($chatId,$fj,$token){
    $msg=$fj['message']??'⚠️ Please join our channel(s) to use this bot!';
    $media=$fj['media']??'';
    $btns=$fj['buttons']??[];
    $rows=[];
    foreach($btns as $b){if(empty($b['text']))continue;if(!empty($b['url']))$rows[]=[['text'=>$b['text'],'url'=>$b['url']]];}
    $kb=$rows?json_encode(['inline_keyboard'=>$rows]):null;
    sendMsg($chatId,null,$msg,$media,$kb,false,$token);
}

function execPage($botId,$chatId,$msgId,$u,&$db,$s,$query,$p,$token){
    $lmid=$msgId;
    $loadingMsgIds=[];

    if(!empty($p['loading_steps'])){
        foreach($p['loading_steps'] as $idx=>$step){
            if(empty(trim($step['text']??''))&&empty(trim($step['media']??'')))continue;
            $lt=pv($step['text']??'',$u,$s,$query,$p['custom_vars']??'');
            $r=sendMsg($chatId,$lmid,$lt,$step['media']??'',null,$lmid!==null,$token);
            if(isset($r['result']['message_id'])){$lmid=$r['result']['message_id'];$loadingMsgIds[]=$lmid;}
            if($idx<count($p['loading_steps'])-1)usleep(800000);
        }
    }elseif(!empty(trim($p['msg_loading']??''))){
        $lt=pv($p['msg_loading'],$u,$s,$query,$p['custom_vars']??'');
        $r=sendMsg($chatId,null,$lt,'',null,false,$token);
        if(isset($r['result']['message_id'])){$lmid=$r['result']['message_id'];$loadingMsgIds[]=$lmid;}
    }
    if($p['type']==='api'){
        $apiUrl=pv($p['api_url']??'',$u,$s,urlencode($query),$p['custom_vars']??'');
        $timeout=!empty($p['api_timeout'])?(int)$p['api_timeout']:15;
        $maxR=!empty($p['api_retry'])?2:1;$attempt=0;$apiData=null;
        while($attempt<$maxR){
            // User-configured API URL — SSL verify enabled; set to false only if hitting self-signed certs
            $ch=curl_init();curl_setopt_array($ch,[CURLOPT_URL=>$apiUrl,CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_TIMEOUT=>$timeout]);
            $res=curl_exec($ch);curl_close($ch);
            if($res){$td=json_decode($res,true);if(is_array($td)){$apiData=$td;break;}}
            $attempt++;if($attempt<$maxR)sleep(1);
        }
        $nf=false;
        if(!is_array($apiData)){$nf=true;$apiData=['error'=>'No response'];}
        else{
            if(isset($apiData['success'])&&in_array((string)$apiData['success'],['0','false',''],true))$nf=true;
            elseif(isset($apiData['status'])&&in_array((string)$apiData['status'],['0','false','404'],true))$nf=true;
            elseif(isset($apiData['error'])&&!empty($apiData['error']))$nf=true;
        }
        $targetData=[];
        if(!$nf){
            $td=$apiData;
            if(!empty($p['json_root'])){foreach(explode('.',$p['json_root']) as $pt){if(is_array($td)&&isset($td[$pt]))$td=$td[$pt];else{$td=null;break;}}}
            else{if(isAssoc($td)){foreach($td as $k=>$v){if(is_array($v)&&!isAssoc($v)){$td=$v;break;}}}}
            if(is_array($td)){$targetData=isAssoc($td)?[$td]:$td;}
            if(empty($targetData))$nf=true;
            else{$targetData=array_values(array_filter($targetData,fn($i)=>is_array($i)&&!empty($i)));if(empty($targetData))$nf=true;}
        }
        if($nf){
            if(!empty(trim($p['not_found']??''))||!empty(trim($p['media_error']??''))){
                $et=pv($p['not_found']??'🚫 Not found',$u,$s,$query,$p['custom_vars']??'',null,$apiData);
                $et=preg_replace('/\{[a-zA-Z0-9_ \.]+\}/','N/A',$et);
                sendMsg($chatId,$lmid,$et,$p['media_error']??'',null,$lmid!==null,$token);
            }
            addLog($botId,"API Fail: /{$p['trigger']} $query",'error');
        }else{
            $sid=uniqid();setCache($botId,$sid,['root'=>$apiData,'records'=>$targetData,'query'=>$query]);
            $total=count($targetData);$record=$targetData[0];
            $txt=$p['text']??'';$txt=str_replace(['{page_current}','{page_total}'],[1,$total],$txt);
            $txt=pv($txt,$u,$s,$query,$p['custom_vars']??'',$record,$apiData,$db);
            $txt=preg_replace('/\{[a-zA-Z0-9_ \.]+\}/','N/A',$txt);
            $navRow=[];$otherRows=[];
            foreach($p['buttons']??[] as $cb){
                if(!empty($cb['cond'])&&!checkCond($cb['cond'],$u,$s,$query,$p['custom_vars']??'',$record,$apiData))continue;
                $bt=pv($cb['text']??'',$u,$s,$query,$p['custom_vars']??'',$record,$apiData);
                if(!empty($cb['url'])){$otherRows[]=[['text'=>$bt,'url'=>$cb['url']]];}
                elseif($cb['target']==='_NEXT_'){if($total>1)$navRow[]=['text'=>$bt,'callback_data'=>"pg|{$sid}|1|{$p['id']}"];}
                elseif($cb['target']==='_PREV_'){}
                else{$otherRows[]=[['text'=>$bt,'callback_data'=>'go|'.$cb['target'].'|'.($cb['edit']?'1':'0').'|'.($cb['delay']??'0')]];}
            }
            $fk=[];if($navRow)$fk[]=$navRow;foreach($otherRows as $rr)$fk[]=$rr;
            $kb=$fk?json_encode(['inline_keyboard'=>$fk]):null;
            setCache($botId,'lmsg_'.$u['id']??'',$txt);
            sendLong($botId,$chatId,$lmid,$txt,$p['media_main']??'',$kb,$lmid!==null,$token);
            addLog($botId,"API OK: /{$p['trigger']} $query",'success');
        }
        return;
    }
    if($p['type']==='curl'){

        $varMap=buildVarMap($u,$s,$query);

        $curl_url=trim($p['curl_url']??'');
        $curl_url=str_replace('{query}',rawurlencode($query),$curl_url);
        foreach($varMap as $vk=>$vv)if($vk!=='query'&&$vk!=='QUERY')$curl_url=str_replace('{'.$vk.'}',$vv,$curl_url);

        $curl_body=$p['curl_body']??'';

        $jq=json_encode($query);
        $jq=substr($jq,1,strlen($jq)-2); // strip outer quotes
        $curl_body=str_replace(['{query}','{QUERY}'],[$jq,$jq],$curl_body);
        foreach($varMap as $vk=>$vv)if($vk!=='query'&&$vk!=='QUERY')$curl_body=str_replace('{'.$vk.'}',$vv,$curl_body);

        $curl_headers=$p['curl_headers']??'';
        foreach($varMap as $vk=>$vv)$curl_headers=str_replace('{'.$vk.'}',$vv,$curl_headers);

        $curlTimeout=max(5,(int)($p['curl_timeout']??$p['api_timeout']??120));

        $result=doCurl($curl_url,$p['curl_method']??'POST',$curl_headers,$curl_body,$curlTimeout);
        $apiData=json_decode($result['body'],true);

        $rawVal=null;
        $respPath=trim($p['curl_response_path']??'');
        if($respPath!==''){

            $rawVal=jsonPath($apiData,$respPath);
        }

        if(($rawVal===null||$rawVal==='')&&$result['code']<400){
            if(is_array($apiData)){

                foreach(['result','response','text','content','answer','message','output','data'] as $fk){
                    if(isset($apiData[$fk])&&is_string($apiData[$fk])&&trim($apiData[$fk])!==''){
                        $rawVal=$apiData[$fk];break;
                    }
                }
            }

            if($rawVal===null||$rawVal==='')$rawVal=$result['body']??'';
        }

        $failed=($result['code']>=400||$rawVal===null||$rawVal==='');

        foreach($loadingMsgIds as $lmsgId){
            tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$lmsgId],$token);
        }
        if($failed){
            addLog($botId,"cURL Fail HTTP {$result['code']}: ".($p['id']??'')." err:{$result['error']}",'error');
            if(!empty(trim($p['not_found']??''))||!empty($p['media_error']??'')){
                $et=pvNoStamp($p['not_found']??'🚫 Error',$u,$s,$query,$p['custom_vars']??'',$db);
                sendMsg($chatId,null,$et,$p['media_error']??'',null,false,$token);
            }
        }else{

            $tmpl=!empty(trim($p['text']??''))?$p['text']:'{curl_response}';
            $rawStr=(string)$rawVal;
            $rawHtml=htmlspecialchars($rawStr,ENT_NOQUOTES,'UTF-8');

            $tmpl=str_replace(['{curl_response}','{response}','{result}','{message}','{reply}','{output}','{answer}','{text}'],[$rawHtml,$rawHtml,$rawHtml,$rawHtml,$rawHtml,$rawHtml,$rawHtml,$rawHtml],$tmpl);

            if($respPath!=='')$tmpl=str_replace('{'.$respPath.'}',$rawHtml,$tmpl);

            if($respPath!==''){
                $rpParts=explode('.',$respPath);
                $leafKey=$rpParts[count($rpParts)-1];
                if($leafKey)$tmpl=str_replace('{'.$leafKey.'}',$rawHtml,$tmpl);
            }

            if(is_array($apiData)){
                $jmap=flattenJson($apiData);
                uksort($jmap,function($a,$b){return strlen($b)-strlen($a);});
                foreach($jmap as $jk=>$jv){
                    $tmpl=str_replace('{'.$jk.'}',htmlspecialchars((string)$jv,ENT_NOQUOTES,'UTF-8'),$tmpl);
                }
            }

            $tmpl=pvNoStamp($tmpl,$u,$s,$query,$p['custom_vars']??'',$db);
            $kb=buildKb($p['buttons']??[],$u,$s,$query,$p['custom_vars']??'');
            setCache($botId,'lmsg_'.($u['id']??''),$tmpl);

            sendLong($botId,$chatId,null,$tmpl,$p['media_main']??'',$kb,false,$token);
            addLog($botId,"cURL OK[".($p['id']??'')."]: ".mb_substr($query,0,40),'success');
        }
        return;
    }
}

function handleFreeText($botId,$chatId,$isGroup,$uid,$u,&$db,$s,$msgText,$token,$botUsername=''){
    $fired=false;
    $fj=$s['force_join']??['enabled'=>false,'channels'=>[]];

    $ftPages=[];
    foreach($db['pages']??[] as $p){
        if(empty($p['is_free_text']))continue;
        $cm=$p['ft_chat_mode']??'both';
        if($cm==='dm'&&$isGroup)continue;
        if($cm==='group'&&!$isGroup)continue;
        if(!empty($p['ft_mention_only'])&&$isGroup&&$botUsername){
            if(stripos($msgText,'@'.$botUsername)===false)continue;
        }
        if(!empty($p['ft_access_control'])&&!hasAccess($uid,$chatId,$p['ft_access_control'],$s['global_vars']??''))continue;
        $ftPages[]=$p;
    }

    usort($ftPages,function($a,$b){return((int)!empty($a['force_join']))-((int)!empty($b['force_join']));});
    foreach($ftPages as $p){

        if(!empty($p['force_join'])&&!empty($fj['enabled'])){
            if(!checkForceJoin($uid,$fj,$token)){
                sendForceJoinMsg($chatId,$fj,$token);
                return true;
            }
        }
        if($p['type']==='text'){
            $rt=pv($p['text']??'',$u,$s,$msgText,$p['custom_vars']??'',null,null,$db);
            $kb=buildKb($p['buttons']??[],$u,$s,$msgText,$p['custom_vars']??'');
            $kb=injectOwnerEditBtn($kb,$p['id']??'',$u['id']??'',$s['adminId']??'');
            sendLong($botId,$chatId,null,$rt,$p['media_main']??'',$kb,false,$token);
        }else{
            execPage($botId,$chatId,null,$u,$db,$s,$msgText,$p,$token);
        }
        addLog($botId,"FreeText[{$p['id']}]: ".mb_substr($msgText,0,40).' by '.($u['name']??''),'info');
        $fired=true;
        break;
    }
    if($fired)return true;

    return false;
}

function getLaCaptchaSessFile($botId,$uid,$ruleId){
    return getBotDir($botId).'lacap_'.preg_replace('/\W/','_',$uid).'_'.preg_replace('/\W/','_',$ruleId).'.json';
}

function execLinkAutomationBrowser($botId,$chatId,$u,&$db,$s,$msgText,$rule,$token,$extraVars=[]){
    $uid=(string)($u['id']??'');
    $ruleId=$rule['id'];
    $varMap=buildVarMap($u,$s,$msgText);
    $vars=$varMap;
    // For startswith/contains trigger mode, also expose the argument part after the trigger keyword as {query_arg}
    $triggerKw=strtolower(trim($rule['trigger']??''));
    $tMode=$rule['trigger_mode']??'exact';
    if($tMode==='startswith'&&$triggerKw!==''){
        $after=ltrim(substr($msgText,strlen($triggerKw)));
        $vars['query_arg']=$after;
    } elseif($tMode==='contains'&&$triggerKw!==''){
        $vars['query_arg']=$msgText;
    } else {
        $vars['query_arg']='';
    }
    foreach($db['dyn_vars']??[] as $dk=>$dv)$vars[$dk]=$dv;
    $vars=array_merge($vars,$extraVars);

    // Determine browser steps: use rule's steps if defined, else auto-open the URL
    $steps=$rule['browser_steps']??[];
    if(empty($steps)){
        $ruleUrl=trim($rule['url']??'');
        foreach($varMap as $vk=>$vv)$ruleUrl=str_replace('{'.$vk.'}',$vv,$ruleUrl);
        $steps=[['type'=>'open','value'=>$ruleUrl,'stop_on_error'=>true]];
    }

    $sessFile=getLaCaptchaSessFile($botId,$uid,$ruleId);
    $resFile=getBotDir($botId).'lacres_'.preg_replace('/\W/','_',$uid).'_'.preg_replace('/\W/','_',$ruleId).'.json';
    if(file_exists($resFile))@unlink($resFile);

    $from=0;
    if(!empty($extraVars['__lacap_resume'])){
        $sess=file_exists($sessFile)?json_decode(file_get_contents($sessFile),true):[];
        $from=(int)($sess['resume_from']??0);
        $cVar=$sess['captcha_var']??'captcha';
        $vars[$cVar]=$extraVars['captcha']??'';
        foreach($sess['vars']??[] as $k=>$v)if(!isset($vars[$k]))$vars[$k]=$v;
    }

    $script=buildBrowserScript($steps,$vars,$sessFile,$resFile,$from);
    $scrFile=getBotDir($botId).'lacsc_'.preg_replace('/\W/','_',$uid).'_'.preg_replace('/\W/','_',$ruleId).'.py';
    file_put_contents($scrFile,$script);

    $timeout=max(30,min(300,(int)($rule['timeout']??60)));
    exec('timeout '.escapeshellarg($timeout).' python3 '.escapeshellarg($scrFile).' 2>/dev/null');
    @unlink($scrFile);

    $res=file_exists($resFile)?json_decode(file_get_contents($resFile),true):null;
    if(!$res){
        $errMsg=htmlspecialchars($rule['error_message']??'⚠️ Error fetching link response.',ENT_NOQUOTES,'UTF-8');
        tg('sendMessage',['chat_id'=>$chatId,'text'=>$errMsg,'parse_mode'=>'HTML'],$token);
        addLog($botId,"LinkAuto Browser FAIL [{$ruleId}]",'error');
        return;
    }

    if(($res['status']??'')==='captcha_needed'){
        $b64=$res['captcha_image']??'';
        $prompt=$res['captcha_prompt']??($rule['captcha_prompt']??'🔐 Solve the captcha and reply:');
        // Save session state for resume
        $sessData=['resume_from'=>$res['resume_from'],'captcha_var'=>$res['captcha_var']??'captcha','vars'=>$res['vars']??[],'rule_id'=>$ruleId];
        file_put_contents($sessFile,json_encode($sessData,JSON_UNESCAPED_UNICODE),LOCK_EX);
        // Mark user as waiting for captcha reply for this rule
        $db['users'][$uid]['active_page']='__lacap__'.$ruleId;
        saveDB($botId,$db);
        if($b64){
            $tmp=tempnam(sys_get_temp_dir(),'lacap_').'.png';
            file_put_contents($tmp,base64_decode($b64));
            $ch=curl_init();
            curl_setopt_array($ch,[CURLOPT_URL=>TG_BASE.$token.'/sendPhoto',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_POSTFIELDS=>['chat_id'=>$chatId,'caption'=>$prompt,'parse_mode'=>'HTML','photo'=>new CURLFile($tmp,'image/png','cap.png')]]);
            curl_exec($ch);curl_close($ch);@unlink($tmp);
        }else{
            tg('sendMessage',['chat_id'=>$chatId,'text'=>$prompt,'parse_mode'=>'HTML'],$token);
        }
        addLog($botId,"LinkAuto Browser captcha [{$ruleId}]",'info');
        return;
    }

    // Send any screenshots from steps
    foreach($res['steps']??[] as $step){
        if(($step['type']??'')==='screenshot'&&!empty($step['send'])&&!empty($step['image'])){
            $tmp=tempnam(sys_get_temp_dir(),'lass_').'.png';
            file_put_contents($tmp,base64_decode($step['image']));
            $cap=htmlspecialchars($step['caption']??'',ENT_NOQUOTES,'UTF-8');
            $ch=curl_init();
            curl_setopt_array($ch,[CURLOPT_URL=>TG_BASE.$token.'/sendPhoto',CURLOPT_RETURNTRANSFER=>true,CURLOPT_POST=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,
                CURLOPT_POSTFIELDS=>['chat_id'=>$chatId,'caption'=>$cap,'parse_mode'=>'HTML','photo'=>new CURLFile($tmp,'image/png','ss.png')]]);
            $sr=json_decode(curl_exec($ch),true);curl_close($ch);@unlink($tmp);
            if(!empty($step['delete_after'])&&!empty($sr['result']['message_id'])){
                sleep(5);tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$sr['result']['message_id']],$token);
            }
        }
    }

    // Build reply using result vars from browser + reply_template
    $allVars=array_merge($vars,$res['vars']??[]);
    $resultVar=$rule['browser_result_var']??'result';
    $extracted=isset($allVars[$resultVar])?(string)$allVars[$resultVar]:null;
    if($extracted===null){
        // Try common var names
        foreach(['result','response','text','content','answer','output','data'] as $fk){
            if(isset($allVars[$fk])&&trim((string)$allVars[$fk])!==''){$extracted=(string)$allVars[$fk];break;}
        }
    }
    if($extracted===null)$extracted='';

    $rawHtml=htmlspecialchars($extracted,ENT_NOQUOTES,'UTF-8');
    $tmpl=$rule['reply_template']??'{response}';
    $tmpl=str_replace(['{response}','{result}','{curl_response}'],[$rawHtml,$rawHtml,$rawHtml],$tmpl);
    // Replace any {varname} from browser vars
    foreach($allVars as $k=>$v)$tmpl=str_replace('{'.$k.'}',htmlspecialchars((string)$v,ENT_NOQUOTES,'UTF-8'),$tmpl);
    $tmpl=pvNoStamp($tmpl,$u,$s,$msgText,'',$db);

    tg('sendMessage',['chat_id'=>$chatId,'text'=>$tmpl,'parse_mode'=>'HTML'],$token);
    $st=$res['status']??'done';
    addLog($botId,"LinkAuto Browser ".strtoupper($st)." [{$ruleId}]: ".mb_substr($msgText,0,40)." by ".($u['name']??''),'success');
    // Clean up
    if(file_exists($sessFile))@unlink($sessFile);
    @unlink($resFile);
}

function execLinkAutomation($botId,$chatId,$u,&$db,$s,$msgText,$token){
    $laCfg=$s['link_automation']??['enabled'=>false,'rules'=>[]];
    if(empty($laCfg['enabled']))return false;
    $rules=$laCfg['rules']??[];
    $msgLower=strtolower(trim($msgText));
    foreach($rules as $rule){
        if(empty($rule['enabled']))continue;
        $trigger=strtolower(trim($rule['trigger']??''));
        if($trigger==='')continue;
        $tMode=$rule['trigger_mode']??'exact';
        $matched=false;
        if($tMode==='startswith') $matched=str_starts_with($msgLower,$trigger);
        elseif($tMode==='contains') $matched=(str_contains($msgLower,$trigger));
        else $matched=($trigger===$msgLower);
        if(!$matched)continue;
        if(!empty($rule['access_control'])&&!hasAccess($u['id']??'',$chatId,$rule['access_control'],$s['global_vars']??''))continue;
        // Browser mode: delegate to browser executor with captcha support
        if(!empty($rule['use_browser'])){
            execLinkAutomationBrowser($botId,$chatId,$u,$db,$s,$msgText,$rule,$token);
            return true;
        }
        $ruleUrl=trim($rule['url']??'');
        if(empty($ruleUrl))continue;
        // Replace {query}, {tg_name}, {tg_id}, {tg_username} in URL and body
        $varMap=buildVarMap($u,$s,$msgText);
        foreach($varMap as $vk=>$vv)$ruleUrl=str_replace('{'.$vk.'}',$vv,$ruleUrl);
        $ruleHeaders=$rule['headers']??'';
        foreach($varMap as $vk=>$vv)$ruleHeaders=str_replace('{'.$vk.'}',$vv,$ruleHeaders);
        $ruleBody=$rule['body']??'';
        foreach($varMap as $vk=>$vv)$ruleBody=str_replace('{'.$vk.'}',$vv,$ruleBody);
        $timeout=max(5,min(120,(int)($rule['timeout']??30)));
        $result=doCurl($ruleUrl,$rule['method']??'GET',$ruleHeaders,$ruleBody,$timeout);
        $rawBody=$result['body']??'';
        $respData=json_decode($rawBody,true);
        $extracted=null;
        $respPath=trim($rule['response_path']??'');
        if($respPath!==''&&$respData!==null){$extracted=jsonPath($respData,$respPath);}
        if($extracted===null&&$respData!==null){
            foreach(['result','response','text','content','answer','message','output','data'] as $fk){
                if(isset($respData[$fk])&&is_string($respData[$fk])&&trim($respData[$fk])!==''){$extracted=$respData[$fk];break;}
            }
        }
        if($extracted===null)$extracted=$rawBody;
        $failed=($result['code']>=400||($extracted===null||$extracted===''));
        if($failed){
            $errMsg=pv($rule['error_message']??'⚠️ Error fetching link response.',$u,$s,$msgText,'');
            tg('sendMessage',['chat_id'=>$chatId,'text'=>$errMsg,'parse_mode'=>'HTML'],$token);
            addLog($botId,"LinkAuto Fail [{$rule['id']}] HTTP {$result['code']}",'error');
        }else{
            $rawHtml=htmlspecialchars((string)$extracted,ENT_NOQUOTES,'UTF-8');
            $tmpl=$rule['reply_template']??'{response}';
            $tmpl=str_replace(['{response}','{result}','{curl_response}'],[$rawHtml,$rawHtml,$rawHtml],$tmpl);
            if($respPath!==''){ $tmpl=str_replace('{'.$respPath.'}',$rawHtml,$tmpl); }
            if(is_array($respData)){
                $jmap=flattenJson($respData);
                uksort($jmap,function($a,$b){return strlen($b)-strlen($a);});
                foreach($jmap as $jk=>$jv)$tmpl=str_replace('{'.$jk.'}',htmlspecialchars((string)$jv,ENT_NOQUOTES,'UTF-8'),$tmpl);
            }
            $tmpl=pvNoStamp($tmpl,$u,$s,$msgText,'',$db);
            tg('sendMessage',['chat_id'=>$chatId,'text'=>$tmpl,'parse_mode'=>'HTML'],$token);
            addLog($botId,"LinkAuto OK [{$rule['id']}]: ".mb_substr($msgText,0,40).' by '.($u['name']??''),'success');
        }
        return true;
    }
    return false;
}

if(isset($_GET['webhook_bot'])){
    $botId=preg_replace('/[^a-zA-Z0-9_]/','_',$_GET['webhook_bot']);
    $bots=loadBots();$token='';$curBot=null;
    foreach($bots as $b){if($b['id']===$botId){$curBot=$b;$token=$b['token'];break;}}
    if(!$token||!$curBot){http_response_code(200);exit;}
    // Verify Telegram webhook secret token if configured
    $wSecret=$curBot['webhook_secret']??'';
    if($wSecret!==''){
        $sentSecret=$_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN']??'';
        if(!hash_equals($wSecret,$sentSecret)){http_response_code(403);exit;}
    }
    $update=json_decode(file_get_contents('php://input'),true);
    if(!is_array($update)){http_response_code(200);exit;}
    $db=loadDB($botId);$s=$db['settings'];
    $botMaint=$curBot['maintenance']??false;$botFree=(int)($curBot['free_searches']??3);$botUsername=$curBot['username']??'';
    $fj=$s['force_join']??['enabled'=>false,'channels'=>[],'message'=>'','media'=>'','buttons'=>[]];

    if(isset($update['message']['new_chat_members'])||isset($update['message']['left_chat_member'])){
        $wm=$db['settings']['welcome_message']??['enabled'=>false];
        $wchatId=(string)($update['message']['chat']['id']??'');
        $wmEnabled=(isset($wm['enabled'])&&($wm['enabled']===true||$wm['enabled']===1));

        addLog($botId,'[WM] new_chat_members event received. enabled='.($wmEnabled?'true':'false').' chat='.$wchatId,'info');
        if(isset($update['message']['new_chat_members'])){

            $botSelfId='';
            $botInfoResp=tg('getMe',[],$token);
            if(!empty($botInfoResp['result']['id']))$botSelfId=(string)$botInfoResp['result']['id'];
            foreach($update['message']['new_chat_members'] as $nm2){
                if(!empty($nm2['is_bot']))continue;
                $nmUid=(string)($nm2['id']??'');
                if(!$nmUid)continue;
                if($botSelfId&&$nmUid===$botSelfId)continue; // skip self
                $nmName=trim(($nm2['first_name']??'').' '.($nm2['last_name']??''));
                if(!$nmName)$nmName='Member';
                $nmUser=$nm2['username']??'';

                if(!isset($db['group_members'][$wchatId]))$db['group_members'][$wchatId]=[];
                $db['group_members'][$wchatId][$nmUid]=['id'=>$nmUid,'name'=>$nmName,'username'=>$nmUser,'joined'=>date('Y-m-d H:i:s')];
                if(!isset($db['users'][$nmUid])){
                    $db['users'][$nmUid]=['id'=>$nmUid,'name'=>$nmName,'username'=>$nmUser,'searches'=>0,
                        'searchesLeft'=>$botFree,'joined'=>date('Y-m-d H:i:s'),'banned'=>false,'key'=>'','active_page'=>''];
                }
                saveDB($botId,$db);
                if($wmEnabled){

                    $mention=$nmUser
                        ? '@'.htmlspecialchars($nmUser,ENT_NOQUOTES,'UTF-8')
                        : '<a href="tg://user?id='.$nmUid.'">'.htmlspecialchars($nmName,ENT_NOQUOTES,'UTF-8').'</a>';

                    $wmText=$wm['text']??'👋 Welcome {tg_mention}!';
                    $wmText=str_replace(
                        ['{tg_name}','{tg_username}','{tg_id}','{tg_mention}'],
                        [htmlspecialchars($nmName,ENT_NOQUOTES,'UTF-8'),
                         htmlspecialchars($nmUser,ENT_NOQUOTES,'UTF-8'),
                         $nmUid,
                         $mention],
                        $wmText
                    );

                    $wmKb=null;
                    $wmRows=[];
                    foreach($wm['buttons']??[] as $wb){
                        if(!empty(trim($wb['text']??''))&&!empty(trim($wb['url']??'')))
                            $wmRows[]=[['text'=>trim($wb['text']),'url'=>trim($wb['url'])]];
                    }
                    // Contact in DM button — bot ka t.me link
                    $wmDmUrl='https://t.me/'.($botUsername?:($db['username']??'bot'));
                    $wmRows[]=[['text'=>'💬 Contact Me in DM','url'=>$wmDmUrl]];
                    if($wmRows)$wmKb=json_encode(['inline_keyboard'=>$wmRows]);

                    $wmMedia=trim($wm['media']??'');
                    $sendOk=false;
                    if($wmMedia){
                        $ext=strtolower(pathinfo(parse_url($wmMedia,PHP_URL_PATH),PATHINFO_EXTENSION));
                        $p2=['chat_id'=>$wchatId,'caption'=>$wmText,'parse_mode'=>'HTML'];
                        if($wmKb)$p2['reply_markup']=$wmKb;
                        if(in_array($ext,['mp4','mov'])){$p2['video']=$wmMedia;$r2=tg('sendVideo',$p2,$token);}
                        elseif($ext==='gif'){$p2['animation']=$wmMedia;$r2=tg('sendAnimation',$p2,$token);}
                        elseif(in_array($ext,['jpg','jpeg','png','webp'])){$p2['photo']=$wmMedia;$r2=tg('sendPhoto',$p2,$token);}
                        else{$tp=['chat_id'=>$wchatId,'text'=>$wmText,'parse_mode'=>'HTML'];if($wmKb)$tp['reply_markup']=$wmKb;$r2=tg('sendMessage',$tp,$token);}
                        $sendOk=$r2['ok']??false;
                    } else {
                        $tp=['chat_id'=>$wchatId,'text'=>$wmText,'parse_mode'=>'HTML'];
                        if($wmKb)$tp['reply_markup']=$wmKb;
                        $r2=tg('sendMessage',$tp,$token);
                        $sendOk=$r2['ok']??false;
                    }
                    if($sendOk){
                        addLog($botId,"[WM] ✅ Welcome sent to: $nmName ($nmUid)",'success');
                    } else {
                        $errDesc=$r2['description']??'unknown error';
                        addLog($botId,"[WM] ❌ Failed to send welcome to $nmName: $errDesc",'error');
                    }
                }
            }
        }
        if(isset($update['message']['left_chat_member'])){
            $leftUid=(string)($update['message']['left_chat_member']['id']??'');
            if($leftUid&&isset($db['group_members'][$wchatId][$leftUid])){
                unset($db['group_members'][$wchatId][$leftUid]);
                saveDB($botId,$db);
            }
        }
        http_response_code(200);exit;
    }

    if(isset($update['callback_query'])){
        $cb=$update['callback_query'];$cbd=$cb['data'];
        $chatId=$cb['message']['chat']['id'];$msgId=$cb['message']['message_id'];
        $uid=(string)$cb['from']['id'];

        if(!isset($db['users'][$uid])){
            $db['users'][$uid]=['id'=>$uid,'name'=>$cb['from']['first_name']??'User',
                'username'=>$cb['from']['username']??'','searches'=>0,
                'searchesLeft'=>$botFree,'joined'=>date('Y-m-d H:i:s'),
                'banned'=>false,'key'=>'','active_page'=>''];
            saveDB($botId,$db);
        }
        $u=&$db['users'][$uid];
        $u['name']=$cb['from']['first_name']??$u['name']??'User';
        if(!isset($u['active_page']))$u['active_page']='';

        if(str_starts_with($cbd,'__owner_edit__|')){
            $ownerId=$s['adminId']??'';
            tg('answerCallbackQuery',['callback_query_id'=>$cb['id'],'text'=>'Opening editor...'],$token);
            if((string)$uid===(string)$ownerId){
                $pgId=explode('|',$cbd)[1]??'';
                $panelUrl='https://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?admin=1#page_'.$pgId;
                tg('sendMessage',[
                    'chat_id'=>$chatId,
                    'text'=>"✏️ <b>Page Editor</b>\n\n🆔 Page ID: <code>$pgId</code>\n\n👇 Press the button below to edit this page in the Panel:",
                    'parse_mode'=>'HTML',
                    'reply_markup'=>json_encode(['inline_keyboard'=>[[
                        ['text'=>'🖊️ Open in Panel','url'=>$panelUrl]
                    ]]])
                ],$token);
            }
            http_response_code(200);exit;
        }
        if(str_starts_with($cbd,'lp|')){
            $lpn=(int)explode('|',$cbd)[1];tg('answerCallbackQuery',['callback_query_id'=>$cb['id']],$token);
            $cached=getCache($botId,'lmsg_'.$uid);if($cached)sendLong($botId,$chatId,$msgId,$cached,'',null,true,$token,$lpn);
        }elseif(str_starts_with($cbd,'go|')){
            $pts=explode('|',$cbd);$gTarget=$pts[1];$gEdit=(int)$pts[2];$gDelay=(float)($pts[3]??0);
            if($gDelay>0)usleep((int)($gDelay*1000000));
            $gPage=null;foreach(($db['pages']??[]) as $pg){if($pg['id']==$gTarget){$gPage=$pg;break;}}
            tg('answerCallbackQuery',['callback_query_id'=>$cb['id']],$token);
            if($gPage){
                if(!empty($gPage['force_join'])&&!empty($fj['enabled'])){
                    if(!checkForceJoin($uid,$fj,$token)){sendForceJoinMsg($chatId,$fj,$token);http_response_code(200);exit;}
                }
                if(!hasAccess($uid,$chatId,$gPage['access_control']??'',$s['global_vars']??'')){
                    if(!empty($gPage['fallback_page'])){$fb=null;foreach(($db['pages']??[]) as $pg2){if($pg2['id']==$gPage['fallback_page']){$fb=$pg2;break;}}if($fb)$gPage=$fb;else{http_response_code(200);exit;}}
                    else{http_response_code(200);exit;}
                }
                if(!empty($gPage['is_free_text'])){

                    $u['active_page']=$gPage['id'];
                    saveDB($botId,$db);

                    if($gPage['type']==='text'){
                        $rt=pvNoStamp($gPage['text']??'',$u,$s,'',$gPage['custom_vars']??'',$db);
                        $rt=preg_replace('/\{query\}/i','',$rt);
                        $rt=trim($rt)?:' ';
                        $kb=buildKb($gPage['buttons']??[],$u,$s,'',$gPage['custom_vars']??'');
                        $kb=injectOwnerEditBtn($kb,$gPage['id']??'',$uid,$s['adminId']??'');
                        sendLong($botId,$chatId,null,$rt,$gPage['media_main']??'',$kb,false,$token);
                    }else{

                        $introText='';
                        if(!empty(trim($gPage['msg_missing']??''))){
                            $introText=pvNoStamp($gPage['msg_missing'],$u,$s,'',$gPage['custom_vars']??'',$db);
                        }elseif(!empty(trim($gPage['text']??''))){
                            $introText=pvNoStamp($gPage['text'],$u,$s,'',$gPage['custom_vars']??'',$db);
                            $introText=preg_replace('/\{query\}/i','',$introText);
                            $introText=trim($introText);
                        }
                        $kb=buildKb($gPage['buttons']??[],$u,$s,'',$gPage['custom_vars']??'');
                        $kb=injectOwnerEditBtn($kb,$gPage['id']??'',$uid,$s['adminId']??'');
                        $introMedia=$gPage['media_main']??'';
                        if($introText||$introMedia){
                            sendLong($botId,$chatId,null,$introText?:' ',$introMedia,$kb,false,$token);
                        }else{
                            tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Ready! Send your message.','parse_mode'=>'HTML'],$token);
                        }
                    }
                }else{

                    if(!empty($u['active_page'])){$u['active_page']='';saveDB($botId,$db);}
                    if($gPage['type']==='text'){
                        $rt=pv($gPage['text']??'',$u,$s,'',$gPage['custom_vars']??'',null,null,$db);
                        $kb=buildKb($gPage['buttons']??[],$u,$s,'',$gPage['custom_vars']??'');
                        $kb=injectOwnerEditBtn($kb,$gPage['id']??'',$uid,$s['adminId']??'');
                        sendLong($botId,$chatId,$msgId,$rt,$gPage['media_main']??'',$kb,$gEdit,$token);
                    }else{execPage($botId,$chatId,$msgId,$u,$db,$s,'',$gPage,$token);}
                }
            }
        }elseif(str_starts_with($cbd,'pg|')){
            $pts=explode('|',$cbd);$sid=$pts[1];$pn=(int)$pts[2];$cid=$pts[3];
            $cached=getCache($botId,$sid);
            if(!$cached){tg('answerCallbackQuery',['callback_query_id'=>$cb['id'],'text'=>'❌ Session expired.','show_alert'=>true],$token);}
            else{
                $cc=null;foreach(($db['pages']??[]) as $pg){if($pg['id']==$cid){$cc=$pg;break;}}
                if($cc){
                    $apiData=$cached['root']??[];$tdata=$cached['records']??[];$q=$cached['query']??'';
                    $total=count($tdata);$record=$tdata[$pn]??[];
                    $txt=$cc['text']??'';$txt=str_replace(['{page_current}','{page_total}'],[$pn+1,$total],$txt);
                    $txt=pv($txt,$u,$s,$q,$cc['custom_vars']??'',$record,$apiData,$db);
                    $txt=preg_replace('/\{[a-zA-Z0-9_ \.]+\}/','N/A',$txt);
                    $navRow=[];$otherRows=[];
                    foreach($cc['buttons']??[] as $cbtn){
                        if(!empty($cbtn['cond'])&&!checkCond($cbtn['cond'],$u,$s,$q,$cc['custom_vars']??'',$record,$apiData))continue;
                        $bt=pv($cbtn['text']??'',$u,$s,$q,$cc['custom_vars']??'',$record,$apiData);
                        if(!empty($cbtn['url'])){$otherRows[]=[['text'=>$bt,'url'=>$cbtn['url']]];}
                        elseif($cbtn['target']==='_NEXT_'){if($pn<$total-1)$navRow[]=['text'=>$bt,'callback_data'=>"pg|{$sid}|".($pn+1)."|{$cid}"];}
                        elseif($cbtn['target']==='_PREV_'){if($pn>0)$navRow[]=['text'=>$bt,'callback_data'=>"pg|{$sid}|".($pn-1)."|{$cid}"];}
                        else{$otherRows[]=[['text'=>$bt,'callback_data'=>'go|'.$cbtn['target'].'|'.($cbtn['edit']?'1':'0').'|'.($cbtn['delay']??'0')]];}
                    }
                    $fk=[];if($navRow)$fk[]=$navRow;foreach($otherRows as $rr)$fk[]=$rr;
                    $kb=$fk?json_encode(['inline_keyboard'=>$fk]):null;
                    setCache($botId,'lmsg_'.$uid,$txt);sendLong($botId,$chatId,$msgId,$txt,$cc['media_main']??'',$kb,true,$token);
                    tg('answerCallbackQuery',['callback_query_id'=>$cb['id']],$token);
                }
            }
        }elseif(str_starts_with($cbd,'rose_help|')){
            tg('answerCallbackQuery',['callback_query_id'=>$cb['id']],$token);
            $rhCat=explode('|',$cbd)[1]??'menu';
            $backBtn=[['text'=>'⬅️ Back to Menu','callback_data'=>'rose_help|menu']];
            $roseHelpTexts=[
                'admin'=>"👑 <b>Admin Commands</b>\n\n/promote [user] — Promote user to admin\n/demote [user] — Remove from admin\n/adminlist — List all admins\n/admins — Same as adminlist\n/info [user] — View user info\n/id — View chat and user ID",
                'antiflood'=>"🌊 <b>Antiflood Commands</b>\n\n/setflood [num] — Set flood limit\n/setfloodmode [ban/kick/mute] — Set action\n/flood — View current flood settings\n/setfloodtime [secs] — Set window time",
                'antiraid'=>"🛡 <b>AntiRaid Commands</b>\n\n/raid — Enable/disable AntiRaid\n/raidtime [secs] — Set raid detection window\n/raidaction [ban/kick/mute] — Set action",
                'approval'=>"✅ <b>Approval Commands</b>\n\n/approve [user] — Approve a user\n/unapprove [user] — Remove approval\n/approved — List approved users\n/unapproveall — Unapprove all",
                'bans'=>"🚫 <b>Bans Commands</b>\n\n/ban [user] [reason] — Ban a user\n/sban [user] — Silent ban\n/tban [user] [time] — Temp ban (e.g. 10m, 2h)\n/unban [user] — Unban a user\n/kick [user] — Kick a user\n/skick [user] — Silent kick\n/kickme — Kick yourself",
                'blocklist'=>"📋 <b>Blocklist Commands</b>\n\n/addblacklist [word] — Add word to blacklist\n/blacklist — View current blacklist\n/rmblacklist [word] — Remove word\n/unblacklist [word] — Same as rmblacklist\n/blacklistmode [del/warn/ban] — Set action",
                'captcha'=>"🤖 <b>CAPTCHA Commands</b>\n\n/captcha on — Enable CAPTCHA\n/captcha off — Disable CAPTCHA\n\n<i>New members must verify after joining.</i>",
                'connections'=>"🔗 <b>Connections Commands</b>\n\n/connect [chat_id] — Connect to a group\n/disconnect — Disconnect\n/allowconnect on/off — Allow users to connect",
                'filters'=>"🔍 <b>Filters Commands</b>\n\n/filter [keyword] [reply] — Set a filter\n/filters — View all filters\n/stop [keyword] — Remove a filter\n/stopall — Remove all filters",
                'languages'=>"🌐 <b>Languages Commands</b>\n\n/setlang [lang_code] — Set bot language\n\n<i>Available: en, hi, etc.</i>",
                'locks'=>"🔒 <b>Locks Commands</b>\n\n/lock [type] — Lock something\n/unlock [type] — Unlock something\n/locks — View current locks\n\n<b>Types:</b> url, photo, video, sticker, gif, voice, audio, document, forward, game, location, contact, poll",
                'logchannels'=>"📢 <b>Log Channels Commands</b>\n\n/logchannel [channel_id] — Set log channel\n/logchannel — View current log channel\n\n<i>Bot will log all actions in that channel.</i>",
                'notes'=>"📝 <b>Notes Commands</b>\n\n/save [name] [text] — Save a note\n/get [name] — View a note\n#[name] — View note via shortcut\n/notes — List all notes\n/clear [name] — Delete a note\n/clearall — Delete all notes",
                'pin'=>"📌 <b>Pin Commands</b>\n\n/pin — Reply to a message to pin it\n/unpin — Unpin\n/unpinall — Remove all pins\n/pinned — View pinned message",
                'purges'=>"🗑 <b>Purges Commands</b>\n\n/purge — Delete all messages above this one\n/purge [num] — Delete last N messages\n/del — Reply to a message to delete it",
                'reports'=>"📊 <b>Reports Commands</b>\n\n/report — Reply to a message to report it\n@admin — Tag admins\n/reports on/off — Enable/disable reports (admin only)",
                'rules'=>"📜 <b>Rules Commands</b>\n\n/setrules [text] — Set rules\n/rules — View rules\n/clearrules — Clear rules",
                'topics'=>"💬 <b>Topics Commands</b>\n\n/topic [name] — Create a topic\n/closetopic — Close topic\n/opentopic — Open topic\n/deletetopic — Delete topic",
                'warns'=>"⚠️ <b>Warnings Commands</b>\n\n/warn [user] [reason] — Warn a user\n/dwarn [user] — Warn + delete message\n/warns [user] — Check warns\n/resetwarns [user] — Reset warns\n/setwarnlimit [num] — Set warn limit\n/setwarnmode [ban/kick/mute] — Set warn action",
                'welcome'=>"👋 <b>Welcome Commands</b>\n\n/setwelcome [text] — Set welcome message\n/welcome on/off — Toggle welcome on/off\n/resetwelcome — Reset welcome\n/goodbye on/off — Goodbye message\n/setgoodbye [text] — Set goodbye text\n/cleanservice on/off — Delete join/leave messages\n/welcomemute on/off — Mute new users",
                'users'=>"👤 <b>Users Commands</b>\n\n/info [user] — View user info\n/id — View ID\n/kickme — Kick yourself\n/mute [user] [time] — Mute a user\n/unmute [user] — Unmute a user\n/tmute [user] [time] — Temp mute",
            ];
            $roseHelpMainKb=json_encode(['inline_keyboard'=>[
                [['text'=>'👑 Admin','callback_data'=>'rose_help|admin'],['text'=>'🌊 Antiflood','callback_data'=>'rose_help|antiflood'],['text'=>'🛡 AntiRaid','callback_data'=>'rose_help|antiraid']],
                [['text'=>'✅ Approval','callback_data'=>'rose_help|approval'],['text'=>'🚫 Bans','callback_data'=>'rose_help|bans'],['text'=>'📋 Blocklist','callback_data'=>'rose_help|blocklist']],
                [['text'=>'🤖 CAPTCHA','callback_data'=>'rose_help|captcha'],['text'=>'🔗 Connections','callback_data'=>'rose_help|connections'],['text'=>'🔍 Filters','callback_data'=>'rose_help|filters']],
                [['text'=>'🌐 Languages','callback_data'=>'rose_help|languages'],['text'=>'🔒 Locks','callback_data'=>'rose_help|locks'],['text'=>'📢 Log Channels','callback_data'=>'rose_help|logchannels']],
                [['text'=>'📝 Notes','callback_data'=>'rose_help|notes'],['text'=>'📌 Pin','callback_data'=>'rose_help|pin'],['text'=>'🗑 Purges','callback_data'=>'rose_help|purges']],
                [['text'=>'📊 Reports','callback_data'=>'rose_help|reports'],['text'=>'📜 Rules','callback_data'=>'rose_help|rules'],['text'=>'💬 Topics','callback_data'=>'rose_help|topics']],
                [['text'=>'⚠️ Warnings','callback_data'=>'rose_help|warns'],['text'=>'👋 Welcome','callback_data'=>'rose_help|welcome'],['text'=>'👤 Users','callback_data'=>'rose_help|users']],
            ]]);
            if($rhCat==='menu'){
                tg('editMessageText',['chat_id'=>$chatId,'message_id'=>$msgId,'text'=>"👋 <b>Hi! I'm a group management bot.</b>\nAll commands are in the buttons below — tap a category!\n\n<i>All commands can be used with: / !</i>",'parse_mode'=>'HTML','reply_markup'=>$roseHelpMainKb],$token);
            }else{
                $catText=$roseHelpTexts[$rhCat]??("ℹ️ <b>".ucfirst($rhCat)."</b>\n\nYeh category ka help abhi available nahi hai.");
                $catKb=json_encode(['inline_keyboard'=>[$backBtn]]);
                tg('editMessageText',['chat_id'=>$chatId,'message_id'=>$msgId,'text'=>$catText,'parse_mode'=>'HTML','reply_markup'=>$catKb],$token);
            }
        }
        http_response_code(200);exit;
    }

    if(isset($update['message'])){
        $msg=$update['message'];$chatId=(string)($msg['chat']['id']??'');
        $msgText=trim($msg['text']??'');$uid=(string)($msg['from']['id']??'');
        $name=$msg['from']['first_name']??'User';$uname=$msg['from']['username']??'';
        $isGroup=in_array($msg['chat']['type']??'',['group','supergroup','channel']);
        if(!$uid||!$chatId){http_response_code(200);exit;}

        $ownerId=$db['settings']['adminId']??'';
        if($uid===$ownerId&&(isset($msg['forward_origin'])||isset($msg['forward_from'])||isset($msg['forward_from_chat']))){
            $fwdFromChatId='';$fwdMsgId='';

            if(isset($msg['forward_from_chat'])){
                $fwdFromChatId=(string)($msg['forward_from_chat']['id']??'');
                $fwdMsgId=(string)($msg['forward_from_message_id']??'');
            }

            if((!$fwdFromChatId||!$fwdMsgId)&&isset($msg['forward_origin'])){
                $fo=$msg['forward_origin'];
                if(($fo['type']??'')==='channel'){
                    $fwdFromChatId=(string)($fo['chat']['id']??'');
                    $fwdMsgId=(string)($fo['message_id']??'');
                }
            }

            if(!$fwdFromChatId||!$fwdMsgId){
                $fwdFromChatId=$chatId;
                $fwdMsgId=(string)($msg['message_id']??'');
            }

            $fwdType='message';
            if(isset($msg['sticker']))$fwdType='sticker';
            elseif(isset($msg['photo']))$fwdType='photo';
            elseif(isset($msg['video']))$fwdType='video';
            elseif(isset($msg['animation']))$fwdType='animation';
            elseif(isset($msg['voice']))$fwdType='voice';
            elseif(isset($msg['audio']))$fwdType='audio';
            elseif(isset($msg['document']))$fwdType='document';
            $autoLabel=ucfirst($fwdType).' Forward #'.(count(loadForwards($botId))+1);
            $wasSaved=addForwardToLib($botId,$fwdFromChatId,$fwdMsgId,$autoLabel,$fwdType);
            $fwdReply=$wasSaved
                ?"✅ <b>Forward saved!</b>\n📌 Type: <code>$fwdType</code>\n🆔 from_chat_id: <code>$fwdFromChatId</code>\n📨 message_id: <code>$fwdMsgId</code>\n\n<i>Panel → 📨 Forward Library se use karo</i>"
                :"ℹ️ Already in Forward Library.";
            tg('sendMessage',['chat_id'=>$chatId,'text'=>$fwdReply,'parse_mode'=>'HTML'],$token);
            http_response_code(200);exit;
        }

        if(isset($msg['sticker'])&&!$msgText){
            if(!$isGroup){ // works only in private/DM
                $stk=$msg['sticker'];$fileId=$stk['file_id']??'';
                $isPrem=!empty($stk['premium_animation']);
                $isAnim=!empty($stk['is_animated'])||!empty($stk['is_video']);
                $emoji=$stk['emoji']??'🌟';
                $ownerId=$db['settings']['adminId']??'';
                if($uid===$ownerId&&$fileId){
                    $saved=addStickerToLib($botId,$fileId,$isAnim,$isPrem,$emoji.' Sticker');
                    $type=$isPrem?'⭐ Premium':($isAnim?'🎬 Animated':'📌 Static');
                    $reply=$saved?"✅ <b>Sticker saved!</b>\n$type\n<code>$fileId</code>":"ℹ️ Already in library.";
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>$reply,'parse_mode'=>'HTML'],$token);
                }
            }
            http_response_code(200);exit;
        }

        $ownerId2=$db['settings']['adminId']??'';
        if($uid===$ownerId2&&!$isGroup){ // works only in private/DM
            $allEnts=array_merge($msg['entities']??[],$msg['caption_entities']??[]);
            $cemojis=array_filter($allEnts,fn($e)=>($e['type']??'')==='custom_emoji'&&!empty($e['custom_emoji_id']));
            if(!empty($cemojis)){
                $savedCount=0;$newIds=[];
                foreach($cemojis as $ent){
                    $eid=$ent['custom_emoji_id'];
                    $offset=$ent['offset']??0;$len=$ent['length']??1;
                    $src=$msg['text']??$msg['caption']??'';
                    $fb=$src!==''?mb_substr($src,$offset,$len):'⭐';
                    $autoLabel=$fb.' Emoji';
                    if(addPremEmojiToLib($botId,$eid,$fb,$autoLabel)){$savedCount++;$newIds[]=$eid;}
                }
                if($savedCount>0){
                    syncEmojiDynVars($botId,$db);
                    saveDB($botId,$db);
                    $lib=loadPremEmojis($botId);
                    $replyLines=["✅ <b>$savedCount Premium Emoji".($savedCount>1?'s':'')." captured!</b>\n"];
                    foreach($lib as $e){
                        if(in_array($e['emoji_id'],$newIds)){
                            $dkey='emoji_'.preg_replace('/[^a-zA-Z0-9_]/','_',strtolower($e['label']));
                            $replyLines[]="• <b>".htmlspecialchars($e['label'],ENT_NOQUOTES,'UTF-8')."</b>\n  🆔 <code>".htmlspecialchars($e['emoji_id'],ENT_NOQUOTES,'UTF-8')."</code>\n  📝 Use: <code>{".$dkey."}</code>";
                        }
                    }
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",$replyLines),'parse_mode'=>'HTML'],$token);
                    http_response_code(200);exit;
                }
            }
        }

        $adminSetupStep=$db['dyn_vars']['__admin_setup_step__']??'';
        $adminSetupOwner=$s['adminId']??'';
        if($uid===$adminSetupOwner&&$adminSetupStep!==''){

            if($adminSetupStep==='waiting_video'&&isset($msg['video'])&&!$msgText){
                $videoFileId=$msg['video']['file_id']??'';
                if($videoFileId){
                    $db['dyn_vars']['__welcome_video_file_id__']=$videoFileId;
                    $db['dyn_vars']['__admin_setup_step__']='waiting_apk';
                    saveDB($botId,$db);
                    tg('sendMessage',[
                        'chat_id'=>$chatId,
                        'text'=>"✅ <b>Video saved!</b>\n\n📱 <b>Step 2:</b> Now send me the <b>APK file</b> that new users will receive.\n\n<i>Sirf .apk file bhejo.</i>",
                        'parse_mode'=>'HTML'
                    ],$token);
                }else{
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Video not received. Please send again.','parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($adminSetupStep==='waiting_apk'&&isset($msg['document'])&&!$msgText){
                $doc=$msg['document'];
                $apkFileId=$doc['file_id']??'';
                $apkFileName=$doc['file_name']??'app.apk';
                $apkExt=strtolower(pathinfo($apkFileName,PATHINFO_EXTENSION));
                if($apkFileId&&$apkExt==='apk'){
                    $db['dyn_vars']['__welcome_apk_file_id__']=$apkFileId;
                    $db['dyn_vars']['__welcome_apk_name__']=$apkFileName;
                    $db['dyn_vars']['__admin_setup_step__']=''; // session khatam
                    saveDB($botId,$db);
                    tg('sendMessage',[
                        'chat_id'=>$chatId,
                        'text'=>"✅ <b>APK also saved!</b>\n\n🎉 <b>Setup Complete!</b>\nWhenever a user runs /start, they will receive:\n• 🎬 Video\n• 📱 APK\n\n<i>To change again, use the /admin command.</i>",
                        'parse_mode'=>'HTML'
                    ],$token);
                }else{
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ APK file not received or wrong format. Please send only .apk files.','parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($adminSetupStep==='waiting_video'&&!$msgText){
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'⚠️ Please send the <b>video</b> first (Step 1).','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }
            if($adminSetupStep==='waiting_apk'&&!$msgText){
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'⚠️ Now send the <b>APK file</b> (Step 2).','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }
        }

        if(!$msgText && isset($msg['document'])){
            $apkCfg = $db['settings']['apk_renamer'] ?? ['enabled'=>false];
            $doc    = $msg['document'];
            $origName = $doc['file_name'] ?? 'file.apk';
            $ext    = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
            if(!empty($apkCfg['enabled']) && $ext === 'apk'){
                if(!empty($apkCfg['admin_only']) && $uid !== ($db['settings']['adminId']??'')){
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'⛔ Only the admin can send APK files.','parse_mode'=>'HTML'],$token);
                    http_response_code(200);exit;
                }
                $fileId = $doc['file_id'] ?? '';
                if(!$fileId){ http_response_code(200);exit; }
                $fpRes    = tg('getFile',['file_id'=>$fileId],$token);
                $filePath = $fpRes['result']['file_path'] ?? '';
                if(!$filePath){
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ File not found.','parse_mode'=>'HTML'],$token);
                    http_response_code(200);exit;
                }
                $dlUrl = 'https://api.telegram.org/file/bot'.$token.'/'.$filePath;
                $ch = curl_init($dlUrl);
                curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_SSL_VERIFYPEER=>true,CURLOPT_SSL_VERIFYHOST=>2,CURLOPT_TIMEOUT=>120,CURLOPT_FOLLOWLOCATION=>true]);
                $fileData = curl_exec($ch);
                curl_close($ch);
                if(!$fileData){
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Download failed.','parse_mode'=>'HTML'],$token);
                    http_response_code(200);exit;
                }
                $newBaseName = trim($apkCfg['new_name'] ?? 'RebelApp') ?: 'RebelApp';
                $newFileName = $newBaseName.'.apk';
                $tmpOut = sys_get_temp_dir().'/'.preg_replace('/[^a-zA-Z0-9._-]/','_',$newFileName);
                file_put_contents($tmpOut, $fileData);
                $pm   = tg('sendMessage',['chat_id'=>$chatId,'text'=>'⏳ <b>APK is being renamed...</b>','parse_mode'=>'HTML'],$token);
                $pmId = $pm['result']['message_id'] ?? null;
                $caption = $apkCfg['caption'] ?? '✅ APK is ready!';
                $caption = str_replace(
                    ['{original_name}','{new_name}','{tg_name}'],
                    [htmlspecialchars($origName,ENT_NOQUOTES,'UTF-8'),
                     htmlspecialchars($newFileName,ENT_NOQUOTES,'UTF-8'),
                     htmlspecialchars($name,ENT_NOQUOTES,'UTF-8')],
                    $caption
                );
                $ch2 = curl_init();
                curl_setopt_array($ch2,[
                    CURLOPT_URL            => TG_BASE.$token.'/sendDocument',
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_POST           => true,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_TIMEOUT        => 120,
                    CURLOPT_POSTFIELDS     => [
                        'chat_id'    => $chatId,
                        'caption'    => $caption,
                        'parse_mode' => 'HTML',
                        'document'   => new CURLFile($tmpOut,'application/vnd.android.package-archive',$newFileName),
                    ]
                ]);
                $sendRes = json_decode(curl_exec($ch2),true);
                curl_close($ch2);
                if($pmId) tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$pmId],$token);
                @unlink($tmpOut);
                if($sendRes['ok']??false)
                    addLog($botId,"APK Renamed: $origName → $newFileName by $name ($uid)",'success');
                else
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ APK send failed.','parse_mode'=>'HTML'],$token);
            }
            http_response_code(200);exit;
        }
        if(!$msgText){http_response_code(200);exit;}
        $isNew=!isset($db['users'][$uid]);
        if($isNew){
            $db['users'][$uid]=['id'=>$uid,'name'=>$name,'username'=>$uname,'searches'=>0,
                'searchesLeft'=>$botFree,'joined'=>date('Y-m-d H:i:s'),'banned'=>false,'key'=>'','active_page'=>''];
            addLog($botId,"New User: $name ($uid)",'success');
        }
        dynVarSet($db,'users_ids',$uid,'append_unique');
        if($isGroup){
            dynVarSet($db,'group_ids',$chatId,'append_unique');
            if(($msg['chat']['type']??'')==='channel')
                dynVarSet($db,'channel_ids',$chatId,'append_unique');

            if(!isset($db['group_members'][$chatId]))$db['group_members'][$chatId]=[];
            $db['group_members'][$chatId][$uid]=['id'=>$uid,'name'=>$name,'username'=>$uname,'last_seen'=>date('Y-m-d H:i:s')];
        }
        saveDB($botId,$db);
        $u=&$db['users'][$uid];$u['name']=$name;if($uname)$u['username']=$uname;
        if($u['banned']??false){http_response_code(200);exit;}
        if($botMaint&&$uid!==($s['adminId']??'')){http_response_code(200);exit;}

        $utSettings=$s['user_tagger']??['enabled'=>false,'trigger'=>'@all','message'=>'📢 Tagging everyone:','batch_size'=>5,'delay'=>1];
        if(!empty($utSettings['enabled'])&&$isGroup){
            $utTrigger=strtolower(trim($utSettings['trigger']??'@all'));
            $msgLower=strtolower($msgText);
            if(str_starts_with($msgLower,$utTrigger)||$msgLower===$utTrigger){
                $caMember=tg('getChatMember',['chat_id'=>$chatId,'user_id'=>$uid],$token);
                $caStatus=$caMember['result']['status']??'';
                $isAdminOrOwner=in_array($caStatus,['administrator','creator']);
                if($isAdminOrOwner){
                    $groupUsers=[];$seenUids=[];

                    foreach($db['group_members'][$chatId]??[] as $gmUid=>$gmUsr){
                        if(empty($gmUsr['id']))continue;
                        $groupUsers[$gmUid]=$gmUsr;$seenUids[$gmUid]=true;
                    }

                    $adminsResp=tg('getChatAdministrators',['chat_id'=>$chatId],$token);
                    foreach($adminsResp['result']??[] as $adm){
                        if(!empty($adm['user']['is_bot']))continue;
                        $admUid=(string)($adm['user']['id']??'');
                        if(!$admUid||isset($seenUids[$admUid]))continue;
                        $groupUsers[$admUid]=['id'=>$admUid,'name'=>$adm['user']['first_name']??'Admin','username'=>$adm['user']['username']??''];
                        $seenUids[$admUid]=true;
                    }
                    if(empty($groupUsers)){
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>"⚠️ <b>No members tracked yet!</b>\n\nBot records members as they send messages in this group. Once members interact, they will be tagged.\n\n💡 Admins are always taggable via Telegram API.",'parse_mode'=>'HTML'],$token);
                        http_response_code(200);exit;
                    }
                    $batchSize=max(1,min(10,(int)($utSettings['batch_size']??5)));
                    $delayMs=max(300000,(int)((float)($utSettings['delay']??1)*1000000));
                    $headerMsg=trim($utSettings['message']??'📢 Tagging everyone:');
                    $customMsg=trim(implode(' ',array_slice(explode(' ',$msgText),1)));
                    if($customMsg)$headerMsg.="\n\n".$customMsg;
                    $groupUsersArr=array_values($groupUsers);
                    $batches=array_chunk($groupUsersArr,$batchSize);
                    $batchNum=0;$totalTagged=count($groupUsersArr);

                    $headerHasTgEmoji=(strpos($headerMsg,'<tg-emoji')!==false);
                    if($headerHasTgEmoji){
                        $headerParsed=htmlToEntities($headerMsg);
                        $headerPlain=$headerParsed['text'];
                        $headerEntities=$headerParsed['entities'];
                    } else {
                        $headerPlain=$headerMsg;
                        $headerEntities=[];
                    }

                    $headerUtf16Len=(int)(mb_strlen(mb_convert_encoding($headerPlain,'UTF-16LE','UTF-8'),'8bit')/2);
                    $separatorUtf16Len=2; // "\n\n"
                    foreach($batches as $batch){
                        $mentions='';
                        $mentionEntities=[];
                        $mentionOffset=0;
                        foreach($batch as $usr){
                            $un=$usr['username']??'';$nm=$usr['name']??'User';$uid2=$usr['id'];
                            if($un){
                                $part='@'.$un.' ';
                                $mentions.=$part;
                                $mentionOffset+=(int)(mb_strlen(mb_convert_encoding($part,'UTF-16LE','UTF-8'),'8bit')/2);
                            } else {
                                $part=$nm.' ';
                                $mentions.=$part;
                                $utf16len=(int)(mb_strlen(mb_convert_encoding($nm,'UTF-16LE','UTF-8'),'8bit')/2);
                                $mentionEntities[]=['type'=>'text_link','offset'=>$mentionOffset,'length'=>$utf16len,'url'=>'tg://user?id='.$uid2];
                                $mentionOffset+=(int)(mb_strlen(mb_convert_encoding($part,'UTF-16LE','UTF-8'),'8bit')/2);
                            }
                        }

                        $fullText=$headerPlain."\n\n".trim($mentions);
                        $mentionsStartOffset=$headerUtf16Len+$separatorUtf16Len;
                        $shiftedMentions=array_map(function($e) use($mentionsStartOffset){
                            $e['offset']+=$mentionsStartOffset;return $e;
                        },$mentionEntities);
                        $allEntities=array_merge($headerEntities,$shiftedMentions);
                        $payload=['chat_id'=>$chatId,'text'=>$fullText,'disable_notification'=>true];
                        if(!empty($allEntities)) $payload['entities']=$allEntities;
                        else $payload['parse_mode']='HTML';
                        tg('sendMessage',$payload,$token);
                        $batchNum++;
                        if(count($batches)>1)usleep($delayMs);
                    }
                    addLog($botId,"@all by $name in $chatId — tagged $totalTagged users",'info');
                }else{
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'🚫 Only group admins/owners can use the tag-all command.','parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }
        }

        $rose=$db['settings']['rose']??[];
        $roseEnabled=!empty($rose['enabled']);
        $isGroupChat=in_array($msg['chat']['type']??'',['group','supergroup']);

        $roseIsAdmin=function($checkUid) use($chatId,$token){
            $r=tg('getChatMember',['chat_id'=>$chatId,'user_id'=>$checkUid],$token);
            return in_array($r['result']['status']??'',['administrator','creator']);
        };
        $roseLog=function($txt) use($rose,$token){
            $lch=trim($rose['log_channel']??'');
            if($lch) tg('sendMessage',['chat_id'=>$lch,'text'=>$txt,'parse_mode'=>'HTML'],$token);
        };
        $roseMention=function($mUid,$mName){
            return '<a href="tg://user?id='.$mUid.'">'.htmlspecialchars(trim($mName),ENT_NOQUOTES,'UTF-8').'</a>';
        };

        $roseParseTime=function($str) {
            if(!$str)return 0;
            if(preg_match('/^(\d+)(s|m|h|d|w)$/i',$str,$m)){
                $v=(int)$m[1];$u=strtolower($m[2]);
                return $u==='s'?$v:($u==='m'?$v*60:($u==='h'?$v*3600:($u==='d'?$v*86400:$v*604800)));
            }
            return 0;
        };

        $roseTarget=function($rargs=[]) use($msg,$chatId,$token){
            if(!empty($msg['reply_to_message']['from']['id'])&&empty($msg['reply_to_message']['from']['is_bot'])){
                $ru=$msg['reply_to_message']['from'];
                return ['id'=>(string)$ru['id'],'name'=>trim(($ru['first_name']??'').' '.($ru['last_name']??'')),'user'=>$ru];
            }
            $arg=$rargs[0]??'';
            if($arg){
                $lookup=ltrim($arg,'@');
                $r=tg('getChatMember',['chat_id'=>$chatId,'user_id'=>is_numeric($lookup)?$lookup:'@'.$lookup],$token);
                if(!empty($r['result']['user']['id'])){
                    $ru=$r['result']['user'];
                    return ['id'=>(string)$ru['id'],'name'=>trim(($ru['first_name']??'').' '.($ru['last_name']??'')),'user'=>$ru];
                }
            }
            return null;
        };

        // Helper: send a rose bot message supporting tg-emoji entities
        $roseSend=function($text,$extraParams=[]) use($chatId,$token){
            $hasTgEmoji=(strpos((string)$text,'<tg-emoji')!==false);
            if($hasTgEmoji){
                $parsed=htmlToEntities((string)$text);
                $p=array_merge(['chat_id'=>$chatId,'text'=>$parsed['text'],'entities'=>$parsed['entities']],$extraParams);
                unset($p['parse_mode']);
            } else {
                $p=array_merge(['chat_id'=>$chatId,'text'=>$text,'parse_mode'=>'HTML'],$extraParams);
            }
            return tg('sendMessage',$p,$token);
        };

        $roseDoAction=function($action,$tUid,$tName,$reason='',$durSec=0) use($chatId,$token,$roseLog,$roseMention,$rose,$roseIsAdmin,$roseSend){
            $men=$roseMention($tUid,$tName);
            $esc=fn($s)=>htmlspecialchars($s,ENT_NOQUOTES,'UTF-8');
            $rm=$rose['reply_msgs']??[];
            // Helper: apply vars to custom message template
            $applyRoseMsg=function($tmpl,$vars=[]) use($men,$tName,$reason,$esc){
                $tmpl=str_replace('{mention}',$men,$tmpl);
                $tmpl=str_replace('{name}',htmlspecialchars($tName,ENT_NOQUOTES,'UTF-8'),$tmpl);
                $tmpl=str_replace('{reason}',$reason?$esc($reason):'No reason given',$tmpl);
                foreach($vars as $k=>$v) $tmpl=str_replace('{'.$k.'}',$v,$tmpl);
                return $tmpl?:' ';
            };
            switch($action){
                case 'ban':
                    tg('banChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'revoke_messages'=>false],$token);
                    $banMsg=!empty($rm['ban'])?$applyRoseMsg($rm['ban']):"<b>User Banned!</b> 🚨\n👤 $men\n📝 Reason: ".($reason?$esc($reason):'No reason given');
                    $roseSend($banMsg);
                    $roseLog("🚫 Banned $tName ($tUid) | Reason: $reason");
                    break;
                case 'sban':
                    tg('banChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'revoke_messages'=>true],$token);
                    $roseLog("🚫 Silently Banned $tName ($tUid) | Reason: $reason");
                    break;
                case 'tban':
                    $until=$durSec>0?time()+$durSec:0;
                    tg('banChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'until_date'=>$until,'revoke_messages'=>false],$token);
                    $ds=$durSec>0?gmdate('H\h i\m',$durSec):'forever';
                    $tbanMsg=!empty($rm['tban'])?$applyRoseMsg($rm['tban'],['duration'=>$ds]):"<b>User Temp Banned!</b> ⏳\n👤 $men\n⏱ Duration: $ds\n📝 Reason: ".($reason?$esc($reason):'No reason given');
                    $roseSend($tbanMsg);
                    $roseLog("⏳ TBanned $tName ($tUid) for $ds | Reason: $reason");
                    break;
                case 'kick':
                    if($roseIsAdmin($tUid)){$roseSend('❌ Cannot kick an admin!');break;}
                    tg('banChatMember',['chat_id'=>$chatId,'user_id'=>$tUid],$token);
                    usleep(300000);
                    tg('unbanChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'only_if_banned'=>true],$token);
                    $kickMsg=!empty($rm['kick'])?$applyRoseMsg($rm['kick']):"<b>User Kicked!</b> 👢\n👤 $men\n📝 Reason: ".($reason?$esc($reason):'No reason given');
                    $roseSend($kickMsg);
                    $roseLog("👢 Kicked $tName ($tUid) | Reason: $reason");
                    break;
                case 'skick':
                    if($roseIsAdmin($tUid)){$roseSend('❌ Cannot kick an admin!');break;}
                    tg('banChatMember',['chat_id'=>$chatId,'user_id'=>$tUid],$token);
                    usleep(300000);
                    tg('unbanChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'only_if_banned'=>true],$token);
                    $roseLog("👢 Silently Kicked $tName ($tUid)");
                    break;
                case 'unban':
                    tg('unbanChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'only_if_banned'=>true],$token);
                    $unbanMsg=!empty($rm['unban'])?$applyRoseMsg($rm['unban']):"<b>User Unbanned!</b> ✅\n👤 $men";
                    $roseSend($unbanMsg);
                    break;
                case 'mute':
                    $until2=$durSec>0?time()+$durSec:0;
                    tg('restrictChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'permissions'=>['can_send_messages'=>false,'can_send_media_messages'=>false,'can_send_other_messages'=>false,'can_add_web_page_previews'=>false],'until_date'=>$until2],$token);
                    $ds2=$durSec>0?gmdate('H\h i\m',$durSec):'forever';
                    $muteMsg=!empty($rm['mute'])?$applyRoseMsg($rm['mute'],['duration'=>$ds2]):"<b>User Muted!</b> 🔇\n👤 $men\n⏱ Duration: $ds2\n📝 Reason: ".($reason?$esc($reason):'No reason given');
                    $roseSend($muteMsg);
                    $roseLog("🔇 Muted $tName ($tUid) for $ds2 | Reason: $reason");
                    break;
                case 'unmute':
                    tg('restrictChatMember',['chat_id'=>$chatId,'user_id'=>$tUid,'permissions'=>['can_send_messages'=>true,'can_send_media_messages'=>true,'can_send_other_messages'=>true,'can_add_web_page_previews'=>true,'can_send_polls'=>true,'can_invite_users'=>true,'can_pin_messages'=>false,'can_change_info'=>false]],$token);
                    $unmuteMsg=!empty($rm['unmute'])?$applyRoseMsg($rm['unmute']):"<b>User Unmuted!</b> 🔊\n👤 $men";
                    $roseSend($unmuteMsg);
                    break;
            }
        };

        $roseWarn=function($tUid,$tName,$reason) use($chatId,$rose,&$db,$botId,$roseMention,$roseDoAction){
            $wkey=$chatId.'_'.$tUid;
            if(!isset($db['rose_warns'][$wkey]))$db['rose_warns'][$wkey]=[];
            $db['rose_warns'][$wkey][]=['reason'=>$reason?$reason:'No reason given','time'=>date('Y-m-d H:i')];
            $wcount=count($db['rose_warns'][$wkey]);
            $wlimit=(int)($rose['warn_limit']??3);
            saveDB($botId,$db);
            $men=$roseMention($tUid,$tName);
            return ['count'=>$wcount,'limit'=>$wlimit,'mention'=>$men,'reached'=>$wcount>=$wlimit];
        };

        if($roseEnabled&&$isGroupChat&&isset($msg['new_chat_members'])){
            $welcomeCfg=$rose['welcome']??[];
            if(!empty($welcomeCfg['enabled'])){
                foreach($msg['new_chat_members'] as $nm){
                    if(!empty($nm['is_bot']))continue;
                    $nmid=(string)$nm['id'];
                    $nmname=trim(($nm['first_name']??'').' '.($nm['last_name']??''));
                    $nmuser=$nm['username']??'';
                    $wmText=$welcomeCfg['text']??'Welcome {first}!';
                    $wmText=str_replace(['{first}','{last}','{fullname}','{username}','{mention}','{id}','{chatname}'],
                        [$nm['first_name']??'User',$nm['last_name']??'',$nmname,$nmuser?'@'.$nmuser:$nmname,'<a href="tg://user?id='.$nmid.'">'.$nmname.'</a>',$nmid,$msg['chat']['title']??''],$wmText);
                    $wmMedia=$welcomeCfg['media']??'';
                    $wmBtns=$welcomeCfg['buttons']??[];
                    $wkb=null;
                    if(!empty($wmBtns)){
                        $wrows=[];foreach($wmBtns as $wb){if(!empty($wb['text'])&&!empty($wb['url']))$wrows[]=[['text'=>$wb['text'],'url'=>$wb['url']]];}
                        if($wrows)$wkb=json_encode(['inline_keyboard'=>$wrows]);
                    }
                    $wp=['chat_id'=>$chatId,'parse_mode'=>'HTML'];
                    if($wkb)$wp['reply_markup']=$wkb;
                    if($wmMedia){tg('sendPhoto',array_merge($wp,['photo'=>$wmMedia,'caption'=>$wmText]),$token);}
                    else{tg('sendMessage',array_merge($wp,['text'=>$wmText]),$token);}
                    if(!empty($welcomeCfg['mute_new'])){
                        $wmDur=(int)($welcomeCfg['mute_duration']??0);
                        tg('restrictChatMember',['chat_id'=>$chatId,'user_id'=>$nmid,'permissions'=>['can_send_messages'=>false,'can_send_media_messages'=>false,'can_send_other_messages'=>false,'can_add_web_page_previews'=>false],'until_date'=>$wmDur>0?time()+$wmDur*60:0],$token);
                    }
                }
            }
            if(!empty($rose['cleanservice'])){
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
            }
            http_response_code(200);exit;
        }

        if($roseEnabled&&$isGroupChat&&isset($msg['left_chat_member'])){
            $gbCfg=$rose['goodbye']??[];
            if(!empty($gbCfg['enabled'])){
                $lm=$msg['left_chat_member'];
                if(empty($lm['is_bot'])){
                    $lmname=trim(($lm['first_name']??'').' '.($lm['last_name']??''));
                    $gbText=$gbCfg['text']??'Goodbye {first}!';
                    $gbText=str_replace(['{first}','{fullname}','{mention}'],[$lm['first_name']??'User',$lmname,'<a href="tg://user?id='.(string)$lm['id'].'">'.$lmname.'</a>'],$gbText);
                    $roseSend($gbText);
                }
            }
            if(!empty($rose['cleanservice'])){
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
            }
            http_response_code(200);exit;
        }
        if($roseEnabled&&$isGroupChat&&$msgText){

            $flood=$rose['flood']??['enabled'=>false];
            if(!empty($flood['enabled'])&&!$roseIsAdmin($uid)){
                $fkey=$chatId.'_'.$uid;
                $now2=time();$fw=(int)($flood['window']??10);$fl=(int)($flood['limit']??5);
                $fd=&$db['rose_flood'];
                if(!isset($fd[$fkey]))$fd[$fkey]=['count'=>0,'start'=>$now2];
                if($now2-$fd[$fkey]['start']>$fw){$fd[$fkey]=['count'=>1,'start'=>$now2];}
                else{$fd[$fkey]['count']++;}
                if($fd[$fkey]['count']>=$fl){
                    $fd[$fkey]=['count'=>0,'start'=>$now2];
                    saveDB($botId,$db);
                    $faction=$flood['action']??'mute';$fdur=(int)($flood['mute_duration']??5)*60;
                    tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                    $floodMsg=!empty($rose['reply_msgs']['flood'])?$rose['reply_msgs']['flood']:'⚠️ <b>Flood Detected!</b> Slow down!';
                    $roseSend($floodMsg);
                    $roseDoAction($faction,$uid,$name,'Flooding',$fdur);
                    http_response_code(200);exit;
                }
                saveDB($botId,$db);
            }

            $bl=$rose['blacklist']??[];
            if(!empty($bl)&&!$roseIsAdmin($uid)){
                $ml=strtolower($msgText);
                foreach($bl as $bword){
                    if(!trim($bword))continue;
                    $bw=strtolower(trim($bword));
                    $matched2=!empty($rose['blacklist_regex'])?(@preg_match('/'.$bw.'/iu',$msgText)===1):(strpos($ml,$bw)!==false);
                    if($matched2){
                        tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                        $bact=$rose['blacklist_action']??'delete';
                        if($bact==='warn'){
                            $wr=$roseWarn($uid,$name,'Blacklisted word: '.$bword);
                            $rm2bl=$rose['reply_msgs']??[];
                            $blWarnTmpl=!empty($rm2bl['warn'])?$rm2bl['warn']:'⚠️ <b>Warning {count}/{limit}</b>'."\n👤 {mention}\n📝 {reason}";
                            $blWarnMsg=str_replace(['{mention}','{count}','{limit}','{reason}'],[$wr['mention'],(string)$wr['count'],(string)$wr['limit'],'Blacklisted word used.'],$blWarnTmpl);
                            $roseSend($blWarnMsg);
                            if($wr['reached']){
                                $db['rose_warns'][$chatId.'_'.$uid]=[];saveDB($botId,$db);
                                $blWact=$rose['warn_action']??'kick';$blWdur=($blWact==='mute')?(int)($rose['warn_mute_duration']??60)*60:0;
                                $blWlTmpl=!empty($rm2bl['warn_limit'])?$rm2bl['warn_limit']:'🚨 {mention} has hit the warn limit! Action: <b>{action}</b>';
                                $blWlMsg=str_replace(['{mention}','{action}'],[$wr['mention'],$blWact],$blWlTmpl);
                                $roseSend($blWlMsg);
                                $roseDoAction($blWact,$uid,$name,'Warn limit reached',$blWdur);
                            }
                        }elseif($bact==='ban'){$roseDoAction('ban',$uid,$name,'Blacklisted word: '.$bword);}
                        else{$blMsg=!empty($rose['reply_msgs']['blacklist'])?$rose['reply_msgs']['blacklist']:'⚠️ That word is not allowed here.';$roseSend($blMsg);}
                        http_response_code(200);exit;
                    }
                }
            }

            $locks=$rose['locks']??[];
            if(!$roseIsAdmin($uid)){
                $shouldDel=false;$lockReason='';
                if(!empty($locks['url'])&&preg_match('/https?:\/\/\S+|t\.me\/\S+/i',$msgText)){$shouldDel=true;$lockReason='URLs';}
                if(!$shouldDel&&!empty($locks['sticker'])&&isset($msg['sticker'])){$shouldDel=true;$lockReason='Stickers';}
                if(!$shouldDel&&!empty($locks['gif'])&&isset($msg['animation'])){$shouldDel=true;$lockReason='GIFs';}
                if(!$shouldDel&&!empty($locks['voice'])&&isset($msg['voice'])){$shouldDel=true;$lockReason='Voice messages';}
                if(!$shouldDel&&!empty($locks['audio'])&&isset($msg['audio'])){$shouldDel=true;$lockReason='Audio';}
                if(!$shouldDel&&!empty($locks['document'])&&isset($msg['document'])){$shouldDel=true;$lockReason='Documents';}
                if(!$shouldDel&&!empty($locks['photo'])&&isset($msg['photo'])){$shouldDel=true;$lockReason='Photos';}
                if(!$shouldDel&&!empty($locks['video'])&&isset($msg['video'])){$shouldDel=true;$lockReason='Videos';}
                if(!$shouldDel&&!empty($locks['forward'])&&(isset($msg['forward_from'])||isset($msg['forward_from_chat']))){$shouldDel=true;$lockReason='Forwarded messages';}
                if(!$shouldDel&&!empty($locks['game'])&&isset($msg['game'])){$shouldDel=true;$lockReason='Games';}
                if(!$shouldDel&&!empty($locks['location'])&&isset($msg['location'])){$shouldDel=true;$lockReason='Locations';}
                if(!$shouldDel&&!empty($locks['contact'])&&isset($msg['contact'])){$shouldDel=true;$lockReason='Contacts';}
                if(!$shouldDel&&!empty($locks['poll'])&&isset($msg['poll'])){$shouldDel=true;$lockReason='Polls';}
                if(!$shouldDel&&!empty($locks['inline'])&&isset($msg['via_bot'])){$shouldDel=true;$lockReason='Inline bots';}
                if(!$shouldDel&&!empty($locks['all'])){$shouldDel=true;$lockReason='All messages';}
                if($shouldDel){
                    tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                    $lockTmpl=!empty($rose['reply_msgs']['locked'])?$rose['reply_msgs']['locked']:'🔒 <b>{locktype} are locked</b> in this group.';
                    $lockMsg=str_replace('{locktype}',$lockReason,$lockTmpl);
                    $roseSend($lockMsg);
                    http_response_code(200);exit;
                }
            }

            $filters=$rose['filters']??[];
            if(!empty($filters)){
                $ml2=strtolower($msgText);
                foreach($filters as $flt){
                    $kw=strtolower(trim($flt['keyword']??''));
                    if(!$kw)continue;
                    if(!empty($flt['is_regex'])){$matched3=@preg_match('/'.$kw.'/iu',$msgText)===1;}
                    elseif(!empty($flt['word_match'])){$matched3=(bool)preg_match('/\b'.preg_quote($kw,'/').'(?:s|ed|ing|er)?\b/iu',$ml2);}
                    else{$matched3=(strpos($ml2,$kw)!==false);}
                    if($matched3){
                        $freply=trim($flt['reply']??'');
                        $fmedia=trim($flt['media']??'');
                        $fmtype=$flt['media_type']??'';
                        $fbtns=$flt['buttons']??[];
                        $fkb=null;
                        if(!empty($fbtns)){$fbrows=[];foreach($fbtns as $fb2){if(!empty($fb2['text'])&&!empty($fb2['url']))$fbrows[]=[['text'=>$fb2['text'],'url'=>$fb2['url']]];}if($fbrows)$fkb=json_encode(['inline_keyboard'=>$fbrows]);}
                        $fp=['chat_id'=>$chatId,'parse_mode'=>'HTML'];if($fkb)$fp['reply_markup']=$fkb;
                        if(!empty($flt['reply_to_msg']))$fp['reply_to_message_id']=$msg['message_id'];
                        if($fmedia){
                            if($fmtype==='photo'||preg_match('/\.(jpg|jpeg|png|webp)$/i',$fmedia)){tg('sendPhoto',array_merge($fp,['photo'=>$fmedia,'caption'=>$freply]),$token);}
                            elseif($fmtype==='video'||preg_match('/\.(mp4|mov|mkv)$/i',$fmedia)){tg('sendVideo',array_merge($fp,['video'=>$fmedia,'caption'=>$freply]),$token);}
                            elseif($fmtype==='audio'){tg('sendAudio',array_merge($fp,['audio'=>$fmedia,'caption'=>$freply]),$token);}
                            elseif($fmtype==='document'){tg('sendDocument',array_merge($fp,['document'=>$fmedia,'caption'=>$freply]),$token);}
                            elseif($fmtype==='sticker'){tg('sendSticker',['chat_id'=>$chatId,'sticker'=>$fmedia],$token);}
                            elseif($fmtype==='voice'){tg('sendVoice',array_merge($fp,['voice'=>$fmedia,'caption'=>$freply]),$token);}
                            else{if($freply)tg('sendMessage',array_merge($fp,['text'=>$freply]),$token);}
                        }elseif($freply){tg('sendMessage',array_merge($fp,['text'=>$freply]),$token);}
                        if(!empty($flt['delete_trigger']))tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                        http_response_code(200);exit;
                    }
                }
            }

            if(preg_match('/^#([a-zA-Z0-9_]+)/',$msgText,$nm2)){
                $nname2=strtolower($nm2[1]);
                $found3=null;foreach($rose['notes']??[] as $n2){if(strtolower($n2['name']??'')===$nname2){$found3=$n2;break;}}
                if($found3){
                    $nmedia2=$found3['media']??'';$ntext2=$found3['text']??'';$nbtns2=$found3['buttons']??[];
                    $nkb2=null;if(!empty($nbtns2)){$nbrows=[];foreach($nbtns2 as $nb){if(!empty($nb['text'])&&!empty($nb['url']))$nbrows[]=[['text'=>$nb['text'],'url'=>$nb['url']]];}if($nbrows)$nkb2=json_encode(['inline_keyboard'=>$nbrows]);}
                    $np2=['chat_id'=>$chatId,'parse_mode'=>'HTML','reply_to_message_id'=>$msg['message_id']];if($nkb2)$np2['reply_markup']=$nkb2;
                    if($nmedia2){
                        $r2=tg('sendPhoto',array_merge($np2,['photo'=>$nmedia2,'caption'=>$ntext2]),$token);
                        if(!($r2['ok']??false))tg('sendVideo',array_merge($np2,['video'=>$nmedia2,'caption'=>$ntext2]),$token);
                    }else{tg('sendMessage',array_merge($np2,['text'=>$ntext2?:' ']),$token);}
                    http_response_code(200);exit;
                }
            }

            if(!empty($rose['cleanservice'])){
                if(isset($msg['new_chat_title'])||isset($msg['new_chat_photo'])||isset($msg['pinned_message'])){
                    tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                    http_response_code(200);exit;
                }
            }

            if((stripos($msgText,'@admin')!==false||str_starts_with($msgText,'/report'))&&!empty($rose['report']['enabled'])){
                $rreply2=trim($rose['report']['reply']??'🚨 Report submitted to admins!');
                $roseSend($rreply2,['reply_to_message_id'=>$msg['message_id']]);
                $adminsR2=tg('getChatAdministrators',['chat_id'=>$chatId],$token);
                $rReporter2=$roseMention($uid,$name);
                $rptMsg2="🚨 <b>Report received!</b>\n👤 Reporter: {$rReporter2}\n🏠 Chat: ".htmlspecialchars($msg['chat']['title']??'',ENT_NOQUOTES,'UTF-8')." (<code>{$chatId}</code>)";
                if(!empty($msg['reply_to_message'])){
                    $rru2=$msg['reply_to_message']['from']??[];
                    $rruName=trim(($rru2['first_name']??'').' '.($rru2['last_name']??''));
                    $rptMsg2.="\n🎯 Reported: ".$roseMention((string)($rru2['id']??''),$rruName);
                }
                foreach($adminsR2['result']??[] as $adm2){
                    if(!empty($adm2['user']['is_bot']))continue;
                    @tg('sendMessage',['chat_id'=>$adm2['user']['id'],'text'=>$rptMsg2,'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }
        }// end roseEnabled non-command checks

        if($roseEnabled&&$isGroupChat&&str_starts_with($msgText,'/')){
            $rpts=explode(' ',$msgText);
            $rcmd=strtolower(explode('@',$rpts[0])[0]);
            $rcmdStr=ltrim($rcmd,'/');
            $rargs=array_slice($rpts,1);
            $rquery=trim(implode(' ',$rargs));
            $rIsAdmin=$roseIsAdmin($uid);
            $rTarget=$roseTarget($rargs);
            $rReason=($rTarget&&isset($rargs[0])&&(str_starts_with($rargs[0],'@')||is_numeric($rargs[0])))?trim(implode(' ',array_slice($rargs,1))):$rquery;
            $esc2=fn($s)=>htmlspecialchars($s,ENT_NOQUOTES,'UTF-8');

            if($rcmdStr==='warn'){
                if(!$rIsAdmin){$roseSend('❌ Only admins can warn users!');http_response_code(200);exit;}
                if(!$rTarget){$roseSend('❌ Who should I warn? Reply to their message or give a username.');http_response_code(200);exit;}
                $wr=$roseWarn($rTarget['id'],$rTarget['name'],$rReason?:null);
                $rm2=$rose['reply_msgs']??[];
                $wKb=json_encode(['inline_keyboard'=>[[['text'=>'🗑 Remove warn','callback_data'=>'rose_rmwarn|'.$rTarget['id'].'|'.($wr['count']-1)]]]]);
                $warnTmpl=!empty($rm2['warn'])?$rm2['warn']:'⚠️ <b>{mention} has been warned!</b> [{count}/{limit}]'."\nReason: {reason}";
                $warnMsg=str_replace(['{mention}','{count}','{limit}','{reason}'],[$wr['mention'],(string)$wr['count'],(string)$wr['limit'],$rReason?$esc2($rReason):'No reason given'],$warnTmpl);
                $roseSend($warnMsg,['reply_markup'=>$wKb]);
                if($wr['reached']){
                    $db['rose_warns'][$chatId.'_'.$rTarget['id']]=[];saveDB($botId,$db);
                    $wact=$rose['warn_action']??'kick';
                    $wdur=($wact==='mute')?(int)($rose['warn_mute_duration']??60)*60:0;
                    $wlTmpl=!empty($rm2['warn_limit'])?$rm2['warn_limit']:'🚨 {mention} has hit the warn limit! Action: <b>{action}</b>';
                    $wlMsg=str_replace(['{mention}','{action}'],[$wr['mention'],$wact],$wlTmpl);
                    $roseSend($wlMsg);
                    $roseDoAction($wact,$rTarget['id'],$rTarget['name'],'Warn limit reached',$wdur);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='dwarn'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                if(!$rTarget){$roseSend('❌ Reply to a message to warn+delete.');http_response_code(200);exit;}
                if(!empty($msg['reply_to_message']['message_id']))tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['reply_to_message']['message_id']],$token);
                $wr=$roseWarn($rTarget['id'],$rTarget['name'],$rReason?:null);
                $rm2=$rose['reply_msgs']??[];
                $warnTmpl2=!empty($rm2['warn'])?$rm2['warn']:'⚠️ <b>{mention} has been warned!</b> [{count}/{limit}]'."\nReason: {reason}";
                $warnMsg2=str_replace(['{mention}','{count}','{limit}','{reason}'],[$wr['mention'],(string)$wr['count'],(string)$wr['limit'],$rReason?$esc2($rReason):'No reason given'],$warnTmpl2);
                $roseSend($warnMsg2);
                if($wr['reached']){
                    $db['rose_warns'][$chatId.'_'.$rTarget['id']]=[];saveDB($botId,$db);
                    $wact2=$rose['warn_action']??'kick';
                    $wdur2=($wact2==='mute')?(int)($rose['warn_mute_duration']??60)*60:0;
                    $wlTmpl2=!empty($rm2['warn_limit'])?$rm2['warn_limit']:'🚨 {mention} has hit the warn limit! Action: <b>{action}</b>';
                    $wlMsg2=str_replace(['{mention}','{action}'],[$wr['mention'],$wact2],$wlTmpl2);
                    $roseSend($wlMsg2);
                    $roseDoAction($wact2,$rTarget['id'],$rTarget['name'],'Warn limit reached',$wdur2);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='warns'){
                $wt=$rTarget??['id'=>$uid,'name'=>$name];
                $wkey2=$chatId.'_'.$wt['id'];$warnsL=$db['rose_warns'][$wkey2]??[];$wlimit2=(int)($rose['warn_limit']??3);
                $wmen=$roseMention($wt['id'],$wt['name']);
                if(empty($warnsL)){tg('sendMessage',['chat_id'=>$chatId,'text'=>"$wmen has no warnings in this chat!",'parse_mode'=>'HTML'],$token);}
                else{
                    $lines2=["<b>$wmen has ".count($warnsL)."/$wlimit2 warnings:</b>"];
                    foreach($warnsL as $wi=>$ww)$lines2[]=($wi+1).". ".$esc2($ww['reason'])." <i>({$ww['time']})</i>";
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",$lines2),'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='resetwarns'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply to a user or give username.'],$token);http_response_code(200);exit;}
                $db['rose_warns'][$chatId.'_'.$rTarget['id']]=[];saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"Warns reset for ".$roseMention($rTarget['id'],$rTarget['name'])."!",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='setwarnlimit'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $wl2=max(1,(int)$rquery);$rose['warn_limit']=$wl2;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Warn limit set to <b>$wl2</b>.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='setwarnaction'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $wa=strtolower(trim($rquery));
                if(!in_array($wa,['ban','kick','mute'])){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Valid actions: ban, kick, mute'],$token);http_response_code(200);exit;}
                $rose['warn_action']=$wa;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Warn action set to <b>$wa</b>.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='warnlimit'){
                $wl3=(int)($rose['warn_limit']??3);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"Warn limit is set to <b>$wl3</b> warns.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='ban'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins can ban users!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Who should I ban? Reply to their message or give a username.'],$token);http_response_code(200);exit;}
                $roseDoAction('ban',$rTarget['id'],$rTarget['name'],$rReason);
                http_response_code(200);exit;
            }

            if($rcmdStr==='sban'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply to a message or give username.'],$token);http_response_code(200);exit;}
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                $roseDoAction('sban',$rTarget['id'],$rTarget['name'],$rReason);
                http_response_code(200);exit;
            }

            if($rcmdStr==='tban'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply to a message or give username.'],$token);http_response_code(200);exit;}
                $durArg2=end($rargs);$durSec2=$roseParseTime($durArg2);
                if(!$durSec2){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Invalid time! Use: 5m, 2h, 1d, 1w'],$token);http_response_code(200);exit;}
                $roseDoAction('tban',$rTarget['id'],$rTarget['name'],$rReason,$durSec2);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unban'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply to a message or give username.'],$token);http_response_code(200);exit;}
                $roseDoAction('unban',$rTarget['id'],$rTarget['name'],'');
                http_response_code(200);exit;
            }

            if($rcmdStr==='kick'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins can kick users!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Who should I kick? Reply or give username.'],$token);http_response_code(200);exit;}
                $roseDoAction('kick',$rTarget['id'],$rTarget['name'],$rReason);
                http_response_code(200);exit;
            }

            if($rcmdStr==='skick'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply or username.'],$token);http_response_code(200);exit;}
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                $roseDoAction('skick',$rTarget['id'],$rTarget['name'],'');
                http_response_code(200);exit;
            }

            if($rcmdStr==='mute'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins can mute users!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Who should I mute? Reply or give username.'],$token);http_response_code(200);exit;}
                $roseDoAction('mute',$rTarget['id'],$rTarget['name'],$rReason,0);
                http_response_code(200);exit;
            }

            if($rcmdStr==='tmute'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply or username.'],$token);http_response_code(200);exit;}
                $durArg3=end($rargs);$durSec3=$roseParseTime($durArg3);
                if(!$durSec3){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Invalid time! Use: 5m, 2h, 1d'],$token);http_response_code(200);exit;}
                $roseDoAction('mute',$rTarget['id'],$rTarget['name'],$rReason,$durSec3);
                http_response_code(200);exit;
            }

            if($rcmdStr==='smute'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Reply or username.'],$token);http_response_code(200);exit;}
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                $roseDoAction('mute',$rTarget['id'],$rTarget['name'],'',$durSec3??0);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unmute'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Who should I unmute? Reply or give username.'],$token);http_response_code(200);exit;}
                $roseDoAction('unmute',$rTarget['id'],$rTarget['name'],'');
                http_response_code(200);exit;
            }

            if($rcmdStr==='del'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!empty($msg['reply_to_message']['message_id']))tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['reply_to_message']['message_id']],$token);
                tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$msg['message_id']],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='purge'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                if(empty($msg['reply_to_message']['message_id'])){$roseSend('❌ Reply to the message you want to start purging from.');http_response_code(200);exit;}
                $fromMsgId=(int)$msg['reply_to_message']['message_id'];$curMsgId=(int)$msg['message_id'];
                $deleted=0;
                for($pmi=$fromMsgId;$pmi<=$curMsgId;$pmi++){$r3=tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$pmi],$token);if($r3['ok']??false)$deleted++;}
                $rm2=$rose['reply_msgs']??[];
                $purgedTmpl=!empty($rm2['purged'])?$rm2['purged']:'🗑 Purged {count} messages.';
                $purgedMsg=str_replace('{count}',(string)$deleted,$purgedTmpl);
                $notif=$roseSend($purgedMsg);
                usleep(2000000);
                if(!empty($notif['result']['message_id']))tg('deleteMessage',['chat_id'=>$chatId,'message_id'=>$notif['result']['message_id']],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='promote'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                if(!$rTarget){$roseSend('❌ Reply or username.');http_response_code(200);exit;}
                $title=trim($rReason);
                $pp=['chat_id'=>$chatId,'user_id'=>$rTarget['id'],'can_manage_chat'=>true,'can_delete_messages'=>true,'can_restrict_members'=>true,'can_pin_messages'=>true,'can_invite_users'=>true,'can_change_info'=>false,'can_promote_members'=>false,'can_manage_video_chats'=>true,'is_anonymous'=>false];
                if($title)$pp['custom_title']=$title;
                tg('promoteChatMember',$pp,$token);
                $men2=$roseMention($rTarget['id'],$rTarget['name']);
                $rm2=$rose['reply_msgs']??[];
                $promTmpl=!empty($rm2['promoted'])?$rm2['promoted']:'⬆️ <b>Promoted!</b>'."\n👤 {mention}";
                $promMsg=str_replace('{mention}',$men2,$promTmpl).($title?"\n🏷 Title: ".htmlspecialchars($title,ENT_NOQUOTES,'UTF-8'):'');
                $roseSend($promMsg);
                http_response_code(200);exit;
            }

            if($rcmdStr==='demote'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                if(!$rTarget){$roseSend('❌ Reply or username.');http_response_code(200);exit;}
                tg('promoteChatMember',['chat_id'=>$chatId,'user_id'=>$rTarget['id'],'can_manage_chat'=>false,'can_delete_messages'=>false,'can_restrict_members'=>false,'can_pin_messages'=>false,'can_invite_users'=>false,'can_change_info'=>false],$token);
                $men2=$roseMention($rTarget['id'],$rTarget['name']);
                $rm2=$rose['reply_msgs']??[];
                $demTmpl=!empty($rm2['demoted'])?$rm2['demoted']:'⬇️ <b>Demoted!</b>'."\n👤 {mention}";
                $demMsg=str_replace('{mention}',$men2,$demTmpl);
                $roseSend($demMsg);
                http_response_code(200);exit;
            }

            if($rcmdStr==='settitle'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rTarget||!$rReason){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Usage: /settitle @user <title>'],$token);http_response_code(200);exit;}
                tg('setChatAdministratorCustomTitle',['chat_id'=>$chatId,'user_id'=>$rTarget['id'],'custom_title'=>$rReason],$token);
                $men2=$roseMention($rTarget['id'],$rTarget['name']);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"🏷 Title set to <b>".$esc2($rReason)."</b> for $men2.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='pin'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                if(empty($msg['reply_to_message']['message_id'])){$roseSend('❌ Reply to the message you want to pin.');http_response_code(200);exit;}
                $loud=strtolower($rquery)!=='silent';
                tg('pinChatMessage',['chat_id'=>$chatId,'message_id'=>$msg['reply_to_message']['message_id'],'disable_notification'=>!$loud],$token);
                $rm2=$rose['reply_msgs']??[];
                $pinTmpl=!empty($rm2['pinned'])?$rm2['pinned']:'📌 Message pinned.';
                if(strtolower($rquery)==='silent')$roseSend('📌 Pinned silently.');
                else $roseSend($pinTmpl);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unpin'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                if(!empty($msg['reply_to_message']['message_id'])){tg('unpinChatMessage',['chat_id'=>$chatId,'message_id'=>$msg['reply_to_message']['message_id']],$token);}
                else{tg('unpinChatMessage',['chat_id'=>$chatId],$token);}
                $rm2=$rose['reply_msgs']??[];
                $unpinTmpl=!empty($rm2['unpinned'])?$rm2['unpinned']:'📌 Message unpinned.';
                $roseSend($unpinTmpl);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unpinall'){
                if(!$rIsAdmin){$roseSend('❌ Only admins!');http_response_code(200);exit;}
                tg('unpinAllChatMessages',['chat_id'=>$chatId],$token);
                $roseSend('📌 All messages unpinned.');
                http_response_code(200);exit;
            }

            if($rcmdStr==='rules'){
                $rules2=trim($rose['rules']??'');
                if(!$rules2){tg('sendMessage',['chat_id'=>$chatId,'text'=>'This group has no rules set! Ask admins to set them.'],$token);}
                else{
                    $chatTitle=$msg['chat']['title']??'this group';
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"<b>Rules for ".htmlspecialchars($chatTitle,ENT_NOQUOTES,'UTF-8').":</b>\n\n".$rules2,'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='setrules'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $newRules=trim($rquery)?:trim($msg['reply_to_message']['text']??'');
                $rose['rules']=$newRules;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>$newRules?'✅ Rules have been set!':'✅ Rules have been cleared!'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='resetrules'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $rose['rules']='';$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Rules have been reset.'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='save'||$rcmdStr==='note'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $nparts2=explode(' ',$rquery,2);$nname3=strtolower(trim($nparts2[0]??''));$ntext3=trim($nparts2[1]??'');
                if(!$nname3){tg('sendMessage',['chat_id'=>$chatId,'text'=>"❌ Usage:\n/save <notename> <text>\n/save <notename> (reply to a message)"],$token);http_response_code(200);exit;}
                $nmedia3='';$nmtype='';$nbtns3=[];
                if(!empty($msg['reply_to_message'])){
                    $rr3=$msg['reply_to_message'];
                    if(!empty($rr3['photo'])){$nmedia3=end($rr3['photo'])['file_id'];$nmtype='photo';}
                    elseif(!empty($rr3['video']['file_id'])){$nmedia3=$rr3['video']['file_id'];$nmtype='video';}
                    elseif(!empty($rr3['audio']['file_id'])){$nmedia3=$rr3['audio']['file_id'];$nmtype='audio';}
                    elseif(!empty($rr3['document']['file_id'])){$nmedia3=$rr3['document']['file_id'];$nmtype='document';}
                    elseif(!empty($rr3['sticker']['file_id'])){$nmedia3=$rr3['sticker']['file_id'];$nmtype='sticker';}
                    elseif(!empty($rr3['voice']['file_id'])){$nmedia3=$rr3['voice']['file_id'];$nmtype='voice';}
                    if(!$ntext3)$ntext3=$rr3['text']??$rr3['caption']??'';
                }
                $rose['notes']=array_values(array_filter($rose['notes']??[],fn($n3)=>strtolower($n3['name']??'')!==$nname3));
                $rose['notes'][]=['name'=>$nname3,'text'=>$ntext3,'media'=>$nmedia3,'media_type'=>$nmtype,'buttons'=>$nbtns3];
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Note <code>$nname3</code> saved! Get it with <code>#$nname3</code> or <code>/get $nname3</code>",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='get'){
                $nname4=strtolower(trim($rquery));
                $found4=null;foreach($rose['notes']??[] as $n4){if(strtolower($n4['name']??'')===$nname4){$found4=$n4;break;}}
                if(!$found4){tg('sendMessage',['chat_id'=>$chatId,'text'=>"Note <code>$nname4</code> doesn't exist!",'parse_mode'=>'HTML'],$token);}
                else{
                    $nmedia4=$found4['media']??'';$ntext4=$found4['text']??'';$nmtype4=$found4['media_type']??'';
                    $np4=['chat_id'=>$chatId,'parse_mode'=>'HTML','reply_to_message_id'=>$msg['message_id']];
                    if($nmedia4){
                        if($nmtype4==='photo'){tg('sendPhoto',array_merge($np4,['photo'=>$nmedia4,'caption'=>$ntext4]),$token);}
                        elseif($nmtype4==='video'){tg('sendVideo',array_merge($np4,['video'=>$nmedia4,'caption'=>$ntext4]),$token);}
                        elseif($nmtype4==='audio'){tg('sendAudio',array_merge($np4,['audio'=>$nmedia4,'caption'=>$ntext4]),$token);}
                        elseif($nmtype4==='document'){tg('sendDocument',array_merge($np4,['document'=>$nmedia4,'caption'=>$ntext4]),$token);}
                        elseif($nmtype4==='sticker'){tg('sendSticker',['chat_id'=>$chatId,'sticker'=>$nmedia4],$token);}
                        elseif($nmtype4==='voice'){tg('sendVoice',array_merge($np4,['voice'=>$nmedia4,'caption'=>$ntext4]),$token);}
                        else{tg('sendPhoto',array_merge($np4,['photo'=>$nmedia4,'caption'=>$ntext4]),$token);}
                    }else{tg('sendMessage',array_merge($np4,['text'=>$ntext4?:' ']),$token);}
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='notes'){
                $nlist2=$rose['notes']??[];
                if(empty($nlist2)){tg('sendMessage',['chat_id'=>$chatId,'text'=>'No notes in this chat!'],$token);}
                else{
                    $ctitle=htmlspecialchars($msg['chat']['title']??'this chat',ENT_NOQUOTES,'UTF-8');
                    $nlines2=["📝 <b>Notes in $ctitle:</b>"];
                    foreach($nlist2 as $nn2)$nlines2[]='• #'.htmlspecialchars($nn2['name'],ENT_NOQUOTES,'UTF-8');
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",$nlines2),'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='clear'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $nname5=strtolower(trim($rquery));
                $bc=count($rose['notes']??[]);
                $rose['notes']=array_values(array_filter($rose['notes']??[],fn($n5)=>strtolower($n5['name']??'')!==$nname5));
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>$bc>count($rose['notes'])?"✅ Note <code>$nname5</code> deleted!":'❌ Note not found.','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='clearall'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $rose['notes']=[];$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ All notes deleted!'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='filter'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rquery){tg('sendMessage',['chat_id'=>$chatId,'text'=>"❌ Usage: /filter <keyword> <reply text>\n\nOr reply to a message to use it as the filter response."],$token);http_response_code(200);exit;}
                $fparts3=explode(' ',$rquery,2);$fkw3=strtolower(trim($fparts3[0]??''));$frep3=trim($fparts3[1]??'');
                $fmedia3='';$fmtype3='';
                if(!empty($msg['reply_to_message'])){
                    $rr4=$msg['reply_to_message'];
                    if(!empty($rr4['photo'])){$fmedia3=end($rr4['photo'])['file_id'];$fmtype3='photo';}
                    elseif(!empty($rr4['video']['file_id'])){$fmedia3=$rr4['video']['file_id'];$fmtype3='video';}
                    elseif(!empty($rr4['audio']['file_id'])){$fmedia3=$rr4['audio']['file_id'];$fmtype3='audio';}
                    elseif(!empty($rr4['document']['file_id'])){$fmedia3=$rr4['document']['file_id'];$fmtype3='document';}
                    elseif(!empty($rr4['sticker']['file_id'])){$fmedia3=$rr4['sticker']['file_id'];$fmtype3='sticker';}
                    elseif(!empty($rr4['voice']['file_id'])){$fmedia3=$rr4['voice']['file_id'];$fmtype3='voice';}
                    if(!$frep3)$frep3=$rr4['text']??$rr4['caption']??'';
                }
                $rose['filters']=array_values(array_filter($rose['filters']??[],fn($f3)=>strtolower($f3['keyword']??'')!==$fkw3));
                $rose['filters'][]=['keyword'=>$fkw3,'reply'=>$frep3,'media'=>$fmedia3,'media_type'=>$fmtype3,'is_regex'=>false,'buttons'=>[],'delete_trigger'=>false,'reply_to_msg'=>false];
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Filter added for: <code>".htmlspecialchars($fkw3,ENT_NOQUOTES,'UTF-8')."</code>\n\nAnytime someone says this, I'll respond!",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='filters'){
                $flist2=$rose['filters']??[];
                if(empty($flist2)){tg('sendMessage',['chat_id'=>$chatId,'text'=>'No filters in this chat!'],$token);}
                else{
                    $ctitle2=htmlspecialchars($msg['chat']['title']??'this chat',ENT_NOQUOTES,'UTF-8');
                    $flines2=["🔍 <b>Current filters in $ctitle2:</b>"];
                    foreach($flist2 as $f4)$flines2[]='• <code>'.htmlspecialchars($f4['keyword'],ENT_NOQUOTES,'UTF-8').'</code>';
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",$flines2),'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='stop'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $fkw4=strtolower(trim($rquery));
                $bc2=count($rose['filters']??[]);
                $rose['filters']=array_values(array_filter($rose['filters']??[],fn($f5)=>strtolower($f5['keyword']??'')!==$fkw4));
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>$bc2>count($rose['filters'])?"✅ Filter for <code>".htmlspecialchars($fkw4,ENT_NOQUOTES,'UTF-8')."</code> stopped!":'❌ Filter not found.','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='stopall'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $rose['filters']=[];$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ All filters have been stopped!'],$token);
                http_response_code(200);exit;
            }

            $allLockTypes=['all','url','text','media','other','voice','video','document','photo','gif','sticker','music','contact','video_note','location','poll','game','forward','bot','photo','inline'];
            if($rcmdStr==='lock'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $ltype2=strtolower(trim($rquery));
                if(!$ltype2){tg('sendMessage',['chat_id'=>$chatId,'text'=>"❌ What do you want to lock?\n\nAvailable locks: ".implode(', ',$allLockTypes)],$token);http_response_code(200);exit;}
                $rose['locks'][$ltype2]=true;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"🔒 <b>Locked:</b> $ltype2",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unlock'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $ltype3=strtolower(trim($rquery));
                if(!$ltype3){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ What do you want to unlock?'],$token);http_response_code(200);exit;}
                $rose['locks'][$ltype3]=false;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"🔓 <b>Unlocked:</b> $ltype3",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='locks'){
                $lockedItems=array_keys(array_filter($rose['locks']??[]));
                if(empty($lockedItems)){tg('sendMessage',['chat_id'=>$chatId,'text'=>'🔓 Nothing is locked in this chat.'],$token);}
                else{
                    $ctitle3=htmlspecialchars($msg['chat']['title']??'',ENT_NOQUOTES,'UTF-8');
                    $ll=implode(', ',array_map(fn($l)=>"<code>$l</code>",$lockedItems));
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"🔒 <b>Locks in $ctitle3:</b>\n$ll",'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='lockall'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                foreach($allLockTypes as $lt2)$rose['locks'][$lt2]=true;
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'🔒 <b>All locks enabled!</b>','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unlockall'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                foreach($allLockTypes as $lt3)$rose['locks'][$lt3]=false;
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'🔓 <b>All locks disabled!</b>','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='allowlist'||$rcmdStr==='whitelist'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $wlitem=strtolower(trim($rquery));
                if(!$wlitem){
                    $wl4=$rose['allowlist']??[];
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>empty($wl4)?'No items in allowlist.':'✅ <b>Allowlist:</b>\n'.implode("\n",array_map(fn($w4)=>"• $w4",$wl4)),'parse_mode'=>'HTML'],$token);
                }else{
                    if(!in_array($wlitem,$rose['allowlist']??[]))$rose['allowlist'][]=$wlitem;
                    $db['settings']['rose']=$rose;saveDB($botId,$db);
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ <code>$wlitem</code> added to allowlist.",'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='rmallowlist'||$rcmdStr==='rmwhitelist'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $wlitem2=strtolower(trim($rquery));
                $rose['allowlist']=array_values(array_filter($rose['allowlist']??[],fn($w5)=>$w5!==$wlitem2));
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Removed <code>$wlitem2</code> from allowlist.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='addblocklist'||$rcmdStr==='addblacklist'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!$rquery){tg('sendMessage',['chat_id'=>$chatId,'text'=>"❌ Usage: /addblocklist <word1> <word2>..."],$token);http_response_code(200);exit;}
                $newBLWords=array_filter(array_map('trim',explode(' ',$rquery)));
                $added=0;foreach($newBLWords as $bw2){$bwl=strtolower($bw2);if(!in_array($bwl,$rose['blacklist']??[])){$rose['blacklist'][]=$bwl;$added++;}}
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Added <b>$added</b> word(s) to the blocklist.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unblocklist'||$rcmdStr==='unblacklist'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $bw3=strtolower(trim($rquery));
                $bc3=count($rose['blacklist']??[]);
                $rose['blacklist']=array_values(array_filter($rose['blacklist']??[],fn($b3)=>$b3!==$bw3));
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>$bc3>count($rose['blacklist'])?"✅ Removed <code>$bw3</code> from blocklist.":'❌ Word not found in blocklist.','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='unblocklistall'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $rose['blacklist']=[];$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Blocklist cleared!'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='blocklist'||$rcmdStr==='blacklist'){
                $bll=$rose['blacklist']??[];
                if(empty($bll)){tg('sendMessage',['chat_id'=>$chatId,'text'=>'No blocklist words in this chat!'],$token);}
                else{
                    $blines=["🚫 <b>Blocklist for ".htmlspecialchars($msg['chat']['title']??'',ENT_NOQUOTES,'UTF-8').":</b>"];
                    foreach($bll as $bw4)$blines[]='• <code>'.htmlspecialchars($bw4,ENT_NOQUOTES,'UTF-8').'</code>';
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",$blines),'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='setflood'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(strtolower(trim($rquery))==='off'||$rquery==='0'){
                    $rose['flood']['enabled']=false;$db['settings']['rose']=$rose;saveDB($botId,$db);
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Antiflood has been disabled.'],$token);
                }elseif(is_numeric(trim($rquery))&&(int)$rquery>0){
                    $rose['flood']['enabled']=true;$rose['flood']['limit']=(int)$rquery;
                    $db['settings']['rose']=$rose;saveDB($botId,$db);
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Antiflood has been set to <b>{$rquery}</b> messages!",'parse_mode'=>'HTML'],$token);
                }else{
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"Flood count is currently <b>".($rose['flood']['limit']??5)."</b>. Use /setflood <num> or /setflood off.",'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='setfloodmode'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $fmode=strtolower(trim($rquery));
                if(!in_array($fmode,['ban','kick','mute','tban','tmute'])){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Valid modes: ban, kick, mute, tban, tmute'],$token);http_response_code(200);exit;}
                $rose['flood']['action']=$fmode;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Flood mode set to <b>$fmode</b>.",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='flood'){
                $fe2=!empty($rose['flood']['enabled']);$fl2=(int)($rose['flood']['limit']??5);$fa=$rose['flood']['action']??'mute';
                if(!$fe2){tg('sendMessage',['chat_id'=>$chatId,'text'=>'Antiflood is currently disabled.'],$token);}
                else{tg('sendMessage',['chat_id'=>$chatId,'text'=>"Antiflood is set to <b>$fl2</b> messages. Action: <b>$fa</b>",'parse_mode'=>'HTML'],$token);}
                http_response_code(200);exit;
            }

            if($rcmdStr==='setwelcome'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!isset($rose['welcome']))$rose['welcome']=['enabled'=>false,'text'=>'','media'=>'','buttons'=>[]];
                $rose['welcome']['enabled']=true;
                $wmText2='';$wmMedia2='';
                if(!empty($msg['reply_to_message'])){
                    $rr5=$msg['reply_to_message'];
                    $wmText2=$rr5['text']??$rr5['caption']??'';
                    if(!empty($rr5['photo']))$wmMedia2=end($rr5['photo'])['file_id'];
                    elseif(!empty($rr5['video']['file_id']))$wmMedia2=$rr5['video']['file_id'];
                }elseif($rquery){$wmText2=$rquery;}
                if($wmText2||$wmMedia2){$rose['welcome']['text']=$wmText2;$rose['welcome']['media']=$wmMedia2;}
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Welcome message set!\n\nVariables: {first}, {last}, {fullname}, {username}, {mention}, {id}, {chatname}",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='welcome'){
                $wc=$rose['welcome']??[];
                $wstatus=!empty($wc['enabled'])?'enabled':'disabled';
                $wt3=trim($wc['text']??'Not set');
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"Welcome message is <b>$wstatus</b>.\n\nCurrent text:\n<i>$wt3</i>",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='resetwelcome'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $rose['welcome']=['enabled'=>false,'text'=>'','media'=>'','buttons'=>[]];
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Welcome message reset!'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='setgoodbye'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                if(!isset($rose['goodbye']))$rose['goodbye']=['enabled'=>false,'text'=>''];
                $rose['goodbye']['enabled']=true;
                $gbText2=$rquery?:($msg['reply_to_message']['text']??'');
                if($gbText2)$rose['goodbye']['text']=$gbText2;
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Goodbye message set!\n\nVariables: {first}, {fullname}, {mention}"],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='goodbye'){
                $gc=$rose['goodbye']??[];
                $gstatus=!empty($gc['enabled'])?'enabled':'disabled';
                $gt=trim($gc['text']??'Not set');
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"Goodbye message is <b>$gstatus</b>.\n\nCurrent text:\n<i>$gt</i>",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='resetgoodbye'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $rose['goodbye']=['enabled'=>false,'text'=>''];$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Goodbye message reset!'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='welcomemute'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $wmo=strtolower(trim($rquery));
                if($wmo==='off'){$rose['welcome']['mute_new']=false;tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Welcome mute disabled.'],$token);}
                elseif(in_array($wmo,['on','soft','hard'])){$rose['welcome']['mute_new']=true;tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Welcome mute set to <b>$wmo</b>.",'parse_mode'=>'HTML'],$token);}
                else{tg('sendMessage',['chat_id'=>$chatId,'text'=>'Usage: /welcomemute on/soft/hard/off'],$token);}
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                http_response_code(200);exit;
            }

            if($rcmdStr==='captcha'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $co=strtolower(trim($rquery));
                if($co==='off'){$rose['captcha']=['enabled'=>false];tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Captcha disabled.'],$token);}
                elseif($co==='on'||$co==='button'){$rose['captcha']=['enabled'=>true,'mode'=>'button'];tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Captcha enabled (button mode)."],$token);}
                else{$rose['captcha']=['enabled'=>false];tg('sendMessage',['chat_id'=>$chatId,'text'=>"Captcha is currently: ".(!empty($rose['captcha']['enabled'])?'enabled':'disabled')."\n\nUsage: /captcha on | /captcha off"],$token);}
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                http_response_code(200);exit;
            }

            if($rcmdStr==='cleanservice'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $cso=strtolower(trim($rquery));
                $rose['cleanservice']=($cso==='on'||$cso==='yes'||$cso==='true');
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Clean service messages: <b>'.($rose['cleanservice']?'ON':'OFF').'</b>','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='reports'){
                if($rIsAdmin){
                    $rena=strtolower(trim($rquery));
                    if(in_array($rena,['on','off'])){
                        $rose['report']['enabled']=($rena==='on');$db['settings']['rose']=$rose;saveDB($botId,$db);
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Reports are now <b>".strtoupper($rena)."</b>.",'parse_mode'=>'HTML'],$token);
                    }else{
                        $status=!empty($rose['report']['enabled'])?'enabled':'disabled';
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>"Reports are currently <b>$status</b>.",'parse_mode'=>'HTML'],$token);
                    }
                }else{
                    $status2=!empty($rose['report']['enabled'])?'enabled':'disabled';
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"Reports are currently <b>$status2</b>. Use @admin to report a user.",'parse_mode'=>'HTML'],$token);
                }
                http_response_code(200);exit;
            }

            if($rcmdStr==='logchannel'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $lc2=trim($rquery);
                $rose['log_channel']=$lc2;$db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>$lc2?"✅ Log channel set to: <code>$lc2</code>":'✅ Log channel removed.','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='info'){
                $it=$rTarget??['id'=>$uid,'name'=>$name];
                $itUid=$it['id'];$itName=htmlspecialchars($it['name'],ENT_NOQUOTES,'UTF-8');
                $wkey5=$chatId.'_'.$itUid;$wcount5=count($db['rose_warns'][$wkey5]??[]);$wlimit5=(int)($rose['warn_limit']??3);
                $cmem5=tg('getChatMember',['chat_id'=>$chatId,'user_id'=>$itUid],$token);
                $cstatus5=$cmem5['result']['status']??'member';
                $ituser=$it['user']??[];
                $uname=$ituser['username']??'';$itfirst=$ituser['first_name']??$itName;$itlast=$ituser['last_name']??'';
                $lines5=["<b>User info for</b> <a href=\"tg://user?id=$itUid\">$itName</a>:",
                    "ID: <code>$itUid</code>",
                    "Name: $itfirst".($itlast?" $itlast":''),
                    $uname?"Username: @$uname":'',
                    "Status: <b>$cstatus5</b>",
                    "Warns: <b>$wcount5/$wlimit5</b>",
                ];
                if(!empty($db['users'][$itUid]['joined']))$lines5[]="First seen: ".$db['users'][$itUid]['joined'];
                tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",array_filter($lines5)),'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='id'){
                $it2=$rTarget??null;
                $txt2="🏠 Chat ID: <code>$chatId</code>\n👤 Your ID: <code>$uid</code>";
                if($it2)$txt2.="\n🎯 ".$roseMention($it2['id'],$it2['name'])."'s ID: <code>".$it2['id']."</code>";
                tg('sendMessage',['chat_id'=>$chatId,'text'=>$txt2,'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='adminlist'||$rcmdStr==='admins'){
                $adminsR3=tg('getChatAdministrators',['chat_id'=>$chatId],$token);
                $ctitle4=htmlspecialchars($msg['chat']['title']??'',ENT_NOQUOTES,'UTF-8');
                $alines=["👮 <b>Admins in $ctitle4:</b>"];
                $creators=[];$admins3=[];
                foreach($adminsR3['result']??[] as $a3){
                    if(!empty($a3['user']['is_bot']))continue;
                    $aname2=htmlspecialchars(trim(($a3['user']['first_name']??'').' '.($a3['user']['last_name']??'')),ENT_NOQUOTES,'UTF-8');
                    $uname2=$a3['user']['username']??'';
                    $title2=$a3['custom_title']??'';
                    $line2=($a3['status']==='creator'?'👑':'🛡 ').'<a href="tg://user?id='.$a3['user']['id'].'">'.$aname2.'</a>'.($uname2?" (@$uname2)":'').($title2?" — <i>$title2</i>":'');
                    if($a3['status']==='creator')$creators[]=$line2;else $admins3[]=$line2;
                }
                $alines=array_merge($alines,$creators,$admins3);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>implode("\n",$alines),'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='export'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $exportData=['filters'=>$rose['filters']??[],'notes'=>$rose['notes']??[],'rules'=>$rose['rules']??'','locks'=>$rose['locks']??[],'blacklist'=>$rose['blacklist']??[],'warn_limit'=>$rose['warn_limit']??3,'warn_action'=>$rose['warn_action']??'kick'];
                $exportJson=json_encode($exportData,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE);
                tg('sendDocument',['chat_id'=>$chatId,'document'=>['attach://export'],'caption'=>'📦 Rose Bot config export for '.htmlspecialchars($msg['chat']['title']??'',ENT_NOQUOTES,'UTF-8')],$token,['export'=>['filename'=>'rose_config.json','content'=>$exportJson]]);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"📦 <b>Export data</b> (copy this):\n\n<pre>".htmlspecialchars(substr($exportJson,0,3000),ENT_NOQUOTES,'UTF-8')."</pre>",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='privatenotes'){
                if(!$rIsAdmin){tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Only admins!'],$token);http_response_code(200);exit;}
                $pno=strtolower(trim($rquery));
                $rose['private_notes']=($pno==='on'||$pno==='yes');
                $db['settings']['rose']=$rose;saveDB($botId,$db);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ Private notes: <b>'.($rose['private_notes']?'ON':'OFF').'</b>','parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($rcmdStr==='help'){
                $helpDmUrl='https://t.me/'.($botUsername?:($db['username']??'bot')).'?start=help';
                $helpKb=json_encode(['inline_keyboard'=>[
                    [['text'=>'💬 Contact Me in DM','url'=>$helpDmUrl]],
                ]]);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"ℹ️ Come to DM for help — all commands list is available there!",'parse_mode'=>'HTML','reply_markup'=>$helpKb],$token);
                http_response_code(200);exit;
            }
        }// end roseEnabled commands

        if(str_starts_with($msgText,'/')){
            $db['stats']['cmds']++;saveDB($botId,$db);
            $pts=explode(' ',$msgText);$cmd=strtolower(explode('@',$pts[0])[0]);
            $cmdStr=ltrim($cmd,'/');$args=array_slice($pts,1);$query=trim(implode(' ',$args));

            if($cmdStr==='redeem'){
                $inputKey=strtoupper($args[0]??'');
                if($inputKey){
                    $found=null;
                    foreach(['ukeys','lkeys'] as $kt){foreach($db[$kt] as &$k2){if($k2['key']===$inputKey&&$k2['status']==='unused'){$found=&$k2;break 2;}}}
                    if($found){
                        $found['status']='active';$found['assigned']=$name;$u['key']=$inputKey;
                        $u['keyExpires']=date('Y-m-d',strtotime("+".($found['days']??30)." days"));
                        $u['searchesLeft']=(($found['searches']??100)==999999)?999999:(int)$found['searches'];
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ <b>Key Activated!</b>\n🔑 Key: <code>$inputKey</code>\n📊 Searches: ".$u['searchesLeft'],'parse_mode'=>'HTML'],$token);
                        addLog($botId,"Key redeemed: $inputKey by $name",'success');
                    }else tg('sendMessage',['chat_id'=>$chatId,'text'=>'❌ Invalid or already used key!'],$token);
                    saveDB($botId,$db);
                }
                http_response_code(200);exit;
            }

            if($cmdStr==='save'){
                $ownerId=$s['adminId']??dynVarGet($db,'owner_id');
                if($uid!==$ownerId&&$uid!==dynVarGet($db,'owner_id')){
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'🚫 <b>YOU DONT HAVE ADMIN RIGHTS</b>','parse_mode'=>'HTML'],$token);
                    http_response_code(200);exit;
                }
                if(preg_match('/^([a-zA-Z0-9_]+)\+\+(.+)$/',$query,$m)){
                    dynVarSet($db,$m[1],$m[2],'append_unique');$op="appended (unique) <code>{$m[2]}</code> to";
                }elseif(preg_match('/^([a-zA-Z0-9_]+)\+(.+)$/',$query,$m)){
                    dynVarSet($db,$m[1],$m[2],'append');$op="appended <code>{$m[2]}</code> to";
                }elseif(preg_match('/^([a-zA-Z0-9_]+)=(.*)$/',$query,$m)){
                    dynVarSet($db,$m[1],$m[2],'set');$op="set";
                }else{
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"❌ Usage:\n/save name=value\n/save name++value\n/save name+value"],$token);
                    http_response_code(200);exit;
                }
                saveDB($botId,$db);
                $varName=preg_match('/^([a-zA-Z0-9_]+)/',$query,$mn)?$mn[1]:'?';
                $curVal=dynVarGet($db,$varName);
                tg('sendMessage',['chat_id'=>$chatId,'text'=>"✅ Variable $op <b>{$varName}</b>\nCurrent: <code>$curVal</code>",'parse_mode'=>'HTML'],$token);
                http_response_code(200);exit;
            }

            if($cmdStr==='stop'){
                if(!empty($u['active_page'])){
                    $prevPage=$u['active_page'];
                    $u['active_page']='';
                    saveDB($botId,$db);
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'✅ <b>Mode deactivated.</b> Send /start to begin again.','parse_mode'=>'HTML'],$token);
                }else{
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'ℹ️ No active mode to stop.'],$token);
                }
                http_response_code(200);exit;
            }

            if($cmdStr==='broadcast'){
                if($uid===($s['adminId']??'')){
                    $bcMsg=trim(implode(' ',$args));
                    if($bcMsg){
                        $allUids=array_keys($db['users']??[]);$sent=0;$fail=0;
                        foreach($allUids as $tuid){
                            $r=tg('sendMessage',['chat_id'=>$tuid,'text'=>$bcMsg,'parse_mode'=>'HTML'],$token);
                            if($r['ok']??false)$sent++;else $fail++;
                            usleep(50000);
                        }
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>"📣 Broadcast done!\n✅ Sent: $sent\n❌ Failed: $fail",'parse_mode'=>'HTML'],$token);
                        addLog($botId,"Bot Broadcast: $sent sent, $fail failed",'info');
                    }
                }
                http_response_code(200);exit;
            }

            if($cmdStr==='admin'){
                $ownerId=$s['adminId']??'';
                if($uid!==($ownerId)){
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>'🚫 <b>Only the owner can use this command!</b>','parse_mode'=>'HTML'],$token);
                    http_response_code(200);exit;
                }

                $db['dyn_vars']['__admin_setup_step__']='waiting_video';
                $db['dyn_vars']['__admin_setup_chat__']=(string)$chatId;
                saveDB($botId,$db);
                tg('sendMessage',[
                    'chat_id'=>$chatId,
                    'text'=>"🎬 <b>Admin Setup Mode Active!</b>\n\n📹 <b>Step 1:</b> Please send me the <b>video</b> that new users will receive.\n\n<i>Send only the video — no other commands.</i>",
                    'parse_mode'=>'HTML'
                ],$token);
                http_response_code(200);exit;
            }

            if($cmdStr==='start'){
                if(!empty($u['active_page'])){
                    $u['active_page']='';
                    saveDB($botId,$db);
                }

                // --- Rose Help deeplink: /start help ---
                if(trim($query)==='help'&&!$isGroup){
                    $roseHelpMainKb=json_encode(['inline_keyboard'=>[
                        [['text'=>'👑 Admin','callback_data'=>'rose_help|admin'],['text'=>'🌊 Antiflood','callback_data'=>'rose_help|antiflood'],['text'=>'🛡 AntiRaid','callback_data'=>'rose_help|antiraid']],
                        [['text'=>'✅ Approval','callback_data'=>'rose_help|approval'],['text'=>'🚫 Bans','callback_data'=>'rose_help|bans'],['text'=>'📋 Blocklist','callback_data'=>'rose_help|blocklist']],
                        [['text'=>'🤖 CAPTCHA','callback_data'=>'rose_help|captcha'],['text'=>'🔗 Connections','callback_data'=>'rose_help|connections'],['text'=>'🔍 Filters','callback_data'=>'rose_help|filters']],
                        [['text'=>'🌐 Languages','callback_data'=>'rose_help|languages'],['text'=>'🔒 Locks','callback_data'=>'rose_help|locks'],['text'=>'📢 Log Channels','callback_data'=>'rose_help|logchannels']],
                        [['text'=>'📝 Notes','callback_data'=>'rose_help|notes'],['text'=>'📌 Pin','callback_data'=>'rose_help|pin'],['text'=>'🗑 Purges','callback_data'=>'rose_help|purges']],
                        [['text'=>'📊 Reports','callback_data'=>'rose_help|reports'],['text'=>'📜 Rules','callback_data'=>'rose_help|rules'],['text'=>'💬 Topics','callback_data'=>'rose_help|topics']],
                        [['text'=>'⚠️ Warnings','callback_data'=>'rose_help|warns'],['text'=>'👋 Welcome','callback_data'=>'rose_help|welcome'],['text'=>'👤 Users','callback_data'=>'rose_help|users']],
                    ]]);
                    tg('sendMessage',['chat_id'=>$chatId,'text'=>"👋 <b>Hi! I'm a group management bot.</b>\nAll commands are in the buttons below — tap a category!:\n\n<i>All commands can be used with: / !</i>",'parse_mode'=>'HTML','reply_markup'=>$roseHelpMainKb],$token);
                    http_response_code(200);exit;
                }

                $welcomeVideoId=$db['dyn_vars']['__welcome_video_file_id__']??'';
                $welcomeApkId=$db['dyn_vars']['__welcome_apk_file_id__']??'';
                $welcomeApkName=$db['dyn_vars']['__welcome_apk_name__']??'app.apk';
                if($welcomeVideoId){
                    tg('sendVideo',['chat_id'=>$chatId,'video'=>$welcomeVideoId,'parse_mode'=>'HTML'],$token);
                    usleep(500000); // 0.5s delay
                }
                if($welcomeApkId){
                    tg('sendDocument',['chat_id'=>$chatId,'document'=>$welcomeApkId,'caption'=>'📱 <b>Yeh rahi aapki APK!</b>','parse_mode'=>'HTML'],$token);
                    usleep(300000);
                }

            }

            foreach(($db['pages']??[]) as $p){

                if(!empty($p['is_free_text']))continue;
                if(strtolower(trim($p['trigger']??''))!==strtolower($cmdStr))continue;
                if(!empty($p['force_join'])&&!empty($fj['enabled'])){
                    if(!checkForceJoin($uid,$fj,$token)){sendForceJoinMsg($chatId,$fj,$token);http_response_code(200);exit;}
                }
                if(!hasAccess($uid,$chatId,$p['access_control']??'',$s['global_vars']??'')){
                    if(!empty($p['fallback_page'])){$fb=null;foreach(($db['pages']??[]) as $p2){if($p2['id']==$p['fallback_page']){$fb=$p2;break;}}if($fb)$p=$fb;else{http_response_code(200);exit;}}
                    else{http_response_code(200);exit;}
                }
                if($p['type']==='text'){
                    saveDB($botId,$db);
                    $rt=pv($p['text']??'',$u,$s,$query,$p['custom_vars']??'',null,null,$db);
                    $kb=buildKb($p['buttons']??[],$u,$s,$query,$p['custom_vars']??'');

                    $kb=injectOwnerEditBtn($kb,$p['id']??'',$uid,$s['adminId']??'');

                    if(!empty(trim($p['sticker_id']??''))){
                        $stkId=pv($p['sticker_id'],$u,$s,$query,$p['custom_vars']??'');
                        sendSticker($chatId,trim($stkId),$token);
                        usleep(300000);
                    }

                    if(!empty(trim($p['document_url']??''))){
                        $docUrl=pv($p['document_url'],$u,$s,$query,$p['custom_vars']??'',null,null,$db);
                        sendDocument($chatId,$docUrl,$rt,$kb,$token);
                    }else{
                        sendLong($botId,$chatId,null,$rt,$p['media_main']??'',$kb,false,$token);
                    }
                    addLog($botId,"Cmd: /$cmdStr by $name",'info');
                }else{
                    if(!empty($p['requires_credit'])&&empty($u['key'])&&($u['searchesLeft']??0)<=0){
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>'🔑 Quota empty. Use /redeem [key]'],$token);http_response_code(200);exit;
                    }
                    if(!$query&&$p['type']==='api'){
                        if(!empty(trim($p['msg_missing']??''))||!empty($p['media_missing']??''))
                            sendMsg($chatId,null,pv($p['msg_missing']??'🔍 Send something',$u,$s,$cmdStr,$p['custom_vars']??''),$p['media_missing']??'',null,false,$token);
                        http_response_code(200);exit;
                    }
                    if(!empty($p['requires_credit'])&&($u['searchesLeft']??0)!=999999)$u['searchesLeft']--;
                    $u['searches']=($u['searches']??0)+1;$db['stats']['searches']++;saveDB($botId,$db);
                    if($p['type']==='browser'){
                        execBrowser($botId,$chatId,null,$u,$db,$s,$query,$p,$token);
                    }else{
                        execPage($botId,$chatId,null,$u,$db,$s,$query,$p,$token);
                    }
                }
                http_response_code(200);exit;
            }
            http_response_code(200);exit;
        }

        $activePgId=$u['active_page']??'';
        if(str_starts_with($activePgId,'__brcap__')){
            $realPgId=substr($activePgId,9);
            $brPage=null;foreach(($db['pages']??[]) as $pg){if($pg['id']===$realPgId){$brPage=$pg;break;}}
            if($brPage){
                $u['active_page']='';saveDB($botId,$db);
                execBrowser($botId,$chatId,null,$u,$db,$s,$msgText,$brPage,$token,['captcha'=>$msgText,'__captcha_resume'=>true]);
            }
            http_response_code(200);exit;
        }
        // Link Automation captcha resume: user replied to captcha for a browser-mode LA rule
        if(str_starts_with($activePgId,'__lacap__')){
            $laRuleId=substr($activePgId,9);
            $laRule=null;
            $laRules=$s['link_automation']['rules']??[];
            foreach($laRules as $lr){if(($lr['id']??'')===($laRuleId))$laRule=$lr;}
            $u['active_page']='';saveDB($botId,$db);
            if($laRule){
                execLinkAutomationBrowser($botId,$chatId,$u,$db,$s,$msgText,$laRule,$token,['captcha'=>$msgText,'__lacap_resume'=>true]);
            }
            http_response_code(200);exit;
        }
        // Website Form Capture: user is filling a form triggered from website
        if(str_starts_with($activePgId,'__lafc__')){
            handleLaFormCapture($botId,$chatId,$u,$db,$s,$msgText,$token);
            http_response_code(200);exit;
        }
        if($activePgId){
            $activePg=null;
            foreach(($db['pages']??[]) as $pg){if($pg['id']===$activePgId){$activePg=$pg;break;}}
            if($activePg){

                $cm=$activePg['ft_chat_mode']??'both';
                if(empty(trim($cm)))$cm='both';
                $skip=($cm==='dm'&&$isGroup)||($cm==='group'&&!$isGroup);
                if(!$skip&&!empty($activePg['ft_mention_only'])&&$isGroup&&$botUsername){
                    if(stripos($msgText,'@'.$botUsername)===false)$skip=true;
                }
                if(!$skip){
                    if(!empty($activePg['requires_credit'])&&empty($u['key'])&&($u['searchesLeft']??0)<=0){
                        tg('sendMessage',['chat_id'=>$chatId,'text'=>'ð Quota empty. Use /redeem [key]'],$token);
                        http_response_code(200);exit;
                    }
                    if(!empty($activePg['requires_credit'])&&($u['searchesLeft']??0)!=999999)$u['searchesLeft']--;
                    $u['searches']=($u['searches']??0)+1;$db['stats']['searches']++;
                    saveDB($botId,$db);
                    if($activePg['type']==='text'){
                        $rt=pv($activePg['text']??'',$u,$s,$msgText,$activePg['custom_vars']??'',null,null,$db);
                        $kb=buildKb($activePg['buttons']??[],$u,$s,$msgText,$activePg['custom_vars']??'');
                        sendLong($botId,$chatId,null,$rt,$activePg['media_main']??'',$kb,false,$token);
                    }elseif($activePg['type']==='browser'){
                        execBrowser($botId,$chatId,null,$u,$db,$s,$msgText,$activePg,$token);
                    }else{
                        execPage($botId,$chatId,null,$u,$db,$s,$msgText,$activePg,$token);
                    }
                    addLog($botId,"ActivePage[{$activePgId}]: ".mb_substr($msgText,0,40)." by $name",'info');
                    http_response_code(200);exit;
                }

            }else{

                $u['active_page']='';saveDB($botId,$db);
            }
        }

        if(execLinkAutomation($botId,$chatId,$u,$db,$s,$msgText,$token)){http_response_code(200);exit;}
        handleFreeText($botId,$chatId,$isGroup,$uid,$u,$db,$s,$msgText,$token,$botUsername);
    }
    http_response_code(200);exit;
}

// ─── Website Form Capture Webhook ────────────────────────────────────────────
// Endpoint: ?la_webhook={botId}
// Website calls this with JSON: {rule_id, chat_id, fields:{name:value,...}}
// Bot asks user for each field, collects responses, submits back to fc_submit_url
if(isset($_GET['la_webhook'])){
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    if($_SERVER['REQUEST_METHOD']==='OPTIONS'){http_response_code(200);exit;}
    $laBotId=preg_replace('/[^a-zA-Z0-9_]/','_',$_GET['la_webhook']);
    $allBotsLa=loadBots();$laToken='';
    foreach($allBotsLa as $bLa){if($bLa['id']===$laBotId){$laToken=$bLa['token'];break;}}
    if(!$laToken){echo json_encode(['ok'=>false,'error'=>'Bot not found']);exit;}
    $laDb=loadDB($laBotId);$laS=$laDb['settings'];
    $laInput=json_decode(file_get_contents('php://input'),true)??[];
    $laAction=trim($laInput['action']??$_GET['la_action']??'start');
    $laChatId=trim($laInput['chat_id']??'');
    $laRuleId=trim($laInput['rule_id']??'');

    // Find matching rule
    $laRules=$laS['link_automation']['rules']??[];
    $laRule=null;
    foreach($laRules as $lr){if(($lr['id']??'')===$laRuleId){$laRule=$lr;break;}}
    if(!$laRule||empty($laRule['form_capture'])){echo json_encode(['ok'=>false,'error'=>'Rule not found or form_capture not enabled']);exit;}

    if($laAction==='start'){
        // Website initiates a form session — bot will ask the user fields
        if(!$laChatId){echo json_encode(['ok'=>false,'error'=>'chat_id required']);exit;}
        // Generate session token
        $laSessionToken=bin2hex(random_bytes(16));
        // Parse fields definition: "field_name|Prompt\nfield2|Prompt2"
        $laFieldDefs=[];
        foreach(explode("\n",trim($laRule['fc_fields']??'')) as $fl){
            $fl=trim($fl);if($fl==='')continue;
            $laParts=explode('|',$fl,2);
            $laFieldDefs[]=['key'=>trim($laParts[0]),'prompt'=>trim($laParts[1]??$laParts[0])];
        }
        if(empty($laFieldDefs)){echo json_encode(['ok'=>false,'error'=>'No fields defined in rule']);exit;}
        // Store session in user's active_page state
        $laUsers=$laDb['users']??[];$laUidKey=null;
        foreach($laUsers as $luk=>$luv){if((string)($luv['id']??'')===(string)$laChatId){$laUidKey=$luk;break;}}
        $laSession=[
            'token'=>$laSessionToken,
            'rule_id'=>$laRuleId,
            'fields'=>$laFieldDefs,
            'step'=>0,
            'answers'=>[],
            'submit_url'=>$laRule['fc_submit_url']??'',
            'fc_headers'=>$laRule['fc_headers']??'',
            'success_msg'=>$laRule['fc_success_msg']??'✅ Form submit ho gaya!',
        ];
        // Store session keyed by chat_id
        if(!isset($laDb['la_fc_sessions']))$laDb['la_fc_sessions']=[];
        $laDb['la_fc_sessions'][(string)$laChatId]=$laSession;
        // Set user active_page to special form-capture state
        if($laUidKey!==null){$laDb['users'][$laUidKey]['active_page']='__lafc__'.$laChatId;}
        else{
            // User may not exist yet — create minimal entry
            $laDb['users'][]=['id'=>$laChatId,'name'=>'User','active_page'=>'__lafc__'.$laChatId,'searchesLeft'=>0,'searches'=>0,'banned'=>false];
        }
        saveDB($laBotId,$laDb);
        // Send first prompt to user via bot
        $firstPrompt=$laFieldDefs[0]['prompt'];
        tg('sendMessage',['chat_id'=>$laChatId,'text'=>$firstPrompt,'parse_mode'=>'HTML'],$laToken);
        echo json_encode(['ok'=>true,'session_token'=>$laSessionToken,'message'=>'Form session started, bot asked first field']);exit;
    }

    // status action — check if session is complete
    if($laAction==='status'){
        $laSessions=$laDb['la_fc_sessions']??[];
        $laSess=$laSessions[(string)$laChatId]??null;
        if(!$laSess){echo json_encode(['ok'=>true,'status'=>'not_found']);exit;}
        if(isset($laSess['completed'])){echo json_encode(['ok'=>true,'status'=>'completed','answers'=>$laSess['answers']??[]]);exit;}
        echo json_encode(['ok'=>true,'status'=>'pending','step'=>$laSess['step'],'total'=>count($laSess['fields'])]);exit;
    }
    echo json_encode(['ok'=>false,'error'=>'Unknown la_action']);exit;
}

// ─── Form Capture Bot Reply Handler ──────────────────────────────────────────
// Processes __lafc__{chatId} active_page state in webhook flow
function handleLaFormCapture($botId,$chatId,$u,&$db,$s,$msgText,$token){
    $sessions=$db['la_fc_sessions']??[];
    $sess=$sessions[(string)$chatId]??null;
    if(!$sess)return false;
    // Store answer for current step
    $step=(int)($sess['step']??0);
    $fields=$sess['fields']??[];
    if(!isset($fields[$step]))return false;
    $fieldKey=$fields[$step]['key'];
    $sess['answers'][$fieldKey]=$msgText;
    $sess['step']=$step+1;
    // Next step or submit
    if($sess['step']<count($fields)){
        // Ask next field
        $nextPrompt=$fields[$sess['step']]['prompt'];
        tg('sendMessage',['chat_id'=>$chatId,'text'=>$nextPrompt,'parse_mode'=>'HTML'],$token);
        $db['la_fc_sessions'][(string)$chatId]=$sess;
        saveDB($botId,$db);
        return true;
    }
    // All fields collected — POST answers to submit_url
    $submitUrl=trim($sess['submit_url']??'');
    $submitOk=false;
    if($submitUrl!==''){
        $postData=array_merge($sess['answers'],['chat_id'=>$chatId,'la_session_token'=>$sess['token']??'']);
        $postJson=json_encode($postData,JSON_UNESCAPED_UNICODE);
        $fcHeaders='Content-Type: application/json';
        if(!empty($sess['fc_headers'])){
            $fcHeaders.="\n".$sess['fc_headers'];
        }
        $curlResult=doCurl($submitUrl,'POST',$fcHeaders,$postJson,30);
        $submitOk=($curlResult['code']>=200&&$curlResult['code']<300);
    }
    // Send success message to user
    $successMsg=$sess['success_msg']??'✅ Form submit ho gaya!';
    tg('sendMessage',['chat_id'=>$chatId,'text'=>$successMsg,'parse_mode'=>'HTML'],$token);
    // Mark session completed and clear user's active_page
    $sess['completed']=true;
    $db['la_fc_sessions'][(string)$chatId]=$sess;
    // Clear active_page
    foreach($db['users'] as &$lusr){
        if((string)($lusr['id']??'')===(string)$chatId){
            $lusr['active_page']='';break;
        }
    }
    unset($lusr);
    saveDB($botId,$db);
    addLog($botId,'LA Form Capture complete for chat '.$chatId.($submitOk?' (submitted OK)':' (submit_url empty or failed)'),'success');
    return true;
}

// ─── Python Aadhaar Bot Webhook ──────────────────────────────────────────
if(isset($_GET['py_webhook'])){
    $abCfg=lrLoadConfig();
    $abTok=trim($abCfg['py_bot_token']??'');
    $abUpdate=json_decode(file_get_contents('php://input'),true);
    if(!is_array($abUpdate)){http_response_code(200);exit;}
    $abMsg=$abUpdate['message']??$abUpdate['channel_post']??null;
    if($abMsg&&$abTok){
        $abChatId=(string)($abMsg['chat']['id']??'');
        $abText=trim($abMsg['text']??'');
        $abCmd=strtolower(explode(' ',$abText)[0]??'');
        $abFetchCmd=trim($abCfg['py_fetch_cmd']??'/fetch');
        $abCancelCmd=trim($abCfg['py_cancel_cmd']??'/cancel');
        $abRefreshCmd=trim($abCfg['py_refresh_cmd']??'/refresh');

        // ── Active session check ─────────────────────────────
        $abSession=lrSessionGet($abChatId);
        if($abSession){
            if($abCmd===$abCancelCmd||$abCmd==='/cancel'){
                lrSessionDel($abChatId);
                $cancelMsg=str_replace('\n',"\n",$abCfg['py_cancel_msg']??'❌ Process cancel kar diya.');
                lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>$cancelMsg,'parse_mode'=>'HTML'],$abTok);
                lrLog("PY-BOT: session cancelled — chat={$abChatId}",'info');
                http_response_code(200);exit;
            }
            // Process session answer
            $abStep=$abSession['step']??0;
            $abFields=$abSession['fields']??[];
            if(isset($abFields[$abStep])){
                $abSession['answers'][$abFields[$abStep]]=$abText;
                $abSession['step']=$abStep+1;
                lrSessionSet($abChatId,$abSession);
                if($abSession['step']<count($abFields)){
                    $abNextLabel=$abSession['field_labels'][$abSession['step']]??$abFields[$abSession['step']];
                    $abTotal=count($abFields);$abCurr=$abSession['step']+1;
                    lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>"✏️ <b>".htmlspecialchars($abNextLabel,ENT_QUOTES)."</b> dalo: <i>({$abCurr}/{$abTotal})</i>\n<i>(ya {$abCancelCmd} likho)</i>",'parse_mode'=>'HTML'],$abTok);
                    http_response_code(200);exit;
                }
                // All fields done — submit
                lrSessionDel($abChatId);
                lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>str_replace('\n',"\n",$abCfg['py_success_msg']??'✅ Done!'),'parse_mode'=>'HTML'],$abTok);
                lrLog("PY-BOT: form complete — chat={$abChatId}",'success');
            }
            http_response_code(200);exit;
        }

        // ── /start ───────────────────────────────────────────
        if($abCmd==='/start'){
            $abStartMsg=str_replace('\n',"\n",$abCfg['py_start_msg']??'👾 Aadhaar Bot online!');
            lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>$abStartMsg,'parse_mode'=>'HTML'],$abTok);
            lrLog("PY-BOT: /start — chat={$abChatId}",'info');
        }
        // ── /fetch command ────────────────────────────────────
        elseif($abCmd===$abFetchCmd||str_starts_with(strtolower($abText),strtolower($abFetchCmd).' ')){
            $abLoadingRaw=trim($abCfg['py_loading_steps']??'');
            $abSteps=array_filter(array_map('trim',explode("\n",$abLoadingRaw)),fn($s)=>$s!=='');
            foreach($abSteps as $abStep2){
                lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>$abStep2,'parse_mode'=>'HTML'],$abTok);
                usleep(800000); // 0.8s delay between steps
            }
            // After loading — show captcha message
            $abCapMsg=str_replace('\n',"\n",$abCfg['py_captcha_msg']??'📸 Captcha enter karo:');
            lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>$abCapMsg,'parse_mode'=>'HTML'],$abTok);
            // Start a session for captcha → OTP flow
            lrSessionSet($abChatId,['type'=>'adhar_flow','step'=>0,'fields'=>['captcha','otp'],'field_labels'=>['📸 Captcha','🔢 OTP'],'answers'=>[],'link_id'=>'adhar_fetch']);
            lrLog("PY-BOT: /fetch started — chat={$abChatId}",'info');
        }
        // ── Unknown ───────────────────────────────────────────
        else{
            $abStartMsg=str_replace('\n',"\n",$abCfg['py_start_msg']??'👾 Aadhaar Bot online!');
            lrTg('sendMessage',['chat_id'=>$abChatId,'text'=>$abStartMsg,'parse_mode'=>'HTML'],$abTok);
        }
    }
    http_response_code(200);exit;
}

// ─── RBD (Deposit Bot) Webhook ───────────────────────────────────────────
if(isset($_GET['rbd_webhook'])){
    $rbdCfg=rbdLoadConfig();
    $rbdUpdate=json_decode(file_get_contents('php://input'),true);
    if(is_array($rbdUpdate))rbdHandleUpdate($rbdUpdate,$rbdCfg);
    http_response_code(200);exit;
}

// ─── Link Runner Webhook ─────────────────────────────────────────────────
if(isset($_GET['lr_webhook'])){
    $lrCfg=lrLoadConfig();$lrWToken=trim($lrCfg['webhook_token']?:$lrCfg['bot_token']);
    $lrUpdate=json_decode(file_get_contents('php://input'),true);
    if(!is_array($lrUpdate)){http_response_code(200);exit;}
    $lrMsg=$lrUpdate['message']??$lrUpdate['channel_post']??null;
    if($lrMsg){
        $lrText=trim($lrMsg['text']??'');
        $lrChatId=(string)($lrMsg['chat']['id']??'');
        $lrCmd=trim($lrCfg['webhook_cmd']??'/run');

        // ── Active form-fill session check ──────────────────
        $lrSession=lrSessionGet($lrChatId);
        if($lrSession){
            if(strtolower($lrText)==='/cancel'){
                lrSessionDel($lrChatId);
                lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>'❌ Form fill cancelled.','parse_mode'=>'HTML'],$lrWToken);
                http_response_code(200);exit;
            }
            $lrSession['answers'][$lrSession['fields'][$lrSession['step']]]=$lrText;
            $lrSession['step']++;
            lrSessionSet($lrChatId,$lrSession);
            if($lrSession['step']<count($lrSession['fields'])){
                $lrNextLabel=$lrSession['field_labels'][$lrSession['step']]??$lrSession['fields'][$lrSession['step']];
                $lrTotal=count($lrSession['fields']);$lrCurr=$lrSession['step']+1;
                lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>"✏️ <b>".htmlspecialchars($lrNextLabel,ENT_QUOTES)."</b> dalo: <i>({$lrCurr}/{$lrTotal})</i>\n<i>(ya /cancel)</i>",'parse_mode'=>'HTML'],$lrWToken);
                http_response_code(200);exit;
            }
            // All fields collected — find link and submit
            $lrFormLink=null;foreach($lrCfg['links'] as $lk){if(($lk['id']??'')===$lrSession['link_id']){$lrFormLink=$lk;break;}}
            if(!$lrFormLink){lrSessionDel($lrChatId);lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>'⚠️ Link config nahi mila.'],$lrWToken);http_response_code(200);exit;}
            $lrVars=array_merge(['ts'=>date('Y-m-d H:i:s'),'date'=>date('Y-m-d'),'time'=>date('H:i:s')],$lrSession['answers']);
            $lrFillUrl=lrReplace(trim($lrFormLink['url']??''),$lrVars);$lrFillH=lrReplace(trim($lrFormLink['headers']??''),$lrVars);$lrFillB=lrReplace(trim($lrFormLink['body']??''),$lrVars);
            if(empty($lrFillB)&&strtoupper($lrFormLink['method']??'GET')==='POST'){$lrFillB=http_build_query($lrSession['answers']);if(empty($lrFillH))$lrFillH='Content-Type: application/x-www-form-urlencoded';}
            $lrTo=max(5,min(120,(int)($lrFormLink['timeout']??30)));$lrSSL=!isset($lrFormLink['ssl_verify'])||(bool)$lrFormLink['ssl_verify'];
            $lrFillRes=lrFetch($lrFillUrl,strtoupper($lrFormLink['method']??'POST'),$lrFillH,$lrFillB,$lrTo,$lrSSL);
            lrSessionDel($lrChatId);
            $lrOk2=$lrFillRes['code']>=200&&$lrFillRes['code']<400;
            $lrSummary=$lrOk2?"✅ <b>Form submit ho gaya!</b>\nHTTP: <code>{$lrFillRes['code']}</code>":"⚠️ <b>Submit fail hua.</b>\nHTTP: <code>{$lrFillRes['code']}</code>\n<pre>".htmlspecialchars(mb_substr($lrFillRes['body']??'',0,300))."</pre>";
            lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>$lrSummary,'parse_mode'=>'HTML'],$lrWToken);
            lrLog("Form fill [{$lrSession['link_id']}] → HTTP {$lrFillRes['code']}",$lrOk2?'success':'error');
            http_response_code(200);exit;
        }

        // ── /fill command ────────────────────────────────────
        if(str_starts_with(strtolower($lrText),'/fill')){
            $lrParts=explode(' ',$lrText,2);$lrSearch=strtolower(trim($lrParts[1]??''));$lrFound=null;
            foreach($lrCfg['links'] as $lk){if(!empty($lk['form_fill_mode'])&&(strtolower($lk['name']??'')===$lrSearch||strtolower($lk['id']??'')===$lrSearch||$lrSearch==='')){$lrFound=$lk;break;}}
            if(!$lrFound){
                $lrList=array_filter($lrCfg['links'],fn($l)=>!empty($l['form_fill_mode']));
                if(empty($lrList))lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>'⚠️ Koi form-fill link configure nahi hai.','parse_mode'=>'HTML'],$lrWToken);
                else{$lrNames=implode("\n",array_map(fn($l)=>"• <code>".htmlspecialchars($l['name'])."</code>",$lrList));lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>"📋 Available forms:\n{$lrNames}\n\n/fill &lt;name&gt; likho",'parse_mode'=>'HTML'],$lrWToken);}
                http_response_code(200);exit;
            }
            $lrManFields=array_values(array_filter(array_map('trim',explode(',',$lrFound['form_fields']??'')),fn($f)=>$f!==''));
            if(!empty($lrManFields)){$lrFieldMap=[];foreach($lrManFields as $f)$lrFieldMap[$f]=$f;}
            else{
                lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>'🔍 Site ke form fields detect ho rahe hain...','parse_mode'=>'HTML'],$lrWToken);
                $lrPageUrl=lrReplace(trim($lrFound['url']??''),['ts'=>date('Y-m-d H:i:s'),'date'=>date('Y-m-d'),'time'=>date('H:i:s')]);
                $lrFieldMap=lrDetectFormFields($lrPageUrl,20);
                if(empty($lrFieldMap)){lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>"⚠️ Auto-detect fail hua.\nAdmin panel mein <b>Form Fields</b> manually likho.",'parse_mode'=>'HTML'],$lrWToken);http_response_code(200);exit;}
            }
            $lrFN=array_keys($lrFieldMap);$lrFL=array_values($lrFieldMap);
            lrSessionSet($lrChatId,['link_id'=>$lrFound['id'],'fields'=>$lrFN,'field_labels'=>$lrFL,'step'=>0,'answers'=>[]]);
            lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>"📝 <b>".htmlspecialchars($lrFound['name'])."</b> form shuru!\n\n✏️ <b>".htmlspecialchars($lrFL[0])."</b> dalo:\n<i>(ya /cancel)</i>",'parse_mode'=>'HTML'],$lrWToken);
            http_response_code(200);exit;
        }

        // ── Normal /run command ──────────────────────────────
        if(str_starts_with(strtolower($lrText),strtolower($lrCmd))){
            lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>'⏳ Running links...','parse_mode'=>'HTML'],$lrWToken);
            $lrResults=lrRunAll($lrCfg,['tg_chat'=>$lrChatId]);
            $lrOk=count(array_filter($lrResults,fn($r)=>!$r['failed']));$lrTot=count($lrResults);
            lrTg('sendMessage',['chat_id'=>$lrChatId,'text'=>"✅ <b>Link Runner Done!</b>\n\n📊 Results: <code>{$lrOk}/{$lrTot}</code> success",'parse_mode'=>'HTML'],$lrWToken);
        }
    }
    http_response_code(200);exit;
}

// ─── Link Runner URL trigger (?lr_run=1&secret=X) ────────────────────────
if(isset($_GET['lr_run'])){
    $lrCfg2=lrLoadConfig();$lrSecret=$_GET['secret']??'';
    if($lrSecret!==$lrCfg2['run_secret']){http_response_code(403);echo json_encode(['ok'=>false,'error'=>'Invalid secret']);exit;}
    header('Content-Type: application/json');$lrRes2=lrRunAll($lrCfg2);
    echo json_encode(['ok'=>true,'results'=>$lrRes2,'total'=>count($lrRes2),'success'=>count(array_filter($lrRes2,fn($r)=>!$r['failed']))]);exit;
}

if(session_status()===PHP_SESSION_NONE){session_start();}
$savedActId=$_SESSION['act']??'';
$actName='No bot selected';
foreach(loadBots() as $b){if($b['id']===$savedActId){$actName=$b['name'].' (@'.($b['username']??'?').')';break;}}
function san($x){return htmlspecialchars(strip_tags(trim($x)),ENT_QUOTES,'UTF-8');}
function jout($d){header('Content-Type: application/json');echo json_encode($d);exit;}
$page=san($_GET['page']??'panel');
$action=preg_replace('/[^a-zA-Z0-9_]/','',($_POST['action']??$_GET['action']??''));
if($page==='login'){
    if($_SERVER['REQUEST_METHOD']==='POST'){
        $clientIp=$_SERVER['HTTP_CF_CONNECTING_IP']??$_SERVER['HTTP_X_REAL_IP']??$_SERVER['REMOTE_ADDR']??'unknown';
        $lockedSecs=getLoginLockedSecs($clientIp);
        if(isLoginRateLimited($clientIp)){
            $loginErr='Too many failed attempts. Try again in '.ceil($lockedSecs/60).' min.';
        }elseif(!verifyCsrf()){
            $loginErr='Invalid security token. Please refresh and try again.';
        }elseif(($_POST['user']??'')===ADMIN_USER&&verifyAdminPassword($_POST['pass']??'')){
            clearLoginFails($clientIp);
            session_regenerate_id(true);
            $_SESSION['rebel_ok']=true;
            header('Location: ?page=panel');exit;
        }else{
            recordLoginFail($clientIp);
            $loginErr='Wrong credentials!';
        }
    }
    goto RENDER;
}
if($page==='logout'){session_unset();session_destroy();header('Location: ?page=login');exit;}
if(empty($_SESSION['rebel_ok'])){header('Location: ?page=login');exit;}
if(empty($_SESSION['act'])){
    $_botsAuto=loadBots();
    if(!empty($_botsAuto))$_SESSION['act']=$_botsAuto[0]['id'];
}
$savedActId=$_SESSION['act']??'';
$actName='No bot selected';
foreach(loadBots() as $b){if($b['id']===$savedActId){$actName=$b['name'].' (@'.($b['username']??'?').')';break;}}
// CSRF guard for all admin POST API calls (JSON body carries token via header)
if($page==='api'&&$_SERVER['REQUEST_METHOD']==='POST'&&!verifyCsrf()){
    jout(['ok'=>false,'error'=>'CSRF validation failed. Please reload the page.']);
}

if($page==='api'){
    $bots=loadBots();$body=json_decode(file_get_contents('php://input'),true)??[];
    $actId=$body['botId']??$_SESSION['act']??'';

    if($action==='get_users'){
        if(!$actId){jout(['ok'=>false,'error'=>'No bot selected. Go to Bots tab and click Select on your bot.']);}
        $uPage=max(1,(int)($body['page']??1));
        $uLimit=max(10,min(100,(int)($body['limit']??30)));
        $uSearch=trim($body['search']??'');
        jout(['ok'=>true]+getUsersPage($actId,$uPage,$uLimit,$uSearch));
    }

    if($action==='repair_users'&&$actId){
        @unlink(usersIndexFile($actId));
        $users=loadUsersRaw($actId);
        if(!empty($users)){saveUsersRaw($actId,$users);usersStripFromDataJson($actId);}
        $idx=rebuildUsersIndex($actId);
        jout(['ok'=>true,'total'=>$idx['total']??0,'message'=>'Users repaired']);
    }

    $TOK='';
    foreach($bots as $b){if($b['id']===$actId){$TOK=$b['token'];break;}}
    if($actId){$db=loadDB($actId);$db['pages']??=[];$db['users']??=[];$db['ukeys']??=[];$db['lkeys']??=[];$db['stats']??=['searches'=>0,'cmds'=>0];$db['settings']??=[];$db['dyn_vars']??=[];}
    else{$db=['users'=>[],'ukeys'=>[],'lkeys'=>[],'stats'=>['searches'=>0,'cmds'=>0],'settings'=>[],'pages'=>[],'dyn_vars'=>[]];}
    switch($action){
        case 'upload_media':
            if(isset($_FILES['file'])&&$_FILES['file']['error']==0&&$actId){
                $dir=getBotDir($actId).'uploads/';$ext=strtolower(pathinfo($_FILES['file']['name'],PATHINFO_EXTENSION));
                $blockedExt=['php','phtml','php3','php4','php5','phar','cgi','pl','py','sh','bash'];
                if(in_array($ext,$blockedExt,true))jout(['ok'=>false,'error'=>'File type not allowed']);
                $fn=uniqid('m_').'.'.$ext;
                if(move_uploaded_file($_FILES['file']['tmp_name'],$dir.$fn)){
                    $pr=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https://':'http://';
                    $url=$pr.$_SERVER['HTTP_HOST'].dirname($_SERVER['REQUEST_URI']).'/bots/'.$actId.'/uploads/'.$fn;
                    jout(['ok'=>true,'url'=>$url]);
                }
            }
            jout(['ok'=>false,'error'=>'Upload failed']);break;
        case 'get_bots':
            $list=[];foreach($bots as $b){$b['active']=($b['id']===$actId);$list[]=$b;}
            jout(['ok'=>true,'data'=>$list,'active_id'=>$actId]);break;
        case 'add_bot':
            $t=trim($body['token']??'');if(!$t)jout(['ok'=>false,'error'=>'Token required']);
            $check=tg('getMe',[],$t);if(empty($check['ok']))jout(['ok'=>false,'error'=>'Invalid token: '.($check['description']??'')]);
            $nId=uniqid('bot_');
            $bots[]=['id'=>$nId,'token'=>$t,'name'=>$check['result']['first_name'],'username'=>$check['result']['username']??'','maintenance'=>false,'free_searches'=>3];
            saveBots($bots);if(count($bots)===1)$_SESSION['act']=$nId;loadDB($nId);jout(['ok'=>true]);break;
        case 'set_active_bot':$_SESSION['act']=$body['botId']??'';jout(['ok'=>true]);break;
        case 'delete_bot':$bots=array_values(array_filter($bots,fn($b)=>$b['id']!==$body['botId']));saveBots($bots);jout(['ok'=>true]);break;
        case 'bot_info':
            if(!$TOK)jout(['ok'=>false]);
            $me=tg('getMe',[],$TOK);$wh=tg('getWebhookInfo',[],$TOK);
            $cc=null;foreach($bots as $b){if($b['id']===$actId){$cc=$b;break;}}
            jout(['ok'=>true,'data'=>$me['result']??null,'webhook'=>$wh['result']??null,'active_name'=>$me['result']['first_name']??'Bot','bot_config'=>$cc]);break;
        case 'save_bot_config':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot']);
            foreach($bots as $k=>$b){if($b['id']===$actId){$bots[$k]['maintenance']=(bool)$body['maintenance'];$bots[$k]['free_searches']=(int)$body['free_searches'];break;}}
            saveBots($bots);jout(['ok'=>true]);break;
        case 'start_bot':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $pr=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https://':'http://';
            $url=$pr.$_SERVER['HTTP_HOST'].explode('?',$_SERVER['REQUEST_URI'])[0].'?webhook_bot='.$actId;
            // Generate or reuse webhook secret token for this bot
            $wSecret='';
            foreach($bots as $bk=>$bv){
                if($bv['id']===$actId){
                    if(empty($bv['webhook_secret'])){
                        $wSecret=bin2hex(random_bytes(32));
                        $bots[$bk]['webhook_secret']=$wSecret;
                        saveBots($bots);
                    }else{$wSecret=$bv['webhook_secret'];}
                    break;
                }
            }
            $whParams=['url'=>$url,'allowed_updates'=>['message','callback_query','inline_query','chosen_inline_result']];
            if($wSecret)$whParams['secret_token']=$wSecret;
            $r=tg('setWebhook',$whParams,$TOK);addLog($actId,'Engine Started','success');jout(['ok'=>$r['ok']??false]);break;
        case 'stop_bot':tg('deleteWebhook',[],$TOK);addLog($actId,'Engine Stopped','warn');jout(['ok'=>true]);break;
        case 'get_stats':
            $uCnt=(loadUsersIndex($actId)['total']??count($db['users']));
            jout(['ok'=>true,'data'=>['users'=>$uCnt,'searches'=>$db['stats']['searches']??0,'cmds'=>$db['stats']['cmds']??0,'keys'=>count($db['ukeys'])+count($db['lkeys'])]]);break;
        case 'get_users':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot selected. Go to Bots tab and click Select on your bot.']);
            $uPage=max(1,(int)($body['page']??1));
            $uLimit=max(10,min(100,(int)($body['limit']??30)));
            jout(['ok'=>true]+getUsersPage($actId,$uPage,$uLimit,trim($body['search']??'')));break;
        case 'delete_user':unset($db['users'][$body['uid']]);saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'ban_user':$db['users'][$body['uid']]['banned']=true;saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'unban_user':$db['users'][$body['uid']]['banned']=false;saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'get_ukeys':jout(['ok'=>true,'data'=>$db['ukeys']]);break;
        case 'delete_ukey':$db['ukeys']=array_values(array_filter($db['ukeys'],fn($k)=>$k['id']!==$body['id']));saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'get_lkeys':jout(['ok'=>true,'data'=>$db['lkeys']]);break;
        case 'delete_lkey':$db['lkeys']=array_values(array_filter($db['lkeys'],fn($k)=>$k['id']!==$body['id']));saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'gen_keys':
            $type=$body['type']??'USER';$tier=$body['tier']??'STD';$qty=(int)($body['qty']??1);$srch=(int)($body['searches']??100);$days=(int)($body['days']??30);$kg=[];
            for($i=0;$i<$qty;$i++){$ch='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';$k='';for($j=0;$j<15;$j++)$k.=$ch[random_int(0,strlen($ch)-1)];$k=$type.'-'.chunk_split($k,5,'-').date('y');$kg[]=$k;$obj=['id'=>uniqid('k_'),'key'=>$k,'tier'=>$tier,'searches'=>$srch,'days'=>$days,'status'=>'unused','created'=>date('Y-m-d')];if($type==='LIC')$db['lkeys'][]=$obj;else $db['ukeys'][]=$obj;}
            saveDB($actId,$db);jout(['ok'=>true,'keys'=>$kg]);break;
        case 'get_settings':jout(['ok'=>true,'data'=>['settings'=>$db['settings']]]);break;
        case 'change_admin_pass':
            $cur=$body['current']??'';$new=$body['new']??'';
            if(!verifyAdminPassword($cur))jout(['ok'=>false,'error'=>'Current password wrong']);
            if(strlen($new)<1)jout(['ok'=>false,'error'=>'New password cannot be empty']);
            $cf=__DIR__.'/.admin_pass';file_put_contents($cf,$new,LOCK_EX);chmod($cf,0600);
            jout(['ok'=>true,'note'=>'Password updated successfully.']);break;
        case 'save_settings':$db['settings']=array_merge($db['settings'],$body['settings']??[]);saveDB($actId,$db);jout(['ok'=>true]);break;

        case 'get_force_join':
            jout(['ok'=>true,'data'=>$db['settings']['force_join']??['enabled'=>false,'channels'=>[],'message'=>'','media'=>'','buttons'=>[]]]);break;
        case 'save_force_join':
            $fj=$body['fj']??[];
            $db['settings']['force_join']=['enabled'=>(bool)($fj['enabled']??false),'channels'=>array_values(array_filter($fj['channels']??[],fn($c)=>!empty(trim($c['id']??'')))),'message'=>$fj['message']??'⚠️ Please join our channels first!','media'=>$fj['media']??'','buttons'=>array_values(array_filter($fj['buttons']??[],fn($b)=>!empty(trim($b['text']??''))))];
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'get_api_keys':jout(['ok'=>true,'data'=>$db['settings']['api_keys']??[]]);break;
        case 'save_api_key':
            $db['settings']['api_keys']??=[];
            $nk=['id'=>!empty($body['id'])?$body['id']:uniqid('ak_'),'name'=>strtoupper(preg_replace('/[^a-zA-Z0-9_]/','_',$body['name']??'')),'value'=>$body['value']??'','desc'=>$body['desc']??''];
            $found=false;foreach($db['settings']['api_keys'] as $ki=>$kv){if($kv['id']===$nk['id']){$db['settings']['api_keys'][$ki]=$nk;$found=true;break;}}
            if(!$found)$db['settings']['api_keys'][]=$nk;
            saveDB($actId,$db);jout(['ok'=>true,'data'=>$nk]);break;
        case 'delete_api_key':$db['settings']['api_keys']=array_values(array_filter($db['settings']['api_keys']??[],fn($k)=>$k['id']!==$body['id']));saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'get_bot_vars':jout(['ok'=>true,'data'=>$db['settings']['bot_vars']??'']);break;
        case 'save_bot_vars':$db['settings']['bot_vars']=$body['bot_vars']??'';saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'get_dyn_vars':jout(['ok'=>true,'data'=>$db['dyn_vars']??[]]);break;
        case 'set_dyn_var':
            $vk=preg_replace('/[^a-zA-Z0-9_]/','_',$body['key']??'');$vv=$body['value']??'';
            if($vk){$db['dyn_vars'][$vk]=$vv;saveDB($actId,$db);jout(['ok'=>true]);}
            else jout(['ok'=>false,'error'=>'Invalid key']);break;
        case 'delete_dyn_var':
            $vk=preg_replace('/[^a-zA-Z0-9_]/','_',$body['key']??'');
            unset($db['dyn_vars'][$vk]);saveDB($actId,$db);jout(['ok'=>true]);break;

        case 'parse_curl':$r=parseCurl($body['curl']??'');jout(['ok'=>true,'parsed'=>$r]);break;

        case 'parse_python':
            $py=trim($body['python']??'');
            $pr=['method'=>'POST','url'=>'','headers_str'=>'','body'=>''];
            if($py){

                if(preg_match('/requests\.\w+\(\s*[\'"]([^\'"]+)[\'"]/u',$py,$m))$pr['url']=$m[1];

                if(preg_match('/requests\.(get|post|put|delete|patch)\(/iu',$py,$m))$pr['method']=strtoupper($m[1]);

                $headers=[];
                if(preg_match('/headers\s*=\s*\{([^}]+)\}/su',$py,$m)){
                    preg_match_all('/[\'"]([^\'"]+)[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]/u',$m[1],$hm);
                    foreach($hm[1] as $i=>$hk)$headers[]=$hk.': '.$hm[2][$i];
                }
                $pr['headers_str']=implode("\n",$headers);

                if(preg_match('/json\s*=\s*(\{[^)]+\})/su',$py,$m))$pr['body']=$m[1];

                elseif(preg_match('/data\s*=\s*[\'"]([^\'"]+)[\'"]/u',$py,$m))$pr['body']=$m[1];

                elseif(preg_match('/data\s*=\s*(\{[^)]+\})/su',$py,$m))$pr['body']=$m[1];
            }
            jout(['ok'=>true,'parsed'=>$pr]);break;
        case 'get_pages':jout(['ok'=>true,'data'=>$db['pages']??[]]);break;
        case 'import_pages':
            $imp=$body['pages']??[];if(!is_array($imp))jout(['ok'=>false,'error'=>'Invalid']);
            foreach($imp as $np){$f=false;foreach(($db['pages']??[]) as $ki=>$kv){if($kv['id']==$np['id']){$db['pages'][$ki]=$np;$f=true;break;}}if(!$f)$db['pages'][]=$np;}
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'save_page':
            if(!$actId)jout(['ok'=>false,'error'=>'No Bot']);
            $np=['id'=>strtolower(preg_replace('/[^a-zA-Z0-9_]/','_',$body['id']?:uniqid('pg_'))),'trigger'=>strtolower(preg_replace('/[^a-zA-Z0-9_]/','_',$body['trigger']??'')),'type'=>$body['type']??'text','is_free_text'=>(bool)($body['is_free_text']??false),'ft_chat_mode'=>$body['ft_chat_mode']??'both','ft_mention_only'=>(bool)($body['ft_mention_only']??false),'ft_access_control'=>$body['ft_access_control']??'','force_join'=>(bool)($body['force_join']??false),'access_control'=>$body['access_control']??'','fallback_page'=>$body['fallback_page']??'','requires_credit'=>(bool)($body['requires_credit']??false),'media_main'=>$body['media_main']??'','media_missing'=>$body['media_missing']??'','media_error'=>$body['media_error']??'','document_url'=>$body['document_url']??'','custom_vars'=>$body['custom_vars']??'','text'=>$body['text']??'','api_url'=>$body['api_url']??'','json_root'=>$body['json_root']??'','not_found'=>$body['not_found']??'','msg_missing'=>$body['msg_missing']??'','msg_loading'=>$body['msg_loading']??'','loading_steps'=>$body['loading_steps']??[],'api_timeout'=>(int)($body['api_timeout']??15),'api_retry'=>(bool)($body['api_retry']??false),'buttons'=>$body['buttons']??[],'curl_url'=>$body['curl_url']??'','curl_method'=>$body['curl_method']??'POST','curl_headers'=>$body['curl_headers']??'','curl_body'=>$body['curl_body']??'','curl_response_path'=>$body['curl_response_path']??'','curl_timeout'=>(int)($body['curl_timeout']??120),'browser_var_names'=>$body['browser_var_names']??'','browser_done_msg'=>$body['browser_done_msg']??'✅ Done!','browser_steps'=>$body['browser_steps']??[],'sticker_id'=>$body['sticker_id']??''];
            if(!$np['id'])jout(['ok'=>false,'error'=>'ID required']);
            $f=false;foreach(($db['pages']??[]) as $ki=>$kv){if($kv['id']==$np['id']){$db['pages'][$ki]=$np;$f=true;break;}}
            if(!$f)$db['pages'][]=$np;saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'delete_page':$db['pages']=array_values(array_filter($db['pages'],fn($c)=>$c['id']!==$body['id']));saveDB($actId,$db);jout(['ok'=>true]);break;

        case 'get_stickers':jout(['ok'=>true,'data'=>loadStickers($actId)]);break;
        case 'delete_sticker':
            $lib=loadStickers($actId);
            $lib=array_values(array_filter($lib,fn($s)=>$s['id']!==($body['id']??'')));
            saveStickers($actId,$lib);jout(['ok'=>true]);break;
        case 'rename_sticker':
            $lib=loadStickers($actId);
            foreach($lib as &$s){if($s['id']===($body['id']??'')){$s['label']=htmlspecialchars($body['label']??$s['label'],ENT_QUOTES,'UTF-8');break;}}
            saveStickers($actId,$lib);jout(['ok'=>true]);break;
        case 'save_sticker_manual':
            $fid=trim($body['file_id']??'');$lbl=trim($body['label']??'Manual Sticker');
            if(!$fid)jout(['ok'=>false,'error'=>'file_id required']);
            $saved=addStickerToLib($actId,$fid,false,false,$lbl);
            jout(['ok'=>true,'added'=>$saved]);break;
        case 'send_sticker':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $r=sendSticker($body['chat_id']??'',$body['file_id']??'',$TOK);
            jout(['ok'=>$r['ok']??false]);break;
        case 'broadcast_sticker':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $stkFileId=$body['file_id']??'';
            if(!$stkFileId)jout(['ok'=>false,'error'=>'file_id required']);
            $targets=array_keys($db['users']??[]);$sent=0;$fail=0;
            foreach($targets as $tuid){
                $r=sendSticker($tuid,$stkFileId,$TOK);
                if($r['ok']??false)$sent++;else $fail++;
                usleep(50000);
            }
            addLog($actId,"Sticker Broadcast: $sent sent, $fail failed",'info');
            jout(['ok'=>true,'sent'=>$sent,'failed'=>$fail]);break;
        case 'send_direct_message':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $dmChatId=trim($body['chat_id']??'');
            $dmText=trim($body['text']??'');
            $dmMedia=trim($body['media']??'');
            $dmStickerId=trim($body['sticker_id']??'');

            $dmStickerIds=is_array($body['sticker_ids']??null)?$body['sticker_ids']:($dmStickerId?[$dmStickerId]:[]);
            $dmButtons=$body['buttons']??null;
            if(!$dmChatId)jout(['ok'=>false,'error'=>'Chat ID required']);
            $dmResult=['ok'=>false,'msg_sent'=>false,'sticker_sent'=>false,'stickers_sent'=>0,'stickers_failed'=>0,'error'=>''];
            if($dmText||$dmMedia){
                $dmHasTgEmoji=(strpos($dmText,'<tg-emoji')!==false);
                if($dmHasTgEmoji){$dmParsed=htmlToEntities($dmText);$dmFinalText=$dmParsed['text'];$dmEnts=$dmParsed['entities'];}
                else{$dmFinalText=$dmText;$dmEnts=[];}
                $dmP=['chat_id'=>$dmChatId];
                if($dmHasTgEmoji&&!empty($dmEnts))$dmP['entities']=$dmEnts;else $dmP['parse_mode']='HTML';
                if($dmButtons&&!empty($dmButtons['inline_keyboard']))$dmP['reply_markup']=$dmButtons;
                if($dmMedia&&(str_starts_with($dmMedia,'http')||str_starts_with($dmMedia,'https'))){
                    $lm=strtolower($dmMedia);$isAnim=str_ends_with($lm,'.gif')||str_ends_with($lm,'.mp4');
                    $dmP[$isAnim?'animation':'photo']=$dmMedia;
                    $dmP['caption']=$dmFinalText?:' ';
                    if($dmHasTgEmoji&&!empty($dmEnts)){unset($dmP['parse_mode']);$dmP['caption_entities']=$dmEnts;}
                    else $dmP['parse_mode']='HTML';
                    $mr=tg($isAnim?'sendAnimation':'sendPhoto',$dmP,$TOK);
                    if(!($mr['ok']??false)){unset($dmP['caption'],$dmP['animation'],$dmP['photo'],$dmP['caption_entities']);$dmP['text']=$dmFinalText?:' ';$mr=tg('sendMessage',$dmP,$TOK);}
                }else{$dmP['text']=$dmFinalText?:' ';$mr=tg('sendMessage',$dmP,$TOK);}
                $dmResult['msg_sent']=$mr['ok']??false;
                if(!$dmResult['msg_sent'])$dmResult['error']=$mr['description']??'Message failed';
            }

            foreach($dmStickerIds as $dmSid){
                $dmSid=trim((string)$dmSid);if(!$dmSid)continue;
                $sr=sendSticker($dmChatId,$dmSid,$TOK);
                if($sr['ok']??false){$dmResult['stickers_sent']++;$dmResult['sticker_sent']=true;}
                else{$dmResult['stickers_failed']++;if(!$dmResult['error'])$dmResult['error']=$sr['description']??'Sticker failed';}
                if(count($dmStickerIds)>1)usleep(300000);
            }

            $dmEmojiIds=is_array($body['emoji_ids']??null)?$body['emoji_ids']:[];
            $dmEmojisSent=0;$dmEmojisFailed=0;
            if(!empty($dmEmojiIds)){
                $dmCombinedText='';
                $dmCombinedEnts=[];
                $dmUtf16Offset=0;
                foreach($dmEmojiIds as $dmEobj){
                    $dmEid=trim((string)($dmEobj['emoji_id']??''));
                    $dmEfb=(string)($dmEobj['fallback']??'⭐');
                    if(!$dmEid)continue;
                    $dmELen=(int)(mb_strlen(mb_convert_encoding($dmEfb,'UTF-16LE','UTF-8'),'8bit')/2);
                    $dmCombinedEnts[]=['type'=>'custom_emoji','offset'=>$dmUtf16Offset,'length'=>$dmELen,'custom_emoji_id'=>$dmEid];
                    $dmCombinedText.=$dmEfb.' ';
                    $dmUtf16Offset+=$dmELen+1; // +1 for space character
                }
                if($dmCombinedText){
                    $dmCombinedText=rtrim($dmCombinedText);
                    $dmER=tg('sendMessage',['chat_id'=>$dmChatId,'text'=>$dmCombinedText,'entities'=>$dmCombinedEnts],$TOK);
                    if($dmER['ok']??false)$dmEmojisSent=count($dmEmojiIds);
                    else{$dmEmojisFailed=count($dmEmojiIds);if(!$dmResult['error'])$dmResult['error']=$dmER['description']??'Emoji failed';}
                }
            }
            $dmResult['emojis_sent']=$dmEmojisSent;
            $dmResult['emojis_failed']=$dmEmojisFailed;
            $dmResult['ok']=($dmResult['msg_sent']||$dmResult['sticker_sent']||$dmEmojisSent>0);
            jout($dmResult);break;
        case 'get_welcome_message':
            jout(['ok'=>true,'data'=>$db['settings']['welcome_message']??['enabled'=>false,'text'=>'👋 Welcome {tg_mention} to the group!\n\nGlad to have you here 🎉','media'=>'','buttons'=>[]]]);break;
        case 'save_welcome_message':
            $wmIn=$body['wm']??[];

            $wmEnabled=($wmIn['enabled']===true||$wmIn['enabled']==='true'||$wmIn['enabled']===1||$wmIn['enabled']==='1');
            $db['settings']['welcome_message']=[
                'enabled'=>$wmEnabled,
                'text'=>$wmIn['text']??'👋 Welcome {tg_mention}!',
                'media'=>$wmIn['media']??'',
                'buttons'=>array_values(array_filter($wmIn['buttons']??[],fn($b)=>!empty(trim($b['text']??''))))
            ];
            saveDB($actId,$db);
            addLog($actId,'Welcome Message '.($wmEnabled?'ENABLED':'DISABLED'),'info');
            jout(['ok'=>true,'enabled'=>$wmEnabled]);break;
        case 'get_user_tagger':
            jout(['ok'=>true,'data'=>$db['settings']['user_tagger']??['enabled'=>false,'trigger'=>'@all','message'=>'📢 Tagging everyone:','batch_size'=>5,'delay'=>1]]);break;
        case 'save_user_tagger':
            $utIn=$body['ut']??[];
            $db['settings']['user_tagger']=['enabled'=>(bool)($utIn['enabled']??false),'trigger'=>trim($utIn['trigger']??'@all'),'message'=>$utIn['message']??'📢 Tagging everyone:','batch_size'=>max(1,min(10,(int)($utIn['batch_size']??5))),'delay'=>max(0,(float)($utIn['delay']??1))];
            saveDB($actId,$db);jout(['ok'=>true,'enabled'=>$db['settings']['user_tagger']['enabled']]);break;
        case 'get_group_members':
            $gid=$body['chat_id']??'';
            if($gid){jout(['ok'=>true,'data'=>array_values($db['group_members'][$gid]??[]),'total'=>count($db['group_members'][$gid]??[])]);}
            else{// Return all groups summary
                $summary=[];foreach($db['group_members']??[] as $gid2=>$members)$summary[]=['chat_id'=>$gid2,'count'=>count($members)];
                jout(['ok'=>true,'data'=>$summary]);
            }break;
        case 'get_logs':jout(['ok'=>true,'data'=>loadLogs($actId)]);break;

        case 'get_prem_emojis':
            $lib=loadPremEmojis($actId);
            foreach($lib as &$e){
                $dk='emoji_'.preg_replace('/[^a-zA-Z0-9_]/','_',strtolower($e['label']));
                $e['dyn_key']=$dk;
                $e['html']='<tg-emoji emoji-id="'.$e['emoji_id'].'">'.$e['fallback'].'</tg-emoji>';
            }
            jout(['ok'=>true,'data'=>$lib]);break;
        case 'delete_prem_emoji':
            $lib=loadPremEmojis($actId);

            $delIds=is_array($body['ids']??null)?$body['ids']:($body['id']??null?[$body['id']]:[]);
            $lib=array_values(array_filter($lib,fn($e)=>!in_array($e['id'],$delIds,true)));
            savePremEmojis($actId,$lib);
            syncEmojiDynVars($actId,$db);
            saveDB($actId,$db);
            jout(['ok'=>true,'deleted'=>count($delIds)]);break;
        case 'rename_prem_emoji':
            $lib=loadPremEmojis($actId);
            foreach($lib as &$e){
                if($e['id']===($body['id']??'')){
                    $e['label']=htmlspecialchars($body['label']??$e['label'],ENT_QUOTES,'UTF-8');
                    break;
                }
            }
            savePremEmojis($actId,$lib);
            syncEmojiDynVars($actId,$db);
            saveDB($actId,$db);
            jout(['ok'=>true]);break;
        case 'save_prem_emoji_manual':
            $eid2=trim($body['emoji_id']??'');
            $efb=trim($body['fallback']??'⭐');
            $elbl=trim($body['label']??'');
            if(!$eid2)jout(['ok'=>false,'error'=>'emoji_id required']);
            $esaved=addPremEmojiToLib($actId,$eid2,$efb,$elbl?:($efb.' Emoji'));
            if($esaved){syncEmojiDynVars($actId,$db);saveDB($actId,$db);}
            jout(['ok'=>true,'added'=>$esaved]);break;
        case 'send_prem_emoji':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $pechatId=$body['chat_id']??'';
            $peEmojiId=$body['emoji_id']??'';
            $peFallback=$body['fallback']??'⭐';
            $peCaption=trim($body['caption']??'');
            if(!$pechatId||!$peEmojiId)jout(['ok'=>false,'error'=>'chat_id and emoji_id are required']);

            $peFbLen=(int)(mb_strlen(mb_convert_encoding($peFallback,'UTF-16LE','UTF-8'),'8bit')/2);
            $peEntities=[['type'=>'custom_emoji','offset'=>0,'length'=>$peFbLen,'custom_emoji_id'=>$peEmojiId]];
            $peText=$peFallback.($peCaption?"\n".$peCaption:'');
            $per=tg('sendMessage',['chat_id'=>$pechatId,'text'=>$peText,'entities'=>$peEntities],$TOK);
            jout(['ok'=>$per['ok']??false,'error'=>$per['description']??'']);break;
        case 'broadcast_prem_emoji':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $bpeEmojiId=$body['emoji_id']??'';
            $bpeFallback=$body['fallback']??'⭐';
            $bpeCaption=trim($body['caption']??'');
            if(!$bpeEmojiId)jout(['ok'=>false,'error'=>'emoji_id required']);

            $bpeFbLen=(int)(mb_strlen(mb_convert_encoding($bpeFallback,'UTF-16LE','UTF-8'),'8bit')/2);
            $bpeEntities=[['type'=>'custom_emoji','offset'=>0,'length'=>$bpeFbLen,'custom_emoji_id'=>$bpeEmojiId]];
            $bpeText=$bpeFallback.($bpeCaption?"\n".$bpeCaption:'');
            $bpTargets=array_keys($db['users']??[]);
            $bpSent=0;$bpFail=0;
            foreach($bpTargets as $tuid){
                $r=tg('sendMessage',['chat_id'=>$tuid,'text'=>$bpeText,'entities'=>$bpeEntities],$TOK);
                if($r['ok']??false)$bpSent++;else $bpFail++;
                usleep(50000);
            }
            addLog($actId,"PremEmoji Broadcast: $bpSent sent, $bpFail failed",'info');
            jout(['ok'=>true,'sent'=>$bpSent,'failed'=>$bpFail]);break;

        case 'get_forwards':
            jout(['ok'=>true,'data'=>loadForwards($actId)]);break;
        case 'save_forward_manual':
            $fc=trim($body['from_chat_id']??'');
            $fm=trim($body['message_id']??'');
            $fl=trim($body['label']??'');
            $ft=trim($body['preview_type']??'message');
            if(!$fc||!$fm)jout(['ok'=>false,'error'=>'from_chat_id and message_id are required']);
            $wasSaved=addForwardToLib($actId,$fc,$fm,$fl?:('Forward '.date('H:i:s')),$ft);
            jout(['ok'=>true,'added'=>$wasSaved]);break;
        case 'delete_forward':
            $lib=loadForwards($actId);
            $lib=array_values(array_filter($lib,fn($f)=>$f['id']!==($body['id']??'')));
            saveForwards($actId,$lib);jout(['ok'=>true]);break;
        case 'rename_forward':
            $lib=loadForwards($actId);
            foreach($lib as &$f){
                if($f['id']===($body['id']??'')){
                    $f['label']=htmlspecialchars($body['label']??$f['label'],ENT_QUOTES,'UTF-8');
                    break;
                }
            }
            saveForwards($actId,$lib);jout(['ok'=>true]);break;
        case 'test_forward':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $r=forwardMsg($body['chat_id']??'',$body['from_chat_id']??'',$body['message_id']??'',$TOK);
            jout(['ok'=>$r['ok']??false,'error'=>$r['description']??'']);break;
        case 'broadcast_forward':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $bfc=$body['from_chat_id']??'';
            $bfm=$body['message_id']??'';
            if(!$bfc||!$bfm)jout(['ok'=>false,'error'=>'from_chat_id aur message_id required']);
            $targets=array_keys($db['users']??[]);$sent=0;$fail=0;
            foreach($targets as $tuid){
                $r=forwardMsg($tuid,$bfc,$bfm,$TOK);
                if($r['ok']??false)$sent++;else $fail++;
                usleep(60000);
            }
            addLog($actId,"Forward Broadcast: $sent sent, $fail failed",'info');
            jout(['ok'=>true,'sent'=>$sent,'failed'=>$fail]);break;
        case 'broadcast':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $msg=$body['message']??'';$media=$body['media']??'';
            $toUsers=(bool)($body['to_users']??true);$toGroups=(bool)($body['to_groups']??false);$toChannels=(bool)($body['to_channels']??false);
            if(!$msg&&!$media)jout(['ok'=>false,'error'=>'Message required']);
            if(!$actId)jout(['ok'=>false,'error'=>'No active bot']);
            $targets=[];
            if($toUsers){foreach(array_keys($db['users']??[]) as $uid)$targets[$uid]=true;}
            if($toGroups){$gids=explode(',',dynVarGet($db,'group_ids'));foreach($gids as $gid){$gid=trim($gid);if($gid)$targets[$gid]=true;}}
            if($toChannels){$cids=explode(',',dynVarGet($db,'channel_ids'));foreach($cids as $cid){$cid=trim($cid);if($cid)$targets[$cid]=true;}}
            $sent=0;$fail=0;
            foreach(array_keys($targets) as $tuid){
                if(!empty($media)){$lm=strtolower($media);$isAnim=str_ends_with($lm,'.gif')||str_ends_with($lm,'.mp4');$pm=['chat_id'=>$tuid,'caption'=>$msg,'parse_mode'=>'HTML'];$pm[$isAnim?'animation':'photo']=$media;$r=tg($isAnim?'sendAnimation':'sendPhoto',$pm,$TOK);if(!($r['ok']??false)){$pm2=['chat_id'=>$tuid,'text'=>$msg,'parse_mode'=>'HTML'];$r=tg('sendMessage',$pm2,$TOK);}
                }else{$r=tg('sendMessage',['chat_id'=>$tuid,'text'=>$msg,'parse_mode'=>'HTML'],$TOK);}
                if($r['ok']??false)$sent++;else $fail++;usleep(50000);
            }
            addLog($actId,"Panel Broadcast: $sent sent, $fail failed",'info');
            jout(['ok'=>true,'sent'=>$sent,'failed'=>$fail]);break;

        case 'he_get_config':
            $heCfg=$db['settings']['he_config']??['enabled'=>false,'openrouter_key'=>'','community_channel'=>'','quiz_timer'=>120,'bot_version'=>'3.1.7'];
            jout(['ok'=>true,'data'=>$heCfg]);break;
        case 'he_save_config':
            $hIn=$body['config']??[];
            $db['settings']['he_config']=['enabled'=>(bool)($hIn['enabled']??false),'openrouter_key'=>trim($hIn['openrouter_key']??''),'community_channel'=>trim($hIn['community_channel']??''),'quiz_timer'=>max(30,(int)($hIn['quiz_timer']??120)),'bot_version'=>trim($hIn['bot_version']??'3.1.7')];
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'he_get_users':
            $heUsers=array_values($db['he_users']??[]);
            usort($heUsers,fn($a,$b)=>($b['points']??0)<=>($a['points']??0));
            jout(['ok'=>true,'data'=>$heUsers,'total'=>count($heUsers)]);break;
        case 'he_save_user':
            $hu=$body['user']??[];$huid=(string)($hu['user_id']??'');
            if(!$huid)jout(['ok'=>false,'error'=>'user_id required']);
            if(!isset($db['he_users']))$db['he_users']=[];
            $db['he_users'][$huid]=array_merge($db['he_users'][$huid]??[],$hu);
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'he_ban_user':
            $huid2=(string)($body['user_id']??'');if(!$huid2)jout(['ok'=>false,'error'=>'user_id required']);
            if(!isset($db['he_users'][$huid2]))$db['he_users'][$huid2]=['user_id'=>$huid2];
            $db['he_users'][$huid2]['banned']=(bool)($body['banned']??true);
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'he_set_credits':
            $huid3=(string)($body['user_id']??'');$hcred=(int)($body['credits']??1000);
            if(!$huid3)jout(['ok'=>false,'error'=>'user_id required']);
            if(!isset($db['he_users'][$huid3]))$db['he_users'][$huid3]=['user_id'=>$huid3];
            $db['he_users'][$huid3]['credits']=$hcred;saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'he_add_admin':
            $huid4=(string)($body['user_id']??'');if(!$huid4)jout(['ok'=>false,'error'=>'user_id required']);
            if(!isset($db['he_admins']))$db['he_admins']=[];
            $db['he_admins'][$huid4]=['user_id'=>$huid4,'added'=>date('Y-m-d H:i:s')];
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'he_remove_admin':
            $huid5=(string)($body['user_id']??'');unset($db['he_admins'][$huid5]);
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'he_get_admins':
            jout(['ok'=>true,'data'=>array_values($db['he_admins']??[])]);break;
        case 'he_get_groups':
            jout(['ok'=>true,'data'=>array_values($db['he_groups']??[]),'total'=>count($db['he_groups']??[])]);break;
        case 'he_get_stats':
            $heU=count($db['he_users']??[]);$heG=count($db['he_groups']??[]);
            $heTotalPts=0;$heTotalQ=0;$heBanned=0;
            foreach($db['he_users']??[] as $hu2){$heTotalPts+=(int)($hu2['points']??0);$heTotalQ+=(int)($hu2['quizzes_played']??0);if(!empty($hu2['banned']))$heBanned++;}
            jout(['ok'=>true,'data'=>['users'=>$heU,'groups'=>$heG,'total_points'=>$heTotalPts,'quizzes'=>$heTotalQ,'banned'=>$heBanned]]);break;
        case 'he_generate_quiz':
            $heDomain=$body['domain']??'General Knowledge';$heDiff=$body['difficulty']??'Easy';$heNum=max(1,min(20,(int)($body['num']??5)));
            $heKey=$db['settings']['he_config']['openrouter_key']??'';
            if(!$heKey)jout(['ok'=>false,'error'=>'OpenRouter API key not configured. Add it in HiddenEye Config.']);
            $heAngleArr=["Focus on lesser-known facts.","Include recent developments.","Ask about historical milestones.","Practical applications.","Test deep understanding.","Numbers and statistics."];
            $heDiffHints=['Easy'=>'Basic beginner-friendly.','Hard'=>'Challenging analytical.','Impossible'=>'Extremely hard expert-level.'];
            $heSeed=rand(100000,999999);$heAngle=$heAngleArr[array_rand($heAngleArr)];
            $hePrompt="Generate exactly $heNum UNIQUE multiple-choice questions about \"$heDomain\". Difficulty: $heDiff. ".($heDiffHints[$heDiff]??'')." $heAngle Seed: $heSeed-".date('YmdHis').". Return ONLY raw JSON array. No markdown. Each object: {\"question\":\"...\",\"options\":[\"A\",\"B\",\"C\",\"D\"],\"correct_index\":0,\"explanation\":\"...\"}";
            $ctx=stream_context_create(['http'=>['method'=>'POST','header'=>"Authorization: Bearer $heKey\r\nContent-Type: application/json\r\n",'content'=>json_encode(['model'=>'deepseek/deepseek-r1:free','max_tokens'=>2500,'messages'=>[['role'=>'system','content'=>'Quiz generator. Output only valid JSON.'],['role'=>'user','content'=>$hePrompt]]]),'timeout'=>90]]);
            $heResp=@file_get_contents('https://openrouter.ai/api/v1/chat/completions',false,$ctx);
            if(!$heResp)jout(['ok'=>false,'error'=>'AI request failed. Check OpenRouter key.']);
            $heJson=json_decode($heResp,true);$heText=$heJson['choices'][0]['message']['content']??'';
            $heText=preg_replace('/<think>.*?<\/think>/s','',$heText);
            $heText=preg_replace('/```json\s*/m','',$heText);$heText=preg_replace('/```/m','',$heText);
            $heS=strpos($heText,'[');$heE=strrpos($heText,']');
            if($heS===false||$heE===false)jout(['ok'=>false,'error'=>'Invalid AI response format']);
            $heQ=json_decode(substr($heText,$heS,$heE-$heS+1),true);
            if(!is_array($heQ))jout(['ok'=>false,'error'=>'JSON parse failed']);
            $heValid=array_values(array_filter($heQ,fn($q)=>isset($q['question'],$q['options'],$q['correct_index'])&&is_array($q['options'])&&count($q['options'])==4&&(int)$q['correct_index']>=0&&(int)$q['correct_index']<=3));
            jout(['ok'=>true,'data'=>$heValid,'count'=>count($heValid),'model'=>'deepseek/deepseek-r1:free']);break;
        case 'he_send_quiz_poll':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot token']);
            $heChatId=$body['chat_id']??'';$heQData=$body['questions']??[];$heDomainN=$body['domain']??'Quiz';
            $heTimerN=(int)($db['settings']['he_config']['quiz_timer']??120);
            if(!$heChatId||empty($heQData))jout(['ok'=>false,'error'=>'chat_id and questions required']);
            $heSent=0;$heFail=0;
            foreach($heQData as $heIdx=>$heQ2){
                $heP=['chat_id'=>$heChatId,'question'=>'Q'.($heIdx+1).'/'.count($heQData).' // '.$heDomainN."\n\n".substr($heQ2['question']??'',0,250),'options'=>$heQ2['options']??[],'type'=>'quiz','correct_option_id'=>(int)($heQ2['correct_index']??0),'is_anonymous'=>false,'open_period'=>$heTimerN];
                if(!empty($heQ2['explanation']))$heP['explanation']=substr($heQ2['explanation'],0,200);
                $heR=tg('sendPoll',$heP,$TOK);
                if($heR['ok']??false)$heSent++;else $heFail++;
                if($heIdx<count($heQData)-1)usleep(800000);
            }
            addLog($actId,"[HiddenEye] Quiz sent to $heChatId: $heSent polls",'info');
            jout(['ok'=>true,'sent'=>$heSent,'failed'=>$heFail]);break;
        case 'he_broadcast':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $heMsg=$body['message']??'';if(!$heMsg)jout(['ok'=>false,'error'=>'Message required']);
            $heSentB=0;$heFailB=0;
            foreach($db['he_users']??[] as $heUid=>$heUsr){
                if(!empty($heUsr['banned']))continue;
                $heRB=tg('sendMessage',['chat_id'=>$heUid,'text'=>$heMsg,'parse_mode'=>'HTML'],$TOK);
                if($heRB['ok']??false)$heSentB++;else $heFailB++;usleep(60000);
            }
            addLog($actId,"[HiddenEye] Broadcast: $heSentB sent, $heFailB failed",'info');
            jout(['ok'=>true,'sent'=>$heSentB,'failed'=>$heFailB]);break;

        case 'save_apk_renamer':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot']);
            $apkData=$body['apk_renamer']??null;
            if(is_array($apkData)){
                $db['settings']['apk_renamer']=[
                    'enabled'    => !empty($apkData['enabled']),
                    'new_name'   => trim($apkData['new_name']??'RebelApp')?:'RebelApp',
                    'caption'    => $apkData['caption']??'✅ APK is ready!',
                    'admin_only' => !empty($apkData['admin_only']),
                ];
                saveDB($actId,$db);jout(['ok'=>true]);
            }
            jout(['ok'=>false,'error'=>'Invalid data']);break;
        case 'get_rose':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot']);
            jout(['ok'=>true,'data'=>$db['settings']['rose']??[]]);break;
        case 'save_rose':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot']);
            $rd=$body['rose']??[];
            $lockTypes2=['url','photo','video','sticker','gif','voice','audio','document','forward','game','location','contact','poll'];
            $locks2=[];foreach($lockTypes2 as $lt)$locks2[$lt]=!empty($rd['locks'][$lt]);
            $db['settings']['rose']=[
                'enabled'         =>(bool)($rd['enabled']??false),
                'warn_limit'      =>max(1,(int)($rd['warn_limit']??3)),
                'warn_action'     =>in_array($rd['warn_action']??'kick',['kick','ban','mute'])?$rd['warn_action']:'kick',
                'warn_mute_duration'=>max(1,(int)($rd['warn_mute_duration']??60)),
                'rules'           =>trim($rd['rules']??''),
                'filters'         =>$db['settings']['rose']['filters']??[],
                'notes'           =>$db['settings']['rose']['notes']??[],
                'locks'           =>$locks2,
                'flood'           =>[
                    'enabled'       =>(bool)($rd['flood_enabled']??false),
                    'limit'         =>max(2,(int)($rd['flood_limit']??5)),
                    'window'        =>max(3,(int)($rd['flood_window']??10)),
                    'action'        =>in_array($rd['flood_action']??'mute',['mute','kick','ban'])?$rd['flood_action']:'mute',
                    'mute_duration' =>max(1,(int)($rd['flood_mute_duration']??5)),
                ],
                'blacklist'       =>array_values(array_filter(array_map('trim',explode(',',$rd['blacklist']??'')),fn($w)=>$w!=='')),
                'blacklist_action'=>in_array($rd['blacklist_action']??'delete',['delete','warn','ban'])?$rd['blacklist_action']:'delete',
                'report'          =>['enabled'=>(bool)($rd['report_enabled']??true),'reply'=>trim($rd['report_reply']??'🚨 Report sent!')],
                'cleanservice'    =>(bool)($rd['cleanservice']??false),
                'log_channel'     =>trim($rd['log_channel']??''),
                'greeting'        =>$db['settings']['rose']['greeting']??['enabled'=>false],
                'goodbye'         =>$db['settings']['rose']['goodbye']??['enabled'=>false],
                'anti_spam'       =>$db['settings']['rose']['anti_spam']??['enabled'=>false],
                'reply_msgs'      =>[
                    'warn'      =>trim($rd['reply_msgs']['warn']??''),
                    'warn_limit'=>trim($rd['reply_msgs']['warn_limit']??''),
                    'ban'       =>trim($rd['reply_msgs']['ban']??''),
                    'kick'      =>trim($rd['reply_msgs']['kick']??''),
                    'mute'      =>trim($rd['reply_msgs']['mute']??''),
                    'tban'      =>trim($rd['reply_msgs']['tban']??''),
                    'unmute'    =>trim($rd['reply_msgs']['unmute']??''),
                    'unban'     =>trim($rd['reply_msgs']['unban']??''),
                    'flood'     =>trim($rd['reply_msgs']['flood']??''),
                    'blacklist' =>trim($rd['reply_msgs']['blacklist']??''),
                    'locked'    =>trim($rd['reply_msgs']['locked']??''),
                    'promoted'  =>trim($rd['reply_msgs']['promoted']??''),
                    'demoted'   =>trim($rd['reply_msgs']['demoted']??''),
                    'pinned'    =>trim($rd['reply_msgs']['pinned']??''),
                    'unpinned'  =>trim($rd['reply_msgs']['unpinned']??''),
                    'purged'    =>trim($rd['reply_msgs']['purged']??''),
                ],
            ];
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'get_promo_bot':
            $promo=$db['settings']['promo_bot']??['enabled'=>false,'schedule_type'=>'interval','interval_minutes'=>60,'trigger_keywords'=>[],'messages'=>[]];
            jout(['ok'=>true,'data'=>$promo]);break;
        case 'save_promo_bot':
            $pd=$body['promo_bot']??[];
            $db['settings']['promo_bot']=[
                'enabled'=>(bool)($pd['enabled']??false),
                'schedule_type'=>$pd['schedule_type']??'interval',
                'interval_minutes'=>max(1,(int)($pd['interval_minutes']??60)),
                'trigger_keywords'=>array_values(array_filter($pd['trigger_keywords']??[],fn($k)=>!empty(trim($k)))),
                'messages'=>array_values(array_filter($pd['messages']??[],fn($m)=>!empty(trim($m['text']??''))||!empty(trim($m['media']??'')))),
            ];
            saveDB($actId,$db);jout(['ok'=>true]);break;
        case 'send_promo_now':
            if(!$TOK)jout(['ok'=>false,'error'=>'No bot']);
            $promo=$db['settings']['promo_bot']??[];
            $msgs=$promo['messages']??[];
            if(empty($msgs))jout(['ok'=>false,'error'=>'No promo message configured']);
            $idx=array_rand($msgs);$pm=$msgs[$idx];
            $targets=array_keys($db['users']??[]);$sent=0;$fail=0;
            $pmText=$pm['text']??'';$pmMedia=$pm['media']??'';
            $pmApk=$pm['apk_url']??'';$pmVideo=$pm['video_url']??'';
            $pmBtns=$pm['buttons']??[];
            $rows=[];foreach($pmBtns as $b2){if(!empty($b2['text'])&&!empty($b2['url']))$rows[]=[['text'=>$b2['text'],'url'=>$b2['url']]];}
            $kb=$rows?json_encode(['inline_keyboard'=>$rows]):null;
            foreach($targets as $tuid){
                if(!empty($pmApk)){
                    $apkP=['chat_id'=>$tuid,'document'=>$pmApk,'parse_mode'=>'HTML'];
                    if($pmText)$apkP['caption']=$pmText;
                    if($kb)$apkP['reply_markup']=$kb;
                    $r=tg('sendDocument',$apkP,$TOK);
                } elseif(!empty($pmVideo)){
                    $vidP=['chat_id'=>$tuid,'video'=>$pmVideo,'parse_mode'=>'HTML'];
                    if($pmText)$vidP['caption']=$pmText;
                    if($kb)$vidP['reply_markup']=$kb;
                    $r=tg('sendVideo',$vidP,$TOK);
                } else {
                    $r=sendMsg($tuid,null,$pmText,$pmMedia,$kb,false,$TOK);
                }
                if($r['ok']??false)$sent++;else $fail++;
                usleep(60000);
            }
            addLog($actId,"Promo Broadcast: $sent sent, $fail failed",'info');
            jout(['ok'=>true,'sent'=>$sent,'failed'=>$fail]);break;
        case 'get_link_automation':
            $la=$db['settings']['link_automation']??['enabled'=>false,'rules'=>[]];
            // Also return the assigned la_bot_id from global bots config
            $allBotsG=loadBots();$laBotIdG='';
            foreach($allBotsG as $bG){if(!empty($bG['la_bot']))$laBotIdG=$bG['la_bot_id']??'';}
            // la_bot_id is stored per-bot in the active bot's settings
            $laBotIdG2=trim($db['settings']['la_bot_id']??'');
            jout(['ok'=>true,'data'=>$la,'la_bot_id'=>$laBotIdG2]);break;
        case 'set_la_bot':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot selected']);
            $newLaBotId=preg_replace('/[^a-zA-Z0-9_]/','_',trim($body['la_bot_id']??''));
            $db['settings']['la_bot_id']=$newLaBotId;
            saveDB($actId,$db);
            addLog($actId,'Link Automation bot set to: '.$newLaBotId,'info');
            jout(['ok'=>true,'la_bot_id'=>$newLaBotId]);break;
        case 'save_link_automation':
            $laIn=$body['link_automation']??[];
            $laRules=[];
            foreach($laIn['rules']??[] as $rule){
                $ruleUrl=trim($rule['url']??'');
                $usesBrowser=(bool)($rule['use_browser']??false);
                $usesFc=(bool)($rule['form_capture']??false);
                // URL required for curl-mode; for browser-mode or form-capture URL may live elsewhere
                if(empty($ruleUrl)&&!$usesBrowser&&!$usesFc)continue;
                $rawBrowserSteps=$rule['browser_steps']??[];
                $browserSteps=[];
                foreach($rawBrowserSteps as $bs){
                    if(!is_array($bs)||empty($bs['type']))continue;
                    $browserSteps[]=$bs;
                }
                $laRules[]=[
                    'id'=>!empty($rule['id'])?$rule['id']:uniqid('la_'),
                    'label'=>trim($rule['label']??$ruleUrl),
                    'url'=>$ruleUrl,
                    'method'=>in_array(strtoupper($rule['method']??'GET'),['GET','POST','PUT','DELETE'])?strtoupper($rule['method']):'GET',
                    'headers'=>trim($rule['headers']??''),
                    'body'=>trim($rule['body']??''),
                    'response_path'=>trim($rule['response_path']??''),
                    'trigger'=>strtolower(trim($rule['trigger']??'')),
                    'trigger_mode'=>in_array($rule['trigger_mode']??'exact',['exact','startswith','contains'])?$rule['trigger_mode']:'exact',
                    'reply_template'=>trim($rule['reply_template']??'{response}'),
                    'error_message'=>trim($rule['error_message']??'⚠️ Error fetching link response.'),
                    'enabled'=>(bool)($rule['enabled']??true),
                    'access_control'=>trim($rule['access_control']??''),
                    'timeout'=>max(5,min(300,(int)($rule['timeout']??60))),
                    'use_browser'=>$usesBrowser,
                    'browser_steps'=>$browserSteps,
                    'browser_result_var'=>trim($rule['browser_result_var']??'result'),
                    'captcha_prompt'=>trim($rule['captcha_prompt']??'🔐 Solve the captcha and reply:'),
                    'form_capture'=>$usesFc,
                    'fc_submit_url'=>trim($rule['fc_submit_url']??''),
                    'fc_fields'=>trim($rule['fc_fields']??''),
                    'fc_success_msg'=>trim($rule['fc_success_msg']??'✅ Form submit ho gaya!'),
                    'fc_headers'=>trim($rule['fc_headers']??''),
                ];
            }
            $db['settings']['link_automation']=['enabled'=>(bool)($laIn['enabled']??false),'rules'=>$laRules];
            // Save la_bot_id if provided in payload
            if(isset($laIn['la_bot_id'])&&$laIn['la_bot_id']!==''){
                $db['settings']['la_bot_id']=preg_replace('/[^a-zA-Z0-9_]/','_',trim($laIn['la_bot_id']));
            }
            saveDB($actId,$db);
            addLog($actId,'Link Automation settings saved ('.(count($laRules)).' rules)','info');
            jout(['ok'=>true,'count'=>count($laRules)]);break;
        case 'test_link_automation':
            if(!$actId)jout(['ok'=>false,'error'=>'No bot selected']);
            $testUrl=trim($body['url']??'');
            $testMethod=strtoupper($body['method']??'GET');
            $testHeaders=trim($body['headers']??'');
            $testBody=trim($body['body']??'');
            $testPath=trim($body['response_path']??'');
            $testTimeout=max(5,min(120,(int)($body['timeout']??30)));
            if(empty($testUrl))jout(['ok'=>false,'error'=>'URL required']);
            $testResult=doCurl($testUrl,$testMethod,$testHeaders,$testBody,$testTimeout);
            $rawResp=$testResult['body']??'';
            $respData=json_decode($rawResp,true);
            $extracted=null;
            if($testPath!==''&&$respData!==null){$extracted=jsonPath($respData,$testPath);}
            if($extracted===null&&$respData!==null){
                foreach(['result','response','text','content','answer','message','output','data'] as $fk){
                    if(isset($respData[$fk])&&is_string($respData[$fk])&&trim($respData[$fk])!==''){$extracted=$respData[$fk];break;}
                }
            }
            if($extracted===null)$extracted=$rawResp;
            jout(['ok'=>true,'http_code'=>$testResult['code'],'raw_body'=>mb_substr($rawResp,0,2000),'extracted'=>mb_substr((string)$extracted,0,1000),'error'=>$testResult['error']??'']);break;

        // ─── RBD (Deposit Bot) API Actions ──────────────────────────
        case 'rbd_get_config':
            $rbdC=rbdLoadConfig();unset($rbdC['admin_pass']);jout(['ok'=>true,'data'=>$rbdC]);break;
        case 'rbd_save_config':
            $rbdC=rbdLoadConfig();foreach(['bot_token','admin_chat_id','rb_phone','rb_password','rb_branch','rb_bank_id','welcome_msg','deposit_thanks'] as $rk){if(isset($body[$rk]))$rbdC[$rk]=trim($body[$rk]);}foreach(['min_deposit','max_deposit'] as $rk){if(isset($body[$rk]))$rbdC[$rk]=(int)$body[$rk];}if(!empty($body['new_pass'])&&strlen(trim($body['new_pass']))>=4)$rbdC['admin_pass']=trim($body['new_pass']);rbdSaveConfig($rbdC);rbdLog('Config saved','info');jout(['ok'=>true]);break;
        case 'rbd_set_webhook':
            $rbdC=rbdLoadConfig();$rbdTok=trim($rbdC['bot_token']??'');if(!$rbdTok)jout(['ok'=>false,'error'=>'Bot token not set']);
            $rbdPr=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https://':'http://';$rbdWUrl=$rbdPr.$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'],'?').'?rbd_webhook=1';
            $rbdR=tg('setWebhook',['url'=>$rbdWUrl,'allowed_updates'=>['message','channel_post','callback_query']],$rbdTok);jout(['ok'=>$rbdR['ok']??false,'webhook_url'=>$rbdWUrl,'tg'=>$rbdR]);break;
        case 'rbd_remove_webhook':
            $rbdC=rbdLoadConfig();$rbdTok=trim($rbdC['bot_token']??'');if(!$rbdTok)jout(['ok'=>false,'error'=>'Bot token not set']);
            $rbdR=tg('deleteWebhook',[],$rbdTok);jout(['ok'=>$rbdR['ok']??false]);break;
        case 'rbd_test_rb_login':
            $rbdC=rbdLoadConfig();@unlink(RBD_COOKIE_DIR.'admin.txt');$rbdU=rbdAdminLogin($rbdC);jout($rbdU?['ok'=>true,'user'=>$rbdU]:['ok'=>false,'error'=>'Login failed']);break;
        case 'rbd_test_bank':
            $rbdC=rbdLoadConfig();$rbdBk=rbdGetBankDetails($rbdC,500);jout(['ok'=>(bool)$rbdBk,'bank'=>$rbdBk,'source'=>'powerdreams.co/api/online/request/fetchAvailablePeer']);break;
        case 'rbd_send_test':
            $rbdC=rbdLoadConfig();$rbdCid=trim($body['chat_id']??$rbdC['admin_chat_id']??'');$rbdTok=trim($rbdC['bot_token']??'');if(!$rbdCid||!$rbdTok)jout(['ok'=>false,'error'=>'Token/chat_id missing']);$rbdR=rbdTgSend($rbdTok,$rbdCid,"✅ <b>Rebel B2W</b> is working!\n\n".date('d/m/Y H:i:s'));jout(['ok'=>$rbdR['ok']??false]);break;
        case 'rbd_approve_deposit':
            $rbdCid=trim($body['chat_id']??'');$rbdAmt=(float)($body['amount']??0);$rbdUtr=trim($body['utr']??'');$rbdTxn=trim($body['txn_id']??'');if(!$rbdCid||$rbdAmt<=0)jout(['ok'=>false,'error'=>'chat_id and amount required']);rbdLdAddDeposit($rbdCid,$rbdAmt,$rbdUtr,$rbdTxn);$rbdC=rbdLoadConfig();$rbdTok=trim($rbdC['bot_token']??'');if($rbdTok)rbdTgSend($rbdTok,$rbdCid,"✅ <b>Deposit Approved!</b>\n\n💰 ₹".number_format($rbdAmt,2)." credited.\n".($rbdUtr?"🔢 UTR: <code>{$rbdUtr}</code>\n":"")."\nUse /Balance to check balance.");rbdLog("Deposit approved — chat={$rbdCid} amount={$rbdAmt}",'success');jout(['ok'=>true,'user'=>rbdLdGetUser($rbdCid)]);break;
        case 'rbd_get_ledger':
            $rbdLd=rbdLdLoad();jout(['ok'=>true,'ledger'=>$rbdLd,'total_users'=>count($rbdLd)]);break;
        case 'rbd_get_blocked':
            $rbdRl=rbdRlLoad();$rbdNow=time();$rbdBl=[];foreach($rbdRl as $rbdCk=>$rbdRec){if(!empty($rbdRec['blocked_until'])&&$rbdRec['blocked_until']>$rbdNow)$rbdBl[$rbdCk]=['blocked_until'=>$rbdRec['blocked_until'],'remaining_mins'=>ceil(($rbdRec['blocked_until']-$rbdNow)/60),'incomplete'=>$rbdRec['incomplete']??0];}jout(['ok'=>true,'blocked'=>$rbdBl,'total'=>count($rbdBl)]);break;
        case 'rbd_unblock_user':
            $rbdCid=trim($body['chat_id']??'');if(!$rbdCid)jout(['ok'=>false,'error'=>'chat_id required']);rbdRlCompleted($rbdCid);jout(['ok'=>true,'msg'=>"User {$rbdCid} unblocked"]);break;
        case 'rbd_get_logs':
            $rbdLogs=file_exists(RBD_LOG_FILE)?(json_decode(file_get_contents(RBD_LOG_FILE),true)?:[]):[];jout(['ok'=>true,'data'=>array_slice($rbdLogs,0,150)]);break;
        case 'rbd_clear_logs':
            file_put_contents(RBD_LOG_FILE,'[]',LOCK_EX);jout(['ok'=>true]);break;

        // ─── Link Runner API Actions ─────────────────────────────────
        case 'lr_get_config':
            $lrC=lrLoadConfig();unset($lrC['admin_pass']);jout(['ok'=>true,'data'=>$lrC]);break;
        case 'lr_save_config':
            $lrC=lrLoadConfig();foreach(['bot_token','chat_id','send_prefix','run_secret','webhook_token','webhook_cmd'] as $lk){if(isset($body[$lk]))$lrC[$lk]=trim($body[$lk]);}if(!empty($body['new_pass'])&&strlen(trim($body['new_pass']))>=4)$lrC['admin_pass']=trim($body['new_pass']);lrSaveConfig($lrC);lrLog('Config saved','info');jout(['ok'=>true]);break;
        case 'lr_save_links':
            $lrC=lrLoadConfig();$lrLinks=[];foreach($body['links']??[] as $lk){$lrU=trim($lk['url']??'');if(!$lrU)continue;$lrLinks[]=['id'=>preg_replace('/[^a-zA-Z0-9_]/','_',$lk['id']??uniqid('l_')),'name'=>trim($lk['name']??'Link'),'enabled'=>(bool)($lk['enabled']??true),'url'=>$lrU,'method'=>strtoupper(trim($lk['method']??'GET')),'headers'=>trim($lk['headers']??''),'body'=>trim($lk['body']??''),'timeout'=>max(5,min(120,(int)($lk['timeout']??30))),'ssl_verify'=>!isset($lk['ssl_verify'])||(bool)$lk['ssl_verify'],'response_path'=>trim($lk['response_path']??''),'reply_template'=>trim($lk['reply_template']??'📌 <b>{name}</b>\n\n{response}'),'error_message'=>trim($lk['error_message']??'⚠️ <b>{name}</b> failed!\nHTTP: <code>{http_code}</code>'),'send_on_error'=>(bool)($lk['send_on_error']??false),'chat_id'=>trim($lk['chat_id']??''),'screenshot_mode'=>(bool)($lk['screenshot_mode']??false),'screenshot_caption'=>trim($lk['screenshot_caption']??'📸 <b>{name}</b>\n🌐 <code>{url}</code>\n🕐 {ts}'),'form_fill_mode'=>(bool)($lk['form_fill_mode']??false),'form_fields'=>trim($lk['form_fields']??'')];}$lrC['links']=$lrLinks;lrSaveConfig($lrC);lrLog('Links saved — '.count($lrLinks).' rule(s)','info');jout(['ok'=>true,'count'=>count($lrLinks)]);break;
        case 'lr_run_now':
            $lrC=lrLoadConfig();$lrRes=lrRunAll($lrC);lrLog('Manual run — '.count($lrRes).' link(s)','info');jout(['ok'=>true,'results'=>$lrRes,'success'=>count(array_filter($lrRes,fn($r)=>!$r['failed']))]);break;
        case 'lr_run_single':
            $lrC=lrLoadConfig();$lrLinkId=trim($body['link_id']??'');$lrSingle=null;foreach($lrC['links'] as $lk){if(($lk['id']??'')===$lrLinkId){$lrSingle=$lk;break;}}if(!$lrSingle)jout(['ok'=>false,'error'=>'Link not found']);$lrTmpC=$lrC;$lrTmpC['links']=[$lrSingle];$lrRes=lrRunAll($lrTmpC);jout(['ok'=>true,'result'=>$lrRes[0]??null]);break;
        case 'lr_test_link':
            $lrU=trim($body['url']??'');$lrM=strtoupper(trim($body['method']??'GET'));$lrH=trim($body['headers']??'');$lrB=trim($body['body']??'');$lrTo=max(5,min(60,(int)($body['timeout']??15)));if(!$lrU)jout(['ok'=>false,'error'=>'URL required']);$lrR=lrFetch($lrU,$lrM,$lrH,$lrB,$lrTo);jout(['ok'=>true,'code'=>$lrR['code'],'body'=>mb_substr($lrR['body'],0,2000),'error'=>$lrR['error']]);break;
        case 'lr_set_webhook':
            $lrC=lrLoadConfig();$lrTok=trim($lrC['webhook_token']?:$lrC['bot_token']);if(!$lrTok)jout(['ok'=>false,'error'=>'Bot token not set']);
            $lrPr=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https://':'http://';$lrWUrl=$lrPr.$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'],'?').'?lr_webhook=1';
            $lrR=lrTg('setWebhook',['url'=>$lrWUrl,'allowed_updates'=>['message','channel_post']],$lrTok);jout(['ok'=>$lrR['ok']??false,'webhook_url'=>$lrWUrl,'tg'=>$lrR]);break;
        case 'lr_remove_webhook':
            $lrC=lrLoadConfig();$lrTok=trim($lrC['webhook_token']?:$lrC['bot_token']);if(!$lrTok)jout(['ok'=>false,'error'=>'Bot token not set']);$lrR=lrTg('deleteWebhook',[],$lrTok);jout(['ok'=>$lrR['ok']??false]);break;
        case 'lr_get_logs':
            $lrLogs=file_exists(LR_LOG_FILE)?(json_decode(file_get_contents(LR_LOG_FILE),true)?:[]):[];jout(['ok'=>true,'data'=>array_slice($lrLogs,0,100)]);break;
        case 'lr_clear_logs':
            file_put_contents(LR_LOG_FILE,'[]',LOCK_EX);jout(['ok'=>true]);break;

        case 'lr_get_py_config':
            $lrC2=lrLoadConfig();
            $lrPyKeys=['py_bot_token','py_uidai_proxy','py_fetch_cmd','py_cancel_cmd','py_refresh_cmd','py_start_msg','py_loading_steps','py_otp_steps','py_captcha_msg','py_otp_msg','py_success_msg','py_cancel_msg','py_error_prefix'];
            $lrPyOut=[];foreach($lrPyKeys as $k)$lrPyOut[$k]=$lrC2[$k]??'';
            jout(['ok'=>true,'data'=>$lrPyOut]);break;

        case 'lr_save_py_config':
            $lrC2=lrLoadConfig();
            $lrPyKeys=['py_bot_token','py_uidai_proxy','py_fetch_cmd','py_cancel_cmd','py_refresh_cmd','py_start_msg','py_loading_steps','py_otp_steps','py_captcha_msg','py_otp_msg','py_success_msg','py_cancel_msg','py_error_prefix'];
            foreach($lrPyKeys as $k){if(isset($body[$k]))$lrC2[$k]=$body[$k];}
            lrSaveConfig($lrC2);
            $lrBotCfg=[];foreach($lrPyKeys as $k)$lrBotCfg[$k]=$lrC2[$k]??'';
            file_put_contents(__DIR__.'/bot_config.json',json_encode($lrBotCfg,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE),LOCK_EX);
            lrLog('Python Aadhaar bot config saved','info');jout(['ok'=>true]);break;

        // ─── Aadhaar Bot Testing & Monitoring Actions ────────
        case 'ab_set_webhook':
            $abC=lrLoadConfig();$abTok=trim($body['token']??$abC['py_bot_token']??'');
            if(!$abTok)jout(['ok'=>false,'error'=>'Bot token not set — pehle config save karo']);
            $abPr=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https://':'http://';
            $abWUrl=$abPr.$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'],'?').'?py_webhook=1';
            $abR=lrTg('setWebhook',['url'=>$abWUrl,'allowed_updates'=>['message','channel_post','callback_query']],$abTok);
            lrLog('Aadhaar bot webhook '.($abR['ok']??false?'set':'failed').': '.$abWUrl,'info');
            jout(['ok'=>$abR['ok']??false,'webhook_url'=>$abWUrl,'tg'=>$abR]);break;

        case 'ab_remove_webhook':
            $abC=lrLoadConfig();$abTok=trim($abC['py_bot_token']??'');
            if(!$abTok)jout(['ok'=>false,'error'=>'Bot token not set']);
            $abR=lrTg('deleteWebhook',[],$abTok);jout(['ok'=>$abR['ok']??false]);break;

        case 'ab_bot_info':
            $abC=lrLoadConfig();$abTok=trim($abC['py_bot_token']??'');
            if(!$abTok)jout(['ok'=>false,'error'=>'Bot token not set']);
            $abMe=lrTg('getMe',[],$abTok);$abWh=lrTg('getWebhookInfo',[],$abTok);
            jout(['ok'=>true,'me'=>$abMe['result']??null,'webhook'=>$abWh['result']??null]);break;

        case 'ab_send_test':
            $abC=lrLoadConfig();$abTok=trim($abC['py_bot_token']??'');
            $abCid=trim($body['chat_id']??'');$abText=trim($body['text']??'✅ Aadhaar Bot test — working!');
            if(!$abTok)jout(['ok'=>false,'error'=>'Bot token not set']);
            if(!$abCid)jout(['ok'=>false,'error'=>'Chat ID required']);
            $abR=lrTg('sendMessage',['chat_id'=>$abCid,'text'=>$abText,'parse_mode'=>'HTML'],$abTok);
            lrLog('Test message → chat='.$abCid.' ok='.json_encode($abR['ok']??false),'info');
            jout(['ok'=>$abR['ok']??false,'tg'=>$abR]);break;

        case 'ab_get_sessions':
            $abSessions=file_exists(LR_SESSION_FILE)?(json_decode(file_get_contents(LR_SESSION_FILE),true)?:[]):[];
            jout(['ok'=>true,'sessions'=>$abSessions,'total'=>count($abSessions)]);break;

        case 'ab_clear_sessions':
            file_put_contents(LR_SESSION_FILE,'{}',LOCK_EX);
            lrLog('All bot sessions cleared','warn');jout(['ok'=>true]);break;

        case 'ab_delete_session':
            $abCid=trim($body['chat_id']??'');if(!$abCid)jout(['ok'=>false,'error'=>'chat_id required']);
            lrSessionDel($abCid);lrLog("Session deleted for chat={$abCid}",'info');jout(['ok'=>true]);break;

        case 'ab_get_logs':
            $abLogs=file_exists(LR_LOG_FILE)?(json_decode(file_get_contents(LR_LOG_FILE),true)?:[]):[];
            jout(['ok'=>true,'data'=>array_slice($abLogs,0,200)]);break;

        case 'ab_clear_logs':
            file_put_contents(LR_LOG_FILE,'[]',LOCK_EX);jout(['ok'=>true]);break;

        default:jout(['ok'=>false,'error'=>'Unknown action']);
    }
}

RENDER:

?>

<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<meta name="color-scheme" content="dark"><meta name="theme-color" content="#030712">
<title>REBEL ADMIN v7.1</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600&family=Share+Tech+Mono&display=swap" rel="stylesheet">

<style>
:root{--bg:#030712;--s:#0d1117;--s2:#161b22;--s3:#1c2130;--c:#00f5ff;--g:#39ff14;--r:#ff2d55;--y:#ffd60a;--p:#bf5af2;--o:#ff9f0a;--b:rgba(0,245,255,.15);--t:#e6edf3;--td:#8b949e;--tf:#4a5568;}

*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
html,body{height:100%;margin:0;padding:0;}
html{background:#030712;color-scheme:dark only;-webkit-text-size-adjust:100%;scroll-behavior:auto;}
body{background:var(--bg)!important;color:var(--t)!important;font-family:'Rajdhani',sans-serif;font-size:15px;width:100vw;overflow-x:hidden;min-height:100dvh;-webkit-font-smoothing:antialiased;}
@media screen and (orientation:portrait){body{background:#030712!important;color:#e6edf3!important;}.fi,.fsel,.fta{background:#161b22!important;color:#e6edf3!important;}option{background:#161b22;color:#e6edf3;}}
.lw{display:flex;align-items:center;justify-content:center;min-height:100dvh;padding:16px;background:var(--bg);}
.lb{background:rgba(13,17,23,.97);border:1px solid var(--b);border-radius:16px;padding:36px;width:100%;max-width:340px;text-align:center;}
.fi,.fsel,.fta{background:var(--s2);border:1px solid var(--b);border-radius:6px;color:var(--t);font-family:'Share Tech Mono';font-size:13px;padding:9px 12px;outline:none;width:100%;max-width:100%;-webkit-appearance:none;appearance:none;}
.fta{resize:vertical;min-height:76px;white-space:pre-wrap;}
.fsel{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath fill='%238b949e' d='M6 8L0 0h12z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px;}
.fi:focus,.fsel:focus,.fta:focus{border-color:var(--c);box-shadow:0 0 0 2px rgba(0,245,255,.1);}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 18px;border-radius:6px;border:none;cursor:pointer;font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:700;text-transform:uppercase;text-decoration:none;transition:all .2s;-webkit-appearance:none;}
.btn:active{transform:scale(.97);}
.bp{background:var(--c);color:#000;}.bsu{background:var(--g);color:#000;}.bd{background:var(--r);color:#fff;}.bw{background:var(--y);color:#000;}.bg{background:transparent;color:var(--td);border:1px solid var(--b);}.bo{background:var(--o);color:#000;}
.bsm{padding:5px 10px;font-size:11px;}
.wrap{display:flex;min-height:100vh;width:100%;overflow-x:hidden;position:relative;}
.sb{width:240px;background:rgba(13,17,23,.99);border-right:1px solid var(--b);display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;z-index:10000;transition:transform .3s;overflow-y:auto;}
.logo{display:flex;align-items:center;gap:12px;padding:18px 16px;border-bottom:1px solid var(--b);}
.main{margin-left:240px;flex:1;display:flex;flex-direction:column;width:calc(100% - 240px);min-height:100vh;}
.topbar{background:rgba(13,17,23,.95);border-bottom:1px solid var(--b);padding:0 18px;height:52px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50;flex-shrink:0;}
.con{padding:18px;flex:1;overflow-x:hidden;padding-top:18px;}
.panel{display:none;}.panel.active{display:block;}
.card{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:16px;margin-bottom:14px;width:100%;}
.sh{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px;}
.st{font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;color:var(--c);text-transform:uppercase;letter-spacing:1px;}
.fg{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;}
.fgrp{display:flex;flex-direction:column;gap:4px;width:100%;}
.fl{font-size:10px;font-family:'Share Tech Mono';color:var(--td);text-transform:uppercase;}
.mb{margin-bottom:12px;}
.tr{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;}
.tw{border-radius:8px;border:1px solid var(--b);width:100%;min-width:460px;}
table{width:100%;border-collapse:collapse;font-size:13px;text-align:left;white-space:nowrap;}
thead th{background:var(--s2);color:var(--td);font-family:'Share Tech Mono';font-size:10px;text-transform:uppercase;padding:9px 11px;border-bottom:1px solid var(--b);}
tbody tr{border-bottom:1px solid rgba(255,255,255,.04);}tbody tr:hover{background:rgba(255,255,255,.02);}
td{padding:9px 11px;vertical-align:middle;}
.badge{padding:2px 7px;border-radius:20px;font-size:10px;font-family:'Share Tech Mono';font-weight:700;}
.ba{background:rgba(57,255,20,.1);color:var(--g);border:1px solid rgba(57,255,20,.3);}
.bi{background:rgba(255,45,85,.1);color:var(--r);border:1px solid rgba(255,45,85,.3);}
.by{background:rgba(255,214,10,.1);color:var(--y);border:1px solid rgba(255,214,10,.3);}
.bc{background:rgba(0,245,255,.1);color:var(--c);border:1px solid rgba(0,245,255,.3);}
.bpv{background:rgba(191,90,242,.1);color:var(--p);border:1px solid rgba(191,90,242,.3);}
.bfj{background:rgba(255,45,85,.1);color:var(--r);border:1px solid rgba(255,45,85,.3);}
.toast{position:fixed;top:14px;right:14px;background:var(--s2);border-left:3px solid var(--c);padding:11px 16px;border-radius:8px;z-index:999999;font-family:'Share Tech Mono';font-size:12px;max-width:calc(100vw - 28px);animation:si .3s ease;}
.toast.success{border-color:var(--g);}.toast.error{border-color:var(--r);}.toast.warn{border-color:var(--y);}
@keyframes si{from{opacity:0;transform:translateX(20px);}to{opacity:1;transform:translateX(0);}}
.ni{display:flex;align-items:center;gap:10px;padding:9px 16px;cursor:pointer;color:var(--td);font-size:13px;border:none;background:none;width:100%;text-align:left;text-decoration:none;border-left:3px solid transparent;transition:.2s;}
.ni:hover,.ni.active{color:var(--t);background:rgba(0,245,255,.06);border-left-color:var(--c);}
.sov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:9999;}
.mbox{position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:99999;display:none;align-items:flex-start;justify-content:center;padding:16px;padding-top:18px;overflow-y:auto;-webkit-overflow-scrolling:touch;}
.mbox.open{display:flex;}
.modal{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:18px;width:100%;max-width:780px;position:relative;margin:auto;}
.mc{position:absolute;top:12px;right:12px;background:none;border:none;color:var(--td);cursor:pointer;font-size:18px;}
.ham{display:none;background:none;border:none;color:var(--c);font-size:24px;cursor:pointer;padding:4px;}
.bb{background:rgba(0,245,255,.02);border:1px dashed var(--c);border-radius:8px;padding:13px;margin-top:12px;}
.br{display:flex;gap:7px;align-items:center;margin-bottom:7px;background:var(--s2);padding:8px;border-radius:6px;border:1px solid var(--b);flex-wrap:wrap;}
.br input,.br select{flex:1;min-width:70px;}
.tg{position:relative;width:44px;height:24px;cursor:pointer;flex-shrink:0;display:inline-block;}
.tg input{position:absolute;width:100%;height:100%;opacity:0;cursor:pointer;z-index:2;margin:0;}
.ts{position:absolute;inset:0;background:var(--s3);border:1px solid var(--b);border-radius:24px;transition:all .3s;pointer-events:none;}
.ts::before{content:'';position:absolute;left:3px;top:3px;width:16px;height:16px;background:var(--td);border-radius:50%;transition:all .3s;}
.tg input:checked+.ts{background:rgba(0,245,255,.15);border-color:var(--c);}
.tg input:checked+.ts::before{transform:translateX(20px);background:var(--c);}
.tw2{display:flex;align-items:center;gap:10px;}
.log-t{background:var(--s2);border:1px solid var(--b);border-radius:6px;padding:11px;font-family:'Share Tech Mono';font-size:11px;max-height:220px;overflow-y:auto;line-height:1.7;}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:14px;}
.sc{background:var(--s2);border:1px solid var(--b);border-radius:10px;padding:13px;text-align:center;}
.sn{font-family:'Orbitron';font-size:20px;font-weight:900;color:var(--c);}
.sl{font-size:10px;color:var(--td);font-family:'Share Tech Mono';margin-top:3px;}
.vpill{display:inline-block;background:rgba(0,245,255,.1);color:var(--c);padding:2px 7px;border-radius:4px;font-family:'Share Tech Mono';font-size:11px;margin:2px;}
.vpillo{display:inline-block;background:rgba(255,159,10,.1);color:var(--o);padding:2px 7px;border-radius:4px;font-family:'Share Tech Mono';font-size:11px;margin:2px;}
.ft-opts{display:none;background:rgba(191,90,242,.05);border:1px solid rgba(191,90,242,.3);border-radius:8px;padding:12px;margin-top:10px;}
.ft-opts.show{display:block!important;}
.fj-ch-row{display:flex;gap:7px;align-items:center;margin-bottom:7px;background:var(--s2);padding:8px;border-radius:6px;border:1px solid rgba(255,45,85,.2);flex-wrap:wrap;}
.fj-btn-row{display:flex;gap:7px;align-items:center;margin-bottom:7px;background:var(--s2);padding:8px;border-radius:6px;border:1px solid rgba(0,245,255,.2);flex-wrap:wrap;}
.bc-check-row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px;background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;}
.bc-check-item{display:flex;align-items:center;gap:8px;cursor:pointer;}
.bc-check-item input[type=checkbox]{width:18px;height:18px;accent-color:var(--c);cursor:pointer;}

/* FIX indicator box */
.fix-note{background:rgba(57,255,20,.05);border:1px solid rgba(57,255,20,.3);border-radius:8px;padding:10px 12px;font-family:'Share Tech Mono';font-size:11px;color:var(--g);margin-bottom:12px;line-height:1.8;}
@media(max-width:768px){
  html,body{background:#030712!important;width:100vw;height:auto!important;}
  .sb{transform:translateX(-100%);box-shadow:4px 0 20px rgba(0,0,0,.8);}
  .sb.open{transform:translateX(0);}
  .sov.open{display:block;}
  .main{margin-left:0!important;width:100%!important;min-height:100vh;}
  .ham{display:block;}
  .fg{grid-template-columns:1fr;}
  .con{padding:10px;padding-top:10px;}
  .card{padding:11px;}
  .br{flex-direction:column;align-items:stretch;}
  .br input,.br select,.br button,.br textarea{width:100%!important;min-width:0;}
  .modal{width:100%;border-radius:10px;}
  .mbox{padding:10px;}
  select.fsel{color:#e6edf3!important;background-color:#161b22!important;}
  option{background:#161b22;color:#e6edf3;}
  #pemj-add-grid{grid-template-columns:1fr!important;}
  #dm-top-grid{grid-template-columns:1fr!important;}
}
</style></head><body>

<div id="tc"></div>
<input type="file" id="fup" style="display:none" onchange="handleUp(this)" accept="image/*,video/*">
<input type="file" id="fimp" style="display:none" accept=".json" onchange="importFlows(this)">
<input type="hidden" id="cut">
<?php if($page==='login'): ?>

<div class="lw"><div class="lb">

  <div style="font-size:40px;margin-bottom:8px">🤖</div>
  <h1 style="font-family:Orbitron;color:var(--c);margin-bottom:4px;font-size:20px">REBEL ADMIN</h1>

  <div style="font-size:11px;color:var(--td);font-family:'Share Tech Mono';margin-bottom:22px">v7.1 Fixed</div>
  <?php if(!empty($loginErr)):?><div style="color:var(--r);font-size:12px;margin-bottom:10px;padding:8px;background:rgba(255,45,85,.1);border-radius:6px"><?=htmlspecialchars($loginErr,ENT_QUOTES,'UTF-8')?></div><?php endif?>
  <form method="POST">
    <input type="hidden" name="<?=CSRF_TOKEN_NAME?>" value="<?=csrfToken()?>">
    <div class="fgrp" style="margin-bottom:9px"><input type="text" class="fi" name="user" placeholder="Username" required autocomplete="username"></div>

    <div class="fgrp" style="margin-bottom:16px"><input type="password" class="fi" name="pass" placeholder="Password" required></div>
    <button type="submit" class="btn bp" style="width:100%">⚡ LOGIN</button>
  </form>
</div></div>
<?php else: ?>

<div class="sov" id="sov" onclick="closeSb()"></div>

<div class="wrap">
<aside class="sb" id="sb">

  <div class="logo"><div style="font-size:22px">🤖</div><div><h2 style="font-family:Orbitron;color:var(--c);font-size:12px">REBEL ADMIN</h2><div style="font-size:10px;color:var(--td);font-family:'Share Tech Mono'">v7.1 Fixed</div></div></div>

  <div style="margin:10px 12px;padding:9px;background:rgba(57,255,20,.05);border:1px solid rgba(57,255,20,.2);border-radius:8px;font-family:'Share Tech Mono';font-size:11px">

    <div style="color:var(--td);font-size:9px">ACTIVE BOT</div>

    <div style="color:var(--g);font-weight:bold;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" id="abN"><?=htmlspecialchars($actName)?></div>
  </div>
  <nav style="flex:1">
    <button class="ni active" onclick="nav('dash',this)">📊 Dashboard</button>
    <button class="ni" onclick="nav('bots',this)">🤖 Manage Bots</button>
    <button class="ni" onclick="nav('cfg',this)">⚙️ Bot Config &amp; Security</button>
    <button class="ni" onclick="nav('fj',this)">🔒 Force Join</button>
    <button class="ni" onclick="nav('welcome',this)">👋 Welcome Message</button>
    <button class="ni" onclick="nav('tagger',this)">📣 User Tagger</button>
    <button class="ni" onclick="nav('broadcast',this)">📣 Broadcast</button>
    <button class="ni" onclick="nav('vault',this)">🔐 API Key Vault</button>
    <button class="ni" onclick="nav('bvars',this)">📦 Bot Variables</button>
    <button class="ni" onclick="nav('dvars',this)">🗄️ Live Variables</button>
    <button class="ni" onclick="nav('builder',this)">🚀 Flow Builder</button>
    <button class="ni" onclick="nav('users',this)">👥 Users</button>
    <button class="ni" onclick="nav('ukeys',this)">🔑 User Keys</button>
    <button class="ni" onclick="nav('lkeys',this)">🪪 Licence Keys</button>
    <button class="ni" onclick="nav('keygen',this)">⚡ Key Gen</button>
    <button class="ni" onclick="nav('guide',this)">📖 Full Guide</button>
    <button class="ni" onclick="nav('stickers',this)">🌟 Sticker Library</button>
    <button class="ni" onclick="nav('forwards',this)">📨 Forward Library</button>
    <button class="ni" onclick="nav('premoji',this)">💎 Premium Emoji</button>
    <button class="ni" onclick="nav('apkrenamer',this)">📦 APK Renamer</button>
    <button class="ni" onclick="nav('rosebot',this)" style="color:#ff6b9d;border-left:2px solid #ff6b9d">🔥 The Rebel Bot</button>
    <button class="ni" onclick="nav('hiddeneye',this)" style="color:#39ff14;border-left:2px solid #39ff14">👁 Hidden Eye Bot</button>
        <button class="ni" onclick="nav('promobot',this)" style="color:#ff9f0a;border-left:2px solid #ff9f0a">📢 Promo Bot</button>
    <button class="ni" onclick="nav('linkautomation',this)" style="color:#00f5ff;border-left:2px solid #00f5ff">🔗 Link Automation</button>
    <button class="ni" onclick="nav('depositbot',this)" style="color:#ff6b1a;border-left:2px solid #ff6b1a">💰 Deposit Bot</button>
    <button class="ni" onclick="nav('linkrunner',this)" style="color:#7c7cff;border-left:2px solid #7c7cff">🔗 Link Runner</button>
    <button class="ni" onclick="nav('adharbot',this)" style="color:#63b3ed;border-left:2px solid #63b3ed">👾 Aadhaar Bot</button>
    <a href="?page=logout" class="ni" style="color:var(--r)">🚪 Logout</a>
  </nav>
</aside>

<div class="main">

  <div class="topbar">

    <div style="display:flex;align-items:center;gap:10px"><button class="ham" onclick="openSb()">☰</button><div style="font-family:Orbitron;font-weight:700;font-size:12px;color:var(--c)">REBEL v7.1</div></div>
  </div>

  <div class="con">

  <!-- DASHBOARD -->

  <div class="panel active" id="p-dash">

    <div class="sg"><div class="sc"><div class="sn" id="st-u">—</div><div class="sl">👥 Users</div></div><div class="sc"><div class="sn" id="st-s">—</div><div class="sl">🔍 Searches</div></div><div class="sc"><div class="sn" id="st-k">—</div><div class="sl">🔑 Keys</div></div></div>

    <div class="card" style="border-color:var(--g)">

      <div class="sh"><div class="st" style="color:var(--g)">⚡ BOT ENGINE</div></div>

      <div style="background:var(--s2);padding:12px;border-radius:8px;border:1px solid var(--b);margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">

        <div><div style="font-family:'Share Tech Mono';font-size:9px;color:var(--td)">ACTIVE BOT</div><div style="font-size:14px;font-weight:bold;color:var(--c);margin-top:3px" id="dashN">Checking...</div></div>
        <span class="badge" id="dashB">...</span>
      </div>

      <div style="display:flex;gap:7px;flex-wrap:wrap">
        <button class="btn bsu" onclick="startBot()">▶️ Start</button>
        <button class="btn bd" onclick="stopBot()">🛑 Stop</button>
        <button class="btn bg" onclick="checkBot()">🔍 Status</button>
      </div>
    </div>

    <div class="card"><div class="sh"><div class="st">📋 LIVE LOGS</div><button class="btn bg bsm" onclick="loadLogs()">🔄</button></div><div class="log-t" id="logB"><div style="color:var(--tf)">Loading...</div></div></div>
  </div>

  <!-- BOT CONFIG -->

  <div class="panel" id="p-cfg">

    <div class="card"><div class="sh"><div class="st">⚙️ BOT CONFIG</div></div>

      <div class="tw2 mb"><label class="tg"><input type="checkbox" id="bc-maint"><span class="ts"></span></label><div><strong style="font-size:13px;color:var(--y)">🔧 Maintenance Mode</strong><div style="font-size:11px;color:var(--td)">Only admin can use bot when ON</div></div></div>

      <div class="fgrp" style="max-width:200px;margin-bottom:13px"><label class="fl">💳 Free Searches (New Users)</label><input type="number" id="bc-free" class="fi" value="3"></div>

      <div class="fgrp" style="max-width:280px;margin-bottom:13px"><label class="fl">👑 Master Admin Telegram ID</label><input type="text" id="g-adminid" class="fi" placeholder="Your Telegram numeric ID"></div>
      <button class="btn bp" onclick="saveCfg()">💾 Save Config</button>
    </div>

    <!-- SECURITY SETTINGS -->
    <div class="card" style="border-color:rgba(57,255,20,.35)">
      <div class="sh"><div class="st" style="color:var(--g)">🔐 SECURITY — Change Admin Password</div></div>
      <div style="font-size:11px;color:var(--td);margin-bottom:12px;line-height:1.7">
        Password is stored as a bcrypt hash. After changing, you'll need to use the new password on next login.<br>
        You can also set <code style="color:var(--c)">REBEL_ADMIN_PASS</code> or <code style="color:var(--c)">REBEL_ADMIN_HASH</code> environment variables.
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">Current Password</label><input type="password" id="sec-cur" class="fi" placeholder="Your current password" autocomplete="current-password"></div>
        <div class="fgrp"><label class="fl">New Password (min 8 chars)</label><input type="password" id="sec-new" class="fi" placeholder="New secure password" autocomplete="new-password"></div>
        <div class="fgrp"><label class="fl">Confirm New Password</label><input type="password" id="sec-cnf" class="fi" placeholder="Repeat new password" autocomplete="new-password"></div>
      </div>
      <button class="btn bp" onclick="changeAdminPass()" style="background:rgba(57,255,20,.2);border-color:var(--g);color:var(--g)">🔐 Update Password</button>
      <div id="sec-result" style="margin-top:10px;font-size:12px;font-family:'Share Tech Mono'"></div>
    </div>

    <!-- FREE TEXT GLOBAL SETTINGS -->

    <div class="card" style="border-color:rgba(0,245,255,.35)">

      <div class="sh">

        <div class="st" style="color:var(--c)">💬 FREE TEXT — GLOBAL REPLY</div>

        <div style="display:flex;align-items:center;gap:8px">
          <span id="ft-status-label" style="font-family:'Share Tech Mono';font-size:11px;color:var(--td)">OFF</span>
          <button id="ft-toggle-btn" class="btn bsm bg" onclick="toggleFreeText()" style="min-width:60px">Enable</button>
        </div>
      </div>
      <p style="font-size:12px;color:var(--td);margin-bottom:13px">When user sends any message <b style="color:var(--t)">without /</b> the bot replies with this. Per-page Free Text (in Flow Builder) takes priority.</p>

      <div class="fg mb">

        <div class="fgrp"><label class="fl">📍 Where to Reply</label><select class="fsel" id="ft-chatmode" onchange="saveFtLive()"><option value="both">DM + Groups (Both)</option><option value="dm">DM Only</option><option value="group">Groups Only</option></select></div>

        <div class="fgrp"><label class="fl">🔇 Groups: Mention-only</label><div class="tw2" style="margin-top:8px"><label class="tg"><input type="checkbox" id="ft-mention" onchange="saveFtLive()"><span class="ts"></span></label><div style="font-size:11px;color:var(--td)">Reply only if @botname mentioned</div></div></div>

        <div class="fgrp"><label class="fl">🔒 Access Control (blank=everyone)</label><input type="text" id="ft-access" class="fi" placeholder="{ADMINS} or 123456,789" oninput="clearFtSaveTimer()"></div>
      </div>

      <div class="fgrp mb"><label class="fl" style="color:var(--g)">💬 Reply Message</label><textarea id="ft-text" class="fta" style="min-height:90px" placeholder="👋 Hi {tg_name}!&#10;You said: {query}" oninput="clearFtSaveTimer()"></textarea></div>

      <div class="fgrp mb"><label class="fl">🖼️ Media URL (optional)</label><div style="display:flex;gap:7px"><input type="text" id="ft-media" class="fi" placeholder="https://..." oninput="clearFtSaveTimer()"><button class="btn bg bsm" onclick="tup('ft-media')">📁</button></div></div>
      <button class="btn bp" onclick="saveFtBase()" style="width:100%;padding:11px">💾 Save Free Text Settings</button>
    </div>
  </div>

  <!-- FORCE JOIN PANEL -->

  <div class="panel" id="p-fj">

    <div class="card" style="border-color:rgba(255,45,85,.4)">

      <div class="sh">

        <div class="st" style="color:var(--r)">🔒 FORCE JOIN SYSTEM</div>

        <div style="display:flex;align-items:center;gap:8px"><span id="fj-status-label" style="font-family:'Share Tech Mono';font-size:11px;color:var(--td)">OFF</span><button id="fj-toggle-btn" class="btn bsm bg" onclick="toggleFj()" style="min-width:60px">Enable</button></div>
      </div>
      <p style="font-size:12px;color:var(--td);margin-bottom:14px">Users must join all configured channels before using commands that have Force Join checked in Flow Builder.</p>

      <div style="margin-bottom:14px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--r);text-transform:uppercase;margin-bottom:8px">📢 CHANNELS (Add multiple)</div>

        <div id="fj-channels"></div>
        <button class="btn bd bsm" onclick="addFjChannel()" style="margin-top:6px">+ Add Channel</button>

        <div style="font-size:11px;color:var(--td);margin-top:6px">Use channel ID <code style="color:var(--c)">-100123456789</code> or username <code style="color:var(--c)">@mychannel</code>. Bot must be admin.</div>
      </div>

      <div style="background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.2);border-radius:8px;padding:13px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--r);text-transform:uppercase;margin-bottom:10px">⚠️ MESSAGE SHOWN WHEN NOT JOINED</div>

        <div class="fgrp mb"><label class="fl">Message (HTML supported)</label><textarea id="fj-msg" class="fta" style="min-height:80px" placeholder="⚠️ &lt;b&gt;Please join our channel(s) first!&lt;/b&gt;&#10;&#10;Click the buttons below to join, then try again 😊"></textarea></div>

        <div class="fgrp mb"><label class="fl">🖼️ Media URL (optional)</label><div style="display:flex;gap:7px"><input type="text" id="fj-media" class="fi" placeholder="https://..."><button class="btn bg bsm" onclick="tup('fj-media')">📁</button></div></div>

        <div>

          <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--c);text-transform:uppercase;margin-bottom:8px">🔘 JOIN BUTTONS (URL — tap to open channel)</div>

          <div id="fj-buttons"></div>
          <button class="btn bg bsm" onclick="addFjBtn()" style="margin-top:6px">+ Add Button</button>

          <div style="font-size:11px;color:var(--td);margin-top:5px">Use <code style="color:var(--c)">https://t.me/channelname</code> as URL.</div>
        </div>
      </div>
      <button class="btn bd" onclick="saveFj()" style="width:100%;padding:12px;font-size:14px">💾 SAVE FORCE JOIN SETTINGS</button>
    </div>
  </div>

  <!-- BROADCAST -->

  <!-- BROADCAST + DIRECT MESSAGE STUDIO -->

  <div class="panel" id="p-broadcast">

    <!-- DIRECT MESSAGE STUDIO -->

    <div class="card" style="border-color:rgba(0,245,255,.5);background:linear-gradient(160deg,rgba(0,245,255,.03) 0%,rgba(13,17,23,1) 60%)">

      <div class="sh" style="margin-bottom:16px">

        <div>

          <div class="st" style="color:var(--c);font-size:13px">💬 DIRECT MESSAGE STUDIO</div>

          <div style="font-size:10px;color:var(--td);margin-top:2px">Enter User ID → Write message → Tap sticker to send!</div>
        </div>

        <div id="dm-status-dot" style="width:11px;height:11px;border-radius:50%;background:var(--td);transition:background .3s;flex-shrink:0;box-shadow:0 0 0 0 rgba(0,245,255,0);animation:none"></div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 2fr;gap:10px;margin-bottom:10px" id="dm-top-grid">

        <div>
          <label class="fl" style="color:var(--c)">👤 USER / CHAT ID</label>
          <input type="text" id="dm-uid" class="fi" placeholder="123456789" style="margin-top:4px;font-size:15px;font-weight:700;color:var(--c);letter-spacing:1px" oninput="dmCheckReady()">

          <div style="font-size:9px;color:var(--td);margin-top:4px;font-family:'Share Tech Mono'">Telegram numeric ID</div>
        </div>

        <div>
          <label class="fl" style="color:var(--g)">✉️ MESSAGE (optional)</label>
          <textarea id="dm-msg" class="fta" style="margin-top:4px;min-height:64px;font-size:12px" placeholder="Hello! 👋&#10;Sending you this message!" oninput="dmCheckReady()"></textarea>
        </div>
      </div>

      <div style="display:flex;gap:7px;margin-bottom:14px;align-items:center">
        <span style="font-size:10px;color:var(--td);font-family:'Share Tech Mono';white-space:nowrap;flex-shrink:0">🖼️ MEDIA</span>
        <input type="text" id="dm-media" class="fi" placeholder="Photo / GIF URL (optional)" style="flex:1;font-size:11px">
        <button class="btn bg bsm" onclick="tup('dm-media')">📁</button>
      </div>
      <button id="dm-send-msg-btn" onclick="dmSendMsg()" disabled
        style="width:100%;padding:11px;font-size:13px;font-weight:700;border-radius:8px;cursor:not-allowed;margin-bottom:18px;transition:all .25s;background:rgba(0,245,255,.06);border:2px dashed rgba(0,245,255,.2);color:var(--td);letter-spacing:.5px">
        📤 Message Bhejo
      </button>

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">

        <div style="flex:1;height:1px;background:linear-gradient(90deg,transparent,rgba(191,90,242,.5))"></div>

        <div style="font-size:10px;color:#bf5af2;font-family:'Share Tech Mono';white-space:nowrap;padding:3px 10px;background:rgba(191,90,242,.1);border:1px solid rgba(191,90,242,.3);border-radius:20px">💎 STICKERS — TAP TO SEND</div>

        <div style="flex:1;height:1px;background:linear-gradient(90deg,rgba(191,90,242,.5),transparent)"></div>
      </div>

      <div id="dm-sticker-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(76px,1fr));gap:8px;margin-bottom:12px">

        <div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">⏳ Loading stickers...</div>
      </div>

      <!-- Premium Emoji Multi-Select Section -->

      <div style="border-top:1px solid rgba(191,90,242,.2);padding-top:13px;margin-bottom:12px">

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;gap:8px;flex-wrap:wrap">

          <div style="font-size:10px;color:#bf5af2;font-family:'Share Tech Mono';white-space:nowrap;padding:3px 10px;background:rgba(191,90,242,.1);border:1px solid rgba(191,90,242,.3);border-radius:20px">✨ EMOJIS — SELECT AND SEND</div>

          <div style="display:flex;gap:6px">
            <button class="btn bsm" onclick="dmSelectAllEmojis()" style="font-size:10px;background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;padding:4px 9px">☑️ All</button>
            <button class="btn bsm" onclick="dmClearEmojis()" style="font-size:10px;background:rgba(100,100,120,.15);border:1px solid rgba(150,150,170,.3);color:var(--td);padding:4px 9px">✖ Clear</button>
            <button class="btn bsm" id="dm-emj-send-btn" onclick="dmSendSelectedEmojis()" style="font-size:10px;background:rgba(57,255,20,.12);border:1px solid rgba(57,255,20,.4);color:var(--g);padding:4px 9px;display:none">📤 Send</button>
          </div>
        </div>

        <div id="dm-emj-count" style="font-size:10px;color:var(--td);font-family:'Share Tech Mono';margin-bottom:8px">0 emoji selected</div>

        <div id="dm-emj-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(76px,1fr));gap:8px">

          <div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:12px">⏳ Loading emojis...</div>
        </div>
      </div>

      <div id="dm-log" style="max-height:140px;overflow-y:auto;display:flex;flex-direction:column;gap:4px"></div>
    </div>

    <!-- BROADCAST (collapsed) -->

    <div class="card" style="padding:0;overflow:hidden;border-color:rgba(255,159,10,.35)">

      <div onclick="toggleDmBc()" style="display:flex;align-items:center;justify-content:space-between;padding:13px 16px;cursor:pointer;background:rgba(255,159,10,.04);user-select:none">

        <div style="font-size:12px;font-weight:700;color:var(--o)">📣 Broadcast — Send to All Users</div>
        <span id="dm-bc-arrow" style="color:var(--td);font-size:12px;transition:transform .2s">▼</span>
      </div>

      <div id="dm-bc-body" style="display:none;padding:14px;border-top:1px solid rgba(255,159,10,.2)">

        <div class="bc-check-row" style="margin-bottom:12px">
          <label class="bc-check-item"><input type="checkbox" id="bc-to-users" checked><div><div style="font-size:13px;font-weight:700;color:var(--t)">👥 All Users</div></div></label>
          <label class="bc-check-item"><input type="checkbox" id="bc-to-groups"><div><div style="font-size:13px;font-weight:700;color:var(--t)">💬 Groups</div></div></label>
          <label class="bc-check-item"><input type="checkbox" id="bc-to-channels"><div><div style="font-size:13px;font-weight:700;color:var(--t)">📢 Channels</div></div></label>
        </div>

        <div class="fgrp mb"><label class="fl">Message</label><textarea id="bc-msg" class="fta" style="min-height:80px" placeholder="📢 Hello everyone!"></textarea></div>

        <div class="fgrp mb"><label class="fl">Media URL</label><div style="display:flex;gap:7px"><input type="text" id="bc-media" class="fi" placeholder="https://..."><button class="btn bg bsm" onclick="tup('bc-media')">📁</button></div></div>

        <div id="bc-result" style="margin-bottom:12px;display:none"></div>
        <button class="btn bo" onclick="doBroadcast()" style="width:100%;padding:11px">📣 Send Broadcast</button>
      </div>
    </div>

    <!-- DIRECT SEND TO SPECIFIC USER (collapsed) — same style as broadcast -->

    <div class="card" style="padding:0;overflow:hidden;border-color:rgba(0,245,255,.35)">

      <div onclick="toggleDmSingle()" style="display:flex;align-items:center;justify-content:space-between;padding:13px 16px;cursor:pointer;background:rgba(0,245,255,.04);user-select:none">

        <div style="font-size:12px;font-weight:700;color:var(--c)">💬 Direct Send — Send to a Specific User</div>
        <span id="dm-single-arrow" style="color:var(--td);font-size:12px;transition:transform .2s">▼</span>
      </div>

      <div id="dm-single-body" style="display:none;padding:14px;border-top:1px solid rgba(0,245,255,.2)">

        <!-- User / Chat ID input -->

        <div class="fgrp mb">
          <label class="fl" style="color:var(--c)">👤 User / Chat ID</label>
          <input type="text" id="dms-uid" class="fi" placeholder="123456789  (ya group/channel ID)"
            style="font-size:15px;font-weight:700;color:var(--c);letter-spacing:1px"
            oninput="dmsCheckReady()">

          <div style="font-size:9px;color:var(--td);margin-top:4px;font-family:'Share Tech Mono'">Telegram numeric ID (user, group or channel)</div>
        </div>

        <!-- Message -->

        <div class="fgrp mb">
          <label class="fl">✉️ Message</label>
          <textarea id="dms-msg" class="fta" style="min-height:80px" placeholder="Hello! 👋&#10;This message was sent only to you!"></textarea>
        </div>

        <!-- Media URL -->

        <div class="fgrp mb">
          <label class="fl">🖼️ Media URL</label>

          <div style="display:flex;gap:7px">
            <input type="text" id="dms-media" class="fi" placeholder="https://... (Photo / GIF optional)">
            <button class="btn bg bsm" onclick="tup('dms-media')">📁</button>
          </div>
        </div>

        <!-- Inline Buttons (same JSON format as builder) -->

        <div class="fgrp mb">
          <label class="fl">🔘 Inline Buttons <span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono'">(optional — JSON format)</span></label>
          <textarea id="dms-buttons" class="fta" style="min-height:60px;font-family:'Share Tech Mono';font-size:11px"
            placeholder='[{"text":"Visit","url":"https://example.com"},{"text":"Close","callback_data":"close"}]'></textarea>

          <div style="font-size:9px;color:var(--td);margin-top:3px">Format: <code style="color:var(--c)">[{"text":"...","url":"..."}]</code> — ek row ke liye ya <code style="color:var(--c)">[[...],[...]]</code> multiple rows ke liye</div>
        </div>

        <!-- Multi-Select Sticker Section -->

        <div style="border-top:1px solid rgba(191,90,242,.2);padding-top:13px;margin-bottom:13px">

          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;gap:8px;flex-wrap:wrap">

            <div style="font-size:11px;font-weight:700;color:#bf5af2;font-family:'Share Tech Mono'">💎 STICKERS — Select Multiple to Send</div>

            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <button class="btn bsm" onclick="dmsSelectAllStickers()" style="font-size:10px;background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;padding:4px 9px">☑️ All</button>
              <button class="btn bsm" onclick="dmsClearStickers()" style="font-size:10px;background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3);color:var(--r);padding:4px 9px">✖ Clear</button>
              <button class="btn bsm" onclick="dmsDeleteSelected()" id="dms-del-btn" style="font-size:10px;background:rgba(255,45,85,.12);border:1px solid rgba(255,45,85,.5);color:var(--r);padding:4px 9px;display:none">🗑 Delete Selected</button>
            </div>
          </div>

          <!-- Selected count badge -->

          <div id="dms-sel-count" style="font-size:10px;color:var(--td);font-family:'Share Tech Mono';margin-bottom:8px">0 sticker selected</div>

          <!-- Sticker grid -->

          <div id="dms-stk-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(80px,1fr));gap:8px">

            <div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">⏳ Loading stickers...</div>
          </div>
        </div>

        <!-- Multi-Select Premium Emoji Section -->

        <div style="border-top:1px solid rgba(191,90,242,.2);padding-top:13px;margin-bottom:13px">

          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;gap:8px;flex-wrap:wrap">

            <div style="font-size:11px;font-weight:700;color:#bf5af2;font-family:'Share Tech Mono'">✨ PREMIUM EMOJIS — Select Multiple to Send</div>

            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <button class="btn bsm" onclick="dmsSelectAllEmojis()" style="font-size:10px;background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;padding:4px 9px">☑️ All</button>
              <button class="btn bsm" onclick="dmsClearEmojis()" style="font-size:10px;background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3);color:var(--r);padding:4px 9px">✖ Clear</button>
            </div>
          </div>

          <div id="dms-emj-count" style="font-size:10px;color:var(--td);font-family:'Share Tech Mono';margin-bottom:8px">0 emoji selected</div>

          <div id="dms-emj-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(90px,1fr));gap:8px">

            <div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">⏳ Loading emojis...</div>
          </div>
        </div>

        <!-- Result box -->

        <div id="dms-result" style="margin-bottom:12px;display:none"></div>

        <!-- Send button -->
        <button id="dms-send-btn" class="btn" onclick="dmsDoSend()"
          style="width:100%;padding:11px;font-size:13px;font-weight:700;border-radius:8px;background:rgba(0,245,255,.12);border:2px solid rgba(0,245,255,.4);color:var(--c);cursor:not-allowed;transition:all .25s;letter-spacing:.5px"
          disabled>
          💬 Direct Message Bhejo
        </button>
      </div>
    </div>
  </div>

  <!-- API KEY VAULT -->

  <div class="panel" id="p-vault"><div class="card"><div class="sh"><div class="st">🔐 API KEY VAULT</div><button class="btn bsu bsm" onclick="openModal('m-ak')">+ Add Key</button></div><div style="font-size:12px;color:var(--td);margin-bottom:10px">Use as <code style="color:var(--c)">{KEY_NAME}</code> anywhere.</div><div class="tr"><div class="tw"><table><thead><tr><th>Variable</th><th>Value</th><th>Note</th><th>Action</th></tr></thead><tbody id="vb"></tbody></table></div></div></div></div>

  <!-- BOT VARIABLES -->

  <div class="panel" id="p-bvars"><div class="card"><div class="sh"><div class="st">📦 BOT VARIABLES</div></div><div style="font-size:12px;color:var(--td);margin-bottom:10px">KEY=value per line. Use as <code style="color:var(--c)">{KEY}</code> anywhere.</div><textarea id="bv-text" class="fta" style="min-height:110px" placeholder="PRICE=₹99&#10;SUPPORT=@myuser"></textarea><button class="btn bp" onclick="saveBotVars()" style="margin-top:10px;width:100%">💾 Save Variables</button></div>

  <div class="card"><div class="sh"><div class="st">ALL AVAILABLE VARS</div></div><div><span class="vpill">{tg_name}</span><span class="vpill">{tg_id}</span><span class="vpill">{tg_username}</span><span class="vpill">{tg_searches}</span><span class="vpill">{user_key}</span><span class="vpill">{query}</span><span class="vpill">{tg_role}</span><span class="vpill">{page_current}</span><span class="vpill">{page_total}</span><span class="vpill">{curl_response}</span><br><div style="margin-top:8px;font-size:10px;color:var(--o)">⚡ LIVE DYNAMIC VARS:</div><span class="vpillo">{users_ids}</span><span class="vpillo">{group_ids}</span><span class="vpillo">{channel_ids}</span><span class="vpillo">{owner_id}</span><span class="vpillo">{any_saved_var}</span></div></div></div>

  <!-- LIVE DYNAMIC VARIABLES -->

  <div class="panel" id="p-dvars"><div class="card"><div class="sh"><div class="st" style="color:var(--o)">🗄️ LIVE VARIABLES</div><button class="btn bg bsm" onclick="loadDynVars()">🔄 Refresh</button></div><div style="font-size:12px;color:var(--td);margin-bottom:12px">Runtime variables created by <code style="color:var(--o)">/save</code> or auto-collected.</div><div id="dv-list"></div><div style="margin-top:12px;border-top:1px solid var(--b);padding-top:12px"><div class="st" style="font-size:10px;margin-bottom:8px">➕ ADD / EDIT VARIABLE</div><div class="fg mb"><div class="fgrp"><label class="fl">Variable Name</label><input type="text" id="dv-key" class="fi" placeholder="my_var"></div><div class="fgrp"><label class="fl">Value</label><input type="text" id="dv-val" class="fi" placeholder="value here"></div></div><button class="btn bo bsm" onclick="saveDynVar()">💾 Save Variable</button></div></div></div>

  <!-- FLOW BUILDER -->

  <div class="panel" id="p-builder">

    <div class="card">

      <div class="sh"><div class="st">🚀 FLOW BUILDER</div>

        <div style="display:flex;gap:5px;flex-wrap:wrap">
          <button class="btn bg bsm" onclick="exportFlows()">📥 Export</button>
          <button class="btn bg bsm" onclick="g('fimp').click()">📤 Import</button>
          <button class="btn bsu bsm" onclick="openCmdModal()">+ New Page</button>
        </div>
      </div>

      <div class="tr"><div class="tw"><table><thead><tr><th>ID</th><th>Trigger / Free Text</th><th>Type</th><th>Credit</th><th>Force Join</th><th>Action</th></tr></thead><tbody id="cb"></tbody></table></div></div>
    </div>
  </div>

  <!-- STICKER LIBRARY -->

  <div class="panel" id="p-stickers">

    <div class="card">

      <div class="sh">

        <div class="st" style="color:var(--y)">🌟 STICKER LIBRARY</div>

        <div style="display:flex;gap:7px;flex-wrap:wrap">
          <button class="btn bg bsm" onclick="refreshStickers()">🔄 Refresh</button>
          <button class="btn bw bsm" onclick="showStickerHelp()">❓ Help</button>
        </div>
      </div>

      <div style="background:rgba(0,245,255,.04);border:1px solid var(--b);border-radius:8px;padding:12px;margin-bottom:12px;font-size:12px;color:var(--td);line-height:1.9">
        📥 <b style="color:var(--c)">Auto-Capture:</b> Forward any sticker to the bot from the owner account — it will be saved automatically.<br>
        ✏️ <b style="color:var(--c)">Manual Add:</b> You can also add by pasting the file_id below.
      </div>

      <!-- Owner ID Section -->

      <div style="background:rgba(57,255,20,.04);border:1px solid rgba(57,255,20,.25);border-radius:8px;padding:12px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--g);margin-bottom:8px">👑 OWNER / MASTER ADMIN ID</div>

        <div style="font-size:11px;color:var(--td);margin-bottom:8px">Only the account with this ID can forward stickers to the bot and save them in the library.</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <input type="text" id="stk-owner-id" class="fi" placeholder="Apna Telegram numeric ID (e.g. 123456789)" style="flex:1;min-width:200px">
          <button class="btn bsu bsm" onclick="saveOwnerIdFromSticker()">💾 Save Owner ID</button>
        </div>

        <div style="font-size:10px;color:var(--td);margin-top:6px">ℹ️ This is linked to the Master Admin ID in Bot Config — both are the same.</div>
      </div>

      <!-- Manual Add -->

      <div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--y);margin-bottom:8px">➕ MANUALLY ADD STICKER</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <input type="text" id="stk-fileid" class="fi" placeholder="file_id (bot ko sticker bhej ke milega)" style="flex:2;min-width:200px">
          <input type="text" id="stk-label" class="fi" placeholder="Label (e.g. 🔥 Fire Sticker)" style="flex:1;min-width:120px">
          <button class="btn bw bsm" onclick="addStickerManual()">➕ Add</button>
        </div>
      </div>

      <!-- Test Send -->

      <div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--c);margin-bottom:8px">🧪 TEST SEND</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <input type="text" id="stk-test-chatid" class="fi" placeholder="Chat ID ya Telegram ID" style="flex:1;min-width:140px">
          <select id="stk-test-select" class="fsel" style="flex:2;min-width:180px"><option value="">— Library se select karo —</option></select>
          <button class="btn bp bsm" onclick="testSendSticker()">📤 Send</button>
        </div>
      </div>

      <!-- Broadcast -->

      <div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;margin-bottom:16px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--r);margin-bottom:8px">📣 BROADCAST STICKER TO ALL USERS</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <select id="stk-bc-select" class="fsel" style="flex:2;min-width:200px"><option value="">— Select a sticker —</option></select>
          <button class="btn bd bsm" onclick="broadcastSticker()">📣 Broadcast</button>
        </div>

        <div style="font-size:10px;color:var(--r);margin-top:5px">⚠️ Sab users ko sticker jayega. Carefully use karo.</div>
      </div>

      <!-- Library Grid -->

      <div id="stk-list" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px">

        <div style="color:var(--td);font-size:12px;text-align:center;grid-column:1/-1;padding:20px">Click 🔄 Refresh to load library...</div>
      </div>
    </div>
  </div>
  </div>

  <!-- FORWARD LIBRARY -->

  <div class="panel" id="p-forwards">

    <div class="card">

      <div class="sh">

        <div class="st" style="color:var(--o)">📨 FORWARD LIBRARY</div>

        <div style="display:flex;gap:7px;flex-wrap:wrap">
          <button class="btn bg bsm" onclick="refreshForwards()">🔄 Refresh</button>
          <button class="btn bw bsm" onclick="showForwardHelp()">❓ Help</button>
        </div>
      </div>

      <div style="background:rgba(255,159,10,.06);border:1px solid rgba(255,159,10,.3);border-radius:8px;padding:12px;margin-bottom:12px;font-size:12px;color:var(--td);line-height:1.9">
        📨 <b style="color:var(--o)">Auto-Capture:</b> Forward any message to the bot from the owner account — it will be saved in the library automatically.<br>
        ✅ <b style="color:var(--o)">Premium Safe:</b> Premium stickers, animated emoji — all preserved in forwards! Works with normal bots too.<br>
        ✏️ <b style="color:var(--o)">Manual Add:</b> Paste from_chat_id and message_id below to add directly.
      </div>

      <!-- IDs kaise milenge -->

      <div style="background:var(--s2);border:1px solid rgba(255,159,10,.2);border-radius:8px;padding:12px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--o);margin-bottom:8px">💡 How to get from_chat_id and message_id?</div>

        <div style="font-size:11px;color:var(--td);line-height:2">
          <b style="color:var(--t)">Easy Way (Recommended):</b> Forward any message to the bot (from owner account) → Bot will automatically reply with the IDs ✅<br>
          <b style="color:var(--t)">Manual Way:</b> Copy the message link from Telegram Web →
          <span style="color:var(--c);font-family:'Share Tech Mono'">t.me/c/1234567890/42</span><br>
          Chat ID: <span style="color:var(--g);font-family:'Share Tech Mono'">-1001234567890</span> &nbsp;|&nbsp; Msg ID: <span style="color:var(--g);font-family:'Share Tech Mono'">42</span>
        </div>
      </div>

      <!-- Manual Add -->

      <div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--o);margin-bottom:8px">➕ MANUALLY ADD FORWARD</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
          <input type="text" id="fwd-from-chat" class="fi" placeholder="from_chat_id (e.g. -1001234567890)" style="flex:2;min-width:180px">
          <input type="text" id="fwd-msg-id" class="fi" placeholder="message_id (e.g. 42)" style="flex:1;min-width:90px">
        </div>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <input type="text" id="fwd-label" class="fi" placeholder="Label (e.g. 🔥 Premium Sticker)" style="flex:2;min-width:180px">
          <select id="fwd-type" class="fsel" style="flex:1;min-width:120px">
            <option value="message">💬 Message</option>
            <option value="sticker">🌟 Sticker</option>
            <option value="photo">🖼️ Photo</option>
            <option value="video">🎬 Video</option>
            <option value="animation">🎭 GIF</option>
            <option value="voice">🎙️ Voice</option>
            <option value="audio">🎵 Audio</option>
            <option value="document">📄 File</option>
          </select>
          <button class="btn bw bsm" onclick="addForwardManual()">➕ Add</button>
        </div>
      </div>

      <!-- Test Send -->

      <div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;margin-bottom:12px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--c);margin-bottom:8px">🧪 TEST FORWARD</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <input type="text" id="fwd-test-chatid" class="fi" placeholder="Apna Chat ID (test ke liye)" style="flex:1;min-width:140px">
          <select id="fwd-test-select" class="fsel" style="flex:2;min-width:200px"><option value="">— Library se select karo —</option></select>
          <button class="btn bp bsm" onclick="testSendForward()">📤 Forward</button>
        </div>
      </div>

      <!-- Broadcast -->

      <div style="background:var(--s2);border:1px solid rgba(255,45,85,.2);border-radius:8px;padding:12px;margin-bottom:16px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--r);margin-bottom:8px">📣 BROADCAST TO ALL USERS</div>

        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <select id="fwd-bc-select" class="fsel" style="flex:2;min-width:200px"><option value="">— Select a forward —</option></select>
          <button class="btn bd bsm" onclick="broadcastForward()">📣 Broadcast</button>
        </div>

        <div style="font-size:10px;color:var(--r);margin-top:5px">⚠️ Sab users ko yeh forwarded message jayega. Premium content bhi preserve rahega ✅</div>
      </div>

      <!-- Library Grid -->

      <div id="fwd-list" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px">

        <div style="color:var(--td);font-size:12px;text-align:center;grid-column:1/-1;padding:20px">Click 🔄 Refresh to load Forward Library...</div>
      </div>
    </div>
  </div>

  <!-- BOTS -->

  <div class="panel" id="p-bots"><div class="card"><div class="sh"><div class="st">🤖 MANAGE BOTS</div><button class="btn bsu bsm" onclick="openModal('m-ab')">+ Add Bot</button></div><div id="blist"><div style="color:var(--td);text-align:center;padding:20px">Loading...</div></div></div></div>

  <!-- PREMIUM EMOJI LIBRARY — REDESIGNED -->

  <div class="panel" id="p-premoji">

    <!-- STEP 1: Add Emoji -->

    <div class="card" style="border-color:rgba(191,90,242,.5);background:linear-gradient(135deg,rgba(191,90,242,.04),rgba(13,17,23,1))">

      <div class="sh">

        <div style="display:flex;align-items:center;gap:10px">

          <div style="width:32px;height:32px;background:rgba(191,90,242,.2);border:2px solid rgba(191,90,242,.6);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:#bf5af2;flex-shrink:0">1</div>

          <div>

            <div class="st" style="color:#bf5af2;font-size:12px">ADD EMOJI</div>

            <div style="font-size:10px;color:var(--td);margin-top:1px">Send to bot from Telegram or paste the ID</div>
          </div>
        </div>
        <button class="btn bg bsm" onclick="refreshPremEmojis()">🔄 Refresh</button>
      </div>

      <!-- Two ways side by side -->

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:4px" id="pemj-add-grid">

        <!-- Auto capture -->

        <div style="background:rgba(57,255,20,.05);border:1px solid rgba(57,255,20,.25);border-radius:10px;padding:14px">

          <div style="font-size:20px;margin-bottom:6px">📱</div>

          <div style="font-size:12px;font-weight:700;color:var(--g);margin-bottom:5px">Auto Capture</div>

          <div style="font-size:11px;color:var(--td);line-height:1.7">Send any message containing a premium emoji to the bot from your <b style="color:var(--t)">Premium account</b> on Telegram.<br><br>Bot reply karega: <code style="color:var(--g);font-size:10px">✅ X emoji captured!</code></div>
        </div>

        <!-- Manual add -->

        <div style="background:rgba(191,90,242,.06);border:1px solid rgba(191,90,242,.3);border-radius:10px;padding:14px">

          <div style="font-size:20px;margin-bottom:6px">⌨️</div>

          <div style="font-size:12px;font-weight:700;color:#bf5af2;margin-bottom:8px">Manual Add</div>
          <input type="text" id="pemj-id" class="fi" placeholder="Emoji ID — 19 digit number" style="font-size:11px;margin-bottom:6px">

          <div style="display:flex;gap:5px;margin-bottom:6px">
            <input type="text" id="pemj-fb" class="fi" placeholder="⭐ fallback" style="flex:1;font-size:13px;max-width:80px">
            <input type="text" id="pemj-label" class="fi" placeholder="fire / star / etc." style="flex:2;font-size:11px">
          </div>
          <button onclick="addPremEmojiManual()" style="width:100%;background:rgba(191,90,242,.2);border:1px solid rgba(191,90,242,.5);color:#bf5af2;border-radius:6px;padding:7px;font-size:12px;cursor:pointer;font-weight:700">➕ Add to Library</button>
        </div>
      </div>
    </div>

    <!-- STEP 2: Saved Emojis (Library) -->

    <div class="card" style="border-color:rgba(0,245,255,.3)">

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">

        <div style="width:32px;height:32px;background:rgba(0,245,255,.1);border:2px solid rgba(0,245,255,.4);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:var(--c);flex-shrink:0">2</div>

        <div>

          <div class="st" style="color:var(--c);font-size:12px">SAVED EMOJIS — CLICK TO COPY</div>

          <div style="font-size:10px;color:var(--td);margin-top:1px">Copy the placeholder to use in any message</div>
        </div>
      </div>

      <!-- Search + multi-select toolbar -->

      <div style="display:flex;align-items:center;gap:7px;margin-bottom:10px;flex-wrap:wrap">
        <input type="text" id="pemj-search" class="fi" placeholder="🔍 Label se dhundho..." oninput="filterPemjLibrary()" style="flex:1;min-width:140px;font-size:12px">
        <button class="btn bsm" onclick="pemjSelectAll()" style="font-size:10px;background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;padding:4px 9px;white-space:nowrap">☑️ All</button>
        <button class="btn bsm" onclick="pemjClearSel()" style="font-size:10px;background:rgba(100,100,120,.15);border:1px solid rgba(150,150,170,.3);color:var(--td);padding:4px 9px;white-space:nowrap">✖ Clear</button>
        <button class="btn bsm" id="pemj-bulk-del-btn" onclick="pemjBulkDelete()" style="font-size:10px;background:rgba(255,45,85,.12);border:1px solid rgba(255,45,85,.5);color:var(--r);padding:4px 9px;white-space:nowrap;display:none">🗑 Delete Selected</button>
      </div>

      <div id="pemj-sel-count" style="font-size:10px;color:var(--td);font-family:'Share Tech Mono';margin-bottom:8px;display:none">0 selected</div>

      <div id="pemj-list" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px;max-height:340px;overflow-y:auto">

        <div style="color:var(--td);font-size:12px;text-align:center;grid-column:1/-1;padding:20px">⏳ Loading...</div>
      </div>
    </div>

    <!-- STEP 3: Use in Messages -->

    <div class="card" style="border-color:rgba(255,159,10,.3)">

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">

        <div style="width:32px;height:32px;background:rgba(255,159,10,.1);border:2px solid rgba(255,159,10,.4);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;color:var(--o);flex-shrink:0">3</div>

        <div>

          <div class="st" style="color:var(--o);font-size:12px">USE IN FLOW BUILDER</div>

          <div style="font-size:10px;color:var(--td);margin-top:1px">Press 💎 button while writing the message — direct insert!</div>
        </div>
      </div>

      <div style="background:rgba(255,159,10,.06);border:1px solid rgba(255,159,10,.2);border-radius:8px;padding:12px;font-size:12px;color:var(--td);line-height:2">
        <b style="color:var(--o)">Flow Builder</b> → Page Edit/New → Go to Message Template section<br>
        <b style="color:var(--t)">💎 Premium Emoji Insert</b> button will appear → click it → select emoji → <b style="color:var(--g)">insert!</b><br>
        <span style="font-size:10px">Or type directly: <code style="color:var(--c)">{emoji_fire}</code> <code style="color:var(--c)">{emoji_star}</code> etc.</span>
      </div>
    </div>

    <!-- Test & Broadcast collapsed cards -->

    <div class="card" style="padding:0;overflow:hidden">

      <!-- Test accordion -->

      <div onclick="togglePemjAccordion('test')" style="display:flex;align-items:center;justify-content:space-between;padding:13px 16px;cursor:pointer;background:rgba(0,245,255,.03);border-bottom:1px solid rgba(0,245,255,.15)">

        <div style="font-size:12px;font-weight:700;color:var(--c)">🧪 Test — Send to Someone</div>
        <span id="pemj-acc-test-arrow" style="color:var(--td);font-size:12px;transition:transform .2s">▼</span>
      </div>

      <div id="pemj-acc-test" style="display:none;padding:14px;border-bottom:1px solid var(--b)">

        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
          <input type="text" id="pemj-test-chatid" class="fi" placeholder="Chat ID (apna Telegram ID)" style="flex:1;min-width:140px">
          <select id="pemj-test-select" class="fsel" style="flex:2;min-width:180px"><option value="">— Select an emoji —</option></select>
        </div>
        <input type="text" id="pemj-test-caption" class="fi" placeholder="Caption (optional)" style="margin-bottom:8px">
        <button class="btn bp bsm" onclick="testSendPremEmoji()" style="width:100%;padding:9px">📤 Test Send</button>

        <div id="pemj-test-result" style="display:none;margin-top:8px;padding:8px;border-radius:6px;font-size:12px;font-family:'Share Tech Mono'"></div>
      </div>

      <!-- Broadcast accordion -->

      <div onclick="togglePemjAccordion('bc')" style="display:flex;align-items:center;justify-content:space-between;padding:13px 16px;cursor:pointer;background:rgba(255,45,85,.03)">

        <div style="font-size:12px;font-weight:700;color:var(--r)">📣 Broadcast — To All Users</div>
        <span id="pemj-acc-bc-arrow" style="color:var(--td);font-size:12px;transition:transform .2s">▼</span>
      </div>

      <div id="pemj-acc-bc" style="display:none;padding:14px">

        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
          <select id="pemj-bc-select" class="fsel" style="flex:1"><option value="">— Select an emoji —</option></select>
        </div>
        <input type="text" id="pemj-bc-caption" class="fi" placeholder="Caption (optional)" style="margin-bottom:8px">

        <div style="font-size:10px;color:var(--r);margin-bottom:8px">⚠️ Sab users ko jayega. Pehle Test karo!</div>
        <button class="btn bd bsm" onclick="broadcastPremEmoji()" style="width:100%;padding:9px">📣 Broadcast</button>

        <div id="pemj-bc-result" style="display:none;margin-top:8px;padding:8px;border-radius:6px;font-size:12px;font-family:'Share Tech Mono'"></div>
      </div>
    </div>
  </div>

  <!-- USERS -->

  <div class="panel" id="p-users"><div class="card"><div class="sh"><div class="st">👥 USERS <span id="users-count" style="font-size:11px;color:var(--td)"></span></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><input class="fi" id="users-search" placeholder="Search name, ID, username..." style="width:200px;padding:6px 10px;font-size:12px" oninput="usersSearchDebounced()"><button class="btn bg bsm" onclick="loadUsers(1)">🔄</button><button class="btn bo bsm" onclick="repairUsers()" title="Fix missing users">🔧 Repair</button></div></div><div id="users-bot-hint" style="font-size:11px;color:var(--y);padding:0 0 8px;display:none"></div><div class="tr"><div class="tw"><table><thead><tr><th>Name</th><th>ID</th><th>Searches</th><th>Key</th><th>Status</th><th>Action</th></tr></thead><tbody id="ub"></tbody></table></div></div><div id="users-pager" style="display:flex;justify-content:space-between;align-items:center;padding:10px 0 0;gap:8px;flex-wrap:wrap"></div></div></div>

  <!-- USER KEYS -->

  <div class="panel" id="p-ukeys"><div class="card"><div class="sh"><div class="st">🔑 USER KEYS</div><button class="btn bg bsm" onclick="loadUK()">🔄</button></div><div class="tr"><div class="tw"><table><thead><tr><th>Key</th><th>Quota</th><th>Expires</th><th>Status</th><th>Del</th></tr></thead><tbody id="ukb"></tbody></table></div></div></div></div>

  <!-- LICENCE KEYS -->

  <div class="panel" id="p-lkeys"><div class="card"><div class="sh"><div class="st">🪪 LICENCE KEYS</div><button class="btn bg bsm" onclick="loadLK()">🔄</button></div><div class="tr"><div class="tw"><table><thead><tr><th>Key</th><th>Tier</th><th>Quota</th><th>Status</th><th>Del</th></tr></thead><tbody id="lkb"></tbody></table></div></div></div></div>

  <!-- KEY GEN -->

  <div class="panel" id="p-keygen"><div class="card"><div class="sh"><div class="st">⚡ KEY GENERATOR</div></div><div class="fg mb"><div class="fgrp"><label class="fl">Type</label><select class="fsel" id="kg-t"><option value="USER">User Key</option><option value="LIC">Licence</option></select></div><div class="fgrp"><label class="fl">Quota</label><input type="number" class="fi" id="kg-s" value="100"></div><div class="fgrp"><label class="fl">Qty</label><input type="number" class="fi" id="kg-q" value="1" min="1"></div></div><button class="btn bp" onclick="genKeys()" style="width:100%">⚡ Generate</button><div id="kg-out" style="margin-top:12px"></div></div></div>

  <!-- GUIDE -->

  <div class="panel" id="p-guide"><div class="card"><div class="sh"><div class="st" style="color:var(--g)">📖 COMPLETE GUIDE</div></div>

    <div style="background:var(--s2);border-left:3px solid var(--g);border-radius:8px;padding:14px;margin-bottom:14px">

      <div style="color:var(--g);font-family:'Orbitron';font-size:11px;margin-bottom:8px">v7.1 BUG FIXES</div>

      <div style="font-size:12px;color:var(--td);line-height:2">
        <b style="color:var(--t)">Fix 1 — Free Text as Command:</b> Pages with FREE TEXT mode ON are now completely ignored in the command handler. They only fire for non-command messages.<br>
        <b style="color:var(--t)">Fix 2 — Multiple Free Text Pages:</b> You can have multiple Free Text pages — the first matching one fires (by chat mode + access control). Global Free Text is fallback.<br>
        <b style="color:var(--t)">Fix 3 — cURL Parser:</b> Complete rewrite. Now correctly parses single/double/no quotes, multiline curl, --data-raw, --data-binary, $'...' style, nested JSON bodies.<br>
        <b style="color:var(--t)">Fix 4 — cURL Slow API:</b> Bot sends "⏳ Please wait..." message first, then edits it with the result. Timeout increased to 120s. No more blank responses.
      </div>
    </div>

    <div style="background:var(--s2);border-left:3px solid var(--c);border-radius:8px;padding:14px;margin-bottom:14px">

      <div style="color:var(--c);font-family:'Orbitron';font-size:11px;margin-bottom:8px">FREE TEXT USAGE</div>

      <div style="background:rgba(0,0,0,.4);border:1px solid var(--b);border-radius:6px;padding:10px;font-family:'Share Tech Mono';font-size:11px;color:var(--td);line-height:2">
        Per-page (Flow Builder):<br>
        → Create page → check FREE TEXT → set chat mode<br>
        → This page replies to non-command messages<br>
        → Multiple FT pages = first matching one fires<br><br>
        Global (Bot Config → Free Text):<br>
        → Used when NO per-page FT matches<br>
        → Simple text/media reply only
      </div>
    </div>

    <div style="background:var(--s2);border-left:3px solid var(--r);border-radius:8px;padding:14px;margin-bottom:14px">

      <div style="color:var(--r);font-family:'Orbitron';font-size:11px;margin-bottom:8px">CURL PAGE TIPS</div>

      <div style="background:rgba(0,0,0,.4);border:1px solid var(--b);border-radius:6px;padding:10px;font-family:'Share Tech Mono';font-size:11px;color:var(--td);line-height:2">
        Paste your curl command → click ⚡ Parse<br>
        Works with: -d, --data, --data-raw, --data-binary<br>
        Supports: single quotes, double quotes, $'...' style<br>
        Multiline curl (with \ line continuation) also works<br><br>
        Slow API? Bot sends "⏳ Please wait..." and edits<br>
        when response arrives (up to 120 seconds wait).<br>
        You can also set "Loading Message" in the page.
      </div>
    </div>
  </div></div>

  <!-- WELCOME MESSAGE PANEL -->

  <div class="panel" id="p-welcome">

    <div class="card" style="border-color:rgba(57,255,20,.4)">

      <div class="sh">

        <div class="st" style="color:var(--g)">👋 WELCOME MESSAGE</div>

        <div style="display:flex;align-items:center;gap:8px">
          <span id="wm-status-label" style="font-family:'Share Tech Mono';font-size:11px;color:var(--td)">OFF</span>
          <button id="wm-toggle-btn" class="btn bsm bg" onclick="toggleWelcome()" style="min-width:72px">Enable</button>
        </div>
      </div>
      <p style="font-size:12px;color:var(--td);margin-bottom:12px">Bot sends this message automatically when a new member joins the group. Bot must be an <b style="color:var(--t)">admin</b> in the group with message permission.</p>

      <div style="background:rgba(57,255,20,.05);border:1px solid rgba(57,255,20,.2);border-radius:8px;padding:10px 12px;margin-bottom:14px;font-family:'Share Tech Mono';font-size:11px;color:var(--g);line-height:2">
        <b>Placeholders:</b><br>
        <span style="color:var(--c)">{tg_name}</span> — First name &nbsp;|&nbsp; <span style="color:var(--c)">{tg_username}</span> — @username<br>
        <span style="color:var(--c)">{tg_id}</span> — User ID &nbsp;|&nbsp; <span style="color:var(--c)">{tg_mention}</span> — Clickable mention (works for all users)
      </div>

      <div class="fgrp mb">
        <label class="fl" style="color:var(--g)">💬 Welcome Text</label>
        <button type="button" onclick="toggleMiniEmojiPicker('wm-text')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="wm-text-emoji-arrow" style="font-size:8px">▼</span></button>
        <div id="wm-text-emoji-panel" style="display:none;margin-bottom:8px"></div>
        <textarea id="wm-text" class="fta" style="min-height:100px" placeholder="👋 Welcome {tg_mention} to the group!&#10;&#10;Glad to have you here 🎉"></textarea>
      </div>

      <div class="fgrp mb">
        <label class="fl">🖼️ Media URL (optional)</label>

        <div style="display:flex;gap:7px"><input type="text" id="wm-media" class="fi" placeholder="https://..."><button class="btn bg bsm" onclick="tup('wm-media')">📁</button></div>
      </div>

      <div style="margin-bottom:14px">

        <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--c);text-transform:uppercase;margin-bottom:8px">🔗 URL Buttons (optional)</div>

        <div id="wm-buttons"></div>
        <button class="btn bg bsm" onclick="addWmButton()" style="margin-top:6px">+ Add Button</button>
      </div>
      <button class="btn bsu" onclick="saveWelcome()" style="width:100%;padding:11px">💾 Save Welcome Settings</button>
    </div>
  </div>

  <!-- USER TAGGER PANEL -->

  <div class="panel" id="p-tagger">

    <div class="card" style="border-color:rgba(255,159,10,.4)">

      <div class="sh">

        <div class="st" style="color:var(--o)">📣 USER TAGGER</div>

        <div style="display:flex;align-items:center;gap:8px">
          <span id="ut-status-label" style="font-family:'Share Tech Mono';font-size:11px;color:var(--td)">OFF</span>
          <button id="ut-toggle-btn" class="btn bsm bg" onclick="toggleTagger()" style="min-width:72px">Enable</button>
        </div>
      </div>
      <p style="font-size:12px;color:var(--td);margin-bottom:12px">When a <b style="color:var(--t)">group admin</b> types the trigger word (e.g. <code style="color:var(--o)">@all</code>), the bot tags all tracked group members. Admin can also write a custom message: <code style="color:var(--c)">@all Please read the pinned post!</code></p>

      <div style="background:rgba(255,159,10,.06);border:1px solid rgba(255,159,10,.25);border-radius:8px;padding:10px 12px;margin-bottom:14px;font-size:11px;color:var(--o);line-height:1.9;font-family:'Share Tech Mono'">
        ⚡ <b>How tracking works:</b><br>
        • Bot records every member who sends a message in the group<br>
        • New members who join are also tracked automatically<br>
        • Group admins are always fetched live from Telegram API<br>
        • The more members interact, the bigger your tag list gets
      </div>

      <div class="fg mb">

        <div class="fgrp">
          <label class="fl">🎯 Trigger Word</label>
          <input type="text" id="ut-trigger" class="fi" placeholder="@all" value="@all">
        </div>

        <div class="fgrp">
          <label class="fl">📦 Users Per Message (1–10)</label>
          <input type="number" id="ut-batch" class="fi" value="5" min="1" max="10">
        </div>

        <div class="fgrp">
          <label class="fl">⏱️ Delay Between Messages (sec)</label>
          <input type="number" id="ut-delay" class="fi" value="1" min="0.3" max="10" step="0.5">
        </div>
      </div>

      <div class="fgrp mb">
        <label class="fl" style="color:var(--o)">📢 Header Message</label>
        <textarea id="ut-message" class="fta" style="min-height:60px" placeholder="📢 Attention everyone!"></textarea>
      </div>

      <!-- Premium Emoji Picker for Tagger Header -->

      <div style="background:rgba(191,90,242,.06);border:1px solid rgba(191,90,242,.25);border-radius:10px;padding:12px;margin-bottom:14px">

        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <span style="font-size:11px;font-weight:600;color:#bf5af2;font-family:'Share Tech Mono'">✨ Premium Emoji — Header me insert karo</span>
          <button class="btn bsm" onclick="utLoadEmojiPicker()" style="font-size:10px;background:rgba(191,90,242,.15);border:1px solid rgba(191,90,242,.4);color:#bf5af2;padding:3px 9px">🔄 Refresh</button>
        </div>

        <div id="ut-emoji-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(72px,1fr));gap:6px;max-height:180px;overflow-y:auto;padding-right:2px">

          <div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:10px">⏳ Loading...</div>
        </div>

        <div style="margin-top:8px;font-size:10px;color:var(--td);font-family:'Share Tech Mono'">💡 Emoji pe click karo — cursor jahan hai wahan will be inserted</div>
      </div>
      <button class="btn bo" onclick="saveTagger()" style="width:100%;padding:11px">💾 Save Tagger Settings</button>
    </div>

    <div class="card" style="border-color:rgba(255,159,10,.2)">

      <div class="sh"><div class="st" style="color:var(--o)">📊 GROUP MEMBER STATS</div><button class="btn bg bsm" onclick="loadTaggerStats()">🔄 Refresh</button></div>

      <div id="ut-groups-container">

        <div style="text-align:center;color:var(--td);font-size:12px;padding:16px">Loading group data...</div>
      </div>

      <div style="margin-top:10px;font-size:11px;color:var(--td);font-family:'Share Tech Mono'">Each group is tracked separately. Members grow as they chat.</div>
    </div>
  </div>

  <!-- HIDDEN EYE BOT PANEL -->
  <div class="panel" id="p-hiddeneye">

    <!-- STATS ROW -->
    <div class="sg" id="he-stats-grid" style="margin-bottom:16px">
      <div class="sc"><div class="sn" id="he-st-users" style="color:#39ff14">—</div><div class="sl">👤 Operatives</div></div>
      <div class="sc"><div class="sn" id="he-st-groups" style="color:var(--c)">—</div><div class="sl">👥 Networks</div></div>
      <div class="sc"><div class="sn" id="he-st-quizzes" style="color:var(--o)">—</div><div class="sl">🧠 Quizzes Run</div></div>
      <div class="sc"><div class="sn" id="he-st-banned" style="color:var(--r)">—</div><div class="sl">🚫 Banned</div></div>
    </div>

    <!-- CONFIG CARD -->
    <div class="card" style="border-color:rgba(57,255,20,.35)">
      <div class="sh"><div class="st" style="color:#39ff14">⚙️ HIDDEN EYE CONFIG</div><button class="btn bsm" onclick="heSaveConfig()" style="background:rgba(57,255,20,.15);border:1px solid rgba(57,255,20,.5);color:#39ff14">💾 Save</button></div>
      <div class="fg mb">
        <div class="fgrp">
          <label class="fl">🔑 OpenRouter API Key</label>
          <input type="password" id="he-or-key" class="fi" placeholder="sk-or-v1-...">
        </div>
        <div class="fgrp">
          <label class="fl">📡 Community Channel (e.g. @YourChannel)</label>
          <input type="text" id="he-channel" class="fi" placeholder="@Crack_by_izen">
        </div>
        <div class="fgrp">
          <label class="fl">⏱️ Quiz Timer (seconds per question)</label>
          <input type="number" id="he-timer" class="fi" value="120" min="30" max="600">
        </div>
        <div class="fgrp">
          <label class="fl">🔢 Bot Version String</label>
          <input type="text" id="he-version" class="fi" placeholder="3.1.7">
        </div>
      </div>
    </div>

    <!-- QUIZ GENERATOR CARD -->
    <div class="card" style="border-color:rgba(0,245,255,.35)">
      <div class="sh"><div class="st" style="color:var(--c)">🧠 AI QUIZ GENERATOR</div><button class="btn bsm bg" onclick="heGenerateQuiz()" id="he-gen-btn">⚡ Generate</button></div>
      <p style="font-size:12px;color:var(--td);margin-bottom:12px">Generate a quiz with AI (OpenRouter) and send it directly to a group in Telegram poll format.</p>
      <div class="fg mb">
        <div class="fgrp">
          <label class="fl">📚 Domain / Subject</label>
          <select class="fsel" id="he-domain">
            <optgroup label="🎓 Competitive Exams">
              <option>NEET</option><option>JEE MAIN</option><option>GATE</option><option>IBPS PO</option>
              <option>SSC CGL</option><option>SSC GD</option><option>NDA</option><option>CDS</option>
              <option>DRDO</option><option>UPSC</option><option>Railways (RRB)</option><option>Police Exam</option>
            </optgroup>
            <optgroup label="📖 Academic Domains">
              <option>Physics</option><option>Chemistry</option><option>Biology</option><option>Mathematics</option>
              <option>Computer Science</option><option>History</option><option>Geography</option><option>Literature</option>
              <option>Economics</option><option>Psychology</option><option>General Knowledge</option>
              <option>Astronomy</option><option>Mythology</option><option>Music</option><option>Cinema & Movies</option>
              <option>Gaming</option><option>Medicine</option><option>Artificial Intelligence</option>
              <option>Business & Finance</option><option>Law</option><option>Sports</option>
              <option>Anime & Manga</option><option>Cryptocurrency</option><option>Cyber Security</option>
              <option>Cloud Computing</option><option>Philosophy</option><option>Electronics</option>
            </optgroup>
          </select>
        </div>
        <div class="fgrp">
          <label class="fl">⚡ Difficulty</label>
          <select class="fsel" id="he-difficulty">
            <option value="Easy">🟢 Easy</option>
            <option value="Hard">🟠 Hard</option>
            <option value="Impossible">🔴 Impossible</option>
          </select>
        </div>
        <div class="fgrp">
          <label class="fl">🔢 Number of Questions (1-20)</label>
          <input type="number" id="he-numq" class="fi" value="5" min="1" max="20">
        </div>
      </div>

      <!-- Generated Questions Preview -->
      <div id="he-quiz-preview" style="display:none;margin-bottom:12px">
        <div style="font-size:11px;color:var(--g);font-family:'Share Tech Mono';margin-bottom:8px" id="he-quiz-meta"></div>
        <div id="he-quiz-list" style="max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:8px"></div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <input type="text" id="he-send-chatid" class="fi" placeholder="Group Chat ID (e.g. -100123456)" style="flex:1;min-width:180px">
          <button class="btn bsu" onclick="heSendQuizToGroup()" id="he-send-btn">📤 Send to Group</button>
        </div>
      </div>
    </div>

    <!-- USERS / LEADERBOARD CARD -->
    <div class="card" style="border-color:rgba(191,90,242,.35)">
      <div class="sh">
        <div class="st" style="color:#bf5af2">👥 OPERATIVE DATABASE</div>
        <div style="display:flex;gap:6px">
          <input type="text" id="he-user-search" class="fi" placeholder="🔍 Search..." style="width:140px;font-size:11px" oninput="heFilterUsers()">
          <button class="btn bsm bg" onclick="heLoadUsers()">🔄</button>
        </div>
      </div>
      <div id="he-users-table" style="overflow-x:auto">
        <div style="color:var(--td);font-size:12px;padding:12px;text-align:center">Loading operatives...</div>
      </div>
    </div>

    <!-- ADMIN MANAGEMENT CARD -->
    <div class="card" style="border-color:rgba(255,159,10,.35)">
      <div class="sh"><div class="st" style="color:var(--o)">🛡️ ADMIN MANAGEMENT</div><button class="btn bsm bg" onclick="heLoadAdmins()">🔄</button></div>
      <div style="display:flex;gap:7px;margin-bottom:10px;flex-wrap:wrap">
        <input type="text" id="he-new-admin-id" class="fi" placeholder="Telegram User ID" style="flex:1;min-width:140px">
        <button class="btn bsm" onclick="heAddAdmin()" style="background:rgba(57,255,20,.15);border:1px solid rgba(57,255,20,.5);color:#39ff14">+ Add Admin</button>
      </div>
      <div id="he-admins-list" style="display:flex;flex-wrap:wrap;gap:6px">
        <div style="color:var(--td);font-size:12px">Loading admins...</div>
      </div>
    </div>

    <!-- BROADCAST CARD -->
    <div class="card" style="border-color:rgba(255,45,85,.35)">
      <div class="sh"><div class="st" style="color:var(--r)">📢 HE BROADCAST</div></div>
      <p style="font-size:12px;color:var(--td);margin-bottom:10px">Send a message to all registered HiddenEye users (banned users will be skipped).</p>
      <div class="fgrp mb">
        <label class="fl">📝 Message (HTML ok)</label>
        <textarea id="he-bcast-msg" class="fta" style="min-height:80px" placeholder="👁 HIDDEN EYE ALERT&#10;━━━━━━━━━━━━&#10;Your message here..."></textarea>
      </div>
      <button class="btn bd" onclick="heBroadcast()" id="he-bcast-btn" style="width:100%;padding:10px">📤 Send Broadcast to All Operatives</button>
    </div>

    <!-- GROUPS CARD -->
    <div class="card" style="border-color:rgba(0,245,255,.2)">
      <div class="sh"><div class="st" style="color:var(--c)">🌐 NETWORK GROUPS</div><button class="btn bsm bg" onclick="heLoadGroups()">🔄</button></div>
      <div id="he-groups-table" style="overflow-x:auto">
        <div style="color:var(--td);font-size:12px;padding:12px;text-align:center">Loading networks...</div>
      </div>
    </div>
  </div><!-- /p-hiddeneye -->

  <!-- ═══ APK RENAMER PANEL ═══ -->
  <div class="panel" id="p-apkrenamer">
    <div class="card">
      <div style="font-family:Orbitron;font-size:14px;color:var(--c);margin-bottom:14px">📦 APK Renamer</div>
      <p style="font-size:12px;color:var(--td);margin-bottom:16px">
        User sends APK to bot → bot renames it and sends it back.<br>
        Caption variables: <code style="background:rgba(0,245,255,.1);padding:1px 5px;border-radius:3px">{original_name}</code>
        <code style="background:rgba(0,245,255,.1);padding:1px 5px;border-radius:3px">{new_name}</code>
        <code style="background:rgba(0,245,255,.1);padding:1px 5px;border-radius:3px">{tg_name}</code>
      </p>
      <div class="fgrp" style="margin-bottom:12px">
        <label class="fl">Status</label>
        <select id="apkr-enabled" class="fi" style="max-width:220px">
          <option value="0">❌ Disabled</option>
          <option value="1">✅ Enabled</option>
        </select>
      </div>
      <div class="fgrp" style="margin-bottom:12px">
        <label class="fl">📝 New APK Name <span style="color:var(--td);font-size:10px">(do not include .apk)</span></label>
        <input type="text" id="apkr-name" class="fi" placeholder="e.g. RebelApp" style="max-width:320px">
      </div>
      <div class="fgrp" style="margin-bottom:12px">
        <label class="fl">💬 Caption</label>
        <textarea id="apkr-caption" class="fi" rows="4" placeholder="✅ {new_name} is ready!&#10;&#10;📁 Original: {original_name}"></textarea>
      </div>
      <div class="fgrp" style="margin-bottom:18px">
        <label class="fl">Admin Only</label>
        <select id="apkr-adminonly" class="fi" style="max-width:220px">
          <option value="0">👥 All users can use</option>
          <option value="1">👑 Admin Only</option>
        </select>
      </div>
      <button class="btn bp" onclick="apkrSave()">💾 Save Settings</button>
    </div>
  </div>

  <!-- ═══ ROSE BOT PANEL ═══ -->
  <div class="panel" id="p-rosebot">
    <div class="card" style="border-color:rgba(255,107,157,.3)">
      <div style="font-family:Orbitron;font-size:15px;color:#ff6b9d;margin-bottom:6px">🔥 The Rebel Bot — Group Management</div>
      <p style="font-size:12px;color:var(--td);margin-bottom:18px">Full group management system — warns, bans, filters, notes, locks, flood control and more.</p>

      <!-- Enable Toggle -->
      <div class="fgrp" style="margin-bottom:18px">
        <label class="fl">Status</label>
        <select id="rose-enabled" class="fi" style="max-width:220px">
          <option value="0">❌ Disabled</option>
          <option value="1">✅ Enabled</option>
        </select>
      </div>

      <!-- WARN SETTINGS -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:12px">⚠️ WARN SETTINGS</div>
        <div class="fg mb">
          <div class="fgrp">
            <label class="fl">Warn Limit</label>
            <input type="number" id="rose-warn-limit" class="fi" value="3" min="1" max="20" style="max-width:120px">
          </div>
          <div class="fgrp">
            <label class="fl">Action at Limit</label>
            <select id="rose-warn-action" class="fi" style="max-width:180px">
              <option value="kick">👢 Kick</option>
              <option value="ban">🚫 Ban</option>
              <option value="mute">🔇 Mute</option>
            </select>
          </div>
          <div class="fgrp">
            <label class="fl">Mute Duration (min) <span style="color:var(--td);font-size:10px">if action=mute</span></label>
            <input type="number" id="rose-warn-mute" class="fi" value="60" min="1" style="max-width:120px">
          </div>
        </div>
      </div>

      <!-- FLOOD CONTROL -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:12px">🌊 FLOOD CONTROL</div>
        <div class="fg mb">
          <div class="fgrp">
            <label class="fl">Status</label>
            <select id="rose-flood-enabled" class="fi" style="max-width:180px">
              <option value="0">❌ Disabled</option>
              <option value="1">✅ Enabled</option>
            </select>
          </div>
          <div class="fgrp">
            <label class="fl">Message Limit</label>
            <input type="number" id="rose-flood-limit" class="fi" value="5" min="2" style="max-width:120px">
          </div>
          <div class="fgrp">
            <label class="fl">Window (seconds)</label>
            <input type="number" id="rose-flood-window" class="fi" value="10" min="3" style="max-width:120px">
          </div>
          <div class="fgrp">
            <label class="fl">Flood Action</label>
            <select id="rose-flood-action" class="fi" style="max-width:180px">
              <option value="mute">🔇 Mute</option>
              <option value="kick">👢 Kick</option>
              <option value="ban">🚫 Ban</option>
            </select>
          </div>
          <div class="fgrp">
            <label class="fl">Mute Duration (min)</label>
            <input type="number" id="rose-flood-mute" class="fi" value="5" min="1" style="max-width:120px">
          </div>
        </div>
      </div>

      <!-- RULES -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:10px">📜 RULES</div>
        <div class="fgrp">
          <label class="fl">Group Rules (HTML supported). Users can view them with /rules.</label>
          <textarea id="rose-rules" class="fi" rows="5" placeholder="1. Respect everyone&#10;2. No spam&#10;3. Follow admins"></textarea>
        </div>
      </div>

      <!-- BLACKLIST -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:10px">🚫 BLACKLIST</div>
        <div class="fg mb">
          <div class="fgrp" style="flex:2">
            <label class="fl">Blacklisted Words (comma separated)</label>
            <textarea id="rose-blacklist" class="fi" rows="3" placeholder="badword1, badword2, badword3"></textarea>
          </div>
          <div class="fgrp">
            <label class="fl">Action</label>
            <select id="rose-bl-action" class="fi" style="max-width:180px">
              <option value="delete">🗑 Delete Only</option>
              <option value="warn">⚠️ Warn</option>
              <option value="ban">🚫 Ban</option>
            </select>
          </div>
        </div>
      </div>

      <!-- LOCKS -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:12px">🔒 CONTENT LOCKS</div>
        <div style="display:flex;flex-wrap:wrap;gap:10px" id="rose-locks-grid"></div>
      </div>

      <!-- REPORT -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:10px">🚨 REPORT SYSTEM</div>
        <div class="fg mb">
          <div class="fgrp">
            <label class="fl">Report Enabled</label>
            <select id="rose-report-enabled" class="fi" style="max-width:180px">
              <option value="1">✅ Yes</option>
              <option value="0">❌ No</option>
            </select>
          </div>
          <div class="fgrp" style="flex:2">
            <label class="fl">Report Reply Message</label>
            <input type="text" id="rose-report-reply" class="fi" placeholder="🚨 Report sent! Admins notified.">
          </div>
        </div>
      </div>

      <!-- MISC -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.2);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:11px;color:#ff6b9d;margin-bottom:12px">⚙️ MISC SETTINGS</div>
        <div class="fg mb">
          <div class="fgrp">
            <label class="fl">Clean Service Messages <span style="color:var(--td);font-size:10px">(join/leave msgs)</span></label>
            <select id="rose-cleanservice" class="fi" style="max-width:180px">
              <option value="0">❌ Off</option>
              <option value="1">✅ On</option>
            </select>
          </div>
          <div class="fgrp" style="flex:2">
            <label class="fl">📡 Log Channel ID <span style="color:var(--td);font-size:10px">(optional, e.g. -100...)</span></label>
            <input type="text" id="rose-logchannel" class="fi" placeholder="-1001234567890">
          </div>
        </div>
      </div>

      <!-- ═══ REPLY MESSAGES EDITOR ═══ -->
      <div style="background:rgba(255,107,157,.06);border:1px solid rgba(255,107,157,.35);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-family:Orbitron;font-size:12px;color:#ff6b9d;margin-bottom:6px">✏️ REPLY MESSAGES — Edit Every Bot Reply</div>
        <div style="font-size:11px;color:var(--td);margin-bottom:12px;line-height:1.8">
          Customize all bot automatic replies from here.<br>
          <b style="color:#ff6b9d">Variables:</b>
          <span class="vpill">{mention}</span>
          <span class="vpill">{name}</span>
          <span class="vpill">{reason}</span>
          <span class="vpill">{duration}</span>
          <span class="vpill">{count}</span>
          <span class="vpill">{limit}</span>
          <span class="vpill">{action}</span>
          <span class="vpill">{locktype}</span>
        </div>

        <!-- Emoji Picker for Reply Messages -->
        <div style="background:rgba(191,90,242,.06);border:1px solid rgba(191,90,242,.25);border-radius:8px;padding:10px;margin-bottom:14px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <span style="font-size:11px;font-weight:600;color:#bf5af2;font-family:'Share Tech Mono'">✨ Premium Emoji — Reply mein insert karo</span>
            <button class="btn bsm" onclick="roseLoadEmojiPicker()" style="font-size:10px;background:rgba(191,90,242,.15);border:1px solid rgba(191,90,242,.4);color:#bf5af2;padding:3px 9px">🔄 Load</button>
          </div>
          <div id="rose-emoji-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(72px,1fr));gap:6px;max-height:160px;overflow-y:auto;padding-right:2px">
            <div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:10px">Click 🔄 Load to show emojis</div>
          </div>
          <div style="margin-top:7px;font-size:10px;color:var(--td);font-family:'Share Tech Mono'">💡 Place cursor in any textarea → click the emoji → insert!</div>
        </div>

        <!-- Warn Messages -->
        <div style="background:rgba(255,214,10,.05);border:1px solid rgba(255,214,10,.2);border-radius:8px;padding:12px;margin-bottom:10px">
          <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--y);margin-bottom:10px">⚠️ WARN MESSAGES</div>
          <div class="fg mb">
            <div class="fgrp">
              <label class="fl">Warn Notification <span style="color:var(--td);font-size:9px">({mention} {count} {limit} {reason})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-warn')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-warn-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-warn-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-warn" class="fta" style="min-height:70px" placeholder="⚠️ &lt;b&gt;{mention} has been warned!&lt;/b&gt; [{count}/{limit}]&#10;Reason: {reason}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Warn Limit Reached <span style="color:var(--td);font-size:9px">({mention} {action})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-warn-limit')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-warn-limit-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-warn-limit-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-warn-limit" class="fta" style="min-height:70px" placeholder="🚨 {mention} has hit the warn limit! Action: &lt;b&gt;{action}&lt;/b&gt;"></textarea>
            </div>
          </div>
        </div>

        <!-- Ban/Kick/Mute Messages -->
        <div style="background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.2);border-radius:8px;padding:12px;margin-bottom:10px">
          <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--r);margin-bottom:10px">🚫 BAN / KICK / MUTE MESSAGES</div>
          <div class="fg mb">
            <div class="fgrp">
              <label class="fl">Ban Message <span style="color:var(--td);font-size:9px">({mention} {reason})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-ban')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-ban-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-ban-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-ban" class="fta" style="min-height:65px" placeholder="🚫 &lt;b&gt;User Banned!&lt;/b&gt;&#10;👤 {mention}&#10;📝 Reason: {reason}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Temp Ban Message <span style="color:var(--td);font-size:9px">({mention} {duration} {reason})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-tban')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-tban-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-tban-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-tban" class="fta" style="min-height:65px" placeholder="⏳ &lt;b&gt;User Temp Banned!&lt;/b&gt;&#10;👤 {mention}&#10;⏱ Duration: {duration}&#10;📝 {reason}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Kick Message <span style="color:var(--td);font-size:9px">({mention} {reason})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-kick')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-kick-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-kick-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-kick" class="fta" style="min-height:65px" placeholder="👢 &lt;b&gt;User Kicked!&lt;/b&gt;&#10;👤 {mention}&#10;📝 Reason: {reason}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Mute Message <span style="color:var(--td);font-size:9px">({mention} {duration} {reason})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-mute')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-mute-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-mute-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-mute" class="fta" style="min-height:65px" placeholder="🔇 &lt;b&gt;User Muted!&lt;/b&gt;&#10;👤 {mention}&#10;⏱ Duration: {duration}&#10;📝 {reason}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Unban Message <span style="color:var(--td);font-size:9px">({mention})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-unban')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-unban-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-unban-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-unban" class="fta" style="min-height:65px" placeholder="✅ &lt;b&gt;User Unbanned!&lt;/b&gt;&#10;👤 {mention}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Unmute Message <span style="color:var(--td);font-size:9px">({mention})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-unmute')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-unmute-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-unmute-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-unmute" class="fta" style="min-height:65px" placeholder="🔊 &lt;b&gt;User Unmuted!&lt;/b&gt;&#10;👤 {mention}"></textarea>
            </div>
          </div>
        </div>

        <!-- Flood / Blacklist Messages -->
        <div style="background:rgba(0,245,255,.04);border:1px solid rgba(0,245,255,.2);border-radius:8px;padding:12px;margin-bottom:10px">
          <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--c);margin-bottom:10px">🌊 FLOOD / BLACKLIST / LOCKS</div>
          <div class="fg mb">
            <div class="fgrp">
              <label class="fl">Flood Detected Message</label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-flood')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-flood-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-flood-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-flood" class="fta" style="min-height:55px" placeholder="⚠️ &lt;b&gt;Flood Detected!&lt;/b&gt; Slow down!"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Blacklist Delete Message</label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-blacklist')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-blacklist-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-blacklist-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-blacklist" class="fta" style="min-height:55px" placeholder="⚠️ That word is not allowed here."></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Content Locked Message <span style="color:var(--td);font-size:9px">({locktype})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-locked')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-locked-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-locked-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-locked" class="fta" style="min-height:55px" placeholder="🔒 &lt;b&gt;{locktype} are locked&lt;/b&gt; in this group."></textarea>
            </div>
          </div>
        </div>

        <!-- Admin Action Messages -->
        <div style="background:rgba(57,255,20,.04);border:1px solid rgba(57,255,20,.2);border-radius:8px;padding:12px;margin-bottom:10px">
          <div style="font-size:10px;font-family:'Share Tech Mono';color:var(--g);margin-bottom:10px">👮 ADMIN ACTION MESSAGES</div>
          <div class="fg mb">
            <div class="fgrp">
              <label class="fl">Promoted Message <span style="color:var(--td);font-size:9px">({mention})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-promoted')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-promoted-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-promoted-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-promoted" class="fta" style="min-height:55px" placeholder="⬆️ &lt;b&gt;Promoted!&lt;/b&gt;&#10;👤 {mention}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Demoted Message <span style="color:var(--td);font-size:9px">({mention})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-demoted')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-demoted-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-demoted-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-demoted" class="fta" style="min-height:55px" placeholder="⬇️ &lt;b&gt;Demoted!&lt;/b&gt;&#10;👤 {mention}"></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Pin Message</label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-pinned')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-pinned-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-pinned-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-pinned" class="fta" style="min-height:55px" placeholder="📌 Message pinned."></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Unpin Message</label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-unpinned')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-unpinned-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-unpinned-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-unpinned" class="fta" style="min-height:55px" placeholder="📌 Message unpinned."></textarea>
            </div>
            <div class="fgrp">
              <label class="fl">Purge Done Message <span style="color:var(--td);font-size:9px">({count})</span></label>
              <button type="button" onclick="toggleMiniEmojiPicker('rmsg-purged')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="rmsg-purged-emoji-arrow" style="font-size:8px">▼</span></button>
              <div id="rmsg-purged-emoji-panel" style="display:none;margin-bottom:8px"></div>
              <textarea id="rmsg-purged" class="fta" style="min-height:55px" placeholder="🗑 Purged {count} messages."></textarea>
            </div>
          </div>
        </div>

        <div style="font-size:10px;color:var(--td);font-family:'Share Tech Mono';margin-top:4px">
          💡 Koi bhi field blank chhodo toh default message use hoga • HTML supported (b, i, u, code) • Premium emojis upar se insert karo
        </div>
      </div>

      <!-- COMMANDS REFERENCE -->
      <div style="background:rgba(0,0,0,.3);border:1px solid rgba(255,107,157,.15);border-radius:10px;padding:14px;margin-bottom:18px">
        <div style="font-family:Orbitron;font-size:10px;color:#ff6b9d;margin-bottom:10px">📋 COMMANDS REFERENCE</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px;color:var(--td)">
          <div><code style="color:#ff6b9d">/warn</code> — Warn user (reply)</div>
          <div><code style="color:#ff6b9d">/warns</code> — Check warns</div>
          <div><code style="color:#ff6b9d">/resetwarns</code> — Clear warns</div>
          <div><code style="color:#ff6b9d">/ban</code> — Ban user</div>
          <div><code style="color:#ff6b9d">/unban</code> — Unban user</div>
          <div><code style="color:#ff6b9d">/kick</code> — Kick user</div>
          <div><code style="color:#ff6b9d">/mute [30m/1h]</code> — Mute</div>
          <div><code style="color:#ff6b9d">/unmute</code> — Unmute</div>
          <div><code style="color:#ff6b9d">/tban [30m/1h]</code> — Temp ban</div>
          <div><code style="color:#ff6b9d">/del</code> — Delete message</div>
          <div><code style="color:#ff6b9d">/pin / /unpin</code> — Pin</div>
          <div><code style="color:#ff6b9d">/promote / /demote</code> — Admin</div>
          <div><code style="color:#ff6b9d">/rules</code> — Show rules</div>
          <div><code style="color:#ff6b9d">/setrules</code> — Set rules</div>
          <div><code style="color:#ff6b9d">/filter kw reply</code> — Add filter</div>
          <div><code style="color:#ff6b9d">/filters</code> — List filters</div>
          <div><code style="color:#ff6b9d">/stopfilter kw</code> — Remove filter</div>
          <div><code style="color:#ff6b9d">/note name text</code> — Save note</div>
          <div><code style="color:#ff6b9d">#notename</code> — Get note</div>
          <div><code style="color:#ff6b9d">/notes</code> — List notes</div>
          <div><code style="color:#ff6b9d">/lock url/sticker...</code> — Lock</div>
          <div><code style="color:#ff6b9d">/unlock type</code> — Unlock</div>
          <div><code style="color:#ff6b9d">/blacklist word</code> — Add BL</div>
          <div><code style="color:#ff6b9d">/setflood 5</code> — Flood limit</div>
          <div><code style="color:#ff6b9d">/adminlist</code> — Show admins</div>
          <div><code style="color:#ff6b9d">/info</code> — User info</div>
          <div><code style="color:#ff6b9d">/id</code> — Get IDs</div>
          <div><code style="color:#ff6b9d">@admin</code> — Report</div>
          <div><code style="color:#ff6b9d">/rosehelp</code> — Full help</div>
        </div>
      </div>
      <button class="btn" style="background:linear-gradient(135deg,#ff6b9d,#c44569);width:100%;padding:13px;font-size:14px;font-family:Orbitron" onclick="roseSave()">🔥 Save The Rebel Bot Settings</button>
      <div id="rose-save-result" style="margin-top:10px;display:none"></div>
    </div>
  </div>
  </div><!-- /con -->
</div><!-- /main -->
</div><!-- /wrap -->

<!-- MODALS -->

<div class="mbox" id="m-ab"><div class="modal"><button class="mc" onclick="closeModal('m-ab')">✕</button>
  <h3 style="color:var(--c);margin-bottom:12px;font-family:Orbitron;font-size:13px">🤖 ADD BOT</h3>

  <div class="fgrp mb"><label class="fl">Bot Token (from @BotFather)</label><input type="text" id="abt" class="fi" placeholder="1234567890:AAXX..."></div>
  <button class="btn bsu" onclick="addBot()" style="width:100%">✅ Verify & Add</button>
</div></div>

<div class="mbox" id="m-ak"><div class="modal"><button class="mc" onclick="closeModal('m-ak');g('ak-id').value=''">✕</button>
  <h3 style="color:var(--c);margin-bottom:12px;font-family:Orbitron;font-size:13px">🔐 API KEY</h3>
  <input type="hidden" id="ak-id">

  <div class="fg mb"><div class="fgrp"><label class="fl">Name → used as {NAME}</label><input type="text" id="ak-n" class="fi" placeholder="OPENAI_KEY"></div></div>

  <div class="fgrp mb"><label class="fl">Value</label><input type="text" id="ak-v" class="fi" placeholder="sk-xxxx..."></div>

  <div class="fgrp mb"><label class="fl">Note</label><input type="text" id="ak-d" class="fi" placeholder="OpenAI GPT key"></div>
  <button class="btn bp" onclick="saveAK()" style="width:100%">💾 Save</button>
</div></div>

<!-- PAGE BUILDER MODAL -->

<div class="mbox" id="m-builder"><div class="modal" style="max-width:820px">
  <button class="mc" onclick="closeModal('m-builder')">✕</button>
  <h3 style="color:var(--c);margin-bottom:12px;font-family:Orbitron;font-size:12px">🛠️ PAGE / FLOW BUILDER</h3>

  <div class="fg mb">

    <div class="fgrp"><label class="fl">Page ID</label><input type="text" id="pb-id" class="fi" placeholder="home, search_page..."></div>

    <div class="fgrp">
      <label class="fl">Trigger Command (no /) <span style="color:var(--p);font-size:9px">leave blank for Free Text only</span></label>

      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="text" id="pb-trigger" class="fi" placeholder="start, search..." style="flex:1;min-width:120px">

        <div style="display:flex;align-items:center;gap:6px;background:var(--s2);border:1px solid var(--b);border-radius:6px;padding:6px 10px;white-space:nowrap;cursor:pointer" onclick="g('pb-ft-on').checked=!g('pb-ft-on').checked;onFtToggle(g('pb-ft-on'))">
          <input type="checkbox" id="pb-ft-on" style="width:15px;height:15px;accent-color:var(--p);cursor:pointer;pointer-events:none">
          <span style="font-size:11px;color:var(--p);font-family:'Share Tech Mono';pointer-events:none">FREE TEXT</span>
        </div>
      </div>
    </div>

    <div class="fgrp"><label class="fl">Type</label><select class="fsel" id="pb-type" onchange="onType()"><option value="text">📄 Static Text</option><option value="api">🌐 API (GET)</option><option value="curl">🔗 cURL / POST</option><option value="browser">🌐 Browser (Selenium/PW)</option></select></div>
  </div>

  <!-- Free Text options -->

  <div id="ft-opts-row" class="ft-opts" style="margin-bottom:12px">

    <div style="font-size:11px;color:var(--p);font-family:'Share Tech Mono';margin-bottom:8px">📲 FREE TEXT SETTINGS — replies to non-command messages only</div>

    <div class="fg">

      <div class="fgrp"><label class="fl">Where to Respond</label><select class="fsel" id="pb-ft-chatmode"><option value="both">DM + Groups</option><option value="dm">DM Only</option><option value="group">Groups Only</option></select></div>

      <div class="fgrp"><div class="tw2" style="margin-top:20px"><label class="tg"><input type="checkbox" id="pb-ft-mention"><span class="ts"></span></label><div><strong style="font-size:12px;color:var(--y)">Groups: Mention-only</strong></div></div></div>

      <div class="fgrp"><label class="fl">Access Control (blank=all)</label><input type="text" id="pb-ft-access" class="fi" placeholder="{ADMINS} or 123,456"></div>
    </div>
  </div>

  <!-- Force Join toggle -->

  <div style="background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.25);border-radius:8px;padding:10px;margin-bottom:12px">

    <div class="tw2">
      <label class="tg"><input type="checkbox" id="pb-fj"><span class="ts"></span></label>

      <div><strong style="font-size:13px;color:var(--r)">🔒 Require Force Join</strong><div style="font-size:11px;color:var(--td)">User must join all configured channels to access this command</div></div>
    </div>
  </div>

  <div class="fg mb">

    <div class="fgrp"><label class="fl" style="color:var(--r)">🔒 Access Control</label><input type="text" id="pb-ac" class="fi" placeholder="{ADMINS} or 123,456"></div>

    <div class="fgrp"><label class="fl" style="color:var(--y)">🔀 Fallback Page ID</label><input type="text" id="pb-fb" class="fi" placeholder="access_denied"></div>
  </div>

  <!-- API fields -->

  <div id="f-api" style="display:none">

    <div class="tw2 mb"><label class="tg"><input type="checkbox" id="pb-cr"><span class="ts"></span></label><strong style="font-size:13px;color:var(--g)">Requires Credit</strong></div>

    <div class="fgrp mb"><label class="fl">API URL — {query} = search term</label><input type="text" id="pb-apiurl" class="fi" placeholder="https://api.example.com/search?q={query}"></div>

    <div class="fg mb"><div class="fgrp"><label class="fl">JSON Root Path</label><input type="text" id="pb-root" class="fi" placeholder="data.results (blank=auto)"></div><div class="fgrp"><label class="fl">Timeout (s)</label><input type="number" id="pb-to" class="fi" value="15"></div><div class="fgrp"><div class="tw2" style="margin-top:18px"><label class="tg"><input type="checkbox" id="pb-retry"><span class="ts"></span></label><div style="font-size:11px;color:var(--y)">Auto Retry</div></div></div></div>
  </div>

  <!-- cURL fields — FIX: improved parser + wait message note -->

  <div id="f-curl" style="display:none">

    <div class="tw2 mb"><label class="tg"><input type="checkbox" id="pb-ccr"><span class="ts"></span></label><strong style="font-size:13px;color:var(--g)">Requires Credit</strong></div>

    <div class="bb" style="border-color:var(--y);margin-bottom:12px">

      <div style="font-size:10px;color:var(--y);font-family:'Share Tech Mono';margin-bottom:7px">📋 Paste full cURL command → Auto Fill (improved parser v7.1)</div>
      <textarea id="pb-cpaste" class="fta" style="min-height:75px;font-size:11px" placeholder="curl 'https://api.example.com/v1/...' \&#10;  -H 'Authorization: Bearer sk-...' \&#10;  -H 'Content-Type: application/json' \&#10;  -d '{&quot;query&quot;: &quot;{query}&quot;}'"></textarea>

      <div style="display:flex;gap:7px;margin-top:7px">
        <button class="btn bw bsm" onclick="parsePageCurl()" style="flex:1">⚡ Parse cURL</button>
        <button class="btn bp bsm" onclick="parsePagePython()" style="flex:1">🐍 Parse Python</button>
      </div>
    </div>

    <div style="font-size:10px;color:var(--td);margin-bottom:6px;font-family:'Share Tech Mono'">Python paste format: <code style="color:var(--p)">requests.post('url', headers={...}, json={...})</code></div>

    <div class="fg mb"><div class="fgrp"><label class="fl">URL</label><input type="text" id="pb-curl-url" class="fi" placeholder="https://..."></div><div class="fgrp"><label class="fl">Method</label><select class="fsel" id="pb-curl-m"><option>POST</option><option>GET</option><option>PUT</option><option>DELETE</option></select></div></div>

    <div class="fg mb"><div class="fgrp"><label class="fl">Timeout (s) — default 120 for slow APIs</label><input type="number" id="pb-curl-to" class="fi" value="120" placeholder="120"></div></div>

    <div class="fgrp mb"><label class="fl">Headers (Key: Value per line)</label><textarea id="pb-curl-h" class="fta" style="min-height:60px" placeholder="Content-Type: application/json&#10;Authorization: Bearer {MY_KEY}"></textarea></div>

    <div class="fgrp mb"><label class="fl">Body — {query}, {KEY_NAME}</label><textarea id="pb-curl-b" class="fta" style="min-height:65px" placeholder='{"prompt":"{query}"}'></textarea></div>

    <div class="fgrp mb"><label class="fl">Response Path</label><input type="text" id="pb-curl-rp" class="fi" placeholder="choices.0.message.content"></div>
  </div>

  <!-- Shared ext fields (api+curl) -->

  <div id="f-ext" style="display:none">

    <div class="bb" style="border-color:var(--y);padding:11px">
      <label class="fl" style="color:var(--y)">❓ MISSING QUERY</label>

      <div style="display:flex;gap:7px;margin:7px 0;flex-wrap:wrap"><input type="text" id="pb-mmedia" class="fi" placeholder="Media URL..." style="flex:1;min-width:120px"><button class="btn bg bsm" onclick="tup('pb-mmedia')">📁</button></div>
      <button type="button" onclick="toggleMiniEmojiPicker('miss')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="miss-emoji-arrow" style="font-size:8px">▼</span></button>

      <div id="miss-emoji-panel" style="display:none;margin-bottom:7px"></div>
      <textarea id="pb-miss" class="fta" style="min-height:45px" placeholder="🔍 Please send something."></textarea>
    </div>

    <div class="bb" style="border-color:var(--c);padding:11px">
      <label class="fl" style="color:var(--c)">⏳ LOADING STEPS</label>
      <button type="button" onclick="toggleMiniEmojiPicker('ls')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:7px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="ls-emoji-arrow" style="font-size:8px">▼</span></button>

      <div id="ls-emoji-panel" style="display:none;margin-bottom:7px"></div>

      <div id="lsc"></div>
      <button class="btn bg bsm" onclick="addLS()" style="margin-top:7px">+ Add Step</button>
    </div>

    <div class="bb" style="border-color:var(--r);padding:11px">
      <label class="fl" style="color:var(--r)">🚫 ERROR / NOT FOUND</label>

      <div style="display:flex;gap:7px;margin:7px 0;flex-wrap:wrap"><input type="text" id="pb-emedia" class="fi" placeholder="Media URL..." style="flex:1;min-width:120px"><button class="btn bg bsm" onclick="tup('pb-emedia')">📁</button></div>
      <button type="button" onclick="toggleMiniEmojiPicker('err')" style="background:rgba(191,90,242,.12);border:1px solid rgba(191,90,242,.4);color:#bf5af2;font-size:10px;padding:4px 9px;border-radius:5px;cursor:pointer;margin-bottom:6px;display:inline-flex;align-items:center;gap:5px">💎 Emoji Insert <span id="err-emoji-arrow" style="font-size:8px">▼</span></button>

      <div id="err-emoji-panel" style="display:none;margin-bottom:7px"></div>
      <textarea id="pb-err" class="fta" style="min-height:45px" placeholder="🚫 Not found."></textarea>
    </div>
  </div>

  <!-- Page vars -->

  <div class="bb" style="border-color:var(--td);padding:11px">
    <label class="fl">🗃️ PAGE VARIABLES (KEY=value per line)</label>
    <textarea id="pb-vars" class="fta" style="min-height:40px" placeholder="price=₹99"></textarea>
  </div>

  <!-- Document / APK field -->

  <div class="bb" style="border-color:var(--o);padding:11px">
    <label class="fl" style="color:var(--o)">📦 SEND DOCUMENT / APK (optional)</label>

    <div style="font-size:10px;color:var(--td);margin-bottom:6px">Direct link to .apk / .pdf / any file. Bot will send as document. Caption = Message Template below.</div>

    <div style="display:flex;gap:7px"><input type="text" id="pb-docurl" class="fi" placeholder="https://example.com/app.apk"><button class="btn bg bsm" onclick="tup('pb-docurl')">📁</button></div>
  </div>

  <!-- ═══ BROWSER AUTOMATION SECTION ═══ -->

  <div id="f-browser" style="display:none">

    <div style="background:rgba(57,255,20,.06);border:1px solid rgba(57,255,20,.3);border-radius:10px;padding:14px;margin-bottom:12px">

      <div style="color:var(--g);font-family:'Orbitron';font-size:11px;margin-bottom:10px">🌐 BROWSER AUTOMATION — Selenium / Playwright</div>

      <div style="font-size:11px;color:var(--td);margin-bottom:10px;line-height:1.8">Auto-detects: Playwright → Selenium. Browser: Chrome → Chromium.<br>
      Variables from command args: <code style="color:var(--c)">{var1}</code> <code style="color:var(--c)">{var2}</code> etc. Or use named vars below.</div>

      <div class="fg mb">

        <div class="fgrp">
          <label class="fl">Variable Names (comma-separated, maps to args)</label>
          <input type="text" id="pb-bv-names" class="fi" placeholder="mail,pass,otp — maps /cmd a b c → {mail}=a {pass}=b">
        </div>

        <div class="fgrp">
          <label class="fl">Done Message (after all steps finish)</label>
          <input type="text" id="pb-bv-done" class="fi" placeholder="✅ Done! Result: {result}">
        </div>
      </div>

      <div style="font-size:10px;color:var(--y);font-family:'Share Tech Mono';margin-bottom:8px">⚡ AUTOMATION STEPS — executed top to bottom</div>

      <div id="bsteps-c" style="display:flex;flex-direction:column;gap:6px"></div>

      <div style="margin-bottom:8px">
        <label style="font-size:10px;color:var(--y);font-family:'Share Tech Mono'">⚡ QUICK TEMPLATES:</label>
        <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:5px">
          <button class="btn bsm" style="background:rgba(0,245,255,.1);border:1px solid rgba(0,245,255,.3);font-size:10px" onclick="addAutomationTemplate('login')">🔑 Login Flow</button>
          <button class="btn bsm" style="background:rgba(57,255,20,.1);border:1px solid rgba(57,255,20,.3);font-size:10px" onclick="addAutomationTemplate('form')">📋 Form Fill</button>
          <button class="btn bsm" style="background:rgba(191,90,242,.1);border:1px solid rgba(191,90,242,.3);font-size:10px" onclick="addAutomationTemplate('scrape')">📊 Data Scrape</button>
          <button class="btn bsm" style="background:rgba(255,159,10,.1);border:1px solid rgba(255,159,10,.3);font-size:10px" onclick="addAutomationTemplate('signup')">📝 Sign Up</button>
        </div>
      </div>
      <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:8px">
        <button class="btn bg bsm" onclick="addBrowserStep({type:'open'})">🌐 Open URL</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'click'})">👆 Click</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'double_click'})">👆👆 Dbl Click</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'right_click'})">🖱 Right Click</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'fill'})">⌨️ Fill Input</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'type_slow'})">⌨️ Type Slow</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'clear_field'})">🗑 Clear</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'screenshot'})">📸 Screenshot</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'ask_captcha'})">🔐 Ask Captcha</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'wait'})">⏱ Wait</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'wait_element'})">⌛ Wait Elem</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'wait_url'})">⌛ Wait URL</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'scroll'})">↕️ Scroll</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'get_text'})">📋 Get Text</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'get_attr'})">🔗 Get Attr</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'js_eval'})">⚡ JS Eval</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'assert_text'})">✅ Assert</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'key'})">⌨️ Key Press</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'select'})">📋 Select</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'hover'})">🖱 Hover</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'drag_drop'})">↔️ Drag Drop</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'upload_file'})">📁 Upload File</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'iframe_switch'})">🖼 IFrame In</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'iframe_main'})">🖼 IFrame Out</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'cookie_set'})">🍪 Set Cookie</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'cookie_get'})">🍪 Get Cookie</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'reload'})">🔄 Reload</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'set_var'})">📦 Set Var</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'random_var'})">🎲 Random Var</button>
        <button class="btn bg bsm" onclick="addBrowserStep({type:'raw'})">⚡ Raw Python</button>
      </div>
    </div>

    <div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:10px;margin-bottom:10px;font-family:'Share Tech Mono';font-size:10px;color:var(--td);line-height:2">
      <span style="color:var(--c)">Available vars anywhere:</span> <code>{var1}</code> <code>{var2}</code> (args) · <code>{mail}</code> <code>{pass}</code> (named) · <code>{random:MYVAR}</code> (random from comma list) · <code>{result}</code> <code>{anyvar}</code> (extracted)<br>
      <span style="color:var(--y)">Selectors:</span> CSS <code>#id</code> <code>.class</code> or XPath <code>//div[@class='x']</code>
    </div>
  </div>

  <!-- Sticker ID field -->

  <div class="bb" style="padding:11px;border-color:var(--y)">
    <label class="fl" style="color:var(--y)">🌟 STICKER ID (optional)</label>

    <div style="font-size:10px;color:var(--td);margin-bottom:6px">Yeh page trigger hone par sticker bhi bhejega. Library se pick karo ya file_id manually daalo.</div>

    <div style="display:flex;gap:7px;flex-wrap:wrap">
      <input type="text" id="pb-sticker-id" class="fi" placeholder="file_id — Library → 🌟 Sticker Library se copy karo" style="flex:1">
      <button class="btn bw bsm" onclick="pickStickerForPage()">📚 Library</button>
    </div>
  </div>

  <!-- Message template -->

  <div class="bb" style="padding:11px;border-color:var(--g)">
    <label class="fl" style="color:var(--g)">🎨 MESSAGE TEMPLATE</label>

    <div style="display:flex;gap:7px;margin:7px 0;flex-wrap:wrap"><input type="text" id="pb-media" class="fi" placeholder="Photo/GIF/MP4 URL..." style="flex:1;min-width:120px"><button class="btn bg bsm" onclick="tup('pb-media')">📁</button></div>

    <div style="font-size:10px;color:var(--td);margin-bottom:5px">Use {curl_response} {tg_name} {query} {fieldname} — Long text paginates!</div>

    <!-- 💎 PREMIUM EMOJI PICKER -->

    <div style="margin-bottom:7px">
      <button type="button" class="btn bsm" onclick="togglePbEmojiPicker()" style="background:rgba(191,90,242,.15);border:1px solid rgba(191,90,242,.5);color:#bf5af2;font-size:11px;padding:5px 11px;border-radius:6px;cursor:pointer;display:flex;align-items:center;gap:6px">
        💎 <span>Premium Emoji Insert</span>
        <span id="pb-emoji-arrow" style="font-size:9px;transition:transform .2s">▼</span>
      </button>

      <div id="pb-emoji-panel" style="display:none;margin-top:7px;background:rgba(13,17,23,.97);border:1px solid rgba(191,90,242,.4);border-radius:10px;padding:12px;box-shadow:0 4px 24px rgba(191,90,242,.15)">

        <!-- Search bar -->

        <div style="display:flex;gap:7px;margin-bottom:10px;align-items:center">
          <input type="text" id="pb-emoji-search" class="fi" placeholder="🔍 Label se dhundho..." oninput="filterPbEmojis()" style="flex:1;font-size:12px;padding:6px 10px">
          <button type="button" class="btn bg bsm" onclick="refreshPbEmojiList()" title="Refresh library">🔄</button>
        </div>

        <!-- Emoji grid -->

        <div id="pb-emoji-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:6px;max-height:220px;overflow-y:auto;padding-right:2px">

          <div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:14px">⏳ Loading library...</div>
        </div>

        <!-- Quick insert tips -->

        <div style="margin-top:9px;padding-top:8px;border-top:1px solid rgba(191,90,242,.2);font-size:10px;color:var(--td);line-height:1.8;font-family:'Share Tech Mono'">
          💡 <b style="color:#bf5af2">Click karo</b> → cursor position pe will be inserted<br>
          📝 Format: <code style="color:var(--c)">&lt;tg-emoji emoji-id="..."&gt;⭐&lt;/tg-emoji&gt;</code><br>
          ✨ Ya sirf <code style="color:var(--c)">{emoji_label}</code> placeholder use karo
        </div>

        <!-- Insert mode toggle -->

        <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <span style="font-size:10px;color:var(--td);font-family:'Share Tech Mono'">Insert as:</span>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:11px;color:var(--c)">
            <input type="radio" name="pb-emoji-mode" value="tag" checked style="accent-color:#bf5af2"> &lt;tg-emoji&gt; tag
          </label>
          <label style="display:flex;align-items:center;gap:4px;cursor:pointer;font-size:11px;color:var(--o)">
            <input type="radio" name="pb-emoji-mode" value="placeholder" style="accent-color:#bf5af2"> {emoji_label}
          </label>
        </div>
      </div>
    </div>

    <!-- /💎 PREMIUM EMOJI PICKER -->
    <textarea id="pb-text" class="fta" style="min-height:95px" placeholder="Your message...&#10;{tg_name}: {query}&#10;Result: {curl_response}"></textarea>
  </div>

  <!-- Buttons -->

  <div class="bb" style="border-color:var(--p);padding:11px">
    <label class="fl" style="color:var(--p)">🔘 BUTTONS</label>

    <div style="font-size:10px;color:var(--td);margin-bottom:7px"><b style="color:var(--c)">Page</b> = go to page | <b style="color:var(--o)">URL</b> = open link | <b style="color:var(--g)">Next/Prev</b> = paginate</div>

    <div id="btnc"></div>
    <button class="btn bg bsm" onclick="addBtn()" style="margin-top:7px">+ Add Button</button>
  </div>
  <button class="btn bp" onclick="savePage()" style="width:100%;margin-top:14px;padding:11px;font-size:14px">💾 SAVE PAGE</button>
</div></div>

  <!-- PROMO BOT PANEL -->
  <div class="panel" id="p-promobot">

    <div class="card" style="border-color:rgba(255,159,10,.5);background:linear-gradient(135deg,rgba(255,159,10,.06),rgba(13,17,23,1))">
      <div class="sh">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="width:36px;height:36px;background:rgba(255,159,10,.2);border:2px solid rgba(255,159,10,.7);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px">&#128226;</div>
          <div>
            <div class="st" style="color:var(--o);font-size:13px">PROMO BOT MANAGER</div>
            <div style="font-size:10px;color:var(--td);margin-top:1px">Automatic promotional messages &#8212; APK, Video, Image ke saath</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span id="promo-status-label" style="font-family:'Share Tech Mono';font-size:11px;color:var(--td)">OFF</span>
          <button id="promo-toggle-btn" class="btn bsm bg" onclick="promoToggle()" style="min-width:72px">Enable</button>
        </div>
      </div>
      <p style="font-size:12px;color:var(--td);margin-bottom:0">Bot automatically sends promo messages to all registered users. Each message can have a different APK/video/image.</p>
    </div>

    <div class="card" style="border-color:rgba(0,245,255,.3)">
      <div class="sh"><div class="st" style="color:var(--c)">&#9200; SCHEDULE CONFIG</div></div>
      <div class="fg mb">
        <div class="fgrp">
          <label class="fl">Schedule Type</label>
          <select id="promo-schedule-type" class="fsel" onchange="promoOnScheduleChange()">
            <option value="interval">Every X Minutes (Interval)</option>
            <option value="keyword">Keyword Triggered</option>
          </select>
        </div>
        <div class="fgrp" id="promo-interval-grp">
          <label class="fl">Interval (minutes)</label>
          <input type="number" id="promo-interval" class="fi" value="60" min="1" max="10080" placeholder="60">
          <div style="font-size:10px;color:var(--td);margin-top:3px">60 = every hour | 1440 = daily | 10080 = weekly</div>
        </div>
      </div>
      <div class="fgrp mb" id="promo-keyword-grp" style="display:none">
        <label class="fl">Trigger Keywords (comma separated)</label>
        <input type="text" id="promo-keywords" class="fi" placeholder="promo, deal, offer, buy">
        <div style="font-size:10px;color:var(--td);margin-top:3px">Promo will trigger when user sends any of these keywords</div>
      </div>
    </div>

    <div class="card" style="border-color:rgba(57,255,20,.35)">
      <div class="sh">
        <div class="st" style="color:var(--g)">&#128640; PROMO FLOW BUILDER</div>
        <button class="btn bsu bsm" onclick="promoAddMessage()">+ Add Message</button>
      </div>
      <p style="font-size:12px;color:var(--td);margin-bottom:12px">A random message will be selected for each broadcast. Each message can have its own text, APK, Video, Image and buttons.</p>
      <div id="promo-messages-list" style="display:flex;flex-direction:column;gap:14px">
        <div style="text-align:center;color:var(--td);font-size:12px;padding:20px;border:1px dashed rgba(255,255,255,.1);border-radius:8px">No messages yet. Click &quot;+ Add Message&quot; above.</div>
      </div>
    </div>

    <div class="card" style="border-color:rgba(255,45,85,.3)">
      <div class="sh"><div class="st" style="color:var(--r)">&#129514; TEST & SAVE</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        <button class="btn bo" onclick="promoSendNow()" style="flex:1;min-width:150px;padding:11px">&#128228; Send Promo Now (Test)</button>
        <button class="btn bsu" onclick="promoSave()" style="flex:1;min-width:150px;padding:11px">&#128190; Save All Settings</button>
      </div>
      <div id="promo-save-result" style="display:none"></div>
    </div>
  </div>

  <!-- LINK AUTOMATION SECTION -->
  <div class="panel" id="p-linkautomation">

    <!-- Header card -->
    <div class="card" style="border-color:rgba(0,245,255,.5);background:linear-gradient(135deg,rgba(0,245,255,.05),rgba(13,17,23,1))">
      <div class="sh">
        <div>
          <div class="st" style="color:var(--c);font-size:14px">&#128279; LINK AUTOMATION</div>
          <div style="font-size:12px;color:var(--td);margin-top:3px">User keyword bheje → bot URL fetch kare → response wapas bheje</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <span id="la-status-label" style="font-family:'Share Tech Mono';font-size:12px;color:var(--td);font-weight:700">OFF</span>
          <button id="la-toggle-btn" class="btn bsm bg" onclick="laToggle()" style="min-width:80px;padding:7px 14px">Enable</button>
        </div>
      </div>
      <!-- Quick how-to -->
      <div style="background:rgba(0,245,255,.06);border:1px solid rgba(0,245,255,.2);border-radius:8px;padding:10px;font-size:12px;color:var(--td);line-height:1.8">
        <b style="color:var(--c)">Kaise use kare:</b><br>
        1&#65039;&#8423; Bot ka webhook Start karo (Dashboard &gt; Start Bot)<br>
        2&#65039;&#8423; Enable button click karo (upar)<br>
        3&#65039;&#8423; &quot;+ Add Rule&quot; click karo, Trigger keyword aur URL bharo<br>
        4&#65039;&#8423; &quot;&#128190; Save All&quot; click karo<br>
        5&#65039;&#8423; Telegram pe trigger keyword bhejo — bot reply karega!
      </div>
    </div>

    <!-- Rules Card -->
    <div class="card" style="border-color:rgba(57,255,20,.35)">
      <div class="sh">
        <div>
          <div class="st" style="color:var(--g)">&#128396; RULES</div>
          <div style="font-size:11px;color:var(--td);margin-top:2px">Trigger = exact word jo user type kare (case insensitive)</div>
        </div>
        <button class="btn bsu bsm" onclick="laAddRule()" style="padding:7px 14px">+ Add Rule</button>
      </div>

      <div id="la-rules-list" style="display:flex;flex-direction:column;gap:12px">
        <div style="text-align:center;color:var(--td);font-size:12px;padding:24px;border:1px dashed rgba(255,255,255,.1);border-radius:8px">
          Koi rule nahi hai. &quot;+ Add Rule&quot; click karo.
        </div>
      </div>

      <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn bsu" onclick="laSave()" style="flex:1;padding:11px;font-size:14px">&#128190; Save All Rules</button>
      </div>
      <div id="la-save-result" style="margin-top:8px;display:none"></div>
    </div>

    <!-- Bot Selector for Form Capture (advanced, collapsible) -->
    <div class="card" style="border-color:rgba(191,90,242,.3)">
      <div onclick="laToggleAdvanced()" style="display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none">
        <div class="st" style="color:var(--p)">&#9881;&#65039; ADVANCED — Form Capture &amp; Bot Selector</div>
        <span id="la-adv-arrow" style="color:var(--p);font-size:16px">&#9660;</span>
      </div>
      <div id="la-advanced-section" style="display:none;margin-top:12px">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:8px">
          <div style="font-size:12px;color:var(--td)">&#129302; Form Capture ke liye bot assign karo:</div>
          <button class="btn bsm" style="background:rgba(191,90,242,.2);border:1px solid rgba(191,90,242,.5);color:var(--p)" onclick="laSelectBot()">&#128257; Bot Select Karo</button>
        </div>
        <div id="la-bot-info" style="background:var(--s2);border:1px solid rgba(191,90,242,.25);border-radius:8px;padding:10px;font-family:'Share Tech Mono';font-size:12px;margin-bottom:10px">
          <span style="color:var(--td)">Loading...</span>
        </div>
        <div style="background:rgba(255,214,10,.06);border:1px solid rgba(255,214,10,.2);border-radius:7px;padding:8px 10px;font-size:11px;color:var(--y)">
          &#9888;&#65039; <b>Webhook URL</b> (website form ke liye):<br>
          <div style="display:flex;align-items:center;gap:6px;margin-top:6px;flex-wrap:wrap">
            <code id="la-webhook-url" style="background:var(--s2);border:1px solid var(--b);padding:5px 9px;border-radius:5px;font-size:10px;color:var(--c);word-break:break-all;flex:1">—</code>
            <button class="btn bg bsm" onclick="laCopyWebhook()" style="white-space:nowrap">&#128203; Copy</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Bot Selector Modal -->
    <div id="la-bot-select-modal" style="display:none;position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.75);align-items:center;justify-content:center">
      <div style="background:var(--s);border:1px solid rgba(191,90,242,.5);border-radius:14px;padding:20px;width:90%;max-width:420px;max-height:80vh;overflow-y:auto">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="st" style="color:var(--p)">&#129302; Bot Select Karo</div>
          <button class="btn bd bsm" onclick="g('la-bot-select-modal').style.display='none'">&#10005;</button>
        </div>
        <p style="font-size:12px;color:var(--td);margin-bottom:12px">Form Capture ke liye ek bot select karo.</p>
        <div id="la-bot-select-list" style="display:flex;flex-direction:column;gap:8px">
          <div style="color:var(--td);text-align:center;padding:12px;font-size:12px">Loading...</div>
        </div>
      </div>
    </div>

  </div>

  <!-- ═══════════════════════════════════════════════════════ -->
  <!-- 💰 DEPOSIT BOT PANEL                                    -->
  <!-- ═══════════════════════════════════════════════════════ -->
  <div class="panel" id="p-depositbot">
    <div class="card" style="border-color:rgba(255,107,26,.5);background:linear-gradient(135deg,rgba(255,107,26,.05),rgba(13,17,23,1))">
      <div class="sh">
        <div>
          <div class="st" style="color:#ff6b1a;font-size:14px">💰 REBEL B2W DEPOSIT BOT</div>
          <div style="font-size:12px;color:var(--td);margin-top:3px">Users /Deposit karke amount dalte hain — QR code auto send hota hai</div>
        </div>
      </div>
      <div style="background:rgba(57,255,20,.06);border:1px solid rgba(57,255,20,.2);border-radius:8px;padding:10px;font-size:12px;color:var(--g);line-height:1.8">
        ✅ <b>Flow:</b> User /Deposit → Amount enter → QR code + bank details → User pays → UTR/Screenshot submit → Admin gets notification
      </div>
    </div>

    <!-- Action Bar -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--c)">⚡ QUICK ACTIONS</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn bsu bsm" onclick="rbdSaveCfg()">💾 Save Config</button>
        <button class="btn bg bsm" onclick="rbdSetWebhook()">🔗 Set Webhook</button>
        <button class="btn bd bsm" onclick="rbdRemoveWebhook()">❌ Remove Webhook</button>
        <button class="btn bg bsm" onclick="rbdTestLogin()">🔑 Test RB Login</button>
        <button class="btn bg bsm" onclick="rbdTestBank()">🏦 Test Bank/UPI</button>
        <button class="btn bsu bsm" onclick="rbdSendTest()">📨 Send Test</button>
        <button class="btn bsm" style="background:rgba(255,107,26,.2);color:#ff6b1a;border:1px solid #ff6b1a" onclick="rbdLoadLedger()">👥 User Ledger</button>
        <button class="btn bd bsm" onclick="rbdLoadBlocked()">🚫 Blocked Users</button>
        <button class="btn bg bsm" onclick="rbdLoadLogs()">📋 Logs</button>
        <button class="btn bd bsm" onclick="rbdClearLogs()">🗑️ Clear Logs</button>
      </div>
    </div>

    <!-- Config Card -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--c)">⚙️ BOT CONFIGURATION</div></div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">🤖 Telegram Bot Token</label><input type="password" id="rbd-token" class="fi" placeholder="123456789:ABCdef..."></div>
        <div class="fgrp"><label class="fl">👑 Admin Chat ID (notifications)</label><input type="text" id="rbd-admin-chat" class="fi" placeholder="-100xxxx or personal ID"></div>
      </div>
      <div style="background:rgba(255,107,26,.07);border:1px solid rgba(255,107,26,.25);border-radius:8px;padding:12px;margin-bottom:10px">
        <div style="color:#ff6b1a;font-size:12px;font-weight:700;margin-bottom:8px">🎯 Rebel B2W / RockyBook Account</div>
        <div class="fg mb">
          <div class="fgrp"><label class="fl">👤 Username / Phone (loginType)</label><input type="text" id="rbd-rbphone" class="fi" placeholder="username or phone"></div>
          <div class="fgrp"><label class="fl">🔒 Password</label><input type="password" id="rbd-rbpass" class="fi" placeholder="Account password"></div>
        </div>
        <div class="fg mb">
          <div class="fgrp"><label class="fl">🌿 Branch Name</label><input type="text" id="rbd-branch" class="fi" placeholder="RBVIP1D"></div>
          <div class="fgrp"><label class="fl">🏦 Bank ID (optional)</label><input type="text" id="rbd-bankid" class="fi" placeholder="auto-detect if blank"></div>
        </div>
        <div style="background:rgba(57,255,20,.07);border:1px solid rgba(57,255,20,.25);border-radius:6px;padding:10px;font-size:12px;color:var(--g)">🔒 <b>Hardcoded Deposit User:</b> <code>@Ujjwal0999</code> — All deposits go to this account.</div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">💰 Min Deposit (₹)</label><input type="number" id="rbd-minDep" class="fi" placeholder="500" min="100" value="500"></div>
        <div class="fgrp"><label class="fl">💰 Max Deposit (₹)</label><input type="number" id="rbd-maxDep" class="fi" placeholder="100000" value="100000"></div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">👋 Welcome Message (\n for newline)</label><textarea id="rbd-welcome" class="fi fta" rows="3"></textarea></div>
        <div class="fgrp"><label class="fl">✅ Deposit Thanks Message</label><textarea id="rbd-thanks" class="fi fta" rows="3"></textarea></div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">🔒 Change Admin Password (min 4 chars)</label><input type="password" id="rbd-newpass" class="fi" placeholder="Leave blank to keep current"></div>
      </div>
      <button class="btn bsu" onclick="rbdSaveCfg()" style="width:100%;margin-top:8px">💾 Save Config</button>
    </div>

    <!-- Users/Logs display -->
    <div class="card" id="rbd-info-card" style="display:none">
      <div class="sh"><div class="st" id="rbd-info-title" style="color:var(--c)">📊 Info</div><button class="btn bg bsm" onclick="g('rbd-info-card').style.display='none'">✕ Close</button></div>
      <div id="rbd-info-body"></div>
    </div>

    <!-- Logs Card -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--c)">📋 DEPOSIT BOT LOGS</div><div style="display:flex;gap:6px"><button class="btn bg bsm" onclick="rbdLoadLogs()">🔄 Refresh</button><button class="btn bd bsm" onclick="rbdClearLogs()">🗑️ Clear</button></div></div>
      <div class="log-t" id="rbd-log-box"><div style="color:var(--td)">Loading...</div></div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════ -->
  <!-- 🔗 LINK RUNNER PANEL                                    -->
  <!-- ═══════════════════════════════════════════════════════ -->
  <div class="panel" id="p-linkrunner">
    <div class="card" style="border-color:rgba(124,124,255,.5);background:linear-gradient(135deg,rgba(124,124,255,.05),rgba(13,17,23,1))">
      <div class="sh">
        <div>
          <div class="st" style="color:var(--c);font-size:14px">🔗 REBEL LINK RUNNER <small style="font-size:10px;color:var(--td)">v<?=LR_VERSION?></small></div>
          <div style="font-size:12px;color:var(--td);margin-top:3px">Specific links run karo — responses Telegram pe send karo</div>
        </div>
      </div>
    </div>

    <!-- Action Bar -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--g)">⚡ QUICK ACTIONS</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button class="btn bg bsm" onclick="lrRunAll()">▶️ Run All Now</button>
        <button class="btn bsu bsm" onclick="lrSavePage()">💾 Save All</button>
        <button class="btn bg bsm" onclick="lrSetWebhook()">🔗 Set Webhook</button>
        <button class="btn bd bsm" onclick="lrRemoveWebhook()">❌ Remove Webhook</button>
        <button class="btn bg bsm" onclick="lrLoadLogs()">📋 Refresh Logs</button>
        <button class="btn bd bsm" onclick="lrClearLogs()">🗑️ Clear Logs</button>
        <span id="lr-run-status" style="font-size:12px;color:var(--td)"></span>
      </div>
    </div>

    <!-- Global Config -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--c)">⚙️ GLOBAL CONFIG</div></div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">🤖 Bot Token</label><input type="password" id="lr-token" class="fi" placeholder="123456789:ABC..."></div>
        <div class="fgrp"><label class="fl">💬 Default Chat ID</label><input type="text" id="lr-chat" class="fi" placeholder="-100xxxx or @channel"></div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">📝 Message Prefix (use \n for newline)</label><input type="text" id="lr-prefix" class="fi" placeholder="🔗 &lt;b&gt;Link Runner&lt;/b&gt;\n\n"></div>
        <div class="fgrp"><label class="fl">🔑 URL Run Secret (?lr_run=1&amp;secret=X)</label><input type="text" id="lr-secret" class="fi" placeholder="changeme123"></div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">🔔 Webhook Bot Token (blank = use main)</label><input type="text" id="lr-wtoken" class="fi" placeholder="Same or different token"></div>
        <div class="fgrp"><label class="fl">📟 Webhook Trigger Command</label><input type="text" id="lr-wcmd" class="fi" placeholder="/run"></div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">🔒 Change Admin Password (min 4 chars)</label><input type="password" id="lr-newpass" class="fi" placeholder="Leave blank to keep current"></div>
      </div>
      <button class="btn bsu" onclick="lrSaveConfig()" style="width:100%;margin-top:8px">💾 Save Config</button>
    </div>

    <!-- Python Debugger Card -->
    <div class="card" style="border-color:rgba(191,90,242,.4)">
      <div class="sh">
        <div>
          <div class="st" style="color:#bf5af2">🐍 PYTHON ADHAR DEBUGGER</div>
          <div style="font-size:11px;color:var(--td);margin-top:3px">Python <code style="color:#bf5af2">requests</code> code paste karo → automatically Link Runner mein import ho jayega</div>
        </div>
        <button class="btn bsm" style="background:rgba(191,90,242,.15);color:#bf5af2;border:1px solid rgba(191,90,242,.4)" onclick="lrTogglePyDebugger()">▼ Show / Hide</button>
      </div>
      <div id="lr-py-debugger" style="display:none">
        <div style="background:rgba(191,90,242,.06);border:1px solid rgba(191,90,242,.2);border-radius:8px;padding:10px;font-size:11px;color:var(--td);margin-bottom:12px;line-height:1.8">
          <b style="color:#bf5af2">Kaise use kare:</b><br>
          1️⃣ Python <code style="color:#bf5af2">requests</code> snippet paste karo neeche<br>
          2️⃣ <b style="color:var(--g)">🔍 Parse &amp; Import</b> click karo<br>
          3️⃣ URL, Method, Headers, Body automatically extract hoke naya Link Rule ban jayega<br>
          4️⃣ <b>💾 Save All</b> click karo<br><br>
          <b>Supported formats:</b><br>
          <code style="color:#bf5af2">requests.post('url', headers={...}, json={...})</code><br>
          <code style="color:#bf5af2">requests.get('url', headers={...})</code><br>
          <code style="color:#bf5af2">requests.put('url', data='body')</code>
        </div>
        <div class="fgrp mb">
          <label class="fl">🐍 Python Code (requests snippet)</label>
          <textarea id="lr-py-input" class="fi fta" rows="8" style="font-family:'Share Tech Mono',monospace;font-size:12px;min-height:160px" placeholder="import requests&#10;&#10;response = requests.post(&#10;    'https://api.example.com/data',&#10;    headers={&#10;        'Authorization': 'Bearer YOUR_TOKEN',&#10;        'Content-Type': 'application/json'&#10;    },&#10;    json={&#10;        'key': 'value'&#10;    }&#10;)&#10;print(response.json())"></textarea>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <button class="btn bsm" style="background:rgba(191,90,242,.2);color:#bf5af2;border:1px solid rgba(191,90,242,.4)" onclick="lrParsePython()">🔍 Parse &amp; Import as New Link</button>
          <button class="btn bg bsm" onclick="lrParsePythonDebug()">🐛 Debug Only (show parsed)</button>
          <button class="btn bsm" style="background:var(--s2);color:var(--td);border:1px solid var(--b)" onclick="g('lr-py-input').value='';g('lr-py-result').style.display='none'">🗑️ Clear</button>
        </div>
        <div id="lr-py-result" style="display:none;margin-top:12px;background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:12px;font-size:12px;font-family:'Share Tech Mono',monospace">
        </div>
      </div>
    </div>

    <!-- Link Rules Card -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--c)">🔗 LINK RULES <span id="lr-link-count" style="background:rgba(0,245,255,.1);color:var(--c);padding:2px 8px;border-radius:4px;font-size:10px;margin-left:6px">0</span></div><button class="btn bsu bsm" onclick="lrAddLink()">+ Add Link</button></div>
      <div id="lr-links-container"></div>
    </div>

    <!-- Run Results -->
    <div class="card" id="lr-results-card" style="display:none">
      <div class="sh"><div class="st" style="color:var(--g)">📊 LAST RUN RESULTS</div></div>
      <div id="lr-results-body"></div>
    </div>

    <!-- Logs -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--c)">📋 LINK RUNNER LOGS</div><div style="display:flex;gap:6px"><button class="btn bg bsm" onclick="lrLoadLogs()">🔄</button><button class="btn bd bsm" onclick="lrClearLogs()">🗑️</button></div></div>
      <div class="log-t" id="lr-log-box"><div style="color:var(--td)">Loading...</div></div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════ -->
  <!-- 👾 AADHAAR BOT PANEL                                    -->
  <!-- ═══════════════════════════════════════════════════════ -->
  <div class="panel" id="p-adharbot">
    <div class="card" style="border-color:rgba(99,179,237,.5);background:linear-gradient(135deg,rgba(99,179,237,.05),rgba(13,17,23,1))">
      <div class="sh">
        <div>
          <div class="st" style="color:#63b3ed;font-size:14px">👾 PYTHON AADHAAR BOT</div>
          <div style="font-size:12px;color:var(--td);margin-top:3px">Bot messages, commands aur flow customize karo — save hone pe <code style="color:#63b3ed">bot_config.json</code> auto-generate hota hai</div>
        </div>
      </div>
      <div style="background:rgba(99,179,237,.06);border:1px solid rgba(99,179,237,.2);border-radius:8px;padding:10px;font-size:12px;color:var(--td);line-height:1.9">
        💡 <b style="color:#63b3ed">Flow:</b> User <code>/fetch &lt;mobile&gt; &lt;name&gt;</code> → Loading animation → Captcha → OTP → Aadhaar PDF send<br>
        🔄 <b>Yahan save karo</b> → <code>bot_config.json</code> update → Python bot automatically naya config use karega (restart nahi chahiye)
      </div>
    </div>

    <!-- Action Bar -->
    <div class="card">
      <div class="sh"><div class="st" style="color:var(--g)">⚡ QUICK ACTIONS</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn bsm" style="background:rgba(99,179,237,.2);color:#63b3ed;border:1px solid #63b3ed" onclick="adharSaveConfig()">💾 Save Config</button>
        <button class="btn bg bsm" onclick="adharSetWebhook()">🔗 Set Webhook</button>
        <button class="btn bd bsm" onclick="adharRemoveWebhook()">❌ Remove Webhook</button>
        <button class="btn bg bsm" onclick="adharCheckBotInfo()">🔍 Bot Status</button>
        <button class="btn bsu bsm" onclick="adharSendTestMsg()">📨 Send Test Message</button>
        <button class="btn bg bsm" onclick="adharLoadLogs()">📋 Logs</button>
        <button class="btn bd bsm" onclick="adharClearLogs()">🗑️ Clear Logs</button>
        <button class="btn bg bsm" onclick="adharLoadSessions()">👥 Active Sessions</button>
        <button class="btn bd bsm" onclick="adharClearSessions()">🧹 Clear Sessions</button>
        <button class="btn bd bsm" onclick="adharResetDefaults()">↩️ Reset Defaults</button>
      </div>
    </div>

    <!-- Bot Status Card -->
    <div class="card" id="ab-status-card" style="display:none">
      <div class="sh"><div class="st" id="ab-status-title" style="color:#63b3ed">📊 Status</div><button class="btn bd bsm" onclick="g('ab-status-card').style.display='none'">✕</button></div>
      <div id="ab-status-body"></div>
    </div>

    <!-- Test Message Card -->
    <div class="card">
      <div class="sh"><div class="st" style="color:#63b3ed">📨 TEST MESSAGE</div></div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">💬 Chat ID (test message bhejne ke liye)</label><input type="text" id="ab-test-chat" class="fi" placeholder="apna Telegram Chat ID"></div>
        <div class="fgrp"><label class="fl">📝 Message Text</label><input type="text" id="ab-test-text" class="fi" value="✅ Aadhaar Bot test message — working!" placeholder="Test message text"></div>
      </div>
      <div id="ab-test-result" style="display:none;margin-top:8px;font-size:12px;padding:8px;background:var(--s2);border-radius:6px"></div>
    </div>

    <!-- Bot Credentials -->
    <div class="card">
      <div class="sh"><div class="st" style="color:#63b3ed">🔐 BOT CREDENTIALS</div></div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">🤖 Bot Token (Python bot ka alag token)</label><input type="password" id="ab-token" class="fi" placeholder="123456789:ABCdef..."></div>
        <div class="fgrp"><label class="fl">🌐 UIDAI Proxy (optional — socks5://host:port)</label><input type="text" id="ab-proxy" class="fi" placeholder="socks5://127.0.0.1:1080 ya khali chhodo"></div>
      </div>
      <div class="fg mb">
        <div class="fgrp"><label class="fl">📟 Fetch Command</label><input type="text" id="ab-fetch-cmd" class="fi" placeholder="/fetch"></div>
        <div class="fgrp"><label class="fl">❌ Cancel Command</label><input type="text" id="ab-cancel-cmd" class="fi" placeholder="/cancel"></div>
        <div class="fgrp"><label class="fl">🔄 Refresh Command</label><input type="text" id="ab-refresh-cmd" class="fi" placeholder="/refresh"></div>
      </div>
      <button class="btn bsm" style="background:rgba(99,179,237,.2);color:#63b3ed;border:1px solid #63b3ed;width:100%;margin-top:4px" onclick="adharSaveSection('credentials')">💾 Save Credentials</button>
      <div id="ab-cred-result" style="display:none;margin-top:8px;font-size:12px"></div>
    </div>

    <!-- Bot Messages -->
    <div class="card">
      <div class="sh"><div class="st" style="color:#63b3ed">💬 BOT MESSAGES</div></div>
      <div class="fgrp mb">
        <label class="fl">👋 Start / Welcome Message</label>
        <textarea id="ab-start-msg" class="fi fta" rows="5" placeholder="/start ya /fetch pe dono ko yahi message jaata hai"></textarea>
      </div>
      <div class="fg mb">
        <div class="fgrp">
          <label class="fl">📸 Captcha Message</label>
          <textarea id="ab-captcha-msg" class="fi fta" rows="4"></textarea>
        </div>
        <div class="fgrp">
          <label class="fl">📲 OTP Message <span style="color:var(--td);font-size:10px">({mobile} use kar sakte ho)</span></label>
          <textarea id="ab-otp-msg" class="fi fta" rows="4"></textarea>
        </div>
      </div>
      <div class="fg mb">
        <div class="fgrp">
          <label class="fl">✅ Success Message (PDF send hone ke baad)</label>
          <textarea id="ab-success-msg" class="fi fta" rows="3"></textarea>
        </div>
        <div class="fgrp">
          <label class="fl">❌ Cancel Message</label>
          <textarea id="ab-cancel-msg" class="fi fta" rows="3"></textarea>
        </div>
      </div>
      <div class="fgrp mb">
        <label class="fl">⚠️ Error Prefix</label>
        <input type="text" id="ab-error-prefix" class="fi" placeholder="❌ &lt;b&gt;Error:&lt;/b&gt;">
      </div>
      <button class="btn bsm" style="background:rgba(99,179,237,.2);color:#63b3ed;border:1px solid #63b3ed;width:100%;margin-top:4px" onclick="adharSaveSection('messages')">💾 Save Messages</button>
      <div id="ab-msg-result" style="display:none;margin-top:8px;font-size:12px"></div>
    </div>

    <!-- Loading Steps -->
    <div class="card">
      <div class="sh"><div class="st" style="color:#63b3ed">⏳ LOADING ANIMATIONS</div></div>
      <div style="font-size:11px;color:var(--td);margin-bottom:12px;background:rgba(99,179,237,.06);border:1px solid rgba(99,179,237,.2);border-radius:6px;padding:8px 12px;line-height:1.8">
        Har line ek step hai — bot ek ek karke yeh messages bhejta hai, jaise real processing chal rahi ho.<br>
        <b style="color:#63b3ed">Tip:</b> Interesting emojis + technical jargon = realistic loading effect 😈
      </div>
      <div class="fg mb">
        <div class="fgrp">
          <label class="fl">⏳ Fetch / Initial Loading Steps <span style="color:var(--td);font-size:10px">(ek line = ek step)</span></label>
          <textarea id="ab-loading-steps" class="fi fta" rows="10" style="font-family:'Share Tech Mono',monospace;font-size:12px"></textarea>
        </div>
        <div class="fgrp">
          <label class="fl">🔐 OTP Verify Loading Steps <span style="color:var(--td);font-size:10px">(ek line = ek step)</span></label>
          <textarea id="ab-otp-steps" class="fi fta" rows="10" style="font-family:'Share Tech Mono',monospace;font-size:12px"></textarea>
        </div>
      </div>
      <button class="btn bsm" style="background:rgba(99,179,237,.2);color:#63b3ed;border:1px solid #63b3ed;width:100%;margin-top:4px" onclick="adharSaveSection('loading')">💾 Save Loading Animations</button>
      <div id="ab-load-result" style="display:none;margin-top:8px;font-size:12px"></div>
    </div>

    <!-- Save All button -->
    <div class="card">
      <button class="btn bsm" style="background:rgba(99,179,237,.2);color:#63b3ed;border:1px solid #63b3ed;width:100%;padding:12px;font-size:14px" onclick="adharSaveConfig()">💾 Save ALL Config</button>
      <div id="ab-save-result" style="margin-top:10px;font-size:12px;display:none"></div>
    </div>

    <!-- Webhook Info Card -->
    <div class="card">
      <div class="sh"><div class="st" style="color:#63b3ed">🔗 WEBHOOK INFO</div></div>
      <div style="font-size:12px;color:var(--td);line-height:2;background:var(--s2);padding:12px;border-radius:8px;border:1px solid var(--b)">
        <b style="color:var(--t)">Set Webhook URL (PHP side):</b><br>
        <code id="ab-webhook-url" style="color:#63b3ed;font-size:11px;word-break:break-all"><?php $abPr=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off')?'https://':'http://';echo htmlspecialchars($abPr.($_SERVER['HTTP_HOST']??'yoursite.com').strtok($_SERVER['REQUEST_URI']??'/','?').'?rbd_webhook=1'); ?></code><br><br>
        <b style="color:var(--t)">Python bot ke liye webhook URL:</b><br>
        <code id="ab-py-webhook-url" style="color:var(--g);font-size:11px;word-break:break-all"><?php echo htmlspecialchars($abPr.($_SERVER['HTTP_HOST']??'yoursite.com').strtok($_SERVER['REQUEST_URI']??'/','?')); ?>?py_webhook=1</code><br>
        <div style="margin-top:8px;font-size:11px;color:var(--tf)">💡 Python bot ka token alag ho sakta hai — Set Webhook button uska token use karta hai.</div>
      </div>
    </div>

    <!-- Active Sessions Card -->
    <div class="card">
      <div class="sh">
        <div class="st" style="color:#63b3ed">👥 ACTIVE BOT SESSIONS</div>
        <div style="display:flex;gap:6px">
          <button class="btn bsm" style="background:rgba(99,179,237,.15);color:#63b3ed;border:1px solid rgba(99,179,237,.4)" onclick="adharLoadSessions()">🔄 Refresh</button>
          <button class="btn bd bsm" onclick="adharClearSessions()">🧹 Clear All</button>
        </div>
      </div>
      <div id="ab-sessions-body"><div style="color:var(--td);font-size:12px;text-align:center;padding:16px">Click 🔄 Refresh to load sessions</div></div>
    </div>

    <!-- Logs Card -->
    <div class="card">
      <div class="sh">
        <div class="st" style="color:#63b3ed">📋 AADHAAR BOT LOGS</div>
        <div style="display:flex;gap:6px">
          <button class="btn bsm" style="background:rgba(99,179,237,.15);color:#63b3ed;border:1px solid rgba(99,179,237,.4)" onclick="adharLoadLogs()">🔄 Refresh</button>
          <button class="btn bd bsm" onclick="adharClearLogs()">🗑️ Clear</button>
        </div>
      </div>
      <div class="log-t" id="ab-log-box"><div style="color:var(--td)">Loading...</div></div>
    </div>
  </div>

<?php endif ?>

<script>
const A='?page=api&action=';
const CSRF_TOKEN='<?=csrfToken()?>';
let ACTIVE_BOT_ID='<?=addslashes($savedActId)?>';
let ACTIVE_BOT_NAME='<?=addslashes($actName)?>';
async function ensureActiveBot(){
  if(ACTIVE_BOT_ID)return true;
  const r=await api('get_bots');
  const list=r.data||[];
  const b=list.find(x=>x.active)||list[0];
  if(!b)return false;
  if(!b.active){const s=await api('set_active_bot',{botId:b.id});if(!s.ok)return false;}
  ACTIVE_BOT_ID=b.id;ACTIVE_BOT_NAME=b.name+' (@'+(b.username||'?')+')';
  if(g('abN'))g('abN').textContent=ACTIVE_BOT_NAME;
  return true;
}
function g(id){return document.getElementById(id);}
function toast(m,t='info'){const d=document.createElement('div');d.className='toast '+t;d.innerHTML=`<span style="color:var(--${t==='success'?'g':t==='error'?'r':t==='warn'?'y':'c'})">● </span>${m}`;g('tc').appendChild(d);setTimeout(()=>{d.style.opacity=0;d.style.transform='translateX(20px)';setTimeout(()=>d.remove(),300);},3000);}
function openSb(){g('sb').classList.add('open');g('sov').classList.add('open');document.body.style.overflow='hidden';}
function closeSb(){g('sb').classList.remove('open');g('sov').classList.remove('open');document.body.style.overflow='';}
function nav(id,btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.ni').forEach(n=>n.classList.remove('active'));
  g('p-'+id).classList.add('active');btn.classList.add('active');closeSb();
  // Scroll to top immediately
  const scrollToTop=()=>{
    window.scrollTo(0,0);
    document.documentElement.scrollTop=0;
    document.body.scrollTop=0;
  };
  scrollToTop();
  requestAnimationFrame(scrollToTop);
  setTimeout(scrollToTop,50);
  const m={dash:()=>{loadDash();checkBot();loadLogs();},bots:loadBots,users:loadUsers,ukeys:loadUK,lkeys:loadLK,builder:loadPages,cfg:loadCfg,vault:loadVault,bvars:loadBV,dvars:loadDynVars,fj:loadFj,broadcast:()=>{dmLoadStickers();dmLoadEmojis();dmsLoadStickers();dmsLoadEmojis();},guide:()=>{},stickers:refreshStickers,forwards:refreshForwards,welcome:loadWelcome,tagger:()=>{loadTagger();utLoadEmojiPicker();},hiddeneye:loadHiddenEye,apkrenamer:apkrLoad,promobot:promoLoad,rosebot:roseLoad,linkautomation:laLoad,depositbot:rbdInit,linkrunner:lrInit,adharbot:adharBotInit};
  if(m[id])m[id]();
}
function openModal(id){g(id).classList.add('open');document.body.style.overflow='hidden';}
function closeModal(id){g(id).classList.remove('open');document.body.style.overflow='';}
async function api(action,data={}){try{const r=await fetch(A+action,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify(data)});return await r.json();}catch(e){return{ok:false,error:e.message};}}
function tup(tid){g('cut').value=tid;g('fup').click();}
async function handleUp(inp){
  if(!inp.files||!inp.files.length)return;
  let fd=new FormData();fd.append('file',inp.files[0]);fd.append('action','upload_media');
  toast('Uploading...','info');
  try{const r=await fetch('?page=api',{method:'POST',body:fd});const d=await r.json();if(d.ok){g(g('cut').value).value=d.url;toast('✅ Uploaded!','success');}else toast('Upload Failed','error');}catch(e){toast('Upload Error','error');}
  inp.value='';
}
async function exportFlows(){const r=await api('get_pages');if(r.ok&&r.data){const b=new Blob([JSON.stringify(r.data,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='rebel_flows.json';a.click();toast('Exported!','success');}}
function importFlows(inp){if(!inp.files||!inp.files.length)return;const reader=new FileReader();reader.onload=async(e)=>{try{const p=JSON.parse(e.target.result);const r=await api('import_pages',{pages:p.pages||p});if(r.ok){toast('Imported!','success');loadPages();}else toast('Error','error');}catch(e){toast('Invalid JSON','error');};inp.value='';};reader.readAsText(inp.files[0]);}
async function checkBot(){const r=await api('bot_info');const b=g('dashB');const n=g('dashN');if(!b||!n)return;if(!r.ok||!r.active_name){n.textContent='No Bot';b.className='badge bi';b.textContent='NO BOT';return;}n.textContent=r.active_name;b.className=r.webhook?.url?'badge ba':'badge bi';b.textContent=r.webhook?.url?'🟢 ONLINE':'🔴 OFFLINE';}
async function startBot(){const r=await api('start_bot');if(r.ok){toast('✅ Started!','success');checkBot();loadLogs();}else toast('Error: '+(r.error||''),'error');}
async function stopBot(){const r=await api('stop_bot');if(r.ok){toast('Stopped','info');checkBot();}}
async function loadDash(){const r=await api('get_stats');if(r.ok&&r.data){g('st-u').textContent=r.data.users;g('st-s').textContent=r.data.searches;g('st-k').textContent=r.data.keys;}}
async function loadLogs(){const r=await api('get_logs');const b=g('logB');if(r.ok&&r.data&&r.data.length){b.innerHTML=r.data.map(l=>`<div><span style="color:var(--tf)">[${new Date(l.time).toLocaleTimeString()}]</span> <span style="color:var(--${l.type==='success'?'g':l.type==='error'?'r':l.type==='warn'?'y':'c'})">${l.text}</span></div>`).join('');}else b.innerHTML='<div style="color:var(--tf)">No logs yet.</div>';}

async function loadBots(){
  const r=await api('get_bots');const list=g('blist');list.innerHTML='';
  if(!r.ok){list.innerHTML='<div style="color:var(--r);text-align:center;padding:14px">⚠️ Error loading bots.</div>';return;}
  if(!r.data||r.data.length===0){list.innerHTML='<div style="text-align:center;color:var(--td);padding:24px;background:var(--s2);border-radius:8px;border:1px dashed var(--b)">🤖 No bots added yet.<br><br>Click <b style="color:var(--c)">+ Add Bot</b>!</div>';return;}
  r.data.forEach(b=>{list.innerHTML+=`<div style="background:var(--s2);padding:12px;border-radius:8px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;border:1px solid ${b.active?'rgba(57,255,20,.35)':'var(--b)'}"><div><strong style="color:var(--t)">${b.name}</strong> <span style="font-size:11px;color:var(--c)">@${b.username||'?'}</span>${b.active?'<span class="badge ba" style="margin-left:8px">ACTIVE</span>':''}</div><div style="display:flex;gap:5px">${!b.active?`<button class="btn bsm bp" onclick="api('set_active_bot',{botId:'${b.id}'}).then(r=>{if(r.ok)location.reload();else toast('Error','error')})">✅ Select</button>`:''}<button class="btn bsm bd" onclick="if(confirm('Delete this bot?'))api('delete_bot',{botId:'${b.id}'}).then(r=>{if(r.ok){toast('Deleted','info');loadBots();}})">🗑️</button></div></div>`;});
}
async function addBot(){const t=g('abt').value.trim();if(!t)return;toast('Verifying...','info');const r=await api('add_bot',{token:t});if(r.ok){toast('✅ Bot Added!','success');closeModal('m-ab');g('abt').value='';loadBots();}else toast('Error: '+(r.error||'Invalid token'),'error');}

let _usersPage=1,_usersSearchTimer=null,_usersReqId=0;
function usersEsc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');}
function usersSearchDebounced(){clearTimeout(_usersSearchTimer);_usersSearchTimer=setTimeout(()=>loadUsers(1),400);}
function usersShowHint(msg){const h=g('users-bot-hint');if(h){h.style.display=msg?'block':'none';h.textContent=msg||'';}}
async function repairUsers(){if(!ACTIVE_BOT_ID){toast('Pehle bot select karo','warn');return;}toast('Repairing users...','info');const r=await api('repair_users',{botId:ACTIVE_BOT_ID});if(r.ok){toast('✅ '+r.total+' users repaired','success');loadUsers(1);}else toast(r.error||'Repair failed','error');}
function renderUsersPager(total,page,pages,limit){
  const p=g('users-pager');if(!p)return;
  if(!total){p.innerHTML='';return;}
  const from=(page-1)*limit+1;const to=Math.min(page*limit,total);
  p.innerHTML=`<span style="font-size:11px;color:var(--td)">${from}-${to} of ${total}</span><div style="display:flex;gap:6px"><button class="btn bg bsm" onclick="loadUsers(${page-1})" ${page<=1?'disabled style="opacity:.4;cursor:not-allowed"':''}>◀ Prev</button><button class="btn bg bsm" onclick="loadUsers(${page+1})" ${page>=pages?'disabled style="opacity:.4;cursor:not-allowed"':''}>Next ▶</button></div>`;
}
async function loadUsers(page){
  if(page!==undefined)_usersPage=Math.max(1,page);
  const b=g('ub');if(!b)return;
  const search=(g('users-search')?.value||'').trim();
  const reqId=++_usersReqId;
  usersShowHint('');
  if(!ACTIVE_BOT_ID){
    b.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--td);padding:16px">Loading bot...</td></tr>';
    if(!(await ensureActiveBot())){
      b.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--y);padding:16px">⚠️ Koi bot select nahi hai.<br><br><b>Bots</b> tab me jao aur apne bot pe <b>✅ Select</b> dabao.</td></tr>';
      renderUsersPager(0,1,1,30);if(g('users-count'))g('users-count').textContent='';return;
    }
  }
  usersShowHint('Active bot: '+ACTIVE_BOT_NAME);
  b.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--td);padding:16px">Loading...</td></tr>';
  let r;
  try{
    const res=await fetch(A+'get_users',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},body:JSON.stringify({page:_usersPage,limit:30,search,botId:ACTIVE_BOT_ID})});
    if(reqId!==_usersReqId)return;
    const txt=await res.text();
    try{r=JSON.parse(txt);}catch(e){b.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--r);padding:16px">Server error — 🔧 Repair try karo</td></tr>';return;}
  }catch(e){if(reqId!==_usersReqId)return;b.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--r);padding:16px">Network error</td></tr>';return;}
  const cnt=g('users-count');const limit=r.limit||30;
  if(!r.ok){b.innerHTML=`<tr><td colspan="6" style="text-align:center;color:var(--r);padding:16px">${usersEsc(r.error||'Failed to load users')}</td></tr>`;renderUsersPager(0,1,1,limit);if(cnt)cnt.textContent='';return;}
  const total=r.total||0;
  if(cnt)cnt.textContent=total?`(${total})`:'';
  if(!r.data?.length){b.innerHTML=`<tr><td colspan="6" style="text-align:center;color:var(--td);padding:16px">${search?'No users match search':total?'No users on this page':'No users yet — 🔧 Repair try karo'}</td></tr>`;renderUsersPager(total,r.page||1,r.pages||1,limit);return;}
  const rows=r.data.map(u=>{
    const id=usersEsc(u.id);const name=usersEsc(u.name||'?');const key=usersEsc(u.key||'—');
    const left=u.searchesLeft==999999?'∞':(u.searchesLeft||0);
    const banBtn=u.banned?`<button class="btn bsu bsm" onclick="api('unban_user',{uid:'${id}'}).then(()=>loadUsers(_usersPage))">Unban</button>`:`<button class="btn bd bsm" onclick="api('ban_user',{uid:'${id}'}).then(()=>loadUsers(_usersPage))">Ban</button>`;
    return `<tr><td><b>${name}</b>${u.username?`<div style="font-size:10px;color:var(--td)">@${usersEsc(u.username)}</div>`:''}</td><td style="font-size:11px;color:var(--td)">${id}</td><td style="color:var(--c)">${left}</td><td><code style="color:var(--c);font-size:11px">${key}</code></td><td><span class="badge ${u.banned?'bi':'ba'}">${u.banned?'BANNED':'Active'}</span></td><td>${banBtn} <button class="btn bg bsm" onclick="if(confirm('Delete?'))api('delete_user',{uid:'${id}'}).then(()=>loadUsers(_usersPage))">Del</button></td></tr>`;
  }).join('');
  b.innerHTML=rows;
  renderUsersPager(total,r.page||1,r.pages||1,limit);
}
async function loadUK(){const r=await api('get_ukeys');const b=g('ukb');b.innerHTML='';if(!r.data?.length){b.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--td);padding:12px">None</td></tr>';return;}r.data.forEach(k=>b.innerHTML+=`<tr><td style="color:var(--c);font-family:'Share Tech Mono';font-size:11px">${k.key}</td><td>${k.searches}</td><td style="font-size:11px">${k.expires||'Never'}</td><td><span class="badge ${k.status==='active'?'ba':'bi'}">${k.status}</span></td><td><button class="btn bd bsm" onclick="api('delete_ukey',{id:'${k.id}'}).then(loadUK)">Del</button></td></tr>`);}
async function loadLK(){const r=await api('get_lkeys');const b=g('lkb');b.innerHTML='';if(!r.data?.length){b.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--td);padding:12px">None</td></tr>';return;}r.data.forEach(k=>b.innerHTML+=`<tr><td style="color:var(--c);font-family:'Share Tech Mono';font-size:11px">${k.key}</td><td><span class="badge bc">${k.tier||'STD'}</span></td><td>${k.searches}</td><td><span class="badge ${k.status==='active'?'ba':'bi'}">${k.status}</span></td><td><button class="btn bd bsm" onclick="api('delete_lkey',{id:'${k.id}'}).then(loadLK)">Del</button></td></tr>`);}
async function genKeys(){const r=await api('gen_keys',{type:g('kg-t').value,tier:'STD',searches:parseInt(g('kg-s').value)||100,days:30,qty:parseInt(g('kg-q').value)||1});if(r.ok){toast(r.keys.length+' key(s) generated!','success');g('kg-out').innerHTML=`<div style="background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:10px">${r.keys.map(k=>`<div style="color:var(--c);font-family:'Share Tech Mono';font-size:13px;padding:4px;cursor:pointer" onclick="navigator.clipboard.writeText('${k}');toast('Copied!','success')">${k}</div>`).join('')}</div>`;if(g('kg-t').value==='LIC')loadLK();else loadUK();}else toast('Error','error');}

let _ftSaveTimer=null;
function clearFtSaveTimer(){clearTimeout(_ftSaveTimer);_ftSaveTimer=setTimeout(()=>saveFtBase(true),1500);}
async function loadCfg(){
  const r=await api('bot_info');
  if(r.ok&&r.bot_config){g('bc-maint').checked=r.bot_config.maintenance||false;g('bc-free').value=r.bot_config.free_searches||3;}
  const r2=await api('get_settings');
  if(r2.ok&&r2.data)g('g-adminid').value=r2.data.settings.adminId||'';
}

// [Global Free Text removed — use per-page Free Text in Flow Builder]

async function saveCfg(){
  const r=await api('save_bot_config',{maintenance:g('bc-maint').checked,free_searches:parseInt(g('bc-free').value)||3});
  if(r.ok){const r2=await api('save_settings',{settings:{adminId:g('g-adminid').value}});if(r2.ok)toast('✅ Config Saved!','success');}
  else toast(r.error||'Error','error');
}

async function changeAdminPass(){
  const cur=g('sec-cur')?.value||'';
  const nw=g('sec-new')?.value||'';
  const cnf=g('sec-cnf')?.value||'';
  const res=g('sec-result');
  if(!cur||!nw){if(res)res.innerHTML='<span style="color:var(--r)">All fields required.</span>';return;}
  if(nw!==cnf){if(res)res.innerHTML='<span style="color:var(--r)">New passwords do not match.</span>';return;}
  if(nw.length<8){if(res)res.innerHTML='<span style="color:var(--r)">Password must be at least 8 characters.</span>';return;}
  const r=await api('change_admin_pass',{current:cur,new:nw});
  if(r.ok){
    if(res)res.innerHTML='<span style="color:var(--g)">✅ Password updated! Hash saved to server.<br>Copy this hash to REBEL_ADMIN_HASH env or code:<br><code style="word-break:break-all;font-size:10px">'+r.hash+'</code></span>';
    g('sec-cur').value='';g('sec-new').value='';g('sec-cnf').value='';
    toast('✅ Password changed successfully!','success');
  }else{
    if(res)res.innerHTML='<span style="color:var(--r)">❌ '+(r.error||'Failed')+'</span>';
    toast(r.error||'Error','error');
  }
}

async function loadFj(){
  const r=await api('get_force_join');if(!r.ok)return;const d=r.data||{};
  _updateFjUI(d.enabled||false);
  g('fj-msg').value=d.message||'⚠️ <b>Please join our channel(s) first!</b>\n\nClick the buttons below, then try again 😊';
  g('fj-media').value=d.media||'';
  g('fj-channels').innerHTML='';(d.channels||[]).forEach(ch=>addFjChannel(ch));
  g('fj-buttons').innerHTML='';(d.buttons||[]).forEach(b=>addFjBtn(b));
}
function _updateFjUI(enabled){const btn=g('fj-toggle-btn');const lbl=g('fj-status-label');if(enabled){btn.textContent='Disable';btn.className='btn bsm bd';lbl.textContent='ON';lbl.style.color='var(--r)';}else{btn.textContent='Enable';btn.className='btn bsm bsu';lbl.textContent='OFF';lbl.style.color='var(--td)';}}
async function toggleFj(){const isOn=g('fj-status-label').textContent==='ON';_updateFjUI(!isOn);await saveFj();toast(!isOn?'✅ Force Join ENABLED':'Force Join DISABLED','info');}
function addFjChannel(data={}){const d=document.createElement('div');d.className='fj-ch-row';d.innerHTML=`<span style="font-size:11px;color:var(--r);min-width:18px">📢</span><input type="text" class="fi fj-ch-id" placeholder="@username or -100123456789" value="${(data.id||'').replace(/"/g,'&quot;')}" style="flex:2"><input type="text" class="fi fj-ch-name" placeholder="Display Name (optional)" value="${(data.name||'').replace(/"/g,'&quot;')}" style="flex:2"><button class="btn bd bsm" onclick="this.parentElement.remove()">✕</button>`;g('fj-channels').appendChild(d);}
function addFjBtn(data={}){const d=document.createElement('div');d.className='fj-btn-row';d.innerHTML=`<span style="font-size:11px;color:var(--c);min-width:18px">🔘</span><input type="text" class="fi fj-btn-text" placeholder="Button Text (e.g. 📢 Join Channel)" value="${(data.text||'').replace(/"/g,'&quot;')}" style="flex:2"><input type="text" class="fi fj-btn-url" placeholder="https://t.me/channel" value="${(data.url||'').replace(/"/g,'&quot;')}" style="flex:3"><button class="btn bd bsm" onclick="this.parentElement.remove()">✕</button>`;g('fj-buttons').appendChild(d);}
async function saveFj(){
  const enabled=g('fj-status-label').textContent==='ON';
  const channels=[];document.querySelectorAll('#fj-channels .fj-ch-row').forEach(row=>{const id=row.querySelector('.fj-ch-id')?.value.trim();const name=row.querySelector('.fj-ch-name')?.value.trim();if(id)channels.push({id,name:name||id});});
  const buttons=[];document.querySelectorAll('#fj-buttons .fj-btn-row').forEach(row=>{const text=row.querySelector('.fj-btn-text')?.value.trim();const url=row.querySelector('.fj-btn-url')?.value.trim();if(text)buttons.push({text,url:url||''});});
  const fj={enabled,channels,message:g('fj-msg').value,media:g('fj-media').value,buttons};
  const r=await api('save_force_join',{fj});if(r.ok)toast('✅ Force Join Saved!','success');else toast(r.error||'Error','error');
}

async function loadVault(){
  const r=await api('get_api_keys');const b=g('vb');b.innerHTML='';
  if(!r.data||!r.data.length){b.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--td);padding:14px">No API keys stored yet.</td></tr>';return;}
  r.data.forEach(k=>{const safeVal=k.value.length>24?k.value.substring(0,24)+'…':k.value;const safeValEsc=k.value.replace(/'/g,"\\'").replace(/"/g,'&quot;');b.innerHTML+=`<tr><td><code style="color:var(--c);font-family:'Share Tech Mono';font-size:11px">{${k.name}}</code></td><td><code style="color:var(--td);font-family:'Share Tech Mono';font-size:11px">${safeVal}</code></td><td style="color:var(--td);font-size:12px">${k.desc||'—'}</td><td><button class="btn bw bsm" onclick="editAK('${k.id}','${k.name}','${safeValEsc}','${(k.desc||'').replace(/'/g,"\\'")}')">Edit</button> <button class="btn bd bsm" onclick="if(confirm('Delete?'))api('delete_api_key',{id:'${k.id}'}).then(r=>{if(r.ok)loadVault();})">Del</button></td></tr>`;});
}
function editAK(id,name,value,desc){g('ak-id').value=id;g('ak-n').value=name;g('ak-v').value=value;g('ak-d').value=desc;openModal('m-ak');}
async function saveAK(){const id=g('ak-id').value;const n=g('ak-n').value.trim();const v=g('ak-v').value.trim();const d=g('ak-d').value.trim();if(!n||!v)return toast('Name and Value are required','error');const r=await api('save_api_key',{id,name:n,value:v,desc:d});if(r.ok){toast('✅ Key Saved!','success');closeModal('m-ak');g('ak-id').value='';loadVault();}else toast(r.error||'Error','error');}

async function loadBV(){const r=await api('get_bot_vars');if(r.ok!==false)g('bv-text').value=r.data||'';}
async function saveBotVars(){const r=await api('save_bot_vars',{bot_vars:g('bv-text').value});if(r.ok)toast('✅ Variables Saved!','success');else toast(r.error||'Error','error');}

async function loadDynVars(){
  const r=await api('get_dyn_vars');const box=g('dv-list');box.innerHTML='';
  if(!r.ok||!r.data||Object.keys(r.data).length===0){box.innerHTML='<div style="color:var(--td);text-align:center;padding:14px;background:var(--s2);border-radius:8px">No live variables yet.</div>';return;}
  Object.entries(r.data).forEach(([k,v])=>{const preview=String(v).length>60?String(v).substring(0,60)+'…':String(v);box.innerHTML+=`<div style="background:var(--s2);padding:10px 12px;border-radius:8px;margin-bottom:7px;display:flex;justify-content:space-between;align-items:center;gap:8px;border:1px solid var(--b);flex-wrap:wrap"><div style="flex:1;min-width:0"><code style="color:var(--o);font-family:'Share Tech Mono';font-size:11px">{${k}}</code><div style="font-size:11px;color:var(--td);margin-top:3px;word-break:break-all">${preview}</div></div><div style="display:flex;gap:5px"><button class="btn bg bsm" onclick="editDynVar('${k}','${String(v).replace(/'/g,"\\'")}')">Edit</button><button class="btn bd bsm" onclick="if(confirm('Delete?'))api('delete_dyn_var',{key:'${k}'}).then(r=>{if(r.ok)loadDynVars();})">Del</button></div></div>`;});
}
function editDynVar(key,val){g('dv-key').value=key;g('dv-val').value=val;}
async function saveDynVar(){const k=g('dv-key').value.trim();const v=g('dv-val').value;if(!k)return toast('Key name required','error');const r=await api('set_dyn_var',{key:k,value:v});if(r.ok){toast('✅ Variable saved!','success');loadDynVars();g('dv-key').value='';g('dv-val').value='';}else toast(r.error||'Error','error');}

async function doBroadcast(){
  const msg=g('bc-msg').value.trim();const media=g('bc-media').value.trim();
  const toUsers=g('bc-to-users').checked;const toGroups=g('bc-to-groups').checked;const toChannels=g('bc-to-channels').checked;
  if(!msg&&!media)return toast('Enter a message first!','error');
  if(!toUsers&&!toGroups&&!toChannels)return toast('Select at least one target!','warn');
  if(!confirm('Send broadcast? Cannot be undone!'))return;
  const res=g('bc-result');res.style.display='block';res.innerHTML='<div style="color:var(--y);font-family:\'Share Tech Mono\';font-size:12px">📣 Broadcasting... please wait</div>';
  const r=await api('broadcast',{message:msg,media,to_users:toUsers,to_groups:toGroups,to_channels:toChannels});
  if(r.ok){res.innerHTML=`<div style="background:rgba(57,255,20,.1);border:1px solid rgba(57,255,20,.3);border-radius:8px;padding:12px;font-family:'Share Tech Mono';font-size:12px"><div style="color:var(--g)">✅ Broadcast Complete!</div><div style="color:var(--td);margin-top:4px">Sent: ${r.sent} | Failed: ${r.failed}</div></div>`;toast('Broadcast sent!','success');}
  else{res.innerHTML=`<div style="color:var(--r)">❌ Error: ${r.error||'Failed'}</div>`;toast('Broadcast failed','error');}
}

let _dmsStickerLib = [];
let _dmsSelected = new Set(); // selected sticker IDs
function toggleDmSingle(){
  const body=g('dm-single-body');
  const arrow=g('dm-single-arrow');
  if(!body)return;
  const open=body.style.display!=='none';
  body.style.display=open?'none':'block';
  if(arrow)arrow.style.transform=open?'rotate(0deg)':'rotate(180deg)';
  if(!open&&!_dmsStickerLib.length)dmsLoadStickers();
}
function dmsCheckReady(){
  const uid=g('dms-uid')?.value.trim();
  const btn=g('dms-send-btn');
  const ready=!!(uid&&uid.length>3);
  if(btn){
    btn.disabled=!ready;
    if(ready){
      btn.style.background='rgba(0,245,255,.18)';
      btn.style.borderColor='rgba(0,245,255,.7)';
      btn.style.color='var(--c)';
      btn.style.cursor='pointer';
    }else{
      btn.style.background='rgba(0,245,255,.06)';
      btn.style.borderColor='rgba(0,245,255,.2)';
      btn.style.color='var(--td)';
      btn.style.cursor='not-allowed';
    }
  }
}
function _dmsUpdateSelCount(){
  const cnt=g('dms-sel-count');
  const delBtn=g('dms-del-btn');
  const n=_dmsSelected.size;
  if(cnt)cnt.textContent=n===0?'0 sticker selected':`✅ ${n} sticker${n>1?'s':''} selected`;
  if(delBtn)delBtn.style.display=n>0?'inline-flex':'none';
}
function _dmsRenderStickerGrid(data){
  const grid=g('dms-stk-grid');
  if(!grid)return;
  if(!data.length){
    grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">📭 Koi sticker nahi.<br><small>Sticker Library mein pehle add karo.</small></div>';
    return;
  }
  grid.innerHTML='';
  data.forEach(stk=>{
    const isSelected=_dmsSelected.has(stk.file_id);
    const card=document.createElement('div');
    card.dataset.fileId=stk.file_id;
    card.dataset.stkId=stk.id;
    card.style.cssText=`position:relative;background:${isSelected?'rgba(191,90,242,.28)':'rgba(191,90,242,.07)'};border:2px solid ${isSelected?'rgba(191,90,242,.9)':'rgba(191,90,242,.22)'};border-radius:10px;padding:10px 6px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:5px;transition:all .15s;user-select:none`;
    card.innerHTML=`

      <div style="position:absolute;top:5px;right:5px;width:15px;height:15px;border-radius:50%;border:2px solid rgba(191,90,242,.6);background:${isSelected?'#bf5af2':'transparent'};display:flex;align-items:center;justify-content:center;font-size:9px;transition:all .15s">${isSelected?'✓':''}</div>
      <span style="font-size:26px;line-height:1">${stk.is_premium?'💎':stk.is_animated?'✨':'🌟'}</span>
      <span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono';word-break:break-all;text-align:center;line-height:1.3;max-width:70px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${stk.label}</span>`;
    card.onmouseenter=()=>{ if(!_dmsSelected.has(stk.file_id))card.style.background='rgba(191,90,242,.16)'; };
    card.onmouseleave=()=>{ if(!_dmsSelected.has(stk.file_id))card.style.background='rgba(191,90,242,.07)'; };
    card.onclick=()=>_dmsToggleSticker(stk.file_id,card);
    grid.appendChild(card);
  });
  _dmsUpdateSelCount();
}
function _dmsToggleSticker(fileId,card){
  if(_dmsSelected.has(fileId)){
    _dmsSelected.delete(fileId);
    card.style.background='rgba(191,90,242,.07)';
    card.style.borderColor='rgba(191,90,242,.22)';
    card.querySelector('div').style.background='transparent';
    card.querySelector('div').textContent='';
  }else{
    _dmsSelected.add(fileId);
    card.style.background='rgba(191,90,242,.28)';
    card.style.borderColor='rgba(191,90,242,.9)';
    card.querySelector('div').style.background='#bf5af2';
    card.querySelector('div').textContent='✓';
  }
  _dmsUpdateSelCount();
}
function dmsSelectAllStickers(){
  _dmsSelected.clear();
  _dmsStickerLib.forEach(s=>_dmsSelected.add(s.file_id));
  _dmsRenderStickerGrid(_dmsStickerLib);
}
function dmsClearStickers(){
  _dmsSelected.clear();
  _dmsRenderStickerGrid(_dmsStickerLib);
}
async function dmsLoadStickers(){
  const grid=g('dms-stk-grid');
  if(grid)grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">⏳ Loading stickers...</div>';
  const r=await api('get_stickers');
  if(!r.ok||!r.data||!r.data.length){
    _dmsStickerLib=[];
    _dmsRenderStickerGrid([]);
    return;
  }
  _dmsStickerLib=r.data;
  _dmsRenderStickerGrid(r.data);
}
async function dmsDeleteSelected(){
  if(!_dmsSelected.size)return toast('Please select a sticker first!','error');
  if(!confirm(`${_dmsSelected.size} sticker${_dmsSelected.size>1?'s':''} delete karne hain library se?`))return;
  const ids=_dmsStickerLib.filter(s=>_dmsSelected.has(s.file_id)).map(s=>s.id);
  let deleted=0,failed=0;
  for(const id of ids){
    const r=await api('delete_sticker',{id});
    if(r.ok)deleted++;else failed++;
  }
  _dmsSelected.clear();
  toast(deleted>0?`🗑 ${deleted} sticker${deleted>1?'s':''} delete ho gaye!${failed?' ('+failed+' failed)':''}`:'❌ Delete failed','success');
  await dmsLoadStickers();

  // Also refresh main sticker library if visible

  refreshStickers();
}
async function dmsDoSend(){
  const uid=g('dms-uid')?.value.trim();
  const msg=g('dms-msg')?.value.trim();
  const media=g('dms-media')?.value.trim();
  const btnsRaw=g('dms-buttons')?.value.trim();
  const res=g('dms-result');
  if(!uid)return toast('User / Chat ID daalo pehle!','error');
  if(!msg&&!media&&!_dmsSelected.size)return toast('Message, media ya sticker — kuch toh daalo!','error');

  // Parse inline buttons (optional)

  let buttons=null;
  if(btnsRaw){
    try{
      let parsed=JSON.parse(btnsRaw);
      if(parsed.length&&!Array.isArray(parsed[0]))parsed=[parsed];
      buttons={inline_keyboard:parsed};
    }catch{
      return toast('Buttons ka JSON galat hai — check karo!','error');
    }
  }
  const stickerIds=[..._dmsSelected];
  const emojiIds=_dmsEmojiLib.filter(e=>_dmsEmojiSelected.has(e.emoji_id)).map(e=>({emoji_id:e.emoji_id,fallback:e.fallback}));
  const stkCount=stickerIds.length;
  const emjCount=emojiIds.length;
  if(!confirm(`Send to user \${uid}?\n📝 Message: ${msg?'Yes':'No'} | 🖼 Media: ${media?'Yes':'No'} | 💎 Stickers: ${stkCount} | ✨ Emojis: ${emjCount}`))return;
  const btn=g('dms-send-btn');
  const origTxt=btn?.innerHTML;
  if(btn){btn.disabled=true;btn.innerHTML='⏳ Sending...';}
  if(res){res.style.display='block';res.innerHTML='<div style="color:var(--y);font-family:\'Share Tech Mono\';font-size:12px">📤 Sending... please wait</div>';}
  const r=await api('send_direct_message',{chat_id:uid,text:msg,media,sticker_id:'',sticker_ids:stickerIds,emoji_ids:emojiIds,buttons});
  if(btn){btn.disabled=false;btn.innerHTML=origTxt;dmsCheckReady();}
  if(r.ok){
    const details=[];
    if(r.msg_sent)details.push('✉️ Message');
    if(r.stickers_sent>0)details.push(`💎 ${r.stickers_sent} sticker${r.stickers_sent>1?'s':''}`);
    if(r.emojis_sent>0)details.push(`✨ ${r.emojis_sent} emoji${r.emojis_sent>1?'s':''}`);
    if(r.stickers_failed>0||r.emojis_failed>0)details.push(`⚠️ ${(r.stickers_failed||0)+(r.emojis_failed||0)} failed`);
    if(res)res.innerHTML=`<div style="background:rgba(57,255,20,.1);border:1px solid rgba(57,255,20,.3);border-radius:8px;padding:12px;font-family:'Share Tech Mono';font-size:12px"><div style="color:var(--g)">✅ Sent!</div><div style="color:var(--td);margin-top:4px">${details.join(' · ')}<br>Chat ID: ${uid}</div></div>`;
    toast('✅ Message bhej diya!','success');
    _dmsSelected.clear();_dmsRenderStickerGrid(_dmsStickerLib);
    _dmsEmojiSelected.clear();_dmsRenderEmojiGrid(_dmsEmojiLib);
  }else{
    if(res)res.innerHTML=`<div style="color:var(--r);font-family:'Share Tech Mono';font-size:12px">❌ Failed: ${r.error||'Unknown error'}</div>`;
    toast('❌ Failed: '+(r.error||'Unknown'),'error');
  }
}

let _dmStickerLib = [];
let _dmReady = false;
let _dmSending = false;
function toggleDmBc(){
  const body = g('dm-bc-body');
  const arrow = g('dm-bc-arrow');
  if(!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  if(arrow) arrow.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
}
function dmCheckReady(){
  const uid = g('dm-uid')?.value.trim();
  const btn = g('dm-send-msg-btn');
  const dot = g('dm-status-dot');
  _dmReady = !!(uid && uid.length > 3);
  if(btn){
    if(_dmReady){
      btn.disabled = false;
      btn.style.cssText = btn.style.cssText.replace(/cursor:[^;]+/,'cursor:pointer');
      btn.style.background = 'rgba(0,245,255,.15)';
      btn.style.borderColor = 'rgba(0,245,255,.6)';
      btn.style.color = 'var(--c)';
      btn.style.borderStyle = 'solid';
    } else {
      btn.disabled = true;
      btn.style.background = 'rgba(0,245,255,.06)';
      btn.style.borderColor = 'rgba(0,245,255,.2)';
      btn.style.color = 'var(--td)';
      btn.style.borderStyle = 'dashed';
    }
  }
  if(dot) dot.style.background = _dmReady ? '#39ff14' : 'var(--td)';

  // Refresh sticker grid enabled state

  document.querySelectorAll('.dm-stk-btn').forEach(b => {
    b.style.opacity = _dmReady ? '1' : '0.35';
    b.style.cursor = _dmReady ? 'pointer' : 'not-allowed';
    b.style.pointerEvents = _dmReady ? 'auto' : 'none';
  });

  // Refresh emoji grid enabled state

  if(g('dm-emj-grid')) _dmRenderEmojiGrid(_dmEmojiLib);
  _dmEmojiUpdateUI();
}
function dmAddLog(text, type='info'){
  const log = g('dm-log');
  if(!log) return;
  const colors = {success:'#39ff14', error:'#ff2d55', info:'#00f5ff', warn:'#ffd60a'};
  const icons = {success:'✅', error:'❌', info:'📤', warn:'⚠️'};
  const row = document.createElement('div');
  row.style.cssText = `display:flex;align-items:center;gap:7px;padding:5px 9px;border-radius:5px;font-family:'Share Tech Mono';font-size:11px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);animation:si .2s ease`;
  row.innerHTML = `<span style="color:${colors[type]||colors.info}">${icons[type]||'•'}</span><span style="color:var(--t);flex:1">${text}</span><span style="color:var(--tf);font-size:9px">${new Date().toLocaleTimeString()}</span>`;
  log.insertBefore(row, log.firstChild);

  // Keep max 20 entries

  while(log.children.length > 20) log.removeChild(log.lastChild);
}
async function dmSendMsg(){
  const uid = g('dm-uid')?.value.trim();
  const msg = g('dm-msg')?.value.trim();
  const media = g('dm-media')?.value.trim();
  if(!uid) return toast('Please enter User ID first!', 'error');
  if(!msg && !media) return toast('Message ya media daalo!', 'error');
  const btn = g('dm-send-msg-btn');
  const origTxt = btn?.innerHTML;
  if(btn){ btn.disabled=true; btn.innerHTML='⏳ Sending...'; }
  const r = await api('send_direct_message', {chat_id:uid, text:msg, media, sticker_id:''});
  if(btn){ btn.disabled=false; btn.innerHTML=origTxt; }
  if(r.ok){
    toast('✅ Message bhej diya!', 'success');
    dmAddLog(`💬 Message → ${uid}`, 'success');
  } else {
    toast('❌ Failed: '+(r.error||'Unknown'), 'error');
    dmAddLog(`❌ Msg failed: ${r.error||'err'}`, 'error');
  }
}
async function dmSendSticker(fileId, label, btnEl){
  const uid = g('dm-uid')?.value.trim();
  if(!uid){ toast('Please enter User ID first!', 'error'); return; }
  if(_dmSending) return; // debounce
  _dmSending = true;

  // Visual tap feedback

  if(btnEl){
    btnEl.style.transform = 'scale(0.88)';
    btnEl.style.background = 'rgba(191,90,242,.35)';
    setTimeout(()=>{ btnEl.style.transform='scale(1)'; btnEl.style.background=''; }, 180);
  }
  const r = await api('send_direct_message', {chat_id:uid, text:'', media:'', sticker_id:fileId});
  _dmSending = false;
  if(r.ok){
    dmAddLog(`🌟 ${label} → ${uid}`, 'success');

    // Flash status dot

    const dot = g('dm-status-dot');
    if(dot){ dot.style.background='#bf5af2'; dot.style.boxShadow='0 0 8px #bf5af2'; setTimeout(()=>{ dot.style.background='#39ff14'; dot.style.boxShadow='none'; }, 400); }
  } else {
    toast('❌ Sticker failed: '+(r.error||''), 'error');
    dmAddLog(`❌ Sticker failed: ${r.error||'err'}`, 'error');
  }
}
async function dmLoadStickers(){
  const grid = g('dm-sticker-grid');
  if(!grid) return;
  const r = await api('get_stickers');
  if(!r.ok || !r.data || !r.data.length){
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:16px;color:var(--td);font-size:11px">📭 Koi sticker nahi.<br><small>Sticker Library mein pehle add karo.</small></div>';
    return;
  }
  _dmStickerLib = r.data;
  grid.innerHTML = '';
  r.data.forEach(stk => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'dm-stk-btn';
    btn.title = stk.label;
    btn.style.cssText = 'background:rgba(191,90,242,.08);border:1px solid rgba(191,90,242,.25);border-radius:10px;padding:10px 6px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:5px;transition:all .15s;width:100%;opacity:0.35;pointer-events:none;';
    btn.innerHTML = `<span style="font-size:26px;line-height:1">${stk.is_premium?'💎':stk.is_animated?'✨':'🌟'}</span><span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono';word-break:break-all;text-align:center;line-height:1.3;max-width:68px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${stk.label}</span>`;
    btn.onmouseenter = () => { if(_dmReady){ btn.style.background='rgba(191,90,242,.25)'; btn.style.borderColor='rgba(191,90,242,.7)'; btn.style.transform='translateY(-2px)'; } };
    btn.onmouseleave = () => { btn.style.background='rgba(191,90,242,.08)'; btn.style.borderColor='rgba(191,90,242,.25)'; btn.style.transform=''; };
    btn.onclick = () => dmSendSticker(stk.file_id, stk.label, btn);
    grid.appendChild(btn);
  });
  dmCheckReady();
}

let _dmEmojiLib = [];
let _dmEmojiSelected = new Set();
function _dmEmojiUpdateUI(){
  const n = _dmEmojiSelected.size;
  const cnt = g('dm-emj-count');
  const sendBtn = g('dm-emj-send-btn');
  if(cnt) cnt.textContent = n === 0 ? '0 emoji selected' : `✅ ${n} emoji${n>1?'s':''} selected`;
  if(sendBtn) sendBtn.style.display = (n > 0 && _dmReady) ? 'inline-flex' : 'none';
}
function _dmRenderEmojiGrid(data){
  const grid = g('dm-emj-grid'); if(!grid) return;
  if(!data.length){
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:12px">📭 Koi emoji nahi.<br><small>Premium Emoji Library mein pehle add karo.</small></div>';
    return;
  }
  grid.innerHTML = '';
  data.forEach(emj => {
    const isSel = _dmEmojiSelected.has(emj.emoji_id);
    const card = document.createElement('div');
    card.style.cssText = `position:relative;background:${isSel?'rgba(191,90,242,.28)':'rgba(191,90,242,.07)'};border:2px solid ${isSel?'rgba(191,90,242,.9)':'rgba(191,90,242,.22)'};border-radius:10px;padding:10px 6px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:5px;transition:all .15s;user-select:none;opacity:${_dmReady?'1':'0.4'};pointer-events:${_dmReady?'auto':'none'};`;
    card.innerHTML = `

      <div style="position:absolute;top:5px;right:5px;width:14px;height:14px;border-radius:50%;border:2px solid rgba(191,90,242,.6);background:${isSel?'#bf5af2':'transparent'};display:flex;align-items:center;justify-content:center;font-size:8px;transition:all .15s">${isSel?'✓':''}</div>
      <span style="font-size:24px;line-height:1">${emj.fallback||'⭐'}</span>
      <span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono';word-break:break-all;text-align:center;line-height:1.3;max-width:68px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${emj.label}</span>`;
    card.onmouseenter = () => { if(_dmReady && !_dmEmojiSelected.has(emj.emoji_id)) card.style.background='rgba(191,90,242,.16)'; };
    card.onmouseleave = () => { if(!_dmEmojiSelected.has(emj.emoji_id)) card.style.background='rgba(191,90,242,.07)'; };
    card.onclick = () => _dmToggleEmoji(emj.emoji_id, card);
    grid.appendChild(card);
  });
  _dmEmojiUpdateUI();
}
function _dmToggleEmoji(emojiId, card){
  if(_dmEmojiSelected.has(emojiId)){
    _dmEmojiSelected.delete(emojiId);
    card.style.background = 'rgba(191,90,242,.07)';
    card.style.borderColor = 'rgba(191,90,242,.22)';
    const dot = card.querySelector('div'); if(dot){dot.style.background='transparent';dot.textContent='';}
  } else {
    _dmEmojiSelected.add(emojiId);
    card.style.background = 'rgba(191,90,242,.28)';
    card.style.borderColor = 'rgba(191,90,242,.9)';
    const dot = card.querySelector('div'); if(dot){dot.style.background='#bf5af2';dot.textContent='✓';}
  }
  _dmEmojiUpdateUI();
}
function dmSelectAllEmojis(){
  _dmEmojiSelected.clear();
  _dmEmojiLib.forEach(e => _dmEmojiSelected.add(e.emoji_id));
  _dmRenderEmojiGrid(_dmEmojiLib);
}
function dmClearEmojis(){
  _dmEmojiSelected.clear();
  _dmRenderEmojiGrid(_dmEmojiLib);
}
async function dmLoadEmojis(){
  const grid = g('dm-emj-grid'); if(!grid) return;
  grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:12px">⏳ Loading...</div>';
  const r = await api('get_prem_emojis');
  if(!r.ok || !r.data || !r.data.length){ _dmEmojiLib=[]; _dmRenderEmojiGrid([]); return; }
  _dmEmojiLib = r.data;
  _dmRenderEmojiGrid(r.data);
}
async function dmSendSelectedEmojis(){
  const uid = g('dm-uid')?.value.trim();
  if(!uid) return toast('Please enter User ID first!', 'error');
  if(!_dmEmojiSelected.size) return toast('Koi emoji select nahi hai!', 'error');
  const emojiIds = _dmEmojiLib.filter(e => _dmEmojiSelected.has(e.emoji_id)).map(e => ({emoji_id:e.emoji_id, fallback:e.fallback}));
  const btn = g('dm-emj-send-btn');
  const origTxt = btn?.innerHTML;
  if(btn){ btn.disabled=true; btn.innerHTML='⏳...'; }
  const r = await api('send_direct_message', {chat_id:uid, text:'', media:'', sticker_id:'', sticker_ids:[], emoji_ids:emojiIds, buttons:null});
  if(btn){ btn.disabled=false; btn.innerHTML=origTxt; }
  if(r.ok){
    const n = r.emojis_sent||emojiIds.length;
    toast(`✅ ${n} emoji${n>1?'s':''} bhej diye!`, 'success');
    dmAddLog(`✨ ${n} emoji${n>1?'s':''} → ${uid}`, 'success');
    const dot = g('dm-status-dot');
    if(dot){ dot.style.background='#bf5af2'; dot.style.boxShadow='0 0 8px #bf5af2'; setTimeout(()=>{ dot.style.background='#39ff14'; dot.style.boxShadow='none'; },400); }
    _dmEmojiSelected.clear();
    _dmRenderEmojiGrid(_dmEmojiLib);
  } else {
    toast('❌ Failed: '+(r.error||'Unknown'), 'error');
    dmAddLog(`❌ Emoji failed: ${r.error||'err'}`, 'error');
  }
}

// Load stickers when broadcast panel is opened

function onFtToggle(cb){
  const opts=g('ft-opts-row');
  if(cb.checked){opts.style.display='block';g('pb-trigger').placeholder='Optional trigger (or blank for free text only)';}
  else{opts.style.display='none';g('pb-trigger').placeholder='start, search...';}
}
function onType(){
  const t=g('pb-type').value;
  g('f-api').style.display=t==='api'?'block':'none';
  g('f-curl').style.display=t==='curl'?'block':'none';
  g('f-ext').style.display=(t==='api'||t==='curl')?'block':'none';
  g('f-browser').style.display=t==='browser'?'block':'none';
}
function openCmdModal(){
  ['pb-id','pb-trigger','pb-ac','pb-fb','pb-media','pb-mmedia','pb-emedia','pb-vars','pb-apiurl','pb-root','pb-miss','pb-err','pb-text','pb-curl-url','pb-curl-h','pb-curl-b','pb-curl-rp','pb-cpaste','pb-ft-access','pb-docurl','pb-bv-names','pb-bv-done','pb-sticker-id'].forEach(id=>{const el=g(id);if(el)el.value='';});
  g('pb-type').value='text';if(g('pb-to'))g('pb-to').value='15';if(g('pb-curl-to'))g('pb-curl-to').value='120';
  ['pb-cr','pb-retry','pb-ccr','pb-ft-on','pb-ft-mention','pb-fj'].forEach(id=>{const el=g(id);if(el)el.checked=false;});
  if(g('pb-ft-chatmode'))g('pb-ft-chatmode').value='both';
  g('ft-opts-row').classList.remove('show');g('ft-opts-row').style.display='none';
  g('btnc').innerHTML='';g('lsc').innerHTML='';g('bsteps-c').innerHTML='';onType();openModal('m-builder');
}
window.PAGES=[];
function editPage(id){
  const c=window.PAGES.find(p=>p.id===id);if(!c)return;
  g('pb-id').value=c.id||'';g('pb-trigger').value=c.trigger||'';g('pb-type').value=c.type||'text';
  g('pb-ac').value=c.access_control||'';g('pb-fb').value=c.fallback_page||'';
  if(g('pb-cr'))g('pb-cr').checked=c.requires_credit||false;
  if(g('pb-ccr'))g('pb-ccr').checked=c.requires_credit||false;
  if(g('pb-fj'))g('pb-fj').checked=c.force_join||false;
  g('pb-media').value=c.media_main||'';g('pb-mmedia').value=c.media_missing||'';g('pb-emedia').value=c.media_error||'';
  g('pb-vars').value=c.custom_vars||'';g('pb-apiurl').value=c.api_url||'';g('pb-root').value=c.json_root||'';
  g('pb-err').value=c.not_found||'';g('pb-miss').value=c.msg_missing||'';
  if(g('pb-to'))g('pb-to').value=c.api_timeout||15;
  if(g('pb-curl-to'))g('pb-curl-to').value=c.curl_timeout||120;
  if(g('pb-retry'))g('pb-retry').checked=c.api_retry||false;
  g('pb-text').value=c.text||'';
  g('pb-curl-url').value=c.curl_url||'';g('pb-curl-m').value=c.curl_method||'POST';
  g('pb-curl-h').value=c.curl_headers||'';g('pb-curl-b').value=c.curl_body||'';g('pb-curl-rp').value=c.curl_response_path||'';
  if(g('pb-docurl'))g('pb-docurl').value=c.document_url||'';

  // Browser fields

  if(g('pb-bv-names'))g('pb-bv-names').value=c.browser_var_names||'';
  if(g('pb-bv-done'))g('pb-bv-done').value=c.browser_done_msg||'✅ Done!';
  g('bsteps-c').innerHTML='';if(c.browser_steps)c.browser_steps.forEach(s=>addBrowserStep(s));
  if(g('pb-sticker-id'))g('pb-sticker-id').value=c.sticker_id||'';
  const isFt=c.is_free_text||false;
  if(g('pb-ft-on'))g('pb-ft-on').checked=isFt;
  onFtToggle(g('pb-ft-on'));
  if(g('pb-ft-chatmode'))g('pb-ft-chatmode').value=c.ft_chat_mode||'both';
  if(g('pb-ft-mention'))g('pb-ft-mention').checked=c.ft_mention_only||false;
  if(g('pb-ft-access'))g('pb-ft-access').value=c.ft_access_control||'';
  g('btnc').innerHTML='';if(c.buttons)c.buttons.forEach(b=>addBtn(b));
  g('lsc').innerHTML='';if(c.loading_steps)c.loading_steps.forEach(ls=>addLS(ls));
  onType();openModal('m-builder');
}
async function loadPages(){
  const r=await api('get_pages');const b=g('cb');b.innerHTML='';window.PAGES=r.data||[];
  if(!window.PAGES.length){b.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--td);padding:16px">No pages yet. Click <b>+ New Page</b>.</td></tr>';return;}
  const tm={text:'<span class="badge by">TEXT</span>',api:'<span class="badge bc">API</span>',curl:'<span class="badge bpv">CURL</span>'};
  window.PAGES.forEach(c=>{
    const trigLabel=c.is_free_text
      ?`<span class="badge bpv">FREE TEXT</span> <span style="font-size:10px;color:var(--p)">${c.ft_chat_mode||'both'}</span>`
      :`<span class="badge ba">/${c.trigger||'—'}</span>`;
    const fjBadge=c.force_join?'<span class="badge bfj" style="font-size:9px">🔒 FJ</span>':'<span style="color:var(--tf);font-size:11px">—</span>';
    b.innerHTML+=`<tr>
      <td><b style="color:var(--c);font-family:'Share Tech Mono';font-size:11px">${c.id}</b></td>
      <td>${trigLabel}</td>
      <td>${tm[c.type]||c.type}</td>
      <td>${c.requires_credit?'<span class="badge bi">Paid</span>':'<span class="badge ba">Free</span>'}</td>
      <td>${fjBadge}</td>
      <td><button class="btn by bsm" onclick="editPage('${c.id}')">Edit</button> <button class="btn bd bsm" onclick="if(confirm('Delete?'))api('delete_page',{id:'${c.id}'}).then(r=>{if(r.ok)loadPages();})">Del</button></td>
    </tr>`;
  });
}
async function savePage(){
  try{
    let btns=[];
    document.querySelectorAll('.prow').forEach(row=>{
      const btype=row.querySelector('.btype2')?.value||'page';
      const text=row.querySelector('.bn2')?.value||'';
      const url=row.querySelector('.burl2')?.value||'';
      const targ=btype==='url'?'':btype!=='page'?btype:row.querySelector('.bt2')?.value||'';
      btns.push({text,type:btype,target:targ,url:btype==='url'?url:'',cond:row.querySelector('.bc2')?.value||'',edit:row.querySelector('.be2')?.value==='1',delay:row.querySelector('.bd2')?.value||'0'});
    });
    let ls=[];document.querySelectorAll('.lsrow').forEach(r=>{ls.push({text:r.querySelector('.ls-t')?.value||'',media:r.querySelector('.ls-m')?.value||''});});
    const isFt=g('pb-ft-on')?.checked||false;
    const d={
      id:g('pb-id').value.trim(),trigger:g('pb-trigger').value.trim(),type:g('pb-type').value,
      is_free_text:isFt,ft_chat_mode:g('pb-ft-chatmode')?.value||'both',
      ft_mention_only:g('pb-ft-mention')?.checked||false,ft_access_control:g('pb-ft-access')?.value||'',
      force_join:g('pb-fj')?.checked||false,
      access_control:g('pb-ac').value,fallback_page:g('pb-fb').value,
      requires_credit:(g('pb-type').value==='curl'?(g('pb-ccr')?.checked||false):(g('pb-cr')?.checked||false)),
      media_main:g('pb-media').value,media_missing:g('pb-mmedia').value,media_error:g('pb-emedia').value,
      custom_vars:g('pb-vars').value,text:g('pb-text').value,api_url:g('pb-apiurl').value,
      json_root:g('pb-root').value,not_found:g('pb-err').value,msg_missing:g('pb-miss').value,
      msg_loading:'',loading_steps:ls,
      api_timeout:parseInt(g('pb-to')?.value)||15,
      curl_timeout:parseInt(g('pb-curl-to')?.value)||120,
      api_retry:g('pb-retry')?.checked||false,buttons:btns,
      curl_url:g('pb-curl-url').value,curl_method:g('pb-curl-m').value,
      curl_headers:g('pb-curl-h').value,curl_body:g('pb-curl-b').value,curl_response_path:g('pb-curl-rp').value,
      document_url:g('pb-docurl')?.value||'',
      browser_var_names:g('pb-bv-names')?.value||'',
      browser_done_msg:g('pb-bv-done')?.value||'✅ Done!',
      browser_steps:getBrowserSteps(),
      sticker_id:g('pb-sticker-id')?.value?.trim()||''
    };
    if(!d.id)return toast('Page ID required!','error');
    const r=await api('save_page',d);if(r.ok){toast('✅ Saved!','success');closeModal('m-builder');loadPages();}else toast(r.error||'Error','error');
  }catch(e){toast('UI Error: '+e.message,'error');console.error(e);}
}

const _miniEmojiState={};
function _buildMiniPanel(panelEl,targetId){
  panelEl.innerHTML=`

    <div style="background:rgba(13,17,23,.97);border:1px solid rgba(191,90,242,.35);border-radius:9px;padding:10px">

      <div style="display:flex;gap:6px;margin-bottom:8px;align-items:center">
        <input type="text" class="fi mini-emoji-search" placeholder="🔍 Label se dhundho..." oninput="filterMiniEmojis(this,'${targetId}')" style="flex:1;font-size:11px;padding:5px 9px">
        <button type="button" class="btn bg bsm" onclick="refreshMiniGrid('${targetId}')">🔄</button>
      </div>

      <div id="mini-grid-${targetId}" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:5px;max-height:180px;overflow-y:auto">

        <div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:12px">⏳ Loading...</div>
      </div>

      <div style="margin-top:7px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding-top:7px;border-top:1px solid rgba(191,90,242,.2)">
        <span style="font-size:10px;color:var(--td);font-family:'Share Tech Mono'">Insert as:</span>
        <label style="display:flex;align-items:center;gap:3px;cursor:pointer;font-size:10px;color:var(--c)">
          <input type="radio" name="mini-mode-${targetId}" value="tag" checked style="accent-color:#bf5af2"> &lt;tg-emoji&gt;
        </label>
        <label style="display:flex;align-items:center;gap:3px;cursor:pointer;font-size:10px;color:var(--o)">
          <input type="radio" name="mini-mode-${targetId}" value="placeholder" style="accent-color:#bf5af2"> {placeholder}
        </label>
      </div>
    </div>`;
}
function _renderMiniGrid(gridId,list,targetId){
  const grid=g(gridId);if(!grid)return;
  if(!list||list.length===0){
    grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:10px">'+(list===null?'📭 Library empty hai.':'🔍 Koi match nahi.')+'</div>';
    return;
  }
  grid.innerHTML='';
  list.forEach(emj=>{
    const btn=document.createElement('button');
    btn.type='button';
    btn.title=emj.label;
    btn.style.cssText='background:rgba(191,90,242,.08);border:1px solid rgba(191,90,242,.22);border-radius:6px;padding:5px 7px;cursor:pointer;display:flex;align-items:center;gap:6px;color:var(--t);font-size:11px;width:100%;text-align:left;transition:background .15s;';
    btn.onmouseenter=()=>{btn.style.background='rgba(191,90,242,.22)';};
    btn.onmouseleave=()=>{btn.style.background='rgba(191,90,242,.08)';};
    btn.innerHTML=`<span style="font-size:18px;min-width:22px;text-align:center">${emj.fallback||'⭐'}</span><div style="overflow:hidden"><div style="font-size:10px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${emj.label}</div><div style="font-size:8px;color:var(--td);font-family:'Share Tech Mono'">${emj.emoji_id.substring(0,10)}…</div></div>`;
    btn.onclick=()=>insertMiniEmoji(emj,targetId);
    grid.appendChild(btn);
  });
}
async function refreshMiniGrid(targetId){
  const gridId='mini-grid-'+targetId;
  const grid=g(gridId);if(!grid)return;
  grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:12px">⏳ Loading...</div>';
  const r=await api('get_prem_emojis');
  const list=(r.ok&&r.data)?r.data:null;
  _miniEmojiState[targetId]=list||[];
  _renderMiniGrid(gridId,list,targetId);
}
function filterMiniEmojis(input,targetId){
  const q=input.value.toLowerCase().trim();
  const full=_miniEmojiState[targetId]||[];
  _renderMiniGrid('mini-grid-'+targetId,q?full.filter(e=>(e.label||'').toLowerCase().includes(q)||(e.fallback||'').includes(q)):full,targetId);
}
function insertMiniEmoji(emj,targetId){
  let ta=null;
  if(targetId==='miss')ta=g('pb-miss');
  else if(targetId==='err')ta=g('pb-err');
  else if(targetId==='ls'){
    ta=document.querySelector('.ls-t:focus')||document.querySelector('.ls-t');
  }
  // 🌹 Rose Bot reply message textareas — direct ID se milao
  else if(g(targetId)){ta=g(targetId);}
  if(!ta){toast('Textarea nahi mila: '+targetId,'warn');return;}
  const mode=document.querySelector(`input[name="mini-mode-${targetId}"]:checked`)?.value||'tag';
  let txt;
  if(mode==='placeholder'){
    const key='emoji_'+emj.label.toLowerCase().replace(/[^a-z0-9]/g,'_');
    txt='{'+key+'}';
  }else{
    txt=`<tg-emoji emoji-id="${emj.emoji_id}">${emj.fallback||'⭐'}</tg-emoji>`;
  }
  const s=ta.selectionStart,e=ta.selectionEnd;
  ta.value=ta.value.substring(0,s)+txt+ta.value.substring(e);
  ta.focus();ta.setSelectionRange(s+txt.length,s+txt.length);
  toast('✅ '+emj.fallback+' inserted!','success');
}
async function toggleMiniEmojiPicker(targetId){
  const panel=g(targetId+'-emoji-panel');
  const arrow=g(targetId+'-emoji-arrow');
  if(!panel)return;
  const isOpen=panel.style.display!=='none';
  panel.style.display=isOpen?'none':'block';
  if(arrow)arrow.style.transform=isOpen?'rotate(0deg)':'rotate(180deg)';
  if(!isOpen){

    // Build panel HTML if not yet built

    if(!panel.innerHTML.trim()||panel.innerHTML.includes('none')){
      _buildMiniPanel(panel,targetId);
    }
    await refreshMiniGrid(targetId);
  }
}

let _pbEmojiLib=[];
let _pbEmojiOpen=false;
let _pbTextCursorPos=0;
function togglePbEmojiPicker(){
  const panel=g('pb-emoji-panel');
  const arrow=g('pb-emoji-arrow');
  _pbEmojiOpen=!_pbEmojiOpen;
  panel.style.display=_pbEmojiOpen?'block':'none';
  arrow.style.transform=_pbEmojiOpen?'rotate(180deg)':'rotate(0deg)';
  if(_pbEmojiOpen)refreshPbEmojiList();
}
async function refreshPbEmojiList(){
  const grid=g('pb-emoji-grid');
  if(!grid)return;
  grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:14px">⏳ Library load ho rahi hai...</div>';
  const r=await api('get_prem_emojis');
  if(!r.ok||!r.data||r.data.length===0){
    grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:14px">📭 Library empty hai.<br><small style="color:var(--tf)">Premium Emoji Library mein emojis add karo pehle.</small></div>';
    _pbEmojiLib=[];return;
  }
  _pbEmojiLib=r.data;
  renderPbEmojiGrid(_pbEmojiLib);
}
function renderPbEmojiGrid(list){
  const grid=g('pb-emoji-grid');
  if(!grid)return;
  if(list.length===0){
    grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:14px">🔍 Koi emoji match nahi mila.</div>';
    return;
  }
  grid.innerHTML='';
  list.forEach(emj=>{
    const card=document.createElement('button');
    card.type='button';
    card.title='Click to insert: '+emj.label;
    card.style.cssText='background:rgba(191,90,242,.08);border:1px solid rgba(191,90,242,.25);border-radius:7px;padding:7px 9px;cursor:pointer;display:flex;align-items:center;gap:7px;color:var(--t);font-size:12px;width:100%;text-align:left;transition:background .15s,border-color .15s;';
    card.onmouseenter=()=>{card.style.background='rgba(191,90,242,.22)';card.style.borderColor='rgba(191,90,242,.6)';};
    card.onmouseleave=()=>{card.style.background='rgba(191,90,242,.08)';card.style.borderColor='rgba(191,90,242,.25)';};
    card.innerHTML=`<span style="font-size:20px;line-height:1;min-width:24px;text-align:center">${emj.fallback||'⭐'}</span><div style="overflow:hidden"><div style="font-size:11px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--t)">${emj.label||'Emoji'}</div><div style="font-size:9px;color:var(--td);font-family:'Share Tech Mono'">${emj.emoji_id.substring(0,10)}…</div></div>`;
    card.onclick=()=>insertPbEmoji(emj);
    grid.appendChild(card);
  });
}
function filterPbEmojis(){
  const q=(g('pb-emoji-search')?.value||'').toLowerCase().trim();
  if(!q){renderPbEmojiGrid(_pbEmojiLib);return;}
  renderPbEmojiGrid(_pbEmojiLib.filter(e=>(e.label||'').toLowerCase().includes(q)||(e.fallback||'').includes(q)));
}
function insertPbEmoji(emj){
  const ta=g('pb-text');
  if(!ta)return;
  const mode=document.querySelector('input[name="pb-emoji-mode"]:checked')?.value||'tag';
  let insertText;
  if(mode==='placeholder'){
    const key='emoji_'+emj.label.toLowerCase().replace(/[^a-z0-9]/g,'_');
    insertText='{'+key+'}';
  }else{
    insertText=`<tg-emoji emoji-id="${emj.emoji_id}">${emj.fallback||'⭐'}</tg-emoji>`;
  }

  // Insert at cursor or append

  const start=ta.selectionStart;
  const end=ta.selectionEnd;
  const before=ta.value.substring(0,start);
  const after=ta.value.substring(end);
  ta.value=before+insertText+after;

  // Restore cursor after inserted text

  const newPos=start+insertText.length;
  ta.focus();
  ta.setSelectionRange(newPos,newPos);
  toast('✅ '+emj.fallback+' inserted!','success');
}

// Track cursor position in pb-text so insert goes at right spot

document.addEventListener('DOMContentLoaded',()=>{
  const ta=document.getElementById('pb-text');
  if(ta){
    ta.addEventListener('click',()=>{_pbTextCursorPos=ta.selectionStart;});
    ta.addEventListener('keyup',()=>{_pbTextCursorPos=ta.selectionStart;});
  }
});

function addBtn(data={text:'',type:'page',target:'',url:'',cond:'',edit:true,delay:0}){
  const btype=data.url?'url':(data.target==='_NEXT_'?'_NEXT_':data.target==='_PREV_'?'_PREV_':'page');
  const d=document.createElement('div');d.className='br prow';
  d.innerHTML=`
    <input type="text" class="fi bn2" placeholder="Button Text" value="${(data.text||'').replace(/"/g,'&quot;')}" style="flex:2">
    <select class="fsel btype2" onchange="onBtnTypeChange(this)" style="flex:1.2">
      <option value="page" ${btype==='page'?'selected':''}>Go to Page</option>
      <option value="url" ${btype==='url'?'selected':''}>🔗 URL</option>
      <option value="_NEXT_" ${btype==='_NEXT_'?'selected':''}>Next ⏭️</option>
      <option value="_PREV_" ${btype==='_PREV_'?'selected':''}>Prev ⏪</option>
    </select>
    <input type="text" class="fi bt2" placeholder="Page ID" value="${btype==='page'?(data.target||''):''}" style="flex:2;display:${btype==='page'?'block':'none'}">
    <input type="text" class="fi burl2" placeholder="https://t.me/channel" value="${data.url||''}" style="flex:2;display:${btype==='url'?'block':'none'}">
    <input type="text" class="fi bc2" placeholder="Condition" value="${data.cond||''}" style="flex:2">
    <select class="fsel be2" style="flex:1"><option value="1" ${data.edit!==false?'selected':''}>Edit</option><option value="0" ${data.edit===false?'selected':''}>New</option></select>
    <input type="number" class="fi bd2" placeholder="Delay" value="${data.delay||0}" style="flex:1">
    <button class="btn bd bsm" onclick="this.parentElement.remove()">✕</button>
  `;
  g('btnc').appendChild(d);
}
function onBtnTypeChange(sel){
  const row=sel.parentElement;
  const pi=row.querySelector('.bt2');const ui=row.querySelector('.burl2');
  if(sel.value==='page'){pi.style.display='block';ui.style.display='none';}
  else if(sel.value==='url'){pi.style.display='none';ui.style.display='block';}
  else{pi.style.display='none';ui.style.display='none';}
}
function addLS(data={text:'',media:''}){
  const d=document.createElement('div');d.className='br lsrow';
  const rid='ls_'+Math.random().toString(36).substr(2,7);
  const epid='lsep_'+rid;
  const escaped=(data.text||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
  d.innerHTML=`

    <div style="display:flex;flex-direction:column;gap:5px;flex:2">

      <div style="display:flex;gap:5px;align-items:center;flex-wrap:wrap">
        <button type="button" onclick="_lsToggleEmoji('${epid}',this)" style="background:rgba(191,90,242,.13);border:1px solid rgba(191,90,242,.42);color:#bf5af2;font-size:10px;padding:3px 9px;border-radius:5px;cursor:pointer;display:inline-flex;align-items:center;gap:4px;white-space:nowrap">💎 Emoji <span style="font-size:8px;transition:transform .2s" class="lsep-arrow">▼</span></button>
      </div>

      <div id="${epid}" style="display:none;margin-bottom:3px"></div>
      <textarea class="fta ls-t" placeholder="Loading text..." style="min-height:48px">${escaped}</textarea>
    </div>

    <div style="display:flex;flex-direction:column;gap:4px;flex:1">
      <input type="text" class="fi ls-m" id="${rid}" placeholder="Media URL..." value="${data.media||''}">

      <div style="display:flex;gap:4px">
        <button class="btn bg bsm" style="flex:1" onclick="tup('${rid}')">📁</button>
        <button class="btn bd bsm" style="flex:1" onclick="this.parentElement.parentElement.parentElement.remove()">✕</button>
      </div>
    </div>`;
  g('lsc').appendChild(d);
}
function _lsToggleEmoji(panelId, btn){
  const panel=g(panelId);if(!panel)return;
  const arrow=btn.querySelector('.lsep-arrow');
  const isOpen=panel.style.display!=='none';
  panel.style.display=isOpen?'none':'block';
  if(arrow)arrow.style.transform=isOpen?'rotate(0deg)':'rotate(180deg)';
  if(!isOpen){
    if(!panel.innerHTML.trim()){

      // Build mini panel but targeting the ls-t textarea in THIS row

      const rowDiv=panel.closest('.lsrow');
      const ta=rowDiv?rowDiv.querySelector('.ls-t'):null;
      _buildLsEmojiPanel(panel, ta);
      _loadLsEmojiGrid(panel);
    }
  }
}
function _buildLsEmojiPanel(panel, ta){
  const gid='lseg_'+Math.random().toString(36).substr(2,7);
  panel.setAttribute('data-gid', gid);
  panel.setAttribute('data-ta-id', ta ? ta.id : '');
  panel.innerHTML=`

    <div style="background:rgba(13,17,23,.97);border:1px solid rgba(191,90,242,.35);border-radius:9px;padding:10px">

      <div style="display:flex;gap:6px;margin-bottom:8px;align-items:center">
        <input type="text" class="fi" placeholder="🔍 Label se dhundho..." oninput="_filterLsEmoji(this,'${gid}')" style="flex:1;font-size:11px;padding:5px 9px">
        <button type="button" class="btn bg bsm" onclick="_loadLsEmojiGrid(this.closest('[data-gid]'))">🔄</button>
      </div>

      <div id="${gid}" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:5px;max-height:180px;overflow-y:auto">

        <div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:12px">⏳ Loading...</div>
      </div>

      <div style="margin-top:7px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding-top:7px;border-top:1px solid rgba(191,90,242,.2)">
        <span style="font-size:10px;color:var(--td);font-family:'Share Tech Mono'">Insert as:</span>
        <label style="display:flex;align-items:center;gap:3px;cursor:pointer;font-size:10px;color:var(--c)">
          <input type="radio" name="lsmode-${gid}" value="tag" checked style="accent-color:#bf5af2"> &lt;tg-emoji&gt;
        </label>
        <label style="display:flex;align-items:center;gap:3px;cursor:pointer;font-size:10px;color:var(--o)">
          <input type="radio" name="lsmode-${gid}" value="placeholder" style="accent-color:#bf5af2"> {placeholder}
        </label>
      </div>
    </div>`;
}
async function _loadLsEmojiGrid(panelOrChild){
  const panel=panelOrChild.closest ? panelOrChild.closest('[data-gid]') : panelOrChild;
  if(!panel)return;
  const gid=panel.getAttribute('data-gid');
  const grid=g(gid);if(!grid)return;
  grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:12px">⏳ Loading...</div>';
  const r=await api('get_prem_emojis');
  const list=(r.ok&&r.data&&r.data.length)?r.data:null;
  panel._emojiList=list||[];
  _renderLsEmojiGrid(grid, list, panel);
}
function _filterLsEmoji(input, gid){
  const grid=g(gid);if(!grid)return;
  const panel=grid.closest('[data-gid]');
  const full=(panel&&panel._emojiList)||[];
  const q=input.value.toLowerCase().trim();
  _renderLsEmojiGrid(grid, q?full.filter(e=>(e.label||'').toLowerCase().includes(q)||(e.fallback||'').includes(q)):full, panel);
}
function _renderLsEmojiGrid(grid, list, panel){
  if(!grid)return;
  if(!list||!list.length){
    grid.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:10px">'+(list===null?'📭 Library empty.':'🔍 Koi match nahi.')+'</div>';
    return;
  }
  const gid=grid.id;
  grid.innerHTML='';
  list.forEach(emj=>{
    const btn=document.createElement('button');
    btn.type='button';
    btn.title=emj.label;
    btn.style.cssText='background:rgba(191,90,242,.08);border:1px solid rgba(191,90,242,.22);border-radius:6px;padding:5px 7px;cursor:pointer;display:flex;align-items:center;gap:6px;color:var(--t);font-size:11px;width:100%;text-align:left;transition:background .15s;';
    btn.onmouseenter=()=>{btn.style.background='rgba(191,90,242,.22)';};
    btn.onmouseleave=()=>{btn.style.background='rgba(191,90,242,.08)';};
    btn.innerHTML=`<span style="font-size:18px;min-width:22px;text-align:center">${emj.fallback||'⭐'}</span><div style="overflow:hidden"><div style="font-size:10px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${emj.label}</div><div style="font-size:8px;color:var(--td);font-family:'Share Tech Mono'">${emj.emoji_id.substring(0,10)}…</div></div>`;
    btn.onclick=()=>{

      // Find the ls-t textarea in this row

      const rowDiv=grid.closest('.lsrow');
      const ta=rowDiv?rowDiv.querySelector('.ls-t'):null;
      if(!ta){toast('Loading step textarea nahi mila','warn');return;}
      const mode=document.querySelector(`input[name="lsmode-${gid}"]:checked`)?.value||'tag';
      let txt;
      if(mode==='placeholder'){
        const key='emoji_'+emj.label.toLowerCase().replace(/[^a-z0-9]/g,'_');
        txt='{'+key+'}';
      }else{
        txt=`<tg-emoji emoji-id="${emj.emoji_id}">${emj.fallback||'⭐'}</tg-emoji>`;
      }
      const s=ta.selectionStart,e=ta.selectionEnd;
      ta.value=ta.value.substring(0,s)+txt+ta.value.substring(e);
      ta.focus();ta.setSelectionRange(s+txt.length,s+txt.length);
      toast('✅ '+emj.fallback+' inserted!','success');
    };
    grid.appendChild(btn);
  });
}

// FIX: cURL parser — improved JS side: sends raw curl to improved PHP parser

async function parsePageCurl(){
  const raw=g('pb-cpaste').value;
  if(!raw.trim())return toast('Paste curl first','error');
  toast('Parsing...','info');
  const r=await api('parse_curl',{curl:raw});
  if(r.ok&&r.parsed){
    const p=r.parsed;
    if(p.url)g('pb-curl-url').value=p.url;
    if(p.method)g('pb-curl-m').value=p.method;
    if(p.headers_str)g('pb-curl-h').value=p.headers_str;
    if(p.body)g('pb-curl-b').value=p.body;
    const parts=[];
    if(p.url)parts.push('URL ✅');
    if(p.method&&p.method!=='GET')parts.push('Method: '+p.method+' ✅');
    if(p.headers_str)parts.push('Headers ✅');
    if(p.body)parts.push('Body ✅');
    toast('Parsed: '+parts.join(', '),'success');
  }else{
    toast('Could not parse — check curl format','error');
  }
}

// NEW: Python requests snippet parser

async function parsePagePython(){
  const raw=g('pb-cpaste').value;
  if(!raw.trim())return toast('Paste Python code first','error');
  toast('Parsing Python...','info');
  const r=await api('parse_python',{python:raw});
  if(r.ok&&r.parsed){
    const p=r.parsed;
    if(p.url)g('pb-curl-url').value=p.url;
    if(p.method)g('pb-curl-m').value=p.method;
    if(p.headers_str)g('pb-curl-h').value=p.headers_str;
    if(p.body)g('pb-curl-b').value=p.body;
    const parts=[];
    if(p.url)parts.push('URL ✅');
    if(p.method&&p.method!=='GET')parts.push('Method: '+p.method+' ✅');
    if(p.headers_str)parts.push('Headers ✅');
    if(p.body)parts.push('Body ✅');
    toast('Python Parsed: '+parts.join(', '),'success');
  }else{
    toast('Could not parse — check Python format','error');
  }
}

// BROWSER AUTOMATION STEP BUILDER JS

const BS_TYPES={
  open:{label:'🌐 Open URL',fields:[{k:'value',ph:'https://site.com or {var1}',label:'URL'}]},
  click:{label:'👆 Click',fields:[{k:'selector',ph:'#btn or //button',label:'Selector'},{k:'x',ph:'X (optional)',label:'X'},{k:'y',ph:'Y (optional)',label:'Y'}]},
  double_click:{label:'👆👆 Double Click',fields:[{k:'selector',ph:'#element',label:'Selector'}]},
  right_click:{label:'🖱 Right Click',fields:[{k:'selector',ph:'#element',label:'Selector'}]},
  fill:{label:'⌨️ Fill Input',fields:[{k:'selector',ph:'#email',label:'Selector'},{k:'value',ph:'{mail} or text',label:'Value/Var'}]},
  type_slow:{label:'⌨️ Type Slow (human)',fields:[{k:'selector',ph:'#input',label:'Selector'},{k:'value',ph:'Hello {user}',label:'Text'},{k:'delay_ms',ph:'50',label:'Delay ms/char'}]},
  clear_field:{label:'🗑 Clear Field',fields:[{k:'selector',ph:'#input',label:'Selector'}]},
  screenshot:{label:'📸 Screenshot',fields:[{k:'caption',ph:'Result: {title}',label:'Caption'},{k:'crop_x',ph:'X blank=full',label:'X'},{k:'crop_y',ph:'Y',label:'Y'},{k:'crop_w',ph:'W',label:'Width'},{k:'crop_h',ph:'H',label:'Height'}],checks:[{k:'send_ss',label:'Send to user'},{k:'delete_after',label:'Del after'}]},
  ask_captcha:{label:'🔐 Ask Captcha',fields:[{k:'caption',ph:'🔐 Reply with captcha:',label:'Prompt msg'},{k:'crop_x',ph:'X blank=full',label:'X'},{k:'crop_y',ph:'Y',label:'Y'},{k:'crop_w',ph:'W',label:'Width'},{k:'crop_h',ph:'H',label:'Height'},{k:'var_name',ph:'captcha',label:'Reply→var'}]},
  wait:{label:'⏱ Wait Secs',fields:[{k:'value',ph:'2',label:'Seconds'}]},
  wait_element:{label:'⌛ Wait Elem',fields:[{k:'selector',ph:'#result',label:'Selector'},{k:'timeout',ph:'10',label:'Timeout(s)'}]},
  wait_url:{label:'⌛ Wait URL Contains',fields:[{k:'value',ph:'/dashboard',label:'URL fragment'},{k:'timeout',ph:'10',label:'Timeout(s)'}]},
  scroll:{label:'↕️ Scroll',fields:[{k:'value',ph:'500 or -300',label:'Pixels'}]},
  reload:{label:'🔄 Reload',fields:[]},
  get_text:{label:'📋 Get Text→Var',fields:[{k:'selector',ph:'#result',label:'Selector'},{k:'var_name',ph:'result',label:'Save as'}]},
  get_attr:{label:'🔗 Get Attribute→Var',fields:[{k:'selector',ph:'a.link',label:'Selector'},{k:'attribute',ph:'href',label:'Attribute'},{k:'var_name',ph:'link',label:'Save as'}]},
  js_eval:{label:'⚡ JS Evaluate→Var',fields:[{k:'value',ph:'document.title',label:'JS expression'},{k:'var_name',ph:'js_result',label:'Save as'}]},
  assert_text:{label:'✅ Assert Text',fields:[{k:'selector',ph:'#status',label:'Selector'},{k:'value',ph:'Success',label:'Expected text'}]},
  key:{label:'⌨️ Key Press',fields:[{k:'value',ph:'Enter Tab Escape',label:'Key'}]},
  select:{label:'📋 Select Option',fields:[{k:'selector',ph:'select#country',label:'Selector'},{k:'value',ph:'India or {v}',label:'Option'}]},
  hover:{label:'🖱 Hover',fields:[{k:'selector',ph:'.menu',label:'Selector'}]},
  drag_drop:{label:'↔️ Drag & Drop',fields:[{k:'selector',ph:'#drag-source',label:'Source'},{k:'target',ph:'#drop-target',label:'Target'}]},
  upload_file:{label:'📁 Upload File',fields:[{k:'selector',ph:'input[type=file]',label:'Selector'},{k:'value',ph:'/tmp/file.pdf or {filepath}',label:'File path'}]},
  iframe_switch:{label:'🖼 Switch to IFrame',fields:[{k:'selector',ph:'iframe#frame1',label:'IFrame selector'}]},
  iframe_main:{label:'🖼 Switch to Main Frame',fields:[]},
  cookie_set:{label:'🍪 Set Cookie',fields:[{k:'name',ph:'session',label:'Cookie name'},{k:'value',ph:'{token}',label:'Cookie value'}]},
  cookie_get:{label:'🍪 Get Cookie→Var',fields:[{k:'name',ph:'auth_token',label:'Cookie name'},{k:'var_name',ph:'cookie_val',label:'Save as'}]},
  set_var:{label:'📦 Set Var',fields:[{k:'var_name',ph:'myvar',label:'Var name'},{k:'value',ph:'fixed or {other}',label:'Value'}]},
  random_var:{label:'🎲 Random from List',fields:[{k:'var_name',ph:'proxy',label:'Var name'},{k:'value',ph:'a,b,c or {LIST}',label:'Comma list'}]},
  raw:{label:'⚡ Raw Python',fields:[{k:'value',ph:'PAGE.evaluate("return document.title")',label:'Python (PAGE=page/BROWSER=driver)'}]}
};
function addBrowserStep(data={}){
  const stype=data.type||'open';const def=BS_TYPES[stype]||BS_TYPES.open;
  const d=document.createElement('div');d.className='bstep-row';
  d.style.cssText='background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:10px;margin-bottom:5px';
  d.innerHTML=`<div style="display:flex;align-items:center;gap:6px;margin-bottom:7px;flex-wrap:wrap">
    <select class="fsel bs-type" onchange="onBsTypeChange(this)" style="flex:1;min-width:150px;font-size:11px">
      ${Object.entries(BS_TYPES).map(([k,v])=>`<option value="${k}" ${k===stype?'selected':''}>${v.label}</option>`).join('')}
    </select>
    <label style="font-size:10px;color:var(--r);display:flex;align-items:center;gap:3px;cursor:pointer"><input type="checkbox" class="bs-stop" ${data.stop_on_error?'checked':''}>stop on err</label>
    <button class="btn bg bsm" onclick="const r=this.closest('.bstep-row');const p=r.previousElementSibling;if(p&&p.classList.contains('bstep-row'))r.parentNode.insertBefore(r,p)" style="padding:3px 7px">↑</button>
    <button class="btn bg bsm" onclick="const r=this.closest('.bstep-row');const n=r.nextElementSibling;if(n&&n.classList.contains('bstep-row'))r.parentNode.insertBefore(n,r)" style="padding:3px 7px">↓</button>
    <button class="btn bd bsm" onclick="this.closest('.bstep-row').remove()" style="padding:3px 7px">✕</button>
  </div><div class="bs-fields" style="display:flex;flex-wrap:wrap;gap:6px">${buildBsFields(def,data)}</div>`;
  g('bsteps-c').appendChild(d);
}
function buildBsFields(def,data={}){
  let h='';
  for(const f of(def.fields||[])){const v=(data[f.k]||'').toString().replace(/"/g,'&quot;');h+=`<div style="display:flex;flex-direction:column;gap:2px;flex:1;min-width:110px"><label style="font-size:9px;color:var(--td);font-family:'Share Tech Mono'">${f.label}</label><input type="text" class="fi bs-f-${f.k}" placeholder="${(f.ph||'').replace(/'/g,'&#39;')}" value="${v}" style="font-size:11px"></div>`;}
  for(const c of(def.checks||[])){h+=`<div style="display:flex;align-items:center;gap:4px;padding-top:14px"><input type="checkbox" class="bs-f-${c.k}" ${data[c.k]?'checked':''}><label style="font-size:10px;color:var(--td)">${c.label}</label></div>`;}
  return h;
}
function onBsTypeChange(sel){const row=sel.closest('.bstep-row');const def=BS_TYPES[sel.value]||{fields:[],checks:[]};row.querySelector('.bs-fields').innerHTML=buildBsFields(def);}
function getBrowserSteps(){
  const steps=[];
  document.querySelectorAll('.bstep-row').forEach(row=>{
    const stype=row.querySelector('.bs-type')?.value||'open';
    const def=BS_TYPES[stype]||{fields:[],checks:[]};
    const s={type:stype,stop_on_error:row.querySelector('.bs-stop')?.checked||false};
    for(const f of(def.fields||[])){const el=row.querySelector('.bs-f-'+f.k);if(el)s[f.k]=el.value||'';}
    for(const c of(def.checks||[])){const el=row.querySelector('.bs-f-'+c.k);if(el)s[c.k]=el.checked||false;}
    steps.push(s);
  });
  return steps;
}

// Automation template presets
const AUTOMATION_TEMPLATES={
  login:[
    {type:'open',value:'{LOGIN_URL}',stop_on_error:true},
    {type:'wait_element',selector:'input[type="text"],input[type="email"],#username',timeout:'10',stop_on_error:true},
    {type:'fill',selector:'input[type="text"],input[type="email"],#username',value:'{username}',stop_on_error:true},
    {type:'fill',selector:'input[type="password"],#password',value:'{password}',stop_on_error:true},
    {type:'click',selector:'button[type="submit"],input[type="submit"],.login-btn,#login',stop_on_error:true},
    {type:'wait_url',value:'/dashboard',timeout:'15',stop_on_error:false},
    {type:'screenshot',caption:'Login result',send_ss:true,delete_after:false}
  ],
  form:[
    {type:'open',value:'{FORM_URL}',stop_on_error:true},
    {type:'wait_element',selector:'form',timeout:'10',stop_on_error:true},
    {type:'fill',selector:'#name,input[name="name"]',value:'{name}',stop_on_error:false},
    {type:'fill',selector:'#email,input[name="email"]',value:'{email}',stop_on_error:false},
    {type:'fill',selector:'#phone,input[name="phone"]',value:'{phone}',stop_on_error:false},
    {type:'click',selector:'button[type="submit"],.submit-btn',stop_on_error:true},
    {type:'wait',value:'2'},
    {type:'screenshot',caption:'Form submitted ✅',send_ss:true,delete_after:false}
  ],
  scrape:[
    {type:'open',value:'{PAGE_URL}',stop_on_error:true},
    {type:'wait_element',selector:'body',timeout:'15',stop_on_error:true},
    {type:'get_text',selector:'h1,.title,.heading',var_name:'title',stop_on_error:false},
    {type:'get_text',selector:'.price,.amount,.value',var_name:'price',stop_on_error:false},
    {type:'get_attr',selector:'a.primary-link,a.main-link',attribute:'href',var_name:'link',stop_on_error:false},
    {type:'js_eval',value:'document.querySelectorAll(".item").length',var_name:'count',stop_on_error:false},
    {type:'screenshot',caption:'📊 Page: {title}\n💰 Price: {price}\n🔗 Link: {link}\n📦 Items: {count}',send_ss:true,delete_after:false}
  ],
  signup:[
    {type:'open',value:'{SIGNUP_URL}',stop_on_error:true},
    {type:'wait_element',selector:'form',timeout:'10',stop_on_error:true},
    {type:'fill',selector:'input[name="name"],#name,#fullname',value:'{name}',stop_on_error:false},
    {type:'fill',selector:'input[name="email"],#email',value:'{email}',stop_on_error:false},
    {type:'fill',selector:'input[name="password"],#password',value:'{password}',stop_on_error:false},
    {type:'fill',selector:'input[name="password_confirm"],#confirm_password',value:'{password}',stop_on_error:false},
    {type:'wait',value:'1'},
    {type:'click',selector:'button[type="submit"],.register-btn,.signup-btn',stop_on_error:true},
    {type:'wait',value:'3'},
    {type:'screenshot',caption:'Signup result',send_ss:true,delete_after:false}
  ]
};
function addAutomationTemplate(name){
  const steps=AUTOMATION_TEMPLATES[name];
  if(!steps)return;
  const c=g('bsteps-c');
  if(c&&c.children.length>0){if(!confirm('Existing steps will be replaced. Continue?'))return;c.innerHTML='';}
  steps.forEach(s=>addBrowserStep(s));
  toast('✅ Template loaded: '+name,'success');
}

// FORWARD LIBRARY JS

const FWD_ICON={message:'💬',sticker:'🌟',photo:'🖼️',video:'🎬',animation:'🎭',voice:'🎙️',audio:'🎵',document:'📄'};
async function refreshForwards(){
  const r=await api('get_forwards');
  const list=g('fwd-list');
  const testSel=g('fwd-test-select');
  const bcSel=g('fwd-bc-select');
  if(testSel)testSel.innerHTML='<option value="">— Library se select karo —</option>';
  if(bcSel)bcSel.innerHTML='<option value="">— Select a forward —</option>';
  if(!r.ok||!r.data||!r.data.length){
    if(list)list.innerHTML='<div style="color:var(--td);font-size:12px;text-align:center;grid-column:1/-1;padding:20px">📭 Library empty hai.<br><small>Bot ko koi message forward karo (owner account se).</small></div>';
    return;
  }
  if(list)list.innerHTML='';
  r.data.forEach(fwd=>{
    const icon=FWD_ICON[fwd.preview_type]||'💬';
    const valJson=JSON.stringify({fc:fwd.from_chat_id,mi:fwd.message_id});
    const card=document.createElement('div');
    card.style.cssText='background:var(--s2);border:1px solid rgba(255,159,10,.3);border-radius:8px;padding:10px;';
    card.innerHTML=`

      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <span style="background:rgba(255,159,10,.15);color:var(--o);border-radius:4px;font-size:9px;padding:2px 6px;font-weight:bold">${icon} ${(fwd.preview_type||'message').toUpperCase()}</span>
        <button class="btn bd bsm" onclick="deleteForward('${fwd.id}')" style="padding:2px 7px;font-size:11px">🗑</button>
      </div>

      <div style="font-size:13px;font-weight:bold;margin-bottom:6px;color:var(--t)">${fwd.label||'Forward'}</div>

      <div style="font-size:10px;color:var(--td);font-family:monospace;margin-bottom:3px">📡 Chat: <span style="color:var(--c)">${fwd.from_chat_id}</span></div>

      <div style="font-size:10px;color:var(--td);font-family:monospace;margin-bottom:6px">📨 Msg ID: <span style="color:var(--c)">${fwd.message_id}</span></div>

      <div style="font-size:10px;color:var(--td);margin-bottom:8px">Saved: ${fwd.saved_at||'-'}</div>

      <div style="display:flex;gap:5px">
        <button class="btn bg bsm" style="flex:1;font-size:10px" onclick="navigator.clipboard.writeText('${fwd.from_chat_id}');toast('Chat ID copied!','success')">📋 Chat ID</button>
        <button class="btn bg bsm" style="flex:1;font-size:10px" onclick="navigator.clipboard.writeText('${fwd.message_id}');toast('Msg ID copied!','success')">📋 Msg ID</button>
        <button class="btn bw bsm" style="font-size:10px" onclick="renameForwardPrompt('${fwd.id}','${(fwd.label||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'")}')">✏️</button>
      </div>
    `;
    if(list)list.appendChild(card);
    if(testSel){const o=document.createElement('option');o.value=valJson;o.textContent=icon+' '+fwd.label+' (msg#'+fwd.message_id+')';testSel.appendChild(o);}
    if(bcSel){const o=document.createElement('option');o.value=valJson;o.textContent=icon+' '+fwd.label;bcSel.appendChild(o);}
  });
}
async function addForwardManual(){
  const fc=g('fwd-from-chat')?.value.trim();
  const mi=g('fwd-msg-id')?.value.trim();
  const lbl=g('fwd-label')?.value.trim();
  const ft=g('fwd-type')?.value||'message';
  if(!fc||!mi)return toast('from_chat_id and message_id are required','error');
  const r=await api('save_forward_manual',{from_chat_id:fc,message_id:mi,label:lbl,preview_type:ft});
  if(r.ok){
    toast(r.added?'✅ Forward add ho gaya!':'ℹ️ Already in library','success');
    g('fwd-from-chat').value='';g('fwd-msg-id').value='';g('fwd-label').value='';
    refreshForwards();
  }else toast('Error: '+(r.error||'Failed'),'error');
}
async function deleteForward(id){
  if(!confirm('Delete this forward from the library?'))return;
  const r=await api('delete_forward',{id});
  if(r.ok){toast('Deleted!','success');refreshForwards();}else toast('Error','error');
}
async function renameForwardPrompt(id,cur){
  const nl=prompt('New name:',cur);
  if(!nl)return;
  const r=await api('rename_forward',{id,label:nl});
  if(r.ok){toast('Renamed!','success');refreshForwards();}
}
async function testSendForward(){
  const chatId=g('fwd-test-chatid')?.value.trim();
  const val=g('fwd-test-select')?.value;
  if(!chatId)return toast('Apna Chat ID daalo','error');
  if(!val)return toast('Select a forward','error');
  let d;try{d=JSON.parse(val);}catch{return toast('Selection error','error');}
  toast('Forwarding...','info');
  const r=await api('test_forward',{chat_id:chatId,from_chat_id:d.fc,message_id:d.mi});
  if(r.ok)toast('✅ Forward ho gaya! Premium content bhi preserve hai 🎉','success');
  else toast('❌ Failed: '+(r.error||'Bot us chat ka member hai?'),'error');
}
async function broadcastForward(){
  const val=g('fwd-bc-select')?.value;
  if(!val)return toast('Please select a forward first','error');
  let d;try{d=JSON.parse(val);}catch{return toast('Selection error','error');}
  if(!confirm('Forward this message to all users?'))return;
  toast('Broadcasting...','info');
  const r=await api('broadcast_forward',{from_chat_id:d.fc,message_id:d.mi});
  if(r.ok)toast('✅ Done! Sent: '+r.sent+', Failed: '+r.failed,'success');
  else toast('❌ Broadcast failed','error');
}
function showForwardHelp(){
  alert('📖 Forward Library — Kaise Kaam Karta Hai\n\n'+
    '✅ NORMAL BOT BHI KAR SAKTA HAI!\n'+
    'Bot message khud generate nahi karta — sirf forward karta hai.\n'+
    'Isliye Premium stickers, animated emoji sab preserve rehta hai.\n\n'+
    '1️⃣ AUTO-CAPTURE (Recommended):\n'+
    '   → Telegram mein koi bhi message dhundho\n'+
    '     (Premium sticker, special emoji, koi bhi content)\n'+
    '   → FORWARD that message to your BOT\n'+
    '   → ONLY the account with OWNER ID can capture\n'+
    '   → Bot reply karega: ✅ Forward saved!\n\n'+
    '2️⃣ MANUAL ADD:\n'+
    '   → Copy the message link from Telegram Web\n'+
    '   → Example: t.me/c/1234567890/42\n'+
    '   → Chat ID: -1001234567890  |  Msg ID: 42\n\n'+
    '3️⃣ TEST & BROADCAST:\n'+
    '   → Test: Try on your own ID first\n'+
    '   → Broadcast: Forwarded to all users\n\n'+
    '⚠️ IMPORTANT:\n'+
    '   Bot ko us channel/group ka MEMBER hona chahiye\n'+
    '   from where the message is being forwarded!');
}
window.onload=()=>{
  window.addEventListener('orientationchange',()=>setTimeout(()=>{document.body.style.background='#030712';document.body.style.color='#e6edf3';},100));

  // Auto-reconnect: re-register webhook every 8 minutes to keep bot online

  // This prevents hosting providers from dropping the webhook

  setInterval(async()=>{
    const r=await api('bot_info');
    if(r.ok&&r.active_name){

      // Only re-register if webhook is missing or broken

      if(!r.webhook?.url){await api('start_bot');console.log('Auto-reconnected webhook');}
    }
  },8*60*1000);
};

// STICKER LIBRARY JS

async function saveOwnerIdFromSticker(){
  const oid=g('stk-owner-id')?.value.trim();
  if(!oid)return toast('Owner ID daalo pehle','error');
  const r=await api('save_settings',{settings:{adminId:oid}});
  if(r.ok){toast('✅ Owner ID saved!','success');}
  else toast('Error saving','error');
}
async function loadOwnerIdForSticker(){
  const r=await api('get_settings');
  if(r.ok&&r.data&&g('stk-owner-id')){
    g('stk-owner-id').value=r.data.settings?.adminId||'';
  }
}
async function refreshStickers(){
  loadOwnerIdForSticker();
  const r=await api('get_stickers');
  const list=g('stk-list');
  const testSel=g('stk-test-select');
  const bcSel=g('stk-bc-select');
  if(testSel){testSel.innerHTML='<option value="">— Library se select karo —</option>';}
  if(bcSel){bcSel.innerHTML='<option value="">— Select a sticker —</option>';}
  if(!r.ok||!r.data||r.data.length===0){
    if(list)list.innerHTML='<div style="color:var(--td);font-size:12px;text-align:center;grid-column:1/-1;padding:20px">📭 Library empty hai.<br><small>Bot ko koi sticker forward karo (owner account se).</small></div>';
    return;
  }
  if(list)list.innerHTML='';
  r.data.forEach(stk=>{
    const badge=stk.is_premium
      ?'<span style="background:#f9c74f;color:#000;border-radius:4px;font-size:9px;padding:2px 5px;font-weight:bold">⭐ PREMIUM</span>'
      :stk.is_animated
      ?'<span style="background:#4cc9f0;color:#000;border-radius:4px;font-size:9px;padding:2px 5px">🎬 ANIMATED</span>'
      :'<span style="background:#adb5bd;color:#000;border-radius:4px;font-size:9px;padding:2px 5px">📌 STATIC</span>';
    const card=document.createElement('div');
    card.style.cssText='background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:10px;';
    card.innerHTML=`

      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        ${badge}
        <button class="btn bd bsm" onclick="deleteSticker('${stk.id}')" style="padding:2px 7px;font-size:11px">🗑</button>
      </div>

      <div style="font-size:13px;font-weight:bold;margin-bottom:4px;color:var(--t)">${stk.label||'Sticker'}</div>

      <div style="font-size:9px;color:var(--td);word-break:break-all;margin-bottom:6px;font-family:monospace">${stk.file_id}</div>

      <div style="font-size:10px;color:var(--td);margin-bottom:6px">Saved: ${stk.saved_at||'-'}</div>

      <div style="display:flex;gap:5px">
        <button class="btn bg bsm" style="flex:1;font-size:11px" onclick="navigator.clipboard.writeText('${stk.file_id}');toast('Copied!','success')">📋 Copy ID</button>
        <button class="btn bw bsm" style="flex:1;font-size:11px" onclick="renameStickerPrompt('${stk.id}','${(stk.label||'').replace(/'/g,"\\'")}')">✏️ Rename</button>
      </div>
    `;
    if(list)list.appendChild(card);
    if(testSel){const o=document.createElement('option');o.value=stk.file_id;o.textContent=(stk.is_premium?'⭐ ':stk.is_animated?'🎬 ':'📌 ')+stk.label+' ('+stk.file_id.substr(0,18)+'...)';testSel.appendChild(o);}
    if(bcSel){const o=document.createElement('option');o.value=stk.file_id;o.textContent=(stk.is_premium?'⭐ ':stk.is_animated?'🎬 ':'📌 ')+stk.label;bcSel.appendChild(o);}
  });
}
async function addStickerManual(){
  const fid=g('stk-fileid')?.value.trim();
  const label=g('stk-label')?.value.trim();
  if(!fid)return toast('file_id daalo pehle','error');
  const r=await api('save_sticker_manual',{file_id:fid,label:label||'Manual Sticker'});
  if(r.ok){toast(r.added?'✅ Sticker add ho gaya!':'ℹ️ Already in library','success');if(g('stk-fileid'))g('stk-fileid').value='';if(g('stk-label'))g('stk-label').value='';refreshStickers();}
  else toast('Error: '+(r.error||'Failed'),'error');
}
async function deleteSticker(id){
  if(!confirm('Delete this sticker from the library?'))return;
  const r=await api('delete_sticker',{id});
  if(r.ok){toast('Deleted!','success');refreshStickers();}else toast('Error deleting','error');
}
async function renameStickerPrompt(id,currentLabel){
  const newLabel=prompt('New name:',currentLabel);
  if(!newLabel)return;
  const r=await api('rename_sticker',{id,label:newLabel});
  if(r.ok){toast('Renamed!','success');refreshStickers();}
}
async function testSendSticker(){
  const chatId=g('stk-test-chatid')?.value.trim();
  const fileId=g('stk-test-select')?.value;
  if(!chatId)return toast('Chat ID daalo','error');
  if(!fileId)return toast('Select a sticker','error');
  toast('Sending...','info');
  const r=await api('send_sticker',{chat_id:chatId,file_id:fileId});
  if(r.ok)toast('✅ Sticker bhej diya!','success');else toast('❌ Failed','error');
}
async function broadcastSticker(){
  const fileId=g('stk-bc-select')?.value;
  if(!fileId)return toast('Pehle sticker select karo','error');
  if(!confirm('Send this sticker to all users?'))return;
  toast('Broadcasting...','info');
  const r=await api('broadcast_sticker',{file_id:fileId});
  if(r.ok)toast('✅ Done! Sent: '+r.sent+', Failed: '+r.failed,'success');else toast('❌ Broadcast failed','error');
}
function showStickerHelp(){
  alert('📖 Premium Sticker Add Karne Ka Tarika:\n\n'+
    '1️⃣ AUTO-CAPTURE MODE:\n'+
    '   → FORWARD any Premium sticker to your bot\n'+
    '   → Only the account with the Owner ID can capture\n'+
    '   → Bot reply karega: ✅ Sticker saved!\n\n'+
    '2️⃣ MANUAL MODE:\n'+
    '   → Send the sticker to bot → copy file_id from reply\n'+
    '   → Paste it in the "Manually Add" box below\n\n'+
    '3️⃣ PAGE MEIN USE:\n'+
    '   → Flow Builder → Page edit karo\n'+
    '   → "Paste file_id in the "Sticker ID" field\n'+
    '   → Bot will auto-send the sticker when the page is triggered');
}
async function pickStickerForPage(){
  const r=await api('get_stickers');
  if(!r.ok||!r.data||!r.data.length){toast('Library is empty! Please add a sticker first.','error');return;}
  const opts=r.data.map((s,i)=>`${i+1}. ${s.is_premium?'⭐':s.is_animated?'🎬':'📌'} ${s.label}`).join('\n');
  const choice=prompt('Select a sticker (number daalo):\n\n'+opts);
  if(!choice)return;
  const idx=parseInt(choice)-1;
  if(idx>=0&&idx<r.data.length){if(g('pb-sticker-id'))g('pb-sticker-id').value=r.data[idx].file_id;toast('✅ Sticker select ho gaya!','success');}
  else toast('Invalid choice','error');
}

// PREMIUM EMOJI LIBRARY JS — REDESIGNED

let _pemjAll=[];
let _pemjSelected=new Set(); // for library bulk-delete
function togglePemjAccordion(id){
  const el=g('pemj-acc-'+id);
  const arrow=g('pemj-acc-'+id+'-arrow');
  if(!el)return;
  const open=el.style.display!=='none';
  el.style.display=open?'none':'block';
  if(arrow)arrow.style.transform=open?'rotate(0deg)':'rotate(180deg)';
}

function _pemjUpdateSelUI(){
  const n=_pemjSelected.size;
  const cnt=g('pemj-sel-count');
  const btn=g('pemj-bulk-del-btn');
  if(cnt){cnt.style.display=n>0?'block':'none';cnt.textContent=`✅ ${n} emoji${n>1?'s':''} selected`;}
  if(btn)btn.style.display=n>0?'inline-flex':'none';
}
function pemjSelectAll(){
  _pemjSelected.clear();
  (_pemjAll).forEach(e=>_pemjSelected.add(e.id));
  _renderPemjGrid(_pemjAll);
}
function pemjClearSel(){
  _pemjSelected.clear();
  _renderPemjGrid(_pemjAll);
}
async function pemjBulkDelete(){
  if(!_pemjSelected.size)return toast('Please select an emoji first!','error');
  const n=_pemjSelected.size;
  if(!confirm(`${n} emoji${n>1?'s':''} delete karne hain library se?`))return;
  const ids=[..._pemjSelected];
  const r=await api('delete_prem_emoji',{ids});
  if(r.ok){
    toast(`🗑 ${r.deleted||n} emoji${n>1?'s':''} delete ho gaye!`,'success');
    _pemjSelected.clear();
    refreshPremEmojis();

    // Sync DMS emoji grid too

    dmsLoadEmojis();
  }else toast('❌ Delete failed: '+(r.error||''),'error');
}
async function refreshPremEmojis(){
  const list=g('pemj-list');
  if(list)list.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:16px">⏳ Loading...</div>';
  const r=await api('get_prem_emojis');
  const testSel=g('pemj-test-select');
  const bcSel=g('pemj-bc-select');
  if(testSel)testSel.innerHTML='<option value="">— Select an emoji —</option>';
  if(bcSel)bcSel.innerHTML='<option value="">— Select an emoji —</option>';
  if(!r.ok||!r.data||r.data.length===0){
    _pemjAll=[];
    if(list)list.innerHTML='<div style="color:var(--td);font-size:12px;text-align:center;grid-column:1/-1;padding:20px">📭 Koi emoji nahi.<br><small style="color:var(--tf)">Upar Step 1 se add karo!</small></div>';
    return;
  }
  _pemjAll=r.data;
  _pemjSelected.clear();
  _pemjUpdateSelUI();
  _renderPemjGrid(r.data);
  r.data.forEach(emj=>{
    const val=JSON.stringify({emoji_id:emj.emoji_id,fallback:emj.fallback});
    if(testSel){const o=document.createElement('option');o.value=val;o.textContent=emj.fallback+' '+emj.label;testSel.appendChild(o);}
    if(bcSel){const o=document.createElement('option');o.value=val;o.textContent=emj.fallback+' '+emj.label;bcSel.appendChild(o);}
  });
}
function _renderPemjGrid(data){
  const list=g('pemj-list');if(!list)return;
  if(!data.length){list.innerHTML='<div style="color:var(--td);font-size:11px;text-align:center;grid-column:1/-1;padding:12px">🔍 Koi match nahi</div>';return;}
  list.innerHTML='';
  data.forEach(emj=>{
    const dynKey='emoji_'+emj.label.toLowerCase().replace(/[^a-z0-9]/g,'_');
    const isSel=_pemjSelected.has(emj.id);
    const card=document.createElement('div');
    card.dataset.pemjId=emj.id;
    card.style.cssText=`background:${isSel?'rgba(191,90,242,.22)':'var(--s2)'};border:${isSel?'2px solid rgba(191,90,242,.9)':'1px solid rgba(191,90,242,.25)'};border-radius:10px;padding:11px;display:flex;flex-direction:column;gap:6px;transition:border-color .15s;cursor:pointer;position:relative;`;
    card.onmouseenter=()=>{if(!_pemjSelected.has(emj.id))card.style.borderColor='rgba(191,90,242,.6)';};
    card.onmouseleave=()=>{if(!_pemjSelected.has(emj.id))card.style.borderColor='rgba(191,90,242,.25)';};
    card.onclick=(ev)=>{

      // If clicking action buttons, don't toggle selection

      if(ev.target.closest('button'))return;
      _pemjToggle(emj.id,card);
    };
    card.innerHTML=`

      <div style="position:absolute;top:6px;right:6px;width:15px;height:15px;border-radius:50%;border:2px solid rgba(191,90,242,.6);background:${isSel?'#bf5af2':'transparent'};display:flex;align-items:center;justify-content:center;font-size:9px;transition:all .15s;pointer-events:none">${isSel?'✓':''}</div>

      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:28px;min-width:36px;text-align:center">${emj.fallback||'⭐'}</span>

        <div style="flex:1;overflow:hidden">

          <div style="font-size:13px;font-weight:700;color:var(--t);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${emj.label}</div>

          <div style="font-size:9px;color:var(--td);font-family:monospace">${emj.emoji_id}</div>
        </div>
        <button class="btn bd bsm" onclick="deletePremEmoji('${emj.id}')" style="padding:3px 7px;font-size:10px;flex-shrink:0" title="Delete">🗑</button>
      </div>
      <button onclick="navigator.clipboard.writeText('{${dynKey}}');toast('✅ {${dynKey}} copied!','success')" style="width:100%;background:rgba(0,245,255,.08);border:1px solid rgba(0,245,255,.3);color:var(--c);border-radius:6px;padding:6px;font-size:11px;cursor:pointer;font-family:'Share Tech Mono';font-weight:700" title="Click to copy placeholder">
        📋 {${dynKey}}
      </button>

      <div style="display:flex;gap:5px">
        <button class="btn bg bsm" style="flex:1;font-size:10px" onclick="quickInsertFromLib('${emj.emoji_id}','${(emj.fallback||'⭐').replace(/'/g,"\\'")}','${dynKey}')" title="Insert into active textarea">⚡ Insert</button>
        <button class="btn bw bsm" style="flex:1;font-size:10px" onclick="renamePremEmojiPrompt('${emj.id}','${(emj.label||'').replace(/'/g,"\\'")}')">✏️ Rename</button>
      </div>`;
    list.appendChild(card);
  });
  _pemjUpdateSelUI();
}
function _pemjToggle(id,card){
  if(_pemjSelected.has(id)){
    _pemjSelected.delete(id);
    card.style.background='var(--s2)';
    card.style.border='1px solid rgba(191,90,242,.25)';
    const dot=card.querySelector('div[style*="position:absolute"]');
    if(dot){dot.style.background='transparent';dot.textContent='';}
  }else{
    _pemjSelected.add(id);
    card.style.background='rgba(191,90,242,.22)';
    card.style.border='2px solid rgba(191,90,242,.9)';
    const dot=card.querySelector('div[style*="position:absolute"]');
    if(dot){dot.style.background='#bf5af2';dot.textContent='✓';}
  }
  _pemjUpdateSelUI();
}
function filterPemjLibrary(){
  const q=(g('pemj-search')?.value||'').toLowerCase().trim();
  _renderPemjGrid(q?_pemjAll.filter(e=>(e.label||'').toLowerCase().includes(q)||(e.fallback||'').includes(q)):_pemjAll);
}

let _dmsEmojiLib=[];
let _dmsEmojiSelected=new Set(); // Set of emoji_ids
function _dmsUpdateEmojiCount(){
  const n=_dmsEmojiSelected.size;
  const cnt=g('dms-emj-count');
  if(cnt)cnt.textContent=n===0?'0 emoji selected':`✅ ${n} emoji${n>1?'s':''} selected`;
}
function _dmsRenderEmojiGrid(data){
  const grid=g('dms-emj-grid');if(!grid)return;
  if(!data.length){
    grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">📭 Koi emoji nahi.<br><small>Premium Emoji Library mein pehle add karo.</small></div>';
    return;
  }
  grid.innerHTML='';
  data.forEach(emj=>{
    const isSel=_dmsEmojiSelected.has(emj.emoji_id);
    const card=document.createElement('div');
    card.style.cssText=`position:relative;background:${isSel?'rgba(191,90,242,.28)':'rgba(191,90,242,.07)'};border:2px solid ${isSel?'rgba(191,90,242,.9)':'rgba(191,90,242,.22)'};border-radius:10px;padding:10px 6px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:5px;transition:all .15s;user-select:none;`;
    card.innerHTML=`

      <div style="position:absolute;top:5px;right:5px;width:15px;height:15px;border-radius:50%;border:2px solid rgba(191,90,242,.6);background:${isSel?'#bf5af2':'transparent'};display:flex;align-items:center;justify-content:center;font-size:9px;transition:all .15s">${isSel?'✓':''}</div>
      <span style="font-size:26px;line-height:1">${emj.fallback||'⭐'}</span>
      <span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono';word-break:break-all;text-align:center;line-height:1.3;max-width:78px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${emj.label}</span>`;
    card.onmouseenter=()=>{if(!_dmsEmojiSelected.has(emj.emoji_id))card.style.background='rgba(191,90,242,.16)';};
    card.onmouseleave=()=>{if(!_dmsEmojiSelected.has(emj.emoji_id))card.style.background='rgba(191,90,242,.07)';};
    card.onclick=()=>_dmsToggleEmoji(emj.emoji_id,card);
    grid.appendChild(card);
  });
  _dmsUpdateEmojiCount();
}
function _dmsToggleEmoji(emojiId,card){
  if(_dmsEmojiSelected.has(emojiId)){
    _dmsEmojiSelected.delete(emojiId);
    card.style.background='rgba(191,90,242,.07)';
    card.style.borderColor='rgba(191,90,242,.22)';
    const dot=card.querySelector('div');
    if(dot){dot.style.background='transparent';dot.textContent='';}
  }else{
    _dmsEmojiSelected.add(emojiId);
    card.style.background='rgba(191,90,242,.28)';
    card.style.borderColor='rgba(191,90,242,.9)';
    const dot=card.querySelector('div');
    if(dot){dot.style.background='#bf5af2';dot.textContent='✓';}
  }
  _dmsUpdateEmojiCount();
}
function dmsSelectAllEmojis(){
  _dmsEmojiSelected.clear();
  _dmsEmojiLib.forEach(e=>_dmsEmojiSelected.add(e.emoji_id));
  _dmsRenderEmojiGrid(_dmsEmojiLib);
}
function dmsClearEmojis(){
  _dmsEmojiSelected.clear();
  _dmsRenderEmojiGrid(_dmsEmojiLib);
}
async function dmsLoadEmojis(){
  const grid=g('dms-emj-grid');
  if(grid)grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:16px">⏳ Loading emojis...</div>';
  const r=await api('get_prem_emojis');
  if(!r.ok||!r.data||!r.data.length){_dmsEmojiLib=[];_dmsRenderEmojiGrid([]);return;}
  _dmsEmojiLib=r.data;
  _dmsRenderEmojiGrid(r.data);
}

// ⚡ Quick Insert — inserts into whatever textarea is currently focused in the page builder

function quickInsertFromLib(emojiId, fallback, dynKey){

  // Try to find active / last focused textarea in builder modal

  const ta = document.activeElement?.tagName==='TEXTAREA' ? document.activeElement
           : g('pb-text') || document.querySelector('.fta');
  if(!ta){

    // Just copy placeholder if no textarea focused

    navigator.clipboard.writeText('{'+dynKey+'}');
    toast('📋 {'+dynKey+'} copied! — Kisi textarea mein paste karo','info');
    return;
  }
  const txt=`<tg-emoji emoji-id="${emojiId}">${fallback}</tg-emoji>`;
  const s=ta.selectionStart,e=ta.selectionEnd;
  ta.value=ta.value.substring(0,s)+txt+ta.value.substring(e);
  ta.focus();ta.setSelectionRange(s+txt.length,s+txt.length);
  toast('✅ '+fallback+' inserted!','success');
}
async function testSendPremEmoji(){
  const chatId=g('pemj-test-chatid')?.value.trim();
  const sel=g('pemj-test-select')?.value;
  const caption=g('pemj-test-caption')?.value.trim();
  const res=g('pemj-test-result');
  if(!chatId)return toast('Chat ID daalo','error');
  if(!sel)return toast('Select an emoji','error');
  let d;try{d=JSON.parse(sel);}catch{return toast('Invalid selection','error');}
  toast('Sending...','info');
  const r=await api('send_prem_emoji',{chat_id:chatId,emoji_id:d.emoji_id,fallback:d.fallback,caption});
  if(res){
    res.style.display='block';
    if(r.ok){res.style.cssText+='background:rgba(57,255,20,.08);border:1px solid rgba(57,255,20,.3);color:var(--g)';res.textContent='✅ Emoji sent!';}
    else{res.style.cssText+='background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3);color:var(--r)';res.textContent='❌ Failed: '+(r.error||'Unknown error');}
  }
  if(r.ok)toast('✅ Emoji bhej diya!','success');else toast('❌ Failed: '+(r.error||''),'error');
}
async function broadcastPremEmoji(){
  const sel=g('pemj-bc-select')?.value;
  const caption=g('pemj-bc-caption')?.value.trim();
  const res=g('pemj-bc-result');
  if(!sel)return toast('Pehle emoji select karo','error');
  let d;try{d=JSON.parse(sel);}catch{return toast('Invalid selection','error');}
  if(!confirm('Send this emoji to all users?'))return;
  toast('Broadcasting...','info');
  if(res){res.style.display='block';res.textContent='⏳ Broadcasting...';res.style.cssText+='background:rgba(0,245,255,.06);border:1px solid rgba(0,245,255,.2);color:var(--c)';}
  const r=await api('broadcast_prem_emoji',{emoji_id:d.emoji_id,fallback:d.fallback,caption});
  if(res){
    if(r.ok){res.style.cssText+='background:rgba(57,255,20,.08);border:1px solid rgba(57,255,20,.3);color:var(--g)';res.textContent='✅ Done! Sent: '+r.sent+' | Failed: '+r.failed;}
    else{res.style.cssText+='background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3);color:var(--r)';res.textContent='❌ Failed: '+(r.error||'');}
  }
  if(r.ok)toast('✅ Done! Sent: '+r.sent+', Failed: '+r.failed,'success');
  else toast('❌ Broadcast failed','error');
}
async function addPremEmojiManual(){
  const eid=g('pemj-id')?.value.trim();
  const fb=g('pemj-fb')?.value.trim()||'⭐';
  const lbl=g('pemj-label')?.value.trim();
  if(!eid)return toast('Emoji ID daalo pehle','error');
  const r=await api('save_prem_emoji_manual',{emoji_id:eid,fallback:fb,label:lbl||fb+' Emoji'});
  if(r.ok){
    toast(r.added?'✅ Emoji add ho gaya!':'ℹ️ Already in library','success');
    if(g('pemj-id'))g('pemj-id').value='';
    if(g('pemj-fb'))g('pemj-fb').value='';
    if(g('pemj-label'))g('pemj-label').value='';
    refreshPremEmojis();
  }else toast('Error: '+(r.error||'Failed'),'error');
}
async function deletePremEmoji(id){
  if(!confirm('Delete karo?'))return;
  const r=await api('delete_prem_emoji',{ids:[id]});
  if(r.ok){toast('Deleted!','success');refreshPremEmojis();dmsLoadEmojis();}
  else toast('Error deleting','error');
}
async function renamePremEmojiPrompt(id,currentLabel){
  const newLabel=prompt('New label:',currentLabel);
  if(!newLabel)return;
  const r=await api('rename_prem_emoji',{id,label:newLabel});
  if(r.ok){toast('Renamed!','success');refreshPremEmojis();}
}
function showPremEmojiHelp(){}

// WELCOME MESSAGE JS

let _wmData={enabled:false,text:'',media:'',buttons:[]};
async function loadWelcome(){
  const r=await api('get_welcome_message');
  if(!r.ok)return;
  _wmData=r.data||{enabled:false,text:'',media:'',buttons:[]};
  _applyWmUI();
}
function _applyWmUI(){
  const en=!!_wmData.enabled;
  const btn=g('wm-toggle-btn'),lbl=g('wm-status-label');
  if(btn){btn.textContent=en?'Disable':'Enable';btn.className='btn bsm '+(en?'bd':'bsu');}
  if(lbl){lbl.textContent=en?'🟢 ON':'⭕ OFF';lbl.style.color=en?'var(--g)':'var(--td)';}
  if(g('wm-text'))g('wm-text').value=_wmData.text||'';
  if(g('wm-media'))g('wm-media').value=_wmData.media||'';
  renderWmButtons(_wmData.buttons||[]);
}
function renderWmButtons(btns){
  const c=g('wm-buttons');if(!c)return;c.innerHTML='';
  (btns||[]).forEach((b,i)=>{
    const row=document.createElement('div');row.className='fj-btn-row';
    row.innerHTML=`<input type="text" class="fi" placeholder="Button Text" value="${(b.text||'').replace(/"/g,'&quot;')}" style="flex:2;min-width:100px" oninput="_wmData.buttons[${i}].text=this.value">
    <input type="text" class="fi" placeholder="https://url..." value="${(b.url||'').replace(/"/g,'&quot;')}" style="flex:3;min-width:120px" oninput="_wmData.buttons[${i}].url=this.value">
    <button class="btn bd bsm" onclick="removeWmButton(${i})">✕</button>`;
    c.appendChild(row);
  });
}
function addWmButton(){_wmData.buttons=_wmData.buttons||[];_wmData.buttons.push({text:'',url:''});renderWmButtons(_wmData.buttons);}
function removeWmButton(i){_wmData.buttons.splice(i,1);renderWmButtons(_wmData.buttons);}
async function toggleWelcome(){
  const newEnabled=!(_wmData.enabled||false);
  const payload={
    enabled: newEnabled,
    text: g('wm-text')?.value||_wmData.text||'👋 Welcome {tg_mention}!',
    media: g('wm-media')?.value||_wmData.media||'',
    buttons: _wmData.buttons||[]
  };
  console.log('[WM Toggle] sending enabled='+newEnabled, payload);
  const r=await api('save_welcome_message',{wm:payload});
  console.log('[WM Toggle] response:', r);
  if(r.ok){
    _wmData={...payload};
    _applyWmUI();
    toast(newEnabled?'✅ Welcome Message Enabled!':'ℹ️ Welcome Message Disabled','success');
  }else{
    toast('❌ Save failed: '+(r.error||JSON.stringify(r)),'error');
  }
}
async function saveWelcome(){
  const payload={
    enabled: _wmData.enabled||false,
    text: g('wm-text')?.value||'',
    media: g('wm-media')?.value||'',
    buttons: _wmData.buttons||[]
  };
  const r=await api('save_welcome_message',{wm:payload});
  if(r.ok){_wmData={...payload};toast('✅ Welcome settings saved!','success');_applyWmUI();}
  else toast('❌ Save failed: '+(r.error||''),'error');
}

// USER TAGGER JS

let _utData={enabled:false,trigger:'@all',message:'📢 Tagging everyone:',batch_size:5,delay:1};
async function loadTagger(){
  const r=await api('get_user_tagger');
  if(!r.ok)return;
  _utData=r.data||_utData;
  _applyUtUI();
  loadTaggerStats();
}

let _utEmojiLib=[];
let _utMsgCursor={start:0,end:0}; // remember last cursor position in ut-message
function _utSaveCursor(){
  const ta=g('ut-message');if(!ta)return;
  _utMsgCursor={start:ta.selectionStart,end:ta.selectionEnd};
}
async function utLoadEmojiPicker(){
  const grid=g('ut-emoji-grid');
  if(grid)grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:10px">⏳ Loading...</div>';
  const r=await api('get_prem_emojis');
  if(!r.ok||!r.data||!r.data.length){
    _utEmojiLib=[];
    if(grid)grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:12px">📭 Koi emoji nahi.<br><small>Premium Emoji Library mein pehle add karo.</small></div>';
    return;
  }
  _utEmojiLib=r.data;
  _utRenderEmojiGrid(r.data);

  // attach cursor saver to textarea

  const ta=g('ut-message');
  if(ta){
    ta.addEventListener('blur',_utSaveCursor,{passive:true});
    ta.addEventListener('keyup',_utSaveCursor,{passive:true});
    ta.addEventListener('click',_utSaveCursor,{passive:true});
  }
}
function _utRenderEmojiGrid(data){
  const grid=g('ut-emoji-grid');if(!grid)return;
  if(!data.length){
    grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:12px">📭 Koi emoji nahi.</div>';
    return;
  }
  grid.innerHTML='';
  data.forEach(emj=>{
    const card=document.createElement('div');
    card.style.cssText='background:rgba(191,90,242,.07);border:1.5px solid rgba(191,90,242,.22);border-radius:8px;padding:8px 4px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:4px;transition:all .15s;user-select:none;';
    card.innerHTML=`<span style="font-size:22px;line-height:1">${emj.fallback||'⭐'}</span><span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono';text-align:center;word-break:break-all;max-width:64px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${emj.label}</span>`;
    card.onmouseenter=()=>{card.style.background='rgba(191,90,242,.22)';card.style.borderColor='rgba(191,90,242,.7)';};
    card.onmouseleave=()=>{card.style.background='rgba(191,90,242,.07)';card.style.borderColor='rgba(191,90,242,.22)';};
    card.onclick=()=>utInsertEmoji(emj.emoji_id,emj.fallback);
    grid.appendChild(card);
  });
}
function utInsertEmoji(emojiId,fallback){
  const ta=g('ut-message');if(!ta)return;
  const ins=`<tg-emoji emoji-id="${emojiId}">${fallback}</tg-emoji>`;
  const s=_utMsgCursor.start,e=_utMsgCursor.end;
  const cur=ta.value;
  ta.value=cur.substring(0,s)+ins+cur.substring(e);
  const newPos=s+ins.length;
  ta.focus();ta.setSelectionRange(newPos,newPos);
  _utMsgCursor={start:newPos,end:newPos};

  // flash card feedback

  toast('✨ Emoji inserted!','success');
}
function _applyUtUI(){
  const en=!!_utData.enabled;
  const btn=g('ut-toggle-btn'),lbl=g('ut-status-label');
  if(btn){btn.textContent=en?'Disable':'Enable';btn.className='btn bsm '+(en?'bd':'bsu');}
  if(lbl){lbl.textContent=en?'🟢 ON':'⭕ OFF';lbl.style.color=en?'var(--o)':'var(--td)';}
  if(g('ut-trigger'))g('ut-trigger').value=_utData.trigger||'@all';
  if(g('ut-batch'))g('ut-batch').value=_utData.batch_size||5;
  if(g('ut-delay'))g('ut-delay').value=_utData.delay??1;
  if(g('ut-message'))g('ut-message').value=_utData.message||'';
}
async function loadTaggerStats(){
  const con=g('ut-groups-container');
  if(con)con.innerHTML='<div style="text-align:center;color:var(--td);font-size:12px;padding:12px">⏳ Loading...</div>';
  const r=await api('get_group_members');
  if(!r.ok||!r.data||!r.data.length){
    if(con)con.innerHTML='<div style="text-align:center;color:var(--td);font-size:12px;padding:16px">No groups tracked yet. Members are recorded as they chat.</div>';
    return;
  }
  const groups=r.data||[];

  // Fetch per-group detail in parallel

  const details=await Promise.all(groups.map(gr=>api('get_group_members',{chat_id:gr.chat_id})));
  let html='<table style="width:100%;border-collapse:collapse;font-size:11px;font-family:\'Share Tech Mono\'">';
  html+='<thead><tr style="border-bottom:1px solid rgba(255,255,255,.1)">'
    +'<th style="text-align:left;padding:6px 4px;color:var(--td)">Group ID</th>'
    +'<th style="text-align:center;padding:6px 4px;color:var(--o)">👥 Total</th>'
    +'<th style="text-align:center;padding:6px 4px;color:var(--g)">@username</th>'
    +'<th style="text-align:center;padding:6px 4px;color:var(--c)">Mention</th>'
    +'</tr></thead><tbody>';
  groups.forEach((gr,i)=>{
    const members=(details[i]?.ok?details[i].data:[])||[];
    const withUn=members.filter(m=>m.username&&m.username.trim()).length;
    const total=members.length;
    const mention=total-withUn;
    const shortId=gr.chat_id.length>15?'...'+gr.chat_id.slice(-12):gr.chat_id;
    html+=`<tr style="border-bottom:1px solid rgba(255,255,255,.05)">
      <td style="padding:7px 4px;color:var(--t)" title="${gr.chat_id}">${shortId}</td>
      <td style="text-align:center;padding:7px 4px;color:var(--o);font-weight:bold">${total}</td>
      <td style="text-align:center;padding:7px 4px;color:var(--g)">${withUn}</td>
      <td style="text-align:center;padding:7px 4px;color:var(--c)">${mention}</td>
    </tr>`;
  });
  html+='</tbody></table>';
  if(con)con.innerHTML=html;
}
async function toggleTagger(){
  const newEnabled=!_utData.enabled;
  _utData.trigger=g('ut-trigger')?.value.trim()||'@all';
  _utData.batch_size=parseInt(g('ut-batch')?.value||5);
  _utData.delay=parseFloat(g('ut-delay')?.value??1);
  _utData.message=g('ut-message')?.value||'';
  const r=await api('save_user_tagger',{ut:{..._utData,enabled:newEnabled}});
  if(r.ok){_utData.enabled=newEnabled;_applyUtUI();toast(newEnabled?'✅ User Tagger Enabled!':'ℹ️ User Tagger Disabled','success');}
  else toast('❌ Save failed: '+(r.error||''),'error');
}
async function saveTagger(){
  _utData.trigger=g('ut-trigger')?.value.trim()||'@all';
  _utData.batch_size=parseInt(g('ut-batch')?.value||5);
  _utData.delay=parseFloat(g('ut-delay')?.value??1);
  _utData.message=g('ut-message')?.value||'';
  const r=await api('save_user_tagger',{ut:_utData});
  if(r.ok){toast('✅ Tagger settings saved!','success');_applyUtUI();}
  else toast('❌ Save failed: '+(r.error||''),'error');
}
// HIDDEN EYE BOT — JS ENGINE
let _heUsers=[];
let _heQuizData=[];
const HE_RANKS=[
  [150000,'👑','GRANDMASTER'],[130000,'🔱','MYTHIC'],[110000,'🌌','ASCENDED'],
  [95000,'⚔️','SHOGUN'],[80000,'🛡️','VANGUARD'],[65000,'📿','SAGE'],
  [50000,'🗿','TITAN'],[35000,'🦅','Guardian'],[20000,'🌟','Legend'],
  [17000,'🧘','Guru'],[15000,'🎯','Master'],[12000,'🧙','Wizard'],
  [8000,'🔮','Mage'],[4000,'💀','Hacker'],[3000,'⚡','Adept'],
  [2000,'🚀','Voyager'],[1500,'👁','Visionary'],[1000,'🔍','Seeker'],
  [500,'🧭','Pathfinder'],[200,'📘','Apprentice'],[0,'🌱','Neophyte']
];
function heGetRank(pts){
  for(const [t,e,n] of HE_RANKS) if(pts>=t) return `${e} ${n}`;
  return '🌱 Neophyte';
}
async function loadHiddenEye(){
  await Promise.all([heLoadConfig(),heLoadStats(),heLoadUsers(),heLoadAdmins(),heLoadGroups()]);
}
async function heLoadConfig(){
  const r=await api('he_get_config');
  if(!r.ok)return;
  const d=r.data||{};
  if(g('he-or-key'))g('he-or-key').value=d.openrouter_key||'';
  if(g('he-channel'))g('he-channel').value=d.community_channel||'';
  if(g('he-timer'))g('he-timer').value=d.quiz_timer||120;
  if(g('he-version'))g('he-version').value=d.bot_version||'3.1.7';
}
async function heSaveConfig(){
  const payload={
    openrouter_key:g('he-or-key')?.value.trim()||'',
    community_channel:g('he-channel')?.value.trim()||'',
    quiz_timer:parseInt(g('he-timer')?.value||120),
    bot_version:g('he-version')?.value.trim()||'3.1.7'
  };
  const r=await api('he_save_config',{config:payload});
  if(r.ok)toast('✅ HiddenEye config saved!','success');
  else toast('❌ Save failed: '+(r.error||''),'error');
}
async function heLoadStats(){
  const r=await api('he_get_stats');
  if(!r.ok||!r.data)return;
  const d=r.data;
  if(g('he-st-users'))g('he-st-users').textContent=d.users||0;
  if(g('he-st-groups'))g('he-st-groups').textContent=d.groups||0;
  if(g('he-st-quizzes'))g('he-st-quizzes').textContent=d.quizzes||0;
  if(g('he-st-banned'))g('he-st-banned').textContent=d.banned||0;
}
async function heLoadUsers(){
  const r=await api('he_get_users');
  _heUsers=r.data||[];
  heRenderUsers(_heUsers);
}
function heFilterUsers(){
  const q=(g('he-user-search')?.value||'').toLowerCase();
  heRenderUsers(q?_heUsers.filter(u=>(u.first_name||'').toLowerCase().includes(q)||(u.username||'').toLowerCase().includes(q)||(String(u.user_id)).includes(q)):_heUsers);
}
function heRenderUsers(list){
  const c=g('he-users-table');if(!c)return;
  if(!list.length){c.innerHTML='<div style="color:var(--td);font-size:12px;padding:12px;text-align:center">No operatives found.</div>';return;}
  let h='<table style="width:100%;border-collapse:collapse;font-size:11px">';
  h+='<thead><tr style="border-bottom:1px solid rgba(255,255,255,.1)">'
    +'<th style="padding:6px 4px;text-align:left;color:var(--td)">ID</th>'
    +'<th style="padding:6px 4px;text-align:left;color:var(--td)">Name</th>'
    +'<th style="padding:6px 4px;text-align:center;color:#39ff14">Pts</th>'
    +'<th style="padding:6px 4px;text-align:center;color:var(--c)">Rank</th>'
    +'<th style="padding:6px 4px;text-align:center;color:var(--o)">Credits</th>'
    +'<th style="padding:6px 4px;text-align:center;color:var(--td)">Actions</th>'
    +'</tr></thead><tbody>';
  list.forEach((u,i)=>{
    const banned=u.banned?'background:rgba(255,45,85,.08)':'';
    const pts=u.points||0;
    const rank=heGetRank(pts);
    const streak=u.streak||0;
    h+=`<tr style="border-bottom:1px solid rgba(255,255,255,.04);${banned}">
      <td style="padding:6px 4px;font-family:'Share Tech Mono';color:var(--td)">${u.user_id}</td>
      <td style="padding:6px 4px">
        <div style="color:var(--t);font-weight:600">${(u.first_name||'?').replace(/</g,'&lt;')}</div>
        <div style="color:var(--td);font-size:9px">${u.username?'@'+u.username:''} ${streak>=3?'🔥'+streak:''} ${u.banned?'<span style="color:var(--r)">BANNED</span>':''}</div>
      </td>
      <td style="padding:6px 4px;text-align:center;color:#39ff14;font-weight:bold">${pts.toLocaleString()}</td>
      <td style="padding:6px 4px;text-align:center;font-size:10px">${rank}</td>
      <td style="padding:6px 4px;text-align:center;color:var(--o)">${u.credits??'?'}</td>
      <td style="padding:6px 4px;text-align:center">
        <div style="display:flex;gap:3px;justify-content:center;flex-wrap:wrap">
          <button class="btn bsm" onclick="heSetCreditsPrompt('${u.user_id}')" style="font-size:9px;padding:2px 6px;background:rgba(255,159,10,.15);border-color:rgba(255,159,10,.4);color:var(--o)">💳</button>
          ${u.banned
            ?`<button class="btn bsm" onclick="heToggleBan('${u.user_id}',false)" style="font-size:9px;padding:2px 6px;background:rgba(57,255,20,.1);border-color:rgba(57,255,20,.4);color:#39ff14">✅</button>`
            :`<button class="btn bsm bd" onclick="heToggleBan('${u.user_id}',true)" style="font-size:9px;padding:2px 6px">🚫</button>`
          }
        </div>
      </td>
    </tr>`;
  });
  h+='</tbody></table>';
  c.innerHTML=h;
}
async function heToggleBan(uid,ban){
  if(!confirm((ban?'Ban':'Unban')+' user '+uid+'?'))return;
  const r=await api('he_ban_user',{user_id:uid,banned:ban});
  if(r.ok){toast(ban?'🚫 Banned!':'✅ Unbanned!','success');heLoadUsers();heLoadStats();}
  else toast('❌ Failed: '+(r.error||''),'error');
}
async function heSetCreditsPrompt(uid){
  const amt=prompt('Credits amount for user '+uid+'\n(Enter number, or 999999 for unlimited):');
  if(amt===null)return;
  const n=parseInt(amt);
  if(isNaN(n)){toast('❌ Invalid amount','error');return;}
  const r=await api('he_set_credits',{user_id:uid,credits:n});
  if(r.ok){toast('✅ Credits updated!','success');heLoadUsers();}
  else toast('❌ Failed: '+(r.error||''),'error');
}
async function heLoadAdmins(){
  const r=await api('he_get_admins');
  const list=r.data||[];
  const c=g('he-admins-list');if(!c)return;
  if(!list.length){c.innerHTML='<div style="color:var(--td);font-size:12px">No extra admins added.</div>';return;}
  c.innerHTML=list.map(a=>`<div style="display:flex;align-items:center;gap:6px;background:rgba(255,159,10,.08);border:1px solid rgba(255,159,10,.25);border-radius:6px;padding:5px 8px">
    <span style="font-family:'Share Tech Mono';font-size:11px;color:var(--o)">${a.user_id}</span>
    <span style="font-size:9px;color:var(--td)">${a.added||''}</span>
    <button class="btn bd bsm" onclick="heRemoveAdmin('${a.user_id}')" style="font-size:9px;padding:2px 6px;margin-left:auto">✕</button>
  </div>`).join('');
}
async function heAddAdmin(){
  const uid=(g('he-new-admin-id')?.value||'').trim();
  if(!uid)return toast('User ID daalo','error');
  const r=await api('he_add_admin',{user_id:uid});
  if(r.ok){toast('✅ Admin added!','success');g('he-new-admin-id').value='';heLoadAdmins();}
  else toast('❌ Failed: '+(r.error||''),'error');
}
async function heRemoveAdmin(uid){
  if(!confirm('Remove admin '+uid+'?'))return;
  const r=await api('he_remove_admin',{user_id:uid});
  if(r.ok){toast('✅ Admin removed','info');heLoadAdmins();}
  else toast('❌ Failed','error');
}
async function heLoadGroups(){
  const r=await api('he_get_groups');
  const list=r.data||[];
  const c=g('he-groups-table');if(!c)return;
  if(!list.length){c.innerHTML='<div style="color:var(--td);font-size:12px;padding:12px;text-align:center">No groups tracked yet.</div>';return;}
  let h='<table style="width:100%;border-collapse:collapse;font-size:11px"><thead><tr style="border-bottom:1px solid rgba(255,255,255,.1)"><th style="padding:5px 4px;text-align:left;color:var(--td)">Chat ID</th><th style="padding:5px 4px;text-align:left;color:var(--td)">Title</th><th style="padding:5px 4px;text-align:center;color:var(--o)">Quizzes</th></tr></thead><tbody>';
  list.forEach(g2=>{
    h+=`<tr style="border-bottom:1px solid rgba(255,255,255,.04)">
      <td style="padding:5px 4px;font-family:'Share Tech Mono';color:var(--td)">${g2.chat_id}</td>
      <td style="padding:5px 4px;color:var(--t)">${(g2.title||'Unknown').replace(/</g,'&lt;')}</td>
      <td style="padding:5px 4px;text-align:center;color:var(--o)">${g2.quizzes_hosted||0}</td>
    </tr>`;
  });
  h+='</tbody></table>';
  c.innerHTML=h;
}
async function heGenerateQuiz(){
  const domain=g('he-domain')?.value||'General Knowledge';
  const diff=g('he-difficulty')?.value||'Easy';
  const num=parseInt(g('he-numq')?.value||5);
  const btn=g('he-gen-btn');
  if(btn){btn.disabled=true;btn.innerHTML='⏳ Generating...';}
  const r=await api('he_generate_quiz',{domain,difficulty:diff,num});
  if(btn){btn.disabled=false;btn.innerHTML='⚡ Generate';}
  if(!r.ok){toast('❌ Failed: '+(r.error||'Unknown'),'error');return;}
  _heQuizData=r.data||[];
  if(!_heQuizData.length){toast('❌ No questions generated','error');return;}
  const meta=g('he-quiz-meta');
  if(meta)meta.textContent=`✅ ${_heQuizData.length} questions generated | Domain: ${domain} | Diff: ${diff} | Model: ${r.model||'AI'}`;
  const listC=g('he-quiz-list');
  if(listC){
    listC.innerHTML='';
    _heQuizData.forEach((q,i)=>{
      const card=document.createElement('div');
      card.style.cssText='background:rgba(0,245,255,.04);border:1px solid rgba(0,245,255,.18);border-radius:8px;padding:10px 12px;';
      card.innerHTML=`<div style="font-size:11px;color:var(--c);font-weight:600;margin-bottom:6px">Q${i+1}. ${q.question.replace(/</g,'&lt;')}</div>`
        +q.options.map((opt,oi)=>`<div style="font-size:10px;padding:2px 0;color:${oi===q.correct_index?'#39ff14':'var(--td)'}">${oi===q.correct_index?'✅':'○'} ${opt.replace(/</g,'&lt;')}</div>`).join('')
        +(q.explanation?`<div style="font-size:9px;color:var(--td);margin-top:4px;font-style:italic">💡 ${q.explanation.replace(/</g,'&lt;')}</div>`:'');
      listC.appendChild(card);
    });
  }
  g('he-quiz-preview').style.display='block';
  toast(`✅ ${_heQuizData.length} questions ready!`,'success');
}
async function heSendQuizToGroup(){
  const chatId=(g('he-send-chatid')?.value||'').trim();
  if(!chatId)return toast('Group Chat ID daalo','error');
  if(!_heQuizData.length)return toast('Pehle quiz generate karo','error');
  const domain=g('he-domain')?.value||'Quiz';
  const btn=g('he-send-btn');
  if(btn){btn.disabled=true;btn.innerHTML='⏳ Sending...';}
  const r=await api('he_send_quiz_poll',{chat_id:chatId,questions:_heQuizData,domain});
  if(btn){btn.disabled=false;btn.innerHTML='📤 Send to Group';}
  if(r.ok)toast(`✅ ${r.sent} polls sent! (${r.failed} failed)`,'success');
  else toast('❌ Failed: '+(r.error||''),'error');
}
async function heBroadcast(){
  const msg=(g('he-bcast-msg')?.value||'').trim();
  if(!msg)return toast('Please write a message first','error');
  if(!confirm('Broadcast to all HiddenEye users?'))return;
  const btn=g('he-bcast-btn');
  if(btn){btn.disabled=true;btn.innerHTML='⏳ Broadcasting...';}
  const r=await api('he_broadcast',{message:msg});
  if(btn){btn.disabled=false;btn.innerHTML='📤 Send Broadcast to All Operatives';}
  if(r.ok)toast(`✅ Sent: ${r.sent}, Failed: ${r.failed}`,'success');
  else toast('❌ Failed: '+(r.error||''),'error');
}
async function apkrLoad(){
  const r=await api('get_settings');
  const c=r.data?.apk_renamer??{};
  if(g('apkr-enabled'))    g('apkr-enabled').value    = c.enabled?'1':'0';
  if(g('apkr-name'))       g('apkr-name').value        = c.new_name??'RebelApp';
  if(g('apkr-caption'))    g('apkr-caption').value     = c.caption??'✅ {new_name} is ready!';
  if(g('apkr-adminonly'))  g('apkr-adminonly').value   = c.admin_only?'1':'0';
}
async function apkrSave(){
  const r=await api('save_apk_renamer',{apk_renamer:{
    enabled:    g('apkr-enabled')?.value==='1',
    new_name:   (g('apkr-name')?.value||'RebelApp').trim(),
    caption:    g('apkr-caption')?.value||'✅ APK is ready!',
    admin_only: g('apkr-adminonly')?.value==='1',
  }});
  r.ok?toast('✅ Saved!','success'):toast('❌ Failed: '+(r.error||''),'error');
}
// 🌹 ROSE BOT — JS ENGINE

const _roseLocks=['url','photo','video','sticker','gif','voice','audio','document','forward','game','location','contact','poll'];
function roseRenderLocks(locksData){
  const grid=g('rose-locks-grid');
  if(!grid)return;
  grid.innerHTML='';
  _roseLocks.forEach(lt=>{
    const checked=(locksData&&locksData[lt])?'checked':'';
    const div=document.createElement('div');
    div.style.cssText='display:flex;align-items:center;gap:6px;background:rgba(255,107,157,.08);border:1px solid rgba(255,107,157,.2);border-radius:8px;padding:8px 12px;cursor:pointer;min-width:120px';
    div.innerHTML=`<input type="checkbox" id="rose-lock-${lt}" ${checked} style="accent-color:#ff6b9d"><label for="rose-lock-${lt}" style="font-size:12px;color:var(--td);cursor:pointer;text-transform:capitalize">${lt}</label>`;
    grid.appendChild(div);
  });
}
async function roseLoad(){
  const r=await api('get_rose');
  const c=r.data??{};
  if(g('rose-enabled'))         g('rose-enabled').value         = c.enabled?'1':'0';
  if(g('rose-warn-limit'))      g('rose-warn-limit').value      = c.warn_limit??3;
  if(g('rose-warn-action'))     g('rose-warn-action').value     = c.warn_action??'kick';
  if(g('rose-warn-mute'))       g('rose-warn-mute').value       = c.warn_mute_duration??60;
  if(g('rose-rules'))           g('rose-rules').value           = c.rules??'';
  if(g('rose-flood-enabled'))   g('rose-flood-enabled').value   = c.flood?.enabled?'1':'0';
  if(g('rose-flood-limit'))     g('rose-flood-limit').value     = c.flood?.limit??5;
  if(g('rose-flood-window'))    g('rose-flood-window').value    = c.flood?.window??10;
  if(g('rose-flood-action'))    g('rose-flood-action').value    = c.flood?.action??'mute';
  if(g('rose-flood-mute'))      g('rose-flood-mute').value      = c.flood?.mute_duration??5;
  if(g('rose-blacklist'))       g('rose-blacklist').value       = (c.blacklist??[]).join(', ');
  if(g('rose-bl-action'))       g('rose-bl-action').value       = c.blacklist_action??'delete';
  if(g('rose-report-enabled'))  g('rose-report-enabled').value  = (c.report?.enabled!==false)?'1':'0';
  if(g('rose-report-reply'))    g('rose-report-reply').value    = c.report?.reply??'🚨 Report sent!';
  if(g('rose-cleanservice'))    g('rose-cleanservice').value    = c.cleanservice?'1':'0';
  if(g('rose-logchannel'))      g('rose-logchannel').value      = c.log_channel??'';
  roseRenderLocks(c.locks??{});
  // Load reply messages
  const rm=c.reply_msgs??{};
  const rmFields=['warn','warn-limit','ban','tban','kick','mute','unmute','unban','flood','blacklist','locked','promoted','demoted','pinned','unpinned','purged'];
  rmFields.forEach(f=>{
    const el=g('rmsg-'+f);
    if(el) el.value=rm[f.replace('-','_')]||rm[f]||'';
  });
}
async function roseSave(){
  const locks={};
  _roseLocks.forEach(lt=>{locks[lt]=!!(g('rose-lock-'+lt)?.checked);});
  const replyMsgs={};
  ['warn','warn_limit','ban','tban','kick','mute','unmute','unban','flood','blacklist','locked','promoted','demoted','pinned','unpinned','purged'].forEach(k=>{
    const el=g('rmsg-'+k.replace('_','-'));
    if(el) replyMsgs[k]=el.value||'';
  });
  const payload={
    enabled:          g('rose-enabled')?.value==='1',
    warn_limit:       parseInt(g('rose-warn-limit')?.value||3),
    warn_action:      g('rose-warn-action')?.value||'kick',
    warn_mute_duration: parseInt(g('rose-warn-mute')?.value||60),
    rules:            g('rose-rules')?.value||'',
    flood_enabled:    g('rose-flood-enabled')?.value==='1',
    flood_limit:      parseInt(g('rose-flood-limit')?.value||5),
    flood_window:     parseInt(g('rose-flood-window')?.value||10),
    flood_action:     g('rose-flood-action')?.value||'mute',
    flood_mute_duration: parseInt(g('rose-flood-mute')?.value||5),
    blacklist:        g('rose-blacklist')?.value||'',
    blacklist_action: g('rose-bl-action')?.value||'delete',
    report_enabled:   g('rose-report-enabled')?.value==='1',
    report_reply:     g('rose-report-reply')?.value||'🚨 Report sent!',
    cleanservice:     g('rose-cleanservice')?.value==='1',
    log_channel:      g('rose-logchannel')?.value||'',
    locks:            locks,
    reply_msgs:       replyMsgs,
  };
  const res=g('rose-save-result');
  const r=await api('save_rose',{rose:payload});
  if(res){res.style.display='block';res.innerHTML=r.ok?'<div style="color:var(--g);font-family:\'Share Tech Mono\';font-size:12px;padding:8px;background:rgba(57,255,20,.1);border:1px solid rgba(57,255,20,.3);border-radius:8px">✅ 🔥 The Rebel Bot settings saved!</div>':'<div style="color:var(--r);font-size:12px">❌ '+(r.error||'Error')+'</div>';}
  r.ok?toast('🔥 The Rebel Bot saved!','success'):toast('❌ Failed: '+(r.error||''),'error');
}

// Rose Bot Emoji Picker
let _roseEmojiLib=[];
async function roseLoadEmojiPicker(){
  const grid=g('rose-emoji-grid');
  if(grid)grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:10px">⏳ Loading...</div>';
  const r=await api('get_prem_emojis');
  if(!r.ok||!r.data||!r.data.length){
    _roseEmojiLib=[];
    if(grid)grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:12px">📭 Koi emoji nahi.<br><small>Premium Emoji Library mein pehle add karo.</small></div>';
    return;
  }
  _roseEmojiLib=r.data;
  _roseRenderEmojiGrid(r.data);
}
function _roseRenderEmojiGrid(data){
  const grid=g('rose-emoji-grid');if(!grid)return;
  if(!data.length){grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--td);font-size:11px;padding:10px">📭 Koi match nahi</div>';return;}
  grid.innerHTML='';
  data.forEach(emj=>{
    const card=document.createElement('div');
    card.style.cssText='background:rgba(191,90,242,.07);border:1.5px solid rgba(191,90,242,.22);border-radius:8px;padding:8px 4px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:4px;transition:all .15s;user-select:none;';
    card.innerHTML=`<span style="font-size:22px;line-height:1">${emj.fallback||'⭐'}</span><span style="font-size:9px;color:var(--td);font-family:'Share Tech Mono';text-align:center;word-break:break-all;max-width:64px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${emj.label}</span>`;
    card.onmouseenter=()=>{card.style.background='rgba(191,90,242,.22)';card.style.borderColor='rgba(191,90,242,.7)';};
    card.onmouseleave=()=>{card.style.background='rgba(191,90,242,.07)';card.style.borderColor='rgba(191,90,242,.22)';};
    card.onclick=()=>{
      const ta=document.activeElement?.tagName==='TEXTAREA'&&document.activeElement.closest('#p-rosebot')?document.activeElement:null;
      if(!ta){toast('Click in a reply textarea first, then click the emoji!','warn');return;}
      const ins=`<tg-emoji emoji-id="${emj.emoji_id}">${emj.fallback||'⭐'}</tg-emoji>`;
      const s=ta.selectionStart,e=ta.selectionEnd;
      ta.value=ta.value.substring(0,s)+ins+ta.value.substring(e);
      ta.focus();ta.setSelectionRange(s+ins.length,s+ins.length);
      toast('✅ '+emj.fallback+' inserted!','success');
    };
    grid.appendChild(card);
  });
}
// PROMO BOT MANAGER JS

let _promoData = {enabled:false, schedule_type:'interval', interval_minutes:60, trigger_keywords:[], messages:[]};
async function promoLoad(){
  const r = await api('get_promo_bot');
  if(!r.ok) return;
  _promoData = r.data || _promoData;
  promoRenderUI();
}
function promoRenderUI(){
  const d = _promoData;
  const lbl = g('promo-status-label');
  const btn = g('promo-toggle-btn');
  if(lbl){ lbl.textContent = d.enabled ? 'ON' : 'OFF'; lbl.style.color = d.enabled ? 'var(--g)' : 'var(--td)'; }
  if(btn){ btn.textContent = d.enabled ? 'Disable' : 'Enable'; btn.className = 'btn bsm ' + (d.enabled ? 'bd' : 'bg'); }
  if(g('promo-schedule-type')) g('promo-schedule-type').value = d.schedule_type || 'interval';
  if(g('promo-interval')) g('promo-interval').value = d.interval_minutes || 60;
  if(g('promo-keywords')) g('promo-keywords').value = (d.trigger_keywords||[]).join(', ');
  promoOnScheduleChange();
  promoRenderMessages();
}
function promoOnScheduleChange(){
  const t = g('promo-schedule-type')?.value || 'interval';
  if(g('promo-interval-grp')) g('promo-interval-grp').style.display = t==='interval' ? 'flex' : 'none';
  if(g('promo-keyword-grp')) g('promo-keyword-grp').style.display = t==='keyword' ? 'flex' : 'none';
}
function promoToggle(){
  _promoData.enabled = !_promoData.enabled;
  promoRenderUI();
  promoSave(true);
}
function promoRenderMessages(){
  const container = g('promo-messages-list');
  if(!container) return;
  const msgs = _promoData.messages || [];
  if(!msgs.length){
    container.innerHTML = '<div style="text-align:center;color:var(--td);font-size:12px;padding:20px;border:1px dashed rgba(255,255,255,.1);border-radius:8px">No messages yet. Click &quot;+ Add Message&quot; above.</div>';
    return;
  }
  container.innerHTML = '';
  msgs.forEach((msg, idx) => {
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--s2);border:1px solid rgba(255,159,10,.3);border-radius:10px;padding:14px;position:relative';
    const safeText = (msg.text||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    card.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">' +
        '<div style="font-family:\'Share Tech Mono\';font-size:11px;color:var(--o);font-weight:700">&#128226; PROMO MESSAGE ' + (idx+1) + '</div>' +
        '<button class="btn bd bsm" onclick="promoDeleteMsg(' + idx + ')" style="padding:3px 8px;font-size:11px">&#128465; Delete</button>' +
      '</div>' +
      '<div class="fgrp mb">' +
        '<label class="fl" style="color:var(--g)">&#128172; Message Text (HTML supported)</label>' +
        '<textarea class="fta" style="min-height:90px" placeholder="Check out our offer!" oninput="promoUpdateMsg(' + idx + ',\'text\',this.value)">' + safeText + '</textarea>' +
      '</div>' +
      '<div style="background:rgba(255,159,10,.06);border:1px solid rgba(255,159,10,.2);border-radius:8px;padding:11px;margin-bottom:10px">' +
        '<div style="font-size:10px;font-family:\'Share Tech Mono\';color:var(--o);margin-bottom:8px">&#128228; MEDIA — Sirf EK choose karo (APK ya Video ya Image)</div>' +
        '<div class="fgrp mb">' +
          '<label class="fl">&#128241; APK File URL (.apk direct link)</label>' +
          '<div style="display:flex;gap:7px">' +
            '<input type="text" class="fi" value="' + (msg.apk_url||'') + '" placeholder="https://example.com/app.apk" oninput="promoUpdateMsg(' + idx + ',\'apk_url\',this.value)" style="flex:1">' +
            '<button class="btn bg bsm" onclick="promoUploadMedia(' + idx + ',\'apk_url\')">&#128193;</button>' +
          '</div>' +
        '</div>' +
        '<div class="fgrp mb">' +
          '<label class="fl">&#127909; Video URL (.mp4 direct link)</label>' +
          '<div style="display:flex;gap:7px">' +
            '<input type="text" class="fi" value="' + (msg.video_url||'') + '" placeholder="https://example.com/promo.mp4" oninput="promoUpdateMsg(' + idx + ',\'video_url\',this.value)" style="flex:1">' +
            '<button class="btn bg bsm" onclick="promoUploadMedia(' + idx + ',\'video_url\')">&#128193;</button>' +
          '</div>' +
        '</div>' +
        '<div class="fgrp">' +
          '<label class="fl">&#128247; Image URL (.jpg/.png direct link)</label>' +
          '<div style="display:flex;gap:7px">' +
            '<input type="text" class="fi" value="' + (msg.media||'') + '" placeholder="https://example.com/banner.jpg" oninput="promoUpdateMsg(' + idx + ',\'media\',this.value)" style="flex:1">' +
            '<button class="btn bg bsm" onclick="promoUploadMedia(' + idx + ',\'media\')">&#128193;</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div>' +
        '<div style="font-size:10px;font-family:\'Share Tech Mono\';color:var(--c);margin-bottom:6px">&#128280; URL BUTTONS (optional)</div>' +
        '<div class="promo-btn-list" id="promo-btns-' + idx + '"></div>' +
        '<button class="btn bg bsm" onclick="promoAddBtnUI(' + idx + ')" style="margin-top:6px;font-size:11px">+ Add Button</button>' +
      '</div>';
    container.appendChild(card);
    (msg.buttons||[]).forEach((btn, bi) => promoRenderBtnRow(idx, bi, btn));
  });
}
function promoAddMessage(){
  if(!_promoData.messages) _promoData.messages = [];
  _promoData.messages.push({text:'', media:'', apk_url:'', video_url:'', buttons:[]});
  promoRenderMessages();
}
function promoDeleteMsg(idx){
  if(!confirm('Yeh message delete karo?')) return;
  _promoData.messages.splice(idx, 1);
  promoRenderMessages();
}
function promoUpdateMsg(idx, field, value){
  if(_promoData.messages[idx]) _promoData.messages[idx][field] = value;
}
function promoAddBtnUI(msgIdx){
  if(!_promoData.messages[msgIdx].buttons) _promoData.messages[msgIdx].buttons = [];
  const bi = _promoData.messages[msgIdx].buttons.length;
  _promoData.messages[msgIdx].buttons.push({text:'', url:''});
  promoRenderBtnRow(msgIdx, bi, {text:'', url:''});
}
function promoRenderBtnRow(msgIdx, btnIdx, btnData){
  const container = g('promo-btns-'+msgIdx);
  if(!container) return;
  const row = document.createElement('div');
  row.className = 'br';
  row.id = 'promo-btn-row-'+msgIdx+'-'+btnIdx;
  row.style.cssText = 'display:flex;gap:6px;align-items:center;margin-bottom:6px;flex-wrap:wrap';
  row.innerHTML =
    '<input type="text" class="fi" style="flex:1;min-width:100px;font-size:12px" placeholder="Button Text" value="' + (btnData.text||'').replace(/"/g,'&quot;') + '" oninput="promoUpdateBtn(' + msgIdx + ',' + btnIdx + ',\'text\',this.value)">' +
    '<input type="text" class="fi" style="flex:2;min-width:150px;font-size:12px" placeholder="URL (https://...)" value="' + (btnData.url||'').replace(/"/g,'&quot;') + '" oninput="promoUpdateBtn(' + msgIdx + ',' + btnIdx + ',\'url\',this.value)">' +
    '<button class="btn bd bsm" onclick="promoRemoveBtn(' + msgIdx + ',' + btnIdx + ')" style="padding:4px 8px">&#10005;</button>';
  container.appendChild(row);
}
function promoUpdateBtn(msgIdx, btnIdx, field, value){
  if(_promoData.messages[msgIdx]?.buttons?.[btnIdx])
    _promoData.messages[msgIdx].buttons[btnIdx][field] = value;
}
function promoRemoveBtn(msgIdx, btnIdx){
  if(_promoData.messages[msgIdx]?.buttons)
    _promoData.messages[msgIdx].buttons.splice(btnIdx, 1);
  promoRenderMessages();
}
async function promoUploadMedia(msgIdx, field){
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = field==='apk_url' ? '.apk,application/vnd.android.package-archive' : field==='video_url' ? 'video/*' : 'image/*';
  input.onchange = async () => {
    const file = input.files[0]; if(!file) return;
    const fd = new FormData(); fd.append('file', file);
    toast('Uploading...', 'info');
    try {
      const resp = await fetch(A+'upload_media', {method:'POST', body:fd});
      const r = await resp.json();
      if(r.ok){ promoUpdateMsg(msgIdx, field, r.url); promoRenderMessages(); toast('Upload complete!', 'success'); }
      else toast('Upload failed: '+(r.error||''), 'error');
    } catch(e){ toast('Upload error', 'error'); }
  };
  input.click();
}
function promoCollectData(){
  return {
    enabled: _promoData.enabled,
    schedule_type: g('promo-schedule-type')?.value || 'interval',
    interval_minutes: parseInt(g('promo-interval')?.value||60),
    trigger_keywords: (g('promo-keywords')?.value||'').split(',').map(k=>k.trim()).filter(k=>k),
    messages: _promoData.messages || [],
  };
}
async function promoSave(silent=false){
  const d = promoCollectData();
  const r = await api('save_promo_bot', {promo_bot: d});
  _promoData = {..._promoData, ...d};
  if(r.ok){
    if(!silent) toast('Promo Bot settings save ho gayi!', 'success');
    promoRenderUI();
  } else {
    toast('Save failed: '+(r.error||''), 'error');
  }
}
async function promoSendNow(){
  if(!confirm('Send promo to all users now?')) return;
  const res = g('promo-save-result');
  await api('save_promo_bot', {promo_bot: promoCollectData()});
  if(res){ res.style.display='block'; res.innerHTML='<div style="color:var(--y);font-family:\'Share Tech Mono\';font-size:12px">Sending promo to all users...</div>'; }
  const r = await api('send_promo_now');
  if(r.ok){
    toast('Promo sent! Sent: '+r.sent+', Failed: '+r.failed, 'success');
    if(res) res.innerHTML = '<div style="background:rgba(57,255,20,.1);border:1px solid rgba(57,255,20,.3);border-radius:8px;padding:12px;font-family:\'Share Tech Mono\';font-size:12px"><div style="color:var(--g)">Promo Broadcast Complete!</div><div style="color:var(--td);margin-top:4px">Sent: ' + r.sent + ' | Failed: ' + r.failed + '</div></div>';
  } else {
    toast('Failed: '+(r.error||''), 'error');
    if(res) res.innerHTML = '<div style="color:var(--r);font-family:\'Share Tech Mono\';font-size:12px">' + (r.error||'Unknown error') + '</div>';
  }
}

// ─── LINK AUTOMATION ────────────────────────────────────────────────────────
let _laData = {enabled:false, rules:[]};

function laRenderUI(){
  const lbl = g('la-status-label');
  const btn = g('la-toggle-btn');
  if(lbl){ lbl.textContent = _laData.enabled ? 'ON' : 'OFF'; lbl.style.color = _laData.enabled ? 'var(--g)' : 'var(--td)'; }
  if(btn){ btn.textContent = _laData.enabled ? 'Disable' : 'Enable'; btn.className = 'btn bsm ' + (_laData.enabled ? 'bd' : 'bg'); }
  laRenderRules();
}

function laToggle(){
  _laData.enabled = !_laData.enabled;
  laRenderUI();
  laSave(true);
}

function laAddRule(){
  if(!_laData.rules) _laData.rules = [];
  _laData.rules.push({
    id: 'la_' + Date.now(),
    label: 'New Rule',
    url: '',
    method: 'GET',
    headers: '',
    body: '',
    response_path: '',
    trigger: '',
    trigger_mode: 'exact',
    reply_template: '🔗 Response:\n{response}',
    error_message: '⚠️ Error fetching response.',
    enabled: true,
    access_control: '',
    timeout: 60,
    use_browser: false,
    browser_steps: [],
    browser_result_var: 'result',
    captcha_prompt: '🔐 Captcha solve karke reply karo:',
    form_capture: false,
    fc_submit_url: '',
    fc_fields: '',
    fc_success_msg: '✅ Form submit ho gaya!',
    fc_headers: '',
  });
  laRenderRules();
}

function laApplyUidaiTemplate(tpl, bsContId){
  const container = g(bsContId);
  if(!container) return;
  container.innerHTML = '';
  const steps = {
    verify: [
      {type:'set_var', var_name:'aadhaar_no', value:'{query_arg}'},
      {type:'open', value:'https://myaadhaar.uidai.gov.in/verifyAadhaar', stop_on_error:true},
      {type:'wait_load', value:'networkidle', timeout:'20'},
      {type:'wait_element', selector:'input[formcontrolname="aadhaarId"], input[placeholder*="Aadhaar"], input[placeholder*="aadhaar"], #aadhaarNo', timeout:'20'},
      {type:'fill', selector:'input[formcontrolname="aadhaarId"], input[placeholder*="Aadhaar"], input[placeholder*="aadhaar"], #aadhaarNo', value:'{aadhaar_no}'},
      {type:'screenshot', caption:'Aadhaar number filled', crop_x:'', crop_y:'', crop_w:'', crop_h:'', send_ss:false, delete_after:false},
      {type:'ask_captcha', caption:'🔐 Neeche security code dikhta hai, woh reply karo:', crop_x:'300', crop_y:'280', crop_w:'400', crop_h:'120', var_name:'captcha'},
      {type:'fill', selector:'input[formcontrolname="securityCode"], input[placeholder*="security code"], input[placeholder*="Security Code"], #captcha, input[name="captcha"]', value:'{captcha}'},
      {type:'click', selector:'button[type="submit"], button.submit-btn, .verify-btn, .btn-verify, .btn-primary', stop_on_error:false},
      {type:'wait_load', value:'networkidle', timeout:'25'},
      {type:'screenshot', caption:'Verification result', send_ss:true, delete_after:false},
      {type:'get_text', selector:'.verification-status, .result-msg, .success-message, mat-card, .ng-star-inserted h2, .alert, mat-dialog-content', var_name:'result'},
    ],
    status: [
      {type:'set_var', var_name:'enrolment_id', value:'{query_arg}'},
      {type:'open', value:'https://myaadhaar.uidai.gov.in/CheckAadhaarStatus', stop_on_error:true},
      {type:'wait_load', value:'networkidle', timeout:'20'},
      {type:'wait_element', selector:'input[formcontrolname="eid"], input[placeholder*="Enrolment"], input[placeholder*="enrolment"], #eid, input[name="eid"]', timeout:'20'},
      {type:'fill', selector:'input[formcontrolname="eid"], input[placeholder*="Enrolment"], input[placeholder*="enrolment"], #eid, input[name="eid"]', value:'{enrolment_id}'},
      {type:'ask_captcha', caption:'🔐 Security code reply karo:', crop_x:'300', crop_y:'250', crop_w:'400', crop_h:'120', var_name:'captcha'},
      {type:'fill', selector:'input[formcontrolname="captcha"], input[placeholder*="security"], input[placeholder*="Security"], #captcha, input[name="captcha"]', value:'{captcha}'},
      {type:'click', selector:'button[type="submit"], .submit-btn, .check-status-btn, .btn-primary'},
      {type:'wait_load', value:'networkidle', timeout:'25'},
      {type:'screenshot', caption:'Status result', send_ss:true, delete_after:false},
      {type:'get_text', selector:'.status-result, .result-msg, mat-card, .ng-star-inserted, .alert, h2', var_name:'result'},
    ],
    lock: [
      {type:'set_var', var_name:'aadhaar_no', value:'{query_arg}'},
      {type:'open', value:'https://myaadhaar.uidai.gov.in/lock-unlock-uid', stop_on_error:true},
      {type:'wait_load', value:'networkidle', timeout:'20'},
      {type:'wait_element', selector:'input[formcontrolname="aadhaarId"], input[placeholder*="Aadhaar"], input[placeholder*="aadhaar"], #aadhaarNo', timeout:'20'},
      {type:'fill', selector:'input[formcontrolname="aadhaarId"], input[placeholder*="Aadhaar"], input[placeholder*="aadhaar"], #aadhaarNo', value:'{aadhaar_no}'},
      {type:'ask_captcha', caption:'🔐 Security captcha reply karo:', crop_x:'300', crop_y:'250', crop_w:'400', crop_h:'120', var_name:'captcha'},
      {type:'fill', selector:'input[formcontrolname="captcha"], input[placeholder*="security"], input[name="captcha"], #captcha', value:'{captcha}'},
      {type:'click', selector:'button[type="submit"], .btn-primary, .send-otp-btn'},
      {type:'wait_load', value:'networkidle', timeout:'20'},
      {type:'screenshot', caption:'OTP sent screen', send_ss:true, delete_after:false},
      {type:'get_text', selector:'.otp-msg, .info-msg, mat-card, .ng-star-inserted, .alert, h2', var_name:'result'},
    ],
  };
  (steps[tpl]||[]).forEach(s => laAddBrowserStep(bsContId, s));
  toast('✅ UIDAI template load ho gaya! Steps adjust karo.', 'success');
}

function laDeleteRule(idx){
  if(!confirm('Yeh rule delete karo?')) return;
  _laData.rules.splice(idx, 1);
  laRenderRules();
}

function laUpdateRule(idx, field, value){
  if(_laData.rules[idx]) _laData.rules[idx][field] = value;
}

// ─── LA Browser Step Helpers ─────────────────────────────────────────────────
const LA_BS_TYPES = {
  open:{label:'🌐 Open URL',fields:[{k:'value',ph:'https://site.com',label:'URL'}]},
  wait_load:{label:'⌚ Wait Load',fields:[{k:'value',ph:'networkidle',label:'State (networkidle/domcontentloaded/load)'},{k:'timeout',ph:'15',label:'Timeout(s)'}]},
  click:{label:'👆 Click',fields:[{k:'selector',ph:'#btn or //button',label:'Selector'},{k:'x',ph:'X (optional)',label:'X'},{k:'y',ph:'Y (optional)',label:'Y'}]},
  fill:{label:'⌨️ Fill Input',fields:[{k:'selector',ph:'#email',label:'Selector'},{k:'value',ph:'{query} or text',label:'Value'}]},
  type_slow:{label:'⌨️ Type Slow',fields:[{k:'selector',ph:'#aadhaar-input',label:'Selector'},{k:'value',ph:'{query}',label:'Text'},{k:'delay_ms',ph:'80',label:'Delay(ms)'}]},
  screenshot:{label:'📸 Screenshot',fields:[{k:'caption',ph:'Result',label:'Caption'},{k:'crop_x',ph:'X blank=full',label:'X'},{k:'crop_y',ph:'Y',label:'Y'},{k:'crop_w',ph:'W',label:'W'},{k:'crop_h',ph:'H',label:'H'}],checks:[{k:'send_ss',label:'Send to user'},{k:'delete_after',label:'Del after'}]},
  ask_captcha:{label:'🔐 Ask Captcha (relay to bot)',fields:[{k:'caption',ph:'🔐 Reply with captcha:',label:'Prompt'},{k:'crop_x',ph:'X blank=full',label:'X'},{k:'crop_y',ph:'Y',label:'Y'},{k:'crop_w',ph:'W',label:'W'},{k:'crop_h',ph:'H',label:'H'},{k:'var_name',ph:'captcha',label:'Reply→var'}]},
  wait:{label:'⏱ Wait',fields:[{k:'value',ph:'2',label:'Secs'}]},
  wait_element:{label:'⌛ Wait Elem',fields:[{k:'selector',ph:'#result',label:'Selector'},{k:'timeout',ph:'10',label:'Timeout(s)'}]},
  wait_url:{label:'⌛ Wait URL',fields:[{k:'value',ph:'dashboard',label:'URL contains'},{k:'timeout',ph:'15',label:'Timeout(s)'}]},
  get_text:{label:'📋 Get Text→Var',fields:[{k:'selector',ph:'#result',label:'Selector'},{k:'var_name',ph:'result',label:'Save as'}]},
  get_attr:{label:'🔗 Get Attr→Var',fields:[{k:'selector',ph:'a.link',label:'Selector'},{k:'attribute',ph:'href',label:'Attribute'},{k:'var_name',ph:'result',label:'Save as'}]},
  js_eval:{label:'⚡ JS Eval→Var',fields:[{k:'value',ph:'document.title',label:'JS'},{k:'var_name',ph:'js_result',label:'Save as'}]},
  scroll:{label:'↕️ Scroll',fields:[{k:'value',ph:'500',label:'Pixels'}]},
  reload:{label:'🔄 Reload',fields:[]},
  set_var:{label:'📦 Set Var',fields:[{k:'var_name',ph:'myvar',label:'Var name'},{k:'value',ph:'fixed or {other}',label:'Value'}]},
  key:{label:'⌨️ Key Press',fields:[{k:'value',ph:'Enter Tab Escape',label:'Key'}]},
  select:{label:'📋 Select Option',fields:[{k:'selector',ph:'select#lang',label:'Selector'},{k:'value',ph:'English',label:'Option'}]},
  hover:{label:'🖱 Hover',fields:[{k:'selector',ph:'#menu',label:'Selector'}]},
  double_click:{label:'👆👆 Double Click',fields:[{k:'selector',ph:'#item',label:'Selector'}]},
  clear_field:{label:'🗑 Clear Field',fields:[{k:'selector',ph:'#input',label:'Selector'}]},
  cookie_set:{label:'🍪 Set Cookie',fields:[{k:'name',ph:'session',label:'Name'},{k:'value',ph:'{token}',label:'Value'}]},
  cookie_get:{label:'🍪 Get Cookie→Var',fields:[{k:'name',ph:'auth_token',label:'Name'},{k:'var_name',ph:'cookie_val',label:'Save as'}]},
  iframe_switch:{label:'🖼 IFrame In',fields:[{k:'selector',ph:'iframe#frame1',label:'Selector'}]},
  iframe_main:{label:'🖼 IFrame Out',fields:[]},
  assert_text:{label:'✅ Assert Text',fields:[{k:'selector',ph:'#status',label:'Selector'},{k:'value',ph:'Success',label:'Expected text'}]},
  upload_file:{label:'📁 Upload File',fields:[{k:'selector',ph:'input[type=file]',label:'Selector'},{k:'value',ph:'/path/to/file',label:'File path'}]},
  drag_drop:{label:'↔️ Drag & Drop',fields:[{k:'selector',ph:'#draggable',label:'Source'},{k:'target',ph:'#target',label:'Target'}]},
  raw:{label:'⚡ Raw Python',fields:[{k:'value',ph:'PAGE.evaluate("return document.title")',label:'Python code'}]},
};

function laBuildBsFields(def, data={}){
  let h='';
  for(const f of(def.fields||[])){
    const v=(data[f.k]||'').toString().replace(/"/g,'&quot;');
    h+=`<div style="display:flex;flex-direction:column;gap:2px;flex:1;min-width:100px"><label style="font-size:9px;color:var(--td);font-family:'Share Tech Mono'">${f.label}</label><input type="text" class="fi la-bs-f-${f.k}" placeholder="${(f.ph||'').replace(/'/g,"&#39;")}" value="${v}" style="font-size:11px"></div>`;
  }
  for(const c of(def.checks||[])){
    h+=`<div style="display:flex;align-items:center;gap:4px;padding-top:14px"><input type="checkbox" class="la-bs-f-${c.k}" ${data[c.k]?'checked':''}><label style="font-size:10px;color:var(--td)">${c.label}</label></div>`;
  }
  return h;
}

function laAddBrowserStep(containerId, data={}){
  const stype = data.type||'open';
  const def = LA_BS_TYPES[stype]||LA_BS_TYPES.open;
  const d = document.createElement('div');
  d.className = 'la-bstep-row';
  d.style.cssText = 'background:var(--s3);border:1px solid rgba(191,90,242,.3);border-radius:7px;padding:9px;margin-bottom:5px';
  d.innerHTML = `<div style="display:flex;align-items:center;gap:5px;margin-bottom:6px;flex-wrap:wrap">
    <select class="fsel la-bs-type" onchange="onLaBsTypeChange(this)" style="flex:1;min-width:140px;font-size:11px">
      ${Object.entries(LA_BS_TYPES).map(([k,v])=>`<option value="${k}" ${k===stype?'selected':''}>${v.label}</option>`).join('')}
    </select>
    <label style="font-size:10px;color:var(--r);display:flex;align-items:center;gap:3px;cursor:pointer"><input type="checkbox" class="la-bs-stop" ${data.stop_on_error?'checked':''}>stop on err</label>
    <button class="btn bg bsm" onclick="const r=this.closest('.la-bstep-row');const p=r.previousElementSibling;if(p&&p.classList.contains('la-bstep-row'))r.parentNode.insertBefore(r,p)" style="padding:3px 7px">↑</button>
    <button class="btn bg bsm" onclick="const r=this.closest('.la-bstep-row');const n=r.nextElementSibling;if(n&&n.classList.contains('la-bstep-row'))r.parentNode.insertBefore(n,r)" style="padding:3px 7px">↓</button>
    <button class="btn bd bsm" onclick="this.closest('.la-bstep-row').remove()" style="padding:3px 7px">✕</button>
  </div><div class="la-bs-fields" style="display:flex;flex-wrap:wrap;gap:6px">${laBuildBsFields(def,data)}</div>`;
  const container = g(containerId);
  if(container) container.appendChild(d);
}

function onLaBsTypeChange(sel){
  const row = sel.closest('.la-bstep-row');
  const def = LA_BS_TYPES[sel.value]||{fields:[],checks:[]};
  row.querySelector('.la-bs-fields').innerHTML = laBuildBsFields(def);
}

function laGetBrowserSteps(containerId){
  const steps = [];
  const container = g(containerId);
  if(!container) return steps;
  container.querySelectorAll('.la-bstep-row').forEach(row => {
    const stype = row.querySelector('.la-bs-type')?.value||'open';
    const def = LA_BS_TYPES[stype]||{fields:[],checks:[]};
    const s = {type:stype, stop_on_error: row.querySelector('.la-bs-stop')?.checked||false};
    for(const f of(def.fields||[])){const el=row.querySelector('.la-bs-f-'+f.k);if(el)s[f.k]=el.value||'';}
    for(const c of(def.checks||[])){const el=row.querySelector('.la-bs-f-'+c.k);if(el)s[c.k]=el.checked||false;}
    steps.push(s);
  });
  return steps;
}

function laRenderRules(){
  const container = g('la-rules-list');
  if(!container) return;
  const rules = _laData.rules || [];
  if(!rules.length){
    container.innerHTML = '<div style="text-align:center;color:var(--td);font-size:12px;padding:24px;border:1px dashed rgba(255,255,255,.1);border-radius:8px">Koi rule nahi hai. &quot;+ Add Rule&quot; click karo.</div>';
    return;
  }
  container.innerHTML = '';
  rules.forEach((rule, idx) => {
    const card = document.createElement('div');
    card.style.cssText = 'background:var(--s2);border:1px solid rgba(0,245,255,.2);border-radius:10px;overflow:hidden';
    const safe = v => (v||'').toString().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const useBrowser = !!rule.use_browser;
    const bsContId = 'la-bs-c-'+idx;
    // Compact header bar
    card.innerHTML =
      // ── Header bar ──
      '<div style="background:'+(rule.enabled?'rgba(0,245,255,.08)':'rgba(255,255,255,.03)')+';padding:10px 14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;border-bottom:1px solid rgba(0,245,255,.12)">' +
        '<label style="display:flex;align-items:center;gap:5px;cursor:pointer">' +
          '<input type="checkbox" '+(rule.enabled?'checked':'')+' onchange="laUpdateRule('+idx+',\'enabled\',this.checked);this.closest(\'[style*=overflow]\').querySelector(\'div\').style.background=this.checked?\'rgba(0,245,255,.08)\':\'rgba(255,255,255,.03)\'" style="accent-color:var(--g);width:14px;height:14px">' +
          '<span style="font-size:12px;color:var(--t);font-weight:600">'+(rule.label||'Rule '+(idx+1))+'</span>' +
        '</label>' +
        '<span style="font-size:11px;color:var(--y);font-family:\'Share Tech Mono\';background:rgba(255,214,10,.1);border:1px solid rgba(255,214,10,.3);padding:1px 8px;border-radius:4px">trigger: '+(rule.trigger||'(empty)')+'</span>' +
        '<div style="margin-left:auto;display:flex;gap:5px">' +
          '<button class="btn bd bsm" onclick="laDeleteRule('+idx+')" style="padding:3px 10px">&#128465;</button>' +
        '</div>' +
      '</div>' +
      // ── Body ──
      '<div style="padding:12px 14px">' +
        // Label + Trigger row
        '<div class="fg mb">' +
          '<div class="fgrp">' +
            '<label class="fl">Name / Label</label>' +
            '<input type="text" class="fi" value="'+safe(rule.label)+'" placeholder="My Rule" oninput="laUpdateRule('+idx+',\'label\',this.value);this.closest(\'[style*=overflow]\').querySelector(\'span[style*=font-weight]\').textContent=this.value||\'Rule '+(idx+1)+'\'">' +
          '</div>' +
          '<div class="fgrp">' +
            '<label class="fl" style="color:var(--y)">&#9889; Trigger Keyword <span style="font-weight:normal;color:var(--td)">(user yahi type kare)</span></label>' +
            '<input type="text" class="fi" value="'+safe(rule.trigger)+'" placeholder="aadhaar / verify / status" oninput="laUpdateRule('+idx+',\'trigger\',this.value);this.closest(\'[style*=overflow]\').querySelectorAll(\'span\')[1].textContent=\'trigger: \'+(this.value||\'(empty)\')" style="color:var(--y);border-color:rgba(255,214,10,.4)">' +
          '</div>' +
          '<div class="fgrp" style="flex:0.7;min-width:130px">' +
            '<label class="fl">Trigger Mode</label>' +
            '<select class="fsel" onchange="laUpdateRule('+idx+',\'trigger_mode\',this.value)">' +
              ['exact','startswith','contains'].map(m=>'<option value="'+m+'"'+((rule.trigger_mode||'exact')===m?' selected':'')+'>'+m+'</option>').join('') +
            '</select>' +
          '</div>' +
        '</div>' +
        // URL + Method row (simple curl mode)
        '<div id="la-curl-section-'+idx+'" style="display:'+(useBrowser?'none':'block')+'">' +
          '<div class="fg mb">' +
            '<div class="fgrp" style="flex:3">' +
              '<label class="fl">&#127758; API URL <span style="color:var(--td);font-size:9px">({query} {tg_name} {tg_id} supported)</span></label>' +
              '<input type="text" class="fi" value="'+safe(rule.url)+'" placeholder="https://api.example.com/data?q={query}" oninput="laUpdateRule('+idx+',\'url\',this.value)">' +
            '</div>' +
            '<div class="fgrp" style="flex:1;min-width:90px">' +
              '<label class="fl">Method</label>' +
              '<select class="fsel" onchange="laUpdateRule('+idx+',\'method\',this.value)">' +
                ['GET','POST','PUT','DELETE'].map(m=>'<option value="'+m+'"'+(rule.method===m?' selected':'')+'>'+m+'</option>').join('') +
              '</select>' +
            '</div>' +
          '</div>' +
          // Optional advanced fields (collapsible)
          '<details style="margin-bottom:10px">' +
            '<summary style="font-size:11px;color:var(--td);cursor:pointer;padding:4px 0;font-family:\'Share Tech Mono\'">&#9881; Advanced (Headers / Body / Response Path)</summary>' +
            '<div style="margin-top:8px;display:flex;flex-direction:column;gap:8px">' +
              '<div class="fgrp">' +
                '<label class="fl">Headers (Key: Value per line)</label>' +
                '<textarea class="fta" style="min-height:44px;font-size:11px" placeholder="Authorization: Bearer {MY_KEY}" oninput="laUpdateRule('+idx+',\'headers\',this.value)">'+safe(rule.headers)+'</textarea>' +
              '</div>' +
              '<div class="fgrp">' +
                '<label class="fl">Body (POST/PUT ke liye)</label>' +
                '<textarea class="fta" style="min-height:40px;font-size:11px" placeholder=\'{"q":"{query}"}\' oninput="laUpdateRule('+idx+',\'body\',this.value)">'+safe(rule.body)+'</textarea>' +
              '</div>' +
              '<div class="fgrp">' +
                '<label class="fl">Response Path (blank=auto) e.g. data.price</label>' +
                '<input type="text" class="fi" value="'+safe(rule.response_path)+'" placeholder="choices.0.message.content" oninput="laUpdateRule('+idx+',\'response_path\',this.value)">' +
              '</div>' +
            '</div>' +
          '</details>' +
          '<button class="btn bg bsm" onclick="laTestRule('+idx+')" style="font-size:11px;margin-bottom:8px">&#9889; Test URL</button>' +
          '<div id="la-test-result-'+idx+'" style="margin-top:4px;display:none"></div>' +
        '</div>' +
        // Browser mode toggle
        '<div style="background:rgba(191,90,242,.07);border:1px solid rgba(191,90,242,.2);border-radius:7px;padding:9px;margin-bottom:10px">' +
          '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px">' +
            '<span style="font-size:11px;color:var(--p);font-family:\'Share Tech Mono\'">&#129302; Browser Mode (Playwright/Selenium)</span>' +
            '<label style="display:flex;align-items:center;gap:6px;cursor:pointer">' +
              '<input type="checkbox" id="la-use-browser-'+idx+'" '+(useBrowser?'checked':'')+' onchange="laToggleBrowserMode('+idx+',this.checked)" style="accent-color:var(--p);width:14px;height:14px">' +
              '<span style="font-size:11px;color:'+(useBrowser?'var(--p)':'var(--td)')+';font-family:\'Share Tech Mono\'">'+(useBrowser?'ON':'OFF')+'</span>' +
            '</label>' +
          '</div>' +
          '<div id="la-browser-section-'+idx+'" style="display:'+(useBrowser?'block':'none')+';margin-top:8px">' +
            '<div style="font-size:9px;color:var(--td);margin-bottom:6px">Browser steps (open, click, fill...). Blank = URL se direct open.</div>' +
            '<div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px">' +
              '<span style="font-size:9px;color:var(--p);font-family:\'Share Tech Mono\';align-self:center">UIDAI Templates:</span>' +
              '<button class="btn bsm" style="background:rgba(255,159,10,.15);border:1px solid rgba(255,159,10,.4);color:var(--o);font-size:10px;padding:2px 8px" onclick="laApplyUidaiTemplate(\'verify\',\''+bsContId+'\')">🆔 Verify Aadhaar</button>' +
              '<button class="btn bsm" style="background:rgba(57,255,20,.1);border:1px solid rgba(57,255,20,.3);color:var(--g);font-size:10px;padding:2px 8px" onclick="laApplyUidaiTemplate(\'status\',\''+bsContId+'\')">📋 Aadhaar Status</button>' +
              '<button class="btn bsm" style="background:rgba(0,245,255,.1);border:1px solid rgba(0,245,255,.3);color:var(--c);font-size:10px;padding:2px 8px" onclick="laApplyUidaiTemplate(\'lock\',\''+bsContId+'\')">🔒 Lock/Unlock UID</button>' +
            '</div>' +
            '<div id="'+bsContId+'" style="margin-bottom:6px"></div>' +
            '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">' +
              Object.entries(LA_BS_TYPES).map(([k,v])=>'<button class="btn bg bsm" onclick="laAddBrowserStep(\''+bsContId+'\',{type:\''+k+'\'})" style="font-size:10px;padding:2px 6px">'+v.label+'</button>').join('') +
            '</div>' +
            '<div class="fg">' +
              '<div class="fgrp">' +
                '<label class="fl">Result Var</label>' +
                '<input type="text" class="fi" id="la-result-var-'+idx+'" value="'+safe(rule.browser_result_var||'result')+'" placeholder="result" oninput="laUpdateRule('+idx+',\'browser_result_var\',this.value)" style="font-size:11px">' +
              '</div>' +
              '<div class="fgrp">' +
                '<label class="fl">Captcha Prompt</label>' +
                '<input type="text" class="fi" id="la-captcha-prompt-'+idx+'" value="'+safe(rule.captcha_prompt||'🔐 Solve the captcha and reply:')+'" oninput="laUpdateRule('+idx+',\'captcha_prompt\',this.value)" style="font-size:11px">' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +
        // Reply template
        '<div class="fgrp mb">' +
          '<label class="fl">&#128172; Reply Template — <code style="color:var(--y)">{response}</code> = API response</label>' +
          '<textarea class="fta" style="min-height:58px" placeholder="&#128279; Result:\n{response}" oninput="laUpdateRule('+idx+',\'reply_template\',this.value)">'+safe(rule.reply_template)+'</textarea>' +
        '</div>' +
        '<div class="fgrp mb">' +
          '<label class="fl">Error Message</label>' +
          '<input type="text" class="fi" value="'+safe(rule.error_message)+'" placeholder="&#9888; Error!" oninput="laUpdateRule('+idx+',\'error_message\',this.value)">' +
        '</div>' +
        // Form Capture (advanced toggle)
        '<details style="margin-top:4px">' +
          '<summary style="font-size:11px;color:var(--o);cursor:pointer;padding:4px 0;font-family:\'Share Tech Mono\'">&#127760; Website Form Capture (advanced)</summary>' +
          '<div style="margin-top:8px">' +
            '<label style="display:flex;align-items:center;gap:6px;cursor:pointer;margin-bottom:8px">' +
              '<input type="checkbox" id="la-fc-enabled-'+idx+'" '+(rule.form_capture?'checked':'')+' onchange="laToggleFormCapture('+idx+',this.checked)" style="accent-color:var(--o);width:14px;height:14px">' +
              '<span style="font-size:11px;color:'+(rule.form_capture?'var(--o)':'var(--td)')+';font-family:\'Share Tech Mono\'">'+(rule.form_capture?'ENABLED':'DISABLED')+'</span>' +
            '</label>' +
            '<div id="la-fc-section-'+idx+'" style="display:'+(rule.form_capture?'flex':'none')+';flex-direction:column;gap:8px">' +
              '<div class="fgrp">' +
                '<label class="fl">Submit URL</label>' +
                '<input type="text" class="fi" id="la-fc-submit-'+idx+'" value="'+safe(rule.fc_submit_url||'')+'" placeholder="https://yoursite.com/submit" oninput="laUpdateRule('+idx+',\'fc_submit_url\',this.value)" style="font-size:11px">' +
              '</div>' +
              '<div class="fgrp">' +
                '<label class="fl">Form Fields (field_name|Prompt message per line)</label>' +
                '<textarea class="fta" id="la-fc-fields-'+idx+'" style="min-height:65px;font-size:11px" placeholder="name|Aapka naam?\nemail|Email address?" oninput="laUpdateRule('+idx+',\'fc_fields\',this.value)">'+safe(rule.fc_fields||'')+'</textarea>' +
              '</div>' +
              '<div class="fgrp">' +
                '<label class="fl">Success Message</label>' +
                '<input type="text" class="fi" id="la-fc-success-'+idx+'" value="'+safe(rule.fc_success_msg||'✅ Form submit ho gaya!')+'" oninput="laUpdateRule('+idx+',\'fc_success_msg\',this.value)" style="font-size:11px">' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</details>' +
      '</div>';
    container.appendChild(card);
    if(useBrowser && rule.browser_steps && rule.browser_steps.length){
      rule.browser_steps.forEach(step => laAddBrowserStep(bsContId, step));
    }
  });
}

function laToggleBrowserMode(idx, enabled){
  laUpdateRule(idx, 'use_browser', enabled);
  const bsSection = g('la-browser-section-'+idx);
  const curlSection = g('la-curl-section-'+idx);
  const lbl = document.querySelector('#la-use-browser-'+idx+' ~ span');
  if(bsSection) bsSection.style.display = enabled ? 'block' : 'none';
  if(curlSection) curlSection.style.display = enabled ? 'none' : 'block';
  if(lbl){ lbl.textContent = enabled ? 'ON' : 'OFF'; lbl.style.color = enabled ? 'var(--p)' : 'var(--td)'; }
}

function laToggleFormCapture(idx, enabled){
  laUpdateRule(idx, 'form_capture', enabled);
  const sec = g('la-fc-section-'+idx);
  const lbl = document.querySelector('#la-fc-enabled-'+idx+' ~ span');
  if(sec) sec.style.display = enabled ? 'flex' : 'none';
  if(lbl){ lbl.textContent = enabled ? 'ENABLED' : 'DISABLED'; lbl.style.color = enabled ? 'var(--o)' : 'var(--td)'; }
}

function laToggleAdvanced(){
  const sec = g('la-advanced-section');
  const arr = g('la-adv-arrow');
  if(!sec) return;
  const open = sec.style.display !== 'none';
  sec.style.display = open ? 'none' : 'block';
  if(arr) arr.innerHTML = open ? '&#9660;' : '&#9650;';
}

// ─── LA Bot Selector ─────────────────────────────────────────────────────────
let _laBotId = '';

async function laLoad(){
  const r = await api('get_link_automation');
  if(!r.ok) return;
  _laData = r.data || _laData;
  _laBotId = r.la_bot_id || '';
  laRenderUI();
  laRenderBotInfo();
}

function laRenderBotInfo(){
  const infoEl = g('la-bot-info');
  const wuEl = g('la-webhook-url');
  if(!infoEl) return;
  if(!_laBotId){
    infoEl.innerHTML = '<span style="color:var(--r)">&#10060; Koi bot assign nahi hai — &quot;Change Bot&quot; click karke bot select karo.</span>';
    if(wuEl) wuEl.textContent = '—';
    return;
  }
  api('get_bots').then(r => {
    if(!r.ok||!r.data) return;
    const b = r.data.find(x=>x.id===_laBotId);
    if(b){
      infoEl.innerHTML = '<span style="color:var(--g)">&#9989; </span><b style="color:var(--t)">'+b.name+'</b> <span style="color:var(--c)">@'+(b.username||'?')+'</span> <span style="color:var(--td);font-size:10px">ID: '+b.id+'</span>';
    } else {
      infoEl.innerHTML = '<span style="color:var(--y)">&#9888;&#65039; Bot ID: '+_laBotId+' (panel me nahi mila — shayad delete ho gaya)</span>';
    }
  });
  if(wuEl){
    const base = location.origin + location.pathname;
    wuEl.textContent = base + '?la_webhook=' + encodeURIComponent(_laBotId);
  }
}

function laCopyWebhook(){
  const wuEl = g('la-webhook-url');
  if(!wuEl||wuEl.textContent==='—') return;
  navigator.clipboard.writeText(wuEl.textContent).then(()=>toast('✅ Webhook URL copied!','success')).catch(()=>{
    const ta=document.createElement('textarea');ta.value=wuEl.textContent;document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();toast('✅ Copied!','success');
  });
}

async function laSelectBot(){
  const modal = g('la-bot-select-modal');
  const listEl = g('la-bot-select-list');
  modal.style.display='flex';
  listEl.innerHTML='<div style="color:var(--td);text-align:center;padding:12px;font-size:12px">Loading...</div>';
  const r = await api('get_bots');
  if(!r.ok||!r.data||!r.data.length){
    listEl.innerHTML='<div style="color:var(--r);text-align:center;padding:12px;font-size:12px">Koi bot nahi mila. Pehle bot add karo.</div>';
    return;
  }
  listEl.innerHTML='';
  r.data.forEach(b=>{
    const isSelected = b.id===_laBotId;
    const div=document.createElement('div');
    div.style.cssText='background:var(--s2);border:1px solid '+(isSelected?'rgba(191,90,242,.6)':'var(--b)')+';border-radius:8px;padding:10px;display:flex;justify-content:space-between;align-items:center;gap:8px;cursor:pointer';
    div.innerHTML=`<div><b style="color:var(--t)">${b.name}</b> <span style="font-size:11px;color:var(--c)">@${b.username||'?'}</span>${isSelected?'<span style="margin-left:8px;background:rgba(191,90,242,.2);color:var(--p);font-family:\'Share Tech Mono\';font-size:10px;padding:2px 7px;border-radius:4px">SELECTED</span>':''}</div><button class="btn bsm" style="background:rgba(191,90,242,.2);border:1px solid rgba(191,90,242,.5);color:var(--p)">Select</button>`;
    div.querySelector('button').onclick=async()=>{
      const sr=await api('set_la_bot',{la_bot_id:b.id});
      if(sr.ok){_laBotId=b.id;modal.style.display='none';laRenderBotInfo();toast('✅ Bot set: '+b.name,'success');}
      else toast('Error: '+(sr.error||''),'error');
    };
    listEl.appendChild(div);
  });
}

async function laTestRule(idx){
  const rule = _laData.rules[idx];
  if(!rule) return;
  const res = g('la-test-result-'+idx);
  if(res){ res.style.display='block'; res.innerHTML='<div style="color:var(--y);font-family:\'Share Tech Mono\';font-size:11px">Testing...</div>'; }
  const r = await api('test_link_automation', {
    url: rule.url,
    method: rule.method||'GET',
    headers: rule.headers||'',
    body: rule.body||'',
    response_path: rule.response_path||'',
    timeout: rule.timeout||30,
  });
  if(!res) return;
  res.style.display='block';
  if(r.ok){
    const codeBadge = r.http_code < 400
      ? '<span style="background:rgba(57,255,20,.2);color:var(--g);font-family:\'Share Tech Mono\';font-size:10px;padding:2px 7px;border-radius:4px">HTTP '+r.http_code+'</span>'
      : '<span style="background:rgba(255,45,85,.2);color:var(--r);font-family:\'Share Tech Mono\';font-size:10px;padding:2px 7px;border-radius:4px">HTTP '+r.http_code+'</span>';
    const escExtracted = (r.extracted||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const escRaw = (r.raw_body||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    res.innerHTML =
      '<div style="background:rgba(0,245,255,.06);border:1px solid rgba(0,245,255,.2);border-radius:8px;padding:10px;font-size:11px">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:7px">' + codeBadge + '<span style="color:var(--g);font-family:\'Share Tech Mono\';font-size:10px">&#9989; Response received</span></div>' +
        '<div style="font-family:\'Share Tech Mono\';font-size:10px;color:var(--y);margin-bottom:4px">Extracted Value:</div>' +
        '<div style="background:var(--s2);border:1px solid var(--b);border-radius:5px;padding:7px;color:var(--g);font-family:\'Share Tech Mono\';font-size:11px;white-space:pre-wrap;max-height:120px;overflow-y:auto">' + escExtracted + '</div>' +
        '<details style="margin-top:7px"><summary style="font-size:10px;color:var(--td);cursor:pointer;font-family:\'Share Tech Mono\'">Raw Response (click to expand)</summary><div style="background:var(--s2);border-radius:5px;padding:7px;color:var(--td);font-family:\'Share Tech Mono\';font-size:10px;white-space:pre-wrap;max-height:150px;overflow-y:auto;margin-top:5px">' + escRaw + '</div></details>' +
      '</div>';
  } else {
    res.innerHTML = '<div style="background:rgba(255,45,85,.08);border:1px solid rgba(255,45,85,.3);border-radius:8px;padding:10px;color:var(--r);font-family:\'Share Tech Mono\';font-size:11px">&#10060; ' + (r.error||'Unknown error') + '</div>';
  }
}

async function laSave(silent=false){
  // Collect browser_steps and form_capture fields from DOM for each rule before saving
  const rules = (_laData.rules||[]).map((rule, idx) => {
    const bsContId = 'la-bs-c-'+idx;
    const steps = laGetBrowserSteps(bsContId);
    return {...rule, browser_steps: steps};
  });
  const d = {enabled: _laData.enabled, rules, la_bot_id: _laBotId};
  const r = await api('save_link_automation', {link_automation: d});
  const res = g('la-save-result');
  if(r.ok){
    _laData = {..._laData, ...d};
    if(!silent){ toast('Link Automation settings save ho gayi!', 'success'); }
    if(res){ res.style.display='block'; res.innerHTML='<div style="color:var(--g);font-family:\'Share Tech Mono\';font-size:12px">&#9989; Saved! '+r.count+' rule(s) active.</div>'; }
    laRenderUI();
  } else {
    toast('Save failed: '+(r.error||''), 'error');
    if(res){ res.style.display='block'; res.innerHTML='<div style="color:var(--r);font-family:\'Share Tech Mono\';font-size:12px">&#10060; '+(r.error||'Unknown error')+'</div>'; }
  }
}

// ═══════════════════════════════════════════════════════════
// 💰 DEPOSIT BOT JAVASCRIPT
// ═══════════════════════════════════════════════════════════
function rbdInit(){ rbdLoadCfg(); rbdLoadLogs(); }

async function rbdLoadCfg(){
  const r=await api('rbd_get_config');if(!r.ok)return;const d=r.data||{};
  g('rbd-token').value=d.bot_token||'';g('rbd-admin-chat').value=d.admin_chat_id||'';
  g('rbd-rbphone').value=d.rb_phone||'';g('rbd-rbpass').value=d.rb_password||'';
  g('rbd-branch').value=d.rb_branch||'RBVIP1D';g('rbd-bankid').value=d.rb_bank_id||'';
  g('rbd-minDep').value=d.min_deposit||500;g('rbd-maxDep').value=d.max_deposit||100000;
  g('rbd-welcome').value=d.welcome_msg||'';g('rbd-thanks').value=d.deposit_thanks||'';
}

async function rbdSaveCfg(){
  const payload={
    bot_token:g('rbd-token').value.trim(),admin_chat_id:g('rbd-admin-chat').value.trim(),
    rb_phone:g('rbd-rbphone').value.trim(),rb_password:g('rbd-rbpass').value.trim(),
    rb_branch:g('rbd-branch').value.trim()||'RBVIP1D',rb_bank_id:g('rbd-bankid').value.trim(),
    min_deposit:parseInt(g('rbd-minDep').value)||500,max_deposit:parseInt(g('rbd-maxDep').value)||100000,
    welcome_msg:g('rbd-welcome').value,deposit_thanks:g('rbd-thanks').value,
    new_pass:g('rbd-newpass').value.trim(),
  };
  const r=await api('rbd_save_config',payload);
  r.ok?toast('✅ Deposit Bot config saved!','success'):toast('Error: '+(r.error||''),'error');
}

async function rbdSetWebhook(){
  toast('Setting webhook...','info');
  const r=await api('rbd_set_webhook');
  r.ok?toast('✅ Webhook set: '+r.webhook_url,'success'):toast('❌ '+(r.error||r.tg?.description||'failed'),'error');
}
async function rbdRemoveWebhook(){const r=await api('rbd_remove_webhook');r.ok?toast('Webhook removed','info'):toast('Error','error');}

async function rbdTestLogin(){
  toast('Testing Rebel B2W login...','info');
  const r=await api('rbd_test_rb_login');
  if(r.ok){const u=r.user||{};toast('✅ Login OK! '+(u.clientName||JSON.stringify(u).slice(0,60)),'success');}
  else toast('❌ '+(r.error||'Login failed'),'error');
}

async function rbdTestBank(){
  toast('Fetching bank details...','info');
  const r=await api('rbd_test_bank');
  const card=g('rbd-info-card');const body=g('rbd-info-body');const title=g('rbd-info-title');
  card.style.display='block';title.textContent='🏦 Bank/UPI Details';
  if(r.ok&&r.bank){
    const b=r.bank;toast('✅ Bank details found!','success');
    body.innerHTML=`<div style="font-size:13px;line-height:2.2;background:var(--s2);padding:14px;border-radius:8px">
      <span style="color:var(--g)">✅ Bank Details (powerdreams.co):</span><br>
      📱 UPI ID: <code>${b.upiId||'—'}</code><br>
      👤 Holder: <b>${b.accHolderName||'—'}</b><br>
      🔢 Acc No: <code>${b.accNo||'—'}</code><br>
      🏛 IFSC: <code>${b.ifscCode||'—'}</code><br>
      🏦 Bank: ${b.bankName||'—'}</div>`;
  }else{toast('❌ Bank details not found','error');body.innerHTML=`<div style="color:var(--r);font-size:12px">❌ fetchAvailablePeer failed<pre style="font-size:10px;margin-top:8px;color:var(--td)">${JSON.stringify(r,null,2)}</pre></div>`;}
}

async function rbdSendTest(){
  const cid=g('rbd-admin-chat').value.trim();
  toast('Sending test message...','info');
  const r=await api('rbd_send_test',{chat_id:cid});
  r.ok?toast('✅ Message sent!','success'):toast('❌ '+(r.error||'failed'),'error');
}

async function rbdLoadLedger(){
  const r=await api('rbd_get_ledger');
  const card=g('rbd-info-card');const body=g('rbd-info-body');const title=g('rbd-info-title');
  card.style.display='block';title.textContent='👥 User Ledger';
  if(!r.ok||!Object.keys(r.ledger||{}).length){body.innerHTML='<div style="color:var(--td)">No users yet.</div>';return;}
  let rows='';
  Object.entries(r.ledger||{}).forEach(([cid,u])=>{
    rows+=`<tr>
      <td style="font-family:monospace;font-size:11px">${cid}</td>
      <td style="color:var(--g)">₹${parseFloat(u.balance||0).toFixed(2)}</td>
      <td>${(u.deposits||[]).length}</td>
      <td>${(u.withdrawals||[]).length}</td>
      <td><button class="btn bsu bsm" onclick="rbdApprovePrompt('${cid}')">✅ Credit</button></td>
    </tr>`;
  });
  body.innerHTML=`<div style="margin-bottom:8px;font-size:12px;color:var(--td)">Total Users: <b style="color:var(--c)">${r.total_users}</b></div><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="color:var(--td)"><th style="padding:6px;text-align:left">Chat ID</th><th>Balance</th><th>Deposits</th><th>Withdrawals</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function rbdApprovePrompt(chatId){
  const amt=prompt('Approve deposit amount (₹):');if(!amt||isNaN(parseFloat(amt)))return;
  const utr=prompt('UTR number (optional):');
  const r=await api('rbd_approve_deposit',{chat_id:chatId,amount:parseFloat(amt),utr:utr||''});
  if(r.ok){toast('✅ Deposit approved! Balance updated.','success');rbdLoadLedger();}
  else toast('❌ '+(r.error||''),'error');
}

async function rbdLoadBlocked(){
  const r=await api('rbd_get_blocked');
  const card=g('rbd-info-card');const body=g('rbd-info-body');const title=g('rbd-info-title');
  card.style.display='block';title.textContent='🚫 Blocked Users';
  if(!r.ok||!Object.keys(r.blocked||{}).length){body.innerHTML='<div style="color:var(--g)">✅ No blocked users.</div>';return;}
  let rows='';
  Object.entries(r.blocked||{}).forEach(([cid,info])=>{
    rows+=`<tr><td style="font-family:monospace;font-size:11px">${cid}</td><td style="color:var(--r)">${info.remaining_mins} min</td><td><button class="btn bsu bsm" onclick="rbdUnblock('${cid}')">✅ Unblock</button></td></tr>`;
  });
  body.innerHTML=`<div style="margin-bottom:8px;color:var(--r)">🚫 Blocked: <b>${r.total}</b></div><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="color:var(--td)"><th style="padding:6px;text-align:left">Chat ID</th><th>Time Left</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table>`;
}
async function rbdUnblock(cid){const r=await api('rbd_unblock_user',{chat_id:cid});r.ok?toast('✅ Unblocked: '+cid,'success'):toast('Error','error');rbdLoadBlocked();}

async function rbdLoadLogs(){
  const r=await api('rbd_get_logs');const box=g('rbd-log-box');
  if(!r.ok||!r.data?.length){box.innerHTML='<div style="color:var(--tf)">No logs yet.</div>';return;}
  box.innerHTML=r.data.map(l=>`<div><span style="color:var(--tf)">[${new Date(l.time).toLocaleTimeString()}]</span> <span style="color:var(--${l.type==='success'?'g':l.type==='error'?'r':l.type==='warn'?'y':'c'})">${l.text}</span></div>`).join('');
}
async function rbdClearLogs(){await api('rbd_clear_logs');rbdLoadLogs();toast('Logs cleared','info');}

// ═══════════════════════════════════════════════════════════
// 🔗 LINK RUNNER JAVASCRIPT
// ═══════════════════════════════════════════════════════════
let _lrLinks=[];let _lrLinkIdx=0;

function lrInit(){ lrLoadConfig2(); lrLoadLogs(); }

async function lrLoadConfig2(){
  const r=await api('lr_get_config');if(!r.ok)return;const d=r.data||{};
  g('lr-token').value=d.bot_token||'';g('lr-chat').value=d.chat_id||'';
  g('lr-prefix').value=d.send_prefix||'';g('lr-secret').value=d.run_secret||'';
  g('lr-wtoken').value=d.webhook_token||'';g('lr-wcmd').value=d.webhook_cmd||'/run';
  _lrLinks=d.links||[];lrRenderLinks();
}

async function lrSaveConfig(){
  const payload={bot_token:g('lr-token').value.trim(),chat_id:g('lr-chat').value.trim(),send_prefix:g('lr-prefix').value,run_secret:g('lr-secret').value.trim(),webhook_token:g('lr-wtoken').value.trim(),webhook_cmd:g('lr-wcmd').value.trim(),new_pass:g('lr-newpass').value.trim()};
  const r=await api('lr_save_config',payload);r.ok?toast('✅ Link Runner config saved!','success'):toast('Error: '+(r.error||''),'error');
}

async function lrSaveLinks(){
  const r=await api('lr_save_links',{links:_lrLinks});r.ok?toast('✅ '+r.count+' link(s) saved!','success'):toast('Error: '+(r.error||''),'error');
}

async function lrSavePage(){ await lrSaveConfig(); await lrSaveLinks(); }

async function lrSetWebhook(){toast('Setting webhook...','info');const r=await api('lr_set_webhook');r.ok?toast('✅ Webhook set: '+r.webhook_url,'success'):toast('❌ '+(r.error||r.tg?.description||'failed'),'error');}
async function lrRemoveWebhook(){const r=await api('lr_remove_webhook');r.ok?toast('Webhook removed','info'):toast('Error','error');}

async function lrRunAll(){
  const st=g('lr-run-status');st.textContent='⏳ Running...';st.style.color='var(--y)';
  const r=await api('lr_run_now');st.textContent='';
  if(!r.ok){toast('Error: '+(r.error||''),'error');return;}
  lrShowResults(r.results||[]);toast('✅ Done! '+r.success+'/'+(r.results||[]).length+' success','success');lrLoadLogs();
}

function lrAddLink(preset={}){
  const id=preset.id||('l_'+Date.now()+'_'+(++_lrLinkIdx));
  _lrLinks.push({id,name:preset.name||'New Link',enabled:preset.enabled!==false,url:preset.url||'',method:preset.method||'GET',headers:preset.headers||'',body:preset.body||'',timeout:preset.timeout||30,ssl_verify:preset.ssl_verify!==false,response_path:preset.response_path||'',reply_template:preset.reply_template||'📌 <b>{name}</b>\n\n{response}',error_message:preset.error_message||'⚠️ <b>{name}</b> failed!\nHTTP: <code>{http_code}</code>',send_on_error:preset.send_on_error||false,chat_id:preset.chat_id||'',screenshot_mode:preset.screenshot_mode||false,screenshot_caption:preset.screenshot_caption||'📸 <b>{name}</b>\n🌐 <code>{url}</code>\n🕐 {ts}'});
  lrRenderLinks();const c=g('lr-links-container');if(c)c.lastElementChild?.scrollIntoView({behavior:'smooth'});
}

function lrRenderLinks(){
  const c=g('lr-links-container');if(!c)return;c.innerHTML='';g('lr-link-count').textContent=_lrLinks.length;
  _lrLinks.forEach((lk,i)=>c.appendChild(lrBuildLinkEl(lk,i)));
}

function lrEsc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function lrSyncField(id,field,val){const lk=_lrLinks.find(l=>l.id===id);if(lk)lk[field]=val;}
function lrToggleCard(id){const el=g('lrcard_'+id);if(el)el.classList.toggle('lrcollapsed');}
function lrToggleSsCap(id,show){const w=g('lrss_wrap_'+id);if(w)w.style.display=show?'':'none';}
function lrDeleteLink(id){if(!confirm('Delete this link?'))return;_lrLinks=_lrLinks.filter(l=>l.id!==id);lrRenderLinks();}

function lrBuildLinkEl(lk,i){
  const div=document.createElement('div');
  div.id='lrcard_'+lk.id;
  div.style.cssText='background:var(--s2);border:1px solid var(--b);border-radius:8px;padding:14px;margin-bottom:10px;position:relative';
  div.innerHTML=`
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:6px">
  <div style="display:flex;align-items:center;gap:8px">
    <span style="cursor:pointer;user-select:none;color:var(--td)" onclick="lrToggleCard('${lk.id}')">▼</span>
    <input type="text" value="${lrEsc(lk.name)}" id="lrn_${lk.id}" style="background:transparent;border:none;border-bottom:1px solid var(--b);border-radius:0;padding:2px 4px;width:160px;color:var(--t);font-weight:600;outline:none" onchange="lrSyncField('${lk.id}','name',this.value)">
    <span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;${lk.enabled?'background:rgba(57,255,20,.15);color:var(--g);border:1px solid rgba(57,255,20,.3)':'background:rgba(255,45,85,.15);color:var(--r);border:1px solid rgba(255,45,85,.3)'}" id="lren_badge_${lk.id}">${lk.enabled?'ON':'OFF'}</span>
  </div>
  <div style="display:flex;gap:5px;flex-wrap:wrap">
    <button class="btn bg bsm" onclick="lrRunSingle('${lk.id}')">▶ Test</button>
    <button class="btn bd bsm" onclick="lrDeleteLink('${lk.id}')">🗑</button>
  </div>
</div>
<div style="font-size:11px;color:var(--td);font-family:monospace;word-break:break-all;margin-bottom:8px" id="lrurl_preview_${lk.id}">${lrEsc(lk.url)||'<span style="color:var(--tf)">No URL</span>'}</div>
<div id="lrbody_${lk.id}" style="display:none">
  <div class="fg mb">
    <div class="fgrp"><label class="fl">🌐 URL</label><input type="text" id="lru_${lk.id}" class="fi" value="${lrEsc(lk.url)}" placeholder="https://..." onchange="lrSyncField('${lk.id}','url',this.value);g('lrurl_preview_${lk.id}').textContent=this.value||'No URL'"></div>
    <div class="fgrp" style="max-width:110px"><label class="fl">Method</label><select id="lrm_${lk.id}" class="fsel fi" onchange="lrSyncField('${lk.id}','method',this.value)">${['GET','POST','PUT','PATCH','DELETE'].map(m=>`<option${lk.method===m?' selected':''}>${m}</option>`).join('')}</select></div>
    <div class="fgrp" style="max-width:100px"><label class="fl">Timeout(s)</label><input type="number" id="lrt_${lk.id}" class="fi" value="${lk.timeout||30}" min="5" max="120" onchange="lrSyncField('${lk.id}','timeout',+this.value)"></div>
  </div>
  <div class="fg mb">
    <div class="fgrp"><label class="fl">📋 Headers (Key: Value per line)</label><textarea id="lrh_${lk.id}" class="fi fta" rows="3" onchange="lrSyncField('${lk.id}','headers',this.value)">${lrEsc(lk.headers)}</textarea></div>
    <div class="fgrp"><label class="fl">📦 Request Body (POST/PUT)</label><textarea id="lrb_${lk.id}" class="fi fta" rows="3" onchange="lrSyncField('${lk.id}','body',this.value)">${lrEsc(lk.body)}</textarea></div>
  </div>
  <div class="fg mb">
    <div class="fgrp"><label class="fl">🔍 Response JSON Path (e.g. data.result)</label><input id="lrrp_${lk.id}" class="fi" value="${lrEsc(lk.response_path)}" placeholder="Leave blank for auto-detect" onchange="lrSyncField('${lk.id}','response_path',this.value)"></div>
    <div class="fgrp"><label class="fl">💬 Override Chat ID (blank = use global)</label><input id="lrci_${lk.id}" class="fi" value="${lrEsc(lk.chat_id)}" placeholder="Optional" onchange="lrSyncField('${lk.id}','chat_id',this.value)"></div>
  </div>
  <div class="fgrp mb"><label class="fl">📝 Reply Template</label><textarea id="lrrt_${lk.id}" class="fi fta" rows="3" onchange="lrSyncField('${lk.id}','reply_template',this.value)">${lrEsc(lk.reply_template)}</textarea><div style="font-size:10px;color:var(--td);margin-top:4px">Vars: {name} {url} {response} {result} {http_code} {status} {ts} {date} {time} + any JSON key</div></div>
  <div class="fgrp mb"><label class="fl">❌ Error Message Template</label><textarea id="lrem_${lk.id}" class="fi fta" rows="2" onchange="lrSyncField('${lk.id}','error_message',this.value)">${lrEsc(lk.error_message)}</textarea></div>
  <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
    <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="lrenabled_${lk.id}" ${lk.enabled?'checked':''} style="accent-color:var(--c)" onchange="lrSyncField('${lk.id}','enabled',this.checked);const b=g('lren_badge_${lk.id}');if(b){b.textContent=this.checked?'ON':'OFF';b.style.color=this.checked?'var(--g)':'var(--r)'}"><span style="font-size:12px">Enabled</span></label>
    <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="lrssl_${lk.id}" ${lk.ssl_verify!==false?'checked':''} style="accent-color:var(--c)" onchange="lrSyncField('${lk.id}','ssl_verify',this.checked)"><span style="font-size:12px">SSL Verify</span></label>
    <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="lrsoe_${lk.id}" ${lk.send_on_error?'checked':''} style="accent-color:var(--c)" onchange="lrSyncField('${lk.id}','send_on_error',this.checked)"><span style="font-size:12px">Send on Error</span></label>
    <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="lrssm_${lk.id}" ${lk.screenshot_mode?'checked':''} style="accent-color:var(--c)" onchange="lrSyncField('${lk.id}','screenshot_mode',this.checked);lrToggleSsCap('${lk.id}',this.checked)"><span style="font-size:12px">📸 Screenshot Mode</span></label>
  </div>
  <div id="lrss_wrap_${lk.id}" style="${lk.screenshot_mode?'':'display:none'}">
    <div class="fgrp mb"><label class="fl">📸 Screenshot Caption (HTML)</label><textarea id="lrssc_${lk.id}" class="fi fta" rows="2" onchange="lrSyncField('${lk.id}','screenshot_caption',this.value)">${lrEsc(lk.screenshot_caption||'📸 <b>{name}</b>\n🌐 <code>{url}</code>\n🕐 {ts}')}</textarea><div style="font-size:10px;color:var(--td);margin-top:4px">Vars: {name} {url} {ts} {date} {time}</div></div>
    <div style="background:rgba(57,255,20,.06);border:1px solid rgba(57,255,20,.2);border-radius:6px;padding:8px 12px;margin-top:4px;font-size:11px;color:var(--g)">✅ <b>No browser install needed!</b> Free APIs use hoti hain (thum.io → microlink).</div>
  </div>
  <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--b)">
    <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="lrffm_${lk.id}" ${lk.form_fill_mode?'checked':''} style="accent-color:var(--c)" onchange="lrSyncField('${lk.id}','form_fill_mode',this.checked);lrToggleFormFill('${lk.id}',this.checked)"><span style="font-size:12px">📋 Form Fill Mode (Bot user se form fields puchega)</span></label>
  </div>
  <div id="lrff_wrap_${lk.id}" style="${lk.form_fill_mode?'':'display:none'};margin-top:8px">
    <div class="fgrp mb">
      <label class="fl">📋 Form Fields (comma separated)</label>
      <input type="text" id="lrff_${lk.id}" class="fi" value="${lrEsc(lk.form_fields||'')}" placeholder="username, password, email" onchange="lrSyncField('${lk.id}','form_fields',this.value)">
      <div style="font-size:10px;color:var(--td);margin-top:4px">Khali chhodo = site se auto-detect. Ya manually: <code>username, password, email</code></div>
    </div>
    <div style="background:rgba(99,179,237,.06);border:1px solid rgba(99,179,237,.2);border-radius:6px;padding:8px 12px;font-size:11px;color:var(--td)">
      📌 Bot pe <b>/fill ${lrEsc(lk.name||'link_name')}</b> command bhejo → bot har field puchega → reply karo → submit.<br>
      URL: <code>https://site.com/login?user={username}&pass={password}</code><br>
      Body: <code>username={username}&password={password}</code>
    </div>
  </div>
  <div id="lrresult_${lk.id}" style="margin-top:10px;display:none;background:var(--s2);border:1px solid var(--b);border-radius:6px;padding:10px;font-size:12px"></div>
</div>`;
  div.querySelector('[onclick*="lrToggleCard"]')?.addEventListener('click',()=>{
    const body=g('lrbody_'+lk.id);if(body)body.style.display=body.style.display==='none'?'block':'none';
  });
  return div;
}

async function lrRunSingle(linkId){
  const box=g('lrresult_'+linkId);if(box){box.style.display='block';box.innerHTML='<span style="color:var(--y)">⏳ Testing...</span>';}
  const r=await api('lr_run_single',{link_id:linkId});
  if(!r.ok){if(box)box.innerHTML='<span style="color:var(--r)">Error: '+(r.error||'')+'</span>';return;}
  const res=r.result||{};const isSS=res.mode==='screenshot';
  if(box){box.innerHTML=`<b style="color:${res.failed?'var(--r)':'var(--g)'}">${res.failed?'❌ FAILED':'✅ SUCCESS'}</b>`+(isSS?' <span style="background:rgba(0,245,255,.1);color:var(--c);padding:1px 6px;border-radius:3px;font-size:10px">📸 Screenshot</span>':` HTTP <code>${res.code}</code>`)+(res.sent?' <span style="color:var(--g)">| Sent ✓</span>':'')+(!isSS?`<div style="color:var(--td);font-family:monospace;font-size:11px;white-space:pre-wrap;max-height:150px;overflow:auto;margin-top:6px">${lrEsc(String(res.extracted||'').slice(0,500))}</div>`:'');}
  lrLoadLogs();
}

function lrShowResults(results){
  const card=g('lr-results-card');const body=g('lr-results-body');if(!card||!body)return;
  card.style.display='block';
  body.innerHTML=results.map(r=>`<div style="background:var(--s2);border:1px solid var(--b);border-radius:6px;padding:10px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px"><b>${lrEsc(r.name)}</b><div style="display:flex;gap:5px;align-items:center">${r.mode==='screenshot'?'<span style="background:rgba(0,245,255,.1);color:var(--c);padding:1px 6px;border-radius:3px;font-size:10px">📸</span>':''}<span style="display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;${r.failed?'background:rgba(255,45,85,.15);color:var(--r)':'background:rgba(57,255,20,.15);color:var(--g)'}">${r.failed?'❌ FAILED':'✅ OK'}${r.mode!=='screenshot'?' HTTP '+r.code:''}</span>${r.sent?'<span style="color:var(--g);font-size:11px">✓ Sent</span>':''}</div></div>${(!r.failed&&r.mode!=='screenshot')?`<div style="font-family:monospace;font-size:11px;margin-top:6px;white-space:pre-wrap;max-height:80px;overflow:auto;color:var(--td)">${lrEsc(String(r.extracted||'').slice(0,300))}</div>`:''}</div>`).join('');
}

async function lrLoadLogs(){
  const r=await api('lr_get_logs');const box=g('lr-log-box');if(!box)return;
  if(!r.ok||!r.data?.length){box.innerHTML='<div style="color:var(--tf)">No logs yet.</div>';return;}
  box.innerHTML=r.data.map(l=>`<div><span style="color:var(--tf)">[${new Date(l.time).toLocaleTimeString()}]</span> <span style="color:var(--${l.type==='success'?'g':l.type==='error'?'r':l.type==='warn'?'y':'c'})">${l.text}</span></div>`).join('');
}
async function lrClearLogs(){await api('lr_clear_logs');lrLoadLogs();toast('Logs cleared','info');}

// ─── Form Fill Mode toggle ────────────────────────────────
function lrToggleFormFill(id,show){const w=g('lrff_wrap_'+id);if(w)w.style.display=show?'block':'none';}

// lr_ prefix wale py functions (Link Runner se call hote the — kept for compat)
async function lrLoadPyConfig(){ await adharLoadConfig(); }
async function lrSavePyConfig(){ await adharSaveConfig(); }

// ═══════════════════════════════════════════════════════════
// 👾 AADHAAR BOT JAVASCRIPT (Separate Section)
// ═══════════════════════════════════════════════════════════
const _abElMap={
  'ab-token':'py_bot_token','ab-proxy':'py_uidai_proxy',
  'ab-fetch-cmd':'py_fetch_cmd','ab-cancel-cmd':'py_cancel_cmd','ab-refresh-cmd':'py_refresh_cmd',
  'ab-start-msg':'py_start_msg','ab-loading-steps':'py_loading_steps','ab-otp-steps':'py_otp_steps',
  'ab-captcha-msg':'py_captcha_msg','ab-otp-msg':'py_otp_msg',
  'ab-success-msg':'py_success_msg','ab-cancel-msg':'py_cancel_msg','ab-error-prefix':'py_error_prefix',
};

function adharBotInit(){ adharLoadConfig(); adharLoadLogs(); adharLoadSessions(); adharCheckBotInfo(); }

async function adharLoadConfig(){
  const r=await api('lr_get_py_config');if(!r.ok){toast('Config load failed','error');return;}
  const d=r.data||{};
  Object.entries(_abElMap).forEach(([elId,key])=>{const el=g(elId);if(el)el.value=d[key]||'';});
}

async function adharSaveConfig(){
  const payload={};
  Object.entries(_abElMap).forEach(([elId,key])=>{const el=g(elId);if(el)payload[key]=el.value;});
  const r=await api('lr_save_py_config',payload);
  const res=g('ab-save-result');
  if(r.ok){
    toast('✅ Aadhaar Bot config saved!','success');
    if(res){res.style.display='block';res.innerHTML='<span style="color:var(--g)">✅ Saved! <code>bot_config.json</code> updated.</span>';}
    adharLoadLogs();
  }else{
    toast('Error: '+(r.error||''),'error');
    if(res){res.style.display='block';res.innerHTML='<span style="color:var(--r)">❌ '+(r.error||'Save failed')+'</span>';}
  }
}

async function adharSaveSection(section){
  // Save only specific section fields
  const sectionMap={
    credentials:['ab-token','ab-proxy','ab-fetch-cmd','ab-cancel-cmd','ab-refresh-cmd'],
    messages:['ab-start-msg','ab-captcha-msg','ab-otp-msg','ab-success-msg','ab-cancel-msg','ab-error-prefix'],
    loading:['ab-loading-steps','ab-otp-steps'],
  };
  const resultIds={credentials:'ab-cred-result',messages:'ab-msg-result',loading:'ab-load-result'};
  const fields=sectionMap[section]||[];
  const payload={};
  fields.forEach(elId=>{const key=_abElMap[elId];const el=g(elId);if(key&&el)payload[key]=el.value;});
  const r=await api('lr_save_py_config',payload);
  const res=g(resultIds[section]);
  if(r.ok){
    toast('✅ '+section.charAt(0).toUpperCase()+section.slice(1)+' saved!','success');
    if(res){res.style.display='block';res.innerHTML='<span style="color:var(--g)">✅ Saved!</span>';}
    adharLoadLogs();
  }else{
    toast('❌ Save failed','error');
    if(res){res.style.display='block';res.innerHTML='<span style="color:var(--r)">❌ '+(r.error||'Failed')+'</span>';}
  }
}

// ── Aadhaar Bot — Webhook ─────────────────────────────────
async function adharSetWebhook(){
  const tok=g('ab-token')?.value.trim();
  toast('Setting webhook...','info');
  const r=await api('ab_set_webhook',{token:tok||''});
  const card=g('ab-status-card');const body=g('ab-status-body');const title=g('ab-status-title');
  card.style.display='block';title.textContent='🔗 Webhook Status';
  if(r.ok){
    toast('✅ Webhook set!','success');
    body.innerHTML=`<div style="font-size:12px;line-height:2">
      <span style="color:var(--g)">✅ Webhook set successfully!</span><br>
      <b>URL:</b> <code style="color:#63b3ed;word-break:break-all">${r.webhook_url||''}</code><br>
      <b>TG Response:</b> <code style="font-size:11px">${JSON.stringify(r.tg||{})}</code>
    </div>`;
  }else{
    toast('❌ '+(r.error||r.tg?.description||'Failed'),'error');
    body.innerHTML=`<div style="color:var(--r);font-size:12px">❌ ${r.error||JSON.stringify(r.tg||{})}</div>`;
  }
}

async function adharRemoveWebhook(){
  const r=await api('ab_remove_webhook');
  r.ok?toast('Webhook removed','info'):toast('Error: '+(r.error||''),'error');
}

// ── Aadhaar Bot — Bot Info / Status ──────────────────────
async function adharCheckBotInfo(){
  toast('Checking bot status...','info');
  const r=await api('ab_bot_info');
  const card=g('ab-status-card');const body=g('ab-status-body');const title=g('ab-status-title');
  card.style.display='block';title.textContent='🔍 Bot Status';
  if(!r.ok){body.innerHTML=`<div style="color:var(--r);font-size:12px">❌ ${r.error||'Token not set ya invalid'}</div>`;toast('❌ '+(r.error||''),'error');return;}
  const me=r.me||{};const wh=r.webhook||{};
  const whOk=!!(wh.url);
  body.innerHTML=`<div style="font-size:12px;line-height:2.2">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;background:var(--s2);padding:10px;border-radius:8px">
      <span style="font-size:28px">🤖</span>
      <div>
        <div style="font-weight:700;color:var(--t)">${me.first_name||'Unknown'} <span style="color:var(--td);font-weight:400">@${me.username||'?'}</span></div>
        <div style="font-size:11px;color:var(--td)">ID: <code>${me.id||'?'}</code></div>
      </div>
      <span style="margin-left:auto;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;${whOk?'background:rgba(57,255,20,.15);color:var(--g);border:1px solid rgba(57,255,20,.3)':'background:rgba(255,45,85,.15);color:var(--r);border:1px solid rgba(255,45,85,.3)'}">${whOk?'🟢 ONLINE':'🔴 OFFLINE'}</span>
    </div>
    <b>Webhook URL:</b> <code style="font-size:11px;color:${whOk?'var(--g)':'var(--r)'};word-break:break-all">${wh.url||'Not set'}</code><br>
    <b>Pending Updates:</b> <code>${wh.pending_update_count??0}</code><br>
    ${wh.last_error_message?`<b style="color:var(--r)">Last Error:</b> <code style="color:var(--r)">${wh.last_error_message}</code><br>`:''}
    <b>Bot can join groups:</b> ${me.can_join_groups?'✅':'❌'}<br>
    <b>Can read all messages:</b> ${me.can_read_all_group_messages?'✅':'❌'}
  </div>`;
  toast('✅ Bot info loaded','success');
}

// ── Aadhaar Bot — Test Message ────────────────────────────
async function adharSendTestMsg(){
  const cid=g('ab-test-chat')?.value.trim();
  const txt=g('ab-test-text')?.value.trim();
  if(!cid){toast('Chat ID dalo pehle','error');return;}
  toast('Sending...','info');
  const r=await api('ab_send_test',{chat_id:cid,text:txt});
  const res=g('ab-test-result');
  if(res){res.style.display='block';}
  if(r.ok){
    toast('✅ Message sent!','success');
    if(res)res.innerHTML='<span style="color:var(--g)">✅ Message successfully sent to <code>'+cid+'</code></span>';
  }else{
    toast('❌ '+(r.tg?.description||r.error||'Failed'),'error');
    if(res)res.innerHTML='<span style="color:var(--r)">❌ '+(r.tg?.description||r.error||'Send failed')+'</span>';
  }
}

// ── Aadhaar Bot — Sessions ────────────────────────────────
async function adharLoadSessions(){
  const r=await api('ab_get_sessions');
  const card=g('ab-status-card');const body=g('ab-status-body');const title=g('ab-status-title');
  const sessBody=g('ab-sessions-body');
  if(!r.ok){if(sessBody)sessBody.innerHTML='<div style="color:var(--r);font-size:12px">Error loading sessions</div>';return;}
  const sessions=r.sessions||{};const total=r.total||0;
  if(total===0){if(sessBody)sessBody.innerHTML='<div style="color:var(--g);font-size:12px;text-align:center;padding:12px">✅ Koi active session nahi hai.</div>';return;}
  let rows='';
  Object.entries(sessions).forEach(([cid,sess])=>{
    const step=sess.step??0;const total2=sess.fields?.length??0;
    const linkId=sess.link_id||'?';
    const answers=Object.entries(sess.answers||{}).map(([k,v])=>`<b>${k}:</b> ${v}`).join(' | ')||'—';
    rows+=`<tr>
      <td style="font-family:monospace;font-size:11px">${cid}</td>
      <td><code style="font-size:11px">${linkId}</code></td>
      <td style="color:var(--c)">${step}/${total2}</td>
      <td style="font-size:11px;color:var(--td)">${answers}</td>
      <td><button class="btn bd bsm" onclick="adharDeleteSession('${cid}')">🗑️</button></td>
    </tr>`;
  });
  if(sessBody)sessBody.innerHTML=`<div style="margin-bottom:8px;font-size:12px;color:var(--td)">Active Sessions: <b style="color:#63b3ed">${total}</b></div><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="color:var(--td)"><th style="padding:6px;text-align:left">Chat ID</th><th>Link</th><th>Step</th><th>Answers</th><th>Del</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  toast('Sessions loaded','info');
}

async function adharDeleteSession(cid){
  const r=await api('ab_delete_session',{chat_id:cid});
  r.ok?toast('Session deleted: '+cid,'info'):toast('Error','error');
  adharLoadSessions();
}

async function adharClearSessions(){
  if(!confirm('Sab active sessions clear karein?'))return;
  const r=await api('ab_clear_sessions');
  r.ok?toast('✅ All sessions cleared','success'):toast('Error','error');
  const sb=g('ab-sessions-body');if(sb)sb.innerHTML='<div style="color:var(--g);font-size:12px;text-align:center;padding:12px">✅ All sessions cleared.</div>';
}

// ── Aadhaar Bot — Logs ────────────────────────────────────
async function adharLoadLogs(){
  const r=await api('ab_get_logs');const box=g('ab-log-box');if(!box)return;
  if(!r.ok||!r.data?.length){box.innerHTML='<div style="color:var(--tf)">No logs yet.</div>';return;}
  box.innerHTML=r.data.map(l=>`<div><span style="color:var(--tf)">[${new Date(l.time).toLocaleTimeString()}]</span> <span style="color:var(--${l.type==='success'?'g':l.type==='error'?'r':l.type==='warn'?'y':'c'})">${l.text}</span></div>`).join('');
}
async function adharClearLogs(){
  if(!confirm('Sab logs delete karein?'))return;
  await api('ab_clear_logs');adharLoadLogs();toast('Logs cleared','info');
}

async function adharResetDefaults(){
  if(!confirm('Sab default values restore karein?'))return;
  const defaults={
    py_bot_token:'',py_uidai_proxy:'',
    py_fetch_cmd:'/fetch',py_cancel_cmd:'/cancel',py_refresh_cmd:'/refresh',
    py_start_msg:"👾 <b>Aadhaar Retrieve Bot</b> — Online ✅\n\n📌 <b>Command:</b>\n<code>/fetch <mobile> <fullname></code>\n\nExample:\n<code>/fetch 9876543210 Ravi Kumar</code>",
    py_loading_steps:"🔐 Secure tunnel initialize ho raha hai...\n🛰️ UIDAI node se connect ho raha hai...\n🧬 Session payload inject ho raha hai...\n🔍 Biometric endpoint resolve ho raha hai...\n⚡ Sandbox bypass ho raha hai...\n🗝️ Identity matrix decrypt ho rahi hai...\n📋 Form fill ho raha hai...\n📸 Captcha capture ho raha hai...",
    py_otp_steps:"🔐 OTP token validate ho raha hai...\n🧬 Biometric hash cross-reference ho raha hai...\n📂 Encrypted Aadhaar file locate ho rahi hai...\n⬇️ Document decrypt aur package ho raha hai...\n✅ Document secured. Bhej raha hoon...",
    py_captcha_msg:"📸 <b>Captcha ready hai!</b>\n\nNeeche captcha image dekho aur <b>text reply karo.</b>\n<i>/refresh = naya captcha | /cancel = band karo</i>",
    py_otp_msg:"📲 <b>OTP bheja gaya!</b>\n📱 <code>{mobile}</code> pe OTP aaya hoga.\n\n🔢 <b>OTP reply karo:</b>\n<i>/cancel = band karo</i>",
    py_success_msg:"✅ <b>Aadhaar document ready!</b>\n🔒 <i>Yeh file sirf aapke liye hai. Safely store karo.</i>",
    py_cancel_msg:"❌ <b>Process cancel kar diya.</b>\nDobara shuru karne ke liye /fetch karo.",
    py_error_prefix:"❌ <b>Error:</b>",
  };
  Object.entries(_abElMap).forEach(([elId,key])=>{const el=g(elId);if(el)el.value=defaults[key]||'';});
  toast('Defaults restored! Save karo apply karne ke liye.','info');
}

// ─── Python Adhar Debugger ────────────────────────────────
function lrTogglePyDebugger(){
  const d=g('lr-py-debugger');
  if(d) d.style.display=d.style.display==='none'?'block':'none';
}

async function lrParsePython(){
  const code=g('lr-py-input')?.value||'';
  if(!code.trim()){toast('Python code paste karo pehle','error');return;}
  toast('Parsing Python...','info');
  const r=await api('parse_python',{python:code});
  const resBox=g('lr-py-result');
  if(!r.ok||!r.parsed){
    toast('Parse failed — check Python format','error');
    if(resBox){resBox.style.display='block';resBox.innerHTML='<span style="color:var(--r)">❌ Could not parse. Make sure it is a valid requests.get/post/put/delete snippet.</span>';}
    return;
  }
  const p=r.parsed;
  // Build a new link from parsed data
  const id='py_'+Date.now();
  const newLink={
    id,
    name: 'Python Import '+(new Date().toLocaleTimeString()),
    enabled: true,
    url: p.url||'',
    method: p.method||'GET',
    headers: p.headers_str||'',
    body: p.body||'',
    timeout: 30,
    ssl_verify: true,
    response_path: '',
    reply_template: '📌 <b>{name}</b>\n\n{response}',
    error_message: '⚠️ <b>{name}</b> failed!\nHTTP: <code>{http_code}</code>',
    send_on_error: false,
    chat_id: '',
    screenshot_mode: false,
    screenshot_caption: '📸 <b>{name}</b>\n🌐 <code>{url}</code>\n🕐 {ts}',
  };
  _lrLinks.push(newLink);
  lrRenderLinks();
  // Scroll to new link
  const c=g('lr-links-container');if(c)c.lastElementChild?.scrollIntoView({behavior:'smooth'});

  const parts=[];
  if(p.url)parts.push('✅ URL: <code>'+lrEsc(p.url.slice(0,60))+(p.url.length>60?'...':'')+'</code>');
  if(p.method&&p.method!=='GET')parts.push('✅ Method: <b>'+lrEsc(p.method)+'</b>');
  if(p.headers_str)parts.push('✅ Headers: '+p.headers_str.split('\n').length+' line(s)');
  if(p.body)parts.push('✅ Body extracted');

  if(resBox){
    resBox.style.display='block';
    resBox.innerHTML='<b style="color:var(--g)">✅ Import Successful! New link added.</b><br><br>'+parts.join('<br>');
  }
  toast('✅ Python imported as new link! Click 💾 Save All.','success');
}

async function lrParsePythonDebug(){
  const code=g('lr-py-input')?.value||'';
  if(!code.trim()){toast('Python code paste karo pehle','error');return;}
  toast('Parsing...','info');
  const r=await api('parse_python',{python:code});
  const resBox=g('lr-py-result');
  if(!r.ok||!r.parsed){
    if(resBox){resBox.style.display='block';resBox.innerHTML='<span style="color:var(--r)">❌ Parse failed</span>';}
    return;
  }
  const p=r.parsed;
  if(resBox){
    resBox.style.display='block';
    resBox.innerHTML=
      '<b style="color:#bf5af2">🐍 Parsed Result:</b><br><br>'+
      '<b>Method:</b> <span style="color:var(--g)">'+(p.method||'GET')+'</span><br>'+
      '<b>URL:</b> <code style="color:var(--c);word-break:break-all">'+(lrEsc(p.url)||'<span style="color:var(--r)">NOT FOUND</span>')+'</code><br><br>'+
      '<b>Headers:</b><br><pre style="color:var(--td);font-size:11px;white-space:pre-wrap;margin-top:4px">'+(lrEsc(p.headers_str)||'(none)')+'</pre>'+
      '<b>Body:</b><br><pre style="color:var(--td);font-size:11px;white-space:pre-wrap;margin-top:4px">'+(lrEsc(p.body)||'(none)')+'</pre>';
  }
  toast('Debug complete — result below','success');
}
</script></body></html>