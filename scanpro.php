<?php
// Mulai session untuk menangani login
session_start();

// --- 1. KONFIGURASI & KEAMANAN DASAR ---

// !! GANTI PASSWORD INI DENGAN PASSWORD YANG SANGAT KUAT !!
$password = 'PasswordSangatRahasia123!';

// Atur agar skrip PHP tidak timeout (server web mungkin tetap mematikannya, tapi ini membantu)
@ini_set('max_execution_time', 0);
@set_time_limit(0);

// --- 1A. Enhanced Detection Patterns ---
$signatures = [
    'eval(', 'system(', 'passthru(', 'shell_exec(', 'exec(', 'popen(', 'proc_open(',
    'base64_decode', 'preg_replace', 'move_uploaded_file', 'php_uname', 'fsockopen(',
    'create_function(', 'assert(', 'call_user_func(', 'call_user_func_array(',
    'file_put_contents(', 'fwrite(', 'fopen(', 'unlink(', 'rmdir(',
    'curl_exec(', 'file_get_contents(', 'readfile(', 'gzinflate(', 'str_rot13(',
    'convert_uudecode(', '$_GET["cmd"]', '$_POST["pass"]', '$_REQUEST["action"]',
    '$_FILES', 'upload', 'multipart/form-data',
];

// --- 2. Score-Based Risk Assessment ---
$signature_scores = [
    // Kritis (Eksekusi kode langsung)
    'eval(' => 10, 'system(' => 10, 'passthru(' => 10, 'shell_exec(' => 10, 'exec(' => 10,
    'popen(' => 10, 'proc_open(' => 10, 'assert(' => 10, 'preg_replace' => 8,
    'create_function(' => 8,
    
    // Tinggi (Potensi RCE atau webshell)
    '$_GET["cmd"]' => 8, '$_POST["pass"]' => 8, '$_REQUEST["action"]' => 8,
    'fsockopen(' => 7, 'call_user_func(' => 6, 'call_user_func_array(' => 6,

    // Sedang (Manipulasi file, Obfuscation)
    'file_put_contents(' => 5, 'base64_decode' => 5, 'gzinflate(' => 5,
    'move_uploaded_file' => 5, '$_FILES' => 4, 'fwrite(' => 4, 'fopen(' => 3,
    'str_rot13(' => 3, 'convert_uudecode(' => 3,

    // Rendah (Fungsi umum, bisa jadi noise)
    'file_get_contents(' => 1, 'readfile(' => 1, 'curl_exec(' => 1, 'php_uname' => 2,
    'unlink(' => 2, 'rmdir(' => 2, 'upload' => 1, 'multipart/form-data' => 1,
];

// Kata kunci untuk bonus kombinasi
$danger_keywords = ['eval(', 'system(', 'passthru(', 'shell_exec(', 'exec(', 'popen(', 'proc_open(', 'assert(', 'preg_replace', 'create_function('];
$obfusc_keywords = ['base64_decode', 'gzinflate', 'str_rot13', 'convert_uudecode'];

$scan_dir = __DIR__;
$self_script = basename(__FILE__);
$suspicious_files = [];

// --- 3. FUNGSI BANTUAN ---

function get_file_url($file_path) {
    $document_root = realpath($_SERVER['DOCUMENT_ROOT']);
    $file_path = realpath($file_path);
    $relative_path = str_replace($document_root, '', $file_path);
    $relative_path = str_replace(DIRECTORY_SEPARATOR, '/', $relative_path);
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    return $protocol . '://' . $host . $relative_path;
}

function detect_obfuscation($content) {
    $obfuscation_indicators = [
        '/\/\*+.*eval.*\*+\//is', 'base64_decode.*base64_decode',
        '/eval\s*\(\s*base64_decode/', '/\x[0-9a-f]{2}/i',
        '/\$\w+\s*=\s*\$\w+\s*\.\s*\$\w+/',
    ];
    foreach ($obfuscation_indicators as $pattern) {
        if (preg_match($pattern, $content)) return true;
    }
    return false;
}

function analyze_file_metadata($file_path) {
    if (!file_exists($file_path)) return [];
    $stats = [];
    $stats['size'] = filesize($file_path);
    $stats['modified'] = filemtime($file_path);
    $stats['permissions'] = substr(sprintf('%o', fileperms($file_path)), -4);
    $stats['is_recent'] = (time() - $stats['modified']) < 86400; // 24 jam
    return $stats;
}

function get_risk_level($score) {
    if ($score >= 30) return ['Kritis', 'risk-critical'];
    if ($score >= 15) return ['Tinggi', 'risk-high'];
    if ($score >= 5) return ['Sedang', 'risk-medium'];
    return ['Rendah', 'risk-low'];
}

// --- 4. LOGIKA APLIKASI UTAMA ---

// A. Logika Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    unset($_SESSION['logged_in']);
    header('Location: ' . $self_script);
    exit;
}
// B. Logika Login
if (isset($_POST['password'])) {
    if ($_POST['password'] === $password) {
        $_SESSION['logged_in'] = true;
    } else {
        $login_error = 'Password salah!';
    }
}
// C. Logika Hapus File
$delete_message = '';
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    if (isset($_POST['action']) && $_POST['action'] === 'delete' && isset($_POST['file_path'])) {
        $file_to_delete = realpath($_POST['file_path']);
        if ($file_to_delete && strpos($file_to_delete, realpath($scan_dir)) === 0 && is_file($file_to_delete)) {
            if (unlink($file_to_delete)) {
                $delete_message = '<p class="message-success"><strong>Sukses:</strong> File ' . htmlspecialchars($file_to_delete) . ' telah dihapus.</p>';
            } else {
                $delete_message = '<p class="message-error"><strong>Gagal:</strong> Tidak dapat menghapus file ' . htmlspecialchars($file_to_delete) . '.</p>';
            }
        } else {
            $delete_message = '<p class="message-error"><strong>Gagal:</strong> File tidak valid atau tidak ditemukan.</p>';
        }
    }
}

// D. Logika Scan File (Telah Di-upgrade)
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($scan_dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getFilename() !== $self_script) {
                $ext = strtolower($file->getExtension());
                if (in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'sh', 'pl', 'py'])) {
                    
                    $file_path = $file->getRealPath();
                    $content = @file_get_contents($file_path);
                    if ($content === false) continue;

                    $found_signatures = [];
                    $total_score = 0;
                    $bonus_notes = []; // Untuk menampilkan bonus di tabel

                    // 1. Cek Signature & Hitung Skor dasar
                    foreach ($signatures as $sig) {
                        if (stripos($content, $sig) !== false) {
                            $found_signatures[] = $sig;
                            $total_score += $signature_scores[$sig] ?? 1;
                        }
                    }

                    // 2. Cek Obfuscation (Regex)
                    $is_obfuscated = detect_obfuscation($content);
                    if ($is_obfuscated) {
                        $total_score += 10;
                        $bonus_notes[] = "Deteksi Obfuscation (+10)";
                    }

                    // 3. Cek Metadata
                    $metadata = analyze_file_metadata($file_path);
                    if (!empty($metadata) && $metadata['is_recent']) {
                        $total_score += 5;
                        $bonus_notes[] = "File Baru Diubah (+5)";
                    }
                    
                    // 4. (BARU) Cek Bonus Kombinasi Kritis
                    $found_danger = array_intersect($found_signatures, $danger_keywords);
                    $found_obfusc = array_intersect($found_signatures, $obfusc_keywords);

                    if (!empty($found_danger) && !empty($found_obfusc)) {
                        $total_score += 20; // Bonus besar untuk kombinasi
                        $bonus_notes[] = "Kombinasi Kritis (+20)";
                    }

                    // Hanya tampilkan jika ada yang mencurigakan (skor > 0)
                    if ($total_score > 0) {
                        $file_url = get_file_url($file_path);
                        
                        $suspicious_files[] = [
                            'path'       => $file_path,
                            'signatures' => $found_signatures,
                            'url'        => $file_url,
                            'score'      => $total_score,
                            'bonus_notes'  => $bonus_notes,
                            'metadata'   => $metadata
                        ];
                    }
                }
            }
        }
        
        // Urutkan file berdasarkan skor, dari tertinggi ke terendah
        usort($suspicious_files, function($a, $b) {
            return $b['score'] <=> $a['score'];
        });

    } catch (Exception $e) {
        $scan_error = 'Error saat scanning: ' . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Webshell Scanner (Fast & Score-Based)</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; background-color: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .header, .content, .login-form { padding: 20px; }
        .header { background: #333; color: #fff; border-bottom: 4px solid #d9534f; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .header a { color: #fff; text-decoration: none; background: #5bc0de; padding: 5px 10px; border-radius: 4px; }
        .login-form { text-align: center; }
        .login-form input[type="password"] { width: 250px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        .login-form button { padding: 10px 20px; background: #5cb85c; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        .error, .message-error { color: #d9534f; font-weight: bold; }
        .message-success { color: #5cb85c; font-weight: bold; }
        
        /* Hapus Filter Control karena sudah tidak relevan */
        .filter-controls { display: none; } 
        
        table { width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; word-wrap: break-word; }
        th { background: #f9f9f9; }
        /* Sesuaikan lebar kolom (4 kolom) */
        th:nth-child(1) { width: 45%; } /* Path */
        th:nth-child(2) { width: 30%; } /* Indikasi */
        th:nth-child(3) { width: 10%; } /* Skor */
        th:nth-child(4) { width: 15%; } /* Aksi */
        
        td code { background: #eee; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; display: inline-block; }
        .actions form { display: inline-block; }
        .actions .btn { padding: 5px 10px; text-decoration: none; border-radius: 4px; color: #fff; display: inline-block; margin: 2px 0; }
        .btn-view { background: #0275d8; }
        .btn-delete { background: #d9534f; border: none; font-size: 1em; cursor: pointer; }
        
        .meta-recent { background: #fff3cd; color: #856404; padding: 3px 6px; border-radius: 4px; font-weight: bold; display: inline-block; margin-top: 5px; }
        .meta-perms { font-family: monospace; font-size: 0.9em; color: #555; }
        .bonus-note { background: #f0ad4e; color: #fff; padding: 3px 6px; border-radius: 4px; font-weight: bold; display: inline-block; margin-top: 5px; font-size: 0.9em; }
        .bonus-note.critical { background: #d9534f; }
        
        .risk-critical { font-weight: bold; color: #fff; background-color: #d9534f; padding: 3px 6px; border-radius: 4px; }
        .risk-high { font-weight: bold; color: #d9534f; }
        .risk-medium { font-weight: bold; color: #f0ad4e; }
        .risk-low { color: #0275d8; }
    </style>
    
    </head>
<body>
    <div class="container">
        <div class="header">
            <h1>PHP Webshell Scanner (Cepat & Fokus Skor)</h1>
            <?php if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) : ?>
                <a href="?action=logout">Logout</a>
            <?php endif; ?>
        </div>

        <?php if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) : ?>
            <div class="login-form">
                <p>Skrip ini sangat sensitif. Silakan masukkan password untuk melanjutkan.</p>
                <form action="<?php echo $self_script; ?>" method="POST">
                    <input type="password" name="password" placeholder="Masukkan Password" required>
                    <button type="submit">Login</button>
                </form>
                <?php if (isset($login_error)) : ?><p class="error"><?php echo $login_error; ?></p><?php endif; ?>
            </div>

        <?php else : ?>
            <div class="content">
                <h2>Hasil Scan</h2>
                <p>Memindai direktori: <code><?php echo htmlspecialchars($scan_dir); ?></code></p>
                <p class="message-success">Cek Status HTTP: <strong>DINONAKTIFKAN</strong> (Mode Cepat).</p>
                
                <?php echo $delete_message; ?>
                <?php if (isset($scan_error)) : ?><p class="error"><?php echo $scan_error; ?></p><?php endif; ?>

                <?php if (empty($suspicious_files)) : ?>
                    <p style="color:green; font-weight:bold;">Tidak ada file mencurigakan yang ditemukan.</p>
                <?php else : ?>
                    <p class="error">Ditemukan <?php echo count($suspicious_files); ?> file yang mencurigakan!</p>
                    
                    <table id="resultsTable">
                        <thead>
                            <tr>
                                <th>File Path & Metadata</th>
                                <th>Indikasi & Bonus</th>
                                <th>Risk Score</th>
                                <th>Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($suspicious_files as $file) : ?>
                                <?php
                                    list($risk_label, $risk_class) = get_risk_level($file['score']);
                                ?>
                                <tr>
                                    <td>
                                        <code><?php echo htmlspecialchars($file['path']); ?></code>
                                        <?php if (!empty($file['metadata'])) : ?>
                                        <div style="margin-top: 5px;">
                                            <span class="meta-perms">Perms: <?php echo htmlspecialchars($file['metadata']['permissions']); ?></span> | 
                                            <span class="meta-perms">Size: <?php echo number_format($file['metadata']['size'] / 1024, 2); ?> KB</span>
                                        </div>
                                        <?php if ($file['metadata']['is_recent']) : ?>
                                            <span class="meta-recent">DIUBAH < 24 JAM</span>
                                        <?php endif; ?>
                                        <?php endif; ?>
                                    </td>
                                    
                                    <td>
                                        <?php foreach ($file['bonus_notes'] as $note) : ?>
                                            <span class="bonus-note <?php echo (strpos($note, 'Kritis') !== false) ? 'critical' : ''; ?>">
                                                <?php echo htmlspecialchars($note); ?>
                                            </span><br>
                                        <?php endforeach; ?>

                                        <?php foreach ($file['signatures'] as $sig) : ?>
                                            <code><?php echo htmlspecialchars($sig); ?> (+<?php echo $signature_scores[$sig] ?? 1; ?>)</code><br>
                                        <?php endforeach; ?>
                                    </td>
                                    
                                    <td>
                                        <span class="<?php echo $risk_class; ?>">
                                            <?php echo $file['score']; ?><br>(<?php echo $risk_label; ?>)
                                        </span>
                                    </td>

                                    <td class="actions">
                                        <a href="<?php echo htmlspecialchars($file['url']); ?>" target="_blank" class="btn btn-view">Cek URL (Manual)</a>
                                        <form action="<?php echo $self_script; ?>" method="POST" onsubmit="return confirm('ANDA YAKIN INGIN MENGHAPUS FILE INI?\n<?php echo htmlspecialchars($file['path']); ?>\n\nTindakan ini tidak bisa dibatalkan!');">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                            <button type="submit" class="btn btn-delete">Hapus File</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
