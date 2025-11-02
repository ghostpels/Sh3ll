<?php
// Mulai session untuk menangani login
session_start();

// --- 1. KONFIGURASI & KEAMANAN DASAR ---

// !! GANTI PASSWORD INI DENGAN PASSWORD YANG SANGAT KUAT !!
$password = 'PasswordSangatRahasia123!';

// --- 1A. Enhanced Detection Patterns (Permintaan Anda) ---
$signatures = [
    // Basic dangerous functions
    'eval(', 'system(', 'passthru(', 'shell_exec(', 'exec(', 'popen(', 'proc_open(',
    'base64_decode', 'preg_replace', 'move_uploaded_file', 'php_uname', 'fsockopen(',
    
    // Advanced patterns
    'create_function(', 'assert(', 'call_user_func(', 'call_user_func_array(',
    'file_put_contents(', 'fwrite(', 'fopen(', 'unlink(', 'rmdir(',
    'curl_exec(', 'file_get_contents(', 'readfile(',
    
    // Obfuscation patterns
    'gzinflate(', 'str_rot13(', 'convert_uudecode(',
    
    // Web shell specific
    '$_GET["cmd"]', '$_POST["pass"]', '$_REQUEST["action"]',
    
    // File upload patterns
    '$_FILES', 'upload', 'multipart/form-data',
];

// --- 2. Score-Based Risk Assessment (Permintaan Anda) ---
// Memberikan score berbeda untuk setiap pattern
$signature_scores = [
    // Kritis (Eksekusi kode langsung)
    'eval(' => 10,
    'system(' => 10,
    'passthru(' => 10,
    'shell_exec(' => 10,
    'exec(' => 10,
    'popen(' => 10,
    'proc_open(' => 10,
    'assert(' => 10,
    'preg_replace' => 8, // (Berbahaya dengan /e modifier)
    'create_function(' => 8,
    
    // Tinggi (Potensi RCE atau webshell)
    '$_GET["cmd"]' => 8,
    '$_POST["pass"]' => 8,
    '$_REQUEST["action"]' => 8,
    'fsockopen(' => 7, // Reverse shell
    'call_user_func(' => 6,
    'call_user_func_array(' => 6,

    // Sedang (Manipulasi file, Obfuscation)
    'file_put_contents(' => 5,
    'base64_decode' => 5, // Sering dipakai untuk obfuscation
    'gzinflate(' => 5,
    'move_uploaded_file' => 5,
    '$_FILES' => 4,
    'fwrite(' => 4,
    'fopen(' => 3,
    'str_rot13(' => 3,
    'convert_uudecode(' => 3,

    // Rendah (Info gathering, tapi bisa jadi bagian dari file yang sah)
    'file_get_contents(' => 2,
    'readfile(' => 2,
    'curl_exec(' => 2,
    'php_uname' => 2,
    'unlink(' => 2,
    'rmdir(' => 2,
    'upload' => 1,
    'multipart/form-data' => 1,
];

// Direktori yang akan di-scan
$scan_dir = __DIR__;
$self_script = basename(__FILE__);
$suspicious_files = [];

// --- 3. FUNGSI BANTUAN (Termasuk Permintaan Anda) ---

/**
 * Mengubah path file di server menjadi URL
 */
function get_file_url($file_path) {
    $document_root = realpath($_SERVER['DOCUMENT_ROOT']);
    $file_path = realpath($file_path);
    $relative_path = str_replace($document_root, '', $file_path);
    $relative_path = str_replace(DIRECTORY_SEPARATOR, '/', $relative_path);
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    return $protocol . '://' . $host . $relative_path;
}

/**
 * Mengecek status HTTP dari sebuah URL menggunakan cURL.
 */
function check_http_status($url) {
    if (!function_exists('curl_init')) return -1;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_USERAGENT => 'PHP-Scanner-Bot'
    ]);
    @curl_exec($ch);
    $http_code = curl_errno($ch) ? 0 : curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return (int)$http_code;
}

/**
 * 3. Content Analysis & Obfuscation Detection (Permintaan Anda)
 */
function detect_obfuscation($content) {
    $obfuscation_indicators = [
        '/\/\*+.*eval.*\*+\//is', // Comment stuffing dengan eval
        '/base64_decode.*base64_decode/', // Multiple encoding
        '/eval\s*\(\s*base64_decode/', // Eval dengan base64
        '/\x[0-9a-f]{2}/i', // Hex encoding (bisa memicu false positive)
        '/\$\w+\s*=\s*\$\w+\s*\.\s*\$\w+/', // Complex string concatenation
    ];
    
    foreach ($obfuscation_indicators as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    return false;
}

/**
 * 4. File Metadata Analysis (Permintaan Anda)
 */
function analyze_file_metadata($file_path) {
    if (!file_exists($file_path)) return [];
    
    $stats = [];
    $stats['size'] = filesize($file_path);
    $stats['modified'] = filemtime($file_path);
    $stats['permissions'] = substr(sprintf('%o', fileperms($file_path)), -4);
    
    // Deteksi file baru (modifikasi < 24 jam)
    $stats['is_recent'] = (time() - $stats['modified']) < 86400; // 86400 detik = 24 jam
    
    // Deteksi permission mencurigakan (bisa dieksekusi oleh publik)
    $stats['suspicious_perms'] = in_array($stats['permissions'], ['0777', '0666', '0755', '0644']); // 0755 dan 0644 sangat umum, tapi tetap dicatat
    
    return $stats;
}

/**
 * Memberikan kelas warna berdasarkan skor risiko
 */
function get_risk_level($score) {
    if ($score >= 30) {
        return ['Kritis', 'risk-critical'];
    } elseif ($score >= 15) {
        return ['Tinggi', 'risk-high'];
    } elseif ($score >= 5) {
        return ['Sedang', 'risk-medium'];
    } else {
        return ['Rendah', 'risk-low'];
    }
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
    ini_set('max_execution_time', 300); // Tingkatkan waktu eksekusi untuk scan
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

                    // 1. Cek Signature & Hitung Skor
                    foreach ($signatures as $sig) {
                        if (stripos($content, $sig) !== false) {
                            $found_signatures[] = $sig;
                            $total_score += $signature_scores[$sig] ?? 1; // Default 1 jika tidak ada di list skor
                        }
                    }

                    // 2. Cek Obfuscation
                    $is_obfuscated = detect_obfuscation($content);
                    if ($is_obfuscated) {
                        $total_score += 10; // Tambah skor bonus jika terdeteksi obfuscation
                    }

                    // 3. Cek Metadata
                    $metadata = analyze_file_metadata($file_path);
                    if ($metadata['is_recent']) {
                        $total_score += 5; // Tambah skor bonus jika file baru diubah
                    }

                    // Hanya tampilkan jika ada yang mencurigakan (skor > 0)
                    if ($total_score > 0) {
                        $file_url = get_file_url($file_path);
                        $http_status = check_http_status($file_url);
                        
                        $suspicious_files[] = [
                            'path'       => $file_path,
                            'signatures' => $found_signatures,
                            'url'        => $file_url,
                            'status'     => $http_status,
                            'score'      => $total_score,
                            'is_obfuscated' => $is_obfuscated,
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
    <title>PHP Webshell Scanner (Advanced)</title>
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
        .filter-controls { background: #f9f9f9; padding: 15px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 20px; }
        .filter-controls label { font-weight: bold; margin-right: 10px; }
        .filter-controls select { padding: 5px; border-radius: 4px; border: 1px solid #ccc; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; word-wrap: break-word; }
        th { background: #f9f9f9; }
        th:nth-child(1) { width: 40%; } /* Path */
        th:nth-child(2) { width: 20%; } /* Indikasi */
        th:nth-child(3) { width: 10%; } /* Skor */
        th:nth-child(4) { width: 10%; } /* Status */
        th:nth-child(5) { width: 20%; } /* Aksi */
        td code { background: #eee; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; display: inline-block; }
        .actions form { display: inline-block; }
        .actions .btn { padding: 5px 10px; text-decoration: none; border-radius: 4px; color: #fff; display: inline-block; margin: 2px 0; }
        .btn-view { background: #0275d8; }
        .btn-delete { background: #d9534f; border: none; font-size: 1em; cursor: pointer; }
        .status-200 { color: green; font-weight: bold; }
        .status-other { color: red; font-weight: bold; }
        .status-warn { color: orange; font-weight: bold; }
        .meta-recent { background: #fff3cd; color: #856404; padding: 3px 6px; border-radius: 4px; font-weight: bold; display: inline-block; margin-top: 5px; }
        .meta-perms { font-family: monospace; font-size: 0.9em; color: #555; }
        .obfuscated { background: #d9534f; color: white; padding: 3px 6px; border-radius: 4px; font-weight: bold; display: inline-block; margin-top: 5px; }
        .risk-critical { font-weight: bold; color: #fff; background-color: #d9534f; padding: 3px 6px; border-radius: 4px; }
        .risk-high { font-weight: bold; color: #d9534f; }
        .risk-medium { font-weight: bold; color: #f0ad4e; }
        .risk-low { color: #0275d8; }
    </style>
    
    <script>
        function filterResults() {
            var filterValue = document.getElementById('filterOptions').value;
            var table = document.getElementById('resultsTable');
            var rows = table.getElementsByTagName('tr');
            for (var i = 1; i < rows.length; i++) {
                var row = rows[i];
                if (filterValue === 'all') {
                    row.style.display = '';
                } else if (filterValue === '200') {
                    if (row.classList.contains('status-200-row')) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PHP Webshell Scanner (Advanced)</h1>
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
                <?php if (isset($login_error)) : ?>
                    <p class="error"><?php echo $login_error; ?></p>
                <?php endif; ?>
            </div>

        <?php else : ?>
            <div class="content">
                <h2>Hasil Scan</h2>
                <p>Memindai direktori: <code><?php echo htmlspecialchars($scan_dir); ?></code></p>
                
                <?php echo $delete_message; // Tampilkan pesan sukses/gagal hapus ?>

                <?php if (isset($scan_error)) : ?>
                    <p class="error"><?php echo $scan_error; ?></p>
                <?php endif; ?>
                
                <?php if (function_exists('curl_init') === false) : ?>
                    <p class="error">Peringatan: Ekstensi PHP cURL tidak ditemukan. Fitur cek status HTTP tidak akan berfungsi.</p>
                <?php endif; ?>

                <?php if (empty($suspicious_files)) : ?>
                    <p style="color:green; font-weight:bold;">Tidak ada file mencurigakan yang ditemukan.</p>
                <?php else : ?>
                    <p class="error">Ditemukan <?php echo count($suspicious_files); ?> file yang mencurigakan!</p>
                    
                    <div class="filter-controls">
                        <label for="filterOptions">Filter Tampilan:</label>
                        <select id="filterOptions" onchange="filterResults()">
                            <option value="all">Tampilkan Semua (Direkomendasikan)</option>
                            <option value="200">Hanya Tampilkan Status 200 (OK)</option>
                        </select>
                    </div>

                    <table id="resultsTable">
                        <thead>
                            <tr>
                                <th>File Path & Metadata</th>
                                <th>Indikasi</th>
                                <th>Risk Score</th>
                                <th>Status HTTP</th>
                                <th>Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($suspicious_files as $file) : ?>
                                <?php
                                    $status = $file['status'];
                                    $row_class = ($status == 200) ? 'status-200-row' : 'status-other-row';
                                    list($risk_label, $risk_class) = get_risk_level($file['score']);
                                ?>
                                <tr class="<?php echo $row_class; ?>">
                                    <td>
                                        <code><?php echo htmlspecialchars($file['path']); ?></code>
                                        <div style="margin-top: 5px;">
                                            <span class="meta-perms">Perms: <?php echo htmlspecialchars($file['metadata']['permissions']); ?></span> | 
                                            <span class="meta-perms">Size: <?php echo number_format($file['metadata']['size'] / 1024, 2); ?> KB</span>
                                        </div>
                                        <?php if ($file['metadata']['is_recent']) : ?>
                                            <span class="meta-recent">DIUBAH < 24 JAM</span>
                                        <?php endif; ?>
                                    </td>
                                    
                                    <td>
                                        <?php if ($file['is_obfuscated']) : ?>
                                            <span class="obfuscated">TERDETEKSI OBFUSCATION</span>
                                        <?php endif; ?>
                                        <?php foreach ($file['signatures'] as $sig) : ?>
                                            <code><?php echo htmlspecialchars($sig); ?> (Score: +<?php echo $signature_scores[$sig] ?? 1; ?>)</code><br>
                                        <?php endforeach; ?>
                                    </td>
                                    
                                    <td>
                                        <span class="<?php echo $risk_class; ?>">
                                            <?php echo $file['score']; ?><br>(<?php echo $risk_label; ?>)
                                        </span>
                                    </td>

                                    <td>
                                        <?php
                                            if ($status == 200) echo '<span class="status-200">' . $status . ' (OK)</span>';
                                            elseif ($status == 0) echo '<span class="status-warn">' . $status . ' (Koneksi Gagal)</span>';
                                            elseif ($status == -1) echo '<span class="status-warn">(cURL nonaktif)</span>';
                                            else echo '<span class="status-other">' . $status . ' (Error ' . $status . ')</span>';
                                        ?>
                                    </td>
                                    
                                    <td class="actions">
                                        <a href="<?php echo htmlspecialchars($file['url']); ?>" target="_blank" class="btn btn-view">Cek URL</a>
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
