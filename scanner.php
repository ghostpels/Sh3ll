<?php
// webshell_scanner.php
session_start();

// Konfigurasi
$SCAN_DIRECTORIES = ['.', '../']; // Mulai dari direktori current dan parent
$EXCLUDED_DIRS = ['./vendor', './node_modules', '../vendor', '../node_modules'];
$MAX_FILE_SIZE = 5242880; // 5MB
$SELF_FILE_PATH = realpath(__FILE__); // DITAMBAHKAN: Untuk mengecualikan file ini sendiri

// Pattern untuk mendeteksi webshell
$SUSPICIOUS_PATTERNS = [
    // Basic dangerous functions
    'eval' => '/\beval\s*\(/i',
    'assert' => '/\bassert\s*\(/i',
    'preg_replace_e' => '/preg_replace\s*\(.*[\/\'"].*e.*[\/\'"]/i',
    'create_function' => '/create_function\s*\(/i',
    
    // System commands
    'system' => '/\bsystem\s*\(/i',
    'exec' => '/\bexec\s*\(/i',
    'shell_exec' => '/\bshell_exec\s*\(/i',
    'passthru' => '/\bpassthru\s*\(/i',
    'proc_open' => '/\bproc_open\s*\(/i',
    'popen' => '/\bpopen\s*\(/i',
    
    // File operations
    'file_put_contents' => '/file_put_contents\s*\(/i',
    'file_get_contents' => '/file_get_contents\s*\(/i',
    'move_uploaded_file' => '/move_uploaded_file\s*\(/i',
    'rename' => '/\brename\s*\(/i',
    'copy' => '/\bcopy\s*\(/i',
    'unlink' => '/\bunlink\s*\(/i',
    
    // Network operations
    'curl_exec' => '/\bcurl_exec\s*\(/i',
    'fsockopen' => '/\bfsockopen\s*\(/i',
    
    // Encoding/decoding
    'base64_decode' => '/base64_decode\s*\(/i',
    'gzinflate' => '/gzinflate\s*\(/i',
    'str_rot13' => '/str_rot13\s*\(/i',
    
    // Web shell specific patterns
    'cmd_param' => '/\$_GET\s*\[\s*[\'"]cmd[\'"]\s*\]/i',
    'password_param' => '/\$_POST\s*\[\s*[\'"]pass[\'"]\s*\]/i',
];

class WebShellScanner {
    private $suspiciousFiles = [];
    private $scanStats = [
        'scanned' => 0,
        'suspicious' => 0,
        'errors' => 0
    ];

    public function scanDirectory($directory, $excludedDirs = [], $maxFileSize = 5242880) {
        if (!is_dir($directory)) {
            $this->scanStats['errors']++;
            return;
        }

        try {
            $files = @scandir($directory);
            if ($files === false) {
                $this->scanStats['errors']++;
                return;
            }

            foreach ($files as $file) {
                if ($file == '.' || $file == '..') continue;

                // DIPERBAIKI: Normalisasi path
                $fullPath = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file;
                $realFullPath = @realpath($fullPath);

                if ($realFullPath === false) {
                    $this->scanStats['errors']++;
                    continue;
                }

                // DITAMBAHKAN: Pengecekan untuk mengecualikan file scanner ini sendiri
                global $SELF_FILE_PATH;
                if ($realFullPath == $SELF_FILE_PATH) continue;
                
                // DIPERBAIKI: Pengecekan eksklusi dengan realpath
                $skip = false;
                foreach ($excludedDirs as $excluded) { // $excludedDirs sekarang berisi realpath
                    if (strpos($realFullPath, $excluded) === 0) {
                        $skip = true;
                        break;
                    }
                }
                if ($skip) continue;

                // DIPERBAIKI: Gunakan realpath untuk pengecekan dan rekursi
                if (is_dir($realFullPath)) {
                    $this->scanDirectory($realFullPath, $excludedDirs, $maxFileSize);
                } else {
                    $this->scanStats['scanned']++;
                    $this->checkFile($realFullPath, $maxFileSize);
                }
            }
        } catch (Exception $e) {
            $this->scanStats['errors']++;
        }
    }

    private function checkFile($filePath, $maxFileSize) {
        global $SUSPICIOUS_PATTERNS;

        // Check file size
        $fileSize = @filesize($filePath);
        if ($fileSize === false || $fileSize > $maxFileSize) {
            return;
        }

        // Check file extension
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $suspiciousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc'];
        
        if (!in_array($extension, $suspiciousExtensions)) {
            return;
        }

        try {
            $content = @file_get_contents($filePath);
            if ($content === false) {
                return;
            }

            $suspiciousSigns = [];
            $score = 0;

            // Pattern matching
            foreach ($SUSPICIOUS_PATTERNS as $patternName => $pattern) {
                if (preg_match_all($pattern, $content, $matches)) {
                    $count = count($matches[0]);
                    $suspiciousSigns[$patternName] = $count;
                    $score += $count;
                }
            }

            // Advanced detection
            if ($this->isObfuscated($content)) {
                $suspiciousSigns['obfuscated'] = true;
                $score += 3;
            }

            if ($this->hasRemoteInclusion($content)) {
                $suspiciousSigns['remote_inclusion'] = true;
                $score += 3;
            }

            if ($this->hasUploadFeature($content)) {
                $suspiciousSigns['upload_feature'] = true;
                $score += 2;
            }

            if ($score > 0) {
                $this->suspiciousFiles[] = [
                    'path' => $filePath, // $filePath sudah berisi realpath
                    'score' => $score,
                    'signs' => $suspiciousSigns,
                    'size' => $fileSize,
                    'modified' => @date('Y-m-d H:i:s', filemtime($filePath))
                ];
                $this->scanStats['suspicious']++;
            }

        } catch (Exception $e) {
            $this->scanStats['errors']++;
        }
    }

    private function isObfuscated($content) {
        // Check for comment stuffing dengan fungsi berbahaya
        if (preg_match('/\/\*+.*eval.*\*+\//is', $content)) {
            return true;
        }

        // Check for multiple encoding
        if (preg_match('/base64_decode\s*\(.*base64_decode/', $content)) {
            return true;
        }

        // Check for complex concatenation
        if (preg_match_all('/\\$[a-z0-9_]{1,5}\s*=\s*\\$[a-z0-9_]{1,5}\s*\.\s*\\$[a-z0-9_]{1,5}/', $content) > 3) {
            return true;
        }

        return false;
    }

    private function hasRemoteInclusion($content) {
        return preg_match('/file_get_contents\s*\(\s*[\'\"](http|https|ftp):\/\//i', $content) ||
               preg_match('/curl_exec\s*\(\s*[\'\"](http|https|ftp):\/\//i', $content);
    }

    private function hasUploadFeature($content) {
        return (preg_match('/<input[^>]*type=[\'\"]file[\'\"]/i', $content) && 
                preg_match('/<form[^>]*enctype=[\'\"]multipart\/form-data[\'\"]/i', $content)) ||
               (preg_match('/\$_FILES/i', $content) && preg_match('/move_uploaded_file/i', $content));
    }

    public function getResults() {
        // Urutkan berdasarkan score tertinggi
        usort($this->suspiciousFiles, function($a, $b) {
            return $b['score'] - $a['score'];
        });
        
        return [
            'files' => $this->suspiciousFiles,
            'stats' => $this->scanStats
        ];
    }
}

// DIPINDAHKAN: Fungsi ini dipindah ke atas sebelum dipanggil untuk memperbaiki error 500
function getFileUrl($filePath) {
    // DIPERBAIKI: Gunakan realpath untuk perbandingan yang lebih akurat
    $docRoot = @realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
    $basePath = @realpath(dirname($_SERVER['SCRIPT_FILENAME']));
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    
    // $filePath sudah di-resolve ke realpath oleh scanner
    
    if ($docRoot && strpos($filePath, $docRoot) === 0) {
        $relativePath = str_replace($docRoot, '', $filePath);
        return $protocol . '://' . $host . str_replace(DIRECTORY_SEPARATOR, '/', $relativePath);
    } elseif ($basePath && strpos($filePath, $basePath) === 0) {
        $relativePath = str_replace($basePath, '', $filePath);
        $scriptPath = dirname($_SERVER['SCRIPT_NAME']);
        // Bersihkan scriptPath agar tidak duplikat
        $scriptPath = rtrim($scriptPath, '/\\');
        return $protocol . '://' . $host . $scriptPath . str_replace(DIRECTORY_SEPARATOR, '/', $relativePath);
    } else {
        // Fallback ke path relative dari root (kurang akurat tapi lebih baik daripada error)
        $relativePath = str_replace(DIRECTORY_SEPARATOR, '/', $filePath);
        // Coba hapus bagian path server jika masih ada
        if ($docRoot) {
            $relativePath = str_replace($docRoot, '', $relativePath);
        }
        return $protocol . '://' . $host . '/' . ltrim($relativePath, '/');
    }
}


// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'scan':
                set_time_limit(0); // DITAMBAHKAN: Mencegah timeout saat scan
                
                global $SCAN_DIRECTORIES, $EXCLUDED_DIRS, $MAX_FILE_SIZE;
                
                $scanner = new WebShellScanner();

                // DITAMBAHKAN: Resolve path eksklusi ke realpath
                $realExcludedDirs = [];
                foreach ($EXCLUDED_DIRS as $exDir) {
                    $realExDir = @realpath($exDir);
                    if ($realExDir) {
                        $realExcludedDirs[] = $realExDir;
                    }
                }

                // DIPERBAIKI: Gunakan realpath untuk direktori scan
                foreach ($SCAN_DIRECTORIES as $dir) {
                    $realDir = @realpath($dir);
                    if ($realDir && is_dir($realDir)) {
                        $scanner->scanDirectory($realDir, $realExcludedDirs, $MAX_FILE_SIZE);
                    }
                }
                $_SESSION['scan_results'] = $scanner->getResults();
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
                
            case 'delete':
                if (isset($_POST['file_path']) && file_exists($_POST['file_path'])) {
                    // $_POST['file_path'] seharusnya sudah realpath dari hasil scan
                    if (@unlink($_POST['file_path'])) {
                        $_SESSION['message'] = "File berhasil dihapus: " . htmlspecialchars($_POST['file_path']);
                    } else {
                        $_SESSION['error'] = "Gagal menghapus file (cek permission): " . htmlspecialchars($_POST['file_path']);
                    }
        _SESSION['file_path'] = $_POST['file_path'];
                    }
                }
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShell Scanner</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background: #f0f2f5;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .header h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        
        .header p {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        
        .btn {
            padding: 12px 24px;
            margin: 8px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        
        .btn-scan {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-view {
            background: linear-gradient(135deg, #4ecdc4 0%, #44a08d 100%);
            color: white;
        }
        
        .btn-delete {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
        }
        
        .btn-content {
            background: linear-gradient(135deg, #ffd93d 0%, #ff9a3d 100%);
            color: black;
        }
        
        .message {
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
            font-weight: 500;
        }
        
        .success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .file-list {
            margin-top: 30px;
        }
        
        .file-item {
            border: 1px solid #e1e8ed;
            padding: 20px;
            margin: 15px 0;
    _SESSION['message'] = "File berhasil dihapus: " . htmlspecialchars($_POST['file_path']);
                    } else {
                        $_SESSION['error'] = "Gagal menghapus file: " . htmlspecialchars($_POST['file_path']);
                    }
                }
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
                
            case 'view_url':
                if (isset($_POST['file_path'])) {
                    $url = getFileUrl($_POST['file_path']);
                    header("Location: $url");
                    exit;
                }
                break;
                
            case 'view_content':
                if (isset($_POST['file_path']) && file_exists($_POST['file_path'])) {
                    $content = @file_get_contents($_POST['file_path']);
                    if ($content !== false) {
                        $_SESSION['file_content'] = htmlspecialchars($content);
                                transform: translateY(-2px);
        }
        
        .file-path {
            font-weight: bold;
            color: #2c3e50;
            font-size: 16px;
            margin-bottom: 8px;
            word-break: break-all;
        }
        
        .file-score {
            color: #e74c3c;
            font-weight: bold;
            font-size: 14px;
            margin-bottom: 5px;
        }
        
        .file-size, .file-modified {
            color: #7f8c8d;
            font-size: 12px;
            margin-bottom: 3px;
        }
        
        .file-signs {
            margin: 15px 0;
        }
        
        .sign-item {
            background: #fff3cd;
            padding: 6px 12px;
            margin: 4px;
            border-radius: 20px;
            display: inline-block;
            font-size: 11px;
            font-weight: 600;
            border: 1px solid #ffeaa7;
        }
        
        .stats {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
        }
        
        .stats h3 {
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .content-preview {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            font-size: 12px;
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #34495e;
        }
        
        .high-risk {
            border-left: 6px solid #e74c3c;
            background: #fdf2f2;
        }
        
        .medium-risk {
            border-left: 6px solid #f39c12;
            background: #fef9f2;
        }
        
        .low-risk {
            border-left: 6px solid #27ae60;
            background: #f2fdf2;
        }
        
        .file-actions {
            margin-top: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
                margin: 10px;
            }
            
            .file-actions {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
                margin: 5px 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WebShell Scanner</h1>
            <p>Deteksi dan kelola file webshell yang mencurigakan pada server Anda</p>
        </div>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="message success">✅ <?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="message error">❌ <?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <div style="text-align: center; margin: 30px 0;">
            <form method="post" style="display: inline;">
                <input type="hidden" name="action" value="scan">
                <button type="submit" class="btn btn-scan">🔍 Mulai Scan Server</button>
            </form>
        </div>

        <?php if (isset($_SESSION['file_content'])): ?>
            <div class="content-preview">
                <h4 style="color: #ecf0f1; margin-bottom: 15px;">Konten File: <?php echo htmlspecialchars($_SESSION['file_path']); ?></h4>
                <pre><?php echo $_SESSION['file_content']; ?></pre>
            </div>
            <?php unset($_SESSION['file_content'], $_SESSION['file_path']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['scan_results'])): 
            $results = $_SESSION['scan_results'];
            $files = $results['files'];
            $stats = $results['stats'];
        ?>
            <div class="stats">
                <h3>📊 Statistik Scan</h3>
                <p>✅ File yang di-scan: <?php echo $stats['scanned']; ?></p>
                <p>⚠️ File mencurigakan: <?php echo $stats['suspicious']; ?></p>
                <p>❌ Error: <?php echo $stats['errors']; ?></p>
            </div>

            <?php if (!empty($files)): ?>
                <div class="file-list">
                    <h3 style="color: #e74c3c; margin-bottom: 20px;">🚨 File Mencurigakan Terdeteksi</h3>
                    <?php foreach ($files as $file): 
                        $riskClass = $file['score'] >= 10 ? 'high-risk' : ($file['score'] >= 5 ? 'medium-risk' : 'low-risk');
                    ?>
                        <div class="file-item <?php echo $riskClass; ?>">
                            <div class="file-path">📁 <?php echo htmlspecialchars($file['path']); ?></div>
                            <div class="file-score">🎯 Skor Kecurigaan: <?php echo $file['score']; ?></div>
                            <div class="file-size">📏 Ukuran: <?php echo number_format($file['size']); ?> bytes</div>
                            <div class="file-modified">🕒 Modifikasi: <?php echo $file['modified']; ?></div>
                            
                            <div class="file-signs">
                                <strong>🔍 Tanda Mencurigakan:</strong><br>
                        nbsp; border-radius: 8px;
            background: #fafbfc;
            transition: all 0.3s ease;
        }
        
        .file-item:hover {
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                      <?php foreach ($file['signs'] as $sign => $count): ?>
                                    <span class="sign-item"><?php echo htmlspecialchars("$sign: " . ($count === true ? 'Yes' : $count)); ?></span>
                                <?php endforeach; ?>
                            </div>

                            <div class="file-actions">
                                <form method="post" style="margin: 0;">
                                    <input type="hidden" name="action" value="view_content">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-content">📄 Lihat Konten</button>
                                </form>

                                <form method="post" style="margin: 0;">
                                    <input type="hidden" name="action" value="view_url">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-view">🌐 Buka URL</button>
                                </form>

                                <form method="post" style="margin: 0;">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
section class:
                                    <button type="submit" class="btn btn-delete">🗑️ Hapus</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div style="text-align: center; padding: 40px; color: #27ae60;">
                    <h3>✅ Tidak ditemukan file mencurigakan</h3>
                    <p>Server Anda tampak bersih dari webshell yang terdeteksi</p>
                </div>
            <?php endif; ?>
            
            <?php unset($_SESSION['scan_results']); ?>
        <?php endif; ?>
    </div>

    <script>
        // Konfirmasi sebelum tindakan berbahaya
        document.addEventListener('DOMContentLoaded', function() {
            const forms = document.querySelectorAll('form');
            
            forms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    const action = form.querySelector('input[name="action"]');
                    if (!action) return;

                    if (action.value === 'delete') {
                        if (!confirm('⚠️ PERINGATAN: Yakin ingin menghapus file ini? Tindakan ini tidak dapat dibatalkan!')) {
                            e.preventDefault();
                        }
                    } else if (action.value === 'view_url') {
                        if (!confirm('⚠️ PERINGATAN: Membuka URL file yang mencurigakan bisa berbahaya. Lanjutkan?')) {
                            e.preventDefault();
                        }
                    }
                });
            });
        });
    </script>
</body>
</html>
