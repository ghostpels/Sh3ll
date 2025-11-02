<?php
/* 
 * SIMPLE WEBSHELL SCANNER
 * Versi yang diperbaiki - tanpa error
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
                        
                        // Check for dangerous functions
                        $patterns = array(
                            'eval' => 3,
                            'base64_decode' => 2,
                            'system' => 3,
                            'exec' => 3,
                            'shell_exec' => 3,
                            'passthru' => 3,
                            'file_put_contents' => 2,
                            'curl_exec' => 2,
                            'preg_replace_e' => 3,
                            'create_function' => 2,
                            'assert' => 2,
                            'gzinflate' => 2,
                        );
                        
                        foreach ($patterns as $name => $weight) {
                            $pattern = '';
                            switch($name) {
                                case 'eval': $pattern = '/\beval\s*\(/i'; break;
                                case 'base64_decode': $pattern = '/base64_decode\s*\(/i'; break;
                                case 'system': $pattern = '/\bsystem\s*\(/i'; break;
                                case 'exec': $pattern = '/\bexec\s*\(/i'; break;
                                case 'shell_exec': $pattern = '/\bshell_exec\s*\(/i'; break;
                                case 'passthru': $pattern = '/\bpassthru\s*\(/i'; break;
                                case 'file_put_contents': $pattern = '/file_put_contents\s*\(/i'; break;
                                case 'curl_exec': $pattern = '/\bcurl_exec\s*\(/i'; break;
                                case 'preg_replace_e': $pattern = '/preg_replace\s*\(.*\/e/i'; break;
                                case 'create_function': $pattern = '/create_function\s*\(/i'; break;
                                case 'assert': $pattern = '/\bassert\s*\(/i'; break;
                                case 'gzinflate': $pattern = '/gzinflate\s*\(/i'; break;
                            }
                            
                            if ($pattern && preg_match_all($pattern, $content, $matches)) {
                                $count = count($matches[0]);
                                $suspicious_patterns[$name] = $count;
                                $score += ($count * $weight);
                            }
                        }
                        
                        // Check for remote file inclusion
                        if (preg_match('/file_get_contents\s*\(\s*[\'"](http|https|ftp):\/\//i', $content)) {
                            $suspicious_patterns['remote_inclusion'] = true;
                            $score += 4;
                        }
                        
                        // Check for webshell specific patterns
                        if (preg_match('/\$_GET\s*\[\s*[\'"]cmd[\'"]\s*\]/i', $content) ||
                            preg_match('/\$_POST\s*\[\s*[\'"]pass[\'"]\s*\]/i', $content)) {
                            $suspicious_patterns['webshell_params'] = true;
                            $score += 3;
                        }
                        
                        // Check for file upload features
                        if (preg_match('/move_uploaded_file\s*\(/i', $content) && 
                            preg_match('/\$_FILES/i', $content)) {
                            $suspicious_patterns['upload_feature'] = true;
                            $score += 2;
                        }
                        
                        // Check for obfuscation patterns
                        if (preg_match('/\/\*+.*eval.*\*+\//is', $content)) {
                            $suspicious_patterns['comment_obfuscation'] = true;
                            $score += 4;
                        }
                        
                        // Check for advanced obfuscation
                        if (preg_match('/\/\*+.*@eval.*\*+.*\(.*file_get_contents/is', $content)) {
                            $suspicious_patterns['advanced_obfuscation'] = true;
                            $score += 5;
                        }
                        
                        if ($score > 0) {
                            $suspicious_count++;
                            $results[] = array(
                                'file' => $file,
                                'score' => $score,
                                'patterns' => $suspicious_patterns,
                                'size' => filesize($file),
                                'modified' => date('Y-m-d H:i:s', filemtime($file)),
                                'content_sample' => substr($content, 0, 300) // Sample content untuk preview
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
    <title>WebShell Scanner</title>
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
            <h1>🛡️ WebShell Scanner</h1>
            <p>Detektor webshell dengan pattern matching</p>
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
                <button type="submit" class="btn btn-scan">🔍 Mulai Scan</button>
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
                                    <span class="pattern <?php echo $pattern_class; ?>">
                                        <?php 
                                        if ($count === true) {
                                            echo htmlspecialchars($pattern);
                                        } else {
                                            echo htmlspecialchars($pattern) . ": " . $count;
                                        }
                                        ?>
                                    </span>
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

                                <a href="<?php echo getFileUrl($file['file']); ?>" target="_blank" class="btn btn-view" onclick="return confirm('Buka URL file ini?')">🌐 Buka URL</a>

                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['file']); ?>">
                                    <button type="submit" class="btn btn-delete" onclick="return confirm('Yakin hapus file ini?')">🗑️ Hapus</button>
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
            var deleteButtons = document.querySelectorAll('.btn-delete');
            deleteButtons.forEach(function(button) {
                button.addEventListener('click', function(e) {
                    if (!confirm('Yakin ingin menghapus file ini?')) {
                        e.preventDefault();
                    }
                });
            });
        });
    </script>
</body>
</html>
