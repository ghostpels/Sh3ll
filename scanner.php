<?php
/* 
 * SIMPLE WEBSHELL SCANNER
 * Versi sangat sederhana untuk menghindari error 500
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
                
                // Check only PHP files
                $ext = pathinfo($file, PATHINFO_EXTENSION);
                if (in_array(strtolower($ext), array('php', 'phtml', 'php3', 'php4', 'php5', 'php7'))) {
                    $content = file_get_contents($file);
                    if ($content) {
                        $suspicious_patterns = array();
                        $score = 0;
                        
                        // Check for dangerous functions
                        if (strpos($content, 'eval(') !== false) {
                            $suspicious_patterns[] = 'eval';
                            $score++;
                        }
                        if (strpos($content, 'base64_decode(') !== false) {
                            $suspicious_patterns[] = 'base64_decode';
                            $score++;
                        }
                        if (strpos($content, 'system(') !== false) {
                            $suspicious_patterns[] = 'system';
                            $score++;
                        }
                        if (strpos($content, 'exec(') !== false) {
                            $suspicious_patterns[] = 'exec';
                            $score++;
                        }
                        if (strpos($content, 'shell_exec(') !== false) {
                            $suspicious_patterns[] = 'shell_exec';
                            $score++;
                        }
                        if (strpos($content, 'passthru(') !== false) {
                            $suspicious_patterns[] = 'passthru';
                            $score++;
                        }
                        if (strpos($content, 'file_get_contents(') !== false) {
                            $suspicious_patterns[] = 'file_get_contents';
                            $score++;
                        }
                        if (strpos($content, 'file_put_contents(') !== false) {
                            $suspicious_patterns[] = 'file_put_contents';
                            $score++;
                        }
                        if (strpos($content, 'curl_exec(') !== false) {
                            $suspicious_patterns[] = 'curl_exec';
                            $score++;
                        }
                        
                        // Check for obfuscation
                        if (strpos($content, '/*') !== false && strpos($content, 'eval') !== false) {
                            $suspicious_patterns[] = 'obfuscated';
                            $score += 2;
                        }
                        
                        if ($score > 0) {
                            $suspicious_count++;
                            $results[] = array(
                                'file' => $file,
                                'score' => $score,
                                'patterns' => $suspicious_patterns,
                                'size' => filesize($file),
                                'modified' => date('Y-m-d H:i:s', filemtime($file))
                            );
                        }
                    }
                }
            }
        }
        
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
                $_SESSION['message'] = "File deleted: " . htmlspecialchars($file);
            } else {
                $_SESSION['error'] = "Failed to delete: " . htmlspecialchars($file);
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
    <title>Simple WebShell Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; }
        .header { text-align: center; margin-bottom: 20px; }
        .btn { padding: 10px 15px; margin: 5px; border: none; border-radius: 3px; cursor: pointer; }
        .btn-scan { background: #007bff; color: white; }
        .btn-view { background: #28a745; color: white; }
        .btn-delete { background: #dc3545; color: white; }
        .btn-content { background: #ffc107; color: black; }
        .message { padding: 10px; margin: 10px 0; border-radius: 3px; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .file-item { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 3px; }
        .file-name { font-weight: bold; font-size: 16px; }
        .file-score { color: red; font-weight: bold; }
        .pattern { background: #fff3cd; padding: 3px 8px; margin: 2px; border-radius: 2px; display: inline-block; font-size: 12px; }
        .content-preview { background: #f8f9fa; padding: 15px; border: 1px solid #ddd; margin: 10px 0; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Simple WebShell Scanner</h1>
            <p>Basic scanner untuk mendeteksi file mencurigakan</p>
        </div>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="message success"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="message error"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <form method="post">
            <input type="hidden" name="action" value="scan">
            <button type="submit" class="btn btn-scan">Scan Current Directory</button>
        </form>

        <?php if (isset($_SESSION['file_content'])): ?>
            <div class="content-preview">
                <h3>Content of: <?php echo htmlspecialchars($_SESSION['file_name']); ?></h3>
                <pre><?php echo $_SESSION['file_content']; ?></pre>
            </div>
            <?php unset($_SESSION['file_content'], $_SESSION['file_name']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['scan_results'])): 
            $results = $_SESSION['scan_results'];
            $files = $results['files'];
            $stats = $results['stats'];
        ?>
            <div style="margin: 20px 0; padding: 15px; background: #e9ecef;">
                <h3>Scan Results:</h3>
                <p>Files scanned: <?php echo $stats['scanned']; ?></p>
                <p>Suspicious files: <?php echo $stats['suspicious']; ?></p>
            </div>

            <?php if (!empty($files)): ?>
                <?php foreach ($files as $file): ?>
                    <div class="file-item">
                        <div class="file-name">File: <?php echo htmlspecialchars($file['file']); ?></div>
                        <div class="file-score">Risk Score: <?php echo $file['score']; ?></div>
                        <div>Size: <?php echo number_format($file['size']); ?> bytes</div>
                        <div>Modified: <?php echo $file['modified']; ?></div>
                        
                        <div style="margin: 10px 0;">
                            <strong>Detected patterns:</strong><br>
                            <?php foreach ($file['patterns'] as $pattern): ?>
                                <span class="pattern"><?php echo htmlspecialchars($pattern); ?></span>
                            <?php endforeach; ?>
                        </div>

                        <div>
                            <form method="post" style="display: inline;">
                                <input type="hidden" name="action" value="view_content">
                                <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['file']); ?>">
                                <button type="submit" class="btn btn-content">View Content</button>
                            </form>

                            <a href="<?php echo getFileUrl($file['file']); ?>" target="_blank" class="btn btn-view" onclick="return confirm('Open this URL?')">Open URL</a>

                            <form method="post" style="display: inline;">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="file" value="<?php echo htmlspecialchars($file['file']); ?>">
                                <button type="submit" class="btn btn-delete" onclick="return confirm('Delete this file?')">Delete</button>
                            </form>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p>No suspicious files found.</p>
            <?php endif; ?>
            
            <?php unset($_SESSION['scan_results']); ?>
        <?php endif; ?>
    </div>

    <script>
        // Simple confirmation
        document.addEventListener('DOMContentLoaded', function() {
            var deleteButtons = document.querySelectorAll('.btn-delete');
            for (var i = 0; i < deleteButtons.length; i++) {
                deleteButtons[i].addEventListener('click', function(e) {
                    if (!confirm('Are you sure you want to delete this file?')) {
                        e.preventDefault();
                    }
                });
            }
        });
    </script>
</body>
</html>
