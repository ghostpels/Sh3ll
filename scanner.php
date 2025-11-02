<?php
// webshell_scanner_simple.php
session_start();

// Konfigurasi sederhana
$SCAN_DIRECTORIES = ['.']; // Scan direktori saat ini saja
$MAX_FILE_SIZE = 2097152; // 2MB

// Pattern dasar untuk deteksi webshell
$SUSPICIOUS_PATTERNS = array(
    'eval' => '/eval\s*\(/i',
    'base64_decode' => '/base64_decode\s*\(/i',
    'system' => '/system\s*\(/i',
    'exec' => '/exec\s*\(/i',
    'shell_exec' => '/shell_exec\s*\(/i',
    'passthru' => '/passthru\s*\(/i',
    'file_get_contents' => '/file_get_contents\s*\(/i',
    'file_put_contents' => '/file_put_contents\s*\(/i',
    'curl_exec' => '/curl_exec\s*\(/i'
);

function scanDirectory($directory, $maxFileSize = 2097152) {
    global $SUSPICIOUS_PATTERNS;
    
    $results = array();
    $scanned = 0;
    $suspicious = 0;
    
    if (!is_dir($directory)) {
        return array('files' => array(), 'stats' => array('scanned' => 0, 'suspicious' => 0, 'errors' => 1));
    }
    
    $files = scandir($directory);
    if ($files === false) {
        return array('files' => array(), 'stats' => array('scanned' => 0, 'suspicious' => 0, 'errors' => 1));
    }
    
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;
        
        $fullPath = $directory . DIRECTORY_SEPARATOR . $file;
        
        if (is_dir($fullPath)) {
            // Skip direktori untuk sekarang, fokus file saja
            continue;
        }
        
        $scanned++;
        
        // Check file size
        $fileSize = filesize($fullPath);
        if ($fileSize > $maxFileSize) {
            continue;
        }
        
        // Check file extension
        $extension = strtolower(pathinfo($fullPath, PATHINFO_EXTENSION));
        $phpExtensions = array('php', 'phtml', 'php3', 'php4', 'php5', 'php7');
        
        if (!in_array($extension, $phpExtensions)) {
            continue;
        }
        
        // Read file content
        $content = file_get_contents($fullPath);
        if ($content === false) {
            continue;
        }
        
        $suspiciousSigns = array();
        $score = 0;
        
        // Check patterns
        foreach ($SUSPICIOUS_PATTERNS as $patternName => $pattern) {
            $count = preg_match_all($pattern, $content, $matches);
            if ($count > 0) {
                $suspiciousSigns[$patternName] = $count;
                $score += $count;
            }
        }
        
        // Check for obfuscation
        if (strpos($content, '/*') !== false && strpos($content, 'eval') !== false) {
            $suspiciousSigns['obfuscated'] = true;
            $score += 2;
        }
        
        if ($score > 0) {
            $suspicious++;
            $results[] = array(
                'path' => $fullPath,
                'score' => $score,
                'signs' => $suspiciousSigns,
                'size' => $fileSize,
                'modified' => date('Y-m-d H:i:s', filemtime($fullPath))
            );
        }
    }
    
    return array(
        'files' => $results,
        'stats' => array('scanned' => $scanned, 'suspicious' => $suspicious, 'errors' => 0)
    );
}

// Handle form actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['action'])) {
        $action = $_POST['action'];
        
        if ($action == 'scan') {
            $allResults = array('files' => array(), 'stats' => array('scanned' => 0, 'suspicious' => 0, 'errors' => 0));
            
            foreach ($SCAN_DIRECTORIES as $dir) {
                $result = scanDirectory($dir, $MAX_FILE_SIZE);
                $allResults['files'] = array_merge($allResults['files'], $result['files']);
                $allResults['stats']['scanned'] += $result['stats']['scanned'];
                $allResults['stats']['suspicious'] += $result['stats']['suspicious'];
                $allResults['stats']['errors'] += $result['stats']['errors'];
            }
            
            $_SESSION['scan_results'] = $allResults;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
            
        } elseif ($action == 'delete' && isset($_POST['file_path'])) {
            $file_path = $_POST['file_path'];
            if (file_exists($file_path) && is_file($file_path)) {
                if (unlink($file_path)) {
                    $_SESSION['message'] = "File berhasil dihapus: " . htmlspecialchars($file_path);
                } else {
                    $_SESSION['error'] = "Gagal menghapus file: " . htmlspecialchars($file_path);
                }
            }
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
            
        } elseif ($action == 'view_content' && isset($_POST['file_path'])) {
            $file_path = $_POST['file_path'];
            if (file_exists($file_path) && is_file($file_path)) {
                $content = file_get_contents($file_path);
                if ($content !== false) {
                    $_SESSION['file_content'] = htmlspecialchars($content);
                    $_SESSION['file_path'] = $file_path;
                }
            }
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        }
    }
}

// Simple function to get file URL
function getFileUrl($filePath) {
    $baseDir = dirname($_SERVER['SCRIPT_FILENAME']);
    $webRoot = $_SERVER['DOCUMENT_ROOT'];
    
    // Jika file berada dalam document root
    if (strpos($filePath, $webRoot) === 0) {
        $relativePath = str_replace($webRoot, '', $filePath);
        return 'http://' . $_SERVER['HTTP_HOST'] . $relativePath;
    }
    
    // Jika file berada di direktori yang sama dengan script
    if (strpos($filePath, $baseDir) === 0) {
        $relativePath = str_replace($baseDir, '', $filePath);
        $scriptDir = dirname($_SERVER['SCRIPT_NAME']);
        if ($scriptDir == '\\') $scriptDir = '';
        return 'http://' . $_SERVER['HTTP_HOST'] . $scriptDir . $relativePath;
    }
    
    return '';
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple WebShell Scanner</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f0f0f0;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }
        .btn {
            padding: 10px 15px;
            margin: 5px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            text-decoration: none;
        }
        .btn-scan {
            background: #007bff;
            color: white;
        }
        .btn-view {
            background: #28a745;
            color: white;
        }
        .btn-delete {
            background: #dc3545;
            color: white;
        }
        .btn-content {
            background: #ffc107;
            color: black;
        }
        .message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
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
        .file-item {
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }
        .file-path {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .file-score {
            color: red;
            font-weight: bold;
        }
        .sign-item {
            background: #fff3cd;
            padding: 2px 5px;
            margin: 2px;
            border-radius: 2px;
            font-size: 12px;
            display: inline-block;
        }
        .content-preview {
            background: #f8f9fa;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 3px;
            margin: 10px 0;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Simple WebShell Scanner</h1>
            <p>Scanner sederhana untuk mendeteksi file webshell</p>
        </div>

        <?php if (isset($_SESSION['message'])): ?>
            <div class="message success"><?php echo $_SESSION['message']; unset($_SESSION['message']); ?></div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="message error"><?php echo $_SESSION['error']; unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <form method="post">
            <input type="hidden" name="action" value="scan">
            <button type="submit" class="btn btn-scan">Mulai Scan</button>
        </form>

        <?php if (isset($_SESSION['file_content'])): ?>
            <div class="content-preview">
                <h3>Konten File: <?php echo htmlspecialchars($_SESSION['file_path']); ?></h3>
                <pre><?php echo $_SESSION['file_content']; ?></pre>
            </div>
            <?php unset($_SESSION['file_content'], $_SESSION['file_path']); ?>
        <?php endif; ?>

        <?php if (isset($_SESSION['scan_results'])): 
            $results = $_SESSION['scan_results'];
            $files = $results['files'];
            $stats = $results['stats'];
        ?>
            <div style="margin: 20px 0; padding: 15px; background: #e9ecef; border-radius: 3px;">
                <h3>Statistik Scan:</h3>
                <p>File di-scan: <?php echo $stats['scanned']; ?></p>
                <p>File mencurigakan: <?php echo $stats['suspicious']; ?></p>
                <p>Error: <?php echo $stats['errors']; ?></p>
            </div>

            <?php if (!empty($files)): ?>
                <div>
                    <h3>File Mencurigakan:</h3>
                    <?php foreach ($files as $file): ?>
                        <div class="file-item">
                            <div class="file-path"><?php echo htmlspecialchars($file['path']); ?></div>
                            <div class="file-score">Skor: <?php echo $file['score']; ?></div>
                            <div>Ukuran: <?php echo number_format($file['size']); ?> bytes</div>
                            <div>Modifikasi: <?php echo $file['modified']; ?></div>
                            
                            <div style="margin: 10px 0;">
                                <strong>Tanda:</strong>
                                <?php foreach ($file['signs'] as $sign => $count): ?>
                                    <span class="sign-item"><?php echo htmlspecialchars("$sign: $count"); ?></span>
                                <?php endforeach; ?>
                            </div>

                            <div>
                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="view_content">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-content">Lihat Konten</button>
                                </form>

                                <?php 
                                $fileUrl = getFileUrl($file['path']);
                                if (!empty($fileUrl)): 
                                ?>
                                    <a href="<?php echo $fileUrl; ?>" target="_blank" class="btn btn-view" onclick="return confirm('Buka URL?')">Buka URL</a>
                                <?php endif; ?>

                                <form method="post" style="display: inline;">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file['path']); ?>">
                                    <button type="submit" class="btn btn-delete" onclick="return confirm('Yakin hapus?')">Hapus</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p>Tidak ditemukan file mencurigakan.</p>
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
