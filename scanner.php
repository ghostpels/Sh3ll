<?php
// Mulai session untuk menangani login
session_start();

// --- 1. KONFIGURASI & KEAMANAN DASAR ---

// !! GANTI PASSWORD INI DENGAN PASSWORD YANG SANGAT KUAT !!
$password = 'PasswordSangatRahasia123!';

// Daftar kata kunci (signatures) yang sering ada di webshell
$signatures = [
    'eval(',
    'system(',
    'passthru(',
    'shell_exec(',
    'exec(',
    'popen(',
    'proc_open(',
    'base64_decode',
    'preg_replace', // Sering dipakai dengan modifier /e (obfuscation)
    'move_uploaded_file', // Indikasi fitur upload
    'php_uname', // Sering dipakai untuk info server
    'fsockopen', // Sering dipakai untuk reverse shell
];

// Direktori yang akan di-scan (mulai dari direktori saat ini)
$scan_dir = __DIR__;

// Nama file skrip ini, untuk diabaikan saat scanning
$self_script = basename(__FILE__);

// Array untuk menyimpan file yang mencurigakan
$suspicious_files = [];

// --- 2. FUNGSI BANTUAN ---

/**
 * Mengubah path file di server menjadi URL yang bisa diakses
 * @param string $file_path Path lengkap file
 * @return string URL
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
 * @param string $url URL yang akan dicek
 * @return int Kode status HTTP (misal: 200, 404, 403, 0 jika error)
 */
function check_http_status($url) {
    // Pastikan cURL ada
    if (!function_exists('curl_init')) {
        return -1; // Kode error internal, cURL tidak ada
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, // Mengembalikan hasil sebagai string
        CURLOPT_NOBODY         => true, // Hanya ambil HEADERS, bukan isi body (lebih cepat!)
        CURLOPT_TIMEOUT        => 5,    // Batas waktu 5 detik
        CURLOPT_SSL_VERIFYPEER => false, // Abaikan SSL
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_FOLLOWLOCATION => true, // Ikuti redirects
        CURLOPT_USERAGENT      => 'PHP-Scanner-Bot'
    ]);

    @curl_exec($ch);
    
    if (curl_errno($ch)) {
        $http_code = 0; // Error koneksi
    } else {
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    }
    
    curl_close($ch);
    return (int)$http_code;
}

// --- 3. LOGIKA APLIKASI ---

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

// C. Logika Hapus File (HANYA JIKA SUDAH LOGIN)
$delete_message = '';
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    if (isset($_POST['action']) && $_POST['action'] === 'delete' && isset($_POST['file_path'])) {
        $file_to_delete = realpath($_POST['file_path']);
        
        // Keamanan: Pastikan file yang dihapus ada di dalam direktori scan
        if ($file_to_delete && strpos($file_to_delete, realpath($scan_dir)) === 0 && is_file($file_to_delete)) {
            if (unlink($file_to_delete)) {
                $delete_message = '<p style="color:green;"><strong>Sukses:</strong> File ' . htmlspecialchars($file_to_delete) . ' telah dihapus.</p>';
            } else {
                $delete_message = '<p style="color:red;"><strong>Gagal:</strong> Tidak dapat menghapus file ' . htmlspecialchars($file_to_delete) . '.</p>';
            }
        } else {
            $delete_message = '<p style="color:red;"><strong>Gagal:</strong> File tidak valid atau tidak ditemukan.</p>';
        }
    }
}

// D. Logika Scan File (HANYA JIKA SUDAH LOGIN)
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($scan_dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            // Hanya scan file (bukan direktori) dan abaikan skrip ini sendiri
            if ($file->isFile() && $file->getFilename() !== $self_script) {
                
                // Hanya periksa file dengan ekstensi tertentu
                $ext = strtolower($file->getExtension());
                if (in_array($ext, ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'sh', 'pl', 'py'])) {
                    
                    $content = @file_get_contents($file->getRealPath());
                    if ($content === false) continue; // Lewati file yang tidak bisa dibaca

                    $found_signatures = [];
                    foreach ($signatures as $sig) {
                        if (stripos($content, $sig) !== false) {
                            $found_signatures[] = $sig;
                        }
                    }

                    // Jika ditemukan signature, tambahkan ke daftar
                    if (!empty($found_signatures)) {
                        
                        // Dapatkan URL dan status HTTP-nya
                        $file_url = get_file_url($file->getRealPath());
                        $http_status = check_http_status($file_url);

                        // Tambahkan ke daftar
                        $suspicious_files[] = [
                            'path'       => $file->getRealPath(),
                            'signatures' => $found_signatures,
                            'url'        => $file_url,
                            'status'     => $http_status
                        ];
                    }
                }
            }
        }
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
    <title>PHP Webshell Scanner</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; background-color: #f4f4f4; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .header, .content, .login-form { padding: 20px; }
        .header { background: #333; color: #fff; border-bottom: 4px solid #d9534f; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .header a { color: #fff; text-decoration: none; background: #5bc0de; padding: 5px 10px; border-radius: 4px; }
        .login-form { text-align: center; }
        .login-form input[type="password"] { width: 250px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        .login-form button { padding: 10px 20px; background: #5cb85c; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: #d9534f; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; word-wrap: break-word; }
        th { background: #f9f9f9; }
        th:nth-child(1) { width: 45%; } /* Path */
        th:nth-child(2) { width: 20%; } /* Indikasi */
        th:nth-child(3) { width: 15%; } /* Status */
        th:nth-child(4) { width: 20%; } /* Aksi */
        td code { background: #eee; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; display: inline-block; }
        .actions form { display: inline-block; }
        .actions .btn { padding: 5px 10px; text-decoration: none; border-radius: 4px; color: #fff; display: inline-block; margin: 2px 0; }
        .btn-view { background: #0275d8; }
        .btn-delete { background: #d9534f; border: none; font-size: 1em; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PHP Webshell Scanner</h1>
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
                    <table>
                        <thead>
                            <tr>
                                <th>File Path</th>
                                <th>Indikasi</th>
                                <th>Status HTTP</th>
                                <th>Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($suspicious_files as $file) : ?>
                                <tr>
                                    <td><code><?php echo htmlspecialchars($file['path']); ?></code></td>
                                    
                                    <td>
                                        <?php foreach ($file['signatures'] as $sig) : ?>
                                            <code><?php echo htmlspecialchars($sig); ?></code><br>
                                        <?php endforeach; ?>
                                    </td>
                                    
                                    <td>
                                        <?php
                                            $status = $file['status'];
                                            if ($status == 200) {
                                                echo '<strong style="color:green;">' . $status . ' (OK)</strong>';
                                            } elseif ($status == 0) {
                                                echo '<strong style="color:orange;">' . $status . ' (Koneksi Gagal)</strong>';
                                            } elseif ($status == -1) {
                                                echo '<strong style="color:orange;">(cURL nonaktif)</strong>';
                                            } else {
                                                echo '<strong style="color:red;">' . $status . ' (Misal: 403, 404, 500)</strong>';
                                            }
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
