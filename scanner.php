<?php
echo "<h1>WebShell Scanner Basic</h1>";
echo "<form method='post'><input type='hidden' name='scan' value='1'>";
echo "<button type='submit'>Scan</button></form>";

if (isset($_POST['scan'])) {
    $files = scandir('.');
    foreach ($files as $file) {
        if (strpos($file, '.php') !== false) {
            echo "File: $file<br>";
        }
    }
}
?>
