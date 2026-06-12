<?php
/**
 * PhantomShell Test Target
 *
 * A deliberately vulnerable PHP page for testing PhantomShell.
 * DO NOT deploy on production servers.
 *
 * Usage:
 *   php -S 0.0.0.0:8080 test_target.php
 *
 * Then upload phantom.php through the file upload form.
 */

$upload_dir = '/tmp/uploads/';
if (!is_dir($upload_dir)) @mkdir($upload_dir, 0777, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $target = $upload_dir . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "<p style='color:green'>Uploaded: $target</p>";
        if (pathinfo($target, PATHINFO_EXTENSION) === 'php') {
            echo "<p>Execute: <a href='?exec=" . urlencode($target) . "'>Run</a></p>";
        }
    } else {
        echo "<p style='color:red'>Upload failed</p>";
    }
}

if (isset($_GET['exec'])) {
    $file = $_GET['exec'];
    if (file_exists($file)) {
        echo "<p>Executing $file...</p>";
        include($file);
    }
}

if (isset($_GET['cmd'])) {
    echo "<pre>" . htmlspecialchars(shell_exec($_GET['cmd'])) . "</pre>";
}
?>
<!DOCTYPE html>
<html>
<head><title>Test Target</title></head>
<body>
<h1>PhantomShell Test Target</h1>
<h2>File Upload</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
<h2>Command Execution</h2>
<form method="GET">
    <input type="text" name="cmd" placeholder="Command..." size="40">
    <button type="submit">Execute</button>
</form>
<hr>
<p><small>Test environment only. PHP <?= phpversion() ?></small></p>
</body>
</html>
