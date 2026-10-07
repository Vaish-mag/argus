<?php
// upload.php -- the vulnerability. CWE-434: Unrestricted File Upload.
//
// This is intentionally unfixed: no extension allow-list, no MIME-type check,
// no filename sanitisation beyond basename(), and the destination is directly
// inside the web-served document root. Any authenticated-or-not visitor can
// upload a .php file here and it will execute the next time it is requested --
// exactly DVWA's own "upload" vulnerability, reproduced in app code we wrote
// and fully understand, rather than borrowed.
//
// This file is the ATTACK SURFACE Argus protects against, not a defence --
// do not "fix" it, that would defeat the point of the demo target.
if ($_SERVER["REQUEST_METHOD"] !== "POST" || !isset($_FILES["upload"])) {
    http_response_code(400);
    echo "no file";
    exit;
}

$dir = __DIR__ . "/uploads";
if (!is_dir($dir)) {
    mkdir($dir, 0777, true);
}
// Apache runs as www-data, but a bind-mounted uploads/ belongs to the host user. This
// chmod only helps if www-data owns the directory (e.g. it was created by the mkdir
// above). For the usual host-owned directory the one-time `chmod 777` in the README setup
// is what matters -- and Argus's restores preserve that mode (argus.docker_ops).
@chmod($dir, 0777);

// No extension check. No MIME-type check. No content inspection.
$name = basename($_FILES["upload"]["name"]);
$dest = $dir . "/" . $name;

if (move_uploaded_file($_FILES["upload"]["tmp_name"], $dest)) {
    header("Location: index.php");
    exit;
} else {
    http_response_code(500);
    echo "upload failed";
}
