<?php
/**
 * vuln_upload.php — Demo file with intentionally vulnerable file upload handling.
 * CWE-434: Unrestricted Upload of File with Dangerous Type.
 * CWE-22:  Path Traversal via unsanitised filename.
 * DO NOT use patterns like these in production code.
 */

// ---------------------------------------------------------------------------
// Vulnerability 1: No MIME check, no extension whitelist
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $target = "/var/uploads/" . $_FILES["upload"]["name"];
    // UNSAFE: raw filename allows path traversal; no MIME or extension check
    move_uploaded_file($_FILES["upload"]["tmp_name"], $target);
    echo "Uploaded.";
}

// ---------------------------------------------------------------------------
// Vulnerability 2: Extension check only (no MIME inspection, no whitelist array)
// ---------------------------------------------------------------------------
function handle_upload_weak() {
    $name = $_FILES["file"]["name"];
    $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    // UNSAFE: extension alone is bypassable; no MIME check
    if ($ext === "jpg" || $ext === "png") {
        move_uploaded_file($_FILES["file"]["tmp_name"], "/var/uploads/" . $name);
    }
}

// ---------------------------------------------------------------------------
// Safe example (not flagged) — MIME check + whitelist present
// ---------------------------------------------------------------------------
function handle_upload_safe() {
    $allowed = ["image/jpeg", "image/png", "image/gif"];
    $allowed_ext = ["jpg", "jpeg", "png", "gif"];
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime  = finfo_file($finfo, $_FILES["upload"]["tmp_name"]);
    finfo_close($finfo);
    $ext   = strtolower(pathinfo($_FILES["upload"]["name"], PATHINFO_EXTENSION));
    if (!in_array($mime, $allowed) || !in_array($ext, $allowed_ext)) {
        http_response_code(400);
        exit("Invalid file.");
    }
    // Generate a safe server-side name to avoid path traversal
    $dest = "/var/uploads/" . bin2hex(random_bytes(16)) . "." . $ext;
    move_uploaded_file($_FILES["upload"]["tmp_name"], $dest);
    echo "Uploaded safely.";
}
