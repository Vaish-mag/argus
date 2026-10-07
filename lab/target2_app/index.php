<?php
// MiniGallery -- a deliberately small, deliberately vulnerable demo target.
//
// This app exists to prove Argus is not DVWA-specific: it is protected by the
// same controller, through nothing but a second config file
// (config/target2.yaml), with zero changes to argus/. See docs/architecture.md.
//
// The vulnerability here is real and unpatched (CWE-434, Unrestricted File
// Upload) -- upload.php accepts any file, with no extension or content-type
// check, and saves it directly into this web-served directory. That is
// intentional: it is the same vulnerability class DVWA's own upload page
// demonstrates, reproduced here in a few lines of app we wrote ourselves so
// its behaviour is fully understood rather than borrowed.
$dir = __DIR__ . "/uploads";
$files = is_dir($dir) ? array_diff(scandir($dir), [".", "..", ".htaccess"]) : [];
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>MiniGallery</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header>
    <h1>MiniGallery</h1>
    <p class="tag">A tiny demo target protected by Argus.</p>
  </header>

  <main>
    <section class="upload-box">
      <h2>Share a file</h2>
      <form action="upload.php" method="post" enctype="multipart/form-data">
        <input type="file" name="upload" required>
        <button type="submit">Upload</button>
      </form>
    </section>

    <section>
      <h2>Gallery (<?php echo count($files); ?> files)</h2>
      <ul class="files">
        <?php foreach ($files as $f): ?>
          <li><a href="uploads/<?php echo htmlspecialchars($f); ?>"><?php echo htmlspecialchars($f); ?></a></li>
        <?php endforeach; ?>
        <?php if (!count($files)): ?>
          <li class="empty">No files yet.</li>
        <?php endif; ?>
      </ul>
    </section>
  </main>

  <footer>
    <p>MiniGallery &mdash; lab target #2, protected by Argus (see config/target2.yaml)</p>
  </footer>
</body>
</html>
