<?php
$host = "db";
$dbname = "labdb";
$user = "root";
$pass = "root123";
$message = "";
$comments = [];

function detectSQLi($input) {
    $patterns = [
        "/OR\s+['\"]?1['\"]?\s*=\s*['\"]?1/i",
        "/UNION.*SELECT/i",
        "/DROP.*TABLE/i",
        "/--\s*$/m",
        "/SLEEP\s*\(/i",
        "/OR\s+\d+=\d+/i",
        "/'[^']*'\s*=\s*'[^']*'/i",
        "/1\s*=\s*1/i",
"/'/",
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    return false;
}

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

    if (isset($_POST["login"])) {
        $username = $_POST["username"] ?? "";
        $password = $_POST["password"] ?? "";

        if (detectSQLi($username) || detectSQLi($password)) {
            http_response_code(403);
            die('<!DOCTYPE html><html><head><title>SENTINEL WAF - Blocked</title><style>body{background:#080d18;color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.box{text-align:center;padding:40px;border:1px solid rgba(200,50,50,0.4);border-radius:16px;background:rgba(200,50,50,0.08)}h1{color:#ef4444}p{color:rgba(255,255,255,0.6);margin-top:10px}.shield{font-size:60px;margin-bottom:20px}</style></head><body><div class="box"><div class="shield">🛡</div><h1>SQL Injection Blocked</h1><p>SENTINEL WAFShield AI detected and blocked a SQL Injection attack.</p><p style="color:rgba(200,50,50,0.8);margin-top:20px">Error 403 Forbidden</p></div></body></html>');
        }

        $hashed = hash("sha256", $password);
        $sql = "SELECT id, username FROM users WHERE username = '$username' AND password = '$hashed'";
        $result = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
        $message = $result ? "Welcome " . htmlspecialchars($result["username"]) : "Invalid credentials";
    }

    if (isset($_POST["comment"])) {
        $uname = $_POST["cuser"] ?? "Anonymous";
        $comment = $_POST["comment"] ?? "";
        $pdo->exec("INSERT INTO comments (username, comment) VALUES ('$uname', '$comment')");
        $message = "Comment posted!";
    }

    $comments = $pdo->query("SELECT * FROM comments ORDER BY created_at DESC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    $message = "DB Error: " . $e->getMessage();
}

$page = $_GET["page"] ?? "";
$file_content = "";
if ($page) {
    $filepath = "/var/www/html/pages/" . $page;
    $file_content = file_exists($filepath) ? file_get_contents($filepath) : "Page not found: $page";
}
?>
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>VulnApp WAF Test</title>
<style>*{margin:0;padding:0;box-sizing:border-box;font-family:Arial,sans-serif;}body{background:#f0f4f8;}.header{background:#1a3a5c;color:white;padding:16px 24px;}.container{max-width:900px;margin:24px auto;padding:0 16px;}.card{background:white;border-radius:8px;padding:24px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,0.1);}.card h2{font-size:16px;color:#1a3a5c;margin-bottom:16px;}.msg{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;background:#e8f4fd;color:#1a3a5c;}input,textarea{width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;margin-bottom:10px;font-size:13px;}button{padding:10px 20px;background:#1a3a5c;color:white;border:none;border-radius:6px;cursor:pointer;}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;}.nav{display:flex;gap:8px;margin-bottom:16px;}.nav a{padding:6px 14px;background:#1a3a5c;color:white;border-radius:6px;text-decoration:none;font-size:12px;}.info-box{background:#fffbeb;border:1px solid #fcd34d;border-radius:6px;padding:12px;margin-bottom:16px;font-size:12px;color:#92400e;}.comment-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px;margin-bottom:8px;}.vuln-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:bold;margin-left:8px;}.badge-sql{background:#fee2e2;color:#dc2626;}.badge-xss{background:#fef3c7;color:#d97706;}.badge-lfi{background:#fef9c3;color:#ca8a04;}</style>
</head>
<body>
<div class="header"><h1>VulnApp — WAF Test Target</h1><p>Protected by SENTINEL WAFShield AI</p></div>
<div class="container">
<div class="info-box">This is an intentionally vulnerable application for WAF testing purposes only.</div>
<div class="nav">
    <a href="/vulnapp/?page=about.txt">About Page</a>
    <a href="/vulnapp/?page=../../etc/passwd">LFI Attack Test</a>
    <a href="/vulnapp/?page=../../../etc/shadow">LFI Attack Test 2</a>
</div>
<?php if ($message): ?><div class="msg"><?= $message ?></div><?php endif; ?>
<div class="grid">
<div class="card"><h2>Login <span class="vuln-badge badge-sql">SQLi Vulnerable</span></h2>
<form method="POST" action="/vulnapp/">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit" name="login">Login</button>
</form>
<div style="margin-top:12px;font-size:11px;color:#666;"><strong>Normal:</strong> admin / admin123<br><strong>SQLi:</strong> admin' OR '1'='1 --</div>
</div>
<div class="card"><h2>Comments <span class="vuln-badge badge-xss">XSS Vulnerable</span></h2>
<form method="POST" action="/vulnapp/">
<input type="text" name="cuser" placeholder="Your name">
<textarea name="comment" placeholder="Try: &lt;script&gt;alert('XSS')&lt;/script&gt;" rows="3"></textarea>
<button type="submit" name="comment">Post Comment</button>
</form>
</div>
</div>
<div class="card"><h2>File Viewer <span class="vuln-badge badge-lfi">LFI Vulnerable</span></h2>
<form method="GET" action="/vulnapp/">
<input type="text" name="page" placeholder="Enter filename (try: ../../etc/passwd)">
<button type="submit">View File</button>
</form>
<div style="margin-top:12px;font-size:11px;color:#666;">
<strong>Normal:</strong> about.txt<br>
<strong>LFI Attack:</strong> ../../etc/passwd<br>
<strong>LFI Attack:</strong> ../../../etc/shadow
</div>
</div>
<div class="card"><h2>System Tool <span class="vuln-badge" style="background:#ede9fe;color:#7c3aed;">CMD Vulnerable</span></h2>
<form method="GET" action="/vulnapp/">
<input type="text" name="cmd" placeholder="Enter command (try: whoami)">
<button type="submit">Execute</button>
</form>
<div style="margin-top:12px;font-size:11px;color:#666;">
<strong>Normal:</strong> help, version<br>
<strong>CMD Attack:</strong> whoami<br>
<strong>CMD Attack:</strong> cat /etc/passwd
</div>
</div>
<div class="card"><h2>Recent Comments</h2>
<?php foreach ($comments as $c): ?>
<div class="comment-box">
<div style="font-size:11px;font-weight:bold;color:#1a3a5c;"><?= htmlspecialchars($c["username"]) ?></div>
<div style="font-size:13px;margin-top:4px;"><?= $c["comment"] ?></div>
</div>
<?php endforeach; ?>
</div>
<?php if ($file_content): ?>
<div class="card"><h2>Page Content <span class="vuln-badge badge-lfi">LFI Vulnerable</span></h2>
<pre style="font-size:12px;background:#f8fafc;padding:12px;border-radius:6px;overflow:auto;"><?= htmlspecialchars($file_content) ?></pre>
</div>
<?php endif; ?>
</div></body></html>
