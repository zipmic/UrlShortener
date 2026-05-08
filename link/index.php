<?php
declare(strict_types=1);

// ---------------------------------------------------------------------------
// PHP version guard
// ---------------------------------------------------------------------------

if (PHP_VERSION_ID < 80000) {
    http_response_code(500);
    exit('This application requires PHP 8.0 or later. Current version: ' . PHP_VERSION);
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// To store the DB outside the web root (strongly recommended on production),
// change this to an absolute path above your public_html / www directory.
// Example for typical shared hosting:
//   define('DB_PATH', dirname(__DIR__, 2) . '/urlshortener_data/urls.db');
define('DB_PATH',           __DIR__ . '/data/urls.db');
define('LOG_PATH',          __DIR__ . '/data/app.log');
define('BASE_URL',          'https://www.code.dk/link/');
define('CODE_LEN',          6);
define('MAX_URL_LEN',       2048);
define('RATE_LIMIT_MAX',    10);   // max submissions per IP per window
define('RATE_LIMIT_WINDOW', 60);   // seconds

// If your site runs behind Cloudflare or a reverse proxy, add the proxy's
// IP address(es) here so the real visitor IP is read from X-Forwarded-For.
// Cloudflare's full IP list: https://www.cloudflare.com/ips/
// Example: ['103.21.244.0', '103.22.200.0', ...]
const TRUSTED_PROXIES = [];

const BLOCKED_DOMAINS = [
    'localhost',
    // extend with known phishing / malware domains as needed
];

// ---------------------------------------------------------------------------
// CSP nonce — generated once per request for inline style + script
// ---------------------------------------------------------------------------

$cspNonce = base64_encode(random_bytes(16));

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'nonce-{$cspNonce}'; script-src 'nonce-{$cspNonce}'");
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// ---------------------------------------------------------------------------
// Logging — writes to a local file you can read via FTP, falls back to error_log
// ---------------------------------------------------------------------------

function logError(string $message): void {
    $line = '[' . date('Y-m-d H:i:s') . '] ' . $message . PHP_EOL;
    @file_put_contents(LOG_PATH, $line, FILE_APPEND | LOCK_EX);
    error_log($message);
}

// ---------------------------------------------------------------------------
// Client IP — respects trusted proxy X-Forwarded-For
// ---------------------------------------------------------------------------

function getClientIp(): string {
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if (TRUSTED_PROXIES !== [] && in_array($remoteAddr, TRUSTED_PROXIES, true)) {
        $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        $ip = trim(explode(',', $forwarded)[0]);
        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            return $ip;
        }
    }

    return $remoteAddr;
}

// ---------------------------------------------------------------------------
// Database — singleton per request
// ---------------------------------------------------------------------------

function getDb(): PDO {
    static $db = null;
    if ($db !== null) {
        return $db;
    }

    $dir = dirname(DB_PATH);
    if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create data directory: ' . $dir);
    }

    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("PRAGMA journal_mode=WAL");

    $db->exec("CREATE TABLE IF NOT EXISTS urls (
        code    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        created INTEGER NOT NULL
    )");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_urls_url ON urls(url)");

    $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
        ip  TEXT    NOT NULL,
        ts  INTEGER NOT NULL
    )");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_rate ON rate_limits (ip, ts)");

    // Stores auto-generated secrets (e.g. the IP hash salt)
    $db->exec("CREATE TABLE IF NOT EXISTS config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )");

    return $db;
}

// ---------------------------------------------------------------------------
// IP hashing — salt auto-generated on first run and stored in DB (GDPR-friendly)
// ---------------------------------------------------------------------------

function getIpSalt(): string {
    static $salt = null;
    if ($salt !== null) {
        return $salt;
    }

    $db   = getDb();
    $stmt = $db->prepare('SELECT value FROM config WHERE key = ?');
    $stmt->execute(['ip_salt']);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        $salt = $row['value'];
    } else {
        $salt = bin2hex(random_bytes(32));
        $db->prepare("INSERT INTO config (key, value) VALUES ('ip_salt', ?)")->execute([$salt]);
    }

    return $salt;
}

function hashIp(string $ip): string {
    return hash('sha256', getIpSalt() . $ip);
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

function checkRateLimit(string $hashedIp): bool {
    $db    = getDb();
    $since = time() - RATE_LIMIT_WINDOW;
    $db->prepare('DELETE FROM rate_limits WHERE ts < ?')->execute([$since]);
    $stmt = $db->prepare('SELECT COUNT(*) FROM rate_limits WHERE ip = ? AND ts >= ?');
    $stmt->execute([$hashedIp, $since]);
    return (int) $stmt->fetchColumn() < RATE_LIMIT_MAX;
}

function recordRequest(string $hashedIp): void {
    getDb()->prepare('INSERT INTO rate_limits (ip, ts) VALUES (?, ?)')->execute([$hashedIp, time()]);
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

function isValidUrl(string $url): bool {
    // mb_strlen counts characters (consistent with browser maxlength attribute)
    if (mb_strlen($url, 'UTF-8') > MAX_URL_LEN) {
        return false;
    }
    if (!preg_match('/^https?:\/\//i', $url)) {
        return false;
    }
    if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        return false;
    }

    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($host === '') {
        return false;
    }

    foreach (BLOCKED_DOMAINS as $blocked) {
        if ($host === $blocked || str_ends_with($host, '.' . $blocked)) {
            return false;
        }
    }

    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// URL storage helpers
// ---------------------------------------------------------------------------

function generateCode(): string {
    $db    = getDb();
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    do {
        $code = '';
        for ($i = 0; $i < CODE_LEN; $i++) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }
        $stmt = $db->prepare('SELECT 1 FROM urls WHERE code = ?');
        $stmt->execute([$code]);
    } while ($stmt->fetchColumn());
    return $code;
}

function lookupCode(string $code): ?string {
    $stmt = getDb()->prepare('SELECT url FROM urls WHERE code = ?');
    $stmt->execute([$code]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ? $row['url'] : null;
}

function storeUrl(string $url): string {
    $db   = getDb();
    $stmt = $db->prepare('SELECT code FROM urls WHERE url = ?');
    $stmt->execute([$url]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        return $row['code'];
    }

    // Retry on the rare concurrent UNIQUE-constraint collision
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $code = generateCode();
        try {
            $db->prepare('INSERT INTO urls (code, url, created) VALUES (?, ?, ?)')
               ->execute([$code, $url, time()]);
            return $code;
        } catch (PDOException $e) {
            if (!str_contains($e->getMessage(), 'UNIQUE constraint failed')) {
                throw $e;
            }
        }
    }

    throw new RuntimeException('Failed to generate a unique code after 5 attempts');
}

// ---------------------------------------------------------------------------
// Safe redirect
// ---------------------------------------------------------------------------

function safeRedirect(string $url, int $status = 302): void {
    $url = str_replace(["\r", "\n", "\0"], '', $url);
    header('Location: ' . $url, true, $status);
    exit;
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

function getCsrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(string $token): bool {
    return !empty($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}

// ---------------------------------------------------------------------------
// Request routing
// ---------------------------------------------------------------------------

$code     = trim($_GET['code'] ?? '');
$notFound = false;
$error    = null;
$shortUrl = null;

// Redirect path — attempt lookup before starting a session so bots and
// crawlers hitting short links never incur session-file overhead
if ($code !== '') {
    try {
        $url = lookupCode($code);
        if ($url !== null) {
            safeRedirect($url, 302); // exits here on success
        }
    } catch (Throwable $e) {
        logError('Lookup error: ' . $e->getMessage());
    }
    $notFound = true;
}

// Session is only needed from this point on (form render + POST handling)
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Detect JSON API callers by Content-Type only (not Accept) to avoid
    // accidentally returning JSON to browsers that send Accept: application/json
    $isJson = str_contains($_SERVER['CONTENT_TYPE'] ?? '', 'application/json');

    if ($isJson) {
        $body    = json_decode((string) file_get_contents('php://input'), true) ?? [];
        $longUrl = trim((string) ($body['url'] ?? ''));
        $csrf    = (string) ($body['csrf_token'] ?? '');
    } else {
        $longUrl = trim((string) ($_POST['url'] ?? ''));
        $csrf    = (string) ($_POST['csrf_token'] ?? '');
    }

    try {
        if (!verifyCsrf($csrf)) {
            $error = 'Invalid request. Please refresh the page and try again.';
        } elseif ($longUrl === '') {
            $error = 'Please enter a URL.';
        } elseif (mb_strlen($longUrl, 'UTF-8') > MAX_URL_LEN) {
            $error = 'URL is too long (max ' . MAX_URL_LEN . ' characters).';
        } elseif (!isValidUrl($longUrl)) {
            $error = 'Please enter a valid URL starting with http:// or https://';
        } else {
            $hashedIp = hashIp(getClientIp());
            if (!checkRateLimit($hashedIp)) {
                $error = 'Too many requests. Please wait a moment and try again.';
            } else {
                recordRequest($hashedIp);
                $newCode  = storeUrl($longUrl);
                $shortUrl = BASE_URL . $newCode;
            }
        }
    } catch (Throwable $e) {
        logError('Shorten error: ' . $e->getMessage());
        $error = 'A server error occurred. Please try again later.';
    }

    if ($isJson) {
        header('Content-Type: application/json');
        echo json_encode(
            $error ? ['error' => $error] : ['short_url' => $shortUrl, 'code' => $newCode],
            JSON_THROW_ON_ERROR
        );
        exit;
    }

    // POST-Redirect-GET: flash result and redirect to prevent F5 resubmit
    if (!$error) {
        $_SESSION['flash_short_url'] = $shortUrl;
        safeRedirect('/link/');
    }
}

// Pick up a flashed short URL from a previous POST-redirect
if (isset($_SESSION['flash_short_url'])) {
    $shortUrl = $_SESSION['flash_short_url'];
    unset($_SESSION['flash_short_url']);
}

$csrfToken = getCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Shortener — code.dk</title>
    <style nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES) ?>">
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f13;
            color: #e2e2e8;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem 1rem;
        }

        .card {
            background: #1a1a24;
            border: 1px solid #2a2a3a;
            border-radius: 16px;
            padding: 2.5rem 2rem;
            width: 100%;
            max-width: 520px;
            box-shadow: 0 8px 40px rgba(0,0,0,.5);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: .6rem;
            margin-bottom: 2rem;
        }

        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, #6c63ff, #48cfad);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }

        .logo-text { font-size: 1.2rem; font-weight: 700; color: #fff; }
        .logo-text span { color: #6c63ff; }

        h1 { font-size: 1.6rem; font-weight: 700; color: #fff; margin-bottom: .5rem; }
        .subtitle { color: #888; font-size: .95rem; margin-bottom: 2rem; }

        label {
            display: block;
            font-size: .85rem;
            font-weight: 600;
            color: #aaa;
            margin-bottom: .5rem;
            letter-spacing: .04em;
            text-transform: uppercase;
        }

        .input-row { display: flex; gap: .5rem; }

        input[type="url"] {
            flex: 1;
            background: #12121a;
            border: 1px solid #2a2a3a;
            border-radius: 10px;
            color: #e2e2e8;
            font-size: .95rem;
            padding: .75rem 1rem;
            outline: none;
            transition: border-color .2s;
        }

        input[type="url"]:focus { border-color: #6c63ff; }
        input[type="url"]::placeholder { color: #444; }

        button[type="submit"] {
            background: linear-gradient(135deg, #6c63ff, #5a54e0);
            border: none;
            border-radius: 10px;
            color: #fff;
            cursor: pointer;
            font-size: .95rem;
            font-weight: 600;
            padding: .75rem 1.4rem;
            transition: opacity .2s, transform .1s;
            white-space: nowrap;
        }

        button[type="submit"]:hover  { opacity: .9; }
        button[type="submit"]:active { transform: scale(.97); }

        .error {
            margin-top: 1rem;
            background: rgba(255,80,80,.1);
            border: 1px solid rgba(255,80,80,.3);
            border-radius: 8px;
            color: #ff7070;
            font-size: .9rem;
            padding: .75rem 1rem;
        }

        .result {
            margin-top: 1.5rem;
            background: rgba(72,207,173,.08);
            border: 1px solid rgba(72,207,173,.25);
            border-radius: 12px;
            padding: 1.25rem 1rem;
        }

        .result-label {
            font-size: .8rem;
            font-weight: 600;
            color: #48cfad;
            letter-spacing: .06em;
            text-transform: uppercase;
            margin-bottom: .6rem;
        }

        .result-row { display: flex; align-items: center; gap: .5rem; }

        .short-url {
            flex: 1;
            background: #12121a;
            border: 1px solid #2a2a3a;
            border-radius: 8px;
            color: #fff;
            font-family: 'Courier New', monospace;
            font-size: .95rem;
            padding: .6rem .9rem;
            word-break: break-all;
        }

        .copy-btn {
            background: #2a2a3a;
            border: 1px solid #3a3a4a;
            border-radius: 8px;
            color: #ccc;
            cursor: pointer;
            font-size: .85rem;
            padding: .6rem .9rem;
            transition: background .2s, color .2s;
            white-space: nowrap;
        }

        .copy-btn:hover  { background: #3a3a4a; color: #fff; }
        .copy-btn.copied { background: rgba(72,207,173,.15); color: #48cfad; border-color: #48cfad44; }

        .not-found {
            margin-top: 1rem;
            background: rgba(255,160,50,.08);
            border: 1px solid rgba(255,160,50,.25);
            border-radius: 8px;
            color: #ffa050;
            font-size: .9rem;
            padding: .75rem 1rem;
        }

        .footer { margin-top: 2rem; text-align: center; font-size: .8rem; color: #444; }
        .footer a { color: #6c63ff; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="card">
    <div class="logo">
        <div class="logo-icon">&#x1f517;</div>
        <div class="logo-text"><span>code</span>.dk / link</div>
    </div>

    <h1>Shorten a URL</h1>
    <p class="subtitle">Paste any long link and get a short, shareable URL.</p>

    <form method="POST" action="" id="shorten-form">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES) ?>">
        <label for="url-input">Your long URL</label>
        <div class="input-row">
            <input
                type="url"
                id="url-input"
                name="url"
                placeholder="https://example.com/very/long/url..."
                maxlength="<?= MAX_URL_LEN ?>"
                required
                autofocus
            >
            <button type="submit">Shorten</button>
        </div>
    </form>

    <?php if ($notFound): ?>
        <div class="not-found">
            Short link <strong><?= htmlspecialchars($code, ENT_QUOTES) ?></strong> was not found.
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="error"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
    <?php endif; ?>

    <?php if ($shortUrl): ?>
        <div class="result">
            <div class="result-label">Your short link</div>
            <div class="result-row">
                <div class="short-url" id="short-url-text"><?= htmlspecialchars($shortUrl, ENT_QUOTES) ?></div>
                <button class="copy-btn" id="copy-btn" type="button">Copy</button>
            </div>
        </div>
    <?php endif; ?>

    <div class="footer">
        Links never expire &mdash; <a href="/">code.dk</a>
    </div>
</div>

<script nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES) ?>">
(function () {
    const btn = document.getElementById('copy-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
        const text = document.getElementById('short-url-text').textContent.trim();
        navigator.clipboard.writeText(text).then(function () {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function () {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        });
    });
})();
</script>
</body>
</html>
