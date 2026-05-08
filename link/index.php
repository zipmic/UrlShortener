<?php
declare(strict_types=1);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// To store the DB outside the web root (strongly recommended on production),
// change this to an absolute path above your public_html / www directory.
// Example for typical shared hosting:
//   define('DB_PATH', dirname(__DIR__, 2) . '/urlshortener_data/urls.db');
define('DB_PATH',            __DIR__ . '/data/urls.db');
define('BASE_URL',           'https://www.code.dk/link/');
define('CODE_LEN',           6);
define('MAX_URL_LEN',        2048);
define('RATE_LIMIT_MAX',     10);   // max submissions per IP per window
define('RATE_LIMIT_WINDOW',  60);   // seconds

const BLOCKED_DOMAINS = [
    'localhost',
    // extend with known phishing / malware domains as needed
];

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'");

// ---------------------------------------------------------------------------
// Session + CSRF
// ---------------------------------------------------------------------------

session_start();

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
// Database
// ---------------------------------------------------------------------------

function getDb(): PDO {
    $dir = dirname(DB_PATH);
    if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create data directory: ' . $dir);
    }

    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // WAL mode reduces write-lock contention under concurrent traffic
    $db->exec("PRAGMA journal_mode=WAL");

    $db->exec("CREATE TABLE IF NOT EXISTS urls (
        code    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        created INTEGER NOT NULL
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
        ip  TEXT    NOT NULL,
        ts  INTEGER NOT NULL
    )");

    $db->exec("CREATE INDEX IF NOT EXISTS idx_rate ON rate_limits (ip, ts)");

    return $db;
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

function checkRateLimit(PDO $db, string $ip): bool {
    $since = time() - RATE_LIMIT_WINDOW;

    // Prune expired entries to keep the table small
    $db->prepare('DELETE FROM rate_limits WHERE ts < ?')->execute([$since]);

    $stmt = $db->prepare('SELECT COUNT(*) FROM rate_limits WHERE ip = ? AND ts >= ?');
    $stmt->execute([$ip, $since]);
    return (int) $stmt->fetchColumn() < RATE_LIMIT_MAX;
}

function recordRequest(PDO $db, string $ip): void {
    $db->prepare('INSERT INTO rate_limits (ip, ts) VALUES (?, ?)')->execute([$ip, time()]);
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

function isValidUrl(string $url): bool {
    if (strlen($url) > MAX_URL_LEN) {
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

    // Block explicitly listed domains
    foreach (BLOCKED_DOMAINS as $blocked) {
        if ($host === $blocked || str_ends_with($host, '.' . $blocked)) {
            return false;
        }
    }

    // Block private / loopback / reserved IP addresses
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $isPublic = filter_var(
            $host,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        if ($isPublic === false) {
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// URL storage helpers
// ---------------------------------------------------------------------------

function generateCode(PDO $db): string {
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

function lookupCode(PDO $db, string $code): ?string {
    $stmt = $db->prepare('SELECT url FROM urls WHERE code = ?');
    $stmt->execute([$code]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ? $row['url'] : null;
}

function storeUrl(PDO $db, string $url): string {
    $stmt = $db->prepare('SELECT code FROM urls WHERE url = ?');
    $stmt->execute([$url]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        return $row['code'];
    }

    $code = generateCode($db);
    $db->prepare('INSERT INTO urls (code, url, created) VALUES (?, ?, ?)')
       ->execute([$code, $url, time()]);
    return $code;
}

// ---------------------------------------------------------------------------
// Safe redirect — strips header-injection characters before sending Location
// ---------------------------------------------------------------------------

function safeRedirect(string $url): void {
    $url = str_replace(["\r", "\n", "\0"], '', $url);
    header('Location: ' . $url, true, 301);
    exit;
}

// ---------------------------------------------------------------------------
// Request routing
// ---------------------------------------------------------------------------

$clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$code     = trim($_GET['code'] ?? '');
$shortUrl = null;
$newCode  = null;
$error    = null;
$notFound = false;

try {
    if ($code !== '') {
        $db  = getDb();
        $url = lookupCode($db, $code);
        if ($url !== null) {
            safeRedirect($url);
        }
        $notFound = true;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $isJson = str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')
               || str_contains($_SERVER['CONTENT_TYPE'] ?? '', 'application/json');

        if ($isJson) {
            $body    = json_decode((string) file_get_contents('php://input'), true) ?? [];
            $longUrl = trim((string) ($body['url'] ?? ''));
            $csrf    = (string) ($body['csrf_token'] ?? '');
        } else {
            $longUrl = trim((string) ($_POST['url'] ?? ''));
            $csrf    = (string) ($_POST['csrf_token'] ?? '');
        }

        if (!verifyCsrf($csrf)) {
            $error = 'Invalid request. Please refresh the page and try again.';
        } elseif ($longUrl === '') {
            $error = 'Please enter a URL.';
        } elseif (strlen($longUrl) > MAX_URL_LEN) {
            $error = 'URL is too long (max ' . MAX_URL_LEN . ' characters).';
        } elseif (!isValidUrl($longUrl)) {
            $error = 'Please enter a valid URL starting with http:// or https://';
        } else {
            $db = getDb();
            if (!checkRateLimit($db, $clientIp)) {
                $error = 'Too many requests. Please wait a moment and try again.';
            } else {
                recordRequest($db, $clientIp);
                $newCode  = storeUrl($db, $longUrl);
                $shortUrl = BASE_URL . $newCode;
            }
        }

        if ($isJson) {
            header('Content-Type: application/json');
            echo $error
                ? json_encode(['error' => $error])
                : json_encode(['short_url' => $shortUrl, 'code' => $newCode]);
            exit;
        }
    }
} catch (Throwable $e) {
    error_log('URL shortener error: ' . $e->getMessage());
    $error = 'A server error occurred. Please try again later.';
}

$csrfToken = getCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Shortener — code.dk</title>
    <style>
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

    <form method="POST" action="/link/" id="shorten-form">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES) ?>">
        <label for="url-input">Your long URL</label>
        <div class="input-row">
            <input
                type="url"
                id="url-input"
                name="url"
                placeholder="https://example.com/very/long/url..."
                value="<?= htmlspecialchars($_POST['url'] ?? '', ENT_QUOTES) ?>"
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

<script>
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
