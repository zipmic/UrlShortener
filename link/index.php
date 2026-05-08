<?php
declare(strict_types=1);

define('DB_PATH', __DIR__ . '/data/urls.db');
define('BASE_URL', 'https://www.code.dk/link/');
define('CODE_LENGTH', 6);

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

function getDb(): PDO {
    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("CREATE TABLE IF NOT EXISTS urls (
        code    TEXT PRIMARY KEY,
        url     TEXT NOT NULL,
        created INTEGER NOT NULL
    )");
    return $db;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateCode(PDO $db): string {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    do {
        $code = '';
        for ($i = 0; $i < CODE_LENGTH; $i++) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }
        $stmt = $db->prepare('SELECT 1 FROM urls WHERE code = ?');
        $stmt->execute([$code]);
    } while ($stmt->fetchColumn());
    return $code;
}

function isValidUrl(string $url): bool {
    return filter_var($url, FILTER_VALIDATE_URL) !== false
        && preg_match('/^https?:\/\//i', $url) === 1;
}

function lookupCode(PDO $db, string $code): ?string {
    $stmt = $db->prepare('SELECT url FROM urls WHERE code = ?');
    $stmt->execute([$code]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ? $row['url'] : null;
}

function storeUrl(PDO $db, string $url): string {
    // Return existing code if URL was already shortened
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
// Request routing
// ---------------------------------------------------------------------------

$code = trim($_GET['code'] ?? '');

// Redirect if a short code was requested
if ($code !== '') {
    $db  = getDb();
    $url = lookupCode($db, $code);
    if ($url !== null) {
        header('Location: ' . $url, true, 301);
        exit;
    }
    // Invalid code — fall through to show the page with an error
    $notFound = true;
}

$shortUrl   = null;
$error      = null;

// Handle form submission / JSON API
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $isJson = str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')
           || str_contains($_SERVER['CONTENT_TYPE'] ?? '', 'application/json');

    $body    = $isJson ? json_decode(file_get_contents('php://input'), true) : null;
    $longUrl = trim($body['url'] ?? $_POST['url'] ?? '');

    if ($longUrl === '') {
        $error = 'Please enter a URL.';
    } elseif (!isValidUrl($longUrl)) {
        $error = 'Please enter a valid URL starting with http:// or https://';
    } else {
        $db      = getDb();
        $newCode = storeUrl($db, $longUrl);
        $shortUrl = BASE_URL . $newCode;
    }

    if ($isJson) {
        header('Content-Type: application/json');
        if ($error) {
            echo json_encode(['error' => $error]);
        } else {
            echo json_encode(['short_url' => $shortUrl, 'code' => $newCode]);
        }
        exit;
    }
}
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

        .logo-text {
            font-size: 1.2rem;
            font-weight: 700;
            color: #fff;
        }

        .logo-text span {
            color: #6c63ff;
        }

        h1 {
            font-size: 1.6rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: .5rem;
        }

        .subtitle {
            color: #888;
            font-size: .95rem;
            margin-bottom: 2rem;
        }

        label {
            display: block;
            font-size: .85rem;
            font-weight: 600;
            color: #aaa;
            margin-bottom: .5rem;
            letter-spacing: .04em;
            text-transform: uppercase;
        }

        .input-row {
            display: flex;
            gap: .5rem;
        }

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

        input[type="url"]:focus {
            border-color: #6c63ff;
        }

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

        .result-row {
            display: flex;
            align-items: center;
            gap: .5rem;
        }

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

        .footer {
            margin-top: 2rem;
            text-align: center;
            font-size: .8rem;
            color: #444;
        }

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
        <label for="url-input">Your long URL</label>
        <div class="input-row">
            <input
                type="url"
                id="url-input"
                name="url"
                placeholder="https://example.com/very/long/url..."
                value="<?= htmlspecialchars($_POST['url'] ?? '', ENT_QUOTES) ?>"
                required
                autofocus
            >
            <button type="submit">Shorten</button>
        </div>
    </form>

    <?php if (isset($notFound)): ?>
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
