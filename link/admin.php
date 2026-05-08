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
// Configuration — CHANGE ADMIN_PASSWORD BEFORE UPLOADING
// ---------------------------------------------------------------------------

define('DB_PATH',        __DIR__ . '/data/urls.db');
define('LOG_PATH',       __DIR__ . '/data/app.log');
define('ADMIN_PASSWORD', 'changeme');   // ← set your password here
define('PER_PAGE',       50);

// ---------------------------------------------------------------------------
// CSP nonce + security headers
// ---------------------------------------------------------------------------

$cspNonce = base64_encode(random_bytes(16));

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'nonce-{$cspNonce}'; script-src 'nonce-{$cspNonce}'");
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// ---------------------------------------------------------------------------
// Hardened session
// ---------------------------------------------------------------------------

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function logError(string $message): void {
    $line = '[' . date('Y-m-d H:i:s') . '] ' . $message . PHP_EOL;
    @file_put_contents(LOG_PATH, $line, FILE_APPEND | LOCK_EX);
    error_log($message);
}

// ---------------------------------------------------------------------------
// Database — singleton, shared schema with index.php
// ---------------------------------------------------------------------------

function getDb(): PDO {
    static $db = null;
    if ($db !== null) {
        return $db;
    }

    if (!file_exists(DB_PATH)) {
        http_response_code(503);
        exit('Database not found. Visit the shortener page first to initialise it.');
    }

    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("PRAGMA journal_mode=WAL");

    // Ensure clicks column exists for installs that pre-date it
    try {
        $db->exec("ALTER TABLE urls ADD COLUMN clicks INTEGER NOT NULL DEFAULT 0");
    } catch (PDOException) {
        // Already exists
    }

    return $db;
}

// ---------------------------------------------------------------------------
// Password — bcrypt hash auto-stored in config table on first login
// ---------------------------------------------------------------------------

function getStoredHash(): ?string {
    $stmt = getDb()->prepare("SELECT value FROM config WHERE key = 'admin_password_hash'");
    $stmt->execute();
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ? $row['value'] : null;
}

function storeHash(string $hash): void {
    getDb()->prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('admin_password_hash', ?)")
           ->execute([$hash]);
}

function verifyAdminPassword(string $submitted): bool {
    $stored = getStoredHash();

    if ($stored === null || !password_verify(ADMIN_PASSWORD, $stored)) {
        // First run, or ADMIN_PASSWORD was changed — re-hash and store
        $stored = password_hash(ADMIN_PASSWORD, PASSWORD_DEFAULT);
        storeHash($stored);
    }

    return password_verify($submitted, $stored);
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
// Auth helpers
// ---------------------------------------------------------------------------

function isLoggedIn(): bool {
    return !empty($_SESSION['admin_authed']);
}

function requireLogin(): void {
    if (!isLoggedIn()) {
        header('Location: /link/admin.php');
        exit;
    }
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

$action = $_GET['action'] ?? ($_POST['action'] ?? '');
$error  = null;

// Logout
if ($action === 'logout' && isLoggedIn()) {
    session_destroy();
    header('Location: /link/admin.php');
    exit;
}

// Login POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'login') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request. Please refresh and try again.';
    } else {
        try {
            if (verifyAdminPassword($_POST['password'] ?? '')) {
                session_regenerate_id(true);
                $_SESSION['admin_authed'] = true;
                header('Location: /link/admin.php');
                exit;
            } else {
                $error = 'Incorrect password.';
            }
        } catch (Throwable $e) {
            logError('Admin login error: ' . $e->getMessage());
            $error = 'A server error occurred.';
        }
    }
}

// Delete URL
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'delete') {
    requireLogin();
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid request.';
    } else {
        $code = trim($_POST['code'] ?? '');
        if ($code !== '') {
            try {
                getDb()->prepare('DELETE FROM urls WHERE code = ?')->execute([$code]);
            } catch (Throwable $e) {
                logError('Admin delete error: ' . $e->getMessage());
                $error = 'Failed to delete link.';
            }
        }
        header('Location: /link/admin.php' . (isset($_GET['page']) ? '?page=' . (int) $_GET['page'] : ''));
        exit;
    }
}

// ---------------------------------------------------------------------------
// Dashboard data
// ---------------------------------------------------------------------------

$stats    = null;
$urls     = [];
$total    = 0;
$page     = max(1, (int) ($_GET['page'] ?? 1));
$sort     = in_array($_GET['sort'] ?? '', ['clicks', 'created', 'code'], true) ? $_GET['sort'] : 'clicks';
$dir      = ($_GET['dir'] ?? 'desc') === 'asc' ? 'asc' : 'desc';

if (isLoggedIn()) {
    try {
        $db = getDb();

        $stats = $db->query("SELECT COUNT(*) AS total_links, COALESCE(SUM(clicks),0) AS total_clicks FROM urls")
                    ->fetch(PDO::FETCH_ASSOC);

        $total  = (int) $stats['total_links'];
        $offset = ($page - 1) * PER_PAGE;

        $urls = $db->query(
            "SELECT code, url, created, clicks
             FROM urls
             ORDER BY {$sort} {$dir}
             LIMIT " . PER_PAGE . " OFFSET {$offset}"
        )->fetchAll(PDO::FETCH_ASSOC);

    } catch (Throwable $e) {
        logError('Admin dashboard error: ' . $e->getMessage());
        $error = 'Could not load data.';
    }
}

$csrfToken  = getCsrfToken();
$totalPages = $total > 0 ? (int) ceil($total / PER_PAGE) : 1;

function sortUrl(string $col): string {
    global $sort, $dir, $page;
    $newDir = ($sort === $col && $dir === 'desc') ? 'asc' : 'desc';
    return '/link/admin.php?sort=' . $col . '&dir=' . $newDir . '&page=' . $page;
}

function sortArrow(string $col): string {
    global $sort, $dir;
    if ($sort !== $col) return '<span class="arrow neutral">⇅</span>';
    return '<span class="arrow">' . ($dir === 'asc' ? '↑' : '↓') . '</span>';
}

function pageUrl(int $p): string {
    global $sort, $dir;
    return '/link/admin.php?sort=' . $sort . '&dir=' . $dir . '&page=' . $p;
}

function truncate(string $str, int $max = 60): string {
    return mb_strlen($str) > $max ? mb_substr($str, 0, $max) . '…' : $str;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin — code.dk/link</title>
    <style nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES) ?>">
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f13;
            color: #e2e2e8;
            min-height: 100vh;
            padding: 2rem 1rem;
        }

        a { color: #6c63ff; text-decoration: none; }
        a:hover { text-decoration: underline; }

        /* Login card */
        .login-wrap {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin-top: -2rem;
        }

        .card {
            background: #1a1a24;
            border: 1px solid #2a2a3a;
            border-radius: 16px;
            padding: 2.5rem 2rem;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 8px 40px rgba(0,0,0,.5);
        }

        .card h1 { font-size: 1.4rem; color: #fff; margin-bottom: .4rem; }
        .card .sub { color: #888; font-size: .9rem; margin-bottom: 1.8rem; }

        label {
            display: block;
            font-size: .8rem;
            font-weight: 600;
            color: #aaa;
            letter-spacing: .05em;
            text-transform: uppercase;
            margin-bottom: .45rem;
        }

        input[type="password"] {
            width: 100%;
            background: #12121a;
            border: 1px solid #2a2a3a;
            border-radius: 10px;
            color: #e2e2e8;
            font-size: .95rem;
            padding: .75rem 1rem;
            outline: none;
            transition: border-color .2s;
            margin-bottom: 1rem;
        }

        input[type="password"]:focus { border-color: #6c63ff; }

        .btn-primary {
            width: 100%;
            background: linear-gradient(135deg, #6c63ff, #5a54e0);
            border: none;
            border-radius: 10px;
            color: #fff;
            cursor: pointer;
            font-size: .95rem;
            font-weight: 600;
            padding: .8rem;
            transition: opacity .2s;
        }

        .btn-primary:hover { opacity: .88; }

        .error {
            margin-bottom: 1rem;
            background: rgba(255,80,80,.1);
            border: 1px solid rgba(255,80,80,.3);
            border-radius: 8px;
            color: #ff7070;
            font-size: .88rem;
            padding: .7rem .9rem;
        }

        /* Warning banner */
        .warn-banner {
            background: rgba(255,160,50,.1);
            border: 1px solid rgba(255,160,50,.35);
            border-radius: 10px;
            color: #ffa050;
            font-size: .88rem;
            padding: .8rem 1rem;
            margin-bottom: 1.5rem;
        }

        /* Dashboard layout */
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .topbar h1 { font-size: 1.4rem; color: #fff; }

        .btn-logout {
            background: #2a2a3a;
            border: 1px solid #3a3a4a;
            border-radius: 8px;
            color: #ccc;
            cursor: pointer;
            font-size: .85rem;
            padding: .5rem 1rem;
            text-decoration: none;
            transition: background .2s;
        }

        .btn-logout:hover { background: #3a3a4a; color: #fff; text-decoration: none; }

        /* Stat cards */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat {
            background: #1a1a24;
            border: 1px solid #2a2a3a;
            border-radius: 12px;
            padding: 1.2rem 1.4rem;
        }

        .stat-label { font-size: .78rem; color: #888; text-transform: uppercase; letter-spacing: .05em; margin-bottom: .4rem; }
        .stat-value { font-size: 2rem; font-weight: 700; color: #fff; }

        /* Table */
        .table-wrap {
            background: #1a1a24;
            border: 1px solid #2a2a3a;
            border-radius: 12px;
            overflow: hidden;
        }

        table { width: 100%; border-collapse: collapse; font-size: .88rem; }

        thead { background: #12121a; }

        th {
            padding: .75rem 1rem;
            text-align: left;
            font-size: .78rem;
            font-weight: 600;
            color: #888;
            text-transform: uppercase;
            letter-spacing: .05em;
            white-space: nowrap;
        }

        th a { color: #888; display: inline-flex; align-items: center; gap: .3rem; }
        th a:hover { color: #ccc; text-decoration: none; }
        .arrow { color: #6c63ff; }
        .arrow.neutral { color: #444; }

        td {
            padding: .75rem 1rem;
            border-top: 1px solid #1e1e2e;
            vertical-align: middle;
            color: #ccc;
        }

        tr:hover td { background: #1e1e2a; }

        .code-link { font-family: monospace; color: #6c63ff; font-size: .9rem; }
        .long-url { color: #aaa; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .clicks-badge {
            background: rgba(72,207,173,.12);
            border: 1px solid rgba(72,207,173,.25);
            border-radius: 20px;
            color: #48cfad;
            font-size: .8rem;
            font-weight: 600;
            padding: .2rem .7rem;
            display: inline-block;
        }
        .date-cell { color: #666; font-size: .82rem; white-space: nowrap; }

        .btn-delete {
            background: rgba(255,80,80,.08);
            border: 1px solid rgba(255,80,80,.2);
            border-radius: 6px;
            color: #ff7070;
            cursor: pointer;
            font-size: .8rem;
            padding: .3rem .7rem;
            transition: background .2s;
        }

        .btn-delete:hover { background: rgba(255,80,80,.2); }

        /* Pagination */
        .pagination {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: .5rem;
            margin-top: 1.5rem;
            flex-wrap: wrap;
        }

        .page-btn {
            background: #1a1a24;
            border: 1px solid #2a2a3a;
            border-radius: 7px;
            color: #aaa;
            font-size: .85rem;
            padding: .4rem .8rem;
            text-decoration: none;
            transition: background .2s, color .2s;
        }

        .page-btn:hover { background: #2a2a3a; color: #fff; text-decoration: none; }
        .page-btn.active { background: #6c63ff; border-color: #6c63ff; color: #fff; }
        .page-btn.disabled { opacity: .3; pointer-events: none; }

        .empty { padding: 3rem; text-align: center; color: #555; }
    </style>
</head>
<body>

<?php if (!isLoggedIn()): ?>

<div class="login-wrap">
    <div class="card">
        <h1>Admin login</h1>
        <p class="sub">code.dk / link</p>

        <?php if (ADMIN_PASSWORD === 'changeme'): ?>
            <div class="warn-banner">
                Default password is still set. Edit <code>admin.php</code> and change <code>ADMIN_PASSWORD</code> before using this in production.
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
        <?php endif; ?>

        <form method="POST" action="/link/admin.php?action=login">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES) ?>">
            <input type="hidden" name="action" value="login">
            <label for="pw">Password</label>
            <input type="password" id="pw" name="password" autofocus required>
            <button type="submit" class="btn-primary">Log in</button>
        </form>
    </div>
</div>

<?php else: ?>

<?php if (ADMIN_PASSWORD === 'changeme'): ?>
    <div class="warn-banner">
        Default password active — change <code>ADMIN_PASSWORD</code> in <code>admin.php</code> before going live.
    </div>
<?php endif; ?>

<div class="topbar">
    <h1>URL Shortener — Admin</h1>
    <a href="/link/admin.php?action=logout" class="btn-logout">Log out</a>
</div>

<?php if ($error): ?>
    <div class="error" style="margin-bottom:1.5rem"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
<?php endif; ?>

<!-- Stats -->
<div class="stats">
    <div class="stat">
        <div class="stat-label">Total links</div>
        <div class="stat-value"><?= number_format((int) ($stats['total_links'] ?? 0)) ?></div>
    </div>
    <div class="stat">
        <div class="stat-label">Total clicks</div>
        <div class="stat-value"><?= number_format((int) ($stats['total_clicks'] ?? 0)) ?></div>
    </div>
</div>

<!-- URL table -->
<div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th><a href="<?= sortUrl('code') ?>">Short code <?= sortArrow('code') ?></a></th>
                <th>Long URL</th>
                <th><a href="<?= sortUrl('created') ?>">Created <?= sortArrow('created') ?></a></th>
                <th><a href="<?= sortUrl('clicks') ?>">Clicks <?= sortArrow('clicks') ?></a></th>
                <th></th>
            </tr>
        </thead>
        <tbody>
        <?php if (empty($urls)): ?>
            <tr><td colspan="5" class="empty">No links yet.</td></tr>
        <?php else: ?>
            <?php foreach ($urls as $row): ?>
            <tr>
                <td>
                    <a class="code-link" href="/link/<?= htmlspecialchars($row['code'], ENT_QUOTES) ?>" target="_blank" rel="noopener noreferrer">
                        <?= htmlspecialchars($row['code'], ENT_QUOTES) ?>
                    </a>
                </td>
                <td>
                    <span class="long-url" title="<?= htmlspecialchars($row['url'], ENT_QUOTES) ?>">
                        <?= htmlspecialchars(truncate($row['url']), ENT_QUOTES) ?>
                    </span>
                </td>
                <td class="date-cell"><?= date('Y-m-d H:i', (int) $row['created']) ?></td>
                <td><span class="clicks-badge"><?= number_format((int) $row['clicks']) ?></span></td>
                <td>
                    <form method="POST" action="/link/admin.php?page=<?= $page ?>" onsubmit="return confirm('Delete this link?')">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES) ?>">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="code" value="<?= htmlspecialchars($row['code'], ENT_QUOTES) ?>">
                        <button type="submit" class="btn-delete">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        <?php endif; ?>
        </tbody>
    </table>
</div>

<!-- Pagination -->
<?php if ($totalPages > 1): ?>
<div class="pagination">
    <a href="<?= pageUrl($page - 1) ?>" class="page-btn <?= $page <= 1 ? 'disabled' : '' ?>">← Prev</a>

    <?php
    $start = max(1, $page - 2);
    $end   = min($totalPages, $page + 2);
    if ($start > 1): ?><a href="<?= pageUrl(1) ?>" class="page-btn">1</a><?php if ($start > 2): ?><span class="page-btn disabled">…</span><?php endif; endif; ?>

    <?php for ($p = $start; $p <= $end; $p++): ?>
        <a href="<?= pageUrl($p) ?>" class="page-btn <?= $p === $page ? 'active' : '' ?>"><?= $p ?></a>
    <?php endfor; ?>

    <?php if ($end < $totalPages): ?><?php if ($end < $totalPages - 1): ?><span class="page-btn disabled">…</span><?php endif; ?><a href="<?= pageUrl($totalPages) ?>" class="page-btn"><?= $totalPages ?></a><?php endif; ?>

    <a href="<?= pageUrl($page + 1) ?>" class="page-btn <?= $page >= $totalPages ? 'disabled' : '' ?>">Next →</a>
</div>
<?php endif; ?>

<?php endif; ?>

</body>
</html>
