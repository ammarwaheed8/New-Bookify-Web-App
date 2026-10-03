<?php
declare(strict_types=1);

define('BOOKIFY_ROOT', dirname(__DIR__));

$cfgFile = BOOKIFY_ROOT . '/config.php';
if (!file_exists($cfgFile)) $cfgFile = BOOKIFY_ROOT . '/config.example.php';
$CONFIG = require $cfgFile;

date_default_timezone_set('UTC');
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

function cfg(string $key, mixed $default = null): mixed {
    global $CONFIG;
    $v = $CONFIG;
    foreach (explode('.', $key) as $part) {
        if (!is_array($v) || !array_key_exists($part, $v)) return $default;
        $v = $v[$part];
    }
    return $v;
}

function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $path = cfg('db.path');
        if (!is_dir(dirname($path))) mkdir(dirname($path), 0775, true);
        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec('PRAGMA foreign_keys = ON');
    }
    return $pdo;
}

function start_app_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    session_name(cfg('session.name', 'BOOKIFYSESSID'));
    session_set_cookie_params([
        'lifetime' => (int) cfg('session.lifetime', 7200),
        'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Lax',
    ]);
    session_start();
    if (empty($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } elseif (time() - $_SESSION['created'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

function json_in(): array {
    $raw = file_get_contents('php://input');
    $d = json_decode($raw ?: '[]', true);
    return is_array($d) ? $d : [];
}

function out(mixed $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(string $msg, int $code = 400, array $extra = []): never {
    out(array_merge(['ok' => false, 'error' => $msg], $extra), $code);
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}

function require_csrf(): void {
    $tok = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!$tok || empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $tok)) {
        fail('Your session security token is missing or expired. Reload the page.', 403);
    }
}

function current_user(): ?array {
    if (array_key_exists('user', $_SESSION)) return $_SESSION['user'];
    if (empty($_SESSION['uid'])) { $_SESSION['user'] = null; return null; }
    $st = db()->prepare(
        'SELECT id, name, email, username, phone, type, status, email_verified_at,
                country, city, address, date_of_birth, preferences, created_at
         FROM users WHERE id = ?'
    );
    $st->execute([$_SESSION['uid']]);
    $_SESSION['user'] = $st->fetch() ?: null;
    if (!$_SESSION['user']) unset($_SESSION['uid']);
    return $_SESSION['user'];
}

function invalidate_user_cache(): void { unset($_SESSION['user']); }

function require_login(): array {
    $u = current_user();
    if (!$u) fail('You must be signed in.', 401);
    return $u;
}

function require_verified(): array {
    $u = require_login();
    if ($u['type'] === 'customer') {
        if (!$u['email_verified_at']) fail('Verify your email address before booking.', 403, ['code' => 'unverified']);
        if ($u['status'] !== 'active') fail('Your account is not active. Contact support.', 403, ['code' => 'inactive']);
    }
    return $u;
}

function require_staff(): array {
    $u = require_login();
    if ($u['type'] !== 'admin' || $u['status'] !== 'active') fail('Admin access required.', 403);
    return $u;
}

function is_super(int $uid): bool {
    static $cache = [];
    if (isset($cache[$uid])) return $cache[$uid];
    $st = db()->prepare("SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.name = 'super_admin'");
    $st->execute([$uid]);
    return $cache[$uid] = (bool) $st->fetchColumn();
}

function all_perms(int $uid): array {
    static $cache = [];
    if (isset($cache[$uid])) return $cache[$uid];
    if (is_super($uid)) {
        return $cache[$uid] = array_column(db()->query('SELECT code FROM permissions')->fetchAll(), 'code');
    }
    $st = db()->prepare(
        'SELECT DISTINCT p.code FROM permissions p
         LEFT JOIN role_permissions rp ON rp.permission_id = p.id
         LEFT JOIN user_roles ur ON ur.role_id = rp.role_id AND ur.user_id = ?
         LEFT JOIN user_permissions up ON up.permission_id = p.id AND up.user_id = ?
         WHERE ur.user_id IS NOT NULL OR up.user_id IS NOT NULL'
    );
    $st->execute([$uid, $uid]);
    return $cache[$uid] = array_column($st->fetchAll(), 'code');
}

function can(string $code): bool {
    $u = current_user();
    if (!$u || $u['type'] !== 'admin' || $u['status'] !== 'active') return false;
    return in_array($code, all_perms($u['id']), true);
}

function require_perm(string $code): array {
    $u = require_staff();
    if (!can($code)) fail('You do not have permission to perform this action.', 403, ['code' => 'forbidden', 'perm' => $code]);
    return $u;
}

function audit(string $action, string $entity, ?int $entityId, string $details = ''): void {
    $u = current_user();
    db()->prepare('INSERT INTO audit_logs(actor_id, actor_name, action, entity, entity_id, details, ip) VALUES (?,?,?,?,?,?,?)')
        ->execute([$u['id'] ?? null, $u['name'] ?? 'system', $action, $entity, $entityId, $details,
                   $_SERVER['REMOTE_ADDR'] ?? '']);
}

function send_verification_email(int $uid, string $name, string $email, string $token): string {
    $ttl = (int) cfg('email.verification_ttl_hours', 24);
    $url = cfg('app.base_url') . '/index.html?verify=' . $token;
    $body = "Hi $name,\n\nConfirm your Bookify email address by opening:\n$url\n\n"
          . "This link expires in $ttl hour(s).\n\nIf you did not create this account, ignore this message.\n";
    if (cfg('email.driver') === 'mail') {
        $headers = 'From: ' . cfg('email.from_name', 'Bookify') . ' <' . cfg('email.from') . ">\r\n"
                 . "Content-Type: text/plain; charset=UTF-8\r\n";
        @mail($email, 'Confirm your Bookify account', $body, $headers);
    }
    $log = cfg('email.log_file');
    if (!is_dir(dirname($log))) @mkdir(dirname($log), 0775, true);
    @file_put_contents($log, '[' . date('c') . "] TO: $email\n$body\n", FILE_APPEND);
    return $url;
}

function send_reset_email(array $u, string $token): string {
    $ttl = (int) cfg('email.reset_ttl_hours', 1);
    $url = cfg('app.base_url') . '/index.html#reset=' . $token;
    $body = "Hi {$u['name']},\n\nReset your Bookify password:\n$url\n\nThis link expires in $ttl hour(s).\n";
    if (cfg('email.driver') === 'mail') {
        $headers = 'From: ' . cfg('email.from_name', 'Bookify') . ' <' . cfg('email.from') . ">\r\n";
        @mail($u['email'], 'Reset your Bookify password', $body, $headers);
    }
    $log = cfg('email.log_file');
    if (!is_dir(dirname($log))) @mkdir(dirname($log), 0775, true);
    @file_put_contents($log, '[' . date('c') . "] TO: {$u['email']}\n$body\n", FILE_APPEND);
    return $url;
}

function slugify(string $s): string {
    $s = strtolower(trim(preg_replace('/[^a-z0-9]+/i', '-', $s), '-'));
    return $s ?: 'item';
}

function money(float $n): string { return cfg('booking.symbol', '$') . number_format($n, 2); }
