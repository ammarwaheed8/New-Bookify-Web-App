<?php
declare(strict_types=1);

class ApiException extends RuntimeException
{
    public int $status;

    public function __construct(string $message, int $status = 400)
    {
        parent::__construct($message);
        $this->status = $status;
    }
}

/** Throw a user-facing API error (message is safe to display). */
function fail(string $msg, int $status = 400): void
{
    throw new ApiException($msg, $status);
}

function json_out($data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function json_err(string $msg, int $status = 400): void
{
    json_out(['ok' => false, 'error' => $msg], $status);
}

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $cfg = config()['session'];

    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    session_name($cfg['name'] ?? 'BOOKIFYSESSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();

    $now      = time();
    $lifetime = (int) ($cfg['lifetime'] ?? 7200);

    if (!isset($_SESSION['rotated_at'])) {
        $_SESSION['rotated_at'] = $now;
    } elseif ($now - (int) $_SESSION['rotated_at'] > 900) {
        session_regenerate_id(true); // rotate periodically
        $_SESSION['rotated_at'] = $now;
    }

    // Idle timeout only matters once signed in.
    if (isset($_SESSION['user_id'])) {
        $last = (int) ($_SESSION['last_seen'] ?? $now);
        if ($now - $last > $lifetime) {
            $_SESSION = [];
            session_destroy();
            json_err('Session expired. Please sign in again.', 401);
        }
        $_SESSION['last_seen'] = $now;
    }
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_check(): void
{
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['_csrf'] ?? '');
    if (!is_string($sent) || $sent === '' || !hash_equals((string) ($_SESSION['csrf'] ?? ''), $sent)) {
        fail('Invalid or missing security token. Refresh the page and try again.', 419);
    }
}

function read_input(): array
{
    static $cached = null;
    if ($cached !== null) {
        return $cached;
    }
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method === 'GET') {
        $cached = $_GET;
        return $cached;
    }
    $raw = file_get_contents('php://input') ?: '';
    $data = [];
    if (trim($raw) !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            $data = $decoded;
        }
    }
    if (!$data) {
        $data = $_POST;
    }
    $cached = $data;
    return $cached;
}

/* ---------- validation helpers (throw ApiException 422) ---------- */

function f_str(array $in, string $key, string $label, int $min = 1, int $max = 255, bool $required = true): string
{
    $v = $in[$key] ?? '';
    if (is_array($v) || is_object($v)) {
        fail($label . ' must be text.', 422);
    }
    $v = trim((string) $v);
    if ($v === '') {
        if ($required) {
            fail($label . ' is required.', 422);
        }
        return '';
    }
    $len = mb_strlen($v);
    if ($len < $min) {
        fail($label . " must be at least $min characters.", 422);
    }
    if ($len > $max) {
        fail($label . " must be at most $max characters.", 422);
    }
    return $v;
}

function f_opt(array $in, string $key, string $label, int $max = 255): string
{
    return f_str($in, $key, $label, 0, $max, false);
}

function f_email(array $in, string $key = 'email', string $label = 'Email', bool $required = true): string
{
    $v = f_str($in, $key, $label, 3, 254, $required);
    if ($v === '') {
        return '';
    }
    if (!filter_var($v, FILTER_VALIDATE_EMAIL)) {
        fail('Please enter a valid email address.', 422);
    }
    return strtolower($v);
}

function f_password(array $in, string $key = 'password', string $label = 'Password'): string
{
    $v = (string) ($in[$key] ?? '');
    if ($v === '') {
        fail($label . ' is required.', 422);
    }
    if (strlen($v) < 8) {
        fail($label . ' must be at least 8 characters.', 422);
    }
    if (strlen($v) > 200) {
        fail($label . ' must be at most 200 characters.', 422);
    }
    return $v;
}

function f_int(array $in, string $key, string $label, int $min, int $max, bool $required = true, int $default = 0): int
{
    $raw = $in[$key] ?? '';
    if ($raw === '' || $raw === null) {
        if ($required) {
            fail($label . ' is required.', 422);
        }
        return $default;
    }
    if (is_bool($raw) || is_array($raw) || !is_numeric($raw)) {
        fail($label . ' must be a number.', 422);
    }
    $v = (int) $raw;
    if ($v < $min || $v > $max) {
        fail("$label must be between $min and $max.", 422);
    }
    return $v;
}

function valid_date(string $d): ?string
{
    $ts = DateTime::createFromFormat('Y-m-d', $d);
    return ($ts && $ts->format('Y-m-d') === $d) ? $d : null;
}

function f_date(array $in, string $key, string $label, bool $required = true): string
{
    $v = f_str($in, $key, $label, 10, 10, $required);
    if ($v === '') {
        return '';
    }
    if (!valid_date($v)) {
        fail($label . ' must use YYYY-MM-DD format.', 422);
    }
    return $v;
}

function f_enum(array $in, string $key, string $label, array $allowed): string
{
    $v = f_str($in, $key, $label, 1, 50);
    if (!in_array($v, $allowed, true)) {
        fail('Invalid ' . strtolower($label) . '.', 422);
    }
    return $v;
}

function f_list(array $in, string $key, string $label, bool $required = false): array
{
    $raw = $in[$key] ?? null;
    if ($raw === null || $raw === '') {
        if ($required) {
            fail($label . ' is required.', 422);
        }
        return [];
    }
    if (is_string($raw)) {
        $decoded = json_decode($raw, true);
        $raw = is_array($decoded) ? $decoded : array_filter(array_map('trim', explode(',', $raw)));
    }
    if (!is_array($raw)) {
        fail($label . ' must be a list.', 422);
    }
    return array_values($raw);
}

/** Escape for HTML output. */
function e($s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function client_ip(): string
{
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
}
