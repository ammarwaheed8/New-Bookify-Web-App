<?php
declare(strict_types=1);

define('BOOKIFY_ROOT', dirname(__DIR__));

/* ---------------- configuration ---------------- */

function cfg(?string $key = null, mixed $default = null): mixed {
    static $config = null;
    if ($config === null) {
        $file = BOOKIFY_ROOT . '/config.php';
        if (!is_file($file)) {
            $file = BOOKIFY_ROOT . '/config.example.php';
        }
        $loaded = is_file($file) ? require $file : [];
        $config = is_array($loaded) ? $loaded : [];
    }
    if ($key === null) {
        return $config;
    }
    $value = $config;
    foreach (explode('.', $key) as $segment) {
        if (!is_array($value) || !array_key_exists($segment, $value)) {
            return $default;
        }
        $value = $value[$segment];
    }
    return $value;
}

/* ---------------- database ---------------- */

function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $path = (string) cfg('db.path', BOOKIFY_ROOT . '/database/bookify.sqlite');
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            error_log('bookify: cannot create database directory');
            exit('Storage directory is not writable.');
        }
        try {
            $pdo = new PDO('sqlite:' . $path, null, null, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $ex) {
            error_log('bookify: db connection failed: ' . $ex->getMessage());
            exit('Database is not available.');
        }
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec('PRAGMA busy_timeout = 5000');
    }
    return $pdo;
}

function scalar(string $sql, array $params = []): float {
    $st = db()->prepare($sql);
    $st->execute($params);
    return (float) $st->fetchColumn();
}

/* ---------------- sessions & CSRF ---------------- */

function boot_session(): void {
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    session_name((string) cfg('session.name', 'BOOKIFYSESSID'));
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    ini_set('session.use_strict_mode', '1');
    session_start();
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return (string) $_SESSION['csrf'];
}

function require_csrf(): void {
    $token = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if ($token === '') {
        $token = (string) ($_POST['csrf_token'] ?? '');
    }
    $known = (string) ($_SESSION['csrf'] ?? '');
    if ($known === '' || $token === '' || !hash_equals($known, $token)) {
        fail('Your session security token is invalid. Refresh the page and try again.', 419);
    }
}

function destroy_session(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], (bool) $p['secure'], (bool) $p['httponly']);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

/* ---------------- requests & responses ---------------- */

function read_body(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function respond(array $payload, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function ok(array $data = []): never {
    respond(['ok' => true, 'data' => $data], 200);
}

function fail(string $message, int $status = 400, array $extra = []): never {
    respond(array_merge(['ok' => false, 'error' => $message], $extra), $status);
}

/* ---------------- validation ---------------- */

function req_str(array $d, string $key, string $label, int $min = 1, int $max = 255): string {
    $v = trim((string) ($d[$key] ?? ''));
    $len = function_exists('mb_strlen') ? mb_strlen($v) : strlen($v);
    if ($v === '') {
        fail($label . ' is required.');
    }
    if ($len < $min) {
        fail($label . ' must be at least ' . $min . ' characters.');
    }
    if ($len > $max) {
        fail($label . ' must be at most ' . $max . ' characters.');
    }
    return $v;
}

function opt_str(array $d, string $key, int $max = 500): string {
    $v = trim((string) ($d[$key] ?? ''));
    $len = function_exists('mb_strlen') ? mb_strlen($v) : strlen($v);
    if ($len > $max) {
        fail($key . ' is too long (max ' . $max . ' characters).');
    }
    return $v;
}

function email_value(array $d, string $key = 'email'): string {
    $v = strtolower(trim((string) ($d[$key] ?? '')));
    if ($v === '' || !filter_var($v, FILTER_VALIDATE_EMAIL) || strlen($v) > 254) {
        fail('Please enter a valid email address.');
    }
    return $v;
}

function password_value(array $d, string $key = 'password'): string {
    $p = (string) ($d[$key] ?? '');
    if (strlen($p) < 8) {
        fail('Password must be at least 8 characters long.');
    }
    if (strlen($p) > 200) {
        fail('Password is too long.');
    }
    if (!preg_match('/[A-Za-z]/', $p) || !preg_match('/[0-9]/', $p)) {
        fail('Password must contain at least one letter and one number.');
    }
    return $p;
}

function valid_date(string $v): ?string {
    $v = trim($v);
    if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $v, $m)) {
        return null;
    }
    if (!checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
        return null;
    }
    return $v;
}

function require_date(array $d, string $key, string $label): string {
    $v = valid_date((string) ($d[$key] ?? ''));
    if ($v === null) {
        fail('Please provide a valid ' . $label . ' date (YYYY-MM-DD).');
    }
    return $v;
}

function arr_value(array $d, string $key): array {
    $v = $d[$key] ?? [];
    return is_array($v) ? $v : [];
}

function pick_enum(array $d, string $key, array $allowed, string $default, string $label = 'value'): string {
    $v = trim((string) ($d[$key] ?? ''));
    if ($v === '') {
        $v = $default;
    }
    if (!in_array($v, $allowed, true)) {
        fail('Invalid ' . $label . '.');
    }
    return $v;
}

function now_utc(): string {
    return gmdate('Y-m-d H:i:s');
}

function json_arr(string $raw): array {
    $decoded = json_decode($raw !== '' ? $raw : '[]', true);
    return is_array($decoded) ? $decoded : [];
}

/* ---------------- authorization ---------------- */

function auth_user(): ?array {
    static $cache = [];
    if (empty($_SESSION['user_id'])) {
        return null;
    }
    $id = (int) $_SESSION['user_id'];
    if (!array_key_exists($id, $cache)) {
        $st = db()->prepare('SELECT * FROM users WHERE id = ?');
        $st->execute([$id]);
        $cache[$id] = $st->fetch() ?: null;
        if ($cache[$id] === null) {
            unset($_SESSION['user_id']);
            return null;
        }
    }
    return $cache[$id];
}

function require_login(): array {
    $u = auth_user();
    if ($u === null) {
        fail('Please sign in to continue.', 401, ['code' => 'auth_required']);
    }
    return $u;
}

function require_customer(): array {
    $u = require_login();
    if ($u['type'] !== 'customer') {
        fail('A customer account is required for this action.', 403);
    }
    return $u;
}

function require_verified(): array {
    $u = require_customer();
    if ($u['status'] === 'blocked') {
        fail('Your account has been blocked. Please contact support.', 403, ['code' => 'blocked']);
    }
    if (empty($u['email_verified_at'])) {
        fail('Please verify your email address before making a booking.', 403, ['code' => 'unverified']);
    }
    if ($u['status'] !== 'active') {
        fail('Your account is not active yet.', 403, ['code' => 'pending']);
    }
    return $u;
}

function require_admin(): array {
    $u = require_login();
    if ($u['type'] !== 'admin') {
        fail('Administrator access is required for this action.', 403, ['code' => 'forbidden']);
    }
    if ($u['status'] !== 'active') {
        fail('This administrator account is not active.', 403, ['code' => 'forbidden']);
    }
    return $u;
}

function perms_for(int $userId): array {
    static $cache = [];
    if (isset($cache[$userId])) {
        return $cache[$userId];
    }
    if (has_role($userId, 'super_admin')) {
        return $cache[$userId] = db()->query('SELECT code FROM permissions ORDER BY code')->fetchAll(PDO::FETCH_COLUMN);
    }
    $st = db()->prepare(
        'SELECT p.code FROM user_roles ur
         JOIN role_permissions rp ON rp.role_id = ur.role_id
         JOIN permissions p ON p.id = rp.permission_id
         WHERE ur.user_id = ?'
    );
    $st->execute([$userId]);
    return $cache[$userId] = array_values(array_unique($st->fetchAll(PDO::FETCH_COLUMN)));
}

function has_role(int $userId, string $role): bool {
    $st = db()->prepare("SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? AND r.name = ?");
    $st->execute([$userId, $role]);
    return (int) $st->fetchColumn() > 0;
}

function is_super_admin(int $userId): bool {
    return has_role($userId, 'super_admin');
}

function can(array $admin, string $code): bool {
    return in_array($code, perms_for((int) $admin['id']), true);
}

function require_perm(array $admin, string $code): void {
    if (!can($admin, $code)) {
        fail('You do not have permission to perform this action.', 403, ['code' => 'forbidden', 'permission' => $code]);
    }
}

/* ---------------- audit & mail ---------------- */

function audit(string $action, string $entity, ?int $entityId = null, array $detail = []): void {
    try {
        $u = auth_user();
        $st = db()->prepare(
            'INSERT INTO audit_logs (actor_id, actor_label, action, entity, entity_id, detail, ip, user_agent)
             VALUES (?,?,?,?,?,?,?,?)'
        );
        $st->execute([
            $u['id'] ?? null,
            $u ? (string) ($u['username'] ?: $u['email']) : 'system',
            $action,
            $entity,
            $entityId,
            json_encode($detail, JSON_UNESCAPED_UNICODE),
            (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
            substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255),
        ]);
    } catch (Throwable $ex) {
        error_log('bookify: audit write failed: ' . $ex->getMessage());
    }
}

function send_mail(string $to, string $subject, string $body): array {
    $driver = (string) cfg('email.driver', 'file');
    if ($driver === 'mail') {
        $headers = 'From: ' . cfg('email.from_name', 'Bookify') . ' <' . cfg('email.from', 'no-reply@bookify.local') . ">\r\n"
            . "Content-Type: text/plain; charset=UTF-8\r\nMIME-Version: 1.0";
        if (@mail($to, $subject, $body, $headers)) {
            return ['driver' => 'mail', 'sent' => true];
        }
        error_log('bookify: mail() failed for ' . $to);
    }
    $file = (string) cfg('email.log_file', BOOKIFY_ROOT . '/storage/mail.log');
    $dir = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    $line = sprintf(
        "[%s] TO: %s\nSUBJECT: %s\n%s\n%s\n\n",
        gmdate('c'),
        $to,
        $subject,
        $body,
        str_repeat('-', 64)
    );
    @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    return ['driver' => 'file', 'sent' => false, 'logged' => is_file($file)];
}

/* ---------------- shared data helpers ---------------- */

function slugify(string $value): string {
    $value = strtolower(trim($value));
    $value = preg_replace('/[^a-z0-9]+/', '-', $value) ?? '';
    $value = trim($value, '-');
    return $value !== '' ? $value : 'hotel';
}

function unique_slug(string $name, ?int $ignoreId = null): string {
    $base = slugify($name);
    $slug = $base;
    $i = 1;
    while (true) {
        $sql = 'SELECT COUNT(*) FROM hotels WHERE slug = ?' . ($ignoreId ? ' AND id != ?' : '');
        $st = db()->prepare($sql);
        $st->execute($ignoreId ? [$slug, $ignoreId] : [$slug]);
        if ((int) $st->fetchColumn() === 0) {
            return $slug;
        }
        $slug = $base . '-' . (++$i);
    }
}

function availability_for(int $roomTypeId, string $checkIn, string $checkOut): int {
    $st = db()->prepare('SELECT total_rooms FROM room_types WHERE id = ?');
    $st->execute([$roomTypeId]);
    $roomType = $st->fetch();
    if (!$roomType) {
        return 0;
    }
    $st = db()->prepare('SELECT MIN(total) FROM room_inventory WHERE room_type_id = ? AND date >= ? AND date < ?');
    $st->execute([$roomTypeId, $checkIn, $checkOut]);
    $min = $st->fetchColumn();
    $total = ($min === null || $min === false) ? (int) $roomType['total_rooms'] : (int) $min;
    $st = db()->prepare(
        "SELECT COALESCE(SUM(num_rooms), 0) FROM bookings
         WHERE room_type_id = ? AND status IN ('pending','confirmed')
           AND check_in < ? AND check_out > ?"
    );
    $st->execute([$roomTypeId, $checkOut, $checkIn]);
    $booked = (int) $st->fetchColumn();
    return max(0, $total - $booked);
}

function seed_inventory(int $roomTypeId, int $total, int $days = 180): void {
    $st = db()->prepare('INSERT OR IGNORE INTO room_inventory (room_type_id, date, total) VALUES (?,?,?)');
    $today = new DateTimeImmutable('today');
    for ($i = 0; $i < $days; $i++) {
        $st->execute([$roomTypeId, $today->modify('+' . $i . ' days')->format('Y-m-d'), $total]);
    }
}
