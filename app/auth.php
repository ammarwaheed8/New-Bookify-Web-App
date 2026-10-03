<?php
declare(strict_types=1);

function public_user(?array $u): ?array
{
    if (!$u) {
        return null;
    }
    return [
        'id' => (int) $u['id'], 'name' => $u['name'], 'email' => $u['email'],
        'username' => $u['username'], 'phone' => $u['phone'], 'type' => $u['type'],
        'status' => $u['status'], 'email_verified_at' => $u['email_verified_at'],
        'country' => $u['country'], 'city' => $u['city'], 'address' => $u['address'],
        'date_of_birth' => $u['date_of_birth'], 'preferences' => $u['preferences'],
        'created_at' => $u['created_at'] ?? null,
    ];
}

function current_user(): ?array
{
    static $loaded = false;
    static $cache  = null;
    if ($loaded) {
        return $cache;
    }
    $loaded = true;
    $id = (int) ($_SESSION['user_id'] ?? 0);
    if ($id > 0) {
        $cache = one(
            'SELECT id, name, email, username, phone, type, status, email_verified_at,
                    country, city, address, date_of_birth, preferences, created_at
               FROM users WHERE id = ?',
            [$id]
        );
        if ($cache && $cache['status'] === 'blocked') {
            $cache = null; // blocked accounts lose access immediately
        }
    }
    return $cache;
}

function login_as(array $user): void
{
    session_regenerate_id(true);
    $_SESSION['user_id']   = (int) $user['id'];
    $_SESSION['rotated_at'] = time();
    $_SESSION['last_seen']  = time();
}

function attempt_login(string $identifier, string $password): array
{
    $identifier = trim($identifier);
    $user = one('SELECT * FROM users WHERE email = ? COLLATE NOCASE', [$identifier])
        ?? one('SELECT * FROM users WHERE username = ? COLLATE NOCASE', [$identifier]);

    if (!$user || !password_verify($password, $user['password_hash'])) {
        fail('Invalid credentials.', 401);
    }
    if ($user['status'] === 'blocked') {
        fail('This account has been blocked. Please contact support.', 403);
    }
    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
        q("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
          [password_hash($password, PASSWORD_DEFAULT), $user['id']]);
    }
    login_as($user);
    audit('auth.login', 'users', (int) $user['id'], 'Signed in: ' . $user['email']);
    return $user;
}

function logout(): void
{
    $u = current_user();
    if ($u) {
        audit('auth.logout', 'users', (int) $u['id'], 'Signed out');
    }
    $_SESSION = [];
    session_destroy();
}

function register_customer(array $in): array
{
    $name     = f_str($in, 'name', 'Full name', 2, 100);
    $email    = f_email($in);
    $phone    = f_str($in, 'phone', 'Phone', 5, 30, false);
    $password = f_password($in);
    $confirm  = f_password($in, 'confirm', 'Confirm password');
    if ($password !== $confirm) {
        fail('Passwords do not match.', 422);
    }
    if (one('SELECT id FROM users WHERE email = ? COLLATE NOCASE', [$email])) {
        fail('An account with this email already exists.', 409);
    }
    $dob = f_opt($in, 'date_of_birth', 'Date of birth', 10);
    if ($dob !== '' && !valid_date($dob)) {
        fail('Date of birth must use YYYY-MM-DD format.', 422);
    }
    $id = insert_row(
        "INSERT INTO users (name, email, phone, password_hash, type, status,
                            country, city, address, date_of_birth, preferences, created_at, updated_at)
         VALUES (?,?,?,?, 'customer','pending', ?,?,?,?,?, datetime('now'), datetime('now'))",
        [$name, $email, $phone, password_hash($password, PASSWORD_DEFAULT),
         f_opt($in, 'country', 'Country', 100), f_opt($in, 'city', 'City', 100),
         f_opt($in, 'address', 'Address', 255), $dob !== '' ? $dob : null,
         f_opt($in, 'preferences', 'Preferences', 500)]
    );
    $user = one('SELECT * FROM users WHERE id = ?', [$id]);
    issue_verification($user);
    audit('user.register', 'users', $id, 'Self-registration: ' . $email);
    return $user;
}

/* ---------- email verification ---------- */

function issue_verification(array $user): void
{
    $cfg = config()['email'];
    $ttl = (int) ($cfg['verification_ttl_hours'] ?? 24);
    $token = bin2hex(random_bytes(32));          // shown once, in the link
    $hash  = hash('sha256', $token);             // only the hash is stored

    q('DELETE FROM email_verification_tokens WHERE user_id = ? AND used_at IS NULL', [$user['id']]);
    q("INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, created_at)
       VALUES (?,?, datetime('now', ?), datetime('now'))",
      [$user['id'], $hash, '+' . $ttl . ' hours']);

    $link = rtrim((string) config()['app']['base_url'], '/') . '/?verify=' . $token;
    send_mail(
        $user['email'],
        'Verify your Bookify account',
        "Hi {$user['name']},\n\nConfirm your email address to activate your Bookify account:\n"
        . $link . "\n\nThis link expires in {$ttl} hour(s). If you did not sign up, ignore this email.\n\n— Bookify"
    );
}

function send_mail(string $to, string $subject, string $body): bool
{
    $cfg    = config()['email'];
    $driver = $cfg['driver'] ?? 'file';

    if ($driver === 'mail') {
        $headers = 'From: ' . $cfg['from_name'] . ' <' . $cfg['from'] . ">\r\n"
                 . "Content-Type: text/plain; charset=UTF-8";
        if (@mail($to, $subject, $body, $headers)) {
            return true;
        }
        // fall through to file logging if mail() fails
    }
    $file = (string) $cfg['log_file'];
    $dir  = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    $entry = '[' . gmdate('Y-m-d H:i:s') . " UTC] To: $to\nSubject: $subject\n"
           . str_repeat('-', 40) . "\n$body\n\n";
    return @file_put_contents($file, $entry, FILE_APPEND | LOCK_EX) !== false;
}

function verify_email_token(string $token): array
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        fail('Invalid verification link.', 400);
    }
    $row = one(
        "SELECT * FROM email_verification_tokens
          WHERE token_hash = ? AND used_at IS NULL AND expires_at > datetime('now')",
        [hash('sha256', $token)]
    );
    if (!$row) {
        fail('This verification link is invalid or has expired.', 400);
    }
    q("UPDATE users
          SET email_verified_at = datetime('now'),
              status = CASE WHEN status = 'pending' THEN 'active' ELSE status END,
              updated_at = datetime('now')
        WHERE id = ?", [$row['user_id']]);
    q("UPDATE email_verification_tokens SET used_at = datetime('now') WHERE id = ?", [$row['id']]);

    $user = one('SELECT * FROM users WHERE id = ?', [$row['user_id']]);
    audit('auth.verify', 'users', (int) $row['user_id'], 'Email verified');
    return public_user($user);
}

function resend_verification(string $email): void
{
    $user = one('SELECT * FROM users WHERE email = ? COLLATE NOCASE', [trim($email)]);
    if ($user && !$user['email_verified_at'] && $user['status'] !== 'blocked') {
        issue_verification($user);
    }
    // always the same response — do not reveal whether the email exists
    json_out(['ok' => true, 'message' => 'If that address needs verification, a new link has been sent.']);
}

/* ---------- profile ---------- */

function update_profile(array $in): array
{
    $u = require_login();
    $dob = f_opt($in, 'date_of_birth', 'Date of birth', 10);
    if ($dob !== '' && !valid_date($dob)) {
        fail('Date of birth must use YYYY-MM-DD format.', 422);
    }
    q("UPDATE users SET name = ?, phone = ?, country = ?, city = ?, address = ?,
              date_of_birth = ?, preferences = ?, updated_at = datetime('now')
        WHERE id = ?",
      [f_str($in, 'name', 'Full name', 2, 100),
       f_str($in, 'phone', 'Phone', 5, 30, false),
       f_opt($in, 'country', 'Country', 100), f_opt($in, 'city', 'City', 100),
       f_opt($in, 'address', 'Address', 255), $dob !== '' ? $dob : null,
       f_opt($in, 'preferences', 'Preferences', 500), $u['id']]);
    return public_user(one('SELECT * FROM users WHERE id = ?', [$u['id']]));
}

function change_password(array $in): void
{
    $u = require_login();
    $current = (string) ($in['current_password'] ?? '');
    $new     = f_password($in, 'password', 'New password');
    $confirm = f_password($in, 'confirm', 'Confirm new password');

    $row = one('SELECT password_hash FROM users WHERE id = ?', [$u['id']]);
    if (!$row || !password_verify($current, $row['password_hash'])) {
        fail('Current password is incorrect.', 403);
    }
    if ($new !== $confirm) {
        fail('New passwords do not match.', 422);
    }
    if (password_verify($new, $row['password_hash'])) {
        fail('New password must differ from the current one.', 422);
    }
    q("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
      [password_hash($new, PASSWORD_DEFAULT), $u['id']]);
    session_regenerate_id(true);
    audit('user.password_change', 'users', (int) $u['id'], 'Password changed');
}

/* ---------- guards ---------- */

function require_login(): array
{
    $u = current_user();
    if (!$u) {
        fail('Please sign in to continue.', 401);
    }
    if ($u['status'] === 'blocked') {
        fail('Your account has been blocked.', 403);
    }
    return $u;
}

function require_verified(): array
{
    $u = require_login();
    if (!$u['email_verified_at']) {
        fail('Please verify your email address before booking.', 403);
    }
    return $u;
}

function require_admin(): array
{
    $u = require_login();
    if ($u['type'] !== 'admin' || $u['status'] !== 'active') {
        fail('Admin access required.', 403);
    }
    return $u;
}

/* ---------- RBAC (deny by default) ---------- */

function user_role_names(int $userId): array
{
    return array_column(all(
        'SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?',
        [$userId]
    ), 'name');
}

function user_permission_codes(int $userId): array
{
    static $cache = [];
    if (isset($cache[$userId])) {
        return $cache[$userId];
    }
    $u = one('SELECT type FROM users WHERE id = ?', [$userId]);
    $roles = user_role_names($userId);
    if ($u && $u['type'] === 'admin' && in_array('super_admin', $roles, true)) {
        return $cache[$userId] = ['*'];
    }
    $fromRoles = array_column(all(
        'SELECT DISTINCT p.code FROM permissions p
           JOIN role_permissions rp ON rp.permission_id = p.id
           JOIN user_roles ur ON ur.role_id = rp.role_id
          WHERE ur.user_id = ?', [$userId]
    ), 'code');
    $direct = array_column(all(
        'SELECT DISTINCT p.code FROM permissions p
           JOIN user_permissions up ON up.permission_id = p.id
          WHERE up.user_id = ?', [$userId]
    ), 'code');
    return $cache[$userId] = array_values(array_unique(array_merge($fromRoles, $direct)));
}

function require_permission(string $code): array
{
    $u = require_admin();
    $perms = user_permission_codes((int) $u['id']);
    if (!in_array('*', $perms, true) && !in_array($code, $perms, true)) {
        fail('You do not have permission to perform this action.', 403);
    }
    return $u;
}

/* ---------- audit trail ---------- */

function audit(string $action, string $entity, ?int $entityId, string $details = ''): void
{
    $u = current_user();
    try {
        q("INSERT INTO audit_logs (user_id, action, entity, entity_id, details, ip, created_at)
           VALUES (?,?,?,?,?, ?, datetime('now'))",
          [$u['id'] ?? null, $action, $entity, $entityId, mb_substr($details, 0, 500), client_ip()]);
    } catch (Throwable $e) {
        error_log('Bookify audit failed: ' . $e->getMessage()); // never break the main action
    }
}
