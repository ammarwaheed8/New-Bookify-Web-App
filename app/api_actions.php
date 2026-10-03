<?php
declare(strict_types=1);

function handle(string $action): void {
    $m = $_SERVER['REQUEST_METHOD'];
    $map = $m === 'GET'
        ? ['bootstrap'=>'a_bootstrap','search'=>'a_search','hotel'=>'a_hotel','me'=>'a_me',
           'my_bookings'=>'a_my_bookings','booking'=>'a_booking','dashboard'=>'a_dashboard',
           'admin_hotels'=>'a_admin_hotels','admin_bookings'=>'a_admin_bookings',
           'admin_users'=>'a_admin_users','admin_staff'=>'a_admin_staff',
           'roles'=>'a_roles','audit'=>'a_audit']
        : ['register'=>'a_register','verify_email'=>'a_verify','resend_verification'=>'a_resend',
           'login'=>'a_login','logout'=>'a_logout','update_profile'=>'a_update_profile',
           'change_password'=>'a_change_password','forgot_password'=>'a_forgot',
           'reset_password'=>'a_reset','create_booking'=>'a_create_booking',
           'save_hotel'=>'a_save_hotel','delete_hotel'=>'a_delete_hotel','toggle_hotel'=>'a_toggle_hotel',
           'update_booking'=>'a_update_booking','save_user'=>'a_save_user',
           'update_user_status'=>'a_user_status','delete_user'=>'a_delete_user',
           'save_staff'=>'a_save_staff','delete_staff'=>'a_delete_staff',
           'save_role'=>'a_save_role','delete_role'=>'a_delete_role'];
    if (!isset($map[$action])) fail('Unknown action.', 404);
    ($map[$action])();
}

/* ---------- auth ---------- */

function a_bootstrap(): void {
    $u = current_user();
    out(['ok' => true, 'csrf' => csrf_token(), 'user' => $u,
         'perms' => ($u && $u['type'] === 'admin') ? all_perms($u['id']) : [],
         'config' => ['currency' => cfg('booking.currency'), 'symbol' => cfg('booking.symbol'),
                      'tax_rate' => cfg('booking.tax_rate'), 'service_fee' => cfg('booking.service_fee'),
                      'env' => cfg('app.env'), 'mock_payment' => true]]);
}

function a_register(): void {
    $d = json_in();
    $name  = trim((string) ($d['name'] ?? ''));
    $email = strtolower(trim((string) ($d['email'] ?? '')));
    $phone = trim((string) ($d['phone'] ?? ''));
    $pw    = (string) ($d['password'] ?? '');
    $pw2   = (string) ($d['password_confirm'] ?? '');
    $e = [];
    if (mb_strlen($name) < 2 || mb_strlen($name) > 80) $e['name'] = 'Name must be 2–80 characters.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $e['email'] = 'Enter a valid email address.';
    if (!preg_match('/^[0-9+\-\s()]{7,20}$/', $phone)) $e['phone'] = 'Enter a valid phone number.';
    if (strlen($pw) < 8 || !preg_match('/[A-Za-z]/', $pw) || !preg_match('/\d/', $pw))
        $e['password'] = 'At least 8 characters, including a letter and a number.';
    if ($pw !== $pw2) $e['password_confirm'] = 'Passwords do not match.';
    if ($e) fail('Please fix the highlighted fields.', 422, ['fields' => $e]);

    $st = db()->prepare('SELECT id FROM users WHERE email = ?');
    $st->execute([$email]);
    if ($st->fetch()) fail('An account with that email already exists.', 409, ['fields' => ['email' => 'Already registered.']]);

    db()->prepare("INSERT INTO users(name,email,phone,password_hash,type,status) VALUES (?,?,?,?, 'customer','pending')")
        ->execute([$name, $email, $phone, password_hash($pw, PASSWORD_DEFAULT)]);
    $uid = (int) db()->lastInsertId();

    $token = bin2hex(random_bytes(32));
    db()->prepare('INSERT INTO email_verification_tokens(user_id, token_hash, expires_at) VALUES (?,?,?)')
        ->execute([$uid, hash('sha256', $token),
                   gmdate('Y-m-d H:i:s', time() + (int) cfg('email.verification_ttl_hours', 24) * 3600)]);
    $link = send_verification_email($uid, $name, $email, $token);

    out(['ok' => true, 'message' => 'Account created. Confirm your email to start booking.',
         'dev_link' => cfg('email.driver') === 'file' ? $link : null], 201);
}

function a_verify(): void {
    $d = json_in();
    $tok = trim((string) ($d['token'] ?? ''));
    if (strlen($tok) < 32) fail('Invalid verification link.', 400);
    $st = db()->prepare(
        'SELECT t.id, t.user_id, t.expires_at FROM email_verification_tokens t
         WHERE t.token_hash = ? AND t.used_at IS NULL'
    );
    $st->execute([hash('sha256', $tok)]);
    $row = $st->fetch();
    if (!$row || strtotime($row['expires_at']) < time())
        fail('This verification link is invalid or has expired.', 410, ['code' => 'expired']);

    db()->prepare("UPDATE email_verification_tokens SET used_at = datetime('now') WHERE id = ?")->execute([$row['id']]);
    db()->prepare("UPDATE users SET email_verified_at = COALESCE(email_verified_at, datetime('now')),
                   status = CASE WHEN status = 'pending' THEN 'active' ELSE status END,
                   updated_at = datetime('now') WHERE id = ?")->execute([$row['user_id']]);
    out(['ok' => true, 'message' => 'Email verified. You can now sign in and book.']);
}

function a_resend(): void {
    $u = require_login();
    if ($u['email_verified_at']) fail('Your email is already verified.', 400);
    $token = bin2hex(random_bytes(32));
    db()->prepare('INSERT INTO email_verification_tokens(user_id, token_hash, expires_at) VALUES (?,?,?)')
        ->execute([$u['id'], hash('sha256', $token),
                   gmdate('Y-m-d H:i:s', time() + (int) cfg('email.verification_ttl_hours', 24) * 3600)]);
    $link = send_verification_email($u['id'], $u['name'], $u['email'], $token);
    out(['ok' => true, 'message' => 'A new verification link was sent.',
         'dev_link' => cfg('email.driver') === 'file' ? $link : null]);
}

function a_login(): void {
    $d = json_in();
    $id = strtolower(trim((string) ($d['identifier'] ?? '')));
    $pw = (string) ($d['password'] ?? '');
    if (!$id || $pw === '') fail('Enter your credentials.', 422);

    $st = db()->prepare('SELECT * FROM users WHERE email = ? OR username = ?');
    $st->execute([$id, $id]);
    $u = $st->fetch();
    if (!$u || !password_verify($pw, $u['password_hash']))
        fail('Invalid username/email or password.', 401, ['fields' => ['password' => 'Invalid credentials.']]);
    if ($u['status'] === 'blocked') fail('This account has been blocked. Contact support.', 403);

    session_regenerate_id(true);
    $_SESSION['uid'] = $u['id'];
    invalidate_user_cache();
    $me = current_user();
    out(['ok' => true, 'user' => $me,
         'perms' => $u['type'] === 'admin' ? all_perms($u['id']) : [],
         'message' => 'Signed in.']);
}

function a_logout(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    out(['ok' => true, 'message' => 'Signed out.']);
}

function a_me(): void {
    $u = current_user();
    out(['ok' => true, 'user' => $u,
         'perms' => ($u && $u['type'] === 'admin') ? all_perms($u['id']) : []]);
}

function a_update_profile(): void {
    $u = require_login();
    $d = json_in();
    $name = trim((string) ($d['name'] ?? $u['name']));
    $phone = trim((string) ($d['phone'] ?? $u['phone']));
    $fields = [
        'name' => $name,
        'phone' => $phone,
        'country' => mb_substr(trim((string) ($d['country'] ?? '')), 0, 80),
        'city' => mb_substr(trim((string) ($d['city'] ?? '')), 0, 80),
        'address' => mb_substr(trim((string) ($d['address'] ?? '')), 0, 200),
        'date_of_birth' => ($d['date_of_birth'] ?? '') !== '' ? (string) $d['date_of_birth'] : null,
        'preferences' => mb_substr(trim((string) ($d['preferences'] ?? '')), 0, 500),
    ];
    $e = [];
    if (mb_strlen($fields['name']) < 2) $e['name'] = 'Name is too short.';
    if (!preg_match('/^[0-9+\-\s()]{7,20}$/', $fields['phone'])) $e['phone'] = 'Enter a valid phone number.';
    if ($fields['date_of_birth'] && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $fields['date_of_birth'])) $e['date_of_birth'] = 'Use YYYY-MM-DD.';
    if ($e) fail('Please fix the highlighted fields.', 422, ['fields' => $e]);

    db()->prepare("UPDATE users SET name=?, phone=?, country=?, city=?, address=?, date_of_birth=?,
                   preferences=?, updated_at=datetime('now') WHERE id = ?")
        ->execute([$fields['name'], $fields['phone'], $fields['country'], $fields['city'],
                   $fields['address'], $fields['date_of_birth'], $fields['preferences'], $u['id']]);
    invalidate_user_cache();
    out(['ok' => true, 'message' => 'Profile updated.', 'user' => current_user()]);
}

function a_change_password(): void {
    $u = require_login();
    $d = json_in();
    $cur = (string) ($d['current_password'] ?? '');
    $new = (string) ($d['new_password'] ?? '');
    $cfm = (string) ($d['confirm_password'] ?? '');
    $st = db()->prepare('SELECT password_hash FROM users WHERE id = ?');
    $st->execute([$u['id']]);
    if (!password_verify($cur, (string) $st->fetchColumn()))
        fail('Current password is incorrect.', 401, ['fields' => ['current_password' => 'Incorrect.']]);
    if (strlen($new) < 8 || !preg_match('/[A-Za-z]/', $new) || !preg_match('/\d/', $new))
        fail('New password must be 8+ characters with a letter and a number.', 422,
             ['fields' => ['new_password' => 'Too weak.']]);
    if ($new !== $cfm) fail('Passwords do not match.', 422, ['fields' => ['confirm_password' => 'Mismatch.']]);

    db()->prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        ->execute([password_hash($new, PASSWORD_DEFAULT), $u['id']]);
    session_regenerate_id(true);
    out(['ok' => true, 'message' => 'Password changed.']);
}

function a_forgot(): void {
    $d = json_in();
    $email = strtolower(trim((string) ($d['email'] ?? '')));
    $st = db()->prepare('SELECT * FROM users WHERE email = ?');
    $st->execute([$email]);
    $u = $st->fetch();
    if ($u) {
        $token = bin2hex(random_bytes(32));
        db()->prepare('INSERT INTO password_reset_tokens(user_id, token_hash, expires_at) VALUES (?,?,?)')
            ->execute([$u['id'], hash('sha256', $token),
                       gmdate('Y-m-d H:i:s', time() + (int) cfg('email.reset_ttl_hours', 1) * 3600)]);
        $link = send_reset_email($u, $token);
        out(['ok' => true, 'message' => 'If that account exists, a reset link was sent.',
             'dev_link' => cfg('email.driver') === 'file' ? $link : null]);
    }
    out(['ok' => true, 'message' => 'If that account exists, a reset link was sent.']);
}

function a_reset(): void {
    $d = json_in();
    $tok = trim((string) ($d['token'] ?? ''));
    $pw = (string) ($d['password'] ?? '');
    $pw2 = (string) ($d['password_confirm'] ?? '');
    if (strlen($pw) < 8 || !preg_match('/[A-Za-z]/', $pw) || !preg_match('/\d/', $pw))
        fail('Password must be 8+ characters with a letter and a number.', 422);
    if ($pw !== $pw2) fail('Passwords do not match.', 422);
    $st = db()->prepare('SELECT id, user_id, expires_at FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL');
    $st->execute([hash('sha256', $tok)]);
    $row = $st->fetch();
    if (!$row || strtotime($row['expires_at']) < time()) fail('Reset link is invalid or expired.', 410);
    db()->prepare("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?")->execute([$row['id']]);
    db()->prepare("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        ->execute([password_hash($pw, PASSWORD_DEFAULT), $row['user_id']]);
    out(['ok' => true, 'message' => 'Password reset. You can sign in now.']);
}

/* ---------- catalog ---------- */

function valid_range(?string $ci, ?string $co): int {
    if (!$ci || !$co) return 0;
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $ci) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $co)) return 0;
    $a = strtotime($ci); $b = strtotime($co);
    $today = strtotime(gmdate('Y-m-d'));
    if ($a === false || $b === false || $b <= $a || $a < $today) return 0;
    return (int) (($b - $a) / 86400);
}

function availability_map(?string $ci, ?string $co): array {
    $db = db();
    if (!$ci || !$co) {
        $rows = $db->query('SELECT hotel_id, id, total_rooms, max_guests FROM room_types')->fetchAll();
    } else {
        $st = $db->prepare(
            'SELECT rt.hotel_id, rt.id, rt.total_rooms, rt.max_guests,
              COALESCE((SELECT SUM(b.rooms) FROM bookings b
                        WHERE b.room_type_id = rt.id AND b.status IN ("pending","confirmed")
                          AND b.check_in < ? AND b.check_out > ?), 0) AS booked
             FROM room_types rt'
        );
        $st->execute([$co, $ci]);
        $rows = $st->fetchAll();
    }
    $map = [];
    foreach ($rows as $r) {
        $free = max(0, (int) $r['total_rooms'] - (int) ($r['booked'] ?? 0));
        $h = (int) $r['hotel_id'];
        $map[$h]['free'] = ($map[$h]['free'] ?? 0) + $free;
        $map[$h]['types'][$r['id']] = ['free' => $free, 'max_guests' => (int) $r['max_guests']];
    }
    return $map;
}

function a_search(): void {
    $dest = trim((string) ($_GET['destination'] ?? ''));
    $ci = (string) ($_GET['check_in'] ?? '');
    $co = (string) ($_GET['check_out'] ?? '');
    $nights = valid_range($ci, $co);
    $guests = max(1, (int) ($_GET['guests'] ?? 1));
    $roomsWanted = max(1, (int) ($_GET['rooms'] ?? 1));
    $minP = ($_GET['min_price'] ?? '') !== '' ? (float) $_GET['min_price'] : null;
    $maxP = ($_GET['max_price'] ?? '') !== '' ? (float) $_GET['max_price'] : null;
    $minS = ($_GET['min_stars'] ?? '') !== '' ? (int) $_GET['min_stars'] : null;
    $amen = array_values(array_filter(array_map('trim', explode(',', (string) ($_GET['amenities'] ?? '')))));
    $availOnly = (($_GET['available'] ?? '') === '1') || $nights > 0;
    $sort = (string) ($_GET['sort'] ?? 'rating');
    $page = max(1, (int) ($_GET['page'] ?? 1));
    $per = 6;

    $where = ["h.status = 'published'"];
    $p = [];
    if ($dest !== '') {
        $where[] = '(h.city LIKE ? OR h.country LIKE ? OR h.name LIKE ? OR h.address LIKE ?)';
        $like = "%$dest%";
        array_push($p, $like, $like, $like, $like);
    }
    if ($minS !== null) { $where[] = 'h.star_rating >= ?'; $p[] = $minS; }
    if ($minP !== null) { $where[] = 'h.base_price >= ?'; $p[] = $minP; }
    if ($maxP !== null) { $where[] = 'h.base_price <= ?'; $p[] = $maxP; }
    foreach ($amen as $a) { $where[] = 'h.amenities LIKE ?'; $p[] = '%' . json_encode($a) . '%'; }

    $sql = 'SELECT h.*,
              (SELECT MIN(rt.price_per_night) FROM room_types rt WHERE rt.hotel_id = h.id) AS from_price,
              (SELECT i.url FROM hotel_images i WHERE i.hotel_id = h.id ORDER BY i.sort_order LIMIT 1) AS image,
              (SELECT COUNT(*) FROM room_types rt WHERE rt.hotel_id = h.id) AS room_count
            FROM hotels h WHERE ' . implode(' AND ', $where);
    $st = db()->prepare($sql);
    $st->execute($p);
    $rows = $st->fetchAll();

    $avail = availability_map($nights > 0 ? $ci : null, $nights > 0 ? $co : null);
    $out = [];
    foreach ($rows as $h) {
        $a = $avail[$h['id']] ?? ['free' => 0, 'types' => []];
        $free = (int) $a['free'];
        $fits = false;
        foreach ($a['types'] as $t) {
            if ($t['free'] >= $roomsWanted && $t['max_guests'] >= (int) ceil($guests / $roomsWanted)) { $fits = true; break; }
        }
        if ($availOnly && (!$fits || $free < $roomsWanted)) continue;
        $out[] = [
            'id' => (int) $h['id'], 'name' => $h['name'], 'city' => $h['city'], 'country' => $h['country'],
            'address' => $h['address'], 'location_text' => $h['location_text'],
            'star_rating' => (int) $h['star_rating'], 'rating' => (float) $h['rating'],
            'review_count' => (int) $h['review_count'],
            'amenities' => json_decode($h['amenities'], true) ?: [],
            'from_price' => (float) ($h['from_price'] ?? $h['base_price']),
            'image' => $h['image'] ?: 'assets/img/hero.svg',
            'room_count' => (int) $h['room_count'], 'available_rooms' => $free,
        ];
    }

    usort($out, function ($x, $y) use ($sort) {
        return match ($sort) {
            'price_asc' => $x['from_price'] <=> $y['from_price'],
            'price_desc' => $y['from_price'] <=> $x['from_price'],
            'stars' => $y['star_rating'] <=> $x['star_rating'],
            default => $y['rating'] <=> $x['rating'],
        };
    });

    $total = count($out);
    $pages = max(1, (int) ceil($total / $per));
    $page = min($page, $pages);
    out(['ok' => true, 'hotels' => array_slice($out, ($page - 1) * $per, $per),
         'total' => $total, 'page' => $page, 'pages' => $pages, 'nights' => $nights]);
}

function a_hotel(): void {
    $id = (int) ($_GET['id'] ?? 0);
    $ci = (string) ($_GET['check_in'] ?? '');
    $co = (string) ($_GET['check_out'] ?? '');
    $nights = valid_range($ci, $co);

    $st = db()->prepare("SELECT * FROM hotels WHERE id = ? AND status = 'published'");
    $st->execute([$id]);
    $h = $st->fetch();
    if (!$h) fail('Hotel not found.', 404);

    $im = db()->prepare('SELECT url, alt FROM hotel_images WHERE hotel_id = ? ORDER BY sort_order');
    $im->execute([$id]);
    $images = $im->fetchAll();

    $rt = db()->prepare('SELECT * FROM room_types WHERE hotel_id = ? ORDER BY sort_order');
    $rt->execute([$id]);
    $rooms = $rt->fetchAll();

    $avail = availability_map($nights > 0 ? $ci : null, $nights > 0 ? $co : null)[$id] ?? ['types' => []];
    $roomOut = [];
    foreach ($rooms as $r) {
        $free = $avail['types'][$r['id']]['free'] ?? (int) $r['total_rooms'];
        $roomOut[] = [
            'id' => (int) $r['id'], 'name' => $r['name'], 'description' => $r['description'],
            'max_guests' => (int) $r['max_guests'], 'total_rooms' => (int) $r['total_rooms'],
            'free_rooms' => $free, 'price_per_night' => (float) $r['price_per_night'],
            'amenities' => json_decode($r['amenities'], true) ?: [],
        ];
    }

    out(['ok' => true, 'nights' => $nights,
         'hotel' => [
            'id' => (int) $h['id'], 'name' => $h['name'], 'description' => $h['description'],
            'address' => $h['address'], 'city' => $h['city'], 'country' => $h['country'],
            'location_text' => $h['location_text'], 'star_rating' => (int) $h['star_rating'],
            'rating' => (float) $h['rating'], 'review_count' => (int) $h['review_count'],
            'amenities' => json_decode($h['amenities'], true) ?: [],
            'policies' => json_decode($h['policies'], true) ?: [],
            'images' => $images ?: [['url' => 'assets/img/hero.svg', 'alt' => $h['name']]],
            'room_types' => $roomOut, 'reviews' => [],
         ]]);
}

/* ---------- booking ---------- */

function a_create_booking(): void {
    $u = require_verified();
    $d = json_in();
    $hotelId = (int) ($d['hotel_id'] ?? 0);
    $rtId = (int) ($d['room_type_id'] ?? 0);
    $ci = (string) ($d['check_in'] ?? '');
    $co = (string) ($d['check_out'] ?? '');
    $rooms = max(1, (int) ($d['rooms'] ?? 1));
    $guests = max(1, (int) ($d['guests'] ?? 1));
    $method = (string) ($d['payment_method'] ?? '');
    $gName = trim((string) ($d['guest_name'] ?? ''));
    $gEmail = strtolower(trim((string) ($d['guest_email'] ?? '')));
    $gPhone = trim((string) ($d['guest_phone'] ?? ''));
    $notes = mb_substr(trim((string) ($d['special_requests'] ?? '')), 0, 500);

    $nights = valid_range($ci, $co);
    if (!$nights) fail('Choose a valid future check-in and check-out date.', 422,
        ['fields' => ['check_in' => 'Invalid dates.']]);
    if ($nights > 365) fail('Stays longer than 365 nights are not supported.', 422);
    if (!in_array($method, ['card', 'paypal', 'property'], true))
        fail('Choose a payment method.', 422, ['fields' => ['payment_method' => 'Required.']]);
    $e = [];
    if (mb_strlen($gName) < 2) $e['guest_name'] = 'Guest name is required.';
    if (!filter_var($gEmail, FILTER_VALIDATE_EMAIL)) $e['guest_email'] = 'Valid email required.';
    if (!preg_match('/^[0-9+\-\s()]{7,20}$/', $gPhone)) $e['guest_phone'] = 'Valid phone required.';
    if ($e) fail('Please fix the highlighted fields.', 422, ['fields' => $e]);

    $pdo = db();
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare("SELECT * FROM hotels WHERE id = ? AND status = 'published'");
        $st->execute([$hotelId]);
        $hotel = $st->fetch();
        if (!$hotel) { $pdo->rollBack(); fail('Hotel not found.', 404); }

        $st = $pdo->prepare('SELECT * FROM room_types WHERE id = ? AND hotel_id = ?');
        $st->execute([$rtId, $hotelId]);
        $rt = $st->fetch();
        if (!$rt) { $pdo->rollBack(); fail('Room type not found for this hotel.', 404); }
        if ($guests > (int) $rt['max_guests'] * $rooms) {
            $pdo->rollBack();
            fail('Guest count exceeds the capacity of the rooms selected.', 422,
                 ['fields' => ['guests' => 'Too many guests for this room type.']]);
        }

        $av = $pdo->prepare(
            'SELECT COALESCE(SUM(b.rooms), 0) FROM bookings b
             WHERE b.room_type_id = ? AND b.status IN ("pending","confirmed")
               AND b.check_in < ? AND b.check_out > ?'
        );
        $av->execute([$rtId, $co, $ci]);
        $booked = (int) $av->fetchColumn();
        if ((int) $rt['total_rooms'] - $booked < $rooms) {
            $pdo->rollBack();
            fail('Not enough rooms available for those dates.', 409, ['code' => 'sold_out']);
        }

        $sub = round((float) $rt['price_per_night'] * $nights * $rooms, 2);
        $tax = round($sub * (float) cfg('booking.tax_rate'), 2);
        $fee = (float) cfg('booking.service_fee');
        $total = round($sub + $tax + $fee, 2);
        $ref = 'BK-' . strtoupper(bin2hex(random_bytes(4)));
        $status = $method === 'property' ? 'pending' : 'confirmed';
        $payStatus = $method === 'property' ? 'unpaid' : 'paid';

        $pdo->prepare(
            'INSERT INTO bookings(reference,user_id,hotel_id,room_type_id,check_in,check_out,nights,rooms,guests,
                subtotal,taxes,fees,total,currency,status,payment_method,payment_status,special_requests)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        )->execute([$ref, $u['id'], $hotelId, $rtId, $ci, $co, $nights, $rooms, $guests,
                    $sub, $tax, $fee, $total, cfg('booking.currency', 'USD'), $status, $method, $payStatus, $notes]);
        $bid = (int) $pdo->lastInsertId();

        $pdo->prepare('INSERT INTO booking_guests(booking_id, full_name, email, phone, is_primary) VALUES (?,?,?,?,1)')
            ->execute([$bid, $gName, $gEmail, $gPhone]);
        $pdo->prepare('INSERT INTO payments(booking_id, method, amount, status, is_mock) VALUES (?,?,?,?,1)')
            ->execute([$bid, $method, $total, $payStatus]);

        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $ex;
    }

    out(['ok' => true, 'message' => 'Booking confirmed.',
         'booking' => [
            'reference' => $ref, 'hotel' => $hotel['name'], 'room' => $rt['name'],
            'check_in' => $ci, 'check_out' => $co, 'nights' => $nights, 'rooms' => $rooms,
            'guests' => $guests, 'subtotal' => $sub, 'taxes' => $tax, 'fees' => $fee,
            'total' => $total, 'currency' => cfg('booking.currency', 'USD'),
            'status' => $status, 'payment_method' => $method,
         ]], 201);
}

function a_my_bookings(): void {
    $u = require_login();
    $st = db()->prepare(
        'SELECT b.*, h.name AS hotel_name, h.city AS hotel_city, rt.name AS room_name
         FROM bookings b JOIN hotels h ON h.id = b.hotel_id JOIN room_types rt ON rt.id = b.room_type_id
         WHERE b.user_id = ? ORDER BY b.created_at DESC'
    );
    $st->execute([$u['id']]);
    out(['ok' => true, 'bookings' => $st->fetchAll()]);
}

function a_booking(): void {
    $u = require_login();
    $id = (int) ($_GET['id'] ?? 0);
    $st = db()->prepare(
        'SELECT b.*, h.name AS hotel_name, h.city AS hotel_city, h.country AS hotel_country, rt.name AS room_name
         FROM bookings b JOIN hotels h ON h.id = b.hotel_id JOIN room_types rt ON rt.id = b.room_type_id
         WHERE b.id = ?'
    );
    $st->execute([$id]);
    $b = $st->fetch();
    if (!$b) fail('Booking not found.', 404);
    if ((int) $b['user_id'] !== $u['id'] && $u['type'] !== 'admin') fail('Not allowed.', 403);
    $g = db()->prepare('SELECT full_name, email, phone FROM booking_guests WHERE booking_id = ?');
    $g->execute([$id]);
    out(['ok' => true, 'booking' => $b, 'guests' => $g->fetchAll()]);
}

/* ---------- admin ---------- */

function a_dashboard(): void {
    require_perm('dashboard.view');
    $q = fn(string $sql) => $sql;
    $c = fn(string $sql, array $p = []) => $GLOBALS['x'] ?? (function () use ($sql, $p) {
        $st = db()->prepare($sql); $st->execute($p); return $st->fetchColumn();
    })();

    $one = function (string $sql, array $p = []) {
        $st = db()->prepare($sql); $st->execute($p); return $st->fetchColumn();
    };

    $stats = [
        'total_users'  => (int) $one("SELECT COUNT(*) FROM users WHERE type='customer'"),
        'active_users' => (int) $one("SELECT COUNT(*) FROM users WHERE type='customer' AND status='active'"),
        'blocked_users'=> (int) $one("SELECT COUNT(*) FROM users WHERE type='customer' AND status='blocked'"),
        'pending_users'=> (int) $one("SELECT COUNT(*) FROM users WHERE type='customer' AND status='pending'"),
        'hotels'       => (int) $one('SELECT COUNT(*) FROM hotels'),
        'bookings'     => (int) $one('SELECT COUNT(*) FROM bookings'),
        'pending_bookings' => (int) $one("SELECT COUNT(*) FROM bookings WHERE status='pending'"),
        'revenue' => (float) $one("SELECT COALESCE(SUM(total),0) FROM bookings WHERE status IN ('confirmed','completed')"),
        'revenue_month' => (float) $one("SELECT COALESCE(SUM(total),0) FROM bookings
              WHERE status IN ('confirmed','completed') AND strftime('%Y-%m', created_at) = strftime('%Y-%m','now')"),
    ];
    $stats['pending_approvals'] = $stats['pending_users'] + $stats['pending_bookings'];

    $st = db()->query(
        "SELECT b.reference, b.total, b.status, b.check_in, b.check_out, u.name AS user_name, h.name AS hotel_name
         FROM bookings b JOIN users u ON u.id = b.user_id JOIN hotels h ON h.id = b.hotel_id
         ORDER BY b.created_at DESC LIMIT 8"
    );
    out(['ok' => true, 'stats' => $stats, 'recent' => $st->fetchAll()]);
}

function a_admin_hotels(): void {
    require_perm('hotels.view');
    $st = db()->query(
        'SELECT h.*, (SELECT COUNT(*) FROM room_types rt WHERE rt.hotel_id = h.id) AS room_count,
                (SELECT MIN(price_per_night) FROM room_types rt WHERE rt.hotel_id = h.id) AS min_price,
                (SELECT url FROM hotel_images i WHERE i.hotel_id = h.id ORDER BY sort_order LIMIT 1) AS image
         FROM hotels h ORDER BY h.name'
    );
    out(['ok' => true, 'hotels' => $st->fetchAll()]);
}

function a_save_hotel(): void {
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    require_perm($id ? 'hotels.update' : 'hotels.create');

    $name = trim((string) ($d['name'] ?? ''));
    $city = trim((string) ($d['city'] ?? ''));
    $country = trim((string) ($d['country'] ?? ''));
    $desc = trim((string) ($d['description'] ?? ''));
    $e = [];
    if (mb_strlen($name) < 2) $e['name'] = 'Name is required.';
    if ($city === '') $e['city'] = 'City is required.';
    if ($country === '') $e['country'] = 'Country is required.';
    if (mb_strlen($desc) < 10) $e['description'] = 'Description must be at least 10 characters.';
    $stars = max(1, min(5, (int) ($d['star_rating'] ?? 3)));
    $rating = max(0, min(5, (float) ($d['rating'] ?? 4.5)));
    $status = in_array($d['status'] ?? '', ['draft', 'published'], true) ? $d['status'] : 'draft';
    if ($e) fail('Please fix the highlighted fields.', 422, ['fields' => $e]);

    $amen = array_slice(array_values(array_filter(array_map('trim', (array) ($d['amenities'] ?? [])))), 0, 30);
    $policies = (array) ($d['policies'] ?? []);
    $images = array_slice(array_values(array_filter(array_map('trim', (array) ($d['images'] ?? [])))), 0, 12);
    $rooms = (array) ($d['room_types'] ?? []);

    $pdo = db();
    $pdo->beginTransaction();
    try {
        $slug = slugify($name);
        $dup = $pdo->prepare('SELECT id FROM hotels WHERE slug = ?' . ($id ? ' AND id != ?' : ''));
        $id ? $dup->execute([$slug, $id]) : $dup->execute([$slug]);
        if ($dup->fetch()) $slug .= '-' . random_int(100, 999);

        if ($id) {
            $pdo->prepare(
                'UPDATE hotels SET name=?, slug=?, description=?, address=?, city=?, country=?, location_text=?,
                 star_rating=?, rating=?, amenities=?, policies=?, status=?, updated_at=datetime(\'now\') WHERE id=?'
            )->execute([$name, $slug, $desc, trim((string) ($d['address'] ?? '')), $city, $country,
                        trim((string) ($d['location_text'] ?? '')), $stars, $rating,
                        json_encode($amen, JSON_UNESCAPED_SLASHES), json_encode($policies), $status, $id]);
        } else {
            $pdo->prepare(
                'INSERT INTO hotels(name,slug,description,address,city,country,location_text,star_rating,rating,
                    amenities,policies,base_price,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
            )->execute([$name, $slug, $desc, trim((string) ($d['address'] ?? '')), $city, $country,
                        trim((string) ($d['location_text'] ?? '')), $stars, $rating,
                        json_encode($amen, JSON_UNESCAPED_SLASHES), json_encode($policies),
                        (float) ($d['base_price'] ?? 0), $status]);
            $id = (int) $pdo->lastInsertId();
        }

        if ((bool) ($d['replace_images'] ?? true)) {
            $pdo->prepare('DELETE FROM hotel_images WHERE hotel_id = ?')->execute([$id]);
            $ins = $pdo->prepare('INSERT INTO hotel_images(hotel_id, url, alt, sort_order) VALUES (?,?,?,?)');
            foreach ($images as $i => $url) $ins->execute([$id, $url, $name . ' photo', $i]);
        }

        $keep = [];
        foreach ($rooms as $r) {
            $rn = trim((string) ($r['name'] ?? ''));
            if ($rn === '') continue;
            $price = max(0, (float) ($r['price_per_night'] ?? 0));
            $total = max(1, (int) ($r['total_rooms'] ?? 1));
            $mg = max(1, (int) ($r['max_guests'] ?? 2));
            $rid = (int) ($r['id'] ?? 0);
            if ($rid) {
                $pdo->prepare('UPDATE room_types SET name=?, description=?, max_guests=?, total_rooms=?, price_per_night=? WHERE id=? AND hotel_id=?')
                    ->execute([$rn, trim((string) ($r['description'] ?? '')), $mg, $total, $price, $rid, $id]);
                $keep[] = $rid;
            } else {
                $pdo->prepare('INSERT INTO room_types(hotel_id,name,description,max_guests,total_rooms,price_per_night,amenities,sort_order)
                               VALUES (?,?,?,?,?,?,?,?)')
                    ->execute([$id, $rn, trim((string) ($r['description'] ?? '')), $mg, $total, $price,
                               json_encode($amen, JSON_UNESCAPED_SLASHES), count($keep)]);
                $keep[] = (int) $pdo->lastInsertId();
            }
        }
        if ($keep) {
            $in = implode(',', array_fill(0, count($keep), '?'));
            $pdo->prepare("DELETE FROM room_types WHERE hotel_id = ? AND id NOT IN ($in)")
                ->execute(array_merge([$id], $keep));
        } else {
            $pdo->prepare('DELETE FROM room_types WHERE hotel_id = ?')->execute([$id]);
        }

        $min = $pdo->prepare('SELECT MIN(price_per_night) FROM room_types WHERE hotel_id = ?');
        $min->execute([$id]);
        $base = (float) ($min->fetchColumn() ?: 0);
        $pdo->prepare('UPDATE hotels SET base_price = ? WHERE id = ?')->execute([$base, $id]);

        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $ex;
    }

    audit($id ? 'hotel.update' : 'hotel.create', 'hotel', $id, "Hotel '$name'");
    out(['ok' => true, 'id' => $id, 'message' => 'Hotel saved.']);
}

function a_delete_hotel(): void {
    require_perm('hotels.delete');
    $id = (int) (json_in()['id'] ?? 0);
    $st = db()->prepare('SELECT name FROM hotels WHERE id = ?');
    $st->execute([$id]);
    $name = $st->fetchColumn();
    if (!$name) fail('Hotel not found.', 404);
    $cnt = db()->prepare('SELECT COUNT(*) FROM bookings WHERE hotel_id = ?');
    $cnt->execute([$id]);
    if ((int) $cnt->fetchColumn() > 0)
        fail('This hotel has bookings and cannot be deleted. Unpublish it instead.', 409);
    db()->prepare('DELETE FROM hotels WHERE id = ?')->execute([$id]);
    audit('hotel.delete', 'hotel', $id, "Hotel '$name'");
    out(['ok' => true, 'message' => 'Hotel deleted.']);
}

function a_toggle_hotel(): void {
    require_perm('hotels.publish');
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    $st = db()->prepare('SELECT name, status FROM hotels WHERE id = ?');
    $st->execute([$id]);
    $h = $st->fetch();
    if (!$h) fail('Hotel not found.', 404);
    $new = $h['status'] === 'published' ? 'draft' : 'published';
    db()->prepare("UPDATE hotels SET status = ?, updated_at = datetime('now') WHERE id = ?")->execute([$new, $id]);
    audit('hotel.' . ($new === 'published' ? 'publish' : 'unpublish'), 'hotel', $id, "Hotel '{$h['name']}'");
    out(['ok' => true, 'status' => $new, 'message' => 'Hotel ' . ($new === 'published' ? 'published' : 'unpublished') . '.']);
}

function a_admin_bookings(): void {
    require_perm('bookings.view');
    $status = (string) ($_GET['status'] ?? '');
    $sql = 'SELECT b.*, u.name AS user_name, u.email AS user_email, h.name AS hotel_name, rt.name AS room_name
            FROM bookings b JOIN users u ON u.id = b.user_id
            JOIN hotels h ON h.id = b.hotel_id JOIN room_types rt ON rt.id = b.room_type_id';
    $p = [];
    if ($status !== '') { $sql .= ' WHERE b.status = ?'; $p[] = $status; }
    $sql .= ' ORDER BY b.created_at DESC LIMIT 300';
    $st = db()->prepare($sql);
    $st->execute($p);
    out(['ok' => true, 'bookings' => $st->fetchAll()]);
}

function a_update_booking(): void {
    require_perm('bookings.update');
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    $status = (string) ($d['status'] ?? '');
    if (!in_array($status, ['pending', 'confirmed', 'cancelled', 'completed', 'rejected'], true))
        fail('Invalid status.', 422);
    $st = db()->prepare('SELECT status FROM bookings WHERE id = ?');
    $st->execute([$id]);
    $old = $st->fetchColumn();
    if (!$old) fail('Booking not found.', 404);
    db()->prepare("UPDATE bookings SET status = ?, updated_at = datetime('now') WHERE id = ?")->execute([$status, $id]);
    if ($status === 'cancelled' || $status === 'rejected') {
        db()->prepare("UPDATE payments SET status = 'refunded' WHERE booking_id = ? AND status = 'paid'")->execute([$id]);
    }
    audit('booking.status', 'booking', $id, "$old → $status");
    out(['ok' => true, 'message' => 'Booking updated.']);
}

function a_admin_users(): void {
    require_perm('users.view');
    $q = trim((string) ($_GET['q'] ?? ''));
    $status = (string) ($_GET['status'] ?? '');
    $sql = "SELECT id, name, email, username, phone, type, status, email_verified_at, country, city, created_at
            FROM users WHERE type = 'customer'";
    $p = [];
    if ($q !== '') { $sql .= ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'; $like = "%$q%"; array_push($p, $like, $like, $like); }
    if ($status !== '') { $sql .= ' AND status = ?'; $p[] = $status; }
    $sql .= ' ORDER BY created_at DESC LIMIT 300';
    $st = db()->prepare($sql);
    $st->execute($p);
    out(['ok' => true, 'users' => $st->fetchAll()]);
}

function a_save_user(): void {
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    require_perm($id ? 'users.update' : 'users.create');
    $name = trim((string) ($d['name'] ?? ''));
    $email = strtolower(trim((string) ($d['email'] ?? '')));
    $phone = trim((string) ($d['phone'] ?? ''));
    $status = in_array($d['status'] ?? '', ['pending', 'active', 'blocked'], true) ? $d['status'] : 'active';
    $e = [];
    if (mb_strlen($name) < 2) $e['name'] = 'Name is required.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $e['email'] = 'Valid email required.';
    if ($phone && !preg_match('/^[0-9+\-\s()]{7,20}$/', $phone)) $e['phone'] = 'Invalid phone.';
    $dup = db()->prepare('SELECT id FROM users WHERE email = ?' . ($id ? ' AND id != ?' : ''));
    $id ? $dup->execute([$email, $id]) : $dup->execute([$email]);
    if ($dup->fetch()) $e['email'] = 'Already in use.';
    if ($e) fail('Please fix the highlighted fields.', 422, ['fields' => $e]);

    if ($id) {
        db()->prepare("UPDATE users SET name=?, email=?, phone=?, status=?, updated_at=datetime('now') WHERE id=? AND type='customer'")
            ->execute([$name, $email, $phone, $status, $id]);
    } else {
        $pw = (string) ($d['password'] ?? '');
        if (strlen($pw) < 8) fail('Temporary password must be at least 8 characters.', 422, ['fields' => ['password' => 'Too short.']]);
        db()->prepare("INSERT INTO users(name,email,phone,password_hash,type,status,email_verified_at) VALUES (?,?,?,?,'customer',?, datetime('now'))")
            ->execute([$name, $email, $phone, password_hash($pw, PASSWORD_DEFAULT), $status]);
        $id = (int) db()->lastInsertId();
    }
    audit($id ? 'user.update' : 'user.create', 'user', $id, "$name <$email> status=$status");
    out(['ok' => true, 'id' => $id, 'message' => 'Customer saved.']);
}

function a_user_status(): void {
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    $status = (string) ($d['status'] ?? '');
    if (!in_array($status, ['pending', 'active', 'blocked'], true)) fail('Invalid status.', 422);
    require_perm($status === 'active' ? 'users.approve' : 'users.update');
    $me = current_user();
    if ((int) $me['id'] === $id) fail('You cannot change your own account status.', 403);

    $st = db()->prepare("SELECT name, status FROM users WHERE id = ? AND type = 'customer'");
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) fail('Customer not found.', 404);
    db()->prepare("UPDATE users SET status = ?, updated_at = datetime('now') WHERE id = ?")->execute([$status, $id]);
    audit('user.status', 'user', $id, "{$row['name']}: {$row['status']} → $status");
    out(['ok' => true, 'message' => 'Status updated.']);
}

function a_delete_user(): void {
    require_perm('users.delete');
    $id = (int) (json_in()['id'] ?? 0);
    $me = current_user();
    if ((int) $me['id'] === $id) fail('You cannot delete your own account.', 403);
    if (is_super($id) && !is_super($me['id'])) fail('You cannot delete a super administrator.', 403);
    $st = db()->prepare("SELECT name FROM users WHERE id = ? AND type = 'customer'");
    $st->execute([$id]);
    $name = $st->fetchColumn();
    if (!$name) fail('Customer not found.', 404);
    $cnt = db()->prepare('SELECT COUNT(*) FROM bookings WHERE user_id = ?');
    $cnt->execute([$id]);
    if ((int) $cnt->fetchColumn() > 0) fail('This customer has bookings. Block the account instead of deleting it.', 409);
    db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
    audit('user.delete', 'user', $id, (string) $name);
    out(['ok' => true, 'message' => 'Customer deleted.']);
}

function a_admin_staff(): void {
    require_perm('admins.view');
    $st = db()->query(
        "SELECT id, name, email, username, phone, status, email_verified_at, created_at FROM users
         WHERE type = 'admin' ORDER BY id"
    );
    $staff = $st->fetchAll();
    $roles = db()->query('SELECT id, name, description FROM roles ORDER BY name')->fetchAll();
    $assign = db()->prepare(
        'SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ?'
    );
    $gperm = db()->prepare(
        'SELECT p.code FROM user_permissions up JOIN permissions p ON p.id = up.permission_id WHERE up.user_id = ?'
    );
    foreach ($staff as &$s) {
        $assign->execute([$s['id']]);
        $s['roles'] = $assign->fetchAll(PDO::FETCH_COLUMN);
        $gperm->execute([$s['id']]);
        $s['permissions'] = $gperm->fetchAll(PDO::FETCH_COLUMN);
    }
    out(['ok' => true, 'staff' => $staff, 'roles' => $roles]);
}

function a_save_staff(): void {
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    $actor = require_perm($id ? 'admins.update' : 'admins.create');
    $actorSuper = is_super($actor['id']);

    if ($id && (int) $actor['id'] === $id)
        fail('You cannot edit your own account here.', 403);
    if ($id && !$actorSuper && is_super($id))
        fail('You cannot modify a super administrator.', 403);

    $name = trim((string) ($d['name'] ?? ''));
    $email = strtolower(trim((string) ($d['email'] ?? '')));
    $username = strtolower(trim((string) ($d['username'] ?? '')));
    $phone = trim((string) ($d['phone'] ?? ''));
    $status = in_array($d['status'] ?? '', ['pending', 'active', 'blocked'], true) ? $d['status'] : 'active';
    $roles = array_values(array_filter((array) ($d['roles'] ?? []), 'is_string'));
    $perms = array_values(array_filter((array) ($d['permissions'] ?? []), 'is_string'));

    $e = [];
    if (mb_strlen($name) < 2) $e['name'] = 'Name is required.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $e['email'] = 'Valid email required.';
    if (!preg_match('/^[a-z0-9_.-]{3,30}$/', $username)) $e['username'] = '3–30 chars: a–z 0–9 . _ -';
    $dup = db()->prepare('SELECT id FROM users WHERE (email = ? OR username = ?)' . ($id ? ' AND id != ?' : ''));
    $id ? $dup->execute([$email, $username, $id]) : $dup->execute([$email, $username]);
    if ($dup->fetch()) $e['email'] = 'Email or username already in use.';
    $pw = (string) ($d['password'] ?? '');
    if (!$id && strlen($pw) < 8) $e['password'] = 'At least 8 characters.';
    if ($e) fail('Please fix the highlighted fields.', 422, ['fields' => $e]);

    if (!$actorSuper) {
        require_perm('roles.manage');
        $mine = all_perms($actor['id']);
        foreach ($perms as $p) if (!in_array($p, $mine, true))
            fail("You cannot grant a permission you do not hold: $p", 403);
        if (in_array('super_admin', $roles, true))
            fail('Only a super administrator can grant the super_admin role.', 403);
        $myRoles = db()->prepare('SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ?');
        $myRoles->execute([$actor['id']]);
        $held = $myRoles->fetchAll(PDO::FETCH_COLUMN);
        foreach ($roles as $r) if (!in_array($r, $held, true))
            fail("You cannot grant a role you do not hold: $r", 403);
    }

    $pdo = db();
    $pdo->beginTransaction();
    try {
        if ($id) {
            $pdo->prepare("UPDATE users SET name=?, email=?, username=?, phone=?, status=?, updated_at=datetime('now') WHERE id=? AND type='admin'")
                ->execute([$name, $email, $username, $phone, $status, $id]);
            if ($pw !== '') $pdo->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
                ->execute([password_hash($pw, PASSWORD_DEFAULT), $id]);
        } else {
            $pdo->prepare("INSERT INTO users(name,email,username,phone,password_hash,type,status,email_verified_at)
                           VALUES (?,?,?,?,?,'admin',?, datetime('now'))")
                ->execute([$name, $email, $username, $phone, password_hash($pw, PASSWORD_DEFAULT), $status]);
            $id = (int) $pdo->lastInsertId();
        }

        $pdo->prepare('DELETE FROM user_roles WHERE user_id = ?')->execute([$id]);
        $pdo->prepare('DELETE FROM user_permissions WHERE user_id = ?')->execute([$id]);
        $lr = $pdo->prepare('INSERT OR IGNORE INTO user_roles(user_id, role_id, assigned_by)
                             SELECT ?, r.id, ? FROM roles r WHERE r.name = ?');
        foreach ($roles as $rn) $lr->execute([$id, $actor['id'], $rn]);
        $lp = $pdo->prepare('INSERT OR IGNORE INTO user_permissions(user_id, permission_id, granted_by)
                             SELECT ?, p.id, ? FROM permissions p WHERE p.code = ?');
        foreach ($perms as $pc) $lp->execute([$id, $actor['id'], $pc]);
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $ex;
    }

    audit($id ? 'staff.update' : 'staff.create', 'user', $id, "$name <$email> roles=" . implode(',', $roles));
    out(['ok' => true, 'id' => $id, 'message' => 'Staff account saved.']);
}

function a_delete_staff(): void {
    $id = (int) (json_in()['id'] ?? 0);
    $actor = require_perm('admins.delete');
    if ((int) $actor['id'] === $id) fail('You cannot delete your own account.', 403);
    if (is_super($id) && !is_super($actor['id'])) fail('You cannot delete a super administrator.', 403);
    $st = db()->prepare("SELECT name FROM users WHERE id = ? AND type = 'admin'");
    $st->execute([$id]);
    $name = $st->fetchColumn();
    if (!$name) fail('Staff account not found.', 404);
    $bookings = db()->prepare("SELECT COUNT(*) FROM bookings b JOIN user_roles ur ON 1=0");
    db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
    audit('staff.delete', 'user', $id, (string) $name);
    out(['ok' => true, 'message' => 'Staff account deleted.']);
}

function a_roles(): void {
    require_perm('admins.view');
    $roles = db()->query('SELECT * FROM roles ORDER BY name')->fetchAll();
    $perms = db()->query('SELECT * FROM permissions ORDER BY code')->fetchAll();
    $rp = db()->prepare('SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ?');
    foreach ($roles as &$r) { $rp->execute([$r['id']]); $r['permissions'] = $rp->fetchAll(PDO::FETCH_COLUMN); }
    $cnt = db()->prepare('SELECT COUNT(*) FROM user_roles WHERE role_id = ?');
    foreach ($roles as &$r) { $cnt->execute([$r['id']]); $r['user_count'] = (int) $cnt->fetchColumn(); }
    out(['ok' => true, 'roles' => $roles, 'permissions' => $perms]);
}

function a_save_role(): void {
    require_perm('roles.manage');
    $d = json_in();
    $id = (int) ($d['id'] ?? 0);
    $name = trim((string) ($d['name'] ?? ''));
    $desc = trim((string) ($d['description'] ?? ''));
    $codes = array_values(array_filter((array) ($d['permissions'] ?? []), 'is_string'));
    if (!preg_match('/^[a-z_]{3,40}$/', $name)) fail('Role name: 3–40 lowercase chars/underscores.', 422, ['fields' => ['name' => 'Invalid.']]);
    if ($name === 'super_admin') fail('The super_admin role cannot be modified.', 403);

    $dup = db()->prepare('SELECT id FROM roles WHERE name = ?' . ($id ? ' AND id != ?' : ''));
    $id ? $dup->execute([$name, $id]) : $dup->execute([$name]);
    if ($dup->fetch()) fail('A role with that name exists.', 409, ['fields' => ['name' => 'Duplicate.']]);

    $pdo = db();
    $pdo->beginTransaction();
    try {
        if ($id) $pdo->prepare('UPDATE roles SET name = ?, description = ? WHERE id = ?')->execute([$name, $desc, $id]);
        else { $pdo->prepare('INSERT INTO roles(name, description) VALUES (?, ?)')->execute([$name, $desc]); $id = (int) $pdo->lastInsertId(); }
        $pdo->prepare('DELETE FROM role_permissions WHERE role_id = ?')->execute([$id]);
        $ins = $pdo->prepare('INSERT OR IGNORE INTO role_permissions(role_id, permission_id) SELECT ?, id FROM permissions WHERE code = ?');
        foreach ($codes as $c) $ins->execute([$id, $c]);
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $ex;
    }
    audit('role.update', 'role', $id, "$name (" . count($codes) . ' perms)');
    out(['ok' => true, 'id' => $id, 'message' => 'Role saved.']);
}

function a_delete_role(): void {
    require_perm('roles.manage');
    $id = (int) (json_in()['id'] ?? 0);
    $st = db()->prepare('SELECT name FROM roles WHERE id = ?');
    $st->execute([$id]);
    $name = $st->fetchColumn();
    if (!$name) fail('Role not found.', 404);
    if ($name === 'super_admin') fail('The super_admin role cannot be deleted.', 403);
    $cnt = db()->prepare('SELECT COUNT(*) FROM user_roles WHERE role_id = ?');
    $cnt->execute([$id]);
    if ((int) $cnt->fetchColumn() > 0) fail('Role is assigned to users. Reassign them first.', 409);
    db()->prepare('DELETE FROM roles WHERE id = ?')->execute([$id]);
    audit('role.delete', 'role', $id, (string) $name);
    out(['ok' => true, 'message' => 'Role deleted.']);
}

function a_audit(): void {
    require_perm('audit.view');
    $page = max(1, (int) ($_GET['page'] ?? 1));
    $per = 50;
    $total = (int) db()->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn();
    $st = db()->prepare('SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?');
    $st->execute([$per, ($page - 1) * $per]);
    out(['ok' => true, 'entries' => $st->fetchAll(), 'total' => $total,
         'page' => $page, 'pages' => max(1, (int) ceil($total / $per))]);
}
