<?php
declare(strict_types=1);

/* ================= helpers ================= */

function public_user(array $u): array {
    return [
        'id'              => (int) $u['id'],
        'name'            => $u['name'],
        'email'           => $u['email'],
        'username'        => $u['username'],
        'phone'           => $u['phone'],
        'type'            => $u['type'],
        'status'          => $u['status'],
        'verified'        => !empty($u['email_verified_at']),
        'email_verified_at' => $u['email_verified_at'],
        'country'         => $u['country'],
        'city'            => $u['city'],
        'address'         => $u['address'],
        'date_of_birth'   => $u['date_of_birth'],
        'preferences'     => $u['preferences'],
        'created_at'      => $u['created_at'],
        'roles'           => roles_of((int) $u['id']),
    ];
}

function roles_of(int $userId): array {
    $st = db()->prepare('SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.name');
    $st->execute([$userId]);
    return $st->fetchAll(PDO::FETCH_COLUMN);
}

function issue_verification(array $user): void {
    $raw = bin2hex(random_bytes(32));
    $hash = hash('sha256', $raw);
    $hours = (int) cfg('email.verification_ttl_hours', 24);
    $st = db()->prepare("DELETE FROM email_verification_tokens WHERE user_id = ? OR expires_at < datetime('now')");
    $st->execute([(int) $user['id']]);
    $st = db()->prepare('INSERT INTO email_verification_tokens (user_id, token_hash, expires_at) VALUES (?,?,?)');
    $st->execute([(int) $user['id'], $hash, gmdate('Y-m-d H:i:s', time() + $hours * 3600)]);

    $link = rtrim((string) cfg('app.base_url', 'http://localhost:8000'), '/') . '/index.html?verify=' . $raw;
    send_mail(
        $user['email'],
        'Verify your Bookify account',
        "Hi {$user['name']},\n\nPlease verify your email address to start booking:\n{$link}\n\n"
            . "This link expires in {$hours} hour(s).\n\nIf you did not create this account, ignore this email.\n"
    );
}

function room_options(int $hotelId, string $checkIn, string $checkOut, int $guests, int $rooms): array {
    $st = db()->prepare('SELECT * FROM room_types WHERE hotel_id = ? ORDER BY price_per_night ASC');
    $st->execute([$hotelId]);
    $options = [];
    foreach ($st->fetchAll() as $rt) {
        $available = availability_for((int) $rt['id'], $checkIn, $checkOut);
        if ($available < $rooms || ((int) $rt['capacity']) * $rooms < $guests) {
            continue;
        }
        $options[] = [
            'id'          => (int) $rt['id'],
            'name'        => $rt['name'],
            'description' => $rt['description'],
            'capacity'    => (int) $rt['capacity'],
            'price'       => (float) $rt['price_per_night'],
            'available'   => $available,
            'amenities'   => json_arr($rt['amenities']),
        ];
    }
    return $options;
}

/* ================= bootstrap / auth ================= */

function action_bootstrap(): void {
    $user = auth_user();
    $permissions = [];
    if ($user !== null && $user['type'] === 'admin' && $user['status'] === 'active') {
        $permissions = perms_for((int) $user['id']);
    }
    ok([
        'csrf'        => csrf_token(),
        'user'        => $user ? public_user($user) : null,
        'permissions' => $permissions,
        'settings'    => [
            'currency'    => (string) cfg('booking.currency', 'USD'),
            'symbol'      => (string) cfg('booking.symbol', '$'),
            'tax_rate'    => (float) cfg('booking.tax_rate', 0.12),
            'service_fee' => (float) cfg('booking.service_fee', 15.00),
        ],
    ]);
}

function action_register(array $in): void {
    $name = req_str($in, 'name', 'Full name', 2, 100);
    $email = email_value($in);
    $phone = opt_str($in, 'phone', 25);
    if ($phone !== '' && !preg_match('/^[0-9+()\- ]{6,25}$/', $phone)) {
        fail('Please enter a valid phone number.');
    }
    $password = password_value($in);
    $confirm = (string) ($in['password_confirm'] ?? $in['confirm_password'] ?? '');
    if ($confirm !== $password) {
        fail('Passwords do not match.');
    }

    $st = db()->prepare('SELECT id FROM users WHERE email = ?');
    $st->execute([$email]);
    if ($st->fetch()) {
        fail('An account with this email already exists. Try signing in instead.', 409);
    }

    $st = db()->prepare(
        "INSERT INTO users (name, email, phone, password_hash, type, status, country, city, address, preferences)
         VALUES (?,?,?,?,'customer','pending',?,?,?,?)"
    );
    $st->execute([
        $name,
        $email,
        $phone,
        password_hash($password, PASSWORD_DEFAULT),
        opt_str($in, 'country', 80),
        opt_str($in, 'city', 80),
        opt_str($in, 'address', 200),
        opt_str($in, 'preferences', 400),
    ]);
    $userId = (int) db()->lastInsertId();

    $st = db()->prepare('SELECT * FROM users WHERE id = ?');
    $st->execute([$userId]);
    issue_verification($st->fetch());
    audit('user.register', 'users', $userId, ['email' => $email]);

    ok([
        'message'  => 'Account created. Check your email for the verification link, then sign in.',
        'dev_hint' => 'Local development: the link is also appended to storage/mail.log.',
    ]);
}

function action_verify_email(array $in): void {
    $token = trim((string) ($in['token'] ?? ''));
    if ($token === '' || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        fail('That verification link is not valid.', 400, ['code' => 'bad_token']);
    }
    $st = db()->prepare('SELECT * FROM email_verification_tokens WHERE token_hash = ?');
    $st->execute([hash('sha256', $token)]);
    $row = $st->fetch();
    if (!$row || $row['used_at'] !== null || strtotime($row['expires_at']) < time()) {
        fail('This verification link has expired or was already used. Request a new one.', 400, ['code' => 'bad_token']);
    }
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare("UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?), status = CASE WHEN status = 'pending' THEN 'active' ELSE status END, updated_at = ? WHERE id = ?");
        $st->execute([now_utc(), now_utc(), (int) $row['user_id']]);
        $st = $pdo->prepare('UPDATE email_verification_tokens SET used_at = ? WHERE id = ?');
        $st->execute([now_utc(), (int) $row['id']]);
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('verify failed: ' . $ex->getMessage());
        fail('Could not verify the account. Please try again.', 500);
    }
    audit('user.verify_email', 'users', (int) $row['user_id']);
    ok(['message' => 'Email verified. You can now sign in and book.']);
}

function action_resend_verification(array $in): void {
    $email = email_value($in);
    $st = db()->prepare("SELECT * FROM users WHERE email = ? AND type = 'customer'");
    $st->execute([$email]);
    $user = $st->fetch();
    // Do not reveal whether the address exists.
    if ($user && empty($user['email_verified_at']) && $user['status'] !== 'blocked') {
        issue_verification($user);
        audit('user.resend_verification', 'users', (int) $user['id']);
    }
    ok(['message' => 'If that address needs verification, a new link has been sent (local dev: storage/mail.log).']);
}

function action_login(array $in): void {
    $email = email_value($in);
    $password = (string) ($in['password'] ?? '');
    if ($password === '') {
        fail('Please enter your password.');
    }
    $st = db()->prepare("SELECT * FROM users WHERE email = ? AND type = 'customer'");
    $st->execute([$email]);
    $user = $st->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) {
        fail('Invalid email or password.', 401);
    }
    if ($user['status'] === 'blocked') {
        fail('Your account has been blocked. Please contact support.', 403);
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    audit('user.login', 'users', (int) $user['id']);
    ok(['user' => public_user($user), 'permissions' => []]);
}

function action_admin_login(array $in): void {
    $identifier = req_str($in, 'identifier', 'Username or email', 3, 254);
    $password = (string) ($in['password'] ?? '');
    if ($password === '') {
        fail('Please enter your password.');
    }
    $st = db()->prepare("SELECT * FROM users WHERE type = 'admin' AND (username = ? OR email = ?)");
    $st->execute([$identifier, strtolower($identifier)]);
    $user = $st->fetch();
    if (!$user || !password_verify($password, $user['password_hash'])) {
        fail('Invalid administrator credentials.', 401);
    }
    if ($user['status'] !== 'active') {
        fail('This administrator account is not active.', 403);
    }
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    audit('admin.login', 'users', (int) $user['id']);
    ok(['user' => public_user($user), 'permissions' => perms_for((int) $user['id'])]);
}

function action_logout(): void {
    $u = auth_user();
    if ($u) {
        audit($u['type'] === 'admin' ? 'admin.logout' : 'user.logout', 'users', (int) $u['id']);
    }
    destroy_session();
    ok(['message' => 'Signed out.']);
}

function action_admin_logout(): void {
    action_logout();
}

function action_me(): void {
    $u = require_login();
    $permissions = $u['type'] === 'admin' ? perms_for((int) $u['id']) : [];
    ok(['user' => public_user($u), 'permissions' => $permissions]);
}

/* ================= customer profile ================= */

function action_profile_update(array $in): void {
    $u = require_customer();
    $name = req_str($in, 'name', 'Full name', 2, 100);
    $phone = opt_str($in, 'phone', 25);
    if ($phone !== '' && !preg_match('/^[0-9+()\- ]{6,25}$/', $phone)) {
        fail('Please enter a valid phone number.');
    }
    $dob = trim((string) ($in['date_of_birth'] ?? ''));
    if ($dob !== '' && valid_date($dob) === null) {
        fail('Date of birth must be a valid date (YYYY-MM-DD).');
    }
    if ($dob !== '' && $dob > date('Y-m-d')) {
        fail('Date of birth cannot be in the future.');
    }
    $st = db()->prepare(
        'UPDATE users SET name = ?, phone = ?, country = ?, city = ?, address = ?, date_of_birth = ?, preferences = ?, updated_at = ? WHERE id = ?'
    );
    $st->execute([
        $name,
        $phone,
        opt_str($in, 'country', 80),
        opt_str($in, 'city', 80),
        opt_str($in, 'address', 200),
        $dob === '' ? null : $dob,
        opt_str($in, 'preferences', 400),
        now_utc(),
        (int) $u['id'],
    ]);
    audit('user.profile_update', 'users', (int) $u['id']);
    $st = db()->prepare('SELECT * FROM users WHERE id = ?');
    $st->execute([(int) $u['id']]);
    ok(['user' => public_user($st->fetch()), 'message' => 'Profile updated.']);
}

function action_change_password(array $in): void {
    $u = require_login();
    $current = (string) ($in['current_password'] ?? '');
    if (!password_verify($current, $u['password_hash'])) {
        fail('Your current password is incorrect.', 403);
    }
    $new = password_value($in, 'password');
    $confirm = (string) ($in['password_confirm'] ?? '');
    if ($new !== $confirm) {
        fail('New passwords do not match.');
    }
    if (password_verify($new, $u['password_hash'])) {
        fail('Choose a password different from your current one.');
    }
    $st = db()->prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?');
    $st->execute([password_hash($new, PASSWORD_DEFAULT), now_utc(), (int) $u['id']]);
    session_regenerate_id(true);
    audit('user.password_change', 'users', (int) $u['id']);
    ok(['message' => 'Password changed successfully.']);
}

/* ================= customer bookings ================= */

function action_my_bookings(): void {
    $u = require_customer();
    $st = db()->prepare(
        "SELECT b.id, b.reference, b.check_in, b.check_out, b.nights, b.num_guests, b.num_rooms,
                b.total, b.currency, b.status, b.payment_method, b.created_at,
                h.name AS hotel_name, h.city, h.country, rt.name AS room_name,
                (SELECT i.url FROM hotel_images i WHERE i.hotel_id = h.id ORDER BY i.sort_order, i.id LIMIT 1) AS image
         FROM bookings b
         JOIN hotels h ON h.id = b.hotel_id
         JOIN room_types rt ON rt.id = b.room_type_id
         WHERE b.user_id = ?
         ORDER BY b.created_at DESC"
    );
    $st->execute([(int) $u['id']]);
    $rows = array_map(static function (array $r): array {
        $r['id'] = (int) $r['id'];
        $r['total'] = (float) $r['total'];
        $r['nights'] = (int) $r['nights'];
        $r['num_guests'] = (int) $r['num_guests'];
        $r['num_rooms'] = (int) $r['num_rooms'];
        return $r;
    }, $st->fetchAll());
    ok(['bookings' => $rows]);
}

function action_booking_detail(array $in): void {
    $u = require_customer();
    $id = (int) ($in['id'] ?? 0);
    $st = db()->prepare(
        "SELECT b.*, h.name AS hotel_name, h.city AS hotel_city, h.country AS hotel_country,
                h.address AS hotel_address, rt.name AS room_name
         FROM bookings b
         JOIN hotels h ON h.id = b.hotel_id
         JOIN room_types rt ON rt.id = b.room_type_id
         WHERE b.id = ? AND b.user_id = ?"
    );
    $st->execute([$id, (int) $u['id']]);
    $booking = $st->fetch();
    if (!$booking) {
        fail('Booking not found.', 404);
    }
    $st = db()->prepare('SELECT name, email, phone, is_primary FROM booking_guests WHERE booking_id = ? ORDER BY is_primary DESC, id');
    $st->execute([$id]);
    $guests = $st->fetchAll();
    $st = db()->prepare('SELECT method, amount, currency, status, transaction_ref, created_at FROM payments WHERE booking_id = ?');
    $st->execute([$id]);
    ok(['booking' => $booking, 'guests' => $guests, 'payment' => $st->fetch() ?: null]);
}

/* ================= public catalogue ================= */

function action_hotels(array $in): void {
    $destination = trim((string) ($in['destination'] ?? ''));
    $checkIn = valid_date((string) ($in['check_in'] ?? '')) ?? date('Y-m-d', strtotime('+1 day'));
    $checkOut = valid_date((string) ($in['check_out'] ?? '')) ?? date('Y-m-d', strtotime('+3 days'));
    if ($checkOut <= $checkIn) {
        fail('Check-out must be after check-in.');
    }
    $nights = (int) round((strtotime($checkOut) - strtotime($checkIn)) / 86400);
    if ($nights < 1 || $nights > 30) {
        fail('Stays must be between 1 and 30 nights.');
    }
    $guests = max(1, min(20, (int) ($in['guests'] ?? 1)));
    $rooms = max(1, min(10, (int) ($in['rooms'] ?? 1)));
    $minPrice = is_numeric($in['min_price'] ?? null) ? (float) $in['min_price'] : null;
    $maxPrice = is_numeric($in['max_price'] ?? null) ? (float) $in['max_price'] : null;
    $minRating = is_numeric($in['min_rating'] ?? null) ? (float) $in['min_rating'] : null;
    $minStars = max(0, min(5, (int) ($in['stars'] ?? 0)));
    $amenities = array_filter(array_map('trim', explode(',', (string) ($in['amenities'] ?? ''))));

    $sql = "SELECT h.* FROM hotels h WHERE h.status = 'published'";
    $params = [];
    if ($destination !== '') {
        $sql .= ' AND (h.city LIKE ? OR h.country LIKE ? OR h.name LIKE ? OR h.address LIKE ?)';
        $like = '%' . $destination . '%';
        array_push($params, $like, $like, $like, $like);
    }
    if ($minPrice !== null) {
        $sql .= ' AND h.price_per_night >= ?';
        $params[] = $minPrice;
    }
    if ($maxPrice !== null) {
        $sql .= ' AND h.price_per_night <= ?';
        $params[] = $maxPrice;
    }
    if ($minRating !== null) {
        $sql .= ' AND h.rating >= ?';
        $params[] = $minRating;
    }
    if ($minStars > 0) {
        $sql .= ' AND h.stars >= ?';
        $params[] = $minStars;
    }
    foreach ($amenities as $amenity) {
        if ($amenity === '' || strlen($amenity) > 40) {
            continue;
        }
        $sql .= ' AND h.amenities LIKE ?';
        $params[] = '%"'. $amenity . '"%';
    }
    $sql .= ' ORDER BY h.rating DESC, h.stars DESC LIMIT 60';

    $st = db()->prepare($sql);
    $st->execute($params);

    $results = [];
    foreach ($st->fetchAll() as $h) {
        $options = room_options((int) $h['id'], $checkIn, $checkOut, $guests, $rooms);
        if ($options === []) {
            continue;
        }
        $images = db()->prepare('SELECT url FROM hotel_images WHERE hotel_id = ? ORDER BY sort_order, id LIMIT 1');
        $images->execute([(int) $h['id']]);
        $results[] = [
            'id'             => (int) $h['id'],
            'name'           => $h['name'],
            'city'           => $h['city'],
            'country'        => $h['country'],
            'address'        => $h['address'],
            'stars'          => (int) $h['stars'],
            'rating'         => (float) $h['rating'],
            'reviews_count'  => (int) $h['reviews_count'],
            'amenities'      => json_arr($h['amenities']),
            'image'          => $images->fetchColumn() ?: null,
            'price_from'     => min(array_column($options, 'price')),
            'available_rooms'=> max(array_column($options, 'available')),
            'room_types'     => $options,
        ];
    }
    ok([
        'hotels' => $results,
        'count'  => count($results),
        'search' => [
            'destination' => $destination,
            'check_in'    => $checkIn,
            'check_out'   => $checkOut,
            'nights'      => $nights,
            'guests'      => $guests,
            'rooms'       => $rooms,
        ],
    ]);
}

function action_hotel_detail(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $checkIn = valid_date((string) ($in['check_in'] ?? '')) ?? date('Y-m-d', strtotime('+1 day'));
    $checkOut = valid_date((string) ($in['check_out'] ?? '')) ?? date('Y-m-d', strtotime('+3 days'));
    if ($checkOut <= $checkIn) {
        fail('Check-out must be after check-in.');
    }
    $guests = max(1, min(20, (int) ($in['guests'] ?? 1)));
    $rooms = max(1, min(10, (int) ($in['rooms'] ?? 1)));

    $st = db()->prepare("SELECT * FROM hotels WHERE id = ? AND status = 'published'");
    $st->execute([$id]);
    $hotel = $st->fetch();
    if (!$hotel) {
        fail('Hotel not found.', 404);
    }
    $st = db()->prepare('SELECT url, alt FROM hotel_images WHERE hotel_id = ? ORDER BY sort_order, id');
    $st->execute([$id]);
    $images = $st->fetchAll();
    $nights = (int) round((strtotime($checkOut) - strtotime($checkIn)) / 86400);

    ok([
        'hotel' => [
            'id'            => (int) $hotel['id'],
            'name'          => $hotel['name'],
            'description'   => $hotel['description'],
            'address'       => $hotel['address'],
            'city'          => $hotel['city'],
            'country'       => $hotel['country'],
            'location_text' => $hotel['location_text'],
            'stars'         => (int) $hotel['stars'],
            'rating'        => (float) $hotel['rating'],
            'reviews_count' => (int) $hotel['reviews_count'],
            'amenities'     => json_arr($hotel['amenities']),
            'policies'      => json_arr($hotel['policies']),
            'images'        => $images,
        ],
        'rooms'      => room_options($id, $checkIn, $checkOut, $guests, $rooms),
        'reviews'    => [],
        'review_note'=> 'Reviews are a placeholder in this demo build.',
        'search'     => ['check_in' => $checkIn, 'check_out' => $checkOut, 'nights' => $nights, 'guests' => $guests, 'rooms' => $rooms],
    ]);
}

/* ================= booking creation ================= */

function action_book(array $in): void {
    $u = require_verified(); // server-side gate: unverified accounts cannot book
    $hotelId = (int) ($in['hotel_id'] ?? 0);
    $roomTypeId = (int) ($in['room_type_id'] ?? 0);
    $checkIn = require_date($in, 'check_in', 'check-in');
    $checkOut = require_date($in, 'check_out', 'check-out');

    if ($checkIn < date('Y-m-d')) {
        fail('Check-in date cannot be in the past.');
    }
    if ($checkOut <= $checkIn) {
        fail('Check-out must be after check-in.');
    }
    $nights = (int) round((strtotime($checkOut) - strtotime($checkIn)) / 86400);
    if ($nights < 1 || $nights > 30) {
        fail('Stays must be between 1 and 30 nights.');
    }
    $numRooms = max(1, min(10, (int) ($in['num_rooms'] ?? 1)));

    $st = db()->prepare("SELECT * FROM hotels WHERE id = ? AND status = 'published'");
    $st->execute([$hotelId]);
    $hotel = $st->fetch();
    if (!$hotel) {
        fail('Hotel not found.', 404);
    }
    $st = db()->prepare('SELECT * FROM room_types WHERE id = ? AND hotel_id = ?');
    $st->execute([$roomTypeId, $hotelId]);
    $roomType = $st->fetch();
    if (!$roomType) {
        fail('Please select a valid room type.', 422);
    }

    $guestsIn = arr_value($in, 'guests');
    if ($guestsIn === []) {
        $guestsIn = [[
            'name'  => $u['name'],
            'email' => $u['email'],
            'phone' => $u['phone'],
        ]];
    }
    if (count($guestsIn) > 10) {
        fail('A booking can include at most 10 guests.');
    }
    $guests = [];
    foreach ($guestsIn as $g) {
        $g = is_array($g) ? $g : [];
        $gName = trim((string) ($g['name'] ?? ''));
        $gEmail = trim(strtolower((string) ($g['email'] ?? '')));
        $gPhone = trim((string) ($g['phone'] ?? ''));
        if (mb_strlen($gName) < 2 || mb_strlen($gName) > 100) {
            fail('Each guest needs a valid name.');
        }
        if ($gEmail !== '' && !filter_var($gEmail, FILTER_VALIDATE_EMAIL)) {
            fail('Each guest email must be valid.');
        }
        if ($gPhone !== '' && !preg_match('/^[0-9+()\- ]{6,25}$/', $gPhone)) {
            fail('Each guest phone number must be valid.');
        }
        $guests[] = ['name' => $gName, 'email' => $gEmail, 'phone' => $gPhone];
    }
    $numGuests = count($guests);
    if (((int) $roomType['capacity']) * $numRooms < $numGuests) {
        fail('This room type does not sleep that many guests for the selected number of rooms.');
    }

    $method = pick_enum($in, 'payment_method', ['card', 'paypal', 'property'], 'property', 'payment method');
    $notes = opt_str($in, 'notes', 500);

    if (availability_for($roomTypeId, $checkIn, $checkOut) < $numRooms) {
        fail('Those dates are no longer available. Please choose another room or dates.', 409, ['code' => 'sold_out']);
    }

    $taxRate = (float) cfg('booking.tax_rate', 0.12);
    $serviceFee = (float) cfg('booking.service_fee', 15.00);
    $subtotal = round((float) $roomType['price_per_night'] * $nights * $numRooms, 2);
    $taxes = round($subtotal * $taxRate, 2);
    $total = round($subtotal + $taxes + $serviceFee, 2);
    $currency = (string) cfg('booking.currency', 'USD');
    $reference = 'BKF-' . strtoupper(bin2hex(random_bytes(4)));
    $status = $method === 'property' ? 'pending' : 'confirmed';

    $pdo = db();
    $pdo->beginTransaction();
    try {
        // re-check availability inside the transaction to avoid overselling
        if (availability_for($roomTypeId, $checkIn, $checkOut) < $numRooms) {
            $pdo->rollBack();
            fail('Those dates were just booked by someone else. Please try again.', 409, ['code' => 'sold_out']);
        }
        $st = $pdo->prepare(
            'INSERT INTO bookings (reference, user_id, hotel_id, room_type_id, check_in, check_out, nights,
                num_guests, num_rooms, guest_name, guest_email, guest_phone, subtotal, taxes, service_fee,
                total, currency, payment_method, status, notes)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        );
        $st->execute([
            $reference, (int) $u['id'], $hotelId, $roomTypeId, $checkIn, $checkOut, $nights,
            $numGuests, $numRooms, $guests[0]['name'], $guests[0]['email'] !== '' ? $guests[0]['email'] : $u['email'],
            $guests[0]['phone'], $subtotal, $taxes, $serviceFee, $total, $currency, $method, $status, $notes,
        ]);
        $bookingId = (int) $pdo->lastInsertId();

        $st = $pdo->prepare('INSERT INTO booking_guests (booking_id, name, email, phone, is_primary) VALUES (?,?,?,?,?)');
        foreach ($guests as $i => $g) {
            $st->execute([$bookingId, $g['name'], $g['email'], $g['phone'], $i === 0 ? 1 : 0]);
        }

        $st = $pdo->prepare('INSERT INTO payments (booking_id, method, amount, currency, status, transaction_ref) VALUES (?,?,?,?,?,?)');
        $st->execute([
            $bookingId,
            $method,
            $total,
            $currency,
            $method === 'property' ? 'pending' : 'paid', // mock settlement - no real gateway
            $method === 'property' ? '' : 'MOCK-' . strtoupper(bin2hex(random_bytes(4))),
        ]);
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        if ($ex instanceof PDOException && in_array($ex->getCode(), ['23000', '23505'], true)) {
            fail('That booking could not be saved because of conflicting data.', 409);
        }
        error_log('book failed: ' . $ex->getMessage());
        fail('We could not complete the booking. Please try again.', 500);
    }

    audit('booking.create', 'bookings', $bookingId, ['reference' => $reference, 'total' => $total]);
    ok([
        'message' => 'Booking confirmed. Your reference is ' . $reference . '.',
        'booking' => [
            'id'             => $bookingId,
            'reference'      => $reference,
            'hotel_name'     => $hotel['name'],
            'room_name'      => $roomType['name'],
            'check_in'       => $checkIn,
            'check_out'      => $checkOut,
            'nights'         => $nights,
            'num_guests'     => $numGuests,
            'num_rooms'      => $numRooms,
            'subtotal'       => $subtotal,
            'taxes'          => $taxes,
            'service_fee'    => $serviceFee,
            'total'          => $total,
            'currency'       => $currency,
            'payment_method' => $method,
            'status'         => $status,
        ],
    ]);
}

/* ================= admin: dashboard ================= */

function action_admin_dashboard(): void {
    $admin = require_admin();
    $users = [
        'total'   => (int) scalar("SELECT COUNT(*) FROM users WHERE type = 'customer'"),
        'active'  => (int) scalar("SELECT COUNT(*) FROM users WHERE type = 'customer' AND status = 'active'"),
        'blocked' => (int) scalar("SELECT COUNT(*) FROM users WHERE type = 'customer' AND status = 'blocked'"),
        'pending' => (int) scalar("SELECT COUNT(*) FROM users WHERE type = 'customer' AND status = 'pending'"),
    ];
    $hotels = [
        'total'     => (int) scalar('SELECT COUNT(*) FROM hotels'),
        'published' => (int) scalar("SELECT COUNT(*) FROM hotels WHERE status = 'published'"),
        'draft'     => (int) scalar("SELECT COUNT(*) FROM hotels WHERE status = 'draft'"),
    ];
    $bookings = [
        'total'     => (int) scalar('SELECT COUNT(*) FROM bookings'),
        'pending'   => (int) scalar("SELECT COUNT(*) FROM bookings WHERE status = 'pending'"),
        'confirmed' => (int) scalar("SELECT COUNT(*) FROM bookings WHERE status = 'confirmed'"),
        'completed' => (int) scalar("SELECT COUNT(*) FROM bookings WHERE status = 'completed'"),
        'cancelled' => (int) scalar("SELECT COUNT(*) FROM bookings WHERE status = 'cancelled'"),
    ];
    $revenue = [
        'paid'     => round(scalar("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status = 'paid'"), 2),
        'pending'  => round(scalar("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status = 'pending'"), 2),
        'average'  => round(scalar("SELECT COALESCE(AVG(total),0) FROM bookings WHERE status IN ('confirmed','completed')"), 2),
        'by_month' => [],
    ];
    $st = db()->query(
        "SELECT strftime('%Y-%m', created_at) AS month, ROUND(SUM(amount),2) AS amount
         FROM payments WHERE status = 'paid' GROUP BY month ORDER BY month DESC LIMIT 6"
    );
    $revenue['by_month'] = $st->fetchAll();

    $approvals = [
        'users'   => $users['pending'],
        'bookings'=> $bookings['pending'],
        'total'   => $users['pending'] + $bookings['pending'],
    ];

    $st = db()->query(
        "SELECT b.reference, b.total, b.status, b.check_in, b.check_out, b.created_at,
                u.name AS customer, h.name AS hotel
         FROM bookings b JOIN users u ON u.id = b.user_id JOIN hotels h ON h.id = b.hotel_id
         ORDER BY b.created_at DESC LIMIT 6"
    );
    $recentBookings = $st->fetchAll();

    $recentAudit = [];
    if (can($admin, 'audit.view')) {
        $st = db()->query('SELECT actor_label, action, entity, entity_id, created_at FROM audit_logs ORDER BY id DESC LIMIT 6');
        $recentAudit = $st->fetchAll();
    }

    ok([
        'users' => $users, 'hotels' => $hotels, 'bookings' => $bookings,
        'approvals' => $approvals, 'revenue' => $revenue,
        'recent_bookings' => $recentBookings, 'recent_audit' => $recentAudit,
    ]);
}

/* ================= admin: hotels ================= */

function action_admin_hotels(): void {
    $st = db()->query(
        "SELECT h.id, h.name, h.city, h.country, h.stars, h.rating, h.price_per_night, h.status, h.updated_at,
                (SELECT COUNT(*) FROM room_types r WHERE r.hotel_id = h.id) AS rooms,
                (SELECT COUNT(*) FROM hotel_images i WHERE i.hotel_id = h.id) AS images,
                (SELECT COUNT(*) FROM bookings b WHERE b.hotel_id = h.id) AS bookings,
                (SELECT i.url FROM hotel_images i WHERE i.hotel_id = h.id ORDER BY i.sort_order, i.id LIMIT 1) AS image
         FROM hotels h ORDER BY h.name"
    );
    ok(['hotels' => $st->fetchAll()]);
}

function action_admin_hotel(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $st = db()->prepare('SELECT * FROM hotels WHERE id = ?');
    $st->execute([$id]);
    $hotel = $st->fetch();
    if (!$hotel) {
        fail('Hotel not found.', 404);
    }
    $st = db()->prepare('SELECT id, url, alt, sort_order FROM hotel_images WHERE hotel_id = ? ORDER BY sort_order, id');
    $st->execute([$id]);
    $images = $st->fetchAll();
    $st = db()->prepare(
        'SELECT rt.*, (SELECT COUNT(*) FROM bookings b WHERE b.room_type_id = rt.id AND b.status IN (\'pending\',\'confirmed\')) AS booked
         FROM room_types rt WHERE rt.hotel_id = ? ORDER BY rt.price_per_night'
    );
    $st->execute([$id]);
    $rooms = $st->fetchAll();
    ok(['hotel' => $hotel, 'images' => $images, 'room_types' => $rooms]);
}

function action_admin_hotel_save(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $name = req_str($in, 'name', 'Hotel name', 2, 120);
    $city = req_str($in, 'city', 'City', 2, 80);
    $country = req_str($in, 'country', 'Country', 2, 80);
    $description = req_str($in, 'description', 'Description', 20, 4000);
    $stars = max(1, min(5, (int) ($in['stars'] ?? 3)));
    $rating = max(0, min(5, (float) ($in['rating'] ?? 4.5)));
    $status = pick_enum($in, 'status', ['draft', 'published'], 'draft', 'status');

    $amenities = [];
    foreach (arr_value($in, 'amenities') as $a) {
        $a = trim(is_string($a) ? $a : '');
        if ($a !== '' && mb_strlen($a) <= 60) {
            $amenities[] = $a;
        }
        if (count($amenities) >= 40) {
            break;
        }
    }
    $policies = [];
    foreach (arr_value($in, 'policies') as $p) {
        $p = trim(is_string($p) ? $p : '');
        if ($p !== '' && mb_strlen($p) <= 400) {
            $policies[] = $p;
        }
        if (count($policies) >= 25) {
            break;
        }
    }

    $images = [];
    foreach (arr_value($in, 'images') as $img) {
        if (is_array($img)) {
            $url = trim((string) ($img['url'] ?? ''));
            $alt = trim((string) ($img['alt'] ?? ''));
        } else {
            $url = trim((string) $img);
            $alt = '';
        }
        if ($url === '') {
            continue;
        }
        if (!preg_match('#^(https?://|/assets/|assets/)#i', $url)) {
            fail('Images must be an /assets/ path or an http(s) URL.');
        }
        $images[] = ['url' => $url, 'alt' => $alt !== '' ? mb_substr($alt, 0, 120) : $name];
        if (count($images) >= 10) {
            break;
        }
    }
    if ($images === []) {
        fail('Add at least one image.');
    }

    $roomsIn = arr_value($in, 'room_types');
    if ($roomsIn === []) {
        fail('Add at least one room type.');
    }
    $rooms = [];
    foreach ($roomsIn as $r) {
        $r = is_array($r) ? $r : [];
        $rName = trim((string) ($r['name'] ?? ''));
        if (mb_strlen($rName) < 2 || mb_strlen($rName) > 80) {
            fail('Each room type needs a name.');
        }
        $rooms[] = [
            'id'              => (int) ($r['id'] ?? 0),
            'name'            => $rName,
            'description'     => mb_substr(trim((string) ($r['description'] ?? '')), 0, 500),
            'capacity'        => max(1, min(20, (int) ($r['capacity'] ?? 2))),
            'total_rooms'     => max(0, min(1000, (int) ($r['total_rooms'] ?? 10))),
            'price_per_night' => round(max(0, min(100000, (float) ($r['price_per_night'] ?? 0))), 2),
        ];
    }

    $pdo = db();
    $pdo->beginTransaction();
    try {
        if ($id > 0) {
            $st = $pdo->prepare('SELECT id FROM hotels WHERE id = ?');
            $st->execute([$id]);
            if (!$st->fetch()) {
                $pdo->rollBack();
                fail('Hotel not found.', 404);
            }
            $st = $pdo->prepare(
                'UPDATE hotels SET name=?, slug=?, description=?, address=?, city=?, country=?, location_text=?,
                    stars=?, rating=?, amenities=?, policies=?, status=?, updated_at=? WHERE id=?'
            );
            $st->execute([
                $name, unique_slug($name, $id), $description, opt_str($in, 'address', 200), $city, $country,
                opt_str($in, 'location_text', 300), $stars, $rating,
                json_encode($amenities, JSON_UNESCAPED_UNICODE), json_encode($policies, JSON_UNESCAPED_UNICODE),
                $status, now_utc(), $id,
            ]);
        } else {
            $st = $pdo->prepare(
                'INSERT INTO hotels (name, slug, description, address, city, country, location_text,
                    stars, rating, amenities, policies, status)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
            );
            $st->execute([
                $name, unique_slug($name), $description, opt_str($in, 'address', 200), $city, $country,
                opt_str($in, 'location_text', 300), $stars, $rating,
                json_encode($amenities, JSON_UNESCAPED_UNICODE), json_encode($policies, JSON_UNESCAPED_UNICODE),
                $status,
            ]);
            $id = (int) $pdo->lastInsertId();
        }

        $pdo->prepare('DELETE FROM hotel_images WHERE hotel_id = ?')->execute([$id]);
        $st = $pdo->prepare('INSERT INTO hotel_images (hotel_id, url, alt, sort_order) VALUES (?,?,?,?)');
        foreach ($images as $i => $img) {
            $st->execute([$id, $img['url'], $img['alt'], $i]);
        }

        $keep = [];
        foreach ($rooms as $r) {
            $exists = false;
            if ($r['id'] > 0) {
                $st = $pdo->prepare('SELECT id FROM room_types WHERE id = ? AND hotel_id = ?');
                $st->execute([$r['id'], $id]);
                $exists = (bool) $st->fetch();
            }
            if ($exists) {
                $st = $pdo->prepare('UPDATE room_types SET name=?, description=?, capacity=?, total_rooms=?, price_per_night=? WHERE id=?');
                $st->execute([$r['name'], $r['description'], $r['capacity'], $r['total_rooms'], $r['price_per_night'], $r['id']]);
                $keep[] = (int) $r['id'];
            } else {
                $st = $pdo->prepare('INSERT INTO room_types (hotel_id, name, description, capacity, total_rooms, price_per_night) VALUES (?,?,?,?,?,?)');
                $st->execute([$id, $r['name'], $r['description'], $r['capacity'], $r['total_rooms'], $r['price_per_night']]);
                $newId = (int) $pdo->lastInsertId();
                $keep[] = $newId;
                seed_inventory($newId, $r['total_rooms']);
            }
        }
        // remove room types that were dropped from the form (but never those with bookings)
        $st = $pdo->prepare('SELECT id FROM room_types WHERE hotel_id = ?');
        $st->execute([$id]);
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $existingId) {
            $existingId = (int) $existingId;
            if (in_array($existingId, $keep, true)) {
                continue;
            }
            $has = $pdo->prepare('SELECT COUNT(*) FROM bookings WHERE room_type_id = ?');
            $has->execute([$existingId]);
            if ((int) $has->fetchColumn() === 0) {
                $pdo->prepare('DELETE FROM room_inventory WHERE room_type_id = ?')->execute([$existingId]);
                $pdo->prepare('DELETE FROM room_types WHERE id = ?')->execute([$existingId]);
            }
        }
        $pdo->prepare('UPDATE hotels SET price_per_night = (SELECT COALESCE(MIN(price_per_night),0) FROM room_types WHERE hotel_id = ?) WHERE id = ?')
            ->execute([$id, $id]);
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        if ($ex instanceof PDOException && $ex->getCode() === '23000') {
            fail('A hotel with that name/slug already exists.', 409);
        }
        error_log('hotel save failed: ' . $ex->getMessage());
        fail('Could not save the hotel.', 500);
    }

    audit($id > 0 ? 'hotel.update' : 'hotel.create', 'hotels', $id, ['name' => $name, 'status' => $status]);
    ok(['id' => $id, 'message' => 'Hotel saved.']);
}

function action_admin_hotel_status(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $status = pick_enum($in, 'status', ['draft', 'published'], 'draft', 'status');
    $st = db()->prepare('SELECT name, status FROM hotels WHERE id = ?');
    $st->execute([$id]);
    $hotel = $st->fetch();
    if (!$hotel) {
        fail('Hotel not found.', 404);
    }
    db()->prepare('UPDATE hotels SET status = ?, updated_at = ? WHERE id = ?')->execute([$status, now_utc(), $id]);
    audit('hotel.status', 'hotels', $id, ['from' => $hotel['status'], 'to' => $status, 'name' => $hotel['name']]);
    ok(['message' => $hotel['name'] . ($status === 'published' ? ' published.' : ' unpublished.')]);
}

function action_admin_hotel_delete(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $st = db()->prepare('SELECT name FROM hotels WHERE id = ?');
    $st->execute([$id]);
    $hotel = $st->fetch();
    if (!$hotel) {
        fail('Hotel not found.', 404);
    }
    $st = db()->prepare('SELECT COUNT(*) FROM bookings WHERE hotel_id = ?');
    $st->execute([$id]);
    $count = (int) $st->fetchColumn();
    if ($count > 0) {
        fail('This hotel has ' . $count . ' booking(s) and cannot be deleted. Unpublish it instead.', 409);
    }
    db()->prepare('DELETE FROM hotels WHERE id = ?')->execute([$id]);
    audit('hotel.delete', 'hotels', $id, ['name' => $hotel['name']]);
    ok(['message' => 'Hotel deleted.']);
}

/* ================= admin: bookings ================= */

function action_admin_bookings(array $in): void {
    $status = trim((string) ($in['status'] ?? ''));
    $q = trim((string) ($in['q'] ?? ''));
    $sql = "SELECT b.*, u.name AS customer, u.email AS customer_email, h.name AS hotel_name,
                   rt.name AS room_name,
                   (SELECT p.status FROM payments p WHERE p.booking_id = b.id LIMIT 1) AS payment_status
            FROM bookings b
            JOIN users u ON u.id = b.user_id
            JOIN hotels h ON h.id = b.hotel_id
            JOIN room_types rt ON rt.id = b.room_type_id";
    $where = [];
    $params = [];
    if (in_array($status, ['pending', 'confirmed', 'cancelled', 'completed'], true)) {
        $where[] = 'b.status = ?';
        $params[] = $status;
    }
    if ($q !== '') {
        $where[] = '(b.reference LIKE ? OR b.guest_name LIKE ? OR u.email LIKE ? OR h.name LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }
    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY b.created_at DESC LIMIT 300';
    $st = db()->prepare($sql);
    $st->execute($params);
    ok(['bookings' => $st->fetchAll()]);
}

function action_admin_booking_status(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $status = pick_enum($in, 'status', ['pending', 'confirmed', 'cancelled', 'completed'], 'pending', 'status');
    $st = db()->prepare('SELECT id, status, reference FROM bookings WHERE id = ?');
    $st->execute([$id]);
    $booking = $st->fetch();
    if (!$booking) {
        fail('Booking not found.', 404);
    }
    db()->prepare('UPDATE bookings SET status = ?, updated_at = ? WHERE id = ?')->execute([$status, now_utc(), $id]);
    if ($status === 'cancelled') {
        db()->prepare("UPDATE payments SET status = 'refunded' WHERE booking_id = ? AND status = 'paid'")->execute([$id]);
    }
    audit('booking.status', 'bookings', $id, ['reference' => $booking['reference'], 'from' => $booking['status'], 'to' => $status]);
    ok(['message' => 'Booking ' . $booking['reference'] . ' marked ' . $status . '.']);
}

/* ================= admin: customers ================= */

function action_admin_users(array $in): void {
    $status = trim((string) ($in['status'] ?? ''));
    $q = trim((string) ($in['q'] ?? ''));
    $sql = "SELECT u.id, u.name, u.email, u.phone, u.status, u.email_verified_at, u.country, u.city,
                   u.created_at,
                   (SELECT COUNT(*) FROM bookings b WHERE b.user_id = u.id) AS bookings
            FROM users u WHERE u.type = 'customer'";
    $where = [];
    $params = [];
    if (in_array($status, ['pending', 'active', 'blocked'], true)) {
        $where[] = 'u.status = ?';
        $params[] = $status;
    }
    if ($q !== '') {
        $where[] = '(u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like);
    }
    if ($where) {
        $sql .= ' AND ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY u.created_at DESC LIMIT 300';
    $st = db()->prepare($sql);
    $st->execute($params);
    ok(['users' => $st->fetchAll()]);
}

function action_admin_user_save(array $in): void {
    $id = (int) ($in['id'] ?? 0);
    $name = req_str($in, 'name', 'Full name', 2, 100);
    $email = email_value($in);
    $phone = opt_str($in, 'phone', 25);
    $status = pick_enum($in, 'status', ['pending', 'active', 'blocked'], 'active', 'status');
    $dob = trim((string) ($in['date_of_birth'] ?? ''));
    if ($dob !== '' && valid_date($dob) === null) {
        fail('Date of birth must be a valid date.');
    }
    $password = (string) ($in['password'] ?? '');

    $st = db()->prepare('SELECT id FROM users WHERE email = ? AND id != ?');
    $st->execute([$email, $id]);
    if ($st->fetch()) {
        fail('That email address is already in use.', 409);
    }

    if ($id === 0) {
        if ($password === '') {
            fail('A password is required for new accounts.');
        }
        $password = password_value($in);
        $st = db()->prepare(
            "INSERT INTO users (name, email, phone, password_hash, type, status, email_verified_at,
                country, city, address, date_of_birth, preferences)
             VALUES (?,?,?,?,'customer',?,?,?,?,?,?,?)"
        );
        $st->execute([
            $name, $email, $phone, password_hash($password, PASSWORD_DEFAULT), $status, now_utc(),
            opt_str($in, 'country', 80), opt_str($in, 'city', 80), opt_str($in, 'address', 200),
            $dob === '' ? null : $dob, opt_str($in, 'preferences', 400),
        ]);
        $id = (int) db()->lastInsertId();
        audit('user.create', 'users', $id, ['email' => $email, 'status' => $status]);
    } else {
        $st = db()->prepare("SELECT id, status FROM users WHERE id = ? AND type = 'customer'");
        $st->execute([$id]);
        if (!$st->fetch()) {
            fail('Customer not found.', 404);
        }
        $sql = 'UPDATE users SET name=?, email=?, phone=?, status=?, country=?, city=?, address=?, date_of_birth=?, preferences=?, updated_at=? WHERE id=?';
        $params = [
            $name, $email, $phone, $status, opt_str($in, 'country', 80), opt_str($in, 'city', 80),
            opt_str($in, 'address', 200), $dob === '' ? null : $dob, opt_str($in, 'preferences', 400),
            now_utc(), $id,
        ];
        if ($password !== '') {
            $password = password_value($in);
            array_splice($params, count($params) - 1, 0, [password_hash($password, PASSWORD_DEFAULT)]);
            $sql = 'UPDATE users SET name=?, email=?, phone=?, status=?, password_hash=?, country=?, city=?, address=?, date_of_birth=?, preferences=?, updated_at=? WHERE id=?';
        }
        db()->prepare($sql)->execute($params);
        audit('user.update', 'users', $id, ['email' => $email, 'status' => $status]);
    }
    ok(['id' => $id, 'message' => 'Customer saved.']);
}

function action_admin_user_status(array $in): void {
    $actor = require_admin();
    $id = (int) ($in['id'] ?? 0);
    $status = pick_enum($in, 'status', ['pending', 'active', 'blocked'], 'active', 'status');
    if ($id === (int) $actor['id']) {
        fail('You cannot change your own account status.', 403);
    }
    $st = db()->prepare("SELECT id, name, status FROM users WHERE id = ? AND type = 'customer'");
    $st->execute([$id]);
    $user = $st->fetch();
    if (!$user) {
        fail('Customer not found.', 404);
    }
    db()->prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?')->execute([$status, now_utc(), $id]);
    audit('user.status', 'users', $id, ['from' => $user['status'], 'to' => $status, 'name' => $user['name']]);
    ok(['message' => $user['name'] . ' is now ' . $status . '.']);
}

function action_admin_user_delete(array $in): void {
    $actor = require_admin();
    $id = (int) ($in['id'] ?? 0);
    if ($id === (int) $actor['id']) {
        fail('You cannot delete your own account.', 403);
    }
    $st = db()->prepare("SELECT id, name FROM users WHERE id = ? AND type = 'customer'");
    $st->execute([$id]);
    $user = $st->fetch();
    if (!$user) {
        fail('Customer not found.', 404);
    }
    $st = db()->prepare('SELECT COUNT(*) FROM bookings WHERE user_id = ?');
    $st->execute([$id]);
    $count = (int) $st->fetchColumn();
    if ($count > 0) {
        fail('This customer has ' . $count . ' booking(s) and cannot be deleted. Block the account instead.', 409);
    }
    db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
    audit('user.delete', 'users', $id, ['name' => $user['name']]);
    ok(['message' => 'Customer deleted.']);
}

/* ================= admin: sub-admins, roles, permissions ================= */

function action_admin_admins(): void {
    $st = db()->query(
        "SELECT u.id, u.name, u.email, u.username, u.phone, u.status, u.created_at,
                (SELECT GROUP_CONCAT(r.name, ',') FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id) AS role_names
         FROM users u WHERE u.type = 'admin' ORDER BY u.id"
    );
    $admins = array_map(static function (array $row): array {
        $row['roles'] = $row['role_names'] ? array_map('trim', explode(',', $row['role_names'])) : [];
        unset($row['role_names']);
        return $row;
    }, $st->fetchAll());
    ok(['admins' => $admins]);
}

function assert_admin_target(int $targetId, int $actorId): array {
    if ($targetId === $actorId) {
        fail('You cannot modify your own administrator account here.', 403);
    }
    $st = db()->prepare("SELECT id, name, status, email FROM users WHERE id = ? AND type = 'admin'");
    $st->execute([$targetId]);
    $target = $st->fetch();
    if (!$target) {
        fail('Administrator not found.', 404);
    }
    if (is_super_admin($targetId) && !is_super_admin($actorId)) {
        fail('Only a super administrator can modify the super-admin account.', 403);
    }
    return $target;
}

function normalize_role_names(array $in): array {
    $names = [];
    foreach (arr_value($in, 'roles') as $role) {
        $role = trim(is_string($role) ? $role : '');
        if ($role !== '') {
            $names[] = $role;
        }
    }
    if ($names === []) {
        fail('Select at least one role.');
    }
    $st = db()->prepare('SELECT name FROM roles ORDER BY name');
    $st->execute();
    $valid = $st->fetchAll(PDO::FETCH_COLUMN);
    foreach ($names as $name) {
        if (!in_array($name, $valid, true)) {
            fail('Unknown role: ' . $name);
        }
    }
    return array_values(array_unique($names));
}

function apply_roles(int $userId, array $roleNames): void {
    $pdo = db();
    $pdo->prepare('DELETE FROM user_roles WHERE user_id = ?')->execute([$userId]);
    $st = $pdo->prepare('SELECT id FROM roles WHERE name = ?');
    $insert = $pdo->prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?,?)');
    foreach ($roleNames as $name) {
        $st->execute([$name]);
        $insert->execute([$userId, (int) $st->fetchColumn()]);
    }
}

function guard_grant(int $actorId, array $roleNames): void {
    if (in_array('super_admin', $roleNames, true) && !is_super_admin($actorId)) {
        fail('Only a super administrator can grant the Super Admin role.', 403);
    }
    if (is_super_admin($actorId)) {
        return;
    }
    // a non-super actor may never grant permissions they do not hold themselves
    $actorPerms = perms_for($actorId);
    $st = db()->prepare(
        'SELECT p.code FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
         JOIN permissions p ON p.id = rp.permission_id JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_id = ?'
    );
    $st->execute([$actorId]);
    $granted = [];
    foreach ($roleNames as $name) {
        $stmt = db()->prepare('SELECT code FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id JOIN roles r ON r.id = rp.role_id WHERE r.name = ?');
        $stmt->execute([$name]);
        $granted = array_merge($granted, $stmt->fetchAll(PDO::FETCH_COLUMN));
    }
    foreach (array_unique($granted) as $code) {
        if (!in_array($code, $actorPerms, true)) {
            fail('You cannot grant a permission you do not have: ' . $code, 403);
        }
    }
}

function action_admin_admin_save(array $in): void {
    $actor = require_admin();
    $actorId = (int) $actor['id'];
    $id = (int) ($in['id'] ?? 0);
    $roleNames = normalize_role_names($in);

    $name = req_str($in, 'name', 'Full name', 2, 100);
    $email = email_value($in);
    $username = strtolower(req_str($in, 'username', 'Username', 3, 24));
    if (!preg_match('/^[a-z0-9_.]+$/', $username)) {
        fail('Username may only contain letters, numbers, dots and underscores.');
    }
    $status = pick_enum($in, 'status', ['active', 'blocked'], 'active', 'status');
    $password = (string) ($in['password'] ?? '');

    guard_grant($actorId, $roleNames);

    $st = db()->prepare('SELECT id FROM users WHERE (email = ? OR username = ?) AND id != ?');
    $st->execute([$email, $username, $id]);
    if ($st->fetch()) {
        fail('That email or username is already taken.', 409);
    }

    $pdo = db();
    $pdo->beginTransaction();
    try {
        if ($id === 0) {
            if ($password === '') {
                $pdo->rollBack();
                fail('A password is required for new administrators.');
            }
            $password = password_value($in);
            $st = $pdo->prepare(
                "INSERT INTO users (name, email, username, phone, password_hash, type, status, email_verified_at)
                 VALUES (?,?,?,?,?,'admin',?,?)"
            );
            $st->execute([$name, $email, $username, opt_str($in, 'phone', 25), password_hash($password, PASSWORD_DEFAULT), $status, now_utc()]);
            $id = (int) $pdo->lastInsertId();
        } else {
            assert_admin_target($id, $actorId);
            $sql = 'UPDATE users SET name=?, email=?, username=?, phone=?, status=?, updated_at=? WHERE id=?';
            $params = [$name, $email, $username, opt_str($in, 'phone', 25), $status, now_utc(), $id];
            if ($password !== '') {
                $password = password_value($in);
                $sql = 'UPDATE users SET name=?, email=?, username=?, phone=?, password_hash=?, status=?, updated_at=? WHERE id=?';
                array_splice($params, 4, 0, [password_hash($password, PASSWORD_DEFAULT)]);
            }
            $pdo->prepare($sql)->execute($params);
        }
        apply_roles($id, $roleNames);
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('admin save failed: ' . $ex->getMessage());
        fail('Could not save the administrator.', 500);
    }
    audit($id > 0 && $in['id'] ?? false ? 'admin.update' : 'admin.create', 'users', $id, ['email' => $email, 'roles' => $roleNames]);
    ok(['id' => $id, 'message' => 'Administrator saved.']);
}

function action_admin_admin_status(array $in): void {
    $actor = require_admin();
    $id = (int) ($in['id'] ?? 0);
    $status = pick_enum($in, 'status', ['active', 'blocked'], 'active', 'status');
    $target = assert_admin_target($id, (int) $actor['id']);
    db()->prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?')->execute([$status, now_utc(), $id]);
    audit('admin.status', 'users', $id, ['from' => $target['status'], 'to' => $status, 'email' => $target['email']]);
    ok(['message' => 'Administrator is now ' . $status . '.']);
}

function action_admin_admin_delete(array $in): void {
    $actor = require_admin();
    $id = (int) ($in['id'] ?? 0);
    $target = assert_admin_target($id, (int) $actor['id']);
    if (is_super_admin($id)) {
        fail('The super-admin account cannot be deleted.', 403);
    }
    db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
    audit('admin.delete', 'users', $id, ['email' => $target['email']]);
    ok(['message' => 'Administrator deleted.']);
}

function action_admin_admin_roles(array $in): void {
    $actor = require_admin();
    $id = (int) ($in['id'] ?? 0);
    $roleNames = normalize_role_names($in);
    $target = assert_admin_target($id, (int) $actor['id']);
    guard_grant((int) $actor['id'], $roleNames);
    apply_roles($id, $roleNames);
    audit('admin.roles', 'users', $id, ['email' => $target['email'], 'roles' => $roleNames]);
    ok(['message' => 'Roles updated.']);
}

function action_admin_roles(): void {
    $st = db()->query('SELECT id, code, description FROM permissions ORDER BY code');
    $permissions = $st->fetchAll();
    $st = db()->query(
        "SELECT r.id, r.name, r.description,
                (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id = r.id) AS members
         FROM roles r ORDER BY r.name"
    );
    $roles = $st->fetchAll();
    foreach ($roles as &$role) {
        $stmt = db()->prepare(
            'SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ? ORDER BY p.code'
        );
        $stmt->execute([(int) $role['id']]);
        $role['permissions'] = $stmt->fetchAll(PDO::FETCH_COLUMN);
    }
    unset($role);
    ok(['roles' => $roles, 'permissions' => $permissions]);
}

function action_admin_role_permissions(array $in): void {
    $actor = require_admin();
    $roleId = (int) ($in['role_id'] ?? 0);
    $st = db()->prepare('SELECT id, name FROM roles WHERE id = ?');
    $st->execute([$roleId]);
    $role = $st->fetch();
    if (!$role) {
        fail('Role not found.', 404);
    }
    if ($role['name'] === 'super_admin') {
        fail('The Super Admin role always holds every permission.', 403);
    }
    $codes = [];
    foreach (arr_value($in, 'permissions') as $code) {
        $code = trim(is_string($code) ? $code : '');
        if ($code !== '') {
            $codes[] = $code;
        }
    }
    $st = db()->query('SELECT code FROM permissions');
    $valid = $st->fetchAll(PDO::FETCH_COLUMN);
    foreach ($codes as $code) {
        if (!in_array($code, $valid, true)) {
            fail('Unknown permission: ' . $code);
        }
        if (!is_super_admin((int) $actor['id']) && !can($actor, $code)) {
            fail('You cannot grant a permission you do not have: ' . $code, 403);
        }
    }
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $pdo->prepare('DELETE FROM role_permissions WHERE role_id = ?')->execute([$roleId]);
        $lookup = $pdo->prepare('SELECT id FROM permissions WHERE code = ?');
        $insert = $pdo->prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?,?)');
        foreach (array_unique($codes) as $code) {
            $lookup->execute([$code]);
            $insert->execute([$roleId, (int) $lookup->fetchColumn()]);
        }
        $pdo->commit();
    } catch (Throwable $ex) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('role permissions failed: ' . $ex->getMessage());
        fail('Could not update role permissions.', 500);
    }
    audit('role.permissions', 'roles', $roleId, ['role' => $role['name'], 'permissions' => array_values(array_unique($codes))]);
    ok(['message' => 'Permissions updated for ' . $role['name'] . '.']);
}

/* ================= admin: audit log ================= */

function action_admin_audit(array $in): void {
    $entity = trim((string) ($in['entity'] ?? ''));
    $q = trim((string) ($in['q'] ?? ''));
    $sql = 'SELECT id, actor_label, action, entity, entity_id, detail, ip, created_at FROM audit_logs';
    $where = [];
    $params = [];
    if ($entity !== '') {
        $where[] = 'entity = ?';
        $params[] = $entity;
    }
    if ($q !== '') {
        $where[] = '(action LIKE ? OR actor_label LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like);
    }
    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }
    $sql .= ' ORDER BY id DESC LIMIT 200';
    $st = db()->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();
    foreach ($rows as &$row) {
        $row['detail'] = json_arr($row['detail']);
    }
    unset($row);
    ok(['logs' => $rows]);
}
