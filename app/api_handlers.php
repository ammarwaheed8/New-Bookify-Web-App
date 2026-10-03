<?php
declare(strict_types=1);

const AMENITY_LIST = [
    'wifi' => 'Free Wi-Fi', 'breakfast' => 'Breakfast', 'parking' => 'Parking',
    'pool' => 'Swimming pool', 'gym' => 'Fitness centre', 'spa' => 'Spa',
    'restaurant' => 'Restaurant', 'bar' => 'Bar', 'ac' => 'Air conditioning',
    'airport_shuttle' => 'Airport shuttle', 'pet_friendly' => 'Pet friendly',
    'family_rooms' => 'Family rooms', 'kitchen' => 'Kitchen', 'beach_access' => 'Beach access',
    'business_center' => 'Business centre',
];

function handle_api(string $action, string $method): void
{
    $routes = [
        // action => [method, handler, required permission|null]
        'bootstrap'           => ['GET',  'a_bootstrap', null],
        'register'            => ['POST', 'a_register', null],
        'login'               => ['POST', 'a_login', null],
        'logout'              => ['POST', 'a_logout', null],
        'me'                  => ['GET',  'a_me', null],
        'verify_email'        => ['POST', 'a_verify_email', null],
        'resend_verification' => ['POST', 'a_resend', null],
        'profile_update'      => ['POST', 'a_profile_update', null],
        'change_password'     => ['POST', 'a_change_password', null],
        'hotels'              => ['GET',  'a_hotels', null],
        'hotel'               => ['GET',  'a_hotel', null],
        'bookings'            => ['GET',  'a_my_bookings', null],
        'booking'             => ['GET',  'a_my_booking', null],
        'booking_create'      => ['POST', 'a_booking_create', null],
        'booking_cancel'      => ['POST', 'a_booking_cancel', null],
        // admin
        'admin_dashboard'  => ['GET',  'a_admin_dashboard', 'dashboard.view'],
        'admin_hotels'     => ['GET',  'a_admin_hotels', 'hotels.view'],
        'hotel_save'       => ['POST', 'a_hotel_save', 'hotels.manage'],
        'hotel_status'     => ['POST', 'a_hotel_status', 'hotels.manage'],
        'hotel_delete'     => ['POST', 'a_hotel_delete', 'hotels.manage'],
        'room_type_save'   => ['POST', 'a_room_type_save', 'rooms.manage'],
        'room_type_delete' => ['POST', 'a_room_type_delete', 'rooms.manage'],
        'inventory_save'   => ['POST', 'a_inventory_save', 'rooms.manage'],
        'admin_bookings'   => ['GET',  'a_admin_bookings', 'bookings.view'],
        'booking_status'   => ['POST', 'a_booking_status', 'bookings.manage'],
        'admin_users'      => ['GET',  'a_admin_users', 'users.view'],
        'user_save'        => ['POST', 'a_user_save', 'users.manage'],
        'user_status'      => ['POST', 'a_user_status', 'users.manage'],
        'user_delete'      => ['POST', 'a_user_delete', 'users.manage'],
        'admin_admins'     => ['GET',  'a_admin_admins', 'admins.view'],
        'admin_save'       => ['POST', 'a_admin_save', 'admins.manage'],
        'admin_delete'     => ['POST', 'a_admin_delete', 'admins.manage'],
        'roles'            => ['GET',  'a_roles', 'roles.manage'],
        'permissions'      => ['GET',  'a_permissions', 'roles.manage'],
        'audit_log'        => ['GET',  'a_audit', 'audit.view'],
    ];

    $route = $routes[$action] ?? null;
    if ($route === null) {
        json_err('Unknown action.', 404);
    }
    if ($method !== $route[0]) {
        json_err('Method not allowed.', 405);
    }
    if ($method !== 'GET') {
        csrf_check(); // every state-changing request is CSRF-checked
    }
    if ($route[2] !== null) {
        require_permission($route[2]); // server-side authorization
    }
    $fn = $route[1];
    $fn(read_input());
}

/* ================= public / account ================= */

function a_bootstrap(array $in): void
{
    json_out([
        'ok'          => true,
        'csrf'        => csrf_token(),
        'user'        => public_user(current_user()),
        'booking'     => config()['booking'],
        'amenities'   => AMENITY_LIST,
    ]);
}

function a_register(array $in): void
{
    $user = register_customer($in);
    json_out([
        'ok' => true,
        'user' => public_user($user),
        'message' => 'Account created. Check your email (or storage/mail.log locally) '
                   . 'for the verification link.',
    ], 201);
}

function a_login(array $in): void
{
    $identifier = f_str($in, 'identifier', 'Email or username', 3, 254);
    $password   = (string) ($in['password'] ?? '');
    if ($password === '') {
        fail('Password is required.', 422);
    }
    $user = attempt_login($identifier, $password);
    if ($user['type'] === 'customer' && !$user['email_verified_at']) {
        // allowed to sign in, but not to book — UI shows the banner
    }
    json_out(['ok' => true, 'user' => public_user($user)]);
}

function a_logout(array $in): void
{
    logout();
    json_out(['ok' => true, 'message' => 'Signed out.']);
}

function a_me(array $in): void
{
    json_out(['ok' => true, 'user' => public_user(current_user())]);
}

function a_verify_email(array $in): void
{
    $token = f_str($in, 'token', 'Token', 64, 64);
    json_out(['ok' => true, 'user' => verify_email_token($token),
              'message' => 'Email verified — you can now book.']);
}

function a_resend(array $in): void
{
    resend_verification(f_email($in));
}

function a_profile_update(array $in): void
{
    $user = update_profile($in);
    json_out(['ok' => true, 'user' => $user, 'message' => 'Profile updated.']);
}

function a_change_password(array $in): void
{
    change_password($in);
    json_out(['ok' => true, 'message' => 'Password changed.']);
}

/* ================= hotel search ================= */

function a_hotels(array $in): void
{
    $dest     = trim((string) ($in['destination'] ?? ''));
    $minP     = ($in['min_price'] ?? '') !== '' ? (float) $in['min_price'] : null;
    $maxP     = ($in['max_price'] ?? '') !== '')  !== false && ($in['max_price'] ?? '') !== '' ? (float) $in['max_price'] : null;
    $rating   = ($in['min_rating'] ?? '') !== '' ? (float) $in['min_rating'] : null;
    $guests   = ($in['guests'] ?? '') !== '' ? (int) $in['guests'] : null;
    $roomsNeed = ($in['rooms'] ?? '') !== '' ? max(1, (int) $in['rooms']) : 1;
    $checkIn  = ($in['check_in'] ?? '') !== '' ? valid_date((string) $in['check_in']) : null;
    $checkOut = ($in['check_out'] ?? '') !== '' ? valid_date((string) $in['check_out']) : null;
    if (($in['check_in'] ?? '') !== '' && !$checkIn) {
        fail('Check-in must use YYYY-MM-DD format.', 422);
    }
    if (($in['check_out'] ?? '') !== '' && !$checkOut) {
        fail('Check-out must use YYYY-MM-DD format.', 422);
    }
    $amen = array_values(array_filter(array_map('trim',
        explode(',', (string) ($in['amenities'] ?? '')))));
    $page  = max(1, (int) ($in['page'] ?? 1));
    $limit = min(50, max(1, (int) ($in['limit'] ?? 9)));
    $sortMap = [
        'price_asc'  => 'h.price_per_night ASC',
        'price_desc' => 'h.price_per_night DESC',
        'name'       => 'h.name ASC',
        'rating'     => 'h.rating DESC, h.reviews_count DESC',
    ];
    $order = $sortMap[$in['sort'] ?? ''] ?? $sortMap['rating'];

    $where  = ["h.status = 'published'"];
    $params = [];
    if ($dest !== '') {
        $where[] = '(h.city LIKE ? OR h.country LIKE ? OR h.name LIKE ? OR h.location_text LIKE ?)';
        $like = '%' . $dest . '%';
        array_push($params, $like, $like, $like, $like);
    }
    if ($minP !== null) { $where[] = 'h.price_per_night >= ?'; $params[] = $minP; }
    if ($maxP !== null) { $where[] = 'h.price_per_night <= ?'; $params[] = $maxP; }
    if ($rating !== null) { $where[] = 'h.rating >= ?'; $params[] = $rating; }
    if ($guests !== null) {
        $where[] = 'EXISTS (SELECT 1 FROM room_types rt WHERE rt.hotel_id = h.id AND rt.max_guests >= ? AND rt.total_rooms >= ?)';
        array_push($params, $guests, 1);
    }
    foreach ($amen as $a) {
        if (isset(AMENITY_LIST[$a])) {
            $where[] = 'h.amenities LIKE ?';
            $params[] = '%' . json_encode($a) . '%';
        }
    }
    if ($checkIn && $checkOut && $checkOut > $checkIn) {
        $where[] = 'EXISTS (SELECT 1 FROM room_types rt WHERE rt.hotel_id = h.id
                            AND (rt.total_rooms - COALESCE((
                                  SELECT SUM(b.rooms) FROM bookings b
                                   WHERE b.room_type_id = rt.id
                                     AND b.status IN (' . "'pending','confirmed'" . ')
                                     AND b.check_in < ? AND b.check_out > ?), 0)) >= ?)';
        array_push($params, $checkOut, $checkIn, $roomsNeed);
    }

    $whereSql = implode(' AND ', $where);
    $total = (int) scalar("SELECT COUNT(*) FROM hotels h WHERE $whereSql", $params);
    $rows = all(
        "SELECT h.id, h.name, h.slug, h.city, h.country, h.location_text, h.stars,
                h.rating, h.reviews_count, h.price_per_night, h.amenities, h.policies,
                (SELECT url FROM hotel_images hi WHERE hi.hotel_id = h.id
                  ORDER BY hi.is_primary DESC, hi.sort_order ASC, hi.id ASC LIMIT 1) AS image,
                (SELECT GROUP_CONCAT(rt.name, ' • ') FROM room_types rt
                  WHERE rt.hotel_id = h.id) AS room_type_names
           FROM hotels h
          WHERE $whereSql
          ORDER BY $order
          LIMIT ? OFFSET ?",
        array_merge($params, [$limit, ($page - 1) * $limit])
    );

    foreach ($rows as &$r) {
        $r['id'] = (int) $r['id'];
        $r['stars'] = (int) $r['stars'];
        $r['rating'] = (float) $r['rating'];
        $r['price_per_night'] = (float) $r['price_per_night'];
        $r['amenities'] = json_decode($r['amenities'] ?: '[]', true) ?: [];
        $r['policies']  = json_decode($r['policies'] ?: '[]', true) ?: [];
        $r['available_rooms'] = $checkIn && $checkOut
            ? hotel_availability((int) $r['id'], $checkIn, $checkOut, $roomsNeed)
            : null;
    }
    unset($r);

    json_out([
        'ok' => true, 'hotels' => $rows, 'total' => $total, 'page' => $page,
        'pages' => max(1, (int) ceil($total / $limit)),
    ]);
}

function hotel_availability(int $hotelId, string $checkIn, string $checkOut, int $need): int
{
    $sum = scalar(
        "SELECT COALESCE(SUM(rt.total_rooms - COALESCE((
              SELECT SUM(b.rooms) FROM bookings b
               WHERE b.room_type_id = rt.id AND b.status IN ('pending','confirmed')
                 AND b.check_in < ? AND b.check_out > ?), 0)), 0)
           FROM room_types rt WHERE rt.hotel_id = ?",
        [$checkOut, $checkIn, $hotelId]
    );
    return max(0, (int) $sum);
}

function rooms_available(int $roomTypeId, string $checkIn, string $checkOut): int
{
    $rt = one('SELECT total_rooms FROM room_types WHERE id = ?', [$roomTypeId]);
    if (!$rt) {
        fail('Room type not found.', 404);
    }
    $total = (int) $rt['total_rooms'];
    $inv = one('SELECT MIN(total_rooms) AS m FROM room_inventory
                 WHERE room_type_id = ? AND date >= ? AND date < ?',
               [$roomTypeId, $checkIn, $checkOut]);
    if ($inv && $inv['m'] !== null) {
        $total = min($total, (int) $inv['m']);
    }
    $booked = (int) scalar(
        "SELECT COALESCE(SUM(rooms), 0) FROM bookings
          WHERE room_type_id = ? AND status IN ('pending','confirmed')
            AND check_in < ? AND check_out > ?",
        [$roomTypeId, $checkOut, $checkIn]
    );
    return max(0, $total - $booked);
}

function a_hotel(array $in): void
{
    $hotel = null;
    if (($in['id'] ?? '') !== '') {
        $hotel = one("SELECT * FROM hotels WHERE id = ? AND status = 'published'",
                     [(int) $in['id']]);
    } elseif (($in['slug'] ?? '') !== '') {
        $hotel = one("SELECT * FROM hotels WHERE slug = ? AND status = 'published'",
                     [(string) $in['slug']]);
    }
    if (!$hotel) {
        json_err('Hotel not found.', 404);
    }
    $checkIn  = ($in['check_in'] ?? '') !== '' ? valid_date((string) $in['check_in']) : null;
    $checkOut = ($in['check_out'] ?? '') !== '' ? valid_date((string) $in['check_out']) : null;
    $hotelId  = (int) $hotel['id'];

    $images = all('SELECT id, url, alt, is_primary FROM hotel_images
                    WHERE hotel_id = ? ORDER BY is_primary DESC, sort_order ASC, id ASC', [$hotelId]);
    $roomTypes = all('SELECT * FROM room_types WHERE hotel_id = ? ORDER BY price_per_night ASC', [$hotelId]);
    foreach ($roomTypes as &$rt) {
        $rt['id'] = (int) $rt['id'];
        $rt['price_per_night'] = (float) $rt['price_per_night'];
        $rt['max_guests'] = (int) $rt['max_guests'];
        $rt['total_rooms'] = (int) $rt['total_rooms'];
        $rt['available'] = ($checkIn && $checkOut && $checkOut > $checkIn)
            ? rooms_available((int) $rt['id'], $checkIn, $checkOut)
            : (int) $rt['total_rooms'];
    }
    unset($rt);

    $hotel['id'] = (int) $hotel['id'];
    $hotel['stars'] = (int) $hotel['stars'];
    $hotel['rating'] = (float) $hotel['rating'];
    $hotel['price_per_night'] = (float) $hotel['price_per_night'];
    $hotel['amenities'] = json_decode($hotel['amenities'] ?: '[]', true) ?: [];
    $hotel['policies'] = json_decode($hotel['policies'] ?: '[]', true) ?: [];

    json_out([
        'ok' => true,
        'hotel' => $hotel,
        'images' => $images,
        'room_types' => $roomTypes,
        'reviews' => [], // placeholder — no review data yet
        'review_count' => (int) $hotel['reviews_count'],
    ]);
}

/* ================= bookings (customer) ================= */

function a_booking_create(array $in): void
{
    $user = require_verified(); // server-side gate: unverified users cannot book

    $hotelId    = f_int($in, 'hotel_id', 'Hotel', 1, PHP_INT_MAX);
    $roomTypeId = f_int($in, 'room_type_id', 'Room type', 1, PHP_INT_MAX);
    $checkIn    = f_date($in, 'check_in', 'Check-in');
    $checkOut   = f_date($in, 'check_out', 'Check-out');
    $rooms      = f_int($in, 'rooms', 'Rooms', 1, 10, true, 1);
    $adults     = f_int($in, 'adults', 'Adults', 1, 20, true, 1);
    $children   = f_int($in, 'children', 'Children', 0, 10, true, 0);
    $payment    = f_enum($in, 'payment_method', 'Payment method', ['card', 'paypal', 'property']);
    $gName      = f_str($in, 'guest_name', 'Guest name', 2, 100);
    $gEmail     = f_email($in, 'guest_email', 'Guest email');
    $gPhone     = f_str($in, 'guest_phone', 'Guest phone', 5, 30);
    $notes      = f_opt($in, 'special_requests', 'Special requests', 500);

    if ($checkIn < date('Y-m-d')) {
        fail('Check-in date cannot be in the past.', 422);
    }
    $nights = (int) round((strtotime($checkOut) - strtotime($checkIn)) / 86400);
    if ($nights < 1) {
        fail('Check-out must be after check-in.', 422);
    }
    if ($nights > 60) {
        fail('Stays longer than 60 nights are not supported.', 422);
    }

    $hotel = one("SELECT id, name FROM hotels WHERE id = ? AND status = 'published'", [$hotelId]);
    if (!$hotel) {
        json_err('Hotel not found or unavailable.', 404);
    }
    $rt = one('SELECT id, hotel_id, name, price_per_night, max_guests FROM room_types WHERE id = ?', [$roomTypeId]);
    if (!$rt || (int) $rt['hotel_id'] !== $hotelId) {
        fail('Invalid room type for this hotel.', 422);
    }
    $capacity = (int) $rt['max_guests'] * $rooms;
    if ($adults + $children > $capacity) {
        fail("This room choice sleeps at most $capacity guest(s).", 422);
    }

    $cfg  = config()['booking'];
    $taxRate = (float) $cfg['tax_rate'];
    $fee     = (float) $cfg['service_fee'];
    $symbol  = (string) $cfg['symbol'];

    $booking = tx(function () use ($roomTypeId, $checkIn, $checkOut, $rooms, $nights,
                                   $adults, $children, $payment, $gName, $gEmail, $gPhone,
                                   $notes, $hotelId, $rt, $user, $taxRate, $fee) {
        if (rooms_available($roomTypeId, $checkIn, $checkOut) < $rooms) {
            fail('Not enough rooms available for these dates.', 409);
        }
        $subtotal = round((float) $rt['price_per_night'] * $nights * $rooms, 2);
        $taxes    = round($subtotal * $taxRate, 2);
        $total    = round($subtotal + $taxes + $fee, 2);

        do {
            $reference = 'BK-' . strtoupper(bin2hex(random_bytes(5)));
        } while (one('SELECT id FROM bookings WHERE reference = ?', [$reference]));

        $status = $payment === 'property' ? 'pending' : 'confirmed';
        $bookingId = insert_row(
            "INSERT INTO bookings (reference, user_id, hotel_id, room_type_id, check_in, check_out,
                   nights, rooms, adults, children, guest_name, guest_email, guest_phone,
                   special_requests, subtotal, taxes, fees, total_price, currency,
                   status, payment_method, created_at, updated_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now'), datetime('now'))",
            [$reference, $user['id'], $hotelId, $roomTypeId, $checkIn, $checkOut,
             $nights, $rooms, $adults, $children, $gName, $gEmail, $gPhone,
             $notes, $subtotal, $taxes, $fee, $total, $cfg = config()['booking']['currency'],
             $status, $payment]
        );
        insert_row(
            "INSERT INTO booking_guests (booking_id, name, email, phone, created_at)
             VALUES (?,?,?,?, datetime('now'))",
            [$bookingId, $gName, $gEmail, $gPhone]
        );
        insert_row(
            "INSERT INTO payments (booking_id, method, amount, currency, status, created_at)
             VALUES (?,?,?,?,?, datetime('now'))",
            [$bookingId, $payment, $total, config()['booking']['currency'],
             $payment === 'property' ? 'due' : 'mock_paid']
        );
        return [
            'id' => $bookingId, 'reference' => $reference, 'status' => $status,
            'hotel' => $hotelName = $rt['name'], 'room_type' => $rt['name'],
            'check_in' => $checkIn, 'check_out' => $checkOut, 'nights' => $nights,
            'rooms' => $rooms, 'adults' => $adults, 'children' => $children,
            'subtotal' => $subtotal, 'taxes' => $taxes, 'fees' => $fee,
            'total_price' => $total, 'currency' => config()['booking']['currency'],
            'symbol' => config()['booking']['symbol'], 'payment_method' => $payment,
        ];
    });

    audit('booking.create', 'bookings', (int) $booking['id'], 'Reference ' . $booking['reference']);
    json_out(['ok' => true, 'booking' => $booking,
              'message' => 'Booking ' . $booking['reference'] . ' confirmed.'], 201);
}

function a_my_bookings(array $in): void
{
    $u = require_login();
    $rows = all(
        "SELECT b.*, h.name AS hotel_name, h.city AS city, rt.name AS room_type
           FROM bookings b
           JOIN hotels h ON h.id = b.hotel_id
           LEFT JOIN room_types rt ON rt.id = b.room_type_id
          WHERE b.user_id = ? ORDER BY b.created_at DESC",
        [$u['id']]
    );
    foreach ($rows as &$b) {
        $b['id'] = (int) $b['id'];
        $b['total_price'] = (float) $b['total_price'];
    }
    unset($b);
    json_out(['ok' => true, 'bookings' => $rows]);
}

function a_my_booking(array $in): void
{
    $u = require_login();
    $id = f_int($in, 'id', 'Booking', 1, PHP_INT_MAX);
    $b = one(
        "SELECT b.*, h.name AS hotel_name, h.city, h.country, h.address, rt.name AS room_type
           FROM bookings b JOIN hotels h ON h.id = b.hotel_id
           LEFT JOIN room_types rt ON rt.id = b.room_type_id
          WHERE b.id = ? AND b.user_id = ?",
        [$id, $u['id']]
    );
    if (!$b) {
        json_err('Booking not found.', 404);
    }
    $guests = all('SELECT name, email, phone FROM booking_guests WHERE booking_id = ?', [$id]);
    $pay = one('SELECT method, amount, currency, status, created_at FROM payments WHERE booking_id = ?', [$id]);
    json_out(['ok' => true, 'booking' => $b, 'guests' => $guests, 'payment' => $pay]);
}

function a_booking_cancel(array $in): void
{
    $u = require_login();
    $id = f_int($in, 'id', 'Booking', 1, PHP_INT_MAX);
    $b = one('SELECT * FROM bookings WHERE id = ? AND user_id = ?', [$id, $u['id']]);
    if (!$b) {
        json_err('Booking not found.', 404);
    }
    if (!in_array($b['status'], ['pending', 'confirmed'], true)) {
        fail('This booking can no longer be cancelled.', 409);
    }
    if ($b['check_in'] <= date('Y-m-d')) {
        fail('Bookings can only be cancelled before the check-in date.', 409);
    }
    tx(function () use ($id) {
        q("UPDATE bookings SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?", [$id]);
        q("UPDATE payments SET status = 'refunded_mock' WHERE booking_id = ? AND status = 'mock_paid'", [$id]);
    });
    audit('booking.cancel', 'bookings', $id, 'Cancelled by customer');
    json_out(['ok' => true, 'message' => 'Booking cancelled.']);
}

/* ================= admin ================= */

function a_admin_dashboard(array $in): void
{
    $statusBreakdown = [];
    foreach (all('SELECT status, COUNT(*) c FROM bookings GROUP BY status') as $r) {
        $statusBreakdown[$r['status']] = (int) $r['c'];
    }
    $pendingUsers = (int) scalar("SELECT COUNT(*) FROM users WHERE type = 'customer' AND status = 'pending'");
    $pendingBookings = (int) ($statusBreakdown['pending'] ?? 0);

    json_out(['ok' => true, 'metrics' => [
        'total_users'      => (int) scalar('SELECT COUNT(*) FROM users'),
        'active_users'     => (int) scalar("SELECT COUNT(*) FROM users WHERE status = 'active'"),
        'blocked_users'    => (int) scalar("SELECT COUNT(*) FROM users WHERE status = 'blocked'"),
        'hotels'           => (int) scalar('SELECT COUNT(*) FROM hotels'),
        'published_hotels' => (int) scalar("SELECT COUNT(*) FROM hotels WHERE status = 'published'"),
        'bookings'         => (int) scalar('SELECT COUNT(*) FROM bookings'),
        'booking_statuses' => $statusBreakdown,
        'pending_approvals'=> $pendingUsers + $pendingBookings,
        'pending_users'    => $pendingUsers,
        'pending_bookings' => $pendingBookings,
        'revenue'          => (float) (scalar(
            "SELECT COALESCE(SUM(total_price), 0) FROM bookings
              WHERE status IN ('confirmed','completed')") ?: 0),
        'currency'         => config()['booking']['symbol'],
    ]]);
}

function a_admin_hotels(array $in): void
{
    $q = trim((string) ($in['q'] ?? ''));
    $where = '1=1';
    $params = [];
    if ($q !== '') {
        $where = '(h.name LIKE ? OR h.city LIKE ? OR h.country LIKE ?)';
        $like = '%' . $q . '%';
        $params = [$like, $like, $like];
    }
    $rows = all(
        "SELECT h.*,
                (SELECT COUNT(*) FROM room_types rt WHERE rt.hotel_id = h.id) AS room_type_count,
                (SELECT COUNT(*) FROM hotel_images hi WHERE hi.hotel_id = h.id) AS image_count
           FROM hotels h WHERE $where ORDER BY h.updated_at DESC",
        $params
    );
    foreach ($rows as &$h) {
        $h['id'] = (int) $h['id'];
        $h['amenities'] = json_decode($h['amenities'] ?: '[]', true) ?: [];
        $h['policies'] = json_decode($h['policies'] ?: '[]', true) ?: [];
    }
    unset($h);
    json_out(['ok' => true, 'hotels' => $rows]);
}

function slugify(string $s): string
{
    $s = strtolower(trim(preg_replace('/[^a-z0-9]+/i', '-', $s), '-'));
    return $s !== '' ? $s : 'hotel';
}

function a_hotel_save(array $in): void
{
    $id       = ($in['id'] ?? '') !== '' ? (int) $in['id'] : null;
    $name     = f_str($in, 'name', 'Hotel name', 2, 150);
    $city     = f_str($in, 'city', 'City', 2, 100);
    $country  = f_str($in, 'country', 'Country', 2, 100);
    $address  = f_opt($in, 'address', 'Address', 255);
    $locText  = f_opt($in, 'location_text', 'Map/location text', 255);
    $desc     = f_str($in, 'description', 'Description', 20, 5000);
    $stars    = f_int($in, 'stars', 'Star rating', 1, 5, true, 3);
    $rating   = min(5.0, max(0.0, (float) ($in['rating'] ?? 4.5)));
    $price    = (float) f_str($in, 'price_per_night', 'Price per night', 1, 12);
    if ($price <= 0) {
        fail('Price per night must be greater than zero.', 422);
    }
    $status   = in_array($in['status'] ?? 'draft', ['draft', 'published'], true) ? $in['status'] : 'draft';
    $amenities = array_values(array_intersect(f_list($in, 'amenities', 'Amenities'), array_keys(AMENITY_LIST)));
    $policies  = array_slice(array_map('strval', f_list($in, 'policies', 'Policies')), 0, 20);
    $images    = f_list($in, 'images', 'Images');
    if (count($images) > 12) {
        fail('A hotel can have at most 12 images.', 422);
    }
    foreach ($images as $img) {
        if (!is_string($img) || strlen($img) > 500
            || !preg_match('#^(https?://|/assets/)#i', $img)) {
            fail('Images must be http(s) URLs or local /assets/ paths.', 422);
        }
    }

    $slug = slugify($name);
    tx(function () use ($id, $name, $slug, $city, $country, $address, $locText, $desc,
                        $stars, $rating, $price, $status, $amenities, $policies, $images) {
        if ($id) {
            $existing = one('SELECT id, slug FROM hotels WHERE id = ?', [$id]);
            if (!$existing) {
                json_err('Hotel not found.', 404);
            }
            $slug = $existing['slug'];
            q("UPDATE hotels SET name=?, city=?, country=?, address=?, location_text=?,
                      description=?, stars=?, rating=?, price_per_night=?, amenities=?,
                      policies=?, status=?, updated_at=datetime('now') WHERE id=?",
              [$name, $city, $country, $address, $locText, $desc, $stars, $rating,
               $price, json_encode($amenities), json_encode($policies), $status, $id]);
        } else {
            if (one('SELECT id FROM hotels WHERE slug = ?', [$slug])) {
                $slug .= '-' . random_int(100, 999);
            }
            $id = insert_row(
                "INSERT INTO hotels (name, slug, city, country, address, location_text, description,
                       stars, rating, reviews_count, price_per_night, amenities, policies, status,
                       created_at, updated_at)
                 VALUES (?,?,?,?,?,?,?,?,?,0,?,?,?,?, datetime('now'), datetime('now'))",
              [$name, $slug, $city, $country, $address, $locText, $desc, $stars, $rating,
               $price, json_encode($amenities), json_encode($policies), $status]
            );
        }
        // replace image set
        q('DELETE FROM hotel_images WHERE hotel_id = ?', [$id]);
        foreach (array_values($images) as $i => $url) {
            insert_row(
                "INSERT INTO hotel_images (hotel_id, url, alt, is_primary, sort_order, created_at)
                 VALUES (?,?,?,?,?, datetime('now'))",
                [$id, $url, $name . ' photo ' . ($i + 1), $i === 0 ? 1 : 0, $i]
            );
        }
        return $id;
    });
    audit('hotel.save', 'hotels', $id, 'Saved: ' . $name);
    json_out(['ok' => true, 'id' => $id, 'message' => 'Hotel saved.']);
}

function a_hotel_status(array $in): void
{
    $id     = f_int($in, 'id', 'Hotel', 1, PHP_INT_MAX);
    $status = f_enum($in, 'status', 'Status', ['draft', 'published']);
    if (!one('SELECT id FROM hotels WHERE id = ?', [$id])) {
        json_err('Hotel not found.', 404);
    }
    q("UPDATE hotels SET status = ?, updated_at = datetime('now') WHERE id = ?", [$status, $id]);
    audit('hotel.status', 'hotels', $id, 'Status → ' . $status);
    json_out(['ok' => true, 'message' => 'Hotel ' . ($status === 'published' ? 'published' : 'unpublished') . '.']);
}

function a_hotel_delete(array $in): void
{
    $id = f_int($in, 'id', 'Hotel', 1, PHP_INT_MAX);
    if (!one('SELECT id FROM hotels WHERE id = ?', [$id])) {
        json_err('Hotel not found.', 404);
    }
    $bookings = (int) scalar('SELECT COUNT(*) FROM bookings WHERE hotel_id = ?', [$id]);
    if ($bookings > 0) {
        fail("Cannot delete: $bookings booking(s) reference this hotel. Unpublish it instead.", 409);
    }
    tx(function () use ($id) {
        q('DELETE FROM hotel_images WHERE hotel_id = ?', [$id]);
        q('DELETE FROM room_inventory WHERE room_type_id IN (SELECT id FROM room_types WHERE hotel_id = ?)', [$id]);
        q('DELETE FROM room_types WHERE hotel_id = ?', [$id]);
        q('DELETE FROM hotels WHERE id = ?', [$id]);
    });
    audit('hotel.delete', 'hotels', $id, 'Hotel deleted');
    json_out(['ok' => true, 'message' => 'Hotel deleted.']);
}

function a_room_type_save(array $in): void
{
    $hotelId = f_int($in, 'hotel_id', 'Hotel', 1, PHP_INT_MAX);
    $id      = ($in['id'] ?? '') !== '' ? (int) $in['id'] : null;
    if (!one('SELECT id FROM hotels WHERE id = ?', [$hotelId])) {
        json_err('Hotel not found.', 404);
    }
    $name    = f_str($in, 'name', 'Room name', 2, 100);
    $desc    = f_opt($in, 'description', 'Description', 1000);
    $max     = f_int($in, 'max_guests', 'Max guests', 1, 20, true, 2);
    $price   = (float) f_str($in, 'price_per_night', 'Price per night', 1, 12);
    $total   = f_int($in, 'total_rooms', 'Total rooms', 0, 1000, true, 1);
    if ($price <= 0) {
        fail('Price per night must be greater than zero.', 422);
    }
    if ($id) {
        $ok = q('UPDATE room_types SET name=?, description=?, max_guests=?, price_per_night=?,
                        total_rooms=? WHERE id=? AND hotel_id=?',
                [$name, $desc, $max, $price, $total, $id, $hotelId]);
        if ($ok->rowCount() === 0 && !one('SELECT id FROM room_types WHERE id = ? AND hotel_id = ?', [$id, $hotelId])) {
            json_err('Room type not found.', 404);
        }
    } else {
        $id = insert_row(
            'INSERT INTO room_types (hotel_id, name, description, max_guests, price_per_night,
                    total_rooms, created_at) VALUES (?,?,?,?,?,?, datetime(\'now\'))',
            [$hotelId, $name, $desc, $max, $price, $total]
        );
    }
    audit('room_type.save', 'room_types', $id, $name);
    json_out(['ok' => true, 'id' => $id, 'message' => 'Room type saved.']);
}

function a_room_type_delete(array $in): void
{
    $id = f_int($in, 'id', 'Room type', 1, PHP_INT_MAX);
    if (!one('SELECT id FROM room_types WHERE id = ?', [$id])) {
        json_err('Room type not found.', 404);
    }
    $bookings = (int) scalar('SELECT COUNT(*) FROM bookings WHERE room_type_id = ?', [$id]);
    if ($bookings > 0) {
        fail("Cannot delete: $bookings booking(s) use this room type.", 409);
    }
    tx(function () use ($id) {
        q('DELETE FROM room_inventory WHERE room_type_id = ?', [$id]);
        q('DELETE FROM room_types WHERE id = ?', [$id]);
    });
    audit('room_type.delete', 'room_types', $id, 'Deleted');
    json_out(['ok' => true, 'message' => 'Room type deleted.']);
}

function a_inventory_save(array $in): void
{
    $roomTypeId = f_int($in, 'room_type_id', 'Room type', 1, PHP_INT_MAX);
    if (!one('SELECT id FROM room_types WHERE id = ?', [$roomTypeId])) {
        json_err('Room type not found.', 404);
    }
    $rows = f_list($in, 'rows', 'Inventory rows', true);
    if (!$rows) {
        fail('No inventory rows supplied.', 422);
    }
    $today = date('Y-m-d');
    $limit = date('Y-m-d', strtotime('+365 days'));
    tx(function () use ($rows, $roomTypeId, $today, $limit) {
        foreach ($rows as $row) {
            if (!is_array($row)) {
                fail('Invalid inventory row.', 422);
            }
            $date  = valid_date((string) ($row['date'] ?? '')) ?? fail('Inventory date must be YYYY-MM-DD.', 422);
            $count = (int) ($row['total_rooms'] ?? -1);
            if ($date < $today || $date > $limit || $count < 0 || $count > 1000) {
                fail('Inventory rows need a date within the next year and 0–1000 rooms.', 422);
            }
            q('INSERT INTO room_inventory (room_type_id, date, total_rooms, created_at)
               VALUES (?,?,?, datetime(\'now\'))
               ON CONFLICT(room_type_id, date) DO UPDATE SET total_rooms = excluded.total_rooms',
              [$roomTypeId, $date, $count]);
        }
    });
    audit('inventory.save', 'room_types', $roomTypeId, count($rows) . ' date(s) updated');
    json_out(['ok' => true, 'message' => 'Inventory updated.']);
}

function a_admin_bookings(array $in): void
{
    $status = ($in['status'] ?? '') !== '' && $in['status'] !== 'all'
        ? f_enum($in, 'status', 'Status', ['pending', 'confirmed', 'cancelled', 'completed']) : null;
    $q = trim((string) ($in['q'] ?? ''));
    $page  = max(1, (int) ($in['page'] ?? 1));
    $limit = min(100, max(1, (int) ($in['limit'] ?? 20)));

    $where = '1=1';
    $params = [];
    if ($status) { $where .= ' AND b.status = ?'; $params[] = $status; }
    if ($q !== '') {
        $where .= ' AND (b.reference LIKE ? OR b.guest_name LIKE ? OR b.guest_email LIKE ? OR h.name LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like, $like);
    }
    $total = (int) scalar("SELECT COUNT(*) FROM bookings b JOIN hotels h ON h.id = b.hotel_id WHERE $where", $params);
    $rows = all(
        "SELECT b.*, h.name AS hotel_name, u.name AS customer_name, u.email AS customer_email
           FROM bookings b
           JOIN hotels h ON h.id = b.hotel_id
           LEFT JOIN users u ON u.id = b.user_id
          WHERE $where ORDER BY b.created_at DESC LIMIT ? OFFSET ?",
        array_merge($params, [$limit, ($page - 1) * $limit])
    );
    json_out(['ok' => true, 'bookings' => $rows, 'total' => $total, 'page' => $page,
              'pages' => max(1, (int) ceil($total / $limit))]);
}

function a_booking_status(array $in): void
{
    $id     = f_int($in, 'id', 'Booking', 1, PHP_INT_MAX);
    $status = f_enum($in, 'status', 'Status', ['pending', 'confirmed', 'cancelled', 'completed']);
    if (!one('SELECT id, reference FROM bookings WHERE id = ?', [$id])) {
        json_err('Booking not found.', 404);
    }
    q("UPDATE bookings SET status = ?, updated_at = datetime('now') WHERE id = ?", [$status, $id]);
    if ($status === 'cancelled') {
        q("UPDATE payments SET status = 'refunded_mock' WHERE booking_id = ? AND status = 'mock_paid'", [$id]);
    }
    audit('booking.status', 'bookings', $id, 'Status → ' . $status);
    json_out(['ok' => true, 'message' => 'Booking status updated.']);
}

function a_admin_users(array $in): void
{
    $status = ($in['status'] ?? '') !== '' && $in['status'] !== 'all'
        ? f_enum($in, 'status', 'Status', ['pending', 'active', 'blocked']) : null;
    $q = trim((string) ($in['q'] ?? ''));
    $page  = max(1, (int) ($in['page'] ?? 1));
    $limit = min(100, max(1, (int) ($in['limit'] ?? 20)));

    $where = "type = 'customer'";
    $params = [];
    if ($status) { $where .= ' AND status = ?'; $params[] = $status; }
    if ($q !== '') {
        $where .= ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)';
        $like = '%' . $q . '%';
        array_push($params, $like, $like, $like);
    }
    $total = (int) scalar("SELECT COUNT(*) FROM users WHERE $where", $params);
    $rows = all(
        "SELECT id, name, email, username, phone, status, email_verified_at, country, city,
                created_at,
                (SELECT COUNT(*) FROM bookings b WHERE b.user_id = users.id) AS booking_count
           FROM users WHERE $where ORDER BY created_at DESC LIMIT ? OFFSET ?",
        array_merge($params, [$limit, ($page - 1) * $limit])
    );
    json_out(['ok' => true, 'users' => $rows, 'total' => $total, 'page' => $page,
              'pages' => max(1, (int) ceil($total / $limit))]);
}

function a_user_save(array $in): void
{
    $id    = ($in['id'] ?? '') !== '' ? (int) $in['id'] : null;
    $name  = f_str($in, 'name', 'Full name', 2, 100);
    $email = f_email($in);
    $phone = f_str($in, 'phone', 'Phone', 5, 30, false);
    $status = in_array($in['status'] ?? 'active', ['pending', 'active', 'blocked'], true)
        ? $in['status'] : 'active';

    $dup = one('SELECT id FROM users WHERE email = ? COLLATE NOCASE' . ($id ? ' AND id != ?' : ''),
               $id ? [$email, $id] : [$email]);
    if ($dup) {
        fail('An account with this email already exists.', 409);
    }

    if ($id) {
        $target = one("SELECT id, type FROM users WHERE id = ?", [$id]);
        if (!$target || $target['type'] !== 'customer') {
            json_err('Customer not found.', 404);
        }
        $sql = "UPDATE users SET name=?, email=?, phone=?, status=?, updated_at=datetime('now')";
        $params = [$name, $email, $phone, $status];
        if (($in['password'] ?? '') !== '') {
            $sql .= ', password_hash = ?';
            $params[] = password_hash(f_password($in), PASSWORD_DEFAULT);
        }
        $sql .= ' WHERE id = ?';
        $params[] = $id;
        q($sql, $params);
    } else {
        $id = insert_row(
            "INSERT INTO users (name, email, phone, password_hash, type, status, email_verified_at,
                    created_at, updated_at)
             VALUES (?,?,?,?, 'customer', ?, datetime('now'), datetime('now'), datetime('now'))",
            [$name, $email, $phone, password_hash(f_password($in), PASSWORD_DEFAULT), $status]
        );
    }
    audit('user.save', 'users', $id, ($email) . ' → ' . $status);
    json_out(['ok' => true, 'id' => $id, 'message' => 'Account saved.']);
}

function a_user_status(array $in): void
{
    $actor  = require_permission('users.manage');
    $id     = f_int($in, 'id', 'User', 1, PHP_INT_MAX);
    $status = f_enum($in, 'status', 'Status', ['pending', 'active', 'blocked']);
    $target = one("SELECT id, name, email, type, status FROM users WHERE id = ? AND type = 'customer'", [$id]);
    if (!$target) {
        json_err('Customer not found.', 404);
    }
    if ((int) $actor['id'] === $id) {
        fail('You cannot change your own account status.', 403);
    }
    q("UPDATE users SET status = ?, updated_at = datetime('now') WHERE id = ?", [$status, $id]);
    audit('user.status', 'users', $id, $target['email'] . ' → ' . $status);
    json_out(['ok' => true, 'message' => 'Account ' . $status . '.']);
}

function a_user_delete(array $in): void
{
    $actor = require_permission('users.manage');
    $id = f_int($in, 'id', 'User', 1, PHP_INT_MAX);
    if ((int) $actor['id'] === $id) {
        fail('You cannot delete your own account.', 403);
    }
    $target = one("SELECT id, email FROM users WHERE id = ? AND type = 'customer'", [$id]);
    if (!$target) {
        json_err('Customer not found.', 404);
    }
    $bookings = (int) scalar('SELECT COUNT(*) FROM bookings WHERE user_id = ?', [$id]);
    if ($bookings > 0) {
        fail("Cannot delete: this customer has $bookings booking(s). Block the account instead.", 409);
    }
    tx(function () use ($id) {
        q('DELETE FROM user_roles WHERE user_id = ?', [$id]);
        q('DELETE FROM user_permissions WHERE user_id = ?', [$id]);
        q('DELETE FROM email_verification_tokens WHERE user_id = ?', [$id]);
        q('DELETE FROM users WHERE id = ?', [$id]);
    });
    audit('user.delete', 'users', $id, 'Deleted ' . $target['email']);
    json_out(['ok' => true, 'message' => 'Account deleted.']);
}

/* ---------- sub-admins, roles, permissions ---------- */

function a_admin_admins(array $in): void
{
    $rows = all(
        "SELECT id, name, email, username, status, created_at FROM users
          WHERE type = 'admin' ORDER BY created_at ASC"
    );
    foreach ($rows as &$a) {
        $uid = (int) $a['id'];
        $a['id'] = $uid;
        $a['roles'] = all(
            'SELECT r.id, r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?',
            [$uid]
        );
        $a['permissions'] = array_column(all(
            'SELECT p.id, p.code FROM permissions p
               JOIN user_permissions up ON up.permission_id = p.id WHERE up.user_id = ?', [$uid]
        ), 'code');
        $a['is_super'] = in_array('super_admin', user_role_names($uid), true);
    }
    unset($a);
    json_out(['ok' => true, 'admins' => $rows]);
}

function a_admin_save(array $in): void
{
    $actor      = require_permission('admins.manage');
    $actorPerms = user_permission_codes((int) $actor['id']);
    $actorSuper = in_array('*', $actorPerms, true);
    $actorRoles = user_role_names((int) $actor['id']);

    $id       = ($in['id'] ?? '') !== '' ? (int) $in['id'] : null;
    $name     = f_str($in, 'name', 'Full name', 2, 100);
    $email    = f_email($in);
    $username = f_str($in, 'username', 'Username', 3, 60);
    if (!preg_match('/^[a-zA-Z0-9_.]+$/', $username)) {
        fail('Username may only contain letters, numbers, underscore and dot.', 422);
    }
    $status = in_array($in['status'] ?? 'active', ['pending', 'active', 'blocked'], true)
        ? $in['status'] : 'active';
    $roleIds = array_values(array_unique(array_map('intval', f_list($in, 'roles', 'Roles'))));
    $permIds = array_values(array_unique(array_map('intval', f_list($in, 'permissions', 'Permissions'))));

    $target = null;
    $targetIsSuper = false;
    if ($id) {
        $target = one('SELECT * FROM users WHERE id = ? AND type = ?', [$id, 'admin']);
        if (!$target) {
            json_err('Administrator not found.', 404);
        }
        $targetIsSuper = in_array('super_admin', user_role_names($id), true);
        if ($id === (int) $actor['id']) {
            $targetIsSuper = in_array('super_admin', $actorRoles, true);
        }
    }

    if ($targetIsSuper && !$actorSuper) {
        fail('Only a super admin can modify a super admin account.', 403);
    }

    if (!$actorSuper) {
        // only roles the actor holds may be granted (never super_admin)
        $actorRoleIds = array_map('intval', array_column(all(
            'SELECT r.id FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?',
            [$actor['id']]
        ), 'id'));
        $superRoleId = (int) (scalar("SELECT id FROM roles WHERE name = 'super_admin'") ?: 0);
        $roleIds = array_values(array_intersect($roleIds, $actorRoleIds));
        $roleIds = array_values(array_diff($roleIds, [$superRoleId]));

        // only permissions the actor holds may be granted
        $grantable = array_map('intval', array_column(all(
            'SELECT p.id FROM permissions p WHERE p.code != ?', ['*']
        ), 'id'));
        $actorPermIds = [];
        foreach ($grantable as $pid) {
            // actor permission codes are role+direct; map ids via codes
        }
        $actorPermCodes = $actorPerms;
        $allowed = all("SELECT id, code FROM permissions");
        $actorPermIdSet = [];
        foreach ($allowed as $p) {
            if (in_array($p['code'], $actorPermCodes, true)) {
                $actorPermIdSet[] = (int) $p['id'];
            }
        }
        $permIds = array_values(array_intersect($permIds, $actorPermIdSet));

        // prevent self-elevation of roles/permissions
        if ($id === (int) $actor['id']) {
            $currentRoles = array_map('intval', array_column(all(
                'SELECT role_id FROM user_roles WHERE user_id = ?', [$id]
            ), 'role_id'));
            $currentPerms = array_map('intval', array_column(all(
                'SELECT permission_id FROM user_permissions WHERE user_id = ?', [$id]
            ), 'permission_id'));
            sort($roleIds); sort($currentRoles);
            sort($permIds); sort($currentPerms);
            if ($roleIds !== $currentRoles || $permIds !== $currentPerms) {
                fail('You cannot change your own roles or permissions.', 403);
            }
        }
    }

    $dup = one('SELECT id FROM users WHERE email = ? COLLATE NOCASE' . ($id ? ' AND id != ?' : ''),
               $id ? [$email, $id] : [$email]);
    if ($dup) {
        fail('An account with this email already exists.', 409);
    }
    $dupU = one('SELECT id FROM users WHERE username = ? COLLATE NOCASE' . ($id ? ' AND id != ?' : ''),
                $id ? [$username, $id] : [$username]);
    if ($dupU) {
        fail('That username is already taken.', 409);
    }

    $password = (string) ($in['password'] ?? '');
    if (!$id && $password === '') {
        fail('Password is required for a new administrator.', 422);
    }

    tx(function () use ($id, $name, $email, $username, $status, $password, $roleIds, $permIds) {
        if ($id) {
            $sql = "UPDATE users SET name=?, email=?, username=?, status=?, updated_at=datetime('now')";
            $params = [$name, $email, $username, $status];
            if ($password !== '') {
                if (strlen($password) < 8) {
                    fail('Password must be at least 8 characters.', 422);
                }
                $sql .= ', password_hash = ?';
                $params[] = password_hash($password, PASSWORD_DEFAULT);
            }
            $sql .= ' WHERE id = ?';
            $params[] = $id;
            q($sql, $params);
        } else {
            $id = insert_row(
                "INSERT INTO users (name, email, username, password_hash, type, status,
                        email_verified_at, created_at, updated_at)
                 VALUES (?,?,?,?, 'admin', ?, datetime('now'), datetime('now'), datetime('now'))",
                [$name, $email, $username, password_hash($password, PASSWORD_DEFAULT), $status]
            );
        }
        q('DELETE FROM user_roles WHERE user_id = ?', [$id]);
        q('DELETE FROM user_permissions WHERE user_id = ?', [$id]);
        foreach ($roleIds as $rid) {
            if ($rid > 0) {
                q('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?,?)', [$id, $rid]);
            }
        }
        foreach ($permIds as $pid) {
            if ($pid > 0) {
                q('INSERT OR IGNORE INTO user_permissions (user_id, permission_id) VALUES (?,?)', [$id, $pid]);
            }
        }
        return $id;
    });

    audit('admin.save', 'users', $id, 'Admin ' . $email
        . ' | roles: ' . implode(',', $roleIds) . ' | direct perms: ' . implode(',', $permIds));
    json_out(['ok' => true, 'id' => $id, 'message' => 'Administrator saved.']);
}

function a_admin_delete(array $in): void
{
    $actor = require_permission('admins.manage');
    $actorSuper = in_array('*', user_permission_codes((int) $actor['id']), true);
    $id = f_int($in, 'id', 'Administrator', 1, PHP_INT_MAX);

    if ($id === (int) $actor['id']) {
        fail('You cannot delete your own account.', 403);
    }
    $target = one("SELECT id, email FROM users WHERE id = ? AND type = 'admin'", [$id]);
    if (!$target) {
        json_err('Administrator not found.', 404);
    }
    if (!$actorSuper && in_array('super_admin', user_role_names($id), true)) {
        fail('Only a super admin can delete a super admin account.', 403);
    }
    tx(function () use ($id) {
        q('DELETE FROM user_roles WHERE user_id = ?', [$id]);
        q('DELETE FROM user_permissions WHERE user_id = ?', [$id]);
        q('DELETE FROM users WHERE id = ?', [$id]);
    });
    audit('admin.delete', 'users', $id, 'Deleted ' . $target['email']);
    json_out(['ok' => true, 'message' => 'Administrator deleted.']);
}

function a_roles(array $in): void
{
    $roles = all('SELECT id, name, description FROM roles ORDER BY id');
    foreach ($roles as &$r) {
        $r['id'] = (int) $r['id'];
        $r['permissions'] = array_column(all(
            'SELECT p.code FROM permissions p
               JOIN role_permissions rp ON rp.permission_id = p.id
              WHERE rp.role_id = ? ORDER BY p.code',
            [$r['id']]
        ), 'code');
    }
    unset($r);
    json_out(['ok' => true, 'roles' => $roles]);
}

function a_permissions(array $in): void
{
    json_out(['ok' => true, 'permissions' => all('SELECT id, code, description FROM permissions ORDER BY code')]);
}

function a_audit(array $in): void
{
    $limit = min(500, max(1, (int) ($in['limit'] ?? 200)));
    $rows = all(
        "SELECT a.*, u.name AS actor_name, u.email AS actor_email
           FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
          ORDER BY a.created_at DESC, a.id DESC LIMIT ?",
        [$limit]
    );
    json_out(['ok' => true, 'entries' => $rows]);
}
