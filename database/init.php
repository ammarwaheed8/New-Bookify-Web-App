<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Run from the command line: php database/init.php\n");
    exit(1);
}

require __DIR__ . '/../app/bootstrap.php';

$pdo = db();
$schema = file_get_contents(__DIR__ . '/schema.sql');
if ($schema === false) {
    fwrite(STDERR, "Cannot read schema.sql\n");
    exit(1);
}
$pdo->exec($schema);
echo "  Schema applied\n";

/* ---------- roles & permissions ---------- */

$permissions = [
    'dashboard.view' => 'View admin dashboard metrics',
    'hotels.view'    => 'View hotels',
    'hotels.manage'  => 'Create, edit, publish and delete hotels',
    'bookings.view'  => 'View bookings',
    'bookings.manage'=> 'Update booking statuses',
    'users.view'     => 'View customer accounts',
    'users.manage'   => 'Create, edit, approve, block and delete customers',
    'admins.view'    => 'View administrator accounts',
    'admins.manage'  => 'Create and manage sub-administrators',
    'roles.manage'   => 'Manage roles and permission assignments',
    'audit.view'     => 'View the audit log',
];
$rolePerms = [
    'super_admin'    => array_keys($permissions),
    'hotel_manager'  => ['dashboard.view', 'hotels.view', 'hotels.manage', 'bookings.view', 'bookings.manage'],
    'user_manager'   => ['dashboard.view', 'users.view', 'users.manage'],
    'booking_manager'=> ['dashboard.view', 'bookings.view', 'bookings.manage'],
    'viewer'         => ['dashboard.view'],
];

$pdo->beginTransaction();
foreach ($permissions as $code => $desc) {
    $pdo->prepare('INSERT OR IGNORE INTO permissions (code, description) VALUES (?,?)')->execute([$code, $desc]);
}
foreach ($rolePerms as $role => $codes) {
    $pdo->prepare('INSERT OR IGNORE INTO roles (name, description) VALUES (?,?)')
        ->execute([$role, ucfirst(str_replace('_', ' ', $role))]);
}
$pdo->commit();

$roleId = static function (string $name): int use ($pdo): int {
    $st = $pdo->prepare('SELECT id FROM roles WHERE name = ?');
    $st->execute([$name]);
    return (int) $st->fetchColumn();
};
$permId = static function (string $code): int use ($pdo): int {
    $st = $pdo->prepare('SELECT id FROM permissions WHERE code = ?');
    $st->execute([$code]);
    return (int) $st->fetchColumn();
};

$pdo->beginTransaction();
foreach ($rolePerms as $role => $codes) {
    $rid = $roleId($role);
    foreach ($codes as $code) {
        $pdo->prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?,?)')
            ->execute([$rid, $permId($code)]);
    }
}
$pdo->commit();
echo "  Roles and permissions seeded\n";

/* ---------- account helper ---------- */

function find_user(PDO $pdo, string $field, string $value): ?array {
    $st = $pdo->prepare("SELECT * FROM users WHERE {$field} = ?");
    $st->execute([$value]);
    $row = $st->fetch();
    return $row ?: null;
}

function ensure_account(PDO $pdo, array $data): array {
    $existing = find_user($pdo, $data['type'] === 'admin' ? 'username' : 'email', $data['type'] === 'admin' ? $data['username'] : $data['email']);
    $hash = password_hash($data['password'], PASSWORD_DEFAULT);
    if ($existing) {
        // keep documented dev credentials working even if config changed
        if (!password_verify($data['password'], $existing['password_hash'])) {
            $pdo->prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?')
                ->execute([$hash, now_utc(), (int) $existing['id']]);
        }
        return $existing;
    }
    $st = $pdo->prepare(
        "INSERT INTO users (name, email, username, phone, password_hash, type, status, email_verified_at, city, country)
         VALUES (?,?,?,?,?,?,?,?,?,?)"
    );
    $st->execute([
        $data['name'], $data['email'], $data['username'] ?? null, $data['phone'] ?? '', $hash,
        $data['type'], $data['status'], $data['verified'] ? now_utc() : null,
        $data['city'] ?? '', $data['country'] ?? '',
    ]);
    $id = (int) $pdo->lastInsertId();
    foreach ($data['roles'] as $role) {
        $pdo->prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?,?)')->execute([$id, $roleId($role)]);
    }
    return find_user($pdo, 'id', (string) $id) ?? ['id' => $id];
}

$admin = ensure_account($pdo, [
    'type' => 'admin', 'name' => 'Super Administrator', 'email' => 'admin@bookify.local',
    'username' => (string) cfg('seeds.admin_username', 'admin'), 'password' => (string) cfg('seeds.admin_password', 'admin123'),
    'status' => 'active', 'verified' => true, 'roles' => ['super_admin'],
]);
$sub1 = ensure_account($pdo, [
    'type' => 'admin', 'name' => 'Hotel Manager', 'email' => 'manager@bookify.local',
    'username' => 'manager', 'password' => 'manager123',
    'status' => 'active', 'verified' => true, 'roles' => ['hotel_manager'],
]);
$sub2 = ensure_account($pdo, [
    'type' => 'admin', 'name' => 'Support Desk', 'email' => 'support@bookify.local',
    'username' => 'support', 'password' => 'support123',
    'status' => 'active', 'verified' => true, 'roles' => ['user_manager'],
]);
$demo = ensure_account($pdo, [
    'type' => 'customer', 'name' => 'Emma Carter', 'email' => 'demo@bookify.local',
    'password' => 'demo1234', 'status' => 'active', 'verified' => true, 'roles' => [],
    'city' => 'London', 'country' => 'United Kingdom', 'phone' => '+44 7700 900123',
]);
echo "  Accounts seeded (admin, manager, support, demo customer)\n";

/* ---------- hotels ---------- */

$hotels = [
    [
        'The Grand Meridian', 'Paris', 'France', '2 Rue de la Paix, 75002 Paris, France',
        'Place Vendome, 0.4 km from Louvre',
        'A landmark luxury hotel facing Place Vendome with marble lobbies, a Michelin-starred restaurant and a rooftop spa with city views.',
        5, 4.8, 214, '#173f8f', '#4b8fe0',
        ['Free WiFi', 'Spa', 'Indoor pool', 'Restaurant', 'Fitness centre', 'Room service', 'Concierge', 'Airport shuttle'],
        ['Check-in from 15:00, check-out by 12:00', 'Free cancellation until 48 hours before arrival', 'Non-smoking property', 'Pets welcome on request'],
        [
            ['Deluxe Room', 'King bed, marble bathroom and Haussmann views.', 2, 18, 245],
            ['Executive Suite', 'Separate living room and lounge access.', 3, 8, 380],
            ['Presidential Suite', 'Two bedrooms, terrace and butler service.', 4, 3, 690],
        ],
    ],
    [
        'Harbourview Suites', 'Sydney', 'Australia', '19 Circular Quay W, Sydney NSW 2000, Australia',
        'Circular Quay, opposite the Opera House',
        'Modern all-suite harbour accommodation with floor-to-ceiling windows, a 25m pool and direct ferry access to every major landmark.',
        5, 4.7, 168, '#0d5b63', '#3fb2b8',
        ['Free WiFi', 'Outdoor pool', 'Harbour-view gym', 'Restaurant', 'Parking', 'Laundry'],
        ['Check-in from 14:00, check-out by 11:00', 'Free cancellation until 24 hours before arrival', 'Quiet hours from 22:00'],
        [
            ['Harbour Queen Suite', 'One bedroom with Circular Quay views.', 2, 14, 210],
            ['Two-Bedroom Family Suite', 'Full kitchen and dining area.', 4, 6, 315],
            ['Opera Deluxe', 'Corner suite facing the Opera House.', 3, 5, 420],
        ],
    ],
    [
        'Sakura Ryokan & Spa', 'Kyoto', 'Japan', '321 Gionmachi, Higashiyama-ku, Kyoto 605-0074, Japan',
        'Gion district, 6 min from Yasaka Shrine',
        'A restored wooden ryokan in the heart of Gion offering tatami rooms, private cedar onsen baths and kaiseki dinners prepared nightly.',
        4, 4.9, 132, '#7a2440', '#d97a95',
        ['Free WiFi', 'Onsen spa', 'Kaiseki restaurant', 'Garden', 'Tea ceremony', 'Luggage storage'],
        ['Check-in from 16:00, check-out by 10:00', 'Slippers required indoors', 'Free cancellation until 72 hours before arrival'],
        [
            ['Tatami Room', 'Traditional room with futon bedding.', 2, 12, 180],
            ['Garden View Room', 'Room overlooking the moss garden.', 3, 7, 240],
            ['Private Onsen Suite', 'Suite with in-room cedar bath.', 4, 4, 360],
        ],
    ],
    [
        'Alpine Crest Lodge', 'Zermatt', 'Switzerland', 'Bahnhofstrasse 12, 3920 Zermatt, Switzerland',
        'Old town, 300 m from Gornergrat railway',
        'A ski-in chalet lodge with timber interiors, a panoramic wellness floor and Matterhorn views from every south-facing room.',
        4, 4.6, 97, '#2c3f6d', '#6f8fd1',
        ['Free WiFi', 'Ski storage', 'Sauna', 'Restaurant', 'Bar', 'Shuttle to lifts'],
        ['Check-in from 15:00, check-out by 11:00', 'City tax payable at property', 'Free cancellation until 5 days before arrival'],
        [
            ['Alpine Double', 'Cosy room with wood panelling.', 2, 16, 195],
            ['Matterhorn Family Room', 'Bunk alcove and mountain views.', 4, 9, 265],
            ['Panorama Suite', 'Wraparound balcony facing the Matterhorn.', 4, 4, 440],
        ],
    ],
    [
        'Palm Bay Resort', 'Male', 'Maldives', 'North Male Atoll, 08080 Male, Maldives',
        'Private island, 30 min speedboat from Velana Airport',
        'An overwater resort with villas perched above a turquoise lagoon, a reef house and a spa deck suspended above the Indian Ocean.',
        5, 4.9, 188, '#0b6b8a', '#4fc0d8',
        ['Free WiFi', 'Private beach', 'Dive centre', 'Overwater spa', '2 restaurants', 'Pool', 'Airport transfer'],
        ['Check-in from 14:00, check-out by 12:00', 'Transfers arranged after booking', 'Free cancellation until 14 days before arrival'],
        [
            ['Lagoon Villa', 'Overwater villa with glass-floor panel.', 2, 10, 420],
            ['Sunset Beach Villa', 'Beachfront villa with private pool.', 3, 6, 560],
            ['Reef Residence', 'Two-bedroom residence with jetty.', 6, 3, 940],
        ],
    ],
    [
        'The Urban Nest', 'New York', 'USA', '88 Orchard Street, New York, NY 10002, USA',
        'Lower East Side, 5 min from the subway',
        'A design-forward boutique hotel on the Lower East Side with compact smart rooms, a lobby coffee bar and a rooftop lounge.',
        3, 4.3, 241, '#8a4a12', '#e0a45f',
        ['Free WiFi', 'Rooftop lounge', '24-hour front desk', 'Luggage storage', 'Business corner'],
        ['Check-in from 16:00, check-out by 11:00', 'Non-smoking property', 'Free cancellation until 24 hours before arrival'],
        [
            ['Smart Queen', 'Compact room with rainfall shower.', 2, 24, 139],
            ['Loft Double', 'High ceilings and exposed brick.', 3, 12, 189],
            ['Skyline Studio', 'Corner studio with skyline views.', 4, 5, 249],
        ],
    ],
];

$svgDir = BOOKIFY_ROOT . '/public/assets/img/hotels';
if (!is_dir($svgDir) && !@mkdir($svgDir, 0775, true)) {
    fwrite(STDERR, "Cannot create {$svgDir}\n");
    exit(1);
}

function write_hotel_svg(string $file, string $title, string $subtitle, string $c1, string $c2, int $variant): void {
    $title = htmlspecialchars($title, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $subtitle = htmlspecialchars($subtitle, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $x = 70 + ($variant * 40);
    $svg = <<<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800" viewBox="0 0 1200 800" role="img" aria-label="{$title}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{$c1}"/>
      <stop offset="1" stop-color="{$c2}"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="800" fill="url(#bg)"/>
  <g fill="none" stroke="rgba(255,255,255,0.22)" stroke-width="2">
    <circle cx="980" cy="180" r="140"/>
    <circle cx="980" cy="180" r="220"/>
    <rect x="{$x}" y="420" width="420" height="260" rx="18"/>
  </g>
  <g fill="rgba(255,255,255,0.16)">
    <rect x="60" y="120" width="60" height="140" rx="6"/>
    <rect x="140" y="80" width="60" height="180" rx="6"/>
    <rect x="220" y="150" width="60" height="110" rx="6"/>
  </g>
  <text x="70" y="640" font-family="Georgia, serif" font-size="66" fill="#ffffff">{$title}</text>
  <text x="72" y="694" font-family="Helvetica, Arial, sans-serif" font-size="30" fill="rgba(255,255,255,0.85)">{$subtitle}</text>
</svg>
SVG;
    file_put_contents($file, $svg);
}

$created = 0;
$pdo->beginTransaction();
foreach ($hotels as $h) {
    [
        $hName, $hCity, $hCountry, $hAddress, $hLocation, $hDesc, $hStars, $hRating, $hReviews,
        $c1, $c2, $hAmenities, $hPolicies, $hRooms,
    ] = $h;

    $st = $pdo->prepare('SELECT id FROM hotels WHERE name = ? AND city = ?');
    $st->execute([$hName, $hCity]);
    if ($st->fetch()) {
        continue;
    }
    $price = min(array_column($hRooms, 4));
    $st = $pdo->prepare(
        "INSERT INTO hotels (name, slug, description, address, city, country, location_text, stars, rating,
            reviews_count, price_per_night, amenities, policies, status)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'published')"
    );
    $st->execute([
        $hName, unique_slug($hName), $hDesc, $hAddress, $hCity, $hCountry, $hLocation,
        $hStars, $hRating, $hReviews, $price,
        json_encode($hAmenities, JSON_UNESCAPED_UNICODE),
        json_encode($hPolicies, JSON_UNESCAPED_UNICODE),
    ]);
    $hotelId = (int) $pdo->lastInsertId();

    $variants = ['', '-2', '-3'];
    $img = $pdo->prepare('INSERT INTO hotel_images (hotel_id, url, alt, sort_order) VALUES (?,?,?,?)');
    foreach ($variants as $i => $suffix) {
        $file = $svgDir . '/hotel-' . $hotelId . $suffix . '.svg';
        write_hotel_svg($file, $hName, $hCity . ', ' . $hCountry, $c1, $c2, $i);
        $img->execute([
            $hotelId,
            '/assets/img/hotels/hotel-' . $hotelId . $suffix . '.svg',
            $hName . ' - image ' . ($i + 1),
            $i,
        ]);
    }

    foreach ($hRooms as [$rName, $rDesc, $rCap, $rTotal, $rPrice]) {
        $st = $pdo->prepare(
            'INSERT INTO room_types (hotel_id, name, description, capacity, total_rooms, price_per_night) VALUES (?,?,?,?,?,?)'
        );
        $st->execute([$hotelId, $rName, $rDesc, $rCap, $rTotal, $rPrice]);
        seed_inventory((int) $pdo->lastInsertId(), $rTotal, 180);
    }
    $created++;
}
$pdo->commit();
echo "  {$created} hotel(s) seeded with images, rooms and 180 days of inventory\n";

/* ---------- sample bookings ---------- */

$bookingCount = (int) $pdo->query('SELECT COUNT(*) FROM bookings')->fetchColumn();
if ($bookingCount === 0) {
    $st = $pdo->prepare("SELECT rt.id, rt.hotel_id, rt.price_per_night, h.name FROM room_types rt JOIN hotels h ON h.id = rt.hotel_id WHERE rt.name = 'Deluxe Room' LIMIT 1");
    $st->execute();
    $room = $st->fetch();

    if ($room && $demo) {
        $samples = [
            ['BKF-DEMO0001', date('Y-m-d', strtotime('-30 days')), date('Y-m-d', strtotime('-27 days')), 'confirmed', 'completed', 'card', 'paid'],
            ['BKF-DEMO0002', date('Y-m-d', strtotime('+14 days')), date('Y-m-d', strtotime('+17 days')), 'pending', 'pending', 'property', 'pending'],
        ];
        $pdo->beginTransaction();
        foreach ($samples as [$ref, $in, $out, $status, $payStatus, $method, $payMethodStatus]) {
            $nights = (int) round((strtotime($out) - strtotime($in)) / 86400);
            $subtotal = round(245 * $nights, 2);
            $taxes = round($subtotal * (float) cfg('booking.tax_rate', 0.12), 2);
            $fee = (float) cfg('booking.service_fee', 15.00);
            $total = round($subtotal + $taxes + $fee, 2);
            $st = $pdo->prepare(
                "INSERT INTO bookings (reference, user_id, hotel_id, room_type_id, check_in, check_out, nights,
                    num_guests, num_rooms, guest_name, guest_email, guest_phone, subtotal, taxes, service_fee,
                    total, currency, payment_method, status)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            );
            $st->execute([
                $ref, (int) $demo['id'], (int) $room['hotel_id'], (int) $room['id'], $in, $out, $nights,
                2, 1, 'Emma Carter', 'demo@bookify.local', '+44 7700 900123',
                $subtotal, $taxes, $fee, $total, (string) cfg('booking.currency', 'USD'), $method, $status,
            ]);
            $bookingId = (int) $pdo->lastInsertId();
            $pdo->prepare('INSERT INTO booking_guests (booking_id, name, email, phone, is_primary) VALUES (?,?,?,?,1)')
                ->execute([$bookingId, 'Emma Carter', 'demo@bookify.local', '+44 7700 900123']);
            $pdo->prepare('INSERT INTO payments (booking_id, method, amount, currency, status, transaction_ref) VALUES (?,?,?,?,?,?)')
                ->execute([$bookingId, $method, $total, (string) cfg('booking.currency', 'USD'), $payMethodStatus, 'MOCK-SEED']);
        }
        $pdo->commit();
        echo "  Sample bookings seeded\n";
    }
}

echo "\nDatabase ready: " . (string) cfg('db.path') . "\n";
echo "Admin:    " . cfg('seeds.admin_username', 'admin') . " / " . cfg('seeds.admin_password', 'admin123') . "\n";
echo "Sub-admins: manager / manager123, support / support123\n";
echo "Customer: demo@bookify.local / demo1234\n";
