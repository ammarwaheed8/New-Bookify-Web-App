<?php
// CLI: php database/init.php [--fresh]
require __DIR__ . '/../app/bootstrap.php';

$argv = $_SERVER['argv'] ?? [];
if (in_array('--fresh', $argv, true) && file_exists(cfg('db_path'))) {
    unlink(cfg('db_path'));
    echo "Removed existing database.\n";
}
if (!is_dir(dirname(cfg('db_path')))) mkdir(dirname(cfg('db_path')), 0775, true);

$db = db();
$db->exec(file_get_contents(__DIR__ . '/schema.sql'));
echo "Schema applied.\n";

seed_rbac();
seed_users();
seed_catalog();
seed_bookings();
gen_images();
echo "Seed data written.\nDone.\n";

function seed_rbac(): void {
    $db = db();
    $perms = [
        'dashboard.view' => 'View admin dashboard',
        'hotels.view' => 'View hotels', 'hotels.create' => 'Create hotels',
        'hotels.update' => 'Edit hotels', 'hotels.delete' => 'Delete hotels',
        'hotels.publish' => 'Publish / unpublish hotels',
        'bookings.view' => 'View bookings', 'bookings.update' => 'Update bookings',
        'users.view' => 'View customers', 'users.create' => 'Create customers',
        'users.update' => 'Edit customers', 'users.delete' => 'Delete customers',
        'users.approve' => 'Approve / block customers',
        'admins.view' => 'View staff accounts', 'admins.create' => 'Create staff',
        'admins.update' => 'Edit staff', 'admins.delete' => 'Delete staff',
        'roles.manage' => 'Manage roles and permissions',
        'audit.view' => 'View audit log',
    ];
    $p = $db->prepare('INSERT OR IGNORE INTO permissions(code, description) VALUES (?, ?)');
    foreach ($perms as $code => $desc) $p->execute([$code, $desc]);

    $roles = [
        'super_admin' => 'Unrestricted access',
        'hotel_manager' => 'Manage hotels, rooms and bookings',
        'user_manager' => 'Manage customer accounts and approvals',
        'booking_manager' => 'View and update bookings',
        'viewer' => 'Read-only dashboard access',
    ];
    $r = $db->prepare('INSERT OR IGNORE INTO roles(name, description) VALUES (?, ?)');
    foreach ($roles as $n => $d) $r->execute([$n, $d]);

    $map = [
        'super_admin' => array_keys($perms),
        'hotel_manager' => ['dashboard.view','hotels.view','hotels.create','hotels.update','hotels.publish','bookings.view','bookings.update'],
        'user_manager' => ['dashboard.view','users.view','users.create','users.update','users.approve','users.delete','admins.view'],
        'booking_manager' => ['dashboard.view','bookings.view','bookings.update','hotels.view'],
        'viewer' => ['dashboard.view','hotels.view','bookings.view'],
    ];
    $link = $db->prepare(
        'INSERT OR IGNORE INTO role_permissions(role_id, permission_id)
         SELECT r.id, p.id FROM roles r JOIN permissions p ON p.code = ?
         WHERE r.name = ?'
    );
    foreach ($map as $role => $codes) foreach ($codes as $c) $link->execute([$c, $role]);
}

function seed_users(): void {
    $db = db();
    $mk = fn(string $n, string $e, string $u, string $pw, string $type, string $st, ?string $verified) =>
        [$n, $e, $u, password_hash($pw, PASSWORD_DEFAULT), $type, $st, $verified];

    $rows = [
        $mk('Super Admin', 'admin@bookify.local', cfg('seeds.admin_username'), cfg('seeds.admin_password'), 'admin', 'active', gmdate('Y-m-d H:i:s')),
        $mk('Mia Hotel Manager', 'manager@bookify.local', 'manager', 'manager123', 'admin', 'active', gmdate('Y-m-d H:i:s')),
        $mk('Alice Novak', 'alice@example.com', null, 'password123', 'customer', 'active', gmdate('Y-m-d H:i:s')),
        $mk('Bob Tanaka', 'bob@example.com', null, 'password123', 'customer', 'pending', null),
    ];
    $st = $db->prepare(
        "INSERT OR IGNORE INTO users(name,email,username,password_hash,type,status,email_verified_at)
         VALUES (?,?,?,?,?,?,?)"
    );
    foreach ($rows as $r) $st->execute($r);

    $id = fn(string $email) => (int) db()->prepare('SELECT id FROM users WHERE email = ?')->execute([$email])
        ? (int) db()->query("SELECT id FROM users WHERE email = '$email'")->fetchColumn() : 0;
    $adminId = (int) $db->query("SELECT id FROM users WHERE username = 'admin'")->fetchColumn();
    $mgrId   = (int) $db->query("SELECT id FROM users WHERE username = 'manager'")->fetchColumn();

    $assign = $db->prepare(
        'INSERT OR IGNORE INTO user_roles(user_id, role_id)
         SELECT u.id, r.id FROM users u, roles r WHERE u.id = ? AND r.name = ?'
    );
    $assign->execute([$adminId, 'super_admin']);
    $assign->execute([$mgrId, 'hotel_manager']);
    $assign->execute([$mgrId, 'booking_manager']);
}

function seed_catalog(): void {
    $db = db();
    if ((int) $db->query('SELECT COUNT(*) FROM hotels')->fetchColumn() > 0) return;

    $hotels = [
        ['The Azure Bay Resort', 'Oia', 'Greece', '12 Caldera Road', 'Perched on the Santorini caldera with sunset views over the Aegean.', 5, 4.9, 412, 320, 'published',
            ['Free WiFi','Pool','Spa','Restaurant','Bar','Fitness Center','Air Conditioning','Room Service'],
            [['Standard Sea View',2,18,320],['Deluxe Cave Suite',3,8,480],['Infinity Villa',4,3,860]], ['#0b3d91','#1fa2c6']],
        ['Grand Maple Hotel', 'Toronto', 'Canada', '88 Front Street West', 'A refined downtown hotel steps from the CN Tower and Union Station.', 4, 4.6, 289, 189, 'published',
            ['Free WiFi','Fitness Center','Restaurant','Room Service','Parking','Air Conditioning'],
            [['Standard Queen',2,30,189],['Executive King',2,14,245],['Maple Suite',4,5,360]], ['#7a1f1f','#e08e45']],
        ['Sakura Garden Inn', 'Kyoto', 'Japan', '5 Higashiyama Lane', 'A quiet machiya-style inn with a private garden in the heart of Higashiyama.', 4, 4.8, 356, 156, 'published',
            ['Free WiFi','Spa','Breakfast','Air Conditioning','Airport Shuttle'],
            [['Tatami Room',2,20,156],['Garden Deluxe',3,10,210],['Riverside Suite',4,4,320]], ['#5b2340','#e88fb0']],
        ['Andes Ridge Lodge', 'Cusco', 'Peru', '47 Avenida El Sol', 'A stone-and-timber lodge above the Urubamba valley with guided treks.', 3, 4.4, 173, 98, 'published',
            ['Free WiFi','Restaurant','Bar','Parking','Breakfast'],
            [['Cozy Single',1,12,98],['Double Ridge',2,16,132],['Family Loft',5,6,210]], ['#1e4d2b','#8fbf6b']],
        ['Meridian Downtown', 'Dubai', 'United Arab Emirates', '1 Sheikh Zayed Road', 'Skyline rooms, a rooftop pool and a five-minute walk to the metro.', 5, 4.7, 521, 275, 'published',
            ['Free WiFi','Pool','Spa','Gym','Restaurant','Bar','Airport Shuttle','Air Conditioning'],
            [['Deluxe City Room',2,40,275],['Marina View Room',2,18,340],['Penthouse Suite',4,4,720]], ['#12224a','#3ea0c9']],
        ['Lakeside Bramble Cottage', 'Hallstatt', 'Austria', '9 Seestraße', 'A timber cottage on the shore of Hallstätter See with mountain views.', 3, 4.5, 128, 112, 'draft',
            ['Free WiFi','Parking','Breakfast','Pet Friendly'],
            [['Cottage Double',2,6,112],['Loft Family Room',4,4,168],['Lakeside Cabin',3,3,205]], ['#264653','#84a98c']],
    ];

    $policies = json_encode([
        'checkin' => '15:00', 'checkout' => '11:00',
        'cancellation' => 'Free cancellation until 48 hours before check-in.',
        'children' => 'Children of all ages welcome.',
        'pets' => 'Pets not allowed unless stated otherwise.',
    ], JSON_UNESCAPED_SLASHES);

    foreach ($hotels as $i => $h) {
        [$name, $city, $country, $addr, $desc, $stars, $rating, $reviews, $price, $status, $amen, $rooms, $colors] = $h;
        $slug = strtolower(trim(preg_replace('/[^a-z0-9]+/i', '-', $name), '-'));
        $db->prepare(
            'INSERT INTO hotels(name, slug, description, address, city, country, location_text,
                star_rating, rating, review_count, amenities, policies, base_price, status)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        )->execute([$name, $slug, $desc, $addr, $city, $country,
            "$city, $country — central location, walkable to main attractions.",
            $stars, $rating, $reviews, json_encode($amen, JSON_UNESCAPED_SLASHES), $policies, $price, $status]);
        $hid = (int) $db->lastInsertId();

        foreach ([['assets/img/hotel-' . ($i + 1) . '-a.svg', 0],
                  ['assets/img/hotel-' . ($i + 1) . '-b.svg', 1]] as [$url, $ord]) {
            $db->prepare('INSERT INTO hotel_images(hotel_id, url, alt, sort_order) VALUES (?,?,?,?)')
               ->execute([$hid, $url, $name . ' photo', $ord]);
        }
        foreach ($rooms as $ord => [$rn, $g, $total, $ppn]) {
            $db->prepare('INSERT INTO room_types(hotel_id, name, description, max_guests, total_rooms, price_per_night, amenities, sort_order)
                          VALUES (?,?,?,?,?,?,?,?)')
               ->execute([$hid, $rn, "Comfortable $rn with en-suite bathroom.", $g, $total, $ppn,
                          json_encode($amen, JSON_UNESCAPED_SLASHES), $ord]);
        }
    }
}

function seed_bookings(): void {
    $db = db();
    if ((int) $db->query('SELECT COUNT(*) FROM bookings')->fetchColumn() > 0) return;

    $alice = (int) $db->query("SELECT id FROM users WHERE email = 'alice@example.com'")->fetchColumn();
    $spec = [
        [1, 1, 14, 17, 1, 2, 'confirmed', 'card'],
        [3, 2, 30, 33, 2, 3, 'pending', 'property'],
    ];
    $n = 1;
    foreach ($spec as [$hid, $ord, $plusIn, $plusOut, $rooms, $guests, $status, $method]) {
        $rt = $db->query("SELECT * FROM room_types WHERE hotel_id = $hid ORDER BY sort_order LIMIT 1 OFFSET " . ($ord - 1))->fetch();
        if (!$rt) continue;
        $ci = gmdate('Y-m-d', strtotime("+$plusIn days"));
        $co = gmdate('Y-m-d', strtotime("+$plusOut days"));
        $nights = (int) ((strtotime($co) - strtotime($ci)) / 86400);
        $sub = round($rt['price_per_night'] * $nights * $rooms, 2);
        $tax = round($sub * cfg('booking.tax_rate'), 2);
        $fee = cfg('booking.service_fee');
        $ref = 'BK-' . strtoupper(bin2hex(random_bytes(4)));
        $db->prepare('INSERT INTO bookings(reference,user_id,hotel_id,room_type_id,check_in,check_out,nights,rooms,guests,subtotal,taxes,fees,total,status,payment_method,payment_status)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
           ->execute([$ref, $alice, $hid, $rt['id'], $ci, $co, $nights, $rooms, $guests, $sub, $tax, $fee,
                      round($sub + $tax + $fee, 2), $status, $method,
                      $method === 'property' ? 'unpaid' : 'paid']);
        $bid = (int) $db->lastInsertId();
        $db->prepare('INSERT INTO booking_guests(booking_id, full_name, email, phone, is_primary) VALUES (?,?,?,?,1)')
           ->execute([$bid, 'Alice Novak', 'alice@example.com', '+1 416 555 0111']);
        $db->prepare('INSERT INTO payments(booking_id, method, amount, status, is_mock) VALUES (?,?,?,?,1)')
           ->execute([$bid, $method, round($sub + $tax + $fee, 2), $method === 'property' ? 'pending' : 'paid']);
        $n++;
    }
}

function gen_images(): void {
    $dir = BOOKIFY_ROOT . '/public/assets/img';
    if (!is_dir($dir)) mkdir($dir, 0775, true);
    $palettes = [
        ['#0b3d91','#1fa2c6'], ['#7a1f1f','#e08e45'], ['#5b2340','#e88fb0'],
        ['#1e4d2b','#8fbf6b'], ['#12224a','#3ea0c9'], ['#264653','#84a98c'],
    ];
    foreach ($palettes as $i => [$c1, $c2]) {
        $label = htmlspecialchars('Hotel ' . ($i + 1), ENT_QUOTES);
        $svg = <<<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 520" role="img" aria-label="Hotel placeholder">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="$c1"/><stop offset="1" stop-color="$c2"/>
  </linearGradient></defs>
  <rect width="800" height="520" fill="url(#g)"/>
  <g fill="#ffffff" opacity=".18">
    <rect x="90" y="220" width="150" height="220" rx="6"/>
    <rect x="270" y="150" width="200" height="290" rx="6"/>
    <rect x="500" y="250" width="150" height="190" rx="6"/>
  </g>
  <g fill="#ffffff" opacity=".35">
    ${array_fill(0, 0, '') ? '' : ''}
    <rect x="110" y="245" width="26" height="26"/><rect x="150" y="245" width="26" height="26"/><rect x="190" y="245" width="26" height="26"/>
    <rect x="295" y="180" width="30" height="30"/><rect x="345" y="180" width="30" height="30"/><rect x="395" y="180" width="30" height="30"/>
    <rect x="295" y="240" width="30" height="30"/><rect x="345" y="240" width="30" height="30"/><rect x="395" y="240" width="30" height="30"/>
    <rect x="525" y="275" width="26" height="26"/><rect x="565" y="275" width="26" height="26"/><rect x="605" y="275" width="26" height="26"/>
  </g>
  <text x="400" y="485" font-family="system-ui, sans-serif" font-size="30" fill="#ffffff"
        text-anchor="middle" opacity=".9">Bookify · $label</text>
</svg>
SVG;
        file_put_contents("$dir/hotel-" . ($i + 1) . "-a.svg", $svg);
        file_put_contents("$dir/hotel-" . ($i + 1) . "-b.svg", str_replace($c2, $c1, str_replace('id="g"', 'id="g"', $svg)));
    }
    $hero = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 700"><defs><linearGradient id="h" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0f2f4f"/><stop offset="1" stop-color="#1a6fb5"/></linearGradient></defs><rect width="1600" height="700" fill="url(#h)"/><circle cx="1300" cy="180" r="120" fill="#ffffff" opacity=".12"/><path d="M0 560 L400 420 L800 540 L1200 400 L1600 500 L1600 700 L0 700 Z" fill="#ffffff" opacity=".10"/></svg>';
    file_put_contents("$dir/hero.svg", $hero);
}
