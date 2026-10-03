<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';
require __DIR__ . '/../app/api_actions.php';

boot_session();

$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$body = in_array($method, ['POST', 'PUT', 'PATCH'], true) ? read_body() : [];
$action = (string) ($_GET['action'] ?? $body['action'] ?? '');
$in = array_merge($_GET, $body);
unset($in['action']);

// action => [method, auth level, required permission (admin only)]
$routes = [
    // public / customer
    'bootstrap'           => ['GET',  'public',   null],
    'register'            => ['POST', 'public',   null],
    'verify_email'        => ['POST', 'public',   null],
    'resend_verification' => ['POST', 'public',   null],
    'login'               => ['POST', 'public',   null],
    'hotels'              => ['GET',  'public',   null],
    'hotel_detail'        => ['GET',  'public',   null],
    'admin_login'         => ['POST', 'public',   null],

    // signed-in customer
    'logout'              => ['POST', 'user',     null],
    'me'                  => ['GET',  'user',     null],
    'profile_update'      => ['POST', 'user',     null],
    'change_password'     => ['POST', 'user',     null],
    'my_bookings'         => ['GET',  'user',     null],
    'booking_detail'      => ['GET',  'user',     null],

    // verified customer only
    'book'                => ['POST', 'verified', null],

    // admin panel
    'admin_logout'        => ['POST', 'admin',    null],
    'admin_dashboard'     => ['GET',  'admin',    'dashboard.view'],
    'admin_hotels'        => ['GET',  'admin',    'hotels.view'],
    'admin_hotel'         => ['GET',  'admin',    'hotels.view'],
    'admin_hotel_save'    => ['POST', 'admin',    'hotels.manage'],
    'admin_hotel_status'  => ['POST', 'admin',    'hotels.manage'],
    'admin_hotel_delete'  => ['POST', 'admin',    'hotels.manage'],
    'admin_bookings'      => ['GET',  'admin',    'bookings.view'],
    'admin_booking_status'=> ['POST', 'admin',    'bookings.manage'],
    'admin_users'         => ['GET',  'admin',    'users.view'],
    'admin_user_save'     => ['POST', 'admin',    'users.manage'],
    'admin_user_status'   => ['POST', 'admin',    'users.manage'],
    'admin_user_delete'   => ['POST', 'admin',    'users.manage'],
    'admin_admins'        => ['GET',  'admin',    'admins.view'],
    'admin_admin_save'    => ['POST', 'admin',    'admins.manage'],
    'admin_admin_status'  => ['POST', 'admin',    'admins.manage'],
    'admin_admin_delete'  => ['POST', 'admin',    'admins.manage'],
    'admin_admin_roles'   => ['POST', 'admin',    'roles.manage'],
    'admin_roles'         => ['GET',  'admin',    'roles.manage'],
    'admin_role_permissions' => ['POST', 'admin', 'roles.manage'],
    'admin_audit'         => ['GET',  'admin',    'audit.view'],
];

if ($action === '') {
    fail('Missing API action.', 400);
}
if (!isset($routes[$action])) {
    fail('Unknown API action.', 404);
}

[$requiredMethod, $auth, $permission] = $routes[$action];

if ($method !== $requiredMethod) {
    fail('Method not allowed.', 405);
}
if ($method === 'POST') {
    require_csrf(); // deny by default: every mutation carries a session-bound token
}
if ($auth === 'user') {
    require_login();
} elseif ($auth === 'verified') {
    require_verified();
} elseif ($auth === 'admin') {
    $actor = require_admin();
    if ($permission !== null) {
        require_perm($actor, $permission);
    }
}

$handler = 'action_' . $action;
if (!function_exists($handler)) {
    fail('API action not implemented.', 501);
}
$handler($in);
