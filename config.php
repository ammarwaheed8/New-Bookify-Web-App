<?php
// Local development config — git-ignored. Copy of config.example.php with real paths.
return [
    'app' => [
        'name'     => 'Bookify',
        'env'      => 'local',
        'base_url' => 'http://localhost:8000',
    ],
    'db' => [
        'path' => __DIR__ . '/database/bookify.sqlite',
    ],
    'session' => [
        'name'     => 'BOOKIFYSESSID',
        'lifetime' => 7200, // seconds of idle timeout
    ],
    'booking' => [
        'currency'    => 'USD',
        'symbol'      => '$',
        'tax_rate'    => 0.12,
        'service_fee' => 15.00,
    ],
    'email' => [
        'driver'                => 'file', // 'file' = log only (local dev), 'mail' = PHP mail()
        'from'                  => 'no-reply@bookify.local',
        'from_name'             => 'Bookify',
        'log_file'              => __DIR__ . '/storage/mail.log',
        'verification_ttl_hours' => 24,
        'reset_ttl_hours'       => 1,
    ],
    'seeds' => [
        'admin_username' => 'admin',
        'admin_password' => 'admin123', // development only — change before production
    ],
];
