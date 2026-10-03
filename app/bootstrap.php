<?php
declare(strict_types=1);

define('APP_ROOT', dirname(__DIR__));

function config(): array
{
    static $cfg = null;
    if ($cfg === null) {
        $cfg = require APP_ROOT . '/config.php';
    }
    return $cfg;
}

require __DIR__ . '/db.php';
require __DIR__ . '/security.php';
require __DIR__ . '/auth.php';
require __DIR__ . '/api_handlers.php';
