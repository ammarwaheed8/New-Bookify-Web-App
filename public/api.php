<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

start_secure_session();
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

$action = (string) ($_GET['action'] ?? '');
$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');

try {
    handle_api($action, $method);
} catch (ApiException $e) {
    json_err($e->getMessage(), $e->status);
} catch (Throwable $e) {
    error_log('Bookify error: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    json_err('Unexpected server error. Please try again.', 500);
}
