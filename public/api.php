<?php
require __DIR__ . '/../app/bootstrap.php';
require __DIR__ . '/../app/api_actions.php';

start_app_session();

if ($_SERVER['REQUEST_METHOD'] === 'POST') require_csrf();

try {
    handle($_GET['action'] ?? '');
} catch (PDOException $e) {
    error_log('[bookify] ' . $e->getMessage());
    fail('A database error occurred. Please try again.', 500);
} catch (Throwable $e) {
    error_log('[bookify] ' . $e->getMessage());
    fail('Unexpected server error.', 500);
}
