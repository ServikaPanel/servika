<?php
/**
 * Exchanges a short-lived Servika token for phpMyAdmin signon credentials.
 */
declare(strict_types=1);

session_name('pma_signon');
ini_set('session.cookie_path', '/');
// Session hardening, applied before the session is started because PHP reads
// these settings when it opens the session.
//   use_strict_mode: PHP refuses a session id that is not already in its own
//     store, so an attacker cannot fixate an id of their choosing on a victim.
//   cookie_httponly: script cannot read the cookie, so an XSS anywhere on the
//     host cannot lift the sign-on session.
//   cookie_samesite=Lax: a cross-site request carries no cookie, while the
//     top-level redirect Servika itself performs still does.
//   cookie_secure is conditional: forcing it on a plain-HTTP installation would
//     make the browser drop the cookie and sign-on would stop working.
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', '1');
}
session_start();

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    exit('Open phpMyAdmin from Servika.');
}

$token = isset($_POST['t']) ? (string) $_POST['t'] : '';
if (!preg_match('/^[a-f0-9]{16,128}$/', $token)) {
    http_response_code(400);
    exit('Invalid signon token. Open phpMyAdmin from Servika.');
}

$internalToken = trim((string) @file_get_contents('/etc/servika/pma-internal.token'));
if ($internalToken === '') {
    http_response_code(500);
    exit('phpMyAdmin signon is not configured.');
}

$payload = json_encode(['token' => $token], JSON_THROW_ON_ERROR);
$curl = curl_init('http://127.0.0.1:8080/api/v1/internal/pma-redeem');
if ($curl === false) {
    http_response_code(500);
    exit('phpMyAdmin signon could not be initialized.');
}

curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        'X-Internal-Auth: ' . $internalToken,
    ],
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_TIMEOUT => 5,
]);
$response = curl_exec($curl);
$status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
curl_close($curl);

if ($status !== 200 || !is_string($response)) {
    http_response_code(401);
    exit('The signon token could not be redeemed. Open phpMyAdmin from Servika again.');
}

$data = json_decode($response, true);
if (!is_array($data)
    || !is_string($data['username'] ?? null)
    || !is_string($data['password'] ?? null)
    || !is_string($data['db'] ?? null)
) {
    http_response_code(500);
    exit('The signon service returned an invalid response.');
}

session_regenerate_id(true);
$_SESSION['PMA_single_signon_user'] = $data['username'];
$_SESSION['PMA_single_signon_password'] = $data['password'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
$_SESSION['PMA_single_signon_only_db'] = [$data['db']];
session_write_close();

// Land the user on their DATABASE, not the server root. With '/pma/' phpMyAdmin
// opens in SERVER scope, so its Export tab names the file with the server
// template ($cfg['Export']['file_template_server'] = '@SERVER@'): every export
// downloads as "localhost.sql" and which database it holds is lost. Opening in
// database scope makes the template '@DATABASE@' -> "<db>.sql". (only_db already
// locked to one database; the fault was the OPENING scope, not the privileges.)
$target = '/pma/';
if (!empty($data['db'])) {
    // phpMyAdmin 5.x route form.
    $target = '/pma/index.php?route=/database/structure&db=' . rawurlencode($data['db']);
}
header('Location: ' . $target, true, 302);
exit;
