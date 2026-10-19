<?php
require_once 'sesion_segura.php';

require_once 'conexion.php';
require_once 'brevo_config.php';

header('Content-Type: application/json; charset=utf-8');

function responder($estado, $mensaje, $codigo = 400) {
    http_response_code($codigo);
    echo json_encode([
        'success' => $estado,
        'message' => $mensaje
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder(false, 'Método no permitido.', 405);
}

$correo = trim($_POST['correo'] ?? '');

if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
    responder(false, 'Escribe un correo válido.');
}

$stmt = $conexion->prepare(
    'SELECT id FROM estudiantes WHERE correo = ? LIMIT 1'
);

if (!$stmt) {
    error_log('Error preparando consulta: ' . $conexion->error);
    responder(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('s', $correo);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $stmt->close();
    responder(false, 'Este correo ya tiene una cuenta registrada.');
}

$stmt->close();

$ahora = time();

if (
    isset($_SESSION['ultimo_codigo']) &&
    $ahora - $_SESSION['ultimo_codigo'] < 60
) {
    responder(false, 'Espera un minuto antes de solicitar otro código.', 429);
}

if (!function_exists('curl_init')) {
    responder(false, 'El servidor no tiene habilitada la extensión cURL.', 500);
}

$codigo = (string) random_int(100000, 999999);
$hash = password_hash($codigo, PASSWORD_DEFAULT);
$expira = date('Y-m-d H:i:s', $ahora + 600);

$stmt = $conexion->prepare(
    'DELETE FROM verificaciones_correo WHERE correo = ?'
);

if (!$stmt) {
    error_log('Error preparando eliminación: ' . $conexion->error);
    responder(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('s', $correo);

if (!$stmt->execute()) {
    error_log('Error eliminando verificaciones: ' . $stmt->error);
    $stmt->close();
    responder(false, 'No se pudo preparar la verificación.', 500);
}

$stmt->close();

$stmt = $conexion->prepare(
    'INSERT INTO verificaciones_correo
     (correo, codigo_hash, expira, verificado, intentos)
     VALUES (?, ?, ?, 0, 0)'
);

if (!$stmt) {
    error_log('Error preparando inserción: ' . $conexion->error);
    responder(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('sss', $correo, $hash, $expira);

if (!$stmt->execute()) {
    error_log('Error guardando verificación: ' . $stmt->error);
    $stmt->close();
    responder(false, 'No se pudo guardar la verificación.', 500);
}

$idVerificacion = $conexion->insert_id;
$stmt->close();

$datos = [
    'sender' => [
        'name' => 'PORTALINK',
        'email' => BREVO_REMITENTE
    ],
    'to' => [
        ['email' => $correo]
    ],
    'subject' => 'Tu código de verificación - PORTALINK',
    'textContent' =>
        "Tu código de verificación es: $codigo\n\n" .
        "Este código vence en 10 minutos. " .
        "Si no solicitaste este código, ignora este correo."
];

$ch = curl_init('https://api.brevo.com/v3/smtp/email');

curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        'accept: application/json',
        'api-key: ' . BREVO_API_KEY,
        'content-type: application/json'
    ],
    CURLOPT_POSTFIELDS => json_encode($datos),
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 20
]);

$respuesta = curl_exec($ch);
$estadoHTTP = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$errorCurl = curl_error($ch);
curl_close($ch);

if (
    $respuesta === false ||
    $estadoHTTP < 200 ||
    $estadoHTTP >= 300
) {
    error_log(
        'Error de Brevo. HTTP: ' . $estadoHTTP .
        '; cURL: ' . $errorCurl .
        '; respuesta: ' . (is_string($respuesta) ? $respuesta : '')
    );

    $stmt = $conexion->prepare(
        'DELETE FROM verificaciones_correo WHERE id = ?'
    );

    if ($stmt) {
        $stmt->bind_param('i', $idVerificacion);
        $stmt->execute();
        $stmt->close();
    }

    responder(false, 'No se pudo enviar el correo. Inténtalo más tarde.', 502);
}

$_SESSION['ultimo_codigo'] = $ahora;

responder(
    true,
    'Código enviado. Revisa tu bandeja de entrada y la carpeta de spam.',
    200
);
?>