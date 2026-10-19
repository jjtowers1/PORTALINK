<?php
require_once 'sesion_segura.php';

require_once 'conexion.php';

header('Content-Type: application/json; charset=utf-8');

function responder($estado, $mensaje, $http = 400) {
    http_response_code($http);
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
$codigo = trim($_POST['codigo_verificacion'] ?? '');

if (
    !filter_var($correo, FILTER_VALIDATE_EMAIL) ||
    !preg_match('/^\d{6}$/', $codigo)
) {
    responder(false, 'Escribe un correo válido y un código de seis dígitos.');
}

$stmt = $conexion->prepare(
    'SELECT id, codigo_hash, expira, intentos
     FROM verificaciones_correo
     WHERE correo = ? AND verificado = 0
     ORDER BY id DESC
     LIMIT 1'
);

if (!$stmt) {
    error_log('Error preparando consulta: ' . $conexion->error);
    responder(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('s', $correo);
$stmt->execute();
$stmt->bind_result($id, $hash, $expira, $intentos);

if (!$stmt->fetch()) {
    $stmt->close();
    responder(false, 'No hay un código pendiente para este correo. Solicita uno nuevo.');
}

$stmt->close();

if (strtotime($expira) < time()) {
    responder(false, 'El código venció. Solicita uno nuevo.');
}

if ((int) $intentos >= 5) {
    responder(false, 'Superaste el límite de intentos. Solicita otro código.', 429);
}

if (!password_verify($codigo, $hash)) {
    $stmt = $conexion->prepare(
        'UPDATE verificaciones_correo
         SET intentos = intentos + 1
         WHERE id = ? AND verificado = 0'
    );

    if ($stmt) {
        $stmt->bind_param('i', $id);
        $stmt->execute();
        $stmt->close();
    }

    responder(false, 'El código no es válido. Revísalo e inténtalo de nuevo.');
}

$stmt = $conexion->prepare(
    'UPDATE verificaciones_correo
     SET verificado = 1
     WHERE id = ? AND verificado = 0 AND expira >= NOW()'
);

if (!$stmt) {
    error_log('Error preparando actualización: ' . $conexion->error);
    responder(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('i', $id);
$stmt->execute();
$actualizados = $stmt->affected_rows;
$stmt->close();

if ($actualizados !== 1) {
    responder(false, 'El código venció o ya fue utilizado. Solicita uno nuevo.');
}

$_SESSION['correo_verificado'] = $correo;

responder(true, 'Correo verificado correctamente.', 200);
?>