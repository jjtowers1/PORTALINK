<?php
require_once 'sesion_segura.php';
require_once 'conexion.php';
require_once 'autenticacion_helpers.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder_json(false, 'Método no permitido.', 405);
}

$identificador = trim($_POST['identificador'] ?? '');
$contrasena = $_POST['contrasena'] ?? '';

if ($identificador === '' || $contrasena === '') {
    responder_json(false, 'Escribe tu código de estudiante o correo y contraseña.');
}

if (!empty($_SESSION['usuario_id'])) {
    session_unset();
}

$stmt = $conexion->prepare(
    'SELECT id, nombre, contrasena_hash
     FROM administradores
     WHERE usuario = ? OR correo = ?
     LIMIT 1'
);

if (!$stmt) {
    error_log('Error preparando la búsqueda de administrador: ' . $conexion->error);
    responder_json(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('ss', $identificador, $identificador);

if (!$stmt->execute()) {
    error_log('Error buscando administrador: ' . $stmt->error);
    $stmt->close();
    responder_json(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_result($usuarioId, $nombre, $hash);
$encontrado = $stmt->fetch();
$stmt->close();

if ($encontrado && is_string($hash) && password_verify($contrasena, $hash)) {
    if (!session_regenerate_id(true)) {
        error_log('No se pudo renovar la sesión del administrador.');
        responder_json(false, 'No se pudo iniciar la sesión. Inténtalo de nuevo.', 500);
    }

    session_unset();
    $_SESSION['usuario_id'] = (int) $usuarioId;
    $_SESSION['rol'] = 'admin';
    $_SESSION['usuario_nombre'] = $nombre;
    responder_json(true, 'Inicio de sesión correcto.', 200, [
        'redirect' => 'ADMINISTRADOR.html'
    ]);
}
if ($encontrado) {
    responder_json(false, 'El usuario o la contraseña no son correctos.', 401);
}

if (filter_var($identificador, FILTER_VALIDATE_EMAIL)) {
    $stmt = $conexion->prepare(
        'SELECT id, nombre, contrasena_hash, activo
         FROM psicorientadores WHERE correo = ? LIMIT 1'
    );
} else {
    $stmt = $conexion->prepare(
        'SELECT id, nombre, contrasena_hash, activo
         FROM psicorientadores WHERE usuario = ? LIMIT 1'
    );
}

if (!$stmt) {
    error_log('Error preparando el inicio de sesión: ' . $conexion->error);
    responder_json(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('s', $identificador);

if (!$stmt->execute()) {
    error_log('Error consultando las credenciales: ' . $stmt->error);
    $stmt->close();
    responder_json(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_result($usuarioId, $nombre, $hash, $activo);
$encontrado = $stmt->fetch();
$stmt->close();

if (
    $encontrado &&
    (int) $activo === 1 &&
    is_string($hash) &&
    password_verify($contrasena, $hash)
) {
    if (!session_regenerate_id(true)) {
        error_log('No se pudo renovar la sesión del orientador.');
        responder_json(false, 'No se pudo iniciar la sesión. Inténtalo de nuevo.', 500);
    }

    session_unset();
    $_SESSION['usuario_id'] = (int) $usuarioId;
    $_SESSION['rol'] = 'orientador';
    $_SESSION['usuario_nombre'] = $nombre;
    responder_json(true, 'Inicio de sesión correcto.', 200, [
        'redirect' => 'inicioAdm.html'
    ]);
}
if ($encontrado) {
    responder_json(false, 'El usuario o la contraseña no son correctos.', 401);
}

if (filter_var($identificador, FILTER_VALIDATE_EMAIL)) {
    $stmt = $conexion->prepare(
        'SELECT e.id, e.nombre, e.contrasena_hash,
                COALESCE(a.activo, 1) AS activo
         FROM estudiantes e
         LEFT JOIN estudiantes_activos a ON a.estudiante_id = e.id
         WHERE e.correo = ? LIMIT 1'
    );
} else {
    $stmt = $conexion->prepare(
        'SELECT e.id, e.nombre, e.contrasena_hash,
                COALESCE(a.activo, 1) AS activo
         FROM estudiantes e
         LEFT JOIN estudiantes_activos a ON a.estudiante_id = e.id
         WHERE e.codigo_estudiante = ? LIMIT 1'
    );
}

if (!$stmt) {
    error_log('Error preparando la búsqueda de estudiante: ' . $conexion->error);
    responder_json(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_param('s', $identificador);

if (!$stmt->execute()) {
    error_log('Error buscando estudiante: ' . $stmt->error);
    $stmt->close();
    responder_json(false, 'Error interno. Inténtalo más tarde.', 500);
}

$stmt->bind_result($usuarioId, $nombre, $hash, $activo);
$encontrado = $stmt->fetch();
$stmt->close();

if (
    !$encontrado ||
    (int) $activo !== 1 ||
    !is_string($hash) ||
    !password_verify($contrasena, $hash)
) {
    responder_json(false, 'El código, correo o contraseña no son correctos.', 401);
}

if (!session_regenerate_id(true)) {
    error_log('No se pudo renovar la sesión al iniciar sesión.');
    responder_json(false, 'No se pudo iniciar la sesión. Inténtalo de nuevo.', 500);
}

session_unset();
$_SESSION['usuario_id'] = (int) $usuarioId;
$_SESSION['rol'] = 'estudiante';
$_SESSION['usuario_nombre'] = $nombre;

responder_json(true, 'Inicio de sesión correcto.', 200, [
    'redirect' => 'inicioEstu.html'
]);
?>
