<?php
require_once 'conexion.php';
require_once 'autenticacion_helpers.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder_json(false, 'Método no permitido.', 405);
}

$token = trim($_POST['token'] ?? '');
$contrasena = $_POST['contrasena'] ?? '';
$confirmar = $_POST['confirmar_contrasena'] ?? '';

if (!preg_match('/\A[a-f0-9]{64}\z/i', $token)) {
    responder_json(false, 'El enlace no es válido o venció. Solicita uno nuevo.');
}

$valida =
    strlen($contrasena) >= 8 &&
    preg_match('/[a-z]/', $contrasena) === 1 &&
    preg_match('/[A-Z]/', $contrasena) === 1 &&
    preg_match('/[0-9]/', $contrasena) === 1 &&
    preg_match('/[^A-Za-z0-9]/', $contrasena) === 1;

if (!$valida) {
    responder_json(
        false,
        'Usa al menos 8 caracteres, una minúscula, una mayúscula, un número y un símbolo.'
    );
}

if ($contrasena !== $confirmar) {
    responder_json(false, 'Las contraseñas no coinciden.');
}

$transaccionActiva = false;

try {
    preparar_tabla_recuperaciones($conexion);
    $tokenHash = hash('sha256', $token);
    $conexion->begin_transaction();
    $transaccionActiva = true;

    $stmt = $conexion->prepare(
        'SELECT estudiante_id FROM recuperaciones_contrasena
         WHERE token_hash = ? AND expira > NOW()
         LIMIT 1 FOR UPDATE'
    );

    if (!$stmt) {
        throw new RuntimeException('Error preparando la validación del enlace: ' . $conexion->error);
    }

    $stmt->bind_param('s', $tokenHash);

    if (!$stmt->execute()) {
        throw new RuntimeException('Error validando el enlace: ' . $stmt->error);
    }

    $stmt->bind_result($estudianteId);
    $encontrado = $stmt->fetch();
    $stmt->close();

    if (!$encontrado) {
        $conexion->rollback();
        $transaccionActiva = false;
        responder_json(false, 'El enlace no es válido o venció. Solicita uno nuevo.');
    }

    $contrasenaHash = password_hash($contrasena, PASSWORD_DEFAULT);
    $stmt = $conexion->prepare(
        'UPDATE estudiantes SET contrasena_hash = ? WHERE id = ?'
    );

    if (!$stmt) {
        throw new RuntimeException('Error preparando el cambio de contraseña: ' . $conexion->error);
    }

    $stmt->bind_param('si', $contrasenaHash, $estudianteId);

    if (!$stmt->execute() || $stmt->affected_rows !== 1) {
        throw new RuntimeException('No se pudo actualizar la contraseña del estudiante.');
    }

    $stmt->close();

    $stmt = $conexion->prepare(
        'DELETE FROM recuperaciones_contrasena WHERE estudiante_id = ?'
    );

    if (!$stmt) {
        throw new RuntimeException('Error preparando la invalidación de enlaces: ' . $conexion->error);
    }

    $stmt->bind_param('i', $estudianteId);

    if (!$stmt->execute()) {
        throw new RuntimeException('No se pudieron invalidar los enlaces anteriores.');
    }

    $stmt->close();
    $conexion->commit();
    $transaccionActiva = false;

    responder_json(true, 'Tu contraseña se cambió correctamente. Ya puedes iniciar sesión.');
} catch (Throwable $error) {
    if ($transaccionActiva && !$conexion->rollback()) {
        error_log('No se pudo revertir la transacción de recuperación: ' . $conexion->error);
    }
    error_log('Error restableciendo contraseña: ' . $error->getMessage());
    responder_json(false, 'No se pudo cambiar la contraseña. Inténtalo más tarde.', 500);
}
?>
