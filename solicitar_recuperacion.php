<?php
require_once 'conexion.php';
require_once 'brevo_config.php';
require_once 'autenticacion_helpers.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder_json(false, 'Método no permitido.', 405);
}

$correo = trim($_POST['correo'] ?? '');

if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
    responder_json(false, 'Escribe un correo electrónico válido.');
}

try {
    preparar_tabla_recuperaciones($conexion);

    $stmt = $conexion->prepare(
        'SELECT id FROM estudiantes WHERE correo = ? LIMIT 1'
    );

    if (!$stmt) {
        throw new RuntimeException('Error preparando la búsqueda de cuenta: ' . $conexion->error);
    }

    $stmt->bind_param('s', $correo);

    if (!$stmt->execute()) {
        throw new RuntimeException('Error buscando la cuenta: ' . $stmt->error);
    }

    $stmt->bind_result($estudianteId);
    $existe = $stmt->fetch();
    $stmt->close();

    if (!$existe) {
        responder_json(
            true,
            'Si el correo corresponde a una cuenta, recibirás un enlace para restablecer tu contraseña.'
        );
    }

    $resultadoLimpieza = $conexion->query(
        'DELETE FROM recuperaciones_contrasena WHERE expira <= NOW()'
    );

    if (!$resultadoLimpieza) {
        throw new RuntimeException('Error limpiando enlaces vencidos: ' . $conexion->error);
    }

    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);
    $stmt = $conexion->prepare(
        'INSERT INTO recuperaciones_contrasena (estudiante_id, token_hash, expira)
         VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))'
    );

    if (!$stmt) {
        throw new RuntimeException('Error preparando el enlace: ' . $conexion->error);
    }

    $stmt->bind_param('is', $estudianteId, $tokenHash);

    if (!$stmt->execute()) {
        throw new RuntimeException('Error guardando el enlace: ' . $stmt->error);
    }

    $stmt->close();

    $enlace = url_base_portalink() . '/restaurarContraseña.html?token=' . rawurlencode($token);
    $enlaceHtml = htmlspecialchars($enlace, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $datos = [
        'sender' => [
            'name' => 'PORTALINK',
            'email' => BREVO_REMITENTE
        ],
        'to' => [
            ['email' => $correo]
        ],
        'subject' => 'Restablece tu contraseña - PORTALINK',
        'textContent' =>
            "Recibimos una solicitud para restablecer tu contraseña.\n\n" .
            "Abre este enlace para crear una nueva contraseña:\n$enlace\n\n" .
            "El enlace vence en una hora. Si no solicitaste este cambio, ignora este correo.",
        'htmlContent' =>
            '<p>Recibimos una solicitud para restablecer tu contraseña.</p>' .
            '<p><a href="' . $enlaceHtml . '">Crear una nueva contraseña</a></p>' .
            '<p>El enlace vence en una hora. Si no solicitaste este cambio, ignora este correo.</p>'
    ];

    if (!function_exists('curl_init')) {
        throw new RuntimeException('El servidor no tiene habilitada la extensión cURL.');
    }

    $ch = curl_init('https://api.brevo.com/v3/smtp/email');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'accept: application/json',
            'api-key: ' . BREVO_API_KEY,
            'content-type: application/json'
        ],
        CURLOPT_POSTFIELDS => json_encode($datos, JSON_UNESCAPED_UNICODE),
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20
    ]);

    $respuesta = curl_exec($ch);
    $estadoHTTP = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errorCurl = curl_error($ch);
    curl_close($ch);

    if ($respuesta === false || $estadoHTTP < 200 || $estadoHTTP >= 300) {
        throw new RuntimeException(
            'Error de Brevo. HTTP: ' . $estadoHTTP .
            '; cURL: ' . $errorCurl .
            '; respuesta: ' . (is_string($respuesta) ? $respuesta : '')
        );
    }

    responder_json(
        true,
        'Si el correo corresponde a una cuenta, recibirás un enlace para restablecer tu contraseña.'
    );
} catch (Throwable $error) {
    error_log('Error en solicitud de recuperación: ' . $error->getMessage());

    if (isset($tokenHash)) {
        $stmt = $conexion->prepare(
            'DELETE FROM recuperaciones_contrasena WHERE token_hash = ?'
        );
        if ($stmt) {
            $stmt->bind_param('s', $tokenHash);
            if (!$stmt->execute()) {
                error_log('No se pudo eliminar el enlace fallido: ' . $stmt->error);
            }
            $stmt->close();
        } else {
            error_log('No se pudo preparar la eliminación del enlace fallido: ' . $conexion->error);
        }
    }

    responder_json(false, 'No se pudo enviar el enlace. Inténtalo más tarde.', 502);
}
?>
