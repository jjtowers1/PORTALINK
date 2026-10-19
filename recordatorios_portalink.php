<?php
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once 'conexion.php';
require_once 'brevo_config.php';
require_once 'autenticacion_helpers.php';

$stmt = $conexion->prepare(
    'SELECT c.id, c.estudiante_id, c.fecha_inicio, c.modalidad,
            e.nombre, e.apellidos, e.correo
     FROM citas c
     INNER JOIN estudiantes e ON e.id = c.estudiante_id
     WHERE c.estado = \'aceptada\'
       AND c.recordatorio_enviado IS NULL
       AND c.fecha_inicio > NOW() + INTERVAL 23 HOUR
       AND c.fecha_inicio <= NOW() + INTERVAL 24 HOUR
     ORDER BY c.fecha_inicio'
);

if (!$stmt || !$stmt->execute()) {
    fwrite(STDERR, "No se pudieron consultar las citas para recordar: " . $conexion->error . "\n");
    exit(1);
}

$citas = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();
$enviados = 0;
$errores = 0;

foreach ($citas as $cita) {
    $fecha = date('d/m/Y \a \l\a\s H:i', strtotime($cita['fecha_inicio']));
    $nombre = trim($cita['nombre'] . ' ' . $cita['apellidos']);

    try {
        enviar_correo_portalink(
            $cita['correo'],
            'Recordatorio de tu cita - PORTALINK',
            'Hola ' . $nombre . ', recuerda tu cita de PORTALINK el ' . $fecha .
            '. Modalidad: ' . $cita['modalidad'] .
            '. Si tienes alguna duda, comunícate con tu psicorientador.'
        );

        $update = $conexion->prepare(
            'UPDATE citas SET recordatorio_enviado = NOW()
             WHERE id = ? AND estado = \'aceptada\' AND recordatorio_enviado IS NULL'
        );

        if (!$update) {
            throw new RuntimeException('No se pudo preparar el registro del recordatorio: ' . $conexion->error);
        }

        $update->bind_param('i', $cita['id']);
        if (!$update->execute() || $update->affected_rows !== 1) {
            throw new RuntimeException('No se pudo registrar el envío del recordatorio: ' . $update->error);
        }
        $update->close();
        $enviados++;
    } catch (Throwable $error) {
        error_log(
            'Error enviando recordatorio de cita ' . $cita['id'] . ': ' .
            $error->getMessage()
        );
        $errores++;
    }
}

echo 'Recordatorios enviados: ' . $enviados . '; errores: ' . $errores . PHP_EOL;
if ($errores > 0) {
    exit(1);
}
?>
