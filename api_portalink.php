<?php
require_once 'sesion_segura.php';
require_once 'conexion.php';
require_once 'brevo_config.php';
require_once 'autenticacion_helpers.php';

header('Cache-Control: no-store');

function api_datos_stmt($stmt) {
    $resultado = $stmt->get_result();

    if (!$resultado) {
        throw new RuntimeException('No se pudieron leer los datos solicitados.');
    }

    $filas = $resultado->fetch_all(MYSQLI_ASSOC);
    $resultado->free();
    return $filas;
}

function api_validar_texto($valor, $maximo, $campo) {
    if (!is_string($valor)) {
        responder_json(false, 'El campo ' . $campo . ' no es válido.');
    }

    $valor = trim($valor);

    $longitud = function_exists('mb_strlen')
        ? mb_strlen($valor, 'UTF-8')
        : strlen($valor);

    if ($valor === '' || $longitud > $maximo) {
        responder_json(false, 'El campo ' . $campo . ' es obligatorio y no puede exceder ' . $maximo . ' caracteres.');
    }

    return $valor;
}

function api_obtener_grados($grados) {
    if (!is_array($grados) || count($grados) === 0) {
        responder_json(false, 'Selecciona al menos un grado para el orientador.');
    }

    $limpios = [];
    foreach ($grados as $grado) {
        if (!is_string($grado)) {
            responder_json(false, 'Uno de los grados seleccionados no es válido.');
        }
        $grado = trim($grado);
        $longitud = function_exists('mb_strlen')
            ? mb_strlen($grado, 'UTF-8')
            : strlen($grado);
        if ($grado !== '' && $longitud <= 20) {
            $limpios[$grado] = $grado;
        }
    }

    if (count($limpios) === 0) {
        responder_json(false, 'Selecciona al menos un grado válido.');
    }

    return array_values($limpios);
}

function api_enviar_estudiante($conexion, $estudianteId, $asunto, $texto) {
    $stmt = $conexion->prepare('SELECT correo FROM estudiantes WHERE id = ? LIMIT 1');
    if (!$stmt) {
        throw new RuntimeException('Error buscando el correo del estudiante: ' . $conexion->error);
    }
    $stmt->bind_param('i', $estudianteId);
    if (!$stmt->execute()) {
        throw new RuntimeException('Error leyendo el correo del estudiante: ' . $stmt->error);
    }
    $stmt->bind_result($correo);
    $encontrado = $stmt->fetch();
    $stmt->close();
    if (!$encontrado) {
        throw new RuntimeException('No se encontró el correo del estudiante.');
    }
    enviar_correo_portalink($correo, $asunto, $texto);
}

function api_validar_cuenta_activa($conexion) {
    if ($_SESSION['rol'] === 'admin') {
        $stmt = $conexion->prepare('SELECT id FROM administradores WHERE id = ? LIMIT 1');
    } elseif ($_SESSION['rol'] === 'orientador') {
        $stmt = $conexion->prepare(
            'SELECT id FROM psicorientadores WHERE id = ? AND activo = 1 LIMIT 1'
        );
    } else {
        $stmt = $conexion->prepare(
            'SELECT e.id FROM estudiantes e
             LEFT JOIN estudiantes_activos a ON a.estudiante_id = e.id
             WHERE e.id = ? AND COALESCE(a.activo, 1) = 1 LIMIT 1'
        );
    }

    if (!$stmt) {
        error_log('Error preparando la comprobación de estado: ' . $conexion->error);
        responder_json(false, 'No se pudo validar la cuenta. Inténtalo de nuevo.', 500);
    }

    $stmt->bind_param('i', $_SESSION['usuario_id']);
    if (!$stmt->execute()) {
        error_log('Error comprobando el estado de la cuenta: ' . $conexion->error);
        responder_json(false, 'No se pudo validar la cuenta. Inténtalo de nuevo.', 500);
    }

    $stmt->store_result();
    $activa = $stmt->num_rows === 1;
    $stmt->close();
    if (!$activa) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $parametros = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $parametros['path'],
                $parametros['domain'],
                $parametros['secure'],
                $parametros['httponly']
            );
        }
        session_destroy();
        responder_json(false, 'La cuenta está inactiva o ya no existe.', 403);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    autenticar_rol(['admin', 'orientador', 'estudiante']);
    api_validar_cuenta_activa($conexion);
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    responder_json(true, 'Sesión activa.', 200, [
        'rol' => $_SESSION['rol'],
        'nombre' => $_SESSION['usuario_nombre'],
        'csrf' => $_SESSION['csrf_token']
    ]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder_json(false, 'Método no permitido.', 405);
}

autenticar_rol(['admin', 'orientador', 'estudiante']);
api_validar_cuenta_activa($conexion);
validar_csrf();
$entrada = json_decode(file_get_contents('php://input'), true);

if (!is_array($entrada) || !isset($entrada['accion']) || !is_string($entrada['accion'])) {
    responder_json(false, 'La solicitud no contiene una acción válida.');
}

if ($entrada['accion'] === 'cerrar_sesion') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $parametros = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $parametros['path'],
            $parametros['domain'],
            $parametros['secure'],
            $parametros['httponly']
        );
    }
    session_destroy();
    responder_json(true, 'Sesión cerrada.');
}

try {
    switch ($entrada['accion']) {
        case 'datos_panel':
            if ($_SESSION['rol'] === 'estudiante') {
                $stmt = $conexion->prepare(
                    'SELECT grado, nombre, apellidos
                     FROM estudiantes
                     WHERE id = ? LIMIT 1'
                );
                $stmt->bind_param('i', $_SESSION['usuario_id']);
                if (!$stmt->execute()) {
                    throw new RuntimeException('No se pudo cargar el perfil del estudiante.');
                }
                $perfil = api_datos_stmt($stmt);
                $stmt->close();
                if (!$perfil) {
                    responder_json(false, 'No se encontró el perfil del estudiante.', 404);
                }

                $stmt = $conexion->prepare(
                    'SELECT p.id, p.nombre, p.descripcion, p.foto_url,
                            p.permite_virtual, p.permite_presencial
                     FROM psicorientadores p
                     INNER JOIN psicorientador_grados g
                        ON g.psicorientador_id = p.id
                     WHERE p.activo = 1 AND g.grado = ?
                     ORDER BY p.nombre'
                );
                $stmt->bind_param('s', $perfil[0]['grado']);
                if (!$stmt->execute()) {
                    throw new RuntimeException('No se pudieron cargar los orientadores.');
                }
                $orientadores = api_datos_stmt($stmt);
                $stmt->close();

                $stmt = $conexion->prepare(
                    'SELECT c.id, c.fecha_inicio, c.modalidad, c.motivo, c.estado,
                            p.nombre AS orientador
                     FROM citas c
                     INNER JOIN psicorientadores p ON p.id = c.psicorientador_id
                     WHERE c.estudiante_id = ?
                     ORDER BY c.fecha_inicio DESC LIMIT 30'
                );
                $stmt->bind_param('i', $_SESSION['usuario_id']);
                if (!$stmt->execute()) {
                    throw new RuntimeException('No se pudieron cargar tus citas.');
                }
                $citas = api_datos_stmt($stmt);
                $stmt->close();

                responder_json(true, 'Datos cargados.', 200, [
                    'perfil' => $perfil[0],
                    'orientadores' => $orientadores,
                    'citas' => $citas
                ]);
            }

            if ($_SESSION['rol'] === 'orientador') {
                $stmt = $conexion->prepare(
                    'SELECT c.id, c.estudiante_id, c.fecha_inicio, c.modalidad,
                            c.motivo, c.estado, c.descargo_privado,
                            e.nombre AS estudiante_nombre, e.apellidos,
                            e.correo AS estudiante_correo
                     FROM citas c
                     INNER JOIN estudiantes e ON e.id = c.estudiante_id
                     WHERE c.psicorientador_id = ?
                     ORDER BY c.fecha_inicio DESC LIMIT 250'
                );
                $stmt->bind_param('i', $_SESSION['usuario_id']);
                if (!$stmt->execute()) {
                    throw new RuntimeException('No se pudieron cargar las citas del orientador.');
                }
                $citas = api_datos_stmt($stmt);
                $stmt->close();
                responder_json(true, 'Citas cargadas.', 200, ['citas' => $citas]);
            }

            $stmt = $conexion->prepare(
                'SELECT e.id, e.nombre, e.apellidos, e.codigo_estudiante,
                        e.correo, e.grado, e.telefono, e.fecha_nacimiento,
                        COALESCE(a.activo, 1) AS activo
                 FROM estudiantes e
                 LEFT JOIN estudiantes_activos a ON a.estudiante_id = e.id
                 ORDER BY e.apellidos, e.nombre'
            );
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudieron cargar los estudiantes.');
            }
            $estudiantes = api_datos_stmt($stmt);
            $stmt->close();

            $stmt = $conexion->prepare(
                'SELECT p.id, p.usuario, p.nombre, p.correo, p.descripcion,
                        p.foto_url, p.permite_virtual, p.permite_presencial,
                        p.activo, GROUP_CONCAT(g.grado ORDER BY g.grado SEPARATOR \',\')
                            AS grados
                 FROM psicorientadores p
                 LEFT JOIN psicorientador_grados g ON g.psicorientador_id = p.id
                 GROUP BY p.id
                 ORDER BY p.nombre'
            );
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudieron cargar los orientadores.');
            }
            $orientadores = api_datos_stmt($stmt);
            $stmt->close();

            $stmt = $conexion->prepare(
                'SELECT c.id, c.fecha_inicio, c.modalidad, c.estado,
                        e.nombre AS estudiante_nombre, e.apellidos,
                        p.nombre AS orientador_nombre
                 FROM citas c
                 INNER JOIN estudiantes e ON e.id = c.estudiante_id
                 INNER JOIN psicorientadores p ON p.id = c.psicorientador_id
                 ORDER BY c.fecha_inicio DESC LIMIT 300'
            );
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo cargar el resumen de citas.');
            }
            $citas = api_datos_stmt($stmt);
            $stmt->close();

            responder_json(true, 'Datos cargados.', 200, [
                'estudiantes' => $estudiantes,
                'orientadores' => $orientadores,
                'citas' => $citas
            ]);

        case 'crear_cita':
            autenticar_rol(['estudiante']);
            $orientadorId = filter_var($entrada['orientador_id'] ?? null, FILTER_VALIDATE_INT);
            $fecha = $entrada['fecha_inicio'] ?? '';
            $modalidad = $entrada['modalidad'] ?? '';
            $motivo = api_validar_texto($entrada['motivo'] ?? null, 2000, 'motivo');

            if (!$orientadorId || !is_string($fecha) || !in_array($modalidad, ['virtual', 'presencial'], true)) {
                responder_json(false, 'Completa correctamente los datos de la cita.');
            }

            $fechaObjeto = DateTime::createFromFormat('!Y-m-d\TH:i', $fecha);
            if (
                !$fechaObjeto ||
                $fechaObjeto->format('Y-m-d\TH:i') !== $fecha ||
                $fechaObjeto->getTimestamp() < time() + 3600
            ) {
                responder_json(false, 'Elige una fecha futura, con al menos una hora de anticipación.');
            }

            $stmt = $conexion->prepare(
                'SELECT e.grado, COALESCE(a.activo, 1)
                 FROM estudiantes e
                 LEFT JOIN estudiantes_activos a ON a.estudiante_id = e.id
                 WHERE e.id = ? LIMIT 1'
            );
            $stmt->bind_param('i', $_SESSION['usuario_id']);
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo validar el perfil del estudiante.');
            }
            $stmt->bind_result($gradoEstudiante, $estudianteActivo);
            $perfilExiste = $stmt->fetch();
            $stmt->close();
            if (!$perfilExiste || (int) $estudianteActivo !== 1) {
                responder_json(false, 'La cuenta de estudiante está inactiva.', 403);
            }

            $columnaModalidad = $modalidad === 'virtual'
                ? 'permite_virtual'
                : 'permite_presencial';
            $sql = 'SELECT p.correo FROM psicorientadores p
                    INNER JOIN psicorientador_grados g ON g.psicorientador_id = p.id
                    WHERE p.id = ? AND p.activo = 1 AND g.grado = ?
                    AND p.' . $columnaModalidad . ' = 1 LIMIT 1';
            $stmt = $conexion->prepare($sql);
            $stmt->bind_param('is', $orientadorId, $gradoEstudiante);
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo validar el orientador seleccionado.');
            }
            $stmt->bind_result($correoOrientador);
            $orientadorValido = $stmt->fetch();
            $stmt->close();
            if (!$orientadorValido) {
                responder_json(false, 'Ese orientador no está disponible para tu grado o modalidad.');
            }

            $fechaSql = str_replace('T', ' ', $fecha) . ':00';
            $conexion->begin_transaction();
            $stmt = $conexion->prepare(
                'SELECT id FROM psicorientadores WHERE id = ? AND activo = 1 FOR UPDATE'
            );
            if (!$stmt) {
                $conexion->rollback();
                throw new RuntimeException('No se pudo bloquear el horario del orientador.');
            }
            $stmt->bind_param('i', $orientadorId);
            if (!$stmt->execute()) {
                $stmt->close();
                $conexion->rollback();
                throw new RuntimeException('No se pudo bloquear el horario del orientador.');
            }
            $stmt->store_result();
            if ($stmt->num_rows !== 1) {
                $stmt->close();
                $conexion->rollback();
                responder_json(false, 'El orientador ya no está disponible.');
            }
            $stmt->close();

            $stmt = $conexion->prepare(
                'SELECT id FROM citas
                 WHERE psicorientador_id = ? AND fecha_inicio = ?
                 AND estado IN (\'pendiente\', \'aceptada\')
                 LIMIT 1 FOR UPDATE'
            );
            $stmt->bind_param('is', $orientadorId, $fechaSql);
            if (!$stmt->execute()) {
                $conexion->rollback();
                throw new RuntimeException('No se pudo verificar la disponibilidad.');
            }
            $stmt->store_result();
            if ($stmt->num_rows > 0) {
                $stmt->close();
                $conexion->rollback();
                responder_json(false, 'Ese horario ya está ocupado. Elige otro horario.');
            }
            $stmt->close();

            $stmt = $conexion->prepare(
                'INSERT INTO citas
                 (estudiante_id, psicorientador_id, fecha_inicio, modalidad, motivo)
                 VALUES (?, ?, ?, ?, ?)'
            );
            $stmt->bind_param(
                'iisss',
                $_SESSION['usuario_id'],
                $orientadorId,
                $fechaSql,
                $modalidad,
                $motivo
            );
            if (!$stmt->execute()) {
                $conexion->rollback();
                throw new RuntimeException('No se pudo guardar la solicitud de cita: ' . $stmt->error);
            }
            $stmt->close();
            $conexion->commit();

            $fechaLegible = $fechaObjeto->format('d/m/Y \a \l\a\s H:i');
            try {
                enviar_correo_portalink(
                    $correoOrientador,
                    'Nueva solicitud de cita - PORTALINK',
                    'Tienes una nueva solicitud de cita para el ' . $fechaLegible .
                    ' (' . $modalidad . '). Ingresa a PORTALINK para revisarla.'
                );
            } catch (Throwable $errorCorreo) {
                error_log('No se pudo avisar al orientador sobre la nueva cita: ' . $errorCorreo->getMessage());
                responder_json(
                    true,
                    'La solicitud quedó guardada, pero no se pudo avisar al orientador por correo.',
                    200,
                    ['email_sent' => false]
                );
            }

            responder_json(
                true,
                'La solicitud se envió correctamente. El orientador debe confirmarla.',
                200,
                ['email_sent' => true]
            );

        case 'decidir_cita':
            autenticar_rol(['orientador']);
            $citaId = filter_var($entrada['cita_id'] ?? null, FILTER_VALIDATE_INT);
            $decision = $entrada['decision'] ?? '';
            if (!$citaId || !in_array($decision, ['aceptada', 'rechazada'], true)) {
                responder_json(false, 'La decisión de la cita no es válida.');
            }
            $stmt = $conexion->prepare(
                'SELECT estudiante_id, fecha_inicio, estado
                 FROM citas
                 WHERE id = ? AND psicorientador_id = ? LIMIT 1'
            );
            $stmt->bind_param('ii', $citaId, $_SESSION['usuario_id']);
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo consultar la cita.');
            }
            $stmt->bind_result($estudianteId, $fechaInicio, $estadoActual);
            $existeCita = $stmt->fetch();
            $stmt->close();
            if (!$existeCita || $estadoActual !== 'pendiente') {
                responder_json(false, 'La cita ya fue procesada o no te pertenece.');
            }
            $stmt = $conexion->prepare(
                'UPDATE citas SET estado = ?
                 WHERE id = ? AND psicorientador_id = ? AND estado = \'pendiente\''
            );
            $stmt->bind_param('sii', $decision, $citaId, $_SESSION['usuario_id']);
            if (!$stmt->execute() || $stmt->affected_rows !== 1) {
                throw new RuntimeException('No se pudo actualizar el estado de la cita.');
            }
            $stmt->close();
            $fechaLegible = date('d/m/Y \a \l\a\s H:i', strtotime($fechaInicio));
            try {
                api_enviar_estudiante(
                    $conexion,
                    $estudianteId,
                    'Actualización de tu cita - PORTALINK',
                    'Tu solicitud de cita para el ' . $fechaLegible .
                    ' fue ' . $decision . '. Ingresa a PORTALINK para consultar los detalles.'
                );
            } catch (Throwable $errorCorreo) {
                error_log('La cita cambió de estado, pero no se pudo avisar al estudiante: ' . $errorCorreo->getMessage());
                responder_json(
                    true,
                    'La cita se actualizó, pero no se pudo enviar el correo al estudiante. Revisa el correo del estudiante e inténtalo más tarde.',
                    200,
                    ['email_sent' => false]
                );
            }
            responder_json(true, 'La cita se actualizó y se notificó al estudiante.', 200, [
                'email_sent' => true
            ]);

        case 'guardar_descargo':
            autenticar_rol(['orientador']);
            $citaId = filter_var($entrada['cita_id'] ?? null, FILTER_VALIDATE_INT);
            $descargo = api_validar_texto($entrada['descargo'] ?? null, 10000, 'descargo');
            if (!$citaId) {
                responder_json(false, 'La cita indicada no es válida.');
            }
            $stmt = $conexion->prepare(
                'UPDATE citas SET descargo_privado = ?, estado = \'realizada\'
                 WHERE id = ? AND psicorientador_id = ?
                 AND estado IN (\'aceptada\', \'realizada\')
                 AND fecha_inicio <= NOW()'
            );
            $stmt->bind_param('sii', $descargo, $citaId, $_SESSION['usuario_id']);
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo guardar el descargo: ' . $stmt->error);
            }
            $actualizadas = $stmt->affected_rows;
            $stmt->close();
            if ($actualizadas !== 1) {
                responder_json(false, 'Solo puedes registrar el descargo de una cita aceptada que te pertenece.');
            }
            responder_json(true, 'El descargo privado se guardó correctamente.');

        case 'guardar_orientador':
            autenticar_rol(['admin']);
            $id = filter_var($entrada['id'] ?? 0, FILTER_VALIDATE_INT);
            $usuario = api_validar_texto($entrada['usuario'] ?? null, 80, 'usuario');
            $nombre = api_validar_texto($entrada['nombre'] ?? null, 150, 'nombre');
            $correo = api_validar_texto($entrada['correo'] ?? null, 150, 'correo');
            $descripcion = api_validar_texto($entrada['descripcion'] ?? null, 5000, 'descripción');
            $foto = isset($entrada['foto_url']) && is_string($entrada['foto_url'])
                ? trim($entrada['foto_url'])
                : '';
            $grados = api_obtener_grados($entrada['grados'] ?? null);
            $virtual = !empty($entrada['permite_virtual']) ? 1 : 0;
            $presencial = !empty($entrada['permite_presencial']) ? 1 : 0;
            $password = $entrada['contrasena'] ?? '';

            if (!preg_match('/\A[a-zA-Z0-9._-]{3,80}\z/', $usuario)) {
                responder_json(false, 'El usuario debe tener entre 3 y 80 caracteres (letras, números, punto, guion o guion bajo).');
            }
            if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
                responder_json(false, 'Escribe un correo válido para el orientador.');
            }
            $partesFoto = $foto !== '' ? parse_url($foto) : [];
            if (
                $foto !== '' &&
                (
                    !filter_var($foto, FILTER_VALIDATE_URL) ||
                    !is_array($partesFoto) ||
                    ($partesFoto['scheme'] ?? '') !== 'https'
                )
            ) {
                responder_json(false, 'La foto debe usar una URL https válida o dejarse vacía.');
            }
            if (!$virtual && !$presencial) {
                responder_json(false, 'Activa al menos una modalidad de atención.');
            }

            $conexion->begin_transaction();
            if ($id) {
                $stmt = $conexion->prepare(
                    'UPDATE psicorientadores SET usuario = ?, nombre = ?, correo = ?,
                     descripcion = ?, foto_url = ?, permite_virtual = ?,
                     permite_presencial = ? WHERE id = ?'
                );
                $stmt->bind_param(
                    'sssssiii',
                    $usuario,
                    $nombre,
                    $correo,
                    $descripcion,
                    $foto,
                    $virtual,
                    $presencial,
                    $id
                );
                if (!$stmt->execute()) {
                    $conexion->rollback();
                    responder_json(false, 'No se pudo actualizar el orientador. Revisa si el usuario o correo ya existen.');
                }
                $stmt->close();
                if ($password !== '') {
                    if (
                        !is_string($password) ||
                        strlen($password) < 12 ||
                        preg_match('/[a-z]/', $password) !== 1 ||
                        preg_match('/[A-Z]/', $password) !== 1 ||
                        preg_match('/[0-9]/', $password) !== 1 ||
                        preg_match('/[^A-Za-z0-9]/', $password) !== 1
                    ) {
                        $conexion->rollback();
                        responder_json(false, 'La nueva contraseña del orientador debe tener 12 caracteres, mayúscula, minúscula, número y símbolo.');
                    }
                    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $conexion->prepare(
                        'UPDATE psicorientadores SET contrasena_hash = ? WHERE id = ?'
                    );
                    $stmt->bind_param('si', $passwordHash, $id);
                    if (!$stmt->execute()) {
                        $conexion->rollback();
                        throw new RuntimeException('No se pudo actualizar la contraseña del orientador.');
                    }
                    $stmt->close();
                }
            } else {
                if (
                    !is_string($password) ||
                    strlen($password) < 12 ||
                    preg_match('/[a-z]/', $password) !== 1 ||
                    preg_match('/[A-Z]/', $password) !== 1 ||
                    preg_match('/[0-9]/', $password) !== 1 ||
                    preg_match('/[^A-Za-z0-9]/', $password) !== 1
                ) {
                    $conexion->rollback();
                    responder_json(false, 'La contraseña del orientador debe tener 12 caracteres, mayúscula, minúscula, número y símbolo.');
                }
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $conexion->prepare(
                    'INSERT INTO psicorientadores
                     (usuario, nombre, correo, contrasena_hash, descripcion,
                      foto_url, permite_virtual, permite_presencial)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
                );
                $stmt->bind_param(
                    'ssssssii',
                    $usuario,
                    $nombre,
                    $correo,
                    $passwordHash,
                    $descripcion,
                    $foto,
                    $virtual,
                    $presencial
                );
                if (!$stmt->execute()) {
                    $conexion->rollback();
                    responder_json(false, 'No se pudo crear el orientador. Revisa si el usuario o correo ya existen.');
                }
                $id = $conexion->insert_id;
                $stmt->close();
            }

            $stmt = $conexion->prepare(
                'DELETE FROM psicorientador_grados WHERE psicorientador_id = ?'
            );
            $stmt->bind_param('i', $id);
            if (!$stmt->execute()) {
                $conexion->rollback();
                throw new RuntimeException('No se pudieron actualizar los grados del orientador.');
            }
            $stmt->close();
            $stmt = $conexion->prepare(
                'INSERT INTO psicorientador_grados (psicorientador_id, grado) VALUES (?, ?)'
            );
            foreach ($grados as $grado) {
                $stmt->bind_param('is', $id, $grado);
                if (!$stmt->execute()) {
                    $stmt->close();
                    $conexion->rollback();
                    throw new RuntimeException('No se pudo guardar un grado del orientador.');
                }
            }
            $stmt->close();
            $conexion->commit();
            responder_json(true, 'Los datos del orientador se guardaron correctamente.');

        case 'estado_orientador':
            autenticar_rol(['admin']);
            $id = filter_var($entrada['id'] ?? null, FILTER_VALIDATE_INT);
            $activo = filter_var($entrada['activo'] ?? null, FILTER_VALIDATE_INT);
            if (!$id || !in_array($activo, [0, 1], true)) {
                responder_json(false, 'La solicitud de estado no es válida.');
            }
            $stmt = $conexion->prepare('UPDATE psicorientadores SET activo = ? WHERE id = ?');
            $stmt->bind_param('ii', $activo, $id);
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo cambiar el estado del orientador.');
            }
            $stmt->close();
            responder_json(true, $activo ? 'Orientador activado.' : 'Orientador desactivado.');

        case 'actualizar_estudiante':
            autenticar_rol(['admin']);
            $id = filter_var($entrada['id'] ?? null, FILTER_VALIDATE_INT);
            $nombre = api_validar_texto($entrada['nombre'] ?? null, 100, 'nombre');
            $apellidos = api_validar_texto($entrada['apellidos'] ?? null, 150, 'apellidos');
            $codigo = api_validar_texto($entrada['codigo_estudiante'] ?? null, 30, 'código');
            $correo = api_validar_texto($entrada['correo'] ?? null, 150, 'correo');
            $grado = api_validar_texto($entrada['grado'] ?? null, 20, 'grado');
            $telefono = api_validar_texto($entrada['telefono'] ?? null, 20, 'teléfono');
            $fecha = api_validar_texto($entrada['fecha_nacimiento'] ?? null, 10, 'fecha de nacimiento');
            $password = $entrada['contrasena'] ?? '';
            if (
                $password !== '' &&
                (
                    !is_string($password) ||
                    strlen($password) < 12 ||
                    preg_match('/[a-z]/', $password) !== 1 ||
                    preg_match('/[A-Z]/', $password) !== 1 ||
                    preg_match('/[0-9]/', $password) !== 1 ||
                    preg_match('/[^A-Za-z0-9]/', $password) !== 1
                )
            ) {
                responder_json(false, 'La nueva contraseña debe tener 12 caracteres, mayúscula, minúscula, número y símbolo.');
            }
            $fechaObjeto = DateTime::createFromFormat('!Y-m-d', $fecha);
            if (
                !$id ||
                !filter_var($correo, FILTER_VALIDATE_EMAIL) ||
                !$fechaObjeto ||
                $fechaObjeto->format('Y-m-d') !== $fecha
            ) {
                responder_json(false, 'Verifica que el correo y la fecha de nacimiento sean válidos.');
            }
            $stmt = $conexion->prepare(
                'UPDATE estudiantes
                 SET nombre = ?, apellidos = ?, codigo_estudiante = ?, correo = ?,
                     grado = ?, telefono = ?, fecha_nacimiento = ?,
                     contrasena_hash = COALESCE(?, contrasena_hash)
                 WHERE id = ?'
            );
            $passwordHash = $password === ''
                ? null
                : password_hash($password, PASSWORD_DEFAULT);
            $stmt->bind_param(
                'ssssssssi',
                $nombre,
                $apellidos,
                $codigo,
                $correo,
                $grado,
                $telefono,
                $fecha,
                $passwordHash,
                $id
            );
            if (!$stmt->execute()) {
                responder_json(false, 'No se pudo actualizar el estudiante. Revisa si el código o correo ya están en uso.');
            }
            $stmt->close();
            responder_json(
                true,
                $password === ''
                    ? 'Los datos del estudiante se actualizaron.'
                    : 'Los datos se actualizaron y la contraseña se cambió sin revelar el valor anterior.'
            );

        case 'crear_estudiante':
            autenticar_rol(['admin']);
            $nombre = api_validar_texto($entrada['nombre'] ?? null, 100, 'nombre');
            $apellidos = api_validar_texto($entrada['apellidos'] ?? null, 150, 'apellidos');
            $codigo = api_validar_texto($entrada['codigo_estudiante'] ?? null, 30, 'código');
            $grado = api_validar_texto($entrada['grado'] ?? null, 20, 'grado');
            $correo = api_validar_texto($entrada['correo'] ?? null, 150, 'correo');
            $telefono = api_validar_texto($entrada['telefono'] ?? null, 20, 'teléfono');
            $fecha = api_validar_texto($entrada['fecha_nacimiento'] ?? null, 10, 'fecha de nacimiento');
            $password = $entrada['contrasena'] ?? '';

            if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
                responder_json(false, 'Escribe un correo válido para el estudiante.');
            }
            $fechaObjeto = DateTime::createFromFormat('!Y-m-d', $fecha);
            if (!$fechaObjeto || $fechaObjeto->format('Y-m-d') !== $fecha) {
                responder_json(false, 'La fecha de nacimiento no es válida.');
            }
            if (
                !is_string($password) ||
                strlen($password) < 12 ||
                preg_match('/[a-z]/', $password) !== 1 ||
                preg_match('/[A-Z]/', $password) !== 1 ||
                preg_match('/[0-9]/', $password) !== 1 ||
                preg_match('/[^A-Za-z0-9]/', $password) !== 1
            ) {
                responder_json(false, 'La contraseña debe tener 12 caracteres, mayúscula, minúscula, número y símbolo.');
            }

            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conexion->prepare(
                'INSERT INTO estudiantes
                 (nombre, apellidos, codigo_estudiante, grado, fecha_nacimiento,
                  telefono, correo, contrasena_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            );
            if (!$stmt) {
                throw new RuntimeException('No se pudo preparar el alta del estudiante: ' . $conexion->error);
            }
            $stmt->bind_param(
                'ssssssss',
                $nombre,
                $apellidos,
                $codigo,
                $grado,
                $fecha,
                $telefono,
                $correo,
                $passwordHash
            );
            if (!$stmt->execute()) {
                if ($stmt->errno === 1062) {
                    $stmt->close();
                    responder_json(false, 'El código o correo ya está asociado a otra cuenta.');
                }
                $error = $stmt->error;
                $stmt->close();
                throw new RuntimeException('No se pudo crear al estudiante: ' . $error);
            }
            $stmt->close();
            responder_json(true, 'La cuenta del estudiante se creó correctamente.');

        case 'estado_estudiante':
            autenticar_rol(['admin']);
            $id = filter_var($entrada['id'] ?? null, FILTER_VALIDATE_INT);
            $activo = filter_var($entrada['activo'] ?? null, FILTER_VALIDATE_INT);
            if (!$id || !in_array($activo, [0, 1], true)) {
                responder_json(false, 'La solicitud de estado no es válida.');
            }
            $stmt = $conexion->prepare(
                'INSERT INTO estudiantes_activos (estudiante_id, activo)
                 VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE activo = VALUES(activo)'
            );
            $stmt->bind_param('ii', $id, $activo);
            if (!$stmt->execute()) {
                throw new RuntimeException('No se pudo cambiar el estado del estudiante.');
            }
            $stmt->close();
            responder_json(true, $activo ? 'Estudiante activado.' : 'Estudiante desactivado.');

        default:
            responder_json(false, 'La acción solicitada no existe.', 400);
    }
} catch (Throwable $error) {
    error_log('Error en api_portalink.php: ' . $error->getMessage());
    responder_json(false, 'No se pudo completar la operación. Inténtalo más tarde.', 500);
}
?>
