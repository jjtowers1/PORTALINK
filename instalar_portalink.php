<?php
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once 'conexion.php';

$usuario = trim(getenv('PORTALINK_ADMIN_USER') ?: '');
$correo = trim(getenv('PORTALINK_ADMIN_EMAIL') ?: '');
$contrasena = getenv('PORTALINK_ADMIN_PASSWORD');
$adminConfigurado = $usuario !== '' || $correo !== '' || $contrasena !== false;

if ($adminConfigurado && (
    $usuario === '' ||
    !preg_match('/\A[a-zA-Z0-9._-]{3,80}\z/', $usuario) ||
    !filter_var($correo, FILTER_VALIDATE_EMAIL) ||
    $contrasena === false ||
    strlen($contrasena) < 12 ||
    preg_match('/[a-z]/', $contrasena) !== 1 ||
    preg_match('/[A-Z]/', $contrasena) !== 1 ||
    preg_match('/[0-9]/', $contrasena) !== 1 ||
    preg_match('/[^A-Za-z0-9]/', $contrasena) !== 1
)) {
    fwrite(
        STDERR,
        "Configura PORTALINK_ADMIN_USER, PORTALINK_ADMIN_EMAIL y " .
        "PORTALINK_ADMIN_PASSWORD (mínimo 12 caracteres con mayúscula, minúscula, número y símbolo) como variables de entorno.\n"
    );
    exit(1);
}

$tablas = [
    'CREATE TABLE IF NOT EXISTS administradores (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        usuario VARCHAR(80) NOT NULL,
        nombre VARCHAR(150) NOT NULL,
        correo VARCHAR(150) NOT NULL,
        contrasena_hash VARCHAR(255) NOT NULL,
        creado DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY usuario (usuario),
        UNIQUE KEY correo (correo)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS psicorientadores (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        usuario VARCHAR(80) NOT NULL,
        nombre VARCHAR(150) NOT NULL,
        correo VARCHAR(150) NOT NULL,
        contrasena_hash VARCHAR(255) NOT NULL,
        descripcion TEXT NOT NULL,
        foto_url VARCHAR(500) NOT NULL DEFAULT \'\',
        permite_virtual TINYINT(1) NOT NULL DEFAULT 1,
        permite_presencial TINYINT(1) NOT NULL DEFAULT 1,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        creado DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY usuario (usuario),
        UNIQUE KEY correo (correo),
        KEY activo (activo)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS psicorientador_grados (
        psicorientador_id INT UNSIGNED NOT NULL,
        grado VARCHAR(20) NOT NULL,
        PRIMARY KEY (psicorientador_id, grado),
        KEY grado (grado)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS estudiantes_activos (
        estudiante_id BIGINT UNSIGNED NOT NULL,
        activo TINYINT(1) NOT NULL DEFAULT 1,
        actualizado DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (estudiante_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
    'CREATE TABLE IF NOT EXISTS citas (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        estudiante_id BIGINT UNSIGNED NOT NULL,
        psicorientador_id INT UNSIGNED NOT NULL,
        fecha_inicio DATETIME NOT NULL,
        modalidad ENUM(\'virtual\', \'presencial\') NOT NULL,
        motivo VARCHAR(2000) NOT NULL,
        estado ENUM(\'pendiente\', \'aceptada\', \'rechazada\', \'realizada\')
            NOT NULL DEFAULT \'pendiente\',
        descargo_privado TEXT NULL,
        recordatorio_enviado DATETIME NULL,
        creado DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY estudiante_id (estudiante_id),
        KEY psicorientador_id (psicorientador_id),
        KEY fecha_estado (fecha_inicio, estado),
        KEY recordatorio (recordatorio_enviado, estado)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
];

foreach ($tablas as $sql) {
    if (!$conexion->query($sql)) {
        fwrite(STDERR, "No se pudo crear una tabla: " . $conexion->error . "\n");
        exit(1);
    }
}

if (!$adminConfigurado) {
    echo "Tablas PORTALINK instaladas. Define las variables de entorno del administrador y vuelve a ejecutar este instalador para crear la cuenta inicial.\n";
    exit(0);
}

$resultadoAdmin = $conexion->query('SELECT COUNT(*) AS total FROM administradores');
if (!$resultadoAdmin) {
    fwrite(STDERR, "No se pudo comprobar el administrador inicial: " . $conexion->error . "\n");
    exit(1);
}
$totalAdmins = (int) $resultadoAdmin->fetch_assoc()['total'];
$resultadoAdmin->free();

if ($totalAdmins === 0) {
    $stmt = $conexion->prepare(
        'INSERT INTO administradores (usuario, nombre, correo, contrasena_hash)
         VALUES (?, ?, ?, ?)'
    );

    if (!$stmt) {
        fwrite(STDERR, "No se pudo preparar el administrador: " . $conexion->error . "\n");
        exit(1);
    }

    $nombre = 'Administrador';
    $hash = password_hash($contrasena, PASSWORD_DEFAULT);
    $stmt->bind_param('ssss', $usuario, $nombre, $correo, $hash);

    if (!$stmt->execute()) {
        fwrite(STDERR, "No se pudo guardar el administrador: " . $stmt->error . "\n");
        exit(1);
    }

    $stmt->close();
    echo "PORTALINK instalado y el administrador inicial quedó configurado.\n";
} else {
    echo "Las tablas están listas. El administrador existente no fue modificado.\n";
}
?>
