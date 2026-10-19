<?php
require_once 'sesion_segura.php';

require_once 'conexion.php';

function volverConError($error) {
    header('Location: registrarse.html?error=' . urlencode($error));
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    volverConError('general');
}

$nombre = trim($_POST['nombre'] ?? '');
$apellidos = trim($_POST['apellidos'] ?? '');
$codigo = trim($_POST['codigo_estudiante'] ?? '');
$grado = trim($_POST['grado'] ?? '');
$fecha = trim($_POST['fecha_nacimiento'] ?? '');
$telefono = trim($_POST['telefono'] ?? '');
$correo = trim($_POST['correo'] ?? '');
$contrasena = $_POST['contrasena'] ?? '';
$confirmarContrasena = $_POST['confirmar_contrasena'] ?? '';

if (
    $nombre === '' ||
    $apellidos === '' ||
    $codigo === '' ||
    $grado === '' ||
    $fecha === '' ||
    $telefono === '' ||
    $correo === '' ||
    $contrasena === '' ||
    $confirmarContrasena === ''
) {
    volverConError('campos');
}

if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
    volverConError('correo');
}

if (
    !isset($_SESSION['correo_verificado']) ||
    !hash_equals((string) $_SESSION['correo_verificado'], $correo)
) {
    volverConError('correo_no_verificado');
}

$contrasenaValida =
    strlen($contrasena) >= 8 &&
    preg_match('/[a-z]/', $contrasena) === 1 &&
    preg_match('/[A-Z]/', $contrasena) === 1 &&
    preg_match('/[0-9]/', $contrasena) === 1 &&
    preg_match('/[^A-Za-z0-9]/', $contrasena) === 1;

if (!$contrasenaValida) {
    volverConError('contrasena');
}

if ($contrasena !== $confirmarContrasena) {
    volverConError('confirmar');
}

$fechaObjeto = DateTime::createFromFormat('!Y-m-d', $fecha);

if (!$fechaObjeto || $fechaObjeto->format('Y-m-d') !== $fecha) {
    volverConError('fecha');
}

$contrasenaHash = password_hash($contrasena, PASSWORD_DEFAULT);

$stmt = $conexion->prepare(
    'INSERT INTO estudiantes
     (nombre, apellidos, codigo_estudiante, grado,
      fecha_nacimiento, telefono, correo, contrasena_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
);

if (!$stmt) {
    error_log('Error preparando registro: ' . $conexion->error);
    $conexion->close();
    volverConError('general');
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
    $contrasenaHash
);

try {
    $stmt->execute();
} catch (mysqli_sql_exception $error) {
    $detalleError = $error->getMessage();
    $codigoError = (int) $error->getCode();

    error_log('Error al registrar estudiante: ' . $detalleError);

    $stmt->close();
    $conexion->close();

    if ($codigoError === 1062) {
        if (strpos($detalleError, 'codigo_estudiante') !== false) {
            volverConError('codigo_duplicado');
        }

        if (strpos($detalleError, 'correo') !== false) {
            volverConError('correo_duplicado');
        }
    }

    volverConError('general');
}

$stmt->close();
$conexion->close();

unset($_SESSION['correo_verificado']);

header('Location: index.html');
exit;
?>