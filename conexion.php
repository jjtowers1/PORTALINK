<?php
$servidor = "localhost";
$usuario = "root";
$contrasena = "";
$base_datos = "portalink";

$conexion = new mysqli(
    $servidor,
    $usuario,
    $contrasena,
    $base_datos
);

if ($conexion->connect_error) {
    error_log("Error de conexión: " . $conexion->connect_error);
    http_response_code(500);
    exit("No se pudo conectar con la base de datos.");
}

$conexion->set_charset("utf8mb4");
?>