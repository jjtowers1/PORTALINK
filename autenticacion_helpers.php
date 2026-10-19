<?php
function responder_json($success, $message, $status = 200, $extra = []) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $extra), JSON_UNESCAPED_UNICODE);
    exit;
}

function autenticar_rol($roles) {
    if (
        empty($_SESSION['usuario_id']) ||
        empty($_SESSION['rol']) ||
        !in_array($_SESSION['rol'], $roles, true)
    ) {
        responder_json(false, 'Inicia sesión con una cuenta autorizada.', 401);
    }
}

function validar_csrf() {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';

    if (
        empty($_SESSION['csrf_token']) ||
        !is_string($token) ||
        !hash_equals($_SESSION['csrf_token'], $token)
    ) {
        responder_json(false, 'La sesión expiró. Recarga la página e inténtalo de nuevo.', 403);
    }
}

function enviar_correo_portalink($destinatario, $asunto, $texto, $html = null) {
    if (!function_exists('curl_init')) {
        throw new RuntimeException('El servidor no tiene habilitada la extensión cURL.');
    }

    $datos = [
        'sender' => [
            'name' => 'PORTALINK',
            'email' => BREVO_REMITENTE
        ],
        'to' => [
            ['email' => $destinatario]
        ],
        'subject' => $asunto,
        'textContent' => $texto
    ];

    if ($html !== null) {
        $datos['htmlContent'] = $html;
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
}

function preparar_tabla_recuperaciones($conexion) {
    $resultado = $conexion->query(
        'CREATE TABLE IF NOT EXISTS recuperaciones_contrasena (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            estudiante_id BIGINT UNSIGNED NOT NULL,
            token_hash CHAR(64) NOT NULL,
            expira DATETIME NOT NULL,
            creado DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY token_hash (token_hash),
            KEY estudiante_id (estudiante_id),
            KEY expira (expira)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
    );

    if (!$resultado) {
        throw new RuntimeException(
            'No se pudo preparar la tabla de recuperación: ' . $conexion->error
        );
    }

}

function url_base_portalink() {
    $configurada = getenv('PORTALINK_BASE_URL');

    if ($configurada !== false && trim($configurada) !== '') {
        $partes = parse_url(trim($configurada));

        if (
            $partes === false ||
            !isset($partes['scheme'], $partes['host']) ||
            !in_array(strtolower($partes['scheme']), ['http', 'https'], true) ||
            isset($partes['query']) ||
            isset($partes['fragment'])
        ) {
            throw new RuntimeException('PORTALINK_BASE_URL no es una URL válida.');
        }

        return rtrim(trim($configurada), '/');
    }

    $host = strtolower($_SERVER['HTTP_HOST'] ?? '');

    if (!preg_match('/\A(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?\z/', $host)) {
        throw new RuntimeException(
            'Configura PORTALINK_BASE_URL con el dominio público del sitio.'
        );
    }

    $https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' &&
        strtolower((string) $_SERVER['HTTPS']) !== 'off';
    $esquema = $https ? 'https' : 'http';
    $directorio = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    $directorio = $directorio === '/' || $directorio === '.' ? '' : '/' . trim($directorio, '/');

    return $esquema . '://' . $host . $directorio;
}
?>
