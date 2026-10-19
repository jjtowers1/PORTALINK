<?php
$apiKey = getenv('BREVO_API_KEY');
$remitente = getenv('BREVO_REMITENTE');

if ($apiKey === false || trim($apiKey) === '') {
    throw new RuntimeException('Configura la variable de entorno BREVO_API_KEY.');
}

if ($remitente === false || !filter_var($remitente, FILTER_VALIDATE_EMAIL)) {
    throw new RuntimeException('Configura BREVO_REMITENTE con un correo electrónico válido.');
}

define('BREVO_API_KEY', $apiKey);
define('BREVO_REMITENTE', $remitente);
?>