# PORTALINK

## Requisitos

- PHP con las extensiones `mysqli` y `curl`.
- MariaDB o MySQL, con la base de datos `portalink`.
- Servidor web PHP (no abrir las páginas como archivos locales).

## Configuración

Define las variables de entorno en PowerShell antes de ejecutar PHP o configura valores equivalentes en el servidor web:

- `BREVO_API_KEY`: clave API de Brevo.
- `BREVO_REMITENTE`: correo verificado como remitente en Brevo.
- `PORTALINK_BASE_URL`: URL pública del sitio, por ejemplo `https://portalink.example.com`.

`.env.example` enumera las variables esperadas, pero PHP no carga archivos `.env` automáticamente. No guardes claves reales en ese archivo ni en GitHub.

## Preparar base de datos y administrador inicial

Desde la carpeta del proyecto, configura temporalmente las variables `PORTALINK_ADMIN_USER`, `PORTALINK_ADMIN_EMAIL` y `PORTALINK_ADMIN_PASSWORD`, y ejecuta:

```powershell
php .\instalar_portalink.php
```

La contraseña del administrador requiere al menos 12 caracteres, una mayúscula, una minúscula, un número y un símbolo. El instalador crea las tablas nuevas y el administrador inicial solo si todavía no existe uno.

## Recordatorios de citas

Configura el Programador de tareas de Windows o cron para ejecutar `recordatorios_portalink.php` periódicamente con PHP CLI. El script envía recordatorios para citas aceptadas que ocurren dentro de las próximas 23 a 24 horas.
