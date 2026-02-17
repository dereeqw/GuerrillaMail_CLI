# 📧 Guerrilla Mail CLI

Una herramienta de terminal para recibir correos temporales y enviar emails desde proveedores como SendGrid, Gmail u Outlook — todo desde la línea de comandos.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-orange)

---

## ¿Por qué existe esto?

A veces no quieres dar tu email real. A veces necesitas probar un sistema de envío. A veces solo quieres recibir un código de verificación sin llenar tu bandeja de spam.

Esta herramienta combina dos cosas: los emails temporales de [Guerrilla Mail](https://www.guerrillamail.com/) para recibir, y tu propio proveedor SMTP para enviar. El resultado es una especie de buzón desechable con superpoderes.

---

## Lo que puedes hacer

- Crear un email temporal en segundos, sin registrarte
- Personalizar el nombre del buzón (`MiNombre@guerrillamailblock.com`)
- Leer correos entrantes desde la terminal
- Enviar emails usando SendGrid, Gmail, Outlook o cualquier servidor SMTP
- Adjuntar archivos, enviar HTML, hacer envíos a múltiples destinatarios
- Cambiar de proveedor SMTP sin reiniciar nada

---

## Instalación

Necesitas Python 3.8 o superior.

```bash
git clone https://github.com/tuusuario/GuerrillaMail_CLI.git
cd GuerrillaMail_CLI
pip install -r requirements.txt
```

Copia el archivo de configuración y edítalo con tus credenciales:

```bash
cp config.example.json config.json
nano config.json
```

Listo. Ya puedes ejecutarlo:

```bash
python3 GuerrillaMail.py
```

---

## Configuración

Todo vive en `config.json`. Aquí puedes agregar uno o varios proveedores SMTP. El archivo de ejemplo ya incluye plantillas para SendGrid, Gmail, Outlook, Mailgun y más.

### SendGrid (gratis hasta 100 emails/día)

```json
{
  "default_provider": "sendgrid",
  "smtp_providers": {
    "sendgrid": {
      "name": "SendGrid",
      "smtp_host": "smtp.sendgrid.net",
      "smtp_port": 587,
      "use_tls": true,
      "username": "apikey",
      "password": "SG.tu-api-key-aqui",
      "from_email": "tu@email.com",
      "from_name": "Tu Nombre"
    }
  }
}
```

Para conseguir una API key de SendGrid: Settings → API Keys → Create API Key → Mail Send.

### Gmail

Necesitas activar la verificación en 2 pasos y generar un [App Password](https://myaccount.google.com/apppasswords). Usa ese código como contraseña, no tu contraseña normal.

```json
"gmail": {
  "name": "Gmail",
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "use_tls": true,
  "username": "tu@gmail.com",
  "password": "tu-app-password",
  "from_email": "tu@gmail.com",
  "from_name": "Tu Nombre"
}
```

El archivo `config.example.json` tiene plantillas para Outlook, Mailgun, Yahoo, Zoho y servidores personalizados.

---

## Uso básico

```
guerrilla [sin sesion] > create
guerrilla [abc123@guerrillamailblock.com] > custom MiNombre
guerrilla [MiNombre@guerrillamailblock.com] > inbox
guerrilla [MiNombre@guerrillamailblock.com] > read 1
guerrilla [MiNombre@guerrillamailblock.com] > send
```

El prompt siempre muestra qué buzón tienes activo. Los correos se numeran del 1 en adelante para que sea fácil leerlos o borrarlos.

---

## Comandos

| Comando | Descripción |
|---|---|
| `create` | Crear un buzón temporal |
| `custom <nombre>` | Cambiar el nombre del email |
| `inbox` | Ver correos recibidos |
| `refresh` | Buscar correos nuevos |
| `read <n>` | Leer el correo número n |
| `delete <n>` | Borrar el correo número n |
| `send` | Enviar un email |
| `sendhtml` | Enviar email con HTML |
| `sendbulk` | Enviar a varios destinatarios |
| `provider` | Ver o cambiar proveedor SMTP |
| `provider <nombre>` | Cambiar de proveedor al instante |
| `test` | Probar la conexión SMTP |
| `list` | Ver buzones guardados |
| `select <id>` | Activar un buzón guardado |
| `destroy` | Eliminar el buzón actual |
| `!ls`, `!pwd`... | Ejecutar comandos del sistema |
| `help` | Ver todos los comandos |
| `exit` | Salir |

---

## Enviar un email paso a paso

```
> send

Nombre del remitente [Tu Nombre]: Banco Ejemplo
Para: cliente@correo.com
Asunto: Confirma tu cuenta
Contenido: [t]exto / [h]tml inline / [f]ile html? f

Archivos HTML disponibles:
  [1] plantilla.html

Archivo HTML (o Enter para cancelar): 1
✓ HTML cargado: plantilla.html (3.2 KB)

¿Adjuntar archivos? [Si/no]: no

De: Banco Ejemplo <tu@email.com>
Para: cliente@correo.com
Asunto: Confirma tu cuenta

¿Enviar? [Si/no]: si
[+] Email enviado
```

---

## Un detalle importante

**No subas `config.json` a GitHub.** El archivo ya está incluido en `.gitignore`, así que no debería pasar, pero vale la pena saberlo. Ahí están tus contraseñas y API keys.

Si usas SendGrid, genera una API key con permisos mínimos (solo Mail Send). Si en algún momento crees que una clave se expuso, revócala desde el panel y genera una nueva.

---

## Requisitos

- Python 3.8+
- `requests`
- `prompt-toolkit`
- `rich`

```bash
pip install -r requirements.txt
```

---

## ¿Para qué NO usarlo?

Esta herramienta es para uso personal y educativo. No está pensada para spam, phishing, ni nada que le cause daño a otras personas. Si la usas para eso, eso es problema tuyo.

---

## Licencia

[CC BY-NC-SA 4.0](LICENSE) — Puedes usarlo, modificarlo y compartirlo, pero no para fines comerciales. Si lo adaptas, compártelo bajo la misma licencia.

---

## Créditos

Desarrollado por **Pygramer**.  
Basado en la [API pública de Guerrilla Mail](https://www.guerrillamail.com/GuerrillaMailAPI.html).
