#!/usr/bin/env python3
"""
Guerrilla Mail CLI - Sistema Híbrido Multi-Plataforma
Version: 3.0
Description: Sistema de correo temporal con soporte para múltiples proveedores SMTP
License: Creative Commons BY-NC-SA 4.0

"""

import asyncio
import requests
import sqlite3
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import ssl
import glob

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter, PathCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ============================================================================
# CONFIGURACIÓN GLOBAL
# ============================================================================

CONFIG_FILE = 'config.json'  # Archivo de configuración JSON
DEFAULT_PROVIDER = 'sendgrid'  # Proveedor SMTP por defecto

# ============================================================================
# ESTILOS Y CONFIGURACIÓN DE PROMPT
# ============================================================================

style = Style.from_dict({
    'prompt': '#00ff00 bold',
    'command': '#00ffff bold',
})


# ============================================================================
# FUNCIONES DE CONFIGURACIÓN
# ============================================================================

def load_config() -> Dict:
    """
    Carga la configuración desde el archivo JSON.
    
    Returns:
        Dict: Diccionario con la configuración completa
        
    Raises:
        FileNotFoundError: Si config.json no existe
        json.JSONDecodeError: Si el JSON está mal formateado
    """
    if not os.path.exists(CONFIG_FILE):
        console.print(f"[red][-] Error: {CONFIG_FILE} no encontrado[/red]")
        console.print("[yellow][!] Crea el archivo usando config.example.json como plantilla[/yellow]")
        raise FileNotFoundError(f"{CONFIG_FILE} no existe")
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            console.print(f"[green][+] Configuración cargada desde {CONFIG_FILE}[/green]")
            return config
    except json.JSONDecodeError as e:
        console.print(f"[red][-] Error al parsear JSON: {e}[/red]")
        raise


def get_provider_config(config: Dict, provider_name: str = None) -> Dict:
    """
    Obtiene la configuración de un proveedor SMTP específico.
    
    Args:
        config: Configuración completa cargada
        provider_name: Nombre del proveedor (si es None, usa el default)
        
    Returns:
        Dict: Configuración del proveedor seleccionado
    """
    if provider_name is None:
        provider_name = config.get('default_provider', DEFAULT_PROVIDER)
    
    providers = config.get('smtp_providers', {})
    
    if provider_name not in providers:
        console.print(f"[red][-] Proveedor '{provider_name}' no encontrado[/red]")
        console.print(f"[yellow][!] Proveedores disponibles: {', '.join(providers.keys())}[/yellow]")
        return None
    
    return providers[provider_name]


def create_example_config():
    """
    Crea un archivo config.example.json con plantillas para todos los proveedores.
    """
    example_config = {
        "default_provider": "sendgrid",
        "smtp_providers": {
            "sendgrid": {
                "name": "SendGrid",
                "smtp_host": "smtp.sendgrid.net",
                "smtp_port": 587,
                "use_tls": True,
                "username": "apikey",
                "password": "YOUR_SENDGRID_API_KEY_HERE",
                "from_email": "your-email@example.com",
                "from_name": "Your Name"
            },
            "gmail": {
                "name": "Gmail",
                "smtp_host": "smtp.gmail.com",
                "smtp_port": 587,
                "use_tls": True,
                "username": "your-email@gmail.com",
                "password": "YOUR_APP_PASSWORD_HERE",
                "from_email": "your-email@gmail.com",
                "from_name": "Your Name"
            },
            "outlook": {
                "name": "Outlook/Hotmail",
                "smtp_host": "smtp-mail.outlook.com",
                "smtp_port": 587,
                "use_tls": True,
                "username": "your-email@outlook.com",
                "password": "YOUR_PASSWORD_HERE",
                "from_email": "your-email@outlook.com",
                "from_name": "Your Name"
            },
            "mailgun": {
                "name": "Mailgun",
                "smtp_host": "smtp.mailgun.org",
                "smtp_port": 587,
                "use_tls": True,
                "username": "postmaster@your-domain.mailgun.org",
                "password": "YOUR_MAILGUN_SMTP_PASSWORD",
                "from_email": "noreply@your-domain.com",
                "from_name": "Your Name"
            },
            "custom": {
                "name": "Custom SMTP",
                "smtp_host": "smtp.your-provider.com",
                "smtp_port": 587,
                "use_tls": True,
                "username": "your-username",
                "password": "your-password",
                "from_email": "your-email@example.com",
                "from_name": "Your Name"
            }
        }
    }
    
    with open('config.example.json', 'w', encoding='utf-8') as f:
        json.dump(example_config, f, indent=2, ensure_ascii=False)
    
    console.print("[green][+] Archivo config.example.json creado[/green]")


# ============================================================================
# CLASE: GUERRILLA MAIL API
# ============================================================================

class GuerrillaMailAPI:
    """
    Interfaz para la API de Guerrilla Mail.
    
    Guerrilla Mail proporciona direcciones de correo temporales/desechables
    que se pueden usar para recibir correos sin registro.
    
    Attributes:
        BASE_URL: Endpoint de la API de Guerrilla Mail
        session: Sesión de requests para mantener cookies
    """
    
    BASE_URL = "https://api.guerrillamail.com/ajax.php"
    
    def __init__(self):
        """Inicializa la sesión HTTP con headers personalizados."""
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'GuerrillaMailCLI/3.0'})
    
    def create_mailbox(self) -> Optional[Dict]:
        """
        Crea un nuevo buzón de correo temporal.
        
        Returns:
            Dict con email, alias, sid_token y site_id, o None si falla
        """
        try:
            response = self.session.get(self.BASE_URL, params={'f': 'get_email_address'}, timeout=10)
            response.raise_for_status()
            data = response.json()
            return {
                'email': data.get('email_addr'),
                'alias': data.get('alias'),
                'sid_token': data.get('sid_token'),
                'site_id': data.get('site_id')
            }
        except Exception as e:
            console.print(f"[red][-] Error creando buzón: {e}[/red]")
            return None
    
    def set_email_user(self, username: str, sid_token: str) -> Optional[Dict]:
        """
        Personaliza el nombre de usuario del buzón temporal.
        
        Args:
            username: Nombre deseado para el email (parte antes del @)
            sid_token: Token de sesión del buzón
            
        Returns:
            Dict con el nuevo email y alias, o None si falla
        """
        try:
            response = self.session.get(self.BASE_URL, params={
                'f': 'set_email_user',
                'email_user': username,
                'sid_token': sid_token
            }, timeout=10)
            data = response.json()
            return {'email': data.get('email_addr'), 'alias': data.get('alias')}
        except Exception as e:
            console.print(f"[red][-] Error personalizando email: {e}[/red]")
            return None
    
    def get_email_list(self, sid_token: str, offset: int = 0) -> Optional[Dict]:
        """
        Obtiene la lista de correos en la bandeja de entrada.
        
        Args:
            sid_token: Token de sesión del buzón
            offset: Desplazamiento para paginación
            
        Returns:
            Dict con la lista de emails o None si falla
        """
        try:
            response = self.session.get(self.BASE_URL, params={
                'f': 'get_email_list',
                'offset': offset,
                'sid_token': sid_token
            }, timeout=10)
            return response.json()
        except Exception as e:
            console.print(f"[red][-] Error obteniendo lista: {e}[/red]")
            return None
    
    def fetch_email(self, email_id: str, sid_token: str) -> Optional[Dict]:
        """
        Obtiene el contenido completo de un email específico.
        
        Args:
            email_id: ID del email a obtener
            sid_token: Token de sesión del buzón
            
        Returns:
            Dict con el contenido del email o None si falla
        """
        try:
            response = self.session.get(self.BASE_URL, params={
                'f': 'fetch_email',
                'email_id': email_id,
                'sid_token': sid_token
            }, timeout=10)
            return response.json()
        except Exception as e:
            console.print(f"[red][-] Error obteniendo email: {e}[/red]")
            return None
    
    def check_email(self, sid_token: str, seq: int = 0) -> Optional[Dict]:
        """
        Verifica si hay nuevos correos (para refresh automático).
        
        Args:
            sid_token: Token de sesión del buzón
            seq: Número de secuencia para verificar cambios
            
        Returns:
            Dict con información de nuevos emails o None si falla
        """
        try:
            response = self.session.get(self.BASE_URL, params={
                'f': 'check_email',
                'seq': seq,
                'sid_token': sid_token
            }, timeout=10)
            return response.json()
        except:
            return None
    
    def del_email(self, email_ids: List[str], sid_token: str) -> Optional[Dict]:
        """
        Elimina uno o más correos del buzón.
        
        Args:
            email_ids: Lista de IDs de emails a eliminar
            sid_token: Token de sesión del buzón
            
        Returns:
            Dict con resultado de la operación o None si falla
        """
        try:
            params = {'f': 'del_email', 'sid_token': sid_token}
            for email_id in email_ids:
                params['email_ids[]'] = email_id
            response = self.session.get(self.BASE_URL, params=params, timeout=10)
            return response.json()
        except Exception as e:
            console.print(f"[red][-] Error eliminando email: {e}[/red]")
            return None


# ============================================================================
# CLASE: SMTP EMAIL SENDER (Multi-Proveedor)
# ============================================================================

class SMTPEmailSender:
    """
    Cliente SMTP genérico que soporta múltiples proveedores.
    
    Soporta cualquier proveedor SMTP incluyendo:
    - SendGrid
    - Gmail
    - Outlook/Hotmail
    - Mailgun
    - Proveedores personalizados
    
    Attributes:
        provider_name: Nombre del proveedor SMTP
        smtp_server: Host del servidor SMTP
        smtp_port: Puerto del servidor SMTP
        smtp_user: Usuario para autenticación
        smtp_pass: Contraseña/API key para autenticación
        from_email: Email remitente
        from_name: Nombre del remitente
        use_tls: Si se debe usar TLS/STARTTLS
    """
    
    def __init__(self, provider_config: Dict):
        """
        Inicializa el cliente SMTP con configuración del proveedor.
        
        Args:
            provider_config: Dict con configuración del proveedor SMTP
        """
        self.provider_name = provider_config.get('name', 'Unknown')
        self.smtp_server = provider_config.get('smtp_host')
        self.smtp_port = provider_config.get('smtp_port', 587)
        self.smtp_user = provider_config.get('username')
        self.smtp_pass = provider_config.get('password')
        self.from_email = provider_config.get('from_email')
        self.from_name = provider_config.get('from_name', 'GuerrillaMail CLI')
        self.use_tls = provider_config.get('use_tls', True)
        
        # Mostrar configuración cargada (sin credenciales sensibles)
        console.print(f"[green][+] Proveedor SMTP: {self.provider_name}[/green]")
        console.print(f"  [*] Host: {self.smtp_server}:{self.smtp_port}")
        console.print(f"  [*] From: {self.from_name} <{self.from_email}>")
        console.print(f"  [*] TLS: {'Enabled' if self.use_tls else 'Disabled'}")
        console.print()
    
    def test_connection(self) -> bool:
        """
        Prueba la conexión SMTP con las credenciales configuradas.
        
        Returns:
            bool: True si la conexión fue exitosa, False en caso contrario
        """
        try:
            console.print(f"[cyan][*] Probando conexión a {self.provider_name}...[/cyan]")
            
            # Crear contexto SSL
            context = ssl.create_default_context()
            
            # Conectar al servidor
            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30)
            server.set_debuglevel(1)  # Modo debug para ver detalles
            
            # Usar STARTTLS si está habilitado
            if self.use_tls:
                console.print("[yellow][*] Iniciando STARTTLS...[/yellow]")
                server.starttls(context=context)
            
            # Autenticar
            console.print("[yellow][*] Autenticando...[/yellow]")
            server.login(self.smtp_user, self.smtp_pass)
            
            console.print("[green][+] ¡Conexión exitosa![/green]")
            server.quit()
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            console.print(f"[red][-] Error de autenticación: {e}[/red]")
            console.print("[yellow][!] Verifica tu usuario y contraseña en config.json[/yellow]")
            return False
        except smtplib.SMTPException as e:
            console.print(f"[red][-] Error SMTP: {e}[/red]")
            return False
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            return False
    
    def configure(self, server: str = None, port: int = None, 
                  user: str = None, password: str = None):
        """
        Permite reconfigurar parámetros SMTP en tiempo de ejecución.
        
        Args:
            server: Nuevo servidor SMTP
            port: Nuevo puerto SMTP
            user: Nuevo usuario
            password: Nueva contraseña
        """
        if server:
            self.smtp_server = server
        if port:
            self.smtp_port = port
        if user:
            self.smtp_user = user
        if password:
            self.smtp_pass = password
    
    def send_email(self, from_addr: str, to_addrs: List[str], subject: str,
                   body: str, html: bool = False, attachments: List[str] = None,
                   custom_from_name: str = None) -> bool:
        """
        Envía un correo electrónico usando el proveedor SMTP configurado.
        
        Args:
            from_addr: Dirección de email del remitente (usado en Reply-To)
            to_addrs: Lista de destinatarios
            subject: Asunto del email
            body: Cuerpo del mensaje
            html: Si es True, el cuerpo se envía como HTML
            attachments: Lista de rutas de archivos a adjuntar
            custom_from_name: Nombre personalizado del remitente
            
        Returns:
            bool: True si el envío fue exitoso, False en caso contrario
        """
        try:
            # Crear mensaje MIME multipart
            msg = MIMEMultipart('alternative')
            
            # Configurar remitente
            display_name = custom_from_name if custom_from_name else self.from_name
            msg['From'] = f'{display_name} <{self.from_email}>'
            msg['To'] = ', '.join(to_addrs)
            msg['Subject'] = subject
            
            # Si el from_addr es diferente, agregarlo como Reply-To
            if from_addr and from_addr != self.from_email:
                msg['Reply-To'] = from_addr
                console.print(f"[dim][*] Reply-To: {from_addr}[/dim]")
            
            # Adjuntar el cuerpo del mensaje
            if html:
                msg.attach(MIMEText(body, 'html', 'utf-8'))
            else:
                msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Procesar archivos adjuntos
            if attachments:
                for file_path in attachments:
                    try:
                        with open(file_path, 'rb') as f:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(f.read())
                            encoders.encode_base64(part)
                            part.add_header('Content-Disposition', 
                                          f'attachment; filename={Path(file_path).name}')
                            msg.attach(part)
                        console.print(f"[green][+] Adjuntado: {file_path}[/green]")
                    except Exception as e:
                        console.print(f"[yellow][!] No se pudo adjuntar {file_path}: {e}[/yellow]")
            
            # Conectar y enviar
            console.print(f"[dim][*] Conectando a {self.smtp_server}:{self.smtp_port}...[/dim]")
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                # Usar STARTTLS si está habilitado
                if self.use_tls:
                    server.starttls(context=context)
                
                # Autenticar
                server.login(self.smtp_user, self.smtp_pass)
                
                # Enviar el mensaje
                server.send_message(msg)
            
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            console.print(f"[red][-] Error de autenticación: {e}[/red]")
            return False
        except smtplib.SMTPException as e:
            console.print(f"[red][-] Error SMTP: {e}[/red]")
            return False
        except FileNotFoundError as e:
            console.print(f"[red][-] Archivo no encontrado: {e}[/red]")
            return False
        except Exception as e:
            console.print(f"[red][-] Error enviando email: {e}[/red]")
            return False


# ============================================================================
# CLASE: LOCAL STORAGE (Base de Datos SQLite)
# ============================================================================

class LocalStorage:
    """
    Gestor de almacenamiento local usando SQLite.
    
    Almacena:
    - Sesiones de buzones temporales
    - Configuración SMTP personalizada
    - Historial de correos enviados
    
    Attributes:
        db_path: Ruta al archivo de base de datos SQLite
    """
    
    def __init__(self, db_path: str = "guerrilla_hybrid.db"):
        """
        Inicializa el almacenamiento local.
        
        Args:
            db_path: Ruta al archivo de base de datos
        """
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Crea las tablas necesarias si no existen."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabla de sesiones de buzones temporales
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                alias TEXT,
                sid_token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabla de configuración SMTP (deprecada, ahora usa config.json)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS smtp_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT,
                password TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_email TEXT NOT NULL,
                email_id TEXT NOT NULL,
                mail_from TEXT,
                mail_subject TEXT,
                mail_timestamp INTEGER,
                mail_read INTEGER DEFAULT 0,
                mail_body TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_email) REFERENCES sessions(email),
                UNIQUE(session_email, email_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_session(self, email: str, alias: str, sid_token: str):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO sessions (email, alias, sid_token) VALUES (?, ?, ?)",
                (email, alias, sid_token)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            return False
    
    def get_sessions(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, alias, created_at FROM sessions ORDER BY created_at DESC")
        sessions = cursor.fetchall()
        conn.close()
        return sessions
    
    def get_session_by_id(self, session_id: int):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT email, alias, sid_token FROM sessions WHERE id = ?", (session_id,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return {'email': result[0], 'alias': result[1], 'sid_token': result[2]}
        return None
    
    def delete_session(self, session_id: int):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM sessions WHERE id = ?", (session_id,))
            result = cursor.fetchone()
            if result:
                cursor.execute("DELETE FROM emails WHERE session_email = ?", (result[0],))
                cursor.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
                conn.commit()
            conn.close()
            return True
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            return False
    
    def save_email(self, session_email: str, email_data: dict):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO emails 
                (session_email, email_id, mail_from, mail_subject, mail_timestamp, mail_body)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_email,
                email_data.get('mail_id'),
                email_data.get('mail_from'),
                email_data.get('mail_subject'),
                email_data.get('mail_timestamp'),
                email_data.get('mail_body', '')
            ))
            conn.commit()
            conn.close()
            return True
        except:
            return False
    
    def mark_as_read(self, session_email: str, email_id: str):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE emails SET mail_read = 1 WHERE session_email = ? AND email_id = ?",
            (session_email, email_id)
        )
        conn.commit()
        conn.close()
    
    def save_smtp_config(self, server: str, port: int, username: str = None, password: str = None):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO smtp_config (id, server, port, username, password)
                VALUES (1, ?, ?, ?, ?)
            """, (server, port, username, password))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
            return False
    
    def get_smtp_config(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT server, port, username, password FROM smtp_config WHERE id = 1")
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'server': result[0],
                'port': result[1],
                'username': result[2],
                'password': result[3]
            }
        return None


def list_html_files(directory="."):
    html_files = glob.glob(os.path.join(directory, "*.html")) + \
                 glob.glob(os.path.join(directory, "*.htm"))
    return sorted([os.path.basename(f) for f in html_files])


def list_all_files(directory=".", exclude_exts=['.py', '.db', '.pyc']):
    all_files = []
    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):
            ext = os.path.splitext(file)[1]
            if ext not in exclude_exts:
                all_files.append(file)
    return sorted(all_files)


# ============================================================================
# CLASE PRINCIPAL: CLI HÍBRIDO DE GUERRILLA MAIL
# ============================================================================

class HybridGuerrillaMailCLI:
    """
    Interfaz de línea de comandos para gestionar correos temporales.
    
    Combina:
    - Guerrilla Mail API para recibir correos
    - Proveedores SMTP múltiples para enviar correos
    - Almacenamiento local de sesiones
    - Interfaz interactiva con autocompletado
    
    Attributes:
        api: Cliente de la API de Guerrilla Mail
        sender: Cliente SMTP para envío de correos
        storage: Gestor de almacenamiento local
        current_session: Sesión de buzón activa
        running: Estado de ejecución del CLI
        config: Configuración cargada desde JSON
    """
    
    def __init__(self):
        """Inicializa el CLI y carga la configuración."""
        console.print(f"[green][+] Directorio de trabajo: {os.getcwd()}[/green]\n")
        
        # Cargar configuración desde JSON
        try:
            self.config = load_config()
        except (FileNotFoundError, json.JSONDecodeError):
            console.print("[yellow][!] Creando archivo de ejemplo...[/yellow]")
            create_example_config()
            console.print(f"[red][-] Por favor, configura {CONFIG_FILE} y vuelve a ejecutar[/red]")
            exit(1)
        
        # Obtener configuración del proveedor SMTP
        provider_config = get_provider_config(self.config)
        if not provider_config:
            console.print("[red][-] No se pudo cargar la configuración SMTP[/red]")
            exit(1)
        
        # Inicializar componentes
        self.api = GuerrillaMailAPI()
        self.sender = SMTPEmailSender(provider_config)
        self.storage = LocalStorage()
        self.current_session = None
        self.running = True
        
        # Mapeo de IDs de emails (para usar números simples: 1, 2, 3...)
        self.email_id_map = {}  # {1: 'email_id_real', 2: 'email_id_real', ...}
        self.reverse_id_map = {}  # {'email_id_real': 1, ...}
        
        # Configuración SMTP desde storage (deprecado, ahora usa config.json)
        # Mantenido por compatibilidad con versiones antiguas
        smtp_config = self.storage.get_smtp_config()
        if smtp_config:
            console.print("[yellow][!] Configuración SMTP en base de datos detectada (deprecado)[/yellow]")
            console.print("[yellow][!] Considera migrar a config.json[/yellow]")
        
        # Comandos disponibles
        self.commands = {
            'create': self.cmd_create,
            'list': self.cmd_list,
            'select': self.cmd_select,
            'custom': self.cmd_custom,
            'info': self.cmd_info,
            'inbox': self.cmd_inbox,
            'refresh': self.cmd_refresh,
            'read': self.cmd_read,
            'delete': self.cmd_delete,
            'destroy': self.cmd_destroy,
            'send': self.cmd_send,
            'sendhtml': self.cmd_sendhtml,
            'sendbulk': self.cmd_sendbulk,
            'test': self.cmd_test,
            'smtp': self.cmd_smtp,
            'provider': self.cmd_provider,
            'clear': self.cmd_clear,
            'help': self.cmd_help,
            'exit': self.cmd_exit,
        }
        
        # Configurar autocompletado y historial
        completer = WordCompleter(list(self.commands.keys()), ignore_case=True)
        self.session_prompt = PromptSession(
            completer=completer,
            history=FileHistory('.guerrilla_hybrid_history'),
            auto_suggest=AutoSuggestFromHistory(),
            style=style
        )
    
    def display_banner(self):
        """Muestra el banner de bienvenida."""
        provider_name = self.sender.provider_name
        banner = f"""
[bold cyan]+=================================================================+
|      [*] GUERRILLA MAIL CLI - SISTEMA HÍBRIDO MULTI-SMTP [*]  |
|                                                                 |
|  [>>] Recibe: Guerrilla Mail API (buzones temporales)          |
|  [<<] Envía: {provider_name:<48} |
|  [$] Soporta múltiples proveedores SMTP                        |
|                                                                 |
|  'help' -> comandos | 'send' -> enviar | '!ls' -> sistema      |
+=================================================================+[/bold cyan]
"""
        console.print(banner)
    
    async def run(self):
        self.display_banner()
        
        while self.running:
            try:
                if self.current_session:
                    prompt_text = HTML(f'<ansigreen>guerrilla</ansigreen> [<ansicyan>{self.current_session["email"]}</ansicyan>] > ')
                else:
                    prompt_text = HTML('<ansigreen>guerrilla</ansigreen> [<ansired>sin sesion</ansired>] > ')
                
                user_input = await self.session_prompt.prompt_async(prompt_text)
                
                if not user_input.strip():
                    continue
                
                if user_input.startswith('!'):
                    await self.execute_system_command(user_input[1:])
                    continue
                
                system_cmds = ['ls', 'pwd', 'cd', 'cat', 'nano', 'vim', 'mkdir', 'rm', 'cp', 'mv']
                first_word = user_input.split()[0] if user_input.split() else ''
                if first_word in system_cmds:
                    await self.execute_system_command(user_input)
                    continue
                
                parts = user_input.strip().split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                
                if cmd in self.commands:
                    await self.commands[cmd](args)
                else:
                    console.print(f"[red][-] Comando desconocido: {cmd}[/red]")
                    console.print("[yellow][!] 'help' para ver comandos[/yellow]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow][!] Usa 'exit' para salir[/yellow]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")
    
    async def execute_system_command(self, command: str):
        import subprocess
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.getcwd()
            )
            if result.stdout:
                console.print(result.stdout)
            if result.stderr:
                console.print(f"[red]{result.stderr}[/red]")
        except subprocess.TimeoutExpired:
            console.print("[red][-] Timeout[/red]")
        except Exception as e:
            console.print(f"[red][-] Error: {e}[/red]")
    
    async def cmd_create(self, args: str):
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("[*] Creando buzon...", total=None)
            mailbox = self.api.create_mailbox()
            progress.update(task, completed=True)
        
        if mailbox:
            self.current_session = mailbox
            self.storage.save_session(mailbox['email'], mailbox['alias'], mailbox['sid_token'])
            console.print()
            console.print(f"[green][+] Buzon creado[/green]")
            console.print(f"[cyan][*] Email: {mailbox['email']}[/cyan]")
            console.print(f"[dim][*] Token: {mailbox['sid_token'][:30]}...[/dim]")
            console.print()
        else:
            console.print("[red][-] Error[/red]")
    
    async def cmd_list(self, args: str):
        sessions = self.storage.get_sessions()
        
        if not sessions:
            console.print("[yellow][!] Sin sesiones[/yellow]")
            return
        
        table = Table(title="[+] Sesiones", box=box.ROUNDED)
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Email", style="green")
        table.add_column("Alias", style="yellow")
        table.add_column("Creado", style="blue")
        
        for session in sessions:
            table.add_row(
                str(session[0]),
                session[1],
                session[2] or "N/A",
                session[3][:19] if session[3] else "N/A"
            )
        
        console.print(table)
    
    async def cmd_select(self, args: str):
        if not args:
            console.print("[red][-] Uso: select <id>[/red]")
            return
        
        try:
            session_id = int(args)
            session = self.storage.get_session_by_id(session_id)
            
            if session:
                self.current_session = session
                console.print(f"[green][+] Sesion activa: {session['email']}[/green]")
                self.email_id_map.clear()
                self.reverse_id_map.clear()
            else:
                console.print(f"[red][-] Sesion {session_id} no encontrada[/red]")
        except ValueError:
            console.print("[red][-] ID debe ser numero[/red]")
    
    async def cmd_custom(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        if not args:
            console.print("[red][-] Uso: custom <nombre>[/red]")
            return
        
        console.print(f"[cyan][*] Personalizando a '{args}'...[/cyan]")
        result = self.api.set_email_user(args, self.current_session['sid_token'])
        
        if result:
            self.current_session['email'] = result['email']
            self.current_session['alias'] = result['alias']
            console.print(f"[green][+] Nuevo email: {result['email']}[/green]")
        else:
            console.print("[red][-] Error[/red]")
    
    async def cmd_info(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        panel = Panel(
            f"[cyan][*] Email: {self.current_session['email']}[/cyan]\n"
            f"[cyan][*] Alias: {self.current_session.get('alias', 'N/A')}[/cyan]\n"
            f"[cyan][*] Token: {self.current_session['sid_token'][:30]}...[/cyan]\n"
            f"[cyan][*] SMTP: {self.sender.from_email} ({self.sender.provider_name})[/cyan]\n"
            f"[cyan][*] Dir: {os.getcwd()}[/cyan]",
            title="[+] Info",
            border_style="cyan"
        )
        console.print(panel)
    
    def _build_email_id_map(self, emails):
        self.email_id_map.clear()
        self.reverse_id_map.clear()
        
        for idx, email in enumerate(emails, start=1):
            real_id = str(email.get('mail_id', 'N/A'))
            self.email_id_map[idx] = real_id
            self.reverse_id_map[real_id] = idx
    
    def _get_real_id(self, simple_id: str) -> Optional[str]:
        try:
            simple_id_int = int(simple_id)
            return self.email_id_map.get(simple_id_int)
        except ValueError:
            return simple_id
    
    async def cmd_inbox(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        console.print("[cyan][*] Cargando...[/cyan]")
        result = self.api.get_email_list(self.current_session['sid_token'])
        
        if not result or 'list' not in result:
            console.print("[yellow][!] Sin emails[/yellow]")
            return
        
        emails = result['list']
        
        if not emails:
            console.print("[yellow][!] Inbox vacio[/yellow]")
            return
        
        for email in emails:
            self.storage.save_email(self.current_session['email'], email)
        
        self._build_email_id_map(emails)
        
        table = Table(title=f"[>>] Inbox - {self.current_session['email']}", box=box.ROUNDED)
        table.add_column("ID", style="cyan bold", justify="center", width=6)
        table.add_column("De", style="green", width=30)
        table.add_column("Asunto", style="yellow", width=40)
        table.add_column("Fecha", style="blue", width=20)
        
        for idx, email in enumerate(emails, start=1):
            mail_from = email.get('mail_from', 'Desconocido')[:28]
            subject = email.get('mail_subject', 'Sin asunto')[:38]
            timestamp = datetime.fromtimestamp(int(email.get('mail_timestamp', 0))).strftime('%Y-%m-%d %H:%M')
            
            table.add_row(str(idx), mail_from, subject, timestamp)
        
        console.print(table)
        console.print(f"\n[dim][!] Usa: read 1, delete 2, etc.[/dim]")
    
    async def cmd_refresh(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("[*] Chequeando...", total=None)
            result = self.api.check_email(self.current_session['sid_token'])
            progress.update(task, completed=True)
        
        if result and 'list' in result and result['list']:
            console.print(f"[green][+] {len(result['list'])} nuevos[/green]")
            await self.cmd_inbox("")
        else:
            console.print("[yellow][!] Sin nuevos[/yellow]")
    
    async def cmd_read(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        if not args:
            console.print("[red][-] Uso: read <id>[/red]")
            return
        
        real_id = self._get_real_id(args)
        
        if not real_id:
            console.print(f"[red][-] ID invalido: {args}[/red]")
            return
        
        console.print(f"[cyan][*] Cargando email {args}...[/cyan]")
        result = self.api.fetch_email(real_id, self.current_session['sid_token'])
        
        if not result:
            console.print("[red][-] Error[/red]")
            return
        
        self.storage.mark_as_read(self.current_session['email'], real_id)
        
        panel = Panel(
            f"[cyan][*] De: {result.get('mail_from', 'Desconocido')}[/cyan]\n"
            f"[cyan][*] Asunto: {result.get('mail_subject', 'Sin asunto')}[/cyan]\n"
            f"[cyan][*] Fecha: {datetime.fromtimestamp(int(result.get('mail_timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S')}[/cyan]\n"
            f"\n{result.get('mail_body', 'Sin contenido')}",
            title=f"[>>] Email #{args}",
            border_style="green"
        )
        console.print(panel)
    
    async def cmd_delete(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        if not args:
            console.print("[red][-] Uso: delete <id>[/red]")
            return
        
        real_id = self._get_real_id(args)
        
        if not real_id:
            console.print(f"[red][-] ID invalido: {args}[/red]")
            return
        
        email_ids = [real_id]
        result = self.api.del_email(email_ids, self.current_session['sid_token'])
        
        if result:
            console.print(f"[green][+] Email #{args} eliminado[/green]")
            await self.cmd_inbox("")
        else:
            console.print("[red][-] Error[/red]")
    
    async def cmd_destroy(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        confirm = await self.session_prompt.prompt_async(
            f"[!] Destruir {self.current_session['email']}? [Si/no]: "
        )
        
        if confirm.lower() in ['', 'si', 's', 'yes', 'y']:
            sessions = self.storage.get_sessions()
            session_id = None
            for session in sessions:
                if session[1] == self.current_session['email']:
                    session_id = session[0]
                    break
            
            if session_id and self.storage.delete_session(session_id):
                console.print(f"[green][+] Buzon destruido[/green]")
                self.current_session = None
                self.email_id_map.clear()
                self.reverse_id_map.clear()
            else:
                console.print("[red][-] Error[/red]")
        else:
            console.print("[yellow][!] Cancelado[/yellow]")
    
    async def cmd_smtp(self, args: str):
        console.print("[cyan][===] Config SMTP [===][/cyan]")
        console.print(f"[green][*] Server: {self.sender.smtp_server}:{self.sender.smtp_port}[/green]")
        console.print(f"[green][*] Usuario: {self.sender.smtp_user}[/green]")
        console.print(f"[green][*] TLS: {'Si' if self.sender.use_tls else 'No'}[/green]")
        console.print(f"[green][*] From: {self.sender.from_name} <{self.sender.from_email}>[/green]")
        
        change = await self.session_prompt.prompt_async("\n[?] Cambiar? [Si/no]: ")
        
        if change.lower() in ['', 'si', 's', 'yes', 'y']:
            server = await self.session_prompt.prompt_async(f"Server [{self.sender.smtp_server}]: ")
            port = await self.session_prompt.prompt_async(f"Puerto [{self.sender.smtp_port}]: ")
            username = await self.session_prompt.prompt_async(f"Usuario [{self.sender.smtp_user}]: ")
            password = await self.session_prompt.prompt_async("Password (vacio = no cambiar): ")
            
            if server:
                self.sender.smtp_server = server
            if port:
                self.sender.smtp_port = int(port)
            if username:
                self.sender.smtp_user = username
            if password:
                self.sender.smtp_pass = password
            
            self.storage.save_smtp_config(
                self.sender.smtp_server,
                self.sender.smtp_port,
                self.sender.smtp_user,
                self.sender.smtp_pass
            )
            
            console.print("[green][+] Config actualizada[/green]")
        else:
            console.print("[yellow][!] Cancelado[/yellow]")
    
    async def cmd_test(self, args: str):
        self.sender.test_connection()
    
    async def cmd_send(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        console.print(f"[cyan][===] Enviar Email con {self.sender.provider_name} [===][/cyan]\n")
        
        from_name = await self.session_prompt.prompt_async(
            f"Nombre del remitente [{self.sender.from_name}]: "
        )
        from_name = from_name.strip() or self.sender.from_name
        
        to_addr = await self.session_prompt.prompt_async("Para: ")
        subject = await self.session_prompt.prompt_async("Asunto: ")
        
        content_type = await self.session_prompt.prompt_async(
            "Contenido: [t]exto / [h]tml inline / [f]ile html? "
        )
        
        is_html = False
        body = ""
        
        if content_type.lower().startswith('f'):
            html_files = list_html_files()
            if html_files:
                console.print("\n[cyan][*] Archivos HTML disponibles:[/cyan]")
                for idx, file in enumerate(html_files, 1):
                    console.print(f"  [{idx}] {file}")
                console.print()
            else:
                console.print("[yellow][!] Sin archivos HTML[/yellow]")
            
            html_input = await self.session_prompt.prompt_async("Archivo HTML: ")
            
            try:
                idx = int(html_input)
                if 1 <= idx <= len(html_files):
                    html_file = html_files[idx - 1]
                else:
                    console.print(f"[red][-] Numero invalido[/red]")
                    return
            except ValueError:
                html_file = html_input
            
            try:
                with open(html_file, 'r', encoding='utf-8') as f:
                    body = f.read()
                is_html = True
                console.print(f"[green][+] HTML cargado: {html_file}[/green]")
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")
                return
        elif content_type.lower().startswith('h'):
            console.print("HTML (linea vacia = terminar):")
            html_lines = []
            while True:
                line = await self.session_prompt.prompt_async("  ")
                if not line:
                    break
                html_lines.append(line)
            body = "\n".join(html_lines)
            is_html = True
        else:
            console.print("Mensaje (linea vacia = terminar):")
            body_lines = []
            while True:
                line = await self.session_prompt.prompt_async("  ")
                if not line:
                    break
                body_lines.append(line)
            body = "\n".join(body_lines)
        
        attach = await self.session_prompt.prompt_async("[?] Adjuntar archivos? [Si/no]: ")
        attachments = []
        if attach.lower() in ['', 'si', 's', 'yes', 'y']:
            available_files = list_all_files()
            if available_files:
                console.print("\n[cyan][*] Archivos disponibles:[/cyan]")
                for idx, file in enumerate(available_files, 1):
                    size = os.path.getsize(file) / 1024
                    console.print(f"  [{idx}] {file} ({size:.1f} KB)")
                console.print()
            
            console.print("Archivos (vacio = terminar):")
            while True:
                file_input = await self.session_prompt.prompt_async("  ")
                if not file_input:
                    break
                
                try:
                    idx = int(file_input)
                    if 1 <= idx <= len(available_files):
                        file_path = available_files[idx - 1]
                    else:
                        console.print(f"[red][-] Numero invalido[/red]")
                        continue
                except ValueError:
                    file_path = file_input
                
                if Path(file_path).exists():
                    attachments.append(file_path)
                    console.print(f"[green][+] Adjuntado: {file_path}[/green]")
                else:
                    console.print(f"[yellow][!] No existe: {file_path}[/yellow]")
        
        console.print("\n[cyan][===] Resumen [===][/cyan]")
        console.print(f"[cyan][*] De: {from_name} <{self.sender.from_email}>[/cyan]")
        console.print(f"[cyan][*] Para: {to_addr}[/cyan]")
        console.print(f"[cyan][*] Asunto: {subject}[/cyan]")
        console.print(f"[cyan][*] Tipo: {'HTML' if is_html else 'Texto'}[/cyan]")
        if attachments:
            console.print(f"[cyan][*] Adjuntos: {', '.join(attachments)}[/cyan]")
        
        confirm = await self.session_prompt.prompt_async("\n[?] Enviar? [Si/no]: ")
        if confirm.lower() not in ['', 'si', 's', 'yes', 'y']:
            console.print("[yellow][!] Cancelado[/yellow]")
            return
        
        console.print()
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("[*] Enviando...", total=None)
            success = self.sender.send_email(
                self.current_session['email'],
                [to_addr],
                subject,
                body,
                html=is_html,
                attachments=attachments if attachments else None,
                custom_from_name=from_name
            )
            progress.update(task, completed=True)
        
        if success:
            console.print("\n[green][+] Email enviado[/green]")
            console.print(f"[cyan][*] De: {from_name} <{self.sender.from_email}>[/cyan]")
            console.print(f"[cyan][*] Reply-To: {self.current_session['email']}[/cyan]")
            console.print(f"[dim][>>] Respuestas llegaran a tu buzon temporal[/dim]\n")
        else:
            console.print("\n[red][-] Error enviando[/red]\n")
    
    async def cmd_sendhtml(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        console.print("[cyan][===] Enviar HTML [===][/cyan]\n")
        
        to_addr = await self.session_prompt.prompt_async("Para: ")
        subject = await self.session_prompt.prompt_async("Asunto: ")
        html_choice = await self.session_prompt.prompt_async("HTML desde [f]ile o [i]nline? ")
        
        if html_choice.lower().startswith('f'):
            html_files = list_html_files()
            if html_files:
                console.print("\n[cyan][*] Archivos HTML:[/cyan]")
                for idx, file in enumerate(html_files, 1):
                    console.print(f"  [{idx}] {file}")
                console.print()
            
            html_input = await self.session_prompt.prompt_async("Archivo HTML: ")
            
            try:
                idx = int(html_input)
                if 1 <= idx <= len(html_files):
                    html_file = html_files[idx - 1]
                else:
                    console.print(f"[red][-] Numero invalido[/red]")
                    return
            except ValueError:
                html_file = html_input
            
            try:
                with open(html_file, 'r', encoding='utf-8') as f:
                    html_body = f.read()
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")
                return
        else:
            console.print("HTML (linea vacia = terminar):")
            html_lines = []
            while True:
                line = await self.session_prompt.prompt_async("  ")
                if not line:
                    break
                html_lines.append(line)
            html_body = "\n".join(html_lines)
        
        console.print()
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("[*] Enviando HTML...", total=None)
            success = self.sender.send_email(
                self.current_session['email'],
                [to_addr],
                subject,
                html_body,
                html=True
            )
            progress.update(task, completed=True)
        
        if success:
            console.print("\n[green][+] HTML enviado[/green]\n")
    
    async def cmd_sendbulk(self, args: str):
        if not self.current_session:
            console.print("[red][-] Sin sesion activa[/red]")
            return
        
        console.print("[cyan][===] Envio Masivo [===][/cyan]\n")
        
        list_choice = await self.session_prompt.prompt_async("Lista [f]ile o [m]anual? ")
        
        recipients = []
        if list_choice.lower().startswith('f'):
            list_file = await self.session_prompt.prompt_async("Archivo: ")
            try:
                with open(list_file, 'r') as f:
                    recipients = [line.strip() for line in f if line.strip() and '@' in line]
            except Exception as e:
                console.print(f"[red][-] Error: {e}[/red]")
                return
        else:
            console.print("Emails (uno por linea, vacio = terminar):")
            while True:
                email = await self.session_prompt.prompt_async("  ")
                if not email:
                    break
                if '@' in email:
                    recipients.append(email.strip())
        
        if not recipients:
            console.print("[yellow][!] Sin destinatarios[/yellow]")
            return
        
        console.print(f"\n[cyan][*] Total: {len(recipients)}[/cyan]\n")
        
        subject = await self.session_prompt.prompt_async("Asunto: ")
        console.print("Cuerpo (linea vacia = terminar):")
        body_lines = []
        while True:
            line = await self.session_prompt.prompt_async("  ")
            if not line:
                break
            body_lines.append(line)
        body = "\n".join(body_lines)
        
        success_count = 0
        console.print()
        with Progress(console=console) as progress:
            task = progress.add_task(f"[cyan][*] Enviando...", total=len(recipients))
            for recipient in recipients:
                if self.sender.send_email(self.current_session['email'], [recipient], subject, body):
                    success_count += 1
                progress.advance(task)
                await asyncio.sleep(0.1)
        
        console.print(f"\n[green][+] {success_count}/{len(recipients)} enviados[/green]\n")
    
    async def cmd_provider(self, args: str):
        """
        Comando para cambiar de proveedor SMTP dinámicamente.
        
        Args:
            args: Nombre del proveedor (opcional, muestra lista si no se proporciona)
        """
        providers = self.config.get('smtp_providers', {})
        
        if not args.strip():
            # Mostrar proveedores disponibles
            console.print("[cyan][===] Proveedores SMTP Disponibles [===][/cyan]\n")
            table = Table(box=box.ROUNDED)
            table.add_column("Nombre", style="cyan")
            table.add_column("Host", style="green")
            table.add_column("Puerto", style="yellow")
            table.add_column("Estado", style="magenta")
            
            current_provider = self.config.get('default_provider', DEFAULT_PROVIDER)
            for name, config in providers.items():
                status = "★ Activo" if name == current_provider else ""
                table.add_row(
                    name,
                    config.get('smtp_host', 'N/A'),
                    str(config.get('smtp_port', 'N/A')),
                    status
                )
            
            console.print(table)
            console.print("\n[cyan][*] Uso: provider <nombre>[/cyan]")
            return
        
        # Cambiar proveedor
        provider_name = args.strip().lower()
        
        if provider_name not in providers:
            console.print(f"[red][-] Proveedor '{provider_name}' no encontrado[/red]")
            console.print(f"[yellow][!] Disponibles: {', '.join(providers.keys())}[/yellow]")
            return
        
        # Obtener configuración del nuevo proveedor
        provider_config = providers[provider_name]
        
        # Crear nuevo sender
        self.sender = SMTPEmailSender(provider_config)
        self.config['default_provider'] = provider_name
        
        console.print(f"\n[green][+] Proveedor cambiado a: {provider_config['name']}[/green]")
        console.print("[yellow][!] Nota: Este cambio solo afecta la sesión actual[/yellow]")
        console.print(f"[yellow][!] Para hacer permanente, edita 'default_provider' en {CONFIG_FILE}[/yellow]\n")
    
    async def cmd_clear(self, args: str):
        """Limpia la pantalla y muestra el banner."""
        console.clear()
        self.display_banner()
    
    async def cmd_help(self, args: str):
        """Muestra la ayuda con todos los comandos disponibles."""
        table = Table(title="[+] Comandos Disponibles", box=box.ROUNDED)
        table.add_column("Comando", style="cyan", width=25)
        table.add_column("Descripción", style="green", width=50)
        
        commands = [
            ("create", "Crear buzón temporal"),
            ("list", "Listar sesiones guardadas"),
            ("select <id>", "Seleccionar sesión por ID"),
            ("custom <nombre>", "Personalizar nombre de email"),
            ("info", "Información de sesión actual"),
            ("inbox", "Ver bandeja de entrada (IDs: 1, 2, 3...)"),
            ("refresh", "Verificar nuevos correos"),
            ("read <id>", "Leer email (ej: read 1)"),
            ("delete <id>", "Eliminar email (ej: delete 2)"),
            ("destroy", "Destruir buzón actual"),
            ("", ""),  # Separador
            ("test", "Probar conexión SMTP"),
            ("send", "Enviar email simple"),
            ("sendhtml", "Enviar email HTML"),
            ("sendbulk", "Envío masivo de correos"),
            ("smtp", "Configurar SMTP (deprecado)"),
            ("provider [nombre]", "Ver/cambiar proveedor SMTP"),
            ("", ""),  # Separador
            ("!<comando>", "Ejecutar comando del sistema (ej: !ls)"),
            ("clear", "Limpiar pantalla"),
            ("help", "Mostrar esta ayuda"),
            ("exit", "Salir del programa"),
        ]
        
        for cmd, desc in commands:
            table.add_row(cmd, desc)
        
        console.print(table)
        console.print("\n[cyan][*] Sistema HÍBRIDO Multi-SMTP:[/cyan]")
        console.print("  [>>] Recibe emails: Guerrilla Mail API (buzones temporales)")
        console.print(f"  [<<] Envía emails: {self.sender.provider_name}")
        console.print("  [#] IDs simplificados: 1, 2, 3... (read 1, delete 2)")
        console.print("  [$] Directorio actual: archivos HTML y adjuntos")
        console.print("  [!] Comandos sistema: !ls, !nano, !cat, etc.")
        console.print("  [+] Confirmaciones: Enter = Sí por defecto")
        console.print(f"  [*] Configuración: {CONFIG_FILE}\n")
    
    async def cmd_exit(self, args: str):
        """Sale del programa."""
        console.print("[yellow][!] ¡Adiós![/yellow]")
        self.running = False


async def main():
    cli = HybridGuerrillaMailCLI()
    await cli.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrumpido[/yellow]")
    except Exception as e:
        console.print(f"\n[red][-] Error: {e}[/red]")
