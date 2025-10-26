#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Project:     webdekeepalive
Script:      webdekeepalive.py
Version:     0.9.9
Author:      drhdev
License:     GPL v3
Description: IMAP keep-alive for WEB.DE Freemail accounts, designed to be run by cron.
             - Cron-only; select account via --account (per-account .env)
             - Central secrets via .env (safe for Git)
             - Optional post-login email report per account (templated), including log excerpt
             - Lockfile per account to avoid overlaps
             - Robust error handling with exponential backoff (IMAP/SMTP)
"""
from __future__ import annotations

import argparse
import configparser
import imaplib
import logging
from logging.handlers import RotatingFileHandler
from collections import deque
import os
import random
import smtplib
import socket
import ssl
import sys
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.utils import formatdate
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import subprocess

# -------------------------
# Virtual environment check
# -------------------------
def check_virtual_environment():
    """
    Check if running in a virtual environment and verify requirements.txt is satisfied.
    Exits with error code 4 if not in venv or requirements not met.
    """
    # Check if we're in a virtual environment
    if not (hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)):
        print("ERROR: This script must be run in a virtual environment (venv).", file=sys.stderr)
        print("Erstelle eine virtuelle Umgebung mit: python3 -m venv .venv", file=sys.stderr)
        print("Activate it with: source .venv/bin/activate", file=sys.stderr)
        print("Installiere Dependencies mit: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(4)
    
    # Check if requirements.txt exists and is satisfied
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("WARNUNG: requirements.txt nicht gefunden. Das Skript läuft möglicherweise nicht korrekt.", file=sys.stderr)
        return
    
    try:
        # Check if pip is available and requirements are satisfied
        result = subprocess.run([sys.executable, "-m", "pip", "check"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print("ERROR: Dependencies not satisfied. Run 'pip install -r requirements.txt'.", file=sys.stderr)
            if result.stderr:
                print(f"Details: {result.stderr}", file=sys.stderr)
            sys.exit(4)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
        print(f"WARNUNG: Konnte Dependencies nicht überprüfen: {e}", file=sys.stderr)
        print("Stelle sicher, dass alle erforderlichen Pakete installiert sind.", file=sys.stderr)

# -------------------------
# .env loader (no external dep)
# -------------------------
def load_dotenv(dotenv_path: Optional[str]):
    if not dotenv_path:
        return
    if not os.path.exists(dotenv_path):
        return
    with open(dotenv_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

def load_account_secrets(account_id: str, secrets_dir: str = "secrets"):
    """
    Load account-specific secrets from secrets/{account_id}.env
    """
    account_secrets = Path(secrets_dir) / f"{account_id}.env"
    if account_secrets.exists():
        load_dotenv(str(account_secrets))
        return str(account_secrets)
    
    return None

# -------------------------
# Helpers
# -------------------------
class MemoryLogHandler(logging.Handler):
    """Keeps a rolling memory buffer of log messages for inclusion in mail."""
    def __init__(self, max_lines=200, keep_previous_runs=0, account_id=None):
        super().__init__()
        self.buffer = deque(maxlen=max_lines)
        self.keep_previous_runs = keep_previous_runs
        self.account_id = account_id
        self.run_separator = "=" * 80
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    def emit(self, record):
        try:
            msg = self.format(record)
            # Add run separator if this is a new run and we're keeping previous runs
            if self.keep_previous_runs > 0 and "Directory check completed successfully" in msg:
                self.buffer.append(self.run_separator)
            self.buffer.append(msg)
        except Exception:
            pass
    def tail(self, n: int) -> str:
        if n <= 0:
            return ""
        return "\n".join(list(self.buffer)[-n:])
    def get_account_logs(self, n: int = 50) -> str:
        """Get only INFO and higher level logs for this specific account from the current session."""
        if not self.account_id:
            return self.tail(n)
        
        # Get logs from the current session only (from memory buffer)
        account_logs = []
        for record in self.buffer:
            if hasattr(record, 'getMessage'):
                message = record.getMessage()
                if f"[ACCOUNT={self.account_id}]" in message:
                    # Only include INFO, WARNING, ERROR, and CRITICAL logs (skip DEBUG)
                    level = record.levelname
                    if level in ['INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                        # Format the log entry similar to the file format
                        timestamp = record.created
                        account_logs.append(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} [{level}] {message}")
        
        # Return the last n lines for this account from current session
        if account_logs:
            return "\n".join(account_logs[-n:])
        else:
            # Fallback: try to get logs from the global log file for this account
            # But only from the most recent execution (since last "Directory check completed successfully")
            try:
                log_file = Path("logs/webdekeepalive.log")
                if log_file.exists():
                    account_logs = []
                    current_run_logs = []
                    found_directory_check = False
                    
                    with open(log_file, "r", encoding="utf-8") as f:
                        for line in f:
                            if f"[ACCOUNT={self.account_id}]" in line:
                                # Check if this is the start of a new run
                                if "Directory check completed successfully" in line:
                                    # Start of a new run - clear previous logs and start fresh
                                    current_run_logs = []
                                    found_directory_check = True
                                
                                # Only include INFO, WARNING, ERROR, and CRITICAL logs (skip DEBUG)
                                if any(level in line for level in ['[INFO]', '[WARNING]', '[ERROR]', '[CRITICAL]']):
                                    current_run_logs.append(line.strip())
                    
                    # Return logs from the current run only
                    if current_run_logs:
                        return "\n".join(current_run_logs[-n:])
            except Exception:
                pass
            
            # Final fallback: return a simple status message
            return f"Account {self.account_id}: Recent activity logged successfully"

def ensure_dir(p: Path) -> bool:
    """Create directory if it doesn't exist. Returns True if successful, False otherwise."""
    try:
        p.mkdir(parents=True, exist_ok=True)
        return True
    except (OSError, PermissionError) as e:
        return False

def verify_required_directories(cfg: dict, logger=None) -> bool:
    """
    Verify and create all required directories.
    Returns True if all directories are available, False otherwise.
    """
    required_dirs = []
    
    # Log directory
    log_dir = Path(cfg.get("log_dir", "logs"))
    required_dirs.append(("Log-Verzeichnis", log_dir))
    
    # Lock directory
    lock_dir = Path(cfg.get("lock_dir", "logs"))
    required_dirs.append(("Lock-Verzeichnis", lock_dir))
    
    # Check each directory
    for dir_name, dir_path in required_dirs:
        if not ensure_dir(dir_path):
            error_msg = f"ERROR: Cannot create {dir_name} '{dir_path}'. Check permissions."
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg, file=sys.stderr)
            return False
        else:
            if logger:
                logger.info(f"✓ {dir_name} '{dir_path}' ist verfügbar")
    
    return True

def setup_logging(log_dir: str, log_level: str, verbose: bool, account_id: str = None):
    if not ensure_dir(Path(log_dir)):
        print(f"ERROR: Cannot create log directory '{log_dir}'. Check permissions.", file=sys.stderr)
        sys.exit(3)
    
    # Create account-specific logger name
    logger_name = f"webdekeepalive_{account_id}" if account_id else "webdekeepalive"
    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    logger.handlers.clear()

    # Single global log file for all accounts
    global_log_file = Path(log_dir) / "webdekeepalive.log"
    file_handler = RotatingFileHandler(
        global_log_file, maxBytes=1*1024*1024, backupCount=3, encoding="utf-8"
    )
    formatter = logging.Formatter(f"%(asctime)s [%(levelname)s] [ACCOUNT={account_id}] %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Memory handler for email excerpts (account-specific)
    mem_handler = MemoryLogHandler(max_lines=50, keep_previous_runs=0, account_id=account_id)
    logger.addHandler(mem_handler)

    if verbose:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger, mem_handler

def exp_backoff_sleep(attempt: int, base: float, max_wait: float, jitter: float, min_wait: float = 30.0):
    wait = min(base * (2 ** (attempt - 1)), max_wait) + random.random() * max(0.0, jitter)
    # Add minimum delay to avoid rate limiting (especially for WEB.DE)
    wait = max(wait, min_wait)  # Minimum delay between attempts
    time.sleep(wait)

def safe_format(template: str, vars: Dict[str, Any]) -> str:
    """Format with missing keys tolerated."""
    class SafeDict(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    try:
        return template.format_map(SafeDict(vars))
    except Exception:
        return template

def acquire_lock(lockfile: Path) -> Tuple[bool, Optional[int]]:
    """
    Try to create a lockfile exclusively. If exists and PID alive, return False.
    If exists but stale, remove and acquire.
    """
    try:
        if lockfile.exists():
            try:
                with open(lockfile, "r", encoding="utf-8") as f:
                    pid_str = f.read().strip()
                pid = int(pid_str) if pid_str.isdigit() else None
            except Exception:
                pid = None
            # Check if PID is running (best-effort, POSIX)
            if pid and pid != os.getpid():
                try:
                    os.kill(pid, 0)
                    # process alive
                    return False, pid
                except Exception:
                    # stale lock
                    lockfile.unlink(missing_ok=True)
            else:
                lockfile.unlink(missing_ok=True)
        # create new
        with open(lockfile, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        return True, None
    except Exception:
        return False, None

# -------------------------
# Core actions
# -------------------------
def imap_keepalive(logger, email: str, password: str, host: str, port: int, timeout: int,
                   retry_max: int, retry_base: float, retry_max_wait: float, retry_min_wait: float, jitter: float,
                   send_email: bool = False, email_config: dict = None, mem_handler = None) -> Tuple[bool, str]:
    socket.setdefaulttimeout(timeout)
    last_error = ""
    for attempt in range(1, retry_max + 1):
        try:
            logger.info("IMAP login attempt %d/%d for %s (%s:%d)", attempt, retry_max, email, host, port)
            with imaplib.IMAP4_SSL(host, port) as mail:
                # Log initial server greeting
                logger.debug("Connected to IMAP server %s:%d", host, port)
                logger.debug("Server greeting: %s", mail.welcome.decode('utf-8', errors='ignore').strip() if hasattr(mail, 'welcome') else "No greeting captured")
                # Log server capabilities (already exchanged during connection)
                logger.debug("Server capabilities: %s", mail.capabilities if hasattr(mail, 'capabilities') else "Not available")
                
                # Login attempt with detailed logging
                logger.debug("Attempting IMAP LOGIN command for %s", email)
                try:
                    mail.login(email, password)  # imaplib.IMAP4.error on auth issues
                except imaplib.IMAP4.error as login_error:
                    # Capture detailed server response for login failure
                    logger.error("IMAP LOGIN failed with server response: %s", str(login_error))
                    # Try to get more details from the connection
                    try:
                        logger.debug("Checking server capabilities after failed login")
                        mail.sock.send(b'CAPABILITY\r\n')
                        response = mail.sock.recv(4096)
                        logger.debug("Server response after failed login: %s", response.decode('utf-8', errors='ignore').strip())
                    except Exception as e:
                        logger.debug("Could not get server response after failed login: %s", e)
                    raise login_error
                # Select INBOX with detailed logging
                logger.debug("Attempting IMAP SELECT INBOX command")
                typ, data = mail.select("INBOX")
                logger.debug("IMAP SELECT INBOX response: %s - %s", typ, data)
                if typ != "OK":
                    raise RuntimeError(f"IMAP SELECT INBOX returned {typ}")
                
                # NOOP command with detailed logging
                logger.debug("Attempting IMAP NOOP command")
                typ, data = mail.noop()
                logger.debug("IMAP NOOP response: %s - %s", typ, data)
                
                # Send email notification while IMAP session is still active
                if send_email and email_config and mem_handler:
                    logger.info("📧 Email sending enabled - sending notification during active IMAP session...")
                    logger.debug("📧 Email configuration: send_email=%s, email_config available=%s, mem_handler available=%s", 
                                    send_email, bool(email_config), bool(mem_handler))
                    
                    # Apply email delay
                    email_delay = email_config.get("email_delay", 11.0)
                    if email_delay > 0:
                        logger.info("⏱️ Waiting %d seconds before email sending...", int(email_delay))
                        time.sleep(email_delay)
                else:
                    logger.info("📧 Email sending disabled or configuration incomplete")
                    logger.debug("📧 send_email=%s, email_config=%s, mem_handler=%s", 
                                send_email, bool(email_config), bool(mem_handler))
                
                # Prepare and send email if enabled
                if send_email and email_config and mem_handler:
                    # Prepare email content
                    status = "OK"
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    excerpt_lines = 50  # Fixed value
                    log_excerpt = mem_handler.get_account_logs(max(0, excerpt_lines))
                    
                    # Debug logging for email content
                    logger.debug("📧 Email template variables: status=%s, time=%s, email=%s, log_excerpt_length=%d", 
                                status, now, email, len(log_excerpt))
                    logger.debug("📧 Log excerpt preview: %s", log_excerpt[:200] if log_excerpt else "Empty")
                    logger.debug("📧 Email template body: %s", email_config["body_tmpl"][:200])
                    
                    subject = safe_format(email_config["subject_tmpl"], {
                        "status": status,
                        "time": now,
                        "email": email,
                        "message": "Login successful"
                    })
                    # Get hostname for the email template
                    import socket as socket_module
                    hostname = socket_module.gethostname()
                    
                    body = safe_format(email_config["body_tmpl"], {
                        "status": status,
                        "time": now,
                        "email": email,
                        "message": "Login successful",
                        "log_excerpt": log_excerpt,
                        "hostname": hostname
                    })
                    
                    # Convert \n to actual line breaks
                    body = body.replace('\\n', '\n')
                    
                    # Debug logging for final email content
                    logger.debug("📧 Final email body length: %d", len(body))
                    logger.debug("📧 Final email body preview: %s", body[:300])
                    
                    # Send email
                    send_mail(
                        logger=logger,
                        smtp_host=email_config["smtp_host"],
                        smtp_port=email_config["smtp_port"],
                        smtp_user=email_config["smtp_user"],
                        smtp_password=email_config["smtp_pass"],
                        from_email=email,
                        from_name=email_config["from_name"],
                        to_email=email_config["to_email"],
                        subject=subject,
                        body=body
                    )
                
                # Logout with detailed logging
                logger.debug("Attempting IMAP LOGOUT command")
                typ, data = mail.logout()
                logger.debug("IMAP LOGOUT response: %s - %s", typ, data)
            logger.info("✅ %s: Login successful – Account is active.", email)
            return True, "Login successful"
        except imaplib.IMAP4.error as e:
            last_error = f"IMAP AUTH/PROTO Error: {e}"
            logger.error("%s", last_error)
            if attempt >= min(2, retry_max):
                break
        except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionResetError) as e:
            last_error = f"Network/SSL Error: {e}"
            logger.warning("%s: attempt %d failed: %s", email, attempt, e)
            if attempt < retry_max:
                exp_backoff_sleep(attempt, retry_base, retry_max_wait, jitter, retry_min_wait)
        except Exception as e:
            last_error = f"Unknown Error: {e}"
            logger.warning("%s: attempt %d failed: %s", email, attempt, e)
            if attempt < retry_max:
                exp_backoff_sleep(attempt, retry_base, retry_max_wait, jitter, retry_min_wait)
    logger.error("❌ %s: All attempts failed: %s", email, last_error or "Error")
    return False, last_error or "Fehler"

def send_mail(logger, smtp_host: str, smtp_port: int,
              smtp_user: str, smtp_password: str,
              from_email: str, from_name: str,
              to_email: str, subject: str, body: str,
              retry_max: int = 3, retry_base: float = 3.0, retry_max_wait: float = 30.0, jitter: float = 0.5
              ) -> bool:
    logger.info("📧 Starting email sending: %s -> %s", from_email, to_email)
    logger.debug("📧 Email details: Subject='%s', SMTP=%s:%d, SSL=True", subject, smtp_host, smtp_port)
    
    for attempt in range(1, retry_max + 1):
        try:
            logger.debug("📧 Email attempt %d/%d", attempt, retry_max)
            
            msg = MIMEText(body, "plain", "utf-8")
            from_header = f"{from_name} <{from_email}>" if from_name else from_email
            msg["Subject"] = subject
            msg["From"] = from_header
            msg["To"] = to_email
            msg["Date"] = formatdate(localtime=True)

            logger.debug("📧 Connecting to SMTP server %s:%d", smtp_host, smtp_port)
            
            # Create custom debug handler to capture SMTP responses
            class SMTPDebugHandler:
                def __init__(self, logger):
                    self.logger = logger
                
                def write(self, message):
                    # Clean up the message and log it
                    clean_msg = message.strip()
                    if clean_msg:
                        self.logger.debug("📧 SMTP Server: %s", clean_msg)
            
            # Try with a shorter timeout first
                logger.debug("📧 Attempting SMTP connection with 10s timeout...")
            try:
                # Use SSL connection for port 465, STARTTLS for port 587
                if smtp_port == 465:
                    logger.debug("📧 Using SSL connection for port 465")
                    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                        # Enable debug output to capture server responses
                        server.set_debuglevel(1)
                        server.debuglevel = 1
                        
                        logger.debug("📧 SMTP SSL EHLO")
                        server.ehlo()
                        logger.debug("📧 SMTP SSL EHLO Response: %s", getattr(server, 'ehlo_resp', 'N/A'))
                        
                        if smtp_user and smtp_password:
                            logger.debug("📧 SMTP SSL LOGIN with user: %s", smtp_user)
                            server.login(smtp_user, smtp_password)
                            logger.debug("📧 SMTP SSL LOGIN Response: %s", getattr(server, 'login_resp', 'N/A'))
                            logger.debug("📧 SMTP SSL LOGIN successful")
                        
                        logger.debug("📧 Sending email via SSL...")
                        logger.debug("📧 Email content: From=%s, To=%s, Subject=%s", from_email, to_email, subject)
                        
                        # Log the raw email content for debugging
                        email_content = msg.as_string()
                        logger.debug("📧 Raw Email Content (first 500 chars): %s", email_content[:500])
                        logger.debug("📧 Email Headers: From=%s, To=%s, Subject=%s, Date=%s", 
                                   msg["From"], msg["To"], msg["Subject"], msg["Date"])
                        
                        # Capture the actual sendmail response
                        try:
                            response = server.sendmail(from_email, [to_email], email_content)
                            logger.debug("📧 SMTP SSL sendmail Response: %s", response)
                            if response:
                                logger.warning("📧 SMTP SSL sendmail had problems: %s", response)
                                for recipient, error in response.items():
                                    logger.warning("📧 Error for recipient %s: %s", recipient, error)
                            else:
                                logger.debug("📧 Email successfully sent to server via SSL")
                        except Exception as send_error:
                            logger.error("📧 SMTP SSL sendmail Error: %s", send_error)
                            raise send_error
                else:
                    logger.debug("📧 Using STARTTLS connection for port %d", smtp_port)
                    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                        # Enable debug output to capture server responses
                        server.set_debuglevel(1)
                        server.debuglevel = 1
                        
                        logger.debug("📧 SMTP EHLO")
                        server.ehlo()
                        logger.debug("📧 SMTP EHLO Response: %s", getattr(server, 'ehlo_resp', 'N/A'))
                        
                        # Start TLS for non-SSL ports
                        logger.debug("📧 SMTP STARTTLS")
                        server.starttls()
                        logger.debug("📧 SMTP STARTTLS Response: %s", getattr(server, 'starttls_resp', 'N/A'))
                        server.ehlo()
                        logger.debug("📧 SMTP EHLO after STARTTLS Response: %s", getattr(server, 'ehlo_resp', 'N/A'))
                        
                        if smtp_user and smtp_password:
                            logger.debug("📧 SMTP LOGIN with user: %s", smtp_user)
                            server.login(smtp_user, smtp_password)
                            logger.debug("📧 SMTP LOGIN Response: %s", getattr(server, 'login_resp', 'N/A'))
                            logger.debug("📧 SMTP LOGIN successful")
                        
                        logger.debug("📧 Sending email via STARTTLS...")
                        logger.debug("📧 Email content: From=%s, To=%s, Subject=%s", from_email, to_email, subject)
                        
                        # Log the raw email content for debugging
                        email_content = msg.as_string()
                        logger.debug("📧 Raw Email Content (first 500 chars): %s", email_content[:500])
                        logger.debug("📧 Email Headers: From=%s, To=%s, Subject=%s, Date=%s", 
                                   msg["From"], msg["To"], msg["Subject"], msg["Date"])
                        
                        # Capture the actual sendmail response
                        try:
                            response = server.sendmail(from_email, [to_email], email_content)
                            logger.debug("📧 SMTP STARTTLS sendmail Response: %s", response)
                            if response:
                                logger.warning("📧 SMTP STARTTLS sendmail hatte Probleme: %s", response)
                                for recipient, error in response.items():
                                    logger.warning("📧 Error for recipient %s: %s", recipient, error)
                            else:
                                logger.debug("📧 Email successfully sent to server via STARTTLS")
                        except Exception as send_error:
                            logger.error("📧 SMTP STARTTLS sendmail Error: %s", send_error)
                            raise send_error
                    
                    
                    if smtp_user and smtp_password:
                        logger.debug("📧 SMTP LOGIN mit Benutzer: %s", smtp_user)
                        server.login(smtp_user, smtp_password)
                        logger.debug("📧 SMTP LOGIN Response: %s", getattr(server, 'login_resp', 'N/A'))
                        logger.debug("📧 SMTP LOGIN erfolgreich")
                    
                    logger.debug("📧 Sende E-Mail...")
                    logger.debug("📧 Email content: From=%s, To=%s, Subject=%s", from_email, to_email, subject)
                    
                    # Log the raw email content for debugging
                    email_content = msg.as_string()
                    logger.debug("📧 Raw Email Content (first 500 chars): %s", email_content[:500])
                    logger.debug("📧 Email Headers: From=%s, To=%s, Subject=%s, Date=%s", 
                               msg["From"], msg["To"], msg["Subject"], msg["Date"])
                    
                    # Capture the actual sendmail response
                    try:
                        response = server.sendmail(from_email, [to_email], email_content)
                        logger.debug("📧 SMTP sendmail Response: %s", response)
                        if response:
                            logger.warning("📧 SMTP sendmail hatte Probleme: %s", response)
                            # Log details about failed recipients
                            for recipient, error in response.items():
                                logger.warning("📧 Error for recipient %s: %s", recipient, error)
                        else:
                            logger.debug("📧 E-Mail erfolgreich an Server gesendet (keine Fehler)")
                    except Exception as send_error:
                        logger.error("📧 SMTP sendmail Fehler: %s", send_error)
                        raise send_error
                    
                logger.info("✅ Email successfully sent to %s", to_email)
                logger.info("📧 Email subject: %s", subject)
                return True
            except Exception as smtp_error:
                logger.error("📧 SMTP connection failed: %s", smtp_error)
                raise smtp_error
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException,
                smtplib.SMTPDataError, smtplib.SMTPConnectError, socket.timeout, ssl.SSLError) as e:
            logger.warning("Email attempt %d failed: %s", attempt, e)
            if attempt < retry_max:
                exp_backoff_sleep(attempt, retry_base, retry_max_wait, jitter)
        except Exception as e:
            logger.error("Email sending failed: %s", e)
            return False
    logger.error("Email sending finally failed.")
    return False

# -------------------------
# Config loading
# -------------------------
def load_account_config_from_env(account_id: str, secrets_dir: str = "secrets") -> dict:
    """
    Load complete account configuration from secrets/{account_id}.env
    """
    account_secrets = Path(secrets_dir) / f"{account_id}.env"
    if not account_secrets.exists():
        raise FileNotFoundError(f"Account secrets file not found: {account_secrets}")
    
    # Load environment variables from the secrets file
    load_dotenv(str(account_secrets))
    
    # Build configuration from environment variables
    cfg = {}
    
    # Account settings
    cfg["id"] = os.environ.get("ACCOUNT_ID", account_id)
    cfg["email"] = os.environ.get("ACCOUNT_EMAIL")
    cfg["imap_host"] = os.environ.get("ACCOUNT_IMAP_HOST", "imap.web.de")
    cfg["imap_port"] = int(os.environ.get("ACCOUNT_IMAP_PORT", "993"))
    cfg["imap_timeout"] = int(os.environ.get("ACCOUNT_IMAP_TIMEOUT", "30"))
    cfg["retry_max"] = int(os.environ.get("ACCOUNT_RETRY_MAX", "5"))
    cfg["retry_base"] = float(os.environ.get("ACCOUNT_RETRY_BASE", "5.0"))
    cfg["retry_max_wait"] = float(os.environ.get("ACCOUNT_RETRY_MAX_WAIT", "120.0"))
    cfg["retry_min_wait"] = float(os.environ.get("ACCOUNT_RETRY_MIN_WAIT", "30.0"))
    cfg["jitter"] = float(os.environ.get("ACCOUNT_JITTER", "0.5"))
    cfg["email_delay"] = float(os.environ.get("ACCOUNT_EMAIL_DELAY", "11.0"))
    
    # Secrets (direct from env)
    cfg["from_name"] = os.environ.get("ACCOUNT_FROM_NAME", "")
    cfg["smtp_user"] = os.environ.get("ACCOUNT_SMTP_USER", cfg["email"])
    cfg["smtp_pass"] = os.environ.get("ACCOUNT_SMTP_PASS", "")
    cfg["password"] = cfg["smtp_pass"]  # Use SMTP password for IMAP as well
    
    # Logging
    cfg["log_dir"] = os.environ.get("LOG_DIR", "logs")
    cfg["log_level"] = os.environ.get("LOG_LEVEL", "INFO").upper()
    
    # Mail
    cfg["send_mail"] = os.environ.get("MAIL_SEND", "false").lower() in {"1","true","yes","y"}
    cfg["smtp_host"] = os.environ.get("MAIL_SMTP_HOST", "smtp.web.de")
    cfg["smtp_port"] = int(os.environ.get("MAIL_SMTP_PORT", "587"))
    cfg["to_email"] = os.environ.get("MAIL_TO_EMAIL", cfg["email"])
    
    # Templates
    cfg["subject_tmpl"] = os.environ.get("TEMPLATE_SUBJECT", "WEB.DE KeepAlive [{status}] {time}")
    cfg["body_tmpl"] = os.environ.get("TEMPLATE_BODY", "Account: {email}\nZeit: {time}\nStatus: {status}\nNachricht: {message}\n\nLog:\n{log_excerpt}")
    
    # Lock
    cfg["use_lock"] = os.environ.get("LOCK_USE", "true").lower() in {"1","true","yes","y"}
    cfg["lock_dir"] = os.environ.get("LOCK_DIR", "logs")
    
    return cfg


# -------------------------
# CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="webdekeepalive — WEB.DE IMAP keep-alive (cron)")
    p.add_argument("--account", "-a", required=True, help="Account-ID (z.B. main, alt1)")
    p.add_argument("--env", help="Pfad zur zentralen .env (überschreibt ENV_FILE)", default=None)
    p.add_argument("-v", "--verbose", action="store_true", help="Logausgaben zusätzlich auf der Konsole anzeigen")
    p.add_argument("--send-mail", choices=["yes","no"], help="Force email sending for this run (override)")
    p.add_argument("--excerpt-lines", type=int, help="Wie viele Logzeilen in die Mail aufnehmen (override)")
    return p.parse_args()

# -------------------------
# Main
# -------------------------
def main():
    # Check virtual environment first
    check_virtual_environment()
    
    args = parse_args()

    # Load complete account configuration from secrets/{account_id}.env
    account_id = args.account
    try:
        cfg = load_account_config_from_env(account_id)
    except FileNotFoundError as e:
        print(f"Config error: {e}", file=sys.stderr)
        sys.exit(2)

    # Verify required directories first (before logging setup)
    if not verify_required_directories(cfg):
        sys.exit(3)

    # Validate required fields
    email = cfg["email"]
    if not email:
        print("Config error: ACCOUNT_EMAIL missing in secrets/{account_id}.env", file=sys.stderr)
        sys.exit(2)

    password = cfg["password"]
    if not password:
        print(f"Config error: ACCOUNT_SMTP_PASS missing in secrets/{account_id}.env", file=sys.stderr)
        sys.exit(2)

    # Get SMTP credentials and from_name
    smtp_user = cfg["smtp_user"]
    smtp_pass = cfg["smtp_pass"]
    from_name = cfg["from_name"]

    # Logging
    logger, mem_handler = setup_logging(cfg["log_dir"], cfg["log_level"],
                                        verbose=args.verbose,
                                        account_id=account_id)
    
    # Log directory verification success
    logger.info("Directory check completed successfully")

    # PID/lock to avoid overlapping runs
    if cfg["use_lock"]:
        lock_dir = Path(cfg["lock_dir"])
        lockfile = lock_dir / f".keepalive_{cfg['id']}.lock"
        ok_lock, pid = acquire_lock(lockfile)
        if not ok_lock:
            logger.warning("Another run active (PID=%s). Aborting.", pid if pid else "?")
            sys.exit(0)

    # Prepare email configuration
    send_mail_flag = cfg["send_mail"]
    if args.send_mail == "yes":
        send_mail_flag = True
    elif args.send_mail == "no":
        send_mail_flag = False

    # IMAP keepalive with integrated email sending
    ok, message = imap_keepalive(
        logger=logger,
        email=email,
        password=password,
        host=cfg["imap_host"],
        port=cfg["imap_port"],
        timeout=cfg["imap_timeout"],
        retry_max=cfg["retry_max"],
        retry_base=cfg["retry_base"],
        retry_max_wait=cfg["retry_max_wait"],
        retry_min_wait=cfg["retry_min_wait"],
        jitter=cfg["jitter"],
        send_email=send_mail_flag,
        email_config=cfg,
        mem_handler=mem_handler
    )

    status = "OK" if ok else "FAIL"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Email sending is now integrated into the IMAP session
    if not ok:
        # IMAP login failed - log error
        logger.error("IMAP login failed: %s", message)
        logger.info("No email notification sent (login failed)")

    # Clean up lock
    if cfg.get("use_lock"):
        try:
            (Path(cfg["lock_dir"]) / f".keepalive_{cfg['id']}.lock").unlink(missing_ok=True)
        except Exception:
            pass

    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
