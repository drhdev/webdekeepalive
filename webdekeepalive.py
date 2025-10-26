#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Project:     webdekeepalive
Script:      webdekeepalive.py
Version:     0.9
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
        print("FEHLER: Dieses Skript muss in einer virtuellen Umgebung (venv) ausgeführt werden.", file=sys.stderr)
        print("Erstelle eine virtuelle Umgebung mit: python3 -m venv .venv", file=sys.stderr)
        print("Aktiviere sie mit: source .venv/bin/activate", file=sys.stderr)
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
            print("FEHLER: Dependencies nicht erfüllt. Führe 'pip install -r requirements.txt' aus.", file=sys.stderr)
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
            if self.keep_previous_runs > 0 and "Verzeichnisprüfung erfolgreich abgeschlossen" in msg:
                self.buffer.append(self.run_separator)
            self.buffer.append(msg)
        except Exception:
            pass
    def tail(self, n: int) -> str:
        if n <= 0:
            return ""
        return "\n".join(list(self.buffer)[-n:])
    def get_account_logs(self, n: int = 50) -> str:
        """Get only logs for this specific account from the global log file."""
        if not self.account_id:
            return self.tail(n)
        
        try:
            log_file = Path("logs/webdekeepalive.log")
            if not log_file.exists():
                return self.tail(n)
            
            account_logs = []
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if f"[ACCOUNT={self.account_id}]" in line:
                        account_logs.append(line.strip())
            
            # Return the last n lines for this account
            return "\n".join(account_logs[-n:]) if account_logs else self.tail(n)
        except Exception:
            return self.tail(n)

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
            error_msg = f"FEHLER: Kann {dir_name} '{dir_path}' nicht anlegen. Prüfe Berechtigungen."
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
        print(f"FEHLER: Kann Log-Verzeichnis '{log_dir}' nicht anlegen. Prüfe Berechtigungen.", file=sys.stderr)
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
                   retry_max: int, retry_base: float, retry_max_wait: float, retry_min_wait: float, jitter: float) -> Tuple[bool, str]:
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
                
                # Logout with detailed logging
                logger.debug("Attempting IMAP LOGOUT command")
                typ, data = mail.logout()
                logger.debug("IMAP LOGOUT response: %s - %s", typ, data)
            logger.info("✅ %s: Login erfolgreich – Konto gilt als aktiv.", email)
            return True, "Login erfolgreich"
        except imaplib.IMAP4.error as e:
            last_error = f"IMAP AUTH/PROTO Fehler: {e}"
            logger.error("%s", last_error)
            if attempt >= min(2, retry_max):
                break
        except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionResetError) as e:
            last_error = f"Netzwerk/SSL Fehler: {e}"
            logger.warning("%s: attempt %d failed: %s", email, attempt, e)
            if attempt < retry_max:
                exp_backoff_sleep(attempt, retry_base, retry_max_wait, jitter, retry_min_wait)
        except Exception as e:
            last_error = f"Unbekannter Fehler: {e}"
            logger.warning("%s: attempt %d failed: %s", email, attempt, e)
            if attempt < retry_max:
                exp_backoff_sleep(attempt, retry_base, retry_max_wait, jitter, retry_min_wait)
    logger.error("❌ %s: Alle Versuche fehlgeschlagen: %s", email, last_error or "Fehler")
    return False, last_error or "Fehler"

def send_mail(logger, smtp_host: str, smtp_port: int, use_tls: bool,
              smtp_user: str, smtp_password: str,
              from_email: str, from_name: str,
              to_email: str, subject: str, body: str,
              retry_max: int = 3, retry_base: float = 3.0, retry_max_wait: float = 30.0, jitter: float = 0.5
              ) -> bool:
    for attempt in range(1, retry_max + 1):
        try:
            msg = MIMEText(body, "plain", "utf-8")
            from_header = f"{from_name} <{from_email}>" if from_name else from_email
            msg["Subject"] = subject
            msg["From"] = from_header
            msg["To"] = to_email
            msg["Date"] = formatdate(localtime=True)

            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_email, [to_email], msg.as_string())
            logger.info("E-Mail versendet an %s", to_email)
            return True
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException,
                smtplib.SMTPDataError, smtplib.SMTPConnectError, socket.timeout, ssl.SSLError) as e:
            logger.warning("E-Mail Versuch %d fehlgeschlagen: %s", attempt, e)
            if attempt < retry_max:
                exp_backoff_sleep(attempt, retry_base, retry_max_wait, jitter)
        except Exception as e:
            logger.error("E-Mail Versand fehlgeschlagen: %s", e)
            return False
    logger.error("E-Mail Versand endgültig fehlgeschlagen.")
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
    cfg["smtp_use_tls"] = os.environ.get("MAIL_SMTP_USE_TLS", "true").lower() in {"1","true","yes","y"}
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
    p.add_argument("--send-mail", choices=["yes","no"], help="Mailversand für diesen Lauf erzwingen (override)")
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
        print(f"Config-Fehler: {e}", file=sys.stderr)
        sys.exit(2)

    # Verify required directories first (before logging setup)
    if not verify_required_directories(cfg):
        sys.exit(3)

    # Validate required fields
    email = cfg["email"]
    if not email:
        print("Config-Fehler: ACCOUNT_EMAIL fehlt in secrets/{account_id}.env", file=sys.stderr)
        sys.exit(2)

    password = cfg["password"]
    if not password:
        print(f"Config-Fehler: ACCOUNT_SMTP_PASS fehlt in secrets/{account_id}.env", file=sys.stderr)
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
    logger.info("Verzeichnisprüfung erfolgreich abgeschlossen")

    # PID/lock to avoid overlapping runs
    if cfg["use_lock"]:
        lock_dir = Path(cfg["lock_dir"])
        lockfile = lock_dir / f".keepalive_{cfg['id']}.lock"
        ok_lock, pid = acquire_lock(lockfile)
        if not ok_lock:
            logger.warning("Anderer Lauf aktiv (PID=%s). Abbruch.", pid if pid else "?")
            sys.exit(0)

    # IMAP keepalive
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
        jitter=cfg["jitter"]
    )

    status = "OK" if ok else "FAIL"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Only send email notifications if IMAP login was successful
    if ok:
        # Optional small pause before SMTP
        time.sleep(1.0)

        # Mail?
        send_mail_flag = cfg["send_mail"]
        if args.send_mail == "yes":
            send_mail_flag = True
        elif args.send_mail == "no":
            send_mail_flag = False

        excerpt_lines = args.excerpt_lines if args.excerpt_lines is not None else 50
        log_excerpt = mem_handler.get_account_logs(max(0, excerpt_lines))

        if send_mail_flag:
            subject = safe_format(cfg["subject_tmpl"], {
                "status": status,
                "time": now,
                "email": email,
                "message": message
            })
            body = safe_format(cfg["body_tmpl"], {
                "status": status,
                "time": now,
                "email": email,
                "message": message,
                "log_excerpt": log_excerpt
            })
            send_mail(
                logger=logger,
                smtp_host=cfg["smtp_host"],
                smtp_port=cfg["smtp_port"],
                use_tls=cfg["smtp_use_tls"],
                smtp_user=smtp_user,
                smtp_password=smtp_pass,
                from_email=email,
                from_name=from_name,
                to_email=cfg["to_email"],
                subject=subject,
                body=body
            )
    else:
        # IMAP login failed - log error and exit without sending email
        logger.error("IMAP login fehlgeschlagen: %s", message)
        logger.info("Keine E-Mail-Benachrichtigung gesendet (Login fehlgeschlagen)")

    # Clean up lock
    if cfg.get("use_lock"):
        try:
            (Path(cfg["lock_dir"]) / f".keepalive_{cfg['id']}.lock").unlink(missing_ok=True)
        except Exception:
            pass

    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
