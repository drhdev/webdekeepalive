#!/usr/bin/env python3
# webdekeepalive.py
# Version: 1.0
# Author: drhdev
# License: GPL v3
#
# Description:
# Keeps WEB.DE Freemail accounts (or any other IMAP account) active by logging in via IMAP on a
# schedule, optionally sends a short report mail per account and reports to a heartbeat monitor
# (e.g. Uptime Kuma). Account settings live in 'secrets/<account>.env', global settings in
# 'webdekeepalive.config'.

import argparse
import configparser
import datetime
import fcntl
import imaplib
import logging
import os
import re
import signal
import smtplib
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from logging.handlers import RotatingFileHandler
from typing import Callable, Dict, List, Optional, TypeVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__version__ = "1.0"
SCRIPT_NAME = "webdekeepalive.py"
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROJECT_DIR, "webdekeepalive.config")

# Uptime Kuma accepts longer messages, but short ones stay readable in the UI and in alerts
HEARTBEAT_MESSAGE_LIMIT = 200
# Maximum number of log lines put into a report mail
LOG_EXCERPT_LINES = 50

DEFAULT_SUBJECT = "WEB.DE KeepAlive [{status}] {time} - {email}"
DEFAULT_BODY = ("Account: {email}\nTime: {time}\nStatus: {status}\nMessage: {message}\n\n"
                "Log:\n{log_excerpt}\n\n-- webdekeepalive on {hostname}")

logger = logging.getLogger("webdekeepalive")
T = TypeVar("T")


class ConfigError(Exception):
    """Invalid or incomplete configuration."""


class LoginError(Exception):
    """The server rejected the login or a command. Retrying does not help and could lock the account."""


class Terminated(BaseException):
    """
    SIGTERM received (systemd timeout, shutdown, 'systemctl stop'). Derived from BaseException so
    the per-account error handling does not swallow it and the run stops right away.
    """


# ============================================================================
# Secret redaction
# ============================================================================

class SecretRedactor(logging.Filter):
    """
    Removes registered secrets (passwords, heartbeat URLs) from log records, tracebacks and mail
    texts. For URLs the path and query are registered as well, because HTTP error messages often
    contain only the path (e.g. "Max retries exceeded with url: /...").
    """

    PATTERNS = [
        # Base64 credentials of an SMTP/IMAP AUTH command, should a protocol trace ever reach a log
        (re.compile(r"(AUTH(?:ENTICATE)?\s+(?:PLAIN|LOGIN)\s+)[A-Za-z0-9+/=]+", re.IGNORECASE), r"\1***"),
    ]

    def __init__(self):
        super().__init__()
        self._secrets = set()

    def add(self, secret: Optional[str]):
        if not secret:
            return
        self._secrets.add(secret)
        if "://" in secret:
            parts = urlsplit(secret)
            if len(parts.path) > 1:
                self._secrets.add(parts.path)
            if parts.query:
                self._secrets.add(parts.query)

    def redact(self, text: Optional[str]) -> str:
        if not text:
            return text or ""
        # Longest first, so a full URL is replaced before its path
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, "***")
        for pattern, replacement in self.PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.redact(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = self.redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


REDACTOR = SecretRedactor()


# ============================================================================
# Settings (webdekeepalive.config)
# ============================================================================

DEFAULT_SETTINGS = {
    "DIRECTORIES": {"accounts_dir": "secrets", "logs_dir": "logs"},
    "FILES": {"log_file": "webdekeepalive.log", "lock_file": "webdekeepalive.lock"},
    "TIMING": {"delay_between_accounts": "10"},
    "IMAP": {"timeout": "30", "attempts": "4", "base_delay": "30", "max_delay": "300"},
    "SMTP": {"timeout": "30", "attempts": "2", "base_delay": "30", "max_delay": "300"},
    "LOGGING": {"file_enabled": "true", "level": "INFO", "max_bytes": "1048576", "backup_count": "2"},
    "HEARTBEAT": {"enabled": "false", "url": "", "timeout": "10", "retries": "3"},
}


@dataclass(frozen=True)
class RetryPolicy:
    """Attempts with exponential backoff: base_delay, 2x, 4x, ... capped at max_delay."""
    attempts: int = 4
    base_delay: float = 30
    max_delay: float = 300

    def delay(self, attempt: int) -> float:
        return min(self.base_delay * 2 ** (attempt - 1), self.max_delay)


@dataclass
class HeartbeatSettings:
    enabled: bool = False
    url: Optional[str] = None
    timeout: float = 10
    retries: int = 3


@dataclass
class Settings:
    accounts_dir: str = os.path.join(PROJECT_DIR, "secrets")
    log_file: str = os.path.join(PROJECT_DIR, "logs", "webdekeepalive.log")
    lock_file: str = os.path.join(PROJECT_DIR, "logs", "webdekeepalive.lock")
    delay_between_accounts: float = 10
    imap_timeout: float = 30
    imap_retry: RetryPolicy = RetryPolicy()
    smtp_timeout: float = 30
    smtp_retry: RetryPolicy = RetryPolicy(attempts=2)
    log_to_file: bool = True
    log_level: int = logging.INFO
    log_max_bytes: int = 1048576
    log_backup_count: int = 2
    heartbeat: HeartbeatSettings = field(default_factory=HeartbeatSettings)
    # Problems found while loading, logged once logging is set up
    warnings: List[str] = field(default_factory=list)


def is_placeholder(value: str) -> bool:
    """Detect values copied unchanged from the example files."""
    lowered = value.lower()
    return any(marker in lowered for marker in ("your_", "your-", "example.com", "replace_with"))


def clean_value(value) -> Optional[str]:
    """Return the stripped string, or None for empty values and example placeholders."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or is_placeholder(text):
        return None
    return text


def decode_newlines(text: str) -> Optional[str]:
    """Config values cannot contain line breaks, so templates use a literal '\\n'."""
    return text.replace("\\n", "\n") if text else None


def _retry_policy(section: configparser.SectionProxy) -> RetryPolicy:
    return RetryPolicy(attempts=max(1, section.getint("attempts")),
                       base_delay=section.getfloat("base_delay"),
                       max_delay=section.getfloat("max_delay"))


def load_settings(path: str = CONFIG_FILE) -> Settings:
    """
    Load webdekeepalive.config on top of the defaults. The file is optional. Relative paths are
    relative to the project directory.
    """
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_dict(DEFAULT_SETTINGS)
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as e:
        raise ConfigError(f"Cannot parse '{path}': {e}") from e

    def project_path(*parts: str) -> str:
        return os.path.join(PROJECT_DIR, *parts)

    try:
        logs_dir = project_path(parser.get("DIRECTORIES", "logs_dir"))
        warnings: List[str] = []
        level_name = parser.get("LOGGING", "level").upper()
        log_level = logging.getLevelName(level_name)
        if not isinstance(log_level, int):
            warnings.append(f"[LOGGING] unknown level '{level_name}', using INFO")
            log_level = logging.INFO

        hb = parser["HEARTBEAT"]
        settings = Settings(
            accounts_dir=project_path(parser.get("DIRECTORIES", "accounts_dir")),
            log_file=os.path.join(logs_dir, parser.get("FILES", "log_file")),
            lock_file=os.path.join(logs_dir, parser.get("FILES", "lock_file")),
            delay_between_accounts=parser.getfloat("TIMING", "delay_between_accounts"),
            imap_timeout=parser.getfloat("IMAP", "timeout"),
            imap_retry=_retry_policy(parser["IMAP"]),
            smtp_timeout=parser.getfloat("SMTP", "timeout"),
            smtp_retry=_retry_policy(parser["SMTP"]),
            log_to_file=parser.getboolean("LOGGING", "file_enabled"),
            log_level=log_level,
            log_max_bytes=parser.getint("LOGGING", "max_bytes"),
            log_backup_count=parser.getint("LOGGING", "backup_count"),
            heartbeat=HeartbeatSettings(
                enabled=hb.getboolean("enabled"),
                url=clean_value(hb.get("url")),
                timeout=hb.getfloat("timeout"),
                retries=max(0, hb.getint("retries")),
            ),
            warnings=warnings,
        )
    except ValueError as e:
        raise ConfigError(f"Invalid value in '{path}': {e}") from e

    if settings.heartbeat.enabled and not settings.heartbeat.url:
        settings.warnings.append("[HEARTBEAT] enabled but no url configured, heartbeat disabled")
        settings.heartbeat.enabled = False

    REDACTOR.add(settings.heartbeat.url)
    return settings


# ============================================================================
# Account configuration (secrets/<account>.env)
# ============================================================================

ACCOUNT_KEYS = {
    "ACCOUNT_ID", "ACCOUNT_EMAIL", "ACCOUNT_PASSWORD", "ACCOUNT_IMAP_HOST", "ACCOUNT_IMAP_PORT",
    "ACCOUNT_IMAP_TIMEOUT", "ACCOUNT_FROM_NAME", "ACCOUNT_SMTP_USER", "ACCOUNT_SMTP_PASS",
    "MAIL_SEND", "MAIL_SMTP_HOST", "MAIL_SMTP_PORT", "MAIL_TO_EMAIL",
    "TEMPLATE_SUBJECT", "TEMPLATE_BODY", "HEARTBEAT_URL",
}
# Keys of version 0.9.x that are now global settings in webdekeepalive.config (or no longer needed)
OBSOLETE_KEYS = {
    "ACCOUNT_RETRY_MAX", "ACCOUNT_RETRY_BASE", "ACCOUNT_RETRY_MAX_WAIT", "ACCOUNT_RETRY_MIN_WAIT",
    "ACCOUNT_JITTER", "ACCOUNT_EMAIL_DELAY", "LOG_DIR", "LOG_LEVEL", "LOCK_USE", "LOCK_DIR",
}
TRUE_VALUES = {"1", "true", "yes", "y", "on"}
FALSE_VALUES = {"0", "false", "no", "n", "off", ""}


@dataclass
class MailSettings:
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    from_name: str
    to_email: str
    subject_template: str = DEFAULT_SUBJECT
    body_template: str = DEFAULT_BODY


@dataclass
class Account:
    id: str
    email: str
    password: str
    imap_host: str = "imap.web.de"
    imap_port: int = 993
    imap_timeout: float = 30
    mail: Optional[MailSettings] = None
    heartbeat_url: Optional[str] = None
    notes: List[str] = field(default_factory=list)


def read_env_file(path: str) -> Dict[str, str]:
    """
    Parse KEY=value lines. Values are taken literally (only surrounding quotes are removed), so
    passwords may contain '#' or '=' - which also means comments must be on their own line.
    """
    values: Dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if "=" not in line:
                raise ConfigError(f"line {number} is not KEY=value")
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key.strip()] = value
    return values


def _int(values: Dict[str, str], key: str, default: int) -> int:
    raw = values.get(key, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        raise ConfigError(f"{key} must be a whole number, got '{raw}'") from None


def _float(values: Dict[str, str], key: str, default: float) -> float:
    raw = values.get(key, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        raise ConfigError(f"{key} must be a number, got '{raw}'") from None


def _bool(values: Dict[str, str], key: str, default: bool) -> bool:
    raw = values.get(key, "").strip().lower()
    if key not in values:
        return default
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    raise ConfigError(f"{key} must be true or false, got '{raw}'")


def parse_account(path: str, settings: Settings) -> Account:
    """Read and validate one account file. Raises ConfigError with a message naming the problem."""
    stem = os.path.basename(path)[:-len(".env")]
    try:
        values = read_env_file(path)
    except OSError as e:
        raise ConfigError(f"cannot read file: {e.strerror or e}") from None

    password = clean_value(values.get("ACCOUNT_PASSWORD")) or clean_value(values.get("ACCOUNT_SMTP_PASS"))
    # Register right away, so even an error message about this file cannot leak the password
    REDACTOR.add(password)
    REDACTOR.add(clean_value(values.get("ACCOUNT_SMTP_PASS")))

    email = clean_value(values.get("ACCOUNT_EMAIL"))
    if not email or "@" not in email:
        raise ConfigError("ACCOUNT_EMAIL is missing or still the example value")
    if not password:
        raise ConfigError("ACCOUNT_PASSWORD (or ACCOUNT_SMTP_PASS) is missing or still the example value")

    account = Account(
        id=clean_value(values.get("ACCOUNT_ID")) or stem,
        email=email,
        password=password,
        imap_host=clean_value(values.get("ACCOUNT_IMAP_HOST")) or "imap.web.de",
        imap_port=_int(values, "ACCOUNT_IMAP_PORT", 993),
        imap_timeout=_float(values, "ACCOUNT_IMAP_TIMEOUT", settings.imap_timeout),
        heartbeat_url=clean_value(values.get("HEARTBEAT_URL")),
    )
    REDACTOR.add(account.heartbeat_url)

    if _bool(values, "MAIL_SEND", False):
        account.mail = MailSettings(
            smtp_host=clean_value(values.get("MAIL_SMTP_HOST")) or "smtp.web.de",
            smtp_port=_int(values, "MAIL_SMTP_PORT", 465),
            smtp_user=clean_value(values.get("ACCOUNT_SMTP_USER")) or email,
            smtp_password=clean_value(values.get("ACCOUNT_SMTP_PASS")) or password,
            from_name=values.get("ACCOUNT_FROM_NAME", "").strip(),
            to_email=clean_value(values.get("MAIL_TO_EMAIL")) or email,
            subject_template=decode_newlines(values.get("TEMPLATE_SUBJECT", "").strip()) or DEFAULT_SUBJECT,
            body_template=decode_newlines(values.get("TEMPLATE_BODY", "").strip()) or DEFAULT_BODY,
        )

    obsolete = sorted(OBSOLETE_KEYS & values.keys())
    if obsolete:
        account.notes.append(f"ignores keys no longer used (see webdekeepalive.config): {', '.join(obsolete)}")
    unknown = sorted(values.keys() - ACCOUNT_KEYS - OBSOLETE_KEYS)
    if unknown:
        account.notes.append(f"unknown keys (typo?): {', '.join(unknown)}")
    return account


def account_files(accounts_dir: str, names: Optional[List[str]] = None) -> List[str]:
    """Account file paths: the given names ('user1' or 'user1.env'), or all *.env files (macOS '._*' skipped)."""
    if names:
        return [os.path.join(accounts_dir, n if n.endswith(".env") else f"{n}.env") for n in names]
    return [os.path.join(accounts_dir, f) for f in sorted(os.listdir(accounts_dir))
            if f.endswith(".env") and not f.startswith("._")]


def warn_if_readable_by_others(paths: List[str]):
    exposed = [os.path.basename(p) for p in paths if os.path.exists(p) and os.stat(p).st_mode & 0o077]
    if exposed:
        logger.warning(f"Files with credentials are readable by other users, run 'chmod 600' on: {', '.join(exposed)}")


@dataclass
class AccountResult:
    account_id: str
    email: str = ""
    success: bool = False
    message: str = ""
    error: Optional[str] = None
    # None = no report mail configured (or skipped), True/False = sent or failed
    mail_sent: Optional[bool] = None


def load_accounts(settings: Settings, names: Optional[List[str]] = None):
    """
    Returns (valid accounts, failed results for invalid files). An invalid file counts as a failed
    account, because otherwise that account would silently stop being kept alive.
    """
    accounts: List[Account] = []
    invalid: List[AccountResult] = []
    paths = account_files(settings.accounts_dir, names)
    warn_if_readable_by_others([CONFIG_FILE] + paths)
    seen = set()
    for path in paths:
        name = os.path.basename(path)
        try:
            if not os.path.isfile(path):
                raise ConfigError("file not found")
            account = parse_account(path, settings)
            if account.id in seen:
                raise ConfigError(f"account id '{account.id}' is used twice")
        except ConfigError as e:
            logger.error(f"Invalid account file '{name}': {e}")
            invalid.append(AccountResult(name[:-len('.env')] if name.endswith(".env") else name,
                                         error=f"invalid config: {e}"))
            continue
        seen.add(account.id)
        accounts.append(account)
    return accounts, invalid


# ============================================================================
# IMAP and SMTP
# ============================================================================

def describe(error: BaseException) -> str:
    text = str(error)
    if isinstance(error, imaplib.IMAP4.error) and error.args and isinstance(error.args[0], bytes):
        text = error.args[0].decode("utf-8", "replace")
    return f"{type(error).__name__}: {text}" if text else type(error).__name__


def with_retries(label: str, action: Callable[[], T], policy: RetryPolicy,
                 is_transient: Callable[[BaseException], bool]) -> T:
    """Run `action`, retrying transient errors with exponential backoff. Other errors are raised at once."""
    for attempt in range(1, policy.attempts + 1):
        try:
            return action()
        except Exception as e:
            if attempt >= policy.attempts or not is_transient(e):
                raise
            delay = policy.delay(attempt)
            logger.warning(f"{label}: attempt {attempt}/{policy.attempts} failed ({describe(e)}), "
                           f"retrying in {delay:.0f}s")
            time.sleep(delay)
    raise AssertionError("unreachable")


def is_imap_transient(error: BaseException) -> bool:
    """Network, DNS, TLS and timeout problems and dropped connections. Rejected logins are never retried."""
    return isinstance(error, (OSError, imaplib.IMAP4.abort))


def is_smtp_transient(error: BaseException) -> bool:
    """Like IMAP, plus temporary 4xx SMTP replies. smtplib.SMTPException is an OSError, so check it first."""
    if isinstance(error, smtplib.SMTPResponseException):
        return 400 <= error.smtp_code < 500
    if isinstance(error, smtplib.SMTPServerDisconnected):
        return True
    if isinstance(error, smtplib.SMTPException):
        return False
    return isinstance(error, OSError)


def imap_keepalive(account: Account) -> str:
    """One IMAP session: login, open INBOX read-only, NOOP, logout. Returns the INBOX message count."""
    context = ssl.create_default_context()
    with imaplib.IMAP4_SSL(account.imap_host, account.imap_port, ssl_context=context,
                           timeout=account.imap_timeout) as imap:
        try:
            imap.login(account.email, account.password)
        except imaplib.IMAP4.abort:
            raise
        except imaplib.IMAP4.error as e:
            raise LoginError(f"login rejected: {describe(e).split(': ', 1)[-1]}") from None
        typ, data = imap.select("INBOX", readonly=True)
        if typ != "OK":
            raise LoginError(f"SELECT INBOX returned {typ}")
        imap.noop()
    # Leaving the 'with' block sends LOGOUT
    return data[0].decode("ascii", "replace") if data and data[0] else "?"


def smtp_connect(mail: MailSettings, timeout: float) -> smtplib.SMTP:
    """Connected and logged-in SMTP session: implicit TLS on port 465, STARTTLS on any other port."""
    context = ssl.create_default_context()
    if mail.smtp_port == 465:
        server = smtplib.SMTP_SSL(mail.smtp_host, mail.smtp_port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(mail.smtp_host, mail.smtp_port, timeout=timeout)
    try:
        if mail.smtp_port != 465:
            server.starttls(context=context)
        server.login(mail.smtp_user, mail.smtp_password)
    except BaseException:
        server.close()
        raise
    return server


def build_message(account: Account, subject: str, body: str) -> EmailMessage:
    mail = account.mail
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((mail.from_name, account.email)) if mail.from_name else account.email
    message["To"] = mail.to_email
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=account.email.rsplit("@", 1)[-1])
    message.set_content(body)
    return message


def safe_format(template: str, context: Dict[str, str], fallback: str) -> str:
    """str.format_map that leaves unknown placeholders as they are and falls back on broken templates."""
    class SafeDict(dict):
        def __missing__(self, key):
            return "{" + key + "}"
    try:
        return template.format_map(SafeDict(context))
    except (ValueError, IndexError, AttributeError) as e:
        logger.warning(f"Mail template is invalid ({e}), using the built-in template")
        return fallback.format_map(SafeDict(context))


class LogCapture(logging.Handler):
    """Collects the (already redacted) log lines of one account for its report mail."""

    def __init__(self):
        super().__init__(logging.INFO)
        self.lines: List[str] = []
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord):
        self.lines.append(self.format(record))

    def text(self) -> str:
        return "\n".join(self.lines[-LOG_EXCERPT_LINES:])


# ============================================================================
# Heartbeat
# ============================================================================

def heartbeat_url(base_url: str, up: bool, message: str) -> str:
    """
    Uptime Kuma push URL with status and message. Any status/msg/ping parameters copied along
    with the push URL from Uptime Kuma are replaced.
    """
    parts = urlsplit(base_url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ("status", "msg", "ping")]
    query += [("status", "up" if up else "down"), ("msg", message[:HEARTBEAT_MESSAGE_LIMIT])]
    return urlunsplit(parts._replace(query=urlencode(query)))


def build_http_session(retries: int) -> requests.Session:
    """HTTP session that retries connection errors, 429 and 5xx with backoff (2s, 4s, 8s, ...)."""
    retry = Retry(total=retries, connect=retries, read=retries, status=retries, backoff_factor=2,
                  status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset({"GET"}),
                  respect_retry_after_header=True, raise_on_status=False)
    session = requests.Session()
    session.headers["User-Agent"] = f"{SCRIPT_NAME}/{__version__}"
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


class Notifier:
    def __init__(self, settings: Settings, http: Optional[requests.Session] = None):
        self.settings = settings
        self.http = http or build_http_session(settings.heartbeat.retries)

    def account_finished(self, account: Optional[Account], result: AccountResult):
        """Per-account heartbeat. Never raises."""
        if not account or not account.heartbeat_url:
            return
        try:
            message = f"OK: {result.message}" if result.success else f"FAILED: {result.error}"
            self.send_heartbeat(account.heartbeat_url, result.success, message, f"Heartbeat for '{account.id}'")
        except Exception:
            logger.exception(f"Sending heartbeat for '{account.id}' failed")

    def run_finished(self, up: bool, message: str):
        """Global heartbeat for the whole run. Never raises."""
        hb = self.settings.heartbeat
        if not hb.enabled:
            return
        try:
            self.send_heartbeat(hb.url, up, message, "Heartbeat")
        except Exception:
            logger.exception("Sending heartbeat failed")

    def send_heartbeat(self, base_url: str, up: bool, message: str, label: str) -> bool:
        message = REDACTOR.redact(message)
        logger.info(f"{label}: {'up' if up else 'down'} - {message}")
        try:
            response = self.http.get(heartbeat_url(base_url, up, message), timeout=self.settings.heartbeat.timeout)
        except requests.RequestException as e:
            logger.warning(f"{label} not delivered: {e}")
            return False
        if 200 <= response.status_code < 300:
            return True
        logger.warning(f"{label} not delivered: HTTP {response.status_code} - {response.text[:200]}")
        return False


# ============================================================================
# Keep-alive run
# ============================================================================

class KeepAlive:
    def __init__(self, settings: Settings, notifier: Notifier):
        self.settings = settings
        self.notifier = notifier
        self.hostname = socket.gethostname()

    def login(self, account: Account, result: AccountResult):
        try:
            count = with_retries(f"[{account.id}] IMAP login", lambda: imap_keepalive(account),
                                 self.settings.imap_retry, is_imap_transient)
        except LoginError as e:
            result.error = str(e)
            logger.error(f"[{account.id}] {e}. Check the password and that IMAP is enabled for the account.")
        except Exception as e:
            result.error = describe(e)
            logger.error(f"[{account.id}] IMAP login failed: {result.error}")
        else:
            result.success = True
            result.message = f"login successful, {count} message(s) in INBOX"
            logger.info(f"[{account.id}] {result.message}")

    def send_report(self, account: Account, result: AccountResult, log_excerpt: str) -> bool:
        """Report mail. Only connecting and login are retried, so the mail is never sent twice."""
        mail = account.mail
        context = {
            "account": account.id,
            "email": account.email,
            "status": "OK" if result.success else "FAILED",
            "message": result.message if result.success else (result.error or ""),
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": self.hostname,
            "log_excerpt": log_excerpt,
        }
        subject = REDACTOR.redact(safe_format(mail.subject_template, context, DEFAULT_SUBJECT)).replace("\n", " ")
        body = REDACTOR.redact(safe_format(mail.body_template, context, DEFAULT_BODY))
        try:
            server = with_retries(f"[{account.id}] SMTP connect",
                                  lambda: smtp_connect(mail, self.settings.smtp_timeout),
                                  self.settings.smtp_retry, is_smtp_transient)
            with server:
                server.send_message(build_message(account, subject, body))
        except Exception as e:
            logger.warning(f"[{account.id}] Report mail to {mail.to_email} failed: {describe(e)}")
            return False
        logger.info(f"[{account.id}] Report mail sent to {mail.to_email}")
        return True

    def process(self, account: Account, dry_run: bool = False) -> AccountResult:
        result = AccountResult(account.id, email=account.email)
        for note in account.notes:
            logger.info(f"[{account.id}] {note}")
        if dry_run:
            logger.info(f"[dry run] [{account.id}] would log in to {account.imap_host}:{account.imap_port} "
                        f"as {account.email}" + (f" and mail a report to {account.mail.to_email}" if account.mail else ""))
            result.success, result.message = True, "dry run"
            return result

        capture = LogCapture()
        logger.addHandler(capture)
        try:
            logger.info(f"[{account.id}] Logging in to {account.imap_host}:{account.imap_port} as {account.email}")
            self.login(account, result)
            if account.mail:
                same_password = account.mail.smtp_password == account.password
                if result.error and result.error.startswith("login rejected") and same_password:
                    # Another rejected login with the same password would only bring a lockout closer
                    logger.info(f"[{account.id}] No report mail, the password was just rejected")
                else:
                    result.mail_sent = self.send_report(account, result, capture.text())
        finally:
            logger.removeHandler(capture)
        return result

    def run(self, accounts: List[Account], dry_run: bool = False) -> List[AccountResult]:
        """Process all accounts one after another. A failing account never stops the others."""
        results = []
        for idx, account in enumerate(accounts, 1):
            try:
                result = self.process(account, dry_run=dry_run)
            except Exception as e:
                logger.exception(f"[{account.id}] Unexpected error")
                result = AccountResult(account.id, email=account.email, error=f"unexpected error: {e}")
            logger.info(f"FINAL_STATUS | {account.id} | {'SUCCESS' if result.success else 'FAILURE'} | "
                        f"mail: {'-' if result.mail_sent is None else ('sent' if result.mail_sent else 'failed')}")
            if not dry_run:
                self.notifier.account_finished(account, result)
            results.append(result)
            if idx < len(accounts) and not dry_run:
                time.sleep(self.settings.delay_between_accounts)
        return results


def exit_code(results: List[AccountResult]) -> int:
    """0 = all succeeded, 1 = all failed (or nothing to do), 2 = partial failure."""
    failed = sum(not r.success for r in results)
    if not results or failed == len(results):
        return 1
    return 2 if failed else 0


def run_summary(results: List[AccountResult], duration: float) -> str:
    failed = [r.account_id for r in results if not r.success]
    mail_failed = [r.account_id for r in results if r.mail_sent is False]
    if not failed:
        text = f"OK: {len(results)}/{len(results)} accounts logged in in {duration:.0f}s"
    else:
        text = f"FAILED {len(failed)}/{len(results)} in {duration:.0f}s: {', '.join(failed)}"
    if mail_failed:
        text += f" (report mail failed: {', '.join(mail_failed)})"
    return text


# ============================================================================
# Runtime: logging, lock, entry point
# ============================================================================

def setup_logging(settings: Settings, verbose: bool = False):
    """
    The log file is the main record. To limit SD card writes it is small and rotated, and the
    console (journald) only gets warnings unless --verbose is given or file logging is off.
    """
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.DEBUG if verbose else settings.log_level)
    if REDACTOR not in logger.filters:
        logger.addFilter(REDACTOR)
    formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")

    if settings.log_to_file:
        os.makedirs(os.path.dirname(settings.log_file), exist_ok=True)
        file_handler = RotatingFileHandler(settings.log_file, maxBytes=settings.log_max_bytes,
                                           backupCount=settings.log_backup_count, encoding="utf-8", delay=True)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG if verbose or not settings.log_to_file else logging.WARNING)
    logger.addHandler(console)


def acquire_lock(path: str) -> Optional[int]:
    """Returns the lock file descriptor, or None if another instance holds the lock."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd


def release_lock(fd: int):
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def raise_terminated(signum, frame):
    raise Terminated()


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IMAP keep-alive for WEB.DE Freemail accounts.")
    parser.add_argument("accounts", nargs="*",
                        help="Account names, i.e. files secrets/<name>.env (default: all *.env files)")
    parser.add_argument("-a", "--account", action="append", default=[], dest="account_options",
                        help="Account name, can be given several times (same as the positional names)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show debug output on the console")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Only check the configuration and show what would be done. No logins, no mails, no heartbeat.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    args.accounts = args.accounts + args.account_options
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_arguments(argv)
    try:
        settings = load_settings(CONFIG_FILE)
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    setup_logging(settings, args.verbose)
    for warning in settings.warnings:
        logger.warning(warning)

    lock_fd = acquire_lock(settings.lock_file)
    if lock_fd is None:
        logger.error("Another instance is already running, exiting")
        return 3

    notifier = Notifier(settings)
    started = time.monotonic()
    signal.signal(signal.SIGTERM, raise_terminated)
    try:
        logger.info(f"=== {SCRIPT_NAME} {__version__} started{' (dry run)' if args.dry_run else ''} ===")
        if not os.path.isdir(settings.accounts_dir):
            raise ConfigError(f"accounts directory '{settings.accounts_dir}' does not exist")
        accounts, invalid = load_accounts(settings, args.accounts)
        if not accounts and not invalid:
            raise ConfigError(f"no account files (*.env) found in '{settings.accounts_dir}'")

        results = invalid + KeepAlive(settings, notifier).run(accounts, dry_run=args.dry_run)
        code = exit_code(results)
        summary = run_summary(results, time.monotonic() - started)
        if args.dry_run:
            summary = "[dry run] " + summary.replace("logged in", "checked")
        logger.log(logging.INFO if code == 0 else logging.ERROR, f"=== {summary} ===")
        if not args.dry_run:
            notifier.run_finished(code == 0, summary)
        return code
    except ConfigError as e:
        logger.error(f"Configuration error: {e}")
        if not args.dry_run:
            notifier.run_finished(False, f"Configuration error: {e}")
        return 1
    except Terminated:
        # Ignore a second SIGTERM so the down heartbeat still gets out
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        logger.error("Stopped by SIGTERM (systemd timeout, shutdown or manual stop)")
        if not args.dry_run:
            notifier.run_finished(False, "Stopped: terminated before all accounts were processed")
        return 1
    except Exception as e:
        logger.exception("Unexpected error")
        if not args.dry_run:
            notifier.run_finished(False, f"Crashed: {type(e).__name__}: {e}")
        return 1
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        release_lock(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
