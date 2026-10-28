"""Tests for webdekeepalive.py. IMAP, SMTP and HTTP are faked, see conftest.py."""

import imaplib
import logging
import os
import signal
import smtplib
import socket
import sys
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

import webdekeepalive
from webdekeepalive import (Account, AccountResult, ConfigError, HeartbeatSettings, LoginError, MailSettings,
                            RetryPolicy, Settings)

PASSWORD = "s3cret#pass=word"
PUSH_URL = "https://kuma.test/api/push/pushtoken123"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FakeIMAP:
    """Stands in for imaplib.IMAP4_SSL. `script` is a list of outcomes per connection: None = success."""
    script = []
    sessions = []

    def __init__(self, host, port, ssl_context=None, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.commands = []
        FakeIMAP.sessions.append(self)
        outcome = FakeIMAP.script.pop(0) if FakeIMAP.script else None
        if isinstance(outcome, OSError):
            raise outcome
        self.login_error = outcome

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.commands.append("LOGOUT")

    def login(self, user, password):
        self.commands.append(("LOGIN", user, password))
        if self.login_error:
            raise self.login_error

    def select(self, mailbox, readonly=False):
        self.commands.append(("SELECT", mailbox, readonly))
        return "OK", [b"42"]

    def noop(self):
        self.commands.append("NOOP")
        return "OK", [b""]


class FakeSMTP:
    sent = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def send_message(self, message):
        FakeSMTP.sent.append(message)


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    FakeIMAP.script, FakeIMAP.sessions, FakeSMTP.sent = [], [], []
    monkeypatch.setattr(webdekeepalive.imaplib, "IMAP4_SSL", FakeIMAP)
    monkeypatch.setattr(webdekeepalive, "smtp_connect", lambda mail, timeout: FakeSMTP())


def make_settings(**kwargs):
    defaults = dict(delay_between_accounts=0, imap_retry=RetryPolicy(attempts=3, base_delay=0),
                    smtp_retry=RetryPolicy(attempts=2, base_delay=0), heartbeat=HeartbeatSettings())
    defaults.update(kwargs)
    return Settings(**defaults)


def make_account(id="user1", mail=False, **kwargs):
    account = Account(id=id, email=f"{id}@mail.test", password=PASSWORD, **kwargs)
    if mail:
        account.mail = MailSettings(smtp_host="smtp.mail.test", smtp_port=465, smtp_user=account.email,
                                    smtp_password=PASSWORD, from_name="Bot", to_email="owner@mail.test")
    return account


def write_env(directory, name, text):
    path = directory / f"{name}.env"
    path.write_text(text)
    path.chmod(0o600)
    return str(path)


VALID_ENV = f"ACCOUNT_EMAIL=user1@mail.test\nACCOUNT_PASSWORD={PASSWORD}\n"


# ----------------------------------------------------------------------------
# Account files
# ----------------------------------------------------------------------------

def test_read_env_file_keeps_hash_and_equals_in_values(tmp_path):
    path = write_env(tmp_path, "a", f"# comment\n\nexport ACCOUNT_EMAIL = a@mail.test\nACCOUNT_PASSWORD='{PASSWORD}'\n")
    assert webdekeepalive.read_env_file(path) == {"ACCOUNT_EMAIL": "a@mail.test", "ACCOUNT_PASSWORD": PASSWORD}


def test_read_env_file_rejects_lines_without_equals(tmp_path):
    path = write_env(tmp_path, "a", "ACCOUNT_EMAIL\n")
    with pytest.raises(ConfigError, match="line 1"):
        webdekeepalive.read_env_file(path)


def test_parse_account_defaults(tmp_path):
    account = webdekeepalive.parse_account(write_env(tmp_path, "user1", VALID_ENV), make_settings(imap_timeout=12))
    assert (account.id, account.imap_host, account.imap_port, account.imap_timeout) == ("user1", "imap.web.de", 993, 12)
    assert account.mail is None and account.heartbeat_url is None and account.notes == []


def test_parse_account_falls_back_to_old_smtp_pass_key(tmp_path):
    path = write_env(tmp_path, "old", f"ACCOUNT_EMAIL=a@mail.test\nACCOUNT_SMTP_PASS={PASSWORD}\nLOG_LEVEL=DEBUG\n")
    account = webdekeepalive.parse_account(path, make_settings())
    assert account.password == PASSWORD
    assert "LOG_LEVEL" in account.notes[0]


@pytest.mark.parametrize("text, message", [
    ("ACCOUNT_EMAIL=user@example.com\nACCOUNT_PASSWORD=pw\n", "ACCOUNT_EMAIL"),
    ("ACCOUNT_EMAIL=a@mail.test\nACCOUNT_PASSWORD=replace_with_password\n", "ACCOUNT_PASSWORD"),
    (VALID_ENV + "ACCOUNT_IMAP_PORT=abc\n", "ACCOUNT_IMAP_PORT"),
    (VALID_ENV + "MAIL_SEND=maybe\n", "MAIL_SEND"),
])
def test_parse_account_rejects_invalid_values(tmp_path, text, message):
    with pytest.raises(ConfigError, match=message):
        webdekeepalive.parse_account(write_env(tmp_path, "a", text), make_settings())


def test_parse_account_mail_settings_and_templates(tmp_path):
    text = VALID_ENV + "MAIL_SEND=true\nTEMPLATE_BODY=Line1\\nLine2 {status}\nTYPO_KEY=1\n"
    account = webdekeepalive.parse_account(write_env(tmp_path, "a", text), make_settings())
    assert account.mail.smtp_port == 465 and account.mail.smtp_password == PASSWORD
    assert account.mail.to_email == "user1@mail.test"
    assert account.mail.body_template == "Line1\nLine2 {status}"
    assert "TYPO_KEY" in account.notes[0]


def test_load_accounts_counts_invalid_files_as_failures(tmp_path):
    write_env(tmp_path, "good", VALID_ENV)
    write_env(tmp_path, "bad", "ACCOUNT_EMAIL=\n")
    (tmp_path / "good.env.example").write_text(VALID_ENV)
    accounts, invalid = webdekeepalive.load_accounts(make_settings(accounts_dir=str(tmp_path)))
    assert [a.id for a in accounts] == ["good"]
    assert [r.account_id for r in invalid] == ["bad"] and not invalid[0].success


def test_load_accounts_by_name_reports_missing_file(tmp_path):
    write_env(tmp_path, "good", VALID_ENV)
    accounts, invalid = webdekeepalive.load_accounts(make_settings(accounts_dir=str(tmp_path)), ["good.env", "gone"])
    assert [a.id for a in accounts] == ["good"]
    assert invalid[0].account_id == "gone" and "not found" in invalid[0].error


# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------

def test_load_settings_without_file_uses_defaults(tmp_path):
    settings = webdekeepalive.load_settings(str(tmp_path / "missing.config"))
    assert settings.log_to_file and settings.log_level == logging.INFO
    assert settings.log_max_bytes == 1048576 and settings.log_backup_count == 2
    assert settings.imap_retry == RetryPolicy(attempts=4, base_delay=30, max_delay=300)
    assert not settings.heartbeat.enabled


def test_load_settings_disables_heartbeat_without_url(tmp_path):
    path = tmp_path / "c.config"
    path.write_text("[HEARTBEAT]\nenabled = true\nurl = https://uptime.example.com/api/push/your_push_token\n")
    settings = webdekeepalive.load_settings(str(path))
    assert not settings.heartbeat.enabled and "heartbeat disabled" in settings.warnings[0]


def test_load_settings_invalid_value(tmp_path):
    path = tmp_path / "c.config"
    path.write_text("[IMAP]\nattempts = many\n")
    with pytest.raises(ConfigError):
        webdekeepalive.load_settings(str(path))


# ----------------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------------

def test_redactor_removes_secrets_from_messages_and_tracebacks():
    redactor = webdekeepalive.SecretRedactor()
    redactor.add(PASSWORD)
    redactor.add(PUSH_URL)
    try:
        raise ValueError(f"bad {PASSWORD}")
    except ValueError:
        record = logging.LogRecord("t", logging.ERROR, "", 0, "pw %s url /api/push/pushtoken123", (PASSWORD,),
                                   exc_info=sys.exc_info())
    redactor.filter(record)
    assert PASSWORD not in record.msg and "pushtoken123" not in record.msg
    assert PASSWORD not in record.exc_text
    assert redactor.redact("send: 'AUTH PLAIN AGFiYwBkZWY='") == "send: 'AUTH PLAIN ***'"


# ----------------------------------------------------------------------------
# Retries and IMAP
# ----------------------------------------------------------------------------

def test_with_retries_retries_transient_errors_only():
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise socket.gaierror("Temporary failure in name resolution")
        return "done"

    assert webdekeepalive.with_retries("x", flaky, RetryPolicy(attempts=3, base_delay=0),
                                       webdekeepalive.is_imap_transient) == "done"
    assert len(calls) == 3

    calls.clear()
    with pytest.raises(LoginError):
        webdekeepalive.with_retries("x", lambda: calls.append(1) or (_ for _ in ()).throw(LoginError("no")),
                                    RetryPolicy(attempts=3, base_delay=0), webdekeepalive.is_imap_transient)
    assert len(calls) == 1


def test_retry_policy_backoff_is_capped():
    policy = RetryPolicy(attempts=5, base_delay=30, max_delay=100)
    assert [policy.delay(a) for a in (1, 2, 3, 4)] == [30, 60, 100, 100]


@pytest.mark.parametrize("error, transient", [
    (smtplib.SMTPAuthenticationError(535, b"auth failed"), False),
    (smtplib.SMTPResponseException(421, b"try later"), True),
    (smtplib.SMTPServerDisconnected("gone"), True),
    (smtplib.SMTPNotSupportedError("no STARTTLS"), False),
    (ConnectionResetError(), True),
    (socket.timeout("timed out"), True),
])
def test_is_smtp_transient(error, transient):
    assert webdekeepalive.is_smtp_transient(error) is transient


def test_imap_keepalive_session():
    account = make_account(imap_timeout=7)
    assert webdekeepalive.imap_keepalive(account) == "42"
    session = FakeIMAP.sessions[0]
    assert (session.host, session.port, session.timeout) == ("imap.web.de", 993, 7)
    assert session.commands == [("LOGIN", account.email, PASSWORD), ("SELECT", "INBOX", True), "NOOP", "LOGOUT"]


def test_imap_rejected_login_becomes_login_error():
    FakeIMAP.script = [imaplib.IMAP4.error(b"authentication failed")]
    with pytest.raises(LoginError, match="login rejected: authentication failed"):
        webdekeepalive.imap_keepalive(make_account())


def test_imap_abort_stays_transient():
    FakeIMAP.script = [imaplib.IMAP4.abort("socket error")]
    with pytest.raises(imaplib.IMAP4.abort):
        webdekeepalive.imap_keepalive(make_account())


# ----------------------------------------------------------------------------
# KeepAlive.process / run
# ----------------------------------------------------------------------------

def keepalive(session=None, **settings):
    s = make_settings(**settings)
    return webdekeepalive.KeepAlive(s, webdekeepalive.Notifier(s, http=session or FakeSession()))


def test_process_success_sends_redacted_report(monkeypatch):
    account = make_account(mail=True)
    account.mail.body_template = "{status} {message}\n{log_excerpt}\npw={unknown}"
    webdekeepalive.setup_logging(make_settings(log_to_file=False))
    webdekeepalive.REDACTOR.add(PASSWORD)
    result = keepalive().process(account)
    assert result.success and result.mail_sent and "42 message(s)" in result.message
    body = FakeSMTP.sent[0].get_content()
    assert body.startswith("OK login successful") and "user1@mail.test" in body and "{unknown}" in body
    assert FakeSMTP.sent[0]["To"] == "owner@mail.test"


def test_process_retries_network_errors_then_succeeds():
    FakeIMAP.script = [socket.timeout("timed out"), ConnectionRefusedError()]
    result = keepalive().process(make_account())
    assert result.success and len(FakeIMAP.sessions) == 3


def test_process_gives_up_after_attempts():
    FakeIMAP.script = [OSError(101, "Network is unreachable")] * 3
    result = keepalive().process(make_account())
    assert not result.success and "unreachable" in result.error and len(FakeIMAP.sessions) == 3


def test_process_rejected_login_is_not_retried_and_skips_mail():
    FakeIMAP.script = [imaplib.IMAP4.error(b"authentication failed")]
    result = keepalive().process(make_account(mail=True))
    assert not result.success and len(FakeIMAP.sessions) == 1
    assert result.mail_sent is None and FakeSMTP.sent == []


def test_process_failed_mail_does_not_fail_account(monkeypatch):
    def broken(mail, timeout):
        raise smtplib.SMTPAuthenticationError(535, b"auth failed")
    monkeypatch.setattr(webdekeepalive, "smtp_connect", broken)
    result = keepalive().process(make_account(mail=True))
    assert result.success and result.mail_sent is False


def test_run_continues_after_unexpected_error(monkeypatch):
    runner = keepalive()
    original = runner.process

    def process(account, dry_run=False):
        if account.id == "a":
            raise KeyError("boom")
        return original(account, dry_run)

    monkeypatch.setattr(runner, "process", process)
    results = runner.run([make_account("a"), make_account("b")])
    assert [r.success for r in results] == [False, True]
    assert webdekeepalive.exit_code(results) == 2


def test_run_sends_per_account_heartbeat():
    session = FakeSession()
    FakeIMAP.script = [imaplib.IMAP4.error(b"authentication failed")]
    keepalive(session).run([make_account(heartbeat_url=PUSH_URL + "?status=up&msg=OK&ping=")])
    query = parse_qs(urlsplit(session.urls[0]).query)
    assert query["status"] == ["down"] and query["msg"][0].startswith("FAILED: login rejected")
    assert "ping" not in query


def test_dry_run_makes_no_connections():
    session = FakeSession()
    results = keepalive(session).run([make_account(mail=True, heartbeat_url=PUSH_URL)], dry_run=True)
    assert results[0].success and FakeIMAP.sessions == [] and FakeSMTP.sent == [] and session.urls == []


# ----------------------------------------------------------------------------
# Heartbeat
# ----------------------------------------------------------------------------

def test_heartbeat_url_replaces_copied_parameters():
    url = webdekeepalive.heartbeat_url(PUSH_URL + "?status=up&msg=OK&ping=&keep=1", False, "x" * 500)
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    assert query["status"] == ["down"] and query["keep"] == ["1"] and len(query["msg"][0]) == 200
    assert "ping" not in query


def test_heartbeat_failure_is_only_a_warning(caplog):
    settings = make_settings(heartbeat=HeartbeatSettings(enabled=True, url=PUSH_URL))
    for response in (requests.ConnectionError("down"), FakeResponse(404, "not found")):
        notifier = webdekeepalive.Notifier(settings, http=FakeSession(response))
        assert notifier.send_heartbeat(PUSH_URL, True, "OK", "Heartbeat") is False


def test_http_session_retries_only_get():
    session = webdekeepalive.build_http_session(3)
    retry = session.get_adapter("https://kuma.test").max_retries
    assert retry.total == 3 and retry.allowed_methods == frozenset({"GET"})
    assert 503 in retry.status_forcelist and 429 in retry.status_forcelist


def test_real_http_is_blocked():
    with pytest.raises(RuntimeError, match="disabled"):
        webdekeepalive.build_http_session(0).get("https://kuma.test/api/push/x", timeout=1)


# ----------------------------------------------------------------------------
# Summary and exit codes
# ----------------------------------------------------------------------------

def test_exit_code_and_summary():
    ok, bad = AccountResult("a", success=True), AccountResult("b", error="x")
    assert webdekeepalive.exit_code([ok]) == 0
    assert webdekeepalive.exit_code([ok, bad]) == 2
    assert webdekeepalive.exit_code([bad]) == 1
    assert webdekeepalive.exit_code([]) == 1
    ok.mail_sent = False
    assert webdekeepalive.run_summary([ok, bad], 3) == "FAILED 1/2 in 3s: b (report mail failed: a)"


# ----------------------------------------------------------------------------
# main()
# ----------------------------------------------------------------------------

@pytest.fixture
def project(tmp_path, monkeypatch):
    """A temporary project directory with one valid account and a heartbeat."""
    (tmp_path / "secrets").mkdir()
    write_env(tmp_path / "secrets", "user1", VALID_ENV)
    config = tmp_path / "webdekeepalive.config"
    config.write_text(f"[LOGGING]\nfile_enabled = true\n[HEARTBEAT]\nenabled = true\nurl = {PUSH_URL}\n"
                      "[TIMING]\ndelay_between_accounts = 0\nlock_wait = 0\n[IMAP]\nbase_delay = 0\n")
    config.chmod(0o600)
    monkeypatch.setattr(webdekeepalive, "PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(webdekeepalive, "CONFIG_FILE", str(config))
    session = FakeSession()
    monkeypatch.setattr(webdekeepalive, "build_http_session", lambda retries: session)
    yield tmp_path, session
    logging.getLogger("webdekeepalive").handlers.clear()


def heartbeat_status(session):
    return [parse_qs(urlsplit(url).query)["status"][0] for url in session.urls]


def test_main_success(project):
    tmp_path, session = project
    assert webdekeepalive.main([]) == 0
    assert heartbeat_status(session) == ["up"]
    log = (tmp_path / "logs" / "webdekeepalive.log").read_text()
    assert "login successful" in log and PASSWORD not in log and "pushtoken123" not in log


def test_main_account_failure_reports_down(project):
    _, session = project
    FakeIMAP.script = [imaplib.IMAP4.error(b"authentication failed")]
    assert webdekeepalive.main(["--account", "user1"]) == 1
    assert heartbeat_status(session) == ["down"]


def test_main_config_error_reports_down(project):
    tmp_path, session = project
    os.remove(tmp_path / "secrets" / "user1.env")
    assert webdekeepalive.main([]) == 1
    assert heartbeat_status(session) == ["down"]
    assert "Configuration error" in parse_qs(urlsplit(session.urls[0]).query)["msg"][0]


def test_main_sigterm_reports_down(project, monkeypatch):
    _, session = project

    def terminated(self, accounts, dry_run=False):
        os.kill(os.getpid(), signal.SIGTERM)
        raise AssertionError("SIGTERM handler did not raise")

    monkeypatch.setattr(webdekeepalive.KeepAlive, "run", terminated)
    assert webdekeepalive.main([]) == 1
    assert heartbeat_status(session) == ["down"]
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL


def test_main_crash_reports_down(project, monkeypatch):
    _, session = project
    monkeypatch.setattr(webdekeepalive, "load_accounts", lambda *a: 1 / 0)
    assert webdekeepalive.main([]) == 1
    assert "Crashed: ZeroDivisionError" in parse_qs(urlsplit(session.urls[0]).query)["msg"][0]


def test_main_lock_held(project):
    tmp_path, session = project
    fd = webdekeepalive.acquire_lock(str(tmp_path / "logs" / "webdekeepalive.lock"))
    try:
        assert webdekeepalive.main([]) == 3
    finally:
        webdekeepalive.release_lock(fd)
    assert session.urls == []


def test_lock_waits_for_other_run(tmp_path, monkeypatch):
    path = str(tmp_path / "x.lock")
    holder = webdekeepalive.acquire_lock(path)
    released = []

    def sleep(seconds):
        # The other run finishes while we wait
        if not released:
            webdekeepalive.release_lock(holder)
            released.append(True)

    monkeypatch.setattr(webdekeepalive.time, "sleep", sleep)
    fd = webdekeepalive.acquire_lock(path, wait=60)
    assert fd is not None and released
    webdekeepalive.release_lock(fd)


def test_schedule_key_is_known(tmp_path):
    account = webdekeepalive.parse_account(write_env(tmp_path, "a", VALID_ENV + "SCHEDULE=Sun 10:00\n"),
                                           make_settings())
    assert account.notes == []


def test_main_dry_run_sends_nothing(project):
    _, session = project
    assert webdekeepalive.main(["--dry-run"]) == 0
    assert session.urls == [] and FakeIMAP.sessions == []


def test_tracked_examples_are_placeholders():
    """The example files in the repository must only contain placeholder values."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    values = webdekeepalive.read_env_file(os.path.join(root, "secrets", "user1.env.example"))
    for key in ("ACCOUNT_EMAIL", "ACCOUNT_PASSWORD", "MAIL_TO_EMAIL"):
        assert webdekeepalive.clean_value(values[key]) is None, key
