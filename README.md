# webdekeepalive

Keeps **WEB.DE Freemail accounts** active. WEB.DE deactivates free accounts that have not been
logged in to for a longer period (several months). `webdekeepalive.py` logs in to every configured
account via IMAP on a schedule, so the addresses are not lost.

Built to run unattended on a Raspberry Pi: one weekly systemd timer per account, each on Sunday at
its own time with a new random delay every week, so the logins do not look like a bot.

## Features

- **IMAP keep-alive** for any number of accounts in one run: login, open INBOX read-only, NOOP, logout
- **Robust against WLAN/DNS hiccups**: network errors and timeouts are retried with exponential
  backoff; a rejected password is never retried, so the account is not locked
- **Heartbeat** to an Uptime Kuma push monitor (`status=up/down` with a short message), for the
  whole run and optionally per account. Reports `down` on failed logins, configuration errors,
  crashes and when the run is stopped (SIGTERM).
- **Optional report mail** per account (SMTP over SSL or STARTTLS, templates), sent once per run
- **No secrets in logs**: passwords and heartbeat URLs are masked in log lines, tracebacks and mails
- **SD-card friendly logging**: `INFO` by default, rotating file of 1 MB x 2, or journald only
- **Lock file** against overlapping runs, `--dry-run` to check the configuration
- systemd service and timer templates with hardening, plus an install script that sets up one
  timer per account from its `SCHEDULE` line

## Quick start

```bash
git clone https://github.com/drhdev/webdekeepalive.git ~/python/webdekeepalive
cd ~/python/webdekeepalive
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp webdekeepalive.config.sample webdekeepalive.config
cp secrets/user1.env.example secrets/user1.env        # one file per account
chmod 600 webdekeepalive.config secrets/*.env
nano secrets/user1.env                                 # ACCOUNT_EMAIL, ACCOUNT_PASSWORD, SCHEDULE
.venv/bin/python webdekeepalive.py --dry-run -v
.venv/bin/python webdekeepalive.py user1 -v
./deploy/install-systemd.sh                            # weekly timer per account
```

**The complete step-by-step guide** (WEB.DE settings, all configuration options, Uptime Kuma
monitor, systemd, updates, upgrading from the cron version 0.9, troubleshooting, uninstall) is in
[docs/deploy_git.md](docs/deploy_git.md).

## Usage

```
webdekeepalive.py [-h] [-a ACCOUNT] [-v] [-n] [--version] [accounts ...]

  accounts          account names, i.e. files secrets/<name>.env (default: all *.env files)
  -a, --account     account name, can be given several times
  -v, --verbose     debug output on the console
  -n, --dry-run     only check the configuration, no logins, no mails, no heartbeat
```

Exit codes: `0` all accounts logged in, `1` all failed / configuration error / stopped, `2` some
accounts failed, `3` another instance is running.

## Files

```
webdekeepalive.py                 the script
webdekeepalive.config.sample      global settings (copy to webdekeepalive.config)
secrets/user1.env.example         account template (copy to secrets/<name>.env)
deploy/systemd/                   service and timer templates (one instance per account)
deploy/install-systemd.sh         installs the units
docs/deploy_git.md                deployment guide
tests/                            tests, no network access
```

`webdekeepalive.config`, `secrets/*.env` and `logs/` are ignored by git and never committed.

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

The tests fake IMAP, SMTP and HTTP and fail on any real network connection.

## License

GNU General Public License v3, see [LICENSE](LICENSE).
