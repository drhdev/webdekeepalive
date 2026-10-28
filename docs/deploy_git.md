# Deployment on a Raspberry Pi with git and systemd

This guide installs `webdekeepalive.py` on a Raspberry Pi (tested setup: Raspberry Pi 3, Raspberry
Pi OS Lite, Bookworm or newer) in the home directory of the user that runs it, sets up the
configuration, a daily systemd timer and an Uptime Kuma heartbeat, and shows how to update it with
`git pull`.

The examples use the user `pi` and the directory `~/python/webdekeepalive`, i.e.
`/home/pi/python/webdekeepalive`. Use your own user name; the commands below take it from `$USER`
and `~` automatically.

**Contents**

1. [Prepare the Raspberry Pi](#1-prepare-the-raspberry-pi)
2. [Download with git](#2-download-with-git)
3. [Python environment](#3-python-environment)
4. [Prepare the WEB.DE accounts](#4-prepare-the-webde-accounts)
5. [Account files](#5-account-files-secretsnameenv)
6. [Global configuration](#6-global-configuration-webdekeepaliveconfig)
7. [Uptime Kuma push monitor](#7-uptime-kuma-push-monitor)
8. [Test by hand](#8-test-by-hand)
9. [Install the systemd timer](#9-install-the-systemd-timer)
10. [Test the systemd service](#10-test-the-systemd-service)
11. [Daily operation](#11-daily-operation)
12. [Updates with git pull](#12-updates-with-git-pull)
13. [Upgrading from version 0.9 (cron)](#13-upgrading-from-version-09-cron)
14. [Troubleshooting](#14-troubleshooting)
15. [Uninstall](#15-uninstall)

---

## 1. Prepare the Raspberry Pi

Log in to the Pi (e.g. `ssh pi@raspberrypi.local`) and install the required packages:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv
python3 --version   # must be 3.9 or newer
```

Set the time zone, it decides when the daily run starts:

```bash
sudo timedatectl set-timezone Europe/Berlin
timedatectl
```

`timedatectl` must show `System clock synchronized: yes` and `NTP service: active`. The Raspberry Pi
has no hardware clock and gets its time from the network after every boot. With a wrong date the
TLS certificate check of the IMAP server fails.

## 2. Download with git

```bash
mkdir -p ~/python
cd ~/python
git clone https://github.com/drhdev/webdekeepalive.git webdekeepalive
cd ~/python/webdekeepalive
```

The repository content is now in `~/python/webdekeepalive`. All following commands are run in this
directory unless stated otherwise.

## 3. Python environment

The virtual environment keeps the dependencies (`requests` for the heartbeat) separate from the
system Python:

```bash
cd ~/python/webdekeepalive
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 4. Prepare the WEB.DE accounts

Do this once per account in the WEB.DE web interface:

1. Log in to WEB.DE webmail
2. **Settings** → **POP3/IMAP** (or **E-Mail programs**): allow access via **IMAP** (and **SMTP**
   if you want report mails) and save
3. If your account offers or requires **app-specific passwords** (security settings), create one
   for `webdekeepalive` and copy it, it is only shown once. Otherwise the normal WEB.DE password is
   used.
4. Wait about 15 minutes until the change is active

Server data (defaults in the script): IMAP `imap.web.de:993` (SSL), SMTP `smtp.web.de:465` (SSL)
or `587` (STARTTLS).

## 5. Account files (`secrets/<name>.env`)

Create one file per account in `secrets/`. The file name without `.env` is the account name used
in the log, on the command line and in heartbeat messages.

```bash
cd ~/python/webdekeepalive
cp secrets/user1.env.example secrets/user1.env
nano secrets/user1.env
```

The minimum is:

```bash
ACCOUNT_ID=user1
ACCOUNT_EMAIL=your.name@web.de
ACCOUNT_PASSWORD=PASTE_PASSWORD_HERE
```

| Key | What to enter |
|---|---|
| `ACCOUNT_ID` | Short name for logs and messages, default: file name |
| `ACCOUNT_EMAIL` | The WEB.DE address, also the IMAP user name |
| `ACCOUNT_PASSWORD` | WEB.DE or app-specific password from step 4. Files from version 0.9 with `ACCOUNT_SMTP_PASS` keep working. |
| `ACCOUNT_IMAP_HOST`, `ACCOUNT_IMAP_PORT` | Only change them for other providers |
| `HEARTBEAT_URL` | Optional own Uptime Kuma monitor for this account, see step 7 |
| `MAIL_SEND` | `true` sends a short report mail after every run (also when the login failed for network reasons). With Uptime Kuma you usually do not need it. |
| `MAIL_SMTP_HOST`, `MAIL_SMTP_PORT`, `MAIL_TO_EMAIL`, `ACCOUNT_FROM_NAME` | Report mail settings, defaults: `smtp.web.de`, `465`, the account address, no name |
| `TEMPLATE_SUBJECT`, `TEMPLATE_BODY` | Mail templates, `\n` is a line break. Placeholders: `{account} {email} {time} {status} {message} {log_excerpt} {hostname}` |

Rules for the file: one `KEY=value` per line, no spaces needed around `=`, comments only on their
own line. Everything after `=` belongs to the value, so a password may contain `#`, `=` or spaces.

In nano: save with `Ctrl+O`, `Enter`, quit with `Ctrl+X`. Repeat for every account
(`secrets/user2.env`, ...), then protect the files:

```bash
chmod 700 secrets
chmod 600 secrets/*.env
```

## 6. Global configuration (`webdekeepalive.config`)

```bash
cd ~/python/webdekeepalive
cp webdekeepalive.config.sample webdekeepalive.config
chmod 600 webdekeepalive.config
nano webdekeepalive.config
```

Every option is explained in the file, the defaults fit a daily run. Usually you only change:

```ini
[LOGGING]
level = INFO

[HEARTBEAT]
enabled = true
url = https://uptime.example.com/api/push/AbCdEf1234?status=up&msg=OK&ping=
```

Retry behaviour (section `[IMAP]`): network problems such as a WLAN or DNS hiccup are retried 4
times with pauses of 30, 60 and 120 seconds. A rejected password is never retried, because repeated
failed logins can get the account blocked.

## 7. Uptime Kuma push monitor

The heartbeat reports a failed login **and** a run that did not happen at all (Pi switched off, SD
card broken, timer disabled). After each run the script calls the push URL with `status=up` and a
message like `OK: 2/2 accounts logged in in 4s`, or with `status=down` and the reason, e.g.
`FAILED 1/2 in 215s: user2`. If no push arrives within the heartbeat interval, Uptime Kuma marks the
monitor as down by itself.

### Create the monitor

1. Open Uptime Kuma and click **Add New Monitor**
2. **Monitor Type**: `Push`
3. **Friendly Name**: `WEB.DE keep-alive (Raspberry Pi)`
4. **Push URL**: Uptime Kuma shows a URL like
   `https://uptime.example.com/api/push/AbCdEf1234?status=up&msg=OK&ping=`.
   Click **Copy**. Keep this URL private, anyone who has it can report to the monitor.
5. **Heartbeat Interval**: `90000` seconds (25 hours) for the daily run.
   If your Uptime Kuma version does not accept values above `86400`, enter `86400`.
6. **Retries**: `1`
7. **Heartbeat Retry Interval**: `7200` seconds (2 hours)
8. **Notifications**: enable the channels that should alert you (e.g. Telegram, e-mail).
   If none exist yet, create one under **Settings → Notifications** first.
9. Click **Save**

The monitor shows *Pending* until the first push arrives.

Why these values: the timer starts at 07:15 plus a random delay of up to 30 minutes, and a run takes
seconds (or a few minutes with network retries). So two pushes are between about 23.5 and 24.5
hours apart. Interval plus retry interval (here 27 hours) is clearly longer, so you get no false
alarms, but a missing run is reported on the same day. With **Retries** `1`, Uptime Kuma first
switches to *Pending* and only alerts after the retry interval.

### Enter the URL

Paste the copied URL unchanged into `webdekeepalive.config`:

```ini
[HEARTBEAT]
enabled = true
url = https://uptime.example.com/api/push/AbCdEf1234?status=up&msg=OK&ping=
```

The script replaces `status`, `msg` and `ping` on every call and masks the URL in the log.

### Optional: one monitor per account

To see every account separately, create one more push monitor per account with the same settings and
enter its URL in the account file:

```bash
HEARTBEAT_URL=https://uptime.example.com/api/push/User1Token
```

It reports `OK: login successful, 123 message(s) in INBOX` or `FAILED: <reason>` for this account.
The global monitor keeps reporting the run as a whole.

## 8. Test by hand

Run these steps as your normal user in `~/python/webdekeepalive`.

**a) Reach Uptime Kuma from the Pi**: send a test push with the URL from step 7 (replace the
parameters at the end):

```bash
curl "https://uptime.example.com/api/push/AbCdEf1234?status=up&msg=manual-test"
```

The answer must be `{"ok":true}` and the monitor turns green.

**b) Dry run**: reads all files and shows what would be done, without logging in, sending mail or
calling the heartbeat:

```bash
.venv/bin/python webdekeepalive.py --dry-run -v
```

Check that there is no `Invalid account file` error and one `would log in` line per account.

**c) One real run for a single account**:

```bash
.venv/bin/python webdekeepalive.py user1 -v
echo "exit code: $?"
```

Expected: `[user1] login successful, N message(s) in INBOX`, a `FINAL_STATUS | user1 | SUCCESS`
line and exit code `0`. The heartbeat (and the report mail, if enabled) arrives.

## 9. Install the systemd timer

The repository contains a service and a timer in `deploy/systemd/`. The install script fills in
your user name and directory, copies both to `/etc/systemd/system/`, sets `chmod 600` on all
configuration files, makes `time-sync.target` wait for a synchronised clock and enables the timer:

```bash
cd ~/python/webdekeepalive
./deploy/install-systemd.sh
```

Run it as your normal user (not with `sudo`), it asks for the sudo password itself. At the end it
shows the next start time:

```
NEXT                        LEFT      LAST PASSED UNIT                   ACTIVATES
Thu 2025-01-02 07:31:09 CET 10h left  -    -      webdekeepalive.timer   webdekeepalive.service
```

What the service does (see `deploy/systemd/webdekeepalive.service`):

- runs `.venv/bin/python webdekeepalive.py` (all accounts) as your user in `~/python/webdekeepalive`
- starts only after the network is up and the clock is synchronised
- stops a run that hangs for more than 30 minutes (`TimeoutStartSec`); the script then reports
  `down` to the heartbeat. With more than 3 accounts raise the value in the service file.
- runs with low CPU and disk priority and may only write to `logs/`

The timer starts the service daily at 07:15 (plus up to 30 minutes) and catches up on a missed run
after the Pi was switched off. To change the time, edit `OnCalendar` in
`deploy/systemd/webdekeepalive.timer` and run the install script again. A weekly run
(`OnCalendar=Sat 07:15`) is enough to keep the accounts alive; then set the Uptime Kuma interval to
`691200` seconds (8 days).

## 10. Test the systemd service

Start a run now and follow it:

```bash
sudo systemctl start --no-block webdekeepalive.service
journalctl -u webdekeepalive.service -f
```

`Ctrl+C` ends the `journalctl` view, not the run. Without `--verbose` the journal only shows warnings
and errors; the full log is in the log file:

```bash
tail -f ~/python/webdekeepalive/logs/webdekeepalive.log
```

After the run:

```bash
systemctl status webdekeepalive.service      # "Deactivated successfully" / status=0/SUCCESS
systemctl list-timers webdekeepalive.timer   # LAST shows the run, NEXT the next one
grep FINAL_STATUS ~/python/webdekeepalive/logs/webdekeepalive.log | tail
```

In Uptime Kuma the monitor shows the message `OK: ... accounts logged in in ...`.

## 11. Daily operation

| Task | Command |
|---|---|
| When is the next run? | `systemctl list-timers webdekeepalive.timer` |
| Result of the last run | `systemctl status webdekeepalive.service` |
| Results per account | `grep FINAL_STATUS ~/python/webdekeepalive/logs/webdekeepalive.log \| tail -20` |
| Full log | `less ~/python/webdekeepalive/logs/webdekeepalive.log` |
| Run now | `sudo systemctl start --no-block webdekeepalive.service` |
| Stop a running run | `sudo systemctl stop webdekeepalive.service` (reports `down` to the heartbeat) |
| Pause the daily runs | `sudo systemctl disable --now webdekeepalive.timer` |
| Resume | `sudo systemctl enable --now webdekeepalive.timer` |
| Add an account | create `secrets/<name>.env`, `chmod 600` it, `.venv/bin/python webdekeepalive.py --dry-run -v` |

With level `INFO` a run writes about 5 lines per account. The log file is rotated at 1 MB and keeps
2 old files, so it never uses more than 3 MB. To write nothing at all to the SD card, set
`file_enabled = false` in `[LOGGING]`; the full log then goes to the journal
(`journalctl -u webdekeepalive.service`). Passwords and heartbeat URLs are masked in the log.

## 12. Updates with git pull

Your configuration (`webdekeepalive.config`, `secrets/*.env`) and the logs are not part of the
repository, `git pull` never changes them.

```bash
cd ~/python/webdekeepalive
git pull --ff-only
.venv/bin/pip install -r requirements.txt
.venv/bin/python webdekeepalive.py --dry-run -v
```

Then check what changed:

```bash
git log --oneline ORIG_HEAD..HEAD           # new commits
git diff --stat ORIG_HEAD HEAD              # changed files
```

- **New options in `webdekeepalive.config.sample`**: missing options in your `webdekeepalive.config`
  use their defaults, so nothing breaks. To adopt a new option, compare the files and copy what you
  need: `diff webdekeepalive.config.sample webdekeepalive.config`
- **Files in `deploy/` changed**: install the units again with `./deploy/install-systemd.sh`
- `git pull --ff-only` refuses to merge if you changed tracked files yourself. Show them with
  `git status`, then keep a copy and reset them, e.g. `git stash`, pull again, `git stash pop`.

To go back to the previous version: `git checkout ORIG_HEAD` right after the pull, or
`git log --oneline` and `git checkout <commit>`. Back to the latest version:
`git checkout main && git pull --ff-only`.

## 13. Upgrading from version 0.9 (cron)

Version 1.0 runs all accounts in one run from a systemd timer instead of one cron line per account.

1. Remove the old cron lines: `crontab -e`, delete the `webdekeepalive.py` lines, save
2. Update the code (step 12) and install the new dependencies (step 3)
3. Your `secrets/*.env` files keep working. The keys `ACCOUNT_RETRY_*`, `ACCOUNT_JITTER`,
   `ACCOUNT_EMAIL_DELAY`, `LOG_DIR`, `LOG_LEVEL`, `LOCK_USE` and `LOCK_DIR` are no longer used (the
   log says so once per run); delete them or move the values to `webdekeepalive.config`.
   Remove inline comments after values (`KEY=value  # comment`), they would become part of the value.
4. Create `webdekeepalive.config` (step 6) and continue with step 7
5. Delete old cron output files, they may contain SMTP protocol traces: `rm -f cron_*.out`

Changes in behaviour: exit codes are now `0` all OK, `1` all failed / configuration error, `2` some
accounts failed, `3` already running. The report mail is sent after the IMAP logout and only once.

## 14. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `status=203/EXEC` in `systemctl status` | `.venv` missing or moved: repeat step 3, then `./deploy/install-systemd.sh` |
| `Read-only file system` in the journal | `logs_dir` in `webdekeepalive.config` points outside `logs/`. The service may only write to `logs/`; keep the default. |
| `Invalid account file 'x.env': ...` | The reason is in the message; fix the file and run `--dry-run -v` |
| `login rejected: authentication failed` | Wrong password, IMAP access not enabled (step 4), or the change is not active yet. Not retried on purpose. |
| `retrying in 30s` warnings, then success | Short network problem, nothing to do |
| `gaierror` / `Network is unreachable` until the end | No network or DNS on the Pi: `ping -c3 imap.web.de` |
| `CERTIFICATE_VERIFY_FAILED` | Wrong clock: `timedatectl` (step 1) |
| `Report mail ... failed` | SMTP not enabled or wrong `MAIL_SMTP_PORT`; the keep-alive itself still counts as OK |
| `Another instance is already running` | A run is still active: `systemctl status webdekeepalive.service` |
| `Files with credentials are readable by other users` | `chmod 600 webdekeepalive.config secrets/*.env` |
| Uptime Kuma stays *Pending* | No push yet. Test with `curl` (step 8a) and check `[HEARTBEAT] enabled = true`. |
| Uptime Kuma shows *Down* with a message | The message says which account failed; details in `logs/webdekeepalive.log` |
| Uptime Kuma shows *Down* without a message | No push within the interval: Pi off, timer disabled (`systemctl list-timers`) or no network |
| Run starts long after 07:15 after a reboot | Expected: `Persistent=true` catches up, and the service waits for the clock to be synchronised |

Exit codes: `0` all accounts logged in, `1` all failed / configuration error / stopped, `2` some
accounts failed, `3` another instance is running. `systemctl status` shows any code other than `0`
as failed.

## 15. Uninstall

```bash
sudo systemctl disable --now webdekeepalive.timer
sudo rm /etc/systemd/system/webdekeepalive.service /etc/systemd/system/webdekeepalive.timer
sudo systemctl daemon-reload
rm -rf ~/python/webdekeepalive
```

Delete the Uptime Kuma monitor and, if you created them, the app-specific passwords in the WEB.DE
security settings. Without a regular login the accounts will expire again after some months.
