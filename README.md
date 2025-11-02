# webdekeepalive

A Python script for automatic **IMAP Keep-Alive** for WEB.DE Freemail accounts to prevent email account expiration.

## Problem

**WEB.DE Freemail accounts expire** when no login occurs over a longer period (usually 6-12 months). This affects:

- **Inactive email accounts** are automatically deactivated
- **Important email addresses** are lost
- **No notification** before expiration
- **Manual logins** are time-consuming and easily forgotten

## Solution

**webdekeepalive** solves this problem by:

- **Automatic IMAP logins** via Cron job
- **Per-account configuration** for multiple email addresses
- **Centralized logging** with account identification
- **Email notifications** about success/failure
- **Robust error handling** with retry mechanism
- **Lockfile protection** against overlapping executions

## Installation

### 1. Clone repository
```bash
git clone https://github.com/drhdev/webdekeepalive.git
cd webdekeepalive
```

### 2. Create virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Setup configuration
```bash
# Copy templates to real configuration
cp secrets/user1.env.example secrets/user1.env
cp secrets/user2.env.example secrets/user2.env

# Set security permissions
chmod 600 secrets/*.env

# Enter real values in secrets/*.env
nano secrets/user1.env
nano secrets/user2.env
```

## Configuration

### Prepare WEB.DE account

**IMPORTANT**: Before first use, IMAP/SMTP must be activated and an app-specific password must be created in the WEB.DE web interface:

1. **Open WEB.DE Webmail** → Login
2. **Settings** → **Email Programs** or **IMAP/POP3**
3. **Activate IMAP** (for email receiving)
4. **Activate SMTP** (for email sending)
5. **Create App-Specific Password**:
   - Go to **Security Settings** → **App-Specific Passwords**
   - Create a new password for "webdekeepalive" or similar
   - **Copy the generated password** (you won't see it again!)
6. **Save settings**
7. **Wait 15 minutes** for activation to take effect

**Important**: 
- **Disable 2FA** (not supported)
- **Activation takes 5-15 minutes** to take effect
- **Password type varies by account**:
  - **Some accounts**: Use app-specific password (create in WEB.DE security settings)
  - **Other accounts**: Use your standard WEB.DE login password
  - **Check your WEB.DE account settings** to determine which type is required
- **Script always uses SSL** (no TLS configuration needed)

### Account configuration

Each account is configured in `secrets/{account_id}.env`:

```bash
# Account identification
ACCOUNT_ID=user1
ACCOUNT_EMAIL=my.email@web.de

# IMAP server (WEB.DE standard)
ACCOUNT_IMAP_HOST=imap.web.de
ACCOUNT_IMAP_PORT=993
ACCOUNT_IMAP_TIMEOUT=30

# Retry configuration
ACCOUNT_RETRY_MAX=5
ACCOUNT_RETRY_BASE=5.0
ACCOUNT_RETRY_MAX_WAIT=120.0
ACCOUNT_RETRY_MIN_WAIT=30.0  # Minimum delay between retries (prevents rate limiting)
ACCOUNT_JITTER=0.5

# Email sending delay after IMAP NOOP command (seconds)
ACCOUNT_EMAIL_DELAY=11.0

# Secrets (ENTER REAL VALUES!)
ACCOUNT_FROM_NAME=Max Mustermann
ACCOUNT_SMTP_USER=my.email@web.de
ACCOUNT_SMTP_PASS=my_password  # Use app-specific password OR standard password (check WEB.DE settings)

# Email notifications
MAIL_SEND=true
MAIL_SMTP_HOST=smtp.web.de
MAIL_SMTP_PORT=465
MAIL_TO_EMAIL=my.email@web.de

# Email templates
TEMPLATE_SUBJECT=WEB.DE KeepAlive [{status}] {time} — {email}
TEMPLATE_BODY=Hello,\n\nthis is the KeepAlive report for your web.de email-account.\n\nAccount: {email}\nTime: {time}\nStatus: {status}\nMessage: {message}\n\nRecent log entries:\n{log_excerpt}\n\nRegards, your webdekeepalive-Bot from {hostname}

# Template variables:
# {email} - Account email address
# {time} - Current timestamp
# {status} - Login status (OK/ERROR)
# {message} - Status message
# {log_excerpt} - Recent log entries from current run
# {hostname} - Hostname of the server running the script

# Logging
LOG_DIR=logs
LOG_LEVEL=DEBUG

# Lockfile
LOCK_USE=true
LOCK_DIR=logs
```

## Setup Cron Jobs

### Example: Weekly execution
```bash
# Edit crontab
crontab -e

# user1: Every Saturday at 17:31
31 17 * * 6 cd /path/to/webdekeepalive && /path/to/webdekeepalive/venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user1 >> /path/to/webdekeepalive/cron_user1.out 2>&1

# user2: Every Saturday at 18:44
44 18 * * 6 cd /path/to/webdekeepalive && /path/to/webdekeepalive/venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user2 >> /path/to/webdekeepalive/cron_user2.out 2>&1
```

### Example: Monthly execution
```bash
# user1: 1st of every month at 10:00
0 10 1 * * cd /path/to/webdekeepalive && /path/to/webdekeepalive/venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user1 >> /path/to/webdekeepalive/cron_user1.out 2>&1

# user2: 15th of every month at 14:30
30 14 15 * * cd /path/to/webdekeepalive && /path/to/webdekeepalive/venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user2 >> /path/to/webdekeepalive/cron_user2.out 2>&1
```

### Example: Daily execution
```bash
# user1: Daily at 08:00
0 8 * * * cd /path/to/webdekeepalive && /path/to/webdekeepalive/venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user1 >> /path/to/webdekeepalive/cron_user1.out 2>&1

# user2: Daily at 20:00
0 20 * * * cd /path/to/webdekeepalive && /path/to/webdekeepalive/venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user2 >> /path/to/webdekeepalive/cron_user2.out 2>&1
```

## Testing

### Manual test
```bash
# Activate virtual environment
source venv/bin/activate

# Test with verbose output
python3 webdekeepalive.py --account user1 -v
python3 webdekeepalive.py --account user2 -v
```

### Expected output on success
```
2025-10-26 17:31:00,123 [INFO] [ACCOUNT=user1] Directory check completed successfully
2025-10-26 17:31:00,124 [INFO] [ACCOUNT=user1] IMAP login attempt 1/5 for my.email@web.de (imap.web.de:993)
2025-10-26 17:31:00,245 [INFO] [ACCOUNT=user1] ✅ my.email@web.de: Login successful – Account is active.
2025-10-26 17:31:00,246 [INFO] [ACCOUNT=user1] ✅ Email successfully sent to my.email@web.de
```

### Email notification content
The script sends personalized email notifications with:
- **Subject**: `WEB.DE KeepAlive [OK] 2025-10-26 17:31:00 — my.email@web.de`
- **Body**: KeepAlive report with account details, status, and recent log entries
- **Signature**: `Regards, your webdekeepalive-Bot from [hostname]`
- **Log entries**: Only from the current script execution (filtered for INFO level and above)

## Monitoring

### Central logfile
```bash
# Monitor all accounts (rotating log, max 1MB, 3 backups)
tail -f logs/webdekeepalive.log

# Account-specific monitoring
grep "\[ACCOUNT=user1\]" logs/webdekeepalive.log | tail -f
grep "\[ACCOUNT=user2\]" logs/webdekeepalive.log | tail -f

# Error monitoring
grep "ERROR.*\[ACCOUNT=" logs/webdekeepalive.log
grep "WARNING.*\[ACCOUNT=" logs/webdekeepalive.log

# Debug information (detailed server responses)
grep "DEBUG.*\[ACCOUNT=" logs/webdekeepalive.log | tail -20
```

### Monitor cron output
```bash
tail -f cron_user1.out
tail -f cron_user2.out
```

## Common Problems

### 1. IMAP/SMTP not activated
**Problem**: `authentication failed`
**Solution**: Activate IMAP/SMTP in WEB.DE web interface and wait 15 minutes

### 2. Wrong password type
**Problem**: `authentication failed` despite correct password
**Solution**: Check your WEB.DE account settings to determine the required password type:
- **Some accounts**: Require app-specific password (create in WEB.DE security settings)
- **Other accounts**: Use your standard WEB.DE login password
- **Test both types** if unsure which is required for your account

### 3. 2FA enabled
**Problem**: `authentication failed` despite correct password
**Solution**: Disable 2FA in WEB.DE settings

### 4. Wrong server data
**Problem**: Connection errors
**Solution**: Use correct server data:
- IMAP: `imap.web.de:993` with SSL
- SMTP: `smtp.web.de:465` with SSL (script always uses SSL, no TLS configuration needed)

### 5. Virtual environment not activated
**Problem**: Exit code 4
**Solution**: Activate virtual environment or use `--no-venv-check`

### 6. Lockfile blocking
**Problem**: "Another run active"
**Solution**: Manually delete lockfile: `rm logs/.keepalive_user1.lock`

## Project Structure

```
webdekeepalive/
├── webdekeepalive.py              # Main script (v0.9.9)
├── secrets/
│   ├── user1.env.example          # Template for user1 (79 lines, structured)
│   ├── user2.env.example          # Template for user2 (79 lines, structured)
│   ├── user1.env                  # Real configuration (ignored by git)
│   └── user2.env                  # Real configuration (ignored by git)
├── logs/
│   └── webdekeepalive.log         # Central logfile (rotating, 1MB max)
├── requirements.txt               # Python Dependencies
├── .gitignore                     # Git Ignore Rules
└── README.md                      # This documentation
```

## Features

- ✅ **Per-account configuration** in separate .env files with consistent structure
- ✅ **Centralized logging** with account identification and detailed debug information
- ✅ **Email notifications** with personalized hostname signature and current run logs only
- ✅ **Integrated email workflow** (sends during active IMAP session)
- ✅ **Configurable retry delays** with minimum wait time to prevent rate limiting
- ✅ **Robust error handling** with exponential backoff and detailed server response logging
- ✅ **Lockfile protection** against overlapping executions
- ✅ **Virtual environment** required (security)
- ✅ **No root privileges** needed
- ✅ **WEB.DE-optimized** with correct server data (IMAP: 993 SSL, SMTP: 465 SSL)
- ✅ **Always SSL** for secure email transmission (no TLS configuration needed)
- ✅ **App-specific password** support for WEB.DE
- ✅ **English language** throughout (logs, emails, messages)
- ✅ **Structured .env files** with clear sections and comprehensive comments

## Exit Codes

- **Exit 0**: Success
- **Exit 1**: IMAP login failed
- **Exit 2**: Configuration error (missing email, password)
- **Exit 3**: Directory problems (logs, lockfiles)
- **Exit 4**: Virtual environment missing or dependencies not met

## Security

- **No credentials in logs**: Passwords are never logged
- **Secure .env files**: `chmod 600` for secrets
- **Lockfiles**: Prevent overlapping executions
- **Virtual environment**: Isolated Python environment

## License

GNU PUBLIC LICENSE - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

For problems or questions:

1. **Create Issues** on GitHub
2. **Check logs** in `logs/webdekeepalive.log`
3. **Verify WEB.DE settings** (IMAP/SMTP activated?)
4. **Virtual environment** activated?
