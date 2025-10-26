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
python3 -m venv .venv
source .venv/bin/activate
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

**IMPORTANT**: Before first use, IMAP/SMTP must be activated in the WEB.DE web interface:

1. **Open WEB.DE Webmail** → Login
2. **Settings** → **Email Programs** or **IMAP/POP3**
3. **Activate IMAP** (for email receiving)
4. **Activate SMTP** (for email sending)
5. **Save settings**

**Important**: 
- **Disable 2FA** (not supported)
- **Activation takes 5-15 minutes** to take effect
- **Use normal WEB.DE password** (no app password needed)

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
ACCOUNT_JITTER=0.5

# Secrets (ENTER REAL VALUES!)
ACCOUNT_FROM_NAME=Max Mustermann
ACCOUNT_SMTP_USER=my.email@web.de
ACCOUNT_SMTP_PASS=my_real_password

# Email notifications
MAIL_SEND=true
MAIL_SMTP_HOST=smtp.web.de
MAIL_SMTP_PORT=587
MAIL_SMTP_USE_TLS=true
MAIL_TO_EMAIL=my.email@web.de

# Email templates
TEMPLATE_SUBJECT=WEB.DE KeepAlive [{status}] {time} — {email}
TEMPLATE_BODY=Hello,\n\nthis is the automatic KeepAlive report.\n\nAccount: {email}\nTime: {time}\nStatus: {status}\nMessage: {message}\n\nLast log lines:\n{log_excerpt}\n\nBest regards

# Logging
LOG_DIR=logs
LOG_LEVEL=INFO

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
31 17 * * 6 /path/to/webdekeepalive/.venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user1 >> /path/to/webdekeepalive/cron_user1.out 2>&1

# user2: Every Saturday at 18:44
44 18 * * 6 /path/to/webdekeepalive/.venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user2 >> /path/to/webdekeepalive/cron_user2.out 2>&1
```

### Example: Monthly execution
```bash
# user1: 1st of every month at 10:00
0 10 1 * * /path/to/webdekeepalive/.venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user1 >> /path/to/webdekeepalive/cron_user1.out 2>&1

# user2: 15th of every month at 14:30
30 14 15 * * /path/to/webdekeepalive/.venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user2 >> /path/to/webdekeepalive/cron_user2.out 2>&1
```

### Example: Daily execution
```bash
# user1: Daily at 08:00
0 8 * * * /path/to/webdekeepalive/.venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user1 >> /path/to/webdekeepalive/cron_user1.out 2>&1

# user2: Daily at 20:00
0 20 * * * /path/to/webdekeepalive/.venv/bin/python /path/to/webdekeepalive/webdekeepalive.py --account user2 >> /path/to/webdekeepalive/cron_user2.out 2>&1
```

## Testing

### Manual test
```bash
# Activate virtual environment
source .venv/bin/activate

# Test with verbose output
python3 webdekeepalive.py --account user1 -v
python3 webdekeepalive.py --account user2 -v
```

### Expected output on success
```
2025-10-26 17:31:00,123 [INFO] [ACCOUNT=user1] Directory verification completed successfully
2025-10-26 17:31:00,124 [INFO] [ACCOUNT=user1] IMAP login attempt 1/5 for my.email@web.de (imap.web.de:993)
2025-10-26 17:31:00,245 [INFO] [ACCOUNT=user1] ✓ my.email@web.de: IMAP login successful
2025-10-26 17:31:00,246 [INFO] [ACCOUNT=user1] Email notification sent
```

## Monitoring

### Central logfile
```bash
# Monitor all accounts
tail -f logs/webdekeepalive.log

# Account-specific
grep "\[ACCOUNT=user1\]" logs/webdekeepalive.log | tail -f
grep "\[ACCOUNT=user2\]" logs/webdekeepalive.log | tail -f

# Error monitoring
grep "ERROR.*\[ACCOUNT=" logs/webdekeepalive.log
grep "WARNING.*\[ACCOUNT=" logs/webdekeepalive.log
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

### 2. 2FA enabled
**Problem**: `authentication failed` despite correct password
**Solution**: Disable 2FA in WEB.DE settings

### 3. Wrong server data
**Problem**: Connection errors
**Solution**: Use correct server data:
- IMAP: `imap.web.de:993` with SSL
- SMTP: `smtp.web.de:587` with STARTTLS

### 4. Virtual environment not activated
**Problem**: Exit code 4
**Solution**: Activate virtual environment or use `--no-venv-check`

### 5. Lockfile blocking
**Problem**: "Another run active"
**Solution**: Manually delete lockfile: `rm logs/.keepalive_user1.lock`

## Project Structure

```
webdekeepalive/
├── webdekeepalive.py              # Main script
├── secrets/
│   ├── user1.env.example          # Template for user1
│   ├── user2.env.example          # Template for user2
│   ├── user1.env                  # Real configuration (ignored)
│   └── user2.env                  # Real configuration (ignored)
├── logs/
│   └── webdekeepalive.log         # Central logfile
├── requirements.txt               # Python Dependencies
├── .gitignore                     # Git Ignore Rules
└── README.md                      # This documentation
```

## Features

- ✅ **Per-account configuration** in separate .env files
- ✅ **Centralized logging** with account identification
- ✅ **Email notifications** about success/failure
- ✅ **Robust error handling** with retry mechanism
- ✅ **Lockfile protection** against overlapping executions
- ✅ **Virtual environment** required (security)
- ✅ **No root privileges** needed
- ✅ **WEB.DE-optimized** with correct server data

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
