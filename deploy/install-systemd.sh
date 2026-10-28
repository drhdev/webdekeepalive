#!/usr/bin/env bash
# Installs (or updates) the systemd units for webdekeepalive.py: one weekly timer per account
# file secrets/<name>.env, scheduled by its SCHEDULE line (default: Sun 11:00).
# Run it as the user that owns the installation, it asks for sudo where needed:
#   ./deploy/install-systemd.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="$(id -un)"
UNIT_DIR=/etc/systemd/system
DEFAULT_SCHEDULE="Sun 11:00"

if [[ "$RUN_USER" == "root" ]]; then
    echo "Please run this script as the user that should run the keep-alive, not as root." >&2
    exit 1
fi
if [[ ! -x "$DIR/.venv/bin/python" ]]; then
    echo "Missing $DIR/.venv. Create it first: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi
if [[ ! -f "$DIR/webdekeepalive.config" ]]; then
    echo "Missing $DIR/webdekeepalive.config. Copy webdekeepalive.config.sample and configure it first." >&2
    exit 1
fi
shopt -s nullglob
ACCOUNT_FILES=("$DIR"/secrets/*.env)
if [[ ${#ACCOUNT_FILES[@]} -eq 0 ]]; then
    echo "No account file in $DIR/secrets. Copy secrets/user1.env.example to secrets/<name>.env first." >&2
    exit 1
fi

# The service may only write to logs/ (lock file and log file)
mkdir -p "$DIR/logs"
chmod 700 "$DIR/secrets"
chmod 600 "$DIR/webdekeepalive.config" "${ACCOUNT_FILES[@]}"

# Earlier installs used a single daily timer for all accounts
if [[ -f "$UNIT_DIR/webdekeepalive.timer" ]]; then
    echo "Removing the old daily webdekeepalive.timer"
    sudo systemctl disable --now webdekeepalive.timer || true
    sudo rm -f "$UNIT_DIR/webdekeepalive.timer" "$UNIT_DIR/webdekeepalive.service"
fi

echo "Installing units for user '$RUN_USER' in $DIR"
sed -e "s|__USER__|$RUN_USER|g" -e "s|__DIR__|$DIR|g" "$DIR/deploy/systemd/webdekeepalive@.service" \
    | sudo tee "$UNIT_DIR/webdekeepalive@.service" > /dev/null
sudo cp "$DIR/deploy/systemd/webdekeepalive@.timer" "$UNIT_DIR/webdekeepalive@.timer"

# Makes time-sync.target wait until the clock is really synchronised (Raspberry Pi OS uses systemd-timesyncd)
if systemctl is-active --quiet systemd-timesyncd.service; then
    sudo systemctl enable systemd-time-wait-sync.service
else
    echo "Note: systemd-timesyncd is not active, make sure the clock is synchronised by NTP." >&2
fi

TIMERS=()
for file in "${ACCOUNT_FILES[@]}"; do
    name="$(basename "$file" .env)"
    schedule="$(sed -n 's/^[[:space:]]*SCHEDULE[[:space:]]*=[[:space:]]*//p' "$file" | tail -n 1 | tr -d '\r"'"'")"
    schedule="${schedule:-$DEFAULT_SCHEDULE}"
    if ! systemd-analyze calendar "$schedule" > /dev/null 2>&1; then
        echo "Invalid SCHEDULE '$schedule' in $file, check it with: systemd-analyze calendar \"$schedule\"" >&2
        exit 1
    fi
    timer="webdekeepalive@$(systemd-escape "$name").timer"
    sudo mkdir -p "$UNIT_DIR/$timer.d"
    printf '[Timer]\nOnCalendar=\nOnCalendar=%s\n' "$schedule" | sudo tee "$UNIT_DIR/$timer.d/schedule.conf" > /dev/null
    echo "  $name: $schedule (plus up to 90 minutes random delay)"
    TIMERS+=("$timer")
done

sudo systemctl daemon-reload
for timer in "${TIMERS[@]}"; do
    sudo systemctl enable "$timer"
    # restart picks up a changed schedule of an already running timer
    sudo systemctl restart "$timer"
done

echo
systemctl list-timers 'webdekeepalive@*' --no-pager
echo
echo "Done. Start a run now with:  sudo systemctl start webdekeepalive@<name>.service"
echo "Follow the output with:      journalctl -u 'webdekeepalive@*' -f"
echo "Accounts removed from secrets/ keep their timer: sudo systemctl disable --now webdekeepalive@<name>.timer"
