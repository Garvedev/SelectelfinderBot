#!/bin/bash
set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SERVICE_NAME="${SERVICE_NAME:-swiftshield-watchdog}"
SERVICE_USER="${SERVICE_USER:-finder}"
SERVICE_GROUP="${SERVICE_GROUP:-$SERVICE_USER}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

if [[ "$APP_DIR" == /root/* && "$SERVICE_USER" != "root" ]]; then
    echo "APP_DIR is under /root; using SERVICE_USER=root because system users cannot traverse /root"
    SERVICE_USER="root"
    SERVICE_GROUP="root"
fi

cd "$APP_DIR"

if [[ "$SERVICE_USER" != "root" ]] && ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
fi

if [[ "$SERVICE_USER" != "root" ]] && ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin --gid "$SERVICE_GROUP" "$SERVICE_USER"
fi

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [[ "$SERVICE_USER" != "root" ]]; then
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$APP_DIR"
fi

sed \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$APP_DIR|" \
    -e "s|^EnvironmentFile=.*|EnvironmentFile=$APP_DIR/.env|" \
    -e "s|^ExecStart=.*|ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/swiftshield_watchdog.py|" \
    -e "s|^User=.*|User=$SERVICE_USER|" \
    -e "s|^Group=.*|Group=$SERVICE_GROUP|" \
    -e "s|^ReadWritePaths=.*|ReadWritePaths=$APP_DIR|" \
    systemd/swiftshield-watchdog.service > "$SERVICE_FILE"

cp systemd/swiftshield-watchdog.timer "$TIMER_FILE"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME.timer"
systemctl status "$SERVICE_NAME.timer" --no-pager
