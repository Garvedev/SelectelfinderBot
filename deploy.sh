#!/bin/bash
set -euo pipefail

APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SERVICE_NAME="${SERVICE_NAME:-swiftshield-watchdog}"
SERVICE_USER="${SERVICE_USER:-finder}"
SERVICE_GROUP="${SERVICE_GROUP:-$SERVICE_USER}"

cd "$APP_DIR"

if [[ "${SKIP_GIT_PULL:-false}" == "true" ]]; then
    echo "Code already updated by CI; skipping git pull"
elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git pull --ff-only
else
    echo "No git repository found in $APP_DIR; skipping git pull"
fi

export APP_DIR SERVICE_NAME SERVICE_USER SERVICE_GROUP
bash "$APP_DIR/deploy_swiftshield_watchdog.sh"
