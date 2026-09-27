#!/bin/bash
# Install otx-ingestion-service as a systemd service
set -e

INSTALL_DIR="${1:-/opt/gtic}"
SERVICE_USER="${2:-gtic}"
SERVICE_NAME="otx-ingestion-service"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 [install_dir] [user]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Installing $SERVICE_NAME..."
echo "  Install dir: $INSTALL_DIR"
echo "  Service user: $SERVICE_USER"

# Sync repo to install dir (skip venv/pycache)
rsync -a --exclude='.git' --exclude='venv' --exclude='gtic_env' \
    --exclude='__pycache__' --exclude='*.pyc' \
    "$REPO_ROOT/" "$INSTALL_DIR/"

# Create virtual environment and install dependencies
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/otx_service/requirements.txt" -q

# Configure environment file
ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    cp "$INSTALL_DIR/environment/otx_service/.env.example" "$ENV_FILE"
    echo "WARNING: .env created from example — configure it before starting:"
    echo "  $ENV_FILE"
fi

# Install systemd service (substitute paths and user)
sed -e "s|/opt/gtic|$INSTALL_DIR|g" \
    -e "s|User=gtic|User=$SERVICE_USER|g" \
    -e "s|Group=gtic|Group=$SERVICE_USER|g" \
    "$SCRIPT_DIR/$SERVICE_NAME.service" > "/etc/systemd/system/$SERVICE_NAME.service"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo
echo "$SERVICE_NAME installed and started."
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
