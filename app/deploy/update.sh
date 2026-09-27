#!/bin/bash
# Update gtic-rest-api in place
set -e

INSTALL_DIR="${1:-/home/gtic-admin/gtic-restapi}"
SERVICE_NAME="gtic-rest-api"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 [install_dir]"
    exit 1
fi

echo "Updating $SERVICE_NAME from $INSTALL_DIR..."

cd "$INSTALL_DIR"
git pull

"$INSTALL_DIR/gtic_env/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/gtic_env/bin/pip" install -r "$INSTALL_DIR/app/requirements.txt" -q

SERVICE_USER="gtic"
if [ ! -d "$INSTALL_DIR/logs" ]; then
    mkdir -p "$INSTALL_DIR/logs"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/logs"
    chmod 750 "$INSTALL_DIR/logs"
    echo "Ensured logs directory: $INSTALL_DIR/logs"
fi

UNIT_SRC="$INSTALL_DIR/app/deploy/gtic-rest-api.service"
if [ -f "$UNIT_SRC" ]; then
    sed -e "s|/opt/gtic|$INSTALL_DIR|g" \
        -e "s|Type=exec|Type=simple|g" \
        "$UNIT_SRC" > "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" || true
fi

systemctl restart "$SERVICE_NAME"

echo
echo "$SERVICE_NAME updated and restarted."
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
