#!/bin/bash
# GTIC Services — full deployment
# Deploys: lookup-service, ingestion-services, otx-ingestion-service, gtic-rest-api
#
# Usage: sudo bash deploy.sh [install_dir] [user] [gtic_port] [lookup_port] [ingestion_port]

set -e

INSTALL_DIR="${1:-/opt/gtic}"
SERVICE_USER="${2:-gtic}"
GTIC_PORT="${3:-8000}"
LOOKUP_PORT="${4:-8001}"
INGESTION_PORT="${5:-8002}"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0 [install_dir] [user] [gtic_port] [lookup_port] [ingestion_port]"
    exit 1
fi

if ! command -v rsync &>/dev/null; then
    echo "rsync not found — installing..."
    apt-get install -y rsync -q
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER"
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" "$SERVICE_USER"
fi

echo "GTIC Services Deployment"
echo "  Install dir:  $INSTALL_DIR"
echo "  Service user: $SERVICE_USER"
echo "  Ports:        gtic=$GTIC_PORT  lookup=$LOOKUP_PORT  ingestion=$INGESTION_PORT"
echo

# ── Sync repo ────────────────────────────────────────────────────────────────
rsync -a \
    --exclude='.git' --exclude='venv' --exclude='gtic_env' \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='.env' \
    "$REPO_ROOT/" "$INSTALL_DIR/"

# ── Virtual environment + dependencies ───────────────────────────────────────
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi

PIP="$INSTALL_DIR/venv/bin/pip"
"$PIP" install --upgrade pip -q
for svc in app lookup_service ingestion_services otx_service; do
    "$PIP" install -r "$INSTALL_DIR/$svc/requirements.txt" -q
done

# ── Environment file ──────────────────────────────────────────────────────────
ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$REPO_ROOT/.env" ]; then
        cp "$REPO_ROOT/.env" "$ENV_FILE"
        echo "Copied .env from repo root to $INSTALL_DIR"
    else
        echo "ERROR: .env not found at $ENV_FILE"
        echo "Create it from the per-service templates in environment/:"
        echo "  environment/app/.env.example"
        echo "  environment/lookup_service/.env.example"
        echo "  environment/ingestion_services/.env.example"
        echo "  environment/otx_service/.env.example"
        exit 1
    fi
fi

if [ ! -d "$INSTALL_DIR/logs" ]; then
    mkdir -p "$INSTALL_DIR/logs"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/logs"
    chmod 750 "$INSTALL_DIR/logs"
    echo "Created logs directory: $INSTALL_DIR/logs"
fi

install_unit() {
    local name="$1"
    local src="$2"
    shift 2
    sed -e "s|/opt/gtic|$INSTALL_DIR|g" \
        -e "s|User=gtic|User=$SERVICE_USER|g" \
        -e "s|Group=gtic|Group=$SERVICE_USER|g" \
        -e "s|Type=exec|Type=simple|g" \
        "$@" \
        "$src" > "/etc/systemd/system/$name.service"
    echo "  installed $name.service"
}

install_unit "lookup-service" \
    "$INSTALL_DIR/lookup_service/deploy/lookup-service.service" \
    -e "s|--port 8001|--port $LOOKUP_PORT|g"

install_unit "ingestion-services" \
    "$INSTALL_DIR/ingestion_services/deploy/ingestion-services.service"

install_unit "otx-ingestion-service" \
    "$INSTALL_DIR/otx_service/deploy/otx-ingestion-service.service"

install_unit "gtic-rest-api" \
    "$INSTALL_DIR/app/deploy/gtic-rest-api.service" \
    -e "s|--port 8000|--port $GTIC_PORT|g"

# ── Enable + start ────────────────────────────────────────────────────────────
systemctl daemon-reload

for svc in lookup-service ingestion-services otx-ingestion-service gtic-rest-api; do
    systemctl enable "$svc"
done

systemctl restart lookup-service
sleep 3
systemctl restart ingestion-services otx-ingestion-service
sleep 3
systemctl restart gtic-rest-api

# ── Status report ─────────────────────────────────────────────────────────────
echo
echo "Service Status:"
for svc in lookup-service ingestion-services otx-ingestion-service gtic-rest-api; do
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "failed")
    echo "  • $svc: $status"
done

echo
echo "Endpoints:"
echo "  • GTIC REST API:       http://localhost:$GTIC_PORT/docs"
echo "  • Lookup Service:      http://localhost:$LOOKUP_PORT/health"
echo "  • Ingestion Services:  http://localhost:$INGESTION_PORT/health"
echo
echo "Management:"
echo "  • Logs:    journalctl -u <service> -f"
echo "  • Update:  sudo bash <service>/deploy/update.sh $INSTALL_DIR"
