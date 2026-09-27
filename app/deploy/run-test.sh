#!/bin/bash
# Test environment server runner for GTIC Services

HOST="${1:-0.0.0.0}"
GTIC_PORT="${2:-9000}"
LOOKUP_PORT="${3:-9001}"
INGESTION_PORT="${4:-9002}"
WORKERS="${5:-1}"

echo "GTIC Services Test Environment"
echo "Starting Lookup Service, REST API, and Ingestion Services"
echo
echo -e "Configuration:"
echo "  • Host: $HOST"
echo "  • GTIC REST API Port: $GTIC_PORT"
echo "  • Lookup Service Port: $LOOKUP_PORT"
echo "  • Ingestion Services Port: $INGESTION_PORT"
echo "  • Workers: $WORKERS"
echo "  • Reload: Enabled"
echo "  • Environment: TEST"
echo

if [ ! -d "gtic_env" ]; then
    echo -e "Virtual environment not found. Creating..."
    python3 -m venv gtic_env
    echo -e "Virtual environment created."
fi

source gtic_env/bin/activate

echo -e "Installing dependencies..."
pip install --upgrade pip
pip install -r app/requirements.txt

export ENVIRONMENT=test
export LOG_LEVEL=DEBUG
export LOOKUP_SERVICE_URL="http://localhost:$LOOKUP_PORT"

# Use test env file if it exists
if [ -f ".env.test" ]; then
    echo -e "Using .env.test configuration"
    set -a
    source .env.test
    set +a
fi

echo
echo -e "Starting test services..."

cleanup() {
    echo "Stopping services..."
    if [ ! -z "$LOOKUP_PID" ]; then
        kill $LOOKUP_PID 2>/dev/null
    fi
    if [ ! -z "$INGESTION_PID" ]; then
        kill $INGESTION_PID 2>/dev/null
    fi
    if [ ! -z "$GTIC_PID" ]; then
        kill $GTIC_PID 2>/dev/null
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

echo -e "Starting Lookup Service on port $LOOKUP_PORT..."
PYTHONPATH=. uvicorn lookup_service.main:app \
    --host $HOST \
    --port $LOOKUP_PORT \
    --reload \
    --reload-dir lookup_service \
    --log-level debug &
LOOKUP_PID=$!

sleep 3

echo -e "Starting Ingestion Services on port $INGESTION_PORT..."
cd ingestion_services
PYTHONPATH=.. uvicorn main:app \
    --host $HOST \
    --port $INGESTION_PORT \
    --reload \
    --reload-dir . \
    --log-level debug &
INGESTION_PID=$!
cd ..

sleep 3

echo -e "Starting GTIC REST API on port $GTIC_PORT..."
uvicorn app.main:app \
    --host $HOST \
    --port $GTIC_PORT \
    --workers $WORKERS \
    --reload \
    --reload-dir app \
    --log-level debug &
GTIC_PID=$!

sleep 2

echo
echo -e "Services started successfully!"
echo -e "Access your services at:"
if [ "$HOST" = "0.0.0.0" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "localhost")
    echo "  • GTIC REST API Documentation: http://$SERVER_IP:$GTIC_PORT/docs"
    echo "  • GTIC REST API Health: http://$SERVER_IP:$GTIC_PORT/health"
    echo "  • IOC Check Endpoint: http://$SERVER_IP:$GTIC_PORT/api/v1/check-iocs"
    echo "  • Lookup Service Health: http://$SERVER_IP:$LOOKUP_PORT/health"
    echo "  • CVE Lookup by CPE: http://$SERVER_IP:$LOOKUP_PORT/lookup/cve/by-cpe"
    echo "  • CVE Lookup by ID: http://$SERVER_IP:$LOOKUP_PORT/lookup/cve/by-id"
    echo "  • Ingestion Services Health: http://$SERVER_IP:$INGESTION_PORT/health"
    echo "  • Ingestion Services Stats: http://$SERVER_IP:$INGESTION_PORT/stats"
    echo "  • Manual OTX Trigger: http://$SERVER_IP:$INGESTION_PORT/trigger/otx"
    echo "  • Manual MALWARE Bazaar Trigger: http://$SERVER_IP:$INGESTION_PORT/trigger/malwarebazaar"
    echo "  • Local GTIC API: http://localhost:$GTIC_PORT/docs"
    echo "  • Local Lookup Service: http://localhost:$LOOKUP_PORT/health"
    echo "  • Local Ingestion Services: http://localhost:$INGESTION_PORT/health"
else
    echo "  • GTIC REST API Documentation: http://$HOST:$GTIC_PORT/docs"
    echo "  • GTIC REST API Health: http://$HOST:$GTIC_PORT/health"
    echo "  • IOC Check Endpoint: http://$HOST:$GTIC_PORT/api/v1/check-iocs"
    echo "  • Lookup Service Health: http://$HOST:$LOOKUP_PORT/health"
    echo "  • CVE Lookup by CPE: http://$HOST:$LOOKUP_PORT/lookup/cve/by-cpe"
    echo "  • CVE Lookup by ID: http://$HOST:$LOOKUP_PORT/lookup/cve/by-id"
    echo "  • Ingestion Services Health: http://$HOST:$INGESTION_PORT/health"
    echo "  • Ingestion Services Stats: http://$HOST:$INGESTION_PORT/stats"
    echo "  • Manual OTX Trigger: http://$HOST:$INGESTION_PORT/trigger/otx"
    echo "  • Manual MALWARE Bazaar Trigger: http://$HOST:$INGESTION_PORT/trigger/malwarebazaar"
fi
echo
echo -e "Service PIDs:"
echo "  • Lookup Service: $LOOKUP_PID"
echo "  • Ingestion Services: $INGESTION_PID"
echo "  • GTIC REST API: $GTIC_PID"
echo
echo -e "Manual testing commands:"
echo "  curl -X POST http://localhost:$INGESTION_PORT/trigger/otx"
echo "  curl -X POST http://localhost:$INGESTION_PORT/trigger/malwarebazaar"
echo
echo -e "Press Ctrl+C to stop all services"
echo

wait $LOOKUP_PID $INGESTION_PID $GTIC_PID