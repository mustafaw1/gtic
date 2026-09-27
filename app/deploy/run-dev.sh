#!/bin/bash
# Simple development server runner for GTIC REST API

HOST="${1:-0.0.0.0}"
PORT="${2:-8000}"
WORKERS="${3:-1}"

echo "GTIC REST API Development Server"
echo
echo -e "Configuration:"
echo "  • Host: $HOST"
echo "  • Port: $PORT"
echo "  • Workers: $WORKERS"
echo "  • Reload: Enabled"
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

echo
echo -e "Starting development server..."
echo -e "Access your API at:"
if [ "$HOST" = "0.0.0.0" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "localhost")
    echo "  • Documentation: http://$SERVER_IP:$PORT/docs"
    echo "  • API: http://$SERVER_IP:$PORT/api/"
    echo "  • Health: http://$SERVER_IP:$PORT/health"
    echo "  • Local: http://localhost:$PORT/docs"
else
    echo "  • Documentation: http://$HOST:$PORT/docs"
    echo "  • API: http://$HOST:$PORT/api/"
    echo "  • Health: http://$HOST:$PORT/health"
fi
echo
echo -e "Press Ctrl+C to stop the server"
echo

uvicorn app.main:app \
    --host $HOST \
    --port $PORT \
    --workers $WORKERS \
    --reload \
    --reload-dir app \
    --log-level info