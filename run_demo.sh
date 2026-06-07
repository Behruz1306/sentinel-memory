#!/usr/bin/env bash
# One-command Sentinel demo: starts the LiveKit voice agent worker + the
# dashboard server, then open http://localhost:8000
set -e
cd "$(dirname "$0")"
PY=.venv/bin/python

echo "🛡  Starting Sentinel..."
$PY -m src.middleware.livekit_agent start > /tmp/sentinel-agent.log 2>&1 &
AGENT_PID=$!
$PY -m uvicorn server:app --port 8000 > /tmp/sentinel-server.log 2>&1 &
SERVER_PID=$!
trap "echo; echo 'stopping…'; kill $AGENT_PID $SERVER_PID 2>/dev/null" EXIT

sleep 4
echo "──────────────────────────────────────────────"
echo "  Dashboard : http://localhost:8000"
echo "  Agent log : /tmp/sentinel-agent.log"
echo "  Server log: /tmp/sentinel-server.log"
echo "  Ctrl+C to stop both."
echo "──────────────────────────────────────────────"
wait
