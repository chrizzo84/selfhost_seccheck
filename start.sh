#!/usr/bin/env bash
# Starts SelfHost SecCheck in the background.
#
#   ./start.sh               # http://127.0.0.1:8000 (or the next free port)
#   PORT=9000 ./start.sh     # fixed port, aborts if it is taken
#   HOST=0.0.0.0 ./start.sh  # reachable from the network
#   ./start.sh -f            # foreground (logs in the terminal, Ctrl+C stops)
#
# Creates the virtual environment on first start and installs the
# dependencies (again whenever pyproject.toml changes).

set -euo pipefail

cd "$(dirname "$0")"

HOST="${HOST:-127.0.0.1}"
PORT_FIXED="${PORT:+yes}"
PORT="${PORT:-8000}"
PYTHON="${PYTHON:-python3}"
RUN_DIR=".run"
PID_FILE="$RUN_DIR/seccheck.pid"
LOG_FILE="$RUN_DIR/seccheck.log"
VENV=".venv"

foreground=false
if [[ "${1:-}" == "-f" || "${1:-}" == "--foreground" ]]; then
  foreground=true
fi

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "SecCheck is already running (PID $(cat "$PID_FILE")). Run ./stop.sh first."
  exit 1
fi

# PID listening on the port. macOS allows binding 127.0.0.1 even though another
# process already holds *:PORT; two servers then answer depending on the
# address used. So check before starting.
port_owner() {
  command -v lsof >/dev/null || return 0
  lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | head -n 1
}

owner="$(port_owner "$PORT")"
if [[ -n "$owner" ]]; then
  # Shorten the interpreter path so it stays visible which app holds the port.
  owner_cmd="$(ps -o args= -p "$owner" 2>/dev/null | awk '{ sub(".*/", "", $1); print }' | cut -c1-120)"
  if [[ -n "$PORT_FIXED" ]]; then
    echo "Port $PORT is already in use by PID $owner: $owner_cmd"
    echo "Choose another port, e.g. PORT=$((PORT + 1)) ./start.sh"
    exit 1
  fi
  echo "Port $PORT is in use (PID $owner: $owner_cmd)."
  for candidate in $(seq $((PORT + 1)) $((PORT + 50))); do
    if [[ -z "$(port_owner "$candidate")" ]]; then
      PORT="$candidate"
      break
    fi
  done
  if [[ -n "$(port_owner "$PORT")" ]]; then
    echo "No free port found. Please set PORT=..."
    exit 1
  fi
  echo "Using port $PORT instead."
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "Creating virtual environment …"
  "$PYTHON" -m venv "$VENV"
fi

if [[ ! -f "$VENV/.installed" || pyproject.toml -nt "$VENV/.installed" ]]; then
  echo "Installing dependencies …"
  # [full] adds sslyze (complete cipher analysis). It ships native code; if no
  # wheel exists for this platform, fall back to the base installation.
  if ! "$VENV/bin/pip" install --quiet --disable-pip-version-check -e '.[full]'; then
    echo "sslyze could not be installed - installing without full cipher analysis."
    "$VENV/bin/pip" install --quiet --disable-pip-version-check -e .
  fi
  touch "$VENV/.installed"
fi

if $foreground; then
  echo "Starting SecCheck on http://$HOST:$PORT (Ctrl+C stops)"
  exec "$VENV/bin/python" -m seccheck serve --host "$HOST" --port "$PORT"
fi

mkdir -p "$RUN_DIR"
nohup "$VENV/bin/python" -m seccheck serve --host "$HOST" --port "$PORT" >>"$LOG_FILE" 2>&1 &
echo $! >"$PID_FILE"

# Wait until the server answers (up to ~10 s).
url="http://127.0.0.1:$PORT/api/apps"
for _ in $(seq 1 40); do
  if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "Start failed. Last log lines:"
    tail -n 20 "$LOG_FILE"
    exit 1
  fi
  if curl -fs -o /dev/null "$url"; then
    echo "SecCheck is running on http://$HOST:$PORT (PID $(cat "$PID_FILE"), log: $LOG_FILE)"
    exit 0
  fi
  sleep 0.25
done

echo "Server is not answering yet but is running (PID $(cat "$PID_FILE")). Log: $LOG_FILE"
