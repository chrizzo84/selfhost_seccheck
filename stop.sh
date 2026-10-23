#!/usr/bin/env bash
# Stops a SecCheck server started with ./start.sh.

set -euo pipefail

cd "$(dirname "$0")"

PID_FILE=".run/seccheck.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "SecCheck is not running (no PID file)."
  exit 0
fi

pid="$(cat "$PID_FILE")"
if ! kill -0 "$pid" 2>/dev/null; then
  echo "SecCheck is no longer running (stale PID $pid), cleaning up."
  rm -f "$PID_FILE"
  exit 0
fi

kill "$pid"
# Running scans get up to 10 s to finish cleanly.
for _ in $(seq 1 40); do
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$PID_FILE"
    echo "SecCheck stopped (PID $pid)."
    exit 0
  fi
  sleep 0.25
done

echo "Process does not respond, killing it."
kill -9 "$pid" 2>/dev/null || true
rm -f "$PID_FILE"
echo "SecCheck stopped (PID $pid)."
