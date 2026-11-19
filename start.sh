#!/bin/sh
# Boot the stdlib ledger server on :9100 against this directory's ledger.jsonl.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
export VP_PORT=9100
export VP_DB="$ROOT/ledger.jsonl"
cd "$ROOT"
if curl -sf --max-time 1 "http://127.0.0.1:${VP_PORT}/health" >/dev/null 2>&1; then
  echo "already running"
  curl -sf "http://127.0.0.1:${VP_PORT}/health"
  echo
  exit 0
fi
nohup python server.py >> "$ROOT/server.log" 2>&1 &
echo $! > "$ROOT/server.pid"
i=0
while [ "$i" -lt 20 ]; do
  if curl -sf --max-time 1 "http://127.0.0.1:${VP_PORT}/health" >/dev/null 2>&1; then
    echo "started pid $(cat "$ROOT/server.pid")"
    exit 0
  fi
  i=$((i + 1))
  sleep 0.25
done
echo "failed to start" >&2
exit 1
