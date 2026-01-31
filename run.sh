#!/usr/bin/env bash
set -euo pipefail

# Small helper to create/update a venv and run app.py
# Usage:
#   ./run.sh           # create/update venv and run app.py in foreground
#   ./run.sh --bg      # run app.py in background (nohup)
#   PYTHON=python3.11 ./run.sh  # use custom python

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$PROJECT_DIR/.venv"
REQ="$PROJECT_DIR/requirements.txt"
PYTHON="${PYTHON:-python3}"

command -v "$PYTHON" >/dev/null 2>&1 || { echo "Python not found: $PYTHON"; exit 1; }

if [[ -d "$VENV" ]]; then
  echo "🔁 Updating virtualenv in $VENV"
  "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel
  if [[ -f "$REQ" ]]; then
    "$VENV/bin/pip" install --upgrade -r "$REQ"
  fi
else
  echo "📦 Creating virtualenv in $VENV"
  "$PYTHON" -m venv "$VENV"
  "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel
  if [[ -f "$REQ" ]]; then
    "$VENV/bin/pip" install -r "$REQ"
  fi
fi

# Start the app
if [[ "${1:-}" == "--bg" || "${1:-}" == "-d" ]]; then
  shift || true
  echo "🚀 Starting app.py in background (logs -> $PROJECT_DIR/app.log)"
  nohup "$VENV/bin/python" "$PROJECT_DIR/app.py" "$@" > "$PROJECT_DIR/app.log" 2>&1 &
  echo "$!" > "$PROJECT_DIR/app.pid"
  echo "PID: $(cat "$PROJECT_DIR/app.pid")"
else
  echo "▶️ Starting app.py in foreground"
  exec "$VENV/bin/python" "$PROJECT_DIR/app.py" "$@"
fi
