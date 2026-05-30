#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ConnectSpoofer – Smoke-Test Runner
# ==================================
# Fuehrt smoketest.py aus, der JEDE Funktion von app.py / select_interface.py
# testet (ohne echten Netzwerk-Traffic und ohne Root).
#
# Usage:
#   ./smoke-test.sh
#
# Environment:
#   UV=uv             uv-Executable (Default: uv, falls vorhanden)
#   PYTHON=python3    Fallback-Python, falls uv fehlt (Default: python3)
#
# Exit-Code 0 = alle Tests gruen, sonst != 0.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

SMOKE="$PROJECT_DIR/smoketest.py"
UV="${UV:-uv}"
PYTHON="${PYTHON:-python3}"

log()  { printf '\033[94m[smoke]\033[0m %s\n' "$*"; }
err()  { printf '\033[91m[smoke]\033[0m %s\n' "$*" >&2; }

if [[ ! -f "$SMOKE" ]]; then
  err "smoketest.py nicht gefunden in $PROJECT_DIR"
  exit 2
fi

# Bevorzugt uv (verwaltet .venv inkl. aller Dependencies reproduzierbar).
if command -v "$UV" >/dev/null 2>&1; then
  log "uv gefunden -> synchronisiere Umgebung (uv sync)"
  "$UV" sync --quiet
  log "starte Smoke-Test via uv"
  exec "$UV" run python "$SMOKE" "$@"
fi

# Fallback ohne uv: vorhandenes .venv nutzen oder eines anlegen.
err "uv nicht gefunden – Fallback auf $PYTHON + venv"
VENV="$PROJECT_DIR/.venv"
if [[ ! -x "$VENV/bin/python" ]]; then
  log "lege virtuelle Umgebung an: $VENV"
  "$PYTHON" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
log "installiere Dependencies (requirements.txt)"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r "$PROJECT_DIR/requirements.txt"
log "starte Smoke-Test"
exec python "$SMOKE" "$@"
