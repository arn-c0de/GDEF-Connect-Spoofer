#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ConnectSpoofer launcher
# Usage:
#   sudo ./run.sh install
#   sudo ./run.sh start
#   sudo ./run.sh stop
#   sudo ./run.sh restart
#   sudo ./run.sh status
#   sudo ./run.sh logs
#
# Environment:
#   PYTHON=python3.11      Select Python executable
#   APP_HOST=127.0.0.1     Bind address; use 0.0.0.0 only for trusted networks
#   APP_PORT=8000          Web UI port
#   SOCKETIO_CORS_ORIGINS  Comma-separated allowed browser origins

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$PROJECT_DIR/.venv"
REQ="$PROJECT_DIR/requirements.txt"
PYTHON="${PYTHON:-python3}"
BACKEND_CONF="$PROJECT_DIR/database/backend_conf.json"
LOG_FILE="$PROJECT_DIR/app.log"
PID_FILE="$PROJECT_DIR/app.pid"
APP_HOST="${APP_HOST:-127.0.0.1}"
APP_PORT="${APP_PORT:-8000}"
SOCKETIO_CORS_ORIGINS="${SOCKETIO_CORS_ORIGINS:-}"
COMMAND="${1:-start}"

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

info() {
  echo "[INFO] $*"
}

usage() {
  printf '%s\n' \
    "ConnectSpoofer launcher" \
    "Usage:" \
    "  sudo ./run.sh install" \
    "  sudo ./run.sh start" \
    "  sudo ./run.sh stop" \
    "  sudo ./run.sh restart" \
    "  sudo ./run.sh status" \
    "  sudo ./run.sh logs" \
    "" \
    "Environment:" \
    "  PYTHON=python3.11      Select Python executable" \
    "  APP_HOST=127.0.0.1     Bind address; use 0.0.0.0 only for trusted networks" \
    "  APP_PORT=8000          Web UI port" \
    "  SOCKETIO_CORS_ORIGINS  Comma-separated allowed browser origins" \
    "  RESELECT_INTERFACE=1  Re-run interface selection"
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "Root-Rechte sind fuer Packet-Sniffing noetig. Starte: sudo $0 $*"
  fi
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  elif command -v brew >/dev/null 2>&1; then
    echo "brew"
  else
    echo "none"
  fi
}

install_system_packages() {
  local manager
  manager="$(detect_package_manager)"

  case "$manager" in
    apt)
      info "Installiere Systempakete mit apt..."
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip python3-dev libpcap-dev tcpdump
      ;;
    dnf)
      info "Installiere Systempakete mit dnf..."
      dnf install -y python3 python3-pip python3-devel libpcap-devel tcpdump
      ;;
    yum)
      info "Installiere Systempakete mit yum..."
      yum install -y python3 python3-pip python3-devel libpcap-devel tcpdump
      ;;
    pacman)
      info "Installiere Systempakete mit pacman..."
      pacman -Sy --needed --noconfirm python python-pip libpcap tcpdump
      ;;
    zypper)
      info "Installiere Systempakete mit zypper..."
      zypper --non-interactive install python3 python3-pip python3-devel libpcap-devel tcpdump
      ;;
    brew)
      info "Installiere Systempakete mit brew..."
      brew install python libpcap
      ;;
    none)
      info "Kein unterstuetzter Paketmanager gefunden; pruefe vorhandene Tools."
      ;;
  esac
}

ensure_python() {
  command -v "$PYTHON" >/dev/null 2>&1 || die "Python nicht gefunden: $PYTHON"
  "$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 8):
    raise SystemExit("Python 3.8+ ist erforderlich")
PY
}

ensure_venv() {
  ensure_python

  if [[ ! -d "$VENV" ]]; then
    info "Erstelle virtuelle Umgebung: $VENV"
    "$PYTHON" -m venv "$VENV"
  else
    info "Nutze virtuelle Umgebung: $VENV"
  fi

  "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel

  if [[ -f "$REQ" ]]; then
    "$VENV/bin/python" -m pip install --upgrade -r "$REQ"
  fi
}

ensure_directories() {
  mkdir -p "$PROJECT_DIR/database"
  chmod 700 "$PROJECT_DIR/database" || true
}

configure_interface() {
  if [[ ! -f "$BACKEND_CONF" ]]; then
    info "Keine Interface-Konfiguration gefunden; starte Auswahl."
    "$VENV/bin/python" "$PROJECT_DIR/select_interface.py"
    return
  fi

  if [[ "${RESELECT_INTERFACE:-0}" == "1" ]]; then
    "$VENV/bin/python" "$PROJECT_DIR/select_interface.py"
  else
    info "Interface-Konfiguration vorhanden. Fuer Neuauswahl: RESELECT_INTERFACE=1 sudo ./run.sh start"
  fi
}

install_all() {
  require_root "$@"
  install_system_packages
  ensure_directories
  ensure_venv
  configure_interface
  info "Installation und Einrichtung abgeschlossen."
}

pid_is_running() {
  local pid="${1:-}"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

pid_belongs_to_app() {
  local pid="${1:-}"
  if [[ -r "/proc/$pid/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -F -- "$PROJECT_DIR/app.py" >/dev/null 2>&1
    return
  fi
  ps -p "$pid" -o command= 2>/dev/null | grep -F -- "$PROJECT_DIR/app.py" >/dev/null 2>&1
}

current_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(<"$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  echo "$pid"
}

is_running() {
  local pid
  pid="$(current_pid 2>/dev/null)" || return 1
  pid_is_running "$pid" && pid_belongs_to_app "$pid"
}

start_app() {
  require_root "$@"
  ensure_directories
  ensure_venv
  configure_interface

  if is_running; then
    info "ConnectSpoofer laeuft bereits mit PID $(current_pid)."
    return 0
  fi

  rm -f "$PID_FILE"
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"

  info "Starte ConnectSpoofer im Hintergrund auf http://$APP_HOST:$APP_PORT"
  nohup env APP_HOST="$APP_HOST" APP_PORT="$APP_PORT" SOCKETIO_CORS_ORIGINS="$SOCKETIO_CORS_ORIGINS" "$VENV/bin/python" "$PROJECT_DIR/app.py" >> "$LOG_FILE" 2>&1 &
  local pid="$!"
  echo "$pid" > "$PID_FILE"
  chmod 600 "$PID_FILE"

  sleep 2
  if is_running; then
    info "Gestartet. PID: $pid, Log: $LOG_FILE"
  else
    rm -f "$PID_FILE"
    die "Start fehlgeschlagen. Letzte Logs: $(tail -n 20 "$LOG_FILE" 2>/dev/null | tr '\n' ' ')"
  fi
}

stop_app() {
  require_root "$@"

  if ! is_running; then
    rm -f "$PID_FILE"
    info "ConnectSpoofer laeuft nicht."
    return 0
  fi

  local pid
  pid="$(current_pid)"
  info "Stoppe ConnectSpoofer PID $pid..."
  kill "$pid"

  for _ in {1..20}; do
    if ! pid_is_running "$pid"; then
      rm -f "$PID_FILE"
      info "Gestoppt."
      return 0
    fi
    sleep 0.5
  done

  if pid_belongs_to_app "$pid"; then
    info "Prozess reagiert nicht; sende SIGKILL."
    kill -9 "$pid"
  fi

  rm -f "$PID_FILE"
  info "Gestoppt."
}

restart_app() {
  stop_app "$@"
  start_app "$@"
}

status_app() {
  if is_running; then
    echo "running PID=$(current_pid) URL=http://$APP_HOST:$APP_PORT"
  else
    echo "stopped"
    return 1
  fi
}

show_logs() {
  if [[ ! -f "$LOG_FILE" ]]; then
    die "Noch keine Logdatei vorhanden: $LOG_FILE"
  fi
  tail -f "$LOG_FILE"
}

case "$COMMAND" in
  install|setup)
    install_all "$@"
    ;;
  start)
    start_app "$@"
    ;;
  stop)
    stop_app "$@"
    ;;
  restart)
    restart_app "$@"
    ;;
  status)
    status_app
    ;;
  logs)
    show_logs
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    die "Unbekannter Befehl: $COMMAND"
    ;;
esac
