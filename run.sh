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
# Least-privilege (run as non-root): grant capture capabilities once, then
# start/stop without sudo:
#   sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f .venv/bin/python)"
#   ./run.sh start
#
# Environment:
#   PYTHON=python3.11      Override Python executable/version
#   UV=uv                  Select uv executable
#   APP_HOST=127.0.0.1     Bind address; use 0.0.0.0 only for trusted networks
#   APP_PORT=8000          Web UI port
#   SOCKETIO_CORS_ORIGINS  Comma-separated allowed browser origins

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$PROJECT_DIR/.venv"
REQ="$PROJECT_DIR/requirements.txt"
PYPROJECT="$PROJECT_DIR/pyproject.toml"
PYTHON="${PYTHON:-}"
UV="${UV:-uv}"
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
    "  PYTHON=python3.11      Override Python executable/version" \
    "  UV=uv                  Select uv executable" \
    "  APP_HOST=127.0.0.1     Bind address; use 0.0.0.0 only for trusted networks" \
    "  APP_PORT=8000          Web UI port" \
    "  SOCKETIO_CORS_ORIGINS  Comma-separated allowed browser origins" \
    "  RESELECT_INTERFACE=1  Re-run interface selection"
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "Root privileges are required for this command. Run: sudo $0 $*"
  fi
}

# Packet capture needs CAP_NET_RAW. Allow running as a non-root user when the
# interpreter that will run app.py has been granted the capability via setcap
# (least privilege). Falls back to requiring root otherwise.
require_capture_privileges() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 0
  fi

  local py="$VENV/bin/python"
  if command -v getcap >/dev/null 2>&1 && [[ -x "$py" ]]; then
    local real_py caps
    real_py="$(readlink -f "$py")"
    caps="$(getcap "$real_py" 2>/dev/null || true)"
    if [[ "$caps" == *cap_net_raw* ]]; then
      info "Running as non-root using granted capabilities on $real_py"
      return 0
    fi
  fi

  die "Packet capture needs root or CAP_NET_RAW. Either run: sudo $0 ${COMMAND}
  or grant the capability once to run as a non-root user (least privilege):
    sudo setcap cap_net_raw,cap_net_admin=eip \$(readlink -f \"$VENV/bin/python\")"
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
      info "Installing system packages with apt..."
      apt-get update
      # libcap2-bin is required for setcap (least privilege capture)
      DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip python3-dev libpcap-dev tcpdump libcap2-bin sqlite3 curl
      ;;
    dnf)
      info "Installing system packages with dnf..."
      dnf install -y python3 python3-pip python3-devel libpcap-devel tcpdump libcap sqlite3 curl
      ;;
    yum)
      info "Installing system packages with yum..."
      yum install -y python3 python3-pip python3-devel libpcap-devel tcpdump libcap sqlite3 curl
      ;;
    pacman)
      info "Installing system packages with pacman..."
      pacman -Sy --needed --noconfirm python python-pip libpcap tcpdump libcap sqlite3 curl
      ;;
    zypper)
      info "Installing system packages with zypper..."
      zypper --non-interactive install python3 python3-pip python3-devel libpcap-devel tcpdump libcap-progs sqlite3 curl
      ;;
    brew)
      info "Installing system packages with brew..."
      brew install python libpcap sqlite curl
      ;;
    none)
      info "No supported package manager found; checking existing tools."
      ;;
  esac
}

ensure_python() {
  local python_cmd="${PYTHON:-python3}"
  command -v "$python_cmd" >/dev/null 2>&1 || die "Python not found: $python_cmd"
  "$python_cmd" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required")
PY
}

ensure_venv() {
  if command -v "$UV" >/dev/null 2>&1 && [[ -f "$PYPROJECT" ]]; then
    info "Synchronizing the Python environment with uv..."
    (
      cd "$PROJECT_DIR"
      sync_args=(sync --no-dev)
      if [[ -n "$PYTHON" ]]; then
        sync_args+=(--python "$PYTHON")
      fi
      if [[ -f "$PROJECT_DIR/uv.lock" ]]; then
        sync_args+=(--locked)
      fi
      UV_PROJECT_ENVIRONMENT="$VENV" "$UV" "${sync_args[@]}"
    )
    # Harden venv permissions
    chmod -R go-rwx "$VENV" || true
    return
  fi

  info "uv was not found or pyproject.toml is missing; using the venv/pip fallback."
  ensure_python
  if [[ ! -d "$VENV" ]]; then
    info "Creating virtual environment: $VENV"
    "${PYTHON:-python3}" -m venv "$VENV"
  else
    info "Using virtual environment: $VENV"
  fi

  # Harden venv permissions immediately after creation/use
  chmod -R go-rwx "$VENV" || true

  "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel

  if [[ -f "$REQ" ]]; then
    "$VENV/bin/python" -m pip install --upgrade -r "$REQ"
  fi
}

ensure_directories() {
  info "Hardening project directories..."
  # Ensure the data directory is private
  mkdir -p "$PROJECT_DIR/database"
  chmod 700 "$PROJECT_DIR/database" || true
  
  # Ensure the entire project isn't world-readable/writable by default
  # (only if we are the owner or have root)
  if [[ -O "$PROJECT_DIR" ]] || [[ "$(id -u)" -eq 0 ]]; then
    chmod go-w "$PROJECT_DIR" || true
  fi

  # Touch log and pid files with restricted permissions
  touch "$LOG_FILE" "$PID_FILE" 2>/dev/null || true
  chmod 600 "$LOG_FILE" "$PID_FILE" 2>/dev/null || true
}

configure_interface() {
  if [[ ! -f "$BACKEND_CONF" ]]; then
    info "No interface configuration found; starting interface selection."
    "$VENV/bin/python" "$PROJECT_DIR/select_interface.py"
    return
  fi

  if [[ "${RESELECT_INTERFACE:-0}" == "1" ]]; then
    "$VENV/bin/python" "$PROJECT_DIR/select_interface.py"
  else
    info "Interface configuration found. To select again: RESELECT_INTERFACE=1 sudo ./run.sh start"
  fi
}

install_all() {
  require_root "$@"
  install_system_packages
  ensure_directories
  ensure_venv
  
  # Automatically apply least-privilege capabilities if setcap is available.
  # This allows starting the app later without sudo.
  if command -v setcap >/dev/null 2>&1; then
    local py_path
    py_path="$(readlink -f "$VENV/bin/python")"
    info "Granting packet capture capabilities to $py_path..."
    setcap cap_net_raw,cap_net_admin=eip "$py_path" || info "Warning: Could not apply setcap."
  fi

  configure_interface
  info "Installation and setup completed."
  info "You can now start the app as a normal user: ./run.sh start"
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
  ensure_directories
  ensure_venv
  require_capture_privileges
  configure_interface

  if is_running; then
    info "ConnectSpoofer is already running with PID $(current_pid)."
    return 0
  fi

  rm -f "$PID_FILE"
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"

  info "Starting ConnectSpoofer in the background on http://$APP_HOST:$APP_PORT"
  # Forward security-relevant configuration to the background process. Only
  # variables that are actually set are passed, so an unset variable keeps the
  # in-app default instead of being overridden with an empty string (which would
  # e.g. break int() parsing of the numeric limits). Robust to sudo stripping
  # the environment, since we read whatever reached this script.
  local extra_env=()
  local v
  for v in FLASK_SECRET_KEY IPINFO_TOKEN ALLOW_INSECURE_GEO_API SESSION_COOKIE_SECURE \
           LOGIN_MAX_ATTEMPTS LOGIN_LOCKOUT_SECONDS SOCKET_RATE_LIMIT SOCKET_RATE_WINDOW \
           MAX_PACKET_LEN MAC_NEGATIVE_TTL; do
    if [[ -n "${!v:-}" ]]; then
      extra_env+=("$v=${!v}")
    fi
  done
  nohup env APP_HOST="$APP_HOST" APP_PORT="$APP_PORT" SOCKETIO_CORS_ORIGINS="$SOCKETIO_CORS_ORIGINS" \
    "${extra_env[@]+"${extra_env[@]}"}" "$VENV/bin/python" "$PROJECT_DIR/app.py" >> "$LOG_FILE" 2>&1 &
  local pid="$!"
  echo "$pid" > "$PID_FILE"
  chmod 600 "$PID_FILE"

  sleep 2
  if is_running; then
    info "Started. PID: $pid, log: $LOG_FILE"
  else
    rm -f "$PID_FILE"
    die "Start failed. Last logs: $(tail -n 20 "$LOG_FILE" 2>/dev/null | tr '\n' ' ')"
  fi
}

stop_app() {
  # No root required: the user who started the app owns the process and may
  # signal it. install (package management) still requires root.
  if ! is_running; then
    rm -f "$PID_FILE"
    info "ConnectSpoofer is not running."
    return 0
  fi

  local pid
  pid="$(current_pid)"
  info "Stopping ConnectSpoofer PID $pid..."
  kill "$pid"

  for _ in {1..20}; do
    if ! pid_is_running "$pid"; then
      rm -f "$PID_FILE"
      info "Stopped."
      return 0
    fi
    sleep 0.5
  done

  if pid_belongs_to_app "$pid"; then
    info "Process did not exit; sending SIGKILL."
    kill -9 "$pid"
  fi

  rm -f "$PID_FILE"
  info "Stopped."
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
    die "No log file exists yet: $LOG_FILE"
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
    die "Unknown command: $COMMAND"
    ;;
esac
