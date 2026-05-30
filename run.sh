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

# Load local environment overrides (DB connection, capture interface, etc.) from
# .env if present. Read inside the script so the values survive `sudo` stripping
# the caller's environment. `set -a` exports them so the backgrounded app
# inherits DATABASE_URL / PG* / NETWORK_INTERFACE without extra plumbing.
ENV_FILE="$PROJECT_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  echo "[INFO] Loading environment from .env"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

APP_HOST="${APP_HOST:-127.0.0.1}"
APP_PORT="${APP_PORT:-8000}"
SOCKETIO_CORS_ORIGINS="${SOCKETIO_CORS_ORIGINS:-}"
# Default to HTTPS-only geolocation: disable the unencrypted HTTP fallback
# (ip-api.com) unless the operator explicitly opts back in. Exported so the
# config-forwarding loop below picks it up like any other set variable.
export ALLOW_INSECURE_GEO_API="${ALLOW_INSECURE_GEO_API:-0}"

# --- Local PostgreSQL management (opt-in) ------------------------------------
# When MANAGE_LOCAL_DB=1, run.sh starts a private PostgreSQL cluster on `start`
# and shuts it down on `stop`, so the database lifecycle follows the tool. This
# is for the bare-metal dev path only; Docker users and anyone pointing at an
# external/remote PostgreSQL should leave it at 0 (the default) and just set
# DATABASE_URL. PostgreSQL cannot run as root, so DB management only happens when
# run.sh is invoked as a normal user (least-privilege mode).
MANAGE_LOCAL_DB="${MANAGE_LOCAL_DB:-0}"
# PostgreSQL refuses to run as root, so the local cluster always runs as an
# unprivileged user. Under sudo that is the invoking user ($SUDO_USER) and its
# home, so `sudo ./run.sh start|stop` still manages the database.
DB_OWNER="$(id -un)"
DB_OWNER_HOME="$HOME"
if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  DB_OWNER="$SUDO_USER"
  DB_OWNER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi
PGDATA_LOCAL="${PGDATA_LOCAL:-$DB_OWNER_HOME/.local/share/connectspoofer-pg}"
DB_PORT="${DB_PORT:-54329}"
DB_NAME="${DB_NAME:-connectspoofer}"
DB_USER="${DB_USER:-connectspoofer}"
DB_PASSWORD="${DB_PASSWORD:-connectspoofer}"
PG_CTL="${PG_CTL:-}"  # optional explicit path to pg_ctl

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

# --- Local PostgreSQL helpers ----------------------------------------------- #
# Locate the PostgreSQL bin directory (pg_ctl/initdb/psql). Honours $PG_CTL, then
# common distro locations, then $PATH.
find_pg_bin() {
  if [[ -n "$PG_CTL" && -x "$PG_CTL" ]]; then
    dirname "$PG_CTL"
    return 0
  fi
  local d
  for d in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin \
           /opt/homebrew/opt/postgresql*/bin /usr/local/opt/postgresql*/bin; do
    if [[ -x "$d/pg_ctl" ]]; then
      echo "$d"
      return 0
    fi
  done
  if command -v pg_ctl >/dev/null 2>&1; then
    dirname "$(command -v pg_ctl)"
    return 0
  fi
  return 1
}

# Run a command as the unprivileged DB owner. When run.sh is root (sudo), drop
# to $DB_OWNER via runuser so PostgreSQL never runs as root; otherwise run as-is.
as_db_owner() {
  if [[ "$(id -u)" -eq 0 && "$DB_OWNER" != "root" ]]; then
    runuser -u "$DB_OWNER" -- "$@"
  else
    "$@"
  fi
}

local_db_running() {
  local bin
  bin="$(find_pg_bin)" || return 1
  as_db_owner "$bin/pg_ctl" -D "$PGDATA_LOCAL" status >/dev/null 2>&1
}

# Start (and, on first run, initialize) the tool's private PostgreSQL cluster.
local_db_start() {
  [[ "$MANAGE_LOCAL_DB" == "1" ]] || return 0
  if [[ "$(id -u)" -eq 0 && "$DB_OWNER" == "root" ]]; then
    info "MANAGE_LOCAL_DB is set but no unprivileged user is available (running as real root)."
    info "Run as a normal user (or via sudo so \$SUDO_USER is set), or use Docker. Skipping DB management."
    return 0
  fi
  local bin sock
  bin="$(find_pg_bin)" || { info "PostgreSQL binaries not found (set PG_CTL=/path/to/pg_ctl); skipping local DB management."; return 0; }
  sock="$PGDATA_LOCAL/sockets"

  if [[ ! -s "$PGDATA_LOCAL/PG_VERSION" ]]; then
    info "Initializing private PostgreSQL cluster at $PGDATA_LOCAL (owner: $DB_OWNER)"
    as_db_owner mkdir -p "$PGDATA_LOCAL"
    as_db_owner chmod 700 "$PGDATA_LOCAL"
    as_db_owner "$bin/initdb" -D "$PGDATA_LOCAL" -U postgres --auth-local=trust --auth-host=scram-sha-256 -E UTF8 >/dev/null
    as_db_owner mkdir -p "$sock"
    printf '\n# ConnectSpoofer local dev instance\nlisten_addresses = %s\nport = %s\nunix_socket_directories = %s\n' \
      "'127.0.0.1'" "$DB_PORT" "'$sock'" | as_db_owner tee -a "$PGDATA_LOCAL/postgresql.conf" >/dev/null
    printf 'host all all 127.0.0.1/32 scram-sha-256\n' | as_db_owner tee -a "$PGDATA_LOCAL/pg_hba.conf" >/dev/null
  fi
  as_db_owner mkdir -p "$sock"

  if local_db_running; then
    info "Local PostgreSQL already running (127.0.0.1:$DB_PORT)."
  else
    info "Starting local PostgreSQL (127.0.0.1:$DB_PORT, owner: $DB_OWNER)..."
    as_db_owner "$bin/pg_ctl" -D "$PGDATA_LOCAL" -w -l "$PGDATA_LOCAL/server.log" start >/dev/null \
      || { info "Warning: could not start local PostgreSQL. See $PGDATA_LOCAL/server.log"; return 0; }
  fi

  # Ensure role + database exist (idempotent). Admin via the local socket (trust).
  as_db_owner "$bin/psql" -h "$sock" -p "$DB_PORT" -U postgres -tc \
    "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null | grep -q 1 \
    || as_db_owner "$bin/psql" -h "$sock" -p "$DB_PORT" -U postgres -c \
       "CREATE ROLE \"$DB_USER\" LOGIN PASSWORD '$DB_PASSWORD'" >/dev/null
  as_db_owner "$bin/psql" -h "$sock" -p "$DB_PORT" -U postgres -tc \
    "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null | grep -q 1 \
    || as_db_owner "$bin/psql" -h "$sock" -p "$DB_PORT" -U postgres -c \
       "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_USER\"" >/dev/null
}

# Stop the tool's private PostgreSQL cluster (only the one run.sh manages).
local_db_stop() {
  [[ "$MANAGE_LOCAL_DB" == "1" ]] || return 0
  [[ "$(id -u)" -eq 0 && "$DB_OWNER" == "root" ]] && return 0
  local bin
  bin="$(find_pg_bin)" || return 0
  if local_db_running; then
    info "Stopping local PostgreSQL (127.0.0.1:$DB_PORT)..."
    as_db_owner "$bin/pg_ctl" -D "$PGDATA_LOCAL" -w -m fast stop >/dev/null \
      || info "Warning: could not stop local PostgreSQL."
  else
    info "Local PostgreSQL is not running."
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

  # If the venv already has every runtime dependency (e.g. it was created with
  # uv earlier), don't fail just because uv isn't on PATH (common under `sudo`)
  # and the venv has no pip — use it as-is.
  if [[ -x "$VENV/bin/python" ]] && "$VENV/bin/python" - <<'PY' 2>/dev/null
import importlib.util as u, sys
mods = ["scapy", "flask", "flask_socketio", "psycopg", "requests", "zeroconf", "maxminddb"]
sys.exit(0 if all(u.find_spec(m) for m in mods) else 1)
PY
  then
    info "Dependencies already present in $VENV; skipping dependency sync."
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
  local_db_start
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
  local app_state=0
  if is_running; then
    echo "app: running PID=$(current_pid) URL=http://$APP_HOST:$APP_PORT"
  else
    echo "app: stopped"
    app_state=1
  fi
  if [[ "$MANAGE_LOCAL_DB" == "1" ]]; then
    if local_db_running; then
      echo "db:  running 127.0.0.1:$DB_PORT ($PGDATA_LOCAL)"
    else
      echo "db:  stopped"
    fi
  fi
  return "$app_state"
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
    # Bring the tool's private database down with it (no-op unless
    # MANAGE_LOCAL_DB=1). restart_app intentionally does NOT call this, so a
    # restart keeps the database up.
    local_db_stop
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
