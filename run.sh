#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ConnectSpoofer launcher — Docker Compose orchestrator.
#
# Everything runs in containers: the Flask sniffer/web app (host networking +
# NET_RAW/NET_ADMIN so Scapy sees the real NIC) and PostgreSQL. This sidesteps
# host-level capture-capability issues entirely.
#
# Usage:
#   ./run.sh start      build (if needed) and start the stack
#   ./run.sh stop       stop and remove the containers
#   ./run.sh restart    restart the containers
#   ./run.sh status     show container status
#   ./run.sh logs       follow the app logs
#   ./run.sh build      (re)build the app image
#   ./run.sh token      print the dashboard access token
#   ./run.sh rebuild    rebuild from scratch and start
#
# Requires Docker Engine + the Compose plugin (install separately):
#   https://docs.docker.com/engine/install/
# If your user is not in the 'docker' group, run via sudo (e.g. sudo ./run.sh start).
#
# Configuration lives in .env (copy from .env.example); set NETWORK_INTERFACE there.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"
ENV_FILE="$PROJECT_DIR/.env"
TOKEN_FILE="$PROJECT_DIR/database/access_token.txt"
DOCKER="${DOCKER:-docker}"
COMMAND="${1:-start}"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }

usage() {
  printf '%s\n' \
    "ConnectSpoofer launcher (Docker)" \
    "Usage:" \
    "  ./run.sh start      build (if needed) and start the stack" \
    "  ./run.sh stop       stop and remove the containers" \
    "  ./run.sh restart    restart the containers" \
    "  ./run.sh status     show container status" \
    "  ./run.sh logs       follow the app logs" \
    "  ./run.sh build      (re)build the app image" \
    "  ./run.sh rebuild    rebuild from scratch and start" \
    "  ./run.sh token      print the dashboard access token" \
    "" \
    "Requires Docker Engine + Compose plugin. Configure via .env (see .env.example)."
}

# Resolve the Compose CLI: prefer the v2 plugin ("docker compose"), then the
# legacy v1 binary ("docker-compose").
declare -a COMPOSE
detect_compose() {
  if "$DOCKER" compose version >/dev/null 2>&1; then
    COMPOSE=("$DOCKER" compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    die "Docker Compose not found. Install Docker Engine + the Compose plugin: https://docs.docker.com/engine/install/"
  fi
}

require_docker() {
  command -v "$DOCKER" >/dev/null 2>&1 || die "Docker not found. Install it first: https://docs.docker.com/engine/install/"
  if ! "$DOCKER" info >/dev/null 2>&1; then
    die "Cannot talk to the Docker daemon. Start it (e.g. sudo systemctl start docker) or run this via sudo, and make sure your user is in the 'docker' group."
  fi
  detect_compose
}

compose() {
  "${COMPOSE[@]}" --project-directory "$PROJECT_DIR" -f "$COMPOSE_FILE" "$@"
}

# Read a KEY=VALUE from .env without sourcing it (returns $2 if unset).
env_get() {
  local key="$1" def="${2:-}" val=""
  if [[ -f "$ENV_FILE" ]]; then
    val="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)"
  fi
  echo "${val:-$def}"
}

ensure_env() {
  [[ -f "$COMPOSE_FILE" ]] || die "docker-compose.yml not found at $COMPOSE_FILE"
  [[ -f "$ENV_FILE" ]] || die ".env not found. Copy .env.example to .env and set NETWORK_INTERFACE + a PostgreSQL password."
}

ensure_directories() {
  info "Hardening data directory..."
  mkdir -p "$PROJECT_DIR/database"
  chmod 700 "$PROJECT_DIR/database" 2>/dev/null || true
}

start_stack() {
  ensure_env; ensure_directories
  info "Starting ConnectSpoofer stack (building if needed)..."
  compose up -d --build
  info "Up. Dashboard: http://$(env_get APP_HOST 127.0.0.1):$(env_get APP_PORT 8000)"
  info "Token: ./run.sh token    Logs: ./run.sh logs    Stop: ./run.sh stop"
}

rebuild_stack() {
  ensure_env; ensure_directories
  info "Rebuilding image from scratch..."
  compose build --no-cache
  compose up -d
}

stop_stack()    { ensure_env; info "Stopping ConnectSpoofer stack..."; compose down; }
restart_stack() { ensure_env; info "Restarting ConnectSpoofer stack...";  compose restart; }
status_stack()  { ensure_env; compose ps; }
logs_stack()    { ensure_env; compose logs -f --tail=200 app; }
build_stack()   { ensure_env; ensure_directories; compose build; }

show_token() {
  if [[ -r "$TOKEN_FILE" ]]; then
    cat "$TOKEN_FILE"
  elif [[ -f "$TOKEN_FILE" ]]; then
    # The app container writes the token as root, so the host file is root-owned.
    info "Token file not readable as $(id -un); reading with sudo..."
    sudo cat "$TOKEN_FILE"
  else
    die "Token file not found: $TOKEN_FILE. Start the stack once (./run.sh start), then retry."
  fi
}

case "$COMMAND" in
  start|up)    require_docker; start_stack ;;
  stop|down)   require_docker; stop_stack ;;
  restart)     require_docker; restart_stack ;;
  status|ps)   require_docker; status_stack ;;
  logs)        require_docker; logs_stack ;;
  build)       require_docker; build_stack ;;
  rebuild)     require_docker; rebuild_stack ;;
  token)       show_token ;;
  help|-h|--help) usage ;;
  *)           usage; die "Unknown command: $COMMAND" ;;
esac
