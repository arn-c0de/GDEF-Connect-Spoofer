#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# GDEF-L1NK launcher — Docker Compose orchestrator.
#
# Everything runs in containers: the Flask sniffer/web app (host networking +
# NET_RAW/NET_ADMIN so Scapy sees the real NIC) and PostgreSQL. This sidesteps
# host-level capture-capability issues entirely.
#
# Usage:
#   ./run.sh start      build (if needed) and start the stack (baked image)
#   ./run.sh dev        start with source bind-mounted (live frontend, fast backend reload)
#   ./run.sh stop       stop and remove the containers
#   ./run.sh restart    rebuild changed parts and restart (picks up code edits)
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
DEV_COMPOSE_FILE="$PROJECT_DIR/docker-compose.dev.yml"
DEV_MARKER="$PROJECT_DIR/.dev-mode"
FRITZDUMP_COMPOSE_FILE="$PROJECT_DIR/docker-compose.fritzdump.yml"
FRITZDUMP_MARKER="$PROJECT_DIR/.fritzdump"
ENV_FILE="$PROJECT_DIR/.env"
TOKEN_FILE="$PROJECT_DIR/database/access_token.txt"
DOCKER="${DOCKER:-docker}"
COMMAND="${1:-start}"

die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }

usage() {
  printf '%s\n' \
    "GDEF-L1NK launcher (Docker)" \
    "Usage:" \
    "  ./run.sh start      build (if needed) and start the stack (baked image)" \
    "  ./run.sh dev        start with source bind-mounted (live frontend, fast backend reload)" \
    "  ./run.sh stop       stop and remove the containers" \
    "  ./run.sh restart    rebuild changed parts and restart (picks up code edits)" \
    "  ./run.sh status     show container status" \
    "  ./run.sh logs       follow the app logs" \
    "  ./run.sh build      (re)build the app image" \
    "  ./run.sh rebuild    rebuild from scratch and start" \
    "  ./run.sh token      print the dashboard access token" \
    "  ./run.sh fritzdump on|off   enable/disable the optional FritzDump module (then restart)" \
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

# Layer override files: the dev override while .dev-mode exists (source bind-mount),
# and the FritzDump override while .fritzdump exists (module bind-mount + enable).
compose() {
  local files=(-f "$COMPOSE_FILE")
  [[ -f "$DEV_MARKER" ]]       && files+=(-f "$DEV_COMPOSE_FILE")
  [[ -f "$FRITZDUMP_MARKER" ]] && files+=(-f "$FRITZDUMP_COMPOSE_FILE")
  "${COMPOSE[@]}" --project-directory "$PROJECT_DIR" "${files[@]}" "$@"
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
  # 'start' is the production-like mode: run the baked image, no source mounts.
  rm -f "$DEV_MARKER"
  ensure_env; ensure_directories
  info "Starting GDEF-L1NK stack (building if needed)..."
  compose up -d --build
  info "Up. Dashboard: http://$(env_get APP_HOST 127.0.0.1):$(env_get APP_PORT 8000)"
  info "Token: ./run.sh token    Logs: ./run.sh logs    Stop: ./run.sh stop"
}

dev_stack() {
  # Dev mode: bind-mount the source so edits don't need an image rebuild.
  ensure_env; ensure_directories
  : > "$DEV_MARKER"
  info "Starting GDEF-L1NK in DEV mode (source bind-mounted)..."
  compose up -d --build
  info "Up (dev). Dashboard: http://$(env_get APP_HOST 127.0.0.1):$(env_get APP_PORT 8000)"
  info "Frontend edits (static/, templates/): just refresh the browser — no restart."
  info "Backend edits  (app.py, db.py): ./run.sh restart   (fast process restart, no image build)."
  info "Leave dev mode: ./run.sh start (back to baked image) or ./run.sh stop."
}

rebuild_stack() {
  ensure_env; ensure_directories
  info "Rebuilding image from scratch..."
  compose build --no-cache
  compose up -d
}

stop_stack() {
  ensure_env
  info "Stopping GDEF-L1NK stack..."
  compose down
  rm -f "$DEV_MARKER"
}

restart_stack() {
  ensure_env; ensure_directories
  if [[ -f "$DEV_MARKER" ]]; then
    # Dev mode: source is bind-mounted, so just restart the app process to pick
    # up backend edits — no image rebuild needed (fast). Frontend needs no
    # restart at all (served live from the mount on the next request).
    info "Dev mode: restarting app process to pick up mounted code..."
    compose restart app
  else
    # Prod mode: rebuild changed layers (frontend/backend source) and recreate
    # the app container so code edits are picked up. The Docker layer cache keeps
    # this near-instant when only app.py / static / templates changed.
    info "Rebuilding changed parts and restarting GDEF-L1NK stack..."
    compose up -d --build
  fi
}
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

# Toggle the optional FritzDump module on/off via the .fritzdump marker. The
# module is OFF by default; turning it on layers docker-compose.fritzdump.yml
# (module bind-mount + FRITZDUMP_ENABLED=1) on the next start/restart.
fritzdump_toggle() {
  case "${1:-}" in
    on)
      [[ -d "$PROJECT_DIR/modules/FritzDump" ]] \
        || die "modules/FritzDump not found — add the FritzDump module there first (see README)."
      [[ -f "$PROJECT_DIR/modules/FritzDump/.env" ]] \
        || info "Note: modules/FritzDump/.env is missing — set the FRITZ!Box login before pressing Start."
      touch "$FRITZDUMP_MARKER"
      info "FritzDump module ENABLED."
      ;;
    off)
      rm -f "$FRITZDUMP_MARKER"
      info "FritzDump module DISABLED."
      ;;
    *)
      [[ -f "$FRITZDUMP_MARKER" ]] && info "FritzDump module is currently ON." || info "FritzDump module is currently OFF."
      echo "Usage: ./run.sh fritzdump on|off"
      return 0
      ;;
  esac
  # Apply now by RECREATING the app container so the new volume/env from the
  # override actually take effect — a plain `compose restart` would not pick them
  # up. Keeps the current mode (dev/prod) intact (unlike `start`, which clears it).
  if command -v "$DOCKER" >/dev/null 2>&1 && "$DOCKER" info >/dev/null 2>&1; then
    detect_compose; ensure_env; ensure_directories
    info "Applying — recreating the app container..."
    compose up -d --build
    info "Done. Watch it with: ./run.sh logs"
  else
    info "Docker isn't running — apply later with: ./run.sh start"
  fi
}

case "$COMMAND" in
  start|up)    require_docker; start_stack ;;
  dev)         require_docker; dev_stack ;;
  stop|down)   require_docker; stop_stack ;;
  restart)     require_docker; restart_stack ;;
  status|ps)   require_docker; status_stack ;;
  logs)        require_docker; logs_stack ;;
  build)       require_docker; build_stack ;;
  rebuild)     require_docker; rebuild_stack ;;
  token)       show_token ;;
  fritzdump)   fritzdump_toggle "${2:-}" ;;
  help|-h|--help) usage ;;
  *)           usage; die "Unknown command: $COMMAND" ;;
esac
