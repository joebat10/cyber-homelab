#!/usr/bin/env bash
# =============================================================================
# setup.sh — Cyber-homelab SOAR stack initialization
# Compatible: Git Bash on Windows, WSL2, Linux
# =============================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present (to pick up custom port values)
if [ -f "$SCRIPT_DIR/.env" ]; then
  # Export only VAR=value lines, skip comments and blank lines
  set -a
  # shellcheck disable=SC1090
  source <(grep -E '^[A-Z_]+=.' "$SCRIPT_DIR/.env" | grep -v '^#')
  set +a
fi

THEHIVE_PORT="${THEHIVE_PORT:-9010}"
CORTEX_PORT="${CORTEX_PORT:-9011}"
MISP_PORT="${MISP_PORT:-8443}"

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Cyber-homelab SOAR Stack — Setup Script${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── [1/5] Docker ──────────────────────────────────────────────────────────────
echo -n "[1/5] Checking Docker daemon... "
if ! docker info &>/dev/null; then
  echo -e "${RED}NOT RUNNING${NC}"
  echo ""
  echo "  Docker Desktop is not running. Please start it and retry."
  exit 1
fi
DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
echo -e "${GREEN}OK${NC} (v${DOCKER_VERSION})"

# ── [2/5] .env ────────────────────────────────────────────────────────────────
echo -n "[2/5] Checking .env file... "
if [ ! -f "$SCRIPT_DIR/.env" ]; then
  echo -e "${YELLOW}NOT FOUND${NC}"
  echo ""
  echo "  Creating .env from .env.example..."
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
  echo -e "  ${RED}ACTION REQUIRED: edit .env and replace all CHANGE_ME values, then re-run setup.sh${NC}"
  exit 1
fi

# Check for uncustomized placeholders
if grep -q 'CHANGE_ME' "$SCRIPT_DIR/.env"; then
  echo -e "${YELLOW}HAS DEFAULTS${NC}"
  echo ""
  echo -e "  ${YELLOW}WARNING: .env still contains CHANGE_ME placeholders.${NC}"
  echo "  Edit .env and change all passwords before going further."
  echo "  Continuing anyway for lab use — do NOT do this in production."
  echo ""
else
  echo -e "${GREEN}OK${NC}"
fi

# ── [3/5] Port availability ───────────────────────────────────────────────────
echo "[3/5] Checking port availability on host..."

CONFLICT=0
check_port() {
  local port="$1"
  local service="$2"
  # bash /dev/tcp trick — works in Git Bash, WSL2, Linux
  if (echo >/dev/tcp/localhost/"$port") 2>/dev/null; then
    echo -e "  ${RED}✗ :${port} ($service) — IN USE${NC}"
    CONFLICT=1
  else
    echo -e "  ${GREEN}✓ :${port} ($service) — free${NC}"
  fi
}

check_port "$THEHIVE_PORT" "TheHive"
check_port "$CORTEX_PORT"  "Cortex"
check_port "$MISP_PORT"    "MISP"

if [ "$CONFLICT" -eq 1 ]; then
  echo ""
  echo -e "  ${RED}Port conflict! Edit THEHIVE_PORT / CORTEX_PORT / MISP_PORT in .env${NC}"
  echo "  Current conflicts:"
  docker ps --format "  {{.Names}}: {{.Ports}}" 2>/dev/null | grep -E ":(${THEHIVE_PORT}|${CORTEX_PORT}|${MISP_PORT})->" || true
  exit 1
fi

# ── [4/5] Docker socket ───────────────────────────────────────────────────────
echo -n "[4/5] Checking Docker socket for Cortex analyzers... "
if [ -S /var/run/docker.sock ]; then
  echo -e "${GREEN}OK${NC} (/var/run/docker.sock)"
else
  echo -e "${YELLOW}NOT FOUND${NC}"
  echo ""
  echo "  /var/run/docker.sock not present in this shell environment."
  echo "  On Windows/Docker Desktop this is normal — Docker Desktop exposes"
  echo "  the socket to containers through its own Linux VM (WSL2/Hyper-V)."
  echo "  Cortex analyzers that spawn sub-containers should still work."
  echo ""
fi

# ── [5/5] Start stack ─────────────────────────────────────────────────────────
echo "[5/5] Pulling images and starting SOAR stack..."
echo ""
cd "$SCRIPT_DIR"

docker compose pull --quiet
docker compose up -d

# ── Wait for services ─────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "  Waiting for services to become healthy..."
echo "  (first launch can take 5-10 min — MISP up to 15 min)"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

wait_for_http() {
  local name="$1"
  local url="$2"
  local max_wait="${3:-180}"
  local elapsed=0

  printf "  %-20s" "$name"
  while ! curl -sf --max-time 5 "$url" &>/dev/null; do
    printf "."
    sleep 5
    elapsed=$((elapsed + 5))
    if [ "$elapsed" -ge "$max_wait" ]; then
      echo -e " ${YELLOW}timeout${NC} — check: docker compose logs ${name,,}"
      return 1
    fi
  done
  echo -e " ${GREEN}ready${NC}"
}

wait_for_http "Elasticsearch" "http://localhost:9200/_cluster/health"   120
wait_for_http "TheHive"       "http://localhost:${THEHIVE_PORT}/api/v1/status" 240
wait_for_http "Cortex"        "http://localhost:${CORTEX_PORT}/api/status"     180
echo "  MISP               (check manually — slow first boot)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Stack is up!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  TheHive  →  http://localhost:${THEHIVE_PORT}"
echo "               admin@thehive.local / secret"
echo ""
echo "  Cortex   →  http://localhost:${CORTEX_PORT}"
echo "               (create admin account on first visit)"
echo ""
echo "  MISP     →  https://localhost:${MISP_PORT}"
echo "               admin@admin.test / admin  (change immediately)"
echo ""
echo "  Next steps: see README.md §'Connect TheHive to Cortex'"
echo ""
