#!/usr/bin/env bash
# Status rapide de la plateforme
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE=docker/.env
[[ -f "$ENV_FILE" ]] || ENV_FILE=docker/.env.example

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
ENGINE_PORT="${ENGINE_PORT:-8000}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
N8N_PORT="${N8N_PORT:-5678}"
FLEET_PORT="${FLEET_PORT:-8080}"

docker compose -f docker/docker-compose.yml --env-file "$ENV_FILE" ps
echo
check() {
  local name="$1" url="$2"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" || echo "000")
  printf '%-10s HTTP %s  %s\n' "$name" "$code" "$url"
}
check Engine  "http://127.0.0.1:${ENGINE_PORT}/health"
check Grafana "http://127.0.0.1:${GRAFANA_PORT}/api/health"
check n8n     "http://127.0.0.1:${N8N_PORT}/healthz"
check Fleet   "http://127.0.0.1:${FLEET_PORT}/healthz"
echo
curl -sf "http://127.0.0.1:${ENGINE_PORT}/api/v1/dashboard/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(Engine stats indisponibles)"
