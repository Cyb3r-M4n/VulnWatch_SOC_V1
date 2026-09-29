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
WAZUH_API_HOST_PORT="${WAZUH_API_HOST_PORT:-55000}"

docker compose -f docker/docker-compose.yml --env-file "$ENV_FILE" ps
echo
check() {
  local name="$1" url="$2"
  local extra=()
  if [[ "${3:-}" == "-k" ]]; then
    extra+=(-k)
  fi
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${extra[@]}" "$url" || echo "000")
  printf '%-10s HTTP %s  %s\n' "$name" "$code" "$url"
}
check Engine  "http://127.0.0.1:${ENGINE_PORT}/health"
check Grafana "http://127.0.0.1:${GRAFANA_PORT}/api/health"
check n8n     "http://127.0.0.1:${N8N_PORT}/healthz"
check Wazuh   "https://127.0.0.1:${WAZUH_API_HOST_PORT}/" -k
echo
curl -sf "http://127.0.0.1:${ENGINE_PORT}/api/v1/dashboard/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "(Engine stats indisponibles)"
