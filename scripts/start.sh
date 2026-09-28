#!/usr/bin/env bash
# =============================================================================
# VulnWatch SOC V1 — démarrage complet de la plateforme
# Usage: ./scripts/start.sh [--rebuild] [--reset-db]
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE=(docker compose -f docker/docker-compose.yml --env-file docker/.env)
REBUILD=0
RESET_DB=0

for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD=1 ;;
    --reset-db) RESET_DB=1 ;;
    -h|--help)
      echo "Usage: $0 [--rebuild] [--reset-db]"
      echo "  --rebuild   Force rebuild de l'image engine"
      echo "  --reset-db  Efface volumes Postgres (réexécute init-scripts)"
      exit 0
      ;;
  esac
done

echo "==> VulnWatch SOC — démarrage"

# --- Prérequis ---
if ! command -v docker >/dev/null 2>&1; then
  echo "ERREUR: Docker n'est pas installé."
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERREUR: Docker Compose v2 requis (docker compose)."
  exit 1
fi

# --- .env ---
if [[ ! -f docker/.env ]]; then
  echo "==> Création de docker/.env depuis .env.example"
  cp docker/.env.example docker/.env
  echo "IMPORTANT: éditez docker/.env (NVD_API_KEY, mots de passe) avant la prod."
fi

# shellcheck disable=SC1091
set -a
# shellcheck source=/dev/null
source docker/.env
set +a

ENGINE_PORT="${ENGINE_PORT:-8000}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
N8N_PORT="${N8N_PORT:-5678}"
FLEET_PORT="${FLEET_PORT:-8080}"

# --- Volumes locaux ---
echo "==> Préparation des volumes"
mkdir -p volumes/{postgres,mysql,fleet,n8n,engine,grafana} reports artifacts
touch reports/.gitkeep

if [[ "$RESET_DB" -eq 1 ]]; then
  echo "==> Reset volumes Postgres (+ attention données perdues)"
  "${COMPOSE[@]}" down 2>/dev/null || true
  docker run --rm --user root \
    -v "$ROOT_DIR/volumes/postgres:/data" alpine:3.20 \
    sh -c 'rm -rf /data/* /data/.[!.]* 2>/dev/null || true'
fi

# Permissions Grafana (uid 472)
docker run --rm --user root \
  -v "$ROOT_DIR/volumes/grafana:/data" alpine:3.20 \
  sh -c 'chown -R 472:472 /data 2>/dev/null || true' >/dev/null 2>&1 || true

# --- Lancement ---
echo "==> Démarrage Docker Compose"
if [[ "$REBUILD" -eq 1 ]]; then
  "${COMPOSE[@]}" up -d --build
else
  "${COMPOSE[@]}" up -d --build
fi

# --- Attente health ---
echo "==> Attente des services (max ~120s)"
wait_http() {
  local name="$1" url="$2" max="${3:-60}"
  local i=0
  while (( i < max )); do
    if curl -sf --max-time 2 "$url" >/dev/null 2>&1; then
      echo "  [OK] $name"
      return 0
    fi
    sleep 2
    ((i+=2)) || true
  done
  echo "  [WARN] $name pas encore prêt ($url)"
  return 1
}

wait_http "Postgres (via Engine)" "http://127.0.0.1:${ENGINE_PORT}/health" 90 || true
wait_http "Engine"   "http://127.0.0.1:${ENGINE_PORT}/health" 30 || true
wait_http "Grafana"  "http://127.0.0.1:${GRAFANA_PORT}/api/health" 60 || true
wait_http "n8n"      "http://127.0.0.1:${N8N_PORT}/healthz" 60 || true
wait_http "Fleet"    "http://127.0.0.1:${FLEET_PORT}/healthz" 90 || true

echo
echo "=============================================="
echo " VulnWatch SOC démarré"
echo "=============================================="
echo " Grafana : http://localhost:${GRAFANA_PORT}  (user: ${GRAFANA_ADMIN_USER:-admin})"
echo " n8n     : http://localhost:${N8N_PORT}"
echo " Engine  : http://localhost:${ENGINE_PORT}/docs"
echo " Fleet   : http://localhost:${FLEET_PORT}"
echo
echo " Suite déploiement :"
echo "  1. Renseigner NVD_API_KEY dans docker/.env puis : ./scripts/start.sh"
echo "  2. Importer le workflow n8n : docker/n8n/workflows/daily_vulnerability_scan.json"
echo "  3. Credential Postgres n8n : host=postgres db/user/pass = valeurs .env (SSL disable)"
echo "  4. Activer / Execute le workflow Daily Vulnerability Scan"
echo "  5. (Optionnel) Enroller des agents Fleet — voir README"
echo
echo " Status : ${COMPOSE[*]} ps"
echo " Logs   : ${COMPOSE[*]} logs -f"
echo " Stop   : ./scripts/stop.sh"
echo "=============================================="
