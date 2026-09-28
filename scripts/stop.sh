#!/usr/bin/env bash
# Arrêt propre de VulnWatch SOC
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f docker/.env ]]; then
  echo "docker/.env manquant — arrêt avec .env.example pour les noms de services"
  docker compose -f docker/docker-compose.yml --env-file docker/.env.example down "$@"
else
  docker compose -f docker/docker-compose.yml --env-file docker/.env down "$@"
fi
echo "Stack arrêtée."
