# n8n Workflows - VulnWatch SOC V1

## Workflow principal : `daily_vulnerability_scan.json`

Exécution toutes les **24h**, **séquentielle**, **uniquement via l'API Engine**
(`ENGINE_URL=http://engine:8000` dans le réseau Docker). Aucun credential Postgres n8n.

1. `POST /api/v1/scans/start`
2. NVD 24h → `POST /api/v1/cves/nvd`
3. CISA KEV → `POST /api/v1/cves/kev`
4. Inventaire Wazuh → `POST /api/v1/inventory/sync`
5. `POST /api/v1/correlation/run` → findings + propositions
6. `POST /api/v1/scans/{id}/finish` (`success` seulement si la corrélation répond)

**Pas d'email en V1.** Alertes = Grafana. **Aucun patch automatique.**

## `generate_report.json`

Hors scope V1 (reporting PDF reporté). Les vues SQL utilisées sont les mêmes que Grafana.

## Installation

1. Ouvrir http://localhost:5678 → créer le compte owner
2. Import → `docker/n8n/workflows/daily_vulnerability_scan.json`
3. **Publish / Active**
4. `NVD_API_KEY` dans `docker/.env`

Pas de credential Postgres à créer pour le scan quotidien.
