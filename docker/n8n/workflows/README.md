# n8n Workflows - VulnWatch SOC V1

## Workflow principal : `daily_vulnerability_scan.json`

Exécution toutes les **24h** :

1. Collecte CVE NVD API 2.0 (fenêtre glissante 24h) — clé `NVD_API_KEY`
2. Collecte CISA KEV (feed officiel) — flag `kev`
3. Inventaire hosts Fleet (si agents enrollés)
4. Appel Engine `POST /api/v1/correlation/run` → corrélation + **propositions de correctifs**
5. Journalisation `scan_history`

**Pas d'email en V1.** Les alertes et la file de validation sont dans Grafana / API Engine.  
**Aucun correctif n'est appliqué** — validation cybersec obligatoire.

## `generate_report.json`

Hors scope V1 (reporting PDF reporté).

## Installation

1. Ouvrir http://localhost:5678
2. Import → `docker/n8n/workflows/daily_vulnerability_scan.json`
3. Créer credential Postgres :
   - Host: `postgres`
   - Database / User / Password: valeurs de `docker/.env`
4. Activer le workflow
5. Vérifier `NVD_API_KEY` dans `docker/.env` (sinon rate-limit NVD)

## Variables d'environnement

| Variable | Rôle |
|----------|------|
| `NVD_API_KEY` | Clé NIST NVD (obligatoire en prod) |
| `FLEET_URL` / `FLEET_TOKEN` | Inventaire agents |
| `ENGINE_URL` | `http://engine:8000` |
