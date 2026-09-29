# VulnWatch SOC V1

Plateforme **entreprise** de détection de vulnérabilités :

- collecte automatique des CVE (NVD API 2.0 + CISA KEV)
- corrélation avec l’inventaire interne (agents **Wazuh** / Syscollector)
- alertes Grafana
- **propositions de correctifs sans application automatique**
- validation obligatoire par un ingénieur cybersec avant remediation manuelle

> VulnWatch **détecte, alerte et propose**. Il n’applique aucun patch.

---

## Sommaire

1. [Architecture](#architecture)
2. [Prérequis](#prérequis)
3. [Démarrage rapide](#démarrage-rapide)
4. [Configuration (`.env`)](#configuration-env)
5. [Accès aux interfaces](#accès-aux-interfaces)
6. [Configurer n8n](#configurer-n8n)
7. [Enroller un agent Wazuh](#enroller-un-agent-wazuh)
8. [API validation cybersec](#api-validation-cybersec)
9. [Grafana](#grafana)
10. [Scripts](#scripts)
11. [Dépannage](#dépannage)
12. [Structure du dépôt](#structure-du-dépôt)
13. [Sécurité & GitHub](#sécurité--github)
14. [Roadmap V2](#roadmap-v2)

---

## Architecture

```text
Wazuh agents ──► Wazuh manager ──┐
NVD API (24h)  ──────────────────┼──► n8n ──► PostgreSQL ──► Engine API
CISA KEV       ──────────────────┘              │
                                                ├──► Grafana (alertes UI)
                                                └──► remediations (approve/reject)
```

| Service | Image / code | Rôle |
|---------|--------------|------|
| `postgres` | postgres:15 | Données VulnWatch + corrélation SQL |
| `engine` | `engine/` (FastAPI) | API findings / remediations / sync inventaire |
| `n8n` | n8nio/n8n | Orchestration quotidienne |
| `grafana` | grafana | Dashboards + alert rules |
| `wazuh-manager` | wazuh/wazuh-manager:4.14 | Enrollment + Syscollector (pas d’indexer) |

---

## Prérequis

- Linux (testé sur Kali / Ubuntu)
- Docker Engine + **Docker Compose v2** (`docker compose`)
- Ports hôtes libres (par défaut) :
  - `3000` Grafana
  - `5678` n8n
  - `8000` Engine (ou `8001` si modifié dans `.env`)
  - `1514` Wazuh agents
  - `1515` Wazuh enrollment
  - `55000` API Wazuh (localhost uniquement)
  - `5433` Postgres (mappé, évite conflit avec Postgres local `:5432`)
- Clé API NVD (prod) : https://nvd.nist.gov/developers/request-an-api-key
- Accès Internet sortant pour NVD, CISA KEV, et le paquet `wazuh-agent`

---

## Démarrage rapide

```bash
git clone <URL_DU_REPO> VulnWatch_SOC_V1
cd VulnWatch_SOC_V1

cp docker/.env.example docker/.env
nano docker/.env   # au minimum : NVD_API_KEY + mots de passe

chmod +x scripts/*.sh
./scripts/start.sh
```

Options :

```bash
./scripts/start.sh --rebuild     # rebuild image engine
./scripts/start.sh --reset-db    # efface Postgres et rejoue init-scripts/seed
./scripts/status.sh              # état + stats API
./scripts/stop.sh                # arrêt
```

Première fois Postgres vide → les scripts `docker/init-scripts/` créent le schéma + seed inventaire démo.

---

## Configuration (`.env`)

Fichier : [`docker/.env.example`](docker/.env.example) → copier vers `docker/.env` (**jamais committer `.env`**).

| Variable | Description |
|----------|-------------|
| `POSTGRES_*` | DB applicative VulnWatch |
| `POSTGRES_HOST_PORT` | Port hôte Postgres (défaut `5433`) |
| `WAZUH_API_URL` / `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | API manager (Engine) |
| `WAZUH_ENROLL_PASSWORD` | Mot de passe d’enrollment agents |
| `WAZUH_AGENT_PORT` / `WAZUH_ENROLL_PORT` | Ports agents `1514` / `1515` |
| `WAZUH_API_HOST_PORT` | API locale `55000` |
| `N8N_*` | Port / encryption key n8n |
| `ENGINE_PORT` | Port API (défaut `8000`) |
| `GRAFANA_ADMIN_*` | Login Grafana |
| `NVD_API_KEY` | **Obligatoire en prod** (rate limits NVD) |
| `TZ` | Timezone (ex. `Europe/Paris`) |

SMTP / `ALERT_EMAIL` : réservés V2 (non utilisés en V1).

---

## Accès aux interfaces

Remplacer `localhost` par l’IP du serveur si accès LAN (ex. `192.168.1.81`).

| Service | URL | Auth |
|---------|-----|------|
| Grafana | http://HOST:3000/d/vulnwatch-soc | `GRAFANA_ADMIN_USER` / `PASSWORD` |
| Dashboard ops | http://HOST:3000/d/vulnwatch-soc | — |
| n8n | http://HOST:5678 | compte créé au 1er login |
| Engine OpenAPI | http://HOST:8000/docs | — |
| Wazuh API | https://HOST:55000 (localhost) | `WAZUH_API_USER` / `PASSWORD` |

Vérification rapide :

```bash
./scripts/status.sh
curl -s http://localhost:8000/api/v1/dashboard/stats | jq
```

---

## Configurer n8n

1. Ouvrir http://HOST:5678 → créer le compte owner
2. **Import** → fichier  
   `docker/n8n/workflows/daily_vulnerability_scan.json`
3. **Publish / Active** le workflow
4. Test : **Execute workflow**

Aucun credential Postgres n8n : NVD, KEV, Wazuh et la corrélation passent par l’Engine (`http://engine:8000`).

Le workflow (toutes les 24h) :

1. Pull NVD (fenêtre 24h) + CISA KEV  
2. Inventaire Wazuh (`POST /api/v1/inventory/sync`)  
3. `POST /api/v1/correlation/run` → findings + propositions  
4. Journal `scan_history`  
**Pas d’email / pas d’auto-patch en V1.**

---

## Enroller un agent Wazuh

Le manager écoute **1514/tcp** (données) et **1515/tcp** (enrollment).  
Pas de dashboard Wazuh : l’inventaire est lu par l’Engine via l’API `55000`.

Remplacer `MANAGER_IP` par l’IP LAN du serveur (ex. `192.168.1.81`).  
Le mot de passe est `WAZUH_ENROLL_PASSWORD` dans `docker/.env`.

### Debian / Ubuntu / Kali

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER='MANAGER_IP' WAZUH_REGISTRATION_PASSWORD='<WAZUH_ENROLL_PASSWORD>' apt-get install wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl status wazuh-agent
```

### Vérifier

```bash
# API locale (401 sans auth = manager up)
curl -k -s -o /dev/null -w '%{http_code}\n' https://127.0.0.1:55000/

# Sync inventaire vers Postgres
curl -s -X POST http://localhost:8000/api/v1/inventory/sync | jq
```

Les agents `active` apparaissent dans `assets` / `software` / `processes` après le sync (ou le workflow n8n).

Le **module vulnérabilités Wazuh est désactivé** : NVD + KEV + corrélation restent dans VulnWatch.

---

## API validation cybersec

Base : `http://HOST:8000` (ou le `ENGINE_PORT` du `.env`).

```bash
# Stats
curl -s http://localhost:8000/api/v1/dashboard/stats | jq

# File d'attente
curl -s http://localhost:8000/api/v1/remediations/queue | jq

# Approuver (n'applique AUCUN correctif)
curl -s -X POST http://localhost:8000/api/v1/remediations/ID/approve \
  -H 'Content-Type: application/json' \
  -d '{"validated_by":"j.dupont","notes":"OK change window"}'

# Rejeter
curl -s -X POST http://localhost:8000/api/v1/remediations/ID/reject \
  -H 'Content-Type: application/json' \
  -d '{"validated_by":"j.dupont","notes":"Faux positif"}'

# Après remediation manuelle hors plateforme
curl -s -X POST http://localhost:8000/api/v1/findings/ID/mitigated \
  -H 'Content-Type: application/json' \
  -d '{"mitigated_by":"j.dupont","notes":"openssl mis à jour"}'
```

---

## Grafana

- Provisionné automatiquement (datasource Postgres, dashboards, alert rules)
- Accueil : **VulnWatch SOC — Operations**
- Alertes UI : CRITICAL / KEV / pending validation (pas SMTP en V1)
- Si « No data » : Ctrl+F5 ; vérifier `./scripts/status.sh`

---

## Scripts

| Script | Rôle |
|--------|------|
| `scripts/start.sh` | Crée volumes, lance toute la stack, attend la santé |
| `scripts/stop.sh` | Arrête la stack |
| `scripts/status.sh` | `compose ps` + HTTP checks + stats |
| `scripts/setup.sh` | Alias historique → délègue à `start.sh` |

---

## Dépannage

**Port already in use (5432)**  
Déjà géré via `POSTGRES_HOST_PORT=5433`.

**Grafana permission denied**  
`start.sh` réapplique `chown 472:472` sur `volumes/grafana`.

**Wazuh API 000 / unhealthy**  
Attendre le `start_period` (~2 min). Logs :  
`docker compose -f docker/docker-compose.yml --env-file docker/.env logs wazuh-manager`

**Agent `wazuh-agentd: Unable to connect`**  
Vérifier `WAZUH_MANAGER` = IP du serveur (pas `localhost` depuis une autre machine), ports `1514`/`1515` ouverts.

**Inventaire vide**  
Aucun agent enrollé : le seed démo Postgres reste utilisé. Après enrollment : `POST /api/v1/inventory/sync`.

**Postgres schéma manquant**  
```bash
./scripts/start.sh --reset-db
```

**n8n « server does not support SSL »**  
Credential Postgres → SSL = disable.

**Logs**  
```bash
docker compose -f docker/docker-compose.yml --env-file docker/.env logs -f
```

---

## Structure du dépôt

```text
VulnWatch_SOC_V1/
├── README.md
├── .gitignore
├── docker/
│   ├── docker-compose.yml
│   ├── .env.example          # template (commité)
│   ├── .env                  # secrets (NON commité)
│   ├── init-scripts/         # SQL bootstrap + remediations + seed
│   ├── n8n/workflows/        # workflow quotidien
│   ├── grafana/              # dashboards + provisioning
│   └── configs/wazuh/        # agent.conf + entrypoint manager
├── engine/                   # API FastAPI
├── scripts/                  # start / stop / status
├── reports/                  # sorties (gitkeep)
└── volumes/                  # data runtime (NON commité)
```

`docker/engine/` est un ancien doublon (**deprecated**) — le build utilise `engine/`.

---

## Sécurité & GitHub

Avant `git push` :

```bash
# Vérifier qu'aucun secret n'est tracké
git status
grep -R "NVD_API_KEY\|PASSWORD\|enroll-secret" --include='*.md' --include='*.env' . || true
```

À **ne jamais** committer :

- `docker/.env`
- `volumes/`
- clés API, enroll secrets, mots de passe n8n/Grafana

Initialisation Git (si besoin) :

```bash
git init
git add .
git status   # vérifier : pas de .env ni volumes/
git commit -m "Initial VulnWatch SOC V1"
git branch -M main
git remote add origin git@github.com:<ORG>/<REPO>.git
git push -u origin main
```

---

## Roadmap V2

- Notifications email / Slack / Teams  
- PDF reporting  
- SSO Grafana  
- Ticketing (Jira / ServiceNow)  
- HA  
- **Toujours pas d’auto-patch** (principe produit)
