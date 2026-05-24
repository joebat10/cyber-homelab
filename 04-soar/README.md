# Module 04 — SOAR : TheHive + Cortex + MISP

> **Stack :** TheHive 5 · Cortex 3 · MISP · Elasticsearch 7.17 · Cassandra 4  
> **Referentiel :** FIRST CSIRT Services Framework — *Incident Management + Threat Intelligence*  
> **Reseau :** `cyber-homelab-net` — bridge isole 172.25.0.0/24

---

## Architecture du stack

```
Host (Windows 11)
│
├── :9010  →  TheHive 5      (172.25.0.20)  ← Case Management
├── :9011  →  Cortex 3       (172.25.0.21)  ← Observable Analysis
├── :8443  →  MISP            (172.25.0.40)  ← Threat Intelligence
│
│   [Internal only]
├── 172.25.0.10  Cassandra 4   ← TheHive DB
├── 172.25.0.11  Elasticsearch ← TheHive index + Cortex
├── 172.25.0.30  MySQL 8        ← MISP DB
└── 172.25.0.31  Redis 7        ← MISP cache
```

> **Ports 9000/9001 non utilises** — `cybergrc_minio` les occupe deja sur le host.  
> Modifier `THEHIVE_PORT` / `CORTEX_PORT` dans `.env` si besoin.

---

## Prerequis

- Docker Desktop for Windows (deja installe et running)
- 8 Go RAM minimum disponibles pour ce stack (16 Go recommandes)
- Git Bash (pour `setup.sh`) ou GNU Make
- Ports **9010**, **9011**, **8443** libres sur le host

---

## Demarrage rapide

```bash
# 1. Aller dans le dossier
cd 04-soar/

# 2. Creer et verifier le .env
cp .env.example .env
# Editer .env et changer tous les mots de passe CHANGE_ME

# 3. Lancer le stack (via script de verification)
bash setup.sh

# OU directement via Make
make start
```

---

## Commandes Make

| Commande | Action |
|----------|--------|
| `make start` | Demarrer tous les services (`docker compose up -d`) |
| `make stop` | Arreter tous les services |
| `make status` | Afficher l'etat des conteneurs |
| `make logs` | Suivre les logs en temps reel |
| `make clean` | Arreter ET supprimer les volumes (donnees perdues) |
| `make rebuild` | Pull des images + redemarrage force |

---

## Acces aux services

| Service | URL | Login par defaut |
|---------|-----|-----------------|
| TheHive 5 | http://localhost:9010 | admin@thehive.local / secret |
| Cortex 3 | http://localhost:9011 | (a creer au premier lancement) |
| MISP | https://localhost:8443 | admin@admin.test / admin |
| Elasticsearch | http://localhost:9200 (interne) | — |

> **MISP** : certificat SSL auto-signe — ignorer l'avertissement navigateur.  
> **Premiere connexion TheHive** : changer immediatement le mot de passe admin.

---

## Connexion TheHive → Cortex

### Etape 1 — Creer un compte admin dans Cortex

1. Aller sur http://localhost:9011
2. Au premier lancement, Cortex propose de creer un compte admin
3. Remplir : login `admin`, mot de passe fort
4. Cliquer **Create**

### Etape 2 — Creer une organisation et une cle API

1. Dans Cortex → **Organizations** → **Add Organization**
   - Name : `cyber-homelab`
   - Description : `Cyber homelab SOAR`
2. Cliquer sur l'organisation → **Users** → **Add User**
   - Login : `thehive`
   - Role : `read, analyze`
3. Sur le profil de cet utilisateur → **Create API Key**
4. **Copier la cle API** (affichee une seule fois)

### Etape 3 — Configurer TheHive

**Option A — Via `thehive/application.conf`** (redemarrage requis) :

```hocon
# Decommenter et remplir dans thehive/application.conf
cortex {
  servers: [
    {
      name: "cortex-local"
      url: "http://172.25.0.21:9001"
      auth {
        type: "bearer"
        key: "COLLER_LA_CLE_API_ICI"
      }
    }
  ]
}
```

Puis redemarrer TheHive :
```bash
docker compose restart thehive
```

**Option B — Via l'interface TheHive** :

1. TheHive → **Administration** → **Cortex**
2. **Add Cortex server** :
   - Name : `cortex-local`
   - URL : `http://172.25.0.21:9001`
   - API Key : (cle copiee)
3. **Test connection** → doit retourner `OK`

---

## Connexion TheHive → MISP

### Etape 1 — Generer une cle API MISP

1. Aller sur https://localhost:8443
2. Se connecter : `admin@admin.test` / `admin` → changer le mdp
3. **Administration** → **My Profile** → **Auth key** → **Add**
4. Copier la cle generee

### Etape 2 — Configurer dans `thehive/application.conf`

```hocon
misp {
  interval: 1 hour
  servers: [
    {
      name: "misp-local"
      url: "https://172.25.0.40"
      auth {
        type: "key"
        key: "COLLER_LA_CLE_MISP_ICI"
      }
      wsConfig.ssl.loose.acceptAnyCertificate: true
    }
  ]
}
```

Puis redemarrer TheHive :
```bash
docker compose restart thehive
```

---

## Connexion Cortex → MISP (bidirectionnel)

Cortex peut invoquer des modules MISP comme analyzers et MISP peut invoquer des analyzers Cortex.

### Cortex peut interroger MISP

Dans Cortex → **Organizations** → votre org → **Analyzers** :
- Activer `MISP_2_0` ou `MISP_BloodHound`
- Configurer l'URL MISP et la cle API dans les settings de l'analyzer

### MISP peut appeler Cortex

1. MISP → **Administration** → **Server Settings** → **Plugin**
2. Activer `Plugin.enrichment_cortex_enabled`
3. Renseigner l'URL Cortex : `http://172.25.0.21:9001`
4. Renseigner la cle API Cortex

---

## Ajouter des analyzers Cortex

Cortex charge la liste des analyzers depuis internet au demarrage. Pour installer un analyzer :

1. Aller dans Cortex → **Organizations** → votre org → **Analyzers**
2. Trouver l'analyzer (ex: `VirusTotal_GetReport_3_1`)
3. Cliquer **Enable** et renseigner les cles API requises
4. Tester avec un observable (ex: une IP)

Analyzers recommandes pour commencer :
- `VirusTotal_GetReport_3_1` — hash, IP, URL, domaine
- `AbuseIPDB_1_0` — reputation IP
- `Shodan_DNSResolve_1_0` — enrichissement reseau
- `MISP_2_0` — lookup IOC dans MISP
- `FileInfo_8_0` — analyse fichier (PE, PDF, etc.)
- `Yara_2_0` — regles YARA sur fichiers

---

## Sante du stack

```bash
# Voir l'etat de tous les services
make status

# Logs d'un service specifique
docker compose logs -f thehive
docker compose logs -f cortex
docker compose logs -f misp

# Sante Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Redemarrer un service
docker compose restart thehive
```

### Temps de demarrage typiques

| Service | Temps de demarrage |
|---------|-------------------|
| Elasticsearch | ~30s |
| Cassandra | ~60s |
| TheHive | ~2-3 min (attend Cassandra + ES) |
| Cortex | ~1-2 min |
| MISP | ~3-5 min (premier lancement : 10-15 min) |

---

## Troubleshooting

### TheHive ne demarre pas

```bash
docker compose logs thehive | tail -50
# Si "Cassandra not ready" : attendre et relancer
docker compose restart thehive
```

### Cortex "no analyzer available"

```bash
# Verifier la connexion ES
curl http://localhost:9200/_cat/indices
# Verifier les logs
docker compose logs cortex | grep -i error
```

### MISP — erreur de connexion MySQL

```bash
# Reinitialiser MySQL (supprime les donnees MISP)
docker compose stop misp mysql
docker volume rm cyber-homelab-mysql
docker compose up -d mysql
# Attendre 30s puis
docker compose up -d misp
```

### Port deja utilise

```bash
# Verifier quel process utilise un port
netstat -ano | findstr :9010   # Windows
# Modifier le port dans .env et relancer
```

---

## Arreter proprement

```bash
# Arreter sans perdre les donnees
make stop

# Arreter ET supprimer toutes les donnees (reset complet)
make clean
```

---

## Integration avec les autres modules

| Module | Integration |
|--------|-------------|
| `01-soc/` | Wazuh alert → TheHive case (via `wazuh_alert_manager.py`) |
| `02-dfir/` | Artefacts forensiques → observables Cortex |
| `03-cti/` | IOC MISP → Wazuh rules + TheHive alerts |

Voir les scripts `01-soc/scripts/alert_enricher.py` et `03-cti/scripts/misp_feeder.py` pour les points d'integration existants.

---

## References

- [TheHive 5 Docs](https://docs.strangebee.com/thehive/)
- [Cortex Docs](https://github.com/TheHive-Project/CortexDocs)
- [MISP Docs](https://www.misp-project.org/documentation/)
- [Cortex Analyzers List](https://github.com/TheHive-Project/cortex-analyzers)
