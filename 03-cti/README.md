# 🕵️ Module 03 — CTI : Cyber Threat Intelligence

> **Outils :** MISP + Python OSINT  
> **Référentiel :** FIRST CSIRT Services Framework — *Threat Intelligence*  
> **Cas pratique :** Profil APT complet — APT28 (Fancy Bear / Sofacy)

---

## 📋 Contenu du module

```
03-cti/
├── README.md                               ← Ce fichier
├── scripts/
│   ├── ioc_collector.py                   ← Collecte automatique d'IOC
│   ├── apt_profiler.py                    ← Génération profil APT complet
│   ├── mitre_mapper.py                    ← Mapping TTP → ATT&CK Navigator
│   └── misp_feeder.py                     ← Push automatique vers MISP
├── reports/
│   └── APT28_Fancy_Bear_CTI_Report.md    ← Rapport CTI complet (démo)
├── iocs/
│   ├── apt28_iocs.json                    ← IOC APT28 en STIX 2.1
│   ├── apt28_iocs.csv                     ← Format CSV (import SIEM)
│   └── README.md                          ← Documentation format IOC
└── mitre/
    ├── apt28_navigator_layer.json         ← ATT&CK Navigator layer
    └── README.md                          ← Guide utilisation Navigator
```

---

## 🚀 Installation MISP

### Option A — Docker (recommandée pour homelab)

```bash
# Cloner MISP via Docker
git clone https://github.com/MISP/misp-docker.git
cd misp-docker

# Configurer les variables d'environnement
cp template.env .env
# Éditer .env : MISP_BASEURL=https://localhost

# Lancer MISP
docker-compose up -d

# Accès : https://localhost
# Login : admin@admin.test / admin
```

### Option B — VM Ubuntu (plus stable)

```bash
# Sur Ubuntu 22.04
sudo apt install -y curl

# Script auto-install officiel MISP
curl https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.debian.sh | sudo bash

# Après installation (30-40 min)
# Accès : https://<IP_VM>
# Login : admin@admin.test / admin (à changer)
```

### Configuration post-installation

```bash
# 1. Changer le mot de passe admin
# Administration → Users → Edit admin

# 2. Configurer les feeds automatiques
# Sync Actions → Feeds → Enable MISP default feeds

# 3. Générer une clé API
# Administration → My Profile → Auth key

# 4. Tester la connexion Python
python scripts/misp_feeder.py --test --key <VOTRE_CLE_API>
```

---

## 🎯 Cas pratique — APT28 (Fancy Bear)

### Contexte

APT28 (alias : Fancy Bear, Sofacy, Pawn Storm, STRONTIUM) est un groupe APT attribué au renseignement militaire russe (GRU — Unité 26165 et 74455). Actif depuis ~2007, spécialisé dans l'espionnage politique et militaire.

**Cibles principales :** gouvernements, OTAN, journalistes, opposition politique.

### Rapport CTI complet

Voir [`reports/APT28_Fancy_Bear_CTI_Report.md`](./reports/APT28_Fancy_Bear_CTI_Report.md)

### IOC disponibles

Voir [`iocs/apt28_iocs.json`](./iocs/apt28_iocs.json) — Format STIX 2.1

### Mapping ATT&CK

Importer [`mitre/apt28_navigator_layer.json`](./mitre/apt28_navigator_layer.json) dans ATT&CK Navigator :
→ https://mitre-attack.github.io/attack-navigator/

---

## 🐍 Scripts Python

### `ioc_collector.py` — Collecte automatique d'IOC

```bash
# Collecter les IOC pour un groupe APT depuis des sources publiques
python scripts/ioc_collector.py --apt APT28 --sources all

# Depuis un flux TAXII
python scripts/ioc_collector.py --taxii https://cti.mitre.org/taxii/ --collection enterprise

# Enrichir des IOC existants
python scripts/ioc_collector.py --input iocs/apt28_iocs.csv --enrich
```

### `apt_profiler.py` — Profil APT complet

```bash
# Générer un rapport de profil APT
python scripts/apt_profiler.py --apt APT28 --output reports/

# Lister les groupes APT disponibles (MITRE ATT&CK)
python scripts/apt_profiler.py --list-groups
```

### `mitre_mapper.py` — ATT&CK Navigator

```bash
# Générer un layer Navigator pour un groupe
python scripts/mitre_mapper.py --group APT28 --output mitre/apt28_layer.json

# Mapper depuis une liste de TTP
python scripts/mitre_mapper.py --ttps "T1566,T1203,T1547" --name "Custom Layer"

# Comparer deux groupes APT
python scripts/mitre_mapper.py --compare APT28 APT29 --output comparison.json
```

### `misp_feeder.py` — Integration MISP

```bash
# Push d'IOC vers MISP
python scripts/misp_feeder.py \
  --host https://localhost \
  --key <API_KEY> \
  --input iocs/apt28_iocs.json \
  --event-title "APT28 Campaign Q1-2024"

# Créer un event MISP complet depuis le profil APT
python scripts/misp_feeder.py --create-event --apt APT28
```

---

## 📊 Format IOC — STIX 2.1

Nos IOC suivent le standard **STIX 2.1** (Structured Threat Information eXpression) :

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid>",
  "created": "2024-01-15T00:00:00Z",
  "modified": "2024-01-15T00:00:00Z",
  "name": "APT28 C2 IP",
  "description": "Command and Control infrastructure APT28",
  "indicator_types": ["malicious-activity"],
  "pattern": "[ipv4-addr:value = '185.220.101.45']",
  "pattern_type": "stix",
  "valid_from": "2024-01-01T00:00:00Z",
  "labels": ["apt28", "fancy-bear", "c2"],
  "external_references": [
    {
      "source_name": "mitre-attack",
      "url": "https://attack.mitre.org/groups/G0007/"
    }
  ]
}
```

---

## 📚 Références CTI

| Source | Contenu | URL |
|--------|---------|-----|
| MITRE ATT&CK | Framework TTP | attack.mitre.org |
| MISP Project | Plateforme CTI | misp-project.org |
| OpenCTI | Plateforme CTI alternative | opencti.io |
| APT Groups & Ops | Tracking APT | aptgroups.com |
| Mandiant APT Reports | Rapports IR/APT | mandiant.com |
| CISA Advisories | Alertes US-CERT | cisa.gov |
| Threat Intelligence Feeds | AlienVault OTX | otx.alienvault.com |
| VirusTotal Graph | Relations IOC | virustotal.com |
