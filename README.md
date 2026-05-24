# 🛡️ Cyber Homelab — SOC | DFIR | CTI

> Projet personnel de Joe Bichall — Mastère Cybersécurité & Infrastructures SI (CESI, Bac+5)  
> Alternant Assistant RSSI @ Giphar Groupe (Lille)  
> En recherche d'un premier CDI : CSIRT · SOC · DFIR · CTI · GRC

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh_4.x-00a0e4?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PC9zdmc+)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🎯 Objectif du projet

Ce homelab démontre des compétences opérationnelles en cybersécurité défensive à travers **3 modules complets** couvrant les métiers CSIRT/SOC. Il est construit selon le référentiel **FIRST CSIRT Services Framework v2.1.0** et les bonnes pratiques DCAF pour les équipes de réponse à incident.

| Module | Domaine | Outils | Statut |
|--------|---------|--------|--------|
| [01 — SOC](./01-soc/) | Détection & Monitoring | Wazuh + Sysmon | 🟢 Actif |
| [02 — DFIR](./02-dfir/) | Investigation Forensique | Autopsy + Volatility 3 | 🟢 Actif |
| [03 — CTI](./03-cti/) | Renseignement sur les menaces | MISP + Python OSINT | 🟢 Actif |

---

## 🏗️ Architecture du homelab

```
┌──────────────────────────────────────────────────────────────┐
│                     Windows 11 HOST                          │
│                                                              │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │   VM1: Wazuh    │  │  VM2: Kali   │  │ VM3: Windows  │  │
│  │   Manager       │  │  (Attaquant) │  │ Server 2022   │  │
│  │   Ubuntu 22.04  │  │              │  │  (Cible AD)   │  │
│  │   [SOC/SIEM]    │  │              │  │  + Sysmon     │  │
│  └────────┬────────┘  └──────┬───────┘  └──────┬────────┘  │
│           │                  │                  │           │
│           └──────────────────┴──────────────────┘           │
│                    Réseau Interne (NAT)                      │
└──────────────────────────────────────────────────────────────┘
```

---

## 📁 Structure du projet

```
cyber-homelab/
├── README.md                    ← Ce fichier
├── 01-soc/
│   ├── README.md                ← Guide SOC complet
│   ├── rules/                   ← Règles Wazuh custom (XML)
│   ├── scripts/                 ← Automatisation Python
│   ├── configs/                 ← Configs Sysmon + Wazuh
│   └── docs/                    ← Installation guides
├── 02-dfir/
│   ├── README.md                ← Guide DFIR complet
│   ├── scripts/                 ← Scripts d'analyse Python
│   ├── cases/                   ← Cas pratiques documentés
│   ├── reports/                 ← Templates rapports
│   └── tools/                   ← Outils helper
├── 03-cti/
│   ├── README.md                ← Guide CTI complet
│   ├── scripts/                 ← OSINT & collecte IOC Python
│   ├── reports/                 ← Rapports APT
│   ├── iocs/                    ← Bases d'IOC (JSON/CSV)
│   └── mitre/                   ← Mappings ATT&CK
└── docs/
    ├── architecture/            ← Schémas réseau
    ├── screenshots/             ← Captures dashboards
    └── SETUP_GUIDE.md           ← Guide installation global
```

---

## 🚀 Démarrage rapide

### Prérequis
- Windows 11 (hôte)
- [VirtualBox 7.x](https://www.virtualbox.org/) ou VMware Workstation
- Python 3.10+
- 16 Go RAM minimum recommandés (8 Go minimum)

### Installation en 3 étapes

```bash
# 1. Cloner le projet
git clone https://github.com/joebat10/cyber-homelab.git
cd cyber-homelab

# 2. Installer les dépendances Python globales
pip install -r requirements.txt

# 3. Suivre le guide du module souhaité
# → 01-soc/README.md    (Wazuh + Sysmon)
# → 02-dfir/README.md   (Autopsy + Volatility)
# → 03-cti/README.md    (MISP + Python OSINT)
```

---

## 🔬 Cas pratiques documentés

### Module SOC — Détection d'attaques Active Directory
Simulation d'attaques AD (Pass-the-Hash, Kerberoasting, DCSync) et détection en temps réel via Wazuh + règles SIGMA custom. Basé sur le lab *"Attacking Active Directory with Linux"*.

**Détections implémentées :**
- `T1003.001` — LSASS Memory Dump (Mimikatz)
- `T1558.003` — Kerberoasting  
- `T1021.006` — WinRM latéral
- `T1055` — Process Injection
- `T1078.002` — Valid Accounts (Admin abuse)

### Module DFIR — Investigation image disque NIST CFReDS
Analyse forensique complète sur l'image *Hacking Case* du NIST CFReDS. Timeline, artefacts, rapport professionnel.

**Artefacts analysés :**
- MFT (Master File Table) — fichiers supprimés
- Prefetch files — programmes exécutés
- Registry hives — persistence, autologon
- Browser history — activité web
- Event logs — connexions, services

### Module CTI — Profil APT : Fancy Bear (APT28)
Rapport de renseignement complet sur APT28 (Sandworm/Fancy Bear). IOC collectés, TTP mappés sur MITRE ATT&CK, indicateurs de compromission structurés en STIX 2.1.

---

## 📚 Références & Standards

| Document | Source |
|----------|--------|
| CSIRT Services Framework v2.1.0 | FIRST.org |
| Introduction to CSIRTs | DCAF Geneva Centre |
| MITRE ATT&CK Enterprise | MITRE |
| Sysmon Config (SwiftOnSecurity) | GitHub |
| Sigma Rules | SigmaHQ |

---

## 👤 Contact

**Joe Bichall**  
📍 Lille, France  
🔗 [GitHub: joebat10](https://github.com/joebat10)  
🎓 Mastère Cybersécurité & Infrastructures SI — CESI (fin sept. 2026)  
💼 Alternant Assistant RSSI — Giphar Groupe

---

*Projet construit avec Claude Code pour démontrer des compétences pratiques en cybersécurité opérationnelle.*
