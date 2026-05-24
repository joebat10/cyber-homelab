# 🚀 Guide de Setup Global — Cyber Homelab

> **Pour qui ?** Débutant complet sur ce homelab, Windows 11, Python maîtrisé.  
> **Durée totale estimée :** 3–4 heures (installation) + X heures par module  
> **Coût :** 100% gratuit / open source

---

## Table des matières

1. [Prérequis matériel & logiciel](#1-prérequis)
2. [Installation VirtualBox + ISO](#2-virtualbox)
3. [Configuration réseau des VMs](#3-réseau)
4. [Cloner le projet GitHub](#4-github)
5. [Environnement Python](#5-python)
6. [Ordre recommandé des modules](#6-ordre)
7. [Checklist avant entretien](#7-entretien)

---

## 1. Prérequis

### Matériel minimum
| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| RAM | 8 Go | 16 Go |
| Stockage | 80 Go libres | 150 Go SSD |
| CPU | 4 cœurs | 8 cœurs |
| OS | Windows 11 | Windows 11 |

### Logiciels à télécharger (tous gratuits)

| Logiciel | Lien | Usage |
|----------|------|-------|
| VirtualBox 7.x | https://www.virtualbox.org/ | Hyperviseur |
| Ubuntu Server 22.04 LTS | https://ubuntu.com/download/server | VM Wazuh |
| Kali Linux | https://www.kali.org/get-kali/ | VM Attaquant |
| Windows Server 2022 Eval | https://www.microsoft.com/evalcenter | VM Cible AD |
| Python 3.11 | https://www.python.org/downloads/ | Scripts |
| Git | https://git-scm.com/download/win | Versioning |
| VS Code | https://code.visualstudio.com/ | IDE |

---

## 2. Installation VirtualBox

```powershell
# 1. Télécharger l'installeur VirtualBox
# → https://download.virtualbox.org/virtualbox/7.0.14/VirtualBox-7.0.14-161095-Win.exe

# 2. Activer la virtualisation dans le BIOS si nécessaire
# → Redémarrer, appuyer F2/DEL/F12 selon le constructeur
# → Intel : activer "Intel VT-x"
# → AMD   : activer "AMD-V" ou "SVM Mode"

# 3. Vérifier que la virtualisation est active (dans PowerShell) :
Get-ComputerInfo -Property "HyperVRequirementVirtualizationFirmwareEnabled"
```

### Création des VMs

**VM1 — Wazuh Server (Ubuntu Server 22.04)**
- RAM : 4 Go
- CPU : 2 cœurs
- Disque : 40 Go
- Réseau : Carte 1 = NAT, Carte 2 = Host-Only (192.168.56.0/24)

**VM2 — Kali Linux (Attaquant)**
- RAM : 2 Go
- CPU : 2 cœurs
- Disque : 30 Go
- Réseau : Host-Only (même réseau que VM1)

**VM3 — Windows Server 2022 (Cible AD)**
- RAM : 2 Go minimum
- CPU : 2 cœurs
- Disque : 40 Go
- Réseau : Host-Only

---

## 3. Configuration réseau

```
┌─────────────────────────────────────────┐
│  Réseau Host-Only : 192.168.56.0/24     │
│                                          │
│  VM1 (Wazuh)   : 192.168.56.10          │
│  VM2 (Kali)    : 192.168.56.20          │
│  VM3 (Win2022) : 192.168.56.30          │
│  Hôte Windows  : 192.168.56.1           │
└─────────────────────────────────────────┘
```

Dans VirtualBox :
1. `Fichier → Gestionnaire de réseau hôte`
2. Créer : `192.168.56.1/24`, DHCP désactivé
3. Assigner les IPs statiques dans chaque VM

---

## 4. Cloner le projet

```powershell
# Dans PowerShell (Windows 11)
cd C:\Users\[VotreNom]\Documents

# Cloner
git clone https://github.com/joebat10/cyber-homelab.git
cd cyber-homelab

# Voir la structure
tree /F
```

---

## 5. Environnement Python

```powershell
# Vérifier la version Python (3.10+ requis)
python --version

# Créer un environnement virtuel
python -m venv .venv

# Activer (PowerShell)
.venv\Scripts\Activate.ps1

# Si erreur ExecutionPolicy :
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Installer les dépendances
pip install -r requirements.txt

# Vérifier
pip list
```

---

## 6. Ordre recommandé

```
Semaine 1 : Module SOC
  → docs/01-soc/INSTALL_WAZUH.md
  → docs/01-soc/INSTALL_SYSMON.md
  → Tester la détection avec simulate_attack.py

Semaine 2 : Module DFIR  
  → Télécharger image NIST CFReDS
  → Analyser avec forensic_analyzer.py
  → Rédiger le rapport avec le template

Semaine 3 : Module CTI
  → Configurer MISP (optionnel) ou utiliser les scripts standalone
  → Profiler APT28 avec apt_profiler.py
  → Enrichir le rapport CTI
```

---

## 7. Checklist avant entretien

### Ce que tu dois être capable d'expliquer

- [ ] Architecture du homelab (pourquoi 3 VMs ?)
- [ ] Pourquoi Wazuh + Sysmon ? (complémentarité)
- [ ] Différence SIEM / EDR / IDS
- [ ] Qu'est-ce qu'un IOC ? Un TTP ? (MITRE ATT&CK)
- [ ] Timeline d'un incident (depuis le FIRST CSIRT Framework)
- [ ] Processus DFIR : acquisition → analyse → rapport
- [ ] TLP (Traffic Light Protocol) — niveaux et usage
- [ ] Active Directory : attaques classiques et détections

### Démonstration live (30 minutes)
1. Montrer le dashboard Wazuh avec les alertes custom
2. Lancer `wazuh_alert_manager.py --watch` en live
3. Expliquer une règle XML de détection Kerberoasting
4. Montrer la timeline forensique du cas NIST
5. Présenter le rapport CTI APT28

---

*Mis à jour : 2024 — Joe Bichall (@joebat10)*
