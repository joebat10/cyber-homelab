# 🔍 Module 01 — SOC : Détection & Monitoring

> **Outils :** Wazuh 4.x + Sysmon 15.x  
> **Référentiel :** FIRST CSIRT Services Framework — *Information Security Event Management*  
> **Cas pratique :** Détection attaques Active Directory (T1003, T1558, T1021)

---

## 📋 Contenu du module

```
01-soc/
├── README.md                         ← Ce fichier
├── rules/
│   ├── wazuh_ad_attacks.xml          ← Règles détection AD (PTH, Kerberoast, DCSync)
│   ├── wazuh_lolbins.xml             ← Living-off-the-land binaries
│   ├── wazuh_lateral_movement.xml    ← Mouvement latéral WinRM/SMB
│   └── sigma_to_wazuh.py            ← Convertisseur Sigma → Wazuh XML
├── scripts/
│   ├── wazuh_alert_manager.py        ← Gestionnaire d'alertes automatisé
│   ├── alert_enricher.py            ← Enrichissement IOC (VirusTotal/Shodan)
│   ├── soc_dashboard_exporter.py    ← Export métriques dashboard
│   └── simulate_attack.py           ← Générateur d'événements de test
├── configs/
│   ├── sysmon_config.xml            ← Config Sysmon (basé SwiftOnSecurity)
│   └── wazuh_agent.conf             ← Config agent Wazuh Windows
└── docs/
    ├── INSTALL_WAZUH.md             ← Guide installation Wazuh (Ubuntu VM)
    ├── INSTALL_SYSMON.md            ← Guide installation Sysmon Windows
    └── DETECTION_RULES.md           ← Documentation des règles custom
```

---

## 🚀 Installation rapide

### Étape 1 — Créer la VM Wazuh Manager

**Prérequis :** VirtualBox installé sur Windows 11

```bash
# Télécharger l'OVA Wazuh pré-configurée (le plus simple)
# https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html

# OU installation manuelle sur Ubuntu 22.04 :
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Accès dashboard : https://<IP_VM>:443
# User: admin / Pass: généré à l'installation
```

> 💡 **Recommandation :** Utiliser l'OVA officielle Wazuh (All-in-One). Elle inclut Wazuh Manager + Indexer + Dashboard en 1 VM. RAM : 4 Go minimum.

### Étape 2 — Installer Sysmon sur Windows (hôte ou VM cible)

```powershell
# PowerShell (Admin) — Téléchargement Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"

# Télécharger notre config Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/joebat10/cyber-homelab/main/01-soc/configs/sysmon_config.xml" -OutFile "$env:TEMP\sysmon_config.xml"

# Installer Sysmon avec la config
cd "$env:TEMP\Sysmon"
.\Sysmon64.exe -accepteula -i ..\sysmon_config.xml

# Vérifier l'installation
Get-Service Sysmon64
```

### Étape 3 — Déployer l'agent Wazuh sur Windows

```powershell
# Télécharger l'installeur agent (remplacer <WAZUH_MANAGER_IP>)
$WAZUH_IP = "192.168.56.10"  # IP de ta VM Wazuh

Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"

# Installer et enregistrer l'agent
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER="$WAZUH_IP" WAZUH_AGENT_NAME="WIN11-LAB"

# Démarrer le service
NET START WazuhSvc
```

### Étape 4 — Déployer les règles custom

```bash
# Sur le serveur Wazuh Manager (SSH dans la VM Ubuntu)
cd /var/ossec/etc/rules/

# Copier nos règles
sudo cp /path/to/cyber-homelab/01-soc/rules/*.xml .

# Recharger Wazuh
sudo /var/ossec/bin/wazuh-control restart
```

---

## 🎯 Cas pratique — Détection attaques Active Directory

### Scénario
Simulation des techniques d'attaque AD documentées dans le *"Attacking Active Directory with Linux Lab Manual"* pour construire et valider nos règles de détection.

### Attaques simulées & détections

#### T1003.001 — LSASS Memory Dump (Mimikatz/ProcDump)
```xml
<!-- règle Wazuh — voir rules/wazuh_ad_attacks.xml -->
Event ID 10 (Sysmon ProcessAccess) sur lsass.exe
→ Alert LEVEL 15 : Credential Access - LSASS Memory Access
```

#### T1558.003 — Kerberoasting
```
Event ID 4769 (Windows Security) — Kerberos Service Ticket Request
Conditions : TicketEncryptionType = 0x17 (RC4) + non-machine account
→ Alert LEVEL 13 : Credential Access - Kerberoasting Attempt
```

#### T1021.006 — WinRM Lateral Movement
```
Event ID 4624 (Logon Type 3) + Event ID 7045 (New Service)
→ Alert LEVEL 12 : Lateral Movement - WinRM Session
```

### Résultats en dashboard

![Dashboard Wazuh - Alertes AD](../docs/screenshots/wazuh_ad_dashboard.png)
*(Screenshot à remplacer avec votre instance)*

---

## 🐍 Scripts Python

### `wazuh_alert_manager.py` — Gestion automatisée des alertes
```bash
# Lancer le manager d'alertes (mode watch)
python scripts/wazuh_alert_manager.py --host 192.168.56.10 --watch

# Exporter les alertes des dernières 24h en CSV
python scripts/wazuh_alert_manager.py --export --hours 24 --output alerts.csv

# Mode triage : afficher seulement les alertes HIGH
python scripts/wazuh_alert_manager.py --level 12 --format rich
```

### `alert_enricher.py` — Enrichissement IOC
```bash
# Enrichir une IP avec VirusTotal + Shodan
python scripts/alert_enricher.py --ip 185.220.101.45

# Enrichir depuis un fichier d'alertes
python scripts/alert_enricher.py --file alerts.csv --output enriched.json
```

---

## 📏 Règles de détection — Résumé

| Règle | ID Wazuh | MITRE | Niveau | Description |
|-------|----------|-------|--------|-------------|
| LSASS Access | 100001 | T1003.001 | 15 | Accès mémoire LSASS (Mimikatz) |
| Kerberoasting | 100002 | T1558.003 | 13 | Ticket RC4 pour service account |
| DCSync | 100003 | T1003.006 | 15 | Réplication AD (DS-Replication-Get-Changes) |
| Pass-the-Hash | 100004 | T1550.002 | 14 | Logon avec hash NTLM |
| LOLBin Execution | 100010 | T1218 | 10 | Exécution via certutil/mshta/regsvr32 |
| WinRM Lateral | 100020 | T1021.006 | 12 | Session WinRM suspecte |
| Scheduled Task | 100030 | T1053.005 | 11 | Création tâche planifiée |
| NTLM Hash Dump | 100040 | T1003 | 14 | Dump NTLM via secretsdump |

---

## 📚 Références

- [Wazuh Documentation](https://documentation.wazuh.com)
- [Sysmon Config — SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sigma Rules — SigmaHQ](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [Wazuh SIEM Rules (wazuh-myrules)](https://github.com/socfortress/wazuh-myrules)
