# 🏗️ Architecture — Cyber Homelab

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                      Windows 11 HOST                            │
│                   (Votre machine physique)                      │
│                                                                  │
│  ┌──────────────────┐  ┌───────────────┐  ┌─────────────────┐  │
│  │  VM1: Wazuh      │  │ VM2: Kali     │  │ VM3: Win2022    │  │
│  │  Ubuntu 22.04    │  │ (Attaquant)   │  │ Active Dir.     │  │
│  │  192.168.56.10   │  │ 192.168.56.20 │  │ 192.168.56.30   │  │
│  │                  │  │               │  │ + Sysmon        │  │
│  │  [Wazuh Manager] │  │ [Nmap, Impack │  │ [Wazuh Agent]   │  │
│  │  [Dashboard]     │  │  Mimikatz...) │  │                 │  │
│  └────────┬─────────┘  └──────┬────────┘  └────────┬────────┘  │
│           │                   │                    │            │
│           └───────────────────┴────────────────────┘            │
│                        Réseau Host-Only                         │
│                        192.168.56.0/24                          │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               Scripts Python (Host)                     │    │
│  │   wazuh_alert_manager.py → API Wazuh (port 55000)      │    │
│  │   forensic_analyzer.py   → Images disque locales       │    │
│  │   ioc_collector.py       → Internet (OSINT APIs)       │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Flux de données par module

### Module SOC
```
Windows 11 (Sysmon) 
    │ Events XML → Wazuh Agent
    ↓
Wazuh Manager (Ubuntu)
    │ Corrélation règles custom
    ↓
Dashboard Wazuh → Alertes
    │ API REST (port 55000)
    ↓
wazuh_alert_manager.py (Python Host)
    │ Enrichissement MITRE ATT&CK
    ↓
Export CSV / JSON / Terminal
```

### Module DFIR
```
Image disque NIST CFReDS
    │ Montage via Autopsy
    ↓
Extraction artefacts
    │ MFT, Registry, Prefetch, Logs
    ↓
forensic_analyzer.py (Python)
    │ Parsing + corrélation
    ↓
Timeline chronologique
    │
    ↓
log_timeline.py → rapport_investigation.md
```

### Module CTI
```
Sources OSINT (VirusTotal, OTX, Shodan)
    │
    ↓
ioc_collector.py (Python)
    │ Collecte + qualification IOC
    ↓
STIX 2.1 JSON
    │ (optionnel → import MISP)
    ↓
apt_profiler.py → CTI Report
    │
    ↓
MITRE ATT&CK Navigator Layer (JSON)
```

## Ports importants

| Service | Port | Protocol | VM |
|---------|------|----------|----|
| Wazuh Dashboard | 443 | HTTPS | VM1 |
| Wazuh Manager API | 55000 | HTTPS | VM1 |
| Wazuh Agent enrollment | 1514 | UDP | VM1 |
| SSH Ubuntu | 22 | TCP | VM1 |
| SSH Kali | 22 | TCP | VM2 |
| RDP Windows | 3389 | TCP | VM3 |
| MISP (optionnel) | 443 | HTTPS | VM1 |
