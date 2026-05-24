# 🕵️ Rapport CTI — APT28 (Fancy Bear / Sofacy)

**Classification :** TLP:WHITE — Libre distribution  
**Auteur :** Joe Bichall (@joebat10) — cyber-homelab  
**Date :** 2024-01-15  
**Version :** 1.0  
**Sources :** MITRE ATT&CK, Mandiant, CrowdStrike, Microsoft MSTIC, CISA

---

## 1. Résumé

**APT28** (également connu sous les noms **Fancy Bear**, **Sofacy**, **Pawn Storm** ou **STRONTIUM**) est un groupe de cyberespionnage attribué par plusieurs gouvernements et entreprises de sécurité au **GRU** (renseignement militaire russe), spécifiquement aux **Unités 26165** et **74455**.

Actif depuis au moins **2007**, APT28 est l'un des groupes APT les plus sophistiqués et les plus actifs au niveau mondial. Ses opérations couvrent principalement l'**espionnage politique, militaire et diplomatique**, avec des cibles dans les gouvernements occidentaux, les organisations de l'OTAN, les journalistes et les opposants politiques.

**Faits clés :**
- Compromission du Comité National Démocrate (DNC) en 2016
- Opérations contre les élections françaises (EnMarch!, 2017)
- Attaques contre l'OTAN et membres de l'alliance
- Opération Olympic Destroyer (JO Pyeongchang 2018)

---

## 2. Attribution

| Attribut | Valeur |
|----------|--------|
| **Identifiant MITRE** | G0007 |
| **Pays** | Russie 🇷🇺 |
| **Organisation** | GRU — Unité 26165 (Fancy Bear) / Unité 74455 (Sandworm) |
| **Motivations** | Espionnage, Influence politique |
| **Actif depuis** | ~2007 |
| **Confiance attribution** | Très haute (gouvernements US, UK, EU) |

**Indicateurs d'attribution :**
- Horaires d'activité alignés sur UTC+3 (Moscow)
- Artefacts linguistiques en cyrillique dans les binaires
- Infrastructure réutilisée sur plusieurs campagnes
- Chevauchement de TTP avec d'autres opérations GRU connues

---

## 3. Cibles

### Secteurs ciblés
```
┌─────────────────────────────────────────────┐
│  Gouvernement & Défense    ████████████  45% │
│  Politique & Elections     ██████████    35% │
│  Médias & Journalisme      ████          15% │
│  Recherche & Think Tanks   ██             5% │
└─────────────────────────────────────────────┘
```

### Pays ciblés (non exhaustif)
🇺🇸 États-Unis · 🇫🇷 France · 🇩🇪 Allemagne · 🇺🇦 Ukraine · 🇬🇧 Royaume-Uni  
🇵🇱 Pologne · 🇳🇱 Pays-Bas · 🇬🇪 Géorgie · 🇲🇰 Macédoine du Nord

---

## 4. Tactiques, Techniques et Procédures (TTP)

### Matrice MITRE ATT&CK — APT28

| Tactique | Technique | ID | Description |
|----------|-----------|-----|-------------|
| **Initial Access** | Spearphishing Link | T1566.001 | Emails ciblés avec liens malveillants |
| **Initial Access** | Exploit Public-Facing App | T1190 | Exploitation vulnérabilités web |
| **Execution** | PowerShell | T1059.001 | Scripts PS pour téléchargement/exécution |
| **Execution** | User Execution | T1204.002 | Fichiers malveillants en pièce jointe |
| **Persistence** | Registry Run Keys | T1547.001 | Clés HKLM/HKCU\...\Run |
| **Persistence** | Scheduled Task | T1053.005 | Tâches planifiées Windows |
| **Persistence** | Boot/Logon Autostart | T1547 | Divers mécanismes de persistence |
| **Priv. Escalation** | Exploitation for Privilege | T1068 | CVE-2015-1701, CVE-2017-11882 |
| **Defense Evasion** | Obfuscated Files | T1027 | Encodage, chiffrement des payloads |
| **Defense Evasion** | Masquerading | T1036 | Faux noms de processus |
| **Credential Access** | OS Credential Dumping | T1003 | Mimikatz, WCE, secretsdump |
| **Discovery** | Account Discovery | T1087 | net user, net group |
| **Discovery** | Network Scanning | T1046 | Nmap, outils custom |
| **Lateral Movement** | Pass the Hash | T1550.002 | NTLM hash pour mouvement latéral |
| **Lateral Movement** | Remote Services | T1021 | RDP, SMB, WinRM |
| **Collection** | Email Collection | T1114 | Collecte emails Outlook/Exchange |
| **Exfiltration** | Exfiltration Over C2 | T1041 | Via canal C2 chiffré |
| **C2** | Web Protocols | T1071.001 | HTTP/HTTPS pour C2 |
| **C2** | Domain Fronting | T1090.004 | Masquage infrastructure C2 |

### Chaîne d'attaque type APT28

```
[Reconnaissance]   → OSINT cibles, cartographie réseau
      ↓
[Accès Initial]    → Spearphishing personnalisé (Office macro, PDF exploit)
      ↓
[Exécution]        → Dropper → X-Agent / CHOPSTICK
      ↓
[Persistance]      → Run Key + Scheduled Task (double persistance)
      ↓
[Évasion]          → Obfuscation, LOLBAS, timestomping
      ↓
[Credential Dump]  → Mimikatz sur LSASS, ntds.dit
      ↓
[Mouvement Latéral]→ Pass-the-Hash, WinRM
      ↓
[Collecte]         → Emails, documents, credentials
      ↓
[Exfiltration]     → Via C2 HTTPS / VPN TOR
```

---

## 5. Outils & Malwares

### Arsenal technique APT28

| Outil | Type | Description |
|-------|------|-------------|
| **X-Agent** (CHOPSTICK) | RAT | Backdoor modulaire — Windows/Linux/Android |
| **Sofacy** | Dropper | Implant de première étape |
| **GAMEFISH** | Backdoor | RAT sophistiqué avec modules chiffrés |
| **Zebrocy** | Downloader | Téléchargeur / Reconnaissance |
| **SOURFACE** | Dropper | Dropper obfusqué |
| **LoJax** | UEFI Rootkit | Premier rootkit UEFI en conditions réelles |
| **Drovorub** | Linux Rootkit | Malware Linux pour systèmes critiques |
| **Olympic Destroyer** | Wiper | Sabotage JO Pyeongchang 2018 |

---

## 6. Infrastructure C2

### Caractéristiques de l'infrastructure APT28

**Méthodes utilisées :**
- Hébergement sur VPS légitimes (OVH, Hetzner, Digital Ocean)
- Domaines imitant des services Microsoft/Google
- Rotation rapide des IP
- TLS avec certificats Let's Encrypt (éviter détection)
- Domain Fronting via CDN (CloudFront, Azure)

**Patterns de nommage de domaines (historiques) :**
```
microsoftupdate[.]xyz
windowssupport[.]net
office365-login[.]com
secure-onedrive[.]net
```
> ⚠️ Ces exemples sont à titre éducatif. Ne pas accéder à ces domaines.

---

## 7. Indicateurs de Compromission (IOC)

### Format STIX 2.1 — Voir `iocs/apt28_iocs.json`

#### Hashes (échantillons historiques publics)

| Hash SHA256 | Famille | Source |
|-------------|---------|--------|
| (voir fichier JSON) | X-Agent | VirusTotal |

#### Règles YARA

```yara
rule APT28_XAGENT_Generic {
    meta:
        description = "Détection générique X-Agent (APT28)"
        author = "cyber-homelab - Joe Bichall"
        reference = "ESET Research"
        date = "2024-01-15"
    strings:
        $xagent_str1 = "sofacy" ascii nocase
        $xagent_str2 = "X-Agent" ascii
        $xagent_pdb  = "xagent" ascii nocase
        $ua_chrome   = "Mozilla/5.0 (Windows NT 6.1)" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($xagent_*)) and filesize < 2MB
}

rule APT28_C2_Pattern {
    meta:
        description = "Pattern réseau C2 APT28"
        author = "cyber-homelab - Joe Bichall"
    strings:
        $ua = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:24.0)"
        $path = "/en_US/all.js" ascii
    condition:
        all of them
}
```

#### Règles Sigma (Wazuh/SIEM)

```yaml
title: APT28 X-Agent Persistence Technique
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Détection de la technique de persistance typique d'APT28
author: Joe Bichall (@joebat10)
date: 2024/01/15
references:
  - https://attack.mitre.org/groups/G0007/
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
    Details|endswith:
      - '.dll'
      - 'rundll32.exe'
  condition: selection
falsepositives:
  - Logiciels légitimes utilisant Run Keys
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
  - apt.apt28
```

---

## 8. Recommandations Défensives

### Détection

| Contrôle | Description | Outil |
|----------|-------------|-------|
| Surveiller Event ID 4698 | Création tâche planifiée | Wazuh |
| Détecter LSASS access | Event ID 10 Sysmon | Sysmon + Wazuh |
| Alerter sur RC4 Kerberos | Event ID 4769 EncType=0x17 | SIEM |
| Email gateway | Filtrage pièces jointes Office/PDF | Proofpoint, MX Logic |
| Threat Intel Feed | IOC APT28 dans SIEM | MISP + Wazuh |

### Prévention

- **MFA** sur tous les accès distants (VPN, RDP, OWA)
- **Patch management** — prioriser les CVE dans les outils Microsoft Office
- **Sensibilisation phishing** — simulations régulières
- **Segmentation réseau** — empêcher le mouvement latéral
- **EDR** avec détection comportementale
- **Disable macros** par défaut dans Office

### Chasse aux menaces (Threat Hunting)

```
Hypothèse 1 : "Un système a-t-il accédé à lsass.exe en dehors des processus légitimes ?"
→ Sysmon Event ID 10, TargetImage=lsass.exe, SourceImage NOT IN (whitelist)

Hypothèse 2 : "Y a-t-il des Run Keys créées en dehors de C:\Program Files\ ?"
→ Sysmon Event ID 13, TargetObject=\CurrentVersion\Run\, Details contains (\Temp\, \AppData\)

Hypothèse 3 : "Y a-t-il des Kerberos TGS RC4 requests depuis des workstations ?"
→ Windows Event 4769, TicketEncryptionType=0x17, Client NOT IN (servers)
```

---

## 9. Contexte Géopolitique

APT28 opère dans le cadre des intérêts géopolitiques russes. Les campagnes s'intensifient typiquement lors de :

- Élections dans les pays démocratiques occidentaux
- Crises diplomatiques impliquant la Russie
- Opérations militaires (Ukraine, Géorgie...)
- Événements sportifs internationaux (JO, Coupe du Monde)

**Tendances 2024 :** Ciblage accru des infrastructures critiques européennes en lien avec le conflit ukrainien. Recours croissant aux living-off-the-land (LOTL) pour l'évasion.

---

## 10. Références

| Source | Titre | Lien |
|--------|-------|------|
| MITRE ATT&CK | APT28 Group Profile | attack.mitre.org/groups/G0007 |
| Mandiant | APT28 Report | fireeye.com/threat-research |
| CrowdStrike | Fancy Bear Profile | crowdstrike.com/adversaries |
| CISA | Russian GRU Cyber Operations | cisa.gov |
| ESET | Operation Groundbait | welivesecurity.com |
| Microsoft MSTIC | STRONTIUM | microsoft.com/security |
| DoJ Indictment | GRU Officers | justice.gov/2018 |

---

*Rapport généré via cyber-homelab/03-cti — Joe Bichall (@joebat10)*  
*Les IOC sont à titre éducatif — vérifier la validité avant blocage en production*
