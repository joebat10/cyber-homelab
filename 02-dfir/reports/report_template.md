# 📋 Rapport d'Investigation Forensique

**[MODÈLE PROFESSIONNEL — CSIRT/DFIR]**

---

## En-tête du rapport

| Champ | Valeur |
|-------|--------|
| **Numéro de dossier** | CASE-YYYY-NNN |
| **Classification** | TLP:RED / TLP:AMBER / TLP:WHITE |
| **Date d'ouverture** | YYYY-MM-DD HH:MM UTC |
| **Date de clôture** | YYYY-MM-DD HH:MM UTC |
| **Investigateur principal** | Prénom Nom |
| **Superviseur** | Prénom Nom |
| **Version** | 1.0 |
| **Statut** | BROUILLON / FINAL |

---

## 1. Résumé Exécutif

> *Section destinée aux décideurs non-techniques. Maximum 1 page.*

**Synthèse :**
[3-5 phrases décrivant clairement : ce qui s'est passé, les systèmes impactés, les données exposées et les actions immédiates prises]

**Sévérité :**
- 🔴 **CRITIQUE** — Compromission confirmée / Données exfiltrées
- 🟠 **HAUTE** — Compromission probable / Impact limité
- 🟡 **MOYENNE** — Activité suspecte / Pas de compromission confirmée
- 🟢 **FAIBLE** — Faux positif / Incident mineur

**Impact estimé :**
- Systèmes impactés : X
- Données exposées : [type + volume estimé]
- Durée d'exposition : Du [date] au [date]

---

## 2. Contexte et Périmètre

### 2.1 Déclencheur
[Quelle alerte / signalement a initié l'investigation ?]

### 2.2 Périmètre
- **Systèmes analysés :** 
- **Plage temporelle :** Du [date] au [date]
- **Systèmes exclus :** 

### 2.3 Questions directrices
1. L'incident a-t-il eu lieu ?
2. Comment l'attaquant a-t-il accédé au système ?
3. Quelles actions ont été effectuées ?
4. Des données ont-elles été exfiltrées ?
5. Des mécanismes de persistance ont-ils été installés ?

---

## 3. Méthodologie

**Framework utilisé :** PICERL (Préparation, Identification, Confinement, Éradication, Rétablissement, Leçons)

**Outils :**
| Outil | Version | Usage |
|-------|---------|-------|
| Autopsy | 4.21.0 | Analyse image disque |
| Volatility 3 | 2.5.0 | Analyse mémoire |
| forensic_analyzer.py | 1.0.0 | Automatisation logs |
| Eric Zimmerman Tools | Latest | Artefacts Windows |

---

## 4. Chaîne de Custody (Chain of Custody)

| # | Élément | Type | Taille | Hash SHA256 | Obtenu par | Date | Heure |
|---|---------|------|--------|-------------|------------|------|-------|
| 1 | evidence.dd | Image disque | X GB | `abc123...` | Nom | YYYY-MM-DD | HH:MM |
| 2 | memory.dmp | Dump mémoire | X GB | `def456...` | Nom | YYYY-MM-DD | HH:MM |

**Intégrité vérifiée :** ✅ Oui / ❌ Non (préciser)

---

## 5. Analyse Technique

### 5.1 Accès initial
[Comment l'attaquant a-t-il pénétré le système ?]
- Vecteur : [Phishing / Exploit / Credential stuffing / ...]
- Preuve : [Event ID, fichier, log]
- MITRE ATT&CK : [T1xxx]

### 5.2 Découverte (Discovery)
[Quelles commandes de reconnaissance ont été exécutées ?]
```
[Commandes identifiées — Event ID 4688 / Sysmon EID 1]
```
- MITRE : T1082 (System Info), T1083 (File Discovery), T1033 (User Discovery)

### 5.3 Mouvement latéral
[Propagation vers d'autres systèmes ?]
- Technique : [Pass-the-Hash / WinRM / RDP / ...]
- Systèmes cibles : 
- MITRE : T1021.x

### 5.4 Accès aux informations d'identification
[Dump de credentials ?]
- Outil utilisé : [Mimikatz / secretsdump / procdump ...]
- Comptes compromis :
- MITRE : T1003.x

### 5.5 Persistance
[Mécanismes de persistance installés]

| Mécanisme | Valeur | MITRE |
|-----------|--------|-------|
| Run Key | `HKLM\...\Run\Updater = C:\Temp\mal.exe` | T1547.001 |
| Scheduled Task | `\Microsoft\...\update` | T1053.005 |
| Service | `svchost32` | T1543.003 |

### 5.6 Exfiltration
[Des données ont-elles été sorties ?]
- Volume estimé : 
- Destination : 
- Protocole : 
- MITRE : T1041 / T1071

---

## 6. Timeline des Événements

> *Chronologie complète — voir `timeline.csv` en annexe*

| Timestamp (UTC) | Sévérité | Système | Événement | MITRE |
|-----------------|----------|---------|-----------|-------|
| YYYY-MM-DD HH:MM | 🔴 CRITIQUE | HOSTNAME | Description | T1xxx |
| YYYY-MM-DD HH:MM | 🟠 HIGH | HOSTNAME | Description | T1xxx |

---

## 7. Indicateurs de Compromission (IOC)

### 7.1 Adresses IP
| IP | Type | Pays | Contexte | Score VT |
|----|------|------|---------|----------|
| x.x.x.x | C2 | RU | Communications sortantes port 4444 | 45/72 |

### 7.2 Hashes
| Hash | Type | Nom | Détection |
|------|------|-----|-----------|
| `abc123...` | SHA256 | mal.exe | Trojan.Metasploit |

### 7.3 Domaines
| Domaine | Type | Contexte |
|---------|------|---------|
| evil.xyz | C2 | Résolution DNS à 09:24 |

### 7.4 Règles de détection YARA
```yara
rule Homelab_Malware_Sample {
    meta:
        description = "Détection du binaire identifié"
        author = "Joe Bichall"
        date = "YYYY-MM-DD"
    strings:
        $s1 = "string_identifiée" ascii
        $s2 = { 4D 5A 90 00 }
    condition:
        uint16(0) == 0x5A4D and $s1 and $s2
}
```

---

## 8. Analyse ATT&CK

```
Tactiques identifiées :
┌────────────────────────────────────────────────────┐
│ Initial    │ Execution  │ Persist.  │ Priv.Esc.     │
│ Access     │            │           │               │
├────────────┼────────────┼───────────┼───────────────┤
│ T1566.001  │ T1059.001  │ T1547.001 │ T1068         │
│ Spearphish │ PowerShell │ Run Keys  │ Exploit       │
└────────────┴────────────┴───────────┴───────────────┘
```

---

## 9. Recommandations

### Immédiates (< 24h)
- [ ] Isoler les systèmes compromis
- [ ] Réinitialiser les comptes impactés
- [ ] Bloquer les IOC sur les équipements de sécurité

### Court terme (< 1 semaine)
- [ ] Déployer les règles de détection (Wazuh/SIEM)
- [ ] Auditer les comptes privilégiés
- [ ] Patch des vulnérabilités exploitées
- [ ] Notification RGPD si données personnelles exposées (Art. 33 — 72h)

### Long terme (< 1 mois)
- [ ] Revue de la politique MFA
- [ ] Formation sensibilisation phishing
- [ ] Améliorer la supervision des endpoints (EDR)

---

## 10. Conclusion

[Synthèse de 1 paragraphe résumant les conclusions, le niveau de certitude et la disposition du dossier]

---

## Annexes

- **Annexe A :** Timeline complète (`timeline.csv`)
- **Annexe B :** Capture écran Autopsy
- **Annexe C :** Rapport VirusTotal IOC
- **Annexe D :** Rapport Volatility 3
- **Annexe E :** Preuves documentées (hashes)

---

*Ce rapport a été produit dans le cadre du cyber-homelab de Joe Bichall (@joebat10).*  
*Confidentiel — Ne pas diffuser sans autorisation*
