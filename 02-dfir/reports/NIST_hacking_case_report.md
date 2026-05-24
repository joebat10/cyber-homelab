# 🔬 Rapport d'Investigation DFIR — NIST Hacking Case

| | |
|---|---|
| **Numéro de cas** | DFIR-2024-001 |
| **Analyste** | Joe Bichall |
| **Organisation** | Cyber Homelab — Mastère Cybersécurité CESI |
| **Date rapport** | *(à compléter)* |
| **Classification** | Formation / Public (cas NIST) |
| **Statut** | 🟡 En cours |

---

## 1. Résumé Exécutif

> *(À compléter après l'analyse — 3 à 5 phrases résumant la situation pour un non-technicien)*

Ce rapport présente les conclusions de l'analyse forensique de l'image disque `SCHARDT.DD`, fournie par le NIST dans le cadre du programme CFReDS (Computer Forensics Reference Data Sets). L'image représente un disque dur d'ordinateur portable retrouvé dans des circonstances suspectes.

**Points clés identifiés :**
- *(Remplir après analyse)*

**Niveau de compromission** : 🔴 / 🟠 / 🟡 / 🟢 *(choisir)*

---

## 2. Contexte et Périmètre

### 2.1 Origine du cas
Cas de formation officiel du NIST — Hacking Case. Source : https://www.cfreds.nist.gov/Hacking_Case.html

### 2.2 Questions à traiter (issues du NIST)
1. Quel est le nom du suspect ou du propriétaire présumé ?
2. Quel OS est installé (version, service pack, fuseau horaire) ?
3. Quel est le moment exact du dernier accès au système ?
4. Des outils offensifs sont-ils présents ? Lesquels ?
5. Y a-t-il des preuves de connexions réseau non autorisées ?
6. Des fichiers ont-ils été supprimés ou dissimulés ?
7. Y a-t-il des artefacts de chiffrement ou de stéganographie ?

### 2.3 Périmètre technique
| Élément | Valeur |
|---------|--------|
| Image analysée | SCHARDT.DD |
| Taille | *(à compléter)* |
| Hash MD5 | *(à compléter)* |
| Hash SHA256 | *(à compléter)* |
| OS détecté | *(à compléter)* |
| Système de fichiers | *(à compléter)* |

---

## 3. Méthodologie

L'analyse suit le cadre **PICERL** (Préparation, Identification, Containment, Eradication, Recovery, Lessons Learned) adapté au contexte forensique post-incident.

```
[Acquisition] → [Intégrité] → [Analyse OS] → [Utilisateurs]
      ↓               ↓              ↓               ↓
  Hash MD5/SHA  Copie lecture   Version, TZ     SAM, NTUSER
                  seule

[Réseau] → [Fichiers suspects] → [Timeline] → [Rapport]
    ↓              ↓                  ↓            ↓
 Connexions    Outils offensifs   Chronologie  Conclusions
```

**Outils utilisés :**
| Outil | Version | Usage |
|-------|---------|-------|
| Autopsy | 4.x | Analyse globale, navigation fichiers |
| forensic_analyzer.py | 1.0 | Automatisation extraction artefacts |
| log_timeline.py | 1.0 | Construction timeline |
| registry_parser.py | 1.0 | Analyse clés de registre |
| Python 3.11 | 3.11 | Scripts d'analyse |

---

## 4. Chaîne de Custody

Voir : `cases/NIST_hacking_case/evidence_log.md`

| Étape | Date | Analyste | Action |
|-------|------|---------|--------|
| Acquisition | *(date)* | J. Bichall | Téléchargement + vérification hash |
| Copie de travail | *(date)* | J. Bichall | Copie en lecture seule |
| Analyse | *(date)* | J. Bichall | Analyse forensique complète |

---

## 5. Analyse Technique

### 5.1 Identification du système

| Attribut | Valeur | Source |
|----------|--------|--------|
| Nom de machine | *(à trouver)* | Registre SYSTEM |
| OS | *(à trouver)* | Registre SOFTWARE |
| Version | *(à trouver)* | Registre SOFTWARE |
| Fuseau horaire | *(à trouver)* | Registre SYSTEM |
| Dernier démarrage | *(à trouver)* | Event logs |
| Dernier arrêt | *(à trouver)* | Event logs (6006) |

```
Clé registre : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
Clé registre : HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
```

### 5.2 Comptes utilisateurs

| Compte | SID | Dernière connexion | Actif |
|--------|-----|--------------------|-------|
| *(à compléter)* | | | |

**Commandes utilisées :**
```bash
# Autopsy → Registry → SAM → Users
# Ou via script :
python 02-dfir/scripts/registry_parser.py --hive SAM --demo
```

### 5.3 Activité réseau

*(À compléter après analyse)*

- Adaptateurs réseau détectés :
- Réseaux WiFi connus :
- Connexions récentes :

### 5.4 Outils suspects identifiés

*(À compléter — documenter tout exécutable non standard trouvé)*

| Fichier | Chemin | Hash MD5 | Catégorie | Notes |
|---------|--------|----------|-----------|-------|
| | | | | |

### 5.5 Fichiers supprimés / dissimulés

*(Résultats de la recherche dans les zones non allouées, corbeille, etc.)*

### 5.6 Artefacts d'activité utilisateur

*(RecentDocs, UserAssist, Prefetch, LNK files...)*

---

## 6. Timeline Reconstituée

*(Extrait de la timeline générée par log_timeline.py)*

| Timestamp | Événement | Source | Pertinence |
|-----------|-----------|--------|-----------|
| *(date)* | *(event)* | *(source)* | ⭐⭐⭐ |

**Fichier complet** : `cases/NIST_hacking_case/timeline.csv`

---

## 7. Indicateurs de Compromission (IOC)

### 7.1 Fichiers
| Type | Valeur | Contexte |
|------|--------|---------|
| MD5 | *(hash)* | *(fichier suspect)* |
| Chemin | *(path)* | *(emplacement suspect)* |

### 7.2 Réseau
| Type | Valeur | Contexte |
|------|--------|---------|
| IP | *(IP)* | *(connexion suspecte)* |
| Domaine | *(domain)* | *(DNS résolu)* |

---

## 8. Mapping MITRE ATT&CK

| Tactique | Technique | ID | Preuve |
|----------|-----------|-----|--------|
| *(à compléter)* | | | |

---

## 9. Réponses aux Questions NIST

1. **Nom du suspect** : *(à compléter)*
2. **OS et version** : *(à compléter)*
3. **Dernier accès** : *(à compléter)*
4. **Outils offensifs** : *(à compléter)*
5. **Connexions non autorisées** : *(à compléter)*
6. **Fichiers dissimulés** : *(à compléter)*
7. **Chiffrement/stégano** : *(à compléter)*

---

## 10. Recommandations

*(À compléter à la fin de l'analyse)*

---

## Annexes

- **Annexe A** : Timeline complète — `timeline.csv`
- **Annexe B** : Journal de custody — `evidence_log.md`
- **Annexe C** : Rapport registry_parser — `registry_findings.json`
- **Annexe D** : Résultats forensic_analyzer — `forensic_report.json`

---

*Rapport généré dans le cadre du projet [cyber-homelab](https://github.com/joebat10/cyber-homelab)*  
*Joe Bichall — Mastère Cybersécurité CESI — @joebat10*
