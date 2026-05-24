# 🔬 Module 02 — DFIR : Investigation Forensique

> **Outils :** Autopsy 4.x + Volatility 3  
> **Référentiel :** FIRST CSIRT Services Framework — *Digital Forensics*  
> **Cas pratique :** Analyse image disque NIST CFReDS "Hacking Case"

---

## 📋 Contenu du module

```
02-dfir/
├── README.md                              ← Ce fichier
├── scripts/
│   ├── forensic_analyzer.py              ← Analyse automatisée multi-sources
│   ├── log_timeline.py                   ← Reconstruction timeline événements
│   ├── registry_parser.py               ← Analyse hives registre Windows
│   └── memory_analysis_helper.py        ← Aide analyse Volatility 3
├── cases/
│   ├── NIST_hacking_case/
│   │   ├── case_notes.md                ← Notes d'investigation
│   │   └── evidence_log.md              ← Registre des preuves
│   └── case_template.md                 ← Template pour nouveaux cas
├── reports/
│   ├── report_template.md               ← Template rapport professionnel
│   └── NIST_hacking_case_report.md      ← Rapport cas pratique complet
└── tools/
    └── artifact_checklist.md            ← Checklist artefacts Windows
```

---

## 🚀 Installation

### Autopsy (GUI Forensics)

```powershell
# 1. Télécharger Autopsy
# https://www.autopsy.com/download/
# Version : Autopsy 4.21.0 (Windows 64-bit)

# 2. Télécharger aussi le JDK 8 recommandé (inclus dans l'installeur)

# 3. Lancer l'installeur .msi et suivre les étapes
# → Chemin par défaut : C:\Program Files\Autopsy-4.21.0\

# 4. Vérifier le lancement
# Start Menu → Autopsy

# 5. Télécharger l'image NIST CFReDS (cas pratique)
# https://cfreds.nist.gov/all/NIST/HackingCase
# Fichier : 8-jpeg-search.dd (440 MB)
```

### Volatility 3 (Analyse Mémoire)

```powershell
# Option A : Via pip (recommandé)
pip install volatility3

# Option B : Depuis GitHub
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -r requirements.txt

# Vérifier l'installation
python vol.py --version

# Télécharger les Symbol Tables Windows (requis pour analyse mémoire Windows)
# https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
# → Extraire dans : volatility3/volatility3/symbols/windows/
```

### Autres outils utiles

```powershell
# Eric Zimmerman Tools (incontournables DFIR Windows)
# https://ericzimmermantools.com/all-tools
# → KAPE, MFTECmd, LECmd, AppCompatCacheParser, EvtxECmd...
Invoke-WebRequest "https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip" -OutFile "EZTools.zip"
```

---

## 🎯 Cas pratique — NIST CFReDS "Hacking Case"

### Contexte de l'investigation

> *"Un laptop d'entreprise a été compromis. L'utilisateur suspect aurait téléchargé des outils et effacé des fichiers. Votre mission : reconstruire l'activité et produire un rapport d'investigation."*

**Image analysée :** `8-jpeg-search.dd` (NIST CFReDS Hacking Case)  
**Hash MD5 de référence :** `b94f8419de4e0e87b44a66082f45b12f` *(vérifier après download)*

### Méthodologie d'investigation (PICERL)

```
P — Préparation    : Configuration environnement, hash-verification de l'image
I — Identification : Inventaire des artefacts, timeline initiale
C — Confinement    : (N/A — analyse post-mortem)
E — Éradication    : Identification IOC et vecteur d'attaque
R — Rétablissement : Recommandations
L — Leçons         : Rapport final
```

### Étape 1 — Vérifier l'intégrité de l'image

```powershell
# Windows PowerShell
Get-FileHash "8-jpeg-search.dd" -Algorithm MD5
Get-FileHash "8-jpeg-search.dd" -Algorithm SHA256

# Python (inclus dans ce projet)
python scripts/forensic_analyzer.py --verify-hash "8-jpeg-search.dd"
```

### Étape 2 — Analyse avec Autopsy

1. Ouvrir Autopsy → **New Case**
2. Nom : `NIST_Hacking_Case` / Numéro : `2024-001`
3. Add Data Source → **Disk Image or VM File**
4. Sélectionner `8-jpeg-search.dd`
5. Activer les modules : **Hash Lookup**, **File Type Identification**, **Keyword Search**, **Recent Activity**
6. Attendre l'ingest (~10-15 min)

**Artefacts clés à rechercher :**
- Fichiers supprimés (icône rouge dans l'arborescence)
- Carving JPEG (outils téléchargés ?)
- Browser history (URLs de téléchargement)
- Recent documents

### Étape 3 — Timeline avec notre script Python

```bash
# Générer une timeline complète depuis l'image
python scripts/log_timeline.py \
  --image "8-jpeg-search.dd" \
  --output timeline_nist.csv \
  --format csv

# Filtrer sur une plage horaire
python scripts/log_timeline.py \
  --input timeline_nist.csv \
  --start "2004-08-17 00:00" \
  --end "2004-08-18 23:59" \
  --keywords "http,ftp,download,deleted"
```

### Étape 4 — Analyse du Registre

```bash
# Extraire les infos de persistance depuis le registre
python scripts/registry_parser.py \
  --hive SOFTWARE \
  --keys "CurrentVersion/Run,CurrentVersion/RunOnce" \
  --output registry_persistence.json

# Autologon (mots de passe en clair)
python scripts/registry_parser.py --autologon

# Liste des programmes installés
python scripts/registry_parser.py --installed-software
```

---

## 📝 Template Rapport d'Investigation

Voir [`reports/report_template.md`](./reports/report_template.md)

**Sections obligatoires :**
1. Résumé exécutif (1 page)
2. Contexte et périmètre
3. Méthodologie
4. Chaîne de custody
5. Analyse technique détaillée
6. Timeline des événements
7. Indicateurs de compromission (IOC)
8. Conclusions et recommandations
9. Annexes (screenshots, hashes)

---

## 🐍 Scripts Python — Usage rapide

| Script | Fonction | Commande |
|--------|----------|---------|
| `forensic_analyzer.py` | Analyse complète automatisée | `python forensic_analyzer.py --image case.dd` |
| `log_timeline.py` | Reconstruction timeline | `python log_timeline.py --evtx C:\Windows\System32\winevt\Logs\` |
| `registry_parser.py` | Analyse registre | `python registry_parser.py --hive NTUSER.DAT` |
| `memory_analysis_helper.py` | Aide Volatility 3 | `python memory_analysis_helper.py --dump memory.dmp` |

---

## 📚 Références DFIR

| Ressource | Lien |
|-----------|------|
| NIST CFReDS Images | https://cfreds.nist.gov |
| Volatility 3 Docs | https://volatility3.readthedocs.io |
| Eric Zimmerman Tools | https://ericzimmermantools.com |
| SANS DFIR Posters | https://www.sans.org/posters/ |
| Forensics Wiki | https://forensicswiki.xyz |
| Digital Forensics Framework (FIRST) | FIRST CSIRT Services Framework §4.3 |
