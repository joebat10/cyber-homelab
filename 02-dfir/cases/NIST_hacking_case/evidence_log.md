# 🔐 Journal de chaîne de custody — NIST Hacking Case

> **IMPORTANT** : Ce fichier documente chaque action sur l'image disque.  
> En DFIR professionnel, la chaîne de custody est critique pour la recevabilité en justice.  
> Toujours travailler sur une **copie** de l'image, jamais sur l'original.

---

## Informations sur la preuve

| Champ | Valeur |
|-------|--------|
| Nom du cas | NIST CFReDS — Hacking Case |
| Référence NIST | https://www.cfreds.nist.gov/Hacking_Case.html |
| Fichier image | SCHARDT.DD |
| Format | Image disque brute (raw) |
| Hash MD5 original | *(à documenter après téléchargement)* |
| Hash SHA256 original | *(à documenter après téléchargement)* |
| Taille | *(à documenter)* |
| Analyste | Joe Bichall |
| Date d'acquisition copie de travail | *(à compléter)* |

---

## Journal des actions

| # | Date/Heure | Action | Outil | Résultat | Analyste |
|---|-----------|--------|-------|----------|---------|
| 1 | *(date)* | Téléchargement image NIST | Navigateur | OK | J. Bichall |
| 2 | *(date)* | Vérification hash MD5 | certutil | Hash = ??? | J. Bichall |
| 3 | *(date)* | Copie de travail créée | robocopy | OK | J. Bichall |
| 4 | *(date)* | Import dans Autopsy | Autopsy 4.x | Nouveau cas créé | J. Bichall |
| 5 | *(date)* | Analyse automatisée | forensic_analyzer.py | Rapport généré | J. Bichall |
| 6 | *(date)* | Extraction registre | Autopsy | NTUSER.DAT extrait | J. Bichall |
| 7 | *(date)* | Analyse registre | registry_parser.py | Findings exportés | J. Bichall |
| 8 | *(date)* | Construction timeline | log_timeline.py | timeline.csv | J. Bichall |

---

## Preuves collectées

| ID | Type | Description | Chemin | Hash | Pertinence |
|----|------|-------------|--------|------|-----------|
| E001 | Image disque | SCHARDT.DD — image principale | /evidence/SCHARDT.DD | TBD | ⭐⭐⭐ |
| E002 | Registre | NTUSER.DAT — profil utilisateur | /extracted/NTUSER.DAT | TBD | ⭐⭐⭐ |
| E003 | Registre | SAM — comptes utilisateurs | /extracted/SAM | TBD | ⭐⭐⭐ |
| E004 | Registre | SYSTEM — config système | /extracted/SYSTEM | TBD | ⭐⭐ |
| E005 | Logs | Logs événements Windows | /extracted/logs/ | TBD | ⭐⭐⭐ |
| E006 | Fichiers | Outils suspects trouvés | /extracted/suspicious/ | TBD | TBD |
| E007 | Timeline | Timeline reconstruite | /reports/timeline.csv | N/A | ⭐⭐⭐ |

---

## Notes sur l'intégrité

```bash
# Commandes à exécuter et documenter

# Hash de l'image originale
certutil -hashfile SCHARDT.DD MD5
certutil -hashfile SCHARDT.DD SHA256

# Hash de la copie de travail (doit correspondre à l'original)
certutil -hashfile SCHARDT_WORK.DD MD5

# Vérification avec forensic_analyzer.py
python 02-dfir/scripts/forensic_analyzer.py --verify-hash SCHARDT.DD
```

---

*Document créé dans le cadre du projet cyber-homelab — Joe Bichall (@joebat10)*
