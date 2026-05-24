# 📋 Notes d'investigation — Cas NIST CFReDS Hacking Case

**Référence** : NIST Computer Forensics Reference Data Sets (CFReDS)  
**Cas** : Hacking Case — Image disque fournie par le NIST pour formation DFIR  
**Analyste** : Joe Bichall  
**Date début** : *(à compléter)*  
**Statut** : 🟡 En cours

---

## 📥 Téléchargement de l'image

L'image est disponible gratuitement sur le site officiel du NIST :

```
URL : https://www.cfreds.nist.gov/Hacking_Case.html
Fichier : SCHARDT.DD (image disque brute, environ 1 Go)
MD5     : *(à vérifier après téléchargement)*
```

```powershell
# Vérifier l'intégrité après téléchargement
certutil -hashfile SCHARDT.DD MD5
# Hash attendu : documenter ici
```

---

## 🎯 Contexte du cas (fourni par le NIST)

> *"On 09/20/04, Det. John Smith was contacted by Mr. Neils Schardtof Springfield, Sas, who stated that he found a wireless computer that did not belong to him in his possession..."*

**Résumé** :
- Un ordinateur portable a été retrouvé avec des preuves potentielles de hacking
- L'image disque contient Windows XP
- Les questions portent sur : utilisateurs, connexions réseau, outils installés, activités suspectes

**Questions directrices du NIST** :
1. Quel est le nom du suspect ?
2. Quel OS est installé ? Version ? Fuseau horaire ?
3. Quelle est l'heure exacte du dernier accès ?
4. Des outils de hacking sont-ils présents ?
5. Y a-t-il des preuves de connexions réseau non autorisées ?
6. Des preuves de chiffrement ou dissimulation de données ?

---

## 🔧 Outils d'analyse

| Outil | Usage | Commande |
|-------|-------|---------|
| Autopsy | Analyse globale, navigateur de fichiers | Interface graphique |
| FTK Imager | Monter l'image, vérifier hash | `ftkimager --verify` |
| python forensic_analyzer.py | Extraction automatisée | `python forensic_analyzer.py --image SCHARDT.DD` |
| python log_timeline.py | Timeline des événements | `python log_timeline.py --evtx ...` |
| python registry_parser.py | Analyse registre | Extraire NTUSER.DAT puis parser |
| strings | Chaînes ASCII/Unicode | `strings SCHARDT.DD > strings.txt` |

---

## 📝 Notes d'analyse en cours

### Phase 1 — Acquisition et vérification

- [ ] Télécharger SCHARDT.DD depuis NIST CFReDS
- [ ] Calculer et documenter les hash MD5/SHA256
- [ ] Monter l'image en lecture seule dans Autopsy
- [ ] Vérifier la taille et l'intégrité

```bash
# MD5 calculé : _______________
# SHA256      : _______________
# Taille      : _______________
```

### Phase 2 — Identification du système

- [ ] OS et version
- [ ] Nom de machine (hostname)
- [ ] Fuseau horaire (IMPORTANT pour la timeline)
- [ ] Dernière connexion / shutdown time

**Clés de registre à examiner** :
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion  → Version OS
HKLM\SYSTEM\CurrentControlSet\Control\ComputerName → Hostname
HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation → Timezone
```

### Phase 3 — Utilisateurs et comptes

- [ ] Liste des comptes (SAM)
- [ ] Dernier login de chaque compte
- [ ] Groupes d'appartenance
- [ ] Profils utilisateurs

### Phase 4 — Activité réseau

- [ ] Adaptateurs réseau et config IP
- [ ] Réseaux WiFi connus (HKLM\SOFTWARE\Microsoft\WZCSVC)
- [ ] Connexions récentes
- [ ] Traces de netcat, nmap, metasploit ou outils similaires

### Phase 5 — Outils et programmes suspects

*(À compléter lors de l'analyse)*

---

## 💡 Méthodologie PICERL appliquée

```
P - Préparation : Lab isolé, outils prêts, hash calculé
I - Identification : OS, users, timeline établie
C - Containment : N/A (post-incident forensique)
E - Eradication : N/A
R - Recovery : N/A  
L - Lessons Learned : À documenter dans le rapport final
```

---

## 🔗 Ressources

- [NIST CFReDS Hacking Case](https://www.cfreds.nist.gov/Hacking_Case.html)
- [Autopsy Documentation](https://www.autopsy.com/documentation/)
- [Volatility 3 Docs](https://volatility3.readthedocs.io/)
- [SANS DFIR Cheat Sheets](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/)
