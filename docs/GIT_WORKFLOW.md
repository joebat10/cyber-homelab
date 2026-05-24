# 📋 Stratégie Git — Cyber Homelab

## Convention de commits (Conventional Commits)

```
<type>(<scope>): <description courte>

[corps optionnel]
[footer optionnel]
```

### Types
| Type | Usage |
|------|-------|
| `feat` | Nouveau script, nouvelle règle, nouveau cas pratique |
| `fix` | Correction d'un bug dans un script |
| `docs` | Ajout/modification de documentation |
| `chore` | Maintenance, mise à jour deps |
| `lab` | Résultats d'une expérimentation (output captures) |

### Exemples de messages
```
feat(soc): add Kerberoasting detection rule #T1558.003
feat(dfir): add NIST hacking case forensic analysis
feat(cti): add APT28 STIX threat intelligence report
docs(soc): update Wazuh installation guide
fix(scripts): handle connection timeout in wazuh_alert_manager
lab(dfir): add forensic timeline screenshots from NIST case
```

---

## Stratégie de branches

```
main           ← Stable, démontrable en entretien
  └── develop  ← En cours de développement
        ├── soc/detection-rules
        ├── dfir/nist-case-analysis
        └── cti/apt28-report
```

## Commandes Git pour démarrer

```powershell
# Cloner et configurer
git clone https://github.com/joebat10/cyber-homelab.git
cd cyber-homelab
git config user.name "Joe Bichall"
git config user.email "votre@email.com"

# Créer la branche develop
git checkout -b develop

# Workflow quotidien
git add .
git commit -m "feat(soc): add custom rules for PTH detection"
git push origin develop

# Merge vers main quand c'est stable
git checkout main
git merge develop
git push origin main
```

---

## Ordre des commits recommandé (pour montrer une progression logique)

```
1. "init: project structure and README"
2. "feat(soc): add Wazuh installation guide"
3. "feat(soc): add Sysmon config and installation guide"
4. "feat(soc): add wazuh_alert_manager.py"
5. "feat(soc): add AD attack detection rules (T1003, T1558)"
6. "feat(soc): add alert_enricher.py with MITRE mapping"
7. "feat(dfir): add Autopsy and Volatility installation guides"
8. "feat(dfir): add forensic_analyzer.py"
9. "feat(dfir): add NIST hacking case analysis"
10. "feat(dfir): add professional DFIR report template"
11. "feat(cti): add ioc_collector.py with VirusTotal/OSINT"
12. "feat(cti): add APT28 CTI report with MITRE ATT&CK mapping"
13. "feat(cti): add MISP integration script"
14. "docs: add SETUP_GUIDE and architecture diagrams"
```
