# 🤖 Guide Claude Code — Cyber Homelab

Ce document explique comment utiliser **Claude Code** pour développer et enrichir ce projet.

---

## Qu'est-ce que Claude Code ?

Claude Code est un assistant IA en ligne de commande qui comprend ton code, tes fichiers et ton contexte de projet. Il peut :
- Écrire et modifier des scripts Python
- Expliquer chaque ligne de code
- Déboguer les erreurs en temps réel
- Générer de la documentation
- Faire des commits Git

---

## Installation

```powershell
# Prérequis : Node.js 18+ (https://nodejs.org/)
node --version  # Vérifier

# Installer Claude Code
npm install -g @anthropic-ai/claude-code

# Vérifier
claude --version
```

---

## Utilisation dans ce projet

### Démarrer Claude Code dans le projet
```powershell
cd C:\Users\[VotreNom]\Documents\cyber-homelab
claude
```

### Commandes utiles

#### Comprendre un script existant
```
> explain wazuh_alert_manager.py
> what does the --watch flag do in wazuh_alert_manager.py?
> explain the Kerberoasting detection rule in wazuh_ad_attacks.xml
```

#### Modifier/améliorer un script
```
> add email notification when a CRITICAL alert is detected in wazuh_alert_manager.py
> improve error handling in ioc_collector.py
> add a --dry-run flag to simulate_attack.py
```

#### Créer de nouveaux scripts
```
> create a Python script that parses Volatility3 output and generates a JSON timeline
> write a script to automatically update IOC CSV from OTX AlienVault feeds
> create a Sigma rule for detecting PsExec lateral movement
```

#### Git avec Claude Code
```
> commit all changes with a conventional commit message
> what files have changed since the last commit?
> create a pull request description for the new SOC rules
```

---

## Astuces pour ce projet

### Expliquer ce que tu veux (contexte = clé)
```
# BON prompt :
> I'm working on the SOC module. Add a function to wazuh_alert_manager.py 
> that sends a Slack webhook notification when an alert with MITRE ID T1003 
> (credential dumping) is detected. Use the existing requests library.

# MAUVAIS prompt :
> Add Slack notifications
```

### Apprendre en faisant
```
> explain how this Wazuh XML rule detects Pass-the-Hash, step by step
> what's the difference between Sysmon Event ID 10 and 8?
> why do we use STIX 2.1 format for IOCs?
```

### Déboguer
```
> I get "ConnectionRefusedError" when running wazuh_alert_manager.py, help me fix it
> the ioc_collector.py returns empty results for IP lookups, debug this
```

---

## Workflow recommandé

```
1. Ouvrir Claude Code dans le dossier du projet
2. Demander à Claude d'expliquer le fichier avant de le modifier
3. Faire les modifications avec Claude
4. Tester le script
5. Demander à Claude de committer avec un bon message
6. Passer au prochain fichier
```

---

*Ce projet a été initialement architecturé avec Claude (claude.ai) puis développé et maintenu avec Claude Code.*
