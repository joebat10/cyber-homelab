# 🔍 Guide d'installation Sysmon — Cyber Homelab

> **Objectif** : Installer Sysmon sur Windows 11 pour enrichir la télémétrie envoyée à Wazuh.  
> **Temps estimé** : 15–20 minutes  
> **Prérequis** : Windows 11, droits administrateur, Wazuh agent installé

---

## Pourquoi Sysmon ?

Sysmon (System Monitor) est un outil **gratuit de Microsoft Sysinternals** qui enrichit considérablement les logs Windows. Sans Sysmon, Windows ne log que des événements basiques. Avec Sysmon :

| Sans Sysmon | Avec Sysmon |
|-------------|-------------|
| Processus créés (EventID 4688, incomplet) | Process Create avec hash + ligne de commande complète |
| Connexions réseau (parfois) | Connexions réseau avec PID + processus source |
| ❌ Injections de processus | ✅ CreateRemoteThread détecté |
| ❌ Accès à LSASS | ✅ ProcessAccess sur lsass.exe |
| ❌ Chargement de DLL | ✅ ImageLoad avec hash |

---

## 1. Télécharger Sysmon

```powershell
# PowerShell en Administrateur
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"
```

Ou télécharger manuellement sur : https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## 2. Installer Sysmon avec la config du projet

```powershell
# Copier la config du projet dans C:\Tools\Sysmon\
Copy-Item "01-soc\configs\sysmon_config.xml" -Destination "C:\Tools\Sysmon\"

# Installer Sysmon avec la config
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmon_config.xml

# Vérifier que le service tourne
Get-Service Sysmon64
# Statut doit être : Running
```

---

## 3. Vérifier les logs générés

```powershell
# Voir les derniers events Sysmon dans l'Event Viewer
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | 
  Format-List TimeCreated, Id, Message

# Event IDs Sysmon importants :
# 1  = Process Create          ← le plus utile
# 3  = Network Connect
# 7  = Image Loaded (DLL)
# 8  = CreateRemoteThread      ← injection détectée
# 10 = ProcessAccess           ← accès LSASS
# 11 = FileCreate
# 12/13 = RegistryEvent
# 22 = DNS Query
```

---

## 4. Configurer Wazuh pour collecter les logs Sysmon

Sur l'agent Windows, éditer `C:\Program Files (x86)\ossec-agent\ossec.conf` :

```xml
<ossec_config>
  <!-- Ajouter dans la section <localfile> -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

```powershell
# Redémarrer l'agent Wazuh
Restart-Service WazuhSvc
```

---

## 5. Mettre à jour la config Sysmon

```powershell
# Mettre à jour la config sans réinstaller
.\Sysmon64.exe -c sysmon_config.xml

# Désinstaller (si nécessaire)
.\Sysmon64.exe -u
```

---

## 6. Test rapide — vérifier la détection

```powershell
# Générer un EventID 1 (process create) visible dans Sysmon
cmd.exe /c whoami
net user

# Vérifier dans les logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
  Where-Object Id -eq 1 |
  Select-Object TimeCreated, Message
```

---

## Ressources

- 📖 [Documentation Sysmon (Microsoft)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- ⚙️ [SwiftOnSecurity Sysmon Config (référence)](https://github.com/SwiftOnSecurity/sysmon-config)
- ⚙️ [Sysmon Modular (olafhartong)](https://github.com/olafhartong/sysmon-modular)
- 🗺️ [Sysmon → MITRE ATT&CK mapping](https://github.com/olafhartong/sysmon-attck)
