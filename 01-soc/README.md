# Module 01 — SOC : Detection & Monitoring

> **Tools:** Wazuh 4.x + Sysmon 15.x + TheHive 5 integration
> **Framework:** FIRST CSIRT Services Framework — *Information Security Event Management*
> **Use case:** Active Directory attack detection (T1003, T1558, T1021)

---

## Architecture

```
Windows 11 Host (you)
  ├── VMware VM ──── Ubuntu 22.04 ── Wazuh Manager 4.x (192.168.56.10)
  │                                      ├── Wazuh Indexer   (port 9200)
  │                                      └── Wazuh Dashboard (port 443)
  │
  ├── Docker (04-soar/)
  │     ├── TheHive 5  (port 9010)
  │     └── Cortex 3   (port 9011)
  │
  └── Wazuh Agent ── forwards Sysmon events → Wazuh Manager
        (installed on this Windows host or lab VMs)
```

---

## Installation Order

Follow these steps in sequence. Each step depends on the previous.

### Step 1 — Start the SOAR stack (TheHive + Cortex)

```powershell
# From the project root
cd 04-soar
docker compose up -d
# Wait ~2 minutes for all services to become healthy
docker compose ps
```

TheHive will be at `http://127.0.0.1:9010` — login: `admin@admin.test` / `MISPadmin2024!Lab`

### Step 2 — Install Wazuh on Ubuntu 22.04 VM

Open your VMware console to the Ubuntu 22.04 VM (IP: 192.168.56.10).

```bash
# On the Ubuntu VM
git clone https://github.com/joebat10/cyber-homelab.git
cd cyber-homelab/01-soc/setup
chmod +x install_wazuh.sh
sudo bash install_wazuh.sh
```

**What it does:** Runs the official Wazuh 4.9 all-in-one installer
(Manager + Indexer + Dashboard), deploys custom rules, opens firewall ports.

**Duration:** 10–20 minutes depending on network.

**After install:**
- Dashboard: `https://192.168.56.10` (accept self-signed cert)
- API: `https://192.168.56.10:55000`
- Save the admin password printed at the end

### Step 3 — Install Sysmon on Windows (this machine)

```powershell
# PowerShell as Administrator
cd 01-soc\setup
.\install_sysmon.ps1
# Uses SwiftOnSecurity config by default
# To use local repo config instead:
.\install_sysmon.ps1 -UseLocalConfig
```

Sysmon captures process creation, network connections, LSASS access events, etc.
These feed directly into the Wazuh agent.

### Step 4 — Install Wazuh agent on Windows (this machine)

```powershell
# PowerShell as Administrator
cd 01-soc\setup
.\install_agent_windows.ps1
# With custom agent name:
.\install_agent_windows.ps1 -ManagerIP 192.168.56.10 -AgentName "WIN11-LAB"
```

Verify on the Wazuh Manager:
```bash
sudo /var/ossec/bin/agent_control -l
```

### Step 5 — Deploy custom detection rules

```bash
# On the Wazuh Manager VM
RULES_DIR="/var/ossec/etc/rules"
REPO="/home/$USER/cyber-homelab/01-soc/rules"
sudo cp "$REPO"/*.xml "$RULES_DIR/"
sudo /var/ossec/bin/wazuh-control restart
```

### Step 6 — Get your TheHive API key

1. Open `http://127.0.0.1:9010`
2. Log in as `admin@admin.test`
3. Top-right menu → **API Key** → copy the key
4. Add it to `01-soc/.env`:

```bash
# 01-soc/.env (create this file, do NOT commit it)
THEHIVE_API_KEY=your_api_key_here
WAZUH_PASS=your_wazuh_admin_password_here
```

### Step 7 — Run the bridge (Wazuh → TheHive)

```bash
# One-shot: forward all level 10+ alerts from the last 24h
cd 01-soc
python scripts/wazuh_to_thehive.py

# Daemon mode: watch and forward in real time
python scripts/wazuh_to_thehive.py --watch

# Only HIGH and CRITICAL (level 12+)
python scripts/wazuh_to_thehive.py --watch --level 12
```

### Step 8 — Run the pipeline test

```bash
cd 01-soc/setup
python test_soc_pipeline.py --thehive-key <your_api_key>
```

All 8 checks should pass. See Troubleshooting if any fail.

---

## File Structure

```
01-soc/
├── README.md
├── setup/
│   ├── install_wazuh.sh              ← Wazuh Manager install (Ubuntu 22.04)
│   ├── install_agent_windows.ps1     ← Wazuh agent install (Windows)
│   ├── install_sysmon.ps1            ← Sysmon install with SwiftOnSecurity config
│   └── test_soc_pipeline.py          ← End-to-end connectivity test
├── scripts/
│   ├── wazuh_to_thehive.py           ← Wazuh alert → TheHive bridge (daemon)
│   ├── wazuh_alert_manager.py        ← Alert viewer / exporter / watch mode
│   ├── alert_enricher.py             ← IOC enrichment (VirusTotal/Shodan)
│   ├── simulate_attack.py            ← Synthetic attack event generator
│   └── soc_dashboard_exporter.py     ← Dashboard metrics exporter
├── rules/
│   ├── wazuh_ad_attacks.xml          ← AD attack rules (PTH, Kerberoast, DCSync)
│   ├── wazuh_lolbins.xml             ← Living-off-the-land binary rules
│   └── wazuh_lateral_movement.xml    ← WinRM / SMB lateral movement rules
├── configs/
│   └── sysmon_config.xml             ← Sysmon config (SwiftOnSecurity base)
└── docs/
    ├── INSTALL_WAZUH.md
    └── INSTALL_SYSMON.md
```

---

## How to Verify Everything Works

### Check Wazuh services (on the VM)

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo /var/ossec/bin/wazuh-control status
```

### Check agent is connected (on the VM)

```bash
sudo /var/ossec/bin/agent_control -l
# Expected: your Windows agent listed as Active
```

### Check alerts flowing (from Windows)

```bash
# View live alerts in terminal (requires Wazuh to be running)
python 01-soc/scripts/wazuh_alert_manager.py --watch --level 7

# Export last 24h alerts to CSV
python 01-soc/scripts/wazuh_alert_manager.py --export --output alerts.csv
```

### Simulate an attack (test detection)

```bash
python 01-soc/scripts/simulate_attack.py --host 192.168.56.10
```

### Run full pipeline test

```bash
python 01-soc/setup/test_soc_pipeline.py --thehive-key <key>
```

---

## Scripts Reference

### `wazuh_to_thehive.py`

```bash
python scripts/wazuh_to_thehive.py --help

# One-shot (last 24h, level >= 10)
python scripts/wazuh_to_thehive.py --thehive-key <key>

# Daemon
python scripts/wazuh_to_thehive.py --watch --thehive-key <key>

# Only forward critical
python scripts/wazuh_to_thehive.py --watch --level 13 --thehive-key <key>
```

### `wazuh_alert_manager.py`

```bash
# Terminal table view
python scripts/wazuh_alert_manager.py --level 10

# Export CSV
python scripts/wazuh_alert_manager.py --export --output alerts.csv --hours 48

# Statistics
python scripts/wazuh_alert_manager.py --stats

# Filter by MITRE technique
python scripts/wazuh_alert_manager.py --mitre T1003
```

---

## Detection Rules Summary

| Rule | Wazuh ID | MITRE | Level | Description |
|------|----------|-------|-------|-------------|
| LSASS Access | 100001 | T1003.001 | 15 | LSASS memory access (Mimikatz) |
| Kerberoasting | 100002 | T1558.003 | 13 | RC4 ticket for service account |
| DCSync | 100003 | T1003.006 | 15 | AD replication (DS-Replication-Get-Changes) |
| Pass-the-Hash | 100004 | T1550.002 | 14 | NTLM hash logon |
| LOLBin Execution | 100010 | T1218 | 10 | certutil / mshta / regsvr32 |
| WinRM Lateral | 100020 | T1021.006 | 12 | Suspicious WinRM session |
| Scheduled Task | 100030 | T1053.005 | 11 | Scheduled task creation |
| NTLM Dump | 100040 | T1003 | 14 | NTLM dump via secretsdump |

---

## Troubleshooting

### Wazuh agent not connecting to manager

```powershell
# Windows host
Test-NetConnection -ComputerName 192.168.56.10 -Port 1514
# Must be True — if not, open port on VM:
# sudo ufw allow 1514/tcp
```

```bash
# On VM — check manager is listening
ss -tlnp | grep "1514\|1515"
# If not listening: sudo systemctl restart wazuh-manager
```

### TheHive API key rejected (401)

```
TheHive → login → top-right avatar → API Key → copy
Set in 01-soc/.env:  THEHIVE_API_KEY=<key>
```

### Wazuh API wrong password

The admin password is printed at the end of `install_wazuh.sh` and saved
in `/tmp/wazuh_install.log` on the VM. You can also reset it:

```bash
# On the Wazuh VM
sudo /var/ossec/bin/wazuh-passwords-tool -u admin -p NewPassword123!
```

### Sysmon events not appearing in Wazuh

Check the Wazuh agent config on Windows includes the Sysmon channel:

```xml
<!-- C:\Program Files (x86)\ossec-agent\ossec.conf -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart agent after any config change:
```powershell
Restart-Service WazuhSvc
```

### wazuh_to_thehive.py: "Cannot connect to Wazuh API"

```bash
# Verify API port is open from Windows host
python -c "import socket; s=socket.create_connection(('192.168.56.10', 55000), 3); print('OK')"
# If timeout: check ufw on the VM (sudo ufw allow 55000/tcp)
```

---

## References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [TheHive 5 API](https://docs.strangebee.com/thehive/api-docs/)
- [Sysmon Config — SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [Sigma Rules — SigmaHQ](https://github.com/SigmaHQ/sigma)
