#!/usr/bin/env python3
"""
registry_parser.py — Analyse forensique du registre Windows
Auteur  : Joe Bichall (@joebat10)
Usage   : python registry_parser.py --live      (registre de la machine locale)
          python registry_parser.py --hive NTUSER.DAT --demo

Points d'intérêt DFIR :
  - Persistance (Run keys, Services, Autoruns)
  - Credentials stockés (autologon, credentials manager)
  - Activité utilisateur (RecentDocs, UserAssist, ShellBags, MRU)
  - Traces de connexions réseau (mapped drives, WiFi)
  - Evidence de compression/archivage
"""

import json
import csv
import argparse
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

try:
    __import__("Registry")   # python-registry — availability check
    REGISTRY_LIB = True
except ImportError:
    REGISTRY_LIB = False

try:
    from rich.console import Console
    console = Console()
    RICH = True
except ImportError:
    RICH = False


# ─── MODÈLE ──────────────────────────────────────────────────────────────────

@dataclass
class RegFinding:
    category: str          # Persistence, Credentials, Activity, Network
    key_path: str
    value_name: str
    value_data: str
    last_modified: str
    severity: str          # info / medium / high / critical
    mitre_technique: str
    notes: str


# ─── CLÉS FORENSIQUES D'INTÉRÊT ──────────────────────────────────────────────

# (hive, chemin relatif, description, mitre, sévérité)
FORENSIC_KEYS = {
    "persistence": [
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "Autoruns HKLM — démarrage pour tous les utilisateurs", "T1547.001", "high"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "Autoruns HKCU — démarrage utilisateur courant", "T1547.001", "high"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "RunOnce HKLM — exécution unique au démarrage", "T1547.001", "medium"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Services",
         "Services Windows — possibilité de service malveillant", "T1543.003", "high"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
         "Winlogon — Userinit/Shell peuvent être modifiés", "T1547.004", "high"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
         "Dossiers shell utilisateur", "T1547", "info"),
    ],
    "credentials": [
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
         "Autologon — credentials en clair possibles", "T1552.002", "critical"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
         "WDigest — si UseLogonCredential=1, mots de passe en mémoire LSASS", "T1003.001", "critical"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa",
         "LSA Settings — RunAsPPL protège LSASS", "T1003.001", "high"),
    ],
    "activity": [
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
         "Documents récemment ouverts", "T1005", "medium"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
         "Fichiers ouverts/sauvegardés depuis boîtes de dialogue", "T1005", "medium"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
         "Commandes tapées dans Exécuter (Win+R)", "T1059", "medium"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
         "Chemins tapés dans l'explorateur Windows", "T1005", "info"),
    ],
    "network": [
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
         "Lecteurs réseau montés (historique)", "T1021.002", "medium"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged",
         "Réseaux WiFi connus", "T1016", "info"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
         "Configuration IP des interfaces réseau", "T1016", "info"),
    ],
    "defense_evasion": [
        ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender",
         "Paramètres Windows Defender — désactivé si DisableAntiSpyware=1", "T1562.001", "critical"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Security",
         "Configuration logs de sécurité", "T1070.001", "high"),
    ],
}


# ─── ANALYSEUR REGISTRE LIVE ──────────────────────────────────────────────────

class LiveRegistryAnalyzer:
    """Analyse le registre de la machine Windows locale."""

    HIVES = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
        "HKCU": winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
        "HKCR": winreg.HKEY_CLASSES_ROOT if WINREG_AVAILABLE else None,
    }

    def read_key(self, hive_name: str, key_path: str) -> dict:
        """Lit toutes les valeurs d'une clé de registre."""
        values = {}
        if not WINREG_AVAILABLE:
            return values
        try:
            hive = self.HIVES.get(hive_name)
            if not hive:
                return values
            with winreg.OpenKey(hive, key_path) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = str(data)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[!] Erreur lecture {hive_name}\\{key_path}: {e}")
        return values

    def analyze_autologon(self) -> List[RegFinding]:
        """Détecte la configuration Autologon (credentials en clair)."""
        findings = []
        vals = self.read_key("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
        user = vals.get("DefaultUserName", "")
        password = vals.get("DefaultPassword", "")
        enabled = vals.get("AutoAdminLogon", "0")

        if enabled == "1":
            severity = "critical" if password else "high"
            findings.append(RegFinding(
                category="Credentials",
                key_path=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                value_name="AutoAdminLogon",
                value_data=f"User={user} | Password={'***SET***' if password else 'empty'}",
                last_modified=datetime.now().isoformat(),
                severity=severity,
                mitre_technique="T1552.002",
                notes="Autologon activé — credentials potentiellement stockés en clair dans le registre",
            ))
        return findings

    def analyze_run_keys(self) -> List[RegFinding]:
        """Analyse les clés d'autorun."""
        findings = []
        run_keys = [
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "high"),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "high"),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "medium"),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "medium"),
        ]
        # Entrées Windows légitimes connues
        KNOWN_LEGIT = {"SecurityHealth", "WindowsDefender", "OneDrive", "Teams",
                       "Cortana", "MicrosoftEdgeAutoLaunch"}

        for hive, path, severity in run_keys:
            vals = self.read_key(hive, path)
            for name, data in vals.items():
                if name in KNOWN_LEGIT:
                    sev = "info"
                else:
                    sev = severity
                    # Indices suspects
                    if any(x in data.lower() for x in ["temp", "appdata\\roaming", "powershell", "cmd.exe"]):
                        sev = "critical"

                findings.append(RegFinding(
                    category="Persistence",
                    key_path=f"{hive}\\{path}",
                    value_name=name,
                    value_data=data[:200],
                    last_modified=datetime.now().isoformat(),
                    severity=sev,
                    mitre_technique="T1547.001",
                    notes="Entrée légitime connue" if name in KNOWN_LEGIT else "Vérifier si connue/légitime",
                ))
        return findings

    def analyze_defender(self) -> List[RegFinding]:
        """Vérifie si Windows Defender est désactivé via le registre."""
        findings = []
        vals = self.read_key("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender")
        disabled = vals.get("DisableAntiSpyware", "0")
        if disabled == "1":
            findings.append(RegFinding(
                category="Defense Evasion",
                key_path=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                value_name="DisableAntiSpyware",
                value_data="1 — DEFENDER DÉSACTIVÉ",
                last_modified=datetime.now().isoformat(),
                severity="critical",
                mitre_technique="T1562.001",
                notes="Windows Defender désactivé par GPO ou script — indicateur fort de compromission",
            ))
        return findings

    def analyze_wdigest(self) -> List[RegFinding]:
        """Vérifie si WDigest force les mots de passe en mémoire."""
        findings = []
        vals = self.read_key("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")
        ulc = vals.get("UseLogonCredential", "0")
        if ulc == "1":
            findings.append(RegFinding(
                category="Credentials",
                key_path=r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                value_name="UseLogonCredential",
                value_data="1 — Credentials en clair dans LSASS",
                last_modified=datetime.now().isoformat(),
                severity="critical",
                mitre_technique="T1003.001",
                notes="WDigest activé — un attaquant peut extraire les mots de passe en clair depuis LSASS",
            ))
        return findings

    def run_full_analysis(self) -> List[RegFinding]:
        print("[*] Analyse du registre local en cours...")
        findings = []
        findings.extend(self.analyze_autologon())
        findings.extend(self.analyze_run_keys())
        findings.extend(self.analyze_defender())
        findings.extend(self.analyze_wdigest())
        print(f"[✓] {len(findings)} entrées analysées")
        return findings


# ─── DONNÉES DÉMO ────────────────────────────────────────────────────────────

def generate_demo_findings() -> List[RegFinding]:
    return [
        RegFinding("Persistence",
                   r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                   "WindowsUpdate",
                   r"C:\Users\Public\svchost32.exe -s",
                   "2024-03-15T08:22:00", "critical", "T1547.001",
                   "Nom trompeur 'WindowsUpdate' dans Run — pointe vers %Public%, inhabituel"),
        RegFinding("Persistence",
                   r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                   "OneDrive",
                   r"C:\Users\john.doe\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                   "2024-01-10T14:00:00", "info", "T1547.001",
                   "Entrée OneDrive légitime"),
        RegFinding("Credentials",
                   r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                   "AutoAdminLogon + DefaultPassword",
                   "User=Administrator | Password=***SET***",
                   "2024-03-15T07:55:00", "critical", "T1552.002",
                   "Autologon configuré avec mot de passe en clair — très suspect"),
        RegFinding("Credentials",
                   r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                   "UseLogonCredential",
                   "1 — Credentials en clair dans LSASS",
                   "2024-03-15T08:00:00", "critical", "T1003.001",
                   "WDigest forcé — probablement par l'attaquant avant d'exécuter mimikatz"),
        RegFinding("Defense Evasion",
                   r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                   "DisableAntiSpyware",
                   "1 — DEFENDER DÉSACTIVÉ",
                   "2024-03-15T08:01:30", "critical", "T1562.001",
                   "Defender désactivé peu avant l'extraction de credentials"),
        RegFinding("Network",
                   r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
                   r"\\192.168.1.50\Share",
                   r"\\192.168.1.50\Share — monté le 2024-03-15",
                   "2024-03-15T08:18:00", "medium", "T1021.002",
                   "Partage réseau monté depuis 192.168.1.50 — cohérent avec le lateral movement"),
        RegFinding("Activity",
                   r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                   "a",
                   "powershell -enc SQBFAFgA...",
                   "2024-03-15T08:07:00", "high", "T1059.001",
                   "Commande PowerShell encodée tapée dans Win+R — fileless malware"),
    ]


# ─── OUTPUT ──────────────────────────────────────────────────────────────────

def print_findings(findings: List[RegFinding]):
    sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "ℹ️ "}
    cats = {}
    for f in findings:
        cats.setdefault(f.category, []).append(f)

    for cat, items in cats.items():
        print(f"\n{'─'*60}")
        print(f"  📂 {cat.upper()}")
        print(f"{'─'*60}")
        for f in items:
            icon = sev_icons.get(f.severity, "❓")
            print(f"\n  {icon} [{f.severity.upper()}] {f.value_name}")
            print(f"     Clé  : {f.key_path}")
            print(f"     Data : {f.value_data[:100]}")
            print(f"     MITRE: {f.mitre_technique}")
            if f.notes:
                print(f"     Note : {f.notes}")


def export_csv(findings: List[RegFinding], output: str):
    fields = ["category", "severity", "mitre_technique", "key_path",
              "value_name", "value_data", "last_modified", "notes"]
    with open(output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for finding in findings:
            row = asdict(finding)
            w.writerow({k: row.get(k, "") for k in fields})
    print(f"\n[✓] Export CSV → {output}")


def export_json(findings: List[RegFinding], output: str):
    with open(output, "w", encoding="utf-8") as f:
        json.dump([asdict(f) for f in findings], f, indent=2, ensure_ascii=False)
    print(f"[✓] Export JSON → {output}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse forensique du registre Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python registry_parser.py --live                        # Analyse registre local
  python registry_parser.py --demo                        # Données de démo
  python registry_parser.py --live --output findings.csv  # Export CSV
  python registry_parser.py --demo --output registry_demo.json --format json
"""
    )
    parser.add_argument("--live",   action="store_true", help="Analyser le registre local Windows")
    parser.add_argument("--demo",   action="store_true", help="Données de démonstration")
    parser.add_argument("--output", help="Fichier de sortie")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════╗
║   🔬 Registry Forensic Analyzer — Cyber Homelab   ║
╚═══════════════════════════════════════════════════╝
""")

    findings = []
    if args.demo:
        print("[i] Mode démonstration")
        findings = generate_demo_findings()
    elif args.live:
        if not WINREG_AVAILABLE:
            print("[!] winreg non disponible — exécuter sur Windows")
            print("[i] Passage en mode démo")
            findings = generate_demo_findings()
        else:
            analyzer = LiveRegistryAnalyzer()
            findings = analyzer.run_full_analysis()
    else:
        parser.print_help()
        return

    # Affichage console
    print_findings(findings)

    # Stats
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1
    print(f"\n{'='*50}")
    print(f"  Total : {len(findings)} entrées analysées")
    for sev, count in sev_counts.items():
        if count:
            print(f"  {sev.capitalize():<10} : {count}")

    # Export
    if args.output:
        if args.format == "json":
            export_json(findings, args.output)
        else:
            export_csv(findings, args.output)


if __name__ == "__main__":
    main()
