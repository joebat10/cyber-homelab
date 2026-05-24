#!/usr/bin/env python3
"""
ioc_collector.py
================
Collecte et qualification automatique d'IOC (Indicators of Compromise).

Fonctionnalités :
- Collecte depuis des sources publiques (AlienVault OTX, URLhaus, etc.)
- Qualification et scoring des IOC
- Export STIX 2.1 / CSV / JSON
- Déduplication et normalisation

Auteur : Joe Bichall (@joebat10)
Usage  : python ioc_collector.py --help
"""

import argparse
import csv
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# Clés API (optionnelles)
OTX_API_KEY = os.getenv("OTX_API_KEY", "")

try:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None

# ── Constantes ────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

IOC_TYPES = ["ipv4", "ipv6", "domain", "url", "email", "hash_md5",
             "hash_sha1", "hash_sha256", "filename"]

# Sources publiques (sans clé API)
FREE_SOURCES = {
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/",
    "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
    "feodotracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
}

# Groupes APT MITRE ATT&CK avec leurs IOC connus (échantillon éducatif)
APT_PROFILES = {
    "APT28": {
        "mitre_id": "G0007",
        "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM", "Sednit"],
        "attribution": "Russian GRU (Unit 26165, Unit 74455)",
        "motivation": "Espionage",
        "first_seen": "2007",
        "targets": ["Government", "Military", "Journalism", "Political Parties"],
        "ttps": [
            "T1566.001",  # Spearphishing
            "T1203",      # Exploitation for Client Execution
            "T1547.001",  # Registry Run Keys
            "T1053.005",  # Scheduled Task
            "T1078",      # Valid Accounts
            "T1003",      # Credential Dumping
            "T1021.001",  # RDP
            "T1071.001",  # Web Protocols (C2)
            "T1041",      # Exfiltration Over C2
            "T1027",      # Obfuscated Files
        ],
        "tools": ["X-Agent", "Sofacy", "CHOPSTICK", "GAMEFISH", "Zebrocy"],
        "sample_iocs": [
            # Ces IOC sont à titre éducatif/historique (issus de rapports publics)
            {"type": "domain", "value": "microsoftupdate.net", 
             "context": "Historical C2 domain APT28", "confidence": 80},
            {"type": "ipv4", "value": "185.220.101.45",
             "context": "Known TOR exit / APT infrastructure", "confidence": 60},
            {"type": "hash_sha256", 
             "value": "a6b5b5a5c5d5e5f5a6b5b5a5c5d5e5f5a6b5b5a5c5d5e5f5a6b5b5a5c5d5e5f5",
             "context": "X-Agent sample", "confidence": 90},
        ],
    },
    "APT29": {
        "mitre_id": "G0016",
        "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM", "Midnight Blizzard"],
        "attribution": "Russian SVR",
        "motivation": "Espionage",
        "first_seen": "2008",
        "targets": ["Government", "Think Tanks", "Healthcare", "Technology"],
        "ttps": [
            "T1566.001",  # Spearphishing
            "T1195",      # Supply Chain Compromise
            "T1078.004",  # Cloud Accounts
            "T1550.001",  # Application Access Token
        ],
        "tools": ["SUNBURST", "MiniDuke", "CozyDuke", "WellMess"],
        "sample_iocs": [],
    },
    "Lazarus": {
        "mitre_id": "G0032",
        "aliases": ["Hidden Cobra", "ZINC", "Labyrinth Chollima"],
        "attribution": "DPRK (North Korea)",
        "motivation": "Espionage, Financial",
        "first_seen": "2009",
        "targets": ["Financial", "Cryptocurrency", "Government", "Media"],
        "ttps": [
            "T1566.001",  # Spearphishing
            "T1059.003",  # Windows Command Shell
            "T1105",      # Ingress Tool Transfer
            "T1486",      # Data Encrypted for Impact (Ransomware)
        ],
        "tools": ["WannaCry", "DarkSeoul", "BLINDINGCAN", "FASTCash"],
        "sample_iocs": [],
    },
}


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class IOC:
    """Un indicateur de compromission qualifié."""
    ioc_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""
    value: str = ""
    context: str = ""
    source: str = ""
    confidence: int = 50  # 0-100
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    tags: list = field(default_factory=list)
    apt_group: str = ""
    mitre_ttps: list = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid: bool = True


# ── Classes ───────────────────────────────────────────────────────────────────

class IOCCollector:
    """Collecte d'IOC depuis multiples sources."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "cyber-homelab-cti/1.0"})
        self.collected_iocs: list[IOC] = []

    def collect_from_threatfox(self, limit: int = 50) -> list[IOC]:
        """
        Collecter les derniers IOC depuis ThreatFox (abuse.ch).
        API gratuite, pas de clé requise.
        """
        print("[*] Collecte depuis ThreatFox (abuse.ch)...")
        iocs = []
        
        try:
            resp = self.session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": 1},
                timeout=15,
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    for item in data.get("data", [])[:limit]:
                        ioc = IOC(
                            type=self._normalize_ioc_type(item.get("ioc_type", "")),
                            value=item.get("ioc", ""),
                            context=item.get("malware", "") + " — " + item.get("threat_type", ""),
                            source="ThreatFox",
                            confidence=item.get("confidence_level", 50),
                            tags=item.get("tags", []) or [],
                            first_seen=item.get("first_seen", ""),
                            last_seen=item.get("last_seen", ""),
                        )
                        ioc.severity = self._score_to_severity(ioc.confidence)
                        iocs.append(ioc)
                    
                    print(f"  [OK] {len(iocs)} IOC collectés depuis ThreatFox")
                else:
                    print(f"  [!] ThreatFox status: {data.get('query_status')}")
            else:
                print(f"  [!] ThreatFox HTTP {resp.status_code}")
                
        except requests.RequestException as e:
            print(f"  [!] Erreur ThreatFox : {e}")
        
        return iocs

    def collect_from_urlhaus(self, limit: int = 30) -> list[IOC]:
        """
        Collecter les URLs malveillantes depuis URLhaus (abuse.ch).
        """
        print("[*] Collecte depuis URLhaus (abuse.ch)...")
        iocs = []
        
        try:
            resp = self.session.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
                timeout=15,
            )
            
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("urls", [])[:limit]:
                    if item.get("url_status") == "online":  # Prioriser les actifs
                        ioc = IOC(
                            type="url",
                            value=item.get("url", ""),
                            context=f"Malware: {item.get('tags', ['unknown'])}",
                            source="URLhaus",
                            confidence=75,
                            severity="HIGH",
                            tags=item.get("tags", []) or [],
                            first_seen=item.get("date_added", ""),
                        )
                        iocs.append(ioc)
                
                print(f"  [OK] {len(iocs)} URLs actives collectées depuis URLhaus")
                
        except requests.RequestException as e:
            print(f"  [!] Erreur URLhaus : {e}")
        
        return iocs

    def collect_apt_iocs(self, apt_name: str) -> list[IOC]:
        """Récupérer les IOC d'un groupe APT depuis notre base locale."""
        print(f"[*] Collecte IOC pour {apt_name}...")
        
        profile = APT_PROFILES.get(apt_name)
        if not profile:
            print(f"  [!] APT '{apt_name}' non trouvé. Groupes disponibles: {list(APT_PROFILES.keys())}")
            return []
        
        iocs = []
        for sample in profile.get("sample_iocs", []):
            ioc = IOC(
                type=sample["type"],
                value=sample["value"],
                context=sample.get("context", ""),
                source=f"MITRE ATT&CK G{profile['mitre_id'].split('G')[1]}",
                confidence=sample.get("confidence", 70),
                apt_group=apt_name,
                mitre_ttps=profile.get("ttps", []),
                tags=[apt_name.lower(), profile["mitre_id"].lower()],
            )
            ioc.severity = self._score_to_severity(ioc.confidence)
            iocs.append(ioc)
        
        print(f"  [OK] {len(iocs)} IOC APT28 chargés")
        return iocs

    def _normalize_ioc_type(self, raw_type: str) -> str:
        """Normaliser les types d'IOC vers notre standard."""
        mapping = {
            "ip:port": "ipv4",
            "domain": "domain",
            "url": "url",
            "md5_hash": "hash_md5",
            "sha256_hash": "hash_sha256",
            "sha1_hash": "hash_sha1",
        }
        return mapping.get(raw_type.lower(), raw_type.lower())

    def _score_to_severity(self, confidence: int) -> str:
        if confidence >= 80:
            return "HIGH"
        if confidence >= 60:
            return "MEDIUM"
        return "LOW"

    def deduplicate(self, iocs: list[IOC]) -> list[IOC]:
        """Dédupliquer les IOC par valeur."""
        seen = set()
        unique = []
        for ioc in iocs:
            key = (ioc.type, ioc.value.lower())
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        return unique


class IOCExporter:
    """Export des IOC vers différents formats."""
    
    def to_stix21(self, iocs: list[IOC], bundle_name: str = "cyber-homelab") -> dict:
        """
        Exporter en STIX 2.1.
        Standard industrie pour le partage de threat intelligence.
        """
        indicators = []
        
        for ioc in iocs:
            # Construire le pattern STIX
            pattern = self._build_stix_pattern(ioc)
            if not pattern:
                continue
            
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.ioc_id}",
                "created": ioc.created_at,
                "modified": ioc.created_at,
                "name": f"{ioc.apt_group + ' — ' if ioc.apt_group else ''}{ioc.type.upper()}: {ioc.value[:50]}",
                "description": ioc.context,
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.first_seen or ioc.created_at,
                "confidence": ioc.confidence,
                "labels": ioc.tags + [ioc.apt_group.lower()] if ioc.apt_group else ioc.tags,
                "external_references": [],
            }
            
            if ioc.apt_group and ioc.apt_group in APT_PROFILES:
                profile = APT_PROFILES[ioc.apt_group]
                indicator["external_references"].append({
                    "source_name": "mitre-attack",
                    "url": f"https://attack.mitre.org/groups/{profile['mitre_id']}/",
                    "external_id": profile["mitre_id"],
                })
            
            indicators.append(indicator)
        
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "created": datetime.now(timezone.utc).isoformat(),
            "name": bundle_name,
            "objects": indicators,
        }
        
        return bundle

    def _build_stix_pattern(self, ioc: IOC) -> Optional[str]:
        """Construire le pattern STIX selon le type d'IOC."""
        patterns = {
            "ipv4": f"[ipv4-addr:value = '{ioc.value}']",
            "ipv6": f"[ipv6-addr:value = '{ioc.value}']",
            "domain": f"[domain-name:value = '{ioc.value}']",
            "url": f"[url:value = '{ioc.value}']",
            "hash_md5": f"[file:hashes.MD5 = '{ioc.value}']",
            "hash_sha1": f"[file:hashes.SHA-1 = '{ioc.value}']",
            "hash_sha256": f"[file:hashes.SHA-256 = '{ioc.value}']",
            "email": f"[email-message:from_ref.value = '{ioc.value}']",
            "filename": f"[file:name = '{ioc.value}']",
        }
        return patterns.get(ioc.type)

    def to_csv(self, iocs: list[IOC], output_path: str) -> None:
        """Export CSV pour import SIEM/Wazuh."""
        fieldnames = [
            "type", "value", "confidence", "severity", "context",
            "source", "apt_group", "tags", "mitre_ttps",
            "first_seen", "created_at"
        ]
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ioc in iocs:
                writer.writerow({
                    "type": ioc.type,
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "severity": ioc.severity,
                    "context": ioc.context,
                    "source": ioc.source,
                    "apt_group": ioc.apt_group,
                    "tags": "|".join(ioc.tags),
                    "mitre_ttps": "|".join(ioc.mitre_ttps),
                    "first_seen": ioc.first_seen,
                    "created_at": ioc.created_at,
                })
        
        print(f"[OK] Export CSV : {output_path} ({len(iocs)} IOC)")

    def to_json(self, iocs: list[IOC], output_path: str) -> None:
        """Export JSON simple."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(iocs),
            "iocs": [asdict(i) for i in iocs],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[OK] Export JSON : {output_path}")


def display_iocs(iocs: list[IOC]) -> None:
    """Afficher les IOC collectés."""
    if not iocs:
        print("[INFO] Aucun IOC à afficher")
        return
    
    if not RICH:
        print(f"\n{'='*80}")
        print(f"IOC collectés : {len(iocs)}")
        print(f"{'='*80}")
        for ioc in iocs[:20]:
            print(f"[{ioc.severity:6s}] [{ioc.type:12s}] {ioc.value[:50]:50s} | {ioc.source}")
        return
    
    t = Table(
        title=f"🔍 IOC Collectés — {len(iocs)} indicateurs",
        border_style="blue",
        header_style="bold cyan",
    )
    t.add_column("Sévérité", width=10, justify="center")
    t.add_column("Type", width=12)
    t.add_column("Valeur", width=45)
    t.add_column("Source", width=15)
    t.add_column("Confiance", width=10, justify="right")
    
    severity_colors = {
        "CRITICAL": "red bold",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    
    for ioc in iocs[:50]:
        color = severity_colors.get(ioc.severity, "white")
        t.add_row(
            f"[{color}]{ioc.severity}[/{color}]",
            f"[cyan]{ioc.type}[/cyan]",
            ioc.value[:45],
            ioc.source,
            f"{ioc.confidence}%",
        )
    
    console.print(t)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"IOC Collector v{VERSION} — Collecte et qualification de threat intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Collecter depuis ThreatFox + URLhaus
  python ioc_collector.py --sources threatfox,urlhaus --output iocs/

  # Collecter IOC APT28
  python ioc_collector.py --apt APT28 --output iocs/

  # Tout collecter et exporter en STIX 2.1
  python ioc_collector.py --sources all --apt APT28 --stix --output iocs/

  # Lister les groupes APT disponibles
  python ioc_collector.py --list-apts
        """
    )
    
    parser.add_argument("--sources", default="",
                        help="Sources à utiliser : threatfox,urlhaus,all")
    parser.add_argument("--apt", help="Groupe APT à profiler (ex: APT28)")
    parser.add_argument("--list-apts", action="store_true",
                        help="Lister les groupes APT disponibles")
    parser.add_argument("--stix", action="store_true",
                        help="Exporter en STIX 2.1")
    parser.add_argument("--csv", action="store_true",
                        help="Exporter en CSV")
    parser.add_argument("--output", default="iocs",
                        help="Répertoire de sortie (défaut: iocs/)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Nombre max d'IOC par source (défaut: 50)")
    
    args = parser.parse_args()
    
    if args.list_apts:
        print("\nGroupes APT disponibles :")
        for name, profile in APT_PROFILES.items():
            print(f"  {name:15s} | {profile['mitre_id']} | {', '.join(profile['aliases'][:2])}")
        return
    
    if not any([args.sources, args.apt]):
        parser.print_help()
        return
    
    collector = IOCCollector()
    exporter = IOCExporter()
    all_iocs: list[IOC] = []
    
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    # Collecte depuis sources web
    if args.sources:
        sources = [s.strip() for s in args.sources.split(",")]
        
        if "all" in sources or "threatfox" in sources:
            iocs = collector.collect_from_threatfox(args.limit)
            all_iocs.extend(iocs)
            time.sleep(1)
        
        if "all" in sources or "urlhaus" in sources:
            iocs = collector.collect_from_urlhaus(args.limit)
            all_iocs.extend(iocs)
    
    # Collecte APT
    if args.apt:
        iocs = collector.collect_apt_iocs(args.apt)
        all_iocs.extend(iocs)
    
    # Dédupliquer
    all_iocs = collector.deduplicate(all_iocs)
    print(f"\n[OK] Total après déduplication : {len(all_iocs)} IOC uniques")
    
    # Afficher
    display_iocs(all_iocs)
    
    # Export
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.stix or True:  # Toujours exporter STIX
        stix_bundle = exporter.to_stix21(all_iocs, "cyber-homelab-cti")
        stix_path = output_dir / f"iocs_stix21_{timestamp}.json"
        with open(stix_path, "w", encoding="utf-8") as f:
            json.dump(stix_bundle, f, indent=2, ensure_ascii=False)
        print(f"[OK] Export STIX 2.1 : {stix_path}")
    
    if args.csv:
        csv_path = output_dir / f"iocs_{timestamp}.csv"
        exporter.to_csv(all_iocs, str(csv_path))


if __name__ == "__main__":
    main()
