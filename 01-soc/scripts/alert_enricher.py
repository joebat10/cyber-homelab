#!/usr/bin/env python3
"""
alert_enricher.py
=================
Enrichissement automatique des IOC depuis les alertes Wazuh.

Sources d'enrichissement :
- VirusTotal API v3 (détections AV, réputation)
- Shodan (bannières, ports ouverts)
- AbuseIPDB (score de réputation IP)
- ip-api.com (géolocalisation, gratuit sans clé)

Auteur : Joe Bichall (@joebat10)
Usage  : python alert_enricher.py --ip 185.220.101.45
"""

import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# Clés API (depuis .env)
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Taux de requêtes VirusTotal (API publique : 4 req/min)
VT_RATE_LIMIT_DELAY = 16  # secondes entre requêtes VT

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    console = None


@dataclass
class IOCReport:
    """Rapport d'enrichissement d'un IOC."""
    ioc_value: str
    ioc_type: str  # ip, domain, hash_md5, hash_sha256
    timestamp: str

    # Géolocalisation
    country: str = ""
    city: str = ""
    asn: str = ""
    org: str = ""
    is_tor: bool = False

    # VirusTotal
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total_engines: int = 0
    vt_last_analysis: str = ""
    vt_categories: list = None
    vt_url: str = ""

    # AbuseIPDB
    abuse_score: int = 0
    abuse_total_reports: int = 0
    abuse_is_tor: bool = False

    # Shodan
    shodan_ports: list = None
    shodan_hostnames: list = None
    shodan_os: str = ""
    shodan_tags: list = None

    # Verdict final
    verdict: str = "UNKNOWN"  # CLEAN, SUSPICIOUS, MALICIOUS
    confidence: int = 0  # 0-100

    def __post_init__(self):
        if self.vt_categories is None:
            self.vt_categories = []
        if self.shodan_ports is None:
            self.shodan_ports = []
        if self.shodan_hostnames is None:
            self.shodan_hostnames = []
        if self.shodan_tags is None:
            self.shodan_tags = []


class IOCEnricher:
    """Enrichissement multi-sources d'IOC."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "cyber-homelab/1.0"})

    def enrich_ip(self, ip: str) -> IOCReport:
        """Enrichissement complet d'une adresse IP."""
        report = IOCReport(
            ioc_value=ip,
            ioc_type="ip",
            timestamp=datetime.utcnow().isoformat(),
        )

        print(f"\n[*] Enrichissement de {ip}...")

        # 1. Géolocalisation (gratuit, sans clé)
        self._enrich_geoip(report)

        # 2. VirusTotal
        if VT_API_KEY:
            self._enrich_virustotal_ip(report)
        else:
            print("  [!] VirusTotal : clé API manquante (VIRUSTOTAL_API_KEY)")

        # 3. AbuseIPDB
        if ABUSEIPDB_API_KEY:
            self._enrich_abuseipdb(report)
        else:
            print("  [!] AbuseIPDB : clé API manquante (ABUSEIPDB_API_KEY)")

        # 4. Shodan
        if SHODAN_API_KEY:
            self._enrich_shodan(report)
        else:
            print("  [!] Shodan : clé API manquante (SHODAN_API_KEY)")

        # Calculer le verdict
        self._calculate_verdict(report)

        return report

    def enrich_hash(self, file_hash: str) -> IOCReport:
        """Enrichissement d'un hash de fichier via VirusTotal."""
        report = IOCReport(
            ioc_value=file_hash,
            ioc_type="hash_sha256" if len(file_hash) == 64 else "hash_md5",
            timestamp=datetime.utcnow().isoformat(),
        )

        if not VT_API_KEY:
            print("  [!] VirusTotal requis pour l'analyse de hash")
            return report

        print(f"\n[*] Analyse hash {file_hash[:16]}... via VirusTotal")

        try:
            resp = self.session.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VT_API_KEY},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                report.vt_malicious = stats.get("malicious", 0)
                report.vt_suspicious = stats.get("suspicious", 0)
                report.vt_total_engines = sum(stats.values())
                report.vt_last_analysis = attrs.get("last_analysis_date", "")
                report.vt_url = f"https://www.virustotal.com/gui/file/{file_hash}"

                print(f"  [VT] Détections : {report.vt_malicious}/{report.vt_total_engines}")
            elif resp.status_code == 404:
                print("  [VT] Hash inconnu dans VirusTotal")
            elif resp.status_code == 429:
                print("  [VT] Rate limit atteint")

        except requests.RequestException as e:
            print(f"  [!] Erreur VirusTotal : {e}")

        self._calculate_verdict(report)
        return report

    def _enrich_geoip(self, report: IOCReport) -> None:
        """Géolocalisation via ip-api.com (gratuit, 45 req/min)."""
        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{report.ioc_value}"
                f"?fields=country,city,as,org,proxy",
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                report.country = data.get("country", "")
                report.city = data.get("city", "")
                report.asn = data.get("as", "")
                report.org = data.get("org", "")
                report.is_tor = data.get("proxy", False)
                print(f"  [GEO] {report.city}, {report.country} — {report.asn}")
        except requests.RequestException as e:
            print(f"  [!] Erreur GeoIP : {e}")

    def _enrich_virustotal_ip(self, report: IOCReport) -> None:
        """Interroger VirusTotal pour une IP."""
        try:
            resp = self.session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{report.ioc_value}",
                headers={"x-apikey": VT_API_KEY},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                report.vt_malicious = stats.get("malicious", 0)
                report.vt_suspicious = stats.get("suspicious", 0)
                report.vt_total_engines = sum(stats.values())
                report.vt_url = (
                    f"https://www.virustotal.com/gui/ip-address/{report.ioc_value}"
                )

                # Catégories (spam, malware, phishing...)
                categories = attrs.get("categories", {})
                report.vt_categories = list(set(categories.values()))

                print(f"  [VT] Malicious: {report.vt_malicious} | "
                      f"Suspicious: {report.vt_suspicious} | "
                      f"Total: {report.vt_total_engines}")

            elif resp.status_code == 429:
                print(f"  [VT] Rate limit — attente {VT_RATE_LIMIT_DELAY}s...")
                time.sleep(VT_RATE_LIMIT_DELAY)

        except requests.RequestException as e:
            print(f"  [!] Erreur VirusTotal : {e}")

    def _enrich_abuseipdb(self, report: IOCReport) -> None:
        """Interroger AbuseIPDB pour le score de réputation."""
        try:
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": report.ioc_value, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                report.abuse_score = data.get("abuseConfidenceScore", 0)
                report.abuse_total_reports = data.get("totalReports", 0)
                report.abuse_is_tor = data.get("isTor", False)
                print(f"  [AbuseIPDB] Score: {report.abuse_score}% | "
                      f"Reports: {report.abuse_total_reports}")

        except requests.RequestException as e:
            print(f"  [!] Erreur AbuseIPDB : {e}")

    def _enrich_shodan(self, report: IOCReport) -> None:
        """Interroger Shodan (nécessite une clé API)."""
        try:
            resp = self.session.get(
                f"https://api.shodan.io/shodan/host/{report.ioc_value}",
                params={"key": SHODAN_API_KEY},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                report.shodan_ports = data.get("ports", [])
                report.shodan_hostnames = data.get("hostnames", [])
                report.shodan_os = data.get("os", "") or ""
                report.shodan_tags = data.get("tags", [])
                print(f"  [Shodan] Ports: {report.shodan_ports[:10]} | "
                      f"OS: {report.shodan_os or 'unknown'}")
            elif resp.status_code == 404:
                print("  [Shodan] IP non indexée")

        except requests.RequestException as e:
            print(f"  [!] Erreur Shodan : {e}")

    def _calculate_verdict(self, report: IOCReport) -> None:
        """Calculer un verdict basé sur les sources disponibles."""
        score = 0
        factors = []

        # VirusTotal
        if report.vt_malicious >= 10:
            score += 60
            factors.append(f"VT:{report.vt_malicious} moteurs")
        elif report.vt_malicious >= 3:
            score += 40
        elif report.vt_malicious >= 1:
            score += 20
        if report.vt_suspicious >= 5:
            score += 15

        # AbuseIPDB
        if report.abuse_score >= 80:
            score += 40
            factors.append(f"AbuseIPDB:{report.abuse_score}%")
        elif report.abuse_score >= 50:
            score += 25
        elif report.abuse_score >= 20:
            score += 10

        # TOR / Proxy
        if report.is_tor or report.abuse_is_tor:
            score += 15
            factors.append("TOR/Proxy")

        # VT Categories malveillantes
        bad_cats = {"malware", "phishing", "spam", "botnet", "ransomware"}
        if any(c.lower() in bad_cats for c in report.vt_categories):
            score += 20

        # Normaliser le score
        report.confidence = min(score, 100)

        if report.confidence >= 70:
            report.verdict = "MALICIOUS"
        elif report.confidence >= 30:
            report.verdict = "SUSPICIOUS"
        else:
            report.verdict = "CLEAN"

    def display_report(self, report: IOCReport) -> None:
        """Afficher le rapport d'enrichissement."""
        if not RICH:
            self._display_report_basic(report)
            return

        verdict_color = {
            "MALICIOUS": "red bold",
            "SUSPICIOUS": "yellow",
            "CLEAN": "green",
        }.get(report.verdict, "white")

        console.print(Panel.fit(
            f"[bold]IOC : [cyan]{report.ioc_value}[/cyan][/bold]\n"
            f"Type : {report.ioc_type} | "
            f"Verdict : [{verdict_color}]{report.verdict}[/{verdict_color}] "
            f"(confiance: {report.confidence}%)\n"
            f"📍 {report.city}, {report.country} — {report.asn}",
            title="🔍 Rapport d'enrichissement IOC",
            border_style=verdict_color.split()[0],
        ))

        t = Table(border_style="blue", show_header=True,
                  header_style="bold cyan")
        t.add_column("Source")
        t.add_column("Résultat")

        if report.vt_total_engines:
            vt_str = (f"[red]{report.vt_malicious} malicious[/red] | "
                      f"[yellow]{report.vt_suspicious} suspicious[/yellow] "
                      f"/ {report.vt_total_engines}")
            t.add_row("VirusTotal", vt_str)

        if report.abuse_score is not None:
            color = "red" if report.abuse_score >= 80 else (
                "yellow" if report.abuse_score >= 30 else "green"
            )
            t.add_row("AbuseIPDB",
                      f"[{color}]Score: {report.abuse_score}%[/{color}] "
                      f"({report.abuse_total_reports} reports)")

        if report.shodan_ports:
            t.add_row("Shodan",
                      f"Ports: {report.shodan_ports[:8]} | "
                      f"OS: {report.shodan_os or 'unknown'}")

        if report.vt_url:
            t.add_row("Lien VT", f"[link={report.vt_url}]{report.vt_url}[/link]")

        console.print(t)

    def _display_report_basic(self, report: IOCReport) -> None:
        print(f"\n{'='*60}")
        print(f"IOC: {report.ioc_value}")
        print(f"Verdict: {report.verdict} ({report.confidence}%)")
        print(f"Localisation: {report.city}, {report.country}")
        print(f"VT Malicious: {report.vt_malicious}/{report.vt_total_engines}")
        print(f"AbuseIPDB: {report.abuse_score}%")
        print(f"{'='*60}")

    def save_report(self, report: IOCReport, output_dir: str = "reports") -> str:
        """Sauvegarder le rapport en JSON."""
        Path(output_dir).mkdir(exist_ok=True)
        safe_ioc = report.ioc_value.replace("/", "_").replace(":", "_")
        filename = f"{output_dir}/ioc_{safe_ioc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        
        print(f"\n[OK] Rapport sauvegardé : {filename}")
        return filename


def main() -> None:
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enrichissement IOC — VirusTotal + Shodan + AbuseIPDB"
    )
    parser.add_argument("--ip", help="Adresse IP à enrichir")
    parser.add_argument("--hash", help="Hash MD5/SHA256 à analyser")
    parser.add_argument("--file", help="Fichier CSV d'alertes Wazuh à enrichir")
    parser.add_argument("--output", default=".", help="Répertoire de sortie")
    parser.add_argument("--no-save", action="store_true",
                        help="Ne pas sauvegarder le rapport")
    args = parser.parse_args()

    if not any([args.ip, args.hash, args.file]):
        parser.print_help()
        sys.exit(1)

    enricher = IOCEnricher()

    if args.ip:
        report = enricher.enrich_ip(args.ip)
        enricher.display_report(report)
        if not args.no_save:
            enricher.save_report(report, args.output)

    if args.hash:
        report = enricher.enrich_hash(args.hash)
        enricher.display_report(report)
        if not args.no_save:
            enricher.save_report(report, args.output)

    if args.file:
        import csv
        with open(args.file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            ips_seen = set()
            for row in reader:
                ip = row.get("src_ip", "").strip()
                if ip and ip not in ips_seen and ip not in ("", "0.0.0.0"):
                    ips_seen.add(ip)
                    report = enricher.enrich_ip(ip)
                    enricher.display_report(report)
                    if not args.no_save:
                        enricher.save_report(report, args.output)
                    time.sleep(1)  # Respecter les rate limits


if __name__ == "__main__":
    main()
