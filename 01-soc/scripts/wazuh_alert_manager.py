#!/usr/bin/env python3
"""
wazuh_alert_manager.py
======================
Gestionnaire d'alertes Wazuh automatisé.

Fonctionnalités :
- Connexion à l'API REST Wazuh
- Filtrage par niveau d'alerte et MITRE technique
- Export CSV/JSON
- Mode watch (surveillance temps réel)
- Affichage riche en terminal (Rich)

Auteur : Joe Bichall (@joebat10)
Usage  : python wazuh_alert_manager.py --help
"""

import argparse
import csv
import json
import os
import time
from datetime import datetime, timedelta
from typing import Optional

import requests
import urllib3
from dotenv import load_dotenv

# Désactiver les warnings SSL (certificat auto-signé Wazuh)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Rich pour l'affichage terminal
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None
    print("[WARNING] 'rich' non installé. Affichage basique. → pip install rich")

# Charger les variables d'environnement (.env)
load_dotenv()

# ── Constantes ──────────────────────────────────────────────────────────────

VERSION = "1.0.0"
DEFAULT_HOST = os.getenv("WAZUH_HOST", "192.168.56.10")
DEFAULT_PORT = int(os.getenv("WAZUH_PORT", "55000"))
DEFAULT_USER = os.getenv("WAZUH_USER", "wazuh-wui")
DEFAULT_PASS = os.getenv("WAZUH_PASS", "MyS3cr37P450r.*-")

LEVEL_COLORS = {
    range(1, 7):   "green",
    range(7, 10):  "yellow",
    range(10, 13): "orange1",
    range(13, 16): "red bold",
}

MITRE_CATEGORIES = {
    "T1003": "Credential Access",
    "T1558": "Credential Access",
    "T1021": "Lateral Movement",
    "T1053": "Persistence",
    "T1078": "Defense Evasion",
    "T1055": "Defense Evasion",
    "T1547": "Persistence",
    "T1562": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1136": "Persistence",
}


# ── Classe principale ────────────────────────────────────────────────────────

class WazuhAlertManager:
    """Gestionnaire d'alertes Wazuh via API REST v2."""

    def __init__(self, host: str, port: int, user: str, password: str):
        self.base_url = f"https://{host}:{port}"
        self.user = user
        self.password = password
        self.token: Optional[str] = None
        self.session = requests.Session()
        self.session.verify = False  # Certificat auto-signé

    def authenticate(self) -> bool:
        """Obtenir un token JWT depuis l'API Wazuh."""
        try:
            resp = self.session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
                timeout=10,
            )
            resp.raise_for_status()
            self.token = resp.json()["data"]["token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            return True
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Impossible de se connecter à {self.base_url}")
            print("        Vérifier que la VM Wazuh est démarrée et accessible.")
            return False
        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] Authentification échouée : {e}")
            return False

    def get_alerts(
        self,
        limit: int = 100,
        level_min: int = 7,
        hours: int = 24,
        mitre_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> list[dict]:
        """
        Récupérer les alertes depuis l'API Wazuh.
        
        Paramètres :
            limit      : Nombre max d'alertes à retourner
            level_min  : Niveau minimum (1-15)
            hours      : Fenêtre temporelle en heures
            mitre_id   : Filtrer sur une technique MITRE (ex: T1003)
            agent_id   : Filtrer sur un agent spécifique
        """
        if not self.token:
            if not self.authenticate():
                return []

        # Construire les filtres
        params = {
            "limit": limit,
            "level": f"{level_min}-15",
            "sort": "-timestamp",
        }

        # Filtre temporel
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        params["q"] = f"timestamp>{since}"

        if agent_id:
            params["agents_list"] = agent_id

        try:
            resp = self.session.get(
                f"{self.base_url}/alerts",
                params=params,
                timeout=15,
            )
            resp.raise_for_status()
            alerts = resp.json().get("data", {}).get("affected_items", [])

            # Filtre MITRE post-requête (l'API ne supporte pas nativement)
            if mitre_id:
                alerts = [
                    a for a in alerts
                    if mitre_id.lower() in str(
                        a.get("rule", {}).get("mitre", {}).get("id", [])
                    ).lower()
                ]

            return alerts

        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] Récupération alertes : {e}")
            return []

    def get_alert_stats(self, hours: int = 24) -> dict:
        """Statistiques des alertes par niveau et catégorie MITRE."""
        alerts = self.get_alerts(limit=1000, level_min=1, hours=hours)
        
        stats = {
            "total": len(alerts),
            "by_level": {},
            "by_mitre": {},
            "by_agent": {},
            "critical": 0,  # niveau >= 13
            "high": 0,       # niveau 10-12
            "medium": 0,     # niveau 7-9
            "low": 0,        # niveau 1-6
        }
        
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            agent = alert.get("agent", {}).get("name", "unknown")
            mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
            
            # Comptage par niveau
            stats["by_level"][level] = stats["by_level"].get(level, 0) + 1
            if level >= 13:
                stats["critical"] += 1
            elif level >= 10:
                stats["high"] += 1
            elif level >= 7:
                stats["medium"] += 1
            else:
                stats["low"] += 1
            
            # Comptage par agent
            stats["by_agent"][agent] = stats["by_agent"].get(agent, 0) + 1
            
            # Comptage par MITRE
            for mid in mitre_ids:
                stats["by_mitre"][mid] = stats["by_mitre"].get(mid, 0) + 1
        
        return stats

    def export_to_csv(self, alerts: list[dict], output_path: str) -> None:
        """Exporter les alertes en CSV."""
        if not alerts:
            print("[INFO] Aucune alerte à exporter.")
            return

        fieldnames = [
            "timestamp", "agent_name", "agent_ip", "rule_id",
            "rule_description", "rule_level", "mitre_id", "mitre_technique",
            "src_ip", "dest_ip",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for alert in alerts:
                rule = alert.get("rule", {})
                agent = alert.get("agent", {})
                mitre = rule.get("mitre", {})
                data = alert.get("data", {})
                
                mitre_ids = mitre.get("id", [])
                mitre_id_str = "|".join(mitre_ids) if mitre_ids else ""
                mitre_techs = mitre.get("technique", [])
                mitre_tech_str = "|".join(mitre_techs) if mitre_techs else ""
                
                writer.writerow({
                    "timestamp": alert.get("timestamp", ""),
                    "agent_name": agent.get("name", ""),
                    "agent_ip": agent.get("ip", ""),
                    "rule_id": rule.get("id", ""),
                    "rule_description": rule.get("description", ""),
                    "rule_level": rule.get("level", ""),
                    "mitre_id": mitre_id_str,
                    "mitre_technique": mitre_tech_str,
                    "src_ip": data.get("srcip", ""),
                    "dest_ip": data.get("dstip", ""),
                })

        print(f"[OK] Export CSV : {output_path} ({len(alerts)} alertes)")

    def export_to_json(self, alerts: list[dict], output_path: str) -> None:
        """Exporter les alertes en JSON structuré."""
        export_data = {
            "export_timestamp": datetime.utcnow().isoformat(),
            "total_alerts": len(alerts),
            "alerts": alerts,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        print(f"[OK] Export JSON : {output_path}")

    def display_alerts_rich(self, alerts: list[dict]) -> None:
        """Afficher les alertes dans un tableau Rich coloré."""
        if not RICH_AVAILABLE:
            self._display_alerts_basic(alerts)
            return

        if not alerts:
            console.print("[yellow]Aucune alerte pour les critères sélectionnés.[/yellow]")
            return

        table = Table(
            title=f"🛡️  Alertes Wazuh — {len(alerts)} résultats",
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
        )
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("Agent", width=15)
        table.add_column("Niveau", justify="center", width=7)
        table.add_column("MITRE", width=10)
        table.add_column("Description", width=50)

        for alert in alerts:
            rule = alert.get("rule", {})
            level = rule.get("level", 0)
            mitre_ids = rule.get("mitre", {}).get("id", [])
            mitre_str = ", ".join(mitre_ids) if mitre_ids else "—"
            
            # Couleur selon le niveau
            if level >= 13:
                level_str = f"[red bold]{level}[/red bold]"
                row_style = "on dark_red" if level >= 15 else ""
            elif level >= 10:
                level_str = f"[orange1]{level}[/orange1]"
                row_style = ""
            elif level >= 7:
                level_str = f"[yellow]{level}[/yellow]"
                row_style = ""
            else:
                level_str = f"[green]{level}[/green]"
                row_style = ""

            timestamp = alert.get("timestamp", "")[:19].replace("T", " ")
            agent_name = alert.get("agent", {}).get("name", "unknown")
            description = rule.get("description", "")[:60]

            table.add_row(
                timestamp,
                agent_name,
                level_str,
                f"[cyan]{mitre_str}[/cyan]",
                description,
                style=row_style,
            )

        console.print(table)

    def _display_alerts_basic(self, alerts: list[dict]) -> None:
        """Affichage basique sans Rich."""
        print(f"\n{'='*80}")
        print(f"  Alertes Wazuh — {len(alerts)} résultats")
        print(f"{'='*80}")
        for alert in alerts:
            rule = alert.get("rule", {})
            ts = alert.get("timestamp", "")[:19]
            agent = alert.get("agent", {}).get("name", "unknown")
            level = rule.get("level", 0)
            desc = rule.get("description", "")[:70]
            print(f"[{ts}] {agent:15s} LVL:{level:2d} {desc}")

    def watch_mode(self, level_min: int = 10, poll_interval: int = 30) -> None:
        """
        Mode surveillance : polling des nouvelles alertes toutes les N secondes.
        Appuyer sur Ctrl+C pour arrêter.
        """
        print(f"\n🔍 Mode WATCH activé (niveau >= {level_min}, intervalle {poll_interval}s)")
        print("   Appuyer sur Ctrl+C pour arrêter.\n")
        
        seen_ids: set[str] = set()
        
        try:
            while True:
                alerts = self.get_alerts(
                    limit=50, level_min=level_min, hours=1
                )
                
                new_alerts = [
                    a for a in alerts
                    if a.get("id", "") not in seen_ids
                ]
                
                if new_alerts:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                          f"🚨 {len(new_alerts)} nouvelle(s) alerte(s) !")
                    self.display_alerts_rich(new_alerts)
                    for a in new_alerts:
                        seen_ids.add(a.get("id", ""))
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"✅ Aucune nouvelle alerte (niveau >= {level_min})", 
                          end="\r")
                
                time.sleep(poll_interval)
                
        except KeyboardInterrupt:
            print("\n\n[INFO] Mode watch arrêté.")


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wazuh Alert Manager — Gestion automatisée des alertes SIEM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Afficher les alertes HIGH/CRITICAL des dernières 24h
  python wazuh_alert_manager.py --level 10

  # Exporter en CSV
  python wazuh_alert_manager.py --export --output alerts.csv --hours 48

  # Mode surveillance temps réel
  python wazuh_alert_manager.py --watch --level 12

  # Filtrer par technique MITRE
  python wazuh_alert_manager.py --mitre T1003

  # Statistiques
  python wazuh_alert_manager.py --stats
        """,
    )
    
    # Connexion
    conn = parser.add_argument_group("Connexion Wazuh")
    conn.add_argument("--host", default=DEFAULT_HOST,
                      help=f"IP Wazuh Manager (défaut: {DEFAULT_HOST})")
    conn.add_argument("--port", type=int, default=DEFAULT_PORT,
                      help=f"Port API (défaut: {DEFAULT_PORT})")
    conn.add_argument("--user", default=DEFAULT_USER)
    conn.add_argument("--password", default=DEFAULT_PASS)

    # Filtres
    filt = parser.add_argument_group("Filtres")
    filt.add_argument("--level", type=int, default=7,
                      help="Niveau minimum d'alerte (1-15, défaut: 7)")
    filt.add_argument("--hours", type=int, default=24,
                      help="Fenêtre temporelle en heures (défaut: 24)")
    filt.add_argument("--limit", type=int, default=100,
                      help="Nombre max d'alertes (défaut: 100)")
    filt.add_argument("--mitre", help="Filtrer par technique MITRE (ex: T1003)")
    filt.add_argument("--agent", help="Filtrer par ID agent")

    # Actions
    act = parser.add_argument_group("Actions")
    act.add_argument("--export", action="store_true",
                     help="Exporter les alertes")
    act.add_argument("--output", default="alerts_export.csv",
                     help="Fichier de sortie (défaut: alerts_export.csv)")
    act.add_argument("--format", choices=["csv", "json", "rich"], default="rich",
                     help="Format de sortie (défaut: rich)")
    act.add_argument("--watch", action="store_true",
                     help="Mode surveillance temps réel")
    act.add_argument("--stats", action="store_true",
                     help="Afficher les statistiques")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if RICH_AVAILABLE:
        console.print(Panel.fit(
            f"[bold cyan]🛡️  Wazuh Alert Manager v{VERSION}[/bold cyan]\n"
            f"[dim]Host: {args.host}:{args.port}[/dim]",
            border_style="cyan",
        ))
    else:
        print(f"\n=== Wazuh Alert Manager v{VERSION} ===")
        print(f"Host: {args.host}:{args.port}\n")

    # Initialiser le manager
    manager = WazuhAlertManager(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
    )

    # Mode watch
    if args.watch:
        manager.watch_mode(level_min=args.level)
        return

    # Statistiques
    if args.stats:
        print("\n📊 Calcul des statistiques...")
        stats = manager.get_alert_stats(hours=args.hours)
        
        if RICH_AVAILABLE:
            t = Table(title=f"Statistiques — {args.hours}h", 
                     border_style="blue", header_style="bold cyan")
            t.add_column("Catégorie")
            t.add_column("Valeur", justify="right")
            t.add_row("Total alertes", str(stats["total"]))
            t.add_row("[red]CRITICAL (13-15)[/red]", str(stats["critical"]))
            t.add_row("[orange1]HIGH (10-12)[/orange1]", str(stats["high"]))
            t.add_row("[yellow]MEDIUM (7-9)[/yellow]", str(stats["medium"]))
            t.add_row("[green]LOW (1-6)[/green]", str(stats["low"]))
            console.print(t)
            
            # Top MITRE
            if stats["by_mitre"]:
                t2 = Table(title="Top Techniques MITRE", 
                          border_style="blue", header_style="bold cyan")
                t2.add_column("Technique")
                t2.add_column("Occurrences", justify="right")
                for tid, count in sorted(
                    stats["by_mitre"].items(), key=lambda x: -x[1]
                )[:10]:
                    category = MITRE_CATEGORIES.get(tid[:5], "Unknown")
                    t2.add_row(
                        f"[cyan]{tid}[/cyan] ({category})",
                        str(count)
                    )
                console.print(t2)
        else:
            print(f"Total: {stats['total']}")
            print(f"Critical: {stats['critical']}")
            print(f"High: {stats['high']}")
            print(f"Medium: {stats['medium']}")
        return

    # Récupérer les alertes
    print(f"\n🔍 Récupération des alertes (niveau >= {args.level}, "
          f"fenêtre: {args.hours}h)...")
    
    alerts = manager.get_alerts(
        limit=args.limit,
        level_min=args.level,
        hours=args.hours,
        mitre_id=args.mitre,
        agent_id=args.agent,
    )

    if not alerts:
        print("[INFO] Aucune alerte trouvée avec ces critères.")
        return

    # Affichage ou export
    if args.export:
        if args.format == "json" or args.output.endswith(".json"):
            manager.export_to_json(alerts, args.output)
        else:
            manager.export_to_csv(alerts, args.output)
    else:
        manager.display_alerts_rich(alerts)


if __name__ == "__main__":
    main()
