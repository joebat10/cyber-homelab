#!/usr/bin/env python3
"""
soc_dashboard_exporter.py — Génère un rapport HTML/JSON du dashboard SOC Wazuh
Auteur : Joe Bichall (@joebat10)
Usage  : python soc_dashboard_exporter.py --format html --output rapport_soc.html
"""

import os
import json
import argparse
import requests
import urllib3
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ──────────────────────────────────────────────────────────────────
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://127.0.0.1")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASS = os.getenv("WAZUH_PASSWORD", "wazuh")
BASE_URL    = f"{WAZUH_HOST}:{WAZUH_PORT}"

# Mapping niveau → priorité
LEVEL_LABELS = {
    range(1, 4):  ("low",      "#6c757d"),
    range(4, 8):  ("medium",   "#ffc107"),
    range(8, 12): ("high",     "#fd7e14"),
    range(12, 16):("critical", "#dc3545"),
}

def get_level_info(level: int) -> tuple:
    for r, info in LEVEL_LABELS.items():
        if level in r:
            return info
    return ("unknown", "#adb5bd")


class WazuhDashboardExporter:
    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.session.verify = False

    def authenticate(self) -> bool:
        """Obtient un token JWT depuis l'API Wazuh."""
        try:
            resp = self.session.post(
                f"{BASE_URL}/security/user/authenticate",
                auth=(WAZUH_USER, WAZUH_PASS),
                timeout=10
            )
            resp.raise_for_status()
            self.token = resp.json()["data"]["token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            return True
        except Exception as e:
            print(f"[!] Authentification Wazuh échouée : {e}")
            return False

    def _get(self, endpoint: str, params: dict = None) -> dict:
        try:
            resp = self.session.get(f"{BASE_URL}{endpoint}", params=params, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[!] Erreur GET {endpoint} : {e}")
            return {}

    def get_agents_summary(self) -> dict:
        data = self._get("/agents/summary/status")
        return data.get("data", {})

    def get_alerts_last_24h(self) -> list:
        """Retourne les alertes des dernières 24h (ou données mock si démo)."""
        # En production : récupérer depuis l'API Wazuh/OpenSearch
        # Ici on retourne des données réalistes pour la démo
        now = datetime.now()
        alerts = []
        samples = [
            (15, "T1003.001", "LSASS Memory Access détecté", "WS-FINANCE-01"),
            (14, "T1550.002", "Pass-the-Hash depuis 192.168.1.45", "DC-PROD-01"),
            (13, "T1558.003", "Kerberoasting — RC4 encryption demandée", "WS-COMPTA-03"),
            (12, "T1218.011", "rundll32 avec argument javascript:", "WS-RH-02"),
            (11, "T1059.001", "PowerShell download cradle (IEX+DownloadString)", "WS-DEV-04"),
            (10, "T1021.002", "Connexion share ADMIN$ distant", "WS-FINANCE-01"),
            (10, "T1053.005", "Tâche planifiée créée par SYSTEM", "WS-MGMT-01"),
            (9,  "T1078.002", "Authentification admin hors horaires", "DC-PROD-01"),
            (8,  "T1547.001", "Clé Run registry modifiée", "WS-USER-07"),
            (7,  "T1562.001", "Windows Defender désactivé", "WS-FINANCE-01"),
            (6,  "T1136.002", "Nouveau compte domaine créé", "DC-PROD-01"),
            (5,  "T1021.006", "WinRM connexion depuis 192.168.1.100", "WS-DEV-04"),
            (14, "T1055",     "Process injection (CreateRemoteThread)", "WS-COMPTA-03"),
            (13, "T1197",     "bitsadmin download depuis URL externe", "WS-RH-02"),
            (12, "T1047",     "wmic /node: exécution distante", "WS-FINANCE-01"),
        ]
        for i, (lvl, mitre, desc, agent) in enumerate(samples):
            delta = timedelta(minutes=i * 97 + 5)
            alerts.append({
                "timestamp": (now - delta).strftime("%Y-%m-%dT%H:%M:%S"),
                "level": lvl,
                "rule_mitre_id": mitre,
                "rule_description": desc,
                "agent_name": agent,
                "rule_id": 100001 + i * 10,
            })
        return sorted(alerts, key=lambda x: x["timestamp"], reverse=True)

    def get_stats(self, alerts: list) -> dict:
        stats = {
            "total": len(alerts),
            "critical": sum(1 for a in alerts if a["level"] >= 12),
            "high":     sum(1 for a in alerts if 8 <= a["level"] < 12),
            "medium":   sum(1 for a in alerts if 4 <= a["level"] < 8),
            "low":      sum(1 for a in alerts if a["level"] < 4),
            "top_agents": {},
            "top_mitre": {},
        }
        for a in alerts:
            stats["top_agents"][a["agent_name"]] = stats["top_agents"].get(a["agent_name"], 0) + 1
            stats["top_mitre"][a["rule_mitre_id"]] = stats["top_mitre"].get(a["rule_mitre_id"], 0) + 1
        stats["top_agents"] = sorted(stats["top_agents"].items(), key=lambda x: -x[1])[:5]
        stats["top_mitre"]  = sorted(stats["top_mitre"].items(), key=lambda x: -x[1])[:10]
        return stats

    # ─── HTML EXPORT ──────────────────────────────────────────────────────────
    def export_html(self, alerts: list, stats: dict, output_path: str):
        generated_at = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

        def severity_badge(level):
            label, color = get_level_info(level)
            return f'<span class="badge" style="background:{color}">{label.upper()} ({level})</span>'

        alerts_rows = ""
        for a in alerts:
            alerts_rows += f"""
            <tr>
              <td style="font-size:0.85em;color:#888">{a['timestamp']}</td>
              <td>{severity_badge(a['level'])}</td>
              <td><code>{a['rule_mitre_id']}</code></td>
              <td>{a['rule_description']}</td>
              <td><strong>{a['agent_name']}</strong></td>
              <td style="color:#888;font-size:0.85em">{a['rule_id']}</td>
            </tr>"""

        mitre_rows = ""
        for tid, count in stats["top_mitre"]:
            mitre_rows += f'<tr><td><a href="https://attack.mitre.org/techniques/{tid.replace(".","/")}" target="_blank">{tid}</a></td><td>{count}</td></tr>'

        agent_rows = ""
        for agent, count in stats["top_agents"]:
            agent_rows += f"<tr><td>{agent}</td><td>{count}</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>SOC Dashboard — Cyber Homelab</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }}
    header {{ background: linear-gradient(135deg, #1f6feb, #388bfd); padding: 24px 32px; }}
    header h1 {{ font-size: 1.6em; color: #fff; }}
    header p  {{ color: rgba(255,255,255,0.75); font-size: 0.9em; margin-top: 4px; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    .cards {{ display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }}
    .card {{ flex: 1; min-width: 140px; background: #161b22; border: 1px solid #30363d;
             border-radius: 8px; padding: 20px; text-align: center; }}
    .card .num {{ font-size: 2.4em; font-weight: 700; }}
    .card .lbl {{ font-size: 0.85em; color: #8b949e; margin-top: 4px; }}
    .card.critical .num {{ color: #dc3545; }}
    .card.high     .num {{ color: #fd7e14; }}
    .card.medium   .num {{ color: #ffc107; }}
    .card.low      .num {{ color: #6c757d; }}
    .card.total    .num {{ color: #388bfd; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }}
    .panel {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }}
    .panel h3 {{ font-size: 1em; color: #8b949e; margin-bottom: 14px; text-transform: uppercase; letter-spacing: 0.05em; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
    th {{ text-align: left; padding: 8px 10px; color: #8b949e; border-bottom: 1px solid #30363d; font-size: 0.8em; text-transform: uppercase; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; }}
    tr:last-child td {{ border: none; }}
    tr:hover {{ background: #1c2128; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; color: #fff; }}
    .section-title {{ font-size: 1.1em; color: #c9d1d9; margin-bottom: 16px; padding-bottom: 8px;
                      border-bottom: 1px solid #30363d; }}
    code {{ background: #21262d; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; color: #79c0ff; }}
    a {{ color: #58a6ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    footer {{ text-align: center; padding: 24px; color: #484f58; font-size: 0.8em; border-top: 1px solid #21262d; margin-top: 32px; }}
  </style>
</head>
<body>
  <header>
    <h1>🛡️ SOC Dashboard — Cyber Homelab</h1>
    <p>Rapport généré le {generated_at} · Fenêtre : dernières 24 heures · joebat10/cyber-homelab</p>
  </header>
  <div class="container">

    <div class="cards">
      <div class="card total">   <div class="num">{stats['total']}</div>    <div class="lbl">Total alertes</div></div>
      <div class="card critical"><div class="num">{stats['critical']}</div> <div class="lbl">🔴 Critiques (≥12)</div></div>
      <div class="card high">    <div class="num">{stats['high']}</div>     <div class="lbl">🟠 Hautes (8-11)</div></div>
      <div class="card medium">  <div class="num">{stats['medium']}</div>   <div class="lbl">🟡 Moyennes (4-7)</div></div>
      <div class="card low">     <div class="num">{stats['low']}</div>      <div class="lbl">⚫ Basses (1-3)</div></div>
    </div>

    <div class="grid">
      <div class="panel">
        <h3>🎯 Top Techniques MITRE ATT&CK</h3>
        <table>
          <tr><th>Technique</th><th>Occurrences</th></tr>
          {mitre_rows}
        </table>
      </div>
      <div class="panel">
        <h3>💻 Agents les plus alertés</h3>
        <table>
          <tr><th>Agent / Hostname</th><th>Alertes</th></tr>
          {agent_rows}
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="section-title">📋 Journal des alertes (24h)</div>
      <table>
        <tr>
          <th>Timestamp</th>
          <th>Sévérité</th>
          <th>MITRE</th>
          <th>Description</th>
          <th>Agent</th>
          <th>Rule ID</th>
        </tr>
        {alerts_rows}
      </table>
    </div>

  </div>
  <footer>
    Cyber Homelab · Joe Bichall (@joebat10) · <a href="https://github.com/joebat10/cyber-homelab">github.com/joebat10/cyber-homelab</a>
  </footer>
</body>
</html>"""

        Path(output_path).write_text(html, encoding="utf-8")
        print(f"[✓] Dashboard HTML exporté → {output_path}")

    def export_json(self, alerts: list, stats: dict, output_path: str):
        payload = {
            "generated_at": datetime.now().isoformat(),
            "window": "24h",
            "stats": stats,
            "alerts": alerts,
        }
        Path(output_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[✓] Dashboard JSON exporté → {output_path}")


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Exporte un dashboard SOC depuis Wazuh (HTML ou JSON)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python soc_dashboard_exporter.py --format html
  python soc_dashboard_exporter.py --format json --output /tmp/soc_report.json
  python soc_dashboard_exporter.py --demo         # Données de démonstration
"""
    )
    parser.add_argument("--format",  choices=["html", "json", "both"], default="html")
    parser.add_argument("--output",  default=None, help="Chemin de sortie (défaut : auto)")
    parser.add_argument("--demo",    action="store_true", help="Mode démo (sans Wazuh)")
    args = parser.parse_args()

    exporter = WazuhDashboardExporter()

    if not args.demo:
        if not exporter.authenticate():
            print("[!] Passage en mode démo automatiquement.")

    alerts = exporter.get_alerts_last_24h()
    stats  = exporter.get_stats(alerts)

    ts = datetime.now().strftime("%Y%m%d_%H%M")

    if args.format in ("html", "both"):
        out = args.output or f"soc_dashboard_{ts}.html"
        exporter.export_html(alerts, stats, out)

    if args.format in ("json", "both"):
        out = args.output or f"soc_dashboard_{ts}.json"
        exporter.export_json(alerts, stats, out)

    print(f"\n[i] Résumé : {stats['total']} alertes · "
          f"{stats['critical']} critiques · {stats['high']} hautes")


if __name__ == "__main__":
    main()
