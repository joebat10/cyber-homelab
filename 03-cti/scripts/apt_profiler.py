#!/usr/bin/env python3
"""
apt_profiler.py — Génère des profils structurés de groupes APT
Auteur  : Joe Bichall (@joebat10)
Usage   : python apt_profiler.py --group APT28
          python apt_profiler.py --list
          python apt_profiler.py --group APT28 --format html

Sources : MITRE ATT&CK, CISA Advisories, Mandiant/Google Threat Intelligence
          Références publiques uniquement — données défensives.
"""

import json
import argparse
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict

# ─── DONNÉES APT (SOURCES PUBLIQUES MITRE ATT&CK + CISA) ─────────────────────

APT_DATABASE = {

    "APT28": {
        "name"          : "APT28",
        "aliases"       : ["Fancy Bear", "Sofacy", "STRONTIUM", "Pawn Storm", "Sednit", "Iron Twilight"],
        "origin"        : "Russie",
        "sponsor"       : "GRU (Direction du renseignement militaire russe), Unités 26165 et 74455",
        "active_since"  : "2004",
        "targets"       : ["Gouvernements OTAN", "Organisations militaires", "Médias", "Secteur aérospatial",
                           "Campagnes électorales", "Organisations sportives", "Secteur énergie"],
        "motivation"    : "Espionnage politique et militaire, influence géopolitique",
        "mitre_group_id": "G0007",
        "mitre_url"     : "https://attack.mitre.org/groups/G0007/",
        "cisa_advisories": [
            "AA20-296A — Russian State-Sponsored Cyber Actors",
            "AA22-011A — Understanding and Mitigating Russian State-Sponsored Cyber Threats",
        ],
        "techniques": [
            # [Tactique, ID, Nom, Description courte]
            ["Initial Access",      "T1566.001", "Spearphishing Attachment",    "Pièces jointes malveillantes ciblées (Word, PDF)"],
            ["Initial Access",      "T1566.002", "Spearphishing Link",          "Liens vers pages de credential harvesting"],
            ["Initial Access",      "T1190",     "Exploit Public App",          "Exploitation de Cisco, Exchange, Outlook (CVE-2023-23397)"],
            ["Execution",           "T1059.001", "PowerShell",                  "PowerShell obfusqué pour download et exécution"],
            ["Execution",           "T1059.006", "Python",                      "Scripts Python pour collecte et exfiltration"],
            ["Persistence",         "T1547.001", "Registry Run Keys",           "Persistence via clés Run dans HKCU/HKLM"],
            ["Persistence",         "T1053.005", "Scheduled Task",              "Tâches planifiées pour maintien de l'accès"],
            ["Persistence",         "T1543.003", "Windows Service",             "Services Windows pour persistance"],
            ["Defense Evasion",     "T1036",     "Masquerading",                "Binaires se faisant passer pour processus légitimes"],
            ["Defense Evasion",     "T1027",     "Obfuscated Files",            "Encodage Base64, XOR, RC4 des payloads"],
            ["Defense Evasion",     "T1140",     "Deobfuscate/Decode",          "certutil pour décoder les payloads"],
            ["Credential Access",   "T1003.001", "LSASS Memory",               "Dump LSASS pour récupérer credentials"],
            ["Credential Access",   "T1003.006", "DCSync",                      "Réplication AD pour extraire hashes"],
            ["Credential Access",   "T1528",     "Steal App Token",             "Vol de tokens OAuth pour accès webmail"],
            ["Discovery",           "T1082",     "System Info Discovery",       "Collecte d'info système (whoami, ipconfig)"],
            ["Discovery",           "T1018",     "Remote System Discovery",     "Énumération Active Directory"],
            ["Lateral Movement",    "T1021.001", "RDP",                         "Lateral movement via Remote Desktop"],
            ["Lateral Movement",    "T1021.002", "SMB/Admin Shares",            "Accès aux partages administratifs"],
            ["Collection",          "T1114.002", "Remote Email Collection",     "Accès Exchange/OWA, exfiltration emails"],
            ["Collection",          "T1005",     "Data from Local System",      "Collecte fichiers Word, Excel, PDF ciblés"],
            ["Command & Control",   "T1071.001", "Web Protocols",               "C2 via HTTP/HTTPS (blend dans trafic légitime)"],
            ["Command & Control",   "T1573.001", "Symmetric Cryptography",      "Chiffrement RC4/AES des communications C2"],
            ["Exfiltration",        "T1041",     "Exfil over C2 Channel",       "Exfiltration via le même canal C2"],
            ["Exfiltration",        "T1048",     "Exfil over Alt Protocol",     "Exfiltration DNS, SMTP"],
            ["Impact",              "T1485",     "Data Destruction",            "Destruction de données (NotPetya, Olympic Destroyer)"],
        ],
        "tools": [
            {"name": "X-Agent (Sofacy)",    "type": "RAT",     "description": "Outil d'espionnage cross-platform (Win, Linux, iOS, Android)"},
            {"name": "X-Tunnel",            "type": "Proxy",   "description": "Tunnel chiffré pour communications C2"},
            {"name": "Mimikatz",            "type": "Credential", "description": "Extraction de credentials Windows (usage documenté)"},
            {"name": "LoJax",               "type": "Rootkit", "description": "Rootkit UEFI — premier rootkit UEFI documenté in-the-wild"},
            {"name": "Zebrocy",             "type": "Downloader", "description": "Downloader multi-langage (Delphi, AutoIt, Go)"},
            {"name": "Olympic Destroyer",   "type": "Wiper",   "description": "Malware destructeur — Jeux Olympiques 2018"},
            {"name": "Drovorub",            "type": "Linux",   "description": "Rootkit Linux documenté par NSA/FBI (2020)"},
            {"name": "GoMaple",             "type": "Golang",  "description": "RAT Go — utilisé depuis 2022"},
        ],
        "infrastructure": [
            "Domaines usurpant des organisations légitimes (NATO, gouvernements)",
            "VPN / proxies pour masquer l'origine (TOR, VPS loués avec crypto)",
            "Services cloud légitimes détournés (OneDrive, Dropbox pour C2)",
            "Certificats SSL légitimes (Let's Encrypt) pour HTTPS C2",
            "Infrastructure de phishing lookalike domains",
        ],
        "ioc_types": ["Hash SHA256/MD5", "Domaines C2", "IP C2", "URLs de phishing",
                      "Règles YARA", "Règles Sigma", "Mutex"],
        "defensive_recommendations": [
            "Activer MFA sur tous les accès — priorité absolue contre credential phishing",
            "Patcher rapidement Exchange, Outlook (CVE-2023-23397 exploité activement)",
            "Bloquer les macros Office non signées (politique GPO)",
            "Implémenter DMARC/DKIM/SPF pour lutter contre l'usurpation d'email",
            "Surveiller l'accès à LSASS.exe (Sysmon EventID 10)",
            "Détecter les tickets Kerberos RC4 (EventID 4769 avec EncryptionType 0x17)",
            "Logger et alerter sur les connexions OWA/Exchange depuis IPs inhabituelles",
            "Mettre en place la détection DCSync (EventID 4662 + 4624)",
        ],
    },

    "APT29": {
        "name"          : "APT29",
        "aliases"       : ["Cozy Bear", "Nobelium", "The Dukes", "Dark Halo", "Iron Hemlock"],
        "origin"        : "Russie",
        "sponsor"       : "SVR (Service de renseignement extérieur russe)",
        "active_since"  : "2008",
        "targets"       : ["Gouvernements occidentaux", "Think tanks", "Organisations sanitaires (COVID-19)",
                           "Chaîne d'approvisionnement logicielle (SolarWinds)", "OTAN"],
        "motivation"    : "Espionnage stratégique à long terme, accès silencieux et durable",
        "mitre_group_id": "G0016",
        "mitre_url"     : "https://attack.mitre.org/groups/G0016/",
        "cisa_advisories": [
            "AA21-008A — Detecting Post-Compromise Threat Activity (SolarWinds)",
            "AA23-347A — Russian SVR Actors",
        ],
        "techniques": [
            ["Initial Access",    "T1195.002", "Supply Chain — Software", "Compromission SolarWinds Orion (2020)"],
            ["Initial Access",    "T1566.002", "Spearphishing Link",      "Liens malveillants vers credential harvesting"],
            ["Execution",         "T1059.001", "PowerShell",              "PowerShell avec AMSI bypass"],
            ["Persistence",       "T1098.001", "Additional Cloud Creds",  "Ajout credentials OAuth dans Azure AD"],
            ["Defense Evasion",   "T1036.005", "Match Legit Name/Location","Masquerading processus légitimes"],
            ["Defense Evasion",   "T1070.004", "File Deletion",           "Suppression traces après exfiltration"],
            ["Credential Access", "T1528",     "Steal App Token",         "Vol tokens SAML/OAuth"],
            ["Lateral Movement",  "T1550.001", "Use App Token",           "Mouvement latéral via tokens cloud"],
            ["Collection",        "T1114.002", "Remote Email Collection", "Accès mailboxes Exchange Online"],
            ["Command & Control", "T1071.001", "Web Protocols",           "C2 via HTTPS avec blending"],
            ["C2",                "T1568.002", "Domain Generation Algorithm","DGA pour résistance au sinkholing"],
        ],
        "tools": [
            {"name": "SUNBURST",    "type": "Backdoor", "description": "Backdoor SolarWinds — compromission supply chain 2020"},
            {"name": "TEARDROP",    "type": "Loader",   "description": "Memory-only dropper lié à SUNBURST"},
            {"name": "WellMess",    "type": "RAT",      "description": "RAT Go/DotNet — attaques secteur vaccin COVID"},
            {"name": "MagicWeb",    "type": "Auth",     "description": "Manipulation tokens SAML AD FS (2022)"},
            {"name": "GraphicalProton","type": "Backdoor","description": "Backdoor utilisant Dropbox/OneDrive comme C2"},
        ],
        "infrastructure": [
            "Compromission d'infrastructure légitime (fournisseurs cloud)",
            "Utilisation des APIs Microsoft Graph pour C2",
            "Services cloud légitimes (OneDrive, Dropbox) comme canal C2",
        ],
        "ioc_types": ["Hash", "Domaines C2", "Règles YARA SUNBURST"],
        "defensive_recommendations": [
            "Audit des applications cloud tierces avec accès OAuth",
            "Surveillance connexions inhabituelles Azure AD/M365",
            "MFA résistant au phishing (clés hardware FIDO2)",
            "Vérification intégrité des mises à jour logicielles (supply chain security)",
            "Surveillance modifications AD FS / SAML",
        ],
    },

    "Lazarus": {
        "name"          : "Lazarus Group",
        "aliases"       : ["HIDDEN COBRA", "Guardians of Peace", "APT38", "Zinc", "Nickel Academy"],
        "origin"        : "Corée du Nord",
        "sponsor"       : "Bureau général de reconnaissance (Reconnaissance General Bureau)",
        "active_since"  : "2009",
        "targets"       : ["Institutions financières", "Bourses de cryptomonnaies",
                           "Secteur défense/aérospatial", "Médias", "Échanges crypto"],
        "motivation"    : "Gain financier (financement du régime), espionnage, sabotage",
        "mitre_group_id": "G0032",
        "mitre_url"     : "https://attack.mitre.org/groups/G0032/",
        "cisa_advisories": ["AA22-108A — TraderTraitor (vol crypto)"],
        "techniques": [
            ["Initial Access",    "T1566.002", "Spearphishing Link",      "Faux recruteurs LinkedIn avec offres d'emploi"],
            ["Initial Access",    "T1195.002", "Supply Chain",            "Packages npm malveillants (CoinSwap, etc.)"],
            ["Execution",         "T1059.007", "JavaScript",              "Backdoors JS dans packages npm"],
            ["Persistence",       "T1547.001", "Registry Run Keys",       "Persistence via registre"],
            ["Defense Evasion",   "T1027.002", "Software Packing",        "Malware packé avec LLVM obfuscation"],
            ["Credential Access", "T1555.003", "Credentials from Browser","Vol credentials depuis navigateurs"],
            ["Lateral Movement",  "T1021.001", "RDP",                     "RDP après credential access"],
            ["Collection",        "T1560.001", "Archive via Utility",     "Compression 7zip avant exfiltration"],
            ["Exfiltration",      "T1041",     "Over C2 Channel",         "Exfiltration via C2 chiffré"],
            ["Impact",            "T1485",     "Data Destruction",        "Wiper malware (WhiskeyMaker, TrailBlazer)"],
        ],
        "tools": [
            {"name": "BLINDINGCAN", "type": "RAT",      "description": "RAT Windows — CISA Alert AA20-239A"},
            {"name": "AppleJeus",   "type": "Trojan",   "description": "Faux logiciel crypto pour vol de fonds"},
            {"name": "DTrack",      "type": "Spyware",  "description": "Collecte d'information, keylogger"},
            {"name": "Manuscrypt",  "type": "Backdoor", "description": "Backdoor utilisé contre secteur crypto"},
        ],
        "infrastructure": [
            "Serveurs compromis dans le monde entier",
            "Services bulletproof hosting",
            "Mixeurs cryptocurrency pour blanchiment",
        ],
        "ioc_types": ["Hash", "Domaines", "Packages npm malveillants"],
        "defensive_recommendations": [
            "Formation aux attaques via faux recruteurs (social engineering)",
            "Audit des packages npm / supply chain sécurité",
            "Surveillance des processus accédant aux wallets crypto",
            "MFA sur les exchanges crypto",
            "Ségrégation réseau — cloisonner les systèmes financiers",
        ],
    },
}


# ─── FORMATEURS ───────────────────────────────────────────────────────────────

def format_text_report(group_data: dict) -> str:
    lines = []
    lines.append(f"\n{'='*65}")
    lines.append(f"  PROFIL CTI — {group_data['name']}")
    lines.append(f"{'='*65}\n")

    aliases = " / ".join(group_data["aliases"][:4])
    lines.append(f"  Alias        : {aliases}")
    lines.append(f"  Origine      : {group_data['origin']}")
    lines.append(f"  Sponsor      : {group_data['sponsor']}")
    lines.append(f"  Actif depuis : {group_data['active_since']}")
    lines.append(f"  MITRE ID     : {group_data['mitre_group_id']}")
    lines.append(f"  Motivation   : {group_data['motivation']}")
    lines.append(f"\n  Cibles principales :")
    for t in group_data["targets"]:
        lines.append(f"    • {t}")

    lines.append(f"\n{'─'*65}")
    lines.append("  TOP TECHNIQUES MITRE ATT&CK")
    lines.append(f"{'─'*65}")
    for tac, tid, tname, desc in group_data["techniques"][:10]:
        lines.append(f"  {tid:<15} [{tac[:15]:<15}] {tname}")
        lines.append(f"    → {desc}")

    lines.append(f"\n{'─'*65}")
    lines.append("  ARSENAL LOGICIEL")
    lines.append(f"{'─'*65}")
    for tool in group_data["tools"]:
        lines.append(f"  [{tool['type']:<10}] {tool['name']:<20} — {tool['description']}")

    lines.append(f"\n{'─'*65}")
    lines.append("  RECOMMANDATIONS DÉFENSIVES")
    lines.append(f"{'─'*65}")
    for i, rec in enumerate(group_data["defensive_recommendations"], 1):
        lines.append(f"  {i:2}. {rec}")

    lines.append(f"\n  🔗 MITRE : {group_data['mitre_url']}")
    for adv in group_data.get("cisa_advisories", []):
        lines.append(f"  📄 CISA  : {adv}")
    lines.append("")
    return "\n".join(lines)


def format_html_report(group_data: dict) -> str:
    tactics_html = ""
    by_tactic = {}
    for tac, tid, tname, desc in group_data["techniques"]:
        by_tactic.setdefault(tac, []).append((tid, tname, desc))

    tac_colors = {
        "Initial Access": "#e74c3c", "Execution": "#e67e22", "Persistence": "#f39c12",
        "Defense Evasion": "#1abc9c", "Credential Access": "#9b59b6",
        "Discovery": "#3498db", "Lateral Movement": "#2980b9",
        "Collection": "#16a085", "Command & Control": "#8e44ad",
        "Exfiltration": "#c0392b", "Impact": "#922b21", "C2": "#8e44ad",
    }
    for tac, techniques in by_tactic.items():
        color = tac_colors.get(tac, "#555")
        tac_items = "".join(
            f'<li><code style="background:#21262d;padding:2px 6px;border-radius:3px;color:#79c0ff">'
            f'{tid}</code> <strong>{tname}</strong> — {desc}</li>'
            for tid, tname, desc in techniques
        )
        tactics_html += f'<div class="tactic"><div class="tac-header" style="border-left:4px solid {color}">{tac}</div><ul>{tac_items}</ul></div>'

    tools_html = "".join(
        f'<tr><td><span class="badge">{t["type"]}</span></td><td><strong>{t["name"]}</strong></td><td>{t["description"]}</td></tr>'
        for t in group_data["tools"]
    )
    recs_html = "".join(f"<li>{r}</li>" for r in group_data["defensive_recommendations"])
    targets_html = "".join(f"<span class='tag'>{t}</span>" for t in group_data["targets"])
    aliases_html = " &nbsp;·&nbsp; ".join(f'<code>{a}</code>' for a in group_data["aliases"])

    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>CTI — {group_data['name']}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;margin:0}}
  header{{background:linear-gradient(135deg,#6f42c1,#3d1a78);padding:28px 32px}}
  header h1{{color:#fff;font-size:1.8em}} header p{{color:rgba(255,255,255,0.7);margin-top:4px}}
  .container{{max-width:1100px;margin:0 auto;padding:24px}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}}
  .panel{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}}
  .panel h3{{color:#8b949e;font-size:0.85em;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px}}
  .meta-row{{display:flex;gap:8px;margin-bottom:8px;align-items:baseline}}
  .meta-label{{color:#8b949e;font-size:0.85em;min-width:120px}}
  .tactic{{margin-bottom:14px;background:#0d1117;border-radius:6px;padding:10px 14px}}
  .tac-header{{font-weight:600;margin-bottom:6px;padding-left:8px;color:#c9d1d9}}
  ul{{list-style:none;margin:0;padding:0}} li{{margin:4px 0;font-size:0.9em;color:#8b949e}}
  li strong{{color:#c9d1d9}}
  table{{width:100%;border-collapse:collapse}} th{{color:#8b949e;text-align:left;padding:8px;font-size:0.8em;text-transform:uppercase;border-bottom:1px solid #30363d}}
  td{{padding:8px;border-bottom:1px solid #21262d;font-size:0.9em}}
  .badge{{background:#6f42c1;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75em}}
  .tag{{background:#21262d;border:1px solid #30363d;border-radius:12px;padding:2px 10px;font-size:0.8em;margin:2px;display:inline-block}}
  code{{background:#21262d;padding:2px 6px;border-radius:3px;color:#79c0ff;font-size:0.85em}}
  .rec-list li{{color:#c9d1d9;margin:6px 0;padding-left:4px;border-left:3px solid #388bfd}}
  a{{color:#58a6ff}}
  footer{{text-align:center;padding:20px;color:#484f58;font-size:0.8em;border-top:1px solid #21262d;margin-top:24px}}
</style></head><body>
<header>
  <h1>🎯 {group_data['name']} — Profil CTI</h1>
  <p>{" · ".join(group_data["aliases"][:3])} · Actif depuis {group_data['active_since']} · {group_data['origin']}</p>
</header>
<div class="container">
  <div class="grid">
    <div class="panel">
      <h3>Identité</h3>
      <div class="meta-row"><span class="meta-label">Alias</span><span>{aliases_html}</span></div>
      <div class="meta-row"><span class="meta-label">Origine</span><strong>{group_data['origin']}</strong></div>
      <div class="meta-row"><span class="meta-label">Sponsor</span><span>{group_data['sponsor']}</span></div>
      <div class="meta-row"><span class="meta-label">Actif depuis</span><span>{group_data['active_since']}</span></div>
      <div class="meta-row"><span class="meta-label">MITRE ID</span><a href="{group_data['mitre_url']}" target="_blank">{group_data['mitre_group_id']}</a></div>
      <div class="meta-row"><span class="meta-label">Motivation</span><span>{group_data['motivation']}</span></div>
    </div>
    <div class="panel">
      <h3>Secteurs ciblés</h3>
      <div style="line-height:2">{targets_html}</div>
    </div>
  </div>
  <div class="panel" style="margin-bottom:20px">
    <h3>Techniques MITRE ATT&CK</h3>
    {tactics_html}
  </div>
  <div class="grid">
    <div class="panel">
      <h3>Arsenal logiciel</h3>
      <table><tr><th>Type</th><th>Outil</th><th>Description</th></tr>{tools_html}</table>
    </div>
    <div class="panel">
      <h3>Recommandations défensives</h3>
      <ul class="rec-list">{recs_html}</ul>
    </div>
  </div>
</div>
<footer>Cyber Homelab · Joe Bichall (@joebat10) · Sources: MITRE ATT&CK, CISA, sources publiques</footer>
</body></html>"""


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Générateur de profils CTI pour groupes APT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python apt_profiler.py --list
  python apt_profiler.py --group APT28
  python apt_profiler.py --group APT29 --format html --output apt29_profile.html
  python apt_profiler.py --group Lazarus --format json
"""
    )
    parser.add_argument("--group",  help="Nom du groupe APT")
    parser.add_argument("--list",   action="store_true", help="Lister les groupes disponibles")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text")
    parser.add_argument("--output", help="Fichier de sortie")
    args = parser.parse_args()

    if args.list:
        print("\n📋 Groupes APT disponibles :\n")
        for key, data in APT_DATABASE.items():
            print(f"  {key:<12} {data['origin']:<12} {data['mitre_group_id']}  —  {', '.join(data['aliases'][:2])}")
        print()
        return

    if not args.group:
        parser.print_help()
        return

    group_key = next((k for k in APT_DATABASE if k.lower() == args.group.lower()), None)
    if not group_key:
        print(f"[!] Groupe inconnu : {args.group}")
        print(f"    Disponibles : {', '.join(APT_DATABASE.keys())}")
        return

    group_data = APT_DATABASE[group_key]

    if args.format == "text":
        output = format_text_report(group_data)
        print(output)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"[✓] Rapport → {args.output}")

    elif args.format == "json":
        output = json.dumps(group_data, indent=2, ensure_ascii=False)
        print(output)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"[✓] JSON → {args.output}")

    elif args.format == "html":
        output = format_html_report(group_data)
        out_file = args.output or f"{group_key}_profile.html"
        Path(out_file).write_text(output, encoding="utf-8")
        print(f"[✓] Profil HTML → {out_file}")


if __name__ == "__main__":
    main()
