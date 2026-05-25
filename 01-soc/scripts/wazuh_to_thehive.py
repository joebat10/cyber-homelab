#!/usr/bin/env python3
"""
wazuh_to_thehive.py
===================
Bridges Wazuh alerts to TheHive 5 cases.

- Polls Wazuh API for alerts level >= 10
- Creates a TheHive alert for each new Wazuh alert
- Maps Wazuh severity to TheHive severity
- Attaches MITRE ATT&CK tags when available
- Includes raw Wazuh alert as observable evidence
- Deduplicates via alert sourceRef (Wazuh alert ID)

Usage:
    # One-shot: process alerts from the last 24h
    python wazuh_to_thehive.py

    # Daemon: watch and forward in real time
    python wazuh_to_thehive.py --watch

    # Custom thresholds
    python wazuh_to_thehive.py --level 12 --watch --interval 60

Environment (.env file):
    WAZUH_HOST, WAZUH_PORT, WAZUH_USER, WAZUH_PASS
    THEHIVE_URL, THEHIVE_API_KEY
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

WAZUH_HOST = os.getenv("WAZUH_HOST", "192.168.56.10")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "55000"))
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "MyS3cr37P450r.*-")

THEHIVE_URL     = os.getenv("THEHIVE_URL", "http://127.0.0.1:9010")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

# Wazuh level → TheHive severity (1=low 2=medium 3=high 4=critical)
SEVERITY_MAP = {
    range(1,  7):  1,   # low
    range(7,  10): 2,   # medium
    range(10, 13): 3,   # high
    range(13, 16): 4,   # critical
}


def wazuh_severity(level: int) -> int:
    for r, sev in SEVERITY_MAP.items():
        if level in r:
            return sev
    return 2


def severity_label(sev: int) -> str:
    return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(sev, "MEDIUM")


# ── Wazuh client ──────────────────────────────────────────────────────────────

class WazuhClient:
    def __init__(self, host: str, port: int, user: str, password: str):
        self.base_url = f"https://{host}:{port}"
        self.user = user
        self.password = password
        self.token: Optional[str] = None
        self.session = requests.Session()
        self.session.verify = False

    def authenticate(self) -> bool:
        try:
            resp = self.session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
                timeout=10,
            )
            resp.raise_for_status()
            self.token = resp.json()["data"]["token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            print(f"[Wazuh] Authenticated to {self.base_url}")
            return True
        except requests.exceptions.ConnectionError:
            print(f"[Wazuh] ERROR: Cannot connect to {self.base_url}")
            print("         Is the Wazuh VM running? (192.168.56.10)")
            return False
        except Exception as e:
            print(f"[Wazuh] ERROR: Auth failed: {e}")
            return False

    def get_alerts(
        self,
        level_min: int = 10,
        hours: int = 1,
        limit: int = 100,
    ) -> list[dict]:
        if not self.token:
            if not self.authenticate():
                return []

        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        params = {
            "limit": limit,
            "level": f"{level_min}-15",
            "sort": "-timestamp",
            "q": f"timestamp>{since}",
        }
        try:
            resp = self.session.get(
                f"{self.base_url}/alerts",
                params=params,
                timeout=15,
            )
            if resp.status_code == 401:
                # Token expired — re-auth
                self.token = None
                return self.get_alerts(level_min, hours, limit)
            resp.raise_for_status()
            return resp.json().get("data", {}).get("affected_items", [])
        except Exception as e:
            print(f"[Wazuh] ERROR: get_alerts: {e}")
            return []

    def send_test_alert(self) -> bool:
        """Inject a synthetic alert via agent active response (level 10)."""
        try:
            resp = self.session.put(
                f"{self.base_url}/agents/all/active-response",
                json={"command": "!custom-alert", "alert": {"level": 10}},
                timeout=10,
            )
            return resp.status_code in (200, 202)
        except Exception:
            return False


# ── TheHive client ────────────────────────────────────────────────────────────

class TheHiveClient:
    def __init__(self, url: str, api_key: str):
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def check_connection(self) -> bool:
        try:
            resp = self.session.get(f"{self.base_url}/api/v1/status", timeout=5)
            return resp.status_code in (200, 401)
        except Exception:
            return False

    def alert_exists(self, source_ref: str) -> bool:
        """Check if an alert with this sourceRef already exists (dedup)."""
        try:
            resp = self.session.post(
                f"{self.base_url}/api/v1/alert/_search",
                json={"query": {"_field": "sourceRef", "_value": source_ref}},
                timeout=5,
            )
            if resp.status_code == 200:
                return len(resp.json()) > 0
        except Exception:
            pass
        return False

    def create_alert(self, wazuh_alert: dict) -> Optional[dict]:
        """Create a TheHive 5 alert from a Wazuh alert dict."""
        rule   = wazuh_alert.get("rule", {})
        agent  = wazuh_alert.get("agent", {})
        mitre  = rule.get("mitre", {})
        level  = rule.get("level", 5)
        sev    = wazuh_severity(level)

        # Build MITRE tags
        mitre_ids   = mitre.get("id", [])
        mitre_techs = mitre.get("technique", [])
        tags = [f"mitre:{t}" for t in mitre_ids]
        tags += [f"tactic:{t}" for t in mitre.get("tactic", [])]
        tags += ["wazuh", f"level:{level}", f"agent:{agent.get('name', 'unknown')}"]

        alert_id  = wazuh_alert.get("id", "")
        timestamp = wazuh_alert.get("timestamp", datetime.utcnow().isoformat())
        agent_name = agent.get("name", "unknown")
        agent_ip   = agent.get("ip", "unknown")

        title = (
            f"[Wazuh L{level}] {rule.get('description', 'Security Alert')}"
            f" — {agent_name}"
        )

        description_lines = [
            f"**Wazuh Alert ID:** `{alert_id}`",
            f"**Rule ID:** {rule.get('id', 'N/A')} — {rule.get('description', '')}",
            f"**Level:** {level} ({severity_label(sev)})",
            f"**Agent:** {agent_name} ({agent_ip})",
            f"**Timestamp:** {timestamp}",
        ]
        if mitre_ids:
            techniques = ", ".join(
                f"[{mid}](https://attack.mitre.org/techniques/{mid.replace('.', '/')})"
                for mid in mitre_ids
            )
            description_lines.append(f"**MITRE ATT&CK:** {techniques}")
            if mitre_techs:
                description_lines.append(
                    f"**Techniques:** {', '.join(mitre_techs)}"
                )
        if rule.get("groups"):
            description_lines.append(
                f"**Groups:** {', '.join(rule.get('groups', []))}"
            )

        description = "\n\n".join(description_lines)

        payload = {
            "title":       title,
            "description": description,
            "type":        "external",
            "source":      "wazuh",
            "sourceRef":   alert_id or f"wazuh-{timestamp}",
            "severity":    sev,
            "tlp":         2,     # AMBER
            "pap":         2,     # AMBER
            "tags":        tags,
            "date":        int(datetime.now(timezone.utc).timestamp() * 1000),
            "observables": [
                {
                    "dataType": "other",
                    "data":     json.dumps(wazuh_alert, indent=2),
                    "message":  "Raw Wazuh alert (JSON)",
                    "tags":     ["wazuh-raw"],
                }
            ],
        }

        # Add agent IP as network observable if present
        if agent_ip and agent_ip not in ("unknown", "127.0.0.1"):
            payload["observables"].append({
                "dataType": "ip",
                "data":     agent_ip,
                "message":  f"Agent IP: {agent_name}",
                "tags":     ["wazuh-agent"],
            })

        try:
            resp = self.session.post(
                f"{self.base_url}/api/v1/alert",
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            print(f"[TheHive] ERROR creating alert: {e} — {resp.text[:200]}")
            return None
        except Exception as e:
            print(f"[TheHive] ERROR: {e}")
            return None


# ── Bridge logic ──────────────────────────────────────────────────────────────

class WazuhToTheHive:
    def __init__(
        self,
        wazuh: WazuhClient,
        thehive: TheHiveClient,
        level_min: int = 10,
    ):
        self.wazuh    = wazuh
        self.thehive  = thehive
        self.level_min = level_min
        self.processed: set[str] = set()
        self.stats = {"forwarded": 0, "skipped_dup": 0, "errors": 0}

    def process_alerts(self, hours: int = 1) -> int:
        alerts = self.wazuh.get_alerts(
            level_min=self.level_min, hours=hours, limit=200
        )
        new_count = 0

        for alert in alerts:
            alert_id = alert.get("id", "")

            # In-memory dedup (same run)
            if alert_id and alert_id in self.processed:
                continue

            # Persistent dedup via TheHive query
            if alert_id and self.thehive.alert_exists(alert_id):
                self.processed.add(alert_id)
                self.stats["skipped_dup"] += 1
                continue

            result = self.thehive.create_alert(alert)
            if result:
                hive_id = result.get("_id", "?")
                rule    = alert.get("rule", {})
                level   = rule.get("level", "?")
                desc    = rule.get("description", "")[:60]
                agent   = alert.get("agent", {}).get("name", "unknown")
                print(
                    f"[OK]  Wazuh L{level} → TheHive {hive_id} | "
                    f"{agent} | {desc}"
                )
                self.processed.add(alert_id)
                self.stats["forwarded"] += 1
                new_count += 1
            else:
                self.stats["errors"] += 1

        return new_count

    def watch(self, interval: int = 60) -> None:
        print(f"\n[Bridge] Watch mode — polling every {interval}s (Ctrl+C to stop)")
        print(f"[Bridge] Forwarding Wazuh alerts level >= {self.level_min} to {self.thehive.base_url}\n")

        while True:
            ts = datetime.now().strftime("%H:%M:%S")
            try:
                count = self.process_alerts(hours=1)
                if count:
                    print(f"[{ts}] {count} new alert(s) forwarded to TheHive")
                else:
                    print(
                        f"[{ts}] No new alerts (fwd={self.stats['forwarded']} "
                        f"dup={self.stats['skipped_dup']})",
                        end="\r",
                    )
            except Exception as e:
                print(f"[{ts}] ERROR: {e}")

            time.sleep(interval)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wazuh → TheHive bridge: forward security alerts as cases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wazuh_to_thehive.py                    # one-shot, last 24h
  python wazuh_to_thehive.py --watch             # daemon mode
  python wazuh_to_thehive.py --watch --level 12  # only HIGH+CRITICAL
  python wazuh_to_thehive.py --watch --interval 30

Environment variables (or .env file):
  WAZUH_HOST, WAZUH_PORT, WAZUH_USER, WAZUH_PASS
  THEHIVE_URL, THEHIVE_API_KEY
        """,
    )
    parser.add_argument("--wazuh-host",   default=WAZUH_HOST)
    parser.add_argument("--wazuh-port",   default=WAZUH_PORT, type=int)
    parser.add_argument("--wazuh-user",   default=WAZUH_USER)
    parser.add_argument("--wazuh-pass",   default=WAZUH_PASS)
    parser.add_argument("--thehive-url",  default=THEHIVE_URL)
    parser.add_argument("--thehive-key",  default=THEHIVE_API_KEY)
    parser.add_argument("--level",        default=10, type=int,
                        help="Minimum Wazuh level to forward (default: 10)")
    parser.add_argument("--hours",        default=24, type=int,
                        help="Look-back window for one-shot mode (default: 24)")
    parser.add_argument("--watch",        action="store_true",
                        help="Run as daemon, polling continuously")
    parser.add_argument("--interval",     default=60, type=int,
                        help="Poll interval in seconds for --watch (default: 60)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("=" * 56)
    print("  Wazuh → TheHive Alert Bridge")
    print(f"  Wazuh  : https://{args.wazuh_host}:{args.wazuh_port}")
    print(f"  TheHive: {args.thehive_url}")
    print(f"  Level  : >= {args.level}")
    print("=" * 56)

    if not args.thehive_key:
        print("\n[ERROR] THEHIVE_API_KEY not set.")
        print("  Set it in .env or pass --thehive-key <key>")
        print("  Get your key: TheHive → top-right menu → API Key")
        sys.exit(1)

    wazuh   = WazuhClient(args.wazuh_host, args.wazuh_port, args.wazuh_user, args.wazuh_pass)
    thehive = TheHiveClient(args.thehive_url, args.thehive_key)

    # Pre-flight checks
    print("\n[Check] TheHive connectivity...")
    if not thehive.check_connection():
        print(f"[ERROR] Cannot reach TheHive at {args.thehive_url}")
        print("  Is the SOAR stack running? (cd 04-soar && docker compose up -d)")
        sys.exit(1)
    print("[OK]   TheHive reachable")

    print("[Check] Wazuh API connectivity...")
    if not wazuh.authenticate():
        print("[ERROR] Cannot authenticate to Wazuh API")
        print("  Is the Wazuh VM running at 192.168.56.10?")
        sys.exit(1)

    bridge = WazuhToTheHive(wazuh, thehive, level_min=args.level)

    if args.watch:
        bridge.watch(interval=args.interval)
    else:
        print(f"\n[Run] Processing alerts from last {args.hours}h (level >= {args.level})...")
        bridge.process_alerts(hours=args.hours)
        print(f"\n[Done] Forwarded: {bridge.stats['forwarded']}  "
              f"Duplicates skipped: {bridge.stats['skipped_dup']}  "
              f"Errors: {bridge.stats['errors']}")


if __name__ == "__main__":
    main()
