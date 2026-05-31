#!/usr/bin/env python3
"""
test_soc_pipeline.py
====================
End-to-end connectivity and integration test for the cyber-homelab SOC stack.

Tests:
  1. Ping Wazuh Manager (192.168.56.10)
  2. Wazuh API responds on port 55000
  3. TheHive API responds on port 9010
  4. Cortex API responds on port 9011
  5. Wazuh has at least one active agent
  6. TheHive can create and retrieve an alert
  7. (Optional) Verify a synthetic Wazuh alert appears in TheHive

Usage:
    python test_soc_pipeline.py
    python test_soc_pipeline.py --thehive-key <api_key>
    python test_soc_pipeline.py --skip-e2e    # skip end-to-end alert test
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
WAZUH_HOST      = os.getenv("WAZUH_HOST",    "192.168.56.10")
WAZUH_PORT      = int(os.getenv("WAZUH_PORT", "55000"))
WAZUH_USER      = os.getenv("WAZUH_USER",    "wazuh")
WAZUH_PASS      = os.getenv("WAZUH_PASS",    "")
THEHIVE_URL     = os.getenv("THEHIVE_URL",   "http://127.0.0.1:9010")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")
CORTEX_URL      = os.getenv("CORTEX_URL",    "http://127.0.0.1:9011")


# ── Test result tracking ──────────────────────────────────────────────────────
class Results:
    def __init__(self):
        self.passed:  list[str] = []
        self.failed:  list[str] = []
        self.skipped: list[str] = []
        self.details: dict[str, str] = {}

    def ok(self, name: str, detail: str = "") -> None:
        self.passed.append(name)
        if detail:
            self.details[name] = detail
        print(f"  {_green('PASS')}  {name}" + (f"  [{detail}]" if detail else ""))

    def fail(self, name: str, detail: str = "") -> None:
        self.failed.append(name)
        if detail:
            self.details[name] = detail
        print(f"  {_red('FAIL')}  {name}" + (f"  [{detail}]" if detail else ""))

    def skip(self, name: str, reason: str = "") -> None:
        self.skipped.append(name)
        print(f"  {_yellow('SKIP')}  {name}" + (f"  ({reason})" if reason else ""))

    def report(self) -> int:
        total = len(self.passed) + len(self.failed) + len(self.skipped)
        print("\n" + "=" * 56)
        print(f"  SOC Pipeline Test Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 56)
        print(f"  Total : {total}")
        print(f"  {_green('Passed')}: {len(self.passed)}")
        print(f"  {_red('Failed')}: {len(self.failed)}")
        print(f"  {_yellow('Skipped')}: {len(self.skipped)}")
        if self.failed:
            print("\n  Failed tests:")
            for name in self.failed:
                detail = self.details.get(name, "")
                print(f"    {_red('x')} {name}" + (f": {detail}" if detail else ""))
        print("=" * 56)
        return 1 if self.failed else 0


def _green(s):  return f"\033[32m{s}\033[0m"
def _red(s):    return f"\033[31m{s}\033[0m"
def _yellow(s): return f"\033[33m{s}\033[0m"
def _cyan(s):   return f"\033[36m{s}\033[0m"


# ── Individual tests ──────────────────────────────────────────────────────────

def test_ping(results: Results) -> None:
    """ICMP reachability to Wazuh Manager VM."""
    name = f"Ping Wazuh Manager ({WAZUH_HOST})"
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        ret = subprocess.run(
            ["ping", param, "2", "-w", "1000", WAZUH_HOST]
            if sys.platform == "win32"
            else ["ping", param, "2", "-W", "1", WAZUH_HOST],
            capture_output=True, timeout=5,
        )
        if ret.returncode == 0:
            results.ok(name)
        else:
            results.fail(name, "No ICMP reply — VM may block ping, check with TCP test")
    except Exception as e:
        results.fail(name, str(e))


def test_tcp_port(results: Results, host: str, port: int, label: str) -> bool:
    """TCP connection test."""
    name = f"TCP {label} ({host}:{port})"
    try:
        with socket.create_connection((host, port), timeout=5):
            results.ok(name)
            return True
    except (ConnectionRefusedError, TimeoutError) as e:
        results.fail(name, f"Connection refused/timeout — service down? ({e})")
        return False
    except Exception as e:
        results.fail(name, str(e))
        return False


def test_wazuh_api(results: Results) -> Optional[str]:
    """Authenticate to Wazuh API and return JWT token."""
    name = "Wazuh API authentication"
    try:
        resp = requests.post(
            f"https://{WAZUH_HOST}:{WAZUH_PORT}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False, timeout=10,
        )
        resp.raise_for_status()
        token = resp.json()["data"]["token"]
        results.ok(name, "JWT token received")
        return token
    except requests.exceptions.ConnectionError:
        results.fail(name, "Connection refused — is the Wazuh VM running?")
    except requests.exceptions.HTTPError:
        results.fail(name, f"HTTP {resp.status_code} — wrong credentials?")
    except Exception as e:
        results.fail(name, str(e))
    return None


def test_wazuh_agents(results: Results, token: str) -> None:
    """Check at least one active agent is connected."""
    name = "Wazuh agents connected"
    try:
        resp = requests.get(
            f"https://{WAZUH_HOST}:{WAZUH_PORT}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"status": "active"},
            verify=False, timeout=10,
        )
        resp.raise_for_status()
        agents = resp.json().get("data", {}).get("affected_items", [])
        if agents:
            names = ", ".join(a.get("name", "?") for a in agents[:5])
            results.ok(name, f"{len(agents)} active: {names}")
        else:
            results.fail(name, "No active agents — install agent on Windows host")
    except Exception as e:
        results.fail(name, str(e))


def test_thehive_api(results: Results, api_key: str) -> bool:
    """Check TheHive API status endpoint."""
    name = "TheHive API status"
    try:
        resp = requests.get(
            f"{THEHIVE_URL}/api/v1/status",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5,
        )
        if resp.status_code in (200, 401):
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("versions", {}).get("TheHive", "?")
                results.ok(name, f"TheHive {version}")
            else:
                results.fail(name, "API reachable but API key rejected — check THEHIVE_API_KEY")
            return resp.status_code == 200
        else:
            results.fail(name, f"HTTP {resp.status_code}")
            return False
    except Exception as e:
        results.fail(name, f"{e} — is the SOAR stack running?")
        return False


def test_cortex_api(results: Results) -> None:
    """Check Cortex API status endpoint."""
    name = "Cortex API status"
    try:
        resp = requests.get(f"{CORTEX_URL}/api/status", timeout=5)
        if resp.status_code in (200, 401):
            results.ok(name, f"HTTP {resp.status_code}")
        else:
            results.fail(name, f"HTTP {resp.status_code}")
    except Exception as e:
        results.fail(name, f"{e} — is the SOAR stack running?")


def test_create_thehive_alert(results: Results, api_key: str) -> Optional[str]:
    """Create a test alert in TheHive and return its ID."""
    name = "TheHive — create test alert"
    test_ref = f"soc-pipeline-test-{int(time.time())}"
    payload = {
        "title":       "[SOC Pipeline Test] Connectivity check",
        "description": "Automated test alert created by test_soc_pipeline.py",
        "type":        "external",
        "source":      "soc-pipeline-test",
        "sourceRef":   test_ref,
        "severity":    1,
        "tlp":         1,
        "pap":         1,
        "tags":        ["test", "pipeline", "automated"],
    }
    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload, timeout=10,
        )
        resp.raise_for_status()
        alert_id = resp.json().get("_id", "?")
        results.ok(name, f"Created alert ID: {alert_id}")
        return alert_id
    except Exception as e:
        results.fail(name, str(e))
        return None


def test_retrieve_thehive_alert(results: Results, api_key: str, alert_id: str) -> None:
    """Retrieve the alert we just created."""
    name = "TheHive — retrieve test alert"
    try:
        resp = requests.get(
            f"{THEHIVE_URL}/api/v1/alert/{alert_id}",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5,
        )
        resp.raise_for_status()
        title = resp.json().get("title", "?")
        results.ok(name, f"Title: {title}")
    except Exception as e:
        results.fail(name, str(e))


def cleanup_test_alert(api_key: str, alert_id: str) -> None:
    """Delete the test alert we created."""
    try:
        requests.delete(
            f"{THEHIVE_URL}/api/v1/alert/{alert_id}",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5,
        )
    except Exception:
        pass


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="SOC pipeline end-to-end test")
    p.add_argument("--wazuh-host",   default=WAZUH_HOST)
    p.add_argument("--thehive-url",  default=THEHIVE_URL)
    p.add_argument("--thehive-key",  default=THEHIVE_API_KEY)
    p.add_argument("--cortex-url",   default=CORTEX_URL)
    p.add_argument("--skip-e2e",     action="store_true",
                   help="Skip end-to-end TheHive alert creation test")
    return p.parse_args()


def main():
    args = parse_args()

    # Apply args to globals
    global WAZUH_HOST, THEHIVE_URL, THEHIVE_API_KEY, CORTEX_URL
    WAZUH_HOST      = args.wazuh_host
    THEHIVE_URL     = args.thehive_url
    THEHIVE_API_KEY = args.thehive_key
    CORTEX_URL      = args.cortex_url

    results = Results()
    created_alert_id = None

    print(f"\n{_cyan('SOC Pipeline Test Suite')}")
    print(f"{'='*56}")
    print(f"  Wazuh  : https://{WAZUH_HOST}:{WAZUH_PORT}")
    print(f"  TheHive: {THEHIVE_URL}")
    print(f"  Cortex : {CORTEX_URL}")
    print(f"{'='*56}\n")

    # ── Section 1: Network connectivity ───────────────────────────────────────
    print(f"{_cyan('Section 1: Network Connectivity')}")
    test_ping(results)
    wazuh_tcp_ok  = test_tcp_port(results, WAZUH_HOST, WAZUH_PORT, "Wazuh API")
    test_tcp_port(results, "127.0.0.1", 9010, "TheHive")
    test_tcp_port(results, "127.0.0.1", 9011, "Cortex")

    # ── Section 2: API authentication ─────────────────────────────────────────
    print(f"\n{_cyan('Section 2: API Authentication')}")
    wazuh_token = None
    if wazuh_tcp_ok:
        wazuh_token = test_wazuh_api(results)
    else:
        results.skip("Wazuh API authentication", "TCP port unreachable")

    if not THEHIVE_API_KEY:
        results.skip("TheHive API status",         "No API key (--thehive-key)")
        results.skip("TheHive — create test alert", "No API key")
        results.skip("TheHive — retrieve test alert","No API key")
    else:
        test_thehive_api(results, THEHIVE_API_KEY)

    test_cortex_api(results)

    # ── Section 3: Wazuh state ────────────────────────────────────────────────
    print(f"\n{_cyan('Section 3: Wazuh State')}")
    if wazuh_token:
        test_wazuh_agents(results, wazuh_token)
    else:
        results.skip("Wazuh agents connected", "Auth failed")

    # ── Section 4: TheHive integration ────────────────────────────────────────
    print(f"\n{_cyan('Section 4: TheHive Integration')}")
    if args.skip_e2e:
        results.skip("TheHive — create test alert",  "--skip-e2e flag set")
        results.skip("TheHive — retrieve test alert", "--skip-e2e flag set")
    elif THEHIVE_API_KEY:
        created_alert_id = test_create_thehive_alert(results, THEHIVE_API_KEY)
        if created_alert_id:
            test_retrieve_thehive_alert(results, THEHIVE_API_KEY, created_alert_id)
        else:
            results.skip("TheHive — retrieve test alert", "Create step failed")

    # ── Cleanup ────────────────────────────────────────────────────────────────
    if created_alert_id and THEHIVE_API_KEY:
        cleanup_test_alert(THEHIVE_API_KEY, created_alert_id)

    # ── Report ────────────────────────────────────────────────────────────────
    exit_code = results.report()

    if results.failed:
        print("\n  Troubleshooting hints:")
        if any("Wazuh" in f for f in results.failed):
            print(f"    Wazuh VM: ssh user@{WAZUH_HOST}")
            print( "    Check: sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard")
        if any("TheHive" in f for f in results.failed):
            print( "    SOAR stack: cd 04-soar && docker compose up -d")
            print( "    TheHive API key: top-right menu in TheHive UI → API Key")
        if any("Cortex" in f for f in results.failed):
            print( "    Cortex: cd 04-soar && docker compose up -d")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
