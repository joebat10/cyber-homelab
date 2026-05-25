#!/usr/bin/env bash
# =============================================================================
# install_wazuh.sh — Wazuh 4.x All-in-One on Ubuntu 22.04
#
# Installs: Wazuh Manager + Indexer + Dashboard (single-node)
# Port map : Manager API 55000 · Dashboard HTTPS 443 · Indexer 9200
#
# Usage (on the Ubuntu VM as root or sudo):
#   chmod +x install_wazuh.sh
#   sudo bash install_wazuh.sh
#
# After install:
#   Dashboard : https://192.168.56.10
#   API       : https://192.168.56.10:55000
#   Credentials printed at end of script
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install_wazuh.sh"

OS=$(lsb_release -si 2>/dev/null || echo "Unknown")
VER=$(lsb_release -sr 2>/dev/null || echo "0")
[[ "$OS" != "Ubuntu" || "$VER" != "22.04" ]] && \
    warn "Tested on Ubuntu 22.04 — detected: $OS $VER (continuing anyway)"

RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
[[ $RAM_MB -lt 3800 ]] && \
    warn "Low RAM: ${RAM_MB}MB — Wazuh recommends 4 GB minimum"

info "Starting Wazuh 4.x all-in-one installation on $(hostname) ($(hostname -I | awk '{print $1}'))"
echo ""

# ── Step 1: System prerequisites ─────────────────────────────────────────────
info "Step 1/6 — System update and prerequisites"
apt-get update -qq
apt-get install -y -qq curl apt-transport-https gnupg2 lsb-release \
    ca-certificates wget netcat-openbsd jq 2>/dev/null
success "Prerequisites installed"

# ── Step 2: Download Wazuh installer ─────────────────────────────────────────
info "Step 2/6 — Downloading Wazuh installer"
INSTALLER_URL="https://packages.wazuh.com/4.9/wazuh-install.sh"
CHECKSUM_URL="https://packages.wazuh.com/4.9/wazuh-install.sh.sha512"

wget -qO /tmp/wazuh-install.sh      "$INSTALLER_URL"
wget -qO /tmp/wazuh-install.sh.sha512 "$CHECKSUM_URL"

cd /tmp
sha512sum -c wazuh-install.sh.sha512 2>/dev/null && success "Checksum OK" || \
    warn "Checksum mismatch — network issue? Continuing..."
cd - >/dev/null

# ── Step 3: All-in-One installation ──────────────────────────────────────────
info "Step 3/6 — Installing Wazuh (Manager + Indexer + Dashboard)"
info "This takes 10–20 minutes depending on network speed..."
bash /tmp/wazuh-install.sh -a 2>&1 | tee /tmp/wazuh_install.log
success "Wazuh installation complete"

# ── Step 4: Extract credentials from install log ─────────────────────────────
info "Step 4/6 — Extracting credentials"

# Wazuh installer stores passwords in /usr/share/wazuh-indexer/
PASSWORDS_FILE="/usr/share/wazuh-indexer/opensearch-security/internal_users.yml"
WAZUH_PASS_FILE="/tmp/wazuh-passwords.txt"

# The installer prints credentials to stdout; extract from log
if grep -q "admin password" /tmp/wazuh_install.log 2>/dev/null; then
    ADMIN_PASS=$(grep "admin password" /tmp/wazuh_install.log | tail -1 | awk '{print $NF}')
else
    # Fallback: check the wazuh-passwords file the installer creates
    if [[ -f "$WAZUH_PASS_FILE" ]]; then
        ADMIN_PASS=$(grep "admin:" "$WAZUH_PASS_FILE" | awk '{print $2}')
    else
        ADMIN_PASS="check /tmp/wazuh_install.log for password"
    fi
fi

success "Credentials extracted"

# ── Step 5: Configure Wazuh Manager ──────────────────────────────────────────
info "Step 5/6 — Configuring Wazuh Manager"

OSSEC_CONF="/var/ossec/etc/ossec.conf"

# Ensure remote syslog input is enabled (for agent connectivity)
if ! grep -q "<ossec_config>" "$OSSEC_CONF" 2>/dev/null; then
    warn "ossec.conf not found — skipping manager config patch"
else
    # Enable JSON logging for easier log parsing
    if ! grep -q "jsonout_output" "$OSSEC_CONF"; then
        sed -i 's|<ossec_config>|<ossec_config>\n  <global>\n    <jsonout_output>yes</jsonout_output>\n    <alerts_log>yes</alerts_log>\n  </global>|' "$OSSEC_CONF"
        success "JSON output enabled"
    fi

    # Set log level to capture level 1+ alerts in alerts.log
    if ! grep -q "log_alert_level" "$OSSEC_CONF"; then
        sed -i 's|</alerts>|  <log_alert_level>1</log_alert_level>\n  </alerts>|' "$OSSEC_CONF"
    fi
fi

# Copy our custom rules if they exist
RULES_SRC="$(dirname "$0")/../rules"
if [[ -d "$RULES_SRC" ]]; then
    cp "$RULES_SRC"/*.xml /var/ossec/etc/rules/ 2>/dev/null && \
        success "Custom rules deployed" || true
fi

# ── Step 6: Service control & firewall ───────────────────────────────────────
info "Step 6/6 — Starting services and opening firewall ports"

systemctl daemon-reload
systemctl enable --now wazuh-manager wazuh-indexer wazuh-dashboard

# Allow required ports
if command -v ufw &>/dev/null; then
    ufw allow 1514/tcp  comment "Wazuh agent TCP"   >/dev/null 2>&1 || true
    ufw allow 1515/tcp  comment "Wazuh agent enroll" >/dev/null 2>&1 || true
    ufw allow 1516/tcp  comment "Wazuh cluster"      >/dev/null 2>&1 || true
    ufw allow 55000/tcp comment "Wazuh API"          >/dev/null 2>&1 || true
    ufw allow 443/tcp   comment "Wazuh Dashboard"    >/dev/null 2>&1 || true
    ufw allow 9200/tcp  comment "Wazuh Indexer"      >/dev/null 2>&1 || true
    success "UFW rules added"
fi

# Wait for API to be ready
info "Waiting for Wazuh API (port 55000) to become ready..."
for i in $(seq 1 30); do
    nc -z 127.0.0.1 55000 2>/dev/null && break
    echo -n "."
    sleep 5
done
echo ""

# Reload Wazuh to apply rule changes
/var/ossec/bin/wazuh-control restart 2>/dev/null || true

# ── Verification ──────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Wazuh Installation Complete${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Dashboard : ${CYAN}https://$(hostname -I | awk '{print $1}')${NC}"
echo -e "  API       : ${CYAN}https://$(hostname -I | awk '{print $1}'):55000${NC}"
echo -e "  Username  : ${CYAN}admin${NC}"
echo -e "  Password  : ${CYAN}${ADMIN_PASS}${NC}"
echo ""
echo -e "  Agent port 1514 (TCP) — open for agent connections"
echo -e "  Enroll port 1515 (TCP) — open for agent registration"
echo ""
echo -e "  Service status:"
systemctl is-active --quiet wazuh-manager  && \
    echo -e "    wazuh-manager  ${GREEN}running${NC}" || \
    echo -e "    wazuh-manager  ${RED}stopped${NC}"
systemctl is-active --quiet wazuh-indexer  && \
    echo -e "    wazuh-indexer  ${GREEN}running${NC}" || \
    echo -e "    wazuh-indexer  ${RED}stopped${NC}"
systemctl is-active --quiet wazuh-dashboard && \
    echo -e "    wazuh-dashboard ${GREEN}running${NC}" || \
    echo -e "    wazuh-dashboard ${RED}stopped${NC}"
echo ""
echo -e "  Full install log: /tmp/wazuh_install.log"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo -e "  1. Save the admin password above"
echo -e "  2. From Windows host: run install_agent_windows.ps1"
echo -e "  3. From Windows host: run install_sysmon.ps1"
echo -e "  4. Verify pipeline: python test_soc_pipeline.py"
