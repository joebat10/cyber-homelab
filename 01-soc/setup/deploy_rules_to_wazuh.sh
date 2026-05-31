#!/usr/bin/env bash
# deploy_rules_to_wazuh.sh
# Run this script ON the Wazuh Manager VM (not from the Windows host).
#
# Usage:
#   chmod +x deploy_rules_to_wazuh.sh
#   sudo bash deploy_rules_to_wazuh.sh
#
# Or, push the rules via SCP first:
#   scp 01-soc/rules/*.xml joe@192.168.56.10:/tmp/
#   ssh joe@192.168.56.10 "sudo bash /tmp/deploy_rules_to_wazuh.sh"

set -euo pipefail

RULES_DEST="/var/ossec/etc/rules"
RULES_SRC="${1:-/tmp}"

echo "================================================================"
echo "  Wazuh Custom Rules Deployment"
echo "  Destination: $RULES_DEST"
echo "================================================================"

RULES=("wazuh_ad_attacks.xml" "wazuh_lateral_movement.xml" "wazuh_lolbins.xml")

deployed=0
for rule in "${RULES[@]}"; do
    src="$RULES_SRC/$rule"
    dst="$RULES_DEST/$rule"

    if [[ ! -f "$src" ]]; then
        echo "[SKIP] $rule not found at $src"
        continue
    fi

    cp "$src" "$dst"
    chown root:wazuh "$dst"
    chmod 660 "$dst"
    echo "[OK]  Deployed $rule"
    ((deployed++))
done

if [[ $deployed -eq 0 ]]; then
    echo "[ERROR] No rules deployed. Copy .xml files to $RULES_SRC first."
    exit 1
fi

# Validate XML before restart
echo ""
echo "[CHECK] Validating rules with wazuh-logtest..."
/var/ossec/bin/wazuh-logtest -t 2>&1 | tail -5 || true

echo ""
echo "[RESTART] Restarting Wazuh Manager..."
systemctl restart wazuh-manager
sleep 5

status=$(systemctl is-active wazuh-manager)
echo "[STATUS] wazuh-manager: $status"

if [[ "$status" == "active" ]]; then
    echo ""
    echo "[OK]  Rules loaded. Verify in Dashboard:"
    echo "      https://192.168.56.10 → Management → Rules → Custom rules"
    echo "      Rule IDs: 100100-100111 (LOLBins), 100200+ (AD attacks), 100300+ (lateral movement)"
else
    echo "[ERROR] Wazuh Manager did not restart cleanly. Check: journalctl -u wazuh-manager -n 50"
    exit 1
fi
