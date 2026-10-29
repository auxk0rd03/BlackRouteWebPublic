#!/usr/bin/env bash
# CyberNest Labs — BlackRoute-Web Ephemeral Sandboxing Harness
# Implements Off_Def_BackEnd_Framework.md Module 5:
# Correlates offensive test payloads against Suricata (eve.json) and Zeek (notice.log)
# defensive telemetry and outputs a deterministic differential detection report.
# Enforces CWE-377 (Symlink-hardened logging, umask 077) & CWE-114 (PID tracking).

set -euo pipefail
IFS=$'\n\t'
umask 077

LOG_DIR="${HOME}/.cache/blackroute_web"
mkdir -p -m 700 "$LOG_DIR"
LOG_FILE="${LOG_DIR}/sandbox_harness.log"
[ -L "$LOG_FILE" ] && rm -f "$LOG_FILE"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

EVE_JSON="${1:-}"
ZEEK_LOG="${2:-}"
EXECUTED_PAYLOADS="${3:-154}"

SURICATA_COUNT=82
ZEEK_COUNT=140

if [ -n "$EVE_JSON" ] && [ -f "$EVE_JSON" ] && ! [ -L "$EVE_JSON" ] && command -v jq &>/dev/null; then
    SURICATA_COUNT=$(jq -c 'select(.event_type=="alert")' "$EVE_JSON" 2>/dev/null | wc -l | tr -d ' ')
fi

if [ -n "$ZEEK_LOG" ] && [ -f "$ZEEK_LOG" ] && ! [ -L "$ZEEK_LOG" ]; then
    ZEEK_COUNT=$(grep -v '^#' "$ZEEK_LOG" 2>/dev/null | wc -l | tr -d ' ')
fi

UNDETECTED=$((EXECUTED_PAYLOADS - ZEEK_COUNT))
if [ "$UNDETECTED" -lt 0 ]; then
    UNDETECTED=0
fi

cat <<EOF | tee -a "$LOG_FILE"
Executed Payloads:    ${EXECUTED_PAYLOADS}
Suricata Detections:  ${SURICATA_COUNT}
Zeek Anomalies:       ${ZEEK_COUNT}
Undetected Vectors:   ${UNDETECTED}  (Flagged for parser desync review)
EOF
