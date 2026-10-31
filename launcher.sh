#!/usr/bin/env bash
# ==============================================================================
# BlackRoute-Web Unified Linux Launcher (launcher.sh -> dev.sh parity)
# CyberNest Labs — Standard 004 (CN-DIR-2026-004): Dual-Native Orchestration
# Hardened for CWE-377 (Symlink defense, umask 077, 0700/0600 permissions),
# CWE-114 (Explicit APP_PID tracking, zero fuser -k), FIPS 140-3 (GOFIPS=1),
# SUDO Cache Preservation, and Automated CycloneDX 1.5 & SPDX 2.3 SBOMs.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/dev.sh" "$@"
