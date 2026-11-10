#!/bin/sh
# scripts/sys_telemetry.sh — Emits top status bar HTML fragment for BlackRoute Web
set -eu
DB_PATH="${1:-data/blackroute_archive.db}"
if [ ! -f "$DB_PATH" ]; then
    printf '<span class="val-warn">[DB: OFFLINE]</span>\n'
    exit 0
fi

if command -v sqlite3 >/dev/null 2>&1; then
    WAL_MODE=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;" | tr '[:lower:]' '[:upper:]')
else
    WAL_MODE=$(python3 - "$DB_PATH" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
conn.close()
print(str(mode).upper())
PY
)
fi

DB_SIZE_KB=$(du -k "$DB_PATH" | cut -f1)
SYNC_TIME=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

printf '<span class="val-pos">[DB: %s_OK // %s KB]</span> <span class="val-muted">[SYNC: %s]</span> <span class="val-pos">[LOOPBACK: 127.0.0.1:8090]</span>\n' \
    "$WAL_MODE" "$DB_SIZE_KB" "$SYNC_TIME"
