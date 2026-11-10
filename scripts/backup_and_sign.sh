#!/bin/sh
# scripts/backup_and_sign.sh — Hot-backup blackroute_archive.db and emit HTMX OOB SHA-256 badge
set -eu
DB_PATH="${1:-data/blackroute_archive.db}"
BACKUP_DIR="${2:-data/backups}"
STAMP=$(date -u +"%Y%m%d_%H%M%S")
OUT_FILE="${BACKUP_DIR}/blackroute_snapshot_${STAMP}.db"

if [ -L "$BACKUP_DIR" ]; then
    echo "Security Violation (CWE-377): Backup directory is a symlink." >&2
    exit 1
fi
mkdir -p "$BACKUP_DIR"

if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_PATH" "VACUUM INTO '${OUT_FILE}';"
else
    python3 - "$DB_PATH" "$OUT_FILE" <<'PY'
import os, sqlite3, sys
db_path, out_file = sys.argv[1], sys.argv[2]
if os.path.exists(out_file):
    os.unlink(out_file)
os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA journal_mode = WAL;")
escaped = out_file.replace("'", "''")
conn.execute(f"VACUUM INTO '{escaped}';")
conn.close()
PY
fi

HASH=$(sha256sum "$OUT_FILE" | cut -c1-12 | tr '[:lower:]' '[:upper:]')

printf '<span id="audit-lock-badge" hx-swap-oob="true" class="val-pos">[AUDIT_LOCK: %s // SHA256:%s]</span>\n' "$STAMP" "$HASH"
