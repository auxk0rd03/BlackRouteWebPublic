#!/usr/bin/env python3
"""
scripts/migrate_v2_archive.py — Phase 1 Dual-Path SQLite WAL Schema Migration (`CN-LABS-BRW-2026-02`).

Initializes `scan_sessions`, `findings_ml_hot`, `findings_evidence_cold`, and `findings_vec_index`
in WAL mode with 256MB mmap and 64MB page cache, and backfills any legacy `scans`/`findings` rows.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.core.config import settings
from app.core.database import (
    _archive_scan_to_lakehouse,
    get_archive_db_path,
    get_db_connection,
    init_db,
    init_lakehouse_schema,
)


def migrate_database(db_path: Path) -> dict:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(db_path)
    init_lakehouse_schema(conn)

    cur = conn.cursor()
    journal_mode = cur.execute("PRAGMA journal_mode;").fetchone()[0]
    foreign_keys = cur.execute("PRAGMA foreign_keys;").fetchone()[0]

    # Check if legacy scans table exists and migrate any unarchived scans
    migrated_scans = 0
    migrated_findings = 0
    has_legacy = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
    ).fetchone()
    if has_legacy:
        scans = [dict(r) for r in cur.execute("SELECT * FROM scans ORDER BY id ASC").fetchall()]
        for s in scans:
            scan_id_str = f"SCAN-{int(s['id']):06d}"
            exists = cur.execute(
                "SELECT 1 FROM scan_sessions WHERE scan_id = ?", (scan_id_str,)
            ).fetchone()
            if exists:
                continue
            f_rows = [
                dict(r)
                for r in cur.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (s["id"],)
                ).fetchall()
            ]
            ep_rows = [
                dict(r)
                for r in cur.execute(
                    "SELECT * FROM endpoints WHERE scan_id = ? ORDER BY id ASC", (s["id"],)
                ).fetchall()
            ]
            _archive_scan_to_lakehouse(
                conn=conn,
                scan_id_str=scan_id_str,
                target_url=str(s.get("target_url") or "http://127.0.0.1:8090"),
                findings=f_rows,
                endpoints=ep_rows,
                report_file=str(s.get("report_file") or ""),
            )
            migrated_scans += 1
            migrated_findings += len(f_rows)
        conn.commit()

    tables = [
        r[0]
        for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name"
        ).fetchall()
    ]
    conn.close()
    try:
        if db_path.exists() and not db_path.is_symlink():
            os.chmod(db_path, 0o600)
    except OSError:
        pass

    return {
        "db_path": str(db_path),
        "journal_mode": str(journal_mode).upper(),
        "foreign_keys": int(foreign_keys),
        "tables": tables,
        "migrated_scans": migrated_scans,
        "migrated_findings": migrated_findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialize BlackRoute v2 Lakehouse WAL Schema.")
    parser.add_argument(
        "--db",
        type=str,
        default="",
        help="Optional explicit SQLite DB path to migrate (defaults to data/blackroute_archive.db and blackroute_web.db).",
    )
    args = parser.parse_args(argv)

    init_db()
    targets = [Path(args.db)] if args.db else [get_archive_db_path(), Path(settings.DB_PATH)]
    seen = set()
    for t in targets:
        resolved = t.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        info = migrate_database(t)
        print(
            f"[MIGRATE_V2] DB={info['db_path']} | JOURNAL={info['journal_mode']} | "
            f"FK={info['foreign_keys']} | TABLES={','.join(info['tables'])} | "
            f"MIGRATED_SCANS={info['migrated_scans']} | MIGRATED_FINDINGS={info['migrated_findings']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
