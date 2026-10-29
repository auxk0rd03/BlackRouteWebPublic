import os
import json
import sqlite3
from typing import Dict, List, Optional, Tuple, Any
from app.core.config import settings
from app.core.security import encrypt_aes256_gcm

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()

    # Off_Def_BackEnd_Framework.md Module 2: Streaming Recon Orchestrator targets schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL UNIQUE,
            ip TEXT,
            port INTEGER,
            tech_stack JSON,
            status_code INTEGER,
            last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            target_url TEXT NOT NULL,
            status TEXT DEFAULT 'completed',
            pages_crawled INTEGER DEFAULT 0,
            endpoints_found INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            report_file TEXT,
            encrypted_seal TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            endpoint TEXT,
            evidence TEXT,
            confidence REAL DEFAULT 1.0,
            remediation TEXT,
            curl_command TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    ''')

    # Backward-compatible schema migration for existing databases
    cursor.execute("PRAGMA table_info(findings)")
    columns = [col["name"] for col in cursor.fetchall()]
    if "curl_command" not in columns:
        cursor.execute("ALTER TABLE findings ADD COLUMN curl_command TEXT")
    if "html_poc_content" not in columns:
        cursor.execute("ALTER TABLE findings ADD COLUMN html_poc_content TEXT")
    if "html_poc" not in columns:
        cursor.execute("ALTER TABLE findings ADD COLUMN html_poc TEXT")

    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = [col["name"] for col in cursor.fetchall()]
    if "risk_score" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN risk_score INTEGER DEFAULT 0")
    if "encrypted_seal" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN encrypted_seal TEXT")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            status_code INTEGER,
            content_type TEXT,
            source TEXT DEFAULT 'CRAWLER',
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    ''')

    conn.commit()
    conn.close()
    try:
        if os.path.exists(settings.DB_PATH) and not os.path.islink(settings.DB_PATH):
            os.chmod(settings.DB_PATH, 0o600)
    except OSError:
        pass

def save_scan_record(
    target_url: str,
    findings: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]] = None,
    pages_crawled: int = 0,
    report_file: str = "",
    status: str = "completed",
    risk_score: int = 0
) -> int:
    """Persist scan results, findings, and discovered endpoints into SQLite."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    endpoints = endpoints or []
    endpoints_found = len(endpoints)
    findings_count = len(findings)

    seal_payload = json.dumps({"target_url": target_url, "findings_count": findings_count, "risk_score": risk_score}).encode("utf-8")
    encrypted_seal = encrypt_aes256_gcm(seal_payload)

    cursor.execute(
        """
        INSERT INTO scans (target_url, status, pages_crawled, endpoints_found, findings_count, report_file, risk_score, encrypted_seal)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (target_url, status, pages_crawled, endpoints_found, findings_count, report_file, risk_score, encrypted_seal)
    )
    scan_id = cursor.lastrowid

    for f in findings:
        cursor.execute(
            """
            INSERT INTO findings (scan_id, severity, category, title, description, endpoint, evidence, confidence, remediation, curl_command, html_poc_content, html_poc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                str(f.get("severity", "INFO")).upper(),
                str(f.get("category", "GENERAL")).upper(),
                str(f.get("title", "Security Finding")),
                str(f.get("description", "")),
                str(f.get("endpoint", target_url)),
                str(f.get("evidence", ""))[:1500],
                float(f.get("confidence", 1.0)),
                str(f.get("remediation", "")),
                str(f.get("curl_command", "")),
                str(f.get("html_poc_content", "")),
                str(f.get("html_poc", ""))
            )
        )

    for ep in endpoints:
        cursor.execute(
            """
            INSERT INTO endpoints (scan_id, url, method, status_code, content_type, source)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                str(ep.get("url", "")),
                str(ep.get("method", "GET")),
                ep.get("status_code"),
                str(ep.get("content_type", "")),
                str(ep.get("source", "CRAWLER"))
            )
        )

    conn.commit()
    conn.close()
    return scan_id

def get_latest_scan_findings() -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Retrieve the most recent scan record, its findings, and endpoints."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None, [], []

    scan = dict(scan_row)
    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan["id"],))
    findings = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM endpoints WHERE scan_id = ? ORDER BY id ASC", (scan["id"],))
    endpoints = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return scan, findings, endpoints

def get_scan_by_id(scan_id: int) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Retrieve a specific scan record, its findings, and endpoints by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None, [], []

    scan = dict(scan_row)
    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id ASC", (scan["id"],))
    findings = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM endpoints WHERE scan_id = ? ORDER BY id ASC", (scan["id"],))
    endpoints = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return scan, findings, endpoints

def update_scan_report_file(scan_id: int, report_file: str) -> None:
    """Update report_file field for an existing scan record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET report_file = ? WHERE id = ?", (report_file, scan_id))
    conn.commit()
    conn.close()

