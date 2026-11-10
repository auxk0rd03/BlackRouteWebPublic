import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from app.core.config import settings
from app.core.security import encrypt_aes256_gcm
from services.feature_extractor import (
    apply_lakehouse_pragmas,
    extract_finding_features,
    normalize_host_info,
    upsert_finding_pair,
    upsert_scan_session,
)

LAKEHOUSE_DDL = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    scan_id TEXT PRIMARY KEY,
    target_root_url TEXT NOT NULL,
    target_host_hash TEXT NOT NULL,
    scan_profile TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    total_requests_sent INTEGER DEFAULT 0,
    total_findings_raw INTEGER DEFAULT 0,
    baseline_latency_mean_ms REAL DEFAULT 0.0,
    baseline_latency_std_ms REAL DEFAULT 1.0,
    baseline_404_length INTEGER DEFAULT 0,
    baseline_404_simhash INTEGER DEFAULT 0,
    detected_waf_vendor TEXT DEFAULT 'NONE',
    raw_sarif_path TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_host_hash ON scan_sessions(target_host_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON scan_sessions(started_at);

CREATE TABLE IF NOT EXISTS findings_ml_hot (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scan_sessions(scan_id) ON DELETE CASCADE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    exact_dedup_hash TEXT NOT NULL,
    fuzzy_behavior_hash TEXT NOT NULL,
    host_group_bucket INTEGER NOT NULL,
    occurrence_count INTEGER DEFAULT 1,
    rule_id TEXT NOT NULL,
    cwe_id INTEGER NOT NULL,
    severity_scanner INTEGER NOT NULL,
    http_method_id INTEGER NOT NULL,
    injection_point_id INTEGER NOT NULL,
    endpoint_depth INTEGER NOT NULL,
    is_authenticated_ctx INTEGER NOT NULL,
    http_status_code INTEGER NOT NULL,
    baseline_status_code INTEGER NOT NULL,
    status_code_changed INTEGER NOT NULL,
    response_length_bytes INTEGER NOT NULL,
    response_length_delta INTEGER NOT NULL,
    response_length_ratio REAL NOT NULL,
    word_count_delta INTEGER NOT NULL,
    line_count_delta INTEGER NOT NULL,
    dom_structural_similarity REAL NOT NULL,
    soft_404_similarity REAL NOT NULL,
    response_time_ms REAL NOT NULL,
    response_time_delta_ms REAL NOT NULL,
    response_time_zscore REAL NOT NULL,
    body_shannon_entropy REAL NOT NULL,
    entropy_delta REAL NOT NULL,
    content_type_id INTEGER NOT NULL,
    content_type_mismatch INTEGER NOT NULL,
    payload_length INTEGER NOT NULL,
    payload_entropy REAL NOT NULL,
    reflection_count INTEGER NOT NULL,
    reflection_context_id INTEGER NOT NULL,
    special_chars_preserved_ratio REAL NOT NULL,
    has_sql_error_sig INTEGER NOT NULL,
    has_stack_trace_sig INTEGER NOT NULL,
    has_os_cmd_sig INTEGER NOT NULL,
    has_ssrf_cloud_sig INTEGER NOT NULL,
    has_waf_block_sig INTEGER NOT NULL,
    redirected_to_login INTEGER NOT NULL,
    ground_truth_label INTEGER DEFAULT NULL,
    label_source INTEGER DEFAULT 0,
    teacher_confidence REAL DEFAULT NULL,
    teacher_model_ver TEXT DEFAULT NULL,
    student_pred_prob REAL DEFAULT NULL,
    disagreement_score REAL DEFAULT 0.0,
    needs_human_review INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_hot_exact_dedup ON findings_ml_hot(exact_dedup_hash);
CREATE INDEX IF NOT EXISTS idx_hot_ml_export ON findings_ml_hot(ground_truth_label, label_source, host_group_bucket);
CREATE INDEX IF NOT EXISTS idx_hot_active_learning ON findings_ml_hot(needs_human_review, disagreement_score DESC);
CREATE INDEX IF NOT EXISTS idx_hot_rule_filter ON findings_ml_hot(rule_id, http_status_code);

CREATE TABLE IF NOT EXISTS findings_evidence_cold (
    finding_id TEXT PRIMARY KEY REFERENCES findings_ml_hot(finding_id) ON DELETE CASCADE,
    target_endpoint_raw TEXT NOT NULL,
    vulnerable_parameter TEXT,
    injected_payload_raw TEXT,
    stealth_curl_command TEXT NOT NULL,
    zstd_Http_exchange BLOB,
    request_raw_zstd BLOB,
    response_raw_zstd BLOB,
    reflection_snippet_raw TEXT,
    sanitized_snippet_teacher TEXT,
    teacher_reasoning TEXT,
    stix_bundle_json TEXT
);

CREATE TABLE IF NOT EXISTS findings_vec_index (
    finding_id TEXT PRIMARY KEY,
    response_embedding BLOB
);
"""


def get_db_connection(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    target_path = Path(db_path) if db_path is not None else Path(settings.DB_PATH)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    apply_lakehouse_pragmas(conn)
    return conn


def get_archive_db_path() -> Path:
    env_override = os.environ.get("BLACKROUTE_ARCHIVE_DB_PATH")
    if env_override:
        return Path(env_override)
    return Path(settings.ARCHIVE_DB_PATH)


def init_lakehouse_schema(conn: sqlite3.Connection) -> None:
    apply_lakehouse_pragmas(conn)
    if settings.INIT_SQL_PATH.exists():
        sql_text = settings.INIT_SQL_PATH.read_text(encoding="utf-8")
        try:
            conn.executescript(sql_text)
        except sqlite3.OperationalError:
            conn.executescript(LAKEHOUSE_DDL)
    else:
        conn.executescript(LAKEHOUSE_DDL)
    conn.commit()


def init_db(db_path: Optional[Path | str] = None) -> None:
    conn = get_db_connection(db_path)
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

    # Initialize Phase 1 Dual-Path SQLite WAL Lakehouse Schema
    init_lakehouse_schema(conn)
    conn.close()

    target_db = Path(db_path) if db_path is not None else Path(settings.DB_PATH)
    try:
        if os.path.exists(target_db) and not os.path.islink(target_db):
            os.chmod(target_db, 0o600)
    except OSError:
        pass

    # Also ensure dedicated archive lakehouse DB is initialized in WAL mode
    archive_path = get_archive_db_path()
    if archive_path.resolve() != target_db.resolve():
        arch_conn = get_db_connection(archive_path)
        init_lakehouse_schema(arch_conn)
        arch_conn.close()
        try:
            if os.path.exists(archive_path) and not os.path.islink(archive_path):
                os.chmod(archive_path, 0o600)
        except OSError:
            pass


def _archive_scan_to_lakehouse(
    conn: sqlite3.Connection,
    scan_id_str: str,
    target_url: str,
    findings: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]],
    report_file: str = "",
    baseline_meta: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist scan session and 32-feature hot/cold finding pairs into lakehouse tables."""
    _, host_hash, _ = normalize_host_info(target_url)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    base = baseline_meta or {}

    session_meta = {
        "scan_id": scan_id_str,
        "target_root_url": target_url,
        "target_host_hash": host_hash,
        "scan_profile": str(base.get("scan_profile", "full_dast")),
        "scanner_version": str(base.get("scanner_version", "NEXUS-DAST-2.0")),
        "started_at": str(base.get("started_at", now_iso)),
        "completed_at": now_iso,
        "total_requests_sent": max(len(endpoints), len(findings), 1),
        "total_findings_raw": len(findings),
        "baseline_latency_mean_ms": float(base.get("baseline_latency_mean_ms", 42.0)),
        "baseline_latency_std_ms": float(base.get("baseline_latency_std_ms", 5.0)),
        "baseline_404_length": int(base.get("baseline_404_length", 512)),
        "baseline_404_simhash": int(base.get("baseline_404_simhash", 0)),
        "detected_waf_vendor": str(base.get("detected_waf_vendor", "NONE")),
        "raw_sarif_path": report_file or "",
    }
    upsert_scan_session(conn, session_meta)

    for idx, f in enumerate(findings):
        hot, cold, vec_blob = extract_finding_features(
            finding=f,
            scan_id=scan_id_str,
            target_url=target_url,
            baseline=session_meta,
            finding_index=idx,
        )
        upsert_finding_pair(conn, hot, cold, vec_blob)


def save_scan_record(
    target_url: str,
    findings: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]] = None,
    pages_crawled: int = 0,
    report_file: str = "",
    status: str = "completed",
    risk_score: int = 0,
    baseline_meta: Optional[Dict[str, Any]] = None,
) -> int:
    """Persist scan results, findings, and discovered endpoints into SQLite + Dual-Path Lakehouse."""
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

    scan_id_str = f"SCAN-{scan_id:06d}"
    _archive_scan_to_lakehouse(
        conn=conn,
        scan_id_str=scan_id_str,
        target_url=target_url,
        findings=findings,
        endpoints=endpoints,
        report_file=report_file,
        baseline_meta=baseline_meta,
    )

    conn.commit()
    conn.close()

    # Mirror lakehouse records to dedicated archive database if separate
    archive_path = get_archive_db_path()
    if archive_path.resolve() != Path(settings.DB_PATH).resolve():
        try:
            arch_conn = get_db_connection(archive_path)
            _archive_scan_to_lakehouse(
                conn=arch_conn,
                scan_id_str=scan_id_str,
                target_url=target_url,
                findings=findings,
                endpoints=endpoints,
                report_file=report_file,
                baseline_meta=baseline_meta,
            )
            arch_conn.commit()
            arch_conn.close()
        except Exception:
            pass

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
    cursor.execute("UPDATE scan_sessions SET raw_sarif_path = ? WHERE scan_id = ?", (report_file, f"SCAN-{scan_id:06d}"))
    conn.commit()
    conn.close()
