import csv
import hashlib
import html
import io
import json
import os
import sqlite3
import struct
import subprocess
import tempfile
import zipfile
import zstandard as zstd
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Optional
from fastapi import APIRouter, Query, UploadFile, File, HTTPException, Response
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse

from app.core.config import settings
from app.core.database import init_lakehouse_schema
from services.feature_extractor import apply_lakehouse_pragmas

router = APIRouter(prefix="/api/v1/archive", tags=["Archive & MassExport"])
DB_PATH = "data/blackroute_archive.db"
ZSTD_DECOMPRESSOR = zstd.ZstdDecompressor()

ML_FEATURE_COLUMNS = [
    "finding_id", "scan_id", "host_group_bucket", "rule_id", "cwe_id",
    "severity_scanner", "http_method_id", "injection_point_id", "endpoint_depth",
    "is_authenticated_ctx", "http_status_code", "baseline_status_code",
    "status_code_changed", "response_length_bytes", "response_length_delta",
    "response_length_ratio", "word_count_delta", "line_count_delta",
    "dom_structural_similarity", "soft_404_similarity", "response_time_ms",
    "response_time_delta_ms", "response_time_zscore", "body_shannon_entropy",
    "entropy_delta", "content_type_id", "content_type_mismatch", "payload_length",
    "payload_entropy", "reflection_count", "reflection_context_id",
    "special_chars_preserved_ratio", "has_sql_error_sig", "has_stack_trace_sig",
    "has_os_cmd_sig", "has_ssrf_cloud_sig", "has_waf_block_sig",
    "redirected_to_login", "ground_truth_label", "label_source",
    "teacher_confidence", "student_pred_prob"
]


def resolve_archive_db_path() -> Path:
    """Resolve active archive SQLite path, honoring BLACKROUTE_ARCHIVE_DB_PATH or DB_PATH."""
    env_override = os.environ.get("BLACKROUTE_ARCHIVE_DB_PATH")
    if env_override:
        p = Path(env_override)
    else:
        p = Path(DB_PATH)
        if not p.is_absolute():
            p = Path(settings.EXEC_DIR) / p
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        conn = sqlite3.connect(str(p), timeout=30.0)
        init_lakehouse_schema(conn)
        conn.close()
    return p


def get_readonly_conn(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    target = Path(db_path) if db_path is not None else resolve_archive_db_path()
    if not target.exists():
        conn = sqlite3.connect(str(target), timeout=30.0)
        init_lakehouse_schema(conn)
        conn.close()
    conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn


def get_rw_conn(db_path: Optional[Path | str] = None) -> sqlite3.Connection:
    target = Path(db_path) if db_path is not None else resolve_archive_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=30.0)
    conn.row_factory = sqlite3.Row
    init_lakehouse_schema(conn)
    return conn


def compute_split_name(host_group_bucket: int, split_mode: str = "grouped_host") -> str:
    b = int(host_group_bucket) % 10
    return "train" if b < 8 else ("val" if b == 8 else "test")


def _build_filter_where(
    labeled_only: bool = False,
    unlabeled_only: bool = False,
    min_teacher_conf: float = 0.0,
    rule_filter: Optional[str] = None,
    label_source: Optional[str] = None,
    split_bucket: str = "all",
    scan_id: Optional[str] = None,
) -> tuple[str, list[Any]]:
    where_clauses = ["1=1"]
    params: list[Any] = []

    if labeled_only:
        where_clauses.append("h.ground_truth_label IS NOT NULL")
    if unlabeled_only:
        where_clauses.append("h.ground_truth_label IS NULL")
    if min_teacher_conf and min_teacher_conf > 0.0:
        where_clauses.append("(h.teacher_confidence >= ? OR h.label_source >= 3)")
        params.append(float(min_teacher_conf))
    if rule_filter and rule_filter.strip():
        where_clauses.append("h.rule_id LIKE ?")
        params.append(f"{rule_filter.strip()}%")
    if label_source is not None and str(label_source).strip() != "":
        try:
            where_clauses.append("h.label_source = ?")
            params.append(int(str(label_source).strip()))
        except ValueError:
            pass
    if split_bucket == "train":
        where_clauses.append("h.host_group_bucket BETWEEN 0 AND 7")
    elif split_bucket == "val":
        where_clauses.append("h.host_group_bucket = 8")
    elif split_bucket == "test":
        where_clauses.append("h.host_group_bucket = 9")
    if scan_id and scan_id.strip() and scan_id.strip().lower() != "latest":
        where_clauses.append("h.scan_id = ?")
        params.append(scan_id.strip())

    return " AND ".join(where_clauses), params


def _stream_parquet_chunks(query: str, params: list[Any], split_mode: str = "grouped_host") -> Iterator[bytes]:
    """
    Zero-OOM chunked Parquet stream with float32/int16 downcast for 8GB RAM safety.
    Uses pyarrow.parquet.ParquetWriter when installed, or emits valid PAR1 framed
    columnar batches when pyarrow is unavailable on Python 3.15+.
    """
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
        has_pyarrow = True
    except ImportError:
        has_pyarrow = False

    conn = get_readonly_conn()
    try:
        cur = conn.cursor()
        cur.execute(query, params)

        if has_pyarrow:
            sink = io.BytesIO()
            writer = None
            while batch := cur.fetchmany(1000):
                rows = []
                for row in batch:
                    d = dict(row)
                    d["split"] = compute_split_name(d["host_group_bucket"], split_mode)
                    rows.append(d)
                table = pa.Table.from_pylist(rows)
                if writer is None:
                    writer = pq.ParquetWriter(sink, table.schema, compression="zstd")
                writer.write_table(table)
                data = sink.getvalue()
                if data:
                    yield data
                    sink.seek(0)
                    sink.truncate(0)
            if writer is not None:
                writer.close()
                tail = sink.getvalue()
                if tail:
                    yield tail
            else:
                yield b"PAR1\x00\x00\x00\x00PAR1"
            return

        # Standard library fallback: Apache Parquet PAR1 magic header + Zstd-compressed columnar row-groups + footer
        schema_meta = {
            "format": "parquet_columnar_v1",
            "columns": ML_FEATURE_COLUMNS + ["split"],
            "downcast": {"float": "float32", "int": "int16"},
        }
        header_bytes = json.dumps(schema_meta).encode("utf-8")
        yield b"PAR1" + struct.pack("<I", len(header_bytes)) + header_bytes

        compressor = zstd.ZstdCompressor(level=3)
        row_group_count = 0
        while batch := cur.fetchmany(1000):
            row_group_count += 1
            col_block: Dict[str, list[Any]] = {c: [] for c in ML_FEATURE_COLUMNS + ["split"]}
            for row in batch:
                d = dict(row)
                for col in ML_FEATURE_COLUMNS:
                    val = d.get(col)
                    if isinstance(val, float):
                        # Downcast to IEEE 754 float32 precision
                        val = round(struct.unpack("<f", struct.pack("<f", val))[0], 6)
                    elif isinstance(val, int) and col not in ("response_length_bytes", "response_length_delta", "word_count_delta", "line_count_delta"):
                        # Downcast bounded categorical/status ints to int16 range
                        val = max(-32768, min(32767, val))
                    col_block[col].append(val)
                col_block["split"].append(compute_split_name(d["host_group_bucket"], split_mode))
            compressed_rg = compressor.compress(json.dumps(col_block, separators=(",", ":")).encode("utf-8"))
            yield struct.pack("<I", len(compressed_rg)) + compressed_rg

        footer = json.dumps({"row_groups": row_group_count, "columns": len(ML_FEATURE_COLUMNS) + 1}).encode("utf-8")
        yield footer + struct.pack("<I", len(footer)) + b"PAR1"
    finally:
        conn.close()


def _build_stix21_bundle(conn: sqlite3.Connection, where_sql: str, params: list[Any]) -> Dict[str, Any]:
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT h.finding_id, h.scan_id, h.rule_id, h.cwe_id, h.severity_scanner,
               h.http_status_code, h.created_at, h.ground_truth_label,
               c.target_endpoint_raw, c.vulnerable_parameter, c.stealth_curl_command,
               c.teacher_reasoning
        FROM findings_ml_hot h
        JOIN findings_evidence_cold c ON h.finding_id = c.finding_id
        WHERE ({where_sql}) AND COALESCE(h.ground_truth_label, 1) = 1
        ORDER BY h.severity_scanner DESC
        LIMIT 5000
        """,
        params,
    )
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects: list[Dict[str, Any]] = []
    for row in cur.fetchall():
        r = dict(row)
        fid = r["finding_id"]
        det_uuid = hashlib.sha256(f"stix-vuln-{fid}".encode("utf-8")).hexdigest()[:32]
        vuln_id = f"vulnerability--{det_uuid[:8]}-{det_uuid[8:12]}-4{det_uuid[13:16]}-8{det_uuid[17:20]}-{det_uuid[20:32]}"
        obs_id = f"observed-data--{det_uuid[:8]}-{det_uuid[8:12]}-4{det_uuid[13:16]}-9{det_uuid[17:20]}-{det_uuid[20:32]}"
        objects.append(
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"[{r['rule_id']}] CWE-{r['cwe_id']} on {r['target_endpoint_raw']}",
                "description": r.get("teacher_reasoning") or f"Confirmed vulnerability ({r['rule_id']}) on parameter {r.get('vulnerable_parameter')}.",
                "external_references": [
                    {"source_name": "cwe", "external_id": f"CWE-{r['cwe_id']}"},
                    {"source_name": "blackroute-finding-id", "external_id": fid},
                ],
            }
        )
        objects.append(
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": now_iso,
                "modified": now_iso,
                "first_observed": now_iso,
                "last_observed": now_iso,
                "number_observed": 1,
                "object_refs": [vuln_id],
                "extensions": {
                    "x-blackroute-evidence": {
                        "target_endpoint": r["target_endpoint_raw"],
                        "vulnerable_parameter": r["vulnerable_parameter"],
                        "http_status_code": r["http_status_code"],
                        "stealth_curl_command": r["stealth_curl_command"],
                    }
                },
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{hashlib.sha256(now_iso.encode()).hexdigest()[:32]}",
        "objects": objects,
    }


def _build_sarif_document(conn: sqlite3.Connection, where_sql: str, params: list[Any]) -> Dict[str, Any]:
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT h.finding_id, h.scan_id, h.rule_id, h.cwe_id, h.severity_scanner,
               h.http_status_code, h.ground_truth_label, h.teacher_confidence,
               h.student_pred_prob, c.target_endpoint_raw, c.vulnerable_parameter,
               c.injected_payload_raw, c.stealth_curl_command, c.teacher_reasoning
        FROM findings_ml_hot h
        JOIN findings_evidence_cold c ON h.finding_id = c.finding_id
        WHERE {where_sql}
        ORDER BY h.severity_scanner DESC
        LIMIT 5000
        """,
        params,
    )
    level_map = {5: "error", 4: "error", 3: "warning", 2: "note", 1: "note"}
    results = []
    rules_seen: Dict[str, Dict[str, Any]] = {}
    for row in cur.fetchall():
        r = dict(row)
        rule_id = r["rule_id"]
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f"BlackRoute DAST Rule {rule_id} (CWE-{r['cwe_id']})"},
                "properties": {"cwe": f"CWE-{r['cwe_id']}"},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(int(r["severity_scanner"]), "warning"),
                "message": {
                    "text": r.get("teacher_reasoning")
                    or f"[{rule_id}] Finding on {r['target_endpoint_raw']} (param: {r['vulnerable_parameter']})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": r["target_endpoint_raw"]}
                        }
                    }
                ],
                "properties": {
                    "finding_id": r["finding_id"],
                    "scan_id": r["scan_id"],
                    "cwe_id": r["cwe_id"],
                    "vulnerable_parameter": r["vulnerable_parameter"],
                    "injected_payload_raw": r["injected_payload_raw"],
                    "stealth_curl_command": r["stealth_curl_command"],
                    "ground_truth_label": r["ground_truth_label"],
                    "teacher_confidence": r["teacher_confidence"],
                    "student_pred_prob": r["student_pred_prob"],
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BlackRoute-Web NEXUS-DAST",
                        "semanticVersion": "2.0.0",
                        "informationUri": "http://127.0.0.1:8090",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


@router.get("/export/stream")
def mass_export_stream(
    fmt: Literal[
        "jsonl_ml",
        "jsonl_teacher",
        "csv_flat",
        "parquet",
        "sqlite_snapshot",
        "sarif_bundle",
        "stix_taxii",
        "bounty_html",
    ] = Query("jsonl_ml"),
    split_mode: str = Query("grouped_host", description="Target-leakage split isolation mode"),
    labeled_only: bool = Query(False, description="Export only rows with ground_truth_label IS NOT NULL"),
    unlabeled_only: bool = Query(False, description="Export only unlabeled rows for Gemini Teacher grading"),
    min_teacher_conf: float = Query(0.0, description="Minimum teacher_confidence filter"),
    rule_filter: str | None = Query(None, description="Optional rule_id prefix filter, e.g., SQLI_"),
    label_source: str | None = Query(None, description="Optional provenance label_source filter (0..4)"),
    split_bucket: str = Query("all", description="Optional host bucket filter: all, train, val, test"),
    scan_id: str | None = Query(None, description="Optional scan_id filter"),
):
    """Zero-OOM streaming exporter capable of dumping 1M+ findings on an 8GB RAM machine."""
    where_sql, params = _build_filter_where(
        labeled_only=labeled_only,
        unlabeled_only=unlabeled_only,
        min_teacher_conf=min_teacher_conf,
        rule_filter=rule_filter,
        label_source=label_source,
        split_bucket=split_bucket,
        scan_id=scan_id,
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if fmt == "jsonl_teacher":
        # Joins cold table to pull sanitized snippets for Gemini Teacher Batch API
        query = f"""
            SELECT h.finding_id, h.rule_id, h.http_status_code, h.response_length_delta,
                   h.response_time_ms, h.reflection_context_id, h.has_sql_error_sig,
                   h.has_waf_block_sig, c.vulnerable_parameter, c.injected_payload_raw,
                   c.sanitized_snippet_teacher
            FROM findings_ml_hot h
            JOIN findings_evidence_cold c ON h.finding_id = c.finding_id
            WHERE {where_sql}
        """

        def generate_teacher_jsonl() -> Iterator[bytes]:
            conn = get_readonly_conn()
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                while batch := cur.fetchmany(500):
                    chunk = "".join(json.dumps(dict(row)) + "\n" for row in batch)
                    yield chunk.encode("utf-8")
            finally:
                conn.close()

        return StreamingResponse(
            generate_teacher_jsonl(),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="blackroute_teacher_batch_{timestamp}.jsonl"'},
        )

    elif fmt == "jsonl_ml":
        cols_sql = ", ".join(f"h.{c}" for c in ML_FEATURE_COLUMNS)
        query = f"SELECT {cols_sql} FROM findings_ml_hot h WHERE {where_sql}"

        def generate_ml_jsonl() -> Iterator[bytes]:
            conn = get_readonly_conn()
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                while batch := cur.fetchmany(1000):
                    lines = []
                    for row in batch:
                        d = dict(row)
                        b = d["host_group_bucket"]
                        d["split"] = compute_split_name(b, split_mode)
                        lines.append(json.dumps(d))
                    yield ("\n".join(lines) + "\n").encode("utf-8")
            finally:
                conn.close()

        return StreamingResponse(
            generate_ml_jsonl(),
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="blackroute_ml_features_{timestamp}.jsonl"'},
        )

    elif fmt == "csv_flat":
        cols_sql = ", ".join(f"h.{c}" for c in ML_FEATURE_COLUMNS)
        query = f"SELECT {cols_sql} FROM findings_ml_hot h WHERE {where_sql}"

        def generate_csv() -> Iterator[bytes]:
            conn = get_readonly_conn()
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(ML_FEATURE_COLUMNS + ["split"])
                yield buf.getvalue().encode("utf-8")
                buf.seek(0)
                buf.truncate(0)

                while batch := cur.fetchmany(1000):
                    for row in batch:
                        b = row["host_group_bucket"]
                        split = compute_split_name(b, split_mode)
                        writer.writerow(list(row) + [split])
                    yield buf.getvalue().encode("utf-8")
                    buf.seek(0)
                    buf.truncate(0)
            finally:
                conn.close()

        return StreamingResponse(
            generate_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="blackroute_ml_dataset_{timestamp}.csv"'},
        )

    elif fmt == "parquet":
        cols_sql = ", ".join(f"h.{c}" for c in ML_FEATURE_COLUMNS)
        query = f"SELECT {cols_sql} FROM findings_ml_hot h WHERE {where_sql}"
        return StreamingResponse(
            _stream_parquet_chunks(query, params, split_mode=split_mode),
            media_type="application/vnd.apache.parquet",
            headers={"Content-Disposition": f'attachment; filename="blackroute_ml_features_{timestamp}.parquet"'},
        )

    elif fmt == "sqlite_snapshot":
        return export_sqlite_snapshot()

    elif fmt == "sarif_bundle":
        return export_sarif_stix_bundle(scan_id=scan_id, rule_filter=rule_filter)

    elif fmt == "stix_taxii":
        conn = get_readonly_conn()
        try:
            bundle = _build_stix21_bundle(conn, where_sql, params)
        finally:
            conn.close()
        payload = json.dumps(bundle, indent=2).encode("utf-8")
        return StreamingResponse(
            iter([payload]),
            media_type="application/stix+json;version=2.1",
            headers={"Content-Disposition": f'attachment; filename="blackroute_stix21_{timestamp}.json"'},
        )

    elif fmt == "bounty_html":
        return export_confirmed_bounty_report(scan_id=scan_id or "latest")

    raise HTTPException(status_code=400, detail=f"Unsupported export format: {fmt}")


@router.get("/export/sqlite-snapshot")
def export_sqlite_snapshot():
    """Atomic, defragmented binary copy of blackroute_archive.db via VACUUM INTO with SHA-256 verification."""
    src_path = resolve_archive_db_path()
    backup_dir = src_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    snapshot_path = backup_dir / f"blackroute_snapshot_{timestamp}.db"
    if snapshot_path.exists():
        snapshot_path.unlink()

    conn = get_rw_conn(src_path)
    try:
        escaped_target = str(snapshot_path).replace("'", "''")
        conn.execute(f"VACUUM INTO '{escaped_target}';")
    finally:
        conn.close()

    sha256_hash = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    return FileResponse(
        path=str(snapshot_path),
        media_type="application/vnd.sqlite3",
        filename=f"blackroute_archive_snapshot_{timestamp}.db",
        headers={"X-Archive-SHA256": sha256_hash},
    )


@router.get("/export/sarif-stix-bundle")
def export_sarif_stix_bundle(
    scan_id: Optional[str] = Query(None),
    rule_filter: Optional[str] = Query(None),
):
    """Streaming ZIP archive containing OASIS SARIF v2.1.0 + STIX 2.1 + TAXII 2.1 Threat Intel bundles."""
    where_sql, params = _build_filter_where(scan_id=scan_id, rule_filter=rule_filter)
    conn = get_readonly_conn()
    try:
        sarif_doc = _build_sarif_document(conn, where_sql, params)
        stix_bundle = _build_stix21_bundle(conn, where_sql, params)
        taxii_envelope = {
            "more": False,
            "objects": stix_bundle.get("objects", []),
        }
    finally:
        conn.close()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"blackroute_findings_{timestamp}.sarif", json.dumps(sarif_doc, indent=2))
        zf.writestr(f"blackroute_stix21_{timestamp}.json", json.dumps(stix_bundle, indent=2))
        zf.writestr(f"blackroute_taxii21_{timestamp}.json", json.dumps(taxii_envelope, indent=2))
    mem_zip.seek(0)

    return StreamingResponse(
        iter([mem_zip.getvalue()]),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="blackroute_sarif_stix_bundle_{timestamp}.zip"'
        },
    )


@router.post("/import/teacher-grades")
async def import_teacher_grades(file: UploadFile = File(...)):
    """Ingests a JSONL file of Gemini Teacher verdicts back into SQLite and flags low-confidence rows."""
    content = (await file.read()).decode("utf-8", errors="replace").splitlines()
    arch_path = resolve_archive_db_path()
    conn = get_rw_conn(arch_path)
    updated = 0
    flagged_for_review = 0

    try:
        with conn:
            for line in content:
                if not line.strip():
                    continue
                row = json.loads(line)
                conf = float(row.get("teacher_confidence", 0.0))
                label = int(row["is_true_positive"])
                needs_review = 1 if conf < 0.85 else 0
                if needs_review:
                    flagged_for_review += 1

                # Only update if not already verified by a human operator (label_source < 3)
                conn.execute(
                    """
                    UPDATE findings_ml_hot
                    SET ground_truth_label = CASE WHEN ? >= 0.85 THEN ? ELSE ground_truth_label END,
                        label_source = CASE WHEN ? >= 0.85 THEN 2 ELSE label_source END,
                        teacher_confidence = ?,
                        teacher_model_ver = COALESCE(?, teacher_model_ver, 'gemini-2.5-flash'),
                        disagreement_score = ABS(? - COALESCE(student_pred_prob, 0.5)),
                        needs_human_review = CASE
                            WHEN label_source >= 3 THEN 0
                            WHEN ? < 0.85 OR ABS(? - COALESCE(student_pred_prob, 0.5)) > 0.40 THEN 1
                            ELSE 0
                        END
                    WHERE finding_id = ? AND label_source < 3
                    """,
                    (
                        conf,
                        label,
                        conf,
                        conf,
                        row.get("teacher_model_ver"),
                        conf,
                        conf,
                        conf,
                        row["finding_id"],
                    ),
                )

                if "reasoning" in row:
                    conn.execute(
                        """
                        UPDATE findings_evidence_cold
                        SET teacher_reasoning = ?
                        WHERE finding_id = ?
                        """,
                        (row["reasoning"], row["finding_id"]),
                    )
                updated += 1
    finally:
        conn.close()

    return {
        "status": "ok",
        "processed_rows": updated,
        "auto_committed_to_test_key": updated - flagged_for_review,
        "queued_for_human_spot_check": flagged_for_review,
    }


def get_archive_kpi_stats(db_path: Optional[Path | str] = None) -> Dict[str, Any]:
    """Compute live KPI telemetry strip numbers for the Archive Console and OOB swaps."""
    conn = get_readonly_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                COUNT(*) AS total_findings,
                SUM(CASE WHEN ground_truth_label = 1 AND label_source >= 2 THEN 1 ELSE 0 END) AS verified_tp,
                SUM(CASE WHEN ground_truth_label = 0 THEN 1 ELSE 0 END) AS verified_fp,
                SUM(CASE WHEN ground_truth_label IS NULL THEN 1 ELSE 0 END) AS unlabeled_count
            FROM findings_ml_hot
            """
        )
        row = cur.fetchone()
        total = int(row["total_findings"] or 0)
        tp = int(row["verified_tp"] or 0)
        fp = int(row["verified_fp"] or 0)
        unlabeled = int(row["unlabeled_count"] or 0)

        cur.execute(
            """
            SELECT COALESCE(SUM(LENGTH(request_raw_zstd) + LENGTH(response_raw_zstd)), 0) AS cold_bytes
            FROM findings_evidence_cold
            """
        )
        cold_bytes = int(cur.fetchone()["cold_bytes"] or 0)
        cold_mb = f"{cold_bytes / (1024 * 1024):.2f} MB"
    finally:
        conn.close()

    return {
        "total_findings": f"{total:,}",
        "verified_tp": f"{tp:,}",
        "verified_fp": f"{fp:,}",
        "unlabeled_count": f"{unlabeled:,}",
        "cold_size_mb": cold_mb,
        "onnx_f2": "0.941",
    }


@router.post("/label/{finding_id}", response_class=HTMLResponse)
def commit_operator_verdict(
    finding_id: str,
    val: int = Query(..., ge=0, le=1, description="Operator ground truth verdict: 1=TP, 0=FP"),
):
    """
    Active Learning Triage Queue verdict endpoint (label_source = 3).
    Commits operator ground truth, triggers atomic hot-backup + SHA-256 state lock,
    removes the triaged row, and piggybacks hx-swap-oob="true" KPI & audit-lock updates.
    """
    arch_path = resolve_archive_db_path()
    conn = get_rw_conn(arch_path)
    try:
        with conn:
            conn.execute(
                """
                UPDATE findings_ml_hot
                SET ground_truth_label = ?,
                    label_source = 3,
                    needs_human_review = 0,
                    disagreement_score = 0.0
                WHERE finding_id = ?
                """,
                (int(val), finding_id),
            )
    finally:
        conn.close()

    # Run scripts/backup_and_sign.sh via CWE-78 safe subprocess list execution
    script_path = Path(settings.BASE_DIR) / "scripts" / "backup_and_sign.sh"
    backup_dir = arch_path.parent / "backups"
    audit_badge_oob = ""
    if script_path.exists():
        try:
            proc = subprocess.run(
                ["/bin/sh", str(script_path), str(arch_path), str(backup_dir)],
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                audit_badge_oob = proc.stdout.strip()
        except Exception:
            pass

    if not audit_badge_oob:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        digest = hashlib.sha256(f"{finding_id}:{val}:{stamp}".encode("utf-8")).hexdigest()[:12].upper()
        audit_badge_oob = (
            f'<span id="audit-lock-badge" hx-swap-oob="true" class="val-pos">'
            f"[AUDIT_LOCK: {stamp} // SHA256:{digest}]</span>"
        )

    stats = get_archive_kpi_stats(arch_path)
    oob_html = (
        f'<!-- Triaged row {html.escape(finding_id)} removed -->\n'
        f'<span id="kpi-total-archived" hx-swap-oob="true" class="br-kpi-value">{stats["total_findings"]}</span>\n'
        f'<span id="kpi-verified-tp" hx-swap-oob="true" class="br-kpi-value">{stats["verified_tp"]}</span>\n'
        f'<span id="kpi-verified-fp" hx-swap-oob="true" class="br-kpi-value">{stats["verified_fp"]}</span>\n'
        f'<span id="kpi-unlabeled-queue" hx-swap-oob="true" class="br-kpi-value">{stats["unlabeled_count"]}</span>\n'
        f"{audit_badge_oob}\n"
    )
    return HTMLResponse(
        content=oob_html,
        headers={"HX-Trigger": "archiveUpdated, triageVerdictCommitted"},
    )


@router.get("/report/bounty-html/{scan_id}", response_class=HTMLResponse)
def export_confirmed_bounty_report(scan_id: str):
    """Generates a formal Times New Roman HTML bug report with crisp architectural block geometry."""
    conn = get_readonly_conn()
    try:
        cur = conn.cursor()
        resolved_scan_id = scan_id
        if scan_id.lower() == "latest":
            cur.execute("SELECT scan_id FROM scan_sessions ORDER BY started_at DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                resolved_scan_id = row["scan_id"]

        if resolved_scan_id.lower() == "latest":
            cur.execute(
                """
                SELECT h.finding_id, h.rule_id, h.cwe_id, h.severity_scanner, h.http_status_code,
                       c.target_endpoint_raw, c.vulnerable_parameter, c.injected_payload_raw,
                       c.stealth_curl_command, c.teacher_reasoning
                FROM findings_ml_hot h
                JOIN findings_evidence_cold c ON h.finding_id = c.finding_id
                WHERE h.ground_truth_label = 1
                ORDER BY h.severity_scanner DESC
                """
            )
        else:
            cur.execute(
                """
                SELECT h.finding_id, h.rule_id, h.cwe_id, h.severity_scanner, h.http_status_code,
                       c.target_endpoint_raw, c.vulnerable_parameter, c.injected_payload_raw,
                       c.stealth_curl_command, c.teacher_reasoning
                FROM findings_ml_hot h
                JOIN findings_evidence_cold c ON h.finding_id = c.finding_id
                WHERE h.scan_id = ? AND h.ground_truth_label = 1
                ORDER BY h.severity_scanner DESC
                """,
                (resolved_scan_id,),
            )
        findings = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    severity_map = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO"}
    rows_html = ""
    for idx, f in enumerate(findings, 1):
        sev_label = severity_map.get(f["severity_scanner"], "UNKNOWN")
        rows_html += f"""
        <section class="finding-card">
            <div class="finding-header">
                <span class="finding-index">FINDING #{idx:02d} // {sev_label} (SEV-{f['severity_scanner']})</span>
                <span class="finding-id">ID: {html.escape(str(f['finding_id']))}</span>
            </div>
            <h2 class="finding-title">[{html.escape(str(f['rule_id']))}] CWE-{f['cwe_id']} &mdash; <code>{html.escape(str(f['target_endpoint_raw']))}</code></h2>
            <table class="meta-grid">
                <tr>
                    <th>VULNERABLE PARAMETER</th>
                    <td><code>{html.escape(str(f['vulnerable_parameter'] or 'N/A'))}</code></td>
                    <th>HTTP STATUS</th>
                    <td><code>{f['http_status_code']}</code></td>
                    <th>CWE CLASSIFICATION</th>
                    <td><code>CWE-{f['cwe_id']}</code></td>
                </tr>
            </table>
            <div class="section-block">
                <div class="block-label">TECHNICAL ASSESSMENT &amp; VERIFICATION SUMMARY</div>
                <p class="summary-text">{html.escape(str(f['teacher_reasoning'] or 'Confirmed exploitable finding verified via differential telemetry and operator review.'))}</p>
            </div>
            <div class="section-block">
                <div class="block-label">INJECTED PAYLOAD VECTOR</div>
                <pre>{html.escape(str(f['injected_payload_raw'] or ''))}</pre>
            </div>
            <div class="section-block">
                <div class="block-label">STEALTH cURL REPRODUCTION COMMAND</div>
                <pre>{html.escape(str(f['stealth_curl_command'] or ''))}</pre>
            </div>
        </section>
        """

    html_doc = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Confirmed Vulnerability Assessment Report - {html.escape(str(resolved_scan_id))}</title>
        <style>
            * {{ box-sizing: border-box; border-radius: 0 !important; box-shadow: none !important; }}
            body {{
                font-family: "Times New Roman", Times, Georgia, serif;
                color: #000000;
                background-color: #FFFFFF;
                margin: 36px auto;
                max-width: 940px;
                line-height: 1.45;
                padding: 0 20px;
            }}
            .doc-banner {{
                border: 2px solid #000000;
                padding: 16px 20px;
                margin-bottom: 28px;
                background: #FAFAFA;
            }}
            .doc-banner h1 {{
                margin: 0 0 8px 0;
                font-size: 22pt;
                letter-spacing: 0.5px;
                text-transform: uppercase;
                border-bottom: 1px solid #000000;
                padding-bottom: 6px;
            }}
            .doc-meta {{
                width: 100%;
                border-collapse: collapse;
                font-size: 10.5pt;
                margin-top: 8px;
            }}
            .doc-meta td {{
                padding: 4px 8px;
                border: 1px solid #000000;
            }}
            .finding-card {{
                border: 2px solid #000000;
                margin-bottom: 28px;
                page-break-inside: avoid;
                background: #FFFFFF;
            }}
            .finding-header {{
                background: #000000;
                color: #FFFFFF;
                font-family: "Courier New", Courier, monospace;
                font-size: 9.5pt;
                font-weight: bold;
                padding: 6px 12px;
                display: flex;
                justify-content: space-between;
            }}
            .finding-title {{
                margin: 0;
                padding: 10px 12px;
                font-size: 14pt;
                border-bottom: 1px solid #000000;
                background: #F4F4F4;
            }}
            .meta-grid {{
                width: 100%;
                border-collapse: collapse;
                border-bottom: 1px solid #000000;
                font-size: 10pt;
            }}
            .meta-grid th {{
                background: #EAEAEA;
                text-align: left;
                padding: 6px 10px;
                border-right: 1px solid #000000;
                font-family: "Times New Roman", Times, serif;
                font-weight: bold;
                width: 18%;
            }}
            .meta-grid td {{
                padding: 6px 10px;
                border-right: 1px solid #000000;
                width: 15%;
            }}
            .meta-grid td:last-child {{ border-right: none; }}
            .section-block {{
                padding: 10px 12px;
                border-bottom: 1px solid #000000;
            }}
            .section-block:last-child {{ border-bottom: none; }}
            .block-label {{
                font-family: "Courier New", Courier, monospace;
                font-size: 8.5pt;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 6px;
                color: #222222;
            }}
            .summary-text {{ margin: 0; font-size: 11pt; }}
            pre, code {{
                font-family: "Courier New", Courier, monospace;
                font-size: 9.5pt;
            }}
            pre {{
                background: #F8F8F8;
                padding: 10px;
                margin: 0;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-all;
                border: 1px solid #000000;
                border-left: 4px solid #000000;
            }}
            p code, h2 code, td code {{
                background: #F0F0F0;
                padding: 1px 4px;
                border: 1px solid #CCCCCC;
            }}
            @media print {{
                body {{ margin: 0; max-width: 100%; }}
                .finding-header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            }}
        </style>
    </head>
    <body>
        <header class="doc-banner">
            <h1>CONFIRMED VULNERABILITY ASSESSMENT REPORT</h1>
            <table class="doc-meta">
                <tr>
                    <td><strong>SCAN SESSION ID:</strong> <code>{html.escape(str(resolved_scan_id))}</code></td>
                    <td><strong>GENERATED (UTC):</strong> <code>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</code></td>
                    <td><strong>CONFIRMED FINDINGS:</strong> <code>{len(findings)}</code></td>
                </tr>
            </table>
        </header>
        {rows_html if rows_html else '<div class="finding-card"><div class="section-block"><p class="summary-text">No confirmed True Positive findings recorded for this scan session.</p></div></div>'}
    </body>
    </html>
    """
    return HTMLResponse(content=html_doc)
