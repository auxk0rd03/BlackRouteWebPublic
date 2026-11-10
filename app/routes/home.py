import html
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import zstandard as zstd
from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from app.core.config import resource_path, settings
from routes.archive_api import (
    _build_filter_where,
    get_archive_kpi_stats,
    get_readonly_conn,
    resolve_archive_db_path,
)

router = APIRouter()
templates = Jinja2Templates(directory=resource_path("app/templates"))
ZSTD_DECOMPRESSOR = zstd.ZstdDecompressor()


def _generate_flat_bucket_svg(db_path: Optional[Path] = None) -> str:
    """
    Server-side flat <svg> telemetry generator showing Train (0..7) / Val (8) / Test (9)
    host bucket distribution with 0px border-radius and tabular monospace labels.
    """
    conn = get_readonly_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                SUM(CASE WHEN host_group_bucket BETWEEN 0 AND 7 THEN 1 ELSE 0 END) AS train_cnt,
                SUM(CASE WHEN host_group_bucket = 8 THEN 1 ELSE 0 END) AS val_cnt,
                SUM(CASE WHEN host_group_bucket = 9 THEN 1 ELSE 0 END) AS test_cnt,
                COUNT(*) AS total_cnt
            FROM findings_ml_hot
            """
        )
        row = cur.fetchone()
        train_cnt = int(row["train_cnt"] or 0)
        val_cnt = int(row["val_cnt"] or 0)
        test_cnt = int(row["test_cnt"] or 0)
        total_cnt = max(int(row["total_cnt"] or 0), 1)
    finally:
        conn.close()

    train_pct = round((train_cnt / total_cnt) * 100.0, 1) if (train_cnt + val_cnt + test_cnt) > 0 else 80.0
    val_pct = round((val_cnt / total_cnt) * 100.0, 1) if (train_cnt + val_cnt + test_cnt) > 0 else 10.0
    test_pct = round(max(0.0, 100.0 - train_pct - val_pct), 1)

    bar_width = 600
    train_w = int(round((train_pct / 100.0) * bar_width))
    val_w = int(round((val_pct / 100.0) * bar_width))
    test_w = max(0, bar_width - train_w - val_w)

    return (
        f'<span class="val-pos">[GROUPED_HOST SPLIT TELEMETRY // TRAIN(0..7): {train_cnt:,} ({train_pct:.1f}%) '
        f'| VAL(8): {val_cnt:,} ({val_pct:.1f}%) | TEST(9): {test_cnt:,} ({test_pct:.1f}%)]</span>'
        f'<svg width="604" height="16" viewBox="0 0 604 16" xmlns="http://www.w3.org/2000/svg" '
        f'style="border:1px solid #CC0000; background:#000000; display:inline-block; vertical-align:middle;">'
        f'<rect x="1" y="1" width="{train_w}" height="14" fill="#CC0000" />'
        f'<rect x="{1 + train_w}" y="1" width="{val_w}" height="14" fill="#FF6600" />'
        f'<rect x="{1 + train_w + val_w}" y="1" width="{test_w}" height="14" fill="#3D0000" />'
        f'</svg>'
    )


def _fetch_preview_rows(
    rule_filter: Optional[str] = None,
    label_source: Optional[str] = None,
    min_teacher_conf: float = 0.0,
    split_bucket: str = "all",
    scan_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    where_sql, params = _build_filter_where(
        min_teacher_conf=min_teacher_conf,
        rule_filter=rule_filter,
        label_source=label_source,
        split_bucket=split_bucket,
        scan_id=scan_id,
    )
    conn = get_readonly_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT finding_id, rule_id, cwe_id, host_group_bucket, http_status_code,
                   response_length_delta, response_time_zscore, dom_structural_similarity,
                   teacher_confidence, student_pred_prob, ground_truth_label
            FROM findings_ml_hot h
            WHERE {where_sql}
            ORDER BY created_at DESC, finding_id DESC
            LIMIT ?
            """,
            params + [limit],
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _render_preview_rows_html(rows: List[Dict[str, Any]]) -> str:
    fragments: list[str] = []
    for row in rows:
        gt = row.get("ground_truth_label")
        if gt == 1:
            badge = '<span class="br-badge br-badge-tp">[TP:1]</span>'
        elif gt == 0:
            badge = '<span class="br-badge br-badge-fp">[FP:0]</span>'
        else:
            badge = '<span class="br-badge br-badge-unlabeled">[NULL]</span>'

        t_conf = float(row.get("teacher_confidence") or 0.0)
        s_prob = float(row.get("student_pred_prob") or 0.0)
        fragments.append(
            f"<tr>"
            f"<td><code>{html.escape(str(row['finding_id']))}</code></td>"
            f"<td>{html.escape(str(row['rule_id']))}</td>"
            f"<td>CWE-{int(row['cwe_id'])}</td>"
            f'<td class="val-muted">[B{int(row["host_group_bucket"])}]</td>'
            f'<td class="num-right">{int(row["http_status_code"])}</td>'
            f'<td class="num-right val-pos">{int(row["response_length_delta"]):+d}</td>'
            f'<td class="num-right">{float(row["response_time_zscore"]):.2f}</td>'
            f'<td class="num-right">{float(row["dom_structural_similarity"]):.3f}</td>'
            f'<td class="num-right">{t_conf:.2f}</td>'
            f'<td class="num-right">{s_prob:.2f}</td>'
            f"<td>{badge}</td>"
            f"</tr>"
        )
    if not fragments:
        return (
            '<tr><td colspan="11" class="val-muted">'
            "[NO ARCHIVED FINDINGS MATCHING ACTIVE FILTER MATRIX]"
            "</td></tr>"
        )
    return "\n".join(fragments)


@router.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"title": "BlackRoute-Web | CyberNest Labs"},
    )


@router.get("/ui/archive", response_class=HTMLResponse)
async def get_archive_console(request: Request):
    stats = get_archive_kpi_stats()
    preview_rows = _fetch_preview_rows(limit=50)
    svg_telemetry = _generate_flat_bucket_svg()
    return templates.TemplateResponse(
        request=request,
        name="archive_console.html",
        context={
            "stats": stats,
            "preview_rows": preview_rows,
            "svg_telemetry": svg_telemetry,
        },
    )


@router.get("/ui/archive/preview", response_class=HTMLResponse)
async def get_archive_preview_rows(
    rule_filter: Optional[str] = Query(None),
    label_source: Optional[str] = Query(None),
    min_teacher_conf: float = Query(0.0),
    split_bucket: str = Query("all"),
    scan_id: Optional[str] = Query(None),
):
    rows = _fetch_preview_rows(
        rule_filter=rule_filter,
        label_source=label_source,
        min_teacher_conf=min_teacher_conf,
        split_bucket=split_bucket,
        scan_id=scan_id,
        limit=50,
    )
    return HTMLResponse(content=_render_preview_rows_html(rows))


@router.get("/ui/archive/kpi-strip", response_class=HTMLResponse)
async def get_archive_kpi_strip_fragment():
    stats = get_archive_kpi_stats()
    html_frag = f"""
    <div class="br-kpi-cell">
      <span class="br-kpi-label">01 // TOTAL ARCHIVED</span>
      <span id="kpi-total-archived" class="br-kpi-value">{stats['total_findings']}</span>
      <span class="br-kpi-sub">HOT TABLE: 32 FEATURES</span>
    </div>
    <div class="br-kpi-cell">
      <span class="br-kpi-label">02 // VERIFIED TRUE POS</span>
      <span id="kpi-verified-tp" class="br-kpi-value">{stats['verified_tp']}</span>
      <span class="br-kpi-sub">LABEL_SRC &gt;= 2</span>
    </div>
    <div class="br-kpi-cell">
      <span class="br-kpi-label">03 // VERIFIED FALSE FLAGS</span>
      <span id="kpi-verified-fp" class="br-kpi-value">{stats['verified_fp']}</span>
      <span class="br-kpi-sub">AUTO + TEACHER</span>
    </div>
    <div class="br-kpi-cell">
      <span class="br-kpi-label">04 // UNLABELED QUEUE</span>
      <span id="kpi-unlabeled-queue" class="br-kpi-value">{stats['unlabeled_count']}</span>
      <span class="br-kpi-sub">READY FOR BATCH</span>
    </div>
    <div class="br-kpi-cell">
      <span class="br-kpi-label">05 // COLD ZSTD STORAGE</span>
      <span id="kpi-cold-storage" class="br-kpi-value">{stats['cold_size_mb']}</span>
      <span class="br-kpi-sub">RATIO: 6.4x (ZSTD)</span>
    </div>
    <div class="br-kpi-cell">
      <span class="br-kpi-label">06 // LOCAL ONNX F2-SCORE</span>
      <span id="kpi-onnx-f2" class="br-kpi-value">{stats['onnx_f2']}</span>
      <span class="br-kpi-sub">[█████████░] ORT_CPU</span>
    </div>
    """
    return HTMLResponse(content=html_frag)


@router.get("/ui/archive/svg-telemetry", response_class=HTMLResponse)
async def get_archive_svg_telemetry_fragment():
    return HTMLResponse(content=_generate_flat_bucket_svg())


@router.get("/ui/triage-queue", response_class=HTMLResponse)
async def get_triage_queue_view(request: Request, partial: int = Query(0)):
    conn = get_readonly_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT h.finding_id, h.rule_id, h.has_sql_error_sig, h.has_waf_block_sig,
                   h.teacher_confidence, h.student_pred_prob, h.disagreement_score,
                   c.vulnerable_parameter
            FROM findings_ml_hot h
            JOIN findings_evidence_cold c ON h.finding_id = c.finding_id
            WHERE h.needs_human_review = 1
            ORDER BY h.disagreement_score DESC
            LIMIT 50
            """
        )
        triage_rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    partial_resp = templates.TemplateResponse(
        request=request,
        name="partials/triage_queue.html",
        context={"triage_rows": triage_rows},
    )
    if partial == 1 or request.headers.get("HX-Request") == "true":
        return partial_resp

    partial_body = partial_resp.body.decode("utf-8")
    full_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BLACKROUTE-WEB // ACTIVE LEARNING TRIAGE QUEUE</title>
  <link rel="stylesheet" href="/static/css/blackroute-synth.css">
  <script src="/static/js/htmx.min.js"></script>
</head>
<body>
  <div class="frame-shell">
    <div class="br-topbar" style="margin-bottom: 8px;">
      <span>BLACKROUTE-WEB // ACTIVE LEARNING TRIAGE WORKBENCH</span>
      <span>
        <a href="/" style="color: var(--bg-void); text-decoration: none; margin-right: 10px;">[MISSION CONTROL]</a>
        <a href="/ui/archive" style="color: var(--bg-void); text-decoration: none;">[ARCHIVE &amp; MASSEXPORT]</a>
      </span>
    </div>
    {partial_body}
  </div>
</body>
</html>"""
    return HTMLResponse(content=full_doc)


@router.get("/ui/triage-queue/evidence/{finding_id}", response_class=HTMLResponse)
async def get_triage_finding_evidence(finding_id: str):
    conn = get_readonly_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT target_endpoint_raw, vulnerable_parameter, injected_payload_raw,
                   request_raw_zstd, response_raw_zstd, reflection_snippet_raw,
                   stealth_curl_command, teacher_reasoning
            FROM findings_evidence_cold
            WHERE finding_id = ?
            """,
            (finding_id,),
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        return HTMLResponse(
            content='<td colspan="7" class="val-warn">[COLD EVIDENCE NOT FOUND]</td>'
        )

    r = dict(row)
    req_txt = ""
    resp_txt = ""
    if r.get("request_raw_zstd"):
        try:
            req_txt = ZSTD_DECOMPRESSOR.decompress(bytes(r["request_raw_zstd"])).decode("utf-8", errors="replace")
        except Exception:
            req_txt = "[DECOMPRESSION ERROR]"
    if r.get("response_raw_zstd"):
        try:
            resp_txt = ZSTD_DECOMPRESSOR.decompress(bytes(r["response_raw_zstd"])).decode("utf-8", errors="replace")[:2048]
        except Exception:
            resp_txt = "[DECOMPRESSION ERROR]"

    drawer_html = f"""
    <td colspan="7" style="background-color: var(--bg-panel); padding: 10px; white-space: normal;">
      <div style="margin-bottom: 6px;">
        <strong class="val-pos">[COLD ZSTD EVIDENCE DRAWER // {html.escape(finding_id)}]</strong>
        <span class="val-muted">ENDPOINT: {html.escape(str(r.get('target_endpoint_raw') or ''))}</span>
      </div>
      <div style="margin-bottom: 6px;">
        <span class="val-pos">STEALTH cURL:</span>
        <code>{html.escape(str(r.get('stealth_curl_command') or ''))}</code>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
        <pre style="margin: 0; padding: 6px; border: 1px solid var(--border-muted); background: var(--bg-void); overflow-x: auto;">{html.escape(req_txt)}</pre>
        <pre style="margin: 0; padding: 6px; border: 1px solid var(--border-muted); background: var(--bg-void); overflow-x: auto;">{html.escape(resp_txt)}</pre>
      </div>
    </td>
    """
    return HTMLResponse(content=drawer_html)


@router.get("/telemetry/status", response_class=HTMLResponse)
async def get_posix_telemetry_status():
    """Executes scripts/sys_telemetry.sh (CWE-78 safe) to emit the top status bar HTML fragment."""
    arch_path = resolve_archive_db_path()
    script_path = Path(settings.BASE_DIR) / "scripts" / "sys_telemetry.sh"
    if script_path.exists():
        try:
            proc = subprocess.run(
                ["/bin/sh", str(script_path), str(arch_path)],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return HTMLResponse(content=proc.stdout.strip())
        except Exception:
            pass

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    size_kb = int(arch_path.stat().st_size // 1024) if arch_path.exists() else 0
    fallback_html = (
        f'<span class="val-pos">[DB: WAL_OK // {size_kb} KB]</span> '
        f'<span class="val-muted">[SYNC: {now_utc}]</span> '
        f'<span class="val-pos">[LOOPBACK: 127.0.0.1:8090]</span>'
    )
    return HTMLResponse(content=fallback_html)


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    icon_path = settings.STATIC_DIR / "CyberNestLabsLogo.png"
    if icon_path.exists():
        return FileResponse(icon_path, media_type="image/png")
    return Response(status_code=204)
