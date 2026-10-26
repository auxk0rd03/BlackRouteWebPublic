import asyncio
import datetime
import html
import io
import json
import threading
import uuid
import os
import re
import zipfile
from typing import Optional, Dict, Any, List
from pathlib import Path

from fastapi import APIRouter, Form, File, UploadFile, BackgroundTasks, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, PlainTextResponse, Response

from app.core.database import get_latest_scan_findings, get_scan_by_id, update_scan_report_file
from app.core.config import settings
from app.core.engine_bridge import engine_available
from app.core.security import (
    parse_src_list,
    sanitize_target_input,
    sanitize_filename,
    resolve_sandboxed_path,
)
from app.core.scanner import (
    WebScanner,
    SCAN_LOGS,
    LOG_SUBSCRIBERS,
    LOGS_LOCK,
    run_batch_scan_pipeline,
    build_markdown_triage,
    generate_target_output_artifacts
)
from Sources.Utilities.vids_pdf_gen import generate_web_report, is_vendor_observation, extract_vendor_name, extract_target_asset

router = APIRouter()
logs_lock = LOGS_LOCK


def _render_input_mode_panel(mode: str = "single") -> str:
    """Render the HTMX-swappable input mode control panel for Single Target Domain vs Batch Domain Import."""
    is_batch = str(mode).lower().strip() == "batch"
    single_active_style = (
        "flex: 1; background-color: var(--accent-color); color: #ffffff; border-color: var(--accent-color);"
        if not is_batch else "flex: 1;"
    )
    batch_active_style = (
        "flex: 1; background-color: var(--accent-color); color: #ffffff; border-color: var(--accent-color);"
        if is_batch else "flex: 1;"
    )
    form_endpoint = "/api/scan/batch" if is_batch else "/api/scan"
    mode_val = "batch" if is_batch else "single"
    single_display = "none" if is_batch else "block"
    batch_display = "block" if is_batch else "none"
    single_required = "" if is_batch else "required"

    return f"""
    <div class="input-mode-selector" style="display: flex; gap: 0; margin-bottom: 14px; border: 1px solid var(--border-primary);">
        <button type="button"
                id="toggle-single-mode"
                class="btn mode-toggle-btn {'active' if not is_batch else ''}"
                hx-get="/api/input-mode?mode=single"
                hx-target="#scan-mode-panel"
                hx-swap="innerHTML"
                onclick="if(window.setInputMode) window.setInputMode('single');"
                style="{single_active_style}">
            Single Target Domain
        </button>
        <button type="button"
                id="toggle-batch-mode"
                class="btn mode-toggle-btn {'active' if is_batch else ''}"
                hx-get="/api/input-mode?mode=batch"
                hx-target="#scan-mode-panel"
                hx-swap="innerHTML"
                onclick="if(window.setInputMode) window.setInputMode('batch');"
                style="{batch_active_style}">
            Batch Domain Import
        </button>
    </div>

    <form id="scan-control-form" hx-post="{form_endpoint}" hx-target="#logs-area" hx-swap="innerHTML" hx-encoding="multipart/form-data" enctype="multipart/form-data">
        <input type="hidden" id="input_mode" name="input_mode" value="{mode_val}">

        <div id="single-target-controls" style="display: {single_display};">
            <label for="target_url" style="color: var(--text-secondary); font-weight: 600; font-size: 0.85em; display: block; margin-bottom: 5px; text-transform: uppercase;">
                TARGET WEB APPLICATION / DOMAIN:
            </label>
            <div class="input-group">
                <input type="text" id="target_url" name="target_url" placeholder="https://app.example.com or http://localhost:3000" autocomplete="off" {single_required}>
                <button type="submit" class="btn-scan btn">ENGAGE</button>
            </div>
        </div>

        <div id="batch-target-controls" style="display: {batch_display};">
            <label for="src_list_file" style="color: var(--text-secondary); font-weight: 600; font-size: 0.85em; display: block; margin-bottom: 5px; text-transform: uppercase;">
                BULK SOURCE FILE UPLOAD (src_list.csv):
            </label>
            <div class="input-group" style="margin-bottom: 10px;">
                <input type="file" id="src_list_file" name="src_list_file" accept=".csv,text/csv" style="flex-grow: 1; background-color: var(--bg-color); border: 1px solid var(--border-secondary); color: var(--text-primary); padding: 8px; font-size: 0.85em;">
            </div>
            <label for="batch_targets" style="color: var(--text-secondary); font-weight: 600; font-size: 0.85em; display: block; margin-bottom: 5px; text-transform: uppercase;">
                INLINE COMMA-SEPARATED TARGET DOMAINS:
            </label>
            <textarea id="batch_targets" name="batch_targets" rows="3" placeholder="www.website01.com,www.website02.com,www.website99.com" style="width: 100%; box-sizing: border-box; background-color: var(--bg-color); border: 1px solid var(--border-secondary); color: var(--text-primary); padding: 10px; font-family: var(--font-mono); font-size: 0.85em; margin-bottom: 10px;"></textarea>
            <div style="display: flex; gap: 10px; align-items: center;">
                <button type="submit" class="btn-scan btn" style="flex: 1;">ENGAGE BATCH RECON</button>
                <a href="/api/export/batch-zip" class="btn btn-batch-export" target="_blank" style="text-align: center;">[ EXPORT BATCH ZIP ]</a>
            </div>
        </div>

        <div class="options-group" style="margin-top: 14px; font-size: 0.82em; color: var(--text-secondary); display: flex; flex-direction: column; gap: 8px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" id="stealth_mode" name="stealth_mode" checked style="cursor: pointer;">
                <label for="stealth_mode" style="cursor: pointer; color: var(--accent-color); font-weight: 600;">Enable Stealth Protocol (Passive Recon &amp; Rate Jitter — Low SOC Footprint)</label>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" id="shadow_mode" name="shadow_mode" style="cursor: pointer;">
                <label for="shadow_mode" style="cursor: pointer;">Enable Shadow Architecture (Retain low-entropy secrets &amp; raw findings)</label>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" id="local_staging" name="local_staging" style="cursor: pointer;">
                <label for="local_staging" style="cursor: pointer; color: var(--warning-color);">Enable Local Staging Mode (Permit auditing 127.0.0.1 / private test targets)</label>
            </div>
        </div>

        <details style="margin-top: 12px; font-size: 0.82em; color: var(--text-secondary);">
            <summary style="cursor: pointer; font-weight: 600;">[+] Advanced Authentication &amp; Engagement Headers</summary>
            <div style="margin-top: 8px;">
                <label for="engagement_id" style="display: block; margin-bottom: 4px;">Authorized Engagement ID (X-Security-Engagement for SOC Whitelisting):</label>
                <input type="text" id="engagement_id" name="engagement_id" placeholder="CN-AUDIT-2026-X" style="width: 100%; margin-bottom: 8px;">
            </div>
            <div style="margin-top: 4px;">
                <label for="auth_header" style="display: block; margin-bottom: 4px;">Authorization Header (Bearer / Token / Cookie):</label>
                <input type="text" id="auth_header" name="auth_header" placeholder="Bearer eyJhbGciOi..." style="width: 100%; margin-bottom: 8px;">
            </div>
            <div style="margin-top: 8px;">
                <label for="auth_macros" style="display: block; margin-bottom: 4px;">Authentication Macros (JSON for session refresh):</label>
                <textarea id="auth_macros" name="auth_macros" placeholder='[{{"method": "POST", "url": "https://api.example.com/login", "json": {{"username": "user", "password": "pass"}}, "extract_token": "token", "extract_cookies": ["session_id"]}}]' style="width: 100%; height: 80px; font-family: var(--font-mono); font-size: 0.75em;"></textarea>
                <div style="font-size: 0.7em; color: var(--text-secondary); margin-top: 2px;">JSON array of auth steps for automatic session refresh on 401 errors</div>
            </div>
        </details>
    </form>
    """


@router.get("/input-mode", response_class=HTMLResponse)
@router.get("/ui/input-mode", response_class=HTMLResponse)
async def toggle_input_mode(mode: str = Query("single")):
    """HTMX endpoint to toggle between 'Single Target Domain' and 'Batch Domain Import'."""
    return HTMLResponse(content=_render_input_mode_panel(mode))


@router.post("/scan/batch", response_class=HTMLResponse)
@router.post("/batch-scan", response_class=HTMLResponse)
async def start_batch_scan(
    background_tasks: BackgroundTasks,
    src_list_file: Optional[UploadFile] = File(None),
    batch_targets: Optional[str] = Form(None),
    src_list: Optional[str] = Form(None),
    target_url: Optional[str] = Form(None),
    shadow_mode: bool = Form(False),
    local_staging: bool = Form(False),
    auth_header: Optional[str] = Form(None),
    stealth_mode: bool = Form(True),
    engagement_id: Optional[str] = Form(None),
    auth_macros: Optional[str] = Form(None)
):
    """
    Ingests bulk target domains via .csv upload (src_list.csv) and/or inline comma-separated text area,
    enforces strict security sanitization, and dispatches the asynchronous multi-target scanning pipeline.
    """
    raw_segments: List[str] = []

    if src_list_file and src_list_file.filename:
        fname = os.path.basename(src_list_file.filename.replace("\\", "/").strip())
        if not fname.lower().endswith(".csv") or "\x00" in fname:
            safe_fname = html.escape(fname)
            return f"""
            <div class="log-entry error">[ERROR] Invalid File Format '{safe_fname}': Only .csv files are permitted for batch ingestion.</div>
            <div class="log-entry warning">[HALTED] Batch audit pipeline was not initiated.</div>
            """
        max_csv_bytes = 2 * 1024 * 1024
        file_bytes = await src_list_file.read(max_csv_bytes + 1)
        if len(file_bytes) > max_csv_bytes:
            return """
            <div class="log-entry error">[ERROR] Batch CSV file exceeds maximum allowed size (2MB).</div>
            <div class="log-entry warning">[HALTED] Batch audit pipeline was not initiated.</div>
            """
        file_text = file_bytes.decode("utf-8", errors="replace").strip()
        if file_text:
            raw_segments.append(file_text)

    for text_source in (batch_targets, src_list, target_url):
        if text_source and text_source.strip():
            raw_segments.append(text_source.strip())

    combined_raw = ",".join(raw_segments)

    try:
        parsed_targets = parse_src_list(combined_raw)
    except ValueError as e:
        safe_err = html.escape(str(e))
        return f"""
        <div class="log-entry error">[ERROR] Invalid Batch Target Input: {safe_err}</div>
        <div class="log-entry warning">[HALTED] Batch audit pipeline was not initiated. Please verify target syntax and retry.</div>
        """

    parsed_auth_macros = []
    if auth_macros:
        try:
            parsed_auth_macros = json.loads(auth_macros)
        except json.JSONDecodeError:
            pass

    background_tasks.add_task(
        run_batch_scan_pipeline,
        targets=parsed_targets,
        shadow_mode=shadow_mode,
        local_staging=local_staging,
        auth_header=auth_header,
        stealth_mode=stealth_mode,
        engagement_id=engagement_id,
        auth_macros=parsed_auth_macros
    )

    safe_preview = html.escape(", ".join(parsed_targets[:5]))
    if len(parsed_targets) > 5:
        safe_preview += f" (+{len(parsed_targets) - 5} more)"

    return f"""
    <div class="log-entry info">[BATCH ENGAGED] Queued {len(parsed_targets)} validated target domains: {safe_preview}</div>
    <div class="log-entry info">[MISSION ORCHESTRATOR] Batch Pipeline Activated — Outputting to Output/Targ001..Targ{len(parsed_targets):03d} — Streaming Telemetry via SSE...</div>
    <script>
        if (typeof window.connectSSE === 'function') {{
            window.connectSSE();
        }}
    </script>
    """


@router.post("/scan", response_class=HTMLResponse)
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: Optional[str] = Form(None),
    input_mode: Optional[str] = Form("single"),
    src_list_file: Optional[UploadFile] = File(None),
    batch_targets: Optional[str] = Form(None),
    src_list: Optional[str] = Form(None),
    shadow_mode: bool = Form(False),
    local_staging: bool = Form(False),
    auth_header: Optional[str] = Form(None),
    stealth_mode: bool = Form(True),
    engagement_id: Optional[str] = Form(None),
    auth_macros: Optional[str] = Form(None)  # JSON string of auth macros
):
    """
    Receives target web URL (or batch input) from UI form and starts background audit pipeline.
    """
    has_batch_file = bool(src_list_file and src_list_file.filename)
    has_batch_text = bool((batch_targets and batch_targets.strip()) or (src_list and src_list.strip()))
    is_comma_list = bool(target_url and "," in target_url)

    if str(input_mode).lower().strip() == "batch" or has_batch_file or has_batch_text or is_comma_list:
        return await start_batch_scan(
            background_tasks=background_tasks,
            src_list_file=src_list_file,
            batch_targets=batch_targets,
            src_list=src_list,
            target_url=target_url if is_comma_list or str(input_mode).lower().strip() == "batch" else None,
            shadow_mode=shadow_mode,
            local_staging=local_staging,
            auth_header=auth_header,
            stealth_mode=stealth_mode,
            engagement_id=engagement_id,
            auth_macros=auth_macros
        )

    clean_url = (target_url or "").strip()
    if not clean_url:
        return """
        <div class="log-entry error">[ERROR] Invalid Target URL: Target URL cannot be empty.</div>
        <div class="log-entry warning">[HALTED] Audit pipeline was not initiated. Please verify target URL syntax and retry.</div>
        """
    safe_display = html.escape(clean_url)

    # Parse auth macros if provided
    parsed_auth_macros = []
    if auth_macros:
        try:
            parsed_auth_macros = json.loads(auth_macros)
        except json.JSONDecodeError:
            pass  # Invalid JSON, ignore

    try:
        scanner = WebScanner(
            target_url=clean_url,
            shadow_mode=shadow_mode,
            local_staging=local_staging,
            auth_header=auth_header,
            stealth_mode=stealth_mode,
            engagement_id=engagement_id,
            auth_macros=parsed_auth_macros
        )
    except ValueError as e:
        safe_err = html.escape(str(e))
        return f"""
        <div class="log-entry error">[ERROR] Invalid Target URL: {safe_err}</div>
        <div class="log-entry warning">[HALTED] Audit pipeline was not initiated. Please verify target URL syntax and retry.</div>
        """

    background_tasks.add_task(scanner.run_pipeline)

    return f"""
    <div class="log-entry info">[TARGET ENGAGED] {safe_display}</div>
    <div class="log-entry info">[MISSION ORCHESTRATOR] Pipeline Activated — Streaming Real-Time Telemetry via SSE...</div>
    <script>
        if (typeof window.connectSSE === 'function') {{
            window.connectSSE();
        }}
    </script>
    """

@router.get("/stream-logs-sse")
async def stream_logs_sse(request: Request):
    """
    Yields real-time terminal log events via Server-Sent Events (SSE) over a single persistent connection.
    Eliminates polling overhead and visual stutter.
    """
    queue: asyncio.Queue = asyncio.Queue()
    LOG_SUBSCRIBERS.add(queue)

    async def event_generator():
        try:
            # Send initial backlog if present
            with logs_lock:
                for entry in list(SCAN_LOGS):
                    single_line_entry = entry.replace("\r", "").replace("\n", " ")
                    yield f"data: {single_line_entry}\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15.0)
                    single_line_entry = entry.replace("\r", "").replace("\n", " ")
                    yield f"data: {single_line_entry}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            LOG_SUBSCRIBERS.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/stream-logs", response_class=HTMLResponse)
async def stream_logs():
    """Atomically consume and ship logs for legacy HTTP polling fallbacks."""
    with logs_lock:
        logs_to_ship = list(SCAN_LOGS)
        SCAN_LOGS.clear()
    return "".join(logs_to_ship)

@router.get("/status")
async def get_status():
    return {"status": "ready", "system": "BlackRoute-Web v1.0", "streaming": "SSE"}

@router.get("/engines-status", response_class=HTMLResponse)
async def engines_status():
    """Returns real-time health badges for the polyglot engine stack."""
    rust_spider = engine_available("web_spider")
    go_graph = engine_available("surface_graph")

    def badge(name: str, lang: str, active: bool) -> str:
        color = "var(--accent-color, #5fa8a0)" if active else "var(--warning-color, #b89a5a)"
        status_text = "ACTIVE" if active else "FALLBACK (PY)"
        return f'<span style="background: rgba(0,0,0,0.3); border: 1px solid {color}; padding: 2px 7px; border-radius: 3px; font-size: 0.72em; color: {color}; margin-right: 5px;">[{lang}] {name}: {status_text}</span>'

    html_out = '<div style="display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">'
    html_out += badge("Web Spider", "Rust", rust_spider)
    html_out += badge("Surface Graph", "Go", go_graph)
    html_out += '<span style="background: rgba(0,0,0,0.3); border: 1px solid var(--accent-color); padding: 2px 7px; border-radius: 3px; font-size: 0.72em; color: var(--accent-color);">[Python] DAST &amp; SSE: ONLINE</span>'
    html_out += '</div>'
    return html_out

@router.get("/export/stix")
async def export_stix():
    """Generate authentic STIX 2.1 JSON bundle from recent web audit findings."""
    scan, findings, _ = get_latest_scan_findings()
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    target = scan.get("target_url", "unknown_target") if scan else "active_session"
    bundle_id = f"bundle--{uuid.uuid4()}"
    report_id = f"report--{uuid.uuid4()}"

    stix_objects = []
    object_refs = []

    for f in findings:
        vuln_id = f"vulnerability--{uuid.uuid4()}"
        object_refs.append(vuln_id)

        sev = f.get("severity", "LOW")
        cat = f.get("category", "WEB")
        title = f.get("title", "Web Security Finding")
        endpoint = f.get("endpoint", target)

        vuln_obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"BlackRoute-Web: {title} on {endpoint}",
            "description": f.get("description", ""),
            "labels": ["web-application-security", sev.lower(), cat.lower()],
            "confidence": int(float(f.get("confidence", 1.0)) * 100),
            "external_references": [
                {
                    "source_name": "BlackRoute-Web Security Engine",
                    "description": f"Audited Endpoint: {endpoint} | PoC: {f.get('curl_command', '')}"
                }
            ]
        }
        stix_objects.append(vuln_obj)

    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"BlackRoute-Web Security Assessment: {target}",
        "description": f"Dynamic web application attack surface and security posture audit for {target}.",
        "published": now_iso,
        "report_types": ["vulnerability", "attack-surface", "reconnaissance"],
        "object_refs": object_refs
    }
    stix_objects.insert(0, report_obj)

    return JSONResponse(
        content={"type": "bundle", "id": bundle_id, "objects": stix_objects},
        headers={"Content-Disposition": "attachment; filename=blackroute_web_stix_2_1.json"}
    )

@router.get("/export/taxii")
async def export_taxii():
    """Generate TAXII 2.1 collection envelope containing web security indicators."""
    scan, findings, _ = get_latest_scan_findings()
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    taxii_envelope = {
        "more": False,
        "next": "",
        "objects": [
            {
                "id": f"indicator--{uuid.uuid4()}",
                "type": "indicator",
                "spec_version": "2.1",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Web Threat Indicator: {f.get('title')}",
                "description": f"Category: {f.get('category')} | Severity: {f.get('severity')} | Endpoint: {f.get('endpoint')} | PoC: {f.get('curl_command', '')}",
                "pattern": f"[network-traffic:dst_ref.value = '{f.get('endpoint')}']",
                "pattern_type": "stix"
            }
            for f in findings
        ]
    }
    return JSONResponse(
        content=taxii_envelope,
        headers={"Content-Disposition": "attachment; filename=blackroute_web_taxii_collection.json"}
    )

@router.post("/scans/{scan_id}/report")
@router.get("/scans/{scan_id}/report")
async def generate_report_for_scan(scan_id: int):
    """
    Decoupled on-demand VIDS PDF report compiler for any historical or completed scan.
    Enables reporting engine to execute independently from detection engine.
    """
    scan, findings, endpoints = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": f"Scan ID {scan_id} not found."})

    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    finding_impact = (crit_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 2)
    risk_score = min(100, max(20, finding_impact)) if findings else 15

    sensitive_routes = [e["url"] for e in endpoints if any(s in e["url"] for s in ["/admin", "/api", "/auth", "/login", "/config"])]

    report_data = {
        "target_url": scan["target_url"],
        "pages_crawled": scan["pages_crawled"],
        "endpoints_found": scan["endpoints_found"],
        "findings": findings,
        "technologies": [],
        "sensitive_routes": sensitive_routes,
        "risk_score": risk_score
    }

    loop = asyncio.get_running_loop()
    report_file = await loop.run_in_executor(
        None,
        generate_web_report,
        report_data,
        str(settings.STATIC_DIR)
    )
    update_scan_report_file(scan_id, report_file)

    return JSONResponse({
        "status": "success",
        "scan_id": scan_id,
        "report_file": report_file,
        "download_url": f"/static/{report_file}"
    })

@router.get("/export/report-latest")
async def export_latest_report():
    """Generates and redirects to the PDF audit report for the most recent scan."""
    from fastapi.responses import RedirectResponse
    scan, _, _ = get_latest_scan_findings()
    if not scan:
        return JSONResponse(status_code=404, content={"error": "No scan records found."})

    raw_report_file = scan.get("report_file")
    if raw_report_file:
        try:
            safe_report = sanitize_filename(str(raw_report_file), allowed_extensions=(".pdf",))
            static_pdf = resolve_sandboxed_path(settings.STATIC_DIR, safe_report)
            if static_pdf.is_file() and not static_pdf.is_symlink():
                return RedirectResponse(f"/static/{safe_report}")
        except ValueError:
            pass

    res = await generate_report_for_scan(scan["id"])
    if isinstance(res, JSONResponse):
        import json
        body = json.loads(res.body.decode())
        if "download_url" in body:
            dl_url = str(body["download_url"])
            if dl_url.startswith("/static/"):
                try:
                    safe_dl = sanitize_filename(dl_url[len("/static/"):], allowed_extensions=(".pdf",))
                    return RedirectResponse(f"/static/{safe_dl}")
                except ValueError:
                    pass
    return res

@router.get("/poc/{filename:path}")
async def download_poc(filename: str):
    """Serve HTML PoC files for download with strict filename & sandbox boundary validation."""
    try:
        safe_filename = sanitize_filename(filename, allowed_extensions=(".html",))
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Invalid filename"})
    
    # Try to find the HTML PoC content from the latest scan findings
    scan, findings, _ = get_latest_scan_findings()
    if not scan:
        return JSONResponse(status_code=404, content={"error": "No scan records found."})
    
    # Find the finding with matching HTML PoC filename
    poc_content = None
    for finding in findings:
        if finding.get("html_poc") == safe_filename and "html_poc_content" in finding:
            poc_content = finding["html_poc_content"]
            break
    
    escaped_filename = html.escape(safe_filename)
    if not poc_content:
        # Fallback to a generic PoC template
        poc_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>HTML PoC - {escaped_filename}</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; background: #1a1a1a; color: #eee; }}
        .warning {{ background: #ff6b6b; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="warning">
        <h2>⚠️ Proof of Concept File</h2>
        <p>This is a demonstration file for security testing purposes only.</p>
        <p>File: {escaped_filename}</p>
    </div>
    <p>Note: The specific PoC content was not found in the latest scan. This is a placeholder.</p>
</body>
</html>"""
    
    return HTMLResponse(content=poc_content, headers={
        "Content-Disposition": f"attachment; filename={safe_filename}",
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff"
    })

def _generate_sarif_rule_id(finding: Dict[str, Any]) -> str:
    """Generate unique, deterministic SARIF rule ID based on check type to prevent CI/CD parser collisions."""
    # Check if finding already explicitly assigns a rule ID
    if finding.get("rule_id"):
        return str(finding["rule_id"])

    category = str(finding.get("category", "GENERAL")).upper()
    title = str(finding.get("title", "")).upper()
    description = str(finding.get("description", "")).upper()
    
    # 1. CSP checks (regardless of whether category is HEADERS or CSP)
    if "CSP" in title or "CSP" in category or "CONTENT-SECURITY-POLICY" in title or "CONTENT-SECURITY-POLICY" in description:
        if "UNSAFE-INLINE" in title or "INLINE" in title or "UNSAFE-INLINE" in description:
            return "BR-CSP-INLINE"
        elif "UNSAFE-EVAL" in title or "EVAL" in title or "UNSAFE-EVAL" in description:
            return "BR-CSP-EVAL"
        elif "MISSING" in title or "ABSENT" in title:
            return "BR-CSP-MISSING"
        elif "WILDCARD" in title or "*" in title:
            return "BR-CSP-WILDCARD"
        return "BR-CSP-GENERAL"
    
    # 2. Cookie checks
    if "COOKIE" in category or "COOKIE" in title:
        if "SECURE" in title:
            return "BR-COOKIE-SECURE"
        elif "HTTPONLY" in title:
            return "BR-COOKIE-HTTPONLY"
        elif "SAMESITE" in title:
            return "BR-COOKIE-SAMESITE"
        elif "INSECURE HTTP" in title or "CLEARTEXT" in title:
            return "BR-COOKIE-CLEARTEXT"
        elif "EXPIRATION" in title or "EXPIRES" in description:
            return "BR-COOKIE-EXPIRATION"
        return "BR-COOKIE-GENERAL"
    
    # 3. HTTP Header checks
    if "HSTS" in title or "STRICT-TRANSPORT" in title or "STRICT-TRANSPORT" in description:
        return "BR-HEADER-HSTS"
    elif "CLICKJACKING" in title or "X-FRAME" in title or "FRAME-ANCESTORS" in title:
        return "BR-HEADER-XFRAME"
    elif "SNIFF" in title or "X-CONTENT-TYPE-OPTIONS" in title:
        return "BR-HEADER-NOSNIFF"
    elif "REFERRER" in title or "REFERRER-POLICY" in title:
        return "BR-HEADER-REFERRER"
    elif "PERMISSIONS" in title or "FEATURE-POLICY" in title:
        return "BR-HEADER-PERMISSIONS"
    elif "SERVER BANNER" in title or "BANNER" in title:
        return "BR-HEADER-BANNER"
    elif "X-POWERED-BY" in title:
        return "BR-HEADER-POWEREDBY"
    elif "HEADER" in category:
        return "BR-HEADER-GENERAL"
    
    # 4. CORS checks
    if "CORS" in title or "CORS" in description or "ORIGIN" in title:
        if "WILDCARD" in title or "*" in description:
            return "BR-CORS-WILDCARD"
        elif "CREDENTIAL" in title or "CREDENTIAL" in description:
            return "BR-CORS-CREDENTIALS"
        elif "REFLECTION" in title or "DYNAMIC" in title:
            return "BR-CORS-REFLECTION"
        return "BR-CORS-GENERAL"
    
    # 5. DOM XSS checks
    if "DOM" in category or "XSS" in category:
        if "POSTMESSAGE" in title or "MESSAGE" in title:
            return "BR-DOM-POSTMESSAGE"
        elif "INNERHTML" in title or "DIRECT SOURCE TO SINK" in title:
            return "BR-DOM-INNERHTML"
        elif "EVAL" in title:
            return "BR-DOM-EVAL"
        elif "SINK & SOURCE" in title:
            return "BR-DOM-SINK-SOURCE"
        return "BR-DOM-GENERAL"
    
    # 6. Secrets checks
    if "SECRET" in category:
        if "AWS" in title or "AKIA" in description:
            return "BR-SECRET-AWS"
        elif "STRIPE" in title or "SK_LIVE" in description:
            return "BR-SECRET-STRIPE"
        elif "OPENAI" in title or "SK-" in description:
            return "BR-SECRET-OPENAI"
        elif "GITHUB" in title or "GHP_" in description:
            return "BR-SECRET-GITHUB"
        elif "GOOGLE" in title or "AIZA" in description:
            return "BR-SECRET-GOOGLE"
        elif "JWT" in title:
            return "BR-SECRET-JWT"
        return "BR-SECRET-GENERAL"
    
    # 7. API exposure checks
    if "API" in category:
        if "GRAPHQL" in title:
            if "HARDENED" in title or "PROTECTED" in title:
                return "BR-API-GRAPHQL-HARDENED"
            return "BR-API-GRAPHQL-INTROSPECTION"
        elif "SWAGGER" in title or "OPENAPI" in title:
            return "BR-API-SWAGGER"
        elif "GIT" in title:
            return "BR-API-GIT"
        elif "ENV" in title:
            return "BR-API-ENV"
        elif "ACTUATOR" in title:
            return "BR-API-ACTUATOR"
        elif "LOGIN" in title or "AUTH" in title:
            if "HARDENED" in title:
                return "BR-API-LOGIN-HARDENED"
            return "BR-API-LOGIN"
        return "BR-API-GENERAL"
    
    return "BR-GENERAL-FINDING"

def _build_sarif_report(scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Construct authentic SARIF 2.1.0 document with deterministic rule IDs."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tool_name = "BlackRoute-Web"
    tool_version = "1.0"
    
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error", 
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "none"
    }
    
    sarif_results = []
    rule_definitions = {}
    
    for finding in findings:
        severity = finding.get("severity", "INFO")
        sarif_level = severity_map.get(severity, "none")
        rule_id = _generate_sarif_rule_id(finding)
        
        if rule_id not in rule_definitions:
            rule_definitions[rule_id] = {
                "id": rule_id,
                "name": finding.get("title", "Security Finding"),
                "shortDescription": {
                    "text": finding.get("title", "Security Finding")
                },
                "fullDescription": {
                    "text": finding.get("description", "")
                },
                "help": {
                    "text": finding.get("remediation", "Review and address the security issue.")
                },
                "defaultConfiguration": {
                    "level": sarif_level
                },
                "properties": {
                    "category": finding.get("category", "GENERAL"),
                    "severity": severity,
                    "confidence": finding.get("confidence", 1.0)
                }
            }
        
        result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": finding.get("title", "Security Finding")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("endpoint", scan.get("target_url", "https://target.domain/"))
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": finding.get("endpoint", scan.get("target_url", "https://target.domain/"))
                                            },
                                            "region": {
                                                "startLine": 1,
                                                "startColumn": 1
                                            }
                                        },
                                        "message": {
                                            "text": finding.get("description", "")
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ],
            "fixes": [
                {
                    "description": {
                        "text": finding.get("remediation", "Review and address the security issue.")
                    }
                }
            ],
            "properties": {
                "category": finding.get("category", "GENERAL"),
                "confidence": finding.get("confidence", 1.0),
                "curl_command": finding.get("curl_command", ""),
                "evidence": finding.get("evidence", "")
            }
        }
        sarif_results.append(result)
    
    sarif_rules = list(rule_definitions.values())
    
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/CyberNestLabs/BlackRoute-Web",
                        "rules": sarif_rules
                    }
                },
                "invocations": [
                    {
                        "startTimeUtc": now_iso,
                        "endTimeUtc": now_iso,
                        "toolExecutionNotifications": []
                    }
                ],
                "results": sarif_results,
                "automationDetails": {
                    "id": f"scan-{scan.get('id', 'latest')}",
                    "description": {
                        "text": f"BlackRoute-Web security scan of {scan.get('target_url', '')}"
                    }
                }
            }
        ]
    }

@router.get("/export/sarif")
async def export_sarif():
    """Generate SARIF (Static Analysis Results Interchange Format) for CI/CD integration from latest scan."""
    scan, findings, _ = get_latest_scan_findings()
    if not scan:
        return JSONResponse(status_code=404, content={"error": "No scan records found."})
    
    sarif_report = _build_sarif_report(scan, findings)
    return JSONResponse(
        content=sarif_report,
        headers={"Content-Disposition": "attachment; filename=blackroute_web_sarif.json"}
    )

@router.get("/scans/{scan_id}/export/sarif")
async def export_scan_sarif(scan_id: int):
    """Generate SARIF for a specific scan ID."""
    scan, findings, _ = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": f"Scan ID {scan_id} not found."})
    
    sarif_report = _build_sarif_report(scan, findings)
    return JSONResponse(
        content=sarif_report,
        headers={"Content-Disposition": f"attachment; filename=blackroute_web_sarif_scan_{scan_id}.json"}
    )

def _build_markdown_triage(scan: Dict[str, Any], findings: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> str:
    """Build standardized, pre-formatted Bug Bounty & Triage submission report in Markdown ready for HackerOne/Jira."""
    from Sources.Utilities.vids_pdf_gen import build_bug_bounty_markdown_triage
    return build_bug_bounty_markdown_triage(scan, findings, endpoints)

@router.get("/scans/{scan_id}/export/markdown")
async def export_markdown_triage(scan_id: int):
    """Generate a triage summary in Markdown format for HackerOne, Jira, or GitHub Issues."""
    scan, findings, endpoints = get_scan_by_id(scan_id)
    if not scan:
        return JSONResponse(status_code=404, content={"error": f"Scan ID {scan_id} not found."})
    
    markdown_content = _build_markdown_triage(scan, findings, endpoints)
    return Response(
        content=markdown_content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=blackroute_triage_scan_{scan_id}.md"}
    )

@router.get("/export/markdown")
async def export_latest_markdown_triage():
    """Generate a triage summary in Markdown format for the latest scan."""
    scan, findings, endpoints = get_latest_scan_findings()
    if not scan:
        return JSONResponse(status_code=404, content={"error": "No scan records found."})
    
    raw_id = str(scan.get("id", "latest"))
    safe_id = re.sub(r"[^A-Za-z0-9_\-]", "", raw_id) or "latest"
    markdown_content = _build_markdown_triage(scan, findings, endpoints)
    return Response(
        content=markdown_content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=blackroute_triage_scan_{safe_id}.md"}
    )


def compile_batch_zip_archive(base_output_dir: Optional[Path] = None) -> Optional[bytes]:
    """
    Compile an in-memory ZIP archive containing all Output/Targ00N/ sub-directory reports
    (Markdown triage summaries and VIDS PDF audit reports).
    Maintains zero-footprint memory safety by streaming directly from memory buffer,
    and enforces strict path traversal and symlink boundaries.
    """
    out_root = (Path(base_output_dir) if base_output_dir else settings.OUTPUT_DIR).resolve()
    if not out_root.exists() or out_root.is_symlink():
        return None

    targ_dirs = sorted(
        [
            d for d in out_root.iterdir()
            if not d.is_symlink()
            and d.is_dir()
            and re.fullmatch(r"Targ\d+", d.name)
            and d.resolve().is_relative_to(out_root)
        ],
        key=lambda p: p.name
    )
    if not targ_dirs:
        return None

    buf = io.BytesIO()
    files_added = 0
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for t_dir in targ_dirs:
            for file_path in sorted(t_dir.rglob("*")):
                if file_path.is_symlink() or not file_path.is_file():
                    continue
                resolved_file = file_path.resolve()
                if not resolved_file.is_relative_to(out_root):
                    continue
                if resolved_file.suffix.lower() not in (".md", ".pdf"):
                    continue
                rel_to_out = resolved_file.relative_to(out_root)
                if ".." in rel_to_out.parts:
                    continue
                arcname = str(Path("Output") / rel_to_out)
                zf.write(resolved_file, arcname=arcname)
                files_added += 1

    if files_added == 0:
        return None

    return buf.getvalue()


@router.get("/export/batch-zip")
@router.post("/export/batch-zip")
async def export_batch_zip():
    """
    Generate and download a compiled ZIP archive containing all sub-directory reports
    (Output/Targ001 .. Output/Targ00N) upon completion of a batch scan.
    """
    zip_bytes = compile_batch_zip_archive(settings.OUTPUT_DIR)

    if not zip_bytes:
        # Fallback: if a single scan was completed in SQLite, materialize Output/Targ001 on-demand
        scan, findings, endpoints = get_latest_scan_findings()
        if scan:
            sensitive_routes = [
                e["url"] for e in endpoints
                if any(s in e.get("url", "") for s in ["/admin", "/api", "/auth", "/login", "/config"])
            ]
            report_data = {
                "target_url": scan.get("target_url", ""),
                "pages_crawled": scan.get("pages_crawled", 0),
                "endpoints_found": scan.get("endpoints_found", 0),
                "findings": findings,
                "technologies": [],
                "sensitive_routes": sensitive_routes,
                "risk_score": scan.get("risk_score", 15)
            }
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                generate_target_output_artifacts,
                1,
                scan["id"],
                report_data,
                findings,
                endpoints,
                settings.OUTPUT_DIR,
                scan.get("report_file", "")
            )
            zip_bytes = compile_batch_zip_archive(settings.OUTPUT_DIR)

    if not zip_bytes:
        return JSONResponse(
            status_code=404,
            content={"error": "No batch scan output artifacts found in Output/ directory."}
        )

    now_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"BlackRoute_Batch_Reports_{now_tag}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={zip_filename}"}
    )
