import asyncio
import datetime
import html
import threading
import uuid
from typing import Optional

from fastapi import APIRouter, Form, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.core.database import get_latest_scan_findings, get_scan_by_id, update_scan_report_file
from app.core.config import settings
from app.core.engine_bridge import engine_available
from app.core.scanner import WebScanner, SCAN_LOGS, LOG_SUBSCRIBERS
from Sources.Utilities.vids_pdf_gen import generate_web_report

router = APIRouter()
logs_lock = threading.Lock()

@router.post("/scan", response_class=HTMLResponse)
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(...),
    shadow_mode: bool = Form(False),
    local_staging: bool = Form(False),
    auth_header: Optional[str] = Form(None),
    stealth_mode: bool = Form(True),
    engagement_id: Optional[str] = Form(None)
):
    """
    Receives target web URL from UI form and starts background audit pipeline.
    """
    clean_url = target_url.strip()
    safe_display = html.escape(clean_url)

    scanner = WebScanner(
        target_url=clean_url,
        shadow_mode=shadow_mode,
        local_staging=local_staging,
        auth_header=auth_header,
        stealth_mode=stealth_mode,
        engagement_id=engagement_id
    )

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

    if scan.get("report_file") and (settings.STATIC_DIR / scan["report_file"]).exists():
        return RedirectResponse(f"/static/{scan['report_file']}")

    res = await generate_report_for_scan(scan["id"])
    if isinstance(res, JSONResponse):
        import json
        body = json.loads(res.body.decode())
        if "download_url" in body:
            return RedirectResponse(body["download_url"])
    return res

