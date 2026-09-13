import datetime
import html
import threading
import uuid
from typing import Optional

from fastapi import APIRouter, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse

from app.core.database import get_latest_scan_findings
from app.core.engine_bridge import engine_available
from app.core.scanner import WebScanner, SCAN_LOGS

router = APIRouter()
logs_lock = threading.Lock()

@router.post("/scan", response_class=HTMLResponse)
async def start_scan(
    background_tasks: BackgroundTasks,
    target_url: str = Form(...),
    shadow_mode: bool = Form(False),
    local_staging: bool = Form(False),
    auth_header: Optional[str] = Form(None)
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
        auth_header=auth_header
    )

    background_tasks.add_task(scanner.run_pipeline)

    return f"""
    <div class="log-entry info">[TARGET ENGAGED] {safe_display}</div>
    <div class="log-entry info">[MISSION ORCHESTRATOR] Launching Reconnaissance and Security Pipeline...</div>
    <div hx-get="/api/stream-logs" hx-trigger="every 800ms" hx-swap="beforeend"></div>
    """

@router.get("/stream-logs", response_class=HTMLResponse)
async def stream_logs():
    """Atomically consume and ship logs to the browser stream."""
    with logs_lock:
        logs_to_ship = list(SCAN_LOGS)
        SCAN_LOGS.clear()
    return "".join(logs_to_ship)

@router.get("/status")
async def get_status():
    return {"status": "ready", "system": "BlackRoute-Web v1.0"}

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
    html_out += '<span style="background: rgba(0,0,0,0.3); border: 1px solid var(--accent-color); padding: 2px 7px; border-radius: 3px; font-size: 0.72em; color: var(--accent-color);">[Python] DAST Pipeline: ONLINE</span>'
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
                    "description": f"Audited Endpoint: {endpoint} | Remediation: {f.get('remediation', '')}"
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
                "description": f"Category: {f.get('category')} | Severity: {f.get('severity')} | Endpoint: {f.get('endpoint')}",
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
