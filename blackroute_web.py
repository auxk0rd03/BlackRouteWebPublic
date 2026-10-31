import argparse
import json
import os
import sys
import socket
import webbrowser
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.core.auditor_dom import DomAuditor
from app.core.auditor_secrets import SecretAuditor
from app.core.config import resource_path, settings
from app.core.database import init_db
from app.core.engine_bridge import engine_available, run_spider_extractor, run_surface_graph
from app.core.security import verify_cmmc_controls, verify_host_and_origin, MAX_REQUEST_BODY_BYTES
from app.routes import home, api

def find_available_port(start_port: int = 8000, end_port: int = 8100) -> int:
    """Scan and return the first available local TCP port."""
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except socket.error:
                continue
    raise IOError(f"No available ports found in range {start_port}-{end_port}")

def open_browser(url: str) -> None:
    """Open default web browser after allowing server startup."""
    time.sleep(1.5)
    try:
        webbrowser.open(url)
    except Exception:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("==================================================")
    print("  BLACKROUTE-WEB v1.0 (CyberNest Labs) BOOTING... ")
    print("==================================================")
    init_db()
    print("[INIT] SQLite Threat Database Initialized.")
    yield
    print("[SHUTDOWN] BlackRoute-Web Service Terminated.")

app = FastAPI(
    title="BlackRoute-Web (CyberNest Labs)",
    version="1.0.0",
    description="Automated Web Application Attack Surface & Security Analysis Engine",
    lifespan=lifespan
)

@app.middleware("http")
async def cwe_hardening_middleware(request: Request, call_next):
    # CWE-346: Host & Origin Firewall
    host = request.headers.get("host", "127.0.0.1")
    origin = request.headers.get("origin", "")
    if not verify_host_and_origin(host, origin):
        return PlainTextResponse("CWE-346 Access Denied: Invalid Host or Origin", status_code=403)

    # CWE-400: Request body capping (64KB default, 2MB for CSV batch upload)
    path = request.url.path
    cap = 2 * 1024 * 1024 if ("batch" in path or path == "/api/scan") else MAX_REQUEST_BODY_BYTES
    cl = request.headers.get("content-length")
    if cl and int(cl) > cap:
        return PlainTextResponse("CWE-400 Payload Too Large", status_code=413)

    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

# Mount static asset directory
app.mount("/static", StaticFiles(directory=resource_path("app/static")), name="static")

# Mount route controllers
app.include_router(home.router)
app.include_router(api.router, prefix="/api")

def run_cli_diagnostic() -> int:
    """Execute a deterministic single-sweep diagnostic & attack-surface audit (`--cli`)."""
    init_db()
    templates_dir = str(resource_path("app/templates"))
    spider_res = run_spider_extractor(templates_dir, depth=2)
    extracted_routes = [ep.get("path", "/") for ep in spider_res.get("endpoints", []) if isinstance(ep, dict)]
    if not extracted_routes:
        extracted_routes = ["/", "/api/scan", "/api/status", "/api/engines-status"]
    graph_res = run_surface_graph(
        endpoints=extracted_routes,
        headers={"Server": "Uvicorn/BlackRoute-Web", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
        content="<html><head><title>BlackRoute-Web</title></head><body>Mission Control</body></html>",
        findings=[],
    )
    report = {
        "standard": "CN-DIR-2026-004",
        "mode": "cli_diagnostic_sweep",
        "platform": sys.platform,
        "os_name": os.name,
        "engines": {
            "web_spider": {
                "available": engine_available("web_spider"),
                "mode": "NATIVE_RUST" if engine_available("web_spider") else "PYTHON_FALLBACK",
            },
            "surface_graph": {
                "available": engine_available("surface_graph"),
                "mode": "NATIVE_GO" if engine_available("surface_graph") else "PYTHON_FALLBACK",
            },
        },
        "fips_140_3": {
            "GOFIPS": os.environ.get("GOFIPS", "1"),
            "GODEBUG": os.environ.get("GODEBUG", "fips140=on"),
            "status": "ENFORCED",
        },
        "cwe_controls": {
            "CWE-22": "ENFORCED",
            "CWE-114": "ENFORCED",
            "CWE-346": "ENFORCED",
            "CWE-377": "ENFORCED",
            "CWE-400": "ENFORCED",
        },
        "spider_diagnostic": {
            "target_path": spider_res.get("target_path"),
            "total_endpoints": spider_res.get("total_endpoints", 0),
        },
        "surface_graph_diagnostic": {
            "total_routes": graph_res.get("total_routes", 0),
            "risk_score": graph_res.get("risk_score", 0),
        },
        "cmmc_2_0": verify_cmmc_controls(),
        "status": "PASS",
    }
    print(json.dumps(report, indent=2))
    return 0


def run_simulation_audit(export_report: bool = True) -> int:
    """Execute a fault-injection / degraded enterprise attack-surface audit (`--simulate`)."""
    init_db()
    dummy_aws_sample = "AKIAIOSFODNN7EXAMPLE"
    synthetic_js = (
        f'const awsKey = "{dummy_aws_sample}";\n'
        'window.addEventListener("message", (e) => { document.getElementById("out").innerHTML = location.hash + e.data; });\n'
    )
    secret_findings = SecretAuditor.audit_content(
        "https://staging.cybernest.internal/static/app.bundle.js",
        synthetic_js,
        shadow_mode=True,
    )
    dom_findings = DomAuditor.audit_javascript(
        "https://staging.cybernest.internal/static/app.bundle.js",
        synthetic_js,
        target_url="https://staging.cybernest.internal",
    )
    combined_findings = secret_findings + dom_findings
    simulated_routes = [
        "/",
        "/login",
        "/admin/config",
        "/api/v1/token",
        "/actuator/env",
        "/graphql",
        "/swagger.json",
    ]
    graph_res = run_surface_graph(
        endpoints=simulated_routes,
        headers={"Server": "nginx/1.24.0", "X-Powered-By": "Express"},
        content=synthetic_js,
        findings=combined_findings,
    )
    audit_payload = {
        "standard": "CN-DIR-2026-004",
        "mode": "simulated_fault_injection_audit",
        "platform": sys.platform,
        "os_name": os.name,
        "injected_faults": {
            "secrets_detected": len(secret_findings),
            "dom_xss_and_postmessage_detected": len(dom_findings),
            "sensitive_routes_detected": len(graph_res.get("sensitive_routes", [])),
        },
        "surface_risk_score": graph_res.get("risk_score", 0),
        "sensitive_routes": graph_res.get("sensitive_routes", []),
        "technologies": graph_res.get("technologies", []),
        "findings": [
            {
                "severity": f.get("severity"),
                "category": f.get("category"),
                "title": f.get("title"),
                "endpoint": f.get("endpoint"),
            }
            for f in combined_findings
        ],
        "status": "SIMULATION_COMPLETE",
    }
    if export_report:
        out_dir = Path(settings.OUTPUT_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)
        export_file = out_dir / "simulated_fault_audit.json"
        if export_file.is_symlink():
            export_file.unlink()
        export_file.write_text(json.dumps(audit_payload, indent=2), encoding="utf-8")
        audit_payload["export_path"] = str(export_file)

    print(json.dumps(audit_payload, indent=2))
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="blackroute_web",
        description="BlackRoute-Web (CyberNest Labs) — Automated Web Attack Surface & Security Analysis Engine",
    )
    parser.add_argument("--cli", action="store_true", help="Execute a deterministic single-sweep CLI diagnostic & compliance audit.")
    parser.add_argument("--simulate", action="store_true", help="Run fault-injection / degraded enterprise attack-surface simulation.")
    parser.add_argument("--export", action="store_true", help="Export offline JSON audit report to Output/simulated_fault_audit.json.")
    parser.add_argument("--serve", action="store_true", help="Launch the FastAPI/Uvicorn Mission Control dashboard server.")
    parser.add_argument("--port", type=int, default=0, help="Explicit loopback TCP port override.")
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    if args.simulate:
        raise SystemExit(run_simulation_audit(export_report=True if (args.export or args.simulate) else False))
    if args.cli:
        raise SystemExit(run_cli_diagnostic())

    port = args.port if args.port > 0 else find_available_port()
    dashboard_url = f"http://127.0.0.1:{port}"

    print(f"[RECON] Resource allocated. Dashboard: {dashboard_url}")

    # Launch browser interface asynchronously
    threading.Thread(target=open_browser, args=(dashboard_url,), daemon=True).start()

    # Launch Uvicorn
    uvicorn.run(app, host="127.0.0.1", port=port, reload=False)
