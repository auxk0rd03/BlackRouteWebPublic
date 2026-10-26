import asyncio
import collections
import hashlib
import html
import os
import re
import shutil
import tempfile
import threading
import secrets
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import uuid

import aiofiles
import httpx
from bs4 import BeautifulSoup

from app.core.config import settings
from app.core.security import (
    validate_target_url,
    normalize_target_url,
    resolve_sandboxed_path,
    sanitize_filename,
    is_safe_subresource_url,
)
from app.core.database import save_scan_record
from app.core.engine_bridge import run_spider_extractor, run_surface_graph, _resolve_webpack_chunks_python
from app.core.auditor_headers import HeaderAuditor
from app.core.auditor_secrets import SecretAuditor
from app.core.auditor_api_routes import ApiRouteAuditor
from app.core.auditor_dom import DomAuditor
from Sources.Utilities.vids_pdf_gen import (
    generate_web_report,
    is_vendor_observation,
    extract_vendor_name,
    extract_target_asset,
    STEALTH_CURL_HEADERS_BLOCK,
    ensure_stealth_curl_poc,
    build_bug_bounty_markdown_triage,
)

SCAN_LOGS: List[str] = []
LOG_SUBSCRIBERS: Set[asyncio.Queue] = set()
LOGS_LOCK = threading.Lock()

def broadcast_log(entry: str) -> None:
    """Broadcast log entry to all active SSE subscribers."""
    for queue in list(LOG_SUBSCRIBERS):
        try:
            queue.put_nowait(entry)
        except Exception:
            pass


def build_markdown_triage(scan: Dict[str, Any], findings: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> str:
    """Build standardized, pre-formatted Bug Bounty & Triage submission report in Markdown ready for HackerOne/Jira."""
    return build_bug_bounty_markdown_triage(scan, findings, endpoints)


def generate_target_output_artifacts(
    target_index: int,
    scan_id: int,
    report_data: Dict[str, Any],
    findings: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]],
    base_output_dir: Optional[Path] = None,
    existing_pdf_filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate isolated per-target output artifacts under Output/Targ00N/:
    - blackroute_triage_scan_<scan_id>.md
    - BlackRoute_Web_Report_<YYYYMMDD_HHMMSS>.pdf
    """
    root_dir = (Path(base_output_dir) if base_output_dir else settings.OUTPUT_DIR).resolve()
    os.makedirs(root_dir, exist_ok=True)
    safe_target_idx = max(1, int(target_index))
    targ_folder = sanitize_filename(f"Targ{safe_target_idx:03d}")
    targ_dir = resolve_sandboxed_path(root_dir, targ_folder)
    os.makedirs(targ_dir, exist_ok=True)

    # Clean any stale files inside this target subfolder (never follow symlinks)
    for item in targ_dir.iterdir():
        if not item.is_symlink() and item.is_file() and (item.suffix in (".md", ".pdf")):
            try:
                item.unlink()
            except OSError:
                pass

    # 1. Write Markdown Triage Report: blackroute_triage_scan_<scan_id>.md
    effective_scan_id = int(scan_id) if scan_id is not None else safe_target_idx
    md_filename = sanitize_filename(
        f"blackroute_triage_scan_{effective_scan_id}.md",
        allowed_extensions=(".md",)
    )
    md_path = resolve_sandboxed_path(targ_dir, md_filename)
    scan_meta = {
        "id": effective_scan_id,
        "target_url": report_data.get("target_url", ""),
        "risk_score": report_data.get("risk_score", 15)
    }
    md_content = build_markdown_triage(scan_meta, findings, endpoints)
    md_path.write_text(md_content, encoding="utf-8")

    # 2. Write or copy PDF Report: BlackRoute_Web_Report_<YYYYMMDD_HHMMSS>.pdf
    pdf_filename = ""
    static_root = settings.STATIC_DIR.resolve()
    os.makedirs(static_root, exist_ok=True)
    if existing_pdf_filename:
        try:
            safe_existing = sanitize_filename(str(existing_pdf_filename), allowed_extensions=(".pdf",))
            static_pdf_path = resolve_sandboxed_path(static_root, safe_existing)
            if static_pdf_path.is_file() and not static_pdf_path.is_symlink():
                dest_pdf_path = resolve_sandboxed_path(targ_dir, safe_existing)
                shutil.copy2(static_pdf_path, dest_pdf_path)
                pdf_filename = safe_existing
        except (ValueError, OSError):
            pdf_filename = ""

    if not pdf_filename:
        generated_name = generate_web_report(report_data, output_dir=str(targ_dir))
        pdf_filename = sanitize_filename(generated_name, allowed_extensions=(".pdf",))
        # Ensure copy in STATIC_DIR for dashboard viewing
        try:
            src_pdf = resolve_sandboxed_path(targ_dir, pdf_filename)
            dst_pdf = resolve_sandboxed_path(static_root, pdf_filename)
            shutil.copy2(src_pdf, dst_pdf)
        except (ValueError, OSError):
            pass

    return {
        "target_folder": targ_folder,
        "target_dir": str(targ_dir),
        "markdown_file": md_filename,
        "pdf_file": pdf_filename,
        "scan_id": effective_scan_id
    }

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings based on (category, title, endpoint) tuple."""
    seen = set()
    deduplicated = []
    for finding in findings:
        # Create a unique key based on category, title, and endpoint
        key = (
            finding.get("category", "").lower(),
            finding.get("title", "").lower(),
            finding.get("endpoint", "").lower()
        )
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
    return deduplicated


def generate_curl_poc(finding: Dict[str, Any]) -> str:
    """
    Generate a functional, reproducible cURL proof-of-concept command for a finding,
    automatically embedding full L7 stealth browser persona headers to prevent edge WAF 403 blocks.
    """
    endpoint = finding.get("endpoint", "")
    category = finding.get("category", "").upper()
    title = finding.get("title", "").lower()

    if not endpoint:
        endpoint = "https://target.domain/"

    if category == "HEADERS":
        if "cors" in title or "origin" in title:
            tested_origin = finding.get("tested_origin")
            if not tested_origin:
                parsed = urllib.parse.urlparse(endpoint)
                netloc = parsed.netloc or "target.domain"
                tested_origin = f"https://origin-verify.{netloc}"
            return f'curl -s -i "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK} \\\n  -H "Origin: {tested_origin}"'
        return f'curl -s -I "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK}'

    elif category == "COOKIES":
        return f'curl -s -I "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK} \\\n  | grep -i "set-cookie"'

    elif category == "SECRETS":
        search_hint = finding.get("search_hint", "")
        if not search_hint:
            evidence = finding.get("evidence", "")
            if "AWS_KEY" in evidence:
                search_hint = "AKIA"
            elif "STRIPE_SECRET" in evidence:
                search_hint = "sk_live_"
            elif "OPENAI" in evidence:
                search_hint = "sk-"
            elif "GITHUB" in evidence:
                search_hint = "ghp_"
            elif "GOOGLE" in evidence:
                search_hint = "AIza"
        if search_hint:
            return f'curl -s "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK} \\\n  | grep -n -C 2 "{search_hint}"'
        return f'curl -s "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK}'

    elif category == "API_EXPOSURE":
        if "graphql" in title or "introspection" in title:
            if finding.get("curl_command"):
                return ensure_stealth_curl_poc(finding["curl_command"], endpoint)
            return (
                f'curl -s -X POST "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK} \\\n'
                f'  -H "Content-Type: application/json" \\\n'
                f'  -d \'{{"query": "query IntrospectionQuery{{__schema{{queryType{{name}}mutationType{{name}}subscriptionType{{name}}types{{name kind description}}}}}}}}\' \\\n'
                f'  | jq .'
            )
        return f'curl -s -i "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK}'

    elif category == "DOM_XSS":
        search_hint = finding.get("search_hint", "")
        if not search_hint:
            if "postmessage" in title:
                search_hint = "addEventListener"
            else:
                search_hint = "innerHTML"
        return f'curl -s "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK} \\\n  | grep -n -C 3 "{search_hint}"'

    return f'curl -s -i "{endpoint}"{STEALTH_CURL_HEADERS_BLOCK}'


def generate_html_poc(finding: Dict[str, Any]) -> Optional[str]:
    """Generate standalone HTML proof-of-concept files for certain vulnerability types."""
    endpoint = finding.get("endpoint", "")
    category = finding.get("category", "").upper()
    title = finding.get("title", "").lower()

    if not endpoint:
        return None

    # Clickjacking PoC (missing X-Frame-Options)
    if category == "HEADERS" and ("clickjacking" in title or "frame" in title or "x-frame-options" in title):
        parsed = urllib.parse.urlparse(endpoint)
        target_host = parsed.netloc or "target.domain"
        
        html_poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {endpoint}</title>
    <style>
        body {{ margin: 0; padding: 0; }}
        .overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.7);
            z-index: 10;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
            font-size: 24px;
            color: #333;
        }}
        .target-frame {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
            z-index: 5;
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div class="overlay">
        <div>
            <h2>Clickjacking Vulnerability Demonstration</h2>
            <p>Target: {endpoint}</p>
            <p>The target site is loaded in an iframe below.</p>
            <p>This demonstrates missing X-Frame-Options protection.</p>
        </div>
    </div>
    <iframe src="{endpoint}" class="target-frame"></iframe>
</body>
</html>"""
        return html_poc

    # CORS Misconfiguration PoC
    elif category == "HEADERS" and ("cors" in title or "origin" in title):
        tested_origin = finding.get("tested_origin")
        if not tested_origin:
            parsed = urllib.parse.urlparse(endpoint)
            netloc = parsed.netloc or "target.domain"
            tested_origin = f"https://origin-verify.{netloc}"
        
        html_poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CORS Misconfiguration PoC - {endpoint}</title>
    <script>
        function testCORS() {{
            const targetUrl = '{endpoint}';
            const testOrigin = '{tested_origin}';
            
            fetch(targetUrl, {{
                method: 'GET',
                headers: {{
                    'Origin': testOrigin
                }},
                credentials: 'include'
            }})
            .then(response => {{
                const acao = response.headers.get('Access-Control-Allow-Origin');
                const acac = response.headers.get('Access-Control-Allow-Credentials');
                
                document.getElementById('results').innerHTML = `
                    <h3>CORS Test Results</h3>
                    <p><strong>Target:</strong> ${{targetUrl}}</p>
                    <p><strong>Tested Origin:</strong> ${{testOrigin}}</p>
                    <p><strong>Access-Control-Allow-Origin:</strong> ${{acao || 'Not set'}}</p>
                    <p><strong>Access-Control-Allow-Credentials:</strong> ${{acac || 'Not set'}}</p>
                    <p><strong>Status:</strong> ${{acao === '*' ? 'VULNERABLE - Wildcard origin accepted' : 'Check response above'}}</p>
                `;
            }})
            .catch(error => {{
                document.getElementById('results').innerHTML = `<p>Error: ${{error.message}}</p>`;
            }});
        }}
    </script>
</head>
<body onload="testCORS()">
    <h1>CORS Misconfiguration Test</h1>
    <div id="results">Testing CORS configuration...</div>
</body>
</html>"""
        return html_poc

    # postMessage Origin Validation PoC
    elif category == "DOM_XSS" and "postmessage" in title:
        poc_info = DomAuditor.build_postmessage_poc(endpoint, endpoint)
        return poc_info["html_poc_content"]

    if finding.get("html_poc_content"):
        return finding["html_poc_content"]

    return None


class WebScanner:
    def __init__(
        self,
        target_url: str,
        shadow_mode: bool = False,
        local_staging: bool = False,
        auth_header: Optional[str] = None,
        stealth_mode: bool = True,
        engagement_id: Optional[str] = None,
        generate_pdf: bool = True,
        auth_macros: Optional[List[Dict[str, Any]]] = None,
        target_index: Optional[int] = None,
        output_dir: Optional[str] = None
    ):
        self.raw_target = target_url
        self.target_url = normalize_target_url(target_url) if target_url else ""
        self.shadow_mode = shadow_mode
        self.local_staging = local_staging
        self.auth_header = (
            auth_header.replace("\r", "").replace("\n", "").replace("\x00", "").strip()
            if auth_header else None
        )
        self.stealth_mode = stealth_mode
        self.engagement_id = (
            engagement_id.replace("\r", "").replace("\n", "").replace("\x00", "").strip()
            if engagement_id else None
        )
        self.generate_pdf = generate_pdf
        self.auth_macros = auth_macros or []  # Authentication macros for session refresh
        self.target_index = target_index
        self.output_dir = output_dir
        self.temp_dir: Optional[str] = None
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.pages_crawled: int = 0
        self.harvested_content: List[str] = []
        self.session_cookies: Dict[str, str] = {}  # Dynamic session management
        self.session_token: Optional[str] = None  # Dynamic bearer token
        self.scan_id: Optional[int] = None
        self.report_file: str = ""
        self.markdown_file: str = ""
        self.target_output_dir: Optional[str] = None
        self.risk_score: int = 15

    def log(self, message: str, log_type: str = "info") -> None:
        """Append log to buffer and broadcast in real time to SSE streams."""
        safe_type = html.escape(log_type)
        safe_message = html.escape(str(message))
        entry = f'<div class="log-entry {safe_type}">[{safe_type.upper()}] {safe_message}</div>'
        with LOGS_LOCK:
            SCAN_LOGS.append(entry)
        broadcast_log(entry)
        print(f"[{safe_type.upper()}] {message}")

    async def _execute_auth_macros(self, client: httpx.AsyncClient) -> bool:
        """Execute authentication macros to establish session."""
        if not self.auth_macros:
            return False
        
        self.log(f"Executing {len(self.auth_macros)} authentication macros...", "info")
        
        for macro in self.auth_macros:
            try:
                method = macro.get("method", "GET").upper()
                url = macro.get("url")
                headers = macro.get("headers", {})
                data = macro.get("data", {})
                json_data = macro.get("json", {})
                extract_token = macro.get("extract_token")
                extract_cookies = macro.get("extract_cookies", [])
                
                if not url:
                    self.log("Invalid macro: missing URL", "warn")
                    continue

                if method not in ("GET", "POST"):
                    self.log(f"Invalid macro HTTP method '{method}': only GET and POST permitted", "warn")
                    continue

                # Enforce SSRF and scheme boundary checks on auth macro target URL
                url = validate_target_url(str(url), allow_local_staging=self.local_staging)
                if isinstance(headers, dict):
                    headers = {
                        str(k).replace("\r", "").replace("\n", "").replace("\x00", ""):
                        str(v).replace("\r", "").replace("\n", "").replace("\x00", "")
                        for k, v in headers.items()
                    }
                else:
                    headers = {}
                
                # Make the authentication request
                if method == "POST":
                    if json_data:
                        resp = await client.post(url, json=json_data, headers=headers)
                    else:
                        resp = await client.post(url, data=data, headers=headers)
                else:
                    resp = await client.get(url, headers=headers)
                
                # Extract session token if specified
                if extract_token and resp.status_code == 200:
                    try:
                        token_data = resp.json()
                        # Support JSONPath-like extraction (e.g., "token", "data.access_token")
                        keys = extract_token.split(".")
                        token = token_data
                        for key in keys:
                            token = token.get(key) if isinstance(token, dict) else None
                            if token is None:
                                break
                        
                        if token:
                            self.session_token = str(token).replace("\r", "").replace("\n", "").replace("\x00", "").strip()
                            self.log(f"Extracted session token from {url}", "success")
                    except Exception as e:
                        self.log(f"Failed to extract token: {e}", "warn")
                
                # Extract cookies if specified
                if extract_cookies and resp.status_code == 200:
                    for cookie_name in extract_cookies:
                        if cookie_name in resp.cookies:
                            self.session_cookies[cookie_name] = resp.cookies[cookie_name]
                            self.log(f"Extracted cookie: {cookie_name}", "info")
                
                self.log(f"Auth macro executed: {method} {url} -> {resp.status_code}", "info")
                
            except Exception as e:
                self.log(f"Auth macro failed: {e}", "error")
                return False
        
        return True

    async def _refresh_session(self, client: httpx.AsyncClient) -> bool:
        """Refresh authentication session when 401 is detected."""
        if not self.auth_macros:
            return False
        
        self.log("Session expired (401 detected). Refreshing authentication...", "warn")
        return await self._execute_auth_macros(client)

    def _apply_auth_to_request(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Apply current authentication to request headers."""
        auth_headers = headers.copy()
        
        # Apply dynamic session token
        if self.session_token:
            auth_headers["Authorization"] = f"Bearer {self.session_token}"
        # Apply static auth header if provided
        elif self.auth_header:
            auth_headers["Authorization"] = self.auth_header
        
        # Apply engagement ID
        if self.engagement_id:
            auth_headers["X-Security-Engagement"] = self.engagement_id
            auth_headers["X-Authorized-Audit"] = "true"
        
        return auth_headers

    async def _finalize_and_persist_artifacts(
        self,
        validated_url: str,
        techs: List[Dict[str, str]],
        sensitive_routes: List[str],
        holistic_risk: int,
        status: str = "completed"
    ) -> Optional[int]:
        """Generate PDF/Markdown reports, persist scan record to SQLite, and populate Output/Targ00N/ if applicable."""
        self.risk_score = holistic_risk
        report_data = {
            "target_url": validated_url,
            "pages_crawled": self.pages_crawled,
            "endpoints_found": len(self.endpoints),
            "findings": self.findings,
            "technologies": techs,
            "sensitive_routes": sensitive_routes,
            "risk_score": holistic_risk
        }

        report_file = ""
        if self.generate_pdf:
            loop = asyncio.get_running_loop()
            report_file = await loop.run_in_executor(
                None,
                generate_web_report,
                report_data,
                str(settings.STATIC_DIR)
            )
            self.report_file = report_file
            self.log(f"VIDS PDF Report Generated: {report_file}", "success")
        else:
            self.log("Phase 7: Decoupled Reporting Mode Active — PDF Compilation Deferred (Available On-Demand).", "info")

        scan_id = None
        try:
            scan_id = save_scan_record(
                target_url=validated_url,
                findings=self.findings,
                endpoints=self.endpoints,
                pages_crawled=self.pages_crawled,
                report_file=report_file,
                status=status,
                risk_score=holistic_risk
            )
            self.scan_id = scan_id
            self.log("Scan record persisted to local SQLite database with cURL commands.", "info")
        except Exception as db_err:
            self.log(f"Database Persistence Warning: {db_err}", "warn")

        if self.target_index is not None or self.generate_pdf:
            loop = asyncio.get_running_loop()
            base_out = (Path(self.output_dir) if self.output_dir else settings.OUTPUT_DIR).resolve()
            # When running a standalone single-target scan, clean stale Targ* folders from prior runs
            if self.target_index is None and base_out.exists():
                for existing in base_out.iterdir():
                    if not existing.is_symlink() and existing.is_dir() and re.fullmatch(r"Targ\d+", existing.name):
                        if existing.resolve().is_relative_to(base_out):
                            shutil.rmtree(existing, ignore_errors=True)
            effective_idx = self.target_index if self.target_index is not None else 1
            artifact_info = await loop.run_in_executor(
                None,
                generate_target_output_artifacts,
                effective_idx,
                scan_id if scan_id is not None else effective_idx,
                report_data,
                self.findings,
                self.endpoints,
                base_out,
                report_file
            )
            self.markdown_file = artifact_info["markdown_file"]
            self.report_file = artifact_info["pdf_file"]
            self.target_output_dir = artifact_info["target_dir"]
            self.log(
                f"[ARTIFACT GENERATOR] Output/{artifact_info['target_folder']}/ populated: "
                f"{self.markdown_file}, {self.report_file}",
                "success"
            )

        return scan_id

    async def run_pipeline(self, clear_logs: bool = True) -> None:
        """Execute the end-to-end web cybersecurity audit pipeline."""
        global SCAN_LOGS
        if clear_logs:
            with LOGS_LOCK:
                SCAN_LOGS.clear()

        self.log("Initializing BlackRoute-Web Mission Protocol...", "info")
        self.temp_dir = tempfile.mkdtemp(prefix="br_web_")
        os.chmod(self.temp_dir, 0o700)

        try:
            # 1. SSRF & Target Validation
            self.log(f"Validating target scope: {self.target_url}", "info")
            try:
                validated_url = validate_target_url(self.target_url, allow_local_staging=self.local_staging)
                if self.local_staging:
                    self.log("[STAGE SCOPE] Local Staging Mode ACTIVE (Auditing internal target).", "warn")
            except Exception as val_err:
                self.log(f"Target Validation Aborted: {val_err}", "error")
                if self.target_index is not None and "Unable to resolve host" in str(val_err):
                    await self._finalize_and_persist_artifacts(self.target_url, [], [], 15, status="unreachable")
                return

            req_headers = settings.get_stealth_headers(engagement_id=self.engagement_id)
            
            # Execute authentication macros if provided
            async with httpx.AsyncClient(headers=req_headers, verify=False, follow_redirects=True, timeout=12.0) as auth_client:
                if await self._execute_auth_macros(auth_client):
                    self.log("Authentication macros executed successfully.", "success")
                    # Update headers with dynamic auth
                    req_headers = self._apply_auth_to_request(req_headers)
                else:
                    # Apply static auth header if no macros or macros failed
                    req_headers = self._apply_auth_to_request(req_headers)
                    if self.auth_header:
                        self.log("Static authentication header configured.", "info")
                
                if self.engagement_id:
                    self.log(f"[SOC TAG] Active Engagement Tagging & Akamai Edge Cache Bypass Engaged: X-Security-Engagement: {self.engagement_id}", "info")

            # 2. Phase 1: Header, Cookie, CORS & Transport Posture Audit
            self.log("Phase 1: Assessing HTTP Headers, Cookies, and Transport Security...", "info")
            initial_resp = None
            async with httpx.AsyncClient(headers=req_headers, verify=False, follow_redirects=True, timeout=12.0) as client:
                try:
                    initial_resp = await client.get(validated_url)
                    self.pages_crawled += 1
                    status = initial_resp.status_code
                    self.log(f"Target Acquired: HTTP {status} ({len(initial_resp.content)} bytes)", "success")

                    # Check WAF indications on initial response
                    from app.core.auditor_api_routes import is_waf_block
                    if is_waf_block(initial_resp):
                        self.log("[WAF NOTICE] Target returned perimeter defense / rate-limit signals. Engaging stealth throttles.", "warn")

                    # Header Audit
                    header_findings = HeaderAuditor.audit_response_headers(str(initial_resp.url), initial_resp.headers, status)
                    self.findings.extend(header_findings)
                    self.log(f"Header Posture Evaluated: {len(header_findings)} anomalies flagged.", "info")

                    # Cookie Audit
                    cookie_headers = initial_resp.headers.get_list("set-cookie")
                    if cookie_headers:
                        cookie_findings = HeaderAuditor.audit_cookies(str(initial_resp.url), cookie_headers)
                        self.findings.extend(cookie_findings)
                        self.log(f"Cookie Hygiene Checked: {len(cookie_findings)} security flags raised.", "info")

                    # CORS Dynamic Audit (actively test origin reflection with randomized benign probe origin to prevent SIEM alerts)
                    parsed_host = urllib.parse.urlparse(validated_url).netloc
                    probe_nonce = secrets.token_hex(4)
                    benign_origin = f"https://probe-{probe_nonce}.{parsed_host}"
                    cors_resp = await client.get(validated_url, headers={"Origin": benign_origin})
                    acao = cors_resp.headers.get("access-control-allow-origin", "")
                    acac = cors_resp.headers.get("access-control-allow-credentials", "")
                    cors_findings = HeaderAuditor.audit_cors(str(initial_resp.url), acao, acac, benign_origin)
                    self.findings.extend(cors_findings)

                except Exception as net_err:
                    self.log(f"Network Handshake Failed on {validated_url}: {net_err}", "error")
                    if self.target_index is not None:
                        await self._finalize_and_persist_artifacts(validated_url, [], [], 15, status="unreachable")
                    return

            if initial_resp is None:
                self.log("No response received from target.", "error")
                if self.target_index is not None:
                    await self._finalize_and_persist_artifacts(validated_url, [], [], 15, status="unreachable")
                return

            base_content = initial_resp.text
            self.harvested_content.append(base_content)

            # Save main page to temp dir for engine processing (strictly confined to temp_dir)
            main_page_path = str(resolve_sandboxed_path(self.temp_dir, "index.html"))
            async with aiofiles.open(main_page_path, "w", encoding="utf-8", errors="ignore") as f:
                await f.write(base_content)

            # 3. Phase 2: Web Spider & Asset Harvesting (Rust Engine with Bounded BFS Queue)
            self.log("Phase 2: Spidering Web Assets & Extracting Client Endpoints (Bounded BFS)...", "info")
            parsed_root = urllib.parse.urlparse(validated_url)
            target_domain = (parsed_root.netloc or "").split(":")[0].lower()

            def is_allowed_crawler_domain(u: str) -> bool:
                if not u or u.startswith(("javascript:", "mailto:", "tel:", "#")):
                    return False
                try:
                    p = urllib.parse.urlparse(u)
                    if not p.netloc:
                        return True
                    h = p.netloc.split(":")[0].lower()
                    return h == target_domain or h.endswith("." + target_domain)
                except Exception:
                    return False

            junk_crawl_exts = ('.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.css', '.mp4')
            max_crawl_pages = 25
            max_crawl_scripts = 50
            crawl_depth = 2

            visited_pages = set([validated_url])
            crawl_queue = collections.deque([(validated_url, 0)])
            downloaded_scripts = []
            seen_scripts = set()

            async with httpx.AsyncClient(headers=req_headers, verify=False, follow_redirects=True, timeout=10.0) as crawl_client:
                while crawl_queue and len(visited_pages) <= max_crawl_pages:
                    curr_url, curr_depth = crawl_queue.popleft()
                    
                    page_content = base_content if curr_url == validated_url else None
                    if page_content is None:
                        await asyncio.sleep(0.04)
                        try:
                            resp = await crawl_client.get(curr_url)
                            if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                                page_content = resp.text
                                self.pages_crawled += 1
                                self.harvested_content.append(page_content)
                                p_hash = hashlib.sha256(curr_url.encode("utf-8")).hexdigest()[:12]
                                p_filename = sanitize_filename(f"page_{p_hash}.html", allowed_extensions=(".html",))
                                p_path = str(resolve_sandboxed_path(self.temp_dir, p_filename))
                                async with aiofiles.open(p_path, "w", encoding="utf-8", errors="ignore") as f:
                                    await f.write(page_content)
                        except Exception:
                            continue

                    if not page_content:
                        continue

                    # Parse HTML links and scripts
                    soup = BeautifulSoup(page_content, "html.parser")

                    # Discovered scripts from HTML
                    for s in soup.find_all("script", src=True):
                        s_src = s.get("src", "").strip()
                        if s_src and len(downloaded_scripts) < max_crawl_scripts:
                            s_url = urllib.parse.urljoin(curr_url, s_src)
                            if s_url not in seen_scripts:
                                seen_scripts.add(s_url)
                                await asyncio.sleep(0.04)
                                try:
                                    js_resp = await crawl_client.get(s_url)
                                    if js_resp.status_code == 200 and len(js_resp.content) <= settings.MAX_JS_ASSET_SIZE:
                                        s_hash = hashlib.sha256(s_url.encode("utf-8")).hexdigest()[:12]
                                        s_filename = sanitize_filename(f"asset_{s_hash}.js", allowed_extensions=(".js",))
                                        s_path = str(resolve_sandboxed_path(self.temp_dir, s_filename))
                                        async with aiofiles.open(s_path, "wb") as f:
                                            await f.write(js_resp.content)
                                        downloaded_scripts.append((s_url, s_path, js_resp.text))
                                        self.harvested_content.append(js_resp.text)

                                        # Webpack / Vite / Rollup Chunk Resolver:
                                        # Detect runtime chunks or chunk maps and harvest split code chunks
                                        split_chunks = _resolve_webpack_chunks_python(js_resp.text)
                                        for sc in split_chunks:
                                            if len(downloaded_scripts) >= max_crawl_scripts:
                                                break
                                            chunk_url = urllib.parse.urljoin(s_url, sc)
                                            if chunk_url not in seen_scripts:
                                                seen_scripts.add(chunk_url)
                                                await asyncio.sleep(0.04)
                                                try:
                                                    c_resp = await crawl_client.get(chunk_url)
                                                    if c_resp.status_code == 200 and len(c_resp.content) <= settings.MAX_JS_ASSET_SIZE:
                                                        c_hash = hashlib.sha256(chunk_url.encode("utf-8")).hexdigest()[:12]
                                                        c_filename = sanitize_filename(f"chunk_{c_hash}.js", allowed_extensions=(".js",))
                                                        c_path = str(resolve_sandboxed_path(self.temp_dir, c_filename))
                                                        async with aiofiles.open(c_path, "wb") as f:
                                                            await f.write(c_resp.content)
                                                        downloaded_scripts.append((chunk_url, c_path, c_resp.text))
                                                        self.harvested_content.append(c_resp.text)
                                                except Exception:
                                                    pass
                                except Exception:
                                    pass

                    # Enqueue HTML links for bounded BFS traversal
                    if curr_depth + 1 <= crawl_depth:
                        for a in soup.find_all("a", href=True):
                            link = a.get("href", "").strip()
                            if link and not link.startswith(("javascript:", "mailto:", "tel:", "#")):
                                full_link = urllib.parse.urljoin(curr_url, link)
                                parsed_link = urllib.parse.urlparse(full_link)
                                path_lower = parsed_link.path.lower()
                                if is_allowed_crawler_domain(full_link) and not path_lower.endswith(junk_crawl_exts):
                                    clean_link = urllib.parse.urlunparse((parsed_link.scheme, parsed_link.netloc, parsed_link.path, '', '', ''))
                                    if clean_link not in visited_pages and len(visited_pages) < max_crawl_pages:
                                        visited_pages.add(clean_link)
                                        crawl_queue.append((full_link, curr_depth + 1))

            self.log(f"BFS Crawl Harvested: {len(visited_pages)} pages and {len(downloaded_scripts)} scripts/split-chunks.", "info")

            # Execute Rust web_spider on downloaded assets with bounded depth and target domain
            spider_result = run_spider_extractor(self.temp_dir, depth=crawl_depth, target_domain=target_domain)
            extracted_endpoints = spider_result.get("endpoints", [])
            self.log(f"Spidering Complete: {len(extracted_endpoints)} client routes and API paths harvested.", "success")

            for ep in extracted_endpoints:
                self.endpoints.append({
                    "url": ep.get("path", ""),
                    "method": ep.get("method", "GET"),
                    "status_code": 200,
                    "content_type": ep.get("type", "endpoint"),
                    "source": "JS_SPIDER"
                })

            # 4. Phase 3: Secret & Credential Leak Detection (With Shannon Entropy Filtering)
            self.log("Phase 3: Scanning Assets for Hardcoded Secrets with Shannon Entropy Evaluation...", "info")
            total_secrets = 0
            # Check main HTML
            html_secrets = SecretAuditor.audit_content(validated_url, base_content, shadow_mode=self.shadow_mode)
            self.findings.extend(html_secrets)
            total_secrets += len(html_secrets)

            # Check each downloaded script
            for script_url, _, js_content in downloaded_scripts:
                s_secrets = SecretAuditor.audit_content(script_url, js_content, shadow_mode=self.shadow_mode)
                self.findings.extend(s_secrets)
                total_secrets += len(s_secrets)

            self.log(f"Credential Leak Analysis Complete: {total_secrets} verified high-entropy secrets flagged.", "info" if total_secrets == 0 else "warn")

            # 5. Phase 4: Client-Side DOM XSS & postMessage Auditing
            self.log("Phase 4: Auditing Client-Side DOM Sinks & postMessage Handlers...", "info")
            dom_findings_count = 0
            for script_url, _, js_content in downloaded_scripts:
                dom_findings = DomAuditor.audit_javascript(script_url, js_content, target_url=validated_url)
                self.findings.extend(dom_findings)
                dom_findings_count += len(dom_findings)
            self.log(f"DOM Risk Analysis Complete: {dom_findings_count} sink/origin risks detected.", "info")

            # 6. Phase 5: API Surface & Sensitive Route Discovery (Stealth Protocol vs. Active Mode)
            if self.stealth_mode:
                self.log("[STEALTH PROTOCOL] Suppressed intrusive active path probes (/.env, /.git, /actuators) to preserve zero SOC alarm footprint.", "info")
            else:
                self.log("Phase 5: Probing for Exposed OpenAPI/Swagger Schemas, Actuators & Git Metadata (Paced & Jittered)...", "info")
                
                # Pass discovered endpoints to API auditor for GraphQL detection
                discovered_endpoints = [e.get("url") for e in self.endpoints if e.get("url")]
                graphql_endpoints = [ep for ep in discovered_endpoints if "graphql" in ep.lower()]
                
                if graphql_endpoints:
                    self.log(f"Discovered {len(graphql_endpoints)} GraphQL endpoints during spidering, will check for introspection.", "info")
                
                # Create a client with session refresh capability
                async with httpx.AsyncClient(headers=req_headers, verify=False, follow_redirects=True, timeout=12.0) as api_client:
                    api_findings = await ApiRouteAuditor.audit_api_surface(
                        validated_url, 
                        req_headers,
                        discovered_endpoints=discovered_endpoints
                    )
                    
                    # Verify discovered high-value routes
                    high_value_findings = await ApiRouteAuditor.verify_discovered_routes(
                        discovered_endpoints,
                        validated_url,
                        req_headers
                    )
                    api_findings.extend(high_value_findings)
                    
                    # Check for 401 responses and refresh session if needed
                    if any(f.get("endpoint", "").startswith("http") and "401" in str(f.get("evidence", "")) for f in api_findings):
                        if await self._refresh_session(api_client):
                            # Retry API probing with refreshed session
                            req_headers = self._apply_auth_to_request(req_headers)
                            api_findings = await ApiRouteAuditor.audit_api_surface(
                                validated_url, 
                                req_headers,
                                discovered_endpoints=discovered_endpoints
                            )
                            high_value_findings = await ApiRouteAuditor.verify_discovered_routes(
                                discovered_endpoints,
                                validated_url,
                                req_headers
                            )
                            api_findings.extend(high_value_findings)
                    
                    self.findings.extend(api_findings)
                    self.log(f"Surface Probing Complete: {len(api_findings)} exposed services identified.", "success" if len(api_findings) == 0 else "warn")

            # 6. Deduplicate findings to prevent duplicate reports from redirect chains
            original_count = len(self.findings)
            self.findings = deduplicate_findings(self.findings)
            if len(self.findings) < original_count:
                self.log(f"[DEDUPLICATION] Removed {original_count - len(self.findings)} duplicate findings from redirect chains.", "info")

            # 7. Smart Noise Filtering vs. Shadow Mode
            if not self.shadow_mode:
                suppressed = [f for f in self.findings if f.get("confidence", 1.0) < 0.75]
                if suppressed:
                    self.log(f"[SMART FILTER] Suppressed {len(suppressed)} low-confidence noise findings (< 0.75).", "warn")
                    self.findings = [f for f in self.findings if f.get("confidence", 1.0) >= 0.75]
            else:
                self.log("[SHADOW MODE] Preserving all raw findings across full confidence spectrum.", "warn")

            # 8. Generate Reproducible cURL Commands and HTML PoCs for Every Finding
            for f in self.findings:
                f["curl_command"] = generate_curl_poc(f)
                
                # Generate HTML PoC for certain vulnerability types (Clickjacking, CORS, postMessage)
                html_poc = generate_html_poc(f)
                if html_poc:
                    f["html_poc_content"] = html_poc
                    if not f.get("html_poc"):
                        f["html_poc"] = f"poc_{uuid.uuid4().hex[:8]}.html"
                    self.log(f"Generated HTML PoC: {f['html_poc']}", "info")

            # 9. Phase 6: Attack Surface Topology & Tech Fingerprinting (Go Engine with Normalized Scoring)
            self.log("Phase 6: Computing Attack Surface Topology & Stack Fingerprints (Go Engine)...", "info")
            all_paths = [e.get("url") for e in self.endpoints if e.get("url")]
            all_paths.extend([f.get("endpoint") for f in self.findings if f.get("endpoint")])
            combined_content = "\n".join(self.harvested_content[:10])

            # Preserve multi-value headers (like Set-Cookie) and redirect history
            surface_headers: Dict[str, Any] = {}
            for k in initial_resp.headers.keys():
                values = initial_resp.headers.get_list(k)
                surface_headers[k] = values if len(values) > 1 else values[0]
            # Ensure Set-Cookie directives are preserved as full list
            all_cookies = list(initial_resp.headers.get_list("set-cookie"))
            for hist in getattr(initial_resp, "history", []):
                for cookie in hist.headers.get_list("set-cookie"):
                    if cookie not in all_cookies:
                        all_cookies.append(cookie)
            if all_cookies:
                surface_headers["set-cookie"] = all_cookies

            surface_data = run_surface_graph(all_paths, surface_headers, combined_content, findings=self.findings)
            techs = surface_data.get("technologies", [])
            for t in techs:
                self.log(f"Detected Technology: [{t.get('category')}] {t.get('name')}", "info")

            # 10. Phase 7: Reporting & SQLite Persistence
            self.log("Phase 7: Generating CyberNest VIDS PDF Audit Report...", "info")

            # Composite Normalized Threat Score from Go Surface Graph Engine
            holistic_risk = surface_data.get("risk_score", 15)

            scan_id = await self._finalize_and_persist_artifacts(
                validated_url=validated_url,
                techs=techs,
                sensitive_routes=surface_data.get("sensitive_routes", []),
                holistic_risk=holistic_risk,
                status="completed"
            )

            # Inject Results Grid HTML for dynamic UI rendering
            self._render_results_ui(self.report_file, surface_data.get("risk_score", 20), techs, scan_id=scan_id)

        except Exception as exc:
            self.log(f"Critical Pipeline Failure: {exc}", "error")
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                self.log("Zero-Footprint Protocol: Cleaning temporary harvest directory...", "info")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.log("Audit Pipeline Sequence Finished.", "success")

    def _render_results_ui(self, report_file: str, risk_score: int, techs: List[Dict[str, str]], scan_id: Optional[int] = None) -> None:
        """Construct interactive results grid with reproducible cURL PoC buttons for HTMX UI swap."""
        actionable_findings = [f for f in self.findings if not is_vendor_observation(f)]
        vendor_findings = [f for f in self.findings if is_vendor_observation(f)]

        crit_count = sum(1 for f in actionable_findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in actionable_findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in actionable_findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in actionable_findings if f.get("severity") == "LOW")
        vendor_count = len(vendor_findings)

        safe_report = html.escape(os.path.basename(str(report_file))) if report_file else ""
        if safe_report:
            report_btn_html = f'<a href="/static/{safe_report}" target="_blank" class="btn btn-download">[ ACCESS VIDS AUDIT REPORT ]</a>'
        else:
            report_btn_html = '<a href="/api/export/report-latest" target="_blank" class="btn btn-download">[ GENERATE VIDS AUDIT REPORT ]</a>'

        tech_badges = "".join([
            f'<span style="background: rgba(95,168,160,0.15); border: 1px solid var(--accent-color); padding: 2px 6px; font-size: 0.75em; border-radius: 3px; margin-right: 4px;">{html.escape(t.get("name", ""))}</span>'
            for t in techs[:5]
        ])

        rows_html = ""
        for idx, f in enumerate(actionable_findings):
            sev = html.escape(str(f.get("severity", "INFO")))
            title = html.escape(str(f.get("title", "")))
            cat = html.escape(str(f.get("category", "")))
            endpoint = html.escape(str(f.get("endpoint", "")))
            conf = html.escape(str(f.get("confidence", 1.0)))
            curl_cmd = f.get("curl_command", "")
            safe_curl = html.escape(curl_cmd).replace('"', '&quot;')
            html_poc = f.get("html_poc", "")

            if len(endpoint) > 36:
                endpoint_display = endpoint[:33] + "..."
            else:
                endpoint_display = endpoint

            sev_class = f"sev-{sev.lower()}"

            # Generate additional buttons for HTML PoC
            poc_buttons = ""
            html_poc_content = f.get("html_poc_content", "")
            safe_html_poc_file = html.escape(os.path.basename(str(html_poc)), quote=True) if html_poc else ""
            if html_poc_content:
                safe_poc = html.escape(html_poc_content).replace('"', '&quot;')
                poc_buttons = f'<button onclick="copyHtmlPoC(this)" data-poc="{safe_poc}" class="btn" style="padding: 2px 8px; font-size: 0.72em; border-color: var(--border-secondary);">[COPY HTML PoC]</button>'
                if safe_html_poc_file:
                    poc_buttons += f' <button onclick="downloadHtmlPoC(\'{safe_html_poc_file}\')" class="btn" style="padding: 2px 8px; font-size: 0.72em; border-color: var(--border-secondary);">[HTML PoC File]</button>'
            elif safe_html_poc_file:
                poc_buttons = f'<button onclick="downloadHtmlPoC(\'{safe_html_poc_file}\')" class="btn" style="padding: 2px 8px; font-size: 0.72em; border-color: var(--border-secondary);">[HTML PoC File]</button>'

            rows_html += f"""
            <tr>
                <td class="col-sev {sev_class}">[{sev}]</td>
                <td class="col-cat">[{cat}]</td>
                <td class="col-title">
                    <div>{title}</div>
                    <div style="margin-top: 5px; display: flex; gap: 6px; align-items: center;">
                        <button onclick="copyCurlPoC(this)" data-curl="{safe_curl}" class="btn" style="padding: 2px 8px; font-size: 0.72em; border-color: var(--border-secondary);">[COPY cURL PoC]</button>
                        {poc_buttons}
                        <details style="font-size: 0.75em; color: var(--text-secondary); margin: 0;">
                            <summary style="cursor: pointer;">Command</summary>
                            <div style="background: var(--bg-color); border: 1px solid var(--border-secondary); padding: 4px; margin-top: 4px; font-family: var(--font-mono); font-size: 0.85em; word-break: break-all;">{html.escape(curl_cmd)}</div>
                        </details>
                    </div>
                </td>
                <td class="col-path">{endpoint_display}</td>
                <td class="col-conf">{conf}</td>
            </tr>
            """

        if not rows_html:
            rows_html = "<tr><td colspan='5' style='text-align: center; padding: 20px;'>No actionable vulnerabilities detected. Review VIDS Report.</td></tr>"

        # Construct Section B: Third-Party & Vendor Observations compact drawer/table
        vendor_section_html = ""
        if vendor_findings:
            v_rows = ""
            for vf in vendor_findings:
                v_name = html.escape(extract_vendor_name(vf))
                v_title = html.escape(vf.get("title", "Vendor Notice").replace("[Third-Party] ", ""))
                v_asset = html.escape(extract_target_asset(vf, self.target_url))
                assessment = "Expected vendor telemetry behavior"
                if "httponly" in v_title.lower():
                    assessment = "Client-side JS readable by design"
                elif "secure" in v_title.lower():
                    assessment = "Third-party edge cookie configuration"
                elif "samesite" in v_title.lower():
                    assessment = "Cross-domain vendor tag requirement"
                elif "postmessage" in v_title.lower():
                    assessment = "Third-party SDK iframe communication"

                v_rows += f"""
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 5px 8px; color: var(--accent-color); font-weight: 600;">{v_name}</td>
                    <td style="padding: 5px 8px;">{v_title}</td>
                    <td style="padding: 5px 8px; font-family: var(--font-mono); font-size: 0.85em; color: var(--text-secondary);">{v_asset}</td>
                    <td style="padding: 5px 8px; color: var(--text-secondary); font-size: 0.85em;">{assessment}</td>
                </tr>
                """

            vendor_section_html = f"""
            <details style="margin-top: 15px; border: 1px solid var(--border-secondary); padding: 8px 12px; border-radius: 4px; background: rgba(255,255,255,0.02);">
                <summary style="cursor: pointer; font-size: 0.82em; color: var(--sub-accent); font-weight: 600; display: flex; justify-content: space-between; align-items: center;">
                    <span>>> SECTION B: THIRD-PARTY &amp; VENDOR OBSERVATIONS ({vendor_count} NOTICES)</span>
                    <span style="font-weight: normal; color: var(--text-secondary); font-size: 0.85em;">[Click to toggle compact audit table]</span>
                </summary>
                <div style="font-size: 0.76em; color: var(--text-secondary); margin: 6px 0 8px 0;">
                    These observations represent expected vendor SDK behaviors (Akamai Bot Manager, Adobe Experience Cloud, Tealium iQ) and do not represent first-party application vulnerabilities.
                </div>
                <table style="width: 100%; border-collapse: collapse; font-size: 0.8em; margin-top: 4px;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--border-secondary); text-align: left; color: var(--text-secondary); font-size: 0.85em;">
                            <th style="padding: 4px 8px; width: 22%;">VENDOR</th>
                            <th style="padding: 4px 8px; width: 30%;">OBSERVATION</th>
                            <th style="padding: 4px 8px; width: 20%;">TARGET / ASSET</th>
                            <th style="padding: 4px 8px; width: 28%;">OPERATIONAL ASSESSMENT</th>
                        </tr>
                    </thead>
                    <tbody>
                        {v_rows}
                    </tbody>
                </table>
            </details>
            """

        md_export_url = f"/api/scans/{scan_id}/export/markdown" if scan_id else "/api/export/markdown"

        results_html = f"""
        <div id="temp-results-container" style="display: none;">
            <div class="panel" style="display: flex; flex-direction: column; height: 100%;">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-secondary); padding-bottom: 10px; margin-bottom: 15px;">
                    <div>
                        <span style="color: var(--sub-accent); font-weight: 700; font-size: 0.9em; text-transform: uppercase;">>> MISSION AUDIT INTERCEPTS</span>
                        <div style="margin-top: 4px;">{tech_badges}</div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 0.8em; color: var(--text-secondary);">SURFACE RISK:</span>
                        <span style="font-size: 1.1em; font-weight: bold; color: {'var(--error-color)' if risk_score > 50 else 'var(--accent-color)'};"> {risk_score}/100</span>
                    </div>
                </div>

                <div style="display: flex; gap: 10px; margin-bottom: 12px; font-size: 0.8em; font-weight: 600;">
                    <span style="color: var(--error-color);">CRIT: {crit_count}</span>
                    <span style="color: #e65000;">HIGH: {high_count}</span>
                    <span style="color: var(--warning-color);">MED: {med_count}</span>
                    <span style="color: var(--accent-color);">LOW: {low_count}</span>
                    <span style="color: var(--text-secondary); margin-left: 6px; border-left: 1px solid var(--border-secondary); padding-left: 8px;">VENDOR NOTICES: {vendor_count}</span>
                </div>

                <div style="font-size: 0.82em; font-weight: 600; color: var(--sub-accent); margin-bottom: 6px; text-transform: uppercase;">
                    >> SECTION A: ACTIONABLE INFRASTRUCTURE VULNERABILITIES ({len(actionable_findings)})
                </div>

                <div class="results-grid" style="flex: 1; overflow-y: auto; margin-top: 0; padding-top: 0;">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 11%">SEV</th>
                                <th style="width: 14%">CAT</th>
                                <th>FINDING &amp; cURL PoC</th>
                                <th style="width: 25%">TARGET ENDPOINT</th>
                                <th style="width: 9%">CONF</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>

                    {vendor_section_html}
                </div>

                <div class="report-generation" style="margin-top: auto; padding-top: 15px; border-top: 1px solid var(--border-secondary); text-align: center;">
                    <div style="display: flex; gap: 10px; flex-wrap: wrap; justify-content: center;">
                        {report_btn_html}
                        <a href="/api/export/stix" class="btn" target="_blank">Export STIX 2.1</a>
                        <a href="/api/export/taxii" class="btn" target="_blank">Export TAXII</a>
                        <a href="/api/export/sarif" class="btn" target="_blank">Export SARIF</a>
                        <a href="{md_export_url}" class="btn" target="_blank">Export Triage MD</a>
                        <a href="/api/export/batch-zip" class="btn btn-batch-export" target="_blank">[ DOWNLOAD BATCH ZIP ARCHIVE ]</a>
                    </div>
                </div>
            </div>
        </div>
        <script>
            function copyCurlPoC(btn) {{
                const cmd = btn.getAttribute('data-curl');
                if (navigator.clipboard && cmd) {{
                    navigator.clipboard.writeText(cmd).then(() => {{
                        const original = btn.innerText;
                        btn.innerText = '[COPIED TO CLIPBOARD!]';
                        btn.style.color = 'var(--success-color)';
                        setTimeout(() => {{
                            btn.innerText = original;
                            btn.style.color = '';
                        }}, 1600);
                    }});
                }}
            }}
            
            function copyHtmlPoC(btn) {{
                const poc = btn.getAttribute('data-poc');
                if (navigator.clipboard && poc) {{
                    navigator.clipboard.writeText(poc).then(() => {{
                        const original = btn.innerText;
                        btn.innerText = '[COPIED HTML PoC!]';
                        btn.style.color = 'var(--success-color)';
                        setTimeout(() => {{
                            btn.innerText = original;
                            btn.style.color = '';
                        }}, 1600);
                    }});
                }}
            }}
            
            function downloadHtmlPoC(filename) {{
                // Trigger download via API endpoint
                fetch('/api/poc/' + filename)
                    .then(response => {{
                        if (!response.ok) {{
                            throw new Error('Download failed');
                        }}
                        return response.blob();
                    }})
                    .then(blob => {{
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                    }})
                    .catch(error => {{
                        console.error('Download failed:', error);
                        alert('Failed to download PoC file: ' + error.message);
                    }});
            }}

            setTimeout(() => {{
                const src = document.getElementById('temp-results-container');
                const dest = document.getElementById('results-area');
                if (src && dest) {{
                    dest.innerHTML = src.innerHTML;
                }}
            }}, 80);
        </script>
        """

        self.log("Mission audit completed. Intercept results rendered.", "success")
        with LOGS_LOCK:
            SCAN_LOGS.append(results_html)
        broadcast_log(results_html)


def _render_batch_results_ui(batch_results: List[Dict[str, Any]]) -> None:
    """Render consolidated multi-target batch summary and ZIP export controls into #results-area."""
    total_targets = len(batch_results)
    total_findings = sum(r.get("findings_count", 0) for r in batch_results)
    avg_risk = int(sum(r.get("risk_score", 15) for r in batch_results) / total_targets) if total_targets else 15

    rows_html = ""
    for r in batch_results:
        folder = html.escape(str(r.get("target_folder", "")))
        t_url = html.escape(str(r.get("target_url", "")))
        md_file = html.escape(str(r.get("markdown_file", "")))
        pdf_file = html.escape(str(r.get("pdf_file", "")))
        f_count = int(r.get("findings_count", 0))
        r_score = int(r.get("risk_score", 15))
        scan_id = r.get("scan_id")
        md_link = f"/api/scans/{scan_id}/export/markdown" if scan_id else "/api/export/markdown"
        pdf_link = f"/static/{pdf_file}" if pdf_file else "/api/export/report-latest"

        rows_html += f"""
        <tr>
            <td class="col-sev" style="color: var(--accent-color);">Output/{folder}/</td>
            <td class="col-path">{t_url}</td>
            <td class="col-title">
                <div><a href="{md_link}" target="_blank">{md_file}</a></div>
                <div><a href="{pdf_link}" target="_blank">{pdf_file}</a></div>
            </td>
            <td class="col-conf">{f_count}</td>
            <td class="col-conf" style="color: {'var(--error-color)' if r_score > 50 else 'var(--accent-color)'}; font-weight: bold;">{r_score}/100</td>
        </tr>
        """

    if not rows_html:
        rows_html = "<tr><td colspan='5' style='text-align: center; padding: 20px;'>No batch targets processed.</td></tr>"

    batch_html = f"""
    <div id="temp-batch-results-container" style="display: none;">
        <div class="panel" style="display: flex; flex-direction: column; height: 100%;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-secondary); padding-bottom: 10px; margin-bottom: 15px;">
                <div>
                    <span style="color: var(--sub-accent); font-weight: 700; font-size: 0.9em; text-transform: uppercase;">>> MULTI-TARGET BATCH AUDIT SUMMARY ({total_targets} TARGETS)</span>
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 0.8em; color: var(--text-secondary);">MEAN RISK:</span>
                    <span style="font-size: 1.1em; font-weight: bold; color: {'var(--error-color)' if avg_risk > 50 else 'var(--accent-color)'};"> {avg_risk}/100</span>
                </div>
            </div>

            <div style="display: flex; gap: 15px; margin-bottom: 12px; font-size: 0.8em; font-weight: 600;">
                <span style="color: var(--accent-color);">TARGETS AUDITED: {total_targets}</span>
                <span style="color: var(--warning-color);">TOTAL FINDINGS: {total_findings}</span>
                <span style="color: var(--success-color);">ISOLATED ARTIFACT FOLDERS: Output/Targ001 .. Output/Targ{total_targets:03d}</span>
            </div>

            <div class="results-grid" style="flex: 1; overflow-y: auto; margin-top: 0; padding-top: 0;">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 16%">DIRECTORY</th>
                            <th style="width: 28%">TARGET DOMAIN</th>
                            <th>GENERATED ARTIFACTS (.MD &amp; .PDF)</th>
                            <th style="width: 10%">FINDINGS</th>
                            <th style="width: 10%">RISK</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>

            <div class="report-generation" style="margin-top: auto; padding-top: 15px; border-top: 1px solid var(--border-secondary); text-align: center;">
                <div style="display: flex; gap: 10px; flex-wrap: wrap; justify-content: center;">
                    <a href="/api/export/batch-zip" class="btn btn-download btn-batch-export" target="_blank">[ DOWNLOAD BATCH ZIP ARCHIVE ]</a>
                    <a href="/api/export/report-latest" class="btn" target="_blank">[ ACCESS LATEST VIDS PDF ]</a>
                    <a href="/api/export/stix" class="btn" target="_blank">Export STIX 2.1</a>
                    <a href="/api/export/taxii" class="btn" target="_blank">Export TAXII</a>
                    <a href="/api/export/sarif" class="btn" target="_blank">Export SARIF</a>
                    <a href="/api/export/markdown" class="btn" target="_blank">Export Triage MD</a>
                </div>
            </div>
        </div>
    </div>
    <script>
        setTimeout(() => {{
            const src = document.getElementById('temp-batch-results-container');
            const dest = document.getElementById('results-area');
            if (src && dest) {{
                dest.innerHTML = src.innerHTML;
            }}
        }}, 100);
    </script>
    """
    with LOGS_LOCK:
        SCAN_LOGS.append(batch_html)
    broadcast_log(batch_html)


async def run_batch_scan_pipeline(
    targets: List[str],
    shadow_mode: bool = False,
    local_staging: bool = False,
    auth_header: Optional[str] = None,
    stealth_mode: bool = True,
    engagement_id: Optional[str] = None,
    auth_macros: Optional[List[Dict[str, Any]]] = None,
    base_output_dir: Optional[Path] = None
) -> List[Dict[str, Any]]:
    """
    Execute sequential asynchronous multi-target scanning across all validated targets.
    Outputs isolated per-target directories: Output/Targ001/, Output/Targ002/, ..., Output/Targ00N/.
    Strictly preserves zero-footprint temporary file cleanup and thread-safe SSE log streaming.
    """
    with LOGS_LOCK:
        SCAN_LOGS.clear()

    out_root = (Path(base_output_dir) if base_output_dir else settings.OUTPUT_DIR).resolve()
    os.makedirs(out_root, exist_ok=True)

    # Clean stale Targ* folders from prior batch runs so Output/ reflects the active batch (never follow symlinks)
    for existing in out_root.iterdir():
        if not existing.is_symlink() and existing.is_dir() and re.fullmatch(r"Targ\d+", existing.name):
            if existing.resolve().is_relative_to(out_root):
                shutil.rmtree(existing, ignore_errors=True)

    total = len(targets)
    start_entry = (
        f'<div class="log-entry info">[BATCH ORCHESTRATOR] Initiating Sequential Multi-Target Recon '
        f'across {total} targets -> Output/Targ001..Targ{total:03d}</div>'
    )
    with LOGS_LOCK:
        SCAN_LOGS.append(start_entry)
    broadcast_log(start_entry)

    batch_summary: List[Dict[str, Any]] = []

    for idx, target_url in enumerate(targets, start=1):
        targ_folder = f"Targ{idx:03d}"
        step_entry = (
            f'<div class="log-entry info">[BATCH TARGET {idx}/{total}] '
            f'Engaging {html.escape(target_url)} (Isolated Output: Output/{targ_folder}/)</div>'
        )
        with LOGS_LOCK:
            SCAN_LOGS.append(step_entry)
        broadcast_log(step_entry)

        scanner = WebScanner(
            target_url=target_url,
            shadow_mode=shadow_mode,
            local_staging=local_staging,
            auth_header=auth_header,
            stealth_mode=stealth_mode,
            engagement_id=engagement_id,
            generate_pdf=True,
            auth_macros=auth_macros,
            target_index=idx,
            output_dir=str(out_root)
        )
        await scanner.run_pipeline(clear_logs=False)

        batch_summary.append({
            "target_index": idx,
            "target_folder": targ_folder,
            "target_url": scanner.target_url,
            "scan_id": scanner.scan_id,
            "markdown_file": scanner.markdown_file,
            "pdf_file": scanner.report_file,
            "target_dir": scanner.target_output_dir,
            "findings_count": len(scanner.findings),
            "risk_score": scanner.risk_score
        })

    done_entry = (
        f'<div class="log-entry success">[BATCH COMPLETE] All {total} targets processed. '
        f'Isolated artifacts compiled under Output/Targ001..Targ{total:03d}. Ready for ZIP Archive Export.</div>'
    )
    with LOGS_LOCK:
        SCAN_LOGS.append(done_entry)
    broadcast_log(done_entry)

    _render_batch_results_ui(batch_summary)
    return batch_summary
