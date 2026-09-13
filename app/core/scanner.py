import asyncio
import hashlib
import html
import os
import shutil
import tempfile
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional

import aiofiles
import httpx
from bs4 import BeautifulSoup

from app.core.config import settings
from app.core.security import validate_target_url, normalize_target_url
from app.core.database import save_scan_record
from app.core.engine_bridge import run_spider_extractor, run_surface_graph
from app.core.auditor_headers import HeaderAuditor
from app.core.auditor_secrets import SecretAuditor
from app.core.auditor_api_routes import ApiRouteAuditor
from app.core.auditor_dom import DomAuditor
from Sources.Utilities.vids_pdf_gen import generate_web_report

SCAN_LOGS: List[str] = []

class WebScanner:
    def __init__(
        self,
        target_url: str,
        shadow_mode: bool = False,
        local_staging: bool = False,
        auth_header: Optional[str] = None
    ):
        self.raw_target = target_url
        self.target_url = normalize_target_url(target_url) if target_url else ""
        self.shadow_mode = shadow_mode
        self.local_staging = local_staging
        self.auth_header = auth_header.strip() if auth_header else None
        self.temp_dir: Optional[str] = None
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.pages_crawled: int = 0
        self.harvested_content: List[str] = []

    def log(self, message: str, log_type: str = "info") -> None:
        """Append log to global stream buffer with HTML escaping."""
        safe_type = html.escape(log_type)
        safe_message = html.escape(str(message))
        entry = f'<div class="log-entry {safe_type}">[{safe_type.upper()}] {safe_message}</div>'
        SCAN_LOGS.append(entry)
        print(f"[{safe_type.upper()}] {message}")

    async def run_pipeline(self) -> None:
        """Execute the end-to-end web cybersecurity audit pipeline."""
        global SCAN_LOGS
        SCAN_LOGS.clear()

        self.log("Initializing BlackRoute-Web Mission Protocol...", "info")
        self.temp_dir = tempfile.mkdtemp(prefix="br_web_")

        try:
            # 1. SSRF & Target Validation
            self.log(f"Validating target scope: {self.target_url}", "info")
            try:
                validated_url = validate_target_url(self.target_url, allow_local_staging=self.local_staging)
                if self.local_staging:
                    self.log("[STAGE SCOPE] Local Staging Mode ACTIVE (Auditing internal target).", "warn")
            except Exception as val_err:
                self.log(f"Target Validation Aborted: {val_err}", "error")
                return

            req_headers = {
                "User-Agent": settings.USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
            if self.auth_header:
                req_headers["Authorization"] = self.auth_header
                self.log("Authenticated Audit Session Configured.", "info")

            # 2. Phase 1: Header, Cookie, CORS & Transport Posture Audit
            self.log("Phase 1: Assessing HTTP Headers, Cookies, and Transport Security...", "info")
            initial_resp = None
            async with httpx.AsyncClient(headers=req_headers, verify=False, follow_redirects=True, timeout=12.0) as client:
                try:
                    initial_resp = await client.get(validated_url)
                    self.pages_crawled += 1
                    status = initial_resp.status_code
                    self.log(f"Target Acquired: HTTP {status} ({len(initial_resp.content)} bytes)", "success")

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

                    # CORS Audit (test origin reflection)
                    cors_resp = await client.get(validated_url, headers={"Origin": "https://evil.cybernest.labs"})
                    acao = cors_resp.headers.get("access-control-allow-origin", "")
                    acac = cors_resp.headers.get("access-control-allow-credentials", "")
                    cors_findings = HeaderAuditor.audit_cors(str(initial_resp.url), acao, acac, "https://evil.cybernest.labs")
                    self.findings.extend(cors_findings)

                except Exception as net_err:
                    self.log(f"Network Handshake Failed on {validated_url}: {net_err}", "error")
                    return

            if initial_resp is None:
                self.log("No response received from target.", "error")
                return

            base_content = initial_resp.text
            self.harvested_content.append(base_content)

            # Save main page to temp dir for engine processing
            main_page_path = os.path.join(self.temp_dir, "index.html")
            async with aiofiles.open(main_page_path, "w", encoding="utf-8", errors="ignore") as f:
                await f.write(base_content)

            # 3. Phase 2: Web Spider & Asset Harvesting (Rust Engine)
            self.log("Phase 2: Spidering Web Assets & Extracting Client Endpoints...", "info")
            soup = BeautifulSoup(base_content, "html.parser")
            script_srcs = [s.get("src") for s in soup.find_all("script") if s.get("src")]
            self.log(f"Discovered {len(script_srcs)} linked JavaScript assets.", "info")

            # Download discovered JS assets securely
            downloaded_scripts = []
            async with httpx.AsyncClient(headers=req_headers, verify=False, follow_redirects=True, timeout=10.0) as dl_client:
                for src in script_srcs[:25]: # limit to top 25 scripts to avoid denial of service
                    script_url = urllib.parse.urljoin(validated_url, src)
                    try:
                        js_resp = await dl_client.get(script_url)
                        if js_resp.status_code == 200 and len(js_resp.content) <= settings.MAX_JS_ASSET_SIZE:
                            s_hash = hashlib.sha256(script_url.encode("utf-8")).hexdigest()[:12]
                            s_filename = f"asset_{s_hash}.js"
                            s_path = os.path.join(self.temp_dir, s_filename)
                            async with aiofiles.open(s_path, "wb") as f:
                                await f.write(js_resp.content)
                            downloaded_scripts.append((script_url, s_path, js_resp.text))
                            self.harvested_content.append(js_resp.text)
                    except Exception:
                        pass

            # Execute Rust web_spider on downloaded assets
            spider_result = run_spider_extractor(self.temp_dir)
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

            # 4. Phase 3: Secret & Credential Leak Detection
            self.log("Phase 3: Scanning Web Assets for Hardcoded API Keys, Tokens & Credentials...", "info")
            total_secrets = 0
            # Check main HTML
            html_secrets = SecretAuditor.audit_content(validated_url, base_content)
            self.findings.extend(html_secrets)
            total_secrets += len(html_secrets)

            # Check each downloaded script
            for script_url, _, js_content in downloaded_scripts:
                s_secrets = SecretAuditor.audit_content(script_url, js_content)
                self.findings.extend(s_secrets)
                total_secrets += len(s_secrets)

            self.log(f"Credential Leak Analysis Complete: {total_secrets} potential secrets flagged.", "info" if total_secrets == 0 else "warn")

            # 5. Phase 4: Client-Side DOM XSS & postMessage Auditing
            self.log("Phase 4: Auditing Client-Side DOM Sinks & postMessage Handlers...", "info")
            dom_findings_count = 0
            for script_url, _, js_content in downloaded_scripts:
                dom_findings = DomAuditor.audit_javascript(script_url, js_content)
                self.findings.extend(dom_findings)
                dom_findings_count += len(dom_findings)
            self.log(f"DOM Risk Analysis Complete: {dom_findings_count} sink/origin risks detected.", "info")

            # 6. Phase 5: API Surface & Sensitive Route Discovery
            self.log("Phase 5: Probing for Exposed OpenAPI/Swagger Schemas, Actuators & Git Metadata...", "info")
            api_findings = await ApiRouteAuditor.audit_api_surface(validated_url, req_headers)
            self.findings.extend(api_findings)
            self.log(f"Surface Probing Complete: {len(api_findings)} exposed services identified.", "success" if len(api_findings) == 0 else "warn")

            # 7. Phase 6: Attack Surface Topology & Tech Fingerprinting (Go Engine)
            self.log("Phase 6: Computing Attack Surface Topology & Stack Fingerprints (Go Engine)...", "info")
            all_paths = [e.get("url") for e in self.endpoints if e.get("url")]
            all_paths.extend([f.get("endpoint") for f in self.findings if f.get("endpoint")])
            combined_content = "\n".join(self.harvested_content[:10])

            surface_data = run_surface_graph(all_paths, dict(initial_resp.headers), combined_content)
            techs = surface_data.get("technologies", [])
            for t in techs:
                self.log(f"Detected Technology: [{t.get('category')}] {t.get('name')}", "info")

            # 8. Smart Noise Filtering vs. Shadow Mode
            if not self.shadow_mode:
                suppressed = [f for f in self.findings if f.get("confidence", 1.0) < 0.75]
                if suppressed:
                    self.log(f"[SMART FILTER] Suppressed {len(suppressed)} low-confidence noise findings (< 0.75).", "warn")
                    self.findings = [f for f in self.findings if f.get("confidence", 1.0) >= 0.75]
            else:
                self.log("[SHADOW MODE] Preserving all raw findings across full confidence spectrum.", "warn")

            # 9. Phase 7: Reporting & SQLite Persistence
            self.log("Phase 7: Generating CyberNest VIDS PDF Audit Report...", "info")
            report_data = {
                "target_url": validated_url,
                "pages_crawled": self.pages_crawled,
                "endpoints_found": len(self.endpoints),
                "findings": self.findings,
                "technologies": techs,
                "sensitive_routes": surface_data.get("sensitive_routes", []),
                "risk_score": surface_data.get("risk_score", 20)
            }

            loop = asyncio.get_running_loop()
            report_file = await loop.run_in_executor(
                None,
                generate_web_report,
                report_data,
                str(settings.STATIC_DIR)
            )
            self.log(f"VIDS PDF Report Generated: {report_file}", "success")

            # Persist to SQLite
            try:
                save_scan_record(
                    target_url=validated_url,
                    findings=self.findings,
                    endpoints=self.endpoints,
                    pages_crawled=self.pages_crawled,
                    report_file=report_file,
                    status="completed"
                )
                self.log("Scan record persisted to local SQLite database.", "info")
            except Exception as db_err:
                self.log(f"Database Persistence Warning: {db_err}", "warn")

            # Inject Results Grid HTML for dynamic UI rendering
            self._render_results_ui(report_file, surface_data.get("risk_score", 20), techs)

        except Exception as exc:
            self.log(f"Critical Pipeline Failure: {exc}", "error")
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                self.log("Zero-Footprint Protocol: Cleaning temporary harvest directory...", "info")
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.log("Audit Pipeline Sequence Finished.", "success")

    def _render_results_ui(self, report_file: str, risk_score: int, techs: List[Dict[str, str]]) -> None:
        """Construct interactive results grid for HTMX UI swap."""
        crit_count = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in self.findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in self.findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in self.findings if f.get("severity") == "LOW")
        info_count = sum(1 for f in self.findings if f.get("severity") == "INFO")

        safe_report = html.escape(report_file)

        tech_badges = "".join([
            f'<span style="background: rgba(95,168,160,0.15); border: 1px solid var(--accent-color); padding: 2px 6px; font-size: 0.75em; border-radius: 3px; margin-right: 4px;">{html.escape(t.get("name", ""))}</span>'
            for t in techs[:5]
        ])

        rows_html = ""
        for f in self.findings:
            sev = html.escape(str(f.get("severity", "INFO")))
            title = html.escape(str(f.get("title", "")))
            cat = html.escape(str(f.get("category", "")))
            endpoint = html.escape(str(f.get("endpoint", "")))
            conf = html.escape(str(f.get("confidence", 1.0)))

            if len(endpoint) > 40:
                endpoint = endpoint[:37] + "..."

            sev_class = f"sev-{sev.lower()}"

            rows_html += f"""
            <tr>
                <td class="col-sev {sev_class}">[{sev}]</td>
                <td class="col-cat">[{cat}]</td>
                <td class="col-title">{title}</td>
                <td class="col-path">{endpoint}</td>
                <td class="col-conf">{conf}</td>
            </tr>
            """

        if not rows_html:
            rows_html = "<tr><td colspan='5' style='text-align: center; padding: 20px;'>No high-risk vulnerabilities detected. Review VIDS Report.</td></tr>"

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
                    <span style="color: var(--text-secondary);">INFO: {info_count}</span>
                </div>

                <div class="results-grid" style="flex: 1; overflow-y: auto; margin-top: 0; padding-top: 0;">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 12%">SEV</th>
                                <th style="width: 15%">CAT</th>
                                <th>FINDING TITLE</th>
                                <th style="width: 25%">TARGET ENDPOINT</th>
                                <th style="width: 10%">CONF</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>
                </div>

                <div class="report-generation" style="margin-top: auto; padding-top: 15px; border-top: 1px solid var(--border-secondary); text-align: center;">
                    <div style="display: flex; gap: 10px; flex-wrap: wrap; justify-content: center;">
                        <a href="/static/{safe_report}" target="_blank" class="btn btn-download">[ ACCESS VIDS AUDIT REPORT ]</a>
                        <a href="/api/export/stix" class="btn">Export STIX 2.1</a>
                        <a href="/api/export/taxii" class="btn">Export TAXII</a>
                    </div>
                </div>
            </div>
        </div>
        <script>
            setTimeout(() => {{
                const src = document.getElementById('temp-results-container');
                const dest = document.getElementById('results-area');
                if (src && dest) {{
                    dest.innerHTML = src.innerHTML;
                }}
            }}, 80);
        </script>
        """

        SCAN_LOGS.append(results_html)
