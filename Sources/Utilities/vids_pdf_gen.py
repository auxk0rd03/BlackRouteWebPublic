import datetime
import os
from pathlib import Path
from typing import Dict, Any, List
from fpdf import FPDF

class VIDSWebReport(FPDF):
    def header(self):
        self.set_font('Courier', 'B', 12)
        self.cell(0, 10, 'CYBERNEST LABS - BLACKROUTE-WEB VIDS AUDIT REPORT', align='C')
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font('Courier', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} | CONFIDENTIAL AUDIT ASSESSMENT', align='C')

def sanitize(text: Any) -> str:
    """Sanitize text to Latin-1 encoding for FPDF compatibility."""
    if not isinstance(text, str):
        text = str(text or "")
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_web_report(data: Dict[str, Any], output_dir: str = ".") -> str:
    pdf = VIDSWebReport()
    pdf.add_page()
    pdf.set_font("Courier", size=10)

    target_url = data.get("target_url", "Unknown Target")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Executive Summary
    pdf.set_font("Courier", 'B', 11)
    pdf.cell(0, 8, sanitize("== EXECUTIVE MISSION AUDIT SUMMARY =="))
    pdf.ln(7)

    pdf.set_font("Courier", size=9)
    pdf.cell(0, 6, sanitize(f"Target URL:            {target_url}"))
    pdf.ln(5)
    pdf.cell(0, 6, sanitize(f"Scan Completed:        {timestamp}"))
    pdf.ln(5)
    pdf.cell(0, 6, sanitize(f"Pages Crawled:         {data.get('pages_crawled', 0)}"))
    pdf.ln(5)
    pdf.cell(0, 6, sanitize(f"Endpoints Discovered:  {data.get('endpoints_found', 0)}"))
    pdf.ln(5)
    pdf.cell(0, 6, sanitize(f"Total Findings:        {len(data.get('findings', []))}"))
    pdf.ln(5)
    pdf.cell(0, 6, sanitize(f"Surface Risk Score:    {data.get('risk_score', 0)} / 100"))
    pdf.ln(8)

    # Technology Fingerprints
    techs = data.get("technologies", [])
    if techs:
        pdf.set_font("Courier", 'B', 10)
        pdf.cell(0, 6, sanitize("Detected Technologies & Stack:"))
        pdf.ln(6)
        pdf.set_font("Courier", size=8)
        for t in techs:
            pdf.cell(0, 5, sanitize(f"  - [{t.get('category', 'Stack')}] {t.get('name', 'Unknown')}: {t.get('evidence', '')}"))
            pdf.ln(5)
        pdf.ln(4)

    # Severity Summary Counts
    findings = data.get("findings", [])
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    info_count = sum(1 for f in findings if f.get("severity") == "INFO")

    pdf.set_font("Courier", 'B', 10)
    pdf.cell(0, 6, sanitize(f"Threat Distribution: CRIT: {crit_count} | HIGH: {high_count} | MED: {med_count} | LOW: {low_count} | INFO: {info_count}"))
    pdf.ln(8)

    # 2. Detailed Findings
    pdf.set_font("Courier", 'B', 11)
    pdf.cell(0, 8, sanitize("== DETAILED AUDIT FINDINGS =="))
    pdf.ln(8)

    if not findings:
        pdf.set_font("Courier", size=9)
        pdf.cell(0, 6, sanitize("No vulnerabilities or misconfigurations detected."))
        pdf.ln(6)
    else:
        for f in findings:
            # Avoid orphan finding headers by checking if there is enough vertical space
            if pdf.get_y() > 230:
                pdf.add_page()

            sev = f.get("severity", "INFO").upper()
            title = f.get("title", "Finding")
            cat = f.get("category", "GENERAL")
            conf = f.get("confidence", 1.0)
            endpoint = f.get("endpoint", target_url)
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            remediation = f.get("remediation", "")
            curl_cmd = f.get("curl_command", "")

            # Severity Color
            if sev == "CRITICAL":
                pdf.set_text_color(220, 20, 20)
            elif sev == "HIGH":
                pdf.set_text_color(230, 80, 0)
            elif sev == "MEDIUM":
                pdf.set_text_color(180, 140, 0)
            elif sev == "LOW":
                pdf.set_text_color(40, 120, 180)
            else:
                pdf.set_text_color(100, 100, 100)

            pdf.set_font("Courier", 'B', 9)
            pdf.cell(0, 6, sanitize(f"[{sev}] [{cat}] (Conf: {conf}) {title}"))
            pdf.ln(5)

            # Details
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Courier", size=8)

            details = f"Target: {endpoint}\nDescription: {desc}\nEvidence: {evidence[:200]}\nRemediation: {remediation}\n"
            if curl_cmd:
                details += f"Reproducible cURL PoC: {curl_cmd}\n"

            pdf.multi_cell(0, 4.5, sanitize(details))
            pdf.ln(3)

    # 3. Sensitive Routes Inventory
    sensitive_routes = data.get("sensitive_routes", [])
    if sensitive_routes:
        if pdf.get_y() > 220:
            pdf.add_page()
        else:
            pdf.ln(4)
        pdf.set_font("Courier", 'B', 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, sanitize("== SENSITIVE ROUTE ATTACK SURFACE =="))
        pdf.ln(7)
        pdf.set_font("Courier", size=8)
        for r in sensitive_routes[:40]:
            if pdf.get_y() > 265:
                pdf.add_page()
            pdf.cell(0, 5, sanitize(f"  * {r}"))
            pdf.ln(5)

    # Save artifact
    now_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"BlackRoute_Web_Report_{now_tag}.pdf"
    os.makedirs(output_dir, exist_ok=True)
    out_path = Path(output_dir) / filename
    pdf.output(str(out_path))

    return str(filename)
