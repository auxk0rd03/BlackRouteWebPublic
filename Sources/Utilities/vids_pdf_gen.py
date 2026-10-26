import datetime
import os
from pathlib import Path
from typing import Dict, Any, List
from fpdf import FPDF

STEALTH_CURL_HEADER_LINES: List[str] = [
    '-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"',
    '-H "Sec-Ch-Ua: \\"Chromium\\";v=\\"124\\", \\"Google Chrome\\";v=\\"124\\", \\"Not-A.Brand\\";v=\\"99\\""',
    '-H "Sec-Ch-Ua-Mobile: ?0"',
    '-H "Sec-Ch-Ua-Platform: \\"Linux\\""',
    '-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"',
    '-H "Accept-Language: en-US,en;q=0.5"',
]

STEALTH_CURL_HEADERS_BLOCK: str = "".join(f" \\\n  {line}" for line in STEALTH_CURL_HEADER_LINES)


def ensure_stealth_curl_poc(curl_cmd: str, endpoint: str = "https://target.domain/") -> str:
    """
    Ensure that any generated or persisted cURL command embeds the full L7 stealth browser
    persona headers (User-Agent, Sec-Ch-Ua, Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform, Accept, Accept-Language)
    to prevent edge WAF 403 blocks during bug bounty triage reproduction.
    """
    target = endpoint or "https://target.domain/"
    cmd = (curl_cmd or "").strip()
    if not cmd:
        return f'curl -s -I "{target}"{STEALTH_CURL_HEADERS_BLOCK}'

    if "Sec-Ch-Ua:" in cmd and "User-Agent:" in cmd:
        return cmd

    if " | " in cmd:
        base_cmd, pipe_suffix = cmd.split(" | ", 1)
        return f"{base_cmd.rstrip()}{STEALTH_CURL_HEADERS_BLOCK} \\\n  | {pipe_suffix.lstrip()}"

    return f"{cmd}{STEALTH_CURL_HEADERS_BLOCK}"


def classify_bug_bounty_metadata(finding: Dict[str, Any], default_target: str = "https://target.domain/") -> Dict[str, Any]:
    """
    Map a finding to standardized Bug Bounty Triage metadata:
    - CWE classification (ID + title)
    - CVSS v3.1 Base Score & Vector string
    - Step-by-Step Reproduction Guide
    """
    category = str(finding.get("category", "GENERAL")).upper()
    title = str(finding.get("title", "Security Finding"))
    title_lower = title.lower()
    desc_lower = str(finding.get("description", "")).lower()
    sev = str(finding.get("severity", "INFO")).upper()
    endpoint = str(finding.get("endpoint") or default_target)

    cwe = finding.get("cwe") or "CWE-693: Protection Mechanism Failure"
    cvss_vector = finding.get("cvss_vector") or ""
    cvss_score = finding.get("cvss_score") or ""

    if "csp" in title_lower or "content-security-policy" in title_lower or "content-security-policy" in desc_lower:
        cwe = "CWE-693: Protection Mechanism Failure (Lax Content-Security-Policy)"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        cvss_score = cvss_score or "6.1"
    elif "clickjacking" in title_lower or "x-frame-options" in title_lower or "frame-ancestors" in title_lower:
        cwe = "CWE-1021: Improper Restriction of Rendered UI Layers or Frames (Clickjacking)"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"
        cvss_score = cvss_score or "4.7"
    elif "hsts" in title_lower or "strict-transport" in title_lower:
        cwe = "CWE-319: Cleartext Transmission of Sensitive Information (Missing/Weak HSTS)"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
        cvss_score = cvss_score or "5.3"
    elif "cors" in title_lower or "origin reflection" in title_lower:
        cwe = "CWE-942: Permissive Cross-domain Policy with Untrusted Domains (CORS)"
        if sev == "CRITICAL":
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
            cvss_score = cvss_score or "8.1"
        else:
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
            cvss_score = cvss_score or "6.5"
    elif "referrer" in title_lower:
        cwe = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (Referrer Policy)"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        cvss_score = cvss_score or "3.1"
    elif "nosniff" in title_lower or "x-content-type-options" in title_lower:
        cwe = "CWE-16: Configuration (Missing MIME-Sniffing Protection)"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"
        cvss_score = cvss_score or "3.1"
    elif "permissions-policy" in title_lower or "feature-policy" in title_lower:
        cwe = "CWE-250: Execution with Unnecessary Privileges (Missing Permissions-Policy)"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
        cvss_score = cvss_score or "3.1"
    elif "cookie" in category.lower() or "cookie" in title_lower:
        if "secure" in title_lower:
            cwe = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
            cvss_score = cvss_score or "4.8"
        elif "httponly" in title_lower:
            cwe = "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
            cvss_score = cvss_score or "5.4"
        elif "samesite" in title_lower:
            cwe = "CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
            cvss_score = cvss_score or "4.3"
        else:
            cwe = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
            cvss_score = cvss_score or "4.8"
    elif category == "SECRETS" or any(k in title_lower for k in ["aws", "stripe", "openai", "api key", "secret", "token", "jwt"]):
        cwe = "CWE-798: Use of Hard-coded Credentials"
        cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        cvss_score = cvss_score or "9.1"
    elif category == "DOM_XSS" or "dom" in title_lower or "postmessage" in title_lower:
        if "postmessage" in title_lower:
            cwe = "CWE-346: Origin Validation Error (Unvalidated postMessage Listener)"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
            cvss_score = cvss_score or "6.1"
        else:
            cwe = "CWE-79: Improper Neutralization of Input During Web Page Generation (DOM-Based XSS)"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
            cvss_score = cvss_score or "6.1"
    elif category == "API_EXPOSURE":
        if "graphql" in title_lower:
            cwe = "CWE-200: Exposure of Sensitive Information (GraphQL Introspection Enabled)"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            cvss_score = cvss_score or "5.3"
        else:
            cwe = "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory"
            cvss_vector = cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            cvss_score = cvss_score or "7.5"

    if not cvss_vector:
        if sev == "CRITICAL":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "9.1"
        elif sev == "HIGH":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "7.1"
        elif sev == "MEDIUM":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "5.4"
        elif sev == "LOW":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "3.1"
        else:
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0"

    repro_steps = [
        f"1. Open a terminal and execute the Stealth Browser Persona cURL command below targeting `{endpoint}` (client-hint headers are pre-attached to bypass edge WAF bot filtering).",
        f"2. Inspect the raw HTTP response headers/payload returned by `{endpoint}` and verify the evidence indicator (`{str(finding.get('evidence', title))[:100]}`).",
        f"3. Confirm that `{title}` ({cwe}) is reproducible on the live origin response and evaluate downstream chaining potential."
    ]

    return {
        "cwe": cwe,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "reproduction_steps": repro_steps,
    }


def build_chained_impact_statement(target_url: str, actionable_findings: List[Dict[str, Any]], risk_score: int) -> str:
    """Synthesize an Executive Summary & Chained Triage Impact Statement for bug bounty submission."""
    if not actionable_findings:
        return (
            f"Automated DAST and attack surface reconnaissance against {target_url} (Surface Risk Score: {risk_score}/100) "
            "identified no directly exploitable first-party infrastructure vulnerabilities during this assessment window."
        )

    categories = {str(f.get("category", "")).upper() for f in actionable_findings}
    titles_combined = " ".join(str(f.get("title", "")).lower() for f in actionable_findings)

    chains = []
    if "csp" in titles_combined or "unsafe-inline" in titles_combined or "DOM_XSS" in categories:
        chains.append(
            "permissive script execution policies (e.g., Content-Security-Policy 'unsafe-inline'/'unsafe-eval' or client-side DOM sinks) "
            "lower the barrier for arbitrary JavaScript execution in victim browser sessions"
        )
    if "COOKIES" in categories or "cookie" in titles_combined:
        chains.append(
            "missing transport or script-isolation flags on first-party cookies (Secure / HttpOnly / SameSite) expose session or telemetry state "
            "to cleartext network interception, SSL-stripping downgrades, or DOM readout"
        )
    if "SECRETS" in categories:
        chains.append(
            "hardcoded API credentials/tokens embedded in client-accessible JavaScript bundles allow unauthenticated third-party API abuse and privilege escalation"
        )
    if "API_EXPOSURE" in categories or "cors" in titles_combined:
        chains.append(
            "exposed API schemas, GraphQL introspection, or permissive cross-origin resource sharing (CORS) policies enable attackers to map internal data models and exfiltrate authenticated responses"
        )
    if "referrer" in titles_combined or "clickjacking" in titles_combined or "x-frame-options" in titles_combined:
        chains.append(
            "missing framing restrictions or permissive Referrer-Policy configurations allow UI redressing (Clickjacking) and cross-origin URL token leakage to external origins"
        )

    if not chains:
        chains.append("identified HTTP security posture weaknesses reduce defense-in-depth protections across the target origin")

    chained_prose = "; additionally, ".join(chains)
    return (
        f"During authorized black-box security reconnaissance of {target_url} (Composite Surface Risk Score: {risk_score}/100), "
        f"BlackRoute-Web identified {len(actionable_findings)} actionable first-party security defect(s). "
        f"Chained Triage Impact: In a chained exploitation scenario, {chained_prose}. "
        "Combined, these weaknesses compound overall exploitability and should be remediated at the origin/edge layer."
    )


def build_bug_bounty_markdown_triage(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]]
) -> str:
    """
    Build a standardized, professional Bug Bounty & Triage Submission Report in Markdown (.md)
    featuring Executive Summary, Chained Triage Impact Statement, CWE & CVSS v3.1 vectors,
    Step-by-Step Reproduction Guides, Stealth Browser Persona cURL PoCs, and Remediation Guidance.
    """
    target_url = scan.get("target_url", "https://target.domain/")
    actionable_findings = [f for f in findings if not is_vendor_observation(f)]
    vendor_findings = [f for f in findings if is_vendor_observation(f)]

    crit_count = sum(1 for f in actionable_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in actionable_findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in actionable_findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in actionable_findings if f.get("severity") == "LOW")

    risk_score = scan.get("risk_score")
    if not risk_score:
        base_surface_score = 15
        finding_impact = (crit_count * 25) + (high_count * 15) + (med_count * 5) + (low_count * 2)
        risk_score = min(100, max(base_surface_score, (base_surface_score // 2) + finding_impact)) if actionable_findings else base_surface_score

    counts_parts = []
    if crit_count:
        counts_parts.append(f"{crit_count} Critical")
    if high_count:
        counts_parts.append(f"{high_count} High")
    if med_count:
        counts_parts.append(f"{med_count} Medium")
    if low_count:
        counts_parts.append(f"{low_count} Low")
    actionable_str = ", ".join(counts_parts) if counts_parts else "0"

    impact_statement = build_chained_impact_statement(target_url, actionable_findings, int(risk_score))

    lines = [
        "# BlackRoute-Web Security Assessment & Bug Bounty Triage Report",
        "",
        "### Summary",
        f"- Target: {target_url}",
        f"- Risk Score: {risk_score}/100",
        f"- Actionable Vulnerabilities: {actionable_str}",
        "",
        "### Executive Summary & Chained Triage Impact Statement",
        impact_statement,
        "",
        "### Primary Findings"
    ]

    if not actionable_findings:
        lines.append("No actionable infrastructure vulnerabilities identified.")
    else:
        for idx, f in enumerate(actionable_findings, 1):
            sev_title = str(f.get("severity", "Info")).title()
            title = f.get("title", "Security Finding")
            meta = classify_bug_bounty_metadata(f, target_url)
            lines.append(f"{idx}. {title} - {sev_title} (`{meta['cwe']}` | `{meta['cvss_vector']}`)")

    lines.append("")
    lines.append("### Actionable Details & Proof of Concepts")
    for idx, f in enumerate(actionable_findings, 1):
        sev_title = str(f.get("severity", "Info")).title()
        title = f.get("title", "Security Finding")
        endpoint = f.get("endpoint", target_url)
        raw_curl = f.get("curl_command", "")
        curl_cmd = ensure_stealth_curl_poc(raw_curl, endpoint)
        remediation = f.get("remediation", "Apply origin-level security hardening as recommended.")
        desc = f.get("description", "")
        evidence = f.get("evidence", "")
        meta = classify_bug_bounty_metadata(f, target_url)

        lines.append(f"#### {idx}. {title} [{sev_title}]")
        lines.append(f"- **Target Endpoint**: `{endpoint}`")
        lines.append(f"- **CWE Classification**: `{meta['cwe']}`")
        lines.append(f"- **CVSS v3.1 Base Vector**: `{meta['cvss_vector']}` (Base Score: **{meta['cvss_score']}**)")
        if desc:
            lines.append(f"- **Description**: {desc}")
        if evidence:
            lines.append(f"- **Evidence**: `{evidence[:200]}`")
        lines.append("- **Step-by-Step Reproduction Guide**:")
        for step in meta["reproduction_steps"]:
            lines.append(f"  {step}")
        if remediation:
            lines.append(f"- **Actionable Remediation Guidance**: {remediation}")
            lines.append(f"- **Remediation**: {remediation}")
        lines.append("- **Reproducible Stealth cURL PoC**:")
        lines.append("```bash")
        lines.append(curl_cmd)
        lines.append("```")
        lines.append("")

    if vendor_findings:
        lines.append("### Third-Party & Vendor Observations")
        lines.append("The following findings represent expected third-party telemetry, bot management, and analytics SDK behaviors (Akamai, Adobe, Tealium) and do not represent first-party application vulnerabilities.")
        lines.append("")
        for idx, vf in enumerate(vendor_findings, 1):
            v_name = extract_vendor_name(vf)
            v_title = vf.get("title", "Vendor Observation").replace("[Third-Party] ", "")
            v_asset = extract_target_asset(vf, target_url)
            lines.append(f"- **{v_name}**: {v_title} (`{v_asset}`)")
        lines.append("")

    return "\n".join(lines)

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

def is_vendor_observation(finding: Dict[str, Any]) -> bool:
    """Determine if a finding is a third-party/vendor observation (Akamai, Adobe, Tealium, etc.)."""
    tags = finding.get("tags") or []
    if any(tag in tags for tag in ["vendor_integration", "third_party", "vendor_script", "httponly_false_positive"]):
        return True
    
    vendor_ctx = str(finding.get("vendor_context", "")).lower()
    if vendor_ctx in ["akamai", "adobe", "adobe experience cloud", "tealium", "google analytics"]:
        return True
        
    title = str(finding.get("title", "")).lower()
    desc = str(finding.get("description", "")).lower()
    sev = str(finding.get("severity", "")).upper()
    
    if "[third-party]" in title:
        return True

    # Check for vendor indicators in INFO findings
    if sev == "INFO":
        vendor_keywords = ["akamai", "adobe", "tealium", "_abck", "bm_sz", "bm_mi", "bm_so", "mbox", "utag", "third-party"]
        if any(k in title or k in desc for k in vendor_keywords):
            return True
            
    return False

def extract_vendor_name(finding: Dict[str, Any]) -> str:
    """Extract human-readable vendor family name for finding."""
    vendor_ctx = finding.get("vendor_context")
    if vendor_ctx:
        return str(vendor_ctx)
    tags = finding.get("tags") or []
    for tag in tags:
        if tag in ["Akamai Bot Manager", "Adobe Experience Cloud", "Tealium", "Google Analytics", "Akamai", "Adobe"]:
            return str(tag)
    title = str(finding.get("title", "")).lower()
    desc = str(finding.get("description", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()
    combined = f"{title} {desc} {evidence}"
    if "akamai" in combined or "_abck" in combined or "bm_" in combined:
        return "Akamai Bot Manager"
    if "adobe" in combined or "mbox" in combined or "amcv" in combined:
        return "Adobe Experience Cloud"
    if "tealium" in combined or "utag" in combined:
        return "Tealium iQ"
    if "google" in combined or "_ga" in combined:
        return "Google Analytics"
    return "Vendor Integration"

def extract_target_asset(finding: Dict[str, Any], default_target: str) -> str:
    """Extract specific cookie or script name from finding."""
    evidence = str(finding.get("evidence", ""))
    title = str(finding.get("title", ""))
    endpoint = str(finding.get("endpoint", default_target))
    
    # Check for cookie name in title: Cookie 'NAME' Missing...
    if "'" in title:
        parts = title.split("'")
        if len(parts) >= 3:
            return parts[1]
    
    # Check for cookie in evidence
    if "Set-Cookie:" in evidence:
        cookie_part = evidence.split("Set-Cookie:")[1].strip()
        cookie_name = cookie_part.split(";")[0].split("=")[0].strip()
        if cookie_name:
            return cookie_name
            
    # Extract asset filename from endpoint
    if "/" in endpoint:
        asset_name = endpoint.split("?")[0].rstrip("/").split("/")[-1]
        if asset_name and len(asset_name) < 25:
            return asset_name
            
    return endpoint[:25]

def generate_web_report(data: Dict[str, Any], output_dir: str = ".") -> str:
    pdf = VIDSWebReport()
    pdf.add_page()
    pdf.set_font("Courier", size=10)

    target_url = data.get("target_url", "Unknown Target")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    all_findings = data.get("findings", [])
    actionable_findings = [f for f in all_findings if not is_vendor_observation(f)]
    vendor_findings = [f for f in all_findings if is_vendor_observation(f)]

    # 1. Executive Summary
    pdf.set_font("Courier", 'B', 11)
    pdf.cell(0, 8, sanitize("== EXECUTIVE MISSION AUDIT SUMMARY =="))
    pdf.ln(7)

    pdf.set_font("Courier", size=9)
    pdf.cell(0, 5, sanitize(f"Target URL:                      {target_url}"))
    pdf.ln(5)
    pdf.cell(0, 5, sanitize(f"Scan Completed:                  {timestamp}"))
    pdf.ln(5)
    pdf.cell(0, 5, sanitize(f"Pages Crawled:                   {data.get('pages_crawled', 0)}"))
    pdf.ln(5)
    pdf.cell(0, 5, sanitize(f"Endpoints Discovered:            {data.get('endpoints_found', 0)}"))
    pdf.ln(5)
    pdf.cell(0, 5, sanitize(f"Surface Risk Score:              {data.get('risk_score', 0)} / 100"))
    pdf.ln(5)
    pdf.cell(0, 5, sanitize(f"Actionable Vulnerabilities:      {len(actionable_findings)}"))
    pdf.ln(5)
    pdf.cell(0, 5, sanitize(f"Third-Party / Vendor Notices:    {len(vendor_findings)} (Summarized in Section B)"))
    pdf.ln(7)

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

    # Severity Summary Counts for Actionable Findings
    crit_count = sum(1 for f in actionable_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in actionable_findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in actionable_findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in actionable_findings if f.get("severity") == "LOW")
    info_count = sum(1 for f in actionable_findings if f.get("severity") == "INFO")

    pdf.set_font("Courier", 'B', 10)
    pdf.cell(0, 6, sanitize(f"Actionable Threat Distribution: CRIT: {crit_count} | HIGH: {high_count} | MED: {med_count} | LOW: {low_count} | INFO: {info_count}"))
    pdf.ln(6)

    # Chained Triage Impact Statement
    risk_score_val = int(data.get("risk_score", 0) or 0)
    impact_text = build_chained_impact_statement(target_url, actionable_findings, risk_score_val)
    pdf.set_font("Courier", 'B', 9)
    pdf.cell(0, 6, sanitize("Executive Summary & Chained Triage Impact Statement:"))
    pdf.ln(5)
    pdf.set_font("Courier", size=8)
    pdf.multi_cell(0, 4.5, sanitize(impact_text))
    pdf.ln(6)

    # 2. Section A: Actionable Infrastructure Vulnerabilities (Bug Bounty Submission Structure)
    pdf.set_font("Courier", 'B', 11)
    pdf.cell(0, 8, sanitize(f"== SECTION A: ACTIONABLE INFRASTRUCTURE VULNERABILITIES ({len(actionable_findings)}) =="))
    pdf.ln(7)

    if not actionable_findings:
        pdf.set_font("Courier", size=9)
        pdf.cell(0, 6, sanitize("No actionable infrastructure vulnerabilities or defects detected."))
        pdf.ln(6)
    else:
        for f in actionable_findings:
            if pdf.get_y() > 215:
                pdf.add_page()

            sev = f.get("severity", "INFO").upper()
            title = f.get("title", "Finding")
            cat = f.get("category", "GENERAL")
            conf = f.get("confidence", 1.0)
            endpoint = f.get("endpoint", target_url)
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            remediation = f.get("remediation", "Apply origin-level security hardening as recommended.")
            curl_cmd = ensure_stealth_curl_poc(f.get("curl_command", ""), endpoint)
            meta = classify_bug_bounty_metadata(f, target_url)

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

            # Standardized Bug Bounty Details
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Courier", size=8)

            repro_block = "\n".join(f"  {step}" for step in meta["reproduction_steps"])
            details = (
                f"Target Endpoint: {endpoint}\n"
                f"CWE Classification: {meta['cwe']}\n"
                f"CVSS v3.1 Base Vector: {meta['cvss_vector']} (Score: {meta['cvss_score']})\n"
                f"Description: {desc}\n"
                f"Evidence: {evidence[:200]}\n"
                f"Step-by-Step Reproduction Guide:\n{repro_block}\n"
                f"Actionable Remediation Guidance: {remediation}\n"
                f"Reproducible Stealth cURL PoC:\n{curl_cmd}\n"
            )

            pdf.multi_cell(0, 4.5, sanitize(details))
            pdf.ln(3)

    # 3. Section B: Third-Party & Vendor Observations (Compact Summary Table)
    if vendor_findings:
        if pdf.get_y() > 215:
            pdf.add_page()
        else:
            pdf.ln(4)

        pdf.set_font("Courier", 'B', 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, sanitize(f"== SECTION B: THIRD-PARTY & VENDOR OBSERVATIONS ({len(vendor_findings)}) =="))
        pdf.ln(6)

        pdf.set_font("Courier", 'I', 8)
        pdf.set_text_color(80, 80, 80)
        notice_text = (
            "The following notices represent third-party telemetry, bot management, and analytics SDK behaviors "
            "(Akamai, Adobe, Tealium). Missing flags or dynamic listeners on these assets are expected vendor "
            "mechanisms and are not first-party infrastructure defects."
        )
        pdf.multi_cell(0, 4, sanitize(notice_text))
        pdf.ln(4)

        def draw_table_header():
            pdf.set_fill_color(235, 235, 235)
            pdf.set_text_color(20, 20, 20)
            pdf.set_font("Courier", 'B', 8)
            pdf.cell(42, 6, "Vendor / Platform", border=1, fill=True)
            pdf.cell(50, 6, "Observation", border=1, fill=True)
            pdf.cell(38, 6, "Cookie / Asset", border=1, fill=True)
            pdf.cell(60, 6, "Operational Assessment", border=1, fill=True)
            pdf.ln(6)

        draw_table_header()

        pdf.set_font("Courier", size=7)
        pdf.set_text_color(50, 50, 50)
        for vf in vendor_findings:
            if pdf.get_y() > 265:
                pdf.add_page()
                draw_table_header()
                pdf.set_font("Courier", size=7)
                pdf.set_text_color(50, 50, 50)

            vendor = extract_vendor_name(vf)[:22]
            obs_title = vf.get("title", "Vendor Notice").replace("[Third-Party] ", "")
            if len(obs_title) > 28:
                obs_title = obs_title[:26] + ".."
            target_asset = extract_target_asset(vf, target_url)[:20]
            assessment = "Expected vendor telemetry behavior"
            if "httponly" in obs_title.lower():
                assessment = "Client-side JS readable by design"
            elif "secure" in obs_title.lower():
                assessment = "Third-party edge cookie configuration"
            elif "samesite" in obs_title.lower():
                assessment = "Cross-domain vendor tag requirement"
            elif "postmessage" in obs_title.lower():
                assessment = "Third-party SDK iframe communication"

            pdf.cell(42, 5, sanitize(vendor), border=1)
            pdf.cell(50, 5, sanitize(obs_title), border=1)
            pdf.cell(38, 5, sanitize(target_asset), border=1)
            pdf.cell(60, 5, sanitize(assessment[:34]), border=1)
            pdf.ln(5)

    # 4. Sensitive Routes Inventory
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

    # Save artifact within validated output directory boundary
    if not output_dir or "\x00" in str(output_dir):
        raise ValueError("Invalid output directory for PDF report.")
    now_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.basename(f"BlackRoute_Web_Report_{now_tag}.pdf")
    out_dir_resolved = Path(output_dir).resolve()
    os.makedirs(out_dir_resolved, exist_ok=True)
    out_path = (out_dir_resolved / filename).resolve()
    if not out_path.is_relative_to(out_dir_resolved) or out_path.is_symlink():
        raise ValueError("Security Violation: PDF report output path escapes target directory.")
    pdf.output(str(out_path))

    return str(filename)
