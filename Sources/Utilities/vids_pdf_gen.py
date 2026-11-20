import datetime
import os
import re
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

_CANONICAL_CVSS_BY_SEVERITY: Dict[str, tuple] = {
    "CRITICAL": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "9.1"),
    "HIGH": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "7.1"),
    "MEDIUM": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "5.4"),
    "LOW": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "3.1"),
    "INFO": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "0.0"),
}


def severity_from_cvss_score(score: float) -> str:
    """Map a CVSS v3.1 Base Score to its official qualitative severity rating."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def truncate_clean(text: Any, max_len: int = 160) -> str:
    """Truncate text cleanly at word or token boundaries with '...'."""
    s = str(text or "").strip()
    if len(s) <= max_len:
        return s
    cut = s[:max_len]
    last_sep = max(cut.rfind("; "), cut.rfind(" "), cut.rfind(";"), cut.rfind(","))
    if last_sep > max_len // 2:
        cut = cut[:last_sep].rstrip(" ;,")
    return f"{cut}..."


def ensure_stealth_curl_poc(curl_cmd: str, endpoint: str = "https://target.domain/") -> str:
    """
    Ensure that any generated or persisted cURL command embeds the full L7 stealth browser
    persona headers (User-Agent, Sec-Ch-Ua, Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform, Accept, Accept-Language)
    to prevent edge WAF 403 blocks during bug bounty triage reproduction, and avoids HEAD (-I) or noisy (-i) GET bodies.
    """
    target = endpoint or "https://target.domain/"
    cmd = (curl_cmd or "").strip()
    if not cmd:
        return f'curl -s -D - -o /dev/null "{target}"{STEALTH_CURL_HEADERS_BLOCK}'

    if cmd.startswith("curl -s -I "):
        cmd = "curl -s -D - -o /dev/null " + cmd[len("curl -s -I "):]
    elif cmd.startswith("curl -s -i ") and "-X POST" not in cmd:
        cmd = "curl -s -D - -o /dev/null " + cmd[len("curl -s -i "):]

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
    - CVSS v3.1 Base Score & Vector string strictly calibrated to finding severity
    - Step-by-Step Reproduction Guide
    """
    category = str(finding.get("category", "GENERAL")).upper()
    title = str(finding.get("title", "Security Finding"))
    title_lower = title.lower()
    desc_lower = str(finding.get("description", "")).lower()
    sev = str(finding.get("severity", "INFO")).upper().strip()
    if sev not in _CANONICAL_CVSS_BY_SEVERITY:
        sev = "INFO"
    endpoint = str(finding.get("endpoint") or default_target)

    cwe = finding.get("cwe") or "CWE-693: Protection Mechanism Failure"
    raw_vec = str(finding.get("cvss_vector") or "")
    raw_score = str(finding.get("cvss_score") or "")
    cvss_vector = ""
    cvss_score = ""
    if raw_vec and raw_score:
        try:
            if severity_from_cvss_score(float(raw_score)) == sev:
                cvss_vector = raw_vec
                cvss_score = raw_score
        except ValueError:
            pass

    if "csp" in title_lower or "content-security-policy" in title_lower or "content-security-policy" in desc_lower:
        cwe = "CWE-693: Protection Mechanism Failure (Lax Content-Security-Policy)"
        if not cvss_vector:
            if sev == "LOW":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "3.1"
            elif sev == "MEDIUM":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1"
    elif "clickjacking" in title_lower or "x-frame-options" in title_lower or "frame-ancestors" in title_lower:
        cwe = "CWE-1021: Improper Restriction of Rendered UI Layers or Frames (Clickjacking)"
        if not cvss_vector and sev == "MEDIUM":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "4.7"
    elif "hsts" in title_lower or "strict-transport" in title_lower:
        cwe = "CWE-319: Cleartext Transmission of Sensitive Information (Missing/Weak HSTS)"
        if not cvss_vector:
            if sev == "HIGH":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5"
            elif sev == "MEDIUM":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "4.2"
            elif sev == "LOW":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "3.1"
    elif "cors" in title_lower or "origin reflection" in title_lower:
        cwe = "CWE-942: Permissive Cross-domain Policy with Untrusted Domains (CORS)"
        if not cvss_vector:
            if sev == "CRITICAL":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "9.1"
            elif sev == "HIGH":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "8.1"
            elif sev == "MEDIUM":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "5.4"
            elif sev == "LOW":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "3.1"
    elif "referrer" in title_lower:
        cwe = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (Referrer Policy)"
        if not cvss_vector:
            if sev == "MEDIUM":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "4.3"
            elif sev == "LOW":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "3.1"
    elif "nosniff" in title_lower or "x-content-type-options" in title_lower:
        cwe = "CWE-16: Configuration (Missing MIME-Sniffing Protection)"
        if not cvss_vector and sev == "LOW":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "3.1"
    elif "permissions-policy" in title_lower or "feature-policy" in title_lower:
        cwe = "CWE-250: Execution with Unnecessary Privileges (Missing Permissions-Policy)"
    elif "cookie" in category.lower() or "cookie" in title_lower:
        if "secure" in title_lower and "samesite=none" not in title_lower:
            cwe = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
            if not cvss_vector and sev == "MEDIUM":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", "5.3"
        elif "httponly" in title_lower:
            cwe = "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
            if not cvss_vector:
                if sev == "HIGH":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "7.1"
                elif sev == "MEDIUM":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "5.4"
                elif sev == "LOW":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "3.1"
        elif "samesite" in title_lower:
            cwe = "CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
            if not cvss_vector:
                if sev == "HIGH":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "7.1"
                elif sev == "MEDIUM":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "4.3"
                elif sev == "LOW":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "3.1"
        else:
            cwe = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
            if not cvss_vector and sev == "HIGH":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "7.1"
    elif category == "SECRETS" or any(k in title_lower for k in ["aws", "stripe", "openai", "api key", "secret", "token", "jwt"]):
        cwe = "CWE-798: Use of Hard-coded Credentials"
        if not cvss_vector and sev == "CRITICAL":
            cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "9.1"
    elif category == "DOM_XSS" or "dom" in title_lower or "postmessage" in title_lower:
        if "postmessage" in title_lower:
            cwe = "CWE-346: Origin Validation Error (Unvalidated postMessage Listener)"
        else:
            cwe = "CWE-79: Improper Neutralization of Input During Web Page Generation (DOM-Based XSS)"
        if not cvss_vector:
            if sev == "HIGH":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", "8.2"
            elif sev == "MEDIUM":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1"
    elif category == "API_EXPOSURE":
        if "graphql" in title_lower:
            cwe = "CWE-200: Exposure of Sensitive Information (GraphQL Introspection Enabled)"
            if not cvss_vector:
                if sev == "HIGH":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5"
                elif sev == "MEDIUM":
                    cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "5.3"
        else:
            cwe = "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory"
            if not cvss_vector and sev == "HIGH":
                cvss_vector, cvss_score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5"

    # Strict CVSS-to-severity calibration: INFO is always 0.0 and any vector mismatch falls back to canonical severity vector
    if sev == "INFO":
        cvss_vector, cvss_score = _CANONICAL_CVSS_BY_SEVERITY["INFO"]
    else:
        try:
            score_matches = bool(cvss_vector and cvss_score and severity_from_cvss_score(float(cvss_score)) == sev)
        except ValueError:
            score_matches = False
        if not score_matches:
            cvss_vector, cvss_score = _CANONICAL_CVSS_BY_SEVERITY[sev]

    evidence_snippet = truncate_clean(finding.get("evidence", title), max_len=120)
    repro_steps = [
        f"1. Open a terminal and execute the Stealth Browser Persona cURL command below targeting `{endpoint}` (client-hint headers are pre-attached to bypass edge WAF bot filtering).",
        f"2. Inspect the raw HTTP response headers/payload returned by `{endpoint}` and verify the evidence indicator (`{evidence_snippet}`).",
        f"3. Confirm that `{title}` ({cwe}) is reproducible on the live origin response and evaluate downstream chaining potential."
    ]

    return {
        "cwe": cwe,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "reproduction_steps": repro_steps,
    }


def _infer_rule_id(finding: Dict[str, Any]) -> str:
    """Resolve explicit rule_id or infer deterministic rule ID matching SARIF taxonomy."""
    if finding.get("rule_id"):
        return str(finding["rule_id"]).upper()
    category = str(finding.get("category", "GENERAL")).upper()
    title = str(finding.get("title", "")).upper()
    description = str(finding.get("description", "")).upper()

    if "CSP" in title or "CSP" in category or "CONTENT-SECURITY-POLICY" in title or "CONTENT-SECURITY-POLICY" in description:
        if "UNSAFE-INLINE" in title or "INLINE" in title:
            return "BR-CSP-INLINE"
        if "UNSAFE-EVAL" in title or "EVAL" in title:
            return "BR-CSP-EVAL"
        if "MISSING" in title or "ABSENT" in title:
            return "BR-CSP-MISSING"
        if "WILDCARD" in title or "*" in title:
            return "BR-CSP-WILDCARD"
        return "BR-CSP-GENERAL"
    if "COOKIE" in category or "COOKIE" in title:
        if "INSECURE HTTP" in title or "CLEARTEXT" in title:
            return "BR-COOKIE-CLEARTEXT"
        if "SAMESITE" in title:
            return "BR-COOKIE-SAMESITE"
        if "SECURE" in title:
            return "BR-COOKIE-SECURE"
        if "HTTPONLY" in title:
            return "BR-COOKIE-HTTPONLY"
        return "BR-COOKIE-GENERAL"
    if "HSTS" in title or "STRICT-TRANSPORT" in title:
        return "BR-HEADER-HSTS"
    if "CLICKJACKING" in title or "X-FRAME" in title or "FRAME-ANCESTORS" in title:
        return "BR-HEADER-XFRAME"
    if "SNIFF" in title or "X-CONTENT-TYPE-OPTIONS" in title:
        return "BR-HEADER-NOSNIFF"
    if "REFERRER" in title or "REFERRER-POLICY" in title:
        return "BR-HEADER-REFERRER"
    if "PERMISSIONS" in title or "FEATURE-POLICY" in title:
        return "BR-HEADER-PERMISSIONS"
    if "CORS" in title or "ORIGIN" in title:
        if "SUBDOMAIN" in title:
            return "BR-CORS-SUBDOMAIN"
        if "WILDCARD" in title:
            return "BR-CORS-WILDCARD"
        if "CREDENTIAL" in title:
            return "BR-CORS-CREDENTIALS"
        return "BR-CORS-REFLECTION"
    if "DOM" in category or "XSS" in category:
        if "POSTMESSAGE" in title or "MESSAGE" in title:
            return "BR-DOM-POSTMESSAGE"
        if "INNERHTML" in title:
            return "BR-DOM-INNERHTML"
        if "EVAL" in title:
            return "BR-DOM-EVAL"
        return "BR-DOM-GENERAL"
    if "SECRET" in category:
        return "BR-SECRET-GENERAL"
    if "API" in category:
        if "GRAPHQL" in title:
            if "HARDENED" in title or "PROTECTED" in title:
                return "BR-API-GRAPHQL-HARDENED"
            return "BR-API-GRAPHQL-INTROSPECTION"
        if "SWAGGER" in title or "OPENAPI" in title:
            return "BR-API-SWAGGER"
        if "GIT" in title:
            return "BR-API-GIT"
        if "ENV" in title:
            return "BR-API-ENV"
        if "ACTUATOR" in title:
            return "BR-API-ACTUATOR"
        if "LOGIN" in title or "AUTH" in title:
            return "BR-API-LOGIN"
        return "BR-API-GENERAL"
    return "BR-GENERAL-FINDING"


def build_chained_impact_statement(target_url: str, actionable_findings: List[Dict[str, Any]], risk_score: int) -> str:
    """Synthesize an Executive Summary & Chained Triage Impact Statement strictly gated by observed finding rule IDs."""
    effective_findings = [
        f for f in actionable_findings
        if not is_vendor_observation(f) and str(f.get("severity", "INFO")).upper() != "INFO"
    ]
    if not effective_findings:
        return (
            f"Automated DAST and attack surface reconnaissance against {target_url} (Surface Risk Score: {risk_score}/100) "
            "identified no directly exploitable first-party infrastructure vulnerabilities during this assessment window."
        )

    rule_ids = {_infer_rule_id(f) for f in effective_findings}

    chains = []
    if any(r.startswith("BR-CSP-") for r in rule_ids):
        chains.append(
            "lax Content-Security-Policy directives weaken browser-side script execution barriers"
        )
    if any(r.startswith("BR-DOM-") for r in rule_ids):
        chains.append(
            "client-side DOM sinks or unvalidated postMessage handlers enable arbitrary JavaScript execution in victim browser sessions"
        )
    if "BR-COOKIE-HTTPONLY" in rule_ids:
        chains.append(
            "cookies lacking the HttpOnly flag are readable via client-side JavaScript (document.cookie) if an XSS vector is triggered"
        )
    if any(r in rule_ids for r in ("BR-COOKIE-SECURE", "BR-COOKIE-CLEARTEXT", "BR-HEADER-HSTS")):
        chains.append(
            "missing transport encryption enforcement (HSTS or cookie Secure flags) exposes traffic to cleartext network interception or SSL-stripping downgrades"
        )
    if "BR-COOKIE-SAMESITE" in rule_ids:
        chains.append(
            "missing SameSite cookie attributes increase exposure to cross-site state manipulation"
        )
    if any(r.startswith("BR-SECRET-") for r in rule_ids):
        chains.append(
            "hardcoded API credentials/tokens embedded in client-accessible bundles allow unauthorized third-party API abuse and privilege escalation"
        )
    if any(r.startswith("BR-CORS-") for r in rule_ids):
        chains.append(
            "permissive cross-origin resource sharing (CORS) origin reflection policies allow cross-origin response readout"
        )
    if "BR-API-GRAPHQL-INTROSPECTION" in rule_ids:
        chains.append(
            "enabled GraphQL introspection exposes internal query and mutation schemas"
        )
    if any(r in rule_ids for r in ("BR-API-SWAGGER", "BR-API-GIT", "BR-API-ENV", "BR-API-ACTUATOR", "BR-API-LOGIN", "BR-API-GENERAL")):
        chains.append(
            "exposed API schemas or sensitive administrative endpoints expand the exploitable attack surface"
        )
    if "BR-HEADER-XFRAME" in rule_ids:
        chains.append(
            "missing framing restrictions (X-Frame-Options / frame-ancestors) permit UI redressing (Clickjacking)"
        )
    if "BR-HEADER-REFERRER" in rule_ids:
        chains.append(
            "missing or permissive Referrer-Policy headers may leak URL paths or query parameters to external origins"
        )
    if "BR-HEADER-NOSNIFF" in rule_ids:
        chains.append(
            "missing X-Content-Type-Options: nosniff protection permits browser MIME-type sniffing"
        )

    if not chains:
        chains.append("identified HTTP security posture weaknesses reduce defense-in-depth protections across the target origin")

    chained_prose = "; additionally, ".join(chains)
    return (
        f"During authorized black-box security reconnaissance of {target_url} (Composite Surface Risk Score: {risk_score}/100), "
        f"BlackRoute-Web identified {len(effective_findings)} actionable first-party security defect(s). "
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
    featuring Executive Summary, Diagnostic Telemetry, Chained Triage Impact Statement, CWE & CVSS v3.1 vectors,
    Step-by-Step Reproduction Guides, Stealth Browser Persona cURL PoCs, and Section B Vendor Observations.
    """
    target_url = scan.get("target_url", "https://target.domain/")
    vendor_findings = [f for f in findings if is_vendor_observation(f)]
    info_findings = [
        f for f in findings
        if not is_vendor_observation(f) and str(f.get("severity", "INFO")).upper() == "INFO"
    ]
    actionable_findings = [
        f for f in findings
        if not is_vendor_observation(f) and str(f.get("severity", "INFO")).upper() != "INFO"
    ]

    crit_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "HIGH")
    med_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "MEDIUM")
    low_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "LOW")

    risk_score = scan.get("risk_score")
    if risk_score is None or risk_score == 0:
        if not actionable_findings:
            risk_score = 10
        else:
            from app.core.engine_bridge import _python_fallback_surface_graph
            risk_score = _python_fallback_surface_graph(
                [e.get("url", "") for e in (endpoints or []) if isinstance(e, dict) and e.get("url")],
                {},
                "",
                findings=findings,
            ).get("risk_score", 15)

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

    scan_completed = scan.get("scan_completed") or scan.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_profile = scan.get("scan_profile") or "stealth_mode=True, shadow_mode=False"
    initial_status = scan.get("initial_http_status") or "N/A"
    scan_duration = scan.get("scan_duration")
    scan_duration_str = f"{scan_duration}s" if scan_duration not in (None, "", 0, 0.0) else "N/A"
    engine_mode = scan.get("engine_mode") or "spider=NATIVE_RUST, surface_graph=NATIVE_GO"
    pages_crawled = scan.get("pages_crawled", 0)
    endpoints_found = scan.get("endpoints_found", len(endpoints or []))
    crawl_notes = scan.get("crawl_notes") or (
        f"Harvested {endpoints_found} endpoint(s) across {pages_crawled} page(s)."
        if endpoints_found
        else "0 static endpoints discovered (static HTML or JS-rendered DOM)."
    )

    impact_statement = build_chained_impact_statement(target_url, actionable_findings, int(risk_score))

    lines = [
        "# BlackRoute-Web Security Assessment & Bug Bounty Triage Report",
        "",
        "### Summary",
        f"- Target: {target_url}",
        f"- Scan Completed: {scan_completed}",
        f"- Scan Profile: {scan_profile}",
        f"- Initial HTTP Status: {initial_status}",
        f"- Scan Duration: {scan_duration_str}",
        f"- Engine Mode: {engine_mode}",
        f"- Pages Crawled: {pages_crawled}",
        f"- Endpoints Discovered: {endpoints_found}",
        f"- Crawl Notes: {crawl_notes}",
        f"- Risk Score: {risk_score}/100",
        f"- Actionable Vulnerabilities: {actionable_str}",
        f"- Informational Notices: {len(info_findings)}",
        f"- Third-Party / Vendor Notices: {len(vendor_findings)} (Summarized in Section B)",
        "",
    ]

    technologies = scan.get("technologies") or []
    if technologies:
        lines.append("### Detected Technologies & Stack")
        for t in technologies:
            lines.append(f"- **[{t.get('category', 'Stack')}]** {t.get('name', 'Unknown')}: {t.get('evidence', '')}")
        lines.append("")

    lines.extend([
        "### Executive Summary & Chained Triage Impact Statement",
        impact_statement,
        "",
        "### Primary Findings"
    ])

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
    if not actionable_findings:
        lines.append("No actionable first-party infrastructure vulnerabilities identified.")
        lines.append("")
    else:
        for idx, f in enumerate(actionable_findings, 1):
            sev_title = str(f.get("severity", "Info")).title()
            title = f.get("title", "Security Finding")
            conf = f.get("confidence", 1.0)
            endpoint = f.get("endpoint", target_url)
            raw_curl = f.get("curl_command", "")
            curl_cmd = ensure_stealth_curl_poc(raw_curl, endpoint)
            remediation = f.get("remediation", "Apply origin-level security hardening as recommended.")
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            meta = classify_bug_bounty_metadata(f, target_url)

            lines.append(f"#### {idx}. {title} [{sev_title}] (Conf: {conf})")
            lines.append(f"- **Target Endpoint**: `{endpoint}`")
            lines.append(f"- **Confidence**: `{conf}`")
            lines.append(f"- **CWE Classification**: `{meta['cwe']}`")
            lines.append(f"- **CVSS v3.1 Base Vector**: `{meta['cvss_vector']}` (Base Score: **{meta['cvss_score']}**)")
            if desc:
                lines.append(f"- **Description**: {desc}")
            if evidence:
                lines.append(f"- **Evidence**: `{truncate_clean(evidence, max_len=240)}`")
            lines.append("- **Step-by-Step Reproduction Guide**:")
            for step in meta["reproduction_steps"]:
                lines.append(f"  {step}")
            if remediation:
                lines.append(f"- **Actionable Remediation Guidance**: {remediation}")
            lines.append("- **Reproducible Stealth cURL PoC**:")
            lines.append("```bash")
            lines.append(curl_cmd)
            lines.append("```")
            lines.append("")

    if info_findings:
        lines.append("### Informational Posture Notices")
        for idx, inf in enumerate(info_findings, 1):
            inf_title = inf.get("title", "Informational Notice")
            inf_endpoint = inf.get("endpoint", target_url)
            meta = classify_bug_bounty_metadata(inf, target_url)
            lines.append(f"{idx}. {inf_title} [Info] (`{meta['cwe']}` | CVSS **0.0** | `{inf_endpoint}`)")
        lines.append("")

    lines.append("### Third-Party & Vendor Observations (Section B)")
    if vendor_findings:
        lines.append("The following findings represent expected third-party telemetry, consent, client-hint, bot management, and analytics SDK behaviors and do not represent first-party session vulnerabilities.")
        lines.append("")
        for vf in vendor_findings:
            v_name = extract_vendor_name(vf)
            v_title = vf.get("title", "Vendor Observation").replace("[Third-Party] ", "")
            v_asset = extract_target_asset(vf, target_url)
            lines.append(f"- **{v_name}**: {v_title} (`{v_asset}`)")
    else:
        lines.append("None detected.")
    lines.append("")

    sensitive_routes = scan.get("sensitive_routes") or []
    if sensitive_routes:
        lines.append("### Sensitive Route Attack Surface")
        for r in sensitive_routes[:40]:
            lines.append(f"- `{r}`")
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
    """Sanitize text to clean Latin-1 ASCII-safe encoding and soft-wrap long unbroken tokens for FPDF."""
    if not isinstance(text, str):
        text = str(text or "")
    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u00a0": " ",
        "\u200b": "",
        "\u2026": "...",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    text = text.encode('latin-1', 'replace').decode('latin-1')

    # Soft-wrap unbroken non-whitespace tokens > 88 chars so Courier 8pt never bleeds past PDF margins
    wrapped_lines = []
    for line in text.splitlines():
        if len(line) <= 98:
            wrapped_lines.append(line)
            continue
        out_tokens = []
        for tok in line.split(" "):
            if len(tok) <= 88:
                out_tokens.append(tok)
            else:
                chunks = [tok[i:i + 84] for i in range(0, len(tok), 84)]
                out_tokens.append("\n  ".join(chunks))
        wrapped_lines.append(" ".join(out_tokens))
    return "\n".join(wrapped_lines)

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
    known_families = [
        "Akamai Bot Manager",
        "Adobe Experience Cloud",
        "Tealium",
        "Google Analytics",
        "GDPR & Consent Management",
        "First-Party Analytics / Geo / Client Hints",
        "Akamai",
        "Adobe",
    ]
    for tag in tags:
        if tag in known_families:
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
    if "gdpr" in combined or "consent" in combined:
        return "GDPR & Consent Management"
    if any(k in combined for k in ("yandex_gid", "yandexuid", "yuidss", "_yasc", "'bh'", "bh=")):
        return "Analytics / Geo / Hints"
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
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_font("Courier", size=10)

    target_url = data.get("target_url", "Unknown Target")
    timestamp = data.get("scan_completed") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_profile = data.get("scan_profile") or "stealth_mode=True, shadow_mode=False"
    initial_status = data.get("initial_http_status") or "N/A"
    scan_duration = data.get("scan_duration")
    scan_duration_str = f"{scan_duration}s" if scan_duration not in (None, "", 0, 0.0) else "N/A"
    engine_mode = data.get("engine_mode") or "spider=NATIVE_RUST, surface_graph=NATIVE_GO"
    pages_crawled = data.get("pages_crawled", 0)
    endpoints_found = data.get("endpoints_found", 0)
    crawl_notes = data.get("crawl_notes") or (
        f"Harvested {endpoints_found} endpoint(s) across {pages_crawled} page(s)."
        if endpoints_found
        else "0 static endpoints discovered (static HTML or JS-rendered DOM)."
    )

    all_findings = data.get("findings", [])
    vendor_findings = [f for f in all_findings if is_vendor_observation(f)]
    info_findings = [
        f for f in all_findings
        if not is_vendor_observation(f) and str(f.get("severity", "INFO")).upper() == "INFO"
    ]
    actionable_findings = [
        f for f in all_findings
        if not is_vendor_observation(f) and str(f.get("severity", "INFO")).upper() != "INFO"
    ]

    # 1. Executive Summary
    pdf.set_font("Courier", 'B', 11)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 7, sanitize("== EXECUTIVE MISSION AUDIT SUMMARY =="), align="L")
    pdf.ln(2)

    pdf.set_font("Courier", size=9)
    summary_lines = [
        f"Target URL:                      {target_url}",
        f"Scan Completed:                  {timestamp}",
        f"Scan Profile:                    {scan_profile}",
        f"Initial HTTP Status:             {initial_status}",
        f"Scan Duration:                   {scan_duration_str}",
        f"Engine Mode:                     {engine_mode}",
        f"Pages Crawled:                   {pages_crawled}",
        f"Endpoints Discovered:            {endpoints_found}",
        f"Crawl Notes:                     {crawl_notes}",
        f"Surface Risk Score:              {data.get('risk_score', 0)} / 100",
        f"Actionable Vulnerabilities:      {len(actionable_findings)}",
        f"Informational Notices:           {len(info_findings)}",
        f"Third-Party / Vendor Notices:    {len(vendor_findings)} (Summarized in Section B)",
    ]
    for line in summary_lines:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 5, sanitize(line), align="L")
    pdf.ln(3)

    # Technology Fingerprints
    techs = data.get("technologies", [])
    if techs:
        pdf.set_font("Courier", 'B', 10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 6, sanitize("Detected Technologies & Stack:"), align="L")
        pdf.set_font("Courier", size=8)
        for t in techs:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, 4.5, sanitize(f"  - [{t.get('category', 'Stack')}] {t.get('name', 'Unknown')}: {t.get('evidence', '')}"), align="L")
        pdf.ln(3)

    # Severity Summary Counts for Actionable Findings (excludes INFO)
    crit_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "HIGH")
    med_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "MEDIUM")
    low_count = sum(1 for f in actionable_findings if str(f.get("severity", "")).upper() == "LOW")

    pdf.set_font("Courier", 'B', 10)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(
        pdf.epw,
        6,
        sanitize(
            f"Actionable Threat Distribution: CRIT: {crit_count} | HIGH: {high_count} | "
            f"MED: {med_count} | LOW: {low_count} (INFO Notices: {len(info_findings)})"
        ),
        align="L",
    )
    pdf.ln(2)

    # Chained Triage Impact Statement
    risk_score_val = int(data.get("risk_score", 0) or 0)
    impact_text = build_chained_impact_statement(target_url, actionable_findings, risk_score_val)
    pdf.set_font("Courier", 'B', 9)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 6, sanitize("Executive Summary & Chained Triage Impact Statement:"), align="L")
    pdf.set_font("Courier", size=8)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 4.5, sanitize(impact_text), align="L")
    pdf.ln(4)

    # 2. Section A: Actionable Infrastructure Vulnerabilities (Bug Bounty Submission Structure)
    pdf.set_font("Courier", 'B', 11)
    pdf.set_text_color(0, 0, 0)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 7, sanitize(f"== SECTION A: ACTIONABLE INFRASTRUCTURE VULNERABILITIES ({len(actionable_findings)}) =="), align="L")
    pdf.ln(2)

    if not actionable_findings:
        pdf.set_font("Courier", size=9)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 6, sanitize("No actionable infrastructure vulnerabilities or defects detected."), align="L")
        pdf.ln(4)
    else:
        for idx, f in enumerate(actionable_findings, 1):
            sev = str(f.get("severity", "INFO")).upper()
            title = str(f.get("title", "Finding"))
            cat = str(f.get("category", "GENERAL")).upper()
            conf = f.get("confidence", 1.0)
            endpoint = str(f.get("endpoint", target_url))
            desc = truncate_clean(f.get("description", ""), max_len=500)
            evidence = truncate_clean(f.get("evidence", ""), max_len=240)
            remediation = str(f.get("remediation", "Apply origin-level security hardening as recommended."))
            curl_cmd = ensure_stealth_curl_poc(f.get("curl_command", ""), endpoint)
            meta = classify_bug_bounty_metadata(f, target_url)

            repro_block = "\n".join(f"  {step}" for step in meta["reproduction_steps"])
            details = (
                f"Target Endpoint: {endpoint}\n"
                f"CWE Classification: {meta['cwe']}\n"
                f"CVSS v3.1 Base Vector: {meta['cvss_vector']} (Score: {meta['cvss_score']})\n"
                f"Description: {desc}\n"
                f"Evidence: {evidence}\n"
                f"Step-by-Step Reproduction Guide:\n{repro_block}\n"
                f"Actionable Remediation Guidance: {remediation}\n"
                f"Reproducible Stealth cURL PoC:\n{curl_cmd}\n"
            )
            sanitized_header = sanitize(f"{idx}. [{sev}] [{cat}] (Conf: {conf}) {title}")
            sanitized_details = sanitize(details)
            header_lines = sum(max(1, (len(ln) + 94) // 95) for ln in sanitized_header.splitlines())
            detail_lines = sum(max(1, (len(ln) + 94) // 95) for ln in sanitized_details.splitlines())
            estimated_height = (header_lines + detail_lines + 2) * 4.6
            remaining_space = (pdf.h - pdf.b_margin) - pdf.get_y()
            if pdf.get_y() > 45 and (remaining_space < min(estimated_height, 125) or pdf.get_y() > 210):
                pdf.add_page()

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
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, 5, sanitized_header, align="L")

            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Courier", size=8)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, 4.5, sanitized_details, align="L")
            pdf.ln(3)

    # Informational Posture Notices (non-actionable)
    if info_findings:
        pdf.ln(2)
        pdf.set_font("Courier", 'B', 10)
        pdf.set_text_color(60, 60, 60)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 6, sanitize(f"== INFORMATIONAL POSTURE NOTICES ({len(info_findings)}) =="), align="L")
        pdf.set_font("Courier", size=8)
        for idx, inf in enumerate(info_findings, 1):
            meta = classify_bug_bounty_metadata(inf, target_url)
            inf_line = (
                f"  {idx}. {inf.get('title', 'Notice')} [INFO] "
                f"({meta['cwe']} | CVSS: {meta['cvss_score']}) - {inf.get('endpoint', target_url)}"
            )
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, 4.5, sanitize(inf_line), align="L")
        pdf.ln(3)

    # 3. Section B: Third-Party & Vendor Observations (Always Rendered)
    if pdf.get_y() > 215 and vendor_findings:
        pdf.add_page()
    else:
        pdf.ln(3)

    pdf.set_font("Courier", 'B', 11)
    pdf.set_text_color(0, 0, 0)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(pdf.epw, 7, sanitize(f"== SECTION B: THIRD-PARTY & VENDOR OBSERVATIONS ({len(vendor_findings)}) =="), align="L")
    pdf.ln(2)

    if not vendor_findings:
        pdf.set_font("Courier", size=9)
        pdf.set_text_color(60, 60, 60)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 5, sanitize("None detected."), align="L")
        pdf.ln(3)
    else:
        pdf.set_font("Courier", 'I', 8)
        pdf.set_text_color(80, 80, 80)
        notice_text = (
            "The following notices represent third-party telemetry, consent, client-hint, bot management, "
            "and analytics SDK behaviors. Missing flags or dynamic listeners on these assets are expected "
            "mechanisms and are not first-party session vulnerabilities."
        )
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 4, sanitize(notice_text), align="L")
        pdf.ln(3)

        def draw_table_header():
            pdf.set_x(pdf.l_margin)
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

            pdf.set_x(pdf.l_margin)
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
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(pdf.epw, 7, sanitize("== SENSITIVE ROUTE ATTACK SURFACE =="), align="L")
        pdf.ln(1)
        pdf.set_font("Courier", size=8)
        for r in sensitive_routes[:40]:
            if pdf.get_y() > 265:
                pdf.add_page()
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(pdf.epw, 4.5, sanitize(f"  * {r}"), align="L")

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
