from typing import Dict, List, Any, Optional
import re
import urllib.parse
import httpx

# Vendor WAF / analytics cookies that must remain JS-readable for telemetry.
# Missing HttpOnly on these is expected, not a first-party session defect.
VENDOR_COOKIE_EXCLUSIONS = {
    "Akamai Bot Manager": re.compile(
        r"^(?:_abck|bm_(?:mi|so|sz|sv|lso)|ak_bmsc|akamai_.*)$",
        re.IGNORECASE,
    ),
    "Adobe Experience Cloud": re.compile(
        r"^(?:mbox|mboxEdgeCluster|AMCVS?_.+|s_cc|s_sq)$",
        re.IGNORECASE,
    ),
    "Tealium": re.compile(r"^utag_main$", re.IGNORECASE),
    "Google Analytics": re.compile(r"^(?:_ga(?:_[A-Za-z0-9]+)?|_gid|_gcl_au)$", re.IGNORECASE),
}


def _vendor_cookie_family(cookie_name: str) -> Optional[str]:
    for family, pattern in VENDOR_COOKIE_EXCLUSIONS.items():
        if pattern.match(cookie_name):
            return family
    return None


class HeaderAuditor:
    """
    Analyzes HTTP response headers, SSL/TLS transport posture, and cookie hygiene.
    """

    @staticmethod
    def audit_response_headers(url: str, headers: httpx.Headers, status_code: int) -> List[Dict[str, Any]]:
        findings = []
        h_lower = {k.lower(): v for k, v in headers.items()}

        # 1. Content-Security-Policy (CSP)
        csp = h_lower.get("content-security-policy")
        if not csp:
            findings.append({
                "severity": "MEDIUM",
                "category": "HEADERS",
                "title": "Missing Content-Security-Policy (CSP)",
                "description": "The Content-Security-Policy header is missing, leaving the application vulnerable to cross-site scripting (XSS) and code injection.",
                "endpoint": url,
                "evidence": "Header 'Content-Security-Policy' not found in response.",
                "confidence": 1.0,
                "remediation": "Define a robust Content-Security-Policy header restricting script sources, object sources, and frame ancestors."
            })
        else:
            directives = [d.strip() for d in csp.split(";") if d.strip()]
            dir_map = {}
            for d in directives:
                parts = d.split()
                if parts:
                    dir_map[parts[0].lower()] = parts[1:]

            if "'unsafe-inline'" in csp:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "HEADERS",
                    "title": "Insecure CSP: 'unsafe-inline' Detected",
                    "description": "CSP allows inline script or style execution, significantly reducing protection against XSS.",
                    "endpoint": url,
                    "evidence": f"CSP Directive contains 'unsafe-inline': {csp[:120]}...",
                    "confidence": 0.95,
                    "remediation": "Remove 'unsafe-inline' and employ cryptographic nonces or SHA-256 hashes for authorized scripts."
                })
            if "'unsafe-eval'" in csp:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "HEADERS",
                    "title": "Insecure CSP: 'unsafe-eval' Detected",
                    "description": "CSP permits dynamic string execution (eval, Function constructor), introducing code execution risks.",
                    "endpoint": url,
                    "evidence": f"CSP Directive contains 'unsafe-eval': {csp[:120]}...",
                    "confidence": 0.95,
                    "remediation": "Refactor application logic to eliminate dynamic string code evaluation and remove 'unsafe-eval'."
                })
            if "*" in csp.split():
                findings.append({
                    "severity": "LOW",
                    "category": "HEADERS",
                    "title": "Permissive CSP: Wildcard Host Allowed",
                    "description": "CSP specifies a wildcard '*' allowing resources from any host domain.",
                    "endpoint": url,
                    "evidence": f"Wildcard host detected in CSP: {csp[:120]}...",
                    "confidence": 0.9,
                    "remediation": "Explicitly whitelist trusted origins instead of using wildcard domain scopes."
                })

        # 2. Strict-Transport-Security (HSTS)
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme.lower() == "https":
            hsts = h_lower.get("strict-transport-security")
            if not hsts:
                findings.append({
                    "severity": "HIGH",
                    "category": "HEADERS",
                    "title": "Missing Strict-Transport-Security (HSTS)",
                    "description": "HTTPS connection does not enforce HSTS, allowing potential SSL-stripping and man-in-the-middle downgrade attacks.",
                    "endpoint": url,
                    "evidence": "Header 'Strict-Transport-Security' not present in HTTPS response.",
                    "confidence": 1.0,
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                })
            else:
                max_age = 0
                for part in hsts.split(";"):
                    part = part.strip().lower()
                    if part.startswith("max-age="):
                        try:
                            max_age = int(part.split("=")[1])
                        except ValueError:
                            pass
                if max_age < 15552000:  # less than ~180 days
                    findings.append({
                        "severity": "LOW",
                        "category": "HEADERS",
                        "title": "Suboptimal HSTS max-age Duration",
                        "description": f"HSTS max-age is set to {max_age} seconds (recommended is at least 31536000 seconds / 1 year).",
                        "endpoint": url,
                        "evidence": f"Strict-Transport-Security: {hsts}",
                        "confidence": 0.9,
                        "remediation": "Increase max-age directive to at least 31536000 (1 year) and consider adding 'includeSubDomains'."
                    })

        # 3. X-Frame-Options (Clickjacking)
        xfo = h_lower.get("x-frame-options")
        frame_ancestors = csp and "frame-ancestors" in csp.lower()
        if not xfo and not frame_ancestors:
            findings.append({
                "severity": "MEDIUM",
                "category": "HEADERS",
                "title": "Missing Anti-Clickjacking Header (X-Frame-Options / frame-ancestors)",
                "description": "Application can be embedded inside an iframe on malicious sites, exposing users to UI redress/clickjacking attacks.",
                "endpoint": url,
                "evidence": "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' directive was supplied.",
                "confidence": 0.95,
                "remediation": "Set 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or configure CSP 'frame-ancestors 'self''."
            })

        # 4. X-Content-Type-Options
        xcto = h_lower.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            evidence_str = f"X-Content-Type-Options: {xcto}" if xcto else "Header 'X-Content-Type-Options' not found in response."
            findings.append({
                "severity": "LOW",
                "category": "HEADERS",
                "title": "Missing X-Content-Type-Options: nosniff",
                "description": "Browsers may attempt MIME-type sniffing on responses, leading to script execution from non-script content types.",
                "endpoint": url,
                "evidence": evidence_str,
                "confidence": 1.0,
                "remediation": "Configure web server to return 'X-Content-Type-Options: nosniff'."
            })

        # 5. Referrer-Policy
        ref_policy = h_lower.get("referrer-policy")
        if not ref_policy:
            findings.append({
                "severity": "LOW",
                "category": "HEADERS",
                "title": "Missing Referrer-Policy Header",
                "description": "Without an explicit Referrer-Policy, user paths, session tokens, or sensitive IDs in URLs may leak to external referrers.",
                "endpoint": url,
                "evidence": "Header 'Referrer-Policy' not found in response.",
                "confidence": 0.85,
                "remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            })
        elif "unsafe-url" in ref_policy.lower():
            findings.append({
                "severity": "MEDIUM",
                "category": "HEADERS",
                "title": "Insecure Referrer-Policy: unsafe-url",
                "description": "Referrer-Policy is set to 'unsafe-url', which unconditionally leaks full request paths and queries to third parties.",
                "endpoint": url,
                "evidence": f"Referrer-Policy: {ref_policy}",
                "confidence": 1.0,
                "remediation": "Change Referrer-Policy to 'strict-origin-when-cross-origin'."
            })

        # 6. Permissions-Policy
        perm_policy = h_lower.get("permissions-policy") or h_lower.get("feature-policy")
        if not perm_policy:
            findings.append({
                "severity": "INFO",
                "category": "HEADERS",
                "title": "Missing Permissions-Policy",
                "description": "Permissions-Policy is absent; browser features like camera, microphone, and geolocation are not explicitly restricted.",
                "endpoint": url,
                "evidence": "Header 'Permissions-Policy' not configured.",
                "confidence": 0.8,
                "remediation": "Implement 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
            })

        # 7. Technology & Server Banner Disclosure
        server = h_lower.get("server")
        if server and any(c.isdigit() for c in server):
            findings.append({
                "severity": "LOW",
                "category": "HEADERS",
                "title": "Server Banner Version Disclosure",
                "description": f"The Server header reveals detailed version information: '{server}'.",
                "endpoint": url,
                "evidence": f"Server: {server}",
                "confidence": 1.0,
                "remediation": "Suppress server software version signatures in server configuration."
            })

        x_powered_by = h_lower.get("x-powered-by")
        if x_powered_by:
            findings.append({
                "severity": "LOW",
                "category": "HEADERS",
                "title": "Technology Disclosure via X-Powered-By",
                "description": f"The backend framework discloses its identity: '{x_powered_by}'.",
                "endpoint": url,
                "evidence": f"X-Powered-By: {x_powered_by}",
                "confidence": 1.0,
                "remediation": "Remove the 'X-Powered-By' header in application or proxy settings."
            })

        return findings

    @staticmethod
    def audit_cookies(url: str, cookies_headers: List[str]) -> List[Dict[str, Any]]:
        """Audit Set-Cookie directives for Secure, HttpOnly, and SameSite hygiene."""
        findings = []
        is_https = url.lower().startswith("https://")
        seen_cookies = set()  # Track (cookie_name.lower(), check_type) to prevent duplicates

        for cookie_str in cookies_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            name_val = parts[0]
            cookie_name = name_val.split("=")[0].strip()
            flags = {p.lower().split("=")[0].strip(): (p.split("=")[1].strip() if "=" in p else True) for p in parts[1:]}
            vendor_family = _vendor_cookie_family(cookie_name)
            
            # Skip if we've already processed this cookie for this specific check type
            cookie_key = (cookie_name.lower(), "cookie_audit")
            if cookie_key in seen_cookies:
                continue
            seen_cookies.add(cookie_key)

            # Insecure cleartext HTTP cookie check
            if not is_https:
                is_sensitive = any(kw in cookie_name.lower() for kw in ["sess", "auth", "token", "jwt", "id", "login", "key"])
                if is_sensitive and not vendor_family:
                    findings.append({
                        "severity": "HIGH",
                        "category": "COOKIES",
                        "title": f"Sensitive Cookie '{cookie_name}' Transmitted over Insecure HTTP",
                        "description": f"The sensitive cookie '{cookie_name}' is set over unencrypted plaintext HTTP, exposing credentials and session states to cleartext network interception and downgrade attacks.",
                        "endpoint": url,
                        "evidence": f"Cleartext Set-Cookie: {cookie_str}",
                        "confidence": 1.0,
                        "remediation": f"Enforce TLS/HTTPS across the application and append '; Secure' to the Set-Cookie directive for '{cookie_name}'."
                    })

            # Secure flag
            if is_https and "secure" not in flags:
                findings.append({
                    "severity": "INFO" if vendor_family else "MEDIUM",
                    "category": "COOKIES",
                    "title": f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                    "description": f"The cookie '{cookie_name}' is transmitted over HTTPS but lacks the 'Secure' directive, risking interception via plaintext HTTP downgrade.",
                    "endpoint": url,
                    "evidence": f"Set-Cookie: {cookie_str}",
                    "confidence": 0.8 if vendor_family else 1.0,
                    "remediation": f"Append '; Secure' to the Set-Cookie directive for '{cookie_name}'.",
                    "tags": ["vendor_integration", vendor_family] if vendor_family else [],
                })

            # HttpOnly flag
            if "httponly" not in flags:
                if vendor_family:
                    findings.append({
                        "severity": "INFO",
                        "category": "COOKIES",
                        "title": f"Vendor Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        "description": (
                            f"{vendor_family} cookie '{cookie_name}' is readable by JavaScript by design. "
                            "Anti-bot and analytics SDKs must read and update this cookie in the browser; "
                            "forcing HttpOnly would break vendor integrity checks. This is not a first-party session defect."
                        ),
                        "endpoint": url,
                        "evidence": f"Set-Cookie: {cookie_str}",
                        "confidence": 0.8,
                        "remediation": (
                            f"Do not set HttpOnly on '{cookie_name}'. Confirm the cookie is scoped to the vendor "
                            "integration and is not reused as an application session token."
                        ),
                        "tags": ["vendor_integration", vendor_family, "httponly_false_positive"],
                    })
                else:
                    # Sensitive cookies (session, token, auth, id) deserve higher severity
                    is_sensitive = any(kw in cookie_name.lower() for kw in ["sess", "auth", "token", "jwt", "id", "login", "key"])
                    severity = "HIGH" if is_sensitive else "LOW"
                    findings.append({
                        "severity": severity,
                        "category": "COOKIES",
                        "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        "description": f"The cookie '{cookie_name}' is accessible via client-side JavaScript (`document.cookie`), making it vulnerable to extraction via XSS.",
                        "endpoint": url,
                        "evidence": f"Set-Cookie: {cookie_str}",
                        "confidence": 0.95,
                        "remediation": f"Append '; HttpOnly' to the Set-Cookie directive for '{cookie_name}'."
                    })

            # SameSite flag
            if "samesite" not in flags:
                findings.append({
                    "severity": "INFO" if vendor_family else "LOW",
                    "category": "COOKIES",
                    "title": f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    "description": f"The cookie '{cookie_name}' does not specify SameSite, potentially exposing users to Cross-Site Request Forgery (CSRF).",
                    "endpoint": url,
                    "evidence": f"Set-Cookie: {cookie_str}",
                    "confidence": 0.8 if vendor_family else 0.9,
                    "remediation": f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{cookie_name}'.",
                    "tags": ["vendor_integration", vendor_family] if vendor_family else [],
                })
            elif str(flags["samesite"]).lower() == "none" and "secure" not in flags:
                findings.append({
                    "severity": "HIGH",
                    "category": "COOKIES",
                    "title": f"Insecure SameSite=None Without Secure on '{cookie_name}'",
                    "description": f"Cookie '{cookie_name}' sets SameSite=None without the Secure attribute, which is rejected by modern browsers and leaves it vulnerable to cross-site transmission.",
                    "endpoint": url,
                    "evidence": f"Set-Cookie: {cookie_str}",
                    "confidence": 1.0,
                    "remediation": "Add '; Secure' whenever 'SameSite=None' is declared."
                })

        return findings

    @staticmethod
    def audit_cors(url: str, acao_header: str, acac_header: str, tested_origin: str) -> List[Dict[str, Any]]:
        """Audit Cross-Origin Resource Sharing (CORS) misconfigurations."""
        findings = []
        if not acao_header:
            return findings

        acao = acao_header.strip()
        acac = acac_header.strip().lower() == "true" if acac_header else False

        # Wildcard with credentials
        if acao == "*" and acac:
            findings.append({
                "severity": "CRITICAL",
                "category": "HEADERS",
                "title": "Severe CORS Misconfiguration: Wildcard with Credentials",
                "description": "The server responds with 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'. While standard browsers block this combination to prevent cross-origin credential theft, this misconfiguration breaks cross-origin integrations and frequently leads developers to blindly reflect the Request Origin, creating a critical data exfiltration vulnerability.",
                "endpoint": url,
                "evidence": f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                "confidence": 1.0,
                "remediation": "Never combine wildcard origins with credentials. Restrict Access-Control-Allow-Origin to trusted domains."
            })
        # Origin reflection: verify if server dynamically reflected the tested cross-origin request
        elif acao == tested_origin:
            parsed_test = urllib.parse.urlparse(tested_origin)
            parsed_url = urllib.parse.urlparse(url)
            # Only flag if tested origin is distinct from target host or null
            if (parsed_test.netloc and parsed_test.netloc != parsed_url.netloc) or tested_origin == "null":
                sev = "CRITICAL" if acac else "HIGH"
                findings.append({
                    "severity": sev,
                    "category": "HEADERS",
                    "title": "CORS Insecure Origin Reflection" + (" with Credentials" if acac else ""),
                    "description": f"The server dynamically reflects untrusted Request Origin '{tested_origin}' into Access-Control-Allow-Origin" + (" with credentials allowed, enabling cross-origin authenticated data theft." if acac else "."),
                    "endpoint": url,
                    "evidence": f"Reflected Origin: {acao} (Credentials allowed: {acac})",
                    "confidence": 0.95,
                    "remediation": "Validate the incoming Origin header against an immutable server-side whitelist before returning Access-Control-Allow-Origin.",
                    "tested_origin": tested_origin
                })

        return findings
