from typing import Dict, List, Any, Optional
import re
import urllib.parse
import httpx

# Vendor WAF / analytics / consent cookies that must remain JS-readable for telemetry.
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
    "Google Analytics": re.compile(r"^(?:_ga(?:_[A-Za-z0-9]+)?|_gid|_gcl_au|__utm[a-z])$", re.IGNORECASE),
    "GDPR & Consent Management": re.compile(
        r"^(?:is_gdpr|is_gdpr_b|euconsent(?:-v2)?|OptanonConsent|OptanonAlertBoxClosed|CookieConsent|cookieyes-consent|cmplz_.*)$",
        re.IGNORECASE,
    ),
    "First-Party Analytics / Geo / Client Hints": re.compile(
        r"^(?:yandex_gid|yandexuid|yuidss|yp|_yasc|bh|_ym_uid|_ym_d|_ym_isad|_fbp|_fbc|_clck|_clsk|.*_gid)$",
        re.IGNORECASE,
    ),
}

# Authenticated session/token cookie indicator patterns (avoids naive 'id'/'uid' substring matches)
_AUTHENTICATED_SESSION_COOKIE_RE = re.compile(
    r"(?:^|[_\-\.])(?:sess(?:ion)?(?:_?id)?|sid|phpsessid|jsessionid|aspsessionid|connect\.sid|"
    r"auth(?:_?token)?|jwt|access_?token|refresh_?token|id_?token|csrf(?:_?token)?|xsrf(?:_?token)?|login)(?:$|[_\-\.])|"
    r"^(?:sessionid|authtoken|csrftoken|xsrftoken)$",
    re.IGNORECASE,
)


def _vendor_cookie_family(cookie_name: str) -> Optional[str]:
    for family, pattern in VENDOR_COOKIE_EXCLUSIONS.items():
        if pattern.match(cookie_name):
            return family
    return None


def _is_authenticated_session_cookie(cookie_name: str) -> bool:
    """Return True only when cookie_name matches an explicit session/auth/token indicator."""
    return bool(_AUTHENTICATED_SESSION_COOKIE_RE.search(cookie_name.strip()))


def _is_same_site_subdomain(test_netloc: str, target_netloc: str) -> bool:
    """Return True when test_netloc is a subdomain of target_netloc (or its apex domain)."""
    test_host = (test_netloc or "").split(":")[0].lower().strip()
    target_host = (target_netloc or "").split(":")[0].lower().strip()
    if not test_host or not target_host or test_host == target_host:
        return False
    base_host = target_host[4:] if target_host.startswith("www.") else target_host
    return test_host.endswith("." + target_host) or test_host.endswith("." + base_host)


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
                "rule_id": "BR-CSP-MISSING",
                "title": "Missing Content-Security-Policy (CSP)",
                "description": "The Content-Security-Policy header is missing, leaving the application vulnerable to cross-site scripting (XSS) and code injection.",
                "endpoint": url,
                "evidence": "Header 'Content-Security-Policy' not found in response.",
                "confidence": 1.0,
                "remediation": "Define a robust Content-Security-Policy header restricting script sources, object sources, and frame ancestors."
            })
        else:
            directives = [d.strip() for d in csp.split(";") if d.strip()]
            dir_map: Dict[str, List[str]] = {}
            raw_dir_map: Dict[str, str] = {}
            for d in directives:
                parts = d.split()
                if parts:
                    d_name = parts[0].lower()
                    dir_map[d_name] = parts[1:]
                    raw_dir_map[d_name] = d

            script_dir = "script-src" if "script-src" in dir_map else ("default-src" if "default-src" in dir_map else None)
            if script_dir:
                script_tokens_lower = [t.lower() for t in dir_map[script_dir]]
                raw_script_directive = raw_dir_map[script_dir]
                has_nonce_or_hash = any(
                    t.strip("'\"").startswith(("nonce-", "sha256-", "sha384-", "sha512-"))
                    for t in script_tokens_lower
                )

                # Per CSP Level 2/3, browsers ignore 'unsafe-inline' when a nonce or hash is present in script-src
                if "'unsafe-inline'" in script_tokens_lower and not has_nonce_or_hash:
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "HEADERS",
                        "rule_id": "BR-CSP-INLINE",
                        "title": "Insecure CSP: 'unsafe-inline' Detected",
                        "description": f"CSP '{script_dir}' allows inline script execution without a cryptographic nonce or hash fallback, significantly reducing protection against XSS.",
                        "endpoint": url,
                        "evidence": f"CSP Directive ({script_dir}): {raw_script_directive}",
                        "confidence": 0.95,
                        "remediation": "Remove 'unsafe-inline' and employ cryptographic nonces or SHA-256 hashes for authorized scripts."
                    })
                if "'unsafe-eval'" in script_tokens_lower:
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "HEADERS",
                        "rule_id": "BR-CSP-EVAL",
                        "title": "Insecure CSP: 'unsafe-eval' Detected",
                        "description": f"CSP '{script_dir}' permits dynamic string execution (eval, Function constructor), introducing code execution risks.",
                        "endpoint": url,
                        "evidence": f"CSP Directive ({script_dir}): {raw_script_directive}",
                        "confidence": 0.95,
                        "remediation": "Refactor application logic to eliminate dynamic string code evaluation and remove 'unsafe-eval'."
                    })

            active_wildcard_dirs = [
                "script-src", "default-src", "connect-src", "object-src",
                "frame-src", "frame-ancestors", "style-src", "base-uri"
            ]
            wildcard_candidates = [d for d in active_wildcard_dirs if d in dir_map]
            wildcard_candidates.extend(
                d for d in dir_map if d not in active_wildcard_dirs and d not in ("img-src", "media-src", "font-src")
            )
            for d_name in wildcard_candidates:
                if "*" in dir_map[d_name]:
                    findings.append({
                        "severity": "LOW",
                        "category": "HEADERS",
                        "rule_id": "BR-CSP-WILDCARD",
                        "title": "Permissive CSP: Wildcard Host Allowed",
                        "description": f"CSP '{d_name}' specifies a wildcard '*' allowing resources from any host domain.",
                        "endpoint": url,
                        "evidence": f"Wildcard host detected in CSP ({d_name}): {raw_dir_map[d_name]}",
                        "confidence": 0.9,
                        "remediation": "Explicitly whitelist trusted origins instead of using wildcard domain scopes."
                    })
                    break

        # 2. Strict-Transport-Security (HSTS)
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme.lower() == "https":
            hsts = h_lower.get("strict-transport-security")
            if not hsts:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "HEADERS",
                    "rule_id": "BR-HEADER-HSTS",
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
                        "rule_id": "BR-HEADER-HSTS",
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
                "rule_id": "BR-HEADER-XFRAME",
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
                "rule_id": "BR-HEADER-NOSNIFF",
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
                "rule_id": "BR-HEADER-REFERRER",
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
                "rule_id": "BR-HEADER-REFERRER",
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
                "rule_id": "BR-HEADER-PERMISSIONS",
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
                "rule_id": "BR-HEADER-BANNER",
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
                "rule_id": "BR-HEADER-POWEREDBY",
                "title": "Technology Disclosure via X-Powered-By",
                "description": f"The backend framework discloses its identity: '{x_powered_by}'.",
                "endpoint": url,
                "evidence": f"X-Powered-By: {x_powered_by}",
                "confidence": 1.0,
                "remediation": "Remove the 'X-Powered-By' header in application or proxy settings."
            })

        return findings

    @staticmethod
    def audit_cookies(url: str, cookies_headers: List[str], is_authenticated: bool = False) -> List[Dict[str, Any]]:
        """Audit Set-Cookie directives for Secure, HttpOnly, and SameSite hygiene with auth-context awareness."""
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
            is_session_cookie = _is_authenticated_session_cookie(cookie_name)

            # Skip if we've already processed this cookie for this specific check type
            cookie_key = (cookie_name.lower(), "cookie_audit")
            if cookie_key in seen_cookies:
                continue
            seen_cookies.add(cookie_key)

            # Insecure cleartext HTTP cookie check
            if not is_https:
                if is_session_cookie and not vendor_family:
                    findings.append({
                        "severity": "HIGH",
                        "category": "COOKIES",
                        "rule_id": "BR-COOKIE-CLEARTEXT",
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
                    "rule_id": "BR-COOKIE-SECURE",
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
                        "rule_id": "BR-COOKIE-HTTPONLY",
                        "title": f"Vendor Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        "description": (
                            f"{vendor_family} cookie '{cookie_name}' is readable by JavaScript by design. "
                            "Analytics, consent, client-hint, and anti-bot SDKs read or update this cookie in the browser; "
                            "forcing HttpOnly would break vendor/telemetry behavior. This is not an authenticated session defect."
                        ),
                        "endpoint": url,
                        "evidence": f"Set-Cookie: {cookie_str}",
                        "confidence": 0.8,
                        "remediation": (
                            f"Do not set HttpOnly on '{cookie_name}' if required by client-side telemetry/consent scripts. "
                            "Confirm the cookie is not reused as an authenticated session token."
                        ),
                        "tags": ["vendor_integration", vendor_family, "httponly_false_positive"],
                    })
                else:
                    # Reserve HIGH strictly for explicit session/auth/token cookies in authenticated contexts
                    severity = "HIGH" if (is_authenticated and is_session_cookie) else "LOW"
                    findings.append({
                        "severity": severity,
                        "category": "COOKIES",
                        "rule_id": "BR-COOKIE-HTTPONLY",
                        "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                        "description": f"The cookie '{cookie_name}' is accessible via client-side JavaScript (`document.cookie`), making it readable via XSS.",
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
                    "rule_id": "BR-COOKIE-SAMESITE",
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
                    "rule_id": "BR-COOKIE-SAMESITE",
                    "title": f"Insecure SameSite=None Without Secure on '{cookie_name}'",
                    "description": f"Cookie '{cookie_name}' sets SameSite=None without the Secure attribute, which is rejected by modern browsers and leaves it vulnerable to cross-site transmission.",
                    "endpoint": url,
                    "evidence": f"Set-Cookie: {cookie_str}",
                    "confidence": 1.0,
                    "remediation": "Add '; Secure' whenever 'SameSite=None' is declared."
                })

        return findings

    @staticmethod
    def audit_cors(
        url: str,
        acao_header: str,
        acac_header: str,
        tested_origin: str,
        is_authenticated: bool = False,
    ) -> List[Dict[str, Any]]:
        """Audit Cross-Origin Resource Sharing (CORS) misconfigurations using two-tier origin classification."""
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
                "rule_id": "BR-CORS-WILDCARD",
                "title": "Severe CORS Misconfiguration: Wildcard with Credentials",
                "description": "The server responds with 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'. While standard browsers block this combination to prevent cross-origin credential theft, this misconfiguration breaks cross-origin integrations and frequently leads developers to blindly reflect the Request Origin, creating a critical data exfiltration vulnerability.",
                "endpoint": url,
                "evidence": "Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                "confidence": 1.0,
                "remediation": "Never combine wildcard origins with credentials. Restrict Access-Control-Allow-Origin to trusted domains."
            })
        # Origin reflection: distinguish external third-party origin reflection from same-site subdomain trust
        elif acao == tested_origin:
            parsed_test = urllib.parse.urlparse(tested_origin)
            parsed_url = urllib.parse.urlparse(url)
            if (parsed_test.netloc and parsed_test.netloc != parsed_url.netloc) or tested_origin == "null":
                if _is_same_site_subdomain(parsed_test.netloc, parsed_url.netloc):
                    sev = "MEDIUM" if acac else "LOW"
                    title = "CORS Subdomain Origin Reflection" + (" with Credentials" if acac else "")
                    description = (
                        f"The server reflects same-site subdomain Request Origin '{tested_origin}' into Access-Control-Allow-Origin"
                        + (
                            " with credentials allowed. While same-site subdomain trust is a common first-party pattern, an XSS or subdomain takeover on any sibling subdomain could allow cross-subdomain data access."
                            if acac
                            else "."
                        )
                    )
                    rule_id = "BR-CORS-SUBDOMAIN"
                else:
                    sev = ("CRITICAL" if is_authenticated else "HIGH") if acac else "MEDIUM"
                    title = "CORS Insecure Origin Reflection" + (" with Credentials" if acac else "")
                    description = (
                        f"The server dynamically reflects untrusted external Request Origin '{tested_origin}' into Access-Control-Allow-Origin"
                        + (" with credentials allowed, enabling cross-origin authenticated data theft." if acac else ".")
                    )
                    rule_id = "BR-CORS-CREDENTIALS" if acac else "BR-CORS-REFLECTION"

                findings.append({
                    "severity": sev,
                    "category": "HEADERS",
                    "rule_id": rule_id,
                    "title": title,
                    "description": description,
                    "endpoint": url,
                    "evidence": f"Reflected Origin: {acao} (Credentials allowed: {acac})",
                    "confidence": 0.95,
                    "remediation": "Validate the incoming Origin header against an immutable server-side whitelist before returning Access-Control-Allow-Origin.",
                    "tested_origin": tested_origin
                })

        return findings
