import asyncio
from typing import Dict, List, Any
import urllib.parse
import httpx
import time
import random
from app.core.config import settings


class DynamicPacingController:
    """Monitors server response latency and dynamically adjusts pacing to avoid WAF detection."""
    
    def __init__(self, base_jitter_min: float = 0.25, base_jitter_max: float = 0.75):
        self.base_jitter_min = base_jitter_min
        self.base_jitter_max = base_jitter_max
        self.current_jitter_min = base_jitter_min
        self.current_jitter_max = base_jitter_max
        self.response_times = []
        self.max_history = 10
        self.latency_spike_threshold = 2.0  # 200% increase
        
    def record_response_time(self, response_time: float):
        """Record a response time and adjust pacing if needed."""
        self.response_times.append(response_time)
        if len(self.response_times) > self.max_history:
            self.response_times.pop(0)
        
        # Calculate average response time
        if len(self.response_times) >= 3:
            avg_time = sum(self.response_times) / len(self.response_times)
            
            # Check for latency spike (latest response > 200% of average)
            if response_time > (avg_time * self.latency_spike_threshold):
                self._increase_pacing()
            elif response_time < (avg_time * 0.5) and len(self.response_times) >= 5:
                # Gradually reduce pacing if responses are consistently fast
                self._decrease_pacing()
    
    def _increase_pacing(self):
        """Increase jitter to mimic slower network connection."""
        multiplier = 1.5
        self.current_jitter_min = min(self.current_jitter_min * multiplier, 2.0)
        self.current_jitter_max = min(self.current_jitter_max * multiplier, 5.0)
    
    def _decrease_pacing(self):
        """Gradually decrease pacing back towards baseline."""
        self.current_jitter_min = max(self.current_jitter_min * 0.9, self.base_jitter_min)
        self.current_jitter_max = max(self.current_jitter_max * 0.9, self.base_jitter_max)
    
    def get_current_jitter(self) -> tuple:
        """Get current jitter range."""
        return (self.current_jitter_min, self.current_jitter_max)
    
    def get_pacing_status(self) -> Dict[str, Any]:
        """Get current pacing status for monitoring."""
        avg_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        return {
            "current_jitter_min": self.current_jitter_min,
            "current_jitter_max": self.current_jitter_max,
            "avg_response_time": avg_time,
            "response_count": len(self.response_times),
            "pacing_multiplier": self.current_jitter_max / self.base_jitter_max
        }

PROBE_TARGETS = [
    {
        "path": "/.git/HEAD",
        "title": "Exposed Git Repository Metadata (/.git/HEAD)",
        "severity": "CRITICAL",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and "ref: refs/" in resp.text,
        "description": "The root .git directory is accessible over HTTP. Attackers can download the entire source code repository history.",
        "remediation": "Block access to .git and all hidden directories at the web server/reverse proxy level."
    },
    {
        "path": "/.env",
        "title": "Exposed Environment Configuration File (/.env)",
        "severity": "CRITICAL",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and any(k in resp.text for k in ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "AWS_"]),
        "description": "Environment variables file (.env) is directly accessible, exposing sensitive API keys, database credentials, and secrets.",
        "remediation": "Deny HTTP requests to dotfiles and move .env files outside of the public web root directory."
    },
    {
        "path": "/openapi.json",
        "title": "Exposed OpenAPI Specification (/openapi.json)",
        "severity": "LOW",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and any(k in resp.text.lower() for k in ['"openapi":', '"swagger":', '"paths":']),
        "description": "OpenAPI/Swagger schema is publicly accessible, revealing internal API endpoints, parameters, and schemas.",
        "remediation": "Restrict API documentation to authenticated developers or internal environments if internal endpoints are exposed."
    },
    {
        "path": "/swagger.json",
        "title": "Exposed Swagger Specification (/swagger.json)",
        "severity": "LOW",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and any(k in resp.text.lower() for k in ['"swagger":', '"paths":']),
        "description": "Swagger 2.0 API schema is publicly accessible, facilitating automated API surface enumeration.",
        "remediation": "Disable public Swagger documentation in production deployments."
    },
    {
        "path": "/actuator/env",
        "title": "Exposed Spring Boot Actuator Environment (/actuator/env)",
        "severity": "CRITICAL",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and ("activeProfiles" in resp.text or "propertySources" in resp.text),
        "description": "Spring Boot /actuator/env is publicly exposed, leaking environment variables and runtime configuration.",
        "remediation": "Secure Actuator endpoints using Spring Security and set 'management.endpoints.web.exposure.include=health,info'."
    },
    {
        "path": "/actuator/health",
        "title": "Exposed Spring Boot Actuator Health (/actuator/health)",
        "severity": "INFO",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and '"status"' in resp.text,
        "description": "Actuator health status endpoint is publicly accessible.",
        "remediation": "Ensure health endpoints only expose high-level UP/DOWN status without internal component diagnostics."
    },
    {
        "path": "/phpinfo.php",
        "title": "Exposed PHP Information Diagnostics (/phpinfo.php)",
        "severity": "HIGH",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and "PHP Version" in resp.text and "Configuration File (php.ini)" in resp.text,
        "description": "PHP Diagnostic page is active, exposing PHP compilation flags, server environment variables, and module configs.",
        "remediation": "Delete phpinfo.php immediately from production servers."
    },
    {
        "path": "/server-status",
        "title": "Exposed Apache Server Status (/server-status)",
        "severity": "MEDIUM",
        "category": "API_EXPOSURE",
        "check": lambda resp: resp.status_code == 200 and "Apache Server Status" in resp.text,
        "description": "Apache mod_status page is exposed, disclosing active client IPs, requested URLs, and server CPU loads.",
        "remediation": "Restrict /server-status access to localhost (Require local) or disable mod_status."
    }
]

WAF_SIGNATURE_HEADERS = [
    "cf-ray", "cf-mitigated", "x-amzn-waf-action", "x-amzn-errortype",
    "x-sucuri-id", "x-imperva-id", "x-denied-reason"
]

# Hard 403/block page phrases plus Akamai edge error pages.
WAF_BLOCK_BODY_MARKERS = (
    "attention required! | cloudflare",
    "access denied",
    "waf block",
    "request blocked",
    "errors.edgesuite.net",
    "you don't have permission to access",
    "reference #",
)

# Akamai Bot Manager crypto/behavioral challenges often return HTTP 200/202
# with sensor JS rather than a hard 403/429.
AKAMAI_SOFT_CHALLENGE_MARKERS = (
    "bmak.sensor_data",
    "bmak.get_telemetry",
    "bmak.startobserving",
    "chlgeid",
    "/_sec/cp_challenge",
    "sec-if-cpt",
    "sec-cpt",
    "akamai bot manager",
)

CF_SOFT_CHALLENGE_MARKERS = (
    "checking your browser before accessing",
    "cf-browser-verification",
    "challenge-platform",
    "_cf_chl_opt",
)

SOFT_CHALLENGE_STATUSES = (200, 202, 401, 403, 405, 429, 503)


def _response_body_preview(resp: httpx.Response, limit: int = 8192) -> str:
    """Decode a bounded prefix so challenge detection does not slurp large assets."""
    try:
        raw = resp.content[:limit]
        encoding = resp.encoding or "utf-8"
        return raw.decode(encoding, errors="ignore").lower()
    except Exception:
        return ""


def is_waf_block(resp: httpx.Response) -> bool:
    """Detect WAF blocks, rate-limits, and vendor soft/crypto challenges (Akamai BM, CF)."""
    status = resp.status_code
    server = resp.headers.get("server", "").lower()
    location = resp.headers.get("location", "").lower()
    cf_mitigated = resp.headers.get("cf-mitigated", "").lower()

    if status in (429, 503):
        return True

    # Redirect into an explicit challenge endpoint.
    if "/_sec/cp_challenge" in location or "challenges.cloudflare.com" in location:
        return True

    # Cloudflare managed/JS challenge header can appear on 200 as well as 403.
    if cf_mitigated in ("challenge", "managed"):
        return True

    if status == 403:
        if any(w in server for w in ["cloudflare", "akamai", "akamaighost", "imperva", "sucuri", "incapsula"]):
            return True
        for h in WAF_SIGNATURE_HEADERS:
            if h in resp.headers:
                return True
        body_lower = _response_body_preview(resp)
        if any(phrase in body_lower for phrase in WAF_BLOCK_BODY_MARKERS):
            return True

    # Soft behavioral / PoW challenges: typically 200 HTML with sensor collectors.
    # Do not treat a generic AkamaiGHost 200 as a block — that is normal CDN traffic.
    if status in SOFT_CHALLENGE_STATUSES:
        body_lower = _response_body_preview(resp)
        if any(marker in body_lower for marker in AKAMAI_SOFT_CHALLENGE_MARKERS):
            return True
        if any(marker in body_lower for marker in CF_SOFT_CHALLENGE_MARKERS):
            return True

    return False


class ApiRouteAuditor:
    """Probes for exposed API schemas, administrative dashboards, and dangerous debug files."""

    @staticmethod
    async def audit_api_surface(
        base_url: str,
        custom_headers: Dict[str, str] = None,
        concurrency: int = settings.PROBE_CONCURRENCY_LIMIT,
        jitter_min: float = settings.PROBE_JITTER_MIN,
        jitter_max: float = settings.PROBE_JITTER_MAX,
        enable_dynamic_pacing: bool = True,
        discovered_endpoints: List[str] = None
    ) -> List[Dict[str, Any]]:
        findings = []
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = settings.get_stealth_headers()
        if custom_headers:
            headers.update(custom_headers)

        sem = asyncio.Semaphore(concurrency)
        waf_detected = False
        
        # Initialize dynamic pacing controller
        pacing_controller = DynamicPacingController(jitter_min, jitter_max) if enable_dynamic_pacing else None

        async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True, timeout=8.0) as client:
            async def _paced_probe(target: Dict[str, Any], url: str) -> Any:
                nonlocal waf_detected
                if waf_detected:
                    return None
                async with sem:
                    # Use dynamic pacing if enabled, otherwise use static jitter
                    if pacing_controller:
                        current_min, current_max = pacing_controller.get_current_jitter()
                        await asyncio.sleep(random.uniform(current_min, current_max))
                    else:
                        await asyncio.sleep(random.uniform(jitter_min, jitter_max))
                    
                    if waf_detected:
                        return None
                    try:
                        start_time = time.time()
                        resp = await client.get(url)
                        response_time = time.time() - start_time
                        
                        # Record response time for dynamic pacing
                        if pacing_controller:
                            pacing_controller.record_response_time(response_time)
                        
                        if is_waf_block(resp):
                            waf_detected = True
                            return {
                                "severity": "LOW",
                                "category": "API_EXPOSURE",
                                "title": "WAF / Rate-Limiter Circuit Breaker Engaged",
                                "description": f"Target returned WAF block/rate-limiting signals (HTTP {resp.status_code}). Active probing was gracefully throttled to prevent triggering client SOC incident escalations.",
                                "endpoint": url,
                                "evidence": f"WAF response signature detected on GET {url} -> Status {resp.status_code}",
                                "confidence": 1.0,
                                "remediation": "Verify test IP is whitelisted on client WAF/perimeter controls."
                            }
                        if target["check"](resp):
                            return {
                                "severity": target["severity"],
                                "category": target["category"],
                                "title": target["title"],
                                "description": target["description"],
                                "endpoint": url,
                                "evidence": f"GET {url} -> Status {resp.status_code} ({len(resp.content)} bytes). Snippet: {resp.text[:100].strip()}",
                                "confidence": 0.95,
                                "remediation": target["remediation"]
                            }
                    except Exception:
                        pass
                    return None

            # 1. Run standard sensitive endpoint probes with pacing & concurrency bounds
            tasks = []
            for target in PROBE_TARGETS:
                target_url = urllib.parse.urljoin(origin, target["path"])
                tasks.append(_paced_probe(target, target_url))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, dict):
                    findings.append(res)

            # 2. Check GraphQL Introspection (if WAF circuit breaker has not tripped)
            if not waf_detected:
                # Standard GraphQL endpoints
                graphql_urls = [
                    urllib.parse.urljoin(origin, "/graphql"),
                    urllib.parse.urljoin(origin, "/api/graphql")
                ]
                
                # Add discovered GraphQL endpoints from spidering
                if discovered_endpoints:
                    discovered_graphql_endpoints = [
                        urllib.parse.urljoin(origin, ep) for ep in discovered_endpoints
                        if "graphql" in ep.lower()
                    ]
                    graphql_urls.extend(discovered_graphql_endpoints)
                
                for g_url in graphql_urls:
                    try:
                        # Use dynamic pacing for GraphQL probes as well
                        if pacing_controller:
                            current_min, current_max = pacing_controller.get_current_jitter()
                            await asyncio.sleep(random.uniform(current_min, current_max))
                        else:
                            await asyncio.sleep(random.uniform(jitter_min, jitter_max))
                        
                        start_time = time.time()
                        intro_query = {"query": "{ __schema { queryType { name } } }"}
                        resp = await client.post(g_url, json=intro_query)
                        response_time = time.time() - start_time
                        
                        # Record response time for dynamic pacing
                        if pacing_controller:
                            pacing_controller.record_response_time(response_time)
                        
                        if is_waf_block(resp):
                            findings.append({
                                "severity": "LOW",
                                "category": "API_EXPOSURE",
                                "title": "WAF Rate-Limiter Detected on GraphQL",
                                "description": "Target WAF triggered on GraphQL probe. Circuit breaker aborted remaining queries.",
                                "endpoint": g_url,
                                "evidence": f"POST {g_url} -> Status {resp.status_code}",
                                "confidence": 1.0,
                                "remediation": "Check GraphQL gateway rate limits."
                            })
                            break
                        if resp.status_code == 200 and "__schema" in resp.text:
                            findings.append({
                                "severity": "MEDIUM",
                                "category": "API_EXPOSURE",
                                "title": "GraphQL Introspection Enabled",
                                "description": f"GraphQL endpoint at {g_url} allows introspection queries, allowing full reconstruction of the GraphQL schema, queries, and mutations.",
                                "endpoint": g_url,
                                "evidence": f"POST {g_url} -> 200 OK with schema definition snippet: {resp.text[:120]}",
                                "confidence": 1.0,
                                "remediation": "Disable GraphQL introspection in production environments."
                            })
                            break
                    except Exception:
                        pass

        # Add pacing status to findings if dynamic pacing was used
        if pacing_controller and enable_dynamic_pacing:
            pacing_status = pacing_controller.get_pacing_status()
            if pacing_status["pacing_multiplier"] > 1.2:  # Only log if pacing was significantly increased
                findings.append({
                    "severity": "INFO",
                    "category": "API_EXPOSURE",
                    "title": "Dynamic Pacing Status",
                    "description": f"Scanner automatically adjusted pacing based on server response times. Average response time: {pacing_status['avg_response_time']:.3f}s, Pacing multiplier: {pacing_status['pacing_multiplier']:.2f}x",
                    "endpoint": base_url,
                    "evidence": f"Jitter range: {pacing_status['current_jitter_min']:.2f}s - {pacing_status['current_jitter_max']:.2f}s",
                    "confidence": 1.0,
                    "remediation": "No action required - this is automatic WAF evasion behavior."
                })

        return findings

    @staticmethod
    async def verify_discovered_routes(
        discovered_endpoints: List[str],
        base_url: str,
        headers: Dict[str, str],
        enable_dynamic_pacing: bool = True
    ) -> List[Dict[str, Any]]:
        """Automatically verify high-value discovered routes for actual vulnerability."""
        findings = []
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        
        pacing_controller = DynamicPacingController(0.25, 0.75) if enable_dynamic_pacing else None
        
        # Focus on high-value routes
        high_value_patterns = ["graphql", "universal-login", "login", "auth", "api", "admin", "token", "secret"]
        high_value_endpoints = [
            ep for ep in discovered_endpoints 
            if any(pattern in ep.lower() for pattern in high_value_patterns)
        ]
        
        if not high_value_endpoints:
            return findings
        
        seen_verified = set()

        async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True, timeout=8.0) as client:
            for endpoint in high_value_endpoints:
                # Normalize endpoint path (handling crawler prefixes like */graphql or relative routes)
                clean = endpoint.strip()
                if clean.startswith("*/"):
                    clean = clean[1:]
                elif clean.startswith("*"):
                    clean = clean.lstrip("*")
                
                if clean.startswith("http://") or clean.startswith("https://"):
                    verify_url = clean
                else:
                    if not clean.startswith("/"):
                        clean = "/" + clean
                    verify_url = urllib.parse.urljoin(origin, clean)

                if verify_url in seen_verified:
                    continue
                seen_verified.add(verify_url)

                try:
                    # Apply dynamic pacing
                    if pacing_controller:
                        current_min, current_max = pacing_controller.get_current_jitter()
                        await asyncio.sleep(random.uniform(current_min, current_max))
                    else:
                        await asyncio.sleep(random.uniform(0.25, 0.75))
                    
                    start_time = time.time()
                    
                    # 1. GraphQL-specific verification
                    if "graphql" in endpoint.lower():
                        intro_query = {"query": "{ __schema { queryType { name } mutationType { name } types { name } } }"}
                        resp = await client.post(verify_url, json=intro_query)
                        response_time = time.time() - start_time
                        
                        if pacing_controller:
                            pacing_controller.record_response_time(response_time)
                        
                        is_blocked = is_waf_block(resp) or resp.status_code in [401, 403] or "akamai" in resp.text.lower()
                        has_schema = resp.status_code == 200 and "__schema" in resp.text and any(k in resp.text.lower() for k in ["types", "querytype", "mutationtype"])

                        if has_schema and not is_blocked:
                            schema_dump_curl = f'curl -s -X POST "{verify_url}" -H "Content-Type: application/json" -d \'{{"query": "query IntrospectionQuery{{__schema{{queryType{{name}}mutationType{{name}}subscriptionType{{name}}types{{name kind description}}}}}}}}\' | jq .'
                            findings.append({
                                "severity": "HIGH",
                                "category": "API_EXPOSURE",
                                "rule_id": "BR-API-GRAPHQL-INTROSPECTION",
                                "title": "GraphQL Introspection Enabled",
                                "description": f"GraphQL endpoint at {verify_url} allows introspection queries, enabling full schema reconstruction (types and mutations exposed).",
                                "endpoint": verify_url,
                                "evidence": f"POST {verify_url} -> HTTP 200 OK with active GraphQL __schema definitions ({resp.text[:120].strip()}).",
                                "confidence": 1.0,
                                "remediation": "Disable GraphQL introspection in production environments (e.g., set introspection: false in production GraphQL server configuration).",
                                "curl_command": schema_dump_curl,
                                "tags": ["actionable", "graphql"]
                            })
                        elif is_blocked:
                            findings.append({
                                "severity": "INFO",
                                "category": "API_EXPOSURE",
                                "rule_id": "BR-API-GRAPHQL-HARDENED",
                                "title": f"Hardened GraphQL Endpoint ({verify_url})",
                                "description": f"GraphQL endpoint requires authentication or is protected by edge WAF/bot controls (HTTP {resp.status_code}). Introspection is not anonymously accessible.",
                                "endpoint": verify_url,
                                "evidence": f"POST {verify_url} -> HTTP {resp.status_code} (Protected / Access Denied)",
                                "confidence": 1.0,
                                "remediation": "No action required - endpoint is properly secured against anonymous introspection.",
                                "curl_command": f'curl -s -X POST "{verify_url}" -H "Content-Type: application/json" -d \'{{"query": "{{ __schema {{ queryType {{ name }} }} }}"}}\'',
                                "tags": ["hardened_endpoint", "vendor_blocked" if is_waf_block(resp) else "auth_required"]
                            })
                    
                    # 2. Login/auth/universal-login endpoint verification
                    elif any(pattern in endpoint.lower() for pattern in ["universal-login", "login", "auth", "token"]):
                        resp = await client.get(verify_url)
                        response_time = time.time() - start_time
                        
                        if pacing_controller:
                            pacing_controller.record_response_time(response_time)
                        
                        if is_waf_block(resp) or resp.status_code in [401, 403]:
                            findings.append({
                                "severity": "INFO",
                                "category": "API_EXPOSURE",
                                "rule_id": "BR-API-LOGIN-HARDENED",
                                "title": f"Hardened Auth Endpoint ({clean})",
                                "description": f"Authentication endpoint is protected by perimeter controls or requires authorization (HTTP {resp.status_code}).",
                                "endpoint": verify_url,
                                "evidence": f"GET {verify_url} -> HTTP {resp.status_code}",
                                "confidence": 1.0,
                                "remediation": "No action required - endpoint is properly secured.",
                                "tags": ["hardened_endpoint"]
                            })
                        elif resp.status_code == 200:
                            body_lower = resp.text.lower()
                            if any(k in body_lower for k in ["password", "username", "login", "sign in", "auth"]):
                                findings.append({
                                    "severity": "LOW",
                                    "category": "API_EXPOSURE",
                                    "rule_id": "BR-API-LOGIN",
                                    "title": f"Accessible Login Endpoint ({clean})",
                                    "description": f"Authentication endpoint {clean} is publicly accessible. Ensure proper brute-force defenses and rate limiting.",
                                    "endpoint": verify_url,
                                    "evidence": f"GET {verify_url} -> HTTP 200 (login/auth interface detected)",
                                    "confidence": 0.85,
                                    "remediation": "Ensure proper rate limiting, CAPTCHA, and monitoring on login endpoints.",
                                    "tags": ["actionable", "auth"]
                                })
                
                except Exception:
                    pass
        
        return findings

