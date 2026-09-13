import asyncio
from typing import Dict, List, Any
import urllib.parse
import httpx
from app.core.config import settings

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

class ApiRouteAuditor:
    """Probes for exposed API schemas, administrative dashboards, and dangerous debug files."""

    @staticmethod
    async def audit_api_surface(base_url: str, custom_headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
        findings = []
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "User-Agent": settings.USER_AGENT,
            "Accept": "text/html,application/json,*/*"
        }
        if custom_headers:
            headers.update(custom_headers)

        async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True, timeout=8.0) as client:
            # 1. Run standard sensitive endpoint probes concurrently
            tasks = []
            for target in PROBE_TARGETS:
                target_url = urllib.parse.urljoin(origin, target["path"])
                tasks.append(ApiRouteAuditor._probe_single(client, target, target_url))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, dict):
                    findings.append(res)

            # 2. Check GraphQL Introspection
            graphql_urls = [
                urllib.parse.urljoin(origin, "/graphql"),
                urllib.parse.urljoin(origin, "/api/graphql")
            ]
            for g_url in graphql_urls:
                try:
                    intro_query = {"query": "{ __schema { queryType { name } } }"}
                    resp = await client.post(g_url, json=intro_query)
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

        return findings

    @staticmethod
    async def _probe_single(client: httpx.AsyncClient, target: Dict[str, Any], url: str) -> Any:
        try:
            resp = await client.get(url)
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
