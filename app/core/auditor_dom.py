import re
import logging
import uuid
from typing import Dict, List, Any, Optional

try:
    import esprima
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False

logger = logging.getLogger("blackroute_web.auditor_dom")

# Script URLs whose sinks live in vendor-controlled bundles the client cannot patch.
VENDOR_SCRIPT_PATTERNS = {
    "Tealium": re.compile(r"tealium|utag(?:\.sync)?|tags\.tiqcdn\.com", re.IGNORECASE),
    "Google Tag Manager / Analytics": re.compile(
        r"googletagmanager|google-analytics|gtag/js|www\.google-analytics\.com",
        re.IGNORECASE,
    ),
    "Adobe Experience Cloud": re.compile(
        r"adobedtm|omtrdc\.net|demdex\.net|assets\.adobedtm|mbox",
        re.IGNORECASE,
    ),
    "Akamai": re.compile(r"akamai(?:hd|cdn)?|go-mpulse\.net", re.IGNORECASE),
    "Segment": re.compile(r"cdn\.segment\.com|segment\.io", re.IGNORECASE),
    "Hotjar": re.compile(r"static\.hotjar\.com|hotjar", re.IGNORECASE),
    "New Relic": re.compile(r"js-agent\.newrelic|nr-data\.net", re.IGNORECASE),
    "Sentry": re.compile(r"browser\.sentry-cdn|js\.sentry-cdn", re.IGNORECASE),
    "Facebook Pixel": re.compile(r"connect\.facebook\.net", re.IGNORECASE),
    "OneTrust": re.compile(r"cdn\.cookielaw\.org|onetrust", re.IGNORECASE),
}


def _vendor_script_family(url: str) -> Optional[str]:
    if not url:
        return None
    for family, pattern in VENDOR_SCRIPT_PATTERNS.items():
        if pattern.search(url):
            return family
    return None


class DomAuditor:
    """Audits client-side JavaScript for DOM XSS sinks and insecure postMessage listeners."""

    DOM_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'(?:^|[^a-zA-Z0-9_$])eval\s*\(',
        r'setTimeout\s*\(\s*[\'"][^\'"]+[\'"]',
        r'setInterval\s*\(\s*[\'"][^\'"]+[\'"]',
        r'new\s+Function\s*\('
    ]

    DOM_SOURCES = [
        r'location\.search',
        r'location\.hash',
        r'location\.href',
        r'document\.URL',
        r'document\.referrer',
        r'window\.name',
        r'(?:event|e|msg)\.data'
    ]

    # AST-based sink patterns (more accurate than regex)
    AST_SINK_PROPERTIES = {
        'innerHTML',
        'outerHTML', 
        'write',
        'writeln',
        'eval',
        'setTimeout',
        'setInterval',
        'Function'
    }

    # AST-based source patterns
    AST_SOURCE_PROPERTIES = {
        'search',
        'hash',
        'href',
        'URL',
        'referrer',
        'name',
        'data'
    }

    @staticmethod
    def _analyze_with_ast(js_code: str, url: str, vendor_family: Optional[str]) -> List[Dict[str, Any]]:
        """Perform AST-based JavaScript analysis for higher accuracy DOM XSS detection."""
        if not AST_AVAILABLE:
            logger.debug("AST analysis not available - esprima not installed, falling back to regex")
            return []
        
        findings = []
        
        try:
            # Parse JavaScript code into AST
            tree = esprima.parseScript(js_code, {'loc': True, 'range': True})
            
            # Simple AST analysis for direct source-sink correlations
            def analyze_node(node):
                if not isinstance(node, dict):
                    return
                
                # Check for direct source to sink in same statement
                if node.get('type') == 'AssignmentExpression':
                    left = node.get('left')
                    right = node.get('right')
                    
                    if left and right:
                        # Check if left side is a dangerous sink
                        if left.get('type') == 'MemberExpression':
                            prop = left.get('property')
                            if prop:
                                prop_name = prop.get('name') if prop.get('type') == 'Identifier' else prop.get('value')
                                if prop_name in DomAuditor.AST_SINK_PROPERTIES:
                                    # Check if right side contains source
                                    if contains_source(right):
                                        loc = node.get('loc', {})
                                        findings.append(DomAuditor._apply_vendor_context({
                                            "severity": "HIGH",
                                            "category": "DOM_XSS",
                                            "title": "AST-Based XSS: Direct Source to Sink",
                                            "description": f"AST analysis detected direct data flow from user-controlled source to dangerous sink ({prop_name}).",
                                            "endpoint": url,
                                            "evidence": f"Line {loc.get('start', {}).get('line', '?')}: direct assignment to {prop_name}",
                                            "confidence": 0.95,
                                            "remediation": "Implement proper input sanitization and context-aware encoding. Use DOMPurify for HTML sanitization.",
                                            "search_hint": prop_name
                                        }, vendor_family))
                
                # Check for dangerous function calls
                if node.get('type') == 'CallExpression':
                    callee = node.get('callee')
                    args = node.get('arguments', [])
                    
                    if callee and callee.get('type') == 'Identifier':
                        func_name = callee.get('name')
                        if func_name in ['eval', 'setTimeout', 'setInterval'] and args:
                            for arg in args:
                                if contains_source(arg):
                                    loc = node.get('loc', {})
                                    findings.append(DomAuditor._apply_vendor_context({
                                        "severity": "HIGH",
                                        "category": "DOM_XSS",
                                        "title": f"AST-Based XSS: {func_name} with Source",
                                        "description": f"AST analysis detected user-controlled source passed to {func_name}.",
                                        "endpoint": url,
                                        "evidence": f"Line {loc.get('start', {}).get('line', '?')}: {func_name} with tainted argument",
                                        "confidence": 0.95,
                                        "remediation": "Avoid passing user-controlled data to dynamic code execution functions.",
                                        "search_hint": func_name
                                    }, vendor_family))
                
                # Recursively analyze child nodes
                for key, value in node.items():
                    if isinstance(value, dict):
                        analyze_node(value)
                    elif isinstance(value, list):
                        for item in value:
                            analyze_node(item)
            
            def contains_source(node):
                """Check if node contains DOM source references."""
                if not isinstance(node, dict):
                    return False
                
                if node.get('type') == 'MemberExpression':
                    obj = node.get('object')
                    prop = node.get('property')
                    if obj and prop:
                        obj_name = obj.get('name') if obj.get('type') == 'Identifier' else ''
                        prop_name = prop.get('name') if prop.get('type') == 'Identifier' else prop.get('value')
                        if obj_name in ['location', 'document', 'window'] and prop_name in DomAuditor.AST_SOURCE_PROPERTIES:
                            return True
                
                # Check recursively
                for key, value in node.items():
                    if isinstance(value, dict) and contains_source(value):
                        return True
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and contains_source(item):
                                return True
                return False
            
            analyze_node(tree)
            
        except Exception as e:
            logger.debug(f"AST parsing failed: {e}, falling back to regex analysis")
            return []
        
        return findings

    @staticmethod
    def _apply_vendor_context(finding: Dict[str, Any], vendor_family: Optional[str]) -> Dict[str, Any]:
        if not vendor_family:
            finding["tags"] = ["first_party"]
            return finding

        finding["severity"] = "INFO"
        finding["confidence"] = min(float(finding.get("confidence", 1.0)), 0.8)
        finding["tags"] = ["third_party", "vendor_script", vendor_family]
        finding["vendor_context"] = vendor_family
        finding["title"] = f"[Third-Party] {finding.get('title', 'DOM Finding')}"
        finding["description"] = (
            f"{finding.get('description', '')} Detected in vendor-controlled script "
            f"({vendor_family}); the application owner cannot directly patch this JavaScript file."
        )
        finding["remediation"] = (
            f"Treat as vendor residual risk ({vendor_family}). Constrain the script with CSP, "
            "sandbox third-party frames where possible, and request a patched build from the vendor "
            "rather than modifying the minified bundle."
        )
        return finding

    @staticmethod
    def build_postmessage_poc(target_url: str, script_url: str, body: str = "") -> Dict[str, str]:
        """
        Build an offline HTML PoC template harness demonstrating unvalidated postMessage acceptance.
        Extracts potential target window sink expectations and formats reproducible payload.
        """
        if "json.parse" in body.lower():
            payload_str = 'JSON.stringify({"type": "ping", "action": "audit_probe", "data": "probe_payload"})'
        elif "data.type" in body or "e.data.action" in body or "data.action" in body:
            payload_str = '{"type": "audit_probe", "action": "verify_origin", "source": "blackroute_web"}'
        elif "eval(" in body or "innerhtml" in body.lower() or "document.write" in body.lower():
            payload_str = '{"action": "test", "payload": "<img src=x onerror=console.log(1)>"}'
        else:
            payload_str = '{"type": "ping", "data": "test_message"}'

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>postMessage Origin Validation PoC Harness</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; background: #0d1117; color: #c9d1d9; }}
        .harness-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 16px; }}
        .harness-title {{ color: #58a6ff; margin: 0 0 8px 0; font-size: 1.1em; }}
        .harness-meta {{ font-size: 0.85em; color: #8b949e; margin: 4px 0; }}
        iframe {{ width: 100%; height: 500px; border: 1px solid #30363d; border-radius: 6px; background: #ffffff; }}
    </style>
</head>
<body>
    <div class="harness-card">
        <h3 class="harness-title">postMessage Origin Validation Reproduction Harness</h3>
        <p class="harness-meta"><strong>Target:</strong> {target_url}</p>
        <p class="harness-meta"><strong>Audited Script:</strong> {script_url}</p>
        <p class="harness-meta"><strong>Harness Action:</strong> Dispatches cross-window message with wildcard origin ('*'). If the target fails to validate event.origin, the message is processed.</p>
    </div>
    <iframe id="target" src="{target_url}"></iframe>
    <script>
      window.onload = () => {{
        const payload = {payload_str};
        const targetFrame = document.getElementById('target');
        if (targetFrame && targetFrame.contentWindow) {{
          targetFrame.contentWindow.postMessage(payload, '*');
          console.log('[BlackRoute-Web PoC] Dispatched test postMessage to target:', payload);
        }}
      }};
    </script>
</body>
</html>"""
        return {
            "html_poc_content": html_template,
            "poc_payload": payload_str
        }

    @staticmethod
    def audit_javascript(url: str, js_code: str, target_url: Optional[str] = None) -> List[Dict[str, Any]]:
        findings = []
        if not js_code or len(js_code) < 20:
            return findings

        vendor_family = _vendor_script_family(url)

        # 1. AST-based analysis (primary method for higher accuracy)
        if AST_AVAILABLE:
            logger.debug(f"Using AST-based analysis for {url}")
            ast_findings = DomAuditor._analyze_with_ast(js_code, url, vendor_family)
            findings.extend(ast_findings)
            
            # If AST found significant findings, return early
            if ast_findings:
                return findings

        # 2. Fallback to regex-based analysis (original method)
        logger.debug(f"Using regex-based analysis for {url}")
        
        # Unvalidated postMessage Listeners
        # Look for window.addEventListener('message', function(e) { ... }) without .origin validation
        postmessage_pattern = re.compile(r'(?:window\.)?addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*(?:function\s*\(([a-zA-Z0-9_$]+)\)|(?:\(([a-zA-Z0-9_$]+)\)|([a-zA-Z0-9_$]+))\s*=>)\s*\{([^}]{1,600})\}', re.DOTALL)
        for match in postmessage_pattern.finditer(js_code):
            param = match.group(1) or match.group(2) or match.group(3) or "e"
            body = match.group(4)
            # Check if event.origin or e.origin is referenced in the listener body
            origin_check = re.search(rf'{re.escape(param)}\.origin', body)
            if not origin_check:
                snippet = match.group(0)[:150].replace("\n", " ")
                poc_info = DomAuditor.build_postmessage_poc(target_url or url, url, body)
                poc_filename = f"poc_postmessage_{uuid.uuid4().hex[:8]}.html"
                findings.append(DomAuditor._apply_vendor_context({
                    "severity": "HIGH",
                    "category": "DOM_XSS",
                    "title": "Unvalidated postMessage Origin Listener",
                    "description": "A 'message' event listener does not verify the origin of incoming messages (`event.origin`), allowing malicious origins to inject cross-window messages.",
                    "endpoint": url,
                    "evidence": f"Listener snippet: {snippet}...",
                    "confidence": 0.9,
                    "remediation": "Validate the incoming event origin against a strict list of allowed domains (e.g. `if (event.origin !== 'https://trusted.com') return;`).",
                    "search_hint": "addEventListener('message'",
                    "html_poc_content": poc_info["html_poc_content"],
                    "html_poc": poc_filename,
                    "poc_payload": poc_info["poc_payload"]
                }, vendor_family))
                break

        # DOM XSS Sink with Source in Proximity
        # Search lines or chunks for dangerous sink + source correlation
        lines = js_code.splitlines()
        for idx, line in enumerate(lines):
            line_str = line.strip()
            if len(line_str) > 500:
                continue

            has_source = any(re.search(src, line_str) for src in DomAuditor.DOM_SOURCES)
            has_sink = any(re.search(sink, line_str) for sink in DomAuditor.DOM_SINKS)

            if has_source and has_sink:
                findings.append(DomAuditor._apply_vendor_context({
                    "severity": "HIGH",
                    "category": "DOM_XSS",
                    "title": "DOM-Based XSS Sink & Source Correlation",
                    "description": "User-controlled DOM source (e.g. location.search/hash, event.data) is directly fed into an execution sink (innerHTML/eval/document.write) on the same execution line.",
                    "endpoint": url,
                    "evidence": f"Line {idx + 1}: {line_str[:140]}",
                    "confidence": 0.85,
                    "remediation": "Sanitize user inputs using DOMPurify or replace innerHTML with textContent/innerText.",
                    "search_hint": line_str[:30]
                }, vendor_family))
                if len(findings) >= 3:
                    break

        return findings
