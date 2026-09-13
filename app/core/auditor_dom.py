import re
from typing import Dict, List, Any

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
        r'window\.name'
    ]

    @staticmethod
    def audit_javascript(url: str, js_code: str) -> List[Dict[str, Any]]:
        findings = []
        if not js_code or len(js_code) < 20:
            return findings

        # 1. Unvalidated postMessage Listeners
        # Look for window.addEventListener('message', function(e) { ... }) without .origin validation
        postmessage_pattern = re.compile(r'(?:window\.)?addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*(?:function\s*\(([a-zA-Z0-9_$]+)\)|(?:\(([a-zA-Z0-9_$]+)\)|([a-zA-Z0-9_$]+))\s*=>)\s*\{([^}]{1,600})\}', re.DOTALL)
        for match in postmessage_pattern.finditer(js_code):
            param = match.group(1) or match.group(2) or match.group(3) or "e"
            body = match.group(4)
            # Check if event.origin or e.origin is referenced in the listener body
            origin_check = re.search(rf'{re.escape(param)}\.origin', body)
            if not origin_check:
                snippet = match.group(0)[:150].replace("\n", " ")
                findings.append({
                    "severity": "HIGH",
                    "category": "DOM_XSS",
                    "title": "Unvalidated postMessage Origin Listener",
                    "description": "A 'message' event listener does not verify the origin of incoming messages (`event.origin`), allowing malicious origins to inject cross-window messages.",
                    "endpoint": url,
                    "evidence": f"Listener snippet: {snippet}...",
                    "confidence": 0.9,
                    "remediation": "Validate the incoming event origin against a strict list of allowed domains (e.g. `if (event.origin !== 'https://trusted.com') return;`)."
                })
                break

        # 2. DOM XSS Sink with Source in Proximity
        # Search lines or chunks for dangerous sink + source correlation
        lines = js_code.splitlines()
        for idx, line in enumerate(lines):
            line_str = line.strip()
            if len(line_str) > 500:
                continue

            has_source = any(re.search(src, line_str) for src in DomAuditor.DOM_SOURCES)
            has_sink = any(re.search(sink, line_str) for sink in DomAuditor.DOM_SINKS)

            if has_source and has_sink:
                findings.append({
                    "severity": "HIGH",
                    "category": "DOM_XSS",
                    "title": "DOM-Based XSS Sink & Source Correlation",
                    "description": "User-controlled DOM source (e.g. location.search/hash) is directly fed into an execution sink (innerHTML/eval/document.write) on the same execution line.",
                    "endpoint": url,
                    "evidence": f"Line {idx + 1}: {line_str[:140]}",
                    "confidence": 0.85,
                    "remediation": "Sanitize user inputs using DOMPurify or replace innerHTML with textContent/innerText."
                })
                if len(findings) >= 3:
                    break

        return findings
