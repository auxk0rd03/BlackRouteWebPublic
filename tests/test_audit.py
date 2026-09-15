import unittest
import os
import httpx
from app.core.auditor_headers import HeaderAuditor
from app.core.auditor_secrets import SecretAuditor, calculate_shannon_entropy
from app.core.auditor_dom import DomAuditor
from app.core.security import validate_target_url, normalize_target_url
from app.core.engine_bridge import run_spider_extractor, run_surface_graph, _extract_json_payload
from app.core.scanner import generate_curl_poc
from Sources.Utilities.vids_pdf_gen import generate_web_report

class TestBlackRouteWebAudit(unittest.TestCase):

    def test_url_normalization(self):
        self.assertEqual(normalize_target_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_target_url("http://app.test:8080/api"), "http://app.test:8080/api")

    def test_ssrf_blocking(self):
        with self.assertRaises(ValueError):
            validate_target_url("http://127.0.0.1:8000", allow_local_staging=False)

        valid = validate_target_url("http://127.0.0.1:8000", allow_local_staging=True)
        self.assertTrue(valid.startswith("http://127.0.0.1:8000"))

        with self.assertRaises(ValueError):
            validate_target_url("http://169.254.169.254", allow_local_staging=True)

    def test_header_auditor(self):
        headers = httpx.Headers({
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41 (Ubuntu)"
        })
        findings = HeaderAuditor.audit_response_headers("https://example.com", headers, 200)
        titles = [f["title"] for f in findings]
        self.assertIn("Missing Content-Security-Policy (CSP)", titles)
        self.assertIn("Missing Strict-Transport-Security (HSTS)", titles)
        self.assertIn("Missing Anti-Clickjacking Header (X-Frame-Options / frame-ancestors)", titles)
        self.assertIn("Server Banner Version Disclosure", titles)

    def test_cookie_auditor(self):
        cookie_headers = [
            "sessionid=xyz123; Path=/",
            "auth_token=abc456; Secure; SameSite=None"
        ]
        findings = HeaderAuditor.audit_cookies("https://example.com", cookie_headers)
        titles = [f["title"] for f in findings]
        self.assertTrue(any("Missing 'HttpOnly'" in t for t in titles))
        self.assertTrue(any("Missing 'Secure'" in t for t in titles))

    def test_cors_auditor(self):
        findings = HeaderAuditor.audit_cors(
            "https://example.com/api",
            acao_header="*",
            acac_header="true",
            tested_origin="https://evil.cybernest.labs"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_shannon_entropy_calculation(self):
        # Repetitive strings have near-zero entropy
        low_ent = calculate_shannon_entropy("AKIAAAAAAAAAAAAAAAAA")
        self.assertTrue(low_ent < 1.5, f"Expected low entropy, got {low_ent}")

        # High-randomness cryptographic secrets have high entropy
        high_ent = calculate_shannon_entropy("sk_live_51ABCDEF1234567890abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(high_ent >= 3.5, f"Expected high entropy, got {high_ent}")

    def test_secret_auditor_with_entropy_filter(self):
        # 1. Repetitive dummy key: should be suppressed in normal mode
        dummy_repetitive = 'const key = "AKIAAAAAAAAAAAAAAAAA";'
        findings_suppressed = SecretAuditor.audit_content("https://example.com/app.js", dummy_repetitive, shadow_mode=False)
        self.assertEqual(len(findings_suppressed), 0, "Repetitive mock key should be filtered out by entropy gate")

        # In shadow mode, it should be kept but flagged as low-entropy INFO
        findings_shadow = SecretAuditor.audit_content("https://example.com/app.js", dummy_repetitive, shadow_mode=True)
        self.assertEqual(len(findings_shadow), 1)
        self.assertEqual(findings_shadow[0]["severity"], "INFO")

        # 2. Genuine high-entropy secret
        real_content = """
        const config = {
            aws_key: "AKIAIOSFODNN7EXAMPLE",
            stripe: "sk_live_51ABCDEF1234567890abcdefghijklmnopqrstuvwxyz",
            openai: "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
        };
        """
        findings = SecretAuditor.audit_content("https://example.com/main.js", real_content)
        rule_titles = [f["title"] for f in findings]
        self.assertTrue(any("AWS" in t for t in rule_titles))
        self.assertTrue(any("Stripe" in t for t in rule_titles))
        self.assertTrue(any("OpenAI" in t for t in rule_titles))
        self.assertIn("Entropy:", findings[0]["evidence"])

    def test_curl_poc_generation(self):
        f_cors = {
            "category": "HEADERS",
            "title": "CORS Insecure Origin Reflection",
            "endpoint": "https://api.example.com/data"
        }
        curl_cors = generate_curl_poc(f_cors)
        self.assertIn("curl", curl_cors)
        self.assertIn("Origin: https://origin-verify.api.example.com", curl_cors)
        self.assertNotIn("evil", curl_cors)

        f_secret = {
            "category": "SECRETS",
            "title": "Exposed AWS Access Key ID",
            "endpoint": "https://app.example.com/bundle.js",
            "evidence": "Pattern: AWS_KEY | Token: AKIA****MPLE"
        }
        curl_secret = generate_curl_poc(f_secret)
        self.assertIn("curl", curl_secret)
        self.assertIn("grep", curl_secret)

        f_graphql = {
            "category": "API_EXPOSURE",
            "title": "GraphQL Introspection Enabled",
            "endpoint": "https://app.example.com/graphql"
        }
        curl_graphql = generate_curl_poc(f_graphql)
        self.assertIn("__schema", curl_graphql)

    def test_stealth_headers_and_client_hints(self):
        from app.core.config import settings
        headers = settings.get_stealth_headers(engagement_id="CN-AUDIT-2026-X")
        self.assertIn("Mozilla/5.0", headers["User-Agent"])
        self.assertIn("Chrome/124", headers["User-Agent"])
        self.assertIn("Sec-Ch-Ua", headers)
        self.assertIn("Sec-Fetch-Dest", headers)
        self.assertEqual(headers.get("X-Security-Engagement"), "CN-AUDIT-2026-X")
        self.assertEqual(headers.get("X-Authorized-Audit"), "true")

    def test_waf_block_detection(self):
        from app.core.auditor_api_routes import is_waf_block
        # 429 Rate limited
        r_429 = httpx.Response(429, request=httpx.Request("GET", "https://example.com"))
        self.assertTrue(is_waf_block(r_429))

        # 403 with Cloudflare cf-ray
        r_cf = httpx.Response(403, headers={"cf-ray": "123456", "server": "cloudflare"}, request=httpx.Request("GET", "https://example.com"))
        self.assertTrue(is_waf_block(r_cf))

        # 403 with AWS WAF action
        r_aws = httpx.Response(403, headers={"x-amzn-waf-action": "block"}, request=httpx.Request("GET", "https://example.com"))
        self.assertTrue(is_waf_block(r_aws))

        # Normal 404
        r_404 = httpx.Response(404, request=httpx.Request("GET", "https://example.com"))
        self.assertFalse(is_waf_block(r_404))

        # Normal 200
        r_200 = httpx.Response(200, text="OK", request=httpx.Request("GET", "https://example.com"))
        self.assertFalse(is_waf_block(r_200))

    def test_resilient_json_extraction(self):
        # Direct clean JSON
        clean_json = '{"total_routes": 5, "nodes": ["/a", "/b"]}'
        self.assertEqual(_extract_json_payload(clean_json)["total_routes"], 5)

        # Noisy JSON preceded by compiler warnings or panic traces
        noisy_json = """
        [WARN] Rust runtime initializing...
        [DEBUG] Cache hit on /tmp/sample
        {"total_endpoints": 3, "endpoints": [{"path": "/api"}]}
        [TRACE] Exiting process with code 0
        """
        parsed = _extract_json_payload(noisy_json)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["total_endpoints"], 3)

        # Non-JSON garbage
        self.assertIsNone(_extract_json_payload("Fatal panic at line 42: null pointer"))

    def test_dom_auditor(self):
        dummy_js = """
        window.addEventListener('message', function(event) {
            document.getElementById('display').innerHTML = event.data;
        });
        """
        findings = DomAuditor.audit_javascript("https://example.com/app.js", dummy_js)
        self.assertTrue(any("postMessage" in f["title"] for f in findings))

    def test_engine_bridge_fallbacks(self):
        endpoints = ["/api/v1/users", "/admin/settings", "/login", "https://cdn.example.com/lib.js"]
        headers = {"Server": "Cloudflare", "X-Powered-By": "Express"}
        content = "<html><head><script src='/_next/static/chunks/main.js'></script></head></html>"

        res = run_surface_graph(endpoints, headers, content)
        self.assertIn("total_routes", res)
        self.assertTrue(res["total_routes"] > 0)
        self.assertIn("/admin/settings", res["sensitive_routes"])

    def test_vids_pdf_generation(self):
        dummy_data = {
            "target_url": "https://test-target.cybernest.labs",
            "pages_crawled": 5,
            "endpoints_found": 12,
            "findings": [
                {
                    "severity": "HIGH",
                    "category": "HEADERS",
                    "title": "Missing HSTS",
                    "description": "HSTS not enabled.",
                    "endpoint": "https://test-target.cybernest.labs",
                    "evidence": "No header",
                    "confidence": 1.0,
                    "remediation": "Add header",
                    "curl_command": 'curl -s -I "https://test-target.cybernest.labs"'
                }
            ],
            "technologies": [{"name": "React", "category": "UI", "evidence": "React DOM"}],
            "sensitive_routes": ["/admin"],
            "risk_score": 45
        }
        test_dir = "/tmp/br_test_pdf"
        pdf_file = generate_web_report(dummy_data, output_dir=test_dir)
        full_pdf_path = os.path.join(test_dir, pdf_file)
        self.assertTrue(os.path.exists(full_pdf_path))
        self.assertTrue(os.path.getsize(full_pdf_path) > 500)
        os.remove(full_pdf_path)

if __name__ == "__main__":
    unittest.main()
