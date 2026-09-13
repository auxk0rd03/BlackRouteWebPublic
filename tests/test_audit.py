import unittest
import os
import httpx
from app.core.auditor_headers import HeaderAuditor
from app.core.auditor_secrets import SecretAuditor
from app.core.auditor_dom import DomAuditor
from app.core.security import validate_target_url, normalize_target_url
from app.core.engine_bridge import run_spider_extractor, run_surface_graph
from Sources.Utilities.vids_pdf_gen import generate_web_report

class TestBlackRouteWebAudit(unittest.TestCase):

    def test_url_normalization(self):
        self.assertEqual(normalize_target_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_target_url("http://app.test:8080/api"), "http://app.test:8080/api")

    def test_ssrf_blocking(self):
        # Loopback should be rejected in public mode
        with self.assertRaises(ValueError):
            validate_target_url("http://127.0.0.1:8000", allow_local_staging=False)

        # Loopback should be allowed when local staging mode is enabled
        valid = validate_target_url("http://127.0.0.1:8000", allow_local_staging=True)
        self.assertTrue(valid.startswith("http://127.0.0.1:8000"))

        # Cloud metadata must be blocked ALWAYS
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

    def test_secret_auditor(self):
        dummy_content = """
        const config = {
            aws_key: "AKIAIOSFODNN7EXAMPLE",
            stripe: "sk_live_51ABCDEF1234567890abcdefghijklmnopqrstuvwxyz",
            openai: "sk-abcdefghijklmnopqrstuvwxyz1234567890"
        };
        """
        findings = SecretAuditor.audit_content("https://example.com/main.js", dummy_content)
        rule_titles = [f["title"] for f in findings]
        self.assertTrue(any("AWS" in t for t in rule_titles))
        self.assertTrue(any("Stripe" in t for t in rule_titles))
        self.assertTrue(any("OpenAI" in t for t in rule_titles))

    def test_dom_auditor(self):
        dummy_js = """
        window.addEventListener('message', function(event) {
            document.getElementById('display').innerHTML = event.data;
        });
        """
        findings = DomAuditor.audit_javascript("https://example.com/app.js", dummy_js)
        self.assertTrue(any("postMessage" in f["title"] for f in findings))

    def test_engine_bridge_fallbacks(self):
        # Test surface graph fallback
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
                    "remediation": "Add header"
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
        # Cleanup
        os.remove(full_pdf_path)

if __name__ == "__main__":
    unittest.main()
