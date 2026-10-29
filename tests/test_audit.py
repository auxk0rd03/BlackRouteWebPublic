import unittest
import os
import httpx
from app.core.auditor_headers import HeaderAuditor
from app.core.auditor_secrets import SecretAuditor, calculate_shannon_entropy
from app.core.auditor_dom import DomAuditor
from app.core.security import validate_target_url, normalize_target_url
from app.core.config import Settings
from app.core.engine_bridge import run_spider_extractor, run_surface_graph, _extract_json_payload, _python_fallback_surface_graph, _is_allowed_domain, _resolve_webpack_chunks_python
from app.core.scanner import generate_curl_poc, deduplicate_findings, generate_html_poc
from app.core.auditor_api_routes import DynamicPacingController
from Sources.Utilities.vids_pdf_gen import generate_web_report

class TestBlackRouteWebAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import tempfile
        from pathlib import Path
        from app.core.config import settings
        from app.core.database import init_db
        cls._tmp_env = tempfile.TemporaryDirectory(prefix="br_test_audit_")
        tmp_root = Path(cls._tmp_env.name)
        cls._orig_db = settings.DB_PATH
        cls._orig_out = settings.OUTPUT_DIR
        cls._orig_static = settings.STATIC_DIR
        settings.DB_PATH = tmp_root / "test_blackroute.db"
        settings.OUTPUT_DIR = tmp_root / "Output"
        settings.STATIC_DIR = tmp_root / "static"
        os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
        os.makedirs(settings.STATIC_DIR, exist_ok=True)
        init_db()

    @classmethod
    def tearDownClass(cls):
        from app.core.config import settings
        settings.DB_PATH = cls._orig_db
        settings.OUTPUT_DIR = cls._orig_out
        settings.STATIC_DIR = cls._orig_static
        cls._tmp_env.cleanup()

    def test_url_normalization(self):
        self.assertEqual(normalize_target_url("example.com"), "https://example.com/")
        self.assertEqual(normalize_target_url("http://app.test:8080/api"), "http://app.test:8080/api")
        # Bracketed and wrapped URLs
        self.assertEqual(normalize_target_url("[http://localhost:3000]"), "http://localhost:3000/")
        self.assertEqual(normalize_target_url("<http://localhost:3000>"), "http://localhost:3000/")
        self.assertEqual(normalize_target_url("(http://localhost:3000)"), "http://localhost:3000/")
        self.assertEqual(normalize_target_url("[127.0.0.1:8000]"), "https://127.0.0.1:8000/")
        self.assertEqual(normalize_target_url("127.0.0.1:[8000]"), "https://127.0.0.1:8000/")
        self.assertEqual(normalize_target_url("[localhost:3000]"), "https://localhost:3000/")
        self.assertEqual(normalize_target_url("http://[127.0.0.1]:8000"), "http://127.0.0.1:8000/")
        # Valid IPv6 literals
        self.assertEqual(normalize_target_url("http://[::1]:8000"), "http://[::1]:8000/")
        self.assertEqual(normalize_target_url("[::1]:8000"), "https://[::1]:8000/")
        self.assertEqual(normalize_target_url("[::1]"), "https://[::1]/")
        self.assertEqual(normalize_target_url("http://[2001:db8::1]:8080/path"), "http://[2001:db8::1]:8080/path")

    def test_ssrf_blocking(self):
        with self.assertRaises(ValueError):
            validate_target_url("http://127.0.0.1:8000", allow_local_staging=False)

        valid = validate_target_url("http://127.0.0.1:8000", allow_local_staging=True)
        self.assertTrue(valid.startswith("http://127.0.0.1:8000"))

        # IPv6 loopback
        with self.assertRaises(ValueError):
            validate_target_url("http://[::1]:8000", allow_local_staging=False)
        valid_ipv6 = validate_target_url("http://[::1]:8000", allow_local_staging=True)
        self.assertTrue(valid_ipv6.startswith("http://[::1]:8000"))

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

        # Cleartext HTTP transmission check
        http_findings = HeaderAuditor.audit_cookies("http://example.com", ["session_id=12345; Path=/"])
        http_titles = [f["title"] for f in http_findings]
        self.assertTrue(any("Transmitted over Insecure HTTP" in t for t in http_titles))

    def test_vendor_waf_cookie_exclusions(self):
        vendor_headers = [
            "_abck=akamai-telemetry; Path=/; Secure",
            "bm_mi=1; Path=/",
            "bm_so=1; Path=/",
            "bm_sz=1; Path=/",
            "mbox=session#abc#1; Path=/",
        ]
        findings = HeaderAuditor.audit_cookies("https://example.com", vendor_headers)
        httponly = [f for f in findings if "HttpOnly" in f["title"]]
        self.assertTrue(httponly)
        for finding in httponly:
            self.assertEqual(finding["severity"], "INFO")
            self.assertIn("vendor_integration", finding.get("tags", []))
        first_party = HeaderAuditor.audit_cookies(
            "https://example.com",
            ["sessionid=xyz123; Path=/"],
        )
        session_http_only = [f for f in first_party if "HttpOnly" in f["title"]]
        self.assertTrue(session_http_only)
        self.assertEqual(session_http_only[0]["severity"], "HIGH")

    def test_akamai_session_vendor_cookie_exclusion(self):
        # Test that akamai_session is now recognized as a vendor cookie
        akamai_headers = [
            "akamai_session=xyz123; Path=/",
            "akamai_edge_token=abc456; Path=/",
        ]
        findings = HeaderAuditor.audit_cookies("https://example.com", akamai_headers)
        httponly = [f for f in findings if "HttpOnly" in f["title"]]
        self.assertTrue(httponly)
        for finding in httponly:
            self.assertEqual(finding["severity"], "INFO")
            self.assertIn("vendor_integration", finding.get("tags", []))
            self.assertIn("Akamai Bot Manager", finding.get("tags", []))

    def test_cors_auditor(self):
        findings = HeaderAuditor.audit_cors(
            "https://example.com/api",
            acao_header="*",
            acac_header="true",
            tested_origin="https://origin-verify.example.com"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("misconfiguration breaks", findings[0]["description"])

    def test_cors_dynamic_origin_reflection(self):
        # Dynamic reflection of randomized benign origin with credentials
        random_origin = "https://probe-d8f9a2.example.com"
        findings = HeaderAuditor.audit_cors(
            "https://example.com/api",
            acao_header=random_origin,
            acac_header="true",
            tested_origin=random_origin
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertIn("Insecure Origin Reflection with Credentials", findings[0]["title"])
        self.assertEqual(findings[0]["tested_origin"], random_origin)

        # Dynamic reflection without credentials -> HIGH severity
        findings_nocred = HeaderAuditor.audit_cors(
            "https://example.com/api",
            acao_header=random_origin,
            acac_header="false",
            tested_origin=random_origin
        )
        self.assertEqual(len(findings_nocred), 1)
        self.assertEqual(findings_nocred[0]["severity"], "HIGH")

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
        self.assertEqual(findings[0]["search_hint"], "AKIAIOSF")

    def test_curl_poc_generation(self):
        f_cors = {
            "category": "HEADERS",
            "title": "CORS Insecure Origin Reflection",
            "endpoint": "https://api.example.com/data"
        }
        curl_cors = generate_curl_poc(f_cors)
        self.assertIn("curl", curl_cors)
        self.assertIn("Origin: https://origin-verify.api.example.com", curl_cors)
        self.assertIn("User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", curl_cors)
        self.assertIn("Sec-Ch-Ua:", curl_cors)
        self.assertIn("Sec-Ch-Ua-Mobile: ?0", curl_cors)
        self.assertIn("Sec-Ch-Ua-Platform:", curl_cors)
        self.assertIn("Accept: text/html,application/xhtml+xml", curl_cors)
        self.assertIn("Accept-Language: en-US,en;q=0.5", curl_cors)
        self.assertNotIn("evil", curl_cors)
        self.assertNotIn("-X GET", curl_cors)

        f_secret = {
            "category": "SECRETS",
            "title": "Exposed AWS Access Key ID",
            "endpoint": "https://app.example.com/bundle.js",
            "evidence": "Pattern: AWS_KEY | Token: AKIA************MPLE",
            "search_hint": "AKIAIOSF"
        }
        curl_secret = generate_curl_poc(f_secret)
        self.assertIn("curl", curl_secret)
        self.assertIn("grep", curl_secret)
        self.assertIn("AKIAIOSF", curl_secret)
        self.assertIn("Sec-Ch-Ua:", curl_secret)
        self.assertNotIn("AKIAMPLE", curl_secret)

        f_graphql = {
            "category": "API_EXPOSURE",
            "title": "GraphQL Introspection Enabled",
            "endpoint": "https://app.example.com/graphql"
        }
        curl_graphql = generate_curl_poc(f_graphql)
        self.assertIn("__schema", curl_graphql)
        self.assertIn("Sec-Ch-Ua:", curl_graphql)

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

        # Generic Akamai CDN 200 is not a block
        r_akamai_ok = httpx.Response(
            200,
            headers={"server": "AkamaiGHost"},
            text="<html><body>Welcome</body></html>",
            request=httpx.Request("GET", "https://example.com"),
        )
        self.assertFalse(is_waf_block(r_akamai_ok))

        # Akamai Bot Manager soft crypto-challenge on HTTP 200
        r_akamai_chlg = httpx.Response(
            200,
            headers={"server": "AkamaiGHost"},
            text="<script>bmak.sensor_data='abc'; var chlgeId=1;</script>",
            request=httpx.Request("GET", "https://example.com"),
        )
        self.assertTrue(is_waf_block(r_akamai_chlg))

        # Redirect into Akamai challenge path
        r_akamai_redir = httpx.Response(
            302,
            headers={"location": "https://example.com/_sec/cp_challenge/widget"},
            request=httpx.Request("GET", "https://example.com"),
        )
        self.assertTrue(is_waf_block(r_akamai_redir))

        # Cloudflare JS challenge header on 200
        r_cf_chlg = httpx.Response(
            200,
            headers={"cf-mitigated": "challenge", "server": "cloudflare"},
            text="OK",
            request=httpx.Request("GET", "https://example.com"),
        )
        self.assertTrue(is_waf_block(r_cf_chlg))

        # Hard Akamai 403
        r_akamai_403 = httpx.Response(
            403,
            headers={"server": "AkamaiGHost"},
            text="Access Denied",
            request=httpx.Request("GET", "https://example.com"),
        )
        self.assertTrue(is_waf_block(r_akamai_403))

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
        titles = [f["title"] for f in findings]
        self.assertTrue(any("postMessage" in t for t in titles))
        self.assertTrue(any("DOM-Based XSS" in t for t in titles))
        self.assertTrue(all(f["severity"] == "HIGH" for f in findings))
        self.assertTrue(all("first_party" in f.get("tags", []) for f in findings))

        vendor_url = "https://tags.tiqcdn.com/utag/brand/profile/prod/utag.sync-5.5.0.js"
        vendor_findings = DomAuditor.audit_javascript(vendor_url, dummy_js)
        self.assertTrue(vendor_findings)
        for finding in vendor_findings:
            self.assertEqual(finding["severity"], "INFO")
            self.assertIn("third_party", finding.get("tags", []))
            self.assertEqual(finding.get("vendor_context"), "Tealium")
            self.assertTrue(finding["title"].startswith("[Third-Party]"))

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

    def test_database_get_scan_by_id_and_update(self):
        from app.core.database import save_scan_record, get_scan_by_id, update_scan_report_file
        scan_id = save_scan_record(
            target_url="https://app.test.local",
            findings=[{"severity": "HIGH", "category": "HEADERS", "title": "Test Finding"}],
            endpoints=[{"url": "https://app.test.local/login"}],
            pages_crawled=2,
            report_file=""
        )
        self.assertIsNotNone(scan_id)
        scan, findings, endpoints = get_scan_by_id(scan_id)
        self.assertEqual(scan["id"], scan_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(endpoints), 1)

        update_scan_report_file(scan_id, "test_report.pdf")
        scan_updated, _, _ = get_scan_by_id(scan_id)
        self.assertEqual(scan_updated["report_file"], "test_report.pdf")

    def test_curl_poc_with_tested_origin(self):
        finding = {
            "severity": "CRITICAL",
            "category": "HEADERS",
            "title": "CORS Insecure Origin Reflection with Credentials",
            "endpoint": "https://api.test.local/v1/user",
            "tested_origin": "https://probe-9988aabb.test.local"
        }
        curl_cmd = generate_curl_poc(finding)
        self.assertIn("https://probe-9988aabb.test.local", curl_cmd)
        self.assertIn("api.test.local/v1/user", curl_cmd)

    def test_findings_deduplication(self):
        # Test that duplicate findings are removed
        duplicate_findings = [
            {
                "severity": "HIGH",
                "category": "COOKIES",
                "title": "Cookie 'akamai_session' Missing 'HttpOnly' Flag",
                "endpoint": "https://example.com",
                "description": "Test",
                "evidence": "Test",
                "confidence": 1.0,
                "remediation": "Test"
            },
            {
                "severity": "HIGH",
                "category": "COOKIES",
                "title": "Cookie 'akamai_session' Missing 'HttpOnly' Flag",
                "endpoint": "https://example.com",
                "description": "Test",
                "evidence": "Test",
                "confidence": 1.0,
                "remediation": "Test"
            },
            {
                "severity": "MEDIUM",
                "category": "HEADERS",
                "title": "Missing CSP",
                "endpoint": "https://example.com",
                "description": "Test",
                "evidence": "Test",
                "confidence": 1.0,
                "remediation": "Test"
            }
        ]
        deduplicated = deduplicate_findings(duplicate_findings)
        self.assertEqual(len(deduplicated), 2)
        titles = [f["title"] for f in deduplicated]
        self.assertEqual(titles.count("Cookie 'akamai_session' Missing 'HttpOnly' Flag"), 1)
        self.assertIn("Missing CSP", titles)

    def test_surface_graph_enterprise_signatures(self):
        endpoints = ["/api/v1/checkout", "/account/login"]
        headers = {
            "Server": "AkamaiGHost",
            "Set-Cookie": "_abck=sig123; Path=/; Secure, mbox=adobe_session; Path=/"
        }
        content = "<html><head><script src='https://tags.tiqcdn.com/utag/utag.js'></script></head><body>Portal</body></html>"

        res = run_surface_graph(endpoints, headers, content)
        self.assertIn("technologies", res)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertTrue(any("Akamai" in n for n in tech_names), f"Expected Akamai in {tech_names}")
        self.assertIn("Adobe Experience Cloud", tech_names)
        self.assertIn("Tealium iQ", tech_names)

        # Check that IPC debug payload was written to disk
        debug_file = os.path.join("/tmp", "surface_graph_payload_debug.json")
        self.assertTrue(os.path.exists(debug_file))

    def test_surface_graph_multi_value_headers(self):
        endpoints = ["/api/v1/orders"]
        # Multi-value headers as lists (as httpx get_list produces)
        headers = {
            "Server": ["AkamaiGHost"],
            "Set-Cookie": [
                "_abck=token1; Path=/",
                "mbox=visitor2; Path=/"
            ]
        }
        content = "<html><body>Order Page</body></html>"
        res = run_surface_graph(endpoints, headers, content)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Akamai Bot Manager", tech_names)
        self.assertIn("Adobe Experience Cloud", tech_names)

    def test_python_fallback_enterprise_signatures(self):
        endpoints = ["/portal"]
        headers = {
            "Server": "AkamaiGHost",
            "Set-Cookie": ["bm_mi=1; Path=/", "amcv=test; Path=/"]
        }
        content = "<html><script src='/vendor/utag.sync.js'></script></html>"
        res = _python_fallback_surface_graph(endpoints, headers, content)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Akamai", tech_names)
        self.assertIn("Akamai Bot Manager", tech_names)
        self.assertIn("Adobe Experience Cloud", tech_names)
        self.assertIn("Tealium iQ", tech_names)

    def test_dynamic_pacing_controller(self):
        pacer = DynamicPacingController(base_jitter_min=0.25, base_jitter_max=0.75)
        # Record baseline latency (e.g. 0.1s)
        for _ in range(5):
            pacer.record_response_time(0.1)
        init_min, init_max = pacer.get_current_jitter()
        self.assertEqual(init_min, 0.25)
        self.assertEqual(init_max, 0.75)

        # Latency spike > 200% of average (e.g. 0.5s vs 0.1s avg)
        pacer.record_response_time(0.5)
        spike_min, spike_max = pacer.get_current_jitter()
        self.assertGreater(spike_min, init_min)
        self.assertGreater(spike_max, init_max)

    def test_html_poc_generation(self):
        # Clickjacking finding
        clickjacking_finding = {
            "category": "HEADERS",
            "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "endpoint": "https://target.corp/login",
            "severity": "MEDIUM"
        }
        cj_poc = generate_html_poc(clickjacking_finding)
        self.assertIsNotNone(cj_poc)
        self.assertIn("<iframe src=\"https://target.corp/login\"", cj_poc)
        self.assertIn("Clickjacking", cj_poc)

        # CORS finding
        cors_finding = {
            "category": "HEADERS",
            "title": "CORS Misconfiguration: Arbitrary Origin Reflection",
            "endpoint": "https://target.corp/api/data",
            "tested_origin": "https://probe-1234.target.corp",
            "severity": "HIGH"
        }
        cors_poc = generate_html_poc(cors_finding)
        self.assertIsNotNone(cors_poc)
        self.assertIn("https://probe-1234.target.corp", cors_poc)
        self.assertIn("fetch(targetUrl", cors_poc)

    def test_spider_route_sanitization_and_js_garbage_discard(self):
        # 1. Test surface_graph engine route filtering
        garbage_endpoints = [
            "/api/v1/valid_route",
            "/; %]/,n=/(^\\d{5}\\$)|(^\\d{5}-\\d{4}\\$)/,o t.test(e),s=r.test(e); return o&&e.length<2||s||le",
            "/function() { return true; }",
            "/var x = 1;",
            "/const foo = 'bar'",
            "/test(e)&&o",
            "/(^\\d{5}$)/",
        ]
        res = run_surface_graph(garbage_endpoints, {}, "")
        nodes = res.get("nodes", [])
        sensitive = res.get("sensitive_routes", [])

        # Only the valid route should survive
        self.assertIn("/api/v1/valid_route", nodes)
        for node in nodes:
            self.assertNotIn("return", node)
            self.assertNotIn("test(", node)
            self.assertNotIn("&&", node)
            self.assertNotIn("||", node)
            self.assertNotIn("\\d{", node)

        for s_route in sensitive:
            self.assertNotIn("return", s_route)
            self.assertNotIn("test(", s_route)

        # 2. Test Rust spider route filtering on sample minified JS content
        import tempfile
        sample_js = """
        const zipRegex = /(^\\d{5}$)|(^\\d{5}-\\d{4}$)/;
        function validate(e) {
            return o && e.length < 2 || s || le;
        }
        const apiPath = "/api/v1/users/list";
        const badPath = "/[a-z]+; return x && y;";
        """
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(sample_js)
            temp_path = f.name

        try:
            spider_res = run_spider_extractor(temp_path)
            extracted_paths = [e["path"] for e in spider_res.get("endpoints", [])]
            self.assertIn("/api/v1/users/list", extracted_paths)
            for path in extracted_paths:
                self.assertNotIn("return", path)
                self.assertNotIn("&&", path)
                self.assertNotIn(";", path)
                self.assertNotIn("\\d{", path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_bracketed_urls_and_api_scan_robustness(self):
        """Verify WebScanner and /api/scan gracefully handle bracketed or malformed target URLs."""
        from fastapi.testclient import TestClient
        from blackroute_web import app
        from app.core.scanner import WebScanner

        # 1. WebScanner initialization should normalize bracketed URLs without ValueError
        scanner1 = WebScanner(target_url="[http://localhost:3000]")
        self.assertEqual(scanner1.target_url, "http://localhost:3000/")

        scanner2 = WebScanner(target_url="[127.0.0.1:8000]")
        self.assertEqual(scanner2.target_url, "https://127.0.0.1:8000/")

        scanner3 = WebScanner(target_url="http://[::1]:8000")
        self.assertEqual(scanner3.target_url, "http://[::1]:8000/")

        # 2. TestClient POST /api/scan with bracketed URL
        client = TestClient(app)
        resp = client.post("/api/scan", data={"target_url": "[http://localhost:3000]"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("[TARGET ENGAGED]", resp.text)

        # 3. TestClient POST /api/scan with malformed URL yields friendly error div instead of 500
        bad_resp = client.post("/api/scan", data={"target_url": "http://["})
        self.assertEqual(bad_resp.status_code, 200)
        self.assertIn("[ERROR] Invalid Target URL:", bad_resp.text)
        self.assertIn("[HALTED]", bad_resp.text)

    def test_sarif_deterministic_rule_ids(self):
        """Verify that SARIF rule IDs are unique, deterministic, and prevent CI/CD collisions."""
        from app.routes.api import _generate_sarif_rule_id

        # 1. CSP Inline & Eval
        csp_inline = {"category": "HEADERS", "title": "Insecure CSP: 'unsafe-inline' Detected"}
        csp_eval = {"category": "HEADERS", "title": "Insecure CSP: 'unsafe-eval' Detected"}
        self.assertEqual(_generate_sarif_rule_id(csp_inline), "BR-CSP-INLINE")
        self.assertEqual(_generate_sarif_rule_id(csp_eval), "BR-CSP-EVAL")

        # 2. Cookie Secure & HttpOnly
        cookie_sec = {"category": "COOKIES", "title": "Cookie 'EdgeLocation' Missing 'Secure' Flag"}
        cookie_http = {"category": "COOKIES", "title": "Cookie 'session_id' Missing 'HttpOnly' Flag"}
        self.assertEqual(_generate_sarif_rule_id(cookie_sec), "BR-COOKIE-SECURE")
        self.assertEqual(_generate_sarif_rule_id(cookie_http), "BR-COOKIE-HTTPONLY")

        # 3. Referrer & GraphQL
        ref = {"category": "HEADERS", "title": "Insecure Referrer-Policy: unsafe-url"}
        gql = {"category": "API_EXPOSURE", "title": "GraphQL Introspection Enabled"}
        gql_hard = {"category": "API_EXPOSURE", "title": "Hardened GraphQL Endpoint (https://test/graphql)"}
        self.assertEqual(_generate_sarif_rule_id(ref), "BR-HEADER-REFERRER")
        self.assertEqual(_generate_sarif_rule_id(gql), "BR-API-GRAPHQL-INTROSPECTION")
        self.assertEqual(_generate_sarif_rule_id(gql_hard), "BR-API-GRAPHQL-HARDENED")

    def test_vids_pdf_bifurcation(self):
        """Verify that VIDS PDF report bifurcates Section A (Actionable) and Section B (Vendor)."""
        import tempfile
        from Sources.Utilities.vids_pdf_gen import generate_web_report, is_vendor_observation

        findings = [
            {
                "severity": "MEDIUM",
                "category": "HEADERS",
                "title": "Insecure CSP: 'unsafe-inline' Detected",
                "endpoint": "https://www.rei.com/",
                "evidence": "unsafe-inline in script-src",
                "confidence": 0.95,
                "remediation": "Remove unsafe-inline",
                "curl_command": "curl -s -I https://www.rei.com/"
            },
            {
                "severity": "MEDIUM",
                "category": "COOKIES",
                "title": "Cookie 'EdgeLocation' Missing 'Secure' Flag",
                "endpoint": "https://www.rei.com/",
                "evidence": "Set-Cookie: EdgeLocation=41.4088,-75.6626",
                "confidence": 1.0,
                "remediation": "Append ; Secure",
                "curl_command": "curl -s -I https://www.rei.com/ | grep -i set-cookie"
            },
            {
                "severity": "INFO",
                "category": "COOKIES",
                "title": "Vendor Cookie '_abck' Missing 'HttpOnly' Flag",
                "endpoint": "https://www.rei.com/",
                "evidence": "Set-Cookie: _abck=xyz",
                "confidence": 0.8,
                "remediation": "Do not set HttpOnly on vendor cookie.",
                "tags": ["vendor_integration", "Akamai Bot Manager"]
            },
            {
                "severity": "INFO",
                "category": "COOKIES",
                "title": "Vendor Cookie 'mbox' Missing 'HttpOnly' Flag",
                "endpoint": "https://www.rei.com/",
                "evidence": "Set-Cookie: mbox=abc",
                "confidence": 0.8,
                "remediation": "Adobe cookie readable by JS.",
                "tags": ["vendor_integration", "Adobe Experience Cloud"]
            }
        ]

        # Verify classification
        self.assertFalse(is_vendor_observation(findings[0]))
        self.assertFalse(is_vendor_observation(findings[1]))
        self.assertTrue(is_vendor_observation(findings[2]))
        self.assertTrue(is_vendor_observation(findings[3]))

        with tempfile.TemporaryDirectory() as tmp_dir:
            report_data = {
                "target_url": "https://www.rei.com/",
                "pages_crawled": 5,
                "endpoints_found": 12,
                "findings": findings,
                "technologies": [{"category": "WAF", "name": "Akamai Bot Manager", "evidence": "Cookie detected"}],
                "sensitive_routes": ["/graphql", "/api/v1/auth"],
                "risk_score": 60
            }
            pdf_filename = generate_web_report(report_data, output_dir=tmp_dir)
            pdf_path = os.path.join(tmp_dir, pdf_filename)
            self.assertTrue(os.path.exists(pdf_path))
            self.assertGreater(os.path.getsize(pdf_path), 1000)

    def test_markdown_triage_export(self):
        """Verify that Markdown triage summary formats properly for HackerOne/Jira handoff."""
        from fastapi.testclient import TestClient
        from blackroute_web import app
        from app.core.database import save_scan_record

        test_findings = [
            {
                "severity": "MEDIUM",
                "category": "HEADERS",
                "title": "Insecure CSP ('unsafe-inline', 'unsafe-eval')",
                "endpoint": "https://www.rei.com/",
                "evidence": "unsafe-inline in script-src",
                "confidence": 0.95,
                "remediation": "Remove unsafe-inline and unsafe-eval directives",
                "curl_command": "curl -s -I https://www.rei.com/"
            },
            {
                "severity": "MEDIUM",
                "category": "COOKIES",
                "title": "Sensitive Coordinate Cookie 'EdgeLocation' Missing Secure Flag",
                "endpoint": "https://www.rei.com/",
                "evidence": "Set-Cookie: EdgeLocation=41.4088,-75.6626",
                "confidence": 1.0,
                "remediation": "Append ; Secure to EdgeLocation Set-Cookie directive",
                "curl_command": "curl -s -I https://www.rei.com/ | grep -i set-cookie"
            },
            {
                "severity": "LOW",
                "category": "HEADERS",
                "title": "Permissive Referrer-Policy",
                "endpoint": "https://www.rei.com/",
                "evidence": "Referrer-Policy absent",
                "confidence": 0.85,
                "remediation": "Set Referrer-Policy to strict-origin-when-cross-origin",
                "curl_command": "curl -s -I https://www.rei.com/"
            },
            {
                "severity": "INFO",
                "category": "COOKIES",
                "title": "Vendor Cookie '_abck' Missing 'HttpOnly' Flag",
                "endpoint": "https://www.rei.com/",
                "evidence": "Set-Cookie: _abck=123",
                "tags": ["vendor_integration", "Akamai Bot Manager"]
            }
        ]

        scan_id = save_scan_record(
            target_url="https://www.rei.com/",
            findings=test_findings,
            endpoints=[{"url": "/graphql", "method": "POST"}],
            pages_crawled=10,
            report_file="",
            risk_score=60
        )

        client = TestClient(app)
        resp = client.get(f"/api/scans/{scan_id}/export/markdown")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/markdown", resp.headers["content-type"])
        
        text = resp.text
        self.assertIn("### Summary", text)
        self.assertIn("- Target: https://www.rei.com/", text)
        self.assertIn("- Risk Score: 60/100", text)
        self.assertIn("- Actionable Vulnerabilities: 2 Medium, 1 Low", text)
        self.assertIn("### Executive Summary & Chained Triage Impact Statement", text)
        self.assertIn("Chained Triage Impact:", text)
        self.assertIn("### Primary Findings", text)
        self.assertIn("Insecure CSP ('unsafe-inline', 'unsafe-eval') - Medium", text)
        self.assertIn("Sensitive Coordinate Cookie 'EdgeLocation' Missing Secure Flag - Medium", text)
        self.assertIn("Permissive Referrer-Policy - Low", text)
        self.assertIn("**CWE Classification**:", text)
        self.assertIn("CWE-693", text)
        self.assertIn("CWE-614", text)
        self.assertIn("**CVSS v3.1 Base Vector**:", text)
        self.assertIn("CVSS:3.1/", text)
        self.assertIn("**Step-by-Step Reproduction Guide**:", text)
        self.assertIn("**Actionable Remediation Guidance**:", text)
        self.assertIn("Sec-Ch-Ua:", text)
        self.assertIn("Accept-Language: en-US,en;q=0.5", text)
        self.assertIn("### Third-Party & Vendor Observations", text)
        self.assertIn("Akamai Bot Manager", text)

        # Also test /api/export/markdown convenience endpoint
        latest_resp = client.get("/api/export/markdown")
        self.assertEqual(latest_resp.status_code, 200)
        self.assertIn("### Summary", latest_resp.text)

    def test_graphql_active_route_verification(self):
        """Verify Phase 5 active verification of crawler routes (GraphQL introspection & hardening)."""
        import asyncio
        from app.core.auditor_api_routes import ApiRouteAuditor

        # Mock transport handler using httpx.MockTransport
        def handler(request):
            url_str = str(request.url)
            if "/graphql" in url_str and "hardened" not in url_str:
                if request.method == "POST":
                    body = request.content.decode("utf-8")
                    if "__schema" in body:
                        return httpx.Response(
                            200,
                            json={"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "types": [{"name": "User"}]}}}
                        )
                return httpx.Response(200, text="GraphQL Playground")
            elif "hardened-graphql" in url_str:
                return httpx.Response(403, headers={"Server": "AkamaiGHost"}, text="Access Denied")
            elif "universal-login" in url_str:
                return httpx.Response(200, text="<form><input type='password' name='pass'></form>")
            return httpx.Response(404, text="Not Found")

        mock_transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient
        def custom_async_client(*args, **kwargs):
            kwargs["transport"] = mock_transport
            return real_async_client(*args, **kwargs)

        import unittest.mock
        with unittest.mock.patch("httpx.AsyncClient", side_effect=custom_async_client):
            findings = asyncio.run(ApiRouteAuditor.verify_discovered_routes(
                discovered_endpoints=["*/graphql", "*/hardened-graphql", "*/universal-login"],
                base_url="https://example.com",
                headers={},
                enable_dynamic_pacing=False
            ))

        titles = [f["title"] for f in findings]
        rule_ids = [f.get("rule_id") for f in findings]
        
        # GraphQL Introspection escalation
        self.assertIn("GraphQL Introspection Enabled", titles)
        self.assertIn("BR-API-GRAPHQL-INTROSPECTION", rule_ids)
        
        # Hardened GraphQL logging
        self.assertTrue(any("Hardened GraphQL Endpoint" in t for t in titles))
        self.assertIn("BR-API-GRAPHQL-HARDENED", rule_ids)
        
        # Accessible login form detection
        self.assertTrue(any("Accessible Login Endpoint" in t for t in titles))
        self.assertIn("BR-API-LOGIN", rule_ids)

    def test_bounded_bfs_crawler_and_domain_restriction(self):
        # Verify strict domain boundary filtering
        target_domain = "target.example.com"
        self.assertTrue(_is_allowed_domain("https://target.example.com/dashboard", target_domain))
        self.assertTrue(_is_allowed_domain("https://api.target.example.com/v1", target_domain))
        self.assertTrue(_is_allowed_domain("/static/js/app.js", target_domain))
        self.assertFalse(_is_allowed_domain("https://evil-target.example.com/phish", target_domain))
        self.assertFalse(_is_allowed_domain("https://target.example.com.evil.com/leak", target_domain))
        self.assertFalse(_is_allowed_domain("https://unrelated-domain.org", target_domain))

    def test_dynamic_chunk_resolver_webpack_vite_rollup(self):
        # Sample JS bundle containing Webpack chunk mapping and dynamic import
        js_content = '''
        __webpack_require__.u = function(chunkId) {
            return "static/js/" + chunkId + "." + {"101":"a1b2c3d4","102":"e5f6g7h8"}[chunkId] + ".chunk.js";
        };
        import("./views/AdminDashboard.js");
        import('/assets/chunk-telemetry.js');
        '''
        chunks = _resolve_webpack_chunks_python(js_content)
        self.assertTrue(any("101.a1b2c3d4.chunk.js" in c for c in chunks))
        self.assertTrue(any("102.e5f6g7h8.chunk.js" in c for c in chunks))
        self.assertTrue(any("AdminDashboard.js" in c for c in chunks))
        self.assertTrue(any("chunk-telemetry.js" in c for c in chunks))

    def test_active_postmessage_poc_synthesis(self):
        finding = {
            "title": "Unvalidated postMessage Event Listener (Missing Origin Check)",
            "severity": "HIGH",
            "evidence": "window.addEventListener('message', function(event) { document.getElementById('debug').innerHTML = event.data; });",
            "target_url": "https://staging.internal.cybernest.io/portal"
        }
        poc_res = DomAuditor.build_postmessage_poc("https://staging.internal.cybernest.io/portal", finding.get("evidence", ""))
        poc_html = poc_res.get("html_poc_content", "") if isinstance(poc_res, dict) else poc_res
        self.assertIn("<!DOCTYPE html>", poc_html)
        self.assertIn("postMessage Origin Validation Reproduction Harness", poc_html)
        self.assertIn("https://staging.internal.cybernest.io/portal", poc_html)
        self.assertIn("event.origin", poc_html)

        # Audit script content to ensure finding enrichment with html_poc
        script = "window.addEventListener('message', function(e) { eval(e.data); });"
        dom_findings = DomAuditor.audit_javascript("https://target.local/app.js", script, target_url="https://target.local")
        pm_findings = [f for f in dom_findings if "postMessage" in f.get("title", "")]
        self.assertTrue(len(pm_findings) > 0)
        self.assertTrue(pm_findings[0].get("html_poc", "").startswith("poc_postmessage_"))
        self.assertIn("<!DOCTYPE html>", pm_findings[0].get("html_poc_content", ""))

    def test_targeted_akamai_bypass_headers(self):
        # Without engagement ID: standard headers
        standard_headers = Settings.get_stealth_headers(engagement_id=None)
        self.assertNotIn("X-Security-Engagement", standard_headers)
        self.assertNotIn("X-Akamai-Staging", standard_headers)

        # With engagement ID: targeted Akamai cache bypass and staging debug headers
        engagement_id = "staging:ENG-CYBERNEST-2026-X"
        stealth_headers = Settings.get_stealth_headers(engagement_id=engagement_id)
        self.assertEqual(stealth_headers.get("X-Security-Engagement"), engagement_id)
        self.assertEqual(stealth_headers.get("X-Akamai-Staging"), "true")
        self.assertEqual(stealth_headers.get("X-Akamai-Edge-Token"), "ENG-CYBERNEST-2026-X")
        self.assertIn("akamai-x-cache-on", stealth_headers.get("Pragma", ""))
        self.assertIn("no-cache", stealth_headers.get("Cache-Control", ""))

    def test_surface_risk_score_normalization(self):
        # 1. Vendor endpoints and INFO-only findings should NOT saturate score
        vendor_findings = [
            {"severity": "INFO", "title": "Vendor Cookie Observed: _abck", "tags": ["vendor_integration"]},
            {"severity": "INFO", "title": "Akamai Telemetry Active", "tags": ["vendor_integration"]},
            {"severity": "INFO", "title": "Adobe Analytics Library Found", "tags": ["vendor_integration"]}
        ]
        vendor_routes = ["/akamai/samesite", "/tealium/collect", "/adobe/visitor"]
        
        fallback_res = _python_fallback_surface_graph(
            endpoints=vendor_routes,
            headers={},
            content="",
            findings=vendor_findings
        )
        # Score must be low and bounded (<= 15), preventing the 95-100 saturation bug
        self.assertLessEqual(fallback_res["risk_score"], 15)

        # 2. Critical first-party findings and sensitive routes should escalate score appropriately
        critical_findings = [
            {"severity": "CRITICAL", "title": "Exposed RSA Private Key", "tags": []},
            {"severity": "HIGH", "title": "DOM-Based Cross-Site Scripting (XSS)", "tags": []}
        ]
        internal_routes = ["/admin/api/users", "/api/v1/auth/token"]
        
        escalated_res = _python_fallback_surface_graph(
            endpoints=internal_routes,
            headers={},
            content="",
            findings=critical_findings
        )
        self.assertGreaterEqual(escalated_res["risk_score"], 45)

    def test_src_list_parser_and_security_sanitization(self):
        from app.core.security import parse_src_list, sanitize_target_input

        # 1. Valid comma-separated target domain URIs
        parsed = parse_src_list("www.website01.com,www.website02.com,www.website99.com")
        self.assertEqual(
            parsed,
            [
                "https://www.website01.com/",
                "https://www.website02.com/",
                "https://www.website99.com/"
            ]
        )

        # 2. Explicitly reject hyphen-prefixed strings (argument injection defense)
        for bad_hyphen in ["-oProxyCommand=sh", "--help", "-v", "https://-evil.com", "sub.-evil.com"]:
            with self.subTest(bad_hyphen=bad_hyphen):
                with self.assertRaises(ValueError):
                    sanitize_target_input(bad_hyphen)
                with self.assertRaises(ValueError):
                    parse_src_list(f"www.website01.com,{bad_hyphen}")

        # 3. Proactively block path traversal attempts
        for bad_traversal in [
            "../../etc/passwd",
            "www.website01.com/../../etc/passwd",
            "www.website01.com/%2e%2e/%2e%2e/etc/shadow",
            "www.website01.com\\..\\windows\\win.ini",
            "file:///etc/passwd"
        ]:
            with self.subTest(bad_traversal=bad_traversal):
                with self.assertRaises(ValueError):
                    sanitize_target_input(bad_traversal)
                with self.assertRaises(ValueError):
                    parse_src_list(f"www.website01.com,{bad_traversal}")

        # 4. Proactively block command injection vectors
        for bad_cmd in [
            "www.website01.com; rm -rf /",
            "www.website01.com | cat /etc/passwd",
            "www.website01.com && id",
            "$(whoami).website01.com",
            "`id`.website01.com",
            "www.website01.com\nwww.website02.com"
        ]:
            with self.subTest(bad_cmd=bad_cmd):
                with self.assertRaises(ValueError):
                    parse_src_list(bad_cmd)

    def test_htmx_batch_dashboard_and_input_mode_toggle(self):
        from fastapi.testclient import TestClient
        from blackroute_web import app

        client = TestClient(app)

        # 1. Verify main dashboard contains HTMX toggle switch, CSV file input, inline textarea, and Batch ZIP export
        dash_resp = client.get("/")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("Single Target Domain", dash_resp.text)
        self.assertIn("Batch Domain Import", dash_resp.text)
        self.assertIn('name="src_list_file"', dash_resp.text)
        self.assertIn('accept=".csv,text/csv"', dash_resp.text)
        self.assertIn('name="batch_targets"', dash_resp.text)
        self.assertIn("/api/export/batch-zip", dash_resp.text)

        # 2. Verify HTMX input-mode endpoint toggles between single and batch views
        batch_mode_resp = client.get("/api/input-mode?mode=batch")
        self.assertEqual(batch_mode_resp.status_code, 200)
        self.assertIn('hx-post="/api/scan/batch"', batch_mode_resp.text)
        self.assertIn('value="batch"', batch_mode_resp.text)

        single_mode_resp = client.get("/api/input-mode?mode=single")
        self.assertEqual(single_mode_resp.status_code, 200)
        self.assertIn('hx-post="/api/scan"', single_mode_resp.text)
        self.assertIn('value="single"', single_mode_resp.text)

        # 3. Verify batch endpoint rejects malicious hyphen-prefixed or traversal inputs
        bad_batch_resp = client.post("/api/scan/batch", data={"batch_targets": "www.website01.com,-malicious.com"})
        self.assertEqual(bad_batch_resp.status_code, 200)
        self.assertIn("[ERROR]", bad_batch_resp.text)
        self.assertIn("[HALTED]", bad_batch_resp.text)

    def test_filesystem_sandbox_and_traversal_hardening(self):
        """Verify filesystem confinement, symlink rejection, PoC route sanitization, and subresource SSRF guards."""
        import tempfile
        import io
        import zipfile
        from fastapi.testclient import TestClient
        from blackroute_web import app
        from app.core.config import resource_path
        from app.core.security import resolve_sandboxed_path, sanitize_filename, is_safe_subresource_url
        from app.core.engine_bridge import _validate_path, _find_engine
        from app.routes.api import compile_batch_zip_archive

        # 1. resource_path blocks directory climbing and absolute path overrides
        with self.assertRaises(ValueError):
            resource_path("../../etc/passwd")
        with self.assertRaises(ValueError):
            resource_path("/etc/passwd")

        # 2. sanitize_filename blocks traversal, backslashes, control chars, and invalid extensions
        self.assertEqual(sanitize_filename("poc_1234abcd.html", allowed_extensions=(".html",)), "poc_1234abcd.html")
        for bad_name in [
            "../poc.html",
            "..\\poc.html",
            "poc\r\nInjected: 1.html",
            "<script>alert(1)</script>.html",
            "-flag.html",
            "report.exe",
        ]:
            with self.assertRaises(ValueError):
                sanitize_filename(bad_name, allowed_extensions=(".html",))

        # 3. resolve_sandboxed_path blocks '..', absolute paths, and symlink escapes
        with tempfile.TemporaryDirectory() as tmp_dir:
            safe_file = resolve_sandboxed_path(tmp_dir, "index.html")
            self.assertTrue(str(safe_file).startswith(os.path.realpath(tmp_dir)))

            with self.assertRaises(ValueError):
                resolve_sandboxed_path(tmp_dir, "../escape.html")
            with self.assertRaises(ValueError):
                resolve_sandboxed_path(tmp_dir, "/etc/passwd")

            symlink_path = os.path.join(tmp_dir, "evil_link.html")
            os.symlink("/etc/hosts", symlink_path)
            with self.assertRaises(ValueError):
                resolve_sandboxed_path(tmp_dir, "evil_link.html")
            with self.assertRaises(ValueError):
                _validate_path(symlink_path)

        # 4. _validate_path rejects system paths outside sandbox and _find_engine enforces allowlist
        with self.assertRaises(ValueError):
            _validate_path("/etc/passwd")
        with self.assertRaises(ValueError):
            _validate_path("-oProxyCommand")
        self.assertIsNone(_find_engine("../sh"))
        self.assertIsNone(_find_engine("sh"))

        # 5. Subresource SSRF guard blocks metadata, non-HTTP schemes, and private IPs when local_staging=False
        self.assertFalse(is_safe_subresource_url("file:///etc/passwd", allow_local_staging=True))
        self.assertFalse(is_safe_subresource_url("http://169.254.169.254/latest/meta-data/", allow_local_staging=True))
        self.assertFalse(is_safe_subresource_url("http://127.0.0.1:8080/internal.js", allow_local_staging=False))
        self.assertTrue(is_safe_subresource_url("http://127.0.0.1:8080/internal.js", allow_local_staging=True))
        self.assertTrue(is_safe_subresource_url("https://cdn.example.com/app.js", allow_local_staging=False))

        # 6. /api/poc/{filename} rejects path traversal, backslash, and XSS filenames
        client = TestClient(app)
        for bad_poc in ["..%2Fetc%2Fpasswd.html", "..\\secret.html", "%3Cscript%3E.html", "bad;name.html"]:
            resp = client.get(f"/api/poc/{bad_poc}")
            self.assertEqual(resp.status_code, 400)

        # 7. compile_batch_zip_archive ignores symlinks and non-report files inside Targ001
        with tempfile.TemporaryDirectory() as batch_tmp:
            targ1 = os.path.join(batch_tmp, "Targ001")
            os.makedirs(targ1, exist_ok=True)
            valid_md = os.path.join(targ1, "blackroute_triage_scan_1.md")
            with open(valid_md, "w", encoding="utf-8") as f:
                f.write("# Triage\n")
            os.symlink("/etc/hosts", os.path.join(targ1, "stolen_hosts.md"))

            zip_bytes = compile_batch_zip_archive(batch_tmp)
            self.assertIsNotNone(zip_bytes)
            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                names = zf.namelist()
                self.assertIn("Output/Targ001/blackroute_triage_scan_1.md", names)
                self.assertNotIn("Output/Targ001/stolen_hosts.md", names)

    def test_cmmc_stig_cwe_and_ast_context_hardening(self):
        """Verify CWE-22, CWE-346, AES-256-GCM, Ed25519, AST Context Analyzer, and CMMC/STIG endpoints."""
        import tempfile
        from fastapi.testclient import TestClient
        from blackroute_web import app
        from app.core.security import (
            sanitize_relative_path,
            safe_resolve_under,
            verify_host_and_origin,
            encrypt_aes256_gcm,
            decrypt_aes256_gcm,
            get_or_create_ed25519_identity,
            sign_payload_ed25519,
            sense_network_medium_802,
            verify_cmmc_controls,
        )
        from app.core.auditor_ast_context import analyze_response_ast_context, ContextualASTAddon

        # 1. CWE-22 Path Sanitization
        self.assertEqual(sanitize_relative_path("reports/out.pdf"), "reports/out.pdf")
        for bad in ["../etc/passwd", "/etc/shadow", "a\\b", "-flag"]:
            with self.assertRaises(ValueError):
                sanitize_relative_path(bad)

        with tempfile.TemporaryDirectory() as tmp:
            resolved = safe_resolve_under(tmp, "sub/file.txt")
            self.assertTrue(str(resolved).startswith(os.path.realpath(tmp)))

        # 2. CWE-346 Host & Origin Validation
        self.assertTrue(verify_host_and_origin("127.0.0.1:8000", "http://127.0.0.1:8000", None))
        self.assertFalse(verify_host_and_origin("evil.com", None, None))
        self.assertFalse(verify_host_and_origin("127.0.0.1:8000", "https://evil.com", None))

        # 3. AES-256-GCM & Ed25519 Enclave
        ct = encrypt_aes256_gcm(b"CLASSIFIED_CUI_RECORD")
        pt = decrypt_aes256_gcm(ct)
        self.assertEqual(pt, b"CLASSIFIED_CUI_RECORD")
        ident = get_or_create_ed25519_identity()
        self.assertIn("public_key_hex", ident)
        sig = sign_payload_ed25519(b"audit-payload")
        self.assertTrue(len(sig["signature"]) >= 64)

        # 4. Module 3 (AST Reflection Context)
        sample_html = '<html><body><a href="javascript:Canary123" onclick="eval(Canary123)">link</a><script>var x = "Canary123";</script></body></html>'
        ast_findings = analyze_response_ast_context(
            "https://example.com/search", sample_html, canary="Canary123"
        )
        self.assertTrue(len(ast_findings) >= 2)
        addon = ContextualASTAddon(canary="Canary123")
        self.assertEqual(addon.canary, "Canary123")

        # 5. Compliance & Network Sensing API Endpoints
        net_report = sense_network_medium_802()
        self.assertEqual(net_report["standard"], "IEEE 802.3 / IEEE 802.11w-2009")
        cmmc = verify_cmmc_controls()
        self.assertEqual(cmmc["sprs_score"], 110)

        client = TestClient(app)
        self.assertEqual(client.get("/api/compliance/cmmc").status_code, 200)
        self.assertEqual(client.get("/api/compliance/stig").status_code, 200)
        self.assertEqual(client.get("/api/network-sense").status_code, 200)

if __name__ == "__main__":
    unittest.main()


