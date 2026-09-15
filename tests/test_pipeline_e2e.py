import asyncio
import os
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from app.core.scanner import WebScanner
from app.core.database import get_latest_scan_findings
from app.routes.api import export_stix, export_taxii

class MockVulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            # Set-Cookie without Secure and HttpOnly
            self.send_header("Set-Cookie", "session_id=12345; Path=/")
            # CORS wildcard
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            html_body = """
            <!DOCTYPE html>
            <html>
            <head><title>Mock Vulnerable Portal</title></head>
            <body>
                <h1>Internal Web Portal</h1>
                <a href="/dashboard">Dashboard</a>
                <a href="/admin/settings">Admin Settings</a>
                <script src="/static/app.js"></script>
            </body>
            </html>
            """
            self.wfile.write(html_body.encode("utf-8"))

        elif self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            js_body = """
            const api_config = {
                endpoint: "/api/v1/auth/login",
                aws_token: "AKIAIOSFODNN7EXAMPLE",
                stripe_key: "sk_live_51ABCDEF1234567890abcdefghijklmnopqrstuvwxyz"
            };
            window.addEventListener('message', function(e) {
                document.getElementById('data').innerHTML = e.data;
            });
            """
            self.wfile.write(js_body.encode("utf-8"))

        elif self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")

        elif self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"openapi": "3.0.0", "paths": {}}')

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence server log output in test
        pass


class TestPipelineE2E(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 18888), MockVulnerableHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    async def test_full_web_scan_pipeline(self):
        target = "http://127.0.0.1:18888"
        # Test Active Mode (stealth_mode=False) to verify active API exposure probes
        scanner = WebScanner(
            target_url=target,
            shadow_mode=True,
            local_staging=True,
            stealth_mode=False,
            engagement_id="CN-TEST-ENGAGE"
        )

        await scanner.run_pipeline()

        self.assertTrue(len(scanner.findings) > 0, "Pipeline should generate findings")
        self.assertTrue(len(scanner.endpoints) > 0, "Spider should harvest endpoints")

        # Verify finding categories present
        cats = {f["category"] for f in scanner.findings}
        self.assertIn("HEADERS", cats)
        self.assertIn("COOKIES", cats)
        self.assertIn("SECRETS", cats)
        self.assertIn("DOM_XSS", cats)
        self.assertIn("API_EXPOSURE", cats)

        # Verify DB persistence
        scan_rec, db_findings, db_endpoints = get_latest_scan_findings()
        self.assertIsNotNone(scan_rec)
        self.assertEqual(scan_rec["target_url"], f"{target}/")
        self.assertEqual(len(db_findings), len(scanner.findings))
        self.assertTrue(all("curl" in f.get("curl_command", "") for f in db_findings), "Every finding must include a cURL PoC")

        # Verify STIX 2.1 export
        stix_resp = await export_stix()
        self.assertEqual(stix_resp.status_code, 200)
        import json
        stix_data = json.loads(stix_resp.body.decode("utf-8"))
        self.assertEqual(stix_data["type"], "bundle")
        self.assertTrue(len(stix_data["objects"]) > 1)

        # Verify TAXII export
        taxii_resp = await export_taxii()
        self.assertEqual(taxii_resp.status_code, 200)
        taxii_data = json.loads(taxii_resp.body.decode("utf-8"))
        self.assertIn("objects", taxii_data)

    async def test_stealth_mode_suppression(self):
        """Verify that Stealth Protocol suppresses intrusive Phase 5 active path probes."""
        target = "http://127.0.0.1:18888"
        stealth_scanner = WebScanner(
            target_url=target,
            shadow_mode=True,
            local_staging=True,
            stealth_mode=True
        )

        await stealth_scanner.run_pipeline()

        cats = {f["category"] for f in stealth_scanner.findings}
        # In stealth mode, sensitive route probes (/.git, /actuator, .env) must NOT be executed
        self.assertNotIn("API_EXPOSURE", cats, "Stealth mode must suppress noisy API_EXPOSURE probes")
        # Non-intrusive checks should still pass
        self.assertIn("HEADERS", cats)
        self.assertIn("COOKIES", cats)
        self.assertIn("SECRETS", cats)
        self.assertIn("DOM_XSS", cats)

if __name__ == "__main__":
    unittest.main()

