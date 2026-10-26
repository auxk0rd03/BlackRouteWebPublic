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
        import tempfile
        from pathlib import Path
        from app.core.config import settings
        from app.core.database import init_db
        cls._tmp_env = tempfile.TemporaryDirectory(prefix="br_test_e2e_")
        tmp_root = Path(cls._tmp_env.name)
        cls._orig_db = settings.DB_PATH
        cls._orig_out = settings.OUTPUT_DIR
        cls._orig_static = settings.STATIC_DIR
        settings.DB_PATH = tmp_root / "test_blackroute_e2e.db"
        settings.OUTPUT_DIR = tmp_root / "Output"
        settings.STATIC_DIR = tmp_root / "static"
        os.makedirs(settings.OUTPUT_DIR, exist_ok=True)
        os.makedirs(settings.STATIC_DIR, exist_ok=True)
        init_db()
        cls.server = HTTPServer(("127.0.0.1", 18888), MockVulnerableHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        from app.core.config import settings
        cls.server.shutdown()
        cls.server.server_close()
        settings.DB_PATH = cls._orig_db
        settings.OUTPUT_DIR = cls._orig_out
        settings.STATIC_DIR = cls._orig_static
        cls._tmp_env.cleanup()

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

    async def test_decoupled_scan_and_on_demand_reporting(self):
        """Verify that scan completes without PDF when generate_pdf=False, and report can be compiled on-demand."""
        from app.routes.api import generate_report_for_scan
        import json
        target = "http://127.0.0.1:18888"
        decoupled_scanner = WebScanner(
            target_url=target,
            shadow_mode=True,
            local_staging=True,
            stealth_mode=True,
            generate_pdf=False
        )

        await decoupled_scanner.run_pipeline()
        self.assertTrue(len(decoupled_scanner.findings) > 0)

        # Confirm scan record exists in database
        scan, findings, _ = get_latest_scan_findings()
        self.assertIsNotNone(scan)
        self.assertEqual(scan["report_file"], "", "Report file should be empty during decoupled scan")

        # Compile report on-demand via API handler
        res = await generate_report_for_scan(scan["id"])
        data = json.loads(res.body.decode())
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["report_file"].endswith(".pdf"))
        self.assertIn("/static/", data["download_url"])

    async def test_multi_target_batch_pipeline_and_zip_export(self):
        """Verify batch pipeline generates Output/Targ001..Targ00N with .md and .pdf reports and exports ZIP archive."""
        import io
        import zipfile
        from app.core.security import parse_src_list
        from app.core.scanner import run_batch_scan_pipeline
        from app.core.config import settings
        from app.routes.api import export_batch_zip

        raw_csv = "http://127.0.0.1:18888,http://127.0.0.1:18888/dashboard"
        targets = parse_src_list(raw_csv)
        self.assertEqual(len(targets), 2)

        batch_results = await run_batch_scan_pipeline(
            targets=targets,
            shadow_mode=True,
            local_staging=True,
            stealth_mode=True
        )
        self.assertEqual(len(batch_results), 2)

        # Verify Output/Targ001 and Output/Targ002 directory structure & files
        targ1_dir = settings.OUTPUT_DIR / "Targ001"
        targ2_dir = settings.OUTPUT_DIR / "Targ002"
        self.assertTrue(targ1_dir.is_dir(), "Output/Targ001 must exist")
        self.assertTrue(targ2_dir.is_dir(), "Output/Targ002 must exist")

        for idx, t_dir in enumerate([targ1_dir, targ2_dir], start=1):
            files = [f.name for f in t_dir.iterdir() if f.is_file()]
            md_files = [f for f in files if f.startswith("blackroute_triage_scan_") and f.endswith(".md")]
            pdf_files = [f for f in files if f.startswith("BlackRoute_Web_Report_") and f.endswith(".pdf")]
            self.assertEqual(len(md_files), 1, f"Targ00{idx} must contain 1 triage .md file, got {files}")
            self.assertEqual(len(pdf_files), 1, f"Targ00{idx} must contain 1 VIDS .pdf report, got {files}")

        # Verify ZIP Archive Compilation & Export Endpoint
        zip_resp = await export_batch_zip()
        self.assertEqual(zip_resp.status_code, 200)
        self.assertEqual(zip_resp.headers.get("content-type"), "application/zip")

        with zipfile.ZipFile(io.BytesIO(zip_resp.body), "r") as zf:
            names = zf.namelist()
            self.assertTrue(any(n.startswith("Output/Targ001/blackroute_triage_scan_") and n.endswith(".md") for n in names))
            self.assertTrue(any(n.startswith("Output/Targ001/BlackRoute_Web_Report_") and n.endswith(".pdf") for n in names))
            self.assertTrue(any(n.startswith("Output/Targ002/blackroute_triage_scan_") and n.endswith(".md") for n in names))
            self.assertTrue(any(n.startswith("Output/Targ002/BlackRoute_Web_Report_") and n.endswith(".pdf") for n in names))

if __name__ == "__main__":
    unittest.main()

