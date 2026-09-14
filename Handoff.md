# CyberNest Labs: BlackRoute-Web Developer Handoff Manual

## Document Purpose & Scope

This document serves as the primary technical handover and developer onboarding reference for **BlackRoute-Web** (`Active_Dev/BlackRoute-Web-Linux_VersionPopOS`). It details the end-to-end architecture, explains the role of every file in the codebase, describes how each component interacts within the broader system, and provides actionable guides for extending rules, modifying engines, and maintaining the platform.

---

## 1. Complete Codebase Directory Tree

```text
BlackRoute-Web-Linux_VersionPopOS/
├── .gitignore                          # Git ignore rules (binaries, venvs, databases, cache)
├── CyberNestLabsLogo.png               # Root brand logo asset
├── Handoff.md                          # Technical architecture & maintenance handover manual
├── README.md                           # Operational manual, setup instructions, disclaimer
├── requirements.txt                    # Python library dependency definitions
├── blackroute_web.py                   # Master entrypoint, port scanner & server bootloader
├── launcher.sh                         # Unified Linux CLI launcher, venv manager & compiler
├── launcher.bat                        # Unified Windows CLI launcher
├── app/
│   ├── __init__.py                     # App package marker
│   ├── core/
│   │   ├── __init__.py                 # Core package marker
│   │   ├── config.py                   # Global settings, paths, timeouts & PyInstaller resolution
│   │   ├── database.py                 # SQLite schema, connection lifecycles & query helpers
│   │   ├── security.py                 # SSRF firewall, IP filtering, target normalization & hashing
│   │   ├── auditor_headers.py          # CSP, HSTS, CORS, Clickjacking & Cookie hygiene engine
│   │   ├── auditor_secrets.py          # High-confidence token, key & credential leak detector
│   │   ├── auditor_api_routes.py       # OpenAPI/Swagger, GraphQL, Actuators & Git metadata probes
│   │   ├── auditor_dom.py              # Client-side DOM XSS sinks & unvalidated postMessage audits
│   │   ├── engine_bridge.py            # Secure IPC adapter for Rust/Go binaries with Python fallbacks
│   │   └── scanner.py                  # Master audit orchestrator, crawler pipeline & UI renderer
│   ├── routes/
│   │   ├── __init__.py                 # Routes package marker
│   │   ├── home.py                     # HTML dashboard & favicon router
│   │   └── api.py                      # REST endpoints for scan execution, logs, STIX/TAXII export
│   ├── static/
│   │   ├── CyberNestLabsLogo.png       # Web asset brand logo
│   │   ├── brand.css                   # CyberNest Labs corporate header styles
│   │   └── terminal.css                # Dark military-industrial cyberpunk theme & tables
│   └── templates/
│       ├── layout.html                 # Jinja2 master HTML layout with HTMX loader
│       └── index.html                  # Jinja2 dashboard with dual-column mission control
├── bin/
│   ├── web_spider                      # [Compiled Rust binary] High-performance crawler/regex extractor
│   └── surface_graph                   # [Compiled Go binary] Attack surface topology & tech fingerprinter
├── engines/
│   ├── web_spider/
│   │   ├── Cargo.toml                  # Rust package definition & compiler optimizations (LTO, strip)
│   │   ├── Cargo.lock                  # Pinned offline crate dependencies
│   │   └── src/
│   │       └── main.rs                 # Rust source: Thompson NFA regex crawler & endpoint harvester
│   └── surface_graph/
│       ├── go.mod                      # Go module definition (Go 1.21+, zero external dependencies)
│       └── main.go                     # Go source: concurrent topology tree & tech fingerprinter
├── Sources/
│   ├── __init__.py                     # Sources package marker
│   └── Utilities/
│       ├── __init__.py                 # Utilities package marker
│       └── vids_pdf_gen.py             # CyberNest VIDS PDF Web Audit report generator
└── tests/
    ├── test_audit.py                   # Unit tests for auditors, security policies & engine bridges
    └── test_pipeline_e2e.py            # End-to-end integration test against a mock vulnerable web server
```

---

## 2. Deep File-by-File Breakdown

### Root Control & Configuration Files

#### `blackroute_web.py`
- **Role**: Primary application server entrypoint.
- **What It Does**:
  1. Searches for open local TCP ports in range `8000–8100` (`find_available_port`).
  2. Spawns an asynchronous background thread (`open_browser`) that opens the operating system's default browser after 1.5 seconds.
  3. Defines the FastAPI `lifespan` context manager, printing the boot sequence banner and initializing SQLite tables via `init_db()`.
  4. Mounts `/static` files and registers `home.router` and `api.router` (prefixed with `/api`).
  5. Boots Uvicorn without auto-reload (`reload=False`) to ensure compatibility with PyInstaller standalone compilation.
- **How It Interacts**: Coordinates startup for the entire web stack. Called directly by `launcher.sh` / `launcher.bat` or via CLI `python blackroute_web.py`.
- **How to Modify**:
  - *Change port range*: Adjust `start_port` and `end_port` inside `find_available_port()`.
  - *Disable auto-opening browser*: Comment out `threading.Thread(target=open_browser, ...)`.
  - *Change host binding*: Modify `host="127.0.0.1"` in `uvicorn.run()` (e.g. to `"0.0.0.0"` for remote container deployments).

#### `launcher.sh`
- **Role**: Unified Linux CLI runner, environment manager, and engine compiler.
- **What It Does**:
  - `setup_venv`: Detects system Python 3, checks if `.venv` exists and points to the right path, creates `.venv` if missing, and installs dependencies from `requirements.txt`.
  - `run_application`: Invokes `setup_venv` and boots `blackroute_web.py`.
  - `build_engines`: Compiles Rust `web_spider` (`cargo build --release --offline`) and Go `surface_graph` (`go build -ldflags="-s -w"`), moving binaries to `bin/`.
  - `build_release`: Bundles the application into a single Linux binary (`dist/BlackRoute_Web_v1.0`) via PyInstaller.
  - Interactive menu: Provides a numbered selection menu if invoked without arguments.
- **How It Interacts**: User-facing execution entrypoint for Pop!_OS / Linux.
- **How to Modify**:
  - *Add new compiled engine*: Add compilation logic under `build_engines()` targeting `engines/<new_engine>`.
  - *Add hidden PyInstaller imports*: Append `--hidden-import=<module>` flags to the `pyinstaller` command in `build_release()`.

#### `launcher.bat`
- **Role**: Unified Windows CLI runner and setup script.
- **What It Does**: Provides automated venv creation, dependency installation, and server startup on Windows 10/11.
- **How It Interacts**: User-facing entrypoint for Windows users.
- **How to Modify**: Add Windows-specific environment flags or compilation steps.

#### `requirements.txt`
- **Role**: Python dependency specifications.
- **Dependencies**: `fastapi`, `uvicorn`, `jinja2`, `aiofiles`, `fpdf2`, `pydantic`, `python-multipart`, `beautifulsoup4`, `httpx`.
- **How to Modify**: Add new third-party Python modules here. Ensure versions remain pinned or bounded to prevent upstream breaking changes.

---

### Core Engine & Logic (`app/core/`)

#### `app/core/config.py`
- **Role**: Global runtime configuration, path resolution, and constants.
- **What It Does**:
  - Provides `resource_path(relative_path)`: Detects whether the app is running in standard Python dev mode or as a frozen PyInstaller binary (inspecting `sys._MEIPASS`), resolving assets correctly.
  - `Settings` class: Defines paths to `STATIC_DIR`, `TEMPLATES_DIR`, `DB_PATH`, `ENGINE_BIN_DIR`, default crawling budgets (`CRAWL_MAX_PAGES = 35`, `CRAWL_TIMEOUT = 15.0`), and the default scanning User-Agent string.
- **How It Interacts**: Imported by every module requiring access to filesystem resources, static paths, or database configurations.
- **How to Modify**:
  - *Increase crawl page limit*: Change `Settings.CRAWL_MAX_PAGES`.
  - *Adjust asset size cap*: Modify `Settings.MAX_JS_ASSET_SIZE` (default 5MB).
  - *Change User-Agent*: Update `Settings.USER_AGENT`.

#### `app/core/database.py`
- **Role**: SQLite data persistence layer.
- **What It Does**:
  - `init_db()`: Creates the three relational tables: `scans`, `findings`, and `endpoints`.
  - `save_scan_record()`: Persists target URL, status, pages crawled, findings list (severity, category, title, evidence, remediation), and endpoints into SQLite.
  - `get_latest_scan_findings()`: Retrieves the most recent scan metadata and associated findings/endpoints for STIX/TAXII exports.
- **How It Interacts**: Called during startup by `blackroute_web.py`, by `scanner.py` at the conclusion of every audit, and by `api.py` during STIX/TAXII export queries.
- **How to Modify**:
  - *Add new columns*: Update the `CREATE TABLE` queries in `init_db()` and parameter bindings in `save_scan_record()`.
  - *Query historical scans*: Add custom helper functions querying the `scans` table by date, target URL, or finding severity.

#### `app/core/security.py`
- **Role**: SSRF prevention, URL validation, and string sanitization.
- **What It Does**:
  - `normalize_target_url(raw)`: Strips quotes/whitespace, ensures lowercase scheme, prepends `https://` if absent, and drops fragments.
  - `validate_target_url(url, allow_local_staging)`: Resolves host IP addresses via `socket.getaddrinfo`. Blocks loopback (`127.0.0.1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
  - If `allow_local_staging=True`, allows local dev targets while strictly retaining the cloud metadata block.
  - `sanitize_text(text)`: HTML-escapes content before terminal log injection.
  - `calculate_sha256(filepath)`: Computes cryptographic file checksums.
- **How It Interacts**: Invoked before any network traffic is initiated in `scanner.py`.
- **How to Modify**:
  - *Add blocked hosts*: Add hostnames or CIDR ranges to the blocklist in `validate_target_url()`.
  - *Custom protocol rules*: Adjust allowed schemes in `validate_target_url()`.

#### `app/core/auditor_headers.py`
- **Role**: HTTP response header, cookie security, and transport layer auditor.
- **What It Does**:
  - `audit_response_headers(url, headers, status)`:
    - Analyzes CSP: Flags missing CSP, `'unsafe-inline'`, `'unsafe-eval'`, and wildcard origins (`*`).
    - Analyzes HSTS: Checks header presence on HTTPS, minimum `max-age` (recommended >= 31536000), `includeSubDomains`.
    - Analyzes Anti-Clickjacking: Checks `X-Frame-Options` and CSP `frame-ancestors`.
    - Analyzes MIME Sniffing: Evaluates `X-Content-Type-Options: nosniff`.
    - Analyzes Referrer & Permissions: Evaluates `Referrer-Policy` and `Permissions-Policy`.
    - Detects server banners (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4`).
  - `audit_cookies(url, cookies_headers)`:
    - Parses every `Set-Cookie` header. Flags missing `Secure`, missing `HttpOnly`, missing `SameSite`, and dangerous `SameSite=None` without `Secure`.
  - `audit_cors(url, acao, acac, tested_origin)`:
    - Flags `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true` (CRITICAL).
    - Flags dynamic reflection of arbitrary untrusted origins (`acao == tested_origin`).
- **How It Interacts**: Called during Phase 1 of `scanner.py` when evaluating the initial response from the target.
- **How to Modify**:
  - *Add new header rule*: Add a check inside `audit_response_headers()` returning a dictionary with `severity`, `category`, `title`, `description`, `endpoint`, `evidence`, `confidence`, and `remediation`.

#### `app/core/auditor_secrets.py`
- **Role**: Regex-based token, key, and credential exposure scanner for client-side web assets.
- **What It Does**:
  - Maintains `SECRET_RULES`:
    - `AWS_KEY`: `AKIA[0-9A-Z]{16}` (CRITICAL)
    - `GOOGLE_API_KEY`: `AIza[0-9A-Za-z\-_]{35}` (HIGH)
    - `STRIPE_SECRET_KEY`: `sk_live_[0-9a-zA-Z]{24,}` (CRITICAL)
    - `STRIPE_PUB_KEY`: `pk_live_[0-9a-zA-Z]{24,}` (INFO)
    - `GITHUB_TOKEN`: `ghp_...` / `github_pat_...` (CRITICAL)
    - `GITLAB_TOKEN`: `glpat-...` (CRITICAL)
    - `SLACK_WEBHOOK`: `hooks.slack.com/services/...` (HIGH)
    - `OPENAI_KEY`: `sk-(?:proj-|ant-)?[a-zA-Z0-9\-_]{32,}` (CRITICAL)
    - `JWT_TOKEN`: `eyJ...` (HIGH)
    - `PRIVATE_KEY`: `-----BEGIN ... PRIVATE KEY-----` (CRITICAL)
    - `DATABASE_URI`: `postgres://`, `mongodb://`, `mysql://` (CRITICAL)
  - `audit_content(source_url, content)`: Scans strings, automatically obfuscates matching tokens (e.g. `AKIA****MPLE`) for safe evidence presentation, extracts surrounding context snippets, and returns finding records.
- **How It Interacts**: Executed during Phase 3 of `scanner.py` across all harvested HTML pages and downloaded JS bundles.
- **How to Modify**:
  - *Add new secret detector*: Add a new rule entry to `SECRET_RULES` with `id`, `title`, `regex` (`re.compile`), `severity`, `description`, and `remediation`.

#### `app/core/auditor_api_routes.py`
- **Role**: Non-destructive active probe for exposed API schemas, administrative dashboards, actuators, and debug files.
- **What It Does**:
  - Maintains `PROBE_TARGETS`:
    - `/.git/HEAD`: Exposed Git repository metadata (CRITICAL)
    - `/.env`: Exposed environment configuration file (CRITICAL)
    - `/openapi.json` / `/swagger.json`: Exposed OpenAPI/Swagger specifications (LOW)
    - `/actuator/env`: Exposed Spring Boot Actuator environment (CRITICAL)
    - `/actuator/health`: Exposed Spring Boot health status (INFO)
    - `/phpinfo.php`: Exposed PHP diagnostic dump (HIGH)
    - `/server-status`: Exposed Apache mod_status dashboard (MEDIUM)
  - Probes GraphQL endpoints (`/graphql`, `/api/graphql`) with safe introspection query:
    `{"query": "{ __schema { queryType { name } } }"}`. Flags GraphQL Introspection Enabled (MEDIUM) if the schema is exposed.
- **How It Interacts**: Executed concurrently in Phase 5 of `scanner.py`.
- **How to Modify**:
  - *Add new probe endpoint*: Add an entry to `PROBE_TARGETS` with `path`, `title`, `severity`, `category`, and a `check` lambda evaluating the response (e.g. status code and response body signatures).

#### `app/core/auditor_dom.py`
- **Role**: Static code auditor for client-side JavaScript looking for DOM XSS sinks and insecure postMessage listeners.
- **What It Does**:
  - `DOM_SINKS`: Regex patterns for `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`, `setInterval`, `new Function`.
  - `DOM_SOURCES`: Regex patterns for `location.search`, `location.hash`, `location.href`, `document.URL`, `document.referrer`, `window.name`.
  - `audit_javascript(url, js_code)`:
    1. Scans for unvalidated `postMessage` listeners: flags `window.addEventListener('message', ...)` where the handler body lacks an `e.origin` / `event.origin` check.
    2. Correlates user-controlled DOM sources with dangerous execution sinks on the same line.
- **How It Interacts**: Executed during Phase 4 of `scanner.py` across all downloaded JavaScript files.
- **How to Modify**:
  - *Add new sinks or sources*: Add regex patterns to `DOM_SINKS` or `DOM_SOURCES`.

#### `app/core/engine_bridge.py`
- **Role**: Secure IPC adapter mediating communication between Python and compiled Rust/Go binaries.
- **What It Does**:
  - `_validate_path(path)`: Rejects null bytes (`\0`) and resolves canonical absolute paths.
  - `_find_engine(name)`: Checks if binary exists in `bin/` and has executable permissions (`os.X_OK`).
  - `engine_available(name)`: Health check reporting binary readiness.
  - `_run_engine(binary_path, args, timeout)`: Executes binary with argument lists (never `shell=True`), enforces execution timeouts, and strictly parses JSON output from stdout.
  - `run_spider_extractor(target_path)`: Invokes compiled Rust `web_spider`. If binary is unavailable, seamlessly executes `_python_fallback_spider()`.
  - `run_surface_graph(endpoints, headers, content)`: Invokes compiled Go `surface_graph`. If binary is unavailable, seamlessly executes `_python_fallback_surface_graph()`.
- **How It Interacts**: Primary abstraction layer separating the Python orchestrator from the compiled polyglot engine layer.
- **How to Modify**:
  - *Add a new engine bridge*: Add a new function following the pattern of `_run_engine()` with a corresponding `_python_fallback_<engine>()`.

#### `app/core/scanner.py`
- **Role**: Master audit pipeline orchestrator and real-time mission controller.
- **What It Does**:
  - Manages global thread-safe log buffer `SCAN_LOGS`.
  - `WebScanner` class runs the 7-phase audit sequence:
    1. **SSRF & Scope Validation**: Validates target, enforces loopback/private network blocks (or stages local mode).
    2. **Phase 1 (Headers & Transport)**: Audits CSP, HSTS, CORS, cookies, server banners.
    3. **Phase 2 (Asset Spider)**: Extracts `<script>` tags, downloads bundles into a temp directory, and runs `web_spider` (Rust or Python fallback) to extract all routes and endpoints.
    4. **Phase 3 (Secret Scanner)**: Scans HTML and JS files for credentials via `SecretAuditor`.
    5. **Phase 4 (DOM Risk Audit)**: Analyzes client scripts for DOM XSS and postMessage vulnerabilities via `DomAuditor`.
    6. **Phase 5 (API Surface Probing)**: Probes OpenAPI, GraphQL, actuators, and sensitive paths via `ApiRouteAuditor`.
    7. **Phase 6 (Topology & Tech Fingerprint)**: Dissects routes, builds topology graph, and fingerprints frameworks via `surface_graph` (Go or Python fallback).
    8. **Phase 7 (Reporting & Persistence)**: Applies confidence filters (unless Shadow Mode is enabled), persists results to SQLite, generates the VIDS PDF report, and injects the interactive HTML results grid.
    9. **Zero-Footprint Protocol**: Automatically removes temporary harvest directories on completion.
- **How It Interacts**: Instantiated and scheduled as a background task by `/api/scan` in `app/routes/api.py`.
- **How to Modify**:
  - *Add new scan phase*: Insert your routine in `run_pipeline()` between Phase 1 and Phase 7.
  - *Change confidence filter threshold*: Modify `0.75` in step 8.

---

### Polyglot Compiled Engines (`engines/`)

#### `engines/web_spider/Cargo.toml` & `Cargo.lock`
- **Role**: Rust crate definitions for the `web_spider` engine.
- **Dependencies**: `regex = "1"`, `serde = { version = "1.0", features = ["derive"] }`, `serde_json = "1.0"`.
- **Compiler Profiles**: Configured with `opt-level = 3`, `lto = true`, and `strip = true` for high performance and minimal binary footprint.
- **Cargo.lock**: Pinned offline crate dependencies allowing compilation without network access.

#### `engines/web_spider/src/main.rs`
- **Role**: Compiled Rust asset parser and endpoint extraction engine.
- **What It Does**:
  - CLI usage: `web_spider <file_path>` or `web_spider dir <directory_path>`.
  - Parses HTML to harvest `<a href>`, `<script src>`, `<form action method>`.
  - Uses Thompson NFA linear-time regex (`r#"['"]((?:/|https?://|wss?://)[a-zA-Z0-9_?&=/\-\.:%]+)['"]"#`) to extract endpoints from large minified JS bundles without ReDoS risks.
  - Filters out static asset extensions (`.png`, `.jpg`, `.woff`, `.css`, etc.) and framework noise (`/_next/`, `google-analytics`).
  - Categorizes endpoints (`api_endpoint`, `websocket_endpoint`, `data_endpoint`) and calculates confidence ratings.
  - Outputs structured JSON to stdout.
- **How It Interacts**: Executed via subprocess IPC by `app/core/engine_bridge.py`.
- **How to Modify**:
  - *Add high-value route keywords*: Add terms to `HIGH_VALUE_KEYWORDS`.
  - *Add new asset extensions to ignore*: Add extensions to `JUNK_EXTENSIONS`.
  - *Recompile after edits*: Run `./launcher.sh build_engines`.

#### `engines/surface_graph/go.mod`
- **Role**: Go module specification (`module surface_graph`, `go 1.21`). Uses zero external dependencies (standard library only).

#### `engines/surface_graph/main.go`
- **Role**: Compiled Go attack surface topology analyzer and technology fingerprinter.
- **What It Does**:
  - CLI usage: `surface_graph <json_path | dir <directory>>`.
  - Normalizes route paths, breaks paths into segments, and constructs parent-child graph edges (`/api` -> `/api/v1` -> `/api/v1/users`).
  - Flags sensitive routes containing keywords (`admin`, `auth`, `token`, `actuator`, `upload`, etc.).
  - Extracts external domains contacted by client code.
  - Technology fingerprinter detects: Next.js, React, Vue, Angular, WordPress, Django, Laravel, Apache, Nginx, Cloudflare.
  - Computes attack surface risk score (0–100) based on endpoint volume, sensitive routes, and external domains.
  - Outputs structured JSON to stdout.
- **How It Interacts**: Executed via subprocess IPC by `app/core/engine_bridge.py`.
- **How to Modify**:
  - *Add framework detection rules*: Add checks inside `fingerprintTechnologies()`.
  - *Adjust risk scoring formula*: Tweak the weights in `analyzeSurface()`.
  - *Recompile after edits*: Run `./launcher.sh build_engines`.

---

### Web Interface & Presentation (`app/routes/`, `app/templates/`, `app/static/`)

#### `app/routes/home.py`
- **Role**: HTML dashboard view router.
- **What It Does**:
  - `GET /`: Renders `index.html` using Jinja2 `templates.TemplateResponse` with Starlette 0.36+ keyword syntax (`request=request, name="index.html", context={...}`).
  - `GET /favicon.ico`: Returns the CyberNest Labs brand icon.
- **How It Interacts**: Entrypoint for user browser interaction.

#### `app/routes/api.py`
- **Role**: REST API endpoints for mission orchestration, log streaming, and threat intelligence export.
- **What It Does**:
  - `POST /api/scan`: Accepts `target_url`, `shadow_mode`, `local_staging`, and `auth_header`. Dispatches `scanner.run_pipeline` to FastAPI background tasks. Returns initial feedback HTML with an HTMX polling trigger.
  - `GET /api/stream-logs`: Atomically dequeues and flushes pending log entries using a thread lock to prevent UI race conditions.
  - `GET /api/engines-status`: Returns live HTMX badge fragments indicating the operational state of the Rust Web Spider, Go Surface Graph, and Python DAST pipeline.
  - `GET /api/export/stix`: Builds an authentic STIX 2.1 JSON bundle (`bundle--<uuid>`) containing `vulnerability`, `report`, and `indicator` objects matching current findings.
  - `GET /api/export/taxii`: Builds a TAXII 2.1 envelope containing indicator objects.
- **How It Interacts**: Polled and invoked by the HTMX frontend in `index.html`.
- **How to Modify**:
  - *Change log poll frequency*: Update `hx-trigger="every 800ms"` in `start_scan()`.
  - *Extend STIX attributes*: Add custom fields to `vuln_obj` inside `export_stix()`.

#### `app/templates/layout.html`
- **Role**: Master Jinja2 base template.
- **What It Does**: Provides HTML5 boilerplate, Google Fonts (`Inter`), HTMX script tag (`htmx.org@1.9.10`), static stylesheet links (`terminal.css`, `brand.css`), and the CyberNest Labs header banner.

#### `app/templates/index.html`
- **Role**: Interactive mission control dashboard.
- **What It Does**:
  - **Left Column**: Status bar with live HTMX engine badges, target submission form, Shadow Mode checkbox, Local Staging Mode checkbox, Advanced Auth drawer, and real-time scrolling console log container.
  - **Right Column**: Results area displaying waiting placeholder, automatically swapped with the dynamic results panel upon scan completion (displaying technology badges, surface risk gauge, threat distribution counts, filterable findings table, and export action buttons).

#### `app/static/brand.css`
- **Role**: CyberNest Labs corporate branding stylesheet.
- **What It Does**: Styles the header, company logo, title typography, and version indicators.

#### `app/static/terminal.css`
- **Role**: Military-industrial cyberpunk interface stylesheet.
- **What It Does**:
  - Color palette: `--bg-color: #393834`, `--surface-color: #4c443b`, `--text-primary: #eedba6`, `--accent-color: #5fa8a0`, `--error-color: #a65f5f`.
  - Severity badge classes: `.sev-critical` (Red), `.sev-high` (Orange), `.sev-medium` (Yellow), `.sev-low` (Teal), `.sev-info` (Grey).
  - Responsive grid layouts, tables, scrollbars, input fields, and terminal log entry formatting.
- **How to Modify**:
  - *Customize colors*: Adjust CSS variable values under `:root` in `terminal.css`.

---

### Reporting & Utilities (`Sources/Utilities/`)

#### `Sources/Utilities/vids_pdf_gen.py`
- **Role**: CyberNest VIDS (Vulnerability Identification & Defense Specification) PDF generator.
- **What It Does**:
  - Extends `fpdf.FPDF` as `VIDSWebReport` with custom header (`CYBERNEST LABS - BLACKROUTE-WEB VIDS AUDIT REPORT`) and confidentiality footer.
  - Implements `sanitize(text)` to ensure strict Latin-1 encoding compatibility.
  - Generates:
    1. **Executive Mission Summary**: Target, timestamp, pages crawled, endpoints discovered, surface risk score (0–100), detected technology stack, and threat distribution tally (CRIT, HIGH, MED, LOW, INFO).
    2. **Detailed Audit Findings**: Color-coded severity titles, confidence ratings, descriptions, request/response evidence, and concrete remediation steps.
    3. **Sensitive Route Attack Surface**: Catalog of discovered high-risk endpoints.
  - Outputs to `app/static/BlackRoute_Web_Report_<timestamp>.pdf` and returns filename.
- **How It Interacts**: Executed in a threadpool executor during Phase 7 of `scanner.py`.
- **How to Modify**:
  - *Add new report section*: Call `pdf.add_page()` and render custom text blocks using `pdf.cell()` and `pdf.multi_cell()`.

---

### Test Suites (`tests/`)

#### `tests/test_audit.py`
- **Role**: Unit tests covering core security logic and auditors.
- **What It Tests**:
  1. `test_url_normalization`: Canonical URL formatting.
  2. `test_ssrf_blocking`: Verifies rejection of private/loopback IPs, allowance in local staging mode, and unconditional rejection of cloud metadata (169.254.169.254).
  3. `test_header_auditor`: Verifies CSP, HSTS, XFO, and server banner findings.
  4. `test_cookie_auditor`: Verifies HttpOnly, Secure, and SameSite detection.
  5. `test_cors_auditor`: Verifies detection of wildcard origins with credentials.
  6. `test_secret_auditor`: Verifies detection of AWS, Stripe, and OpenAI tokens.
  7. `test_dom_auditor`: Verifies detection of unvalidated postMessage handlers.
  8. `test_engine_bridge_fallbacks`: Verifies surface graph Python fallback logic.
  9. `test_vids_pdf_generation`: Verifies clean, error-free PDF report creation.
- **How to Run**:
  ```bash
  python -m unittest discover -s tests
  ```

#### `tests/test_pipeline_e2e.py`
- **Role**: Full end-to-end integration test.
- **What It Tests**:
  - Launches a live in-process mock vulnerable HTTP server on `127.0.0.1:18888` serving insecure headers, bad cookies, leaked AWS/Stripe tokens, an unvalidated postMessage listener, an exposed `/.git/HEAD`, and an `openapi.json` file.
  - Executes `WebScanner.run_pipeline()` in Local Staging Mode.
  - Asserts that all 5 vulnerability categories are detected, data is written to SQLite, a PDF report is generated, and STIX 2.1 / TAXII 2.1 exports succeed.

---

## 3. Data Flow & Lifecycle of an Audit

```text
[User Form in Browser]
         │ (POST /api/scan with target_url & options)
         ▼
[api.py: start_scan()]
         │ (Dispatches WebScanner.run_pipeline as Background Task)
         ▼
[scanner.py: Phase 0 - Security & SSRF Validation]
         │ ───► Blocked? ──► Log Error & Abort
         ▼
[scanner.py: Phase 1 - HTTP Header / Cookie / CORS / Transport Audit]
         │ (HeaderAuditor analyzes response headers)
         ▼
[scanner.py: Phase 2 - Asset Crawl & JS Download]
         │ (Downloads HTML & scripts into /tmp/br_web_*)
         │ (Invokes bin/web_spider [Rust] via engine_bridge.py)
         ▼
[scanner.py: Phase 3 - Secret & Credential Leak Scan]
         │ (SecretAuditor scans HTML & JS for tokens/keys)
         ▼
[scanner.py: Phase 4 - Client-Side DOM & postMessage Audit]
         │ (DomAuditor checks sinks and origin checks)
         ▼
[scanner.py: Phase 5 - API Surface & Sensitive Route Probing]
         │ (ApiRouteAuditor tests /.git, /.env, /openapi.json, GraphQL)
         ▼
[scanner.py: Phase 6 - Attack Surface & Stack Fingerprint]
         │ (Invokes bin/surface_graph [Go] via engine_bridge.py)
         ▼
[scanner.py: Phase 7 - Smart Filtering, Reporting & Persistence]
         ├─► Filter low confidence (< 0.75 unless Shadow Mode)
         ├─► Save scan & findings to SQLite (database.py)
         ├─► Generate VIDS PDF Report (vids_pdf_gen.py)
         ├─► Clean temporary harvest folder (Zero-Footprint Protocol)
         └─► Stream dynamic Results Panel HTML to UI via HTMX
```

---

## 4. Developer Extension How-To Guides

### How to Add a New Secret Detection Rule
1. Open `app/core/auditor_secrets.py`.
2. Append a new dictionary to the `SECRET_RULES` list:
   ```python
   {
       "id": "CUSTOM_TOKEN",
       "title": "Exposed Custom Service API Key",
       "regex": re.compile(r'(custom_key_[0-9a-zA-Z]{32})'),
       "severity": "CRITICAL",
       "description": "Hardcoded API key for Custom Service exposed in client assets.",
       "remediation": "Revoke the key immediately and route calls through a backend proxy."
   }
   ```
3. Run `python -m unittest tests/test_audit.py` to verify.

### How to Add a New Active Probe Path
1. Open `app/core/auditor_api_routes.py`.
2. Append a new entry to `PROBE_TARGETS`:
   ```python
   {
       "path": "/api/debug/vars",
       "title": "Exposed Debug Variables (/api/debug/vars)",
       "severity": "HIGH",
       "category": "API_EXPOSURE",
       "check": lambda resp: resp.status_code == 200 and "memstats" in resp.text,
       "description": "Go runtime debug metrics and environment variables exposed.",
       "remediation": "Disable expvar or restrict /debug/vars to internal localhost."
   }
   ```

### How to Add a New Framework Fingerprint to the Go Engine
1. Open `engines/surface_graph/main.go`.
2. In `fingerprintTechnologies()`, add your signature matching rule:
   ```go
   if strings.Contains(contentLower, "gatsby") {
       addTech("Gatsby", "Static Site Generator", "Gatsby runtime signature detected")
   }
   ```
3. Recompile the Go engine:
   ```bash
   ./launcher.sh build_engines
   ```

---

## 5. Maintenance & Operational Commands

```bash
# Launch development server
./launcher.sh launch

# Recompile Rust and Go engines into bin/
./launcher.sh build_engines

# Run all unit and module tests
python -m unittest discover -s tests

# Run end-to-end integration test
python -m unittest tests/test_pipeline_e2e.py

# Package single-file standalone release binary
./launcher.sh build_release
```

---
*CyberNest Labs Internal Tools Group — Authorized Security Engineering Standard.*
