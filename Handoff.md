# CyberNest Labs: BlackRoute-Web Developer Handoff Manual

## Document Purpose & Scope

This document serves as the primary technical handover, architecture specification, and developer onboarding reference for **BlackRoute-Web** (`Active_Dev/BlackRoute-Web-Linux_VersionPopOS`). It details the end-to-end architecture, explains the role of every file in the codebase, describes how each component interacts within the broader system, and provides actionable guides for extending rules, modifying engines, and maintaining the platform.

---

## 1. Complete Codebase Directory Tree

```text
BlackRoute-Web-Linux_VersionPopOS/
├── .dockerignore                       # Docker build context exclusion rules
├── .gitignore                          # Git ignore rules (binaries, venvs, databases, cache)
├── CyberNestLabsLogo.png               # Root brand logo asset
├── Dockerfile                          # Multi-stage production container build (Rust/Go -> Python 3.12)
├── docker-compose.yml                  # Container deployment specification with persistent volumes
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
│   │   ├── database.py                 # SQLite schema, connection lifecycles, migrations & cURL storage
│   │   ├── security.py                 # SSRF firewall, IP filtering, target normalization & hashing
│   │   ├── auditor_headers.py          # CSP, HSTS, CORS, Clickjacking & Cookie hygiene engine
│   │   ├── auditor_secrets.py          # Shannon entropy & high-confidence token/credential leak detector
│   │   ├── auditor_api_routes.py       # OpenAPI/Swagger, GraphQL, Actuators & Git metadata probes
│   │   ├── auditor_dom.py              # Client-side DOM XSS sinks & unvalidated postMessage audits
│   │   ├── engine_bridge.py            # Resilient boundary-aware IPC adapter for Rust/Go binaries
│   │   └── scanner.py                  # Master audit orchestrator, cURL generator & SSE log broadcaster
│   ├── routes/
│   │   ├── __init__.py                 # Routes package marker
│   │   ├── home.py                     # HTML dashboard & favicon router (Starlette 0.36+ compatible)
│   │   └── api.py                      # REST endpoints: scan trigger, SSE streaming, STIX/TAXII export
│   ├── static/
│   │   ├── CyberNestLabsLogo.png       # Web asset brand logo
│   │   ├── brand.css                   # CyberNest Labs corporate header styles
│   │   └── terminal.css                # Dark military-industrial cyberpunk theme & tables
│   └── templates/
│       ├── layout.html                 # Jinja2 master HTML layout with HTMX loader
│       └── index.html                  # Jinja2 dashboard with EventSource SSE & 1-click cURL PoC copy
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
│       └── vids_pdf_gen.py             # CyberNest VIDS PDF Web Audit report generator (with cURL PoCs)
└── tests/
    ├── test_audit.py                   # Unit tests (entropy, cURL generation, resilient IPC, headers)
    └── test_pipeline_e2e.py            # End-to-end integration test against mock vulnerable server
```

---

## 2. Deep File-by-File Breakdown

### Root Control & Containerization Files

#### `Dockerfile`
- **Role**: Multi-stage hardened production container specification.
- **What It Does**:
  - **Stage 1 (`builder`)**: Uses `golang:1.22-bookworm`, installs the Rust toolchain, and compiles `engines/web_spider` (Rust with LTO/strip) and `engines/surface_graph` (Go with `-s -w`). Outputs static binaries to `/build/bin/`.
  - **Stage 2 (`runtime`)**: Uses lightweight `python:3.12-slim`. Copies compiled binaries into `/app/bin/`, installs Python requirements, creates a non-root system user (`cybernest`), configures Docker healthchecks (`/api/status`), and launches the application via Uvicorn on port `8000`.
- **How to Modify**: Adjust base images or add system packages (e.g. `ca-certificates`, `curl`).

#### `docker-compose.yml`
- **Role**: Single-command container deployment orchestration.
- **What It Does**: Builds the Dockerfile, exposes port `8000:8000`, and attaches persistent Docker volumes for the SQLite threat database and generated VIDS PDF audit reports.
- **How to Modify**: Change port mappings or attach custom persistent volume storage.

#### `.dockerignore`
- **Role**: Build context filter preventing unneeded local files (`.venv`, `target/`, `.git`, `*.db`) from polluting the Docker build daemon context.

#### `blackroute_web.py`
- **Role**: Primary application server entrypoint and dynamic port binder.
- **What It Does**:
  1. Dynamically scans local ports in range `8000–8100` (`find_available_port`).
  2. Spawns an asynchronous background thread (`open_browser`) that opens the operating system's default browser after 1.5 seconds.
  3. Defines the FastAPI `lifespan` context manager, printing the boot sequence banner and initializing SQLite tables via `init_db()`.
  4. Mounts `/static` files and registers `home.router` and `api.router` (prefixed with `/api`).
  5. Boots Uvicorn without auto-reload (`reload=False`) to ensure compatibility with PyInstaller standalone compilation.
- **How to Modify**: Adjust port scan ranges or change host binding to `0.0.0.0` for remote container access.

#### `launcher.sh`
- **Role**: Unified Linux CLI runner, environment manager, and engine compiler.
- **What It Does**:
  - `setup_venv`: Detects system Python 3, initializes `.venv` if absent, and installs dependencies from `requirements.txt`.
  - `run_application`: Invokes `setup_venv` and boots `blackroute_web.py`.
  - `build_engines`: Compiles Rust `web_spider` (`cargo build --release --offline`) and Go `surface_graph` (`go build -ldflags="-s -w"`), moving binaries to `bin/`.
  - `build_release`: Bundles the application into a single Linux binary (`dist/BlackRoute_Web_v1.0`) via PyInstaller.
  - Interactive menu: Provides a numbered selection menu if invoked without arguments.
- **How to Modify**: Add new compiler flags or additional pre-flight diagnostic checks.

#### `launcher.bat`
- **Role**: Unified Windows CLI runner and setup script for Windows 10/11 environments.

#### `requirements.txt`
- **Role**: Python dependency definitions.
- **Packages**: `fastapi`, `uvicorn`, `jinja2`, `aiofiles`, `fpdf2`, `pydantic`, `python-multipart`, `beautifulsoup4`, `httpx`, `sse-starlette`.

---

### Core Security & Auditing Layer (`app/core/`)

#### `app/core/config.py`
- **Role**: Global runtime configuration, path resolution, and constants.
- **What It Does**:
  - `resource_path(relative_path)`: Resolves absolute paths dynamically for both development mode and frozen PyInstaller standalone execution (`sys._MEIPASS`).
  - `Settings` class: Defines paths to `STATIC_DIR`, `TEMPLATES_DIR`, `DB_PATH`, `ENGINE_BIN_DIR`, default crawling budgets (`CRAWL_MAX_PAGES = 35`, `CRAWL_TIMEOUT = 15.0`), and the scanning User-Agent string.
- **How to Modify**: Adjust crawl page budgets, request timeouts, or asset size caps.

#### `app/core/database.py`
- **Role**: SQLite persistence layer with automated schema migrations.
- **What It Does**:
  - `init_db()`: Initializes relational tables: `scans`, `findings`, and `endpoints`. Automatically runs schema migrations (`ALTER TABLE findings ADD COLUMN curl_command TEXT`) if older database versions are detected.
  - `save_scan_record()`: Persists target URL, status, pages crawled, findings list (including severity, category, evidence, and reproducible `curl_command`), and endpoints into SQLite.
  - `get_latest_scan_findings()`: Retrieves the most recent scan metadata and associated findings/endpoints for STIX/TAXII exports.
- **How to Modify**: Add columns to table schemas and bind new finding metadata attributes.

#### `app/core/security.py`
- **Role**: SSRF prevention, URL validation, and string sanitization.
- **What It Does**:
  - `normalize_target_url(raw)`: Strips quotes/whitespace, ensures lowercase scheme, prepends `https://` if absent, and drops fragments.
  - `validate_target_url(url, allow_local_staging)`: Resolves host IP addresses via `socket.getaddrinfo`. Blocks loopback (`127.0.0.1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
  - If `allow_local_staging=True`, allows local dev targets while strictly retaining the cloud metadata block.
  - `sanitize_text(text)`: HTML-escapes content before terminal log injection.
  - `calculate_sha256(filepath)`: Computes cryptographic file checksums.
- **How to Modify**: Add blocked hostnames or subnets to the SSRF blocklist.

#### `app/core/auditor_secrets.py`
- **Role**: Shannon entropy and regex-based token/credential leakage scanner.
- **What It Does**:
  - `calculate_shannon_entropy(data: str) -> float`: Calculates average information entropy $H(X) = -\sum p(x) \log_2 p(x)$ in bits per character.
  - Maintains `SECRET_RULES` with specific `min_entropy` thresholds:
    - `AWS_KEY`: `AKIA[0-9A-Z]{16}` (`min_entropy: 3.0`)
    - `GOOGLE_API_KEY`: `AIza[0-9A-Za-z\-_]{35}` (`min_entropy: 3.2`)
    - `STRIPE_SECRET_KEY`: `sk_live_[0-9a-zA-Z]{24,}` (`min_entropy: 3.4`)
    - `GITHUB_TOKEN` / `GITLAB_TOKEN`: (`min_entropy: 3.2`)
    - `OPENAI_KEY`: (`min_entropy: 3.2`)
    - `JWT_TOKEN`: (`min_entropy: 3.4`)
  - **False-Positive Suppression**: Repetitive dummy strings (e.g. `AKIAAAAAAAAAAAAAAAAA`) falling below the entropy threshold are suppressed in normal mode, or flagged as low-confidence `INFO` in Shadow Mode.
  - Obfuscates secret tokens (e.g. `AKIA****MPLE`) and appends exact entropy scores to finding evidence.
- **How to Modify**: Add new regex rules or tune `min_entropy` values to adjust sensitivity.

#### `app/core/auditor_headers.py`
- **Role**: HTTP response header, cookie security, and transport layer auditor.
- **What It Does**:
  - `audit_response_headers(url, headers, status)`:
    - Evaluates Content-Security-Policy (flags missing CSP, `'unsafe-inline'`, `'unsafe-eval'`, and wildcard origins).
    - Evaluates Strict-Transport-Security (HSTS) on HTTPS, minimum `max-age` (recommended >= 31536000), and `includeSubDomains`.
    - Evaluates Anti-Clickjacking: `X-Frame-Options` and CSP `frame-ancestors`.
    - Evaluates MIME Sniffing: `X-Content-Type-Options: nosniff`.
    - Evaluates Referrer and Permissions policies.
    - Detects server banners (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4`).
  - `audit_cookies(url, cookies_headers)`: Audits `Set-Cookie` directives for `Secure`, `HttpOnly`, `SameSite` compliance, and flags `SameSite=None` without `Secure`.
  - `audit_cors(url, acao, acac, tested_origin)`: Flags wildcard origins with credentials (`Access-Control-Allow-Origin: *` + `Credentials: true`) and dynamic untrusted origin reflection.
- **How to Modify**: Add checks inside `audit_response_headers()` returning standardized finding dictionaries.

#### `app/core/auditor_api_routes.py`
- **Role**: Active non-destructive probe for exposed API schemas, actuators, and debug files.
- **What It Does**:
  - Probes `PROBE_TARGETS`: `/.git/HEAD`, `/.env`, `/openapi.json`, `/swagger.json`, `/actuator/env`, `/actuator/health`, `/phpinfo.php`, `/server-status`.
  - Probes GraphQL endpoints (`/graphql`, `/api/graphql`) with safe introspection query:
    `{"query": "{ __schema { queryType { name } } }"}`. Flags exposed introspection schemas.
- **How to Modify**: Append new diagnostic route paths and response validation checks to `PROBE_TARGETS`.

#### `app/core/auditor_dom.py`
- **Role**: Client-side JavaScript auditor looking for DOM XSS sinks and insecure postMessage listeners.
- **What It Does**:
  - Analyzes downloaded JavaScript bundles for dangerous sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`) taking input from DOM sources (`location.search`, `location.hash`) on the same execution line.
  - Flags `window.addEventListener('message', ...)` listeners lacking `event.origin` validation.
- **How to Modify**: Append new sink or source regex patterns to `DOM_SINKS` or `DOM_SOURCES`.

#### `app/core/engine_bridge.py`
- **Role**: Resilient, boundary-aware IPC adapter for compiled Rust and Go engine binaries.
- **What It Does**:
  - `_extract_json_payload(raw)`: Scans stdout for the outermost valid JSON structure `{...}` or `[...]`, ignoring preceding or trailing compiler warnings, debug output, or panic messages.
  - `_run_engine(binary_path, args, timeout)`: Invokes binaries via argument lists (never `shell=True`), validates return codes, separates stderr, and parses JSON output.
  - `run_spider_extractor(target_path)`: Runs Rust `web_spider` with schema validation (`endpoints` array). Automatically falls back to `_python_fallback_spider()` on binary failure or panic.
  - `run_surface_graph(endpoints, headers, content)`: Runs Go `surface_graph` with schema validation (`nodes` / `total_routes`). Automatically falls back to `_python_fallback_surface_graph()` on binary failure.
- **How to Modify**: Add new engine connectors following the `_run_engine()` pattern.

#### `app/core/scanner.py`
- **Role**: Master audit pipeline orchestrator, cURL PoC generator, and real-time SSE broadcaster.
- **What It Does**:
  - `generate_curl_poc(finding)`: Synthesizes reproducible, functional `curl` commands for every finding (CORS origin probes, cookie checks, grep-filtered asset downloads, GraphQL introspection requests).
  - `broadcast_log(entry)`: Broadcasts real-time terminal log entries to all connected SSE subscriber queues (`LOG_SUBSCRIBERS`).
  - `WebScanner.run_pipeline()`:
    1. Validates target and SSRF boundaries.
    2. Phase 1: Header, cookie, CORS, and transport audit.
    3. Phase 2: Spidering web assets and client routes via Rust `web_spider`.
    4. Phase 3: Secret and credential leak detection with Shannon entropy evaluation.
    5. Phase 4: DOM XSS and postMessage risk analysis.
    6. Phase 5: API surface and sensitive path probing.
    7. Phase 6: Attack surface topology and stack fingerprinting via Go `surface_graph`.
    8. Phase 7: Generates cURL PoC for all findings, applies smart noise filtering (unless Shadow Mode), generates VIDS PDF report, saves to SQLite, and broadcasts dynamic results grid with 1-click cURL copy buttons.
    9. Zero-Footprint Protocol: Removes temporary asset directories upon completion.
- **How to Modify**: Add new scan phases or adjust confidence suppression thresholds.

---

### Polyglot Compiled Engines (`engines/`)

#### `engines/web_spider/` (Rust Engine)
- **Files**: `Cargo.toml`, `Cargo.lock`, `src/main.rs`.
- **Role**: High-throughput web asset crawler and Thompson NFA regex extractor.
- **What It Does**:
  - Accepts CLI commands: `web_spider <file_path>` or `web_spider dir <directory_path>`.
  - Parses HTML structures: extracts `<a href>`, `<script src>`, `<form action method>`.
  - Uses linear-time Thompson NFA regexes to extract API routes, client endpoints, and WebSocket URLs (`wss://`) from large minified JavaScript bundles without ReDoS vulnerability.
  - Filters out static asset extensions (`.png`, `.jpg`, `.woff`, `.css`) and framework internals.
  - Outputs structured JSON conforming to `engine_bridge.py`.
- **How to Modify**: Add keywords to `HIGH_VALUE_KEYWORDS` or extensions to `JUNK_EXTENSIONS` in `src/main.rs`. Recompile via `./launcher.sh build_engines`.

#### `engines/surface_graph/` (Go Engine)
- **Files**: `go.mod`, `main.go`.
- **Role**: Concurrent attack surface topology analyzer and technology fingerprinter.
- **What It Does**:
  - Accepts CLI commands: `surface_graph <json_path | dir <directory>>`.
  - Normalizes route paths, decomposes segments, and builds parent-child topology edges.
  - Identifies sensitive administrative routes (`admin`, `auth`, `token`, `actuator`, `upload`).
  - Extracts external domains contacted by client assets.
  - Fingerprints frameworks: Next.js, React, Vue, Angular, WordPress, Django, Laravel, Apache, Nginx, Cloudflare.
  - Computes an overall Attack Surface Risk Score (0–100).
  - Outputs structured JSON conforming to `engine_bridge.py`.
- **How to Modify**: Add new technology signatures in `fingerprintTechnologies()` in `main.go`. Recompile via `./launcher.sh build_engines`.

---

### Presentation & Threat Intelligence (`app/routes/`, `app/templates/`, `app/static/`, `Sources/`)

#### `app/routes/home.py`
- **Role**: Dashboard view router.
- **What It Does**: Serves `index.html` with Starlette 0.36+ keyword syntax (`request=request, name="index.html", context={...}`) and handles `/favicon.ico`.

#### `app/routes/api.py`
- **Role**: REST API endpoints for scanning, log streaming, and threat intelligence export.
- **What It Does**:
  - `POST /api/scan`: Accepts target URL and audit flags, launches `WebScanner.run_pipeline` in background tasks, and returns SSE activation script.
  - `GET /api/stream-logs-sse`: Server-Sent Events endpoint streaming log events over a persistent connection (`text/event-stream`) with automatic keepalive heartbeats.
  - `GET /api/stream-logs`: Legacy HTTP polling fallback.
  - `GET /api/engines-status`: HTMX fragment displaying live badges for Rust Web Spider, Go Surface Graph, and Python DAST pipeline.
  - `GET /api/export/stix`: Builds an authentic STIX 2.1 JSON bundle (`bundle--<uuid>`) containing `vulnerability`, `report`, and `indicator` objects with embedded cURL PoC steps.
  - `GET /api/export/taxii`: Builds a TAXII 2.1 collection envelope containing threat indicators.

#### `app/templates/index.html`
- **Role**: Real-time mission control dashboard.
- **What It Does**:
  - **Left Column**: Live engine status badges, target submission form, Shadow Mode toggle, Local Staging Mode toggle, Advanced Auth drawer, and real-time scrolling console log container with live `SSE CONNECTED` indicator.
  - **Right Column**: Interactive results grid with severity badges, confidence scores, 1-click `[COPY cURL PoC]` buttons for instant HackerOne triage, expandable command drawers, and one-click report export actions.
  - **Client Script**: Implements native JavaScript `EventSource('/api/stream-logs-sse')` with automatic reconnection and clipboard copy handlers.

#### `app/templates/layout.html`
- **Role**: Master base template with Google Fonts (`Inter`), HTMX script tag, brand banner, and stylesheets.

#### `app/static/brand.css` & `app/static/terminal.css`
- **Role**: Corporate branding and dark military-industrial cyberpunk interface themes. Defines typography, severity badge colors (`.sev-critical`, `.sev-high`, `.sev-medium`, `.sev-low`, `.sev-info`), grids, tables, and scrollbars.

#### `Sources/Utilities/vids_pdf_gen.py`
- **Role**: CyberNest VIDS (Vulnerability Identification & Defense Specification) PDF audit report generator.
- **What It Does**: Generates formal downloadable PDF audit reports containing executive mission summaries, threat distribution tallies, detailed findings, evidence snippets, actionable remediation steps, and **reproducible cURL PoC commands** for every vulnerability.

---

### Test Suites (`tests/`)

#### `tests/test_audit.py`
- **Role**: Comprehensive unit test suite covering:
  - URL normalization and SSRF validation rules.
  - Header, cookie, and CORS auditor logic.
  - Shannon entropy calculation and false-positive suppression.
  - Automated cURL PoC generation across finding categories.
  - Resilient boundary-aware JSON extraction in `engine_bridge.py`.
  - DOM XSS sink detection and postMessage origin checks.
  - Engine bridge Python fallback execution.
  - Clean VIDS PDF report generation.
- **Execution**: `python -m unittest tests/test_audit.py`

#### `tests/test_pipeline_e2e.py`
- **Role**: Full end-to-end integration test running against an in-process mock vulnerable HTTP server.
- **What It Verifies**: Verifies that all 5 vulnerability categories are discovered, data is persisted to SQLite with functional `curl_command` attributes, VIDS PDF reports are generated, and STIX 2.1 / TAXII 2.1 exports succeed.
- **Execution**: `python -m unittest tests/test_pipeline_e2e.py`

---

## 3. Data Flow & Lifecycle of an Audit

```text
[User Form in Browser]
         │ (POST /api/scan with target_url & audit options)
         ▼
[api.py: start_scan()]
         │ (Dispatches WebScanner.run_pipeline as Background Task)
         │ (Signals browser to open SSE stream /api/stream-logs-sse)
         ▼
[scanner.py: Security & SSRF Validation]
         │ (Rejects loopback, private IPs & cloud metadata unless Local Staging Mode)
         ▼
[scanner.py: Phase 1 - HTTP Header / Cookie / CORS Audit]
         │ (HeaderAuditor analyzes response headers)
         ▼
[scanner.py: Phase 2 - Asset Crawl & JS Harvest]
         │ (Downloads HTML & scripts into /tmp/br_web_*)
         │ (Invokes bin/web_spider [Rust] via engine_bridge.py)
         ▼
[scanner.py: Phase 3 - Secret & Credential Scan with Shannon Entropy]
         │ (SecretAuditor calculates H(X); suppresses low-entropy false positives)
         ▼
[scanner.py: Phase 4 - Client-Side DOM & postMessage Audit]
         │ (DomAuditor checks execution sinks and event origin validation)
         ▼
[scanner.py: Phase 5 - API Surface & Sensitive Route Probing]
         │ (ApiRouteAuditor probes /.git, /.env, /openapi.json, GraphQL introspection)
         ▼
[scanner.py: Phase 6 - Attack Surface & Stack Fingerprinting]
         │ (Invokes bin/surface_graph [Go] via engine_bridge.py)
         ▼
[scanner.py: Phase 7 - cURL Generation, Reporting & Persistence]
         ├─► Generate reproducible cURL PoC for each finding
         ├─► Filter low confidence (< 0.75 unless Shadow Mode)
         ├─► Save scan, findings & cURL commands to SQLite (database.py)
         ├─► Generate VIDS PDF Report with embedded cURL PoCs (vids_pdf_gen.py)
         ├─► Zero-Footprint Protocol: Clean temporary harvest directory
         └─► Stream dynamic Results Panel HTML with 1-click cURL copy via SSE
```

---

## 4. Developer Extension How-To Guides

### How to Add a New Secret Detection Rule with Entropy Threshold
1. Open `app/core/auditor_secrets.py`.
2. Append a new dictionary to `SECRET_RULES`:
   ```python
   {
       "id": "CUSTOM_TOKEN",
       "title": "Exposed Custom Service API Key",
       "regex": re.compile(r'(custom_key_[0-9a-zA-Z]{32})'),
       "severity": "CRITICAL",
       "min_entropy": 3.2,  # Enforce minimum Shannon randomness
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
# Launch development server locally
./launcher.sh launch

# Recompile Rust and Go engines into bin/
./launcher.sh build_engines

# Run all unit and module tests
python -m unittest discover -s tests

# Run end-to-end integration test
python -m unittest tests/test_pipeline_e2e.py

# Package single-file standalone release binary
./launcher.sh build_release

# Build and run multi-stage Docker container
docker-compose up --build -d

# Check Docker container status and logs
docker-compose logs -f
```

---
*CyberNest Labs Internal Tools Group — Authorized Security Engineering Standard.*
